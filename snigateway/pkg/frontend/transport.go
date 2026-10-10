// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package frontend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/quic-go/quic-go"
)

// Transport represents the data-plane connection provider between the frontend and backends.
type Transport interface {
	// GetConn retrieves or establishes a tunnel connection to the specified backend session.
	GetConn(ctx context.Context, sessionID string) (net.Conn, error)
	// GetConnForSessions retrieves a connection from one of the candidate sessions in order.
	// Returns the connection and the sessionID it belongs to.
	GetConnForSessions(ctx context.Context, sessionIDs []string) (net.Conn, string, error)
	// Close closes the transport and any resources associated with it.
	Close() error
}

// PoolTransport implements Transport using a warm pool of pre-dialed reverse tunnel connections.
type PoolTransport struct {
	mu       sync.Mutex
	pools    map[string][]net.Conn
	notifyCh chan struct{}
	closed   bool
}

// NewPoolTransport creates a new PoolTransport.
func NewPoolTransport() *PoolTransport {
	return &PoolTransport{
		pools:    make(map[string][]net.Conn),
		notifyCh: make(chan struct{}),
	}
}

func (p *PoolTransport) broadcastLocked() {
	close(p.notifyCh)
	p.notifyCh = make(chan struct{})
}

// RegisterSession registers a new backend session in the transport.
func (p *PoolTransport) RegisterSession(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.pools[sessionID]; !exists {
		p.pools[sessionID] = make([]net.Conn, 0, 8)
		p.broadcastLocked()
	}
}

// UnregisterSession removes a session and closes any idle pooled connections for it.
func (p *PoolTransport) UnregisterSession(sessionID string) {
	p.mu.Lock()
	conns := p.pools[sessionID]
	delete(p.pools, sessionID)
	p.broadcastLocked()
	p.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
}

// HasSession returns true if the session is currently registered in the pool transport.
func (p *PoolTransport) HasSession(sessionID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.pools[sessionID]
	return exists
}

// HasIdleConn returns true if the session has at least one idle pooled connection available.
func (p *PoolTransport) HasIdleConn(sessionID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns, exists := p.pools[sessionID]
	return exists && len(conns) > 0
}

// TryGetConn attempts to pop an idle connection for sessionID immediately without blocking.
// Returns the connection if available, or nil if none is available.
func (p *PoolTransport) TryGetConn(sessionID string) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	conns := p.pools[sessionID]
	if len(conns) > 0 {
		conn := conns[0]
		p.pools[sessionID] = conns[1:]
		return conn, nil
	}
	return nil, nil
}

// AddConn adds a newly dialed tunnel connection to the idle pool of sessionID.
func (p *PoolTransport) AddConn(sessionID string, conn net.Conn) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	if _, exists := p.pools[sessionID]; !exists {
		p.mu.Unlock()
		_ = conn.Close()
		return fmt.Errorf("unknown or closed session: %s", sessionID)
	}
	p.pools[sessionID] = append(p.pools[sessionID], conn)
	p.broadcastLocked()
	p.mu.Unlock()
	return nil
}

// GetConn takes an idle connection for sessionID. If the pool is empty, it waits until a connection arrives or ctx is done.
func (p *PoolTransport) GetConn(ctx context.Context, sessionID string) (net.Conn, error) {
	conn, _, err := p.GetConnForSessions(ctx, []string{sessionID})
	return conn, err
}

// GetConnForSessions takes an idle connection from one of the candidate sessions in order.
// Sessions with no idle connections are skipped. If none currently have an idle connection,
// it waits until any candidate session receives an idle connection or ctx is done.
func (p *PoolTransport) GetConnForSessions(ctx context.Context, sessionIDs []string) (net.Conn, string, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, "", net.ErrClosed
		}

		ch := p.notifyCh

		// Try to pop an idle connection from the candidate sessions in order
		for _, sid := range sessionIDs {
			conns := p.pools[sid]
			if len(conns) > 0 {
				conn := conns[0]
				p.pools[sid] = conns[1:]
				p.mu.Unlock()
				return conn, sid, nil
			}
		}

		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-ch:
			// A connection was added or session state changed; retry under lock
		}
	}
}

// Close closes all pooled connections across all sessions.
func (p *PoolTransport) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.broadcastLocked()

	var allConns []net.Conn
	for sid, conns := range p.pools {
		allConns = append(allConns, conns...)
		delete(p.pools, sid)
	}
	p.mu.Unlock()

	for _, c := range allConns {
		_ = c.Close()
	}
	return nil
}

// QUICTransport implements Transport for reverse tunnels over QUIC streams.
type QUICTransport struct {
	mu       sync.Mutex
	sessions map[string]*quic.Conn
	notifyCh chan struct{}
	closed   bool
}

// NewQUICTransport creates a new QUICTransport.
func NewQUICTransport() *QUICTransport {
	return &QUICTransport{
		sessions: make(map[string]*quic.Conn),
		notifyCh: make(chan struct{}),
	}
}

func (q *QUICTransport) broadcastLocked() {
	close(q.notifyCh)
	q.notifyCh = make(chan struct{})
}

// RegisterSession records a QUIC connection for a sessionID.
func (q *QUICTransport) RegisterSession(sessionID string, conn *quic.Conn) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		_ = conn.CloseWithError(0, "transport closed")
		return
	}
	q.sessions[sessionID] = conn
	q.broadcastLocked()
}

// UnregisterSession removes a session and closes its QUIC connection.
func (q *QUICTransport) UnregisterSession(sessionID string) {
	q.mu.Lock()
	conn, exists := q.sessions[sessionID]
	delete(q.sessions, sessionID)
	if exists {
		q.broadcastLocked()
	}
	q.mu.Unlock()

	if exists && conn != nil {
		_ = conn.CloseWithError(0, "session unregistered")
	}
}

// HasSession returns true if the session is currently registered in the QUIC transport.
func (q *QUICTransport) HasSession(sessionID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, exists := q.sessions[sessionID]
	return exists
}

// TryGetConn attempts to open a stream for sessionID immediately without blocking.
// If the session exists, it opens a stream and returns a net.Conn. If the session doesn't exist, returns nil, nil.
func (q *QUICTransport) TryGetConn(ctx context.Context, sessionID string) (net.Conn, error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil, net.ErrClosed
	}
	sessConn, exists := q.sessions[sessionID]
	q.mu.Unlock()

	if !exists || sessConn == nil {
		return nil, nil
	}

	stream, err := sessConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return api.NewQUICStreamConn(stream, sessConn), nil
}

// GetConn opens a new bidirectional stream for sessionID.
func (q *QUICTransport) GetConn(ctx context.Context, sessionID string) (net.Conn, error) {
	conn, _, err := q.GetConnForSessions(ctx, []string{sessionID})
	return conn, err
}

// GetConnForSessions attempts to open a stream on one of the candidate sessions in order.
// If none are currently ready or available, it waits until a session registers or ctx is done.
func (q *QUICTransport) GetConnForSessions(ctx context.Context, sessionIDs []string) (net.Conn, string, error) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return nil, "", net.ErrClosed
		}

		ch := q.notifyCh

		var candidates []*quic.Conn
		var candidateSIDs []string
		for _, sid := range sessionIDs {
			if sessConn, exists := q.sessions[sid]; exists {
				candidates = append(candidates, sessConn)
				candidateSIDs = append(candidateSIDs, sid)
			}
		}
		q.mu.Unlock()

		for i, sessConn := range candidates {
			stream, err := sessConn.OpenStreamSync(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil, "", ctx.Err()
				}
				// Stream opening failed on this session; try next candidate
				continue
			}
			return api.NewQUICStreamConn(stream, sessConn), candidateSIDs[i], nil
		}

		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-ch:
			// Session registered/unregistered; retry under lock
		}
	}
}

// Close closes all QUIC sessions.
func (q *QUICTransport) Close() error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	q.closed = true
	q.broadcastLocked()

	var allConns []*quic.Conn
	for sid, conn := range q.sessions {
		allConns = append(allConns, conn)
		delete(q.sessions, sid)
	}
	q.mu.Unlock()

	for _, conn := range allConns {
		_ = conn.CloseWithError(0, "transport closed")
	}
	return nil
}

// CompositeTransport combines PoolTransport (TCP) and QUICTransport (QUIC) behind the unified Transport interface.
type CompositeTransport struct {
	mu     sync.Mutex
	pool   *PoolTransport
	quic   *QUICTransport
	closed bool
}

// NewCompositeTransport creates a new CompositeTransport wrapping the given pool and quic transports.
func NewCompositeTransport(pool *PoolTransport, quicTr *QUICTransport) *CompositeTransport {
	if pool == nil {
		pool = NewPoolTransport()
	}
	if quicTr == nil {
		quicTr = NewQUICTransport()
	}
	return &CompositeTransport{
		pool: pool,
		quic: quicTr,
	}
}

// Pool returns the underlying PoolTransport.
func (c *CompositeTransport) Pool() *PoolTransport {
	return c.pool
}

// QUIC returns the underlying QUICTransport.
func (c *CompositeTransport) QUIC() *QUICTransport {
	return c.quic
}

// GetConn retrieves a connection for sessionID from whichever transport hosts the session.
func (c *CompositeTransport) GetConn(ctx context.Context, sessionID string) (net.Conn, error) {
	conn, _, err := c.GetConnForSessions(ctx, []string{sessionID})
	return conn, err
}

// GetConnForSessions searches candidate sessions in order across both QUIC and TCP pool transports.
// It snapshots both notification channels BEFORE checking sessions to guarantee no lost wakeups.
func (c *CompositeTransport) GetConnForSessions(ctx context.Context, sessionIDs []string) (net.Conn, string, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, "", net.ErrClosed
		}
		c.mu.Unlock()

		// Read both notify channels before scanning to avoid missed notifications / lost wakeups
		c.pool.mu.Lock()
		poolNotify := c.pool.notifyCh
		c.pool.mu.Unlock()

		c.quic.mu.Lock()
		quicNotify := c.quic.notifyCh
		c.quic.mu.Unlock()

		for _, sid := range sessionIDs {
			// Check QUIC transport first with non-blocking TryGetConn
			if c.quic.HasSession(sid) {
				conn, err := c.quic.TryGetConn(ctx, sid)
				if err != nil {
					if ctx.Err() != nil {
						return nil, "", ctx.Err()
					}
					// Dead stream or error on this session; try next candidate
					continue
				}
				if conn != nil {
					return conn, sid, nil
				}
			}

			// Check TCP pool transport next with non-blocking TryGetConn
			if conn, err := c.pool.TryGetConn(sid); err != nil {
				return nil, "", err
			} else if conn != nil {
				return conn, sid, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-poolNotify:
		case <-quicNotify:
		}
	}
}

// Close closes both underlying transports.
func (c *CompositeTransport) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	_ = c.pool.Close()
	_ = c.quic.Close()
	return nil
}

func generateConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
