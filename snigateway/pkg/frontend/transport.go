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
	"errors"
	"fmt"
	"net"
	"sync"
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
	conns, exists := p.pools[sessionID]
	delete(p.pools, sessionID)
	if exists {
		p.broadcastLocked()
	}
	p.mu.Unlock()

	for _, c := range conns {
		closeCloser(c)
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
		closeCloser(conn)
		return net.ErrClosed
	}
	if _, exists := p.pools[sessionID]; !exists {
		p.mu.Unlock()
		closeCloser(conn)
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
		closeCloser(c)
	}
	return nil
}

// CompositeTransport combines PoolTransport (TCP) and H2Transport (HTTP/2)
// behind the unified Transport interface.
type CompositeTransport struct {
	mu     sync.Mutex
	pool   *PoolTransport
	h2     *H2Transport
	closed bool
}

// NewCompositeTransport creates a new CompositeTransport wrapping pool and h2 transports.
func NewCompositeTransport(pool *PoolTransport, h2Tr *H2Transport) *CompositeTransport {
	if pool == nil {
		pool = NewPoolTransport()
	}
	if h2Tr == nil {
		h2Tr = NewH2Transport()
	}
	return &CompositeTransport{
		pool: pool,
		h2:   h2Tr,
	}
}

// Pool returns the underlying PoolTransport.
func (c *CompositeTransport) Pool() *PoolTransport {
	return c.pool
}

// H2 returns the underlying H2Transport.
func (c *CompositeTransport) H2() *H2Transport {
	return c.h2
}

// GetConn retrieves a connection for sessionID from whichever transport hosts the session.
func (c *CompositeTransport) GetConn(ctx context.Context, sessionID string) (net.Conn, error) {
	conn, _, err := c.GetConnForSessions(ctx, []string{sessionID})
	return conn, err
}

// GetConnForSessions searches candidate sessions in order across H2 and TCP pool transports.
// It snapshots all notification channels BEFORE checking sessions to guarantee no lost wakeups.
func (c *CompositeTransport) GetConnForSessions(ctx context.Context, sessionIDs []string) (net.Conn, string, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, "", net.ErrClosed
		}
		c.mu.Unlock()

		// Read notify channels before scanning to avoid missed notifications / lost wakeups
		c.pool.mu.Lock()
		poolNotify := c.pool.notifyCh
		c.pool.mu.Unlock()

		c.h2.mu.Lock()
		h2Notify := c.h2.notifyCh
		c.h2.mu.Unlock()

		for _, sid := range sessionIDs {
			// Check H2 transport first with non-blocking TryGetConn
			if c.h2.HasSession(sid) {
				conn, err := c.h2.TryGetConn(ctx, sid)
				if err != nil {
					if ctx.Err() != nil {
						return nil, "", ctx.Err()
					}
					// Error on H2 for this session; continue checking TCP pool for this same session below
				} else if conn != nil {
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
		case <-h2Notify:
		}
	}
}

// Close closes all underlying transports.
func (c *CompositeTransport) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	var errs []error
	if err := c.pool.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.h2.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func generateConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
