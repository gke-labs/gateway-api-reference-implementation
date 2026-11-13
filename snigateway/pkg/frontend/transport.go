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
)

// PoolTransport implements a warm pool of pre-dialed reverse tunnel connections.
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

func generateConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
