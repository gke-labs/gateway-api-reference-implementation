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

package proxy

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultUDPIdleTimeout is the default duration after which an idle UDP session expires.
	DefaultUDPIdleTimeout = 60 * time.Second

	// DefaultUDPMaxSessions is the default maximum number of concurrent UDP sessions per listener.
	DefaultUDPMaxSessions = 10000

	// udpBufferSize is the buffer size for UDP datagram reads and writes (64 KiB).
	udpBufferSize = 65536
)

type udpPortListener struct {
	port      gatewayv1.PortNumber
	conn      net.PacketConn
	backends  atomic.Pointer[[]state.InternalUDPBackend]
	closed    atomic.Bool
	accepting atomic.Bool
	done      chan struct{}

	idleTimeout atomic.Int64 // nanoseconds
	maxSessions atomic.Int64

	mu             sync.Mutex
	sessions       map[string]*udpSession
	pending        map[string]bool
	cleanerRunning bool
}

type udpSession struct {
	clientAddr  net.Addr
	backendConn net.Conn
	lastActive  atomic.Int64
	closed      atomic.Bool
	closeOnce   sync.Once
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		closeConn(s.backendConn)
	})
}

func (pl *udpPortListener) close() error {
	if pl.closed.Swap(true) {
		return nil
	}
	close(pl.done)
	err := pl.conn.Close()

	pl.mu.Lock()
	sessions := make([]*udpSession, 0, len(pl.sessions))
	for _, sess := range pl.sessions {
		sessions = append(sessions, sess)
	}
	clear(pl.sessions)
	clear(pl.pending)
	pl.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
	return err
}

func (pl *udpPortListener) removeSession(sess *udpSession) {
	sess.close()
	pl.mu.Lock()
	key := sess.clientAddr.String()
	if current, ok := pl.sessions[key]; ok && current == sess {
		delete(pl.sessions, key)
	}
	pl.mu.Unlock()
}

func (pl *udpPortListener) cleanupInterval() time.Duration {
	idleTimeout := time.Duration(pl.idleTimeout.Load())
	interval := idleTimeout / 2
	if interval > 1*time.Second {
		interval = 1 * time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	return interval
}

func (pl *udpPortListener) cleanerLoop() {
	ticker := time.NewTicker(pl.cleanupInterval())
	defer ticker.Stop()

	for {
		select {
		case <-pl.done:
			return
		case <-ticker.C:
			ticker.Reset(pl.cleanupInterval())
			now := time.Now().UnixNano()
			timeout := pl.idleTimeout.Load()
			var expired []*udpSession
			pl.mu.Lock()
			for key, sess := range pl.sessions {
				if now-sess.lastActive.Load() > timeout {
					delete(pl.sessions, key)
					expired = append(expired, sess)
				}
			}
			if len(pl.sessions) == 0 {
				pl.cleanerRunning = false
				pl.mu.Unlock()
				for _, sess := range expired {
					sess.close()
				}
				return
			}
			pl.mu.Unlock()
			for _, sess := range expired {
				sess.close()
			}
		}
	}
}

func (pl *udpPortListener) backendReaderLoop(sess *udpSession) {
	defer pl.removeSession(sess)
	buf := make([]byte, udpBufferSize)
	for {
		n, err := sess.backendConn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		sess.lastActive.Store(time.Now().UnixNano())
		if _, err := pl.conn.WriteTo(buf[:n], sess.clientAddr); err != nil {
			if pl.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			klog.V(2).Infof("UDP WriteTo %s error: %v", sess.clientAddr, err)
		}
	}
}

func (p *Proxy) updateUDPListenersLocked(listeners []state.InternalListener) {
	if p.closed {
		return
	}
	if p.udpListeners == nil {
		p.udpListeners = make(map[gatewayv1.PortNumber]*udpPortListener)
	}

	desired := make(map[gatewayv1.PortNumber][]state.InternalUDPBackend)
	for _, lis := range listeners {
		if lis.Protocol != gatewayv1.UDPProtocolType {
			continue
		}
		if _, exists := desired[lis.Port]; !exists {
			desired[lis.Port] = lis.UDPBackends
		}
	}

	// Remove ports that are no longer present
	for port, pl := range p.udpListeners {
		if _, exists := desired[port]; !exists {
			if err := pl.close(); err != nil && !errors.Is(err, net.ErrClosed) {
				klog.V(2).Infof("failed to close UDP listener on port %d: %v", port, err)
			}
			delete(p.udpListeners, port)
		}
	}

	// Update existing ports or open new ones
	for port, backends := range desired {
		backendsCopy := make([]state.InternalUDPBackend, len(backends))
		copy(backendsCopy, backends)

		idleTimeout := p.udpIdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = DefaultUDPIdleTimeout
		}
		maxSessions := p.udpMaxSessions
		if maxSessions <= 0 {
			maxSessions = DefaultUDPMaxSessions
		}

		if pl, exists := p.udpListeners[port]; exists {
			pl.backends.Store(&backendsCopy)
			pl.idleTimeout.Store(int64(idleTimeout))
			pl.maxSessions.Store(int64(maxSessions))
		} else {
			listenPacketFn := p.listenPacketFunc
			if listenPacketFn == nil {
				listenPacketFn = net.ListenPacket
			}
			addr := net.JoinHostPort(p.udpBindHost, strconv.Itoa(int(port)))
			conn, err := listenPacketFn("udp", addr)
			if err != nil {
				klog.Errorf("failed to listen on UDP port %d (%s): %v", port, addr, err)
				continue
			}
			pl := &udpPortListener{
				port:     port,
				conn:     conn,
				sessions: make(map[string]*udpSession),
				pending:  make(map[string]bool),
				done:     make(chan struct{}),
			}
			pl.idleTimeout.Store(int64(idleTimeout))
			pl.maxSessions.Store(int64(maxSessions))
			pl.backends.Store(&backendsCopy)
			p.udpListeners[port] = pl
			go p.udpReadLoop(pl)
		}
	}
}

// IsUDPPortAccepting returns whether the UDP listener for port is listening.
func (p *Proxy) IsUDPPortAccepting(port gatewayv1.PortNumber) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pl, ok := p.udpListeners[port]
	return ok && pl.accepting.Load() && !pl.closed.Load()
}

func (p *Proxy) udpReadLoop(pl *udpPortListener) {
	defer pl.accepting.Store(false)
	buf := make([]byte, udpBufferSize)
	for {
		pl.accepting.Store(true)
		n, clientAddr, err := pl.conn.ReadFrom(buf)
		if err != nil {
			if pl.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-pl.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}
		if n == 0 {
			continue
		}
		p.handleUDPDatagram(pl, clientAddr, buf[:n])
	}
}

func (p *Proxy) handleUDPDatagram(pl *udpPortListener, clientAddr net.Addr, data []byte) {
	clientKey := clientAddr.String()

	pl.mu.Lock()
	if pl.closed.Load() {
		pl.mu.Unlock()
		return
	}
	sess, ok := pl.sessions[clientKey]
	if ok {
		sess.lastActive.Store(time.Now().UnixNano())
		pl.mu.Unlock()
		if _, err := sess.backendConn.Write(data); err != nil {
			klog.V(2).Infof("UDP backend write error for %s: %v", clientKey, err)
		}
		return
	}

	// If a session setup is already in flight for this client, drop duplicate
	if pl.pending[clientKey] {
		pl.mu.Unlock()
		return
	}

	// Check cap (active + pending)
	maxSess := int(pl.maxSessions.Load())
	if len(pl.sessions)+len(pl.pending) >= maxSess {
		pl.mu.Unlock()
		klog.V(2).Infof("UDP session cap reached (%d), dropping datagram from %s", maxSess, clientKey)
		return
	}

	// Check if backends are configured before launching goroutine
	bp := pl.backends.Load()
	if bp == nil || len(*bp) == 0 {
		pl.mu.Unlock()
		return
	}

	pl.pending[clientKey] = true
	pl.mu.Unlock()

	// Copy first datagram since buf in udpReadLoop is reused across reads
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	go p.setupUDPSession(pl, clientAddr, clientKey, dataCopy)
}

func (p *Proxy) setupUDPSession(pl *udpPortListener, clientAddr net.Addr, clientKey string, data []byte) {
	deletePending := func() {
		pl.mu.Lock()
		delete(pl.pending, clientKey)
		pl.mu.Unlock()
	}

	if pl.closed.Load() {
		deletePending()
		return
	}

	bp := pl.backends.Load()
	if bp == nil || len(*bp) == 0 {
		deletePending()
		return
	}
	target, ok := state.PickTCPBackend(*bp)
	if !ok || target == "" {
		deletePending()
		return
	}

	dialFn := p.getDialFunc()
	backendConn, err := dialFn("udp", target)
	if err != nil {
		klog.V(2).Infof("UDP backend dial failed for %s to %s: %v", clientKey, target, err)
		deletePending()
		return
	}

	pl.mu.Lock()
	if pl.closed.Load() {
		delete(pl.pending, clientKey)
		pl.mu.Unlock()
		closeConn(backendConn)
		return
	}
	if existing, exists := pl.sessions[clientKey]; exists {
		delete(pl.pending, clientKey)
		pl.mu.Unlock()
		closeConn(backendConn)
		existing.lastActive.Store(time.Now().UnixNano())
		if _, err := existing.backendConn.Write(data); err != nil {
			klog.V(2).Infof("UDP backend write error for %s: %v", clientKey, err)
		}
		return
	}
	maxSess := int(pl.maxSessions.Load())
	if len(pl.sessions) >= maxSess {
		delete(pl.pending, clientKey)
		pl.mu.Unlock()
		closeConn(backendConn)
		klog.V(2).Infof("UDP session cap reached (%d), dropping new session for %s", maxSess, clientKey)
		return
	}

	sess := &udpSession{
		clientAddr:  clientAddr,
		backendConn: backendConn,
	}
	sess.lastActive.Store(time.Now().UnixNano())
	pl.sessions[clientKey] = sess
	delete(pl.pending, clientKey)
	if !pl.cleanerRunning {
		pl.cleanerRunning = true
		go pl.cleanerLoop()
	}
	pl.mu.Unlock()

	go pl.backendReaderLoop(sess)
	if _, err := sess.backendConn.Write(data); err != nil {
		klog.V(2).Infof("UDP backend write error for new session %s: %v", clientKey, err)
	}
}
