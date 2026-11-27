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

package tunnel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

const (
	// recordTypeHandshake is the TLS record type for a handshake message (0x16).
	recordTypeHandshake = 0x16
)

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithBackoff sets the minimum and maximum backoff durations for reconnecting.
func WithBackoff(min, max time.Duration) ManagerOption {
	return func(m *Manager) {
		m.backoffMin = min
		m.backoffMax = max
	}
}

// Manager manages communication with the snigateway frontend, setting up the WireGuard tunnel
// and announcing SNI hostnames.
type Manager struct {
	client          *client.Client
	httpsListener   *Listener
	httpListener    *Listener
	registerTimeout time.Duration
	backoffMin      time.Duration
	backoffMax      time.Duration

	mu         sync.Mutex
	hostnames  []string
	sessionID  string
	connected  bool
	generation uint64
	updateCh   chan struct{}

	registeredHostnames     []string
	lastRegisteredSessionID string
	stateChangeListeners    []func()
	reRegTimer              *time.Timer

	// wireguard manages the WireGuard device and tunnel listener for the controller.
	wireguard *wireguardManager
}

// NewManager creates a new Manager using the given client.
func NewManager(client *client.Client, options ...ManagerOption) *Manager {
	m := &Manager{
		client:          client,
		httpsListener:   NewListener(),
		httpListener:    NewListener(),
		registerTimeout: 5 * time.Second,
		backoffMin:      200 * time.Millisecond,
		backoffMax:      5 * time.Second,
		updateCh:        make(chan struct{}, 1),
		wireguard:       newWireGuardManager(),
	}
	for _, opt := range options {
		opt(m)
	}
	return m
}

// HTTPSListener returns the tunnel Listener used to accept reverse-tunnelled HTTPS connections.
func (m *Manager) HTTPSListener() *Listener {
	return m.httpsListener
}

// HTTPListener returns the tunnel Listener used to accept reverse-tunnelled plain HTTP connections.
func (m *Manager) HTTPListener() *Listener {
	return m.httpListener
}

// IsConnected returns whether the manager currently has an active tunnel session with the frontend.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

// AddStateChangeListener registers a callback invoked when tunnel connectivity or registration state changes.
func (m *Manager) AddStateChangeListener(listener func()) {
	if listener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateChangeListeners = append(m.stateChangeListeners, listener)
}

// HasRegisteredHostnames returns true if the tunnel is currently connected and the most
// recent registration for the active session includes all specified hostnames.
func (m *Manager) HasRegisteredHostnames(hostnames []string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.connected || m.sessionID == "" || m.sessionID != m.lastRegisteredSessionID {
		return false
	}
	for _, h := range hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(m.registeredHostnames, h) {
			return false
		}
	}
	return true
}

func (m *Manager) notifyListeners() {
	m.mu.Lock()
	listeners := slices.Clone(m.stateChangeListeners)
	m.mu.Unlock()
	for _, l := range listeners {
		l()
	}
}

// SessionID returns the currently active session ID, or empty string if not connected.
func (m *Manager) SessionID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionID
}

// UpdateListeners extracts SNI hostnames from the accepted, non-conflicted effective
// listeners and updates the manager.
func (m *Manager) UpdateListeners(listeners []*state.EffectiveListener) {
	hostnames := ExtractHostnames(listeners)
	m.UpdateHostnames(hostnames)
}

// UpdateHostnames updates the set of hostnames to announce to the frontend.
// It coalesces rapid updates and notifies the background registration worker non-blockingly.
func (m *Manager) UpdateHostnames(hostnames []string) {
	m.mu.Lock()
	if slices.Equal(m.hostnames, hostnames) {
		m.mu.Unlock()
		return
	}
	m.hostnames = slices.Clone(hostnames)
	m.mu.Unlock()

	m.triggerRegistration()
}

func (m *Manager) triggerRegistration() {
	select {
	case m.updateCh <- struct{}{}:
	default:
	}
}

func (m *Manager) scheduleTokenReRegistration(token string) {
	exp, err := jwt.ParseTokenExpiry(token)
	if err != nil {
		return
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		return
	}

	reRegDuration := remaining * 7 / 10
	if remaining > 5*time.Minute && remaining-2*time.Minute < reRegDuration {
		reRegDuration = remaining - 2*time.Minute
	}
	if reRegDuration < 100*time.Millisecond {
		reRegDuration = 100 * time.Millisecond
	}
	if reRegDuration > 12*time.Hour {
		reRegDuration = 12 * time.Hour
	}

	m.mu.Lock()
	if m.reRegTimer != nil {
		m.reRegTimer.Stop()
	}
	m.reRegTimer = time.AfterFunc(reRegDuration, func() {
		m.mu.Lock()
		m.generation++
		m.mu.Unlock()
		m.triggerRegistration()
	})
	m.mu.Unlock()
}

// Run starts the session, transport, and registration loops, maintaining connectivity to the frontend
// and feeding connections into the tunnel Listeners until ctx is canceled.
func (m *Manager) Run(ctx context.Context) error {
	defer closeConn(m.httpsListener)
	defer closeConn(m.httpListener)
	defer func() {
		m.mu.Lock()
		if m.reRegTimer != nil {
			m.reRegTimer.Stop()
		}
		m.mu.Unlock()
	}()

	g, ctx := errgroup.WithContext(ctx)

	// Background registration worker for sessions
	g.Go(func() error {
		var lastRegistered []string
		var lastGen uint64
		var hasRegistered bool
		var lastSession string

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-m.updateCh:
				m.mu.Lock()
				connected := m.connected
				sessID := m.sessionID
				gen := m.generation
				curr := slices.Clone(m.hostnames)
				m.mu.Unlock()

				if !connected || sessID == "" {
					continue
				}

				if hasRegistered && lastGen == gen && lastSession == sessID && slices.Equal(lastRegistered, curr) {
					continue
				}

				token, err := m.client.GetToken()
				if err != nil {
					klog.V(2).Infof("Reading token for registration: %v", err)
				}
				regCtx, cancel := context.WithTimeout(ctx, m.registerTimeout)
				resp, err := m.client.Register(regCtx, sessID, curr)
				cancel()

				if err != nil {
					if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
						klog.Errorf("Failed to register hostnames %v with frontend (session %s): %v", curr, sessID, err)
						m.notifyListeners()
						go func() {
							select {
							case <-ctx.Done():
							case <-time.After(500 * time.Millisecond):
								m.triggerRegistration()
							}
						}()
					}
				} else {
					klog.Infof("Successfully registered hostnames with frontend: %v (session: %s)", resp.Hostnames, sessID)
					lastRegistered = curr
					lastGen = gen
					lastSession = sessID
					hasRegistered = true
					m.mu.Lock()
					m.registeredHostnames = slices.Clone(curr)
					m.lastRegisteredSessionID = sessID
					m.mu.Unlock()
					if token != "" {
						m.scheduleTokenReRegistration(token)
					}
					m.notifyListeners()
				}
			}
		}
	})

	// Main session loop
	g.Go(func() error {
		backoff := m.backoffMin

		for {
			if ctx.Err() != nil {
				return nil
			}

			m.runTCPSessionWithBackoff(ctx, &backoff)
		}
	})

	return g.Wait()
}

func (m *Manager) runTCPSessionWithBackoff(ctx context.Context, backoff *time.Duration) {
	sessCtx, sessCancel := context.WithCancel(ctx)
	sessID, sessErrCh, err := m.client.StartSession(sessCtx)
	if err != nil {
		sessCancel()
		if ctx.Err() != nil {
			return
		}
		klog.Warningf("Failed to start session with frontend: %v. Reconnecting in %v...", err, *backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(*backoff):
		}
		*backoff = min(*backoff*2, m.backoffMax)
		return
	}

	wireguardCleanup, err := m.wireguard.setupWireGuard(sessCtx, sessID, m.client, m.handleTunnelConn)
	if err != nil {
		sessCancel()
		if ctx.Err() != nil {
			return
		}
		klog.Warningf("Failed to setup WireGuard tunnel for session %s: %v. Reconnecting in %v...", sessID, err, *backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(*backoff):
		}
		*backoff = min(*backoff*2, m.backoffMax)
		return
	}

	*backoff = m.backoffMin

	m.mu.Lock()
	m.connected = true
	m.sessionID = sessID
	m.generation++
	m.mu.Unlock()
	m.notifyListeners()

	klog.Infof("Established session %s with frontend", sessID)
	m.triggerRegistration()

	select {
	case <-sessCtx.Done():
	case err := <-sessErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			klog.Warningf("Session error from frontend: %v", err)
		}
	}

	sessCancel()
	wireguardCleanup()

	m.mu.Lock()
	m.connected = false
	m.sessionID = ""
	m.mu.Unlock()
	m.notifyListeners()

	if ctx.Err() != nil {
		return
	}

	klog.Warningf("Session %s ended. Reconnecting in %v...", sessID, *backoff)
	select {
	case <-ctx.Done():
		return
	case <-time.After(*backoff):
	}
}

// handleTunnelConn decodes the PROXY v2 header from conn and enqueues the resulting
// proxyproto.Conn into either m.httpsListener (for TLS connections starting with 0x16) or
// m.httpListener (for plain HTTP connections). It closes conn if decoding or enqueuing fails.
// Returns an error if PROXY header decoding, reading the first byte, or reading remaining bytes fails.
func (m *Manager) handleTunnelConn(conn net.Conn) error {
	bufReader := bufio.NewReader(conn)
	hdr, err := proxyproto.Decode(bufReader)
	if err != nil {
		closeConn(conn)
		return err
	}

	// The frontend sends the peeked payload bytes straight after the PROXY header, so
	// the first byte is normally already buffered. Peek(1) waits for this first byte
	// with no local deadline; if a tunnel connection sends the header and nothing else,
	// the wait is bounded by the frontend closing the connection when its attempt
	// deadline expires, unblocking Peek with an error.
	first, err := bufReader.Peek(1)
	if err != nil {
		closeConn(conn)
		return err
	}

	remaining := make([]byte, bufReader.Buffered())
	if _, err := io.ReadFull(bufReader, remaining); err != nil {
		closeConn(conn)
		return err
	}

	targetListener := m.httpListener
	if first[0] == recordTypeHandshake {
		targetListener = m.httpsListener
	}

	proxyConn := proxyproto.NewConn(conn, hdr.SrcAddr, hdr.DstAddr, remaining)
	if err := targetListener.Enqueue(proxyConn); err != nil {
		closeConn(conn)
		return err
	}
	return nil
}

func closeConn(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		klog.V(2).Infof("failed to close: %v", err)
	}
}
