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
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultPoolSize is the default number of idle pooled reverse tunnel connections.
	DefaultPoolSize = 4
)

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithListener sets a custom Listener for the Manager.
func WithListener(lis *Listener) ManagerOption {
	return func(m *Manager) {
		m.listener = lis
	}
}

// WithPoolSize sets the number of idle pooled reverse tunnel connections to maintain.
func WithPoolSize(size int) ManagerOption {
	return func(m *Manager) {
		if size > 0 {
			m.poolSize = size
		}
	}
}

// WithDialTimeout sets the timeout for dialing reverse tunnels.
func WithDialTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) {
		m.dialTimeout = d
	}
}

// WithRegisterTimeout sets the timeout for registration API calls.
func WithRegisterTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) {
		m.registerTimeout = d
	}
}

// WithBackoff sets the minimum and maximum backoff durations for reconnecting.
func WithBackoff(min, max time.Duration) ManagerOption {
	return func(m *Manager) {
		m.backoffMin = min
		m.backoffMax = max
	}
}

// Manager manages communication with the snigateway frontend, maintaining a warm pool
// of pre-dialed reverse tunnel connections and announcing SNI hostnames.
type Manager struct {
	client          *client.Client
	listener        *Listener
	poolSize        int
	dialTimeout     time.Duration
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
}

// NewManager creates a new Manager using the given client.
func NewManager(c *client.Client, opts ...ManagerOption) *Manager {
	m := &Manager{
		client:          c,
		listener:        NewListener(),
		poolSize:        DefaultPoolSize,
		dialTimeout:     10 * time.Second,
		registerTimeout: 5 * time.Second,
		backoffMin:      200 * time.Millisecond,
		backoffMax:      5 * time.Second,
		updateCh:        make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Listener returns the tunnel Listener used to accept reverse-tunnelled connections.
func (m *Manager) Listener() *Listener {
	return m.listener
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
	for _, hostname := range hostnames {
		hostname = strings.ToLower(strings.TrimSpace(hostname))
		if !slices.Contains(m.registeredHostnames, hostname) {
			return false
		}
	}
	return true
}

// HasRegisteredAllHostnames returns true if the tunnel is connected and all currently
// configured hostnames have been successfully registered with the frontend under the active session.
func (m *Manager) HasRegisteredAllHostnames() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.connected || m.sessionID == "" || m.sessionID != m.lastRegisteredSessionID {
		return false
	}
	for _, hostname := range m.hostnames {
		hostname = strings.ToLower(strings.TrimSpace(hostname))
		if !slices.Contains(m.registeredHostnames, hostname) {
			return false
		}
	}
	return true
}

// Hostnames returns a clone of the currently configured hostnames.
func (m *Manager) Hostnames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.hostnames)
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

// UpdateGateways extracts SNI hostnames from the provided Gateways and updates the manager.
func (m *Manager) UpdateGateways(gateways []*gatewayv1.Gateway) {
	hostnames := ExtractHostnames(gateways)
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
// and feeding connections into the tunnel Listener until ctx is canceled.
func (m *Manager) Run(ctx context.Context) error {
	defer closeConn(m.listener)
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

	// Main session loop managing TCP pool
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
		klog.Warningf("Failed to start TCP session with frontend: %v. Reconnecting in %v...", err, *backoff)
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

	klog.Infof("Established TCP pool session %s with frontend", sessID)
	m.triggerRegistration()

	m.runPool(sessCtx, sessID, sessErrCh)
	sessCancel()

	m.mu.Lock()
	m.connected = false
	m.sessionID = ""
	m.mu.Unlock()
	m.notifyListeners()

	if ctx.Err() != nil {
		return
	}

	klog.Warningf("TCP session %s ended. Reconnecting in %v...", sessID, *backoff)
	select {
	case <-ctx.Done():
		return
	case <-time.After(*backoff):
	}
}

// handleTunnelConn decodes the PROXY v2 header from conn and enqueues the resulting
// proxyproto.Conn into m.listener. It closes conn if decoding or enqueuing fails.
// Returns an error if PROXY header decoding or reading remaining bytes fails.
func (m *Manager) handleTunnelConn(conn net.Conn) error {
	bufReader := bufio.NewReader(conn)
	hdr, err := proxyproto.Decode(bufReader)
	if err != nil {
		closeConn(conn)
		return err
	}

	var remaining []byte
	if bufReader.Buffered() > 0 {
		remaining = make([]byte, bufReader.Buffered())
		if _, err := io.ReadFull(bufReader, remaining); err != nil {
			closeConn(conn)
			return err
		}
	}

	proxyConn := proxyproto.NewConn(conn, hdr.SrcAddr, hdr.DstAddr, remaining)
	if err := m.listener.Enqueue(proxyConn); err != nil {
		closeConn(conn)
		return err
	}
	return nil
}

func (m *Manager) runPool(ctx context.Context, sessionID string, sessErrCh <-chan error) {
	refillCh := make(chan struct{}, m.poolSize*2)
	activeIdleMu := sync.Mutex{}
	activeIdle := 0

	triggerRefill := func() {
		select {
		case refillCh <- struct{}{}:
		default:
		}
	}

	dialOne := func() {
		activeIdleMu.Lock()
		if activeIdle >= m.poolSize {
			activeIdleMu.Unlock()
			return
		}
		activeIdle++
		activeIdleMu.Unlock()

		go func() {
			dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
			conn, err := m.client.DialTunnel(dialCtx, sessionID)
			cancel()

			if err != nil {
				activeIdleMu.Lock()
				activeIdle--
				activeIdleMu.Unlock()

				if ctx.Err() == nil {
					klog.Errorf("Failed to dial pooled tunnel connection for session %s: %v", sessionID, err)
					time.Sleep(200 * time.Millisecond)
					triggerRefill()
				}
				return
			}

			// Watch connection for activation via PROXY protocol header or drop.
			notifyConn := &notifyFirstByteConn{
				Conn: conn,
				onFirstByte: func() {
					activeIdleMu.Lock()
					activeIdle--
					activeIdleMu.Unlock()
					triggerRefill()
				},
			}

			if err := m.handleTunnelConn(notifyConn); err != nil {
				if ctx.Err() == nil {
					triggerRefill()
				}
			}
		}()
	}

	// Initial fill of the pool
	for i := 0; i < m.poolSize; i++ {
		dialOne()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sessErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				klog.Warningf("Session error from frontend: %v", err)
			}
			return
		case <-refillCh:
			dialOne()
		}
	}
}

type notifyFirstByteConn struct {
	net.Conn
	onFirstByte func()
	once        sync.Once
}

func (c *notifyFirstByteConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 || err != nil {
		c.once.Do(c.onFirstByte)
	}
	return n, err
}

func closeConn(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		klog.V(2).Infof("failed to close: %v", err)
	}
}
