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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultPoolSize is the default number of idle pooled reverse tunnel connections.
	DefaultPoolSize = 4

	// WireGuardTunnelPort is the TCP port on which the controller listens inside the WireGuard tunnel.
	WireGuardTunnelPort = api.WireGuardTunnelPort

	// recordTypeHandshake is the TLS record type for a handshake message (0x16).
	recordTypeHandshake = 0x16
)

// WireGuardDevice manages peers and device lifecycle on a WireGuard network interface.
type WireGuardDevice interface {
	AddPeer(peer wireguard.Peer) error
	Close() error
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithWireGuard enables or disables WireGuard tunnel transport.
func WithWireGuard(enabled bool) ManagerOption {
	return func(m *Manager) {
		m.wireguardEnabled = enabled
	}
}

// WithWireGuardDeviceOpener sets a custom opener for the WireGuard device.
func WithWireGuardDeviceOpener(opener func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error)) ManagerOption {
	return func(m *Manager) {
		m.deviceOpener = opener
	}
}

// WithListenFunc sets a custom network listener function.
func WithListenFunc(fn func(network, address string) (net.Listener, error)) ManagerOption {
	return func(m *Manager) {
		m.listenFunc = fn
	}
}

// WithHTTPSListener sets a custom HTTPS Listener for the Manager.
func WithHTTPSListener(lis *Listener) ManagerOption {
	return func(m *Manager) {
		m.httpsListener = lis
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
	httpsListener   *Listener
	httpListener    *Listener
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

	wireguardEnabled bool
	deviceOpener     func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error)
	listenFunc       func(network, address string) (net.Listener, error)
}

// NewManager creates a new Manager using the given client.
func NewManager(c *client.Client, opts ...ManagerOption) *Manager {
	m := &Manager{
		client:          c,
		httpsListener:   NewListener(),
		httpListener:    NewListener(),
		poolSize:        DefaultPoolSize,
		dialTimeout:     10 * time.Second,
		registerTimeout: 5 * time.Second,
		backoffMin:      200 * time.Millisecond,
		backoffMax:      5 * time.Second,
		updateCh:        make(chan struct{}, 1),
		deviceOpener: func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
			return wireguard.OpenDevice(ctx, cfg)
		},
		listenFunc: net.Listen,
	}
	for _, opt := range opts {
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

	var wgCleanup func()
	if m.wireguardEnabled {
		wgCleanup = m.setupWireGuard(sessCtx, sessID)
		if wgCleanup != nil {
			defer func() {
				if wgCleanup != nil {
					wgCleanup()
				}
			}()
		}
	}

	m.mu.Lock()
	m.connected = true
	m.sessionID = sessID
	m.generation++
	m.mu.Unlock()
	m.notifyListeners()

	klog.Infof("Established TCP pool session %s with frontend", sessID)
	m.triggerRegistration()

	m.runPool(sessCtx, sessID, sessErrCh)

	if wgCleanup != nil {
		wgCleanup()
		wgCleanup = nil
	}

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

func (m *Manager) setupWireGuard(ctx context.Context, sessionID string) func() {
	if m.client == nil {
		return nil
	}

	privKey, pubKey, err := wireguard.GenerateKey()
	if err != nil {
		klog.Errorf("Failed to generate WireGuard key for session %s: %v; continuing with TCP pool only", sessionID, err)
		return nil
	}

	resp, err := m.client.ExchangeWireGuard(ctx, sessionID, pubKey.String())
	if err != nil {
		if errors.Is(err, client.ErrWireGuardDisabled) {
			klog.Errorf("Frontend has WireGuard disabled for session %s: %v; continuing with TCP pool only", sessionID, err)
		} else {
			klog.Errorf("Failed to exchange WireGuard key with frontend for session %s: %v; continuing with TCP pool only", sessionID, err)
		}
		return nil
	}

	deviceIP := net.ParseIP(resp.PeerAddress)
	_, prefixNet, prefixErr := net.ParseCIDR(resp.Prefix)
	if deviceIP == nil || prefixErr != nil || prefixNet == nil {
		klog.Errorf("Invalid WireGuard configuration received from frontend for session %s (address: %q, prefix: %q); continuing with TCP pool only", sessionID, resp.PeerAddress, resp.Prefix)
		return nil
	}

	dev, err := m.deviceOpener(ctx, wireguard.Config{
		InterfaceName: "wg0",
		PrivateKey:    privKey,
		ListenPort:    0,
		DeviceAddress: deviceIP,
		TunnelPrefix:  prefixNet,
	})
	if err != nil {
		klog.Errorf("Failed to open WireGuard device for session %s: %v; continuing with TCP pool only", sessionID, err)
		return nil
	}

	fePubKey, keyErr := wireguard.ParseKey(resp.PublicKey)
	feHost := ParseFrontendHost(m.client.ServerAddr())
	feEndpoint, epErr := net.ResolveUDPAddr("udp", net.JoinHostPort(feHost, strconv.Itoa(resp.Port)))
	if keyErr != nil || epErr != nil {
		klog.Errorf("Failed to resolve frontend WireGuard peer for session %s (key err: %v, endpoint err: %v); continuing with TCP pool only", sessionID, keyErr, epErr)
		_ = dev.Close()
		return nil
	}

	feTunnelIP := make(net.IP, 16)
	copy(feTunnelIP, prefixNet.IP.To16())
	feTunnelIP[15] = 1

	keepalive := 25 * time.Second
	peer := wireguard.Peer{
		PublicKey:           fePubKey,
		Endpoint:            feEndpoint,
		AllowedIPs:          []net.IPNet{{IP: feTunnelIP, Mask: net.CIDRMask(128, 128)}},
		PersistentKeepalive: &keepalive,
	}
	if err := dev.AddPeer(peer); err != nil {
		klog.Errorf("Failed to add frontend WireGuard peer for session %s: %v; continuing with TCP pool only", sessionID, err)
		_ = dev.Close()
		return nil
	}

	tunnelAddr := net.JoinHostPort(resp.PeerAddress, strconv.Itoa(WireGuardTunnelPort))
	lis, err := m.listenFunc("tcp", tunnelAddr)
	if err != nil {
		klog.Errorf("Failed to listen on WireGuard address %s for session %s: %v; continuing with TCP pool only", tunnelAddr, sessionID, err)
		_ = dev.Close()
		return nil
	}

	klog.Infof("Listening on WireGuard tunnel address %s for session %s", tunnelAddr, sessionID)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if err := m.handleTunnelConn(c); err != nil && ctx.Err() == nil {
					klog.V(2).Infof("Error handling tunnel connection: %v", err)
				}
			}(conn)
		}
	}()

	var closeOnce sync.Once
	return func() {
		closeOnce.Do(func() {
			closeConn(lis)
			if err := dev.Close(); err != nil {
				klog.V(2).Infof("Error closing WireGuard device for session %s: %v", sessionID, err)
			}
		})
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
