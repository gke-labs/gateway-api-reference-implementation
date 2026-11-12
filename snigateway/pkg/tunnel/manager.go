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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultPoolSize is the default number of idle pooled reverse tunnel connections.
	DefaultPoolSize = 4

	// TransportModeAuto attempts QUIC first and falls back to TCP pool.
	TransportModeAuto = "auto"
	// TransportModeQUIC only uses QUIC tunnel transport.
	TransportModeQUIC = "quic"
	// TransportModeTCP only uses TCP pool tunnel transport.
	TransportModeTCP = "tcp"
	// TransportModeH2 only uses HTTP/2 CONNECT multiplexed tunnel transport.
	TransportModeH2 = "h2"
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

// WithTransport sets the transport mode (auto, quic, tcp, h2).
func WithTransport(mode string) ManagerOption {
	return func(m *Manager) {
		switch mode {
		case TransportModeAuto, TransportModeQUIC, TransportModeTCP, TransportModeH2:
			m.transportMode = mode
		default:
			m.transportMode = TransportModeAuto
		}
	}
}

// WithH2PingInterval sets the interval for sending HTTP/2 PINGs on idle connections.
func WithH2PingInterval(d time.Duration) ManagerOption {
	return func(m *Manager) {
		if d > 0 {
			m.h2PingInterval = d
		}
	}
}

// WithH2DrainTimeout sets the timeout for draining in-flight streams on GOAWAY.
func WithH2DrainTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) {
		if d > 0 {
			m.h2DrainTimeout = d
		}
	}
}

// WithQUICDialTimeout sets the timeout for dialing QUIC connections.
func WithQUICDialTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) {
		if d > 0 {
			m.quicDialTimeout = d
		}
	}
}

// WithQUICProbeInterval sets the interval for probing QUIC availability when in TCP fallback.
func WithQUICProbeInterval(d time.Duration) ManagerOption {
	return func(m *Manager) {
		if d > 0 {
			m.quicProbeInterval = d
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

// Manager manages communication with the snigateway frontend, maintaining a QUIC tunnel
// or a warm pool of pre-dialed reverse tunnel connections and announcing SNI hostnames.
type Manager struct {
	client            *client.Client
	listener          *Listener
	transportMode     string
	poolSize          int
	dialTimeout       time.Duration
	quicDialTimeout   time.Duration
	quicProbeInterval time.Duration
	registerTimeout   time.Duration
	h2PingInterval    time.Duration
	h2DrainTimeout    time.Duration
	backoffMin        time.Duration
	backoffMax        time.Duration

	mu          sync.Mutex
	hostnames   []string
	sessionID   string
	connected   bool
	isQUIC      bool
	ctrlStream  *quic.Stream
	ctrlReader  *bufio.Reader
	activeQConn *quic.Conn
	generation  uint64
	updateCh    chan struct{}
	regWorkerMu sync.Mutex

	registeredHostnames     []string
	lastRegisteredSessionID string
	stateChangeListeners    []func()
	reRegTimer              *time.Timer
}

// NewManager creates a new Manager using the given client.
func NewManager(c *client.Client, opts ...ManagerOption) *Manager {
	m := &Manager{
		client:            c,
		listener:          NewListener(),
		transportMode:     TransportModeAuto,
		poolSize:          DefaultPoolSize,
		dialTimeout:       10 * time.Second,
		quicDialTimeout:   3 * time.Second,
		quicProbeInterval: 30 * time.Second,
		registerTimeout:   5 * time.Second,
		h2PingInterval:    api.DefaultH2PingInterval,
		h2DrainTimeout:    api.DefaultH2DrainTimeout,
		backoffMin:        200 * time.Millisecond,
		backoffMax:        5 * time.Second,
		updateCh:          make(chan struct{}, 1),
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

// IsQUIC returns whether the currently active tunnel session is using QUIC transport.
func (m *Manager) IsQUIC() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected && m.isQUIC
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

	// Background registration worker for both QUIC and TCP sessions
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
				isQUIC := m.isQUIC
				sessID := m.sessionID
				gen := m.generation
				curr := slices.Clone(m.hostnames)
				ctrlStream := m.ctrlStream
				ctrlReader := m.ctrlReader
				activeQConn := m.activeQConn
				m.mu.Unlock()

				if !connected || sessID == "" {
					continue
				}

				if hasRegistered && lastGen == gen && lastSession == sessID && slices.Equal(lastRegistered, curr) {
					continue
				}

				if isQUIC && ctrlStream != nil && ctrlReader != nil {
					m.regWorkerMu.Lock()
					token, err := m.client.GetToken()
					if err != nil {
						klog.V(2).Infof("Reading token for QUIC registration: %v", err)
					}
					reqBytes, err := json.Marshal(api.RegistrationRequest{
						Hostnames: curr,
						Token:     token,
					})
					if err != nil {
						m.regWorkerMu.Unlock()
						klog.Errorf("Failed to marshal registration request: %v", err)
						continue
					}

					if err := ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout)); err != nil {
						m.regWorkerMu.Unlock()
						klog.Errorf("Failed to set write deadline on QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
						if activeQConn != nil {
							closeQUICConn(activeQConn, 1, "control stream write deadline error")
						}
						continue
					}
					if _, err := ctrlStream.Write(append(reqBytes, '\n')); err != nil {
						m.regWorkerMu.Unlock()
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							klog.Errorf("Failed to write registration to QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
							if activeQConn != nil {
								closeQUICConn(activeQConn, 1, "control stream write error")
							}
						}
						continue
					}

					if err := ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout)); err != nil {
						m.regWorkerMu.Unlock()
						klog.Errorf("Failed to set read deadline on QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
						if activeQConn != nil {
							closeQUICConn(activeQConn, 1, "control stream read deadline error")
						}
						continue
					}
					respLine, err := api.ReadControlLine(ctrlReader)
					if err != nil {
						m.regWorkerMu.Unlock()
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							klog.Errorf("Failed to read registration response from QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
							if activeQConn != nil {
								closeQUICConn(activeQConn, 1, "control stream read error")
							}
						}
						continue
					}
					if err := ctrlStream.SetDeadline(time.Time{}); err != nil {
						m.regWorkerMu.Unlock()
						klog.Errorf("Failed to clear deadline on QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
						if activeQConn != nil {
							closeQUICConn(activeQConn, 1, "control stream deadline error")
						}
						continue
					}
					m.regWorkerMu.Unlock()

					var regResp api.RegistrationResponse
					if err := json.Unmarshal(bytes.TrimSpace(respLine), &regResp); err != nil {
						klog.Errorf("Failed to decode registration response from QUIC control stream: %v. Tearing down session.", err)
						if activeQConn != nil {
							closeQUICConn(activeQConn, 1, "control stream decode error")
						}
						continue
					}

					if strings.HasPrefix(regResp.Status, "error:") || regResp.Status == "error" {
						klog.Errorf("Registration error from frontend over QUIC (session %s): %s. Tearing down session.", sessID, regResp.Status)
						if activeQConn != nil {
							closeQUICConn(activeQConn, 1, regResp.Status)
						}
						m.notifyListeners()
						continue
					}

					klog.Infof("Successfully registered hostnames over QUIC with frontend: %v (session: %s)", regResp.Hostnames, sessID)
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
				} else if !isQUIC {
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
		}
	})

	// Main session loop managing QUIC, TCP pool, or auto-fallback
	g.Go(func() error {
		backoff := m.backoffMin

		for {
			if ctx.Err() != nil {
				return nil
			}

			switch m.transportMode {
			case TransportModeQUIC:
				sessCtx, sessCancel := context.WithCancel(ctx)
				dialCtx, dialCancel := context.WithTimeout(sessCtx, m.dialTimeout)
				qConn, err := m.client.DialQUIC(dialCtx)
				dialCancel()

				if err != nil {
					sessCancel()
					if ctx.Err() != nil {
						return nil
					}
					klog.Warningf("Failed to dial QUIC to frontend: %v. Reconnecting in %v...", err, backoff)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(backoff):
					}
					backoff = min(backoff*2, m.backoffMax)
					continue
				}

				backoff = m.backoffMin
				err = m.runQUICSession(sessCtx, qConn)
				sessCancel()

				if ctx.Err() != nil {
					return nil
				}
				klog.Warningf("QUIC session ended (%v). Reconnecting in %v...", err, backoff)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(backoff):
				}

			case TransportModeTCP:
				m.runTCPSessionWithBackoff(ctx, &backoff)

			case TransportModeH2:
				m.runH2SessionWithBackoff(ctx, &backoff)

			case TransportModeAuto:
				// Try QUIC first
				dialCtx, dialCancel := context.WithTimeout(ctx, m.quicDialTimeout)
				qConn, err := m.client.DialQUIC(dialCtx)
				dialCancel()

				if err == nil {
					// QUIC connected!
					backoff = m.backoffMin
					sessCtx, sessCancel := context.WithCancel(ctx)
					err = m.runQUICSession(sessCtx, qConn)
					sessCancel()

					if ctx.Err() != nil {
						return nil
					}
					klog.Warningf("QUIC session ended (%v). Reconnecting in %v...", err, backoff)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(backoff):
					}
					continue
				}

				// QUIC failed; fall back to TCP pool with background QUIC probe (make-before-break)
				klog.Warningf("QUIC dial failed (%v); falling back to TCP pool transport", err)
				m.runTCPFallbackWithQUICProbe(ctx, &backoff)
			}
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
	m.isQUIC = false
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

func (m *Manager) runTCPFallbackWithQUICProbe(ctx context.Context, backoff *time.Duration) {
	tcpCtx, tcpCancel := context.WithCancel(ctx)
	defer tcpCancel()

	sessID, sessErrCh, err := m.client.StartSession(tcpCtx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		klog.Warningf("Failed to start TCP fallback session: %v. Reconnecting in %v...", err, *backoff)
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
	m.isQUIC = false
	m.sessionID = sessID
	m.generation++
	m.mu.Unlock()
	m.notifyListeners()

	klog.Infof("Established TCP fallback session %s with frontend", sessID)
	m.triggerRegistration()

	// Make-before-break probe worker
	var probeSession *quicSession
	probeGroup, probeCtx := errgroup.WithContext(tcpCtx)

	probeGroup.Go(func() error {
		ticker := time.NewTicker(m.quicProbeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-probeCtx.Done():
				return nil
			case <-ticker.C:
				pCtx, pCancel := context.WithTimeout(probeCtx, m.quicDialTimeout)
				qConn, err := m.client.DialQUIC(pCtx)
				pCancel()

				if err != nil {
					klog.V(2).Infof("QUIC probe dial failed: %v", err)
					continue
				}

				// Make-before-break: establish and register QUIC session BEFORE retiring TCP session
				sess, err := m.handshakeQUICSession(probeCtx, qConn)
				if err != nil {
					klog.V(2).Infof("QUIC probe handshake failed: %v", err)
					closeQUICConn(qConn, 1, err.Error())
					continue
				}

				// QUIC session is fully established and registered! Now switch over
				klog.Infof("QUIC probe succeeded; established and registered QUIC session %s. Switching from TCP pool to QUIC transport.", sess.sessionID)
				probeSession = sess
				tcpCancel() // Retires TCP session
				return nil
			}
		}
	})

	probeGroup.Go(func() error {
		m.runPool(tcpCtx, sessID, sessErrCh)
		tcpCancel()
		return nil
	})

	if err := probeGroup.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		klog.V(2).Infof("TCP fallback probe group ended: %v", err)
	}

	m.mu.Lock()
	if probeSession == nil {
		m.connected = false
		m.sessionID = ""
	}
	m.mu.Unlock()
	if probeSession == nil {
		m.notifyListeners()
	}

	klog.Infof("TCP fallback session %s retired", sessID)

	if probeSession != nil {
		// Hand over directly to serveQUICSession using the connected QUIC session
		sessCtx, sessCancel := context.WithCancel(ctx)
		defer sessCancel()
		err := m.serveQUICSession(sessCtx, probeSession)
		if err != nil && ctx.Err() == nil {
			klog.Warningf("QUIC session ended (%v). Reconnecting in %v...", err, *backoff)
		}
	}
}

type quicSession struct {
	conn                *quic.Conn
	sessionID           string
	ctrlStream          *quic.Stream
	ctrlReader          *bufio.Reader
	registeredHostnames []string
}

func (m *Manager) handshakeQUICSession(ctx context.Context, qConn *quic.Conn) (*quicSession, error) {
	// 1. Open control stream and send initial handshake line
	ctrlStream, err := qConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening QUIC control stream: %w", err)
	}

	if err := ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout)); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("setting write deadline on QUIC control stream: %w", err)
	}

	token, err := m.client.GetToken()
	if err != nil {
		klog.V(2).Infof("Reading token for QUIC session handshake: %v", err)
	}
	initReq := api.SessionInitRequest{
		Type:  "session",
		Token: token,
	}
	initBytes, err := json.Marshal(initReq)
	if err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("marshaling QUIC session init: %w", err)
	}
	if _, err := ctrlStream.Write(append(initBytes, '\n')); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("initiating QUIC control stream: %w", err)
	}

	// 2. Read SessionResponse from ctrlStream (capped by MaxControlLineBytes)
	reader := bufio.NewReader(ctrlStream)
	if err := ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout)); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("setting read deadline on QUIC control stream: %w", err)
	}
	line, err := api.ReadControlLine(reader)
	if err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("reading session response from QUIC control stream: %w", err)
	}

	var sessResp api.SessionResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("decoding session response from QUIC control stream: %w", err)
	}
	if sessResp.SessionID == "" {
		closeConn(ctrlStream)
		return nil, errors.New("received empty session ID from frontend QUIC session")
	}

	// 3. First registration over QUIC control stream
	m.mu.Lock()
	currHostnames := slices.Clone(m.hostnames)
	m.mu.Unlock()

	reqBytes, err := json.Marshal(api.RegistrationRequest{Hostnames: currHostnames})
	if err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("marshaling initial registration request: %w", err)
	}

	if err := ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout)); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("setting write deadline for initial registration request: %w", err)
	}
	if _, err := ctrlStream.Write(append(reqBytes, '\n')); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("writing initial registration request to QUIC control stream: %w", err)
	}

	if err := ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout)); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("setting read deadline for initial registration response: %w", err)
	}
	respLine, err := api.ReadControlLine(reader)
	if err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("reading initial registration response from QUIC control stream: %w", err)
	}
	if err := ctrlStream.SetDeadline(time.Time{}); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("clearing deadline on QUIC control stream: %w", err)
	}

	var regResp api.RegistrationResponse
	if err := json.Unmarshal(bytes.TrimSpace(respLine), &regResp); err != nil {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("decoding initial registration response from QUIC control stream: %w", err)
	}
	if strings.HasPrefix(regResp.Status, "error:") || regResp.Status == "error" {
		closeConn(ctrlStream)
		return nil, fmt.Errorf("initial registration failed over QUIC control stream: %s", regResp.Status)
	}

	return &quicSession{
		conn:                qConn,
		sessionID:           sessResp.SessionID,
		ctrlStream:          ctrlStream,
		ctrlReader:          reader,
		registeredHostnames: currHostnames,
	}, nil
}

func (m *Manager) serveQUICSession(ctx context.Context, sess *quicSession) error {
	defer closeQUICConn(sess.conn, 0, "session closed")
	defer closeConn(sess.ctrlStream)

	m.mu.Lock()
	m.connected = true
	m.isQUIC = true
	m.sessionID = sess.sessionID
	m.ctrlStream = sess.ctrlStream
	m.ctrlReader = sess.ctrlReader
	m.activeQConn = sess.conn
	m.generation++
	m.registeredHostnames = slices.Clone(sess.registeredHostnames)
	m.lastRegisteredSessionID = sess.sessionID
	m.mu.Unlock()
	m.notifyListeners()

	klog.Infof("Established QUIC session %s with frontend", sess.sessionID)
	m.triggerRegistration()

	defer func() {
		m.mu.Lock()
		m.connected = false
		m.isQUIC = false
		m.sessionID = ""
		m.ctrlStream = nil
		m.ctrlReader = nil
		if m.activeQConn == sess.conn {
			m.activeQConn = nil
		}
		m.mu.Unlock()
		m.notifyListeners()
	}()

	// Accept incoming tunnel streams from frontend
	for {
		stream, err := sess.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		go func(s *quic.Stream) {
			streamConn := api.NewQUICStreamConn(s, sess.conn)
			if err := m.handleTunnelConn(streamConn); err != nil {
				klog.V(2).Infof("QUIC stream tunnel error: %v", err)
			}
		}(stream)
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

func (m *Manager) runQUICSession(ctx context.Context, qConn *quic.Conn) error {
	sess, err := m.handshakeQUICSession(ctx, qConn)
	if err != nil {
		closeQUICConn(qConn, 1, err.Error())
		return err
	}
	return m.serveQUICSession(ctx, sess)
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

func (m *Manager) runH2SessionWithBackoff(ctx context.Context, backoff *time.Duration) {
	// The session context outlives ctx so that when ctx is cancelled (e.g. on
	// manager shutdown), the frontend session control stream stays alive while
	// runH2Pool drains in-flight streams with GOAWAY. sessCancel is called when
	// runH2Pool returns.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	defer sessCancel()

	sessID, sessErrCh, err := m.client.StartSession(sessCtx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		klog.Warningf("Failed to start H2 session with frontend: %v. Reconnecting in %v...", err, *backoff)
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
	m.isQUIC = false
	m.sessionID = sessID
	m.generation++
	m.mu.Unlock()
	m.notifyListeners()

	klog.Infof("Established H2 session %s with frontend", sessID)
	m.triggerRegistration()

	m.runH2Pool(ctx, sessID, sessErrCh)
	sessCancel()

	m.mu.Lock()
	m.connected = false
	m.sessionID = ""
	m.mu.Unlock()
	m.notifyListeners()

	if ctx.Err() != nil {
		return
	}

	klog.Warningf("H2 session %s ended. Reconnecting in %v...", sessID, *backoff)
	select {
	case <-ctx.Done():
		return
	case <-time.After(*backoff):
	}
}

func (m *Manager) runH2Pool(ctx context.Context, sessionID string, sessErrCh <-chan error) {
	poolCtx, poolCancel := context.WithCancel(ctx)
	defer poolCancel()

	refillCh := make(chan struct{}, m.poolSize*2)
	activeConnsMu := sync.Mutex{}
	activeConns := 0

	var connsWg sync.WaitGroup
	var pooledConnsMu sync.Mutex
	pooledConns := make(map[net.Conn]struct{})

	h2Server := api.DefaultH2Server()
	if m.h2PingInterval > 0 {
		h2Server.ReadIdleTimeout = m.h2PingInterval
	}
	hs := &http.Server{}
	if err := http2.ConfigureServer(hs, h2Server); err != nil {
		klog.Errorf("Failed to configure HTTP/2 server: %v", err)
	}

	triggerRefill := func() {
		select {
		case refillCh <- struct{}{}:
		default:
		}
	}

	dialOne := func() {
		activeConnsMu.Lock()
		if poolCtx.Err() != nil || activeConns >= m.poolSize {
			activeConnsMu.Unlock()
			return
		}
		activeConns++
		activeConnsMu.Unlock()

		go func() {
			dialCtx, cancel := context.WithTimeout(poolCtx, m.dialTimeout)
			conn, err := m.client.DialH2Tunnel(dialCtx, sessionID)
			cancel()

			if err != nil {
				activeConnsMu.Lock()
				activeConns--
				activeConnsMu.Unlock()

				if poolCtx.Err() == nil {
					klog.Errorf("Failed to dial H2 tunnel connection for session %s: %v", sessionID, err)
					time.Sleep(200 * time.Millisecond)
					triggerRefill()
				}
				return
			}

			if poolCtx.Err() != nil {
				closeConn(conn)
				activeConnsMu.Lock()
				activeConns--
				activeConnsMu.Unlock()
				return
			}

			connsWg.Add(1)
			defer connsWg.Done()

			pooledConnsMu.Lock()
			pooledConns[conn] = struct{}{}
			pooledConnsMu.Unlock()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}

				w.WriteHeader(http.StatusOK)
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}

				reqCtx, cancelReq := context.WithCancel(r.Context())
				streamConn := newServerStreamConn(w, r.Body, cancelReq, conn)
				defer func() {
					closeConn(streamConn)
					// Ensure all in-flight Writes have finished before handler returns!
					streamConn.inFlight.Wait()
				}()

				go func() {
					select {
					case <-reqCtx.Done():
						closeConn(streamConn)
					case <-streamConn.Done():
					}
				}()

				go func() {
					if err := m.handleTunnelConn(streamConn); err != nil {
						closeConn(streamConn)
					}
				}()

				streamConn.RunDrainLoop()
			})

			h2Server.ServeConn(conn, &http2.ServeConnOpts{
				Handler: handler,
			})
			closeConn(conn)

			pooledConnsMu.Lock()
			delete(pooledConns, conn)
			pooledConnsMu.Unlock()

			activeConnsMu.Lock()
			activeConns--
			activeConnsMu.Unlock()

			if poolCtx.Err() == nil {
				triggerRefill()
			}
		}()
	}

	// Initial fill of the pool
	for i := 0; i < m.poolSize; i++ {
		dialOne()
	}

	drain := func() {
		poolCancel()

		drainCtx, drainCancel := context.WithTimeout(context.Background(), m.h2DrainTimeout)
		defer drainCancel()

		if err := hs.Shutdown(drainCtx); err != nil {
			klog.V(2).Infof("H2 server shutdown error: %v", err)
		}

		drainDone := make(chan struct{})
		go func() {
			connsWg.Wait()
			close(drainDone)
		}()

		select {
		case <-drainDone:
		case <-drainCtx.Done():
			pooledConnsMu.Lock()
			for c := range pooledConns {
				closeConn(c)
			}
			pooledConnsMu.Unlock()
			<-drainDone
		}
	}

	for {
		select {
		case <-ctx.Done():
			drain()
			return
		case err := <-sessErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				klog.Warningf("Session error from frontend: %v", err)
			}
			drain()
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

var h2CopyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// ServerStreamConn implements net.Conn over an HTTP/2 CONNECT server stream.
type ServerStreamConn struct {
	w          http.ResponseWriter
	flusher    http.Flusher
	r          io.ReadCloser
	cancelCtx  context.CancelFunc
	underlying net.Conn
	doneCh     chan struct{}
	closeOnce  sync.Once
	queue      *api.H2ChunkQueue
	drainBuf   []byte

	mu            sync.Mutex
	closed        bool
	inFlight      sync.WaitGroup
	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
	writeTimer    *time.Timer
}

type serverStreamConn = ServerStreamConn

// NewServerStreamConn creates a new ServerStreamConn.
func NewServerStreamConn(w http.ResponseWriter, r io.ReadCloser, cancelCtx context.CancelFunc, underlying net.Conn) *ServerStreamConn {
	flusher, _ := w.(http.Flusher)
	return &ServerStreamConn{
		w:          w,
		flusher:    flusher,
		r:          r,
		cancelCtx:  cancelCtx,
		underlying: underlying,
		doneCh:     make(chan struct{}),
		queue:      api.NewH2ChunkQueue(api.DefaultH2StreamQueueBound),
	}
}

func newServerStreamConn(w http.ResponseWriter, r io.ReadCloser, cancelCtx context.CancelFunc, underlying net.Conn) *ServerStreamConn {
	return NewServerStreamConn(w, r, cancelCtx, underlying)
}

func (s *serverStreamConn) Done() <-chan struct{} {
	return s.doneCh
}

// RunDrainLoop drains queued writes into w until the stream or queue is closed.
// It is intended to run directly inside the HTTP/2 stream's handler goroutine.
func (s *serverStreamConn) RunDrainLoop() {
	for {
		n, err := s.queue.TakeAll(&s.drainBuf)
		if n > 0 {
			s.inFlight.Add(1)
			_, werr := s.w.Write(s.drainBuf)
			if s.flusher != nil && n < 4096 {
				s.flusher.Flush()
			}
			s.inFlight.Done()
			if werr != nil {
				closeConn(s)
				return
			}
		}
		if err != nil {
			closeConn(s)
			return
		}
	}
}

func (s *serverStreamConn) WriteTo(w io.Writer) (int64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	s.mu.Unlock()

	var first [4096]byte
	nr, rerr := s.Read(first[:])
	var written int64
	if nr > 0 {
		nw, werr := w.Write(first[:nr])
		if nw > 0 {
			written += int64(nw)
		}
		if werr != nil {
			return written, werr
		}
		if nr != nw {
			return written, io.ErrShortWrite
		}
	}
	if rerr != nil {
		if rerr == io.EOF {
			rerr = nil
		}
		return written, rerr
	}

	bufPtr := h2CopyBufPool.Get().(*[]byte)
	defer h2CopyBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		nr, rerr := s.Read(buf)
		if nr > 0 {
			nw, werr := w.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (s *serverStreamConn) ReadFrom(r io.Reader) (int64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	s.mu.Unlock()

	var first [4096]byte
	nr, rerr := r.Read(first[:])
	var written int64
	if nr > 0 {
		nw, werr := s.Write(first[:nr])
		if nw > 0 {
			written += int64(nw)
		}
		if werr != nil {
			return written, werr
		}
		if nr != nw {
			return written, io.ErrShortWrite
		}
	}
	if rerr != nil {
		if rerr == io.EOF {
			rerr = nil
		}
		return written, rerr
	}

	bufPtr := h2CopyBufPool.Get().(*[]byte)
	defer h2CopyBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		nr, rerr := r.Read(buf)
		if nr > 0 {
			nw, werr := s.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (s *serverStreamConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
		s.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	s.mu.Unlock()

	return s.r.Read(b)
}

func (s *serverStreamConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
		s.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	s.mu.Unlock()

	return s.queue.Write(b)
}

func (s *serverStreamConn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	if !t.IsZero() && time.Until(t) > 0 {
		s.readTimer = time.AfterFunc(time.Until(t), func() {
			closeConn(s.r)
		})
	}
	return nil
}

func (s *serverStreamConn) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	s.queue.SetWriteDeadline(t)
	if s.writeTimer != nil {
		s.writeTimer.Stop()
		s.writeTimer = nil
	}
	if !t.IsZero() && time.Until(t) > 0 {
		s.writeTimer = time.AfterFunc(time.Until(t), func() {
			s.queue.Wake()
		})
	}
	return nil
}

func (s *serverStreamConn) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

func (s *serverStreamConn) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.readTimer != nil {
			s.readTimer.Stop()
		}
		if s.writeTimer != nil {
			s.writeTimer.Stop()
		}
		s.mu.Unlock()

		if s.cancelCtx != nil {
			s.cancelCtx()
		}
		closeConn(s.queue)
		closeConn(s.r)
		close(s.doneCh)
	})
	return nil
}

func (s *serverStreamConn) LocalAddr() net.Addr {
	if s.underlying != nil {
		return s.underlying.LocalAddr()
	}
	return nil
}

func (s *serverStreamConn) RemoteAddr() net.Addr {
	if s.underlying != nil {
		return s.underlying.RemoteAddr()
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

func closeQUICConn(c *quic.Conn, code quic.ApplicationErrorCode, msg string) {
	if c == nil {
		return
	}
	if err := c.CloseWithError(code, msg); err != nil && !errors.Is(err, net.ErrClosed) {
		klog.V(2).Infof("failed to close QUIC connection: %v", err)
	}
}
