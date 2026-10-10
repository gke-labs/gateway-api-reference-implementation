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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/quic-go/quic-go"
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

// WithTransport sets the transport mode (auto, quic, tcp).
func WithTransport(mode string) ManagerOption {
	return func(m *Manager) {
		switch mode {
		case TransportModeAuto, TransportModeQUIC, TransportModeTCP:
			m.transportMode = mode
		default:
			m.transportMode = TransportModeAuto
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

// Run starts the session, transport, and registration loops, maintaining connectivity to the frontend
// and feeding connections into the tunnel Listener until ctx is canceled.
func (m *Manager) Run(ctx context.Context) error {
	defer m.listener.Close()

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
					reqBytes, err := json.Marshal(api.RegistrationRequest{Hostnames: curr})
					if err != nil {
						m.regWorkerMu.Unlock()
						klog.Errorf("Failed to marshal registration request: %v", err)
						continue
					}

					_ = ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout))
					if _, err := ctrlStream.Write(append(reqBytes, '\n')); err != nil {
						m.regWorkerMu.Unlock()
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							klog.Errorf("Failed to write registration to QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
							if activeQConn != nil {
								_ = activeQConn.CloseWithError(1, "control stream write error")
							}
						}
						continue
					}

					_ = ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout))
					respLine, err := api.ReadControlLine(ctrlReader)
					if err != nil {
						m.regWorkerMu.Unlock()
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							klog.Errorf("Failed to read registration response from QUIC control stream (session %s): %v. Tearing down session.", sessID, err)
							if activeQConn != nil {
								_ = activeQConn.CloseWithError(1, "control stream read error")
							}
						}
						continue
					}
					_ = ctrlStream.SetDeadline(time.Time{})
					m.regWorkerMu.Unlock()

					var regResp api.RegistrationResponse
					if err := json.Unmarshal(bytes.TrimSpace(respLine), &regResp); err != nil {
						klog.Errorf("Failed to decode registration response from QUIC control stream: %v. Tearing down session.", err)
						if activeQConn != nil {
							_ = activeQConn.CloseWithError(1, "control stream decode error")
						}
						continue
					}

					if strings.HasPrefix(regResp.Status, "error:") || regResp.Status == "error" {
						klog.Errorf("Registration error from frontend over QUIC (session %s): %s. Tearing down session.", sessID, regResp.Status)
						if activeQConn != nil {
							_ = activeQConn.CloseWithError(1, regResp.Status)
						}
						continue
					}

					klog.Infof("Successfully registered hostnames over QUIC with frontend: %v (session: %s)", regResp.Hostnames, sessID)
					lastRegistered = curr
					lastGen = gen
					lastSession = sessID
					hasRegistered = true
				} else if !isQUIC {
					regCtx, cancel := context.WithTimeout(ctx, m.registerTimeout)
					resp, err := m.client.Register(regCtx, sessID, curr)
					cancel()

					if err != nil {
						if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
							klog.Errorf("Failed to register hostnames %v with frontend (session %s): %v", curr, sessID, err)
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

	klog.Infof("Established TCP pool session %s with frontend", sessID)
	m.triggerRegistration()

	m.runPool(sessCtx, sessID, sessErrCh)
	sessCancel()

	m.mu.Lock()
	m.connected = false
	m.sessionID = ""
	m.mu.Unlock()

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
					_ = qConn.CloseWithError(1, err.Error())
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

	_ = probeGroup.Wait()

	m.mu.Lock()
	if probeSession == nil {
		m.connected = false
		m.sessionID = ""
	}
	m.mu.Unlock()

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
	conn       *quic.Conn
	sessionID  string
	ctrlStream *quic.Stream
	ctrlReader *bufio.Reader
}

func (m *Manager) handshakeQUICSession(ctx context.Context, qConn *quic.Conn) (*quicSession, error) {
	// 1. Open control stream and send initial handshake line
	ctrlStream, err := qConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening QUIC control stream: %w", err)
	}

	_ = ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout))
	if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("initiating QUIC control stream: %w", err)
	}

	// 2. Read SessionResponse from ctrlStream (capped by MaxControlLineBytes)
	reader := bufio.NewReader(ctrlStream)
	_ = ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout))
	line, err := api.ReadControlLine(reader)
	if err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("reading session response from QUIC control stream: %w", err)
	}

	var sessResp api.SessionResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("decoding session response from QUIC control stream: %w", err)
	}
	if sessResp.SessionID == "" {
		_ = ctrlStream.Close()
		return nil, errors.New("received empty session ID from frontend QUIC session")
	}

	// 3. First registration over QUIC control stream
	m.mu.Lock()
	currHostnames := slices.Clone(m.hostnames)
	m.mu.Unlock()

	reqBytes, err := json.Marshal(api.RegistrationRequest{Hostnames: currHostnames})
	if err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("marshaling initial registration request: %w", err)
	}

	_ = ctrlStream.SetWriteDeadline(time.Now().Add(m.registerTimeout))
	if _, err := ctrlStream.Write(append(reqBytes, '\n')); err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("writing initial registration request to QUIC control stream: %w", err)
	}

	_ = ctrlStream.SetReadDeadline(time.Now().Add(m.registerTimeout))
	respLine, err := api.ReadControlLine(reader)
	if err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("reading initial registration response from QUIC control stream: %w", err)
	}
	_ = ctrlStream.SetDeadline(time.Time{})

	var regResp api.RegistrationResponse
	if err := json.Unmarshal(bytes.TrimSpace(respLine), &regResp); err != nil {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("decoding initial registration response from QUIC control stream: %w", err)
	}
	if strings.HasPrefix(regResp.Status, "error:") || regResp.Status == "error" {
		_ = ctrlStream.Close()
		return nil, fmt.Errorf("initial registration failed over QUIC control stream: %s", regResp.Status)
	}

	return &quicSession{
		conn:       qConn,
		sessionID:  sessResp.SessionID,
		ctrlStream: ctrlStream,
		ctrlReader: reader,
	}, nil
}

func (m *Manager) serveQUICSession(ctx context.Context, sess *quicSession) error {
	defer sess.conn.CloseWithError(0, "session closed")
	defer sess.ctrlStream.Close()

	m.mu.Lock()
	m.connected = true
	m.isQUIC = true
	m.sessionID = sess.sessionID
	m.ctrlStream = sess.ctrlStream
	m.ctrlReader = sess.ctrlReader
	m.activeQConn = sess.conn
	m.generation++
	m.mu.Unlock()

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
	}()

	// Accept incoming tunnel streams from frontend
	for {
		stream, err := sess.conn.AcceptStream(ctx)
		if err != nil {
			return err
		}

		go func(s *quic.Stream) {
			streamConn := api.NewQUICStreamConn(s, sess.conn)
			bufReader := bufio.NewReader(streamConn)
			hdr, err := proxyproto.Decode(bufReader)
			if err != nil {
				_ = streamConn.Close()
				return
			}

			var remaining []byte
			if bufReader.Buffered() > 0 {
				remaining = make([]byte, bufReader.Buffered())
				_, _ = io.ReadFull(bufReader, remaining)
			}

			proxyConn := proxyproto.NewConn(streamConn, hdr.SrcAddr, hdr.DstAddr, remaining)
			if err := m.listener.Enqueue(proxyConn); err != nil {
				_ = streamConn.Close()
			}
		}(stream)
	}
}

func (m *Manager) runQUICSession(ctx context.Context, qConn *quic.Conn) error {
	sess, err := m.handshakeQUICSession(ctx, qConn)
	if err != nil {
		_ = qConn.CloseWithError(1, err.Error())
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
			bufReader := bufio.NewReader(conn)
			hdr, err := proxyproto.Decode(bufReader)

			// Decrement idle count immediately upon read (either activated or closed)
			activeIdleMu.Lock()
			activeIdle--
			activeIdleMu.Unlock()

			if err != nil {
				_ = conn.Close()
				if ctx.Err() == nil {
					triggerRefill()
				}
				return
			}

			// Connection is activated! Trigger pool refill immediately
			triggerRefill()

			var remaining []byte
			if bufReader.Buffered() > 0 {
				remaining = make([]byte, bufReader.Buffered())
				_, _ = io.ReadFull(bufReader, remaining)
			}

			proxyConn := proxyproto.NewConn(conn, hdr.SrcAddr, hdr.DstAddr, remaining)
			if err := m.listener.Enqueue(proxyConn); err != nil {
				_ = conn.Close()
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
