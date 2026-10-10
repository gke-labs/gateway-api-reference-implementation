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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/quic-go/quic-go"
)

// ServerConfig holds configuration options for the frontend server.
type ServerConfig struct {
	ListenAddrs        []string
	UDPListenAddrs     []string
	InternalHostname   string
	ServerTLSConfig    *tls.Config
	ConnectTimeout     time.Duration
	PerAttemptTimeout  time.Duration
	ReadSNITimeout     time.Duration
	Authorizer         Authorizer
	CompositeTransport *CompositeTransport
}

// Server implements the SNI proxy frontend with mTLS API and reverse tunnels.
type Server struct {
	config     ServerConfig
	authorizer Authorizer
	table      *RegistrationTable
	transport  Transport
	pool       *PoolTransport
	quic       *QUICTransport

	internalListener *chanListener
	httpServer       *http.Server

	listenersMu   sync.Mutex
	listeners     []net.Listener
	udpListeners  []net.PacketConn
	quicListeners []*quic.Listener
	closed        bool
	shutdownCh    chan struct{}
}

// NewServer creates a new frontend Server with the given configuration.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.ListenAddrs) == 0 {
		cfg.ListenAddrs = []string{":443"}
	}
	if cfg.InternalHostname == "" {
		cfg.InternalHostname = api.DefaultInternalHostname
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.PerAttemptTimeout <= 0 {
		cfg.PerAttemptTimeout = 2 * time.Second
	}
	if cfg.ReadSNITimeout <= 0 {
		cfg.ReadSNITimeout = 5 * time.Second
	}
	if cfg.ServerTLSConfig == nil {
		return nil, errors.New("ServerTLSConfig is required")
	}

	auth := cfg.Authorizer
	if auth == nil {
		auth = &AllowAllAuthorizer{}
	}

	comp := cfg.CompositeTransport
	if comp == nil {
		comp = NewCompositeTransport(NewPoolTransport(), NewQUICTransport())
	}

	s := &Server{
		config:           cfg,
		authorizer:       auth,
		table:            NewRegistrationTable(),
		transport:        comp,
		pool:             comp.Pool(),
		quic:             comp.QUIC(),
		internalListener: newChanListener(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}),
		shutdownCh:       make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/session", s.handleSession)
	mux.HandleFunc("/v1/registration", s.handleRegistration)
	mux.HandleFunc("/v1/connections", s.handleConnectionUpgrade)
	mux.HandleFunc("/v1/connections/", s.handleConnectionUpgrade)
	mux.HandleFunc("/v1/tunnel", s.handleConnectionUpgrade)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	return s, nil
}

// RegistrationTable returns the server's registration table.
func (s *Server) RegistrationTable() *RegistrationTable {
	return s.table
}

// Transport returns the server's data-plane transport.
func (s *Server) Transport() Transport {
	return s.transport
}

// PoolTransport returns the server's TCP pool transport.
func (s *Server) PoolTransport() *PoolTransport {
	return s.pool
}

// QUICTransport returns the server's QUIC transport.
func (s *Server) QUICTransport() *QUICTransport {
	return s.quic
}

// ListenAndServe starts listening on all configured TCP and UDP addresses and serves traffic.
func (s *Server) ListenAndServe() error {
	var listeners []net.Listener
	for _, addr := range s.config.ListenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}

	var udpConns []net.PacketConn
	udpAddrs := s.config.UDPListenAddrs
	if len(udpAddrs) == 0 {
		udpAddrs = s.config.ListenAddrs
	}
	for _, addr := range udpAddrs {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			for _, p := range udpConns {
				_ = p.Close()
			}
			return fmt.Errorf("listening UDP on %s: %w", addr, err)
		}
		udpConns = append(udpConns, pc)
	}

	return s.ServeAll(listeners, udpConns)
}

// Serve serves TCP traffic on the given pre-created listeners.
func (s *Server) Serve(listeners ...net.Listener) error {
	return s.ServeAll(listeners, nil)
}

// ServeUDP serves QUIC reverse-tunnel traffic on the given pre-created UDP packet connections.
func (s *Server) ServeUDP(udpConns ...net.PacketConn) error {
	return s.ServeAll(nil, udpConns)
}

// ServeAll serves both TCP client traffic and QUIC reverse tunnel connections.
func (s *Server) ServeAll(listeners []net.Listener, udpConns []net.PacketConn) error {
	s.listenersMu.Lock()
	s.listeners = listeners
	s.udpListeners = udpConns
	s.listenersMu.Unlock()

	// Start internal mTLS HTTP server
	errCh := make(chan error, len(listeners)+len(udpConns)+1)
	go func() {
		if err := s.httpServer.Serve(s.internalListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("internal HTTP server: %w", err)
		}
	}()

	// Accept connections on each TCP listener
	for _, ln := range listeners {
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case <-s.shutdownCh:
						return
					default:
						errCh <- err
						return
					}
				}
				go s.handleConnection(conn)
			}
		}(ln)
	}

	// Start QUIC listeners on each UDP packet connection
	for _, pc := range udpConns {
		quicTLS := s.config.ServerTLSConfig.Clone()
		quicTLS.NextProtos = []string{api.TunnelALPN}
		ql, err := quic.Listen(pc, quicTLS, api.DefaultQUICConfig())
		if err != nil {
			return fmt.Errorf("creating QUIC listener on %s: %w", pc.LocalAddr(), err)
		}
		s.listenersMu.Lock()
		s.quicListeners = append(s.quicListeners, ql)
		s.listenersMu.Unlock()

		go func(l *quic.Listener) {
			for {
				qConn, err := l.Accept(context.Background())
				if err != nil {
					select {
					case <-s.shutdownCh:
						return
					default:
						if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
							return
						}
						log.Printf("Frontend: error accepting QUIC connection: %v", err)
						continue
					}
				}
				go s.handleQUICConnection(qConn)
			}
		}(ql)
	}

	select {
	case <-s.shutdownCh:
		return nil
	case err := <-errCh:
		return err
	}
}

// Close gracefully closes all listeners and stops the server.
func (s *Server) Close() error {
	s.listenersMu.Lock()
	if s.closed {
		s.listenersMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.shutdownCh)
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	for _, ql := range s.quicListeners {
		_ = ql.Close()
	}
	for _, pc := range s.udpListeners {
		_ = pc.Close()
	}
	s.listenersMu.Unlock()

	_ = s.internalListener.Close()
	_ = s.transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func setTCPKeepAlive(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(15 * time.Second)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	setTCPKeepAlive(conn)

	sniHostname, peekedConn, err := sni.SniffSNI(conn, s.config.ReadSNITimeout)
	if err != nil {
		_ = peekedConn.Close()
		return
	}

	cleanSNI := CleanHostname(sniHostname)
	cleanInternal := CleanHostname(s.config.InternalHostname)

	// 1. If internal API hostname: terminate TLS and pass to mTLS HTTP server
	if cleanSNI == cleanInternal {
		tlsConn := tls.Server(peekedConn, s.config.ServerTLSConfig)
		if err := s.internalListener.SendConn(tlsConn); err != nil {
			_ = tlsConn.Close()
		}
		return
	}

	// 2. Otherwise route to backend with failover/replay loop
	var rawClientConn net.Conn = peekedConn
	var peekedBytes []byte
	if pc, ok := peekedConn.(*sni.PeekedConn); ok {
		peekedBytes = pc.PeekedBytes()
		rawClientConn = pc.RawConn()
	}

	proxyHdr := &proxyproto.Header{
		Command:   proxyproto.CommandProxy,
		SrcAddr:   peekedConn.RemoteAddr(),
		DstAddr:   peekedConn.LocalAddr(),
		Authority: sniHostname,
	}
	proxyBytes := proxyHdr.Format()

	deadline := time.Now().Add(s.config.ConnectTimeout)
	var committedTunnel net.Conn
	var initialBackendBytes []byte

	for {
		now := time.Now()
		if now.After(deadline) {
			log.Printf("Frontend: connect timeout reached for SNI %q", sniHostname)
			_ = peekedConn.Close()
			return
		}

		remaining := time.Until(deadline)
		attemptTimeout := s.config.PerAttemptTimeout
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}

		sessions := s.table.MatchSessions(cleanSNI)
		if len(sessions) == 0 {
			log.Printf("Frontend: rejecting connection with SNI %q (clean: %q): not registered", sniHostname, cleanSNI)
			_ = peekedConn.Close()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		tunnelConn, _, err := s.transport.GetConnForSessions(ctx, sessions)
		cancel()

		if err != nil {
			// Pool/stream timeout on this attempt, continue until total deadline
			continue
		}

		setTCPKeepAlive(tunnelConn)

		// Set write deadline for PROXY header + peeked ClientHello
		_ = tunnelConn.SetWriteDeadline(time.Now().Add(attemptTimeout))
		if _, err := tunnelConn.Write(proxyBytes); err != nil {
			_ = tunnelConn.Close()
			continue
		}
		if _, err := tunnelConn.Write(peekedBytes); err != nil {
			_ = tunnelConn.Close()
			continue
		}

		// Set read deadline to wait for the first byte from the backend
		_ = tunnelConn.SetReadDeadline(time.Now().Add(attemptTimeout))
		buf := make([]byte, 4096)
		n, err := tunnelConn.Read(buf)
		if err != nil || n == 0 {
			// Failed or unresponsive backend/tunnel connection; drop and replay on next attempt
			_ = tunnelConn.Close()
			continue
		}

		// First byte received from backend! Clear deadlines and commit splice
		_ = tunnelConn.SetDeadline(time.Time{})
		committedTunnel = tunnelConn
		initialBackendBytes = buf[:n]
		break
	}

	// Write initial backend byte(s) to client
	if _, err := rawClientConn.Write(initialBackendBytes); err != nil {
		_ = committedTunnel.Close()
		_ = rawClientConn.Close()
		return
	}

	spliceConnections(rawClientConn, committedTunnel)
}

func spliceConnections(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		_ = c2.Close()
		_ = c1.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
		_ = c1.Close()
		_ = c2.Close()
	}()

	wg.Wait()
}

func extractIdentityFromTLSState(tlsState tls.ConnectionState) (ClientIdentity, error) {
	if len(tlsState.PeerCertificates) == 0 {
		return ClientIdentity{}, errors.New("client certificate required")
	}
	peerCert := tlsState.PeerCertificates[0]
	cn := peerCert.Subject.CommonName
	if cn == "" {
		cn = "unknown-client"
	}

	var rootCert *x509.Certificate
	if len(tlsState.VerifiedChains) > 0 && len(tlsState.VerifiedChains[0]) > 0 {
		chain := tlsState.VerifiedChains[0]
		rootCert = chain[len(chain)-1]
	} else {
		rootCert = peerCert
	}

	fingerprint := fmt.Sprintf("%x", sha256.Sum256(rootCert.Raw))
	id := fmt.Sprintf("%s/%s", fingerprint, cn)

	return ClientIdentity{
		ID:            id,
		CAFingerprint: fingerprint,
		CommonName:    cn,
	}, nil
}

func extractClientIdentity(r *http.Request) (ClientIdentity, error) {
	if r.TLS == nil {
		return ClientIdentity{}, errors.New("TLS connection required")
	}
	return extractIdentityFromTLSState(*r.TLS)
}

func (s *Server) handleQUICConnection(qConn *quic.Conn) {
	clientIdentity, err := extractIdentityFromTLSState(qConn.ConnectionState().TLS)
	if err != nil {
		log.Printf("Frontend: rejecting QUIC connection: %v", err)
		_ = qConn.CloseWithError(1, "unauthorized")
		return
	}

	// 1. Enforce handshake deadline for accepting control stream and reading init message
	handshakeCtx, handshakeCancel := context.WithTimeout(context.Background(), api.QUICHandshakeTimeout)
	ctrlStream, err := qConn.AcceptStream(handshakeCtx)
	if err != nil {
		handshakeCancel()
		log.Printf("Frontend: error accepting QUIC control stream (timeout or closed): %v", err)
		_ = qConn.CloseWithError(1, "control stream error")
		return
	}

	reader := bufio.NewReader(ctrlStream)
	// Read initial control stream ping/init line (bounded by MaxControlLineBytes)
	_ = ctrlStream.SetReadDeadline(time.Now().Add(api.QUICHandshakeTimeout))
	if _, err := api.ReadControlLine(reader); err != nil {
		handshakeCancel()
		log.Printf("Frontend: error reading initial line from QUIC control stream: %v", err)
		_ = qConn.CloseWithError(1, "control stream handshake failed")
		return
	}
	_ = ctrlStream.SetDeadline(time.Time{})
	handshakeCancel()

	sessionID := generateConnID()
	s.table.RegisterSession(sessionID, clientIdentity)
	s.quic.RegisterSession(sessionID, qConn)
	log.Printf("Frontend: created QUIC session %s for client %q", sessionID, clientIdentity.ID)

	defer func() {
		s.table.Unregister(sessionID)
		s.quic.UnregisterSession(sessionID)
		_ = qConn.CloseWithError(0, "session closed")
		log.Printf("Frontend: QUIC session %s closed and unregistered for client %q", sessionID, clientIdentity.ID)
	}()

	// Send initial SessionResponse
	sessResp := api.SessionResponse{
		SessionID: sessionID,
		Status:    "connected",
	}
	respBytes, err := json.Marshal(sessResp)
	if err != nil {
		return
	}
	if _, err := ctrlStream.Write(append(respBytes, '\n')); err != nil {
		return
	}

	// Read and process RegistrationRequests from control stream
	for {
		line, err := api.ReadControlLine(reader)
		if err != nil {
			return
		}
		var regReq api.RegistrationRequest
		if err := json.Unmarshal(bytes.TrimSpace(line), &regReq); err != nil {
			log.Printf("Frontend: failed to decode QUIC registration request from %s: %v", sessionID, err)
			continue
		}

		if err := s.authorizer.Authorize(context.Background(), clientIdentity, regReq.Hostnames); err != nil {
			log.Printf("Frontend: authorization failed for QUIC session %s (%s) registering %v: %v", sessionID, clientIdentity.ID, regReq.Hostnames, err)
			errResp, _ := json.Marshal(api.RegistrationResponse{
				Status: fmt.Sprintf("error: %v", err),
			})
			_, _ = ctrlStream.Write(append(errResp, '\n'))
			continue
		}

		s.table.Register(sessionID, regReq.Hostnames)
		registered := s.table.GetRegisteredHostnames(sessionID)
		log.Printf("Frontend: QUIC session %s (client %q) registered hostnames: %v", sessionID, clientIdentity.ID, registered)

		okResp, _ := json.Marshal(api.RegistrationResponse{
			Status:    "registered",
			Hostnames: registered,
		})
		if _, err := ctrlStream.Write(append(okResp, '\n')); err != nil {
			return
		}
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := extractClientIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	sessionID := generateConnID()
	s.table.RegisterSession(sessionID, clientIdentity)
	s.pool.RegisterSession(sessionID)
	log.Printf("Frontend: created session %s for client %q", sessionID, clientIdentity.ID)

	defer func() {
		s.table.Unregister(sessionID)
		s.pool.UnregisterSession(sessionID)
		log.Printf("Frontend: session %s closed and unregistered for client %q", sessionID, clientIdentity.ID)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(api.SessionResponse{
		SessionID: sessionID,
		Status:    "connected",
	})
	flusher.Flush()

	<-r.Context().Done()
}

func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := extractClientIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sessionID := r.Header.Get(api.HeaderSessionID)
	if sessionID == "" {
		sessionID = r.URL.Query().Get("sessionId")
	}
	if sessionID == "" {
		http.Error(w, "missing session ID header or query parameter", http.StatusBadRequest)
		return
	}

	sessIdentity, ok := s.table.GetSessionIdentity(sessionID)
	if !ok {
		http.Error(w, "session not found or expired", http.StatusNotFound)
		return
	}

	if sessIdentity.ID != clientIdentity.ID {
		http.Error(w, "session identity mismatch", http.StatusForbidden)
		return
	}

	var req api.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.authorizer.Authorize(r.Context(), clientIdentity, req.Hostnames); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	s.table.Register(sessionID, req.Hostnames)
	registered := s.table.GetRegisteredHostnames(sessionID)
	log.Printf("Frontend: session %s (client %q) registered hostnames: %v", sessionID, clientIdentity.ID, registered)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.RegistrationResponse{
		Status:    "registered",
		Hostnames: registered,
	})
}

func (s *Server) handleConnectionUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := extractClientIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	sessionID := r.Header.Get(api.HeaderSessionID)
	if sessionID == "" {
		sessionID = r.URL.Query().Get("sessionId")
	}
	if sessionID == "" {
		sessionID = strings.TrimPrefix(r.URL.Path, "/v1/connections/")
	}
	if sessionID == "" {
		http.Error(w, "missing session ID", http.StatusBadRequest)
		return
	}

	sessIdentity, ok := s.table.GetSessionIdentity(sessionID)
	if !ok {
		http.Error(w, "session not found or expired", http.StatusNotFound)
		return
	}

	if sessIdentity.ID != clientIdentity.ID {
		http.Error(w, "session identity mismatch", http.StatusForbidden)
		return
	}

	// Verify HTTP Upgrade header
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") && !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "upgrade header required", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	rawConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send HTTP 101 Switching Protocols
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + api.UpgradeProtocol + "\r\n\r\n"
	if _, err := rawConn.Write([]byte(resp)); err != nil {
		_ = rawConn.Close()
		return
	}

	var dialedConn net.Conn = rawConn
	if rw != nil && rw.Reader.Buffered() > 0 {
		dialedConn = &bufferedConn{
			Conn:   rawConn,
			reader: rw.Reader,
		}
	}

	if err := s.pool.AddConn(sessionID, dialedConn); err != nil {
		_ = dialedConn.Close()
		return
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// chanListener implements net.Listener over an in-memory channel.
type chanListener struct {
	addr    net.Addr
	connCh  chan net.Conn
	closeCh chan struct{}
	once    sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr:    addr,
		connCh:  make(chan net.Conn, 128),
		closeCh: make(chan struct{}),
	}
}

func (l *chanListener) SendConn(c net.Conn) error {
	select {
	case <-l.closeCh:
		return net.ErrClosed
	default:
	}

	select {
	case <-l.closeCh:
		return net.ErrClosed
	case l.connCh <- c:
		return nil
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.closeCh:
		return nil, net.ErrClosed
	case conn := <-l.connCh:
		select {
		case <-l.closeCh:
			_ = conn.Close()
			return nil, net.ErrClosed
		default:
			return conn, nil
		}
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)

		// Drain and close any queued connections after closing closeCh.
		for {
			select {
			case c := <-l.connCh:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}
