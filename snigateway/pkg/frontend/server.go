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
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"k8s.io/klog/v2"
)

const (
	// DefaultMaxRegistrationBodyBytes is the default maximum allowed size (256 KiB) for a registration request body.
	DefaultMaxRegistrationBodyBytes = 256 * 1024

	// DefaultMaxHostnamesPerSession is the default maximum number of hostnames a session may register.
	DefaultMaxHostnamesPerSession = 1000

	// DefaultLeaseReaperInterval is the default interval for checking expired registration leases.
	DefaultLeaseReaperInterval = 10 * time.Second
)

// ServerConfig holds configuration options for the frontend server.
type ServerConfig struct {
	ListenAddrs              []string
	InternalHostname         string
	ServerTLSConfig          *tls.Config
	ConnectTimeout           time.Duration
	PerAttemptTimeout        time.Duration
	ReadSNITimeout           time.Duration
	Authorizer               Authorizer
	CompositeTransport       *CompositeTransport
	MaxConnections           int
	IdleTimeout              time.Duration
	MaxHostnamesPerSession   int
	MaxRegistrationBodyBytes int64
	JWTVerifier              jwt.TokenVerifier
	LeaseReaperInterval      time.Duration
	// TimeNow overrides time.Now for deterministic testing of lease expiration.
	TimeNow func() time.Time
}

// Server implements the SNI proxy frontend with mTLS API and reverse tunnels.
type Server struct {
	config     ServerConfig
	authorizer Authorizer
	table      *RegistrationTable
	transport  Transport
	pool       *PoolTransport
	h2         *H2Transport

	internalListener *chanListener
	httpServer       *http.Server

	listenersMu sync.Mutex
	listeners   []net.Listener
	closed      bool
	shutdownCh  chan struct{}
	activeConns atomic.Int64
	jwtVerifier jwt.TokenVerifier
	sessionsMu  sync.Mutex
	sessions    map[string]*frontendSession
	timeNow     func() time.Time
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
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 10000
	} else if cfg.MaxConnections < 0 {
		cfg.MaxConnections = 0
	}
	if cfg.MaxHostnamesPerSession <= 0 {
		cfg.MaxHostnamesPerSession = DefaultMaxHostnamesPerSession
	}
	if cfg.MaxRegistrationBodyBytes <= 0 {
		cfg.MaxRegistrationBodyBytes = DefaultMaxRegistrationBodyBytes
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
		comp = NewCompositeTransport(NewPoolTransport(), nil)
	}

	timeNow := cfg.TimeNow
	if timeNow == nil {
		timeNow = time.Now
	}

	s := &Server{
		config:           cfg,
		authorizer:       auth,
		table:            NewRegistrationTable(),
		transport:        comp,
		pool:             comp.Pool(),
		h2:               comp.H2(),
		internalListener: newChanListener(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}),
		shutdownCh:       make(chan struct{}),
		jwtVerifier:      cfg.JWTVerifier,
		sessions:         make(map[string]*frontendSession),
		timeNow:          timeNow,
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

// H2Transport returns the server's HTTP/2 transport.
func (s *Server) H2Transport() *H2Transport {
	return s.h2
}

// ListenAndServe starts listening on all configured TCP addresses and serves traffic.
func (s *Server) ListenAndServe() error {
	var listeners []net.Listener
	for _, addr := range s.config.ListenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				closeCloser(l)
			}
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}

	return s.Serve(listeners...)
}

// Serve serves TCP traffic on the given pre-created listeners.
func (s *Server) Serve(listeners ...net.Listener) error {
	s.listenersMu.Lock()
	s.listeners = listeners
	s.listenersMu.Unlock()

	// Start internal mTLS HTTP server
	errCh := make(chan error, len(listeners)+1)
	go func() {
		if err := s.httpServer.Serve(s.internalListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("internal HTTP server: %w", err)
		}
	}()

	// Start background lease reaper for periodic token expiration
	go s.runLeaseReaper()

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
				if maxConns := s.config.MaxConnections; maxConns > 0 {
					if s.activeConns.Add(1) > int64(maxConns) {
						s.activeConns.Add(-1)
						closeCloser(conn)
						continue
					}
				}
				go s.handleConnection(conn)
			}
		}(ln)
	}

	select {
	case <-s.shutdownCh:
		return nil
	case err := <-errCh:
		return err
	}
}

// ServeAll serves TCP client traffic on the given listeners.
// The udpConns parameter is ignored as UDP tunnel transport has been removed.
func (s *Server) ServeAll(listeners []net.Listener, _ []net.PacketConn) error {
	return s.Serve(listeners...)
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
		closeCloser(ln)
	}
	s.listenersMu.Unlock()

	closeCloser(s.internalListener)
	closeCloser(s.transport)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) runLeaseReaper() {
	interval := s.config.LeaseReaperInterval
	if interval <= 0 {
		interval = DefaultLeaseReaperInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdownCh:
			return
		case <-ticker.C:
			expired := s.table.DropExpiredLeases(s.timeNow())
			for _, sessID := range expired {
				log.Printf("Frontend: lease expired for session %s, closing session", sessID)
				s.CloseSession(sessID)
			}
		}
	}
}

type frontendSession struct {
	cancel  context.CancelFunc // HTTP sessions only
	closers []func()
}

func (s *Server) createSession(sessionID string, cancel context.CancelFunc, closer func()) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sess := &frontendSession{
		cancel: cancel,
	}
	if closer != nil {
		sess.closers = append(sess.closers, closer)
	}
	s.sessions[sessionID] = sess
}

// CloseSession closes an active backend session and any associated connections.
func (s *Server) CloseSession(sessionID string) {
	s.sessionsMu.Lock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		s.sessionsMu.Unlock()
		return
	}
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	s.table.Unregister(sessionID)
	s.pool.UnregisterSession(sessionID)
	s.h2.UnregisterSession(sessionID)

	if sess.cancel != nil {
		sess.cancel()
	}
	for _, c := range sess.closers {
		if c != nil {
			c()
		}
	}
}

func setTCPKeepAlive(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetKeepAlive(true); err != nil {
			klog.V(2).Infof("Frontend: failed to set TCP keepalive: %v", err)
		}
		if err := tcp.SetKeepAlivePeriod(15 * time.Second); err != nil {
			klog.V(2).Infof("Frontend: failed to set TCP keepalive period: %v", err)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.activeConns.Add(-1)
	setTCPKeepAlive(conn)

	sniHostname, peekedConn, err := sni.SniffSNI(conn, s.config.ReadSNITimeout)
	if err != nil {
		closeCloser(peekedConn)
		return
	}

	cleanSNI := CleanHostname(sniHostname)
	cleanInternal := CleanHostname(s.config.InternalHostname)

	// 1. If internal API hostname: terminate TLS and pass to mTLS HTTP server
	if cleanSNI == cleanInternal {
		tlsConn := tls.Server(peekedConn, s.config.ServerTLSConfig)
		if err := s.internalListener.SendConn(tlsConn); err != nil {
			closeCloser(tlsConn)
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
	proxyBytes, err := proxyHdr.Format()
	if err != nil {
		klog.V(2).Infof("Frontend: failed to format proxy header: %v", err)
		closeCloser(peekedConn)
		return
	}

	deadline := time.Now().Add(s.config.ConnectTimeout)
	var committedTunnel net.Conn
	var initialBackendBytes []byte

	for {
		now := time.Now()
		if now.After(deadline) {
			log.Printf("Frontend: connect timeout reached for SNI %q", sniHostname)
			closeCloser(peekedConn)
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
			closeCloser(peekedConn)
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
		if err := tunnelConn.SetWriteDeadline(time.Now().Add(attemptTimeout)); err != nil {
			closeCloser(tunnelConn)
			continue
		}
		if _, err := tunnelConn.Write(proxyBytes); err != nil {
			closeCloser(tunnelConn)
			continue
		}
		if _, err := tunnelConn.Write(peekedBytes); err != nil {
			closeCloser(tunnelConn)
			continue
		}

		// Set read deadline to wait for the first byte from the backend
		if err := tunnelConn.SetReadDeadline(time.Now().Add(attemptTimeout)); err != nil {
			closeCloser(tunnelConn)
			continue
		}
		buf := make([]byte, 4096)
		n, err := tunnelConn.Read(buf)
		if err != nil || n == 0 {
			// Failed or unresponsive backend/tunnel connection; drop and replay on next attempt
			closeCloser(tunnelConn)
			continue
		}

		// First byte received from backend! Clear deadlines and commit splice
		if err := tunnelConn.SetDeadline(time.Time{}); err != nil {
			closeCloser(tunnelConn)
			continue
		}
		committedTunnel = tunnelConn
		initialBackendBytes = buf[:n]
		break
	}

	// Write initial backend byte(s) to client
	if _, err := rawClientConn.Write(initialBackendBytes); err != nil {
		closeCloser(committedTunnel)
		closeCloser(rawClientConn)
		return
	}

	spliceConnections(rawClientConn, committedTunnel, s.config.IdleTimeout)
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

var spliceBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func spliceConnections(c1, c2 net.Conn, idleTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := spliceBufPool.Get().(*[]byte)
		defer spliceBufPool.Put(bufPtr)
		err := copyWithIdleTimeout(c2, c1, *bufPtr, idleTimeout)
		if err != nil {
			if !isNormalClose(err) {
				klog.V(2).Infof("Frontend: splice error copying c1 to c2: %v", err)
			}
			closeCloser(c1)
			closeCloser(c2)
		} else {
			closeCloser(c2)
			closeCloser(c1)
		}
	}()

	go func() {
		defer wg.Done()
		bufPtr := spliceBufPool.Get().(*[]byte)
		defer spliceBufPool.Put(bufPtr)
		err := copyWithIdleTimeout(c1, c2, *bufPtr, idleTimeout)
		if err != nil {
			if !isNormalClose(err) {
				klog.V(2).Infof("Frontend: splice error copying c2 to c1: %v", err)
			}
			closeCloser(c1)
			closeCloser(c2)
		} else {
			closeCloser(c1)
			closeCloser(c2)
		}
	}()

	wg.Wait()
}

// copyWithIdleTimeout copies data from src to dst using buf while refreshing read deadlines on each copy.
// Note: enabling idle timeout gives up io.CopyBuffer's ReaderFrom fast path (kernel splice on Linux for TCP<->TCP).
func copyWithIdleTimeout(dst, src net.Conn, buf []byte, idleTimeout time.Duration) error {
	if idleTimeout <= 0 {
		_, err := io.CopyBuffer(dst, src, buf)
		return err
	}
	for {
		if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			klog.V(2).Infof("Frontend: failed to set read deadline on source connection: %v", err)
			return err
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				klog.V(2).Infof("Frontend: failed to refresh read deadline on source connection: %v", err)
				return err
			}
			if err := dst.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				klog.V(2).Infof("Frontend: failed to refresh read deadline on destination connection: %v", err)
				return err
			}
			_, werr := dst.Write(buf[:nr])
			if werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
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

func (s *Server) extractClientIdentity(r *http.Request) (ClientIdentity, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return extractIdentityFromTLSState(*r.TLS)
	}

	if s.jwtVerifier == nil {
		if r.TLS == nil {
			return ClientIdentity{}, errors.New("TLS connection required")
		}
		return ClientIdentity{}, errors.New("client certificate required")
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ClientIdentity{}, errors.New("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ClientIdentity{}, errors.New("invalid Authorization header format, expected Bearer <token>")
	}
	tokenStr := strings.TrimSpace(parts[1])
	if tokenStr == "" {
		return ClientIdentity{}, errors.New("empty bearer token")
	}

	claims, err := s.jwtVerifier.Verify(r.Context(), tokenStr)
	if err != nil {
		return ClientIdentity{}, fmt.Errorf("token verification failed: %w", err)
	}

	return ClientIdentity{
		ID:          fmt.Sprintf("jwt/%s/%s", claims.Issuer, claims.Subject),
		Issuer:      claims.Issuer,
		Subject:     claims.Subject,
		TokenExpiry: claims.Expiry,
	}, nil
}

func validateRegistrationHostnames(hostnames []string, maxHostnames int) error {
	seen := make(map[string]struct{}, len(hostnames))
	for _, rawHost := range hostnames {
		h := CleanHostname(rawHost)
		if h == "" {
			h = rawHost
		}
		if _, exists := seen[h]; exists {
			return fmt.Errorf("duplicate hostname %q in request", rawHost)
		}
		seen[h] = struct{}{}
	}
	if maxHostnames > 0 && len(hostnames) > maxHostnames {
		return fmt.Errorf("number of hostnames (%d) exceeds limit of %d", len(hostnames), maxHostnames)
	}
	return nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := s.extractClientIdentity(r)
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
	sessCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s.createSession(sessionID, cancel, nil)

	s.table.RegisterSession(sessionID, clientIdentity)
	s.pool.RegisterSession(sessionID)
	s.h2.RegisterSession(sessionID)
	log.Printf("Frontend: created session %s for client %q", sessionID, clientIdentity.ID)

	defer func() {
		s.CloseSession(sessionID)
		log.Printf("Frontend: session %s closed and unregistered for client %q", sessionID, clientIdentity.ID)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(api.SessionResponse{
		SessionID: sessionID,
		Status:    "connected",
	}); err != nil {
		klog.V(2).Infof("Frontend: failed to encode session response: %v", err)
		return
	}
	flusher.Flush()

	<-sessCtx.Done()
}

func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := s.extractClientIdentity(r)
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

	if r.ContentLength > s.config.MaxRegistrationBodyBytes {
		http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRegistrationBodyBytes)
	var req api.RegistrationRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}
	}

	if err := validateRegistrationHostnames(req.Hostnames, s.config.MaxHostnamesPerSession); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.authorizer.Authorize(r.Context(), clientIdentity, req.Hostnames); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var leaseExpiry time.Time
	if clientIdentity.Issuer != "" {
		leaseExpiry = clientIdentity.TokenExpiry
		maxLease := s.timeNow().Add(24 * time.Hour)
		if leaseExpiry.After(maxLease) {
			leaseExpiry = maxLease
		}
	}

	s.table.RegisterWithLease(sessionID, req.Hostnames, leaseExpiry)
	registered := s.table.GetRegisteredHostnames(sessionID)
	log.Printf("Frontend: session %s (client %q) registered hostnames: %v", sessionID, clientIdentity.ID, registered)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(api.RegistrationResponse{
		Status:    "registered",
		Hostnames: registered,
	}); err != nil {
		klog.V(2).Infof("Frontend: failed to encode registration response: %v", err)
		return
	}
}

func (s *Server) handleConnectionUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIdentity, err := s.extractClientIdentity(r)
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

	isH2 := strings.EqualFold(r.Header.Get("Upgrade"), api.UpgradeProtocolH2)
	respProto := api.UpgradeProtocol
	if isH2 {
		respProto = api.UpgradeProtocolH2
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
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + respProto + "\r\n\r\n"
	if _, err := rawConn.Write([]byte(resp)); err != nil {
		closeCloser(rawConn)
		return
	}

	var dialedConn net.Conn = rawConn
	if rw != nil && rw.Reader.Buffered() > 0 {
		buffered := make([]byte, rw.Reader.Buffered())
		if _, err := io.ReadFull(rw.Reader, buffered); err != nil {
			closeCloser(rawConn)
			return
		}
		dialedConn = &bufferedConn{
			Conn:     rawConn,
			buffered: buffered,
		}
	}

	if isH2 {
		if err := s.h2.AddConn(sessionID, dialedConn); err != nil {
			closeCloser(dialedConn)
			return
		}
	} else {
		if err := s.pool.AddConn(sessionID, dialedConn); err != nil {
			closeCloser(dialedConn)
			return
		}
	}
}

type bufferedConn struct {
	net.Conn
	buffered  []byte
	bufOffset int
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if c.buffered != nil {
		n := copy(b, c.buffered[c.bufOffset:])
		c.bufOffset += n
		if c.bufOffset >= len(c.buffered) {
			c.buffered = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
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
			closeCloser(conn)
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
				closeCloser(c)
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

func closeCloser(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("Frontend: failed to close: %v", err)
	}
}
