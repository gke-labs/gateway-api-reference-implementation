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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/httphost"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
	"k8s.io/klog/v2"
)

// WireGuardDevice manages peers on a WireGuard network interface.
type WireGuardDevice interface {
	AddPeer(peer wireguard.Peer) error
	RemovePeer(publicKey wireguard.Key) error
}

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
	ListenAddrs []string
	// ListenHTTPAddrs configures addresses that accept plain HTTP routed by Host.
	// An empty list turns the feature off.
	ListenHTTPAddrs          []string
	InternalHostname         string
	ServerTLSConfig          *tls.Config
	ConnectTimeout           time.Duration
	PerAttemptTimeout        time.Duration
	ReadSNITimeout           time.Duration
	Authorizer               Authorizer
	PoolTransport            *PoolTransport
	MaxConnections           int
	IdleTimeout              time.Duration
	MaxHostnamesPerSession   int
	MaxRegistrationBodyBytes int64
	JWTVerifier              jwt.TokenVerifier
	LeaseReaperInterval      time.Duration
	// TimeNow overrides time.Now for deterministic testing of lease expiration.
	TimeNow            func() time.Time
	WireGuardDevice    WireGuardDevice
	WireGuardPublicKey wireguard.Key
	WireGuardPort      int
	WireGuardPrefix    *net.IPNet
}

// Server implements the SNI proxy frontend with mTLS API and reverse tunnels.
type Server struct {
	config     ServerConfig
	authorizer Authorizer
	table      *RegistrationTable
	pool       *PoolTransport

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

	wireguardDevice       WireGuardDevice
	wireguardPublicKey    wireguard.Key
	wireguardPort         int
	wireguardPrefix       *net.IPNet
	wireguardMu           sync.Mutex
	wireguardSessionAddr  map[string]net.IP
	wireguardSessionKey   map[string]wireguard.Key
	wireguardKeyToSession map[wireguard.Key]string
	wireguardUsedAddrs    map[string]struct{}
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

	pool := cfg.PoolTransport
	if pool == nil {
		pool = NewPoolTransport()
	}

	timeNow := cfg.TimeNow
	if timeNow == nil {
		timeNow = time.Now
	}

	s := &Server{
		config:                cfg,
		authorizer:            auth,
		table:                 NewRegistrationTable(),
		pool:                  pool,
		internalListener:      newChanListener(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}),
		shutdownCh:            make(chan struct{}),
		jwtVerifier:           cfg.JWTVerifier,
		sessions:              make(map[string]*frontendSession),
		timeNow:               timeNow,
		wireguardDevice:       cfg.WireGuardDevice,
		wireguardPublicKey:    cfg.WireGuardPublicKey,
		wireguardPort:         cfg.WireGuardPort,
		wireguardPrefix:       cfg.WireGuardPrefix,
		wireguardSessionAddr:  make(map[string]net.IP),
		wireguardSessionKey:   make(map[string]wireguard.Key),
		wireguardKeyToSession: make(map[wireguard.Key]string),
		wireguardUsedAddrs:    make(map[string]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/session", s.handleSession)
	mux.HandleFunc("/v1/registration", s.handleRegistration)
	mux.HandleFunc("/v1/connections", s.handleConnectionUpgrade)
	mux.HandleFunc("/v1/connections/", s.handleConnectionUpgrade)
	mux.HandleFunc("/v1/tunnel", s.handleConnectionUpgrade)
	mux.HandleFunc("/v1/sessions/{id}/wireguard", s.handleWireGuard)
	mux.HandleFunc("/v1/sessions/", s.handleWireGuard)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	return s, nil
}

// RegistrationTable returns the server's registration table.
func (s *Server) RegistrationTable() *RegistrationTable {
	return s.table
}

// PoolTransport returns the server's TCP pool transport.
func (s *Server) PoolTransport() *PoolTransport {
	return s.pool
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		closeCloser(listener)
	}
}

// ListenAndServe starts listening on all configured TCP addresses and serves traffic.
func (s *Server) ListenAndServe() error {
	var tlsListeners []net.Listener
	for _, addr := range s.config.ListenAddrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			closeListeners(tlsListeners)
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
		tlsListeners = append(tlsListeners, listener)
	}

	var httpListeners []net.Listener
	for _, addr := range s.config.ListenHTTPAddrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			closeListeners(tlsListeners)
			closeListeners(httpListeners)
			return fmt.Errorf("listening on HTTP %s: %w", addr, err)
		}
		httpListeners = append(httpListeners, listener)
	}

	return s.ServeWithHTTP(tlsListeners, httpListeners)
}

// Serve serves TCP traffic on the given pre-created TLS listeners.
func (s *Server) Serve(listeners ...net.Listener) error {
	return s.ServeWithHTTP(listeners, nil)
}

// ServeWithHTTP serves TLS and HTTP TCP traffic on the given pre-created listeners.
func (s *Server) ServeWithHTTP(tlsListeners []net.Listener, httpListeners []net.Listener) error {
	allListeners := slices.Concat(tlsListeners, httpListeners)
	s.listenersMu.Lock()
	s.listeners = allListeners
	s.listenersMu.Unlock()

	// Start internal mTLS HTTP server
	errCh := make(chan error, len(allListeners)+1)
	go func() {
		if err := s.httpServer.Serve(s.internalListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errCh <- fmt.Errorf("internal HTTP server: %w", err)
		}
	}()

	// Start background lease reaper for periodic token expiration
	go s.runLeaseReaper()

	serveListener := func(listener net.Listener, handler func(net.Conn)) {
		go func() {
			for {
				conn, err := listener.Accept()
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
				go handler(conn)
			}
		}()
	}

	for _, listener := range tlsListeners {
		serveListener(listener, s.handleConnection)
	}
	for _, listener := range httpListeners {
		serveListener(listener, s.handleHTTPConnection)
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
	closeListeners(s.listeners)
	s.listenersMu.Unlock()

	closeCloser(s.internalListener)
	closeCloser(s.pool)
	if closer, ok := s.wireguardDevice.(io.Closer); ok {
		closeCloser(closer)
	}
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
	s.removeWireGuardSession(sessionID)

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

	s.routeToBackend(sniHostname, peekedConn)
}

// handleHTTPConnection peeks the HTTP/1.1 request head of an incoming plaintext connection,
// parses its Host header, and routes the connection to a matching backend session via PROXY v2.
// After the first request, the frontend splices the connection and copies raw bytes bidirectionally,
// so later pipelined or keep-alive requests on the same connection go to the same session whatever
// their Host says; the backend routes each request by Host itself and serves only its own Gateways.
func (s *Server) handleHTTPConnection(conn net.Conn) {
	defer s.activeConns.Add(-1)
	setTCPKeepAlive(conn)

	hostname, peekedConn, err := httphost.SniffHost(conn, s.config.ReadSNITimeout)
	if err != nil {
		closeCloser(peekedConn)
		return
	}

	s.routeToBackend(hostname, peekedConn)
}

func (s *Server) routeToBackend(hostname string, peekedConn net.Conn) {
	cleanHost := CleanHostname(hostname)

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
		Authority: hostname,
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
			log.Printf("Frontend: connect timeout reached for host %q", hostname)
			closeCloser(peekedConn)
			return
		}

		remaining := time.Until(deadline)
		attemptTimeout := s.config.PerAttemptTimeout
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}

		sessions := s.table.MatchSessions(cleanHost)
		if len(sessions) == 0 {
			log.Printf("Frontend: rejecting connection with host %q (clean: %q): not registered", hostname, cleanHost)
			closeCloser(peekedConn)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		tunnelConn, _, err := s.pool.GetConnForSessions(ctx, sessions)
		cancel()

		if err != nil {
			// Pool/stream timeout on this attempt, continue until total deadline
			continue
		}

		setTCPKeepAlive(tunnelConn)

		// Set write deadline for PROXY header + peeked bytes
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

	if err := s.pool.AddConn(sessionID, dialedConn); err != nil {
		closeCloser(dialedConn)
		return
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

func (s *Server) removeWireGuardSession(sessionID string) {
	s.wireguardMu.Lock()
	defer s.wireguardMu.Unlock()
	if s.wireguardDevice == nil {
		return
	}
	if key, ok := s.wireguardSessionKey[sessionID]; ok {
		_ = s.wireguardDevice.RemovePeer(key)
		delete(s.wireguardKeyToSession, key)
		delete(s.wireguardSessionKey, sessionID)
	}
	if addr, ok := s.wireguardSessionAddr[sessionID]; ok {
		s.releaseWireGuardAddressLocked(addr)
		delete(s.wireguardSessionAddr, sessionID)
	}
}

func (s *Server) allocateWireGuardAddressLocked() (net.IP, error) {
	if s.wireguardPrefix == nil || len(s.wireguardPrefix.IP) == 0 || s.wireguardPrefix.IP.To16() == nil {
		return nil, errors.New("wireguard prefix is not configured")
	}
	base := s.wireguardPrefix.IP.To16()
	for host := uint64(2); host < math.MaxUint64; host++ {
		ip := make(net.IP, 16)
		copy(ip, base)
		binary.BigEndian.PutUint64(ip[8:], host)
		key := ip.String()
		if _, used := s.wireguardUsedAddrs[key]; !used {
			s.wireguardUsedAddrs[key] = struct{}{}
			return ip, nil
		}
	}
	return nil, errors.New("no free wireguard addresses in prefix")
}

func (s *Server) releaseWireGuardAddressLocked(addr net.IP) {
	if addr != nil {
		delete(s.wireguardUsedAddrs, addr.String())
	}
}

func (s *Server) handleWireGuard(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/wireguard") || s.wireguardDevice == nil || s.wireguardPrefix == nil {
		http.NotFound(w, r)
		return
	}
	if v := reflect.ValueOf(s.wireguardDevice); v.Kind() == reflect.Pointer && v.IsNil() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		sessionID = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/wireguard"), "/")
	}
	if sessionID == "" {
		http.Error(w, "missing session ID", http.StatusBadRequest)
		return
	}

	clientIdentity, err := s.extractClientIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
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

	var req api.WireGuardRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, s.config.MaxRegistrationBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if clientIdentity.Issuer != "" && req.Token != "" {
		regClaims, err := s.jwtVerifier.Verify(r.Context(), req.Token)
		if err != nil {
			http.Error(w, "token verification failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if regClaims.Issuer != clientIdentity.Issuer || regClaims.Subject != clientIdentity.Subject {
			http.Error(w, "session identity mismatch", http.StatusForbidden)
			return
		}
		clientIdentity.TokenExpiry = regClaims.Expiry
	}

	if req.PublicKey == "" {
		http.Error(w, "missing publicKey", http.StatusBadRequest)
		return
	}
	clientPubKey, err := wireguard.ParseKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid publicKey: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.wireguardMu.Lock()
	defer s.wireguardMu.Unlock()

	if existingSession, inUse := s.wireguardKeyToSession[clientPubKey]; inUse && existingSession != sessionID {
		http.Error(w, "public key already in use by another session", http.StatusConflict)
		return
	}

	peerAddr, hasAddr := s.wireguardSessionAddr[sessionID]
	if !hasAddr {
		addr, err := s.allocateWireGuardAddressLocked()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		peerAddr = addr
	}

	if oldKey, hasOldKey := s.wireguardSessionKey[sessionID]; hasOldKey && oldKey != clientPubKey {
		_ = s.wireguardDevice.RemovePeer(oldKey)
		delete(s.wireguardKeyToSession, oldKey)
	}

	peer := wireguard.Peer{
		PublicKey:  clientPubKey,
		AllowedIPs: []net.IPNet{{IP: peerAddr, Mask: net.CIDRMask(128, 128)}},
	}
	if err := s.wireguardDevice.AddPeer(peer); err != nil {
		if !hasAddr {
			s.releaseWireGuardAddressLocked(peerAddr)
		}
		http.Error(w, fmt.Sprintf("adding wireguard peer: %v", err), http.StatusInternalServerError)
		return
	}

	s.wireguardSessionAddr[sessionID] = peerAddr
	s.wireguardSessionKey[sessionID] = clientPubKey
	s.wireguardKeyToSession[clientPubKey] = sessionID

	prefixStr := ""
	if s.wireguardPrefix != nil {
		prefixStr = s.wireguardPrefix.String()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.WireGuardResponse{
		PublicKey:   s.wireguardPublicKey.String(),
		Port:        s.wireguardPort,
		ListenPort:  s.wireguardPort,
		Address:     peerAddr.String(),
		PeerAddress: peerAddr.String(),
		Prefix:      prefixStr,
	})
}
