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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"golang.org/x/net/http2"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ForwardedForMode specifies how the X-Forwarded-For header should be handled.
type ForwardedForMode string

const (
	// ForwardedForModeAppend appends the client IP to any existing X-Forwarded-For header.
	ForwardedForModeAppend ForwardedForMode = "append"
	// ForwardedForModeReplace replaces any existing X-Forwarded-For header with the client IP.
	ForwardedForModeReplace ForwardedForMode = "replace"
)

var (
	defaultForwardedForModeAppend  = ForwardedForModeAppend
	defaultForwardedForModeReplace = ForwardedForModeReplace
)

type contextKey string

const (
	originalHostContextKey  contextKey = "original-host"
	hostRewrittenContextKey contextKey = "host-rewritten"
)

// Proxy is a minimal implementation of a Gateway API proxy.
const (
	// DefaultTCPIdleTimeout is the default duration after which an idle spliced TCP connection expires (0 = disabled).
	DefaultTCPIdleTimeout = 0

	// DefaultTCPMaxConnections is the default maximum number of concurrent TCP connections per listener.
	DefaultTCPMaxConnections = 10000
)

type Proxy struct {
	mu           sync.RWMutex
	routes       []state.InternalRoute
	listeners    []state.InternalListener
	certificates map[string]*tls.Certificate
	defaultCert  *tls.Certificate

	sniConfig              atomic.Pointer[sniConfig]
	clientValidationConfig atomic.Pointer[clientValidationConfig]

	forwardedForMode atomic.Pointer[ForwardedForMode]

	tcpListeners      map[gatewayv1.PortNumber]*tcpPortListener
	tcpBindHost       string
	tcpIdleTimeout    time.Duration
	tcpMaxConnections int
	listenFunc        func(network, addr string) (net.Listener, error)
	dialFunc          func(network, addr string) (net.Conn, error)

	udpListeners     map[gatewayv1.PortNumber]*udpPortListener
	udpBindHost      string
	udpIdleTimeout   time.Duration
	udpMaxSessions   int
	listenPacketFunc func(network, addr string) (net.PacketConn, error)

	// baseTLSConfig and ticketConfig are initialized once in NewProxy and read concurrently
	// without holding p.mu during TLS handshakes.
	baseTLSConfig      *tls.Config
	ticketConfig       *tls.Config
	clientSessionCache *sni.LRUClientSessionCache

	transportsMu sync.Mutex
	transports   map[string]http.RoundTripper

	closed bool
}

type tcpPortListener struct {
	port        gatewayv1.PortNumber
	ln          net.Listener
	backends    atomic.Pointer[[]state.InternalTCPBackend]
	closed      atomic.Bool
	done        chan struct{}
	activeConns atomic.Int64
	maxConns    atomic.Int64
}

type sniConfig struct {
	hasPassthrough bool
	candidates     []state.InternalListener
}

type clientValidationConfig struct {
	listeners  []state.InternalListener
	tlsConfigs map[string]*tls.Config
	tlsErrors  map[string]error
}

func NewProxy() *Proxy {
	p := &Proxy{
		routes:             []state.InternalRoute{},
		listeners:          []state.InternalListener{},
		certificates:       make(map[string]*tls.Certificate),
		tcpListeners:       make(map[gatewayv1.PortNumber]*tcpPortListener),
		tcpIdleTimeout:     DefaultTCPIdleTimeout,
		tcpMaxConnections:  DefaultTCPMaxConnections,
		udpListeners:       make(map[gatewayv1.PortNumber]*udpPortListener),
		udpIdleTimeout:     DefaultUDPIdleTimeout,
		udpMaxSessions:     DefaultUDPMaxSessions,
		clientSessionCache: sni.NewLRUClientSessionCache(256),
		transports:         make(map[string]http.RoundTripper),
		ticketConfig:       &tls.Config{},
	}
	p.forwardedForMode.Store(&defaultForwardedForModeAppend)
	p.baseTLSConfig = &tls.Config{
		GetCertificate:     p.GetCertificate,
		GetConfigForClient: p.GetConfigForClient,
		WrapSession:        p.wrapSession,
		UnwrapSession:      p.unwrapSession,
	}

	p.sniConfig.Store(&sniConfig{})
	p.clientValidationConfig.Store(&clientValidationConfig{})
	return p
}

func (p *Proxy) SetDefaultCertificate(cert *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultCert = cert
}

func (p *Proxy) SetTCPBindHost(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tcpBindHost = host
}

// SetTCPIdleTimeout sets the idle timeout for spliced TCP connections.
func (p *Proxy) SetTCPIdleTimeout(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tcpIdleTimeout = d
}

// SetTCPMaxConnections sets the maximum number of concurrent TCP connections per listener.
func (p *Proxy) SetTCPMaxConnections(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tcpMaxConnections = n
}

func (p *Proxy) getTCPIdleTimeout() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tcpIdleTimeout
}

func (p *Proxy) getTCPMaxConnections() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.tcpMaxConnections <= 0 {
		return DefaultTCPMaxConnections
	}
	return p.tcpMaxConnections
}

func (p *Proxy) SetUDPBindHost(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.udpBindHost = host
}

func (p *Proxy) SetListenFunc(fn func(network, addr string) (net.Listener, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listenFunc = fn
}

func (p *Proxy) SetListenPacketFunc(fn func(network, addr string) (net.PacketConn, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listenPacketFunc = fn
}

func (p *Proxy) SetDialFunc(fn func(network, addr string) (net.Conn, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialFunc = fn
}

func (p *Proxy) SetUDPIdleTimeout(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.udpIdleTimeout = d
}

func (p *Proxy) SetUDPMaxSessions(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.udpMaxSessions = n
}

// SetForwardedForMode sets the forwarding mode for X-Forwarded-For headers (append or replace).
func (p *Proxy) SetForwardedForMode(mode ForwardedForMode) {
	switch strings.ToLower(string(mode)) {
	case string(ForwardedForModeReplace):
		p.forwardedForMode.Store(&defaultForwardedForModeReplace)
	default:
		p.forwardedForMode.Store(&defaultForwardedForModeAppend)
	}
}

func (p *Proxy) getForwardedForMode() ForwardedForMode {
	if m := p.forwardedForMode.Load(); m != nil && *m != "" {
		return *m
	}
	return ForwardedForModeAppend
}

func getOriginalHost(r *http.Request) string {
	if v, ok := r.Context().Value(originalHostContextKey).(string); ok && v != "" {
		return v
	}
	return r.Host
}

func (p *Proxy) GetTCPListener(port gatewayv1.PortNumber) net.Listener {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if pl, ok := p.tcpListeners[port]; ok {
		return pl.ln
	}
	return nil
}

func (p *Proxy) GetUDPListener(port gatewayv1.PortNumber) net.PacketConn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if pl, ok := p.udpListeners[port]; ok {
		return pl.conn
	}
	return nil
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	var errs []error
	for port, pl := range p.tcpListeners {
		pl.closed.Store(true)
		close(pl.done)
		if err := pl.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
		delete(p.tcpListeners, port)
	}
	for port, pl := range p.udpListeners {
		if err := pl.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
		delete(p.udpListeners, port)
	}
	p.transportsMu.Lock()
	for k, tr := range p.transports {
		if ic, ok := tr.(idleConnCloser); ok {
			ic.CloseIdleConnections()
		}
		delete(p.transports, k)
	}
	p.transportsMu.Unlock()
	return errors.Join(errs...)
}

func (p *Proxy) UpdateRoutes(routes []state.InternalRoute) {
	p.mu.Lock()
	p.routes = routes
	p.mu.Unlock()
	p.evictUnusedTransports(routes)
}

func (p *Proxy) UpdateListeners(listeners []state.InternalListener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners = listeners
	p.updateSNIConfigLocked(listeners)
	p.updateClientValidationLocked(listeners)
	p.updateTCPListenersLocked(listeners)
	p.updateUDPListenersLocked(listeners)
}

func (p *Proxy) UpdateConfig(listeners []state.InternalListener, routes []state.InternalRoute) {
	p.mu.Lock()
	p.listeners = listeners
	p.routes = routes
	p.updateSNIConfigLocked(listeners)
	p.updateClientValidationLocked(listeners)
	p.updateTCPListenersLocked(listeners)
	p.updateUDPListenersLocked(listeners)
	p.mu.Unlock()
	p.evictUnusedTransports(routes)
}

func (p *Proxy) updateTCPListenersLocked(listeners []state.InternalListener) {
	if p.closed {
		return
	}
	if p.tcpListeners == nil {
		p.tcpListeners = make(map[gatewayv1.PortNumber]*tcpPortListener)
	}

	desired := make(map[gatewayv1.PortNumber][]state.InternalTCPBackend)
	for _, lis := range listeners {
		if lis.Protocol != gatewayv1.TCPProtocolType {
			continue
		}
		if _, exists := desired[lis.Port]; !exists {
			desired[lis.Port] = lis.TCPBackends
		}
	}

	// Remove ports that are no longer present
	for port, pl := range p.tcpListeners {
		if _, exists := desired[port]; !exists {
			pl.closed.Store(true)
			close(pl.done)
			if err := pl.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				klog.V(2).Infof("failed to close TCP listener on port %d: %v", port, err)
			}
			delete(p.tcpListeners, port)
		}
	}

	// Update existing ports or open new ones
	for port, backends := range desired {
		backendsCopy := make([]state.InternalTCPBackend, len(backends))
		copy(backendsCopy, backends)

		maxConns := p.tcpMaxConnections
		if maxConns <= 0 {
			maxConns = DefaultTCPMaxConnections
		}

		if pl, exists := p.tcpListeners[port]; exists {
			pl.backends.Store(&backendsCopy)
			pl.maxConns.Store(int64(maxConns))
		} else {
			listenFn := p.listenFunc
			if listenFn == nil {
				listenFn = net.Listen
			}
			addr := net.JoinHostPort(p.tcpBindHost, strconv.Itoa(int(port)))
			ln, err := listenFn("tcp", addr)
			if err != nil {
				klog.Errorf("failed to listen on TCP port %d (%s): %v", port, addr, err)
				continue
			}
			pl := &tcpPortListener{
				port: port,
				ln:   ln,
				done: make(chan struct{}),
			}
			pl.backends.Store(&backendsCopy)
			pl.maxConns.Store(int64(maxConns))
			p.tcpListeners[port] = pl
			go p.tcpAcceptLoop(pl)
		}
	}
}

func (p *Proxy) tcpAcceptLoop(pl *tcpPortListener) {
	for {
		conn, err := pl.ln.Accept()
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
		maxConns := pl.maxConns.Load()
		if maxConns > 0 && pl.activeConns.Add(1) > maxConns {
			pl.activeConns.Add(-1)
			closeConn(conn)
			continue
		}
		go p.handleTCPConn(conn, pl)
	}
}

func (p *Proxy) getDialFunc() func(network, addr string) (net.Conn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.dialFunc != nil {
		return p.dialFunc
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).Dial
}

func (p *Proxy) handleTCPConn(conn net.Conn, pl *tcpPortListener) {
	defer pl.activeConns.Add(-1)
	defer closeConn(conn)

	bp := pl.backends.Load()
	if bp == nil || len(*bp) == 0 {
		return
	}
	target, ok := state.PickTCPBackend(*bp)
	if !ok || target == "" {
		return
	}

	dialFn := p.getDialFunc()
	backendConn, err := dialFn("tcp", target)
	if err != nil {
		return
	}

	idleTimeout := p.getTCPIdleTimeout()
	spliceConns(conn, backendConn, idleTimeout)
}

func (p *Proxy) updateSNIConfigLocked(listeners []state.InternalListener) {
	hasPassthrough := false
	var candidates []state.InternalListener
	for _, lis := range listeners {
		if lis.Protocol == gatewayv1.TLSProtocolType {
			hasPassthrough = true
		}
		if lis.Protocol == gatewayv1.HTTPSProtocolType || lis.Protocol == gatewayv1.TLSProtocolType {
			candidates = append(candidates, lis)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Port != candidates[j].Port {
			return candidates[i].Port < candidates[j].Port
		}
		return candidates[i].Name < candidates[j].Name
	})

	p.sniConfig.Store(&sniConfig{
		hasPassthrough: hasPassthrough,
		candidates:     candidates,
	})
}

func isClientValidationServable(cv *state.InternalClientValidation) (bool, string) {
	if cv == nil {
		return true, ""
	}
	if cv.Mode != "" && cv.Mode != gatewayv1.AllowValidOnly && cv.Mode != gatewayv1.AllowInsecureFallback {
		return false, fmt.Sprintf("unsupported validation mode %q (only AllowValidOnly and AllowInsecureFallback are supported)", cv.Mode)
	}
	if len(cv.CACertPEMs) == 0 {
		return false, "no CA certificates provided"
	}
	hasValidCA := false
	pool := x509.NewCertPool()
	for _, pem := range cv.CACertPEMs {
		if pool.AppendCertsFromPEM(pem) {
			hasValidCA = true
		}
	}
	if !hasValidCA {
		return false, "no valid CA certificates could be parsed from PEM"
	}
	return true, ""
}

func hashCAPEMs(pems [][]byte) string {
	h := sha256.New()
	for _, pem := range pems {
		h.Write(pem)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

const caHashSessionExtraPrefix = "gari-ca-hash:"

func (p *Proxy) wrapSession(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
	if cs.ServerName != "" {
		snap := p.clientValidationConfig.Load()
		if snap != nil && len(snap.listeners) > 0 {
			matched, matchType := state.MatchListeners(snap.listeners, cs.ServerName)
			if matchType != state.NoMatch && len(matched) > 0 {
				selected := matched[0]
				if selected.ClientValidation != nil {
					caHash := hashCAPEMs(selected.ClientValidation.CACertPEMs)
					ss.Extra = append(ss.Extra, []byte(caHashSessionExtraPrefix+caHash))
				}
			}
		}
	}
	return p.ticketConfig.EncryptTicket(cs, ss)
}

func (p *Proxy) unwrapSession(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
	ss, err := p.ticketConfig.DecryptTicket(identity, cs)
	if err != nil || ss == nil {
		return nil, nil
	}

	var ticketCAHash string
	for _, extra := range ss.Extra {
		if bytes.HasPrefix(extra, []byte(caHashSessionExtraPrefix)) {
			ticketCAHash = string(bytes.TrimPrefix(extra, []byte(caHashSessionExtraPrefix)))
			break
		}
	}

	snap := p.clientValidationConfig.Load()
	var currentCAHash string
	hasClientValidation := false
	if snap != nil && len(snap.listeners) > 0 && cs.ServerName != "" {
		matched, matchType := state.MatchListeners(snap.listeners, cs.ServerName)
		if matchType != state.NoMatch && len(matched) > 0 {
			selected := matched[0]
			if selected.ClientValidation != nil {
				hasClientValidation = true
				currentCAHash = hashCAPEMs(selected.ClientValidation.CACertPEMs)
			}
		}
	}

	if hasClientValidation {
		// Validated listener: only resume if ticket was minted for the exact current CA set.
		if ticketCAHash == "" || ticketCAHash != currentCAHash {
			return nil, nil
		}
	} else {
		// Unvalidated listener: do not resume tickets minted under a validated listener.
		if ticketCAHash != "" {
			return nil, nil
		}
	}

	return ss, nil
}

func (p *Proxy) updateClientValidationLocked(listeners []state.InternalListener) {
	var httpsListeners []state.InternalListener
	tlsConfigs := make(map[string]*tls.Config)
	tlsErrors := make(map[string]error)

	for _, lis := range listeners {
		if lis.Protocol != gatewayv1.HTTPSProtocolType {
			continue
		}
		httpsListeners = append(httpsListeners, lis)

		if lis.ClientValidation != nil {
			servable, reason := isClientValidationServable(lis.ClientValidation)
			if !servable {
				klog.Warningf("Listener %q with ClientValidation cannot be served: %s", lis.Name, reason)
				tlsErrors[lis.Name] = fmt.Errorf("listener %q cannot be served: %s", lis.Name, reason)
				continue
			}

			caPool := x509.NewCertPool()
			for _, pem := range lis.ClientValidation.CACertPEMs {
				caPool.AppendCertsFromPEM(pem)
			}
			clientAuth := tls.RequireAndVerifyClientCert
			if lis.ClientValidation.Mode == gatewayv1.AllowInsecureFallback {
				clientAuth = tls.RequestClientCert
			}

			cfg := &tls.Config{
				ClientAuth:     clientAuth,
				ClientCAs:      caPool,
				GetCertificate: p.GetCertificate,
				NextProtos:     []string{"h2", "http/1.1"},
				WrapSession:    p.wrapSession,
				UnwrapSession:  p.unwrapSession,
			}

			// Validated listeners (both AllowValidOnly and AllowInsecureFallback) have session tickets
			// enabled for TLS session resumption.
			//
			// Trade-off: When session resumption is enabled on a mutual TLS listener, a resumed TLS
			// handshake (via session ticket) reuses the client certificate verified during the initial
			// full handshake without re-verifying the client certificate against the CA pool on every
			// resumed connection. If a client certificate is revoked or the CA trust pool changes, an
			// existing session ticket could allow resumption until expired or rotated.
			// To ensure tickets cannot resume after a CA change, WrapSession binds the listener's CA
			// set hash into the ticket payload (SessionState.Extra), and UnwrapSession refuses to resume
			// if the ticket's CA hash does not match the listener's current CA set hash.

			tlsConfigs[lis.Name] = cfg
		}
	}

	sort.Slice(httpsListeners, func(i, j int) bool {
		if httpsListeners[i].Port != httpsListeners[j].Port {
			return httpsListeners[i].Port < httpsListeners[j].Port
		}
		return httpsListeners[i].Name < httpsListeners[j].Name
	})

	p.clientValidationConfig.Store(&clientValidationConfig{
		listeners:  httpsListeners,
		tlsConfigs: tlsConfigs,
		tlsErrors:  tlsErrors,
	})
}

// GetConfigForClient selects the per-listener *tls.Config by SNI using the MatchListeners
// precedence the HTTPS path already uses.
// All HTTPS ports collapse onto 8443 behind the Service, so per-port CA pools are distinguished
// by hostname; two validated listeners on different ports with the same hostname cannot be told apart.
func (p *Proxy) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	snap := p.clientValidationConfig.Load()
	if snap == nil || len(snap.listeners) == 0 {
		return nil, nil
	}

	sniHostname := ""
	if hello != nil {
		sniHostname = hello.ServerName
	}

	matched, matchType := state.MatchListeners(snap.listeners, sniHostname)
	if matchType == state.NoMatch || len(matched) == 0 {
		return nil, nil
	}

	selected := matched[0]
	if snap.tlsErrors != nil {
		if err, ok := snap.tlsErrors[selected.Name]; ok {
			return nil, err
		}
	}
	return snap.tlsConfigs[selected.Name], nil
}

// TLSConfig returns a cloned base *tls.Config for HTTPS servers, configured with
// GetCertificate, GetConfigForClient, WrapSession, and UnwrapSession callbacks wired to this Proxy.
// A clone is returned per caller to ensure servers (e.g. HTTPS http.Server and http3.Server) do not
// mutate shared TLS configuration fields (such as NextProtos), while still sharing ticket encryption
// and decryption through Proxy-managed WrapSession and UnwrapSession callbacks.
func (p *Proxy) TLSConfig() *tls.Config {
	return p.baseTLSConfig.Clone()
}

func (p *Proxy) UpdateCertificates(certs map[string]*tls.Certificate, defaultCert *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certificates = certs
	if defaultCert != nil {
		p.defaultCert = defaultCert
	}
}

func (p *Proxy) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if hello != nil && hello.ServerName != "" {
		sni := strings.ToLower(hello.ServerName)
		if cert, ok := p.certificates[sni]; ok {
			return cert, nil
		}
		parts := strings.Split(sni, ".")
		if len(parts) > 1 {
			wildcard := "*." + strings.Join(parts[1:], ".")
			if cert, ok := p.certificates[wildcard]; ok {
				return cert, nil
			}
		}
	}

	if p.defaultCert != nil {
		return p.defaultCert, nil
	}

	if hello != nil && hello.ServerName != "" {
		return nil, fmt.Errorf("no certificate found for server name %s", hello.ServerName)
	}
	return nil, fmt.Errorf("no default certificate available")
}

// HasCertificate reports whether a certificate exists in the proxy for the given SNI (exact or wildcard).
func (p *Proxy) HasCertificate(sni string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if sni == "" {
		return false
	}
	s := strings.ToLower(sni)
	if _, ok := p.certificates[s]; ok {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) > 1 {
		wildcard := "*." + strings.Join(parts[1:], ".")
		if _, ok := p.certificates[wildcard]; ok {
			return true
		}
	}
	return false
}

func splitHostPort(hostPort string, defaultPort int32) (string, int32, bool) {
	h, pStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, defaultPort, false
	}
	p, err := strconv.Atoi(pStr)
	if err != nil {
		return h, defaultPort, false
	}
	return h, int32(p), true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value(originalHostContextKey) == nil {
		r = r.WithContext(context.WithValue(r.Context(), originalHostContextKey, r.Host))
	}
	p.mu.RLock()
	routes := p.routes
	listeners := p.listeners
	p.mu.RUnlock()

	if len(listeners) > 0 {
		if r.TLS != nil {
			reqHost, reqPort, hasPort := splitHostPort(r.Host, 443)
			reqHost = strings.ToLower(reqHost)

			var httpsListeners []state.InternalListener
			for _, l := range listeners {
				if l.Protocol == gatewayv1.HTTPSProtocolType {
					if servable, _ := isClientValidationServable(l.ClientValidation); servable {
						httpsListeners = append(httpsListeners, l)
					}
				}
			}

			if hasPort {
				var filtered []state.InternalListener
				for _, l := range httpsListeners {
					if l.Port == 0 || int32(l.Port) == reqPort {
						filtered = append(filtered, l)
					}
				}
				httpsListeners = filtered
			} else {
				// With no port in Host, do not filter by port; let hostname precedence decide
				// (exact > wildcard > catch-all) with ties broken in favor of port 443.
				sort.SliceStable(httpsListeners, func(i, j int) bool {
					is443I := httpsListeners[i].Port == 443 || httpsListeners[i].Port == 0
					is443J := httpsListeners[j].Port == 443 || httpsListeners[j].Port == 0
					if is443I != is443J {
						return is443I
					}
					return false
				})
			}

			if len(httpsListeners) > 0 {
				sni := strings.ToLower(r.TLS.ServerName)
				connListeners, connMatchType := state.MatchListeners(httpsListeners, sni)
				if len(connListeners) == 0 {
					p.respondNotFound(w, r, fmt.Sprintf("No listener for server name %s", sni))
					return
				}

				reqHostListeners, reqMatchType := state.MatchListeners(httpsListeners, reqHost)

				if connMatchType == state.CatchAllMatch {
					if reqMatchType == state.ExactMatch || reqMatchType == state.WildcardMatch {
						http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
						return
					}
				} else if connMatchType == state.WildcardMatch {
					hasMatchingConnListener := false
					for _, l := range connListeners {
						if state.MatchesWildcard(l.Hostname, reqHost) {
							hasMatchingConnListener = true
							break
						}
					}
					if !hasMatchingConnListener {
						if len(reqHostListeners) > 0 {
							http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
						} else {
							p.respondNotFound(w, r, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path))
						}
						return
					}
					if reqMatchType == state.ExactMatch {
						http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
						return
					}
				} else if connMatchType == state.ExactMatch {
					hasMatchingConnListener := false
					for _, l := range connListeners {
						if strings.EqualFold(l.Hostname, reqHost) {
							hasMatchingConnListener = true
							break
						}
					}
					if !hasMatchingConnListener {
						if len(reqHostListeners) > 0 {
							http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
						} else {
							p.respondNotFound(w, r, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path))
						}
						return
					}
				}

				var connRoutes []state.InternalRoute
				for _, l := range connListeners {
					connRoutes = append(connRoutes, l.Routes...)
				}
				routes = connRoutes
			}
		} else {
			reqHost, reqPort, _ := splitHostPort(r.Host, 80)
			reqHost = strings.ToLower(reqHost)

			var httpListeners []state.InternalListener
			for _, l := range listeners {
				if l.Protocol == gatewayv1.HTTPProtocolType {
					if l.Port == 0 || int32(l.Port) == reqPort {
						httpListeners = append(httpListeners, l)
					}
				}
			}

			if len(httpListeners) > 0 {
				reqHostListeners, _ := state.MatchListeners(httpListeners, reqHost)
				if len(reqHostListeners) == 0 {
					p.respondNotFound(w, r, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path))
					return
				}
				var matchedRoutes []state.InternalRoute
				for _, l := range reqHostListeners {
					matchedRoutes = append(matchedRoutes, l.Routes...)
				}
				routes = matchedRoutes
			}
		}
	}

	bestRule, bestMatch := state.MatchRoute(routes, r)

	if bestRule != nil {
		cors := bestRule.CORS
		if cors == nil && len(bestRule.Backends) > 0 {
			cors = bestRule.Backends[0].CORS
		}

		// Handle CORS preflight request
		if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && cors != nil {
			applyCORSHeaders(w.Header(), r, cors, true)
			if bestRule.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if bestRule.Redirect != nil {
			if bestRule.CORS != nil {
				applyCORSHeaders(w.Header(), r, bestRule.CORS, false)
			}
			if bestRule.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
			}
			p.redirect(w, r, *bestRule.Redirect, bestMatch)
			return
		}
		if bestRule.Error != nil {
			if bestRule.CORS != nil {
				applyCORSHeaders(w.Header(), r, bestRule.CORS, false)
			}
			if bestRule.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
			}
			// Per Gateway API specification, if a rule matches but its backend is invalid
			// or unresolved, the implementation SHOULD return an HTTP 500 Internal Server Error.
			// This is also verified by conformance tests like HTTPRouteInvalidBackendRefUnknownKind.
			http.Error(w, bestRule.Error.HTTPMessage, bestRule.Error.HTTPStatusCode)
			return
		}
		if bestRule.Rewrite != nil {
			r = p.rewrite(r, *bestRule.Rewrite, bestMatch)
		}
		if bestRule.RequestHeaderModifier != nil {
			p.modifyHeaders(r, *bestRule.RequestHeaderModifier)
		}
		if len(bestRule.Backends) > 0 {
			backend, err := pickBackend(bestRule.Backends)
			if err != nil {
				if bestRule.CORS != nil {
					applyCORSHeaders(w.Header(), r, bestRule.CORS, false)
				}
				if bestRule.ResponseHeaderModifier != nil {
					modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if backend.Error != nil {
				effectiveCORS := bestRule.CORS
				if backend.CORS != nil {
					effectiveCORS = backend.CORS
				}
				if effectiveCORS != nil {
					applyCORSHeaders(w.Header(), r, effectiveCORS, false)
				}
				if bestRule.ResponseHeaderModifier != nil {
					modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
				}
				if backend.ResponseHeaderModifier != nil {
					modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
				}
				http.Error(w, backend.Error.HTTPMessage, backend.Error.HTTPStatusCode)
				return
			}

			// Read request body if there are mirrors so it can be sent to both main backend and mirrors.
			// TODO: Support streaming/spooling for request bodies exceeding the memory limit.
			var bodyBytes []byte
			if len(bestRule.Mirrors) > 0 && r.Body != nil && r.Body != http.NoBody {
				const maxMirrorBodySize = 8 * 1024 * 1024 // 8MB limit to avoid OOM
				limitedReader := io.LimitReader(r.Body, maxMirrorBodySize+1)
				var errs []error
				var readErr error
				bodyBytes, readErr = io.ReadAll(limitedReader)
				if readErr != nil {
					errs = append(errs, readErr)
				}
				if closeErr := r.Body.Close(); closeErr != nil {
					errs = append(errs, closeErr)
				}
				if len(errs) > 0 {
					joinedErr := errors.Join(errs...)
					log.Log.Error(joinedErr, "Failed to read request body for mirroring", "path", r.URL.Path)
					if backend.ResponseHeaderModifier != nil {
						modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
					}
					if bestRule.ResponseHeaderModifier != nil {
						modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
					}
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				if int64(len(bodyBytes)) > maxMirrorBodySize {
					log.Log.Info("Request body exceeds maximum size for mirroring", "path", r.URL.Path, "maxBytes", maxMirrorBodySize)
					if backend.ResponseHeaderModifier != nil {
						modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
					}
					if bestRule.ResponseHeaderModifier != nil {
						modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
					}
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			// Process mirrors
			for _, m := range bestRule.Mirrors {
				shouldMirror := false
				if m.Numerator >= m.Denominator && m.Denominator > 0 {
					shouldMirror = true
				} else if m.Numerator > 0 && m.Denominator > 0 {
					if rand.Int32N(m.Denominator) < m.Numerator {
						shouldMirror = true
					}
				}
				if shouldMirror {
					p.mirror(r, bodyBytes, m.Backend, bestRule.Timeouts)
				}
			}

			if backend.RequestHeaderModifier != nil {
				p.modifyHeaders(r, *backend.RequestHeaderModifier)
			}
			p.forward(w, r, backend, bestRule.ResponseHeaderModifier, bestRule.CORS, bestRule.Timeouts, bestRule.Retry)
			return
		}

		if bestRule.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *bestRule.ResponseHeaderModifier)
		}
		http.Error(w, "No backend refs specified", http.StatusInternalServerError)
		return
	}

	p.respondNotFound(w, r, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path))
}

func (p *Proxy) respondNotFound(w http.ResponseWriter, r *http.Request, msg string) {
	if isGRPCRequest(r) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "12")
		w.Header().Set("Grpc-Message", msg)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, msg, http.StatusNotFound)
}

func isGRPCRequest(r *http.Request) bool {
	ct := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Type")))
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") || strings.HasPrefix(ct, "application/grpc;")
}

// modifyHeaders modifies the request headers in place before forwarding.
func (p *Proxy) modifyHeaders(r *http.Request, modifier gatewayv1.HTTPHeaderFilter) {
	modifyHeaders(r.Header, modifier)
}

// modifyHeaders modifies the HTTP headers in place according to the modifier.
func modifyHeaders(header http.Header, modifier gatewayv1.HTTPHeaderFilter) {
	for _, h := range modifier.Remove {
		header.Del(h)
		for k := range header {
			if strings.EqualFold(k, h) {
				delete(header, k)
			}
		}
	}
	for _, h := range modifier.Set {
		for k := range header {
			if strings.EqualFold(k, string(h.Name)) {
				delete(header, k)
			}
		}
		header.Set(string(h.Name), h.Value)
	}
	for _, h := range modifier.Add {
		var existing []string
		for k, v := range header {
			if strings.EqualFold(k, string(h.Name)) {
				existing = append(existing, v...)
				delete(header, k)
			}
		}
		for _, v := range existing {
			header.Add(string(h.Name), v)
		}
		header.Add(string(h.Name), h.Value)
	}
}

// rewrite returns an updated *http.Request with path and host rewritten before forwarding to the backend.
func (p *Proxy) rewrite(r *http.Request, rewrite state.InternalRewrite, match *state.InternalMatch) *http.Request {
	if state.ValueOf(rewrite.Hostname) == "" && rewrite.Path == nil {
		return r
	}
	ctx := r.Context()
	if hostname := state.ValueOf(rewrite.Hostname); hostname != "" {
		if ctx.Value(originalHostContextKey) == nil {
			ctx = context.WithValue(ctx, originalHostContextKey, r.Host)
		}
		ctx = context.WithValue(ctx, hostRewrittenContextKey, true)
	}
	r = r.Clone(ctx)
	if hostname := state.ValueOf(rewrite.Hostname); hostname != "" {
		r.Host = string(hostname)
	}

	if rewrite.Path != nil {
		switch rewrite.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			r.URL.Path = rewrite.Path.Value
			r.URL.RawPath = ""
		case gatewayv1.PrefixMatchHTTPPathModifier:
			prefix := "/"
			isValidPrefixMatch := true
			if match != nil && match.Path != nil {
				if match.Path.Type == gatewayv1.PathMatchPathPrefix {
					prefix = match.Path.Value
				} else {
					isValidPrefixMatch = false
				}
			}
			if isValidPrefixMatch && strings.HasPrefix(r.URL.Path, prefix) {
				suffix := r.URL.Path[len(prefix):]
				if len(suffix) > 0 && !strings.HasPrefix(suffix, "/") {
					suffix = "/" + suffix
				}
				newPath := rewrite.Path.Value + suffix
				for strings.Contains(newPath, "//") {
					newPath = strings.ReplaceAll(newPath, "//", "/")
				}
				r.URL.Path = newPath
				r.URL.RawPath = ""
			}
		}
	}
	return r
}

func (p *Proxy) redirect(w http.ResponseWriter, r *http.Request, redirect state.InternalRedirect, match *state.InternalMatch) {
	newURL := &url.URL{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Determine scheme
	targetScheme := "http"
	if r.TLS != nil {
		targetScheme = "https"
	}
	if scheme := state.ValueOf(redirect.Scheme); scheme != "" {
		targetScheme = scheme
	}
	newURL.Scheme = targetScheme

	// Determine host and port
	inHost, inPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		inHost = r.Host
		inPort = ""
	}

	targetHost := inHost
	if hostname := state.ValueOf(redirect.Hostname); hostname != "" {
		targetHost = string(hostname)
	}

	var targetPort string
	if redirect.Port != nil {
		targetPort = fmt.Sprintf("%d", *redirect.Port)
	} else if redirect.Scheme != nil && *redirect.Scheme != "" {
		// If redirect scheme is not-empty, the redirect port MUST be the well-known port associated with the redirect scheme.
		// Specifically "http" to port 80 and "https" to port 443.
		if targetScheme == "http" {
			targetPort = "80"
		} else if targetScheme == "https" {
			targetPort = "443"
		}
	} else {
		// If redirect scheme is empty, the redirect port MUST be the Gateway Listener port.
		targetPort = inPort
	}

	// Implementations SHOULD NOT add the port number in the 'Location' header if:
	// - HTTP and port 80
	// - HTTPS and port 443
	if (targetScheme == "http" && targetPort == "80") || (targetScheme == "https" && targetPort == "443") {
		targetPort = ""
	}

	if targetPort != "" {
		newURL.Host = net.JoinHostPort(targetHost, targetPort)
	} else {
		newURL.Host = targetHost
	}

	if redirect.Path != nil {
		switch redirect.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			newURL.Path = redirect.Path.Value
		case gatewayv1.PrefixMatchHTTPPathModifier:
			prefix := "/"
			isValidPrefixMatch := true
			if match != nil && match.Path != nil {
				if match.Path.Type == gatewayv1.PathMatchPathPrefix {
					prefix = match.Path.Value
				} else {
					isValidPrefixMatch = false
				}
			}
			if isValidPrefixMatch && strings.HasPrefix(r.URL.Path, prefix) {
				suffix := r.URL.Path[len(prefix):]
				if len(suffix) > 0 && !strings.HasPrefix(suffix, "/") {
					suffix = "/" + suffix
				}
				newPath := redirect.Path.Value + suffix
				for strings.Contains(newPath, "//") {
					newPath = strings.ReplaceAll(newPath, "//", "/")
				}
				newURL.Path = newPath
			}
		}
	}

	statusCode := state.ValueOf(redirect.StatusCode)
	if statusCode == 0 {
		statusCode = http.StatusFound
	}

	log.Log.Info("Redirecting request", "host", r.Host, "path", r.URL.Path, "target", newURL.String(), "status", statusCode)
	http.Redirect(w, r, newURL.String(), statusCode)
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		containsToken(r.Header.Get("Connection"), "upgrade")
}

func containsToken(header, token string) bool {
	for _, v := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}

// setForwardedHeaders stamps X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host
// headers on outbound requests forwarded to backends.
//
// Forwarded Headers Trust Policy:
// 1. X-Forwarded-For:
//   - append mode (default): Appends the immediate downstream client IP to any existing
//     X-Forwarded-For header received from the client. In an edge deployment facing untrusted clients,
//     only the rightmost IP address added by GARI is trustworthy; any preceding entries could be
//     forged by the client unless GARI is deployed behind an upstream trusted proxy.
//   - replace mode (--forwarded-for-mode=replace): Drops any client-supplied X-Forwarded-For header
//     and sets X-Forwarded-For solely to the immediate downstream client IP. This is recommended
//     when GARI is the edge proxy (first hop), ensuring backends receive only verified client IPs.
//
// 2. X-Forwarded-Proto:
//   - Set to "https" when the client connection used TLS (inReq.TLS != nil) or HTTP/3, and "http"
//     for plaintext requests.
//   - Any client-supplied X-Forwarded-Proto header is untrusted and always replaced by GARI,
//     as GARI is the protocol termination and transport boundary.
//
// 3. X-Forwarded-Host:
//   - When URLRewrite modifies the Host header, X-Forwarded-Host is set to the client's
//     original pre-rewrite Host while the outbound Host header carries the rewritten hostname.
//   - When no hostname rewrite occurs, X-Forwarded-Host is omitted (and any client-supplied
//     X-Forwarded-Host is removed) because the outbound Host header already carries the
//     authoritative client Host.
//   - Any client-supplied X-Forwarded-Host header is untrusted and dropped/replaced.
func (p *Proxy) setForwardedHeaders(outReq *http.Request, inReq *http.Request) {
	// 1. X-Forwarded-For
	var clientIP string
	if host, _, err := net.SplitHostPort(inReq.RemoteAddr); err == nil {
		clientIP = host
	} else if inReq.RemoteAddr != "" {
		clientIP = inReq.RemoteAddr
	}

	mode := p.getForwardedForMode()
	if mode == ForwardedForModeReplace {
		if clientIP != "" {
			outReq.Header.Set("X-Forwarded-For", clientIP)
		} else {
			outReq.Header.Del("X-Forwarded-For")
		}
	} else {
		if clientIP != "" {
			priors := outReq.Header.Values("X-Forwarded-For")
			if len(priors) > 0 {
				clientIP = strings.Join(priors, ", ") + ", " + clientIP
			}
			outReq.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	// 2. X-Forwarded-Proto
	proto := "http"
	if inReq.TLS != nil || inReq.ProtoMajor == 3 || strings.HasPrefix(strings.ToUpper(inReq.Proto), "HTTP/3") || strings.EqualFold(inReq.URL.Scheme, "https") {
		proto = "https"
	}
	outReq.Header.Set("X-Forwarded-Proto", proto)

	// 3. X-Forwarded-Host
	origHost := getOriginalHost(inReq)
	rewritten, _ := inReq.Context().Value(hostRewrittenContextKey).(bool)
	if !rewritten && origHost != "" && inReq.Host != "" && origHost != inReq.Host {
		rewritten = true
	}
	if rewritten && origHost != "" {
		outReq.Header.Set("X-Forwarded-Host", origHost)
	} else {
		outReq.Header.Del("X-Forwarded-Host")
	}
}

func (p *Proxy) buildBackendRequest(ctx context.Context, r *http.Request, backend state.InternalBackend, body io.Reader) (*http.Request, *url.URL, error) {
	scheme := "http"
	if strings.EqualFold(state.ValueOf(backend.AppProtocol), "https") {
		scheme = "https"
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     fmt.Sprintf("%s:%d", backend.Host, backend.Port),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), body)
	if err != nil {
		return nil, nil, err
	}

	req.Header = r.Header.Clone()
	removeHopByHopHeaders(req.Header)

	p.setForwardedHeaders(req, r)

	req.Host = r.Host
	return req, targetURL, nil
}

func (p *Proxy) getClientSessionCache() *sni.LRUClientSessionCache {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clientSessionCache == nil {
		p.clientSessionCache = sni.NewLRUClientSessionCache(256)
	}
	return p.clientSessionCache
}

func (p *Proxy) buildBackendTLSConfig(backend state.InternalBackend) *tls.Config {
	var clientCertKey string
	if backend.TLSConfig != nil {
		if backend.TLSConfig.ClientCertID != "" {
			clientCertKey = backend.TLSConfig.ClientCertID
		} else if backend.TLSConfig.ClientCert != nil && len(backend.TLSConfig.ClientCert.Certificate) > 0 {
			h := sha256.Sum256(backend.TLSConfig.ClientCert.Certificate[0])
			clientCertKey = hex.EncodeToString(h[:])
		}
	}
	sessionCache := sni.NewPrefixedClientSessionCache("client-cert:"+clientCertKey+":", p.getClientSessionCache())

	if backend.TLSConfig == nil {
		return &tls.Config{
			ServerName:         backend.Host,
			InsecureSkipVerify: false,
			ClientSessionCache: sessionCache,
		}
	}

	var rootCAs *x509.CertPool
	if backend.TLSConfig.WellKnownCACertificates != nil && *backend.TLSConfig.WellKnownCACertificates == gatewayv1.WellKnownCACertificatesSystem {
		// Leave RootCAs nil so the system pool is used
		rootCAs = nil
	} else if len(backend.TLSConfig.CACerts) > 0 {
		rootCAs = x509.NewCertPool()
		for _, cert := range backend.TLSConfig.CACerts {
			rootCAs.AppendCertsFromPEM(cert)
		}
	} else {
		rootCAs = x509.NewCertPool()
	}

	serverName := backend.TLSConfig.Hostname

	var clientCerts []tls.Certificate
	if backend.TLSConfig.ClientCert != nil {
		clientCerts = []tls.Certificate{*backend.TLSConfig.ClientCert}
	}

	if len(backend.TLSConfig.SubjectAltNames) > 0 {
		sans := backend.TLSConfig.SubjectAltNames
		return &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			Certificates:       clientCerts,
			ClientSessionCache: sessionCache,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("no peer certificates presented")
				}
				leaf := cs.PeerCertificates[0]

				verifyOpts := x509.VerifyOptions{
					Roots:         rootCAs,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					verifyOpts.Intermediates.AddCert(cert)
				}
				if _, err := leaf.Verify(verifyOpts); err != nil {
					return fmt.Errorf("certificate verification failed: %w", err)
				}

				if err := verifySubjectAltNames(leaf, sans); err != nil {
					return err
				}
				return nil
			},
		}
	}

	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		Certificates:       clientCerts,
		ClientSessionCache: sessionCache,
	}
}

func verifySubjectAltNames(cert *x509.Certificate, sans []gatewayv1.SubjectAltName) error {
	if cert == nil {
		return fmt.Errorf("no peer certificate found")
	}
	var lastErr error
	for _, san := range sans {
		switch san.Type {
		case gatewayv1.HostnameSubjectAltNameType:
			expectedHost := string(san.Hostname)
			if err := cert.VerifyHostname(expectedHost); err == nil {
				return nil
			} else {
				lastErr = err
				for _, dns := range cert.DNSNames {
					if strings.EqualFold(dns, expectedHost) {
						return nil
					}
				}
			}
		case gatewayv1.URISubjectAltNameType:
			expectedURI := string(san.URI)
			parsedExpected, err := url.Parse(expectedURI)
			if err != nil {
				lastErr = fmt.Errorf("invalid expected URI %q: %w", expectedURI, err)
				continue
			}
			for _, u := range cert.URIs {
				if u == nil {
					continue
				}
				if u.String() == expectedURI {
					return nil
				}
				if strings.EqualFold(u.Scheme, parsedExpected.Scheme) &&
					strings.EqualFold(u.Host, parsedExpected.Host) &&
					u.Path == parsedExpected.Path &&
					u.RawQuery == parsedExpected.RawQuery {
					return nil
				}
			}
			lastErr = fmt.Errorf("certificate URIs do not match expected URI %q", expectedURI)
		}
	}
	if lastErr != nil {
		return fmt.Errorf("certificate does not match configured SubjectAltNames: %w", lastErr)
	}
	return fmt.Errorf("certificate does not match configured SubjectAltNames")
}

func backendTransportKey(backend state.InternalBackend) string {
	appProto := strings.ToLower(state.ValueOf(backend.AppProtocol))
	if !strings.EqualFold(appProto, "https") && appProto != "kubernetes.io/h2c" {
		return "default"
	}
	target := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
	if appProto == "kubernetes.io/h2c" {
		return fmt.Sprintf("h2c|%s", target)
	}

	var b strings.Builder
	b.WriteString("https|")
	b.WriteString(target)
	b.WriteString("|")
	if backend.TLSConfig != nil {
		b.WriteString("host:")
		b.WriteString(backend.TLSConfig.Hostname)
		b.WriteString("|wk:")
		if backend.TLSConfig.WellKnownCACertificates != nil {
			b.WriteString(string(*backend.TLSConfig.WellKnownCACertificates))
		}
		b.WriteString("|cas:")
		if len(backend.TLSConfig.CACerts) > 0 {
			h := sha256.New()
			for _, ca := range backend.TLSConfig.CACerts {
				h.Write(ca)
				h.Write([]byte{0})
			}
			b.WriteString(hex.EncodeToString(h.Sum(nil)))
		}
		b.WriteString("|sans:")
		for i, san := range backend.TLSConfig.SubjectAltNames {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(string(san.Type))
			b.WriteString(":")
			if san.Type == gatewayv1.HostnameSubjectAltNameType {
				b.WriteString(string(san.Hostname))
			} else if san.Type == gatewayv1.URISubjectAltNameType {
				b.WriteString(string(san.URI))
			}
		}
		b.WriteString("|clientCert:")
		if backend.TLSConfig.ClientCertID != "" {
			b.WriteString(backend.TLSConfig.ClientCertID)
		} else if backend.TLSConfig.ClientCert != nil && len(backend.TLSConfig.ClientCert.Certificate) > 0 {
			h := sha256.Sum256(backend.TLSConfig.ClientCert.Certificate[0])
			b.WriteString(hex.EncodeToString(h[:]))
		}
	} else {
		b.WriteString("system-roots|host:")
		b.WriteString(backend.Host)
	}
	return b.String()
}

type idleConnCloser interface {
	CloseIdleConnections()
}

func (p *Proxy) evictUnusedTransports(activeRoutes []state.InternalRoute) {
	activeKeys := make(map[string]bool)
	distinctTLSCount := 0
	for _, route := range activeRoutes {
		for _, rule := range route.Rules {
			for _, b := range rule.Backends {
				key := backendTransportKey(b)
				if !activeKeys[key] {
					activeKeys[key] = true
					if strings.HasPrefix(key, "https|") {
						distinctTLSCount++
					}
				}
			}
			for _, m := range rule.Mirrors {
				key := backendTransportKey(m.Backend)
				if !activeKeys[key] {
					activeKeys[key] = true
					if strings.HasPrefix(key, "https|") {
						distinctTLSCount++
					}
				}
			}
		}
	}

	desiredCap := 2 * distinctTLSCount
	if desiredCap < 256 {
		desiredCap = 256
	} else if desiredCap > 65536 {
		desiredCap = 65536
	}
	p.getClientSessionCache().SetCapacity(desiredCap)

	p.transportsMu.Lock()
	defer p.transportsMu.Unlock()
	for k, tr := range p.transports {
		if !activeKeys[k] {
			if ic, ok := tr.(idleConnCloser); ok {
				ic.CloseIdleConnections()
			}
			delete(p.transports, k)
		}
	}
}

func (p *Proxy) buildTransport(backend state.InternalBackend) http.RoundTripper {
	key := backendTransportKey(backend)
	if key == "default" {
		return http.DefaultTransport
	}

	p.transportsMu.Lock()
	defer p.transportsMu.Unlock()
	if p.transports == nil {
		p.transports = make(map[string]http.RoundTripper)
	}
	if tr, ok := p.transports[key]; ok {
		return tr
	}

	var tr http.RoundTripper
	if strings.EqualFold(state.ValueOf(backend.AppProtocol), "https") {
		tr = &http.Transport{
			TLSClientConfig: p.buildBackendTLSConfig(backend),
		}
	} else if state.ValueOf(backend.AppProtocol) == "kubernetes.io/h2c" {
		tr = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	} else {
		return http.DefaultTransport
	}

	p.transports[key] = tr
	return tr
}

func (p *Proxy) forwardWebSocket(w http.ResponseWriter, r *http.Request, backend state.InternalBackend, respHeaderModifier *gatewayv1.HTTPHeaderFilter, timeouts *state.InternalTimeouts) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(w.Header(), *respHeaderModifier)
		}
		http.Error(w, "Websocket hijacking not supported", http.StatusInternalServerError)
		return
	}

	reqCtx := r.Context()
	if timeouts != nil && timeouts.Request != nil && *timeouts.Request > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(reqCtx, *timeouts.Request)
		defer cancel()
	}

	backendCtx := reqCtx
	if timeouts != nil && timeouts.BackendRequest != nil && *timeouts.BackendRequest > 0 {
		var cancel context.CancelFunc
		backendCtx, cancel = context.WithTimeout(backendCtx, *timeouts.BackendRequest)
		defer cancel()
	}

	scheme := "http"
	if strings.EqualFold(state.ValueOf(backend.AppProtocol), "https") || strings.EqualFold(state.ValueOf(backend.AppProtocol), "wss") {
		scheme = "https"
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     fmt.Sprintf("%s:%d", backend.Host, backend.Port),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	targetAddr := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
	var backendConn net.Conn
	var err error

	if scheme == "https" {
		tlsConfig := p.buildBackendTLSConfig(backend)
		var d net.Dialer
		backendConn, err = tls.DialWithDialer(&d, "tcp", targetAddr, tlsConfig)
	} else {
		var d net.Dialer
		backendConn, err = d.DialContext(backendCtx, "tcp", targetAddr)
	}

	if err != nil {
		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(w.Header(), *respHeaderModifier)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(backendCtx.Err(), context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer closeConn(backendConn)

	outReq, err := http.NewRequestWithContext(backendCtx, r.Method, targetURL.String(), nil)
	if err != nil {
		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(w.Header(), *respHeaderModifier)
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	outReq.Header = r.Header.Clone()
	for _, k := range hopByHopHeaders {
		if strings.EqualFold(k, "Upgrade") || strings.EqualFold(k, "Connection") {
			continue
		}
		outReq.Header.Del(k)
	}

	p.setForwardedHeaders(outReq, r)

	outReq.Host = r.Host

	log.Log.Info("Forwarding WebSocket handshake", "host", r.Host, "path", r.URL.Path, "target", targetURL.String())

	if err := outReq.Write(backendConn); err != nil {
		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(w.Header(), *respHeaderModifier)
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	br := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(w.Header(), *respHeaderModifier)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(backendCtx.Err(), context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer closeConn(resp.Body)

	resp.Header.Del("Alt-Svc")

	if backend.ResponseHeaderModifier != nil {
		modifyHeaders(resp.Header, *backend.ResponseHeaderModifier)
	}
	if respHeaderModifier != nil {
		modifyHeaders(resp.Header, *respHeaderModifier)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		removeHopByHopHeaders(resp.Header)
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			if !isNormalClose(err) {
				log.Log.Error(err, "Failed to copy websocket response body")
			}
			panic(http.ErrAbortHandler)
		}
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer closeConn(clientConn)

	if err := resp.Write(clientConn); err != nil {
		return
	}

	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		bufferedBytes, err := io.ReadAll(io.LimitReader(clientBuf, int64(clientBuf.Reader.Buffered())))
		if err != nil {
			log.Log.Error(err, "Failed to read buffered websocket client data")
			return
		}
		if len(bufferedBytes) > 0 {
			if _, err := backendConn.Write(bufferedBytes); err != nil {
				log.Log.Error(err, "Failed to write buffered bytes to websocket backend")
				return
			}
		}
	}
	if br.Buffered() > 0 {
		bufferedBytes, err := io.ReadAll(io.LimitReader(br, int64(br.Buffered())))
		if err != nil {
			log.Log.Error(err, "Failed to read buffered websocket backend data")
			return
		}
		if len(bufferedBytes) > 0 {
			if _, err := clientConn.Write(bufferedBytes); err != nil {
				log.Log.Error(err, "Failed to write buffered bytes to websocket client")
				return
			}
		}
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errc <- err
	}()
	<-errc
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, backend state.InternalBackend, respHeaderModifier *gatewayv1.HTTPHeaderFilter, respCORS *gatewayv1.HTTPCORSFilter, timeouts *state.InternalTimeouts, retry *state.CompiledHTTPRouteRetry) {
	if isWebSocketRequest(r) {
		p.forwardWebSocket(w, r, backend, respHeaderModifier, timeouts)
		return
	}

	reqCtx := r.Context()
	if timeouts != nil && timeouts.Request != nil && *timeouts.Request > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(reqCtx, *timeouts.Request)
		defer cancel()
	}

	scheme := "http"
	if strings.EqualFold(state.ValueOf(backend.AppProtocol), "https") {
		scheme = "https"
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     fmt.Sprintf("%s:%d", backend.Host, backend.Port),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	var bodyBytes []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	transport := p.buildTransport(backend)

	maxRetries := 0
	if retry != nil && retry.Attempts != nil && *retry.Attempts > 0 {
		maxRetries = *retry.Attempts
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if reqCtx.Err() != nil {
			effectiveCORS := respCORS
			if backend.CORS != nil {
				effectiveCORS = backend.CORS
			}
			if effectiveCORS != nil {
				applyCORSHeaders(w.Header(), r, effectiveCORS, false)
			}
			if backend.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
			}
			if respHeaderModifier != nil {
				modifyHeaders(w.Header(), *respHeaderModifier)
			}
			if errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			} else {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			}
			return
		}

		if attempt > 0 && retry != nil && retry.Backoff != nil && *retry.Backoff > 0 {
			select {
			case <-time.After(*retry.Backoff):
			case <-reqCtx.Done():
				effectiveCORS := respCORS
				if backend.CORS != nil {
					effectiveCORS = backend.CORS
				}
				if effectiveCORS != nil {
					applyCORSHeaders(w.Header(), r, effectiveCORS, false)
				}
				if backend.ResponseHeaderModifier != nil {
					modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
				}
				if respHeaderModifier != nil {
					modifyHeaders(w.Header(), *respHeaderModifier)
				}
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}
		}

		backendCtx := reqCtx
		var cancel context.CancelFunc
		if timeouts != nil && timeouts.BackendRequest != nil && *timeouts.BackendRequest > 0 {
			backendCtx, cancel = context.WithTimeout(reqCtx, *timeouts.BackendRequest)
		}

		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		outReq, err := http.NewRequestWithContext(backendCtx, r.Method, targetURL.String(), bodyReader)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			effectiveCORS := respCORS
			if backend.CORS != nil {
				effectiveCORS = backend.CORS
			}
			if effectiveCORS != nil {
				applyCORSHeaders(w.Header(), r, effectiveCORS, false)
			}
			if backend.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
			}
			if respHeaderModifier != nil {
				modifyHeaders(w.Header(), *respHeaderModifier)
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		outReq.Header = r.Header.Clone()
		removeHopByHopHeaders(outReq.Header)

		p.setForwardedHeaders(outReq, r)

		outReq.Host = r.Host

		log.Log.Info("Forwarding request", "host", r.Host, "path", r.URL.Path, "target", targetURL.String(), "appProtocol", state.ValueOf(backend.AppProtocol), "attempt", attempt)

		resp, err := transport.RoundTrip(outReq)
		if cancel != nil {
			cancel()
		}

		if err != nil {
			if attempt < maxRetries && reqCtx.Err() == nil {
				continue
			}
			effectiveCORS := respCORS
			if backend.CORS != nil {
				effectiveCORS = backend.CORS
			}
			if effectiveCORS != nil {
				applyCORSHeaders(w.Header(), r, effectiveCORS, false)
			}
			if backend.ResponseHeaderModifier != nil {
				modifyHeaders(w.Header(), *backend.ResponseHeaderModifier)
			}
			if respHeaderModifier != nil {
				modifyHeaders(w.Header(), *respHeaderModifier)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(backendCtx.Err(), context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		shouldRetry := false
		if retry != nil && attempt < maxRetries {
			for _, code := range retry.Codes {
				if resp.StatusCode == code {
					shouldRetry = true
					break
				}
			}
		}

		if shouldRetry {
			if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024)); err != nil && !isNormalClose(err) {
				klog.V(2).Infof("failed to drain retry response body: %v", err)
			}
			closeConn(resp.Body)
			continue
		}

		defer closeConn(resp.Body)

		resp.Header.Del("Alt-Svc")

		effectiveCORS := respCORS
		if backend.CORS != nil {
			effectiveCORS = backend.CORS
		}
		if effectiveCORS != nil {
			applyCORSHeaders(resp.Header, r, effectiveCORS, false)
		}

		if backend.ResponseHeaderModifier != nil {
			modifyHeaders(resp.Header, *backend.ResponseHeaderModifier)
		}
		if respHeaderModifier != nil {
			modifyHeaders(resp.Header, *respHeaderModifier)
		}

		removeHopByHopHeaders(resp.Header)

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			if !isNormalClose(err) {
				log.Log.Error(err, "Failed to copy response body")
			}
			panic(http.ErrAbortHandler)
		}
		closeConn(resp.Body)

		for k, vv := range resp.Trailer {
			for _, v := range vv {
				w.Header().Add(http.TrailerPrefix+k, v)
			}
		}
		return
	}
}

func matchOrigin(allowedOrigins []gatewayv1.CORSOrigin, reqOrigin string) bool {
	if len(allowedOrigins) == 0 || reqOrigin == "" {
		return false
	}
	u, err := url.Parse(reqOrigin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	reqScheme := strings.ToLower(u.Scheme)
	reqHost := u.Hostname()
	reqPort := u.Port()
	if reqPort == "" {
		if reqScheme == "http" {
			reqPort = "80"
		} else if reqScheme == "https" {
			reqPort = "443"
		}
	}

	for _, allowed := range allowedOrigins {
		allowedStr := string(allowed)
		if allowedStr == "*" {
			return true
		}
		au, err := url.Parse(allowedStr)
		if err != nil || au.Scheme == "" || au.Host == "" {
			continue
		}
		allowedScheme := strings.ToLower(au.Scheme)
		allowedHost := au.Hostname()
		allowedPort := au.Port()
		if allowedPort == "" {
			if allowedScheme == "http" {
				allowedPort = "80"
			} else if allowedScheme == "https" {
				allowedPort = "443"
			}
		}

		if allowedScheme != reqScheme {
			continue
		}
		if allowedPort != reqPort {
			continue
		}

		if allowedHost == "*" {
			return true
		}
		if strings.HasPrefix(allowedHost, "*.") {
			suffix := strings.ToLower(allowedHost[1:])
			reqHostLower := strings.ToLower(reqHost)
			if strings.HasSuffix(reqHostLower, suffix) && len(reqHostLower) > len(suffix) {
				return true
			}
		}
		if strings.EqualFold(allowedHost, reqHost) {
			return true
		}
	}
	return false
}

func containsWildcardOrigin(origins []gatewayv1.CORSOrigin) bool {
	for _, o := range origins {
		if string(o) == "*" {
			return true
		}
	}
	return false
}

func containsWildcardMethod(methods []gatewayv1.HTTPMethodWithWildcard) bool {
	for _, m := range methods {
		if string(m) == "*" {
			return true
		}
	}
	return false
}

func containsWildcardHeader(headers []gatewayv1.HTTPHeaderName) bool {
	for _, h := range headers {
		if string(h) == "*" {
			return true
		}
	}
	return false
}

func applyCORSHeaders(header http.Header, r *http.Request, cors *gatewayv1.HTTPCORSFilter, isPreflight bool) bool {
	if cors == nil {
		return false
	}
	reqOrigin := r.Header.Get("Origin")
	if reqOrigin == "" {
		return false
	}
	if !matchOrigin(cors.AllowOrigins, reqOrigin) {
		return false
	}

	allowCredentials := cors.AllowCredentials != nil && *cors.AllowCredentials

	// Access-Control-Allow-Origin
	if allowCredentials {
		header.Set("Access-Control-Allow-Origin", reqOrigin)
	} else if containsWildcardOrigin(cors.AllowOrigins) {
		header.Set("Access-Control-Allow-Origin", "*")
	} else {
		header.Set("Access-Control-Allow-Origin", reqOrigin)
	}

	// Access-Control-Allow-Credentials
	if allowCredentials {
		header.Set("Access-Control-Allow-Credentials", "true")
	} else {
		header.Del("Access-Control-Allow-Credentials")
		for k := range header {
			if strings.EqualFold(k, "Access-Control-Allow-Credentials") {
				delete(header, k)
			}
		}
	}

	// Access-Control-Expose-Headers
	if len(cors.ExposeHeaders) > 0 {
		if containsWildcardHeader(cors.ExposeHeaders) {
			if !allowCredentials {
				header.Set("Access-Control-Expose-Headers", "*")
			}
		} else {
			headers := make([]string, len(cors.ExposeHeaders))
			for i, h := range cors.ExposeHeaders {
				headers[i] = string(h)
			}
			header.Set("Access-Control-Expose-Headers", strings.Join(headers, ", "))
		}
	}

	if isPreflight {
		// Access-Control-Allow-Methods
		if len(cors.AllowMethods) > 0 {
			if containsWildcardMethod(cors.AllowMethods) {
				reqMethod := r.Header.Get("Access-Control-Request-Method")
				if reqMethod != "" {
					header.Set("Access-Control-Allow-Methods", reqMethod)
				} else if !allowCredentials {
					header.Set("Access-Control-Allow-Methods", "*")
				}
			} else {
				methods := make([]string, len(cors.AllowMethods))
				for i, m := range cors.AllowMethods {
					methods[i] = string(m)
				}
				header.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
			}
		}

		// Access-Control-Allow-Headers
		if len(cors.AllowHeaders) > 0 {
			if containsWildcardHeader(cors.AllowHeaders) {
				reqHeaders := r.Header.Get("Access-Control-Request-Headers")
				if reqHeaders != "" {
					header.Set("Access-Control-Allow-Headers", reqHeaders)
				} else if !allowCredentials {
					header.Set("Access-Control-Allow-Headers", "*")
				}
			} else {
				headers := make([]string, len(cors.AllowHeaders))
				for i, h := range cors.AllowHeaders {
					headers[i] = string(h)
				}
				header.Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
			}
		}

		// Access-Control-Max-Age
		maxAge := cors.MaxAge
		if maxAge <= 0 {
			maxAge = 5
		}
		header.Set("Access-Control-Max-Age", strconv.Itoa(int(maxAge)))
	}

	return true
}

// pickBackend selects a backend from the list based on their weights.
// If all backends have weight 0 or the list is empty, an error is returned.
func pickBackend(backends []state.InternalBackend) (state.InternalBackend, error) {
	return state.PickBackend(backends)
}

func (p *Proxy) mirror(r *http.Request, bodyBytes []byte, backend state.InternalBackend, timeouts *state.InternalTimeouts) {
	go func() {
		timeout := 30 * time.Second
		if timeouts != nil && timeouts.BackendRequest != nil && *timeouts.BackendRequest > 0 {
			timeout = *timeouts.BackendRequest
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}

		mirrorReq, targetURL, err := p.buildBackendRequest(ctx, r, backend, body)
		if err != nil {
			log.Log.Error(err, "Failed to create mirror request")
			return
		}

		transport := p.buildTransport(backend)
		log.Log.Info("Mirroring request", "host", mirrorReq.Host, "path", mirrorReq.URL.Path, "target", targetURL.String())

		resp, err := transport.RoundTrip(mirrorReq)
		if err != nil {
			log.Log.Error(err, "Failed to send mirrored request", "target", targetURL.String())
			return
		}
		defer closeConn(resp.Body)
		if _, err := io.Copy(io.Discard, resp.Body); err != nil && !isNormalClose(err) {
			klog.V(2).Infof("failed to discard mirrored response body: %v", err)
		}
	}()
}
