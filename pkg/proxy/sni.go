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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type sniListener struct {
	rawLis      net.Listener
	p           *Proxy
	httpsConnCh chan net.Conn
	closed      atomic.Bool
	closeOnce   sync.Once
	done        chan struct{}
	activeConns atomic.Int64
}

type countedConn struct {
	net.Conn
	onClose func()
	closed  atomic.Bool
}

func wrapCountedConn(c net.Conn, onClose func()) net.Conn {
	return &countedConn{
		Conn:    c,
		onClose: onClose,
	}
}

func (c *countedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.onClose != nil {
			c.onClose()
		}
	}
	return c.Conn.Close()
}

func (c *countedConn) CloseWrite() error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// NewSNIListener creates a net.Listener that wraps rawLis, inspects TLS SNI on incoming connections,
// splices TLS Passthrough connections directly to their backend, and forwards matching HTTPS connections
// to callers of Accept(). Connections matching no listener or non-matching routes are closed without response.
func (p *Proxy) NewSNIListener(rawLis net.Listener) net.Listener {
	l := &sniListener{
		rawLis:      rawLis,
		p:           p,
		httpsConnCh: make(chan net.Conn, 128),
		done:        make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func closeConn(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		klog.V(2).Infof("failed to close connection: %v", err)
	}
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func copyAndCloseWrite(dst, src net.Conn, idleTimeout time.Duration) error {
	var errs []error
	if err := copyWithIdleTimeout(dst, src, idleTimeout); err != nil && !isNormalClose(err) {
		errs = append(errs, err)
	}
	if err := closeWrite(dst); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// copyWithIdleTimeout copies data from src to dst while refreshing read deadlines on each copy.
// Note: enabling idle timeout gives up io.Copy's ReaderFrom fast path (kernel splice on Linux for TCP<->TCP).
func copyWithIdleTimeout(dst, src net.Conn, idleTimeout time.Duration) error {
	if idleTimeout <= 0 {
		_, err := io.Copy(dst, src)
		return err
	}

	buf := make([]byte, 32*1024)
	for {
		if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			klog.V(2).Infof("failed to set read deadline on source connection: %v", err)
			return err
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				klog.V(2).Infof("failed to refresh read deadline on source connection: %v", err)
				return err
			}
			if err := dst.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				klog.V(2).Infof("failed to refresh read deadline on destination connection: %v", err)
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

func (l *sniListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn := <-l.httpsConnCh:
		select {
		case <-l.done:
			closeConn(conn)
			return nil, net.ErrClosed
		default:
			return conn, nil
		}
	}
}

func (l *sniListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.done)
		err = l.rawLis.Close()

		// Drain and close any queued connections after closing done.
		for {
			select {
			case c := <-l.httpsConnCh:
				closeConn(c)
			default:
				return
			}
		}
	})
	return err
}

func (l *sniListener) Addr() net.Addr {
	return l.rawLis.Addr()
}

func (l *sniListener) acceptLoop() {
	for {
		conn, err := l.rawLis.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			select {
			case <-l.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}

		maxConns := int64(l.p.getTCPMaxConnections())
		if maxConns > 0 && l.activeConns.Add(1) > maxConns {
			l.activeConns.Add(-1)
			closeConn(conn)
			continue
		}

		wrapped := wrapCountedConn(conn, func() {
			l.activeConns.Add(-1)
		})

		cfg := l.p.sniConfig.Load()
		if cfg == nil || !cfg.hasPassthrough {
			select {
			case <-l.done:
				closeConn(wrapped)
			case l.httpsConnCh <- wrapped:
			}
			continue
		}

		go l.handleConn(wrapped, cfg)
	}
}

func (l *sniListener) handleConn(conn net.Conn, cfg *sniConfig) {
	sniHostname, peekedConn, err := sni.SniffSNI(conn, 5*time.Second)
	if peekedConn == nil {
		peekedConn = conn
	}
	handedOff := false
	defer func() {
		if !handedOff {
			closeConn(peekedConn)
		}
	}()

	if err != nil && !errors.Is(err, sni.ErrNoSNI) {
		return
	}

	handOffToHTTPS := func() {
		select {
		case l.httpsConnCh <- peekedConn:
			handedOff = true
		case <-l.done:
		}
	}

	candidates := cfg.candidates
	if len(candidates) == 0 {
		handOffToHTTPS()
		return
	}

	matched, matchType := state.MatchListeners(candidates, sniHostname)
	if matchType != state.NoMatch && len(matched) > 0 {
		selected := matched[0]
		if selected.Protocol == gatewayv1.TLSProtocolType && selected.TLSMode != nil && *selected.TLSMode == gatewayv1.TLSModePassthrough {
			backend, ok := selected.SelectTLSBackend(sniHostname)
			if !ok || backend.Target == "" {
				return
			}
			handedOff = true
			l.spliceToBackend(peekedConn, backend.Target)
			return
		}

		if selected.Protocol == gatewayv1.TLSProtocolType && (selected.TLSMode == nil || *selected.TLSMode == gatewayv1.TLSModeTerminate) {
			backend, ok := selected.SelectTLSBackend(sniHostname)
			if !ok || backend.Target == "" {
				klog.Errorf("no backend resolved for SNI %q on listener %q", sniHostname, selected.Name)
				return
			}
			handedOff = true
			l.terminateTLSToBackend(peekedConn, sniHostname, backend)
			return
		}

		if selected.Protocol == gatewayv1.HTTPSProtocolType {
			// All HTTPS ports collapse onto 8443 behind the Service, so per-port CA pools
			// are distinguished by hostname; two validated listeners on different ports with
			// the same hostname cannot be told apart.
			handOffToHTTPS()
			return
		}
	}

	// If an SNI was provided and matched no listener: fail closed.
	if sniHostname != "" {
		return
	}

	// No SNI provided (e.g. direct IP connection): hand to HTTPS server
	handOffToHTTPS()
}

func (l *sniListener) terminateTLSToBackend(clientConn net.Conn, sniHostname string, backend state.InternalTLSBackend) {
	select {
	case <-l.done:
		closeConn(clientConn)
		return
	default:
	}

	if !l.p.HasCertificate(sniHostname) {
		klog.Errorf("no certificate found for SNI %q", sniHostname)
		closeConn(clientConn)
		return
	}

	tlsConn := tls.Server(clientConn, l.p.TLSConfig())
	if err := clientConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		klog.V(2).Infof("failed to set deadline for TLS handshake: %v", err)
		closeConn(clientConn)
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		closeConn(clientConn)
		return
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		klog.V(2).Infof("failed to clear deadline after TLS handshake: %v", err)
		closeConn(tlsConn)
		return
	}

	if backend.Error != nil {
		klog.Errorf("cannot proxy to backend %s: %s", backend.Target, backend.Error.HTTPMessage)
		closeConn(tlsConn)
		return
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var backendConn net.Conn
	var err error
	if backend.TLSConfig != nil {
		// ServerName is derived from backend.TLSConfig.Hostname; Host is omitted.
		tlsConfig := l.p.buildBackendTLSConfig(state.InternalBackend{
			TLSConfig: backend.TLSConfig,
		})
		backendConn, err = tls.DialWithDialer(dialer, "tcp", backend.Target, tlsConfig)
	} else {
		backendConn, err = dialer.Dial("tcp", backend.Target)
	}
	if err != nil {
		klog.Errorf("failed to dial backend %q: %v", backend.Target, err)
		closeConn(tlsConn)
		return
	}

	idleTimeout := l.p.getTCPIdleTimeout()
	go spliceConns(tlsConn, backendConn, idleTimeout)
}

func (l *sniListener) spliceToBackend(clientConn net.Conn, backend string) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	backendConn, err := dialer.Dial("tcp", backend)
	if err != nil {
		closeConn(clientConn)
		return
	}

	idleTimeout := l.p.getTCPIdleTimeout()
	go spliceConns(clientConn, backendConn, idleTimeout)
}

func spliceConns(c1, c2 net.Conn, idleTimeout time.Duration) {
	defer closeConn(c1)
	defer closeConn(c2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		err := copyAndCloseWrite(c2, c1, idleTimeout)
		if err != nil {
			if !isNormalClose(err) {
				klog.V(2).Infof("splice copy error: %v", err)
			}
			closeConn(c1)
			closeConn(c2)
		}
	}()

	go func() {
		defer wg.Done()
		err := copyAndCloseWrite(c1, c2, idleTimeout)
		if err != nil {
			if !isNormalClose(err) {
				klog.V(2).Infof("splice copy error: %v", err)
			}
			closeConn(c1)
			closeConn(c2)
		}
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			klog.V(2).Infof("failed to close write: %v", err)
			return err
		}
	} else if pc, ok := conn.(*sni.PeekedConn); ok {
		if cw, ok := pc.RawConn().(closeWriter); ok {
			if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
				klog.V(2).Infof("failed to close write: %v", err)
				return err
			}
		}
	}
	return nil
}
