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

package proxyproto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// RejectedConnectionsTotal tracks the total number of connections rejected by the listener.
	RejectedConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gari_rejected_connections_total",
			Help: "Total number of connections rejected by the listener filter.",
		},
		[]string{"reason"},
	)
)

func init() {
	if err := crmetrics.Registry.Register(RejectedConnectionsTotal); err != nil {
		klog.V(4).Infof("registering RejectedConnectionsTotal metric: %v", err)
	}
}

// ListenerOptions configures source filtering and PROXY protocol parsing on a Listener.
type ListenerOptions struct {
	// AllowedSourceCIDRs is a list of CIDRs permitted to connect to this listener.
	// If empty, all source IPs are allowed.
	AllowedSourceCIDRs []string

	// ProxyProtocolTrustedCIDRs is a list of CIDRs from which PROXY headers are parsed.
	// If a connection's source IP is not in this list, no PROXY header is parsed,
	// and the original remote address is preserved.
	ProxyProtocolTrustedCIDRs []string

	// ProxyProtocol enables PROXY protocol parsing when set to "enabled".
	// If empty or "disabled", PROXY headers are not parsed.
	ProxyProtocol string
}

// Listener wraps a net.Listener to enforce source CIDR allowlists and parse
// PROXY headers strictly from trusted CIDRs.
type Listener struct {
	net.Listener
	mu           sync.RWMutex
	allowedCIDRs []*net.IPNet
	trustedCIDRs []*net.IPNet
	proxyEnabled bool
}

// NewListener creates a new filtered Listener wrapping the provided net.Listener.
func NewListener(lis net.Listener, opts ListenerOptions) (*Listener, error) {
	l := &Listener{
		Listener: lis,
	}
	if err := l.UpdateOptions(opts); err != nil {
		return nil, err
	}
	return l, nil
}

// UpdateOptions dynamically updates the listener's CIDR filters and PROXY protocol settings.
func (l *Listener) UpdateOptions(opts ListenerOptions) error {
	allowed, err := ParseCIDRs(opts.AllowedSourceCIDRs)
	if err != nil {
		return fmt.Errorf("parsing allowedSourceCIDRs: %w", err)
	}

	trusted, err := ParseCIDRs(opts.ProxyProtocolTrustedCIDRs)
	if err != nil {
		return fmt.Errorf("parsing proxyProtocolTrustedCIDRs: %w", err)
	}

	enabled := strings.EqualFold(opts.ProxyProtocol, "enabled") || (opts.ProxyProtocol == "" && len(trusted) > 0)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.allowedCIDRs = allowed
	l.trustedCIDRs = trusted
	l.proxyEnabled = enabled
	return nil
}

func closeConn(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		_ = err
	}
}

// Accept waits for and returns the next connection to the listener.
// Connections from sources outside AllowedSourceCIDRs are closed immediately before TLS.
// For sources within ProxyProtocolTrustedCIDRs, a connection is returned immediately
// that parses the PROXY header lazily in its own goroutine on first Read or RemoteAddr.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		l.mu.RLock()
		allowed := l.allowedCIDRs
		trusted := l.trustedCIDRs
		proxyEnabled := l.proxyEnabled
		l.mu.RUnlock()

		remoteIP := extractIP(conn.RemoteAddr())

		// 1. Check allowedSourceCIDRs: close connection immediately if not allowed.
		if len(allowed) > 0 {
			if !matchIP(remoteIP, allowed) {
				RejectedConnectionsTotal.WithLabelValues("disallowed_source").Inc()
				klog.V(3).Infof("proxyproto: rejecting connection from %v: source IP not in allowedSourceCIDRs", conn.RemoteAddr())
				closeConn(conn)
				continue
			}
		}

		// 2. Check proxyProtocolTrustedCIDRs: parse PROXY header lazily in the connection's goroutine.
		if proxyEnabled && len(trusted) > 0 && matchIP(remoteIP, trusted) {
			return newLazyConn(conn, 5*time.Second), nil
		}

		// Remote IP is not in trusted CIDRs or proxy protocol is disabled:
		// Do not parse PROXY header, preserve real RemoteAddr.
		return conn, nil
	}
}

// lazyConn parses the PROXY protocol header on first Read or RemoteAddr call.
type lazyConn struct {
	net.Conn
	timeout    time.Duration
	once       sync.Once
	header     *Header
	headerErr  error
	buffered   []byte
	bufOffset  int
	remoteAddr net.Addr
	localAddr  net.Addr
}

func newLazyConn(conn net.Conn, timeout time.Duration) *lazyConn {
	return &lazyConn{
		Conn:    conn,
		timeout: timeout,
	}
}

func (c *lazyConn) parseHeader() {
	if c.timeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			c.headerErr = err
			RejectedConnectionsTotal.WithLabelValues("bad_proxy_header").Inc()
			klog.V(3).Infof("proxyproto: rejecting connection from %v: set deadline error: %v", c.Conn.RemoteAddr(), err)
			closeConn(c.Conn)
			return
		}
	}

	bufReader := bufio.NewReader(c.Conn)
	hdr, err := Decode(bufReader)
	if c.timeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Time{}); err != nil {
			c.headerErr = err
			RejectedConnectionsTotal.WithLabelValues("bad_proxy_header").Inc()
			klog.V(3).Infof("proxyproto: rejecting connection from %v: clear deadline error: %v", c.Conn.RemoteAddr(), err)
			closeConn(c.Conn)
			return
		}
	}

	if err != nil {
		c.headerErr = err
		RejectedConnectionsTotal.WithLabelValues("bad_proxy_header").Inc()
		klog.V(3).Infof("proxyproto: rejecting connection from %v: failed to decode PROXY header: %v", c.Conn.RemoteAddr(), err)
		closeConn(c.Conn)
		return
	}

	c.header = hdr
	if bufReader.Buffered() > 0 {
		c.buffered = make([]byte, bufReader.Buffered())
		if _, err := io.ReadFull(bufReader, c.buffered); err != nil {
			c.headerErr = err
			RejectedConnectionsTotal.WithLabelValues("bad_proxy_header").Inc()
			klog.V(3).Infof("proxyproto: rejecting connection from %v: failed to read buffered bytes: %v", c.Conn.RemoteAddr(), err)
			closeConn(c.Conn)
			return
		}
	}

	if hdr.Command == CommandProxy && hdr.SrcAddr != nil {
		c.remoteAddr = hdr.SrcAddr
	} else {
		c.remoteAddr = c.Conn.RemoteAddr()
	}

	if hdr.DstAddr != nil {
		c.localAddr = hdr.DstAddr
	} else {
		c.localAddr = c.Conn.LocalAddr()
	}
}

func (c *lazyConn) RemoteAddr() net.Addr {
	c.once.Do(c.parseHeader)
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}

func (c *lazyConn) LocalAddr() net.Addr {
	c.once.Do(c.parseHeader)
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.Conn.LocalAddr()
}

func (c *lazyConn) Read(b []byte) (int, error) {
	c.once.Do(c.parseHeader)
	if c.headerErr != nil {
		return 0, c.headerErr
	}
	if len(c.buffered) > 0 {
		n := copy(b, c.buffered[c.bufOffset:])
		c.bufOffset += n
		if c.bufOffset >= len(c.buffered) {
			c.buffered = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *lazyConn) WriteTo(w io.Writer) (int64, error) {
	c.once.Do(c.parseHeader)
	if c.headerErr != nil {
		return 0, c.headerErr
	}
	var n int64
	if c.buffered != nil {
		rem := c.buffered[c.bufOffset:]
		c.buffered = nil
		nw, err := w.Write(rem)
		n += int64(nw)
		if err != nil {
			return n, err
		}
	}
	if wt, ok := c.Conn.(io.WriterTo); ok {
		nw, err := wt.WriteTo(w)
		return n + nw, err
	}
	nw, err := io.Copy(w, c.Conn)
	return n + nw, err
}

func (c *lazyConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(c.Conn, r)
}

// ParseCIDRs parses a list of CIDR strings into []*net.IPNet.
// Items can be comma-separated or separate list elements.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	var result []*net.IPNet
	for _, entry := range cidrs {
		parts := strings.Split(entry, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", trimmed, err)
			}
			result = append(result, ipNet)
		}
	}
	return result, nil
}

func extractIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			return ip4
		}
		return tcpAddr.IP
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			return ip4
		}
		return udpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
	}
	return ip
}

func matchIP(ip net.IP, cidrs []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
