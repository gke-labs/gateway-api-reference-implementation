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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

func TestManager_EndToEnd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	if err != nil {
		t.Fatalf("reading server.crt: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "server.key"))
	if err != nil {
		t.Fatalf("reading server.key: %v", err)
	}
	clientCertPEM, err := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	if err != nil {
		t.Fatalf("reading client.crt: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "client.key"))
	if err != nil {
		t.Fatalf("reading client.key: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	mgr := NewManager(c, WithBackoff(50*time.Millisecond, 200*time.Millisecond))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	parsedCerts, err := certs.ParseCertificatesFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("parsing ca cert PEM: %v", err)
	}
	caFP := fmt.Sprintf("%x", sha256.Sum256(parsedCerts[0].Raw))
	clientID := fmt.Sprintf("%s/mgr-client", caFP)

	// 1. Update hostnames on manager
	mgr.UpdateHostnames([]string{"app1.example.com", "*.wildcard.org"})

	// Poll until registration table reflects hostnames
	var regHosts []string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		regHosts = srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
		slices.Sort(regHosts)
		if slices.Equal(regHosts, []string{"*.wildcard.org", "app1.example.com"}) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !slices.Equal(regHosts, []string{"*.wildcard.org", "app1.example.com"}) {
		t.Fatalf("registered hostnames mismatch, got %v", regHosts)
	}

	// 2. Start an HTTPS server on mgr.HTTPSListener()
	tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}

	tlsLis := tls.NewListener(mgr.HTTPSListener(), &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})

	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("response from " + r.Host))
		}),
	}
	defer httpSrv.Close()

	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	// 3. Connect as external client with matching SNI
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app1.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "app1.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("https://app1.example.com/test")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// 4. Update hostnames dynamically: remove app1.example.com, add app2.example.com
	mgr.UpdateHostnames([]string{"app2.example.com"})

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		regHosts = srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
		if slices.Equal(regHosts, []string{"app2.example.com"}) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !slices.Equal(regHosts, []string{"app2.example.com"}) {
		t.Fatalf("registered hostnames mismatch after update, got %v", regHosts)
	}

	// app2.example.com should now succeed
	httpApp2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app2.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "app2.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp2, err := httpApp2Client.Get("https://app2.example.com/test")
	if err != nil {
		t.Fatalf("HTTP GET app2 failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for app2, got %d", resp2.StatusCode)
	}

	// app1.example.com should now fail / be closed
	_, err = httpClient.Get("https://app1.example.com/test")
	if err == nil {
		t.Fatalf("expected GET app1 to fail after unregistration, but succeeded")
	}
}

func TestManager_SessionReconnect(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-reconn-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	if err != nil {
		t.Fatalf("reading server.crt: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "server.key"))
	if err != nil {
		t.Fatalf("reading server.key: %v", err)
	}
	clientCertPEM, err := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	if err != nil {
		t.Fatalf("reading client.crt: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "client.key"))
	if err != nil {
		t.Fatalf("reading client.key: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	mgr := NewManager(c, WithBackoff(50*time.Millisecond, 100*time.Millisecond))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	mgr.UpdateHostnames([]string{"echo.snigateway.test"})

	tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}

	tlsLis := tls.NewListener(mgr.HTTPSListener(), &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})

	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("response from " + r.Host))
		}),
	}
	defer httpSrv.Close()

	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	parsedCerts, err := certs.ParseCertificatesFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("parsing ca cert PEM: %v", err)
	}
	caFP := fmt.Sprintf("%x", sha256.Sum256(parsedCerts[0].Raw))
	clientID := fmt.Sprintf("%s/mgr-client", caFP)

	// Wait for initial registration
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		regHosts := srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
		if slices.Equal(regHosts, []string{"echo.snigateway.test"}) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "echo.snigateway.test",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "echo.snigateway.test",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("https://echo.snigateway.test/test")
	if err != nil {
		t.Fatalf("initial HTTP GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestManager_SharedTargetDialingAndProxyHeader(t *testing.T) {
	mgr := NewManager(nil)
	defer mgr.HTTPSListener().Close()
	defer mgr.HTTPListener().Close()

	// Test with connection scenarios representing TLS and plain HTTP streams
	testCases := []struct {
		name          string
		srcIP         string
		dstIP         string
		srcPort       uint16
		dstPort       uint16
		payload       []byte
		wantListener  func(m *Manager) *Listener
		otherListener func(m *Manager) *Listener
	}{
		{
			name:          "TLS_Handshake_Record",
			srcIP:         "192.0.2.10",
			dstIP:         "198.51.100.1",
			srcPort:       54321,
			dstPort:       443,
			payload:       []byte("\x16\x03\x01\x00\x05hello"),
			wantListener:  func(m *Manager) *Listener { return m.HTTPSListener() },
			otherListener: func(m *Manager) *Listener { return m.HTTPListener() },
		},
		{
			name:          "Plain_HTTP_Request",
			srcIP:         "192.0.2.10",
			dstIP:         "198.51.100.1",
			srcPort:       54321,
			dstPort:       80,
			payload:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantListener:  func(m *Manager) *Listener { return m.HTTPListener() },
			otherListener: func(m *Manager) *Listener { return m.HTTPSListener() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()

			hdr := &proxyproto.Header{
				Command: proxyproto.CommandProxy,
				SrcAddr: &net.TCPAddr{IP: net.ParseIP(tc.srcIP), Port: int(tc.srcPort)},
				DstAddr: &net.TCPAddr{IP: net.ParseIP(tc.dstIP), Port: int(tc.dstPort)},
			}
			encodedHdr, err := hdr.Format()
			if err != nil {
				t.Fatalf("hdr.Format failed: %v", err)
			}

			// In a goroutine, write header + payload to c1
			go func() {
				_, _ = c1.Write(encodedHdr)
				_, _ = c1.Write(tc.payload)
			}()

			// Call the shared backend method handleTunnelConn
			errCh := make(chan error, 1)
			go func() {
				errCh <- mgr.handleTunnelConn(c2)
			}()

			// Accept from the expected manager listener
			acceptedConn, err := tc.wantListener(mgr).Accept()
			if err != nil {
				t.Fatalf("Listener.Accept failed: %v", err)
			}
			defer acceptedConn.Close()

			if err := <-errCh; err != nil {
				t.Fatalf("handleTunnelConn failed: %v", err)
			}

			// Verify other listener did not receive the connection
			select {
			case unexpected := <-tc.otherListener(mgr).connCh:
				unexpected.Close()
				t.Fatalf("expected other listener to receive nothing, but got a connection")
			default:
			}

			// Verify addresses from PROXY header
			pConn, ok := acceptedConn.(*proxyproto.Conn)
			if !ok {
				t.Fatalf("expected *proxyproto.Conn, got %T", acceptedConn)
			}

			if pConn.RemoteAddr().String() != fmt.Sprintf("%s:%d", tc.srcIP, tc.srcPort) {
				t.Errorf("expected RemoteAddr %s:%d, got %s", tc.srcIP, tc.srcPort, pConn.RemoteAddr())
			}
			if pConn.LocalAddr().String() != fmt.Sprintf("%s:%d", tc.dstIP, tc.dstPort) {
				t.Errorf("expected LocalAddr %s:%d, got %s", tc.dstIP, tc.dstPort, pConn.LocalAddr())
			}

			// Verify payload read and that the first byte is preserved
			buf := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(pConn, buf); err != nil {
				t.Fatalf("reading payload failed: %v", err)
			}
			if !bytes.Equal(buf, tc.payload) {
				t.Errorf("expected payload %q, got %q", tc.payload, buf)
			}
			if buf[0] != tc.payload[0] {
				t.Errorf("first byte mismatch: got 0x%02x, want 0x%02x", buf[0], tc.payload[0])
			}
		})
	}
}

func TestManager_TunnelStateRegistrationAndNotifications(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-state-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	if err != nil {
		t.Fatalf("reading server.crt: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "server.key"))
	if err != nil {
		t.Fatalf("reading server.key: %v", err)
	}
	clientCertPEM, err := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	if err != nil {
		t.Fatalf("reading client.crt: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "client.key"))
	if err != nil {
		t.Fatalf("reading client.key: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer ln.Close()

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	cli := client.NewClient(ln.Addr().String(), clientTLS)

	mgr := NewManager(cli,
		WithPoolSize(2),
		WithBackoff(20*time.Millisecond, 100*time.Millisecond),
	)

	notifyCh := make(chan struct{}, 100)
	mgr.AddStateChangeListener(func() {
		select {
		case notifyCh <- struct{}{}:
		default:
		}
	})

	if mgr.IsConnected() {
		t.Fatalf("expected IsConnected=false initially")
	}
	if mgr.HasRegisteredHostnames([]string{"echo.example.com"}) {
		t.Fatalf("expected HasRegisteredHostnames=false initially")
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	mgrDone := make(chan error, 1)
	go func() {
		mgrDone <- mgr.Run(runCtx)
	}()

	// Wait for connection notification
	deadline := time.Now().Add(5 * time.Second)
	for !mgr.IsConnected() && time.Now().Before(deadline) {
		select {
		case <-notifyCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !mgr.IsConnected() {
		t.Fatalf("timed out waiting for Manager to connect")
	}

	// Register hostnames
	mgr.UpdateHostnames([]string{"echo.example.com"})

	deadline = time.Now().Add(5 * time.Second)
	for !mgr.HasRegisteredHostnames([]string{"echo.example.com"}) && time.Now().Before(deadline) {
		select {
		case <-notifyCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !mgr.HasRegisteredHostnames([]string{"echo.example.com"}) {
		t.Fatalf("expected HasRegisteredHostnames([echo.example.com])=true")
	}

	// Unregistered hostname must return false
	if mgr.HasRegisteredHostnames([]string{"other.example.com"}) {
		t.Fatalf("expected HasRegisteredHostnames([other.example.com])=false")
	}

	// Cancel session
	runCancel()
	<-mgrDone

	if mgr.IsConnected() {
		t.Fatalf("expected IsConnected=false after cancel")
	}
	if mgr.HasRegisteredHostnames([]string{"echo.example.com"}) {
		t.Fatalf("expected HasRegisteredHostnames=false after cancel")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

type fakeFrontendWireGuardDevice struct {
	mu    sync.Mutex
	peers map[wireguard.Key]wireguard.Peer
}

func (f *fakeFrontendWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeFrontendWireGuardDevice) RemovePeer(key wireguard.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}

type fakeMgrTestWireGuardDevice struct {
	mu      sync.Mutex
	peer    wireguard.Peer
	hasPeer bool
	closed  bool
}

func (f *fakeMgrTestWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peer = peer
	f.hasPeer = true
	return nil
}

func (f *fakeMgrTestWireGuardDevice) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeMgrTestWireGuardDevice) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeMgrTestWireGuardDevice) getPeer() (wireguard.Peer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peer, f.hasPeer
}

type fakeTunnelConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *fakeTunnelConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

type fakeTunnelListener struct {
	net.Listener
	defaultRemoteIP    net.IP
	mu                 sync.Mutex
	overrideRemoteAddr net.Addr
}

func (l *fakeTunnelListener) setOverrideRemoteAddr(addr net.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.overrideRemoteAddr = addr
}

func (l *fakeTunnelListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	override := l.overrideRemoteAddr
	l.mu.Unlock()

	remoteAddr := override
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{IP: l.defaultRemoteIP, Port: 51820}
	}
	return &fakeTunnelConn{Conn: conn, remoteAddr: remoteAddr}, nil
}

type fixtureOptions struct {
	frontendWireGuard bool
	managerWireGuard  bool
}

type wireguardFixture struct {
	server           *frontend.Server
	serverListener   net.Listener
	frontendKey      wireguard.Key
	prefixNet        *net.IPNet
	frontendTunnelIP net.IP
	manager          *Manager

	devMu      sync.Mutex
	devices    []*fakeMgrTestWireGuardDevice
	devConfigs []wireguard.Config

	listenMu        sync.Mutex
	listenAddrs     []string
	tunnelListeners []*fakeTunnelListener

	srvErrCh  chan error
	mgrErrCh  chan error
	mgrCancel context.CancelFunc
}

func newWireGuardFixture(t *testing.T, opts fixtureOptions) *wireguardFixture {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "mgr-client")
	if err != nil {
		t.Fatalf("GenerateAll failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	feTunnelIP := make(net.IP, 16)
	copy(feTunnelIP, prefixNet.IP.To16())
	feTunnelIP[15] = 1

	srvCfg := frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
	}
	if opts.frontendWireGuard {
		srvCfg.WireGuardDevice = &fakeFrontendWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		srvCfg.WireGuardPublicKey = feKey
		srvCfg.WireGuardPort = 51820
		srvCfg.WireGuardPrefix = prefixNet
	}

	srv, err := frontend.NewServer(srvCfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	f := &wireguardFixture{
		server:           srv,
		serverListener:   serverLn,
		frontendKey:      feKey,
		prefixNet:        prefixNet,
		frontendTunnelIP: feTunnelIP,
		srvErrCh:         make(chan error, 1),
		mgrErrCh:         make(chan error, 1),
	}

	go func() {
		f.srvErrCh <- srv.Serve(serverLn)
	}()

	opener := func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
		f.devMu.Lock()
		defer f.devMu.Unlock()
		dev := &fakeMgrTestWireGuardDevice{}
		f.devices = append(f.devices, dev)
		f.devConfigs = append(f.devConfigs, cfg)
		return dev, nil
	}

	listenFunc := func(network, address string) (net.Listener, error) {
		f.listenMu.Lock()
		defer f.listenMu.Unlock()
		f.listenAddrs = append(f.listenAddrs, address)
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		tunLn := &fakeTunnelListener{Listener: rawLn, defaultRemoteIP: feTunnelIP}
		f.tunnelListeners = append(f.tunnelListeners, tunLn)
		return tunLn, nil
	}

	c := client.NewClient(serverLn.Addr().String(), clientTLS)
	f.manager = NewManager(c,
		WithWireGuard(opts.managerWireGuard),
		WithWireGuardDeviceOpener(opener),
		WithListenFunc(listenFunc),
		WithBackoff(10*time.Millisecond, 50*time.Millisecond),
	)

	mgrCtx, mgrCancel := context.WithCancel(t.Context())
	f.mgrCancel = mgrCancel
	go func() {
		f.mgrErrCh <- f.manager.Run(mgrCtx)
	}()

	return f
}

func (f *wireguardFixture) cleanup(t *testing.T) {
	t.Helper()
	f.mgrCancel()
	if err := <-f.mgrErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("manager error: %v", err)
	}
	_ = f.server.Close()
	_ = f.serverListener.Close()
	if err := <-f.srvErrCh; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("server error: %v", err)
	}
}

func TestManager_WireGuard_Acceptance(t *testing.T) {
	t.Run("WireGuard session lifecycle and connection dispatching", func(t *testing.T) {
		f := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer f.cleanup(t)

		waitFor(t, 5*time.Second, f.manager.IsConnected)

		f.devMu.Lock()
		if len(f.devices) != 1 {
			f.devMu.Unlock()
			t.Fatalf("expected 1 WireGuard device opened, got %d", len(f.devices))
		}
		dev := f.devices[0]
		devCfg := f.devConfigs[0]
		f.devMu.Unlock()

		if devCfg.InterfaceName != defaultWireGuardInterfaceName {
			t.Errorf("expected interface name %s, got %s", defaultWireGuardInterfaceName, devCfg.InterfaceName)
		}
		if !f.prefixNet.Contains(devCfg.DeviceAddress) {
			t.Errorf("expected DeviceAddress in %s, got %v", f.prefixNet, devCfg.DeviceAddress)
		}

		peer, ok := dev.getPeer()
		if !ok || peer.PublicKey != f.frontendKey {
			t.Fatalf("expected frontend peer %s on device", f.frontendKey)
		}

		expectedEndpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ParseFrontendHost(f.serverListener.Addr().String()), "51820"))
		if err != nil {
			t.Fatalf("ResolveUDPAddr failed: %v", err)
		}
		if peer.Endpoint.String() != expectedEndpoint.String() {
			t.Errorf("expected peer endpoint %s, got %s", expectedEndpoint, peer.Endpoint)
		}

		if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0].String() != "fd00:4444::1/128" {
			t.Errorf("expected AllowedIP fd00:4444::1/128, got %v", peer.AllowedIPs)
		}
		if peer.PersistentKeepalive == nil || *peer.PersistentKeepalive != wireguardPersistentKeepalive {
			t.Errorf("expected keepalive %v, got %v", wireguardPersistentKeepalive, peer.PersistentKeepalive)
		}

		f.listenMu.Lock()
		tunLn := f.tunnelListeners[0]
		listenAddr := f.listenAddrs[0]
		f.listenMu.Unlock()

		expectedListenAddr := net.JoinHostPort(devCfg.DeviceAddress.String(), strconv.Itoa(api.WireGuardTunnelPort))
		if listenAddr != expectedListenAddr {
			t.Errorf("expected listen addr %s, got %s", expectedListenAddr, listenAddr)
		}

		// TLS dispatch to HTTPSListener
		tlsConn, err := net.Dial("tcp", tunLn.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener: %v", err)
		}
		defer tlsConn.Close()

		hdrTLS := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
		}
		encodedTLS, err := hdrTLS.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		tlsPayload := []byte("\x16\x03\x01\x00\x05hello")
		if _, err := tlsConn.Write(append(encodedTLS, tlsPayload...)); err != nil {
			t.Fatalf("write TLS to tunnel: %v", err)
		}

		acceptedTLS, err := f.manager.HTTPSListener().Accept()
		if err != nil {
			t.Fatalf("HTTPSListener.Accept failed: %v", err)
		}
		acceptedTLS.Close()

		// HTTP dispatch to HTTPListener
		httpConn, err := net.Dial("tcp", tunLn.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener for HTTP: %v", err)
		}
		defer httpConn.Close()

		hdrHTTP := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 54321},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 80},
		}
		encodedHTTP, err := hdrHTTP.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := httpConn.Write(append(encodedHTTP, httpPayload...)); err != nil {
			t.Fatalf("write HTTP to tunnel: %v", err)
		}

		acceptedHTTP, err := f.manager.HTTPListener().Accept()
		if err != nil {
			t.Fatalf("HTTPListener.Accept failed: %v", err)
		}
		acceptedHTTP.Close()
	})

	t.Run("Unauthorized connection from another address is closed", func(t *testing.T) {
		f := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer f.cleanup(t)

		waitFor(t, 5*time.Second, f.manager.IsConnected)

		f.listenMu.Lock()
		tunLn := f.tunnelListeners[0]
		f.listenMu.Unlock()

		tunLn.setOverrideRemoteAddr(&net.TCPAddr{IP: net.ParseIP("fd00:4444::99"), Port: 12345})

		unauthConn, err := net.Dial("tcp", tunLn.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener: %v", err)
		}
		defer unauthConn.Close()

		hdr := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
		}
		encoded, err := hdr.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		_, _ = unauthConn.Write(append(encoded, []byte("\x16\x03\x01\x00\x05hello")...))

		buf := make([]byte, 1)
		_ = unauthConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = unauthConn.Read(buf)
		if err == nil {
			t.Errorf("expected read on rejected connection to fail or return EOF, got nil")
		}

		select {
		case c := <-f.manager.HTTPSListener().connCh:
			c.Close()
			t.Errorf("HTTPSListener unexpectedly received connection from unauthorized address")
		case c := <-f.manager.HTTPListener().connCh:
			c.Close()
			t.Errorf("HTTPListener unexpectedly received connection from unauthorized address")
		case <-time.After(50 * time.Millisecond):
		}
	})

	t.Run("Reconnecting session makes a new key and device", func(t *testing.T) {
		f := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer f.cleanup(t)

		waitFor(t, 5*time.Second, f.manager.IsConnected)

		f.devMu.Lock()
		if len(f.devices) != 1 {
			f.devMu.Unlock()
			t.Fatalf("expected 1 device, got %d", len(f.devices))
		}
		dev1 := f.devices[0]
		key1 := f.devConfigs[0].PrivateKey
		f.devMu.Unlock()

		sessID1 := f.manager.SessionID()
		f.server.CloseSession(sessID1)

		waitFor(t, 5*time.Second, func() bool {
			return f.manager.IsConnected() && f.manager.SessionID() != sessID1
		})

		if !dev1.isClosed() {
			t.Errorf("expected device 1 to be closed when session ended")
		}

		f.devMu.Lock()
		if len(f.devices) < 2 {
			f.devMu.Unlock()
			t.Fatalf("expected at least 2 devices opened after reconnect, got %d", len(f.devices))
		}
		key2 := f.devConfigs[1].PrivateKey
		f.devMu.Unlock()

		if key1 == key2 {
			t.Errorf("expected new key on reconnect, got same key %s", key1)
		}
	})

	t.Run("WireGuard-off frontend leaves TCP pool working", func(t *testing.T) {
		f := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: false, managerWireGuard: true})
		defer f.cleanup(t)

		waitFor(t, 5*time.Second, f.manager.IsConnected)

		f.devMu.Lock()
		numDevices := len(f.devices)
		f.devMu.Unlock()
		if numDevices != 0 {
			t.Errorf("expected no devices opened when frontend WireGuard is off, got %d", numDevices)
		}

		f.manager.UpdateHostnames([]string{"pool-test.example.com"})
		waitFor(t, 5*time.Second, func() bool {
			return f.manager.HasRegisteredHostnames([]string{"pool-test.example.com"})
		})
	})

	t.Run("Flag off leaves behaviour unchanged", func(t *testing.T) {
		f := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: false})
		defer f.cleanup(t)

		waitFor(t, 5*time.Second, f.manager.IsConnected)

		f.devMu.Lock()
		numDevices := len(f.devices)
		f.devMu.Unlock()
		if numDevices != 0 {
			t.Errorf("expected no devices opened when flag is off, got %d", numDevices)
		}

		f.manager.UpdateHostnames([]string{"flagoff.example.com"})
		waitFor(t, 5*time.Second, func() bool {
			return f.manager.HasRegisteredHostnames([]string{"flagoff.example.com"})
		})
	})
}
