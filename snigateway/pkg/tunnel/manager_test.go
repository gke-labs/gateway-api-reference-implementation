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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

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

type fakeMgrTestWireGuardDevice struct {
	mu     sync.Mutex
	peers  map[wireguard.Key]wireguard.Peer
	closed bool
}

func (f *fakeMgrTestWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeMgrTestWireGuardDevice) RemovePeer(key wireguard.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}

func (f *fakeMgrTestWireGuardDevice) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeMgrTestWireGuardDevice) IsClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeMgrTestWireGuardDevice) Peer(key wireguard.Key) (wireguard.Peer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.peers[key]
	return p, ok
}

func TestManager_WireGuard_Acceptance(t *testing.T) {
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

	t.Run("WireGuard session lifecycle and connection dispatching", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer ln.Close()

		_, feKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}

		feDev := &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		srv, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig:    serverTLS,
			InternalHostname:   "snigateway.internal",
			WireGuardDevice:    feDev,
			WireGuardPublicKey: feKey,
			WireGuardPort:      51820,
			WireGuardPrefix:    prefixNet,
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		defer srv.Close()

		go func() {
			_ = srv.Serve(ln)
		}()

		var (
			devMu        sync.Mutex
			mgrDevices   []*fakeMgrTestWireGuardDevice
			devConfigs   []wireguard.Config
			listenMu     sync.Mutex
			listenAddrs  []string
			tunListeners []net.Listener
		)

		opener := func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
			devMu.Lock()
			defer devMu.Unlock()
			dev := &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
			mgrDevices = append(mgrDevices, dev)
			devConfigs = append(devConfigs, cfg)
			return dev, nil
		}

		listenFunc := func(network, address string) (net.Listener, error) {
			listenMu.Lock()
			defer listenMu.Unlock()
			listenAddrs = append(listenAddrs, address)
			tunLis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tunListeners = append(tunListeners, tunLis)
			return tunLis, nil
		}

		c := client.NewClient(ln.Addr().String(), clientTLS)
		mgr := NewManager(c,
			WithWireGuard(true),
			WithWireGuardDeviceOpener(opener),
			WithListenFunc(listenFunc),
			WithBackoff(20*time.Millisecond, 100*time.Millisecond),
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		sess1Ctx, sess1Cancel := context.WithCancel(ctx)
		defer sess1Cancel()

		mgrDone := make(chan error, 1)
		go func() {
			mgrDone <- mgr.Run(sess1Ctx)
		}()

		// Wait until session connects
		deadline := time.Now().Add(5 * time.Second)
		for !mgr.IsConnected() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.IsConnected() {
			t.Fatalf("timed out waiting for manager to connect")
		}

		// 1. Verify exchange and device opening:
		devMu.Lock()
		numDevs := len(mgrDevices)
		var dev1 *fakeMgrTestWireGuardDevice
		var cfg1 wireguard.Config
		if numDevs > 0 {
			dev1 = mgrDevices[0]
			cfg1 = devConfigs[0]
		}
		devMu.Unlock()

		if numDevs != 1 {
			t.Fatalf("expected 1 WireGuard device opened, got %d", numDevs)
		}

		if cfg1.InterfaceName != "wg0" {
			t.Errorf("expected InterfaceName wg0, got %s", cfg1.InterfaceName)
		}
		if cfg1.DeviceAddress == nil || !prefixNet.Contains(cfg1.DeviceAddress) {
			t.Errorf("expected DeviceAddress in prefix %s, got %v", prefixNet, cfg1.DeviceAddress)
		}
		if cfg1.TunnelPrefix.String() != prefixNet.String() {
			t.Errorf("expected TunnelPrefix %s, got %s", prefixNet, cfg1.TunnelPrefix)
		}

		// Verify peer configuration on controller device:
		peer1, ok := dev1.Peer(feKey)
		if !ok {
			t.Fatalf("expected frontend peer %s to be registered on device", feKey)
		}

		// Endpoint must be frontend host + UDP port 51820
		feHost := ParseFrontendHost(ln.Addr().String())
		expectedEndpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(feHost, "51820"))
		if err != nil {
			t.Fatalf("ResolveUDPAddr failed: %v", err)
		}
		if peer1.Endpoint.String() != expectedEndpoint.String() {
			t.Errorf("expected peer endpoint %s, got %s", expectedEndpoint, peer1.Endpoint)
		}

		// Allowed IPs must be exactly the frontend's address in the tunnel (the first address of the prefix, as a /128)
		if len(peer1.AllowedIPs) != 1 {
			t.Fatalf("expected 1 AllowedIP, got %d (%v)", len(peer1.AllowedIPs), peer1.AllowedIPs)
		}
		expectedAllowedIP := "fd00:4444::1/128"
		if peer1.AllowedIPs[0].String() != expectedAllowedIP {
			t.Errorf("expected AllowedIP %s, got %s", expectedAllowedIP, peer1.AllowedIPs[0].String())
		}

		// Persistent keepalive of 25 seconds
		if peer1.PersistentKeepalive == nil || *peer1.PersistentKeepalive != 25*time.Second {
			t.Errorf("expected PersistentKeepalive 25s, got %v", peer1.PersistentKeepalive)
		}

		// Listener was opened at its own tunnel address on port 51821
		listenMu.Lock()
		numLis := len(listenAddrs)
		var tunLisAddr string
		var tunLis net.Listener
		if numLis > 0 {
			tunLisAddr = listenAddrs[0]
			tunLis = tunListeners[0]
		}
		listenMu.Unlock()

		if numLis != 1 {
			t.Fatalf("expected 1 tunnel listener opened, got %d", numLis)
		}
		expectedListenAddr := net.JoinHostPort(cfg1.DeviceAddress.String(), "51821")
		if tunLisAddr != expectedListenAddr {
			t.Errorf("expected tunnel listener address %s, got %s", expectedListenAddr, tunLisAddr)
		}

		// 2. Test connections arriving on the tunnel listener reach HTTPS or HTTP listener by first byte:
		// Case A: TLS connection (starts with 0x16) reaches HTTPSListener
		tlsConn, err := net.Dial("tcp", tunLis.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener: %v", err)
		}
		defer tlsConn.Close()

		hdrTLS := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
		}
		encodedHdrTLS, err := hdrTLS.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		tlsPayload := []byte("\x16\x03\x01\x00\x05hello")
		if _, err := tlsConn.Write(append(encodedHdrTLS, tlsPayload...)); err != nil {
			t.Fatalf("write TLS connection to tunnel: %v", err)
		}

		acceptedTLS, err := mgr.HTTPSListener().Accept()
		if err != nil {
			t.Fatalf("HTTPSListener.Accept failed: %v", err)
		}
		defer acceptedTLS.Close()

		pConnTLS, ok := acceptedTLS.(*proxyproto.Conn)
		if !ok {
			t.Fatalf("expected *proxyproto.Conn, got %T", acceptedTLS)
		}
		if pConnTLS.RemoteAddr().String() != "192.0.2.10:12345" {
			t.Errorf("expected remote addr 192.0.2.10:12345, got %s", pConnTLS.RemoteAddr())
		}
		readTLSBuf := make([]byte, len(tlsPayload))
		if _, err := io.ReadFull(pConnTLS, readTLSBuf); err != nil {
			t.Fatalf("read TLS payload failed: %v", err)
		}
		if !bytes.Equal(readTLSBuf, tlsPayload) {
			t.Errorf("expected TLS payload %q, got %q", tlsPayload, readTLSBuf)
		}

		// Case B: Plain HTTP connection reaches HTTPListener
		httpConn, err := net.Dial("tcp", tunLis.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener for HTTP: %v", err)
		}
		defer httpConn.Close()

		hdrHTTP := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 54321},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 80},
		}
		encodedHdrHTTP, err := hdrHTTP.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := httpConn.Write(append(encodedHdrHTTP, httpPayload...)); err != nil {
			t.Fatalf("write HTTP connection to tunnel: %v", err)
		}

		acceptedHTTP, err := mgr.HTTPListener().Accept()
		if err != nil {
			t.Fatalf("HTTPListener.Accept failed: %v", err)
		}
		defer acceptedHTTP.Close()

		pConnHTTP, ok := acceptedHTTP.(*proxyproto.Conn)
		if !ok {
			t.Fatalf("expected *proxyproto.Conn, got %T", acceptedHTTP)
		}
		if pConnHTTP.RemoteAddr().String() != "192.0.2.20:54321" {
			t.Errorf("expected remote addr 192.0.2.20:54321, got %s", pConnHTTP.RemoteAddr())
		}
		readHTTPBuf := make([]byte, len(httpPayload))
		if _, err := io.ReadFull(pConnHTTP, readHTTPBuf); err != nil {
			t.Fatalf("read HTTP payload failed: %v", err)
		}
		if !bytes.Equal(readHTTPBuf, httpPayload) {
			t.Errorf("expected HTTP payload %q, got %q", httpPayload, readHTTPBuf)
		}

		// 3. Ending session closes the device and listener:
		sess1Cancel()
		<-mgrDone

		if !dev1.IsClosed() {
			t.Errorf("expected WireGuard device to be closed after ending session")
		}

		dialClosedConn, err := net.DialTimeout("tcp", tunLis.Addr().String(), 100*time.Millisecond)
		if err == nil {
			dialClosedConn.Close()
			t.Errorf("expected dial to closed tunnel listener to fail, but succeeded")
		}
	})

	t.Run("Reconnecting session makes a new key and device", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer ln.Close()

		_, feKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}

		feDev := &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		srv, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig:    serverTLS,
			InternalHostname:   "snigateway.internal",
			WireGuardDevice:    feDev,
			WireGuardPublicKey: feKey,
			WireGuardPort:      51820,
			WireGuardPrefix:    prefixNet,
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		defer srv.Close()

		go func() {
			_ = srv.Serve(ln)
		}()

		var (
			devMu      sync.Mutex
			mgrDevices []*fakeMgrTestWireGuardDevice
			devConfigs []wireguard.Config
		)

		opener := func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
			devMu.Lock()
			defer devMu.Unlock()
			dev := &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
			mgrDevices = append(mgrDevices, dev)
			devConfigs = append(devConfigs, cfg)
			return dev, nil
		}

		listenFunc := func(network, address string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		}

		c := client.NewClient(ln.Addr().String(), clientTLS)
		mgr := NewManager(c,
			WithWireGuard(true),
			WithWireGuardDeviceOpener(opener),
			WithListenFunc(listenFunc),
			WithBackoff(10*time.Millisecond, 50*time.Millisecond),
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go func() {
			_ = mgr.Run(ctx)
		}()

		// Wait for session 1 to establish
		deadline := time.Now().Add(5 * time.Second)
		for !mgr.IsConnected() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.IsConnected() {
			t.Fatalf("timed out waiting for session 1")
		}

		devMu.Lock()
		if len(mgrDevices) != 1 {
			devMu.Unlock()
			t.Fatalf("expected 1 device, got %d", len(mgrDevices))
		}
		dev1 := mgrDevices[0]
		key1 := devConfigs[0].PrivateKey
		devMu.Unlock()

		// Close session 1 on the server side to force reconnection
		sessID1 := mgr.SessionID()
		srv.CloseSession(sessID1)

		// Wait for session 2 to establish
		deadline = time.Now().Add(5 * time.Second)
		for (mgr.SessionID() == sessID1 || !mgr.IsConnected()) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}

		if !dev1.IsClosed() {
			t.Errorf("expected device 1 to be closed when session 1 ended")
		}

		devMu.Lock()
		if len(mgrDevices) < 2 {
			devMu.Unlock()
			t.Fatalf("expected at least 2 devices opened after reconnection, got %d", len(mgrDevices))
		}
		key2 := devConfigs[1].PrivateKey
		devMu.Unlock()

		if key1 == key2 {
			t.Errorf("expected session 2 to generate a new key, got same key %s", key1)
		}
	})

	t.Run("WireGuard-off frontend leaves TCP pool working", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer ln.Close()

		// Frontend created without WireGuardDevice / WireGuardPort (WireGuard is OFF)
		srv, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig:  serverTLS,
			InternalHostname: "snigateway.internal",
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		defer srv.Close()

		go func() {
			_ = srv.Serve(ln)
		}()

		var openCalled bool
		opener := func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
			openCalled = true
			return &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}, nil
		}

		c := client.NewClient(ln.Addr().String(), clientTLS)
		mgr := NewManager(c,
			WithWireGuard(true),
			WithWireGuardDeviceOpener(opener),
			WithBackoff(20*time.Millisecond, 100*time.Millisecond),
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go func() {
			_ = mgr.Run(ctx)
		}()

		deadline := time.Now().Add(5 * time.Second)
		for !mgr.IsConnected() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.IsConnected() {
			t.Fatalf("timed out waiting for manager to connect with pool")
		}

		if openCalled {
			t.Errorf("expected deviceOpener not to be called when frontend WireGuard is off")
		}

		// Register hostname over pool
		mgr.UpdateHostnames([]string{"pool-test.example.com"})

		deadline = time.Now().Add(5 * time.Second)
		for !mgr.HasRegisteredHostnames([]string{"pool-test.example.com"}) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.HasRegisteredHostnames([]string{"pool-test.example.com"}) {
			t.Fatalf("expected HasRegisteredHostnames([pool-test.example.com])=true")
		}
	})

	t.Run("Flag off leaves behaviour unchanged", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer ln.Close()

		_, feKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}

		feDev := &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		srv, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig:    serverTLS,
			InternalHostname:   "snigateway.internal",
			WireGuardDevice:    feDev,
			WireGuardPublicKey: feKey,
			WireGuardPort:      51820,
			WireGuardPrefix:    prefixNet,
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		defer srv.Close()

		go func() {
			_ = srv.Serve(ln)
		}()

		var openCalled bool
		opener := func(ctx context.Context, cfg wireguard.Config) (WireGuardDevice, error) {
			openCalled = true
			return &fakeMgrTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}, nil
		}

		c := client.NewClient(ln.Addr().String(), clientTLS)
		mgr := NewManager(c,
			WithWireGuardDeviceOpener(opener),
			WithBackoff(20*time.Millisecond, 100*time.Millisecond),
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		go func() {
			_ = mgr.Run(ctx)
		}()

		deadline := time.Now().Add(5 * time.Second)
		for !mgr.IsConnected() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.IsConnected() {
			t.Fatalf("timed out waiting for manager to connect")
		}

		if openCalled {
			t.Errorf("expected deviceOpener not to be called when flag is off")
		}

		mgr.UpdateHostnames([]string{"flagoff.example.com"})
		deadline = time.Now().Add(5 * time.Second)
		for !mgr.HasRegisteredHostnames([]string{"flagoff.example.com"}) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !mgr.HasRegisteredHostnames([]string{"flagoff.example.com"}) {
			t.Fatalf("expected HasRegisteredHostnames([flagoff.example.com])=true")
		}
	})
}
