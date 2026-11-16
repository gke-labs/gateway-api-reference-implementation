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
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

func setupTestWireGuardPair(t *testing.T) (func(*frontend.ServerConfig), []ManagerOption) {
	t.Helper()
	_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, frontendKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	frontendTunnelIP := make(net.IP, 16)
	copy(frontendTunnelIP, prefixNet.IP.To16())
	frontendTunnelIP[15] = 1

	var (
		mu                   sync.Mutex
		activeTunnelListener net.Listener
	)

	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		listener := activeTunnelListener
		mu.Unlock()
		if listener == nil {
			return nil, errors.New("no active tunnel listener")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}

	listenFunc := func(network, address string) (net.Listener, error) {
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listener := &fakeTunnelListener{Listener: rawListener, defaultRemoteIP: frontendTunnelIP}
		mu.Lock()
		activeTunnelListener = listener
		mu.Unlock()
		return listener, nil
	}

	opener := func(ctx context.Context, config wireguard.Config) (WireGuardDevice, error) {
		return &fakeMgrTestWireGuardDevice{}, nil
	}

	applyFrontend := func(config *frontend.ServerConfig) {
		config.WireGuardDevice = &fakeFrontendWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		config.WireGuardPublicKey = frontendKey
		config.WireGuardPort = 51820
		config.WireGuardPrefix = prefixNet
		config.DialContext = dialFunc
	}

	mgrOpts := []ManagerOption{
		WithWireGuardDeviceOpener(opener),
		WithListenFunc(listenFunc),
	}

	return applyFrontend, mgrOpts
}

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

	applyWG, wgOpts := setupTestWireGuardPair(t)
	feCfg := frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	}
	applyWG(&feCfg)
	srv, err := frontend.NewServer(feCfg)
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
	mgr := NewManager(c, append(wgOpts, WithBackoff(50*time.Millisecond, 200*time.Millisecond))...)

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

	applyWG, wgOpts := setupTestWireGuardPair(t)
	feCfg := frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	}
	applyWG(&feCfg)
	srv, err := frontend.NewServer(feCfg)
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
	mgr := NewManager(c, append(wgOpts, WithBackoff(50*time.Millisecond, 100*time.Millisecond))...)

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

	applyWG, wgOpts := setupTestWireGuardPair(t)
	feCfg := frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	}
	applyWG(&feCfg)
	srv, err := frontend.NewServer(feCfg)
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

	mgr := NewManager(cli, append(wgOpts, WithBackoff(20*time.Millisecond, 100*time.Millisecond))...)

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
