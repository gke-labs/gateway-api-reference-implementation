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

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

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
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
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

	// 2. Start an HTTPS server on mgr.Listener()
	tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{
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

func TestManager_Transports(t *testing.T) {
	for _, mode := range []string{TransportModeTCP, TransportModeH2} {
		t.Run("Mode_"+mode, func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", "snigateway-mgr-transports-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
				t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
			}

			caCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
			serverCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.crt"))
			serverKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.key"))
			clientCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.crt"))
			clientKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.key"))

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
			mgr := NewManager(c, WithTransport(mode), WithBackoff(50*time.Millisecond, 100*time.Millisecond))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			go func() {
				_ = mgr.Run(ctx)
			}()

			hostname := fmt.Sprintf("%s.example.com", mode)
			mgr.UpdateHostnames([]string{hostname})

			tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
			if err != nil {
				t.Fatalf("tls.X509KeyPair: %v", err)
			}

			tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			})

			httpSrv := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("hello from " + mode))
				}),
			}
			defer httpSrv.Close()

			go func() {
				_ = httpSrv.Serve(tlsLis)
			}()

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         hostname,
						InsecureSkipVerify: true,
					},
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return tls.Dial("tcp", serverAddr, &tls.Config{
							ServerName:         hostname,
							InsecureSkipVerify: true,
						})
					},
				},
				Timeout: 5 * time.Second,
			}

			// Wait for connection and test request
			deadline := time.Now().Add(5 * time.Second)
			var success bool
			for time.Now().Before(deadline) {
				resp, err := httpClient.Get("https://" + hostname + "/test")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						success = true
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
			}

			if !success {
				t.Fatalf("HTTP GET failed for mode %s", mode)
			}
		})
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

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

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
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
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

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{
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
	defer mgr.Listener().Close()

	// Test with different connection scenarios representing TCP pool and H2 streams
	testCases := []struct {
		name    string
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		payload string
	}{
		{
			name:    "TCP_Pool_Stream",
			srcIP:   "192.0.2.10",
			dstIP:   "198.51.100.1",
			srcPort: 54321,
			dstPort: 443,
			payload: "ClientHello payload from TCP pool",
		},
		{
			name:    "H2_CONNECT_Stream",
			srcIP:   "198.51.100.99",
			dstIP:   "198.51.100.1",
			srcPort: 60000,
			dstPort: 443,
			payload: "ClientHello payload from HTTP/2 CONNECT stream",
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
				_, _ = c1.Write([]byte(tc.payload))
			}()

			// Call the shared backend method handleTunnelConn
			errCh := make(chan error, 1)
			go func() {
				errCh <- mgr.handleTunnelConn(c2)
			}()

			// Accept from manager listener
			acceptedConn, err := mgr.Listener().Accept()
			if err != nil {
				t.Fatalf("Listener.Accept failed: %v", err)
			}
			defer acceptedConn.Close()

			if err := <-errCh; err != nil {
				t.Fatalf("handleTunnelConn failed: %v", err)
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

			// Verify payload read
			buf := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(pConn, buf); err != nil {
				t.Fatalf("reading payload failed: %v", err)
			}
			if string(buf) != tc.payload {
				t.Errorf("expected payload %q, got %q", tc.payload, string(buf))
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
		_ = srv.ServeAll([]net.Listener{ln}, nil)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	cli := client.NewClient(ln.Addr().String(), clientTLS)

	mgr := NewManager(cli,
		WithTransport(TransportModeTCP),
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

type testResponseWriter struct {
	mu      sync.Mutex
	header  http.Header
	buf     []byte
	flushed int
}

func (w *testResponseWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *testResponseWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, b...)
	return len(b), nil
}

func (w *testResponseWriter) WriteHeader(statusCode int) {}

func (w *testResponseWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushed++
}

func (w *testResponseWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	res := make([]byte, len(w.buf))
	copy(res, w.buf)
	return res
}

func (w *testResponseWriter) getFlushed() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushed
}

func (w *testResponseWriter) waitForBytes(targetLen int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		curLen := len(w.buf)
		w.mu.Unlock()
		if curLen >= targetLen {
			return true
		}
		time.Sleep(1 * time.Millisecond)
	}
	return false
}

func TestServerStreamConn_WritingAndDeadlines(t *testing.T) {
	rw := &testResponseWriter{}
	pr, pw := io.Pipe()
	defer pw.Close()

	_, cancel := context.WithCancel(t.Context())
	defer cancel()

	conn := newServerStreamConn(rw, pr, cancel, nil)
	defer conn.Close()
	go conn.RunDrainLoop()

	// Write smaller than 4096 bytes should be written immediately and flushed
	smallChunk := []byte("hello 13 byte")
	n, err := conn.Write(smallChunk)
	if err != nil || n != len(smallChunk) {
		t.Fatalf("Write small chunk failed: %v", err)
	}
	if !rw.waitForBytes(len(smallChunk), 100*time.Millisecond) {
		t.Fatalf("timed out waiting for small chunk write to be drained")
	}
	if string(rw.bytes()) != "hello 13 byte" {
		t.Errorf("expected small chunk to be written immediately, got %q", string(rw.bytes()))
	}
	if rw.getFlushed() != 1 {
		t.Errorf("expected 1 flush for small write, got %d", rw.getFlushed())
	}

	// Write >= 4096 bytes should be written immediately without redundant Flush()
	largeChunk := make([]byte, 8192)
	n, err = conn.Write(largeChunk)
	if err != nil || n != len(largeChunk) {
		t.Fatalf("Write large chunk failed: %v", err)
	}
	expectedTotal := len(smallChunk) + len(largeChunk)
	if !rw.waitForBytes(expectedTotal, 100*time.Millisecond) {
		t.Fatalf("timed out waiting for large chunk write to be drained")
	}
	if len(rw.bytes()) != expectedTotal {
		t.Errorf("expected %d total bytes, got %d", expectedTotal, len(rw.bytes()))
	}
	if rw.getFlushed() != 1 {
		t.Errorf("expected flushes to remain 1 (no extra flush for large write), got %d", rw.getFlushed())
	}

	// Test SetReadDeadline non-destructive behavior
	// Setting deadline in the past should not close the underlying reader
	aLongTimeAgo := time.Unix(1, 0)
	if err := conn.SetReadDeadline(aLongTimeAgo); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	// Clearing deadline should allow reading again
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline failed: %v", err)
	}

	go func() {
		_, _ = pw.Write([]byte("more-data"))
	}()
	moreBuf := make([]byte, 9)
	nr, err := conn.Read(moreBuf)
	if err != nil || string(moreBuf[:nr]) != "more-data" {
		t.Fatalf("Read after clearing deadline failed: %v, got %q", err, string(moreBuf[:nr]))
	}

	// Test WriteTo
	go func() {
		_, _ = pw.Write([]byte("stream-content"))
		_ = pw.Close()
	}()
	var outBuf testResponseWriter
	wt, ok := any(conn).(io.WriterTo)
	if !ok {
		t.Fatalf("expected serverStreamConn to implement io.WriterTo")
	}
	written, err := wt.WriteTo(&outBuf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if string(outBuf.bytes()) != "stream-content" || written != int64(len("stream-content")) {
		t.Errorf("WriteTo output mismatch: got %q, written=%d", string(outBuf.bytes()), written)
	}
}

func TestServerStreamConn_StreamingProbe(t *testing.T) {
	rw := &testResponseWriter{}
	_, cancel := context.WithCancel(t.Context())
	defer cancel()

	conn := newServerStreamConn(rw, nil, cancel, nil)
	defer conn.Close()
	go conn.RunDrainLoop()

	// Probe: a 13-byte Write without concurrent Read is delivered within a few ms
	probe := []byte("hello 13 byte")
	t0 := time.Now()
	n, err := conn.Write(probe)
	if err != nil || n != len(probe) {
		t.Fatalf("Write probe failed: %v", err)
	}
	if !rw.waitForBytes(len(probe), 50*time.Millisecond) {
		t.Fatalf("Probe delivery took too long: %v", time.Since(t0))
	}
	if string(rw.bytes()) != string(probe) {
		t.Fatalf("Probe mismatch: got %q", string(rw.bytes()))
	}
	if rw.getFlushed() != 1 {
		t.Fatalf("expected 1 flush for probe, got %d", rw.getFlushed())
	}
}

func TestServerStreamConn_BackpressureAndClose(t *testing.T) {
	rw := &testResponseWriter{}
	_, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Construct conn without running drain loop (simulating stalled reader)
	conn := newServerStreamConn(rw, nil, cancel, nil)

	// Write up to queue bound (256 KiB = 16 x 16 KiB)
	chunk := make([]byte, 16*1024)
	for i := 0; i < 16; i++ {
		n, err := conn.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	// 17th write must block at queue bound
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(chunk)
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		t.Fatalf("expected write to block, but returned: %v", err)
	case <-time.After(50 * time.Millisecond):
		// correctly blocked
	}

	// Close unblocks it
	_ = conn.Close()

	select {
	case err := <-writeErrCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for Close to unblock writer")
	}
}

func TestManager_H2BackendShutdownGOAWAY(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-h2-goaway-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	serverCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	serverKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.key"))
	clientCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	clientKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.key"))

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

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
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	mgr := NewManager(c,
		WithTransport(TransportModeH2),
		WithPoolSize(2),
		WithH2DrainTimeout(5*time.Second),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)

	mgrCtx, mgrCancel := context.WithCancel(t.Context())
	defer mgrCancel()

	mgrDone := make(chan error, 1)
	go func() {
		mgrDone <- mgr.Run(mgrCtx)
	}()

	hostname := "h2-goaway.example.com"
	mgr.UpdateHostnames([]string{hostname})

	// Wait for manager to establish H2 session and dial connections
	deadline := time.Now().Add(5 * time.Second)
	var sessID string
	var conns []*frontend.H2Conn
	for time.Now().Before(deadline) {
		if mgr.IsConnected() {
			sessID = mgr.SessionID()
			if sessID != "" {
				conns = srv.H2Transport().SessionConns(sessID)
				if len(conns) >= 2 {
					break
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if sessID == "" || len(conns) < 2 {
		t.Fatalf("expected at least 2 active pooled H2 connections, got %d (session: %q)", len(conns), sessID)
	}

	// Verify all connections can take new requests initially
	for i, conn := range conns {
		if !conn.CanTakeNewRequest() {
			t.Fatalf("conn %d: expected CanTakeNewRequest() == true before cancel", i)
		}
		if !conn.ClientConn().CanTakeNewRequest() {
			t.Fatalf("conn %d: expected ClientConn.CanTakeNewRequest() == true before cancel", i)
		}
	}

	// Open a stream on the session from frontend to backend
	streamCtx, streamCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer streamCancel()

	stream, err := srv.H2Transport().GetConn(streamCtx, sessID)
	if err != nil {
		t.Fatalf("GetConn failed: %v", err)
	}
	defer stream.Close()

	// Write PROXY protocol header so the backend listener accepts the connection
	hdr := proxyproto.Header{
		SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		DstAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443},
	}
	if err := proxyproto.Encode(stream, &hdr); err != nil {
		t.Fatalf("proxyproto.Encode failed: %v", err)
	}

	backendConn, err := mgr.Listener().Accept()
	if err != nil {
		t.Fatalf("mgr.Listener().Accept() failed: %v", err)
	}
	defer backendConn.Close()

	// Find the connection carrying the open stream
	var streamConn *frontend.H2Conn
	for _, conn := range conns {
		if conn.ClientConn().State().StreamsActive > 0 {
			streamConn = conn
			break
		}
	}
	if streamConn == nil {
		t.Fatalf("could not find connection with active stream")
	}

	// Verify that before cancellation, streamConn can take new requests
	if !streamConn.CanTakeNewRequest() {
		t.Fatalf("expected streamConn.CanTakeNewRequest() == true before cancellation")
	}
	if !streamConn.ClientConn().CanTakeNewRequest() {
		t.Fatalf("expected streamConn.ClientConn().CanTakeNewRequest() == true before cancellation")
	}

	// Now cancel the backend manager context to trigger graceful GOAWAY drain
	mgrCancel()

	// Assert the frontend receives GOAWAY on each pooled connection before socket closes:
	// h2Conn.CanTakeNewRequest() goes false without having to detect a dead socket.
	goAwayDeadline := time.Now().Add(2 * time.Second)
	var sawGoAway bool
	for time.Now().Before(goAwayDeadline) {
		allFalse := true
		for _, conn := range conns {
			if conn.CanTakeNewRequest() {
				allFalse = false
				break
			}
		}
		if allFalse && !streamConn.ClientConn().CanTakeNewRequest() {
			sawGoAway = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawGoAway {
		for i, conn := range conns {
			t.Logf("conn %d: CanTakeNewRequest=%v, cc.CanTakeNewRequest=%v, cc.State=%+v",
				i, conn.CanTakeNewRequest(), conn.ClientConn().CanTakeNewRequest(), conn.ClientConn().State())
		}
		t.Fatalf("frontend ClientConns did not receive GOAWAY after manager context cancelled")
	}

	// Verify that the connection with the active stream is NOT yet Closed
	if streamConn.ClientConn().State().Closed {
		t.Errorf("ClientConn socket was prematurely Closed while stream still in-flight")
	}

	// Assert the open stream still finishes successfully
	testData := []byte("payload after backend cancellation")
	if _, err := stream.Write(testData); err != nil {
		t.Fatalf("stream.Write failed after cancellation: %v", err)
	}

	readBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(backendConn, readBuf); err != nil {
		t.Fatalf("backendConn.ReadFull failed: %v", err)
	}
	if !bytes.Equal(readBuf, testData) {
		t.Fatalf("received %q, want %q", readBuf, testData)
	}

	echoData := []byte("echo back after goaway")
	if _, err := backendConn.Write(echoData); err != nil {
		t.Fatalf("backendConn.Write failed: %v", err)
	}

	echoBuf := make([]byte, len(echoData))
	if _, err := io.ReadFull(stream, echoBuf); err != nil {
		t.Fatalf("stream.ReadFull failed: %v", err)
	}
	if !bytes.Equal(echoBuf, echoData) {
		t.Fatalf("received %q, want %q", echoBuf, echoData)
	}

	// Close the stream and backend connection now that work is complete
	_ = backendConn.Close()
	_ = stream.Close()

	// Verify manager shutdown completes cleanly within drain timeout
	select {
	case err := <-mgrDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("mgr.Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for manager to exit after stream closed")
	}
}

func TestManager_H2BackendDrainTimeoutForceCloses(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-h2-drain-timeout-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "mgr-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	serverCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	serverKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "server.key"))
	clientCertPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	clientKeyPEM, _ := os.ReadFile(filepath.Join(tempDir, "client.key"))

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

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
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	// Set a very short drain timeout (150ms)
	drainTimeout := 150 * time.Millisecond
	mgr := NewManager(c,
		WithTransport(TransportModeH2),
		WithPoolSize(1),
		WithH2DrainTimeout(drainTimeout),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)

	mgrCtx, mgrCancel := context.WithCancel(t.Context())
	defer mgrCancel()

	mgrDone := make(chan error, 1)
	go func() {
		mgrDone <- mgr.Run(mgrCtx)
	}()

	mgr.UpdateHostnames([]string{"h2-timeout.example.com"})

	// Wait for manager to connect
	deadline := time.Now().Add(5 * time.Second)
	var sessID string
	for time.Now().Before(deadline) {
		if mgr.IsConnected() {
			sessID = mgr.SessionID()
			if sessID != "" && len(srv.H2Transport().SessionConns(sessID)) >= 1 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatalf("manager failed to connect")
	}

	streamCtx, streamCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer streamCancel()

	stream, err := srv.H2Transport().GetConn(streamCtx, sessID)
	if err != nil {
		t.Fatalf("GetConn failed: %v", err)
	}
	defer stream.Close()

	hdr := proxyproto.Header{
		SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		DstAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443},
	}
	if err := proxyproto.Encode(stream, &hdr); err != nil {
		t.Fatalf("proxyproto.Encode failed: %v", err)
	}

	backendConn, err := mgr.Listener().Accept()
	if err != nil {
		t.Fatalf("mgr.Listener().Accept() failed: %v", err)
	}
	defer backendConn.Close()

	start := time.Now()
	// Cancel manager without closing stream or backendConn
	mgrCancel()

	// Manager should exit within ~drainTimeout + small margin, force closing connections
	select {
	case err := <-mgrDone:
		elapsed := time.Since(start)
		if elapsed < drainTimeout {
			t.Fatalf("manager exited prematurely before drain timeout: elapsed %v, drain timeout %v", elapsed, drainTimeout)
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("mgr.Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for manager to force close and exit after drain timeout")
	}

	// Sockets should now be closed; read should return error
	buf := make([]byte, 16)
	_ = stream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = stream.Read(buf)
	if err == nil {
		t.Errorf("expected stream.Read to fail on force closed connection, but succeeded")
	}
}
