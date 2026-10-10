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
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
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
	for _, mode := range []string{TransportModeQUIC, TransportModeTCP, TransportModeAuto} {
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

func TestManager_AutoFallbackAndRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-fallback-*")
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

	// Frontend starts with ONLY TCP listener (UDP blocked / not started yet)
	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	// Set short QUIC dial timeout and probe interval for fast test execution
	mgr := NewManager(c,
		WithTransport(TransportModeAuto),
		WithQUICDialTimeout(300*time.Millisecond),
		WithQUICProbeInterval(500*time.Millisecond),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	hostname := "fallback.example.com"
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
			if r.URL.Path == "/stream" {
				// Long-lived streaming connection spanning the fallback-to-QUIC recovery
				flusher, ok := w.(http.Flusher)
				if ok {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("start-chunk\n"))
					flusher.Flush()
					time.Sleep(1500 * time.Millisecond)
					_, _ = w.Write([]byte("end-chunk\n"))
					flusher.Flush()
					return
				}
			}
			_, _ = w.Write([]byte("response from fallback"))
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

	// 1. Verify requests succeed over TCP fallback
	deadline := time.Now().Add(5 * time.Second)
	var successTCP bool
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("https://" + hostname + "/test")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				successTCP = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !successTCP {
		t.Fatalf("HTTP GET failed during TCP fallback")
	}

	// 2. Open a long-lived streaming connection over TCP fallback before enabling UDP
	longConnErrCh := make(chan error, 1)
	go func() {
		resp, err := httpClient.Get("https://" + hostname + "/stream")
		if err != nil {
			longConnErrCh <- err
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			longConnErrCh <- err
			return
		}
		if string(body) != "start-chunk\nend-chunk\n" {
			longConnErrCh <- fmt.Errorf("unexpected body from stream: %q", string(body))
			return
		}
		longConnErrCh <- nil
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Now start UDP listener on frontend (simulating UDP unblocking)
	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}
	defer pc.Close()

	go func() {
		_ = srv.ServeUDP(pc)
	}()

	// 4. Wait for background QUIC probe to switch to QUIC and verify requests continue to succeed
	time.Sleep(1 * time.Second)

	var successQUIC bool
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("https://" + hostname + "/test")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				successQUIC = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !successQUIC {
		t.Fatalf("HTTP GET failed after QUIC probe recovery")
	}

	// 5. Verify the established connection that spanned the switch survived without dropping
	select {
	case err := <-longConnErrCh:
		if err != nil {
			t.Fatalf("Long-lived TCP connection failed during fallback recovery: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Timeout waiting for long-lived TCP connection to finish")
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

func TestManager_QUICControlStreamErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-ctrl-err-*")
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

	serverTLS, _ := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	parsedCerts, _ := certs.ParseCertificatesFromPEM(caCertPEM)
	caFP := fmt.Sprintf("%x", sha256.Sum256(parsedCerts[0].Raw))

	// Authorizer only allows *.allowed.com
	authorizer := frontend.NewCAAuthorizer(map[string][]string{
		caFP: {"*.allowed.com"},
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	serverAddr := ln.Addr().String()
	pc, _ := net.ListenPacket("udp", serverAddr)

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		Authorizer:       authorizer,
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	clientTLS, _ := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	c := client.NewClient(serverAddr, clientTLS)

	mgr := NewManager(c,
		WithTransport(TransportModeQUIC),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	// 1. Attempt to register a disallowed hostname (authorization denied)
	mgr.UpdateHostnames([]string{"forbidden.com"})
	time.Sleep(300 * time.Millisecond)

	clientID := fmt.Sprintf("%s/mgr-client", caFP)
	reg := srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
	if len(reg) > 0 {
		t.Fatalf("expected forbidden.com not to be registered, got %v", reg)
	}

	// 2. Now update to an allowed hostname -> manager reconnects and successfully registers!
	mgr.UpdateHostnames([]string{"app.allowed.com"})

	deadline := time.Now().Add(3 * time.Second)
	var registered bool
	for time.Now().Before(deadline) {
		reg = srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
		if slices.Equal(reg, []string{"app.allowed.com"}) {
			registered = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	if !registered {
		t.Fatalf("expected app.allowed.com to register after reconnect, got %v", reg)
	}
}

func TestManager_TCPConnectionSurvivesSwitchToQUIC(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-mgr-survive-*")
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

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := tcpLn.Addr().String()

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

	// Frontend starts with ONLY TCP listener
	go func() {
		_ = srv.Serve(tcpLn)
	}()

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	mgr := NewManager(c,
		WithTransport(TransportModeAuto),
		WithQUICDialTimeout(200*time.Millisecond),
		WithQUICProbeInterval(300*time.Millisecond),
		WithBackoff(50*time.Millisecond, 100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	hostname := "survive.example.com"
	mgr.UpdateHostnames([]string{hostname})

	tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})

	finishStream := make(chan struct{})
	streamStarted := make(chan struct{})

	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/stream" {
				flusher, ok := w.(http.Flusher)
				if !ok {
					http.Error(w, "streaming unsupported", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("chunk-before-switch\n"))
				flusher.Flush()
				close(streamStarted)

				// Wait until the manager has switched to QUIC
				<-finishStream

				_, _ = w.Write([]byte("chunk-after-switch\n"))
				flusher.Flush()
				return
			}
			_, _ = w.Write([]byte("ok-quic"))
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
		Timeout: 10 * time.Second,
	}

	// 1. Wait for manager to establish TCP fallback session and register hostname
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.IsConnected() && !mgr.IsQUIC() {
			if _, ok := srv.RegistrationTable().Match(hostname); ok {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !mgr.IsConnected() || mgr.IsQUIC() {
		t.Fatalf("expected manager to be connected via TCP fallback")
	}
	if _, ok := srv.RegistrationTable().Match(hostname); !ok {
		t.Fatalf("expected hostname %s to be registered in frontend table", hostname)
	}

	// 2. Open the streaming connection over TCP fallback
	streamErrCh := make(chan error, 1)
	streamBodyCh := make(chan string, 1)

	go func() {
		resp, err := httpClient.Get("https://" + hostname + "/stream")
		if err != nil {
			streamErrCh <- err
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			streamErrCh <- err
			return
		}
		streamBodyCh <- string(body)
		streamErrCh <- nil
	}()

	// Wait until backend has received request and sent first chunk
	select {
	case <-streamStarted:
	case err := <-streamErrCh:
		t.Fatalf("failed starting stream over TCP fallback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for stream to start")
	}

	// 3. Now start UDP listener on frontend to enable QUIC
	udpPC, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}
	defer udpPC.Close()

	go func() {
		_ = srv.ServeUDP(udpPC)
	}()

	// 4. Wait for background probe to switch manager to QUIC
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.IsQUIC() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !mgr.IsQUIC() {
		t.Fatalf("expected manager to switch to QUIC after UDP became available")
	}

	// 5. Verify new requests succeed over the newly established QUIC session
	newReqResp, err := httpClient.Get("https://" + hostname + "/new")
	if err != nil {
		t.Fatalf("new request failed over QUIC: %v", err)
	}
	newBody, _ := io.ReadAll(newReqResp.Body)
	newReqResp.Body.Close()
	if string(newBody) != "ok-quic" {
		t.Fatalf("unexpected new request body: %s", string(newBody))
	}

	// 6. Signal the streaming connection to finish sending data
	close(finishStream)

	// 7. Verify the TCP connection that was already in-flight survived and completed without error!
	select {
	case err := <-streamErrCh:
		if err != nil {
			t.Fatalf("in-flight TCP connection failed during or after switch to QUIC: %v", err)
		}
		body := <-streamBodyCh
		expectedBody := "chunk-before-switch\nchunk-after-switch\n"
		if body != expectedBody {
			t.Fatalf("expected stream body %q, got %q", expectedBody, body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for in-flight TCP stream to finish")
	}
}
