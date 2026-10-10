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

package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
)

func TestTunnelListenerHTTPSIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-integration-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generate mTLS infrastructure certificates
	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "integration-client"); err != nil {
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

	// 2. Start snigateway-frontend in-process
	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	frontendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	frontendAddr := frontendListener.Addr().String()

	frontendUDP, err := net.ListenPacket("udp", frontendAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

	frontendServer, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer frontendServer.Close()

	go func() {
		_ = frontendServer.ServeAll([]net.Listener{frontendListener}, []net.PacketConn{frontendUDP})
	}()

	// 3. Start tunnel Manager with client connecting to frontend
	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(frontendAddr, clientTLS)
	mgr := tunnel.NewManager(c, tunnel.WithBackoff(50*time.Millisecond, 200*time.Millisecond))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	// 4. Generate backend application certificates and start HTTPS server on tunnel.Listener()
	backendCert, err := generateBackendCert("service.example.com", "updated.example.com")
	if err != nil {
		t.Fatalf("generateBackendCert failed: %v", err)
	}

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{
		Certificates: []tls.Certificate{backendCert},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "ReverseTunnel")
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("X-Real-Client-IP", clientIP)
		_, _ = fmt.Fprintf(w, "Hello from backend for host: %s, path: %s", r.Host, r.URL.Path)
	})

	httpServer := &http.Server{
		Handler: mux,
	}
	defer httpServer.Close()

	go func() {
		_ = httpServer.Serve(tlsLis)
	}()

	// 5. Register initial hostname: service.example.com
	mgr.UpdateHostnames([]string{"service.example.com"})

	// Helper function to send HTTPS request with specific SNI and Host
	sendRequest := func(sniHost string, hostHeader string, path string) (*http.Response, string, error) {
		clientTransport := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", frontendAddr, &tls.Config{
					ServerName:         sniHost,
					InsecureSkipVerify: true,
				})
			},
		}
		httpClient := &http.Client{
			Transport: clientTransport,
			Timeout:   3 * time.Second,
		}

		req, err := http.NewRequest(http.MethodGet, "https://"+sniHost+path, nil)
		if err != nil {
			return nil, "", err
		}
		if hostHeader != "" {
			req.Host = hostHeader
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", err
		}
		return resp, string(body), nil
	}

	// 6. Verify end-to-end HTTPS request with matching SNI
	t.Run("End-to-End HTTPS through tunnel listener", func(t *testing.T) {
		var resp *http.Response
		var body string
		var err error

		// Retry briefly while registration completes
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			resp, body, err = sendRequest("service.example.com", "service.example.com", "/hello")
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}

		if err != nil {
			t.Fatalf("failed to perform HTTPS request: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if gotHeader := resp.Header.Get("X-Custom-Header"); gotHeader != "ReverseTunnel" {
			t.Fatalf("expected header 'ReverseTunnel', got %q", gotHeader)
		}
		if clientIP := resp.Header.Get("X-Real-Client-IP"); clientIP != "127.0.0.1" {
			t.Fatalf("expected real client IP 127.0.0.1 via PROXY protocol, got %q", clientIP)
		}
		expectedBody := "Hello from backend for host: service.example.com, path: /hello"
		if body != expectedBody {
			t.Fatalf("got body %q, want %q", body, expectedBody)
		}
	})

	// 7. Change registered hostnames dynamically: replace service.example.com with updated.example.com
	t.Run("Changing registered hostnames takes effect dynamically", func(t *testing.T) {
		mgr.UpdateHostnames([]string{"updated.example.com"})

		// Verify updated.example.com works
		var resp *http.Response
		var body string
		var err error

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			resp, body, err = sendRequest("updated.example.com", "updated.example.com", "/hello")
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}

		if err != nil {
			t.Fatalf("request to updated.example.com failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200 for updated.example.com, got %d", resp.StatusCode)
		}
		expectedBody := "Hello from backend for host: updated.example.com, path: /hello"
		if body != expectedBody {
			t.Fatalf("got body %q, want %q", body, expectedBody)
		}

		// Verify old hostname service.example.com is now closed / rejected
		_, _, err = sendRequest("service.example.com", "service.example.com", "/hello")
		if err == nil {
			t.Fatalf("expected old hostname service.example.com to fail after update, but succeeded")
		}
	})
}
