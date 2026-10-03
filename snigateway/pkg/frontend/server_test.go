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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
)

// generateTestBackendCert creates a self-signed cert for the fake backend application served over reverse tunnel.
func generateTestBackendCert(hosts ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames:              hosts,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func setupTestServerAndClient(t *testing.T) (*Server, string, *certs.GeneratedCerts, func()) {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	serverAddr := ln.Addr().String()

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	cleanup := func() {
		_ = srv.Close()
	}

	return srv, serverAddr, generated, cleanup
}

func TestEndToEndReverseTunnel(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)

	// Generate backend TLS certificate for target service
	backendCert, err := generateTestBackendCert("app.example.com", "*.wildcard.org")
	if err != nil {
		t.Fatalf("generateTestBackendCert failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Backend handler for incoming tunnels
	serveConn := func(ctx context.Context, connID string, hostname string, tunnel net.Conn) {
		defer tunnel.Close()

		tlsServer := tls.Server(tunnel, &tls.Config{
			Certificates: []tls.Certificate{backendCert},
		})
		defer tlsServer.Close()

		buf := make([]byte, 1024)
		n, err := tlsServer.Read(buf)
		if err != nil {
			return
		}
		reqStr := string(buf[:n])
		respStr := fmt.Sprintf("ECHO from backend for host %s: %s", hostname, reqStr)
		_, _ = tlsServer.Write([]byte(respStr))
	}

	// Start client loop serving hostnames
	go func() {
		_ = c.Run(ctx, []string{"app.example.com", "*.wildcard.org"}, serveConn)
	}()

	// Wait for registration to complete
	time.Sleep(100 * time.Millisecond)

	// 1. Test Exact Match End-to-End
	t.Run("Exact Match End to End", func(t *testing.T) {
		tlsConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("tls.Dial to app.example.com failed: %v", err)
		}
		defer tlsConn.Close()

		payload := "Hello via reverse tunnel!"
		if _, err := tlsConn.Write([]byte(payload)); err != nil {
			t.Fatalf("Write to tlsConn failed: %v", err)
		}

		reply := make([]byte, 1024)
		n, err := tlsConn.Read(reply)
		if err != nil {
			t.Fatalf("Read from tlsConn failed: %v", err)
		}

		got := string(reply[:n])
		want := "ECHO from backend for host app.example.com: " + payload
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	// 2. Test Wildcard Match End-to-End
	t.Run("Wildcard Match End to End", func(t *testing.T) {
		tlsConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "service-1.wildcard.org",
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("tls.Dial to service-1.wildcard.org failed: %v", err)
		}
		defer tlsConn.Close()

		payload := "Wildcard hello!"
		if _, err := tlsConn.Write([]byte(payload)); err != nil {
			t.Fatalf("Write to tlsConn failed: %v", err)
		}

		reply := make([]byte, 1024)
		n, err := tlsConn.Read(reply)
		if err != nil {
			t.Fatalf("Read from tlsConn failed: %v", err)
		}

		got := string(reply[:n])
		want := "ECHO from backend for host service-1.wildcard.org: " + payload
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	// 3. Test Unknown Hostname - should be closed by frontend
	t.Run("Unknown Hostname Closes Connection", func(t *testing.T) {
		conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "unregistered.domain.com",
			InsecureSkipVerify: true,
		})
		if err == nil {
			// If handshake initiated, read should return EOF immediately
			buf := make([]byte, 10)
			_, readErr := conn.Read(buf)
			_ = conn.Close()
			if readErr == nil {
				t.Fatalf("expected connection to be closed for unknown hostname, but read succeeded")
			}
		}
	})
}

func TestRejectionWithoutValidClientCertificate(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerAndClient(t)
	defer cleanup()

	// 1. Connection with no client certificate
	t.Run("No client certificate rejected", func(t *testing.T) {
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(generated.CA.CertPEM)

		tlsConfig := &tls.Config{
			RootCAs:    caPool,
			ServerName: "snigateway.internal",
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &tls.Dialer{Config: tlsConfig}
					return dialer.DialContext(ctx, "tcp", serverAddr)
				},
			},
		}

		_, err := client.Get("https://snigateway.internal/v1/connections")
		if err == nil {
			t.Fatal("expected request without client cert to fail, got nil err")
		}
	})

	// 2. Connection with client certificate signed by untrusted/different CA
	t.Run("Untrusted client certificate rejected", func(t *testing.T) {
		otherCerts, err := certs.GenerateAll("snigateway.internal", "rogue-client")
		if err != nil {
			t.Fatalf("GenerateAll rogue certs failed: %v", err)
		}

		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(generated.CA.CertPEM)

		rogueClientCert, err := tls.X509KeyPair(otherCerts.Client.CertPEM, otherCerts.Client.KeyPEM)
		if err != nil {
			t.Fatalf("parsing rogue cert: %v", err)
		}

		tlsConfig := &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{rogueClientCert},
			ServerName:   "snigateway.internal",
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &tls.Dialer{Config: tlsConfig}
					return dialer.DialContext(ctx, "tcp", serverAddr)
				},
			},
		}

		_, err = client.Get("https://snigateway.internal/v1/connections")
		if err == nil {
			t.Fatal("expected request with untrusted client cert to fail, got nil err")
		}
	})
}

func TestCAAllowlistAuthorization(t *testing.T) {
	// Generate two separate sets of client/CA credentials
	certsA, err := certs.GenerateAll("snigateway.internal", "team-a-client")
	if err != nil {
		t.Fatalf("GenerateAll certsA: %v", err)
	}
	certsB, err := certs.GenerateAll("snigateway.internal", "team-b-client")
	if err != nil {
		t.Fatalf("GenerateAll certsB: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certsA.CA.CertPEM)
	caPool.AppendCertsFromPEM(certsB.CA.CertPEM)

	parsedCAA, err := certs.ParseCertificatesFromPEM(certsA.CA.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesFromPEM certsA: %v", err)
	}
	parsedCAB, err := certs.ParseCertificatesFromPEM(certsB.CA.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesFromPEM certsB: %v", err)
	}

	fpA := fmt.Sprintf("%x", sha256.Sum256(parsedCAA[0].Raw))
	fpB := fmt.Sprintf("%x", sha256.Sum256(parsedCAB[0].Raw))

	authorizer := NewCAAuthorizer(map[string][]string{
		fpA: {"*.a.example.com", "a.example.org"},
		fpB: {"*.b.example.com"},
	})

	serverTLS, err := certs.NewServerTLSConfigWithCertPool(caPool, certsA.Server.CertPEM, certsA.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfigWithCertPool failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
		Authorizer:       authorizer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLSA, err := certs.NewClientTLSConfig(certsA.CA.CertPEM, certsA.Client.CertPEM, certsA.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig A failed: %v", err)
	}
	clientA := client.NewClient(serverAddr, clientTLSA)

	clientTLSB, err := certs.NewClientTLSConfig(certsA.CA.CertPEM, certsB.Client.CertPEM, certsB.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig B failed: %v", err)
	}
	clientB := client.NewClient(serverAddr, clientTLSB)

	ctx := t.Context()

	// 1. Team A attempts to register disallowed hostnames -> rejected with 403 Forbidden
	t.Run("Team A rejected for hostnames outside allowlist", func(t *testing.T) {
		_, err := clientA.Register(ctx, []string{"app.b.example.com"})
		if err == nil {
			t.Fatal("expected registration of app.b.example.com by Team A to fail")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "disallowed hostnames: app.b.example.com") {
			t.Fatalf("unexpected error response: %v", err)
		}
	})

	// 2. Team A attempts to register partially allowed hostnames -> rejected completely (not partially registered)
	t.Run("Team A rejected for mixed allowed and disallowed hostnames", func(t *testing.T) {
		_, err := clientA.Register(ctx, []string{"app.a.example.com", "other.example.com"})
		if err == nil {
			t.Fatal("expected registration of mixed hostnames by Team A to fail")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "disallowed hostnames: other.example.com") {
			t.Fatalf("unexpected error response: %v", err)
		}

		// Verify app.a.example.com was NOT partially registered
		clientID := fmt.Sprintf("%s/team-a-client", fpA)
		hosts := srv.RegistrationTable().GetRegisteredHostnames(clientID)
		if len(hosts) != 0 {
			t.Fatalf("expected 0 registered hostnames for Team A, got %v", hosts)
		}
	})

	// 3. Team A registers allowed hostnames -> succeeds
	t.Run("Team A succeeds for allowed hostnames", func(t *testing.T) {
		resp, err := clientA.Register(ctx, []string{"app.a.example.com", "a.example.org"})
		if err != nil {
			t.Fatalf("unexpected registration failure for Team A: %v", err)
		}
		if len(resp.Hostnames) != 2 {
			t.Fatalf("expected 2 registered hostnames, got %v", resp.Hostnames)
		}
	})

	// 4. Team B registers allowed hostnames -> succeeds
	t.Run("Team B succeeds for allowed hostnames", func(t *testing.T) {
		resp, err := clientB.Register(ctx, []string{"service.b.example.com"})
		if err != nil {
			t.Fatalf("unexpected registration failure for Team B: %v", err)
		}
		if len(resp.Hostnames) != 1 {
			t.Fatalf("expected 1 registered hostname, got %v", resp.Hostnames)
		}
	})

	// 5. Team B attempts to register Team A's hostname -> rejected with 403 Forbidden
	t.Run("Team B cannot hijack Team A hostname", func(t *testing.T) {
		_, err := clientB.Register(ctx, []string{"app.a.example.com"})
		if err == nil {
			t.Fatal("expected registration of app.a.example.com by Team B to fail")
		}
		if !strings.Contains(err.Error(), "403") {
			t.Fatalf("unexpected error response: %v", err)
		}
	})
}
