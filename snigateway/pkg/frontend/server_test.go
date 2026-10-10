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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/quic-go/quic-go"
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

func startBackendWorker(ctx context.Context, t *testing.T, c *client.Client, hostnames []string, cert tls.Certificate, onConn func(net.Conn)) string {
	sessID, sessErrCh, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if len(hostnames) > 0 {
		if _, err := c.Register(ctx, sessID, hostnames); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	// Maintain pool of 4 idle connections
	for i := 0; i < 4; i++ {
		go func() {
			for {
				if ctx.Err() != nil {
					return
				}
				dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				conn, err := c.DialTunnel(dialCtx, sessID)
				cancel()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(50 * time.Millisecond):
						continue
					}
				}

				bufReader := bufio.NewReader(conn)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					_ = conn.Close()
					continue
				}

				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					_, _ = io.ReadFull(bufReader, remaining)
				}

				proxyConn := proxyproto.NewConn(conn, hdr.SrcAddr, hdr.DstAddr, remaining)

				if onConn != nil {
					go onConn(proxyConn)
				}
			}
		}()
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-sessErrCh:
		}
	}()

	return sessID
}

type prefixedConn struct {
	net.Conn
	prefix []byte
	pos    int
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if c.pos < len(c.prefix) {
		n := copy(b, c.prefix[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
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

	handleConn := func(conn net.Conn) {
		defer conn.Close()
		tlsServer := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{backendCert},
		})
		defer tlsServer.Close()

		buf := make([]byte, 1024)
		n, err := tlsServer.Read(buf)
		if err != nil {
			return
		}
		reqStr := string(buf[:n])
		respStr := fmt.Sprintf("ECHO: %s", reqStr)
		_, _ = tlsServer.Write([]byte(respStr))
	}

	startBackendWorker(ctx, t, c, []string{"app.example.com", "*.wildcard.org"}, backendCert, handleConn)

	// Wait for registration and pool
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
		want := "ECHO: " + payload
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
		want := "ECHO: " + payload
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

		_, err := client.Get("https://snigateway.internal/v1/session")
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

		_, err = client.Get("https://snigateway.internal/v1/session")
		if err == nil {
			t.Fatal("expected request with untrusted client cert to fail, got nil err")
		}
	})
}

func TestCAAllowlistAuthorization(t *testing.T) {
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

	sessIDA, _, err := clientA.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession A failed: %v", err)
	}

	sessIDB, _, err := clientB.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession B failed: %v", err)
	}

	// 1. Team A attempts to register disallowed hostnames -> rejected with 403 Forbidden
	t.Run("Team A rejected for hostnames outside allowlist", func(t *testing.T) {
		_, err := clientA.Register(ctx, sessIDA, []string{"app.b.example.com"})
		if err == nil {
			t.Fatal("expected registration of app.b.example.com by Team A to fail")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "disallowed hostnames: app.b.example.com") {
			t.Fatalf("unexpected error response: %v", err)
		}
	})

	// 2. Team A attempts to register partially allowed hostnames -> rejected completely
	t.Run("Team A rejected for mixed allowed and disallowed hostnames", func(t *testing.T) {
		_, err := clientA.Register(ctx, sessIDA, []string{"app.a.example.com", "other.example.com"})
		if err == nil {
			t.Fatal("expected registration of mixed hostnames by Team A to fail")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "disallowed hostnames: other.example.com") {
			t.Fatalf("unexpected error response: %v", err)
		}

		hosts := srv.RegistrationTable().GetRegisteredHostnames(sessIDA)
		if len(hosts) != 0 {
			t.Fatalf("expected 0 registered hostnames for Team A, got %v", hosts)
		}
	})

	// 3. Team A registers allowed hostnames -> succeeds
	t.Run("Team A succeeds for allowed hostnames", func(t *testing.T) {
		resp, err := clientA.Register(ctx, sessIDA, []string{"app.a.example.com", "a.example.org"})
		if err != nil {
			t.Fatalf("unexpected registration failure for Team A: %v", err)
		}
		if len(resp.Hostnames) != 2 {
			t.Fatalf("expected 2 registered hostnames, got %v", resp.Hostnames)
		}
	})

	// 4. Team B registers allowed hostnames -> succeeds
	t.Run("Team B succeeds for allowed hostnames", func(t *testing.T) {
		resp, err := clientB.Register(ctx, sessIDB, []string{"service.b.example.com"})
		if err != nil {
			t.Fatalf("unexpected registration failure for Team B: %v", err)
		}
		if len(resp.Hostnames) != 1 {
			t.Fatalf("expected 1 registered hostname, got %v", resp.Hostnames)
		}
	})

	// 5. Team B attempts to register Team A's hostname -> rejected with 403 Forbidden
	t.Run("Team B cannot hijack Team A hostname", func(t *testing.T) {
		_, err := clientB.Register(ctx, sessIDB, []string{"app.a.example.com"})
		if err == nil {
			t.Fatal("expected registration of app.a.example.com by Team B to fail")
		}
		if !strings.Contains(err.Error(), "403") {
			t.Fatalf("unexpected error response: %v", err)
		}
	})
}

func TestMultipleSessionsLoadBalancing(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerAndClient(t)
	defer cleanup()

	backendCert, err := generateTestBackendCert("multi.example.com")
	if err != nil {
		t.Fatalf("failed to generate backend cert: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c1 := client.NewClient(serverAddr, clientTLS)
	c2 := client.NewClient(serverAddr, clientTLS)

	var session1Events, session2Events atomic.Int32

	handleSession1 := func(conn net.Conn) {
		session1Events.Add(1)
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
		defer tlsConn.Close()
		buf := make([]byte, 1024)
		_, _ = tlsConn.Read(buf)
		_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\nsession-1"))
	}

	handleSession2 := func(conn net.Conn) {
		session2Events.Add(1)
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
		defer tlsConn.Close()
		buf := make([]byte, 1024)
		_, _ = tlsConn.Read(buf)
		_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\nsession-2"))
	}

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	startBackendWorker(ctx1, t, c1, []string{"multi.example.com"}, backendCert, handleSession1)

	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	startBackendWorker(ctx2, t, c2, []string{"multi.example.com"}, backendCert, handleSession2)

	time.Sleep(100 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				ServerName:         "multi.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "multi.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	// Send 4 HTTP requests with SNI "multi.example.com"
	for i := 0; i < 4; i++ {
		resp, err := httpClient.Get("https://multi.example.com/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d got status %d", i, resp.StatusCode)
		}
	}

	s1 := session1Events.Load()
	s2 := session2Events.Load()
	t.Logf("session1 events: %d, session2 events: %d", s1, s2)
	if s1 == 0 || s2 == 0 || s1+s2 != 4 {
		t.Fatalf("expected load balancing across both sessions (sum=4), got s1=%d, s2=%d", s1, s2)
	}

	// Close session 1; session 2 should still serve traffic
	cancel1()
	time.Sleep(100 * time.Millisecond)

	resp, err := httpClient.Get("https://multi.example.com/test")
	if err != nil {
		t.Fatalf("request after session 1 closed failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 after session 1 closed, got: %d", resp.StatusCode)
	}
}

func TestFailover_DeadPooledConnection(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerAndClient(t)
	defer cleanup()

	backendCert, err := generateTestBackendCert("failover.example.com")
	if err != nil {
		t.Fatalf("failed to generate backend cert: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	sessID, _, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if _, err := c.Register(ctx, sessID, []string{"failover.example.com"}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Dial 1st connection and immediately close it on backend side (dead pooled connection)
	deadConn, err := c.DialTunnel(ctx, sessID)
	if err != nil {
		t.Fatalf("DialTunnel deadConn failed: %v", err)
	}
	_ = deadConn.Close()

	// Dial 2nd connection that is healthy and serves backend TLS
	healthyConn, err := c.DialTunnel(ctx, sessID)
	if err != nil {
		t.Fatalf("DialTunnel healthyConn failed: %v", err)
	}
	defer healthyConn.Close()

	go func() {
		bufReader := bufio.NewReader(healthyConn)
		hdr, err := proxyproto.Decode(bufReader)
		if err != nil {
			return
		}
		var remaining []byte
		if bufReader.Buffered() > 0 {
			remaining = make([]byte, bufReader.Buffered())
			_, _ = io.ReadFull(bufReader, remaining)
		}
		proxyConn := proxyproto.NewConn(healthyConn, hdr.SrcAddr, hdr.DstAddr, remaining)
		tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
		defer tlsConn.Close()
		buf := make([]byte, 1024)
		_, _ = tlsConn.Read(buf)
		_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 18\r\n\r\nrecovered-from-rst"))
	}()

	time.Sleep(50 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "failover.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "failover.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("https://failover.example.com/test")
	if err != nil {
		t.Fatalf("expected successful replay after dead pooled connection, got: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "recovered-from-rst" {
		t.Fatalf("expected response 'recovered-from-rst', got %q", string(body))
	}
}

func TestFailover_UnresponsiveBackend(t *testing.T) {
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
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Configure with short PerAttemptTimeout (200ms) for fast test execution
	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:   serverTLS,
		InternalHostname:  "snigateway.internal",
		ConnectTimeout:    5 * time.Second,
		PerAttemptTimeout: 200 * time.Millisecond,
		ReadSNITimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	backendCert, err := generateTestBackendCert("unresponsive.example.com")
	if err != nil {
		t.Fatalf("generateTestBackendCert: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c1 := client.NewClient(serverAddr, clientTLS)
	c2 := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Session 1: unresponsive (reads PROXY header + ClientHello, but sleeps and never responds)
	sessID1, _, err := c1.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession 1 failed: %v", err)
	}
	if _, err := c1.Register(ctx, sessID1, []string{"unresponsive.example.com"}); err != nil {
		t.Fatalf("Register 1 failed: %v", err)
	}

	conn1, err := c1.DialTunnel(ctx, sessID1)
	if err != nil {
		t.Fatalf("DialTunnel 1 failed: %v", err)
	}
	defer conn1.Close()

	go func() {
		buf := make([]byte, 4096)
		_, _ = conn1.Read(buf)
		// Sleep without responding to trigger per-attempt timeout on frontend
		time.Sleep(2 * time.Second)
	}()

	// Session 2: responsive healthy backend
	sessID2, _, err := c2.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession 2 failed: %v", err)
	}
	if _, err := c2.Register(ctx, sessID2, []string{"unresponsive.example.com"}); err != nil {
		t.Fatalf("Register 2 failed: %v", err)
	}

	conn2, err := c2.DialTunnel(ctx, sessID2)
	if err != nil {
		t.Fatalf("DialTunnel 2 failed: %v", err)
	}
	defer conn2.Close()

	go func() {
		bufReader := bufio.NewReader(conn2)
		hdr, err := proxyproto.Decode(bufReader)
		if err != nil {
			return
		}
		var remaining []byte
		if bufReader.Buffered() > 0 {
			remaining = make([]byte, bufReader.Buffered())
			_, _ = io.ReadFull(bufReader, remaining)
		}
		proxyConn := proxyproto.NewConn(conn2, hdr.SrcAddr, hdr.DstAddr, remaining)
		tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
		defer tlsConn.Close()
		buf := make([]byte, 1024)
		_, _ = tlsConn.Read(buf)
		_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 17\r\n\r\nfailover-success!"))
	}()

	time.Sleep(50 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "unresponsive.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "unresponsive.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("https://unresponsive.example.com/test")
	if err != nil {
		t.Fatalf("expected failover to succeed on healthy session, got: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "failover-success!" {
		t.Fatalf("expected response 'failover-success!', got %q", string(body))
	}
}

func setupTestServerWithUDPAndClient(t *testing.T) (*Server, string, *certs.GeneratedCerts, func()) {
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

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:   serverTLS,
		InternalHostname:  "snigateway.internal",
		ConnectTimeout:    5 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		ReadSNITimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	cleanup := func() {
		_ = srv.Close()
	}

	return srv, serverAddr, generated, cleanup
}

func TestQUIC_SessionEstablishmentAndRegistration(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	qConn, err := c.DialQUIC(ctx)
	if err != nil {
		t.Fatalf("DialQUIC failed: %v", err)
	}
	defer qConn.CloseWithError(0, "test done")

	ctrlStream, err := qConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync failed: %v", err)
	}
	defer ctrlStream.Close()

	if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
		t.Fatalf("writing handshake failed: %v", err)
	}

	reader := bufio.NewReader(ctrlStream)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("reading SessionResponse failed: %v", err)
	}

	var sessResp api.SessionResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
		t.Fatalf("unmarshal SessionResponse failed: %v", err)
	}
	if sessResp.SessionID == "" {
		t.Fatalf("expected non-empty SessionID")
	}

	parsedCACerts, err := certs.ParseCertificatesFromPEM(generated.CA.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesFromPEM failed: %v", err)
	}
	caFP := fmt.Sprintf("%x", sha256.Sum256(parsedCACerts[0].Raw))
	clientID := fmt.Sprintf("%s/test-cluster-client", caFP)

	// Send registration request
	regReq := api.RegistrationRequest{
		Hostnames: []string{"quic1.example.com", "quic2.example.com"},
	}
	reqBytes, _ := json.Marshal(regReq)
	if _, err := ctrlStream.Write(append(reqBytes, '\n')); err != nil {
		t.Fatalf("writing RegistrationRequest failed: %v", err)
	}

	respLine, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("reading RegistrationResponse failed: %v", err)
	}

	var regResp api.RegistrationResponse
	if err := json.Unmarshal(bytes.TrimSpace(respLine), &regResp); err != nil {
		t.Fatalf("unmarshal RegistrationResponse failed: %v", err)
	}

	registered := srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
	if len(registered) != 2 {
		t.Fatalf("expected 2 registered hostnames, got %v", registered)
	}
}

func TestQUIC_StreamPerConnectionAndProxyHeader(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	backendCert, err := generateTestBackendCert("stream.example.com")
	if err != nil {
		t.Fatalf("generateTestBackendCert failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	qConn, err := c.DialQUIC(ctx)
	if err != nil {
		t.Fatalf("DialQUIC failed: %v", err)
	}
	defer qConn.CloseWithError(0, "test done")

	ctrlStream, err := qConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync failed: %v", err)
	}
	defer ctrlStream.Close()

	if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
		t.Fatalf("writing handshake failed: %v", err)
	}

	reader := bufio.NewReader(ctrlStream)
	_, err = reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("reading SessionResponse failed: %v", err)
	}

	// Register hostname
	regReq := api.RegistrationRequest{
		Hostnames: []string{"stream.example.com"},
	}
	reqBytes, _ := json.Marshal(regReq)
	_, _ = ctrlStream.Write(append(reqBytes, '\n'))
	_, _ = reader.ReadBytes('\n')

	var streamCount atomic.Int32
	var authorityReceived atomic.Value

	// Backend accepts streams from frontend
	go func() {
		for {
			stream, err := qConn.AcceptStream(ctx)
			if err != nil {
				return
			}
			streamCount.Add(1)

			go func(s *quic.Stream) {
				streamConn := api.NewQUICStreamConn(s, qConn)
				bufReader := bufio.NewReader(streamConn)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					_ = streamConn.Close()
					return
				}
				authorityReceived.Store(hdr.Authority)

				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					_, _ = io.ReadFull(bufReader, remaining)
				}

				proxyConn := proxyproto.NewConn(streamConn, hdr.SrcAddr, hdr.DstAddr, remaining)
				tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
				defer tlsConn.Close()

				buf := make([]byte, 1024)
				_, _ = tlsConn.Read(buf)
				_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 13\r\n\r\nhello-stream!"))
			}(stream)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "stream.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "stream.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	// Send 3 requests
	for i := 0; i < 3; i++ {
		resp, err := httpClient.Get("https://stream.example.com/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello-stream!" {
			t.Fatalf("expected 'hello-stream!', got %q", string(body))
		}
	}

	if streamCount.Load() != 3 {
		t.Fatalf("expected 3 separate streams opened, got %d", streamCount.Load())
	}
	if auth, ok := authorityReceived.Load().(string); !ok || auth != "stream.example.com" {
		t.Fatalf("expected PROXY v2 authority 'stream.example.com', got %v", auth)
	}
}

func TestQUIC_SessionTeardownRemovesRegistrations(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	qConn, err := c.DialQUIC(ctx)
	if err != nil {
		t.Fatalf("DialQUIC failed: %v", err)
	}

	ctrlStream, err := qConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync failed: %v", err)
	}

	if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
		t.Fatalf("writing handshake failed: %v", err)
	}

	reader := bufio.NewReader(ctrlStream)
	line, _ := reader.ReadBytes('\n')
	var sessResp api.SessionResponse
	_ = json.Unmarshal(bytes.TrimSpace(line), &sessResp)

	// Register hostname
	regReq := api.RegistrationRequest{
		Hostnames: []string{"teardown.example.com"},
	}
	reqBytes, _ := json.Marshal(regReq)
	_, _ = ctrlStream.Write(append(reqBytes, '\n'))
	_, _ = reader.ReadBytes('\n')

	parsedCACerts, err := certs.ParseCertificatesFromPEM(generated.CA.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatesFromPEM failed: %v", err)
	}
	caFP := fmt.Sprintf("%x", sha256.Sum256(parsedCACerts[0].Raw))
	clientID := fmt.Sprintf("%s/test-cluster-client", caFP)

	registered := srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
	if len(registered) != 1 || registered[0] != "teardown.example.com" {
		t.Fatalf("expected teardown.example.com registered, got %v", registered)
	}

	// Close QUIC connection
	_ = qConn.CloseWithError(0, "client teardown")

	// Wait for registrations to be removed
	deadline := time.Now().Add(2 * time.Second)
	var removed bool
	for time.Now().Before(deadline) {
		reg := srv.RegistrationTable().GetRegisteredHostnamesForClient(clientID)
		if len(reg) == 0 {
			removed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !removed {
		t.Fatalf("expected registrations to be removed on QUIC session teardown")
	}
}

func TestQUIC_FailoverFromDeadStream(t *testing.T) {
	_, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	backendCert, err := generateTestBackendCert("quic-failover.example.com")
	if err != nil {
		t.Fatalf("generateTestBackendCert failed: %v", err)
	}

	c1 := client.NewClient(serverAddr, clientTLS)
	c2 := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Session 1 (flaky backend: resets first stream immediately before sending byte)
	qConn1, err := c1.DialQUIC(ctx)
	if err != nil {
		t.Fatalf("DialQUIC 1 failed: %v", err)
	}
	defer qConn1.CloseWithError(0, "done")

	ctrl1, _ := qConn1.OpenStreamSync(ctx)
	_, _ = ctrl1.Write([]byte("{\"type\":\"session\"}\n"))
	r1 := bufio.NewReader(ctrl1)
	_, _ = r1.ReadBytes('\n')
	req1, _ := json.Marshal(api.RegistrationRequest{Hostnames: []string{"quic-failover.example.com"}})
	_, _ = ctrl1.Write(append(req1, '\n'))
	_, _ = r1.ReadBytes('\n')

	// Flaky backend immediately resets incoming stream
	go func() {
		for {
			s, err := qConn1.AcceptStream(ctx)
			if err != nil {
				return
			}
			s.CancelRead(42)
			_ = s.Close()
		}
	}()

	// Session 2 (healthy backend)
	qConn2, err := c2.DialQUIC(ctx)
	if err != nil {
		t.Fatalf("DialQUIC 2 failed: %v", err)
	}
	defer qConn2.CloseWithError(0, "done")

	ctrl2, _ := qConn2.OpenStreamSync(ctx)
	_, _ = ctrl2.Write([]byte("{\"type\":\"session\"}\n"))
	r2 := bufio.NewReader(ctrl2)
	_, _ = r2.ReadBytes('\n')
	req2, _ := json.Marshal(api.RegistrationRequest{Hostnames: []string{"quic-failover.example.com"}})
	_, _ = ctrl2.Write(append(req2, '\n'))
	_, _ = r2.ReadBytes('\n')

	// Healthy backend handles stream
	go func() {
		for {
			s, err := qConn2.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func(stream *quic.Stream) {
				streamConn := api.NewQUICStreamConn(stream, qConn2)
				bufReader := bufio.NewReader(streamConn)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					_ = streamConn.Close()
					return
				}
				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					_, _ = io.ReadFull(bufReader, remaining)
				}
				proxyConn := proxyproto.NewConn(streamConn, hdr.SrcAddr, hdr.DstAddr, remaining)
				tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
				defer tlsConn.Close()

				buf := make([]byte, 1024)
				_, _ = tlsConn.Read(buf)
				_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 17\r\n\r\nquic-failover-ok!"))
			}(s)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "quic-failover.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "quic-failover.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("https://quic-failover.example.com/test")
	if err != nil {
		t.Fatalf("expected QUIC failover to succeed, got: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "quic-failover-ok!" {
		t.Fatalf("expected response 'quic-failover-ok!', got %q", string(body))
	}
}

func TestChanListener_ConcurrentSendAndClose(t *testing.T) {
	lis := newChanListener(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})

	const numSenders = 10
	var wg sync.WaitGroup
	wg.Add(numSenders)

	for i := 0; i < numSenders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				c1, c2 := net.Pipe()
				err := lis.SendConn(c1)
				if err != nil {
					_ = c1.Close()
					_ = c2.Close()
					return
				}
				_ = c2.Close()
			}
		}()
	}

	// Concurrently accept connections
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)
	_ = lis.Close()

	wg.Wait()

	// Subsequent SendConn should return net.ErrClosed
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := lis.SendConn(c1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed from SendConn after Close, got: %v", err)
	}

	// Accept should return net.ErrClosed
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed from Accept after Close, got: %v", err)
	}
}
