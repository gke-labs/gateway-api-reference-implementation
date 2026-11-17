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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
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

var (
	testListenersMu sync.Mutex
	testListeners   = make(map[string]net.Listener)
)

func registerTestBackendListener(addr string, ln net.Listener) {
	testListenersMu.Lock()
	defer testListenersMu.Unlock()
	testListeners[addr] = ln
}

func unregisterTestBackendListener(addr string) {
	testListenersMu.Lock()
	defer testListenersMu.Unlock()
	delete(testListeners, addr)
}

func testDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	testListenersMu.Lock()
	ln := testListeners[address]
	testListenersMu.Unlock()
	if ln == nil {
		return nil, fmt.Errorf("no listener registered for %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
}

func newServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert PEM")
	}
	return certs.NewServerTLSConfigWithCertPool(caPool, serverCertPEM, serverKeyPEM)
}

func setupTestServerAndClient(t *testing.T) (*Server, string, *certs.GeneratedCerts, func()) {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	serverAddr := ln.Addr().String()

	_, prefixNet, err := net.ParseCIDR("fd00:1234::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    newFakeWireGuardDevice(),
		WireGuardPublicKey: feKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    prefixNet,
		DialContext:        testDialContext,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		_ = srv.ServeWithHTTP([]net.Listener{ln}, nil)
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

	_, clientKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	wgResp, err := c.ExchangeWireGuard(ctx, sessID, clientKey.String())
	if err != nil {
		t.Fatalf("ExchangeWireGuard failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	tunnelAddr := net.JoinHostPort(wgResp.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	registerTestBackendListener(tunnelAddr, ln)

	go func() {
		<-ctx.Done()
		unregisterTestBackendListener(tunnelAddr)
		if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("failed to close listener: %v", closeErr)
		}
	}()

	if len(hostnames) > 0 {
		if _, err := c.Register(ctx, sessID, hostnames); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				bufReader := bufio.NewReader(c)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
						t.Logf("failed to close conn on decode error: %v", closeErr)
					}
					return
				}

				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					if _, readErr := io.ReadFull(bufReader, remaining); readErr != nil {
						if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
							t.Logf("failed to close conn on read error: %v", closeErr)
						}
						return
					}
				}

				proxyConn := proxyproto.NewConn(c, hdr.SrcAddr, hdr.DstAddr, remaining)
				if onConn != nil {
					go onConn(proxyConn)
				}
			}(conn)
		}
	}()

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

	// Wait for registration and tunnel
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

func startHTTPBackendWorker(ctx context.Context, t *testing.T, c *client.Client, hostnames []string, onConn func(*proxyproto.Header, net.Conn)) string {
	sessID, sessErrCh, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	_, clientKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	wgResp, err := c.ExchangeWireGuard(ctx, sessID, clientKey.String())
	if err != nil {
		t.Fatalf("ExchangeWireGuard failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	tunnelAddr := net.JoinHostPort(wgResp.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	registerTestBackendListener(tunnelAddr, ln)

	go func() {
		<-ctx.Done()
		unregisterTestBackendListener(tunnelAddr)
		if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("failed to close listener: %v", closeErr)
		}
	}()

	if len(hostnames) > 0 {
		if _, err := c.Register(ctx, sessID, hostnames); err != nil {
			t.Fatalf("Register failed: %v", err)
		}
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				bufReader := bufio.NewReader(c)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
						t.Logf("failed to close conn on decode error: %v", closeErr)
					}
					return
				}

				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					if _, readErr := io.ReadFull(bufReader, remaining); readErr != nil {
						if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
							t.Logf("failed to close conn on read error: %v", closeErr)
						}
						return
					}
				}

				proxyConn := proxyproto.NewConn(c, hdr.SrcAddr, hdr.DstAddr, remaining)

				if onConn != nil {
					go onConn(hdr, proxyConn)
				}
			}(conn)
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
		case <-sessErrCh:
		}
	}()

	return sessID
}

func TestHTTPHostRouting(t *testing.T) {
	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	tlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tlsListener failed: %v", err)
	}
	defer tlsListener.Close()

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen httpListener failed: %v", err)
	}
	defer httpListener.Close()

	_, prefixNet, err := net.ParseCIDR("fd00:1234::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		PerAttemptTimeout:  500 * time.Millisecond,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    newFakeWireGuardDevice(),
		WireGuardPublicKey: feKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    prefixNet,
		DialContext:        testDialContext,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.ServeWithHTTP([]net.Listener{tlsListener}, []net.Listener{httpListener})
	}()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(tlsListener.Addr().String(), clientTLS)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	type receivedRequest struct {
		authority string
		srcAddr   string
		reqBytes  string
	}
	receivedCh := make(chan receivedRequest, 10)

	handleConn := func(hdr *proxyproto.Header, conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		// Send initial backend byte(s) back so routeToBackend commits and splices
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")); err != nil {
			return
		}

		var src string
		if hdr.SrcAddr != nil {
			src = hdr.SrcAddr.String()
		}
		receivedCh <- receivedRequest{
			authority: hdr.Authority,
			srcAddr:   src,
			reqBytes:  string(buf[:n]),
		}
	}

	sessID := startHTTPBackendWorker(ctx, t, c, []string{"plain.example.com", "*.wildcard.org"}, handleConn)
	if sessID == "" {
		t.Fatal("expected non-empty session ID from startHTTPBackendWorker")
	}

	// Wait for registration
	deadline := time.Now().Add(5 * time.Second)
	for {
		if len(srv.RegistrationTable().MatchSessions("plain.example.com")) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for session registration")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Valid HTTP/1.1 request reaches backend with correct PROXY header and request bytes
	t.Run("Valid HTTP/1.1 request routed by Host", func(t *testing.T) {
		conn, err := net.Dial("tcp", httpListener.Addr().String())
		if err != nil {
			t.Fatalf("Dial httpListener failed: %v", err)
		}
		defer conn.Close()

		httpRequest := "GET /.well-known/acme-challenge/test-token HTTP/1.1\r\nHost: plain.example.com\r\nUser-Agent: test\r\n\r\n"
		if _, err := conn.Write([]byte(httpRequest)); err != nil {
			t.Fatalf("Write httpRequest failed: %v", err)
		}

		select {
		case req := <-receivedCh:
			if req.authority != "plain.example.com" {
				t.Fatalf("expected authority plain.example.com, got %q", req.authority)
			}
			clientHost, _, err := net.SplitHostPort(conn.LocalAddr().String())
			if err != nil {
				t.Fatalf("SplitHostPort(conn.LocalAddr): %v", err)
			}
			srcHost, _, err := net.SplitHostPort(req.srcAddr)
			if err != nil {
				t.Fatalf("SplitHostPort(req.srcAddr): %v", err)
			}
			if srcHost != clientHost {
				t.Fatalf("expected srcHost %q, got %q", clientHost, srcHost)
			}
			if req.reqBytes != httpRequest {
				t.Fatalf("expected reqBytes %q, got %q", httpRequest, req.reqBytes)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for backend to receive request")
		}

		// Read response from backend through splice
		respBuf := make([]byte, 1024)
		n, err := conn.Read(respBuf)
		if err != nil {
			t.Fatalf("reading response: %v", err)
		}
		if !strings.Contains(string(respBuf[:n]), "200 OK") {
			t.Fatalf("unexpected response: %s", string(respBuf[:n]))
		}
	})

	// 2. Request with Host containing port is stripped and routed properly
	t.Run("Host with port is stripped and routed", func(t *testing.T) {
		conn, err := net.Dial("tcp", httpListener.Addr().String())
		if err != nil {
			t.Fatalf("Dial httpListener failed: %v", err)
		}
		defer conn.Close()

		httpRequest := "GET /index.html HTTP/1.1\r\nHost: plain.example.com:80\r\n\r\n"
		if _, err := conn.Write([]byte(httpRequest)); err != nil {
			t.Fatalf("Write httpRequest failed: %v", err)
		}

		select {
		case req := <-receivedCh:
			if req.authority != "plain.example.com" {
				t.Fatalf("expected authority plain.example.com, got %q", req.authority)
			}
			if req.reqBytes != httpRequest {
				t.Fatalf("expected reqBytes %q, got %q", httpRequest, req.reqBytes)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for backend to receive request")
		}
	})

	// 3. Request with unregistered Host is closed without contacting backend
	t.Run("Unregistered Host closes connection", func(t *testing.T) {
		conn, err := net.Dial("tcp", httpListener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: unregistered.domain.com\r\n\r\n")); err != nil {
			t.Fatalf("writing request: %v", err)
		}
		buf := make([]byte, 10)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected connection to be closed for unregistered host")
		}
		select {
		case req := <-receivedCh:
			t.Fatalf("unexpected backend contact for unregistered host: %+v", req)
		default:
		}
	})

	// 4. Request without Host is closed without contacting backend
	t.Run("Missing Host closes connection", func(t *testing.T) {
		conn, err := net.Dial("tcp", httpListener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n")); err != nil {
			t.Fatalf("writing request: %v", err)
		}
		buf := make([]byte, 10)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatal("expected connection to be closed for missing host header")
		}
		select {
		case req := <-receivedCh:
			t.Fatalf("unexpected backend contact for missing host: %+v", req)
		default:
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
		_ = srv.ServeWithHTTP([]net.Listener{ln}, nil)
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

func TestFailover_UnresponsiveBackend(t *testing.T) {
	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	_, prefixNet, err := net.ParseCIDR("fd00:1234::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Configure with short PerAttemptTimeout (200ms) for fast test execution
	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		PerAttemptTimeout:  200 * time.Millisecond,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    newFakeWireGuardDevice(),
		WireGuardPublicKey: feKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    prefixNet,
		DialContext:        testDialContext,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.ServeWithHTTP([]net.Listener{ln}, nil)
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

	_, clientKey1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 1: %v", err)
	}
	wgResp1, err := c1.ExchangeWireGuard(ctx, sessID1, clientKey1.String())
	if err != nil {
		t.Fatalf("ExchangeWireGuard 1: %v", err)
	}
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 1: %v", err)
	}
	defer ln1.Close()
	tunnelAddr1 := net.JoinHostPort(wgResp1.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	registerTestBackendListener(tunnelAddr1, ln1)
	defer unregisterTestBackendListener(tunnelAddr1)

	go func() {
		for {
			conn, err := ln1.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				if _, readErr := c.Read(buf); readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
					t.Logf("unresponsive backend read error: %v", readErr)
				}
				// Wait for test to end; do not reply so frontend attempt times out
				<-ctx.Done()
				if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					t.Logf("unresponsive backend close error: %v", closeErr)
				}
			}(conn)
		}
	}()

	// Session 2: responsive healthy backend
	sessID2, _, err := c2.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession 2 failed: %v", err)
	}
	if _, err := c2.Register(ctx, sessID2, []string{"unresponsive.example.com"}); err != nil {
		t.Fatalf("Register 2 failed: %v", err)
	}

	_, clientKey2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}
	wgResp2, err := c2.ExchangeWireGuard(ctx, sessID2, clientKey2.String())
	if err != nil {
		t.Fatalf("ExchangeWireGuard 2: %v", err)
	}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 2: %v", err)
	}
	defer ln2.Close()
	tunnelAddr2 := net.JoinHostPort(wgResp2.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	registerTestBackendListener(tunnelAddr2, ln2)
	defer unregisterTestBackendListener(tunnelAddr2)

	go func() {
		for {
			conn, err := ln2.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				bufReader := bufio.NewReader(c)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
						t.Logf("close on decode error: %v", closeErr)
					}
					return
				}
				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					if _, readErr := io.ReadFull(bufReader, remaining); readErr != nil {
						if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
							t.Logf("close on read error: %v", closeErr)
						}
						return
					}
				}
				proxyConn := proxyproto.NewConn(c, hdr.SrcAddr, hdr.DstAddr, remaining)
				tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
				defer tlsConn.Close()
				buf := make([]byte, 1024)
				if _, readErr := tlsConn.Read(buf); readErr != nil && !errors.Is(readErr, io.EOF) {
					t.Logf("tls read error: %v", readErr)
				}
				if _, writeErr := tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 17\r\n\r\nfailover-success!")); writeErr != nil {
					t.Logf("tls write error: %v", writeErr)
				}
			}(conn)
		}
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

func TestFrontendServer_MaxConnections(t *testing.T) {
	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   2 * time.Second,
		ReadSNITimeout:   1 * time.Second,
		MaxConnections:   2,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.ServeWithHTTP([]net.Listener{ln}, nil)
	}()

	serverAddr := ln.Addr().String()

	// Conn 1 (admitted)
	conn1, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial conn1: %v", err)
	}
	defer conn1.Close()

	// Conn 2 (admitted)
	conn2, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial conn2: %v", err)
	}
	defer conn2.Close()

	// Conn 3 (N+1 = 3 > 2: refused by server and immediately closed)
	conn3, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial conn3: %v", err)
	}
	defer conn3.Close()

	_ = conn3.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 64)
	_, readErr := conn3.Read(buf)
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
		t.Fatalf("expected conn3 to be refused and closed (EOF), got %v", readErr)
	}

	// Close Conn 1 to free up a slot
	conn1.Close()
	time.Sleep(30 * time.Millisecond)

	// Conn 4 (now admitted because active conns is 1 <= 2)
	conn4, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial conn4: %v", err)
	}
	defer conn4.Close()

	// Send invalid SNI to verify connection was accepted and handled by server
	_ = conn4.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn4.Write([]byte("not-tls\n"))
}

func TestFrontendServer_IdleTimeout(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen ln1: %v", err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen ln2: %v", err)
	}
	defer ln2.Close()

	t.Run("splice idle timeout enabled closes connections", func(t *testing.T) {
		errCh := make(chan error, 2)
		var c1, c2 net.Conn
		go func() {
			var err error
			c1, err = ln1.Accept()
			errCh <- err
		}()
		go func() {
			var err error
			c2, err = ln2.Accept()
			errCh <- err
		}()

		dial1, err := net.Dial("tcp", ln1.Addr().String())
		if err != nil {
			t.Fatalf("dial1 failed: %v", err)
		}
		defer dial1.Close()

		dial2, err := net.Dial("tcp", ln2.Addr().String())
		if err != nil {
			t.Fatalf("dial2 failed: %v", err)
		}
		defer dial2.Close()

		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("accept failed: %v", err)
			}
		}

		go spliceConnections(c1, c2, 100*time.Millisecond)

		// Test initial communication
		if _, err := dial1.Write([]byte("ping\n")); err != nil {
			t.Fatalf("dial1 write failed: %v", err)
		}
		buf := make([]byte, 64)
		if _, err := dial2.Read(buf); err != nil {
			t.Fatalf("dial2 read failed: %v", err)
		}

		// Now stay idle for 100ms
		start := time.Now()
		_ = dial1.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			_, rerr := dial1.Read(buf)
			if rerr != nil {
				break
			}
		}
		elapsed := time.Since(start)

		if elapsed < 50*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("expected idle connection to be closed around 100ms, elapsed %v", elapsed)
		}
	})

	t.Run("splice idle timeout disabled keeps connections untouched", func(t *testing.T) {
		errCh := make(chan error, 2)
		var c1, c2 net.Conn
		go func() {
			var err error
			c1, err = ln1.Accept()
			errCh <- err
		}()
		go func() {
			var err error
			c2, err = ln2.Accept()
			errCh <- err
		}()

		dial1, err := net.Dial("tcp", ln1.Addr().String())
		if err != nil {
			t.Fatalf("dial1 failed: %v", err)
		}
		defer dial1.Close()

		dial2, err := net.Dial("tcp", ln2.Addr().String())
		if err != nil {
			t.Fatalf("dial2 failed: %v", err)
		}
		defer dial2.Close()

		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("accept failed: %v", err)
			}
		}

		go spliceConnections(c1, c2, 0) // disabled

		time.Sleep(150 * time.Millisecond)

		if _, err := dial1.Write([]byte("hello still here\n")); err != nil {
			t.Fatalf("dial1 write failed: %v", err)
		}
		buf := make([]byte, 64)
		_ = dial2.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := dial2.Read(buf)
		if err != nil {
			t.Fatalf("dial2 read failed: %v", err)
		}
		if string(buf[:n]) != "hello still here\n" {
			t.Errorf("expected %q, got %q", "hello still here\n", string(buf[:n]))
		}
	})
}

func setupTestServerWithConfig(t *testing.T, modifyCfg func(*ServerConfig)) (*Server, string, *certs.GeneratedCerts, func()) {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	serverAddr := ln.Addr().String()

	cfg := ServerConfig{
		ServerTLSConfig:   serverTLS,
		InternalHostname:  "snigateway.internal",
		ConnectTimeout:    5 * time.Second,
		PerAttemptTimeout: 500 * time.Millisecond,
		ReadSNITimeout:    2 * time.Second,
	}
	if modifyCfg != nil {
		modifyCfg(&cfg)
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		_ = srv.ServeWithHTTP([]net.Listener{ln}, nil)
	}()

	cleanup := func() {
		_ = srv.Close()
	}

	return srv, serverAddr, generated, cleanup
}

func TestRegistration_OversizedBody(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerWithConfig(t, nil)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx := t.Context()

	sessID, _, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	// 1. Initial valid registration
	if _, err := c.Register(ctx, sessID, []string{"initial.example.com"}); err != nil {
		t.Fatalf("initial Register failed: %v", err)
	}
	reg := srv.RegistrationTable().GetRegisteredHostnames(sessID)
	if len(reg) != 1 || reg[0] != "initial.example.com" {
		t.Fatalf("expected [initial.example.com], got %v", reg)
	}

	// 2. Send oversized body (> 256 KiB) directly via HTTP PUT
	largeHostnames := make([]string, 15000)
	for i := range largeHostnames {
		largeHostnames[i] = fmt.Sprintf("host-%05d.example.com", i)
	}
	body, err := json.Marshal(api.RegistrationRequest{Hostnames: largeHostnames})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(body) <= DefaultMaxRegistrationBodyBytes {
		t.Fatalf("body length %d <= limit %d", len(body), DefaultMaxRegistrationBodyBytes)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, serverAddr)
			},
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://snigateway.internal/v1/registration", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.HeaderSessionID, sessID)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413 (StatusRequestEntityTooLarge), got %d", resp.StatusCode)
	}

	// 3. Verify no table change occurred
	regAfter := srv.RegistrationTable().GetRegisteredHostnames(sessID)
	if len(regAfter) != 1 || regAfter[0] != "initial.example.com" {
		t.Fatalf("registration table changed after oversized request, expected [initial.example.com], got %v", regAfter)
	}
}

func TestRegistration_HostnameCap(t *testing.T) {
	const cap = 5
	srv, serverAddr, generated, cleanup := setupTestServerWithConfig(t, func(cfg *ServerConfig) {
		cfg.MaxHostnamesPerSession = cap
	})
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	ctx := t.Context()

	t.Run("HTTP path", func(t *testing.T) {
		c := client.NewClient(serverAddr, clientTLS)
		sessID, _, err := c.StartSession(ctx)
		if err != nil {
			t.Fatalf("StartSession failed: %v", err)
		}

		// Initial registration: 2 hostnames
		if _, err := c.Register(ctx, sessID, []string{"h1.example.com", "h2.example.com"}); err != nil {
			t.Fatalf("initial Register failed: %v", err)
		}

		// > cap hostnames (6 > 5) -> rejected with 400 Bad Request
		tooMany := []string{"a1.com", "a2.com", "a3.com", "a4.com", "a5.com", "a6.com"}
		_, err = c.Register(ctx, sessID, tooMany)
		if err == nil {
			t.Fatal("expected registration exceeding cap to fail")
		}
		if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "exceeds limit") {
			t.Fatalf("unexpected error response: %v", err)
		}

		// Table unchanged: still [h1.example.com, h2.example.com]
		reg := srv.RegistrationTable().GetRegisteredHostnames(sessID)
		if len(reg) != 2 {
			t.Fatalf("table modified after rejected registration: %v", reg)
		}

		// at-cap hostnames (5 == 5) -> accepted
		atCap := []string{"b1.com", "b2.com", "b3.com", "b4.com", "b5.com"}
		resp, err := c.Register(ctx, sessID, atCap)
		if err != nil {
			t.Fatalf("at-cap registration failed: %v", err)
		}
		if len(resp.Hostnames) != cap {
			t.Fatalf("expected %d hostnames, got %v", cap, resp.Hostnames)
		}
		regAfter := srv.RegistrationTable().GetRegisteredHostnames(sessID)
		if len(regAfter) != cap {
			t.Fatalf("table expected %d hostnames, got %v", cap, regAfter)
		}
	})
}

func TestRegistration_DuplicateHostnames(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerWithConfig(t, nil)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	ctx := t.Context()

	t.Run("HTTP path duplicate rejection", func(t *testing.T) {
		c := client.NewClient(serverAddr, clientTLS)
		sessID, _, err := c.StartSession(ctx)
		if err != nil {
			t.Fatalf("StartSession failed: %v", err)
		}

		// 1. Exact duplicate strings
		_, err = c.Register(ctx, sessID, []string{"dup.example.com", "dup.example.com"})
		if err == nil {
			t.Fatal("expected duplicate hostnames to be rejected")
		}
		if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "duplicate hostname") {
			t.Fatalf("unexpected error response: %v", err)
		}

		// 2. Case-insensitive duplicate
		_, err = c.Register(ctx, sessID, []string{"case.example.com", "CASE.EXAMPLE.COM"})
		if err == nil {
			t.Fatal("expected case-insensitive duplicate to be rejected")
		}
		if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "duplicate hostname") {
			t.Fatalf("unexpected error response: %v", err)
		}

		// 3. Port variation duplicate
		_, err = c.Register(ctx, sessID, []string{"port.example.com:443", "port.example.com"})
		if err == nil {
			t.Fatal("expected duplicate with port to be rejected")
		}
		if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "duplicate hostname") {
			t.Fatalf("unexpected error response: %v", err)
		}

		// Table must be empty
		reg := srv.RegistrationTable().GetRegisteredHostnames(sessID)
		if len(reg) != 0 {
			t.Fatalf("table expected empty, got %v", reg)
		}
	})
}

func TestRegistration_DefaultHostnameCap(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerWithConfig(t, nil)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx := t.Context()
	sessID, _, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	// 1001 hostnames (> 1000) -> rejected
	hosts1001 := make([]string, 1001)
	for i := range hosts1001 {
		hosts1001[i] = fmt.Sprintf("h%04d.default.test", i)
	}
	_, err = c.Register(ctx, sessID, hosts1001)
	if err == nil {
		t.Fatal("expected 1001 hostnames to be rejected with default cap")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "exceeds limit of 1000") {
		t.Fatalf("unexpected error response: %v", err)
	}

	// 1000 hostnames (== 1000, at-cap) -> accepted
	hosts1000 := make([]string, 1000)
	for i := range hosts1000 {
		hosts1000[i] = fmt.Sprintf("h%04d.default.test", i)
	}
	resp, err := c.Register(ctx, sessID, hosts1000)
	if err != nil {
		t.Fatalf("expected 1000 hostnames to be accepted at-cap: %v", err)
	}
	if len(resp.Hostnames) != 1000 {
		t.Fatalf("expected 1000 hostnames in response, got %d", len(resp.Hostnames))
	}
	reg := srv.RegistrationTable().GetRegisteredHostnames(sessID)
	if len(reg) != 1000 {
		t.Fatalf("expected 1000 hostnames in table, got %d", len(reg))
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

func setupTestHTTPServerAndClient(t *testing.T) (*Server, string, string, *certs.GeneratedCerts, func()) {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := newServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("newServerTLSConfig failed: %v", err)
	}

	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tls failed: %v", err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen http failed: %v", err)
	}

	_, prefixNet, err := net.ParseCIDR("fd00:1234::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		PerAttemptTimeout:  200 * time.Millisecond,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    newFakeWireGuardDevice(),
		WireGuardPublicKey: feKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    prefixNet,
		DialContext:        testDialContext,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.ServeWithHTTP([]net.Listener{tlsLn}, []net.Listener{httpLn})
	}()

	cleanup := func() {
		if err := srv.Close(); err != nil {
			t.Errorf("srv.Close failed: %v", err)
		}
		if err := <-serverErrCh; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeWithHTTP failed: %v", err)
		}
	}

	return srv, tlsLn.Addr().String(), httpLn.Addr().String(), generated, cleanup
}

type testHTTPBackend struct {
	sessionID  string
	tunnelAddr string
	listener   net.Listener
}

func setupHTTPBackend(t *testing.T, ctx context.Context, clientInstance *client.Client, hostname string) *testHTTPBackend {
	t.Helper()

	sessID, _, err := clientInstance.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	if _, err := clientInstance.Register(ctx, sessID, []string{hostname}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	_, clientKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	wgResp, err := clientInstance.ExchangeWireGuard(ctx, sessID, clientKey.String())
	if err != nil {
		t.Fatalf("ExchangeWireGuard failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	tunnelAddr := net.JoinHostPort(wgResp.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	registerTestBackendListener(tunnelAddr, ln)
	t.Cleanup(func() {
		unregisterTestBackendListener(tunnelAddr)
		if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("failed to close listener: %v", closeErr)
		}
	})

	return &testHTTPBackend{
		sessionID:  sessID,
		tunnelAddr: tunnelAddr,
		listener:   ln,
	}
}

func TestHTTPFailover_NoReplayAfterClientBytes(t *testing.T) {
	srv, tlsAddr, httpAddr, generated, cleanup := setupTestHTTPServerAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	client1 := client.NewClient(tlsAddr, clientTLS)
	client2 := client.NewClient(tlsAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	b1ReceivedCh := make(chan string, 1)
	b2ReceivedCh := make(chan string, 1)

	// Backend 1: accepts connection, reads PROXY header and HTTP request head, then closes without replying
	backend1 := setupHTTPBackend(t, ctx, client1, "noreplay.example.com")
	go func() {
		for {
			conn, err := backend1.listener.Accept()
			if err != nil {
				return
			}
			go func(backendConn net.Conn) {
				defer backendConn.Close()
				bufReader := bufio.NewReader(backendConn)
				if _, err := proxyproto.Decode(bufReader); err != nil {
					return
				}
				buf := make([]byte, 2048)
				n, err := bufReader.Read(buf)
				if err != nil && n == 0 {
					return
				}
				b1ReceivedCh <- string(buf[:n])
				// Close immediately without replying
			}(conn)
		}
	}()

	// Backend 2: second registered backend for the same hostname
	backend2 := setupHTTPBackend(t, ctx, client2, "noreplay.example.com")
	go func() {
		for {
			conn, err := backend2.listener.Accept()
			if err != nil {
				return
			}
			go func(backendConn net.Conn) {
				defer backendConn.Close()
				bufReader := bufio.NewReader(backendConn)
				if _, err := proxyproto.Decode(bufReader); err != nil {
					return
				}
				buf := make([]byte, 2048)
				n, err := bufReader.Read(buf)
				if err != nil && n == 0 {
					return
				}
				b2ReceivedCh <- string(buf[:n])
			}(conn)
		}
	}()

	// Wait for registrations to settle in table without advancing round-robin index
	waitFor(t, 5*time.Second, func() bool {
		return len(srv.RegistrationTable().GetRegisteredHostnames(backend1.sessionID)) > 0 &&
			len(srv.RegistrationTable().GetRegisteredHostnames(backend2.sessionID)) > 0
	})

	// Client sends plain HTTP request
	conn, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatalf("Dial http failed: %v", err)
	}
	defer conn.Close()

	httpRequest := "POST /transfer HTTP/1.1\r\nHost: noreplay.example.com\r\nContent-Length: 5\r\n\r\nhello"
	if _, err := conn.Write([]byte(httpRequest)); err != nil {
		t.Fatalf("Write request failed: %v", err)
	}

	// Verify Backend 1 accepted and read the request head
	select {
	case reqHead := <-b1ReceivedCh:
		if !strings.Contains(reqHead, "POST /transfer") {
			t.Fatalf("unexpected request on backend 1: %q", reqHead)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for backend 1 to receive request head")
	}

	// Verify client connection was closed
	replyBuf := make([]byte, 1024)
	n, readErr := conn.Read(replyBuf)
	if readErr == nil && n > 0 {
		t.Fatalf("expected client read to fail on closed connection, got %d bytes: %s", n, replyBuf[:n])
	}

	// Verify Backend 2 received NOTHING
	select {
	case req := <-b2ReceivedCh:
		t.Fatalf("second backend unexpectedly received request: %q", req)
	case <-time.After(300 * time.Millisecond):
		// Success: second backend received nothing
	}
}

func TestHTTPFailover_RefusedDial(t *testing.T) {
	srv, tlsAddr, httpAddr, generated, cleanup := setupTestHTTPServerAndClient(t)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	client1 := client.NewClient(tlsAddr, clientTLS)
	client2 := client.NewClient(tlsAddr, clientTLS)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Backend 1: registered first, but its tunnel listener is closed so dialing is refused
	backend1 := setupHTTPBackend(t, ctx, client1, "refused.example.com")
	if err := backend1.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed to close backend 1 listener: %v", err)
	}

	// Backend 2: registered second, healthy listener that responds 200 OK
	backend2 := setupHTTPBackend(t, ctx, client2, "refused.example.com")
	go func() {
		for {
			conn, err := backend2.listener.Accept()
			if err != nil {
				return
			}
			go func(backendConn net.Conn) {
				defer backendConn.Close()
				bufReader := bufio.NewReader(backendConn)
				if _, err := proxyproto.Decode(bufReader); err != nil {
					return
				}
				buf := make([]byte, 2048)
				n, err := bufReader.Read(buf)
				if err != nil && n == 0 {
					return
				}
				if _, err := backendConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nhello-backend")); err != nil {
					t.Errorf("backendConn.Write failed: %v", err)
				}
			}(conn)
		}
	}()

	// Wait for registrations to settle in table without advancing round-robin index
	waitFor(t, 5*time.Second, func() bool {
		return len(srv.RegistrationTable().GetRegisteredHostnames(backend1.sessionID)) > 0 &&
			len(srv.RegistrationTable().GetRegisteredHostnames(backend2.sessionID)) > 0
	})

	// Client sends request
	conn, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatalf("Dial http failed: %v", err)
	}
	defer conn.Close()

	httpRequest := "GET /test HTTP/1.1\r\nHost: refused.example.com\r\n\r\n"
	if _, err := conn.Write([]byte(httpRequest)); err != nil {
		t.Fatalf("Write request failed: %v", err)
	}

	// Client should successfully read 200 OK from Backend 2 via failover
	replyBuf := make([]byte, 1024)
	n, readErr := conn.Read(replyBuf)
	if readErr != nil {
		t.Fatalf("expected successful response after failover, got read err: %v", readErr)
	}
	gotResp := string(replyBuf[:n])
	if !strings.Contains(gotResp, "200 OK") || !strings.Contains(gotResp, "hello-backend") {
		t.Fatalf("unexpected response: %s", gotResp)
	}
}
