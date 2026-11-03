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

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func generateTestCAAndClientCert(t testing.TB, commonName string) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName + " CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName + " Client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

	clientCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to create client TLS key pair: %v", err)
	}

	return caPEM, clientCert
}

func TestClientCertificateValidation_RealSockets(t *testing.T) {
	// 1. Backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response-ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendHost, backendPortStr, _ := net.SplitHostPort(backendURL.Host)
	backendPort, _ := strconv.Atoi(backendPortStr)

	// 2. Generate CAs and client certs
	ca1PEM, client1Cert := generateTestCAAndClientCert(t, "CA-1")
	ca2PEM, client2Cert := generateTestCAAndClientCert(t, "CA-2")
	_, clientOtherCert := generateTestCAAndClientCert(t, "CA-Other")

	// 3. Generate server certificates sharing a CA
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"a.example.com", "b.example.com", "c.example.com"}, nil)

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCAPEM)

	// 4. Initialize Proxy
	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"a.example.com": &serverCert,
		"b.example.com": &serverCert,
		"c.example.com": &serverCert,
	}, &serverCert)

	routeA := state.InternalRoute{
		Hostnames: testRouteHostnames("a.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}
	routeB := state.InternalRoute{
		Hostnames: testRouteHostnames("b.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}
	routeC := state.InternalRoute{
		Hostnames: testRouteHostnames("c.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}
	routeD := state.InternalRoute{
		Hostnames: testRouteHostnames("d.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}

	// Configure listeners:
	// - a.example.com: HTTPS listener on port 8443 with CA1 validation (AllowValidOnly)
	// - b.example.com: HTTPS listener on port 8443 with CA2 validation (AllowValidOnly)
	// - c.example.com: HTTPS listener on port 8443 with NO client validation
	// - d.example.com: HTTP listener on port 8000
	listeners := []state.InternalListener{
		{
			Name:     "https-a",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "a.example.com",
			Routes:   []state.InternalRoute{routeA},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{ca1PEM},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
		{
			Name:     "https-b",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "b.example.com",
			Routes:   []state.InternalRoute{routeB},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{ca2PEM},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
		{
			Name:     "https-c-unvalidated",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "c.example.com",
			Routes:   []state.InternalRoute{routeC},
		},
		{
			Name:     "http-d",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     8000,
			Hostname: "d.example.com",
			Routes:   []state.InternalRoute{routeD},
		},
	}

	routes := []state.InternalRoute{routeA, routeB, routeC, routeD}
	p.UpdateConfig(listeners, routes)

	// 5. Start HTTPS server with SNI listener and TLSConfig
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := p.TLSConfig()
	httpsSrv := &http.Server{
		Handler:   p,
		TLSConfig: tlsConfig,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	go func() {
		_ = httpsSrv.Serve(tlsLis)
	}()
	defer httpsSrv.Close()

	httpsAddr := rawLis.Addr().String()

	// 6. Start plain HTTP server
	httpRawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for HTTP: %v", err)
	}
	defer httpRawLis.Close()

	httpSrv := &http.Server{Handler: p}
	go func() {
		_ = httpSrv.Serve(httpRawLis)
	}()
	defer httpSrv.Close()

	httpAddr := httpRawLis.Addr().String()

	makeHTTPSRequest := func(serverName string, clientCert *tls.Certificate) (*http.Response, error) {
		var certs []tls.Certificate
		if clientCert != nil {
			certs = []tls.Certificate{*clientCert}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   serverName,
				RootCAs:      serverCAPool,
				Certificates: certs,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, httpsAddr)
			},
		}
		defer tr.CloseIdleConnections()

		client := &http.Client{
			Transport: tr,
			Timeout:   3 * time.Second,
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:8443/", serverName), nil)
		if err != nil {
			return nil, err
		}
		req.Host = fmt.Sprintf("%s:8443", serverName)
		return client.Do(req)
	}

	t.Run("Valid client cert accepted", func(t *testing.T) {
		resp, err := makeHTTPSRequest("a.example.com", &client1Cert)
		if err != nil {
			t.Fatalf("expected request to succeed, got: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "backend-response-ok" {
			t.Errorf("expected body 'backend-response-ok', got %q", string(body))
		}
	})

	t.Run("Cert from another CA rejected at handshake", func(t *testing.T) {
		_, err := makeHTTPSRequest("a.example.com", &clientOtherCert)
		if err == nil {
			t.Fatalf("expected handshake failure with cert from other CA, but request succeeded")
		}
	})

	t.Run("No cert rejected at handshake", func(t *testing.T) {
		_, err := makeHTTPSRequest("a.example.com", nil)
		if err == nil {
			t.Fatalf("expected handshake failure when no client cert is provided, but request succeeded")
		}
	})

	t.Run("Two listeners with different CAs on one port distinguished by SNI", func(t *testing.T) {
		// a.example.com with CA1 -> success
		respA1, err := makeHTTPSRequest("a.example.com", &client1Cert)
		if err != nil {
			t.Fatalf("a.example.com with CA1 should succeed: %v", err)
		}
		respA1.Body.Close()
		if respA1.StatusCode != http.StatusOK {
			t.Errorf("a.example.com expected 200, got: %d", respA1.StatusCode)
		}

		// a.example.com with CA2 -> handshake rejected
		if _, err := makeHTTPSRequest("a.example.com", &client2Cert); err == nil {
			t.Fatalf("a.example.com with CA2 cert should be rejected at handshake")
		}

		// b.example.com with CA2 -> success
		respB2, err := makeHTTPSRequest("b.example.com", &client2Cert)
		if err != nil {
			t.Fatalf("b.example.com with CA2 should succeed: %v", err)
		}
		respB2.Body.Close()
		if respB2.StatusCode != http.StatusOK {
			t.Errorf("b.example.com expected 200, got: %d", respB2.StatusCode)
		}

		// b.example.com with CA1 -> handshake rejected
		if _, err := makeHTTPSRequest("b.example.com", &client1Cert); err == nil {
			t.Fatalf("b.example.com with CA1 cert should be rejected at handshake")
		}
	})

	t.Run("An HTTP listener and an HTTPS listener without validation untouched", func(t *testing.T) {
		// HTTPS listener without validation (c.example.com) succeeds with NO client cert
		respC, err := makeHTTPSRequest("c.example.com", nil)
		if err != nil {
			t.Fatalf("c.example.com without client cert failed: %v", err)
		}
		defer respC.Body.Close()
		if respC.StatusCode != http.StatusOK {
			t.Errorf("c.example.com expected 200, got: %d", respC.StatusCode)
		}

		// Plain HTTP listener (d.example.com) succeeds untouched
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", httpAddr), nil)
		if err != nil {
			t.Fatalf("failed to create HTTP request: %v", err)
		}
		req.Host = "d.example.com"
		httpClient := &http.Client{Timeout: 3 * time.Second}
		respD, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request to d.example.com failed: %v", err)
		}
		defer respD.Body.Close()
		if respD.StatusCode != http.StatusOK {
			t.Errorf("HTTP request to d.example.com expected 200, got: %d", respD.StatusCode)
		}
	})

	t.Run("Dynamic config update swaps CA atomically", func(t *testing.T) {
		// Swap: a.example.com now requires CA2 instead of CA1
		updatedListeners := []state.InternalListener{
			{
				Name:     "https-a",
				Protocol: gatewayv1.HTTPSProtocolType,
				Port:     8443,
				Hostname: "a.example.com",
				Routes:   []state.InternalRoute{routeA},
				ClientValidation: &state.InternalClientValidation{
					CACertPEMs: [][]byte{ca2PEM},
					Mode:       gatewayv1.AllowValidOnly,
				},
			},
		}
		p.UpdateConfig(updatedListeners, routes)

		// Now client1Cert should fail on a.example.com
		if _, err := makeHTTPSRequest("a.example.com", &client1Cert); err == nil {
			t.Fatalf("expected client1Cert to fail after CA swap")
		}

		// And client2Cert should succeed on a.example.com
		resp, err := makeHTTPSRequest("a.example.com", &client2Cert)
		if err != nil {
			t.Fatalf("expected client2Cert to succeed after CA swap: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK after CA swap, got: %d", resp.StatusCode)
		}
	})
}

func TestClientCertificateValidation_FailClosedInvalidConfiguration(t *testing.T) {
	// Backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendHost, backendPortStr, _ := net.SplitHostPort(backendURL.Host)
	backendPort, _ := strconv.Atoi(backendPortStr)

	// Valid CA and client cert
	validCAPEM, validClientCert := generateTestCAAndClientCert(t, "Valid-CA")

	// Server cert covering all test hostnames
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{
		"empty-cas.example.com",
		"unparseable-pem.example.com",
		"unsupported-mode.example.com",
		"sibling.example.com",
	}, nil)

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCAPEM)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"empty-cas.example.com":        &serverCert,
		"unparseable-pem.example.com":  &serverCert,
		"unsupported-mode.example.com": &serverCert,
		"sibling.example.com":          &serverCert,
	}, &serverCert)

	routeFor := func(host string) state.InternalRoute {
		return state.InternalRoute{
			Hostnames: testRouteHostnames(host),
			Rules: []state.InternalRule{
				{
					Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
					Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
				},
			},
		}
	}

	// 4 listeners on the SAME port (8443):
	// 1. empty CACertPEMs
	// 2. unparseable PEM
	// 3. unsupported mode
	// 4. sibling listener without validation
	listeners := []state.InternalListener{
		{
			Name:     "https-empty-cas",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "empty-cas.example.com",
			Routes:   []state.InternalRoute{routeFor("empty-cas.example.com")},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
		{
			Name:     "https-unparseable-pem",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "unparseable-pem.example.com",
			Routes:   []state.InternalRoute{routeFor("unparseable-pem.example.com")},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{[]byte("not a valid pem block")},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
		{
			Name:     "https-unsupported-mode",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "unsupported-mode.example.com",
			Routes:   []state.InternalRoute{routeFor("unsupported-mode.example.com")},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{validCAPEM},
				Mode:       gatewayv1.FrontendValidationModeType("UnsupportedMode"),
			},
		},
		{
			Name:     "https-sibling",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "sibling.example.com",
			Routes:   []state.InternalRoute{routeFor("sibling.example.com")},
		},
	}

	routes := []state.InternalRoute{
		routeFor("empty-cas.example.com"),
		routeFor("unparseable-pem.example.com"),
		routeFor("unsupported-mode.example.com"),
		routeFor("sibling.example.com"),
	}

	p.UpdateConfig(listeners, routes)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := p.TLSConfig()
	httpsSrv := &http.Server{
		Handler:   p,
		TLSConfig: tlsConfig,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	go func() {
		_ = httpsSrv.Serve(tlsLis)
	}()
	defer httpsSrv.Close()

	httpsAddr := rawLis.Addr().String()

	dialTLS := func(serverName string, clientCert *tls.Certificate) (*http.Response, error) {
		var certs []tls.Certificate
		if clientCert != nil {
			certs = []tls.Certificate{*clientCert}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   serverName,
				RootCAs:      serverCAPool,
				Certificates: certs,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, httpsAddr)
			},
		}
		defer tr.CloseIdleConnections()

		client := &http.Client{
			Transport: tr,
			Timeout:   3 * time.Second,
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:8443/", serverName), nil)
		if err != nil {
			return nil, err
		}
		req.Host = fmt.Sprintf("%s:8443", serverName)
		return client.Do(req)
	}

	t.Run("empty CACertPEMs refuses handshake", func(t *testing.T) {
		_, err := dialTLS("empty-cas.example.com", &validClientCert)
		if err == nil {
			t.Fatalf("expected handshake refusal for listener with empty CACertPEMs, but request succeeded")
		}
	})

	t.Run("unparseable PEM refuses handshake", func(t *testing.T) {
		_, err := dialTLS("unparseable-pem.example.com", &validClientCert)
		if err == nil {
			t.Fatalf("expected handshake refusal for listener with unparseable PEM, but request succeeded")
		}
	})

	t.Run("unsupported mode refuses handshake", func(t *testing.T) {
		_, err := dialTLS("unsupported-mode.example.com", &validClientCert)
		if err == nil {
			t.Fatalf("expected handshake refusal for listener with unsupported mode, but request succeeded")
		}
	})

	t.Run("sibling listener without validation on same port still serves", func(t *testing.T) {
		resp, err := dialTLS("sibling.example.com", nil)
		if err != nil {
			t.Fatalf("sibling listener should succeed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("sibling listener expected status 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "backend-ok" {
			t.Errorf("sibling listener expected body 'backend-ok', got %q", string(body))
		}
	})
}

func TestClientCertificateValidation_AllowInsecureFallback(t *testing.T) {
	// Backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response-ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendHost, backendPortStr, _ := net.SplitHostPort(backendURL.Host)
	backendPort, _ := strconv.Atoi(backendPortStr)

	// Generate trusted CA1 and client cert
	ca1PEM, client1Cert := generateTestCAAndClientCert(t, "CA-1")
	// Generate untrusted CA and client cert
	_, clientOtherCert := generateTestCAAndClientCert(t, "CA-Other")

	// Server cert covering fallback.example.com and valid.example.com
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{
		"fallback.example.com",
		"valid.example.com",
	}, nil)

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(serverCAPEM)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"fallback.example.com": &serverCert,
		"valid.example.com":    &serverCert,
	}, &serverCert)

	routeFallback := state.InternalRoute{
		Hostnames: testRouteHostnames("fallback.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}
	routeValid := state.InternalRoute{
		Hostnames: testRouteHostnames("valid.example.com"),
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}}},
				Backends: []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}},
			},
		},
	}

	// Two listeners on the SAME port (8443):
	// 1. fallback.example.com with AllowInsecureFallback
	// 2. valid.example.com with AllowValidOnly
	listeners := []state.InternalListener{
		{
			Name:     "https-fallback",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "fallback.example.com",
			Routes:   []state.InternalRoute{routeFallback},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{ca1PEM},
				Mode:       gatewayv1.AllowInsecureFallback,
			},
		},
		{
			Name:     "https-valid",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "valid.example.com",
			Routes:   []state.InternalRoute{routeValid},
			ClientValidation: &state.InternalClientValidation{
				CACertPEMs: [][]byte{ca1PEM},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
	}

	routes := []state.InternalRoute{routeFallback, routeValid}
	p.UpdateConfig(listeners, routes)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := p.TLSConfig()
	httpsSrv := &http.Server{
		Handler:   p,
		TLSConfig: tlsConfig,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	go func() {
		_ = httpsSrv.Serve(tlsLis)
	}()
	defer httpsSrv.Close()

	httpsAddr := rawLis.Addr().String()

	makeRequest := func(serverName string, clientCert *tls.Certificate) (*http.Response, error) {
		var certs []tls.Certificate
		if clientCert != nil {
			certs = []tls.Certificate{*clientCert}
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   serverName,
				RootCAs:      serverCAPool,
				Certificates: certs,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, httpsAddr)
			},
		}
		defer tr.CloseIdleConnections()

		client := &http.Client{
			Transport: tr,
			Timeout:   3 * time.Second,
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:8443/", serverName), nil)
		if err != nil {
			return nil, err
		}
		req.Host = fmt.Sprintf("%s:8443", serverName)
		return client.Do(req)
	}

	t.Run("Fallback listener accepts valid cert", func(t *testing.T) {
		resp, err := makeRequest("fallback.example.com", &client1Cert)
		if err != nil {
			t.Fatalf("expected request to succeed, got: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "backend-response-ok" {
			t.Errorf("expected body 'backend-response-ok', got %q", string(body))
		}
	})

	t.Run("Fallback listener accepts cert from another CA", func(t *testing.T) {
		resp, err := makeRequest("fallback.example.com", &clientOtherCert)
		if err != nil {
			t.Fatalf("expected fallback listener to accept cert from another CA, got: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
		}
	})

	t.Run("Fallback listener accepts request without client cert", func(t *testing.T) {
		resp, err := makeRequest("fallback.example.com", nil)
		if err != nil {
			t.Fatalf("expected fallback listener to accept request with no cert, got: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
		}
	})

	t.Run("AllowValidOnly listener on same port accepts valid cert", func(t *testing.T) {
		resp, err := makeRequest("valid.example.com", &client1Cert)
		if err != nil {
			t.Fatalf("expected valid.example.com with CA1 cert to succeed, got: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", resp.StatusCode)
		}
	})

	t.Run("AllowValidOnly listener on same port rejects cert from another CA at handshake", func(t *testing.T) {
		if _, err := makeRequest("valid.example.com", &clientOtherCert); err == nil {
			t.Fatalf("expected valid.example.com to reject cert from another CA at handshake")
		}
	})

	t.Run("AllowValidOnly listener on same port rejects request without cert at handshake", func(t *testing.T) {
		if _, err := makeRequest("valid.example.com", nil); err == nil {
			t.Fatalf("expected valid.example.com to reject request without cert at handshake")
		}
	})
}

func TestTLSSessionResumption_ValidatedListener(t *testing.T) {
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"validated.example.com"}, nil)
	clientCA1PEM, client1Cert := generateTestCAAndClientCert(t, "client1")
	clientCA2PEM, client2Cert := generateTestCAAndClientCert(t, "client2")

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendHost, backendPortStr, err := net.SplitHostPort(backendURL.Host)
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}
	backendPort, err := strconv.Atoi(backendPortStr)
	if err != nil {
		t.Fatalf("failed to parse backend port: %v", err)
	}

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"validated.example.com": &serverCert,
	}, &serverCert)

	route := state.InternalRoute{
		Hostnames: testRouteHostnames("validated.example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{
					{
						Host:   backendHost,
						Port:   int32(backendPort),
						Weight: 1,
					},
				},
			},
		},
	}

	listenerCA1 := state.InternalListener{
		Name:     "validated-listener",
		Protocol: gatewayv1.HTTPSProtocolType,
		Port:     8443,
		Hostname: "validated.example.com",
		ClientValidation: &state.InternalClientValidation{
			CACertPEMs: [][]byte{clientCA1PEM},
			Mode:       gatewayv1.AllowValidOnly,
		},
		Routes: []state.InternalRoute{route},
	}
	p.UpdateConfig([]state.InternalListener{listenerCA1}, []state.InternalRoute{route})

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := p.TLSConfig()
	httpsSrv := &http.Server{
		Handler:   p,
		TLSConfig: tlsConfig,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	go func() {
		_ = httpsSrv.Serve(tlsLis)
	}()
	defer httpsSrv.Close()

	addr := rawLis.Addr().String()
	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(serverCAPEM)

	sessionCache := tls.NewLRUClientSessionCache(10)

	dialWithCert := func(clientCert *tls.Certificate) (*tls.Conn, error) {
		var certs []tls.Certificate
		if clientCert != nil {
			certs = []tls.Certificate{*clientCert}
		}
		cCfg := &tls.Config{
			ServerName:         "validated.example.com",
			RootCAs:            serverCertPool,
			Certificates:       certs,
			ClientSessionCache: sessionCache,
		}
		conn, err := tls.Dial("tcp", addr, cCfg)
		if err != nil {
			return nil, err
		}
		req := "GET / HTTP/1.1\r\nHost: validated.example.com\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}
		resp, rErr := io.ReadAll(conn)
		if rErr != nil || len(resp) == 0 {
			conn.Close()
			return nil, fmt.Errorf("handshake failed or connection closed without response: %w", rErr)
		}
		return conn, nil
	}

	// Step 1: Connect with client cert 1 -> Full handshake, DidResume == false
	conn1, err := dialWithCert(&client1Cert)
	if err != nil {
		t.Fatalf("conn 1 failed: %v", err)
	}
	if conn1.ConnectionState().DidResume {
		t.Errorf("conn 1 expected DidResume=false, got true")
	}
	conn1.Close()

	// Step 2: Connect with client cert 1 again -> Resumed handshake, DidResume == true
	conn2, err := dialWithCert(&client1Cert)
	if err != nil {
		t.Fatalf("conn 2 failed: %v", err)
	}
	if !conn2.ConnectionState().DidResume {
		t.Errorf("conn 2 expected DidResume=true, got false")
	}
	conn2.Close()

	// Step 3: Update config: Swap CA to CA2
	listenerCA2 := state.InternalListener{
		Name:     "validated-listener",
		Protocol: gatewayv1.HTTPSProtocolType,
		Port:     8443,
		Hostname: "validated.example.com",
		ClientValidation: &state.InternalClientValidation{
			CACertPEMs: [][]byte{clientCA2PEM},
			Mode:       gatewayv1.AllowValidOnly,
		},
		Routes: []state.InternalRoute{route},
	}
	p.UpdateConfig([]state.InternalListener{listenerCA2}, []state.InternalRoute{route})

	// Step 4: Old client cert 1 should now be rejected at handshake (even if presenting old session ticket)
	if _, err := dialWithCert(&client1Cert); err == nil {
		t.Errorf("expected client cert 1 to fail handshake after CA update to CA2")
	}

	// Step 5: Connect with valid client cert 2 (using same session cache) -> Ticket key was rotated, so DidResume == false
	conn3, err := dialWithCert(&client2Cert)
	if err != nil {
		t.Fatalf("conn 3 with client cert 2 failed: %v", err)
	}
	if conn3.ConnectionState().DidResume {
		t.Errorf("conn 3 expected DidResume=false after CA change, got true")
	}
	conn3.Close()

	// Step 6: Connect with valid client cert 2 again -> Resumed handshake, DidResume == true
	conn4, err := dialWithCert(&client2Cert)
	if err != nil {
		t.Fatalf("conn 4 with client cert 2 failed: %v", err)
	}
	if !conn4.ConnectionState().DidResume {
		t.Errorf("conn 4 expected DidResume=true on second connection with CA2, got false")
	}
	conn4.Close()
}
