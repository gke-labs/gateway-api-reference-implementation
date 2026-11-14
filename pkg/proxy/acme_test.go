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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func generateTestACMECAAndCert(t testing.TB, dnsNames []string, ips []net.IP) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
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

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "upstream"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	srvBytes, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server certificate: %v", err)
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvBytes})
	keyBytes, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("failed to marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("failed to create X509 key pair: %v", err)
	}
	return caPEM, tlsCert
}

func createTestBackend(t *testing.T, responseBody string) (*httptest.Server, state.InternalBackend) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(server.Close)

	reqHost, reqPortStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse test server address: %v", err)
	}
	reqPort, err := strconv.Atoi(reqPortStr)
	if err != nil {
		t.Fatalf("failed to parse test server port: %v", err)
	}

	return server, state.InternalBackend{
		Host:   reqHost,
		Port:   int32(reqPort),
		Weight: 1,
	}
}

func createTestHTTPRoute(pathPrefix string, backend state.InternalBackend) state.InternalRoute {
	return state.InternalRoute{
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{
						Path: &state.InternalPathMatch{
							Type:  gatewayv1.PathMatchPathPrefix,
							Value: pathPrefix,
						},
					},
				},
				Backends: []state.InternalBackend{backend},
			},
		},
	}
}

func TestACMEChallenge_OffByDefault(t *testing.T) {
	_, backend := createTestBackend(t, "user-solver-response")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "http",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     80,
			Routes:   []state.InternalRoute{route},
		},
	}, []state.InternalRoute{route})

	// When off by default, valid challenge paths hit the user's HTTPRoute
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/some-token", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from HTTPRoute, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "user-solver-response" {
		t.Fatalf("expected body %q, got %q", "user-solver-response", body)
	}

	// Malformed tokens are also unaffected and reach the HTTPRoute
	reqMalformed := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/bad$token", nil)
	recMalformed := httptest.NewRecorder()
	p.ServeHTTP(recMalformed, reqMalformed)

	if recMalformed.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from HTTPRoute for malformed path when off, got %d", recMalformed.Code)
	}
	if body := recMalformed.Body.String(); body != "user-solver-response" {
		t.Fatalf("expected body %q, got %q", "user-solver-response", body)
	}
}

func TestACMEChallenge_Relay200(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var (
		receivedHost string
		receivedAuth string
		receivedPath string
	)

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedAuth = r.Header.Get("Authorization")
		receivedPath = r.URL.Path

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Custom-Upstream", "should-not-be-relayed")
		w.Header().Set("Set-Cookie", "session=secret; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("valid-key-authorization-response"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("sa-bearer-token-123"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://target.example.org/.well-known/acme-challenge/my-token-123", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify relayed body
	if body := rec.Body.String(); body != "valid-key-authorization-response" {
		t.Fatalf("expected body %q, got %q", "valid-key-authorization-response", body)
	}

	// Verify Content-Type
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type text/plain; charset=utf-8, got %q", ct)
	}

	// Verify no upstream headers or cookies are relayed
	if val := rec.Header().Get("X-Custom-Upstream"); val != "" {
		t.Fatalf("upstream header X-Custom-Upstream was leaked: %q", val)
	}
	if cookie := rec.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("upstream cookie was leaked: %q", cookie)
	}

	// Verify upstream received the original host and bearer token
	if receivedHost != "target.example.org" {
		t.Fatalf("expected upstream Host target.example.org, got %q", receivedHost)
	}
	if receivedAuth != "Bearer sa-bearer-token-123" {
		t.Fatalf("expected upstream Authorization 'Bearer sa-bearer-token-123', got %q", receivedAuth)
	}
	if receivedPath != "/.well-known/acme-challenge/my-token-123" {
		t.Fatalf("expected upstream Path '/.well-known/acme-challenge/my-token-123', got %q", receivedPath)
	}
}

func TestACMEChallenge_CABundleFilePath(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ca-file-verified"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	caFile, err := os.CreateTemp("", "ca-bundle-*.crt")
	if err != nil {
		t.Fatalf("failed to create ca file: %v", err)
	}
	defer os.Remove(caFile.Name())
	if _, err := caFile.Write(caPEM); err != nil {
		t.Fatalf("failed to write ca file: %v", err)
	}
	caFile.Close()

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL:  upstreamServer.URL,
		CABundlePath: caFile.Name(),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token-ca-path", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "ca-file-verified" {
		t.Fatalf("expected body %q, got %q", "ca-file-verified", body)
	}
}

func TestACMEChallenge_RelaySizeLimited(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	largeBody := strings.Repeat("A", 2048)
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeBody))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token1", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	body := rec.Body.Bytes()
	if len(body) != 1024 {
		t.Fatalf("expected relayed body length 1024 bytes (1 KiB), got %d", len(body))
	}
	if rec.Header().Get("Content-Length") != "1024" {
		t.Fatalf("expected Content-Length 1024, got %q", rec.Header().Get("Content-Length"))
	}
}

func TestACMEChallenge_Upstream404FallsThrough(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for unknown challenge
		http.NotFound(w, r)
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "user-cert-manager-solved")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/unknown-token", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Upstream 404 falls through to the user's HTTPRoute
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from fallback HTTPRoute, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "user-cert-manager-solved" {
		t.Fatalf("expected fallback body %q, got %q", "user-cert-manager-solved", body)
	}
}

func TestACMEChallenge_UpstreamTimeoutFallsThrough(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay longer than the proxy's configured ACME timeout
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("too-late"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "user-fallback-after-timeout")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETimeout(50 * time.Millisecond)
	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/slow-token", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Upstream timeout falls through to normal HTTPRoute
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from fallback HTTPRoute, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "user-fallback-after-timeout" {
		t.Fatalf("expected fallback body %q, got %q", "user-fallback-after-timeout", body)
	}
}

func TestACMEChallenge_UpstreamErrorFallsThrough(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal certserver error", http.StatusInternalServerError)
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "user-fallback-after-500")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/err-token", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Upstream error falls through to normal HTTPRoute
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from fallback HTTPRoute, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "user-fallback-after-500" {
		t.Fatalf("expected fallback body %q, got %q", "user-fallback-after-500", body)
	}
}

func TestACMEChallenge_MalformedTokensFallThroughWithoutContactingUpstream(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var upstreamCallCount atomic.Int64
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCallCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should-never-be-reached"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "fallback-for-malformed")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	malformedPaths := []string{
		"/.well-known/acme-challenge/",
		"/.well-known/acme-challenge",
		"/.well-known/acme-challenge/extra/path",
		"/.well-known/acme-challenge/extra/path/segments",
		"/.well-known/acme-challenge/..",
		"/.well-known/acme-challenge/foo..bar",
		"/.well-known/acme-challenge/" + strings.Repeat("a", 129),
		"/.well-known/acme-challenge/bad$token",
		"/.well-known/acme-challenge/bad+token",
		"/.well-known/acme-challenge/bad=token",
		"/.well-known/acme-challenge/bad%20token",
	}

	for _, path := range malformedPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if path == "/.well-known/acme-challenge" || path == "/.well-known/acme-challenge/.." {
				if rec.Code != http.StatusNotFound {
					t.Fatalf("expected 404 for %q, got %d", path, rec.Code)
				}
			} else {
				// Malformed tokens must fall through to the HTTPRoute, not return 400
				if rec.Code != http.StatusOK {
					t.Fatalf("expected 200 OK from fallback HTTPRoute for %q, got %d", path, rec.Code)
				}
				if body := rec.Body.String(); body != "fallback-for-malformed" {
					t.Fatalf("expected body %q, got %q", "fallback-for-malformed", body)
				}
			}
			if count := upstreamCallCount.Load(); count != 0 {
				t.Fatalf("upstream was contacted %d times for malformed path %q", count, path)
			}
		})
	}
}

func TestACMEChallenge_BearerTokenAndHostPresentUpstream(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var receivedHost string
	var receivedAuth string
	var mu sync.Mutex

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHost = r.Host
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("my-unique-bearer-token-abc"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	testHosts := []string{"sub.domain.example.com", "custom-host.org:80"}
	for _, h := range testHosts {
		t.Run(h, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+h+"/.well-known/acme-challenge/testtoken1", nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", rec.Code)
			}

			mu.Lock()
			gotHost := receivedHost
			gotAuth := receivedAuth
			mu.Unlock()

			if gotHost != h {
				t.Errorf("expected upstream Host %q, got %q", h, gotHost)
			}
			if gotAuth != "Bearer my-unique-bearer-token-abc" {
				t.Errorf("expected upstream Authorization 'Bearer my-unique-bearer-token-abc', got %q", gotAuth)
			}
		})
	}
}

func TestACMEChallenge_RequireHTTPSUpstream(t *testing.T) {
	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("secret-plain-token"))

	// Non-HTTPS upstream must be rejected when config is applied
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: "http://certserver.example.com", // plain http
	})

	// Forwarder must not be active
	if p.acmeForwarder.Load() != nil {
		t.Fatalf("expected acmeForwarder to be nil when plain http upstream is configured")
	}

	// Requests fall through to normal routing (404 when no routes)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/mytoken123", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestACMEChallenge_RequireTokenPath(t *testing.T) {
	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	// Upstream is set but token path is empty and no token source is configured
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: "https://certserver.example.com",
	})

	// Forwarder must not be built
	if p.acmeForwarder.Load() != nil {
		t.Fatalf("expected acmeForwarder to be nil when token path is missing")
	}

	// Requests fall through to normal routing
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token1", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestACMEChallenge_TokenRotation(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var lastReceivedAuth atomic.Value
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReceivedAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	// Create temp token file
	tmpFile, err := os.CreateTemp("", "sa-token-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("initial-token-v1\n"); err != nil {
		t.Fatalf("failed to write initial token: %v", err)
	}
	tmpFile.Close()

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
		TokenPath:   tmpFile.Name(),
	})

	// Request 1: initial token
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/rotatetoken1", nil)
	rec1 := httptest.NewRecorder()
	p.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("req1 failed: %d", rec1.Code)
	}
	if auth, _ := lastReceivedAuth.Load().(string); auth != "Bearer initial-token-v1" {
		t.Fatalf("expected initial auth 'Bearer initial-token-v1', got %q", auth)
	}

	// Rotate the token file
	time.Sleep(10 * time.Millisecond) // ensure mtime changes
	if err := os.WriteFile(tmpFile.Name(), []byte("rotated-token-v2\n"), 0600); err != nil {
		t.Fatalf("failed to overwrite token file: %v", err)
	}

	// Request 2: rotated token
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/rotatetoken2", nil)
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("req2 failed: %d", rec2.Code)
	}
	if auth, _ := lastReceivedAuth.Load().(string); auth != "Bearer rotated-token-v2" {
		t.Fatalf("expected rotated auth 'Bearer rotated-token-v2', got %q", auth)
	}
}

func TestACMEChallenge_NoRedirectsFollowed(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var targetReached atomic.Bool
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReached.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redirect-target"))
	}))
	t.Cleanup(targetServer.Close)

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "fallback-on-redirect")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/redir-token", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Redirect must NOT be followed; non-200 falls through to HTTPRoute
	if targetReached.Load() {
		t.Fatalf("proxy followed upstream redirect to target server")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from fallback, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "fallback-on-redirect" {
		t.Fatalf("expected fallback body %q, got %q", "fallback-on-redirect", body)
	}
}

func TestACMEChallenge_TokenNeverLogged(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server-error-500", http.StatusInternalServerError)
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	secretBearerToken := "SUPER-SECRET-BEARER-SA-TOKEN-XYZ-999"
	challengeToken := "my-secret-challenge-token-12345"

	// Capture klog logs
	var logBuf bytes.Buffer
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	klog.InitFlags(fs)
	klog.SetOutput(&logBuf)

	p.SetACMETokenSource(StaticTokenSource(secretBearerToken))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/"+challengeToken, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	klog.Flush()
	logs := logBuf.String()

	// Verify the secret bearer token was never logged
	if strings.Contains(logs, secretBearerToken) {
		t.Fatalf("secret bearer token was found in log output: %q", logs)
	}

	// Verify the challenge token is redacted or not logged
	if strings.Contains(logs, challengeToken) {
		t.Fatalf("challenge token was found in log output: %q", logs)
	}
}

func TestACMEChallenge_HTTPSListenerNeverForwards(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var upstreamCalled atomic.Bool
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-acme-response"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, backend := createTestBackend(t, "https-route-response")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "https",
			Protocol:      gatewayv1.HTTPSProtocolType,
			Port:          443,
			Hostname:      "secure.example.com",
			Routes:        []state.InternalRoute{route},
			ACMEChallenge: true,
		},
	}, []state.InternalRoute{route})

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	// Request arrives on HTTPS (r.TLS != nil)
	req := httptest.NewRequest(http.MethodGet, "https://secure.example.com/.well-known/acme-challenge/testtoken1", nil)
	req.TLS = &tls.ConnectionState{
		ServerName: "secure.example.com",
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from HTTPS route, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "https-route-response" {
		t.Fatalf("expected body %q, got %q", "https-route-response", body)
	}
	// Verify upstream was NOT contacted because ACME challenge forwarding only applies to plain HTTP
	if upstreamCalled.Load() {
		t.Fatalf("upstream ACME forwarder was unexpectedly called for HTTPS request")
	}
}

func TestACMEChallenge_TwoGatewaysSharedProxyIsolation(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var upstreamCallCount atomic.Int64
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCallCount.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("certserver-response"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	_, gw2Backend := createTestBackend(t, "gw2-user-solver")
	gw2Route := createTestHTTPRoute(ACMEChallengePrefix, gw2Backend)

	p := NewProxy()
	p.SetACMETokenSource(StaticTokenSource("shared-token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	// Gateway 1 has ACME challenge enabled; Gateway 2 has ACME challenge disabled
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "gw1-http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Hostname:      "gw1.example.com",
			ACMEChallenge: true,
		},
		{
			Name:          "gw2-http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			Hostname:      "gw2.example.com",
			Routes:        []state.InternalRoute{gw2Route},
			ACMEChallenge: false,
		},
	}, []state.InternalRoute{gw2Route})

	// Request for Gateway 1 (opted in): forwarded to upstream
	req1 := httptest.NewRequest(http.MethodGet, "http://gw1.example.com/.well-known/acme-challenge/token1", nil)
	rec1 := httptest.NewRecorder()
	p.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for gw1, got %d", rec1.Code)
	}
	if body := rec1.Body.String(); body != "certserver-response" {
		t.Fatalf("expected body %q, got %q", "certserver-response", body)
	}
	if upstreamCallCount.Load() != 1 {
		t.Fatalf("expected 1 upstream call, got %d", upstreamCallCount.Load())
	}

	// Request for Gateway 2 (not opted in): must NOT forward to upstream, must hit gw2's route
	req2 := httptest.NewRequest(http.MethodGet, "http://gw2.example.com/.well-known/acme-challenge/token2", nil)
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from gw2 route, got %d", rec2.Code)
	}
	if body := rec2.Body.String(); body != "gw2-user-solver" {
		t.Fatalf("expected body %q, got %q", "gw2-user-solver", body)
	}
	// Upstream count must STILL be 1 (never called for Gateway 2!)
	if upstreamCallCount.Load() != 1 {
		t.Fatalf("upstream was unexpectedly called for non-opted-in Gateway 2, count: %d", upstreamCallCount.Load())
	}
}

func TestACMEChallenge_Port80ListenerOnBindPort8080(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok-port-80"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.SetACMETokenSource(StaticTokenSource("test-token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	// Listener is configured on port 80 (standard Gateway HTTP listener)
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http-80",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	// In data planes, the HTTP server binds to port 8080 (DataPlaneHTTPPort),
	// so the connection's local address is 127.0.0.1:8080, while the request Host is example.com (defaulting to port 80).
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token1", nil)
	localTCPAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to resolve TCP addr: %v", err)
	}
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey, localTCPAddr)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for port-80 listener on bind port 8080, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "ok-port-80" {
		t.Fatalf("expected body %q, got %q", "ok-port-80", body)
	}
}

func TestACMEChallenge_ConcurrencyNoDataRace(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("concurrent-ok"))
	}))
	upstreamServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	upstreamServer.StartTLS()
	t.Cleanup(upstreamServer.Close)

	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:          "http",
			Protocol:      gatewayv1.HTTPProtocolType,
			Port:          80,
			ACMEChallenge: true,
		},
	}, nil)

	p.SetACMETokenSource(StaticTokenSource("token"))
	p.UpdateACMEChallenge(&ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Concurrently invoke ServeHTTP
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/concur-token", nil)
					rec := httptest.NewRecorder()
					p.ServeHTTP(rec, req)
				}
			}
		}()
	}

	// Concurrently call SetACMETokenSource, SetACMETimeout, UpdateACMEChallenge
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					p.SetACMETokenSource(StaticTokenSource("concurrent-token-" + strconv.Itoa(id)))
					p.SetACMETimeout(time.Duration(100+id) * time.Millisecond)
					p.UpdateACMEChallenge(&ACMEChallengeConfig{
						UpstreamURL: upstreamServer.URL,
						CABundlePEM: string(caPEM),
					})
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestNewACMEChallengeForwarder_Handler(t *testing.T) {
	caPEM, tlsCert := generateTestACMECAAndCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	var lastAuthHeader string
	var mu sync.Mutex
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastAuthHeader = r.Header.Get("Authorization")
		mu.Unlock()

		token := strings.TrimPrefix(r.URL.Path, ACMEChallengePrefix)
		if token == "good-token" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("key-authorization-xyz"))
			return
		}
		if token == "error-token" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	upstreamServer.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	upstreamServer.StartTLS()
	defer upstreamServer.Close()

	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token-123"), 0600); err != nil {
		t.Fatalf("failed to write token: %v", err)
	}

	// 1. Empty UpstreamURL fails construction and does not return typed-nil handler
	emptyHandler, err := NewACMEChallengeForwarder(ACMEChallengeConfig{}, nil)
	if err == nil {
		t.Errorf("expected error for empty upstream URL")
	}
	if emptyHandler != nil {
		t.Errorf("expected nil http.Handler on error, got %v", emptyHandler)
	}

	// 2. Non-HTTPS upstream fails construction
	_, err = NewACMEChallengeForwarder(ACMEChallengeConfig{
		UpstreamURL: "http://example.com",
		TokenPath:   tokenFile,
	}, nil)
	if err == nil {
		t.Errorf("expected error for http upstream URL")
	}

	// 3. Successful construction with HTTPS upstream, CA bundle, and FileTokenSource
	h, err := NewACMEChallengeForwarder(ACMEChallengeConfig{
		UpstreamURL: upstreamServer.URL,
		CABundlePEM: string(caPEM),
		TokenPath:   tokenFile,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error creating forwarder: %v", err)
	}

	// 3. Relays 200 on valid challenge
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/good-token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "key-authorization-xyz" {
		t.Errorf("expected body %q, got %q", "key-authorization-xyz", body)
	}
	mu.Lock()
	auth := lastAuthHeader
	mu.Unlock()
	if auth != "Bearer file-token-123" {
		t.Errorf("expected auth 'Bearer file-token-123', got %q", auth)
	}

	// 4. Non-ACME path falls through with 404
	reqOther := httptest.NewRequest(http.MethodGet, "http://example.com/other-path", nil)
	recOther := httptest.NewRecorder()
	h.ServeHTTP(recOther, reqOther)
	if recOther.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-ACME path, got %d", recOther.Code)
	}

	// 5. Malformed token falls through with 404
	reqBad := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/bad$token", nil)
	recBad := httptest.NewRecorder()
	h.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusNotFound {
		t.Errorf("expected 404 for malformed token, got %d", recBad.Code)
	}

	// 6. Upstream 404 falls through with 404
	req404 := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/missing-token", nil)
	rec404 := httptest.NewRecorder()
	h.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing upstream token, got %d", rec404.Code)
	}

	// 7. Upstream error falls through with 404
	req500 := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/error-token", nil)
	rec500 := httptest.NewRecorder()
	h.ServeHTTP(rec500, req500)
	if rec500.Code != http.StatusNotFound {
		t.Errorf("expected 404 on upstream error, got %d", rec500.Code)
	}
}

func TestProxy_ACMEChallenge_ServedFromDataPlane(t *testing.T) {
	_, backend := createTestBackend(t, "normal route response")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)
	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "http",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     80,
			Hostname: "example.com",
			Routes:   []state.InternalRoute{route},
		},
	}, []state.InternalRoute{route})

	// 1. Without challenges configured, GET /.well-known/acme-challenge/tok-1 falls through to normal route
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "normal route response" {
		t.Fatalf("expected normal route response, got %q", body)
	}

	// 2. Configure pending challenge
	p.UpdateChallenges([]state.HTTP01Challenge{
		{
			Hostname:         "example.com",
			Token:            "tok-1",
			KeyAuthorization: "tok-1.keyauth-signature",
		},
	})

	// 3. Exact hostname and token match returns 200 text/plain and key authorization
	req = httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("expected Content-Type: text/plain, got %q", ct)
	}
	if body := rec.Body.String(); body != "tok-1.keyauth-signature" {
		t.Errorf("expected body %q, got %q", "tok-1.keyauth-signature", body)
	}

	// 4. HEAD request returns headers only
	reqHead := httptest.NewRequest(http.MethodHead, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recHead := httptest.NewRecorder()
	p.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK {
		t.Errorf("expected 200 OK on HEAD, got %d", recHead.Code)
	}
	if ct := recHead.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("expected Content-Type: text/plain on HEAD, got %q", ct)
	}
	if recHead.Body.Len() != 0 {
		t.Errorf("expected empty body on HEAD, got %q", recHead.Body.String())
	}

	// 5. Different token on same hostname gets normal routing
	reqOtherTok := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/other-tok", nil)
	recOtherTok := httptest.NewRecorder()
	p.ServeHTTP(recOtherTok, reqOtherTok)
	if recOtherTok.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route, got %d", recOtherTok.Code)
	}
	if body := recOtherTok.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response for other token, got %q", body)
	}

	// 6. Same token on another hostname gets normal routing (404 here because route is for example.com)
	reqOtherHost := httptest.NewRequest(http.MethodGet, "http://other.com/.well-known/acme-challenge/tok-1", nil)
	recOtherHost := httptest.NewRecorder()
	p.ServeHTTP(recOtherHost, reqOtherHost)
	if recOtherHost.Code == http.StatusOK && recOtherHost.Body.String() == "tok-1.keyauth-signature" {
		t.Errorf("expected challenge NOT to be served on different hostname")
	}

	// 7. Non-GET/HEAD method gets normal routing
	reqPost := httptest.NewRequest(http.MethodPost, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recPost := httptest.NewRecorder()
	p.ServeHTTP(recPost, reqPost)
	if body := recPost.Body.String(); body == "tok-1.keyauth-signature" {
		t.Errorf("POST must not serve challenge body directly")
	}

	// 8. When source drops the challenge, the data plane stops serving it
	p.UpdateChallenges(nil)

	reqDropped := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recDropped := httptest.NewRecorder()
	p.ServeHTTP(recDropped, reqDropped)
	if recDropped.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route, got %d", recDropped.Code)
	}
	if body := recDropped.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response after challenge dropped, got %q", body)
	}
}
