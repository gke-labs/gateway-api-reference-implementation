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

package challenge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/audit"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

func TestChallengeHandler_AcceptanceCriteria(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryStore()
	handler := NewHandler(store)

	now := time.Now()
	store.timeNow = func() time.Time { return now }

	validToken := "valid-token-12345"
	validKeyAuth := "valid-token-12345.thumbprint-abcde"
	validHost := "example.com"

	expiredToken := "expired-token-67890"
	expiredKeyAuth := "expired-token-67890.thumbprint-fghij"

	// Register valid challenge
	if err := store.Put(ctx, validToken, validHost, validKeyAuth, now.Add(10*time.Minute), Requester{}); err != nil {
		t.Fatalf("store.Put valid challenge failed: %v", err)
	}

	// Register expired challenge
	if err := store.Put(ctx, expiredToken, validHost, expiredKeyAuth, now.Add(-1*time.Minute), Requester{}); err != nil {
		t.Fatalf("store.Put expired challenge failed: %v", err)
	}

	tests := []struct {
		name           string
		token          string
		host           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "unknown token",
			token:          "unknown-token-xyz",
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "expired token",
			token:          expiredToken,
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "wrong Host",
			token:          validToken,
			host:           "wrong.example.com",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "correct response",
			token:          validToken,
			host:           validHost,
			expectedStatus: http.StatusOK,
			expectedBody:   validKeyAuth,
		},
		{
			name:           "correct response with host port and uppercase",
			token:          validToken,
			host:           "EXAMPLE.COM:8080",
			expectedStatus: http.StatusOK,
			expectedBody:   validKeyAuth,
		},
		{
			name:           "token too long (exceeds 128 characters)",
			token:          strings.Repeat("a", 129),
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "token with non-base64url characters",
			token:          "invalid+token=with/symbols",
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "token with slash",
			token:          "foo/bar",
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "token that is just a slash",
			token:          "/",
			host:           validHost,
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+tc.token, nil)
			req.Host = tc.host

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			resp := rr.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			if tc.expectedBody != "" {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				if string(body) != tc.expectedBody {
					t.Errorf("expected body %q, got %q", tc.expectedBody, string(body))
				}
			}
		})
	}
}

func TestChallengeHandler_MethodNotAllowedAndMalformedPaths(t *testing.T) {
	store := NewMemoryStore()
	handler := NewHandler(store)

	// POST should return 405 Method Not Allowed
	req := httptest.NewRequest(http.MethodPost, ACMEChallengePrefix+"token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rr.Code)
	}

	// Empty token or path traversal
	for _, path := range []string{
		ACMEChallengePrefix,
		ACMEChallengePrefix + "../other",
		ACMEChallengePrefix + "sub/path",
		"/wrong-prefix/token",
	} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 for path %q, got %d", path, rr.Code)
		}
	}
}

func TestChallengeHandler_CallerIdentity(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryStore()

	var recordedCaller string
	customResolver := &testResolverWithCaller{
		store: store,
		onResolve: func(caller string) {
			recordedCaller = caller
		},
	}

	handler := NewHandler(customResolver, WithCallerFunc(func(r *http.Request) string {
		return r.Header.Get("X-Caller-ID")
	}))

	now := time.Now()
	store.timeNow = func() time.Time { return now }
	if err := store.Put(ctx, "caller-tok", "example.com", "caller-auth", now.Add(time.Minute), Requester{}); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+"caller-tok", nil)
	req.Host = "example.com"
	req.Header.Set("X-Caller-ID", "gateway-cluster-1")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if recordedCaller != "gateway-cluster-1" {
		t.Errorf("expected recorded caller 'gateway-cluster-1', got %q", recordedCaller)
	}
}

type testResolverWithCaller struct {
	store     *MemoryStore
	onResolve func(caller string)
}

func (r *testResolverWithCaller) ResolveChallenge(ctx context.Context, caller string, host string, token string) (string, error) {
	if r.onResolve != nil {
		r.onResolve(caller)
	}
	return r.store.ResolveChallenge(ctx, caller, host, token)
}

func TestChallengeHandler_WithRegistryAndBinding(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryStore()
	bindingStore := registry.NewMemoryBindingStore()

	// Mock JWKS Server
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	const kid = "key-1"

	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		eBytes := []byte{byte(privKey.PublicKey.E >> 16), byte(privKey.PublicKey.E >> 8), byte(privKey.PublicKey.E)}
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		doc := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": kid,
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer jwksServer.Close()

	clusters := []registry.ClusterConfig{
		{
			ClusterID:           "cluster-1",
			IssuerURL:           jwksServer.URL,
			JWKSURL:             jwksServer.URL,
			SharedFrontEndGroup: "fe-group",
		},
		{
			ClusterID:           "cluster-2",
			IssuerURL:           jwksServer.URL + "/cluster-2",
			JWKSURL:             jwksServer.URL,
			SharedFrontEndGroup: "fe-group",
		},
	}

	reg, err := registry.NewRegistry(clusters, registry.WithHTTPClient(jwksServer.Client()))
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	defer reg.Close()

	signToken := func(iss, sub string) string {
		hBytes, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid})
		now := time.Now()
		pBytes, _ := json.Marshal(map[string]any{
			"iss": iss,
			"sub": sub,
			"aud": registry.CertServerAudience,
			"exp": now.Add(time.Hour).Unix(),
			"nbf": now.Add(-time.Minute).Unix(),
		})
		input := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
		hashed := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
		if err != nil {
			t.Fatalf("SignPKCS1v15 failed: %v", err)
		}
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	var auditBuf bytes.Buffer
	auditLogger := registry.NewAuditLogger(&auditBuf)
	promReg := prometheus.NewRegistry()
	m := metrics.New(promReg)

	now := time.Now()
	handler := NewHandler(
		store,
		WithRegistry(reg),
		WithBindingStore(bindingStore),
		WithAuditLogger(auditLogger),
		WithMetrics(m),
		WithTimeNow(func() time.Time { return now }),
	)
	httpHandler := audit.WrapHTTP(auditLogger, handler)

	// Register pending challenge for default/gw-1 in cluster-1 with dataPlaneSA "default/dp-sa-1"
	const testToken = "tok-valid-binding"
	const testKeyAuth = "tok-valid-binding.auth123"
	const testHost = "binding.example.com"

	err = store.Put(ctx, testToken, testHost, testKeyAuth, now.Add(10*time.Minute), Requester{
		ClusterID:               "cluster-1",
		Gateway:                 "default/gw-1",
		DataPlaneServiceAccount: "default/dp-sa-1",
		HostnamesKey:            testHost,
	})
	if err != nil {
		t.Fatalf("store.Put failed: %v", err)
	}

	// 1. Missing Authorization header -> 404
	req := httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+testToken, nil)
	req.Host = testHost
	rr := httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing auth header, got %d", rr.Code)
	}

	// 2. Invalid Bearer token -> 404
	req = httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+testToken, nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer invalid-jwt")
	rr = httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for invalid token, got %d", rr.Code)
	}

	// 3. Valid token but wrong data plane service account -> 404
	wrongSAToken := signToken(jwksServer.URL, "system:serviceaccount:default:dp-wrong")
	req = httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+testToken, nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+wrongSAToken)
	rr = httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for wrong SA, got %d", rr.Code)
	}

	// 4. Valid token from correct data plane SA -> 200
	correctSAToken := signToken(jwksServer.URL, "system:serviceaccount:default:dp-sa-1")
	req = httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+testToken, nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+correctSAToken)
	rr = httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for correct SA, got %d", rr.Code)
	}
	if rr.Body.String() != testKeyAuth {
		t.Errorf("expected body %q, got %q", testKeyAuth, rr.Body.String())
	}

	// Verify validated binding is NOT recorded by the challenge handler.
	// Validated bindings are recorded exclusively in fulfillAuthorization once ACME authorization succeeds.
	if bindingStore.HasValidatedBinding("cluster-1", "default/gw-1", testHost, now) {
		t.Errorf("challenge handler must not record validated binding; only fulfillAuthorization records upon successful ACME authorization")
	}

	// 5. Shared front end group: cluster-2 Gateway has recorded binding
	bindingStore.RecordBinding(registry.Binding{
		ClusterID:               "cluster-2",
		Gateway:                 "default/gw-2",
		DataPlaneServiceAccount: "default/dp-sa-2",
		Hostnames:               []string{testHost},
	})
	sharedSAToken := signToken(jwksServer.URL+"/cluster-2", "system:serviceaccount:default:dp-sa-2")
	req = httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+testToken, nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+sharedSAToken)
	rr = httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for shared front end group SA, got %d", rr.Code)
	}

	// 6. Expired challenge -> 404
	const expToken = "tok-expired-binding"
	err = store.Put(ctx, expToken, testHost, "exp.auth", now.Add(-1*time.Minute), Requester{
		ClusterID:               "cluster-1",
		Gateway:                 "default/gw-1",
		DataPlaneServiceAccount: "default/dp-sa-1",
	})
	if err != nil {
		t.Fatalf("store.Put expired failed: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, ACMEChallengePrefix+expToken, nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+correctSAToken)
	rr = httptest.NewRecorder()
	httpHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for expired challenge, got %d", rr.Code)
	}

	// Verify audit logs contain NO tokens or key authorizations
	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, testToken) {
		t.Errorf("audit log leaked ACME challenge token: %s", auditOutput)
	}
	if strings.Contains(auditOutput, testKeyAuth) {
		t.Errorf("audit log leaked ACME key authorization: %s", auditOutput)
	}
	if strings.Contains(auditOutput, correctSAToken) {
		t.Errorf("audit log leaked bearer token: %s", auditOutput)
	}
}
