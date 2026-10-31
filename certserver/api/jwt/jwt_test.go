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

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Helper to sign RS256 token
func signRS256(t *testing.T, iss, sub string, aud []string, exp, nbf, iat *time.Time, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	hdr := jwtHeader{
		Alg: "RS256",
		Kid: kid,
		Typ: "JWT",
	}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
	}
	if exp != nil {
		payload["exp"] = exp.Unix()
	}
	if nbf != nil {
		payload["nbf"] = nbf.Unix()
	}
	if iat != nil {
		payload["iat"] = iat.Unix()
	}

	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	toSign := hdrB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(toSign))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return toSign + "." + sigB64
}

// Helper to sign ES256 token
func signES256(t *testing.T, iss, sub string, aud []string, exp, nbf, iat *time.Time, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	hdr := jwtHeader{
		Alg: "ES256",
		Kid: kid,
		Typ: "JWT",
	}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
	}
	if exp != nil {
		payload["exp"] = exp.Unix()
	}
	if nbf != nil {
		payload["nbf"] = nbf.Unix()
	}
	if iat != nil {
		payload["iat"] = iat.Unix()
	}

	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	toSign := hdrB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(toSign))
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	return toSign + "." + sigB64
}

// Helper to sign HS256 token
func signHS256(t *testing.T, iss, sub string, aud []string, exp *time.Time, secret []byte) string {
	t.Helper()
	hdr := jwtHeader{Alg: "HS256", Typ: "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
	}
	if exp != nil {
		payload["exp"] = exp.Unix()
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	toSign := hdrB64 + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(toSign))
	sig := mac.Sum(nil)

	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Helper to sign alg=none token
func signNone(t *testing.T, iss, sub string, aud []string, exp *time.Time) string {
	t.Helper()
	hdr := jwtHeader{Alg: "none", Typ: "JWT"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
	}
	if exp != nil {
		payload["exp"] = exp.Unix()
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return hdrB64 + "." + payloadB64 + "."
}

func exportRSAJWK(pub *rsa.PublicKey, kid string) jwkEntry {
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return jwkEntry{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func exportECJWK(pub *ecdsa.PublicKey, kid string) jwkEntry {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	return jwkEntry{
		Kty: "EC",
		Crv: "P-256",
		Kid: kid,
		Use: "sig",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

func TestVerifier_AlgorithmsAndClaims(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := "https://kubernetes.default.svc"
	subject := "system:serviceaccount:default:snigateway-agent"
	audience := "snigateway"

	jwksDoc := jwksDocument{
		Keys: []jwkEntry{
			exportRSAJWK(&rsaKey.PublicKey, "rsa-1"),
			exportECJWK(&ecKey.PublicKey, "ec-1"),
		},
	}
	jwksJSON, err := json.Marshal(jwksDoc)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	jwksFile := filepath.Join(tmpDir, "jwks.json")
	if err := os.WriteFile(jwksFile, jwksJSON, 0644); err != nil {
		t.Fatal(err)
	}

	cache, err := NewJWKSCache([]IssuerConfig{
		{
			IssuerURL: issuer,
			JWKSFile:  jwksFile,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	verifier := NewVerifier(cache, WithAudience("snigateway"))

	now := time.Now()
	expFuture := now.Add(1 * time.Hour)
	expPast := now.Add(-10 * time.Minute)
	nbfFuture := now.Add(10 * time.Minute)
	iatOld := now.Add(-25 * time.Hour)

	t.Run("Valid RS256 token", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expFuture, nil, &now, rsaKey, "rsa-1")
		claims, err := verifier.Verify(t.Context(), token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims.Issuer != issuer || claims.Subject != subject {
			t.Fatalf("unexpected claims: %+v", claims)
		}
	})

	t.Run("Valid ES256 token", func(t *testing.T) {
		token := signES256(t, issuer, subject, []string{audience}, &expFuture, nil, &now, ecKey, "ec-1")
		claims, err := verifier.Verify(t.Context(), token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims.Issuer != issuer || claims.Subject != subject {
			t.Fatalf("unexpected claims: %+v", claims)
		}
	})

	t.Run("Reject alg=none", func(t *testing.T) {
		token := signNone(t, issuer, subject, []string{audience}, &expFuture)
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("expected alg=none to be rejected, got: %v", err)
		}
	})

	t.Run("Reject HS256", func(t *testing.T) {
		token := signHS256(t, issuer, subject, []string{audience}, &expFuture, []byte("super-secret"))
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "HMAC algorithms are rejected") {
			t.Fatalf("expected HS256 to be rejected, got: %v", err)
		}
	})

	t.Run("Reject wrong audience", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{"other-audience"}, &expFuture, nil, &now, rsaKey, "rsa-1")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "audience mismatch") {
			t.Fatalf("expected audience mismatch, got: %v", err)
		}
	})

	t.Run("Reject expired token", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expPast, nil, nil, rsaKey, "rsa-1")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected token expired error, got: %v", err)
		}
	})

	t.Run("Reject nbf in future", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expFuture, &nbfFuture, nil, rsaKey, "rsa-1")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "not valid yet") {
			t.Fatalf("expected nbf in future error, got: %v", err)
		}
	})

	t.Run("Reject iat older than 24h", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expFuture, nil, &iatOld, rsaKey, "rsa-1")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "iat is older than 24 hours") {
			t.Fatalf("expected iat older than 24h error, got: %v", err)
		}
	})

	t.Run("Reject unknown issuer", func(t *testing.T) {
		token := signRS256(t, "https://unknown.issuer.example.com", subject, []string{audience}, &expFuture, nil, nil, rsaKey, "rsa-1")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "unknown or unconfigured issuer") {
			t.Fatalf("expected unknown issuer error, got: %v", err)
		}
	})

	t.Run("Reject unknown kid after refresh", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expFuture, nil, nil, rsaKey, "unknown-kid")
		_, err := verifier.Verify(t.Context(), token)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected kid not found error, got: %v", err)
		}
	})

	t.Run("ParseTokenExpiry", func(t *testing.T) {
		token := signRS256(t, issuer, subject, []string{audience}, &expFuture, nil, nil, rsaKey, "rsa-1")
		extractedExp, err := ParseTokenExpiry(token)
		if err != nil {
			t.Fatalf("ParseTokenExpiry failed: %v", err)
		}
		if extractedExp.Unix() != expFuture.Unix() {
			t.Fatalf("expected exp %v, got %v", expFuture.Unix(), extractedExp.Unix())
		}
	})
}

func TestJWKSCache_OIDCDiscoveryAndRateLimiting(t *testing.T) {
	rsaKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)

	var discoveryRequests atomic.Int32
	var jwksRequests atomic.Int32
	var totalRequests atomic.Int32
	var returnSecondKey atomic.Bool
	var forceError atomic.Bool

	var serverURL string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests.Add(1)
		if forceError.Load() {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveryRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
				Issuer:  serverURL,
				JWKSURI: serverURL + "/jwks.json",
			})

		case "/jwks.json":
			jwksRequests.Add(1)
			keys := []jwkEntry{exportRSAJWK(&rsaKey1.PublicKey, "key-1")}
			if returnSecondKey.Load() {
				keys = append(keys, exportRSAJWK(&rsaKey2.PublicKey, "key-2"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwksDocument{Keys: keys})

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	simulatedTime := time.Now()
	cache, err := NewJWKSCache(
		[]IssuerConfig{{IssuerURL: serverURL}},
		WithHTTPClient(ts.Client()),
		WithUnknownKidRateLimit(1*time.Minute),
		WithJWKSTimeNow(func() time.Time { return simulatedTime }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	ctx := t.Context()

	// 1. First key should be loaded
	key1, err := cache.GetKey(ctx, serverURL, "key-1")
	if err != nil {
		t.Fatalf("failed to get key-1: %v", err)
	}
	if key1 == nil {
		t.Fatal("expected non-nil key1")
	}

	initialJWKSReqs := jwksRequests.Load()

	// 2. Request for known key-1 should use cache and NOT trigger network request
	key1Cached, err := cache.GetKey(ctx, serverURL, "key-1")
	if err != nil || key1Cached == nil {
		t.Fatalf("failed to get key-1 from cache: %v", err)
	}
	if jwksRequests.Load() != initialJWKSReqs {
		t.Fatalf("expected no network call for cached key, but jwksRequests changed from %d to %d", initialJWKSReqs, jwksRequests.Load())
	}

	// 3. Advance time past 1 minute rate limit; request for unknown kid ("key-2") triggers refresh once
	simulatedTime = simulatedTime.Add(2 * time.Minute)
	returnSecondKey.Store(true)
	key2, err := cache.GetKey(ctx, serverURL, "key-2")
	if err != nil {
		t.Fatalf("failed to get key-2 after refresh: %v", err)
	}
	if key2 == nil {
		t.Fatal("expected non-nil key2")
	}
	jwksAfterRefresh := jwksRequests.Load()
	if jwksAfterRefresh <= initialJWKSReqs {
		t.Fatalf("expected jwksRequests to increase after unknown kid refresh")
	}

	// 4. Request for another unknown kid ("key-3") within 1 minute MUST be rate-limited and NOT trigger network request
	_, err = cache.GetKey(ctx, serverURL, "key-3")
	if err == nil {
		t.Fatal("expected error for unknown key-3")
	}
	if jwksRequests.Load() != jwksAfterRefresh {
		t.Fatalf("expected rate-limit to prevent refresh on unknown kid, but requests increased to %d", jwksRequests.Load())
	}

	// 5. Test failed refresh keeps old keys and rate limits subsequent attempts
	forceError.Store(true)
	// Advance time to allow a refresh attempt that fails
	simulatedTime = simulatedTime.Add(2 * time.Minute)

	reqsBeforeFailedRefresh := totalRequests.Load()

	// Try fetching another unknown key (will trigger refresh attempt and fail)
	_, _ = cache.GetKey(ctx, serverURL, "key-unknown")

	reqsAfterFailedRefresh := totalRequests.Load()
	if reqsAfterFailedRefresh <= reqsBeforeFailedRefresh {
		t.Fatalf("expected refresh attempt on unknown key, but totalRequests did not increase")
	}

	// Immediate subsequent request within rate limit window MUST NOT trigger another outbound fetch
	_, _ = cache.GetKey(ctx, serverURL, "key-unknown-2")
	if totalRequests.Load() != reqsAfterFailedRefresh {
		t.Fatalf("expected failed refresh attempt to be rate-limited, but requests increased to %d", totalRequests.Load())
	}

	// Old keys key-1 and key-2 should STILL be present and working!
	k1Still, err := cache.GetKey(ctx, serverURL, "key-1")
	if err != nil || k1Still == nil {
		t.Fatalf("expected key-1 to still be available after failed refresh: %v", err)
	}
	k2Still, err := cache.GetKey(ctx, serverURL, "key-2")
	if err != nil || k2Still == nil {
		t.Fatalf("expected key-2 to still be available after failed refresh: %v", err)
	}
}

func TestJWKSCache_ResponseCapAndHTTPS(t *testing.T) {
	t.Run("Enforce HTTPS only", func(t *testing.T) {
		_, err := NewJWKSCache([]IssuerConfig{
			{IssuerURL: "http://insecure-issuer.example.com"},
		})
		if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
			t.Fatalf("expected HTTPS error, got: %v", err)
		}
	})

	t.Run("Enforce 1 MiB response cap", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Write > 1 MiB
			padding := make([]byte, 1024*1024+100)
			_, _ = w.Write(padding)
		}))
		defer ts.Close()

		cache, err := NewJWKSCache(
			[]IssuerConfig{{IssuerURL: ts.URL}},
			WithHTTPClient(ts.Client()),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()

		_, err = cache.GetKey(t.Context(), ts.URL, "any-kid")
		if err == nil || !strings.Contains(err.Error(), "1 MiB limit") {
			t.Fatalf("expected 1 MiB limit error, got: %v", err)
		}
	})

	t.Run("Startup with unreachable issuer still initializes cache", func(t *testing.T) {
		unreachableURL := "https://127.0.0.1:59999" // port where nothing is listening
		cache, err := NewJWKSCache([]IssuerConfig{
			{IssuerURL: unreachableURL},
		})
		if err != nil {
			t.Fatalf("expected NewJWKSCache to succeed even when issuer unreachable, got: %v", err)
		}
		defer cache.Close()

		// Key request should fail because keys couldn't be loaded
		_, err = cache.GetKey(t.Context(), unreachableURL, "kid")
		if err == nil {
			t.Fatal("expected GetKey to fail for unreachable issuer")
		}
	})
}

func TestParseJWKS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Valid RSA and EC keys", func(t *testing.T) {
		doc := jwksDocument{
			Keys: []jwkEntry{
				exportRSAJWK(&rsaKey.PublicKey, "rsa-key-1"),
				exportECJWK(&ecKey.PublicKey, "ec-key-1"),
			},
		}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := ParseJWKS(data)
		if err != nil {
			t.Fatalf("unexpected error parsing valid JWKS: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}
		if _, ok := keys["rsa-key-1"].(*rsa.PublicKey); !ok {
			t.Errorf("expected *rsa.PublicKey for rsa-key-1, got %T", keys["rsa-key-1"])
		}
		if _, ok := keys["ec-key-1"].(*ecdsa.PublicKey); !ok {
			t.Errorf("expected *ecdsa.PublicKey for ec-key-1, got %T", keys["ec-key-1"])
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		_, err := ParseJWKS([]byte(`{not json`))
		if err == nil {
			t.Fatal("expected error parsing invalid JSON, got nil")
		}
	})

	t.Run("Empty keys list", func(t *testing.T) {
		keys, err := ParseJWKS([]byte(`{"keys":[]}`))
		if err != nil {
			t.Fatalf("unexpected error parsing empty keys: %v", err)
		}
		if len(keys) != 0 {
			t.Fatalf("expected 0 keys, got %d", len(keys))
		}
	})
}

func TestJWKSCache_DynamicIssuers(t *testing.T) {
	tempDir := t.TempDir()
	jwksPath1 := filepath.Join(tempDir, "jwks1.json")
	jwksPath2 := filepath.Join(tempDir, "jwks2.json")

	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	doc1 := jwksDocument{Keys: []jwkEntry{exportRSAJWK(&rsaKey1.PublicKey, "key-1")}}
	docBytes1, _ := json.Marshal(doc1)
	if err := os.WriteFile(jwksPath1, docBytes1, 0600); err != nil {
		t.Fatal(err)
	}

	doc2 := jwksDocument{Keys: []jwkEntry{
		exportRSAJWK(&rsaKey1.PublicKey, "key-1"),
		exportRSAJWK(&rsaKey2.PublicKey, "key-2"),
	}}
	docBytes2, _ := json.Marshal(doc2)
	if err := os.WriteFile(jwksPath2, docBytes2, 0600); err != nil {
		t.Fatal(err)
	}

	cache, err := NewJWKSCache(nil)
	if err != nil {
		t.Fatalf("NewJWKSCache failed: %v", err)
	}
	defer cache.Close()

	ctx := t.Context()
	issuerURL := "https://dynamic-issuer.example.com"

	// Key lookup before registration should fail
	if _, err := cache.GetKey(ctx, issuerURL, "key-1"); err == nil {
		t.Fatal("expected error before issuer is registered")
	}

	// 1. Add new issuer dynamically
	err = cache.AddOrUpdateIssuer(ctx, IssuerConfig{
		IssuerURL: issuerURL,
		JWKSFile:  jwksPath1,
	})
	if err != nil {
		t.Fatalf("AddOrUpdateIssuer failed: %v", err)
	}

	// Key 1 should resolve
	k, err := cache.GetKey(ctx, issuerURL, "key-1")
	if err != nil {
		t.Fatalf("GetKey for key-1 failed: %v", err)
	}
	if k == nil {
		t.Fatal("expected non-nil key")
	}

	// Key 2 should not exist yet
	if _, err := cache.GetKey(ctx, issuerURL, "key-2"); err == nil {
		t.Fatal("expected key-2 to not exist yet")
	}

	// 2. Update issuer with rotation (pointing to jwksPath2 with key-1 and key-2)
	err = cache.AddOrUpdateIssuer(ctx, IssuerConfig{
		IssuerURL: issuerURL,
		JWKSFile:  jwksPath2,
	})
	if err != nil {
		t.Fatalf("AddOrUpdateIssuer rotation failed: %v", err)
	}

	// Both key-1 and key-2 should resolve
	if _, err := cache.GetKey(ctx, issuerURL, "key-1"); err != nil {
		t.Fatalf("GetKey for key-1 after rotation failed: %v", err)
	}
	if _, err := cache.GetKey(ctx, issuerURL, "key-2"); err != nil {
		t.Fatalf("GetKey for key-2 after rotation failed: %v", err)
	}

	// 3. Failed update keeps previous keys
	err = cache.AddOrUpdateIssuer(ctx, IssuerConfig{
		IssuerURL: issuerURL,
		JWKSFile:  filepath.Join(tempDir, "nonexistent.json"),
	})
	if err == nil {
		t.Fatal("expected error on nonexistent JWKS file")
	}

	// Previous keys still resolve
	if _, err := cache.GetKey(ctx, issuerURL, "key-1"); err != nil {
		t.Fatalf("GetKey for key-1 after failed update failed: %v", err)
	}
	if _, err := cache.GetKey(ctx, issuerURL, "key-2"); err != nil {
		t.Fatalf("GetKey for key-2 after failed update failed: %v", err)
	}

	// 4. Update issuer using in-memory JWKSBytes directly
	err = cache.AddOrUpdateIssuer(ctx, IssuerConfig{
		IssuerURL: issuerURL,
		JWKSBytes: docBytes2,
	})
	if err != nil {
		t.Fatalf("AddOrUpdateIssuer with JWKSBytes failed: %v", err)
	}
	if _, err := cache.GetKey(ctx, issuerURL, "key-2"); err != nil {
		t.Fatalf("GetKey for key-2 failed after in-memory JWKSBytes update: %v", err)
	}

	// 5. Remove issuer
	cache.RemoveIssuer(issuerURL)
	if _, err := cache.GetKey(ctx, issuerURL, "key-1"); err == nil {
		t.Fatal("expected error after RemoveIssuer")
	}
}
