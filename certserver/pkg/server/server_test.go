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

package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	acmeclient "github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/acme"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/audit"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/manager"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/testserver"
)

func generateSelfSignedCert(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"certserver test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

func signControllerToken(t *testing.T, iss, sub string, privKey *rsa.PrivateKey, kid string) string {
	t.Helper()
	hBytes, _ := json.Marshal(map[string]any{
		"alg": "RS256",
		"kid": kid,
	})
	now := time.Now()
	pBytes, _ := json.Marshal(map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": registry.CertServerAudience,
		"exp": now.Add(1 * time.Hour).Unix(),
		"nbf": now.Add(-1 * time.Minute).Unix(),
		"iat": now.Unix(),
	})

	input := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
	hashed := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func buildTestJWKS(keys map[string]*rsa.PublicKey) []byte {
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwksDoc struct {
		Keys []jwk `json:"keys"`
	}

	var doc jwksDoc
	for kid, pub := range keys {
		eBytes := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		doc.Keys = append(doc.Keys, jwk{
			Kty: "RSA",
			Kid: kid,
			Alg: "RS256",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}
	data, _ := json.Marshal(doc)
	return data
}

// TestEndToEnd_GetCertificate tests the full lifecycle:
// - A fake cluster JWKS and a controller token
// - Pebble ACME server behind certserver
// - GetCertificate initially returns retryable Unavailable status
// - Background ACME issuance completes
// - Subsequent GetCertificate call returns the certificate and private key
func TestEndToEnd_GetCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// 1. Start mock cluster JWKS server
	clusterKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate cluster key: %v", err)
	}
	const kid = "cluster-key-1"

	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildTestJWKS(map[string]*rsa.PublicKey{kid: &clusterKey.PublicKey}))
	}))
	defer jwksServer.Close()

	// 2. Configure cluster registry, binding store, and challenge handler
	const clusterID = "cluster-test"
	issuerURL := jwksServer.URL

	clusters := []registry.ClusterConfig{
		{
			ClusterID:                clusterID,
			IssuerURL:                issuerURL,
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "gari-controller",
			AllowedHostnames: []string{
				"e2e.example.com",
			},
		},
	}

	reg, err := registry.NewRegistry(clusters, registry.WithHTTPClient(jwksServer.Client()))
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer reg.Close()

	bindingStore := registry.NewMemoryBindingStore()
	auditLogger := registry.NewAuditLogger(nil)
	m := metrics.New(prometheus.NewRegistry())

	challengeStore := challenge.NewMemoryStore()
	challengeHandler := challenge.NewHandler(
		challengeStore,
		challenge.WithRegistry(reg),
		challenge.WithBindingStore(bindingStore),
		challenge.WithAuditLogger(auditLogger),
		challenge.WithMetrics(m),
	)
	challengeSrv := httptest.NewServer(audit.WrapHTTP(auditLogger, challengeHandler))
	defer challengeSrv.Close()

	// Data plane forwarder forwards Pebble challenge validation requests to challengeSrv
	// carrying the requesting Gateway's data-plane token.
	dpToken := signControllerToken(t, issuerURL, "system:serviceaccount:default:dp-sa", clusterKey, kid)
	dataPlaneForwarder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fwdReq, err := http.NewRequestWithContext(r.Context(), r.Method, challengeSrv.URL+r.URL.RequestURI(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fwdReq.Host = r.Host
		fwdReq.Header.Set("Authorization", "Bearer "+dpToken)
		resp, err := http.DefaultClient.Do(fwdReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// 3. Start Pebble ACME test server pointed at dataPlaneForwarder
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod:   86400,
		ChallengeStore:   challengeStore,
		ChallengeHandler: dataPlaneForwarder,
	})

	// 4. Initialize Manager with Pebble ACME client and temp cache
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	diskCache, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}
	accountKey, err := diskCache.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to generate account key: %v", err)
	}

	acmeCli, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		AccountKey:   accountKey,
		HTTPClient:   pebble.HTTPClient,
		UserAgent:    "e2e-test",
	})
	if err != nil {
		t.Fatalf("failed to create acme client: %v", err)
	}

	mgr := manager.NewManager(acmeCli, diskCache, challengeStore, m, func(o *manager.Options) {
		o.BindingStore = bindingStore
		if pebble.ChallengeServer != nil {
			o.SelfCheckClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return net.Dial(network, pebble.ChallengeServer.Listener.Addr().String())
					},
				},
			}
		}
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	defer mgr.Stop()

	// 5. Initialize and start gRPC server over TLS
	srvTLS := generateSelfSignedCert(t)
	serverOpts := Options{
		ListenAddr:   "127.0.0.1:0",
		TLSConfig:    srvTLS,
		ReleaseMode:  true,
		MaxHostnames: 10,
	}

	srv, err := NewServer(serverOpts, reg, mgr, bindingStore, auditLogger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	// 6. Connect gRPC client
	conn, err := grpc.NewClient(
		srv.Addr(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
	)
	if err != nil {
		t.Fatalf("failed to connect gRPC client: %v", err)
	}
	defer conn.Close()

	client := certserverv1.NewCertificateServiceClient(conn)

	// 7. Generate valid controller token
	token := signControllerToken(t, issuerURL, "system:serviceaccount:gateway-system:gari-controller", clusterKey, kid)

	req := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"E2E.EXAMPLE.COM."}, // test case and trailing dot normalization
		Gateway:                 "default/prod-gateway",
		DataPlaneServiceAccount: "default/dp-sa",
		ClusterId:               clusterID,
	}

	callCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	// 8. First call: Expect pending response (empty certificate chain) as issuance is started in background
	resp, err := client.GetCertificate(callCtx, req)
	if err != nil {
		t.Fatalf("expected initial call to return pending response, got error: %v", err)
	}
	if len(resp.CertificateChain) > 0 {
		t.Fatalf("expected empty certificate chain on initial call, got %d bytes", len(resp.CertificateChain))
	}

	// 9. Verify that binding mapping was recorded immediately
	binding, found := bindingStore.GetBinding(clusterID, "default/prod-gateway")
	if !found {
		t.Fatalf("expected gateway binding to be recorded")
	}
	if binding.DataPlaneServiceAccount != "default/dp-sa" {
		t.Errorf("unexpected DP SA in binding: %s", binding.DataPlaneServiceAccount)
	}
	if len(binding.Hostnames) != 1 || binding.Hostnames[0] != "e2e.example.com" {
		t.Errorf("unexpected hostnames in binding: %v", binding.Hostnames)
	}

	// 10. Retry call until issuance completes and certificate is returned from cache
	successResp := waitForCertificate(t, client, callCtx, req)

	// 11. Verify certificate chain and private key
	if len(successResp.CertificateChain) == 0 {
		t.Fatalf("expected non-empty certificate chain in response")
	}
	if len(successResp.PrivateKey) == 0 {
		t.Fatalf("expected non-empty private key in response (release mode)")
	}

	// Verify certificate subject/SAN matches requested hostname via manager
	cachedData, err := mgr.GetCertificate("e2e.example.com", true)
	if err != nil || cachedData == nil {
		t.Fatalf("expected certificate to be cached in manager: %v", err)
	}
	if len(cachedData.CertificateChain) == 0 {
		t.Errorf("expected cached certificate chain")
	}
	if len(cachedData.PrivateKey) == 0 {
		t.Errorf("expected cached private key in release mode")
	}

	// 12. Negative test: Disallowed hostname refused
	disallowedReq := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"disallowed.example.com"},
		Gateway:                 "default/prod-gateway",
		DataPlaneServiceAccount: "default/dp-sa",
		ClusterId:               clusterID,
	}
	_, err = client.GetCertificate(callCtx, disallowedReq)
	if err == nil {
		t.Fatalf("expected disallowed hostname to fail")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for disallowed hostname, got: %v", err)
	}

	// 13. Negative test: Non-controller identity refused
	attackerToken := signControllerToken(t, issuerURL, "system:serviceaccount:default:attacker-sa", clusterKey, kid)
	attackerCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+attackerToken)
	_, err = client.GetCertificate(attackerCtx, req)
	if err == nil {
		t.Fatalf("expected non-controller to fail")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for non-controller identity, got: %v", err)
	}

	// 14. Negative test: Unauthenticated caller receives generic error without leaked details
	badToken := "invalid.jwt.token"
	badAuthCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+badToken)
	_, err = client.GetCertificate(badAuthCtx, req)
	if err == nil {
		t.Fatalf("expected invalid token to fail")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %v", err)
	} else if st.Message() != "authentication failed" {
		t.Errorf("expected generic message 'authentication failed', got: %q", st.Message())
	}
}

// TestGetCertificate_RequesterFromDifferentGatewayDoesNotReceiveChallenge verifies that:
// a requester from a different Gateway, which isn't a candidate, doesn't receive the challenge.
func TestGetCertificate_RequesterFromDifferentGatewayDoesNotReceiveChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	pebble := testserver.StartPebble(t, testserver.ServerConfig{})

	clusterKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate cluster key: %v", err)
	}
	const kid = "key-diff-gw"
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildTestJWKS(map[string]*rsa.PublicKey{kid: &clusterKey.PublicKey}))
	}))
	defer jwksServer.Close()

	const clusterID = "cluster-diff-gw"
	clusters := []registry.ClusterConfig{
		{
			ClusterID:                clusterID,
			IssuerURL:                jwksServer.URL,
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "gari-controller",
			AllowedHostnames: []string{
				"shared.example.com",
			},
		},
	}
	reg, err := registry.NewRegistry(clusters, registry.WithHTTPClient(jwksServer.Client()))
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer reg.Close()

	bindingStore := registry.NewMemoryBindingStore()
	auditLogger := registry.NewAuditLogger(nil)
	challengeStore := challenge.NewMemoryStore()

	// Register a challenge for Gateway A with candidate Gateway Candidate
	reqA := challenge.Requester{
		ClusterID:               clusterID,
		Gateway:                 "default/gw-a",
		DataPlaneServiceAccount: "default/dp-a",
		HostnamesKey:            "shared.example.com",
	}
	candidateShared := challenge.Requester{
		ClusterID:               clusterID,
		Gateway:                 "default/gw-candidate",
		DataPlaneServiceAccount: "default/dp-candidate",
		HostnamesKey:            "shared.example.com",
	}
	if err := challengeStore.PutWithCandidates(ctx, "tok-xyz", "shared.example.com", "tok-xyz.auth", time.Now().Add(10*time.Minute), reqA, []challenge.Requester{candidateShared}); err != nil {
		t.Fatalf("failed to register challenge: %v", err)
	}

	tempDir := t.TempDir()
	diskCache, err := cache.NewDiskCache(tempDir)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}
	accountKey, err := diskCache.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to generate account key: %v", err)
	}
	acmeCli, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		AccountKey:   accountKey,
		HTTPClient:   pebble.HTTPClient,
	})
	if err != nil {
		t.Fatalf("failed to create ACME client: %v", err)
	}

	m := metrics.New(prometheus.NewRegistry())
	mgr := manager.NewManager(acmeCli, diskCache, challengeStore, m)
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	defer mgr.Stop()

	srvTLS := generateSelfSignedCert(t)
	srv, err := NewServer(Options{ListenAddr: "127.0.0.1:0", TLSConfig: srvTLS}, reg, mgr, bindingStore, auditLogger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatalf("failed to connect grpc: %v", err)
	}
	defer conn.Close()

	client := certserverv1.NewCertificateServiceClient(conn)
	token := signControllerToken(t, jwksServer.URL, "system:serviceaccount:gateway-system:gari-controller", clusterKey, kid)
	callCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	// 1. Gateway A (the primary requester) receives the challenge
	respA, err := client.GetCertificate(callCtx, &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"shared.example.com"},
		Gateway:                 "default/gw-a",
		DataPlaneServiceAccount: "default/dp-a",
		ClusterId:               clusterID,
	})
	if err != nil {
		t.Fatalf("Gateway A GetCertificate failed: %v", err)
	}
	if len(respA.Challenges) != 1 || respA.Challenges[0].Token != "tok-xyz" {
		t.Fatalf("expected Gateway A to receive challenge tok-xyz, got %+v", respA.Challenges)
	}

	// 2. Gateway Candidate (the candidate) receives the challenge
	respCandidate, err := client.GetCertificate(callCtx, &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"shared.example.com"},
		Gateway:                 "default/gw-candidate",
		DataPlaneServiceAccount: "default/dp-candidate",
		ClusterId:               clusterID,
	})
	if err != nil {
		t.Fatalf("Gateway Candidate GetCertificate failed: %v", err)
	}
	if len(respCandidate.Challenges) != 1 || respCandidate.Challenges[0].Token != "tok-xyz" {
		t.Fatalf("expected Gateway Candidate to receive challenge tok-xyz, got %+v", respCandidate.Challenges)
	}

	// 3. Gateway B (unrelated gateway, not candidate) does NOT receive the challenge
	respB, err := client.GetCertificate(callCtx, &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"shared.example.com"},
		Gateway:                 "default/gw-b",
		DataPlaneServiceAccount: "default/dp-b",
		ClusterId:               clusterID,
	})
	if err != nil {
		t.Fatalf("Gateway B GetCertificate failed: %v", err)
	}
	if len(respB.Challenges) != 0 {
		t.Fatalf("expected Gateway B to receive 0 challenges, got %d: %+v", len(respB.Challenges), respB.Challenges)
	}
}
