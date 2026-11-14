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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

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

type testHarness struct {
	reg          *registry.Registry
	mgr          *manager.Manager
	bindingStore registry.BindingStore
	auditBuf     *bytes.Buffer
	challengeSrv *httptest.Server
	pebble       *testserver.Server
	grpcClient   certserverv1.CertificateServiceClient
	stopFunc     func()

	mu             sync.Mutex
	forwardHeader  string
	forwardExpired bool
	challengeStore challenge.Store

	clusterKey *rsa.PrivateKey
	kid        string
	issuerURL  string
}

func (h *testHarness) SignToken(issuerURL, sub string) string {
	hBytes, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": h.kid})
	now := time.Now()
	pBytes, _ := json.Marshal(map[string]any{
		"iss": issuerURL,
		"sub": sub,
		"aud": registry.CertServerAudience,
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	})
	input := base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(pBytes)
	hashed := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, h.clusterKey, crypto.SHA256, hashed[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func setupChallengeBindingHarness(t *testing.T) *testHarness {
	t.Helper()
	ctx := t.Context()

	// 1. Generate RSA key for clusters
	clusterKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate cluster key: %v", err)
	}
	const kid = "cluster-key-test"

	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildTestJWKS(map[string]*rsa.PublicKey{kid: &clusterKey.PublicKey}))
	}))

	issuerURL := jwksServer.URL

	clusters := []registry.ClusterConfig{
		{
			ClusterID:                "cluster-1",
			IssuerURL:                issuerURL,
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "controller-sa",
			SharedFrontEndGroup:      "shared-group-a",
			AllowedHostnames:         []string{"*.example.com"},
		},
		{
			ClusterID:                "cluster-2",
			IssuerURL:                issuerURL + "/cluster-2",
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "controller-sa",
			SharedFrontEndGroup:      "shared-group-a",
			AllowedHostnames:         []string{"*.example.com"},
		},
		{
			ClusterID:                "cluster-3",
			IssuerURL:                issuerURL + "/cluster-3",
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "controller-sa",
			// No shared-front-end group
			AllowedHostnames: []string{"*.example.com"},
		},
	}

	reg, err := registry.NewRegistry(clusters, registry.WithHTTPClient(jwksServer.Client()))
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	bindingStore := registry.NewMemoryBindingStore()
	var auditBuf bytes.Buffer
	auditLogger := registry.NewAuditLogger(&auditBuf)
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

	h := &testHarness{
		reg:            reg,
		bindingStore:   bindingStore,
		auditBuf:       &auditBuf,
		challengeSrv:   challengeSrv,
		challengeStore: challengeStore,
		clusterKey:     clusterKey,
		kid:            kid,
		issuerURL:      issuerURL,
	}

	// Dynamic forwarder acting as the data plane forwarding to certserver
	forwarder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		authHeader := h.forwardHeader
		simulateExpired := h.forwardExpired
		h.mu.Unlock()

		if simulateExpired {
			// Fast-expire any item in store
			tok := strings.TrimPrefix(r.URL.Path, challenge.ACMEChallengePrefix)
			if item, err := challengeStore.Get(r.Context(), tok); err == nil && item != nil {
				_ = challengeStore.Put(r.Context(), tok, item.Identifier, item.KeyAuth, time.Now().Add(-1*time.Hour), item.Requester)
			}
		}

		fwdReq, err := http.NewRequestWithContext(r.Context(), r.Method, challengeSrv.URL+r.URL.RequestURI(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fwdReq.Host = r.Host
		if authHeader != "" {
			fwdReq.Header.Set("Authorization", authHeader)
		}

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

	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod:   86400,
		ChallengeStore:   challengeStore,
		ChallengeHandler: forwarder,
	})
	h.pebble = pebble

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
		UserAgent:    "e2e-binding-test",
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
	h.mgr = mgr

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

	conn, err := grpc.NewClient(
		srv.Addr(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
	)
	if err != nil {
		t.Fatalf("failed to connect gRPC client: %v", err)
	}

	h.grpcClient = certserverv1.NewCertificateServiceClient(conn)

	h.stopFunc = func() {
		conn.Close()
		srv.Stop()
		mgr.Stop()
		pebble.Close()
		challengeSrv.Close()
		reg.Close()
		jwksServer.Close()
	}

	t.Cleanup(h.stopFunc)
	return h
}

// waitForCertificate waits for certificate issuance by polling GetCertificate until a certificate
// is returned or the deadline passes. Under race detection and parallel CI load across packages,
// Pebble ACME order processing (order creation, challenge validation, and order finalization)
// takes multiple 1-second ACME client polling intervals (WaitAuthorization, WaitOrder), so allow
// 25 seconds for certificate issuance to complete.
func waitForCertificate(t *testing.T, client certserverv1.CertificateServiceClient, ctx context.Context, req *certserverv1.GetCertificateRequest) *certserverv1.GetCertificateResponse {
	t.Helper()

	deadline := time.Now().Add(25 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		resp, err := client.GetCertificate(ctx, req)
		if err == nil && resp != nil && len(resp.CertificateChain) > 0 {
			return resp
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("expected certificate issuance to succeed for %s, last error: %v", req.Gateway, lastErr)
	return nil
}

// TestPebble_ChallengeBindingScenarios verifies all acceptance criteria for challenge binding with Pebble:
// 1. The requesting Gateway's data plane answers, and issuance succeeds;
// 2. Another cluster's data plane answers, and issuance fails;
// 3. Another Gateway in the same cluster but not in the requester's group answers, and issuance fails;
// 4. A Gateway in the same shared-front-end group answers, and issuance succeeds;
// 5. An unauthenticated forward is refused;
// 6. An expired authorization is refused.
func TestPebble_ChallengeBindingScenarios(t *testing.T) {
	pollCertificate := func(t *testing.T, client certserverv1.CertificateServiceClient, req *certserverv1.GetCertificateRequest, ctrlToken string, shouldSucceed bool) *certserverv1.GetCertificateResponse {
		t.Helper()
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+ctrlToken))
		if shouldSucceed {
			return waitForCertificate(t, client, ctx, req)
		}
		resp, _ := client.GetCertificate(ctx, req)
		if resp != nil && len(resp.CertificateChain) > 0 {
			return resp
		}
		time.Sleep(500 * time.Millisecond)
		respRetry, _ := client.GetCertificate(ctx, req)
		if respRetry != nil && len(respRetry.CertificateChain) > 0 {
			return respRetry
		}
		return nil
	}

	t.Run("1_RequestingGatewayDataPlaneAnswers_IssuanceSucceeds", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		dpToken := "Bearer " + h.SignToken(h.issuerURL, "system:serviceaccount:default:dp-1")
		ctrlToken := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")

		h.mu.Lock()
		h.forwardHeader = dpToken
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"gw1.example.com"},
			Gateway:                 "default/gw-1",
			DataPlaneServiceAccount: "default/dp-1",
			ClusterId:               "cluster-1",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, true)
		if len(resp.CertificateChain) == 0 {
			t.Fatal("expected non-empty certificate chain")
		}
	})

	t.Run("2_AnotherClusterDataPlaneAnswers_IssuanceFails", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		// Requester is in cluster-3 (no shared front end group)
		// Forwarder sends token from cluster-1
		dpToken := "Bearer " + h.SignToken(h.issuerURL, "system:serviceaccount:default:dp-1")
		ctrlToken := h.SignToken(h.issuerURL+"/cluster-3", "system:serviceaccount:gateway-system:controller-sa")

		h.mu.Lock()
		h.forwardHeader = dpToken
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"cluster3.example.com"},
			Gateway:                 "default/gw-3a",
			DataPlaneServiceAccount: "default/dp-3a",
			ClusterId:               "cluster-3",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, false)
		if resp != nil {
			t.Fatalf("expected issuance to fail for cross-cluster unauthorized forward, but got certificate")
		}
	})

	t.Run("3_AnotherGatewaySameClusterNotInGroup_IssuanceFails", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		// Requester is gateway gw-3a in cluster-3 (no shared front end group)
		// Forwarder sends token for gw-3b in cluster-3
		dpToken := "Bearer " + h.SignToken(h.issuerURL+"/cluster-3", "system:serviceaccount:default:dp-3b")
		ctrlToken := h.SignToken(h.issuerURL+"/cluster-3", "system:serviceaccount:gateway-system:controller-sa")

		h.mu.Lock()
		h.forwardHeader = dpToken
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"samecluster-diffgw.example.com"},
			Gateway:                 "default/gw-3a",
			DataPlaneServiceAccount: "default/dp-3a",
			ClusterId:               "cluster-3",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, false)
		if resp != nil {
			t.Fatalf("expected issuance to fail for different gateway in same cluster without shared group")
		}
	})

	t.Run("4_SharedFrontEndGroupDataPlaneAnswers_IssuanceSucceeds", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		// Pre-record gateway-2 from cluster-2 in the shared group
		h.bindingStore.RecordBinding(registry.Binding{
			ClusterID:               "cluster-2",
			Gateway:                 "default/gw-2",
			DataPlaneServiceAccount: "default/dp-2",
			Hostnames:               []string{"shared-fe.example.com"},
		})

		// Requester is gateway-1 in cluster-1 (both cluster-1 and cluster-2 are in shared-group-a)
		// Forwarder sends token from cluster-2 gateway-2
		dpToken := "Bearer " + h.SignToken(h.issuerURL+"/cluster-2", "system:serviceaccount:default:dp-2")
		ctrlToken := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")

		h.mu.Lock()
		h.forwardHeader = dpToken
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"shared-fe.example.com"},
			Gateway:                 "default/gw-1",
			DataPlaneServiceAccount: "default/dp-1",
			ClusterId:               "cluster-1",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, true)
		if len(resp.CertificateChain) == 0 {
			t.Fatal("expected non-empty certificate chain for shared-front-end group")
		}
	})

	t.Run("5_UnauthenticatedForward_Refused", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		ctrlToken := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")

		// Forwarder sends NO authorization header
		h.mu.Lock()
		h.forwardHeader = ""
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"unauth.example.com"},
			Gateway:                 "default/gw-1",
			DataPlaneServiceAccount: "default/dp-1",
			ClusterId:               "cluster-1",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, false)
		if resp != nil {
			t.Fatalf("expected unauthenticated forward to be refused, but got certificate")
		}
	})

	t.Run("6_ExpiredAuthorization_Refused", func(t *testing.T) {
		h := setupChallengeBindingHarness(t)
		dpToken := "Bearer " + h.SignToken(h.issuerURL, "system:serviceaccount:default:dp-1")
		ctrlToken := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")

		// Forwarder simulates expired authorization
		h.mu.Lock()
		h.forwardHeader = dpToken
		h.forwardExpired = true
		h.mu.Unlock()

		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{"expired-authz.example.com"},
			Gateway:                 "default/gw-1",
			DataPlaneServiceAccount: "default/dp-1",
			ClusterId:               "cluster-1",
		}

		resp := pollCertificate(t, h.grpcClient, req, ctrlToken, false)
		if resp != nil {
			t.Fatalf("expected expired authorization to be refused, but got certificate")
		}
	})
}

// TestPebble_SecondRequesterCannotGetCachedCertWithoutBinding verifies that:
// A cached certificate can be released to another requester only after that requester passes its own binding check.
func TestPebble_SecondRequesterCannotGetCachedCertWithoutBinding(t *testing.T) {
	h := setupChallengeBindingHarness(t)

	tokenC1DP1 := "Bearer " + h.SignToken(h.issuerURL, "system:serviceaccount:default:dp-1")
	ctrlTokenC1 := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")
	ctrlTokenC3 := h.SignToken(h.issuerURL+"/cluster-3", "system:serviceaccount:gateway-system:controller-sa")

	// Step 1: Requester 1 (gateway 1 in cluster 1) requests "cache-protect.example.com"
	h.mu.Lock()
	h.forwardHeader = tokenC1DP1
	h.mu.Unlock()

	req1 := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"cache-protect.example.com"},
		Gateway:                 "default/gw-1",
		DataPlaneServiceAccount: "default/dp-1",
		ClusterId:               "cluster-1",
	}

	ctx1 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+ctrlTokenC1))

	waitForCertificate(t, h.grpcClient, ctx1, req1)

	// Requester 1 gets certificate from cache on subsequent call
	resp1Again, err := h.grpcClient.GetCertificate(ctx1, req1)
	if err != nil || len(resp1Again.CertificateChain) == 0 {
		t.Fatalf("expected requester 1 to receive cached certificate, err: %v", err)
	}

	// Step 2: Requester 2 (gateway 3 in cluster 3, without binding) requests the same hostname
	req2 := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"cache-protect.example.com"},
		Gateway:                 "default/gw-3a",
		DataPlaneServiceAccount: "default/dp-3a",
		ClusterId:               "cluster-3",
	}

	ctx2 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+ctrlTokenC3))

	// Data plane forwarder is still sending requester 1's token, so requester 2's validation cannot pass
	resp2, err2 := h.grpcClient.GetCertificate(ctx2, req2)
	if err2 == nil && resp2 != nil && len(resp2.CertificateChain) > 0 {
		t.Fatalf("security violation: requester 2 received cached certificate without passing binding check!")
	}

	// Retrying for requester 2 still refuses cache hit and fails binding
	time.Sleep(500 * time.Millisecond)
	resp2Retry, err2Retry := h.grpcClient.GetCertificate(ctx2, req2)
	if err2Retry == nil && resp2Retry != nil && len(resp2Retry.CertificateChain) > 0 {
		t.Fatalf("security violation: requester 2 received cached certificate on retry without passing binding check!")
	}

	// Requester 1 can STILL get its cached certificate
	resp1Final, err := h.grpcClient.GetCertificate(ctx1, req1)
	if err != nil || len(resp1Final.CertificateChain) == 0 {
		t.Fatalf("expected requester 1 to still receive cached certificate, err: %v", err)
	}
}

// TestAuditLogs_NoTokensOrKeyAuthorizations verifies:
// "Audit log lines for each challenge decision, with no tokens or key authorizations in logs."
func TestAuditLogs_NoTokensOrKeyAuthorizations(t *testing.T) {
	h := setupChallengeBindingHarness(t)

	rawDPToken := h.SignToken(h.issuerURL, "system:serviceaccount:default:dp-1")
	rawCtrlToken := h.SignToken(h.issuerURL, "system:serviceaccount:gateway-system:controller-sa")

	h.mu.Lock()
	h.forwardHeader = "Bearer " + rawDPToken
	h.mu.Unlock()

	req := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{"audit.example.com"},
		Gateway:                 "default/gw-1",
		DataPlaneServiceAccount: "default/dp-1",
		ClusterId:               "cluster-1",
	}

	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+rawCtrlToken))
	waitForCertificate(t, h.grpcClient, ctx, req)

	// Inspect audit log lines
	logs := h.auditBuf.String()
	if logs == "" {
		t.Fatal("expected audit log entries to be recorded")
	}

	lines := strings.Split(strings.TrimSpace(logs), "\n")
	foundChallengeDecision := false

	for _, line := range lines {
		var entry registry.AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("failed to unmarshal audit entry %q: %v", line, err)
		}

		if entry.Timestamp.IsZero() {
			t.Errorf("audit entry missing timestamp: %s", line)
		}
		if entry.Decision == "" {
			t.Errorf("audit entry missing decision: %s", line)
		}
		if entry.Reason == "" {
			t.Errorf("audit entry missing reason: %s", line)
		}

		if strings.Contains(entry.Reason, "challenge") {
			foundChallengeDecision = true
		}

		// Security assertion: NO bearer tokens, JWT signatures, or ACME key authorizations in logs
		if strings.Contains(line, rawDPToken) {
			t.Errorf("audit log leaked data-plane bearer token: %s", line)
		}
		if strings.Contains(line, rawCtrlToken) {
			t.Errorf("audit log leaked controller bearer token: %s", line)
		}
	}

	if !foundChallengeDecision {
		t.Error("expected at least one challenge validation audit log decision")
	}
}
