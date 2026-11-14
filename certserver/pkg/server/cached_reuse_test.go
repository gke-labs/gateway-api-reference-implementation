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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/manager"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

func createTestReuseCert(t *testing.T, hostname string) *cache.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{hostname},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return cache.NewCertificate([]string{hostname}, hostname, certPEM, keyPEM, leaf, time.Now(), time.Now().Add(24*time.Hour))
}

// TestPebble_CachedCertificateReuse_ValidatedViaLocalProbe_NoACMEOrder verifies that:
//   - Two clusters request the same hostname.
//   - The second cluster gets the cached certificate only after a self-check that reaches
//     the data plane which public DNS (faked in the test) points at and that serves its probe token.
//   - No ACME order is created for cache reuse, asserting on Pebble's order count.
func TestPebble_CachedCertificateReuse_ValidatedViaLocalProbe_NoACMEOrder(t *testing.T) {
	const testHost = "reuse.example.com"
	var currentDNS atomic.Pointer[net.TCPAddr]

	// Simulated data plane for cluster 2
	dp2Challenges := make(map[string]string)
	var dp2Mu sync.RWMutex
	dp2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		tok := strings.TrimPrefix(r.URL.Path, prefix)
		dp2Mu.RLock()
		keyAuth, ok := dp2Challenges[tok]
		dp2Mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keyAuth))
	}))
	t.Cleanup(dp2Server.Close)

	dp2Addr := dp2Server.Listener.Addr().(*net.TCPAddr)

	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames: []string{testHost},
		twoClusters:      true,
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			target := currentDNS.Load()
			if target == nil {
				return nil, fmt.Errorf("no DNS answer for %s", host)
			}
			return []net.IP{target.IP}, nil
		},
		managerOptions: func(o *manager.Options) {
			o.SelfCheckClient = &http.Client{
				Transport: &http.Transport{
					DisableKeepAlives: true,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						target := currentDNS.Load()
						if target == nil {
							return nil, fmt.Errorf("DNS resolution failed for %s", addr)
						}
						return (&net.Dialer{}).DialContext(ctx, "tcp", target.String())
					},
				},
			}
		},
	})

	dp1Addr := h.testServer.Listener.Addr().(*net.TCPAddr)
	currentDNS.Store(dp1Addr)

	// Step A: Cluster 1 requests "reuse.example.com"
	req1 := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{testHost},
		Gateway:                 "default/gw-1",
		DataPlaneServiceAccount: "default/dp-1",
		ClusterId:               h.clusterID,
		Addresses:               []string{dp1Addr.IP.String()},
	}

	issued := h.obtainCertificate(t, req1)
	if len(issued.CertificateChain) == 0 {
		t.Fatal("expected cluster 1 to successfully receive certificate")
	}

	if initialOrders := h.pebble.OrderCount(); initialOrders != 1 {
		t.Fatalf("expected 1 ACME order on initial issuance, got %d", initialOrders)
	}

	// Step B: Cluster 2 requests the same hostname
	currentDNS.Store(dp2Addr)

	req2 := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{testHost},
		Gateway:                 "default/gw-2",
		DataPlaneServiceAccount: "default/dp-2",
		ClusterId:               h.cluster2ID,
		Addresses:               []string{dp2Addr.IP.String()},
	}

	resp2Initial, err := h.client.GetCertificate(h.callCtx2, req2)
	if err != nil {
		t.Fatalf("GetCertificate for cluster 2 failed: %v", err)
	}
	if len(resp2Initial.CertificateChain) > 0 {
		t.Fatal("security violation: cluster 2 received certificate without validated binding")
	}
	if len(resp2Initial.Challenges) == 0 {
		t.Fatal("expected pending probe challenge in response for cluster 2")
	}

	// Configure cluster 2 data plane to serve probe challenge
	dp2Mu.Lock()
	for _, ch := range resp2Initial.Challenges {
		dp2Challenges[ch.Token] = ch.KeyAuthorization
	}
	dp2Mu.Unlock()

	// Poll until self-check passes and cached cert is released
	waitForCertificate(t, h.client, h.callCtx2, req2)

	if finalOrders := h.pebble.OrderCount(); finalOrders != 1 {
		t.Fatalf("expected Pebble order count to remain 1 (no ACME order for cache reuse), got %d", finalOrders)
	}
}

// TestPebble_CachedCertificateReuse_DirectFetchDoesNotRecordBinding verifies that:
//   - A data plane fetching the token directly from certserver records no validated binding,
//     and GetCertificate does not release the cached certificate.
func TestPebble_CachedCertificateReuse_DirectFetchDoesNotRecordBinding(t *testing.T) {
	const testHost = "direct-fetch.example.com"
	testCert := createTestReuseCert(t, testHost)

	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames:    []string{testHost},
		twoClusters:         true,
		withChallengeServer: true,
		seededCertificates:  []*cache.Certificate{testCert},
		managerOptions: func(o *manager.Options) {
			o.SelfCheckClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return nil, fmt.Errorf("connection refused")
					},
				},
			}
		},
	})

	// Step 1: Cluster 2 requests certificate, receiving probe challenge
	req2 := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{testHost},
		Gateway:                 "default/gw-2",
		DataPlaneServiceAccount: "default/dp-2",
		ClusterId:               h.cluster2ID,
		Addresses:               []string{h.testServerIP},
	}

	resp, err := h.client.GetCertificate(h.callCtx2, req2)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if len(resp.Challenges) == 0 {
		t.Fatal("expected probe challenge in response")
	}
	probeToken := resp.Challenges[0].Token

	// Step 2: Cluster 2 data plane fetches token directly from certserver challenge endpoint
	dpToken := signControllerToken(t, h.issuerURL2, "system:serviceaccount:default:dp-2", h.clusterKey, h.kid)
	httpReq, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.challengeSrv.URL+"/.well-known/acme-challenge/"+probeToken, nil)
	if err != nil {
		t.Fatalf("creating HTTP request: %v", err)
	}
	httpReq.Host = testHost
	httpReq.Header.Set("Authorization", "Bearer "+dpToken)

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("fetching challenge: %v", err)
	}
	defer httpResp.Body.Close()

	// Assert no validated binding is recorded in binding store
	if h.bindingStore.HasValidatedBinding(h.cluster2ID, "default/gw-2", testHost, time.Now()) {
		t.Fatal("security violation: fetching challenge directly from certserver recorded a validated binding")
	}

	// Step 3: Subsequent GetCertificate does not release the cached certificate
	retryResp, err := h.client.GetCertificate(h.callCtx2, req2)
	if err != nil {
		t.Fatalf("retry GetCertificate failed: %v", err)
	}
	if len(retryResp.CertificateChain) > 0 {
		t.Fatal("security violation: GetCertificate released certificate without validated binding")
	}
}

// TestServer_AddressCheckRejectsUnmatchedDNSAnswer verifies that:
//   - The address check rejects a hostname whose DNS answer isn't among the attested addresses.
func TestServer_AddressCheckRejectsUnmatchedDNSAnswer(t *testing.T) {
	const testHost = "addr-check.example.com"
	testCert := createTestReuseCert(t, testHost)
	dnsIP := net.ParseIP("192.0.2.1")

	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames:   []string{testHost},
		seededCertificates: []*cache.Certificate{testCert},
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{dnsIP}, nil
		},
	})

	t.Run("RejectsUnmatchedAddress", func(t *testing.T) {
		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{testHost},
			Gateway:                 "default/gw-test",
			DataPlaneServiceAccount: "default/dp-test",
			ClusterId:               h.clusterID,
			Addresses:               []string{"198.51.100.99"},
		}

		_, err := h.client.GetCertificate(h.callCtx, req)
		if err == nil {
			t.Fatal("expected GetCertificate to fail when DNS answer does not match attested addresses")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected codes.FailedPrecondition, got code %v, err: %v", st.Code(), err)
		}
		if !strings.Contains(st.Message(), "address check failed") {
			t.Errorf("expected error message to mention 'address check failed', got: %v", st.Message())
		}
		if _, ok := h.bindingStore.GetBinding(h.clusterID, "default/gw-test"); ok {
			t.Fatal("request failing address check must leave no binding behind")
		}
	})

	t.Run("RejectsEmptyAttestedAddresses", func(t *testing.T) {
		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{testHost},
			Gateway:                 "default/gw-test",
			DataPlaneServiceAccount: "default/dp-test",
			ClusterId:               h.clusterID,
			Addresses:               nil,
		}

		_, err := h.client.GetCertificate(h.callCtx, req)
		if err == nil {
			t.Fatal("expected GetCertificate to fail when no attested addresses are provided")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected codes.FailedPrecondition, got code %v, err: %v", st.Code(), err)
		}
	})

	t.Run("RejectsExcessiveAttestedAddresses", func(t *testing.T) {
		tooMany := make([]string, maxAttestedAddresses+1)
		for i := range tooMany {
			tooMany[i] = "192.0.2.1"
		}
		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{testHost},
			Gateway:                 "default/gw-test",
			DataPlaneServiceAccount: "default/dp-test",
			ClusterId:               h.clusterID,
			Addresses:               tooMany,
		}

		_, err := h.client.GetCertificate(h.callCtx, req)
		if err == nil {
			t.Fatal("expected GetCertificate to fail when address count exceeds limit")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected codes.FailedPrecondition, got code %v, err: %v", st.Code(), err)
		}
	})

	t.Run("AcceptsMatchingAddress", func(t *testing.T) {
		req := &certserverv1.GetCertificateRequest{
			Hostnames:               []string{testHost},
			Gateway:                 "default/gw-test",
			DataPlaneServiceAccount: "default/dp-test",
			ClusterId:               h.clusterID,
			Addresses:               []string{"192.0.2.1", "10.0.0.1"},
		}

		resp, err := h.client.GetCertificate(h.callCtx, req)
		if err != nil {
			t.Fatalf("expected GetCertificate to pass address check, got error: %v", err)
		}
		if len(resp.Challenges) == 0 {
			t.Fatal("expected probe challenge in response when address check passes")
		}
	})
}

// TestManager_FailedProbeCooldown verifies that after a failed probe self-check,
// a short cooldown interval suppresses immediate retries for the same requester and hostnames.
func TestManager_FailedProbeCooldown(t *testing.T) {
	clock := &testClock{now: time.Now()}
	challengeStore := challenge.NewMemoryStore()
	bindingStore := registry.NewMemoryBindingStore()
	m := metrics.New(prometheus.NewRegistry())

	cacheDir := filepath.Join(t.TempDir(), "cache")
	diskCache, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}

	mgr := manager.NewManager(nil, diskCache, challengeStore, m, func(o *manager.Options) {
		o.Clock = clock
		o.BindingStore = bindingStore
		o.SelfCheckTimeout = 100 * time.Millisecond
		o.SelfCheckInterval = 20 * time.Millisecond
		o.SelfCheckClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return nil, fmt.Errorf("connection refused")
				},
			},
		}
	})
	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	defer mgr.Stop()

	requester := challenge.Requester{
		ClusterID:    "cluster-1",
		Gateway:      "default/gw-1",
		HostnamesKey: "cooldown.example.com",
	}

	// 1. Initial revalidation attempt starts
	started, err := mgr.EnsureRevalidation(ctx, []string{"cooldown.example.com"}, requester)
	if err != nil || !started {
		t.Fatalf("expected first EnsureRevalidation to start, got started=%v, err=%v", started, err)
	}

	// Wait for the background probe self-check to fail and cooldown to be recorded
	time.Sleep(300 * time.Millisecond)

	// 2. Immediate second call should be suppressed by cooldown
	started2, err := mgr.EnsureRevalidation(ctx, []string{"cooldown.example.com"}, requester)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if started2 {
		t.Fatal("expected EnsureRevalidation during cooldown to be suppressed, but it started")
	}

	if count := mgr.FailedRevalidationsCount(); count != 1 {
		t.Fatalf("expected 1 active failedRevalidation entry during cooldown, got %d", count)
	}

	// 3. Advance clock past FailedProbeCooldown
	clock.Advance(manager.FailedProbeCooldown + time.Second)

	// 4. Verify that the map is empty after the wait passes and renewal check prunes it
	if err := mgr.CheckRenewals(ctx); err != nil {
		t.Fatalf("CheckRenewals failed: %v", err)
	}
	if count := mgr.FailedRevalidationsCount(); count != 0 {
		t.Fatalf("expected failedRevalidations map to be empty after wait passes, got %d", count)
	}

	// 5. Retry after cooldown should start a new probe
	started3, err := mgr.EnsureRevalidation(ctx, []string{"cooldown.example.com"}, requester)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !started3 {
		t.Fatal("expected EnsureRevalidation after cooldown to start a new probe")
	}
}
