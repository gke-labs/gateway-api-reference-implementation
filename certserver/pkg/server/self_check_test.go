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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type orderedBindingStore struct {
	*registry.MemoryBindingStore
	order []registry.Binding
}

func (s *orderedBindingStore) ListBindings() []registry.Binding {
	if len(s.order) > 0 {
		return s.order
	}
	return s.MemoryBindingStore.ListBindings()
}

type trackAcceptTransport struct {
	base        http.RoundTripper
	acceptCalls atomic.Int32
}

func (t *trackAcceptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/chalZ/") {
		t.acceptCalls.Add(1)
	}
	return t.base.RoundTrip(req)
}

type selfCheckHarness struct {
	ctx              context.Context
	cancel           context.CancelFunc
	clusterID        string
	cluster2ID       string
	issuerURL        string
	issuerURL2       string
	clusterKey       *rsa.PrivateKey
	kid              string
	reg              *registry.Registry
	bindingStore     registry.BindingStore
	auditLogger      *registry.AuditLogger
	challengeStore   challenge.Store
	diskCache        *cache.DiskCache
	mgr              *manager.Manager
	srv              *Server
	client           certserverv1.CertificateServiceClient
	callCtx          context.Context
	callCtx2         context.Context
	pebble           *testserver.Server
	testServer       *httptest.Server
	testServerIP     string
	challengeSrv     *httptest.Server
	mu               sync.RWMutex
	servedChallenges map[string]string
}

type selfCheckHarnessConfig struct {
	allowedHostnames    []string
	validityPeriod      uint64
	clock               *testClock
	bindingStore        registry.BindingStore
	pebbleTransportWrap func(http.RoundTripper) http.RoundTripper
	challengeServerWrap func(http.Handler) http.Handler
	managerOptions      func(*manager.Options)
	withChallengeServer bool
	twoClusters         bool
	seededCertificates  []*cache.Certificate
	lookupIP            func(ctx context.Context, host string) ([]net.IP, error)
}

func (h *selfCheckHarness) serveChallenge(token, keyAuth string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.servedChallenges[token] = keyAuth
}

func (h *selfCheckHarness) obtainCertificate(t *testing.T, req *certserverv1.GetCertificateRequest) *certserverv1.GetCertificateResponse {
	t.Helper()
	// Wait for Pebble ACME order creation, challenge self-check, authorization
	// validation, order finalization, and certificate issuance. Under race detection
	// and parallel CI load across packages, multiple 1-second ACME client polling intervals
	// (WaitAuthorization, WaitOrder) can elapse during order fulfillment, so allow
	// 25 seconds (matching renewDeadline) for certificate issuance to complete.
	deadline := time.Now().Add(25 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := h.client.GetCertificate(h.callCtx, req)
		if err != nil {
			lastErr = err
		} else if resp != nil {
			if len(resp.CertificateChain) > 0 {
				return resp
			}
			for _, ch := range resp.Challenges {
				h.serveChallenge(ch.Token, ch.KeyAuthorization)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("timed out waiting for certificate issuance for %s (last error: %v)", req.Gateway, lastErr)
	}
	t.Fatalf("timed out waiting for certificate issuance for %s", req.Gateway)
	return nil
}

func setupSelfCheckTest(t *testing.T, cfg selfCheckHarnessConfig) *selfCheckHarness {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)

	clusterKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate cluster key: %v", err)
	}
	hash := sha256.Sum256([]byte(t.Name()))
	shortID := hex.EncodeToString(hash[:8])
	clusterID := "cluster-" + shortID
	kid := "key-" + shortID
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildTestJWKS(map[string]*rsa.PublicKey{kid: &clusterKey.PublicKey}))
	}))
	t.Cleanup(jwksServer.Close)

	issuerURL := jwksServer.URL + "/" + clusterID
	clusters := []registry.ClusterConfig{
		{
			ClusterID:                clusterID,
			IssuerURL:                issuerURL,
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "gari-controller",
			AllowedHostnames:         cfg.allowedHostnames,
		},
	}
	var cluster2ID, issuerURL2 string
	if cfg.twoClusters {
		cluster2ID = "cluster-2-" + shortID
		issuerURL2 = jwksServer.URL + "/" + cluster2ID
		clusters = append(clusters, registry.ClusterConfig{
			ClusterID:                cluster2ID,
			IssuerURL:                issuerURL2,
			JWKSURL:                  jwksServer.URL,
			ControllerNamespace:      "gateway-system",
			ControllerServiceAccount: "gari-controller",
			AllowedHostnames:         cfg.allowedHostnames,
		})
	}
	reg, err := registry.NewRegistry(clusters, registry.WithHTTPClient(jwksServer.Client()))
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	bindingStore := cfg.bindingStore
	if bindingStore == nil {
		bindingStore = registry.NewMemoryBindingStore()
	}
	auditLogger := registry.NewAuditLogger(nil)
	m := metrics.New(prometheus.NewRegistry())
	challengeStore := challenge.NewMemoryStore()

	harness := &selfCheckHarness{
		ctx:              ctx,
		cancel:           cancel,
		clusterID:        clusterID,
		cluster2ID:       cluster2ID,
		issuerURL:        issuerURL,
		issuerURL2:       issuerURL2,
		clusterKey:       clusterKey,
		kid:              kid,
		reg:              reg,
		bindingStore:     bindingStore,
		auditLogger:      auditLogger,
		challengeStore:   challengeStore,
		servedChallenges: make(map[string]string),
	}

	if cfg.withChallengeServer {
		var challengeHandler http.Handler = challenge.NewHandler(challengeStore,
			challenge.WithRegistry(reg),
			challenge.WithBindingStore(bindingStore),
			challenge.WithAuditLogger(auditLogger),
		)
		if cfg.challengeServerWrap != nil {
			challengeHandler = cfg.challengeServerWrap(challengeHandler)
		}
		harness.challengeSrv = httptest.NewServer(audit.WrapHTTP(auditLogger, challengeHandler))
		t.Cleanup(harness.challengeSrv.Close)
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		harness.mu.RLock()
		keyAuth, ok := harness.servedChallenges[token]
		harness.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keyAuth))
	}))
	t.Cleanup(testServer.Close)
	testIP := testServer.Listener.Addr().(*net.TCPAddr).IP
	harness.testServer = testServer
	harness.testServerIP = testIP.String()

	validityPeriod := cfg.validityPeriod
	if validityPeriod <= 0 {
		validityPeriod = 86400
	}
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod:   validityPeriod,
		ChallengeStore:   challengeStore,
		ChallengeHandler: testServer.Config.Handler,
	})
	harness.pebble = pebble

	cacheDir := filepath.Join(t.TempDir(), "cache")
	diskCache, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}
	harness.diskCache = diskCache

	for _, cert := range cfg.seededCertificates {
		if err := diskCache.Put(cert); err != nil {
			t.Fatalf("failed to seed cache: %v", err)
		}
	}

	accountKey, err := diskCache.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to generate account key: %v", err)
	}

	pebbleHTTPClient := pebble.HTTPClient
	if cfg.pebbleTransportWrap != nil {
		pebbleHTTPClient = &http.Client{
			Transport: cfg.pebbleTransportWrap(pebble.HTTPClient.Transport),
		}
	}

	acmeCli, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		AccountKey:   accountKey,
		HTTPClient:   pebbleHTTPClient,
	})
	if err != nil {
		t.Fatalf("failed to create acme client: %v", err)
	}

	mgr := manager.NewManager(acmeCli, diskCache, challengeStore, m, func(o *manager.Options) {
		o.BindingStore = bindingStore
		o.SelfCheckTimeout = 5 * time.Second
		o.SelfCheckInterval = 50 * time.Millisecond
		o.SelfCheckClient = &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, testServer.Listener.Addr().String())
				},
			},
		}
		if cfg.clock != nil {
			o.Clock = cfg.clock
		}
		if cfg.managerOptions != nil {
			cfg.managerOptions(o)
		}
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	t.Cleanup(func() { mgr.Stop() })
	harness.mgr = mgr

	lookupIP := cfg.lookupIP
	if lookupIP == nil {
		lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{testIP}, nil
		}
	}
	srvTLS := generateSelfSignedCert(t)
	serverOpts := Options{
		ListenAddr:  "127.0.0.1:0",
		TLSConfig:   srvTLS,
		ReleaseMode: true,
		LookupIP:    lookupIP,
	}
	srv, err := NewServer(serverOpts, reg, mgr, bindingStore, auditLogger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	harness.srv = srv

	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		t.Fatalf("failed to connect gRPC: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	harness.client = certserverv1.NewCertificateServiceClient(conn)
	token := signControllerToken(t, issuerURL, "system:serviceaccount:gateway-system:gari-controller", clusterKey, kid)
	harness.callCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if cfg.twoClusters {
		token2 := signControllerToken(t, issuerURL2, "system:serviceaccount:gateway-system:gari-controller", clusterKey, kid)
		harness.callCtx2 = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token2)
	}

	t.Cleanup(func() {
		cancel()
	})

	return harness
}

// TestPebble_ServeChallenges_SelfCheckPasses_CertificateIssued verifies that:
// GetCertificate returns pending challenges, a test HTTP server serves them,
// certserver self-check passes, and the certificate is issued.
func TestPebble_ServeChallenges_SelfCheckPasses_CertificateIssued(t *testing.T) {
	const host = "serve-test.example.com"
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames: []string{host},
	})

	req := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "default/gw-serve",
		DataPlaneServiceAccount: "default/dp-serve",
		ClusterId:               h.clusterID,
	}

	issuedCert := h.obtainCertificate(t, req)
	if len(issuedCert.CertificateChain) == 0 || len(issuedCert.PrivateKey) == 0 {
		t.Fatalf("expected non-empty certificate chain and private key")
	}

	cert, err := h.diskCache.Get(host)
	if err != nil || cert == nil {
		t.Fatalf("expected cached certificate for %s, got err: %v", host, err)
	}
}

// TestPebble_SelfCheckFails_NeverCallsAccept verifies that:
// when the challenge isn't served, the self-check fails and certserver never calls Accept.
func TestPebble_SelfCheckFails_NeverCallsAccept(t *testing.T) {
	tracker := &trackAcceptTransport{}
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames: []string{"unserved.example.com"},
		pebbleTransportWrap: func(base http.RoundTripper) http.RoundTripper {
			tracker.base = base
			return tracker
		},
		managerOptions: func(o *manager.Options) {
			o.SelfCheckTimeout = 150 * time.Millisecond
			o.SelfCheckInterval = 20 * time.Millisecond
		},
	})

	// Challenge is unserved; Obtain should fail during self-check without calling Accept
	_, err := h.mgr.Obtain(h.ctx, []string{"unserved.example.com"}, challenge.Requester{
		ClusterID:    h.clusterID,
		Gateway:      "default/gw",
		HostnamesKey: "unserved.example.com",
	})
	if err == nil {
		t.Fatalf("expected Obtain to fail when challenge is unserved, but succeeded")
	}
	if !strings.Contains(err.Error(), "self-check") {
		t.Errorf("expected self-check error, got: %v", err)
	}
	if calls := tracker.acceptCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 Accept calls to ACME challenge endpoint, got %d", calls)
	}
}

// TestPebble_RenewalDoesNotValidateUnprovedCandidate verifies that:
// Gateway A holds a certificate. Gateway B, in another namespace, calls GetCertificate
// for the same hostnames and serves nothing. A renewal for A succeeds.
// Asserts that B has no validated binding, B was never handed the renewal's challenge,
// and that B's next GetCertificate doesn't return the certificate.
func TestPebble_RenewalDoesNotValidateUnprovedCandidate(t *testing.T) {
	testPebbleRenewalUnprovedCandidate(t, false)
}

// TestPebble_RenewalDoesNotValidateUnprovedCandidate_BFirstInBindingStore verifies the same
// with Gateway B first in the binding store's iteration order.
func TestPebble_RenewalDoesNotValidateUnprovedCandidate_BFirstInBindingStore(t *testing.T) {
	testPebbleRenewalUnprovedCandidate(t, true)
}

func testPebbleRenewalUnprovedCandidate(t *testing.T, bFirst bool) {
	const host = "renew-protect.example.com"
	clock := &testClock{now: time.Now()}
	memoryStore := registry.NewMemoryBindingStore()
	bindingStore := &orderedBindingStore{MemoryBindingStore: memoryStore}

	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames: []string{host},
		validityPeriod:   60,
		clock:            clock,
		bindingStore:     bindingStore,
		managerOptions: func(o *manager.Options) {
			o.RenewalCheckInterval = 50 * time.Millisecond
			o.RenewalJitterPercent = 0
			o.SelfCheckTimeout = 5 * time.Second
			o.SelfCheckInterval = 50 * time.Millisecond
		},
	})

	reqA := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-a/gw-a",
		DataPlaneServiceAccount: "namespace-a/dp-a",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}

	// 1. Gateway A initial issuance
	h.obtainCertificate(t, reqA)
	if !h.bindingStore.HasValidatedBinding(h.clusterID, "namespace-a/gw-a", host, clock.Now()) {
		t.Fatalf("expected Gateway A to have validated binding after initial issuance")
	}

	// 2. Gateway B in another namespace calls GetCertificate for the same hostnames
	reqB := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-b/gw-b",
		DataPlaneServiceAccount: "namespace-b/dp-b",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}
	respB, err := h.client.GetCertificate(h.callCtx, reqB)
	if err != nil {
		t.Fatalf("Gateway B GetCertificate failed: %v", err)
	}
	if len(respB.CertificateChain) > 0 {
		t.Fatalf("security violation: Gateway B received certificate chain without validation")
	}

	if bFirst {
		bBinding, okB := memoryStore.GetBinding(h.clusterID, "namespace-b/gw-b")
		aBinding, okA := memoryStore.GetBinding(h.clusterID, "namespace-a/gw-a")
		if !okA || !okB {
			t.Fatalf("failed to retrieve recorded bindings for A or B: okA=%v, okB=%v", okA, okB)
		}
		bindingStore.order = []registry.Binding{bBinding, aBinding}
	}

	// 3. Trigger renewal for Gateway A
	cachedCert, err := h.diskCache.Get(host)
	if err != nil {
		t.Fatalf("failed to get cached cert: %v", err)
	}
	clock.Set(cachedCert.IssuedAt.Add(45 * time.Second))

	var (
		tokenMu      sync.Mutex
		renewalToken string
	)
	stopRenewalServe := make(chan struct{})
	defer close(stopRenewalServe)
	go func() {
		for {
			select {
			case <-stopRenewalServe:
				return
			case <-time.After(10 * time.Millisecond):
				activeChallenges := h.challengeStore.GetChallengesForRequester(h.ctx, challenge.Requester{
					ClusterID:    h.clusterID,
					Gateway:      "namespace-a/gw-a",
					HostnamesKey: host,
				})
				if len(activeChallenges) > 0 {
					tok := activeChallenges[0].Token
					tokenMu.Lock()
					if renewalToken == "" {
						renewalToken = tok
						// Pin candidate rule: verify Gateway B is not offered the renewal challenge while pending
						respBWhilePending, err := h.client.GetCertificate(h.callCtx, reqB)
						if err != nil {
							t.Errorf("Gateway B GetCertificate during renewal failed: %v", err)
						}
						for _, ch := range respBWhilePending.Challenges {
							if ch.Token == tok {
								t.Errorf("security violation (candidate rule broken): Gateway B offered renewal challenge: %s", ch.Token)
							}
						}

						bChallenges := h.challengeStore.GetChallengesForRequester(h.ctx, challenge.Requester{
							ClusterID:    h.clusterID,
							Gateway:      "namespace-b/gw-b",
							HostnamesKey: host,
						})
						for _, ch := range bChallenges {
							if ch.Token == tok {
								t.Errorf("security violation (candidate rule broken): Gateway B in challenge store has renewal challenge: %s", ch.Token)
							}
						}
					}
					tokenMu.Unlock()

					for _, ch := range activeChallenges {
						h.serveChallenge(ch.Token, ch.KeyAuth)
					}
				}
			}
		}
	}()

	if err := h.mgr.CheckRenewals(h.ctx); err != nil {
		t.Fatalf("CheckRenewals failed: %v", err)
	}

	// Wait for renewed certificate to be stored in cache
	renewDeadline := time.Now().Add(25 * time.Second)
	var renewedCert *cache.Certificate
	for time.Now().Before(renewDeadline) {
		curr, err := h.diskCache.Get(host)
		if err == nil && curr != nil && !curr.IssuedAt.Equal(cachedCert.IssuedAt) {
			renewedCert = curr
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if renewedCert == nil {
		t.Fatalf("timed out waiting for renewed certificate in cache")
	}

	tokenMu.Lock()
	tok := renewalToken
	tokenMu.Unlock()
	if tok == "" {
		t.Fatalf("expected renewal challenge token to be generated")
	}

	// 4. Assert that Gateway B has NO validated binding
	now := clock.Now()
	if h.bindingStore.HasValidatedBinding(h.clusterID, "namespace-b/gw-b", host, now) {
		t.Fatalf("security violation: Gateway B gained a validated binding during Gateway A's renewal!")
	}

	// 5. Assert that Gateway B's next GetCertificate does NOT return the certificate
	respBNext, err := h.client.GetCertificate(h.callCtx, reqB)
	if err != nil {
		t.Fatalf("Gateway B next GetCertificate failed: %v", err)
	}
	if len(respBNext.CertificateChain) > 0 {
		t.Fatalf("security violation: Gateway B received cached certificate without proving domain control!")
	}
	for _, ch := range respBNext.Challenges {
		if ch.Token == renewalToken {
			t.Fatalf("security violation: Gateway B next GetCertificate received renewal challenge %s", ch.Token)
		}
	}

	// 6. Confirm Gateway A can still retrieve the certificate
	respANext, err := h.client.GetCertificate(h.callCtx, reqA)
	if err != nil {
		t.Fatalf("Gateway A next GetCertificate failed: %v", err)
	}
	if len(respANext.CertificateChain) == 0 {
		t.Fatalf("expected Gateway A to retrieve renewed certificate, got empty chain")
	}
}

// TestChallengeEndpoint_DoesNotValidateGatewayBinding verifies that:
// Gateway A holds a certificate, and HTTP for the hostname reaches only A.
// Gateway B calls GetCertificate and receives its pending challenge.
// A request with B's data-plane identity and that token goes to the challenge endpoint.
// B's next GetCertificate returns no certificate.
func TestChallengeEndpoint_DoesNotValidateGatewayBinding(t *testing.T) {
	const host = "endpoint-protect.example.com"
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames:    []string{host},
		withChallengeServer: true,
		managerOptions: func(o *manager.Options) {
			o.SelfCheckTimeout = 1 * time.Second
			o.SelfCheckInterval = 50 * time.Millisecond
		},
	})

	reqA := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-a/gw-a",
		DataPlaneServiceAccount: "namespace-a/dp-sa-a",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}

	// 1. Gateway A initial issuance
	h.obtainCertificate(t, reqA)
	if !h.bindingStore.HasValidatedBinding(h.clusterID, "namespace-a/gw-a", host, time.Now()) {
		t.Fatalf("expected Gateway A to have validated binding after initial issuance")
	}

	// 2. Gateway B in another namespace calls GetCertificate and receives its pending challenge
	reqB := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-b/gw-b",
		DataPlaneServiceAccount: "namespace-b/dp-sa-b",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}
	var challengeTokenB string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		respB, err := h.client.GetCertificate(h.callCtx, reqB)
		if err != nil {
			t.Fatalf("Gateway B GetCertificate failed: %v", err)
		}
		if len(respB.CertificateChain) > 0 {
			t.Fatalf("security violation: Gateway B received certificate chain without validation")
		}
		if len(respB.Challenges) > 0 {
			challengeTokenB = respB.Challenges[0].Token
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if challengeTokenB == "" {
		t.Fatalf("expected Gateway B to receive a pending challenge")
	}

	// 3. A request with B's data-plane identity and that token goes to the challenge endpoint
	dpTokenB := signControllerToken(t, h.issuerURL, "system:serviceaccount:namespace-b:dp-sa-b", h.clusterKey, h.kid)
	fwdReq, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.challengeSrv.URL+"/.well-known/acme-challenge/"+challengeTokenB, nil)
	if err != nil {
		t.Fatalf("failed to create forwarder request: %v", err)
	}
	fwdReq.Host = host
	fwdReq.Header.Set("Authorization", "Bearer "+dpTokenB)

	resp, err := http.DefaultClient.Do(fwdReq)
	if err != nil {
		t.Fatalf("challenge endpoint request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from challenge endpoint, got %d", resp.StatusCode)
	}

	// 4. Assert that B has no validated binding
	if h.bindingStore.HasValidatedBinding(h.clusterID, "namespace-b/gw-b", host, time.Now()) {
		t.Fatalf("security violation: challenge endpoint must not record a validated binding for Gateway B")
	}

	// 5. B's next GetCertificate returns no certificate
	respBNext, err := h.client.GetCertificate(h.callCtx, reqB)
	if err != nil {
		t.Fatalf("Gateway B next GetCertificate failed: %v", err)
	}
	if len(respBNext.CertificateChain) > 0 {
		t.Fatalf("security violation: Gateway B next GetCertificate returned cached certificate after challenge endpoint call!")
	}
}

// TestPebble_RenewalDoesNotRefreshCandidateValidatedBinding verifies that:
// Gateway B holds a validated binding that is still valid when renewal runs for Gateway A,
// so B is a candidate on renewal. After Gateway A serves and the renewal succeeds,
// Gateway B's validated binding has the exact same ExpiresAt as before.
func TestPebble_RenewalDoesNotRefreshCandidateValidatedBinding(t *testing.T) {
	const host = "candidate-refresh.example.com"
	clock := &testClock{now: time.Now()}
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames: []string{host},
		validityPeriod:   60,
		clock:            clock,
		managerOptions: func(o *manager.Options) {
			o.RenewalCheckInterval = 50 * time.Millisecond
			o.RenewalJitterPercent = 0
			o.SelfCheckTimeout = 5 * time.Second
			o.SelfCheckInterval = 50 * time.Millisecond
		},
	})

	reqA := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-a/gw-a",
		DataPlaneServiceAccount: "namespace-a/dp-a",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}

	// 1. Gateway A initial issuance
	h.obtainCertificate(t, reqA)

	// 2. Give Gateway B a validated binding that is still valid when renewal runs
	bInitialExpiresAt := clock.Now().Add(10 * time.Hour)
	h.bindingStore.RecordValidatedBinding(registry.ValidatedBinding{
		ClusterID:    h.clusterID,
		Gateway:      "namespace-b/gw-b",
		HostnamesKey: host,
		ValidatedAt:  clock.Now(),
		ExpiresAt:    bInitialExpiresAt,
	})
	h.bindingStore.RecordBinding(registry.Binding{
		ClusterID:               h.clusterID,
		Gateway:                 "namespace-b/gw-b",
		DataPlaneServiceAccount: "namespace-b/dp-b",
		Hostnames:               []string{host},
	})

	// 3. Trigger renewal for Gateway A
	cachedCert, err := h.diskCache.Get(host)
	if err != nil {
		t.Fatalf("failed to get cached cert: %v", err)
	}
	clock.Set(cachedCert.IssuedAt.Add(45 * time.Second))

	stopRenewalServe := make(chan struct{})
	defer close(stopRenewalServe)
	go func() {
		for {
			select {
			case <-stopRenewalServe:
				return
			case <-time.After(10 * time.Millisecond):
				activeChallenges := h.challengeStore.GetChallengesForRequester(h.ctx, challenge.Requester{
					ClusterID:    h.clusterID,
					Gateway:      "namespace-a/gw-a",
					HostnamesKey: host,
				})
				for _, ch := range activeChallenges {
					h.serveChallenge(ch.Token, ch.KeyAuth)
				}
				resp, _ := h.client.GetCertificate(h.callCtx, reqA)
				if resp != nil {
					for _, ch := range resp.Challenges {
						h.serveChallenge(ch.Token, ch.KeyAuthorization)
					}
				}
			}
		}
	}()

	if err := h.mgr.CheckRenewals(h.ctx); err != nil {
		t.Fatalf("CheckRenewals failed: %v", err)
	}

	// Wait for renewed certificate in cache
	renewDeadline := time.Now().Add(10 * time.Second)
	var renewedCert *cache.Certificate
	for time.Now().Before(renewDeadline) {
		curr, err := h.diskCache.Get(host)
		if err == nil && curr != nil && !curr.IssuedAt.Equal(cachedCert.IssuedAt) {
			renewedCert = curr
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if renewedCert == nil {
		t.Fatalf("timed out waiting for renewed certificate in cache")
	}

	// 4. Pin the no-record rule: assert that Gateway B's binding has the same ExpiresAt as before
	bBindingAfter, ok := h.bindingStore.GetValidatedBinding(h.clusterID, "namespace-b/gw-b", host)
	if !ok {
		t.Fatalf("expected Gateway B validated binding to exist")
	}
	if !bBindingAfter.ExpiresAt.Equal(bInitialExpiresAt) {
		t.Fatalf("security violation (no-record rule broken): Gateway B validated binding ExpiresAt was modified from %v to %v during Gateway A's renewal", bInitialExpiresAt, bBindingAfter.ExpiresAt)
	}
}

// TestPebble_RenewalWithValidatedBinding_ReturnsChallenges_CompletesWithoutForwardingEndpoint verifies that:
// A renewal for a Gateway with a validated binding receives pending challenges alongside the cached
// certificate on GetCertificate, serves them directly on its data plane, and completes renewal
// with the old forwarding endpoint unused.
func TestPebble_RenewalWithValidatedBinding_ReturnsChallenges_CompletesWithoutForwardingEndpoint(t *testing.T) {
	const host = "renew-direct-serve.example.com"
	clock := &testClock{now: time.Now()}

	var forwardingCalls atomic.Int32
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{
		allowedHostnames:    []string{host},
		validityPeriod:      60,
		clock:               clock,
		withChallengeServer: true,
		challengeServerWrap: func(base http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwardingCalls.Add(1)
				base.ServeHTTP(w, r)
			})
		},
		managerOptions: func(o *manager.Options) {
			o.RenewalCheckInterval = 50 * time.Millisecond
			o.RenewalJitterPercent = 0
			o.SelfCheckTimeout = 5 * time.Second
			o.SelfCheckInterval = 50 * time.Millisecond
		},
	})

	reqA := &certserverv1.GetCertificateRequest{
		Hostnames:               []string{host},
		Gateway:                 "namespace-a/gw-a",
		DataPlaneServiceAccount: "namespace-a/dp-a",
		ClusterId:               h.clusterID,
		Addresses:               []string{h.testServerIP},
	}

	// 1. Gateway A initial issuance
	h.obtainCertificate(t, reqA)
	if !h.bindingStore.HasValidatedBinding(h.clusterID, "namespace-a/gw-a", host, clock.Now()) {
		t.Fatalf("expected Gateway A to have validated binding after initial issuance")
	}

	// 2. Trigger renewal for Gateway A
	cachedCert, err := h.diskCache.Get(host)
	if err != nil {
		t.Fatalf("failed to get cached cert: %v", err)
	}
	clock.Set(cachedCert.IssuedAt.Add(45 * time.Second))

	// Reset forwardingCalls counter to ensure we track calls during renewal
	forwardingCalls.Store(0)

	// In the background, Gateway A polls GetCertificate. It should receive pending challenges
	// alongside the cached certificate, and serve them on its simulated data plane (testServer).
	stopServe := make(chan struct{})
	defer close(stopServe)
	var receivedRenewalChallenges atomic.Bool
	go func() {
		for {
			select {
			case <-stopServe:
				return
			case <-time.After(20 * time.Millisecond):
				resp, err := h.client.GetCertificate(h.callCtx, reqA)
				if err == nil && resp != nil {
					// Gateway A has a validated binding, so CertificateChain is returned
					if len(resp.CertificateChain) > 0 && len(resp.Challenges) > 0 {
						receivedRenewalChallenges.Store(true)
						for _, ch := range resp.Challenges {
							h.serveChallenge(ch.Token, ch.KeyAuthorization)
						}
					}
				}
			}
		}
	}()

	if err := h.mgr.CheckRenewals(h.ctx); err != nil {
		t.Fatalf("CheckRenewals failed: %v", err)
	}

	// Wait for renewed certificate to be stored in cache
	renewDeadline := time.Now().Add(10 * time.Second)
	var renewedCert *cache.Certificate
	for time.Now().Before(renewDeadline) {
		curr, err := h.diskCache.Get(host)
		if err == nil && curr != nil && !curr.IssuedAt.Equal(cachedCert.IssuedAt) {
			renewedCert = curr
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if renewedCert == nil {
		t.Fatalf("timed out waiting for renewed certificate in cache")
	}

	if !receivedRenewalChallenges.Load() {
		t.Fatalf("expected Gateway A to receive renewal challenges alongside cached certificate")
	}

	// Confirm that the old forwarding endpoint remained unused during renewal
	if calls := forwardingCalls.Load(); calls != 0 {
		t.Fatalf("expected old forwarding endpoint to be unused during renewal, got %d calls", calls)
	}
}
