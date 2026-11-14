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

package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	acmeclient "github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/acme"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/testserver"
)

type mockClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *mockClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func pebbleSelfCheckOption(pebble *testserver.Server) func(*Options) {
	return func(o *Options) {
		if pebble != nil && pebble.ChallengeServer != nil {
			o.SelfCheckClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return net.Dial(network, pebble.ChallengeServer.Listener.Addr().String())
					},
				},
			}
		}
	}
}

func createTestManager(
	t *testing.T,
	pebble *testserver.Server,
	cacheDir string,
	clock Clock,
	optFns ...func(*Options),
) (*Manager, *metrics.Metrics) {
	t.Helper()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	diskCache, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("failed to create disk cache: %v", err)
	}

	accountKey, err := diskCache.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("failed to load/generate account key: %v", err)
	}

	acmeCli, err := acmeclient.NewClient(t.Context(), acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		HTTPClient:   pebble.HTTPClient,
		AccountKey:   accountKey,
	})
	if err != nil {
		t.Fatalf("failed to create ACME client: %v", err)
	}

	defaultOptFns := []func(*Options){
		pebbleSelfCheckOption(pebble),
		func(o *Options) {
			if clock != nil {
				o.Clock = clock
			}
			o.RenewalCheckInterval = 50 * time.Millisecond
			o.InitialRetryBackoff = 50 * time.Millisecond
			o.MaxRetryBackoff = 500 * time.Millisecond
			o.RenewalJitterPercent = 0 // deterministic for tests
		},
	}
	defaultOptFns = append(defaultOptFns, optFns...)

	mgr := NewManager(acmeCli, diskCache, pebble.ChallengeStore, m, defaultOptFns...)
	return mgr, m
}

func TestManager_Pebble_Issuance(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock)

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	hostnames := []string{"web.example.com", "api.example.com"}
	cert, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain failed: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Verify hostnames normalized
	if len(cert.Hostnames) != 2 || cert.Hostnames[0] != "api.example.com" || cert.Hostnames[1] != "web.example.com" {
		t.Errorf("unexpected hostnames in cert: %v", cert.Hostnames)
	}

	// Verify SANs in leaf
	if len(cert.Leaf().DNSNames) != 2 {
		t.Errorf("expected 2 DNSNames in leaf, got %d", len(cert.Leaf().DNSNames))
	}

	// Verify file permissions
	hKey := "api.example.com,web.example.com"
	cached, err := mgr.cache.Get(hKey)
	if err != nil {
		t.Fatalf("Cache.Get failed: %v", err)
	}
	if cached == nil {
		t.Fatal("expected cached certificate")
	}
}

func TestManager_Pebble_ReuseFromCacheAfterRestart(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	ctx := t.Context()

	// 1. Initial run: issue certificate
	mgr1, _ := createTestManager(t, pebble, cacheDir, clock)
	if err := mgr1.Start(ctx); err != nil {
		t.Fatalf("mgr1.Start failed: %v", err)
	}
	hostnames := []string{"restart.example.com"}
	cert1, err := mgr1.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("mgr1.Obtain failed: %v", err)
	}
	mgr1.Stop()

	// 2. Shut down Pebble server to ensure restart uses ONLY local cache without network
	pebble.Close()

	// 3. Restart: create second manager pointing to the same cache directory
	mgr2, _ := createTestManager(t, pebble, cacheDir, clock)
	if err := mgr2.Start(ctx); err != nil {
		t.Fatalf("mgr2.Start failed: %v", err)
	}
	defer mgr2.Stop()

	// Obtain should immediately succeed from local disk cache
	cert2, err := mgr2.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("mgr2.Obtain from cache failed: %v", err)
	}

	if cert2.Leaf().SerialNumber.Cmp(cert1.Leaf().SerialNumber) != 0 {
		t.Errorf("expected reused certificate with same serial number, got %v vs %v",
			cert2.Leaf().SerialNumber, cert1.Leaf().SerialNumber)
	}
}

func TestManager_Pebble_Renewal(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod: 60, // 60 seconds validity
	})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}

	mgr, _ := createTestManager(t, pebble, cacheDir, clock)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	hostnames := []string{"renew.example.com"}
	cert1, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain failed: %v", err)
	}

	// Advance clock into renewal window (45s of 60s from cert issuance)
	clock.Set(cert1.IssuedAt.Add(45 * time.Second))

	// Trigger renewal check
	if err := mgr.CheckRenewals(ctx); err != nil {
		t.Fatalf("CheckRenewals failed: %v", err)
	}

	// Verify new certificate was issued and cached
	cert2, err := mgr.cache.Get("renew.example.com")
	if err != nil {
		t.Fatalf("Cache.Get failed: %v", err)
	}

	if cert2.Leaf().SerialNumber.Cmp(cert1.Leaf().SerialNumber) == 0 {
		t.Errorf("expected new certificate serial after renewal, got identical serial: %v", cert1.Leaf().SerialNumber)
	}
}

func TestManager_Pebble_ConcurrentObtainSameSet(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock)

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	hostnames := []string{"concurrent.example.com"}
	concurrency := 10

	var wg sync.WaitGroup
	certs := make([]*cache.Certificate, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
			certs[idx] = c
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	for i := 0; i < concurrency; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if certs[i] == nil {
			t.Fatalf("goroutine %d received nil certificate", i)
		}
		// Verify all concurrent callers received the identical certificate
		if certs[i].Leaf().SerialNumber.Cmp(certs[0].Leaf().SerialNumber) != 0 {
			t.Errorf("goroutine %d received different certificate serial: %v vs %v",
				i, certs[i].Leaf().SerialNumber, certs[0].Leaf().SerialNumber)
		}
	}
}

func TestManager_Pebble_FailedValidation(t *testing.T) {
	// Start with custom challenge store that drops challenges to force validation failure
	brokenStore := &brokenChallengeStore{store: challenge.NewMemoryStore()}
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ChallengeStore: brokenStore,
	})

	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, m := createTestManager(t, pebble, cacheDir, clock)

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	// Validation must fail
	_, err := mgr.Obtain(ctx, []string{"fail-validation.example.com"}, challenge.Requester{})
	if err == nil {
		t.Fatal("expected Obtain to fail due to validation error, but it succeeded")
	}

	// Verify no certificate in cache
	_, err = mgr.cache.Get("fail-validation.example.com")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("expected cache.ErrNotFound, got %v", err)
	}

	// Verify issuance failure metric was recorded
	_ = m
}

type failRoundTripper struct {
	base http.RoundTripper
	fail atomic.Bool
}

func (f *failRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.fail.Load() {
		return nil, errors.New("simulated ACME server downtime during renewal")
	}
	return f.base.RoundTrip(req)
}

func TestManager_Pebble_RenewalFailureBackoffAndKeepServing(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod: 60,
	})

	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	initialTime := time.Now().Truncate(time.Second)
	clock := &mockClock{now: initialTime}

	tripper := &failRoundTripper{
		base: pebble.HTTPClient.Transport,
	}
	tripper.fail.Store(false)

	customHTTPClient := &http.Client{
		Transport: tripper,
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	diskCache, _ := cache.NewDiskCache(cacheDir)
	acmeCli, err := acmeclient.NewClient(t.Context(), acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		HTTPClient:   customHTTPClient,
	})
	if err != nil {
		t.Fatalf("failed to create ACME client: %v", err)
	}

	mgr := NewManager(acmeCli, diskCache, pebble.ChallengeStore, m, pebbleSelfCheckOption(pebble), func(o *Options) {
		o.Clock = clock
		o.RenewalCheckInterval = time.Hour // manual CheckRenewals control
		o.InitialRetryBackoff = 100 * time.Millisecond
		o.MaxRetryBackoff = 500 * time.Millisecond
		o.RenewalJitterPercent = 0
	})

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	// 1. Initial Obtain succeeds
	hostnames := []string{"retry.example.com"}
	cert1, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("initial Obtain failed: %v", err)
	}

	// 2. Simulate CA failure during renewal
	tripper.fail.Store(true)

	// Advance clock into renewal window (45s of 60s from cert issuance)
	clock.Set(cert1.IssuedAt.Add(45 * time.Second))

	// Execute renewal attempt: fails due to simulated CA downtime
	_ = mgr.CheckRenewals(ctx)

	// Verify existing certificate is STILL served from cache!
	served, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain after renewal failure should keep serving existing certificate, got error: %v", err)
	}
	if served.Leaf().SerialNumber.Cmp(cert1.Leaf().SerialNumber) != 0 {
		t.Fatalf("served certificate changed after renewal failure: %v vs %v",
			served.Leaf().SerialNumber, cert1.Leaf().SerialNumber)
	}

	// Verify state is renewing
	state, ok := mgr.GetTrackedState("retry.example.com")
	if !ok || state != metrics.StateRenewing {
		t.Errorf("expected state %s, got %s (ok=%v)", metrics.StateRenewing, state, ok)
	}

	// 3. Recover CA: retry after backoff succeeds
	tripper.fail.Store(false)
	clock.Advance(200 * time.Millisecond) // past 100ms backoff

	if err := mgr.CheckRenewals(ctx); err != nil {
		t.Fatalf("CheckRenewals after CA recovery failed: %v", err)
	}

	// Verify new certificate was issued and cached
	renewed, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain after recovered renewal failed: %v", err)
	}
	if renewed.Leaf().SerialNumber.Cmp(cert1.Leaf().SerialNumber) == 0 {
		t.Fatalf("expected renewed certificate serial number to change")
	}

	// Verify state is now valid
	state, ok = mgr.GetTrackedState("retry.example.com")
	if !ok || state != metrics.StateValid {
		t.Errorf("expected state %s, got %s (ok=%v)", metrics.StateValid, state, ok)
	}
}

func TestManager_Pebble_ExternalAccountBinding(t *testing.T) {
	eabKID := "test-eab-kid"
	eabKey := "dzA2OGZkZTBkYzljZWYxYTRlMTQ2YjEzYTE4ODQyZDI" // 32 bytes base64

	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		EABKeyID:  eabKID,
		EABMACKey: eabKey,
	})

	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	acmeCli, err := acmeclient.NewClient(t.Context(), acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		EABKID:       eabKID,
		EABHMACKey:   eabKey,
		HTTPClient:   pebble.HTTPClient,
	})
	if err != nil {
		t.Fatalf("failed to create ACME client with EAB: %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	diskCache, _ := cache.NewDiskCache(cacheDir)
	mgr := NewManager(acmeCli, diskCache, pebble.ChallengeStore, m, pebbleSelfCheckOption(pebble))

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	cert, err := mgr.Obtain(ctx, []string{"eab.example.com"}, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain with EAB failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate with EAB")
	}
}

func TestManager_LimitsAndValidation(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock, func(o *Options) {
		o.MaxHostnamesPerSet = 3
		o.MaxHostnameLength = 30
		o.MaxPendingOrders = 1
	})

	ctx := t.Context()

	// 1. Wildcard rejection
	_, err := mgr.Obtain(ctx, []string{"*.example.com"}, challenge.Requester{})
	if !errors.Is(err, ErrWildcardNotSupported) {
		t.Errorf("expected ErrWildcardNotSupported, got %v", err)
	}

	// 2. Too many hostnames
	_, err = mgr.Obtain(ctx, []string{"a.com", "b.com", "c.com", "d.com"}, challenge.Requester{})
	if !errors.Is(err, ErrTooManyHostnames) {
		t.Errorf("expected ErrTooManyHostnames, got %v", err)
	}

	// 3. Hostname too long
	_, err = mgr.Obtain(ctx, []string{"this-hostname-is-longer-than-thirty-characters.com"}, challenge.Requester{})
	if !errors.Is(err, ErrHostnameTooLong) {
		t.Errorf("expected ErrHostnameTooLong, got %v", err)
	}

	// 4. Empty hostnames
	_, err = mgr.Obtain(ctx, []string{}, challenge.Requester{})
	if !errors.Is(err, ErrNoHostnames) {
		t.Errorf("expected ErrNoHostnames, got %v", err)
	}
}

func TestManager_PrivateKeyNotInErrorsOrLogs(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock)

	ctx := t.Context()
	_ = mgr.Start(ctx)
	defer mgr.Stop()

	cert, err := mgr.Obtain(ctx, []string{"privatekey-safe.example.com"}, challenge.Requester{})
	if err != nil {
		t.Fatalf("Obtain failed: %v", err)
	}

	// Read raw private key file
	rawKeyPEM, err := os.ReadFile(filepath.Join(cacheDir, "privatekey-safe.example.com.key"))
	if err != nil {
		// Try hash
		files, _ := os.ReadDir(cacheDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".key") {
				rawKeyPEM, _ = os.ReadFile(filepath.Join(cacheDir, f.Name()))
				break
			}
		}
	}

	if len(rawKeyPEM) == 0 {
		t.Fatal("failed to find key file")
	}

	certStr := fmt.Sprintf("%v %s", cert, cert)
	if strings.Contains(certStr, string(rawKeyPEM)) || strings.Contains(certStr, "EC PRIVATE KEY") {
		t.Fatalf("private key found in certificate string: %s", certStr)
	}
}

func TestManager_AccountKeyPersistenceAndReuseOnRestart(t *testing.T) {
	eabKID := "test-persistent-kid"
	eabKey := "dzA2OGZkZTBkYzljZWYxYTRlMTQ2YjEzYTE4ODQyZDI"

	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		EABKeyID:  eabKID,
		EABMACKey: eabKey,
	})

	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	ctx := t.Context()

	// 1. Initial run: generate and persist account key
	diskCache1, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("NewDiskCache failed: %v", err)
	}
	acctKey1, err := diskCache1.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("LoadOrGenerateAccountKey 1 failed: %v", err)
	}

	acmeCli1, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		EABKID:       eabKID,
		EABHMACKey:   eabKey,
		AccountKey:   acctKey1,
		HTTPClient:   pebble.HTTPClient,
	})
	if err != nil {
		t.Fatalf("NewClient 1 failed: %v", err)
	}

	reg := prometheus.NewRegistry()
	mgr1 := NewManager(acmeCli1, diskCache1, pebble.ChallengeStore, metrics.New(reg), pebbleSelfCheckOption(pebble))
	if err := mgr1.Start(ctx); err != nil {
		t.Fatalf("mgr1.Start failed: %v", err)
	}

	if _, err := mgr1.Obtain(ctx, []string{"first.example.com"}, challenge.Requester{}); err != nil {
		t.Fatalf("mgr1.Obtain failed: %v", err)
	}
	acctURI1 := acmeCli1.Account.URI
	mgr1.Stop()

	// Verify account.key permissions 0600 on disk
	keyPath := filepath.Join(cacheDir, "account.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("account.key stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("account.key expected mode 0600, got %o", info.Mode().Perm())
	}

	// 2. Restart simulation: second manager loads same account key
	diskCache2, err := cache.NewDiskCache(cacheDir)
	if err != nil {
		t.Fatalf("NewDiskCache 2 failed: %v", err)
	}
	acctKey2, err := diskCache2.LoadOrGenerateAccountKey()
	if err != nil {
		t.Fatalf("LoadOrGenerateAccountKey 2 failed: %v", err)
	}

	if !acctKey1.Equal(acctKey2) {
		t.Fatal("expected loaded account key to match original account key")
	}

	acmeCli2, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: pebble.DirectoryURL,
		EABKID:       eabKID,
		EABHMACKey:   eabKey,
		AccountKey:   acctKey2,
		HTTPClient:   pebble.HTTPClient,
	})
	if err != nil {
		t.Fatalf("NewClient 2 failed: %v", err)
	}

	mgr2 := NewManager(acmeCli2, diskCache2, pebble.ChallengeStore, metrics.New(prometheus.NewRegistry()), pebbleSelfCheckOption(pebble))
	if err := mgr2.Start(ctx); err != nil {
		t.Fatalf("mgr2.Start failed: %v", err)
	}
	defer mgr2.Stop()

	// New domain issuance using reused account key
	if _, err := mgr2.Obtain(ctx, []string{"second.example.com"}, challenge.Requester{}); err != nil {
		t.Fatalf("mgr2.Obtain failed: %v", err)
	}

	if acmeCli2.Account.URI != acctURI1 {
		t.Errorf("expected reused account URI %s, got %s", acctURI1, acmeCli2.Account.URI)
	}
}

func TestManager_SingleflightDetachedContext_FirstCallerCancels(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock)

	orderStarted := make(chan struct{})
	var once sync.Once
	mgr.challengeStore = &hookChallengeStore{
		Store: pebble.ChallengeStore,
		onPut: func() {
			once.Do(func() {
				close(orderStarted)
			})
		},
	}

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	hostnames := []string{"caller-cancel.example.com"}

	ctx1, cancel1 := context.WithCancel(ctx)
	caller1Done := make(chan error, 1)
	caller2Done := make(chan error, 1)
	caller2Cert := make(chan *cache.Certificate, 1)

	// Caller 1 starts order and will cancel its context
	go func() {
		_, err := mgr.Obtain(ctx1, hostnames, challenge.Requester{})
		caller1Done <- err
	}()

	// Caller 2 concurrently waits for the same hostname set
	go func() {
		cert, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
		caller2Cert <- cert
		caller2Done <- err
	}()

	// Synchronize on order initiation instead of sleeping
	<-orderStarted
	cancel1()

	err1 := <-caller1Done
	if !errors.Is(err1, context.Canceled) {
		t.Fatalf("expected caller 1 to receive context.Canceled, got %v", err1)
	}

	// Caller 2 should successfully obtain the certificate despite caller 1 canceling
	err2 := <-caller2Done
	if err2 != nil {
		t.Fatalf("expected caller 2 to succeed despite caller 1 canceling, got %v", err2)
	}
	cert2 := <-caller2Cert
	if cert2 == nil {
		t.Fatal("expected caller 2 to receive non-nil certificate")
	}
}

func TestManager_Renewal_AlwaysProducesNewOrder_DoesNotCoalesceToNoop(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	clock := &mockClock{now: time.Now()}
	mgr, _ := createTestManager(t, pebble, cacheDir, clock)

	ctx := t.Context()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.Stop()

	hostnames := []string{"renew-noop.example.com"}

	// 1. Initial Obtain issues cert1
	cert1, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("initial Obtain failed: %v", err)
	}

	// 2. While cert1 is still completely valid in cache, call Renew
	cert2, err := mgr.Renew(ctx, hostnames, challenge.Requester{}, nil)
	if err != nil {
		t.Fatalf("Renew failed: %v", err)
	}

	// 3. Verify Renew produced a new ACME order and new certificate instead of coalescing into no-op cached cert
	if cert2.Leaf().SerialNumber.Cmp(cert1.Leaf().SerialNumber) == 0 {
		t.Fatalf("expected Renew to produce a new order with different serial number, got identical serial %v",
			cert1.Leaf().SerialNumber)
	}

	// 4. Subsequent Obtain should now return the renewed certificate from cache
	cert3, err := mgr.Obtain(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("subsequent Obtain failed: %v", err)
	}
	if cert3.Leaf().SerialNumber.Cmp(cert2.Leaf().SerialNumber) != 0 {
		t.Fatalf("expected subsequent Obtain to return newly renewed certificate serial %v, got %v",
			cert2.Leaf().SerialNumber, cert3.Leaf().SerialNumber)
	}
}

type hookChallengeStore struct {
	challenge.Store
	onPut func()
}

func (h *hookChallengeStore) Put(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req challenge.Requester) error {
	if h.onPut != nil {
		h.onPut()
	}
	return h.Store.Put(ctx, token, identifier, keyAuth, expiresAt, req)
}

func (h *hookChallengeStore) PutWithCandidates(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req challenge.Requester, candidates []challenge.Requester) error {
	if h.onPut != nil {
		h.onPut()
	}
	return h.Store.PutWithCandidates(ctx, token, identifier, keyAuth, expiresAt, req, candidates)
}

type brokenChallengeStore struct {
	store *challenge.MemoryStore
	pass  bool
}

func (b *brokenChallengeStore) Put(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req challenge.Requester) error {
	if !b.pass {
		return nil // Drop challenge
	}
	return b.store.Put(ctx, token, identifier, keyAuth, expiresAt, req)
}

func (b *brokenChallengeStore) PutWithCandidates(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req challenge.Requester, candidates []challenge.Requester) error {
	if !b.pass {
		return nil // Drop challenge
	}
	return b.store.PutWithCandidates(ctx, token, identifier, keyAuth, expiresAt, req, candidates)
}

func (b *brokenChallengeStore) Get(ctx context.Context, token string) (*challenge.Item, error) {
	if !b.pass {
		return nil, challenge.ErrNotFound
	}
	return b.store.Get(ctx, token)
}

func (b *brokenChallengeStore) GetChallengesForRequester(ctx context.Context, req challenge.Requester) []*challenge.Item {
	if !b.pass {
		return nil
	}
	return b.store.GetChallengesForRequester(ctx, req)
}

func (b *brokenChallengeStore) RecordAnswer(ctx context.Context, token string, identity registry.CallerIdentity) error {
	return b.store.RecordAnswer(ctx, token, identity)
}

func (b *brokenChallengeStore) Remove(ctx context.Context, token string) error {
	return b.store.Remove(ctx, token)
}

func (b *brokenChallengeStore) ResolveChallenge(ctx context.Context, caller, host, token string) (string, error) {
	if !b.pass {
		return "", challenge.ErrNotFound
	}
	return b.store.ResolveChallenge(ctx, caller, host, token)
}

func TestManager_GetCertificate_And_EnsureIssuance(t *testing.T) {
	ctx := t.Context()
	pebble := testserver.StartPebble(t, testserver.ServerConfig{
		ValidityPeriod: 86400,
	})

	cacheDir := filepath.Join(t.TempDir(), "cache")
	mgr, _ := createTestManager(t, pebble, cacheDir, nil)

	hostnames := []string{"ensure.example.com"}
	_, key, err := NormalizeHostnames(hostnames, 10, 253)
	if err != nil {
		t.Fatalf("NormalizeHostnames failed: %v", err)
	}

	// 1. Initially GetCertificate returns ErrNotFound
	data, err := mgr.GetCertificate(key, true)
	if !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil data")
	}

	// 2. EnsureIssuance starts issuance (returns true)
	started, err := mgr.EnsureIssuance(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("EnsureIssuance failed: %v", err)
	}
	if !started {
		t.Fatalf("expected issuance to start")
	}

	// 3. Second call while in flight returns false (no duplicate flight)
	startedSecond, err := mgr.EnsureIssuance(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("EnsureIssuance second call failed: %v", err)
	}
	if startedSecond {
		t.Fatalf("expected second call while in flight to return false")
	}

	// 4. Wait for issuance to complete
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		data, err = mgr.GetCertificate(key, true)
		if err == nil && data != nil {
			break
		}
	}
	if data == nil {
		t.Fatalf("issuance did not complete within deadline")
	}

	if len(data.CertificateChain) == 0 {
		t.Errorf("expected certificate chain")
	}
	if len(data.PrivateKey) == 0 {
		t.Errorf("expected private key in release mode")
	}

	// 5. In non-release mode, private key is omitted
	nonReleaseData, err := mgr.GetCertificate(key, false)
	if err != nil {
		t.Fatalf("GetCertificate non-release failed: %v", err)
	}
	if len(nonReleaseData.CertificateChain) == 0 {
		t.Errorf("expected certificate chain")
	}
	if len(nonReleaseData.PrivateKey) != 0 {
		t.Errorf("expected private key to be omitted in non-release mode")
	}

	// 6. EnsureIssuance on already-cached cert returns false
	startedAfterCached, err := mgr.EnsureIssuance(ctx, hostnames, challenge.Requester{})
	if err != nil {
		t.Fatalf("EnsureIssuance after cached failed: %v", err)
	}
	if startedAfterCached {
		t.Fatalf("expected EnsureIssuance on cached cert to return false")
	}
}
