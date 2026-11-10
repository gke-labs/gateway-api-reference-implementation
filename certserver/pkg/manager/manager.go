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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/sync/singleflight"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	acmeclient "github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/acme"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
)

var (
	// ErrTooManyPendingOrders is returned when the number of concurrent pending orders exceeds the configured cap.
	ErrTooManyPendingOrders = errors.New("maximum number of pending ACME orders reached")
)

// Manager coordinates certificate issuance, caching, and background renewals.
type Manager struct {
	client         *acmeclient.Client
	cache          *cache.DiskCache
	challengeStore challenge.Store
	metrics        *metrics.Metrics
	opts           Options

	obtainSf      singleflight.Group
	renewSf       singleflight.Group
	pendingOrders atomic.Int64

	// mu guards renewals map and metrics updates.
	mu       sync.RWMutex
	renewals map[string]*renewalItem

	// inFlightMu guards inFlightIssuances.
	inFlightMu        sync.Mutex
	inFlightIssuances map[string]struct{}

	cancelLoop context.CancelFunc
	loopWg     sync.WaitGroup
}

// NewManager creates a new certificate Manager.
func NewManager(
	client *acmeclient.Client,
	diskCache *cache.DiskCache,
	challengeStore challenge.Store,
	m *metrics.Metrics,
	optFns ...func(*Options),
) *Manager {
	opts := DefaultOptions()
	for _, fn := range optFns {
		fn(&opts)
	}

	return &Manager{
		client:            client,
		cache:             diskCache,
		challengeStore:    challengeStore,
		metrics:           m,
		opts:              opts,
		renewals:          make(map[string]*renewalItem),
		inFlightIssuances: make(map[string]struct{}),
	}
}

// Start loads certificates from disk cache, initializes renewal tracking, and starts the background renewal loop.
func (m *Manager) Start(ctx context.Context) error {
	if err := m.cache.Load(); err != nil {
		return fmt.Errorf("failed to load certificates from cache: %w", err)
	}

	m.mu.Lock()
	now := m.opts.Clock.Now()
	for _, cert := range m.cache.List() {
		m.trackCertificateLocked(cert, now)
	}
	m.mu.Unlock()

	loopCtx, cancel := context.WithCancel(ctx)
	m.cancelLoop = cancel

	m.loopWg.Add(1)
	go m.runRenewalLoop(loopCtx)

	return nil
}

// Stop terminates the background renewal loop and waits for it to exit.
func (m *Manager) Stop() {
	if m.cancelLoop != nil {
		m.cancelLoop()
	}
	m.loopWg.Wait()
}

// CertificateData contains the certificate chain and, in release mode, the private key.
type CertificateData struct {
	CertificateChain []byte
	PrivateKey       []byte
}

// GetCertificate returns cached certificate data for the given hostname set if present
// and not expired. In release mode, the private key is included; otherwise it is omitted.
// Returns cache.ErrNotFound if no valid cached certificate exists.
func (m *Manager) GetCertificate(hostnamesKey string, releaseMode bool) (*CertificateData, error) {
	cachedCert, err := m.cache.Get(hostnamesKey)
	if err != nil {
		return nil, err
	}
	if cachedCert == nil || cachedCert.IsExpired(m.opts.Clock.Now()) {
		return nil, cache.ErrNotFound
	}

	data := &CertificateData{
		CertificateChain: cachedCert.CertPEM,
	}
	if releaseMode {
		data.PrivateKey = cachedCert.KeyPEM
	}
	return data, nil
}

// GetPendingChallenges returns any active HTTP-01 challenges matching the given requester.
func (m *Manager) GetPendingChallenges(ctx context.Context, req challenge.Requester) []*certserverv1.HTTP01Challenge {
	if m.challengeStore == nil {
		return nil
	}
	items := m.challengeStore.GetChallengesForRequester(ctx, req)
	if len(items) == 0 {
		return nil
	}
	challenges := make([]*certserverv1.HTTP01Challenge, len(items))
	for i, item := range items {
		challenges[i] = &certserverv1.HTTP01Challenge{
			Hostname:         item.Identifier,
			Token:            item.Token,
			KeyAuthorization: item.KeyAuth,
		}
	}
	return challenges
}

// EnsureIssuance starts asynchronous certificate issuance for the given hostnames
// if no issuance is already in flight for that hostname set.
// It uses a detached context (via context.WithoutCancel) with a 10-minute timeout.
// Returns true if a new issuance was started, false if an issuance is already in flight.
func (m *Manager) EnsureIssuance(ctx context.Context, hostnames []string, requester challenge.Requester) (bool, error) {
	normalized, hostnamesKey, err := NormalizeHostnames(hostnames, m.opts.MaxHostnamesPerSet, m.opts.MaxHostnameLength)
	if err != nil {
		return false, err
	}
	requester.HostnamesKey = hostnamesKey

	now := m.opts.Clock.Now()
	// If already in cache and not expired (and requester has validated binding or no requester was given), no need to issue
	if existing, err := m.cache.Get(hostnamesKey); err == nil && existing != nil && !existing.IsExpired(now) {
		if requester.ClusterID == "" || m.opts.BindingStore == nil || m.opts.BindingStore.HasValidatedBinding(requester.ClusterID, requester.Gateway, hostnamesKey, now) {
			return false, nil
		}
	}

	m.inFlightMu.Lock()
	if _, inFlight := m.inFlightIssuances[hostnamesKey]; inFlight {
		m.inFlightMu.Unlock()
		return false, nil
	}
	m.inFlightIssuances[hostnamesKey] = struct{}{}
	m.inFlightMu.Unlock()

	detachedCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	go func() {
		defer cancel()
		defer func() {
			m.inFlightMu.Lock()
			delete(m.inFlightIssuances, hostnamesKey)
			m.inFlightMu.Unlock()
		}()

		if _, err := m.Obtain(detachedCtx, normalized, requester); err != nil {
			log.Printf("certserver: async issuance failed for %s: %v", hostnamesKey, err)
		}
	}()

	return true, nil
}

// EnsureRevalidation starts asynchronous certificate revalidation for the given hostnames and requester
// if no revalidation is already in flight for that requester and hostname set.
// It creates an ACME order to revalidate domain control without issuing a new certificate.
func (m *Manager) EnsureRevalidation(ctx context.Context, hostnames []string, requester challenge.Requester) (bool, error) {
	normalized, hostnamesKey, err := NormalizeHostnames(hostnames, m.opts.MaxHostnamesPerSet, m.opts.MaxHostnameLength)
	if err != nil {
		return false, err
	}
	requester.HostnamesKey = hostnamesKey

	revalKey := fmt.Sprintf("%s/%s/%s", hostnamesKey, requester.ClusterID, requester.Gateway)

	m.inFlightMu.Lock()
	if _, inFlight := m.inFlightIssuances[revalKey]; inFlight {
		m.inFlightMu.Unlock()
		return false, nil
	}
	m.inFlightIssuances[revalKey] = struct{}{}
	m.inFlightMu.Unlock()

	detachedCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	go func() {
		defer cancel()
		defer func() {
			m.inFlightMu.Lock()
			delete(m.inFlightIssuances, revalKey)
			m.inFlightMu.Unlock()
		}()

		if err := m.revalidateControl(detachedCtx, normalized, hostnamesKey, requester); err != nil {
			log.Printf("certserver: async revalidation failed for %s (requester %s/%s): %v",
				hostnamesKey, requester.ClusterID, requester.Gateway, err)
		}
	}()

	return true, nil
}

// revalidateControl creates an ACME order solely to prove domain control for the requester,
// fulfilling authorizations through challenge binding and then deactivating them without finalizing the order.
func (m *Manager) revalidateControl(ctx context.Context, normalized []string, hostnamesKey string, req challenge.Requester) error {
	// Ensure ACME account is registered
	if _, err := m.client.EnsureAccount(ctx); err != nil {
		return fmt.Errorf("failed to ensure ACME account: %w", err)
	}

	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(normalized...))
	if err != nil {
		return fmt.Errorf("failed to authorize ACME order for revalidation: %w", err)
	}

	// Always deactivate authorizations without finalizing the order
	defer func() {
		for _, authzURL := range order.AuthzURLs {
			if revokeErr := m.client.RevokeAuthorization(context.WithoutCancel(ctx), authzURL); revokeErr != nil {
				log.Printf("certserver: failed to revoke authorization %s: %v", authzURL, revokeErr)
			}
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		if err := m.fulfillAuthorization(ctx, authzURL, req, nil); err != nil {
			return err
		}
	}

	return nil
}

// Obtain creates or reuses a certificate order for the normalized hostname set.
// Concurrent calls for the same set share one order via obtainSf.
//
// Note on separate flights: Obtain and Renew use separate singleflight groups (obtainSf and renewSf).
// If a certificate has already expired while a background renewal is retrying, an incoming Obtain
// can initiate its own order. Both orders produce valid certificates and write atomically to cache,
// ensuring caller requests are satisfied without coalescing renewals into no-op cached returns.
func (m *Manager) Obtain(ctx context.Context, hostnames []string, requester challenge.Requester) (*cache.Certificate, error) {
	normalized, hostnamesKey, err := NormalizeHostnames(hostnames, m.opts.MaxHostnamesPerSet, m.opts.MaxHostnameLength)
	if err != nil {
		return nil, err
	}
	requester.HostnamesKey = hostnamesKey

	now := m.opts.Clock.Now()

	// 1. Fast-path: check if valid certificate already exists in cache
	if existing, err := m.cache.Get(hostnamesKey); err == nil && existing != nil && !existing.IsExpired(now) {
		if requester.ClusterID == "" || m.opts.BindingStore == nil || m.opts.BindingStore.HasValidatedBinding(requester.ClusterID, requester.Gateway, hostnamesKey, now) {
			return existing, nil
		}
	}

	// 2. Bound pending orders
	if m.opts.MaxPendingOrders > 0 && m.pendingOrders.Load() >= m.opts.MaxPendingOrders {
		return nil, ErrTooManyPendingOrders
	}

	// 3. Singleflight execution for concurrent Obtain requests of the same set
	ch := m.obtainSf.DoChan(hostnamesKey, func() (any, error) {
		// Re-check cache under singleflight lock
		if existing, err := m.cache.Get(hostnamesKey); err == nil && existing != nil && !existing.IsExpired(m.opts.Clock.Now()) {
			if requester.ClusterID == "" || m.opts.BindingStore == nil || m.opts.BindingStore.HasValidatedBinding(requester.ClusterID, requester.Gateway, hostnamesKey, m.opts.Clock.Now()) {
				return existing, nil
			}
		}

		if m.opts.MaxPendingOrders > 0 {
			if curr := m.pendingOrders.Add(1); curr > m.opts.MaxPendingOrders {
				m.pendingOrders.Add(-1)
				return nil, ErrTooManyPendingOrders
			}
			defer m.pendingOrders.Add(-1)
		}

		// Detached context with independent timeout so that cancellation of the first caller
		// does not abort the shared order for other waiting callers.
		orderCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()

		cert, err := m.issueCertificate(orderCtx, normalized, hostnamesKey, false, requester, nil)
		if err != nil {
			return nil, err
		}
		return cert, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*cache.Certificate), nil
	}
}

// Renew forces a certificate renewal for the normalized hostname set, creating a new ACME order.
// Concurrent renewals for the same set coalesce via renewSf and never return a cached certificate.
func (m *Manager) Renew(ctx context.Context, hostnames []string, requester challenge.Requester, candidates []challenge.Requester) (*cache.Certificate, error) {
	normalized, hostnamesKey, err := NormalizeHostnames(hostnames, m.opts.MaxHostnamesPerSet, m.opts.MaxHostnameLength)
	if err != nil {
		return nil, err
	}
	requester.HostnamesKey = hostnamesKey

	// 1. Bound pending orders
	if m.opts.MaxPendingOrders > 0 && m.pendingOrders.Load() >= m.opts.MaxPendingOrders {
		return nil, ErrTooManyPendingOrders
	}

	// 2. Singleflight execution for renewals of the same set. Always issues a new certificate.
	ch := m.renewSf.DoChan(hostnamesKey, func() (any, error) {
		if m.opts.MaxPendingOrders > 0 {
			if curr := m.pendingOrders.Add(1); curr > m.opts.MaxPendingOrders {
				m.pendingOrders.Add(-1)
				return nil, ErrTooManyPendingOrders
			}
			defer m.pendingOrders.Add(-1)
		}

		orderCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()

		cert, err := m.issueCertificate(orderCtx, normalized, hostnamesKey, true, requester, candidates)
		if err != nil {
			return nil, err
		}
		return cert, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*cache.Certificate), nil
	}
}

// issueCertificate executes the ACME order creation, HTTP-01 challenge completion, CSR submission, and caching.
func (m *Manager) issueCertificate(ctx context.Context, normalized []string, hostnamesKey string, isRenewal bool, req challenge.Requester, candidates []challenge.Requester) (*cache.Certificate, error) {
	cert, err := m.executeACMEOrder(ctx, normalized, hostnamesKey, req, candidates)
	if err != nil {
		if isRenewal {
			m.metrics.RecordRenewal(false)
		} else {
			m.metrics.RecordIssuance(false)
		}
		return nil, err
	}

	if err := m.cache.Put(cert); err != nil {
		if isRenewal {
			m.metrics.RecordRenewal(false)
		} else {
			m.metrics.RecordIssuance(false)
		}
		return nil, fmt.Errorf("failed to cache issued certificate: %w", err)
	}

	m.mu.Lock()
	m.trackCertificateLocked(cert, m.opts.Clock.Now())
	m.mu.Unlock()

	if isRenewal {
		m.metrics.RecordRenewal(true)
	} else {
		m.metrics.RecordIssuance(true)
	}

	return cert, nil
}

func (m *Manager) executeACMEOrder(ctx context.Context, normalized []string, hostnamesKey string, req challenge.Requester, candidates []challenge.Requester) (*cache.Certificate, error) {
	// Ensure ACME account is registered
	if _, err := m.client.EnsureAccount(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure ACME account: %w", err)
	}

	// 1. Authorize order
	order, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(normalized...))
	if err != nil {
		return nil, fmt.Errorf("failed to authorize ACME order: %w", err)
	}

	// Ensure authorizations are relinquished so subsequent orders must prove fresh domain control
	defer func() {
		for _, authzURL := range order.AuthzURLs {
			if revokeErr := m.client.RevokeAuthorization(context.WithoutCancel(ctx), authzURL); revokeErr != nil {
				log.Printf("certserver: failed to revoke authorization %s: %v", authzURL, revokeErr)
			}
		}
	}()

	// 2. Fulfill pending authorizations
	for _, authzURL := range order.AuthzURLs {
		if err := m.fulfillAuthorization(ctx, authzURL, req, candidates); err != nil {
			return nil, err
		}
	}

	// 3. Wait for order to be ready
	order, err = m.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("order failed while waiting for ready: %w", err)
	}

	// 4. Generate ECDSA P-256 certificate key
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate private key: %w", err)
	}

	// 5. Generate Certificate Signing Request (CSR)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: normalized,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// 6. Submit CSR and download certificate chain
	derChain, certURL, err := m.client.CreateCertFromOrder(ctx, order, csrDER, true)
	if err != nil {
		if order.Status == acme.StatusValid && order.CertURL != "" {
			derChain, err = m.client.FetchCert(ctx, order.CertURL, true)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to obtain certificate from order (%s): %w", certURL, err)
		}
	}

	if len(derChain) == 0 {
		return nil, errors.New("empty certificate chain returned from ACME server")
	}

	leaf, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Encode certificate chain to PEM
	var certPEM []byte
	for _, b := range derChain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		})...)
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	cert := cache.NewCertificate(
		normalized,
		hostnamesKey,
		certPEM,
		keyPEM,
		leaf,
		leaf.NotBefore,
		leaf.NotAfter,
	)
	cert.ClusterID = req.ClusterID
	cert.Gateway = req.Gateway
	cert.DataPlaneServiceAccount = req.DataPlaneServiceAccount

	return cert, nil
}

func (m *Manager) fulfillAuthorization(ctx context.Context, authzURL string, req challenge.Requester, candidates []challenge.Requester) error {
	authz, err := m.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("failed to get authorization %s: %w", authzURL, err)
	}
	if authz.Status == acme.StatusValid {
		if revokeErr := m.client.RevokeAuthorization(ctx, authzURL); revokeErr != nil {
			log.Printf("certserver: failed to revoke pre-validated authorization %s: %v", authzURL, revokeErr)
		}
		return fmt.Errorf("authorization for %s was pre-validated on ACME account; revoked to require fresh challenge validation", authz.Identifier.Value)
	}

	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("no HTTP-01 challenge offered for %s", authz.Identifier.Value)
	}

	keyAuth, err := m.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return fmt.Errorf("failed to compute HTTP-01 challenge response: %w", err)
	}

	expiresAt := authz.Expires
	if expiresAt.IsZero() {
		expiresAt = m.opts.Clock.Now().Add(10 * time.Minute)
	}

	if err := m.challengeStore.PutWithCandidates(ctx, chal.Token, authz.Identifier.Value, keyAuth, expiresAt, req, candidates); err != nil {
		return fmt.Errorf("failed to register challenge in store: %w", err)
	}
	defer func(token string) {
		if rmErr := m.challengeStore.Remove(context.WithoutCancel(ctx), token); rmErr != nil && !errors.Is(rmErr, challenge.ErrNotFound) {
			log.Printf("certserver: failed to remove challenge token %s: %v", token, rmErr)
		}
	}(chal.Token)

	if _, err := m.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("failed to accept challenge: %w", err)
	}

	if _, err := m.client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("authorization failed for %s: %w", authz.Identifier.Value, err)
	}

	return nil
}
