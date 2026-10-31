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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultJWKSRefreshInterval is the periodic refresh interval (1 hour).
	DefaultJWKSRefreshInterval = 1 * time.Hour

	// DefaultUnknownKidRateLimit is the rate limit for refreshing on unknown kid (at most once per minute).
	DefaultUnknownKidRateLimit = 1 * time.Minute

	// DefaultHTTPTimeout is the network timeout for OIDC discovery and JWKS requests.
	DefaultHTTPTimeout = 10 * time.Second

	// MaxHTTPResponseBytes is the maximum allowed response size (1 MiB).
	MaxHTTPResponseBytes = 1024 * 1024
)

// KeyProvider supplies public keys for an issuer and key ID.
type KeyProvider interface {
	GetKey(ctx context.Context, issuer string, kid string) (crypto.PublicKey, error)
}

// IssuerConfig defines configuration for a trusted JWT issuer.
type IssuerConfig struct {
	IssuerURL string // HTTPS URL for OIDC discovery
	JWKSURL   string // Direct JWKS URI (optional, bypasses OIDC discovery)
	JWKSFile  string // Path to static JWKS file (alternative to public OIDC discovery)
	JWKSBytes []byte // In-memory validated JWKS document (takes precedence over file/network)
}

// jwkEntry represents a single JSON Web Key in a JWKS.
type jwkEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksDocument represents a JWKS JSON document.
type jwksDocument struct {
	Keys []jwkEntry `json:"keys"`
}

// oidcDiscoveryDocument represents an OIDC .well-known/openid-configuration document.
type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type issuerState struct {
	mu          sync.RWMutex
	issuerURL   string
	jwksFile    string
	jwksURI     string
	jwksBytes   []byte
	keys        map[string]crypto.PublicKey // kid -> public key
	keysLoaded  bool
	lastRefresh time.Time
	lastAttempt time.Time
	lastError   error
	refreshMu   sync.Mutex // ensures only one refresh at a time per issuer
}

// JWKSCache manages cached JWKS public keys across configured issuers.
type JWKSCache struct {
	issuers         map[string]*issuerState // normalized issuer string -> state
	issuersMu       sync.RWMutex
	httpClient      *http.Client
	refreshInterval time.Duration
	rateLimit       time.Duration
	timeNow         func() time.Time
	stopCh          chan struct{}
	stopOnce        sync.Once
}

// JWKSCacheOption configures a JWKSCache.
type JWKSCacheOption func(*JWKSCache)

// WithHTTPClient sets a custom http.Client (e.g. for testing with custom TLS certificates).
func WithHTTPClient(client *http.Client) JWKSCacheOption {
	return func(c *JWKSCache) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithRefreshInterval overrides the periodic refresh interval.
func WithRefreshInterval(d time.Duration) JWKSCacheOption {
	return func(c *JWKSCache) {
		if d > 0 {
			c.refreshInterval = d
		}
	}
}

// WithUnknownKidRateLimit overrides the rate limit for unknown kid refreshes.
func WithUnknownKidRateLimit(d time.Duration) JWKSCacheOption {
	return func(c *JWKSCache) {
		if d > 0 {
			c.rateLimit = d
		}
	}
}

// WithJWKSTimeNow overrides time.Now for deterministic testing.
func WithJWKSTimeNow(fn func() time.Time) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.timeNow = fn
	}
}

// NormalizeIssuer normalizes an issuer URL (removes trailing slash for consistent lookup).
func NormalizeIssuer(iss string) string {
	return strings.TrimRight(strings.TrimSpace(iss), "/")
}

func (c *JWKSCache) requestTimeout() time.Duration {
	if c.httpClient != nil && c.httpClient.Timeout > 0 {
		return c.httpClient.Timeout
	}
	return DefaultHTTPTimeout
}

// NewJWKSCache initializes a JWKSCache for the given issuer configurations.
func NewJWKSCache(configs []IssuerConfig, opts ...JWKSCacheOption) (*JWKSCache, error) {
	cache := &JWKSCache{
		issuers:         make(map[string]*issuerState),
		httpClient:      &http.Client{Timeout: DefaultHTTPTimeout},
		refreshInterval: DefaultJWKSRefreshInterval,
		rateLimit:       DefaultUnknownKidRateLimit,
		timeNow:         time.Now,
		stopCh:          make(chan struct{}),
	}
	for _, opt := range opts {
		opt(cache)
	}

	for _, cfg := range configs {
		if cfg.IssuerURL == "" && cfg.JWKSFile == "" {
			return nil, errors.New("issuer config must specify IssuerURL or JWKSFile")
		}

		normIss := NormalizeIssuer(cfg.IssuerURL)
		if cfg.JWKSFile == "" {
			// Validate HTTPS requirement
			if !strings.HasPrefix(cfg.IssuerURL, "https://") {
				return nil, fmt.Errorf("issuer URL must use HTTPS: %q", cfg.IssuerURL)
			}
		}
		if cfg.JWKSURL != "" && !strings.HasPrefix(cfg.JWKSURL, "https://") {
			return nil, fmt.Errorf("JWKS URL must use HTTPS: %q", cfg.JWKSURL)
		}

		state := &issuerState{
			issuerURL: cfg.IssuerURL,
			jwksFile:  cfg.JWKSFile,
			jwksURI:   cfg.JWKSURL,
			keys:      make(map[string]crypto.PublicKey),
		}
		cache.issuers[normIss] = state

		// Perform initial load:
		// "Startup with an unreachable issuer still starts the frontend; tokens from that issuer are rejected until keys load."
		ctx, cancel := context.WithTimeout(context.Background(), cache.requestTimeout())
		if err := cache.refreshIssuer(ctx, state); err != nil {
			log.Printf("JWKS: initial load failed for issuer %s (will retry on demand/periodically): %v", state.issuerURL, err)
		}
		cancel()
	}

	// Start periodic refresh ticker
	go cache.runPeriodicRefresh()

	return cache, nil
}

// Close stops the periodic refresh loop.
func (c *JWKSCache) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	return nil
}

// AddOrUpdateIssuer registers or updates an issuer in the cache, immediately loading/refreshing its keys.
// If key loading fails, an existing issuer keeps its previous keys and the error is returned.
func (c *JWKSCache) AddOrUpdateIssuer(ctx context.Context, cfg IssuerConfig) error {
	if cfg.IssuerURL == "" && cfg.JWKSFile == "" && len(cfg.JWKSBytes) == 0 {
		return errors.New("issuer config must specify IssuerURL, JWKSFile, or JWKSBytes")
	}

	normIss := NormalizeIssuer(cfg.IssuerURL)
	if cfg.JWKSFile == "" && len(cfg.JWKSBytes) == 0 {
		if !strings.HasPrefix(cfg.IssuerURL, "https://") {
			return fmt.Errorf("issuer URL must use HTTPS: %q", cfg.IssuerURL)
		}
	}
	if cfg.JWKSURL != "" && !strings.HasPrefix(cfg.JWKSURL, "https://") {
		return fmt.Errorf("JWKS URL must use HTTPS: %q", cfg.JWKSURL)
	}

	c.issuersMu.Lock()
	state, exists := c.issuers[normIss]
	if !exists {
		state = &issuerState{
			issuerURL: cfg.IssuerURL,
			jwksFile:  cfg.JWKSFile,
			jwksURI:   cfg.JWKSURL,
			jwksBytes: cfg.JWKSBytes,
			keys:      make(map[string]crypto.PublicKey),
		}
	}
	c.issuersMu.Unlock()

	state.refreshMu.Lock()
	defer state.refreshMu.Unlock()

	oldURL := state.issuerURL
	oldFile := state.jwksFile
	oldURI := state.jwksURI
	oldBytes := state.jwksBytes

	state.issuerURL = cfg.IssuerURL
	state.jwksFile = cfg.JWKSFile
	state.jwksURI = cfg.JWKSURL
	state.jwksBytes = cfg.JWKSBytes

	if err := c.refreshIssuerLocked(ctx, state); err != nil {
		if exists {
			state.issuerURL = oldURL
			state.jwksFile = oldFile
			state.jwksURI = oldURI
			state.jwksBytes = oldBytes
		}
		return fmt.Errorf("loading keys for issuer %s: %w", cfg.IssuerURL, err)
	}

	if !exists {
		c.issuersMu.Lock()
		c.issuers[normIss] = state
		c.issuersMu.Unlock()
	}

	return nil
}

// RemoveIssuer removes an issuer from the cache.
func (c *JWKSCache) RemoveIssuer(issuerURL string) {
	normIss := NormalizeIssuer(issuerURL)
	c.issuersMu.Lock()
	delete(c.issuers, normIss)
	c.issuersMu.Unlock()
}

func (c *JWKSCache) runPeriodicRefresh() {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.issuersMu.RLock()
			states := make([]*issuerState, 0, len(c.issuers))
			for _, s := range c.issuers {
				states = append(states, s)
			}
			c.issuersMu.RUnlock()

			for _, s := range states {
				ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout())
				if err := c.refreshIssuer(ctx, s); err != nil {
					log.Printf("JWKS: periodic refresh failed for issuer %s: %v", s.issuerURL, err)
				}
				cancel()
			}
		}
	}
}

// GetKey implements KeyProvider.
func (c *JWKSCache) GetKey(ctx context.Context, issuer string, kid string) (crypto.PublicKey, error) {
	normIss := NormalizeIssuer(issuer)

	c.issuersMu.RLock()
	state, ok := c.issuers[normIss]
	c.issuersMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown or unconfigured issuer: %q", issuer)
	}

	state.mu.RLock()
	key, found := state.keys[kid]
	state.mu.RUnlock()

	if found {
		return key, nil
	}

	// Key not found. Attempt rate-limited refresh on unknown kid:
	// "refresh on unknown kid at most once per minute"
	state.refreshMu.Lock()
	defer state.refreshMu.Unlock()

	// Double-check under refreshMu
	state.mu.RLock()
	key, found = state.keys[kid]
	lastAttempt := state.lastAttempt
	loaded := state.keysLoaded
	lastErr := state.lastError
	state.mu.RUnlock()

	if found {
		return key, nil
	}

	now := c.timeNow()
	var refreshErr error
	// Rate limit unknown-kid refresh attempts to at most once per rateLimit interval (e.g. 1 minute).
	// This applies to both successes and failures, ensuring unreachable issuers do not trigger outbound
	// fetches for every unauthenticated token presented.
	if lastAttempt.IsZero() || now.Sub(lastAttempt) >= c.rateLimit {
		if err := c.refreshIssuerLocked(ctx, state); err != nil {
			refreshErr = err
			log.Printf("JWKS: refresh on unknown kid %q failed for issuer %s: %v", kid, state.issuerURL, err)
		}
	}

	state.mu.RLock()
	key, found = state.keys[kid]
	loaded = state.keysLoaded
	if state.lastError != nil {
		lastErr = state.lastError
	}
	state.mu.RUnlock()

	if !found {
		if refreshErr != nil {
			return nil, fmt.Errorf("key ID %q not found for issuer %q (refresh failed: %w)", kid, issuer, refreshErr)
		}
		if !loaded && lastErr != nil {
			return nil, fmt.Errorf("key ID %q not found for issuer %q (issuer unavailable: %w)", kid, issuer, lastErr)
		}
		return nil, fmt.Errorf("key ID %q not found for issuer %q", kid, issuer)
	}
	return key, nil
}

func (c *JWKSCache) refreshIssuer(ctx context.Context, s *issuerState) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return c.refreshIssuerLocked(ctx, s)
}

func (c *JWKSCache) refreshIssuerLocked(ctx context.Context, s *issuerState) error {
	s.mu.Lock()
	s.lastAttempt = c.timeNow()
	s.mu.Unlock()

	var jwksBytes []byte
	var err error

	if len(s.jwksBytes) > 0 {
		jwksBytes = s.jwksBytes
	} else if s.jwksFile != "" {
		jwksBytes, err = c.readJWKSFile(s.jwksFile)
	} else {
		jwksBytes, err = c.fetchJWKSHTTP(ctx, s)
	}

	if err != nil {
		// "A failed refresh keeps the previous key set and logs."
		s.mu.Lock()
		s.lastError = err
		s.mu.Unlock()
		return err
	}

	parsedKeys, err := ParseJWKS(jwksBytes)
	if err != nil {
		s.mu.Lock()
		s.lastError = err
		s.mu.Unlock()
		return fmt.Errorf("parsing JWKS document: %w", err)
	}

	s.mu.Lock()
	s.keys = parsedKeys
	s.keysLoaded = true
	s.lastRefresh = c.timeNow()
	s.lastError = nil
	s.mu.Unlock()

	return nil
}

func closeBody(c io.Closer) {
	if c != nil {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("JWKS: error closing stream: %v", err)
		}
	}
}

func (c *JWKSCache) readJWKSFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening JWKS file %s: %w", path, err)
	}
	defer closeBody(f)

	data, err := io.ReadAll(io.LimitReader(f, MaxHTTPResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS file %s: %w", path, err)
	}
	if len(data) > MaxHTTPResponseBytes {
		return nil, fmt.Errorf("JWKS file %s exceeds 1 MiB limit", path)
	}
	return data, nil
}

func (c *JWKSCache) fetchJWKSHTTP(ctx context.Context, s *issuerState) ([]byte, error) {
	// If jwks_uri is not known yet, perform OIDC discovery
	if s.jwksURI == "" {
		discoveryURL := strings.TrimRight(s.issuerURL, "/") + "/.well-known/openid-configuration"
		if !strings.HasPrefix(discoveryURL, "https://") {
			return nil, fmt.Errorf("OIDC discovery URL must use HTTPS: %q", discoveryURL)
		}

		discReq, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating OIDC discovery request: %w", err)
		}

		discResp, err := c.httpClient.Do(discReq)
		if err != nil {
			return nil, fmt.Errorf("fetching OIDC discovery: %w", err)
		}
		defer closeBody(discResp.Body)

		if discResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OIDC discovery returned HTTP status %d", discResp.StatusCode)
		}

		discBytes, err := io.ReadAll(io.LimitReader(discResp.Body, MaxHTTPResponseBytes+1))
		if err != nil {
			return nil, fmt.Errorf("reading OIDC discovery response: %w", err)
		}
		if len(discBytes) > MaxHTTPResponseBytes {
			return nil, errors.New("OIDC discovery response exceeds 1 MiB limit")
		}

		var discDoc oidcDiscoveryDocument
		if err := json.Unmarshal(discBytes, &discDoc); err != nil {
			return nil, fmt.Errorf("parsing OIDC discovery JSON: %w", err)
		}

		if discDoc.JWKSURI == "" {
			return nil, errors.New("OIDC discovery missing 'jwks_uri'")
		}
		if !strings.HasPrefix(discDoc.JWKSURI, "https://") {
			return nil, fmt.Errorf("jwks_uri must use HTTPS: %q", discDoc.JWKSURI)
		}

		s.jwksURI = discDoc.JWKSURI
	}

	// Fetch JWKS
	jwksReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}

	jwksResp, err := c.httpClient.Do(jwksReq)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", s.jwksURI, err)
	}
	defer closeBody(jwksResp.Body)

	if jwksResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching JWKS returned HTTP status %d", jwksResp.StatusCode)
	}

	jwksBytes, err := io.ReadAll(io.LimitReader(jwksResp.Body, MaxHTTPResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}
	if len(jwksBytes) > MaxHTTPResponseBytes {
		return nil, errors.New("JWKS response exceeds 1 MiB limit")
	}

	return jwksBytes, nil
}

// ParseJWKS parses a JWKS document into a map of key ID to crypto.PublicKey.
// It supports RSA and EC (P-256) public keys.
func ParseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	keys := make(map[string]crypto.PublicKey)
	for _, entry := range doc.Keys {
		// Only parse keys intended for signature or unspecified use
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}

		switch entry.Kty {
		case "RSA":
			nBytes, err := base64DecodeURL(entry.N)
			if err != nil {
				continue
			}
			eBytes, err := base64DecodeURL(entry.E)
			if err != nil {
				continue
			}
			var eInt int
			for _, b := range eBytes {
				eInt = (eInt << 8) | int(b)
			}
			if eInt <= 0 {
				continue
			}
			rsaPub := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: eInt,
			}
			if entry.Kid != "" {
				keys[entry.Kid] = rsaPub
			}

		case "EC":
			if entry.Crv != "P-256" {
				continue
			}
			xBytes, err := base64DecodeURL(entry.X)
			if err != nil {
				continue
			}
			yBytes, err := base64DecodeURL(entry.Y)
			if err != nil {
				continue
			}
			x := new(big.Int).SetBytes(xBytes)
			y := new(big.Int).SetBytes(yBytes)
			if !elliptic.P256().IsOnCurve(x, y) {
				continue
			}
			ecPub := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			}
			if entry.Kid != "" {
				keys[entry.Kid] = ecPub
			}
		}
	}

	return keys, nil
}
