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

package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
)

const (
	// CertServerAudience is the required audience for ServiceAccount tokens presented to certserver.
	CertServerAudience = "certserver"
)

type dirClusterState struct {
	config       *ClusterConfig
	clusterBytes []byte
	jwksBytes    []byte
}

type failedClusterState struct {
	clusterBytes   []byte
	jwksBytes      []byte
	invalidDirName bool
}

// Registry manages trusted Kubernetes clusters and token verification.
type Registry struct {
	jwksCache       *jwt.JWKSCache
	verifier        *jwt.Verifier
	httpClient      *http.Client
	unknownKidLimit time.Duration
	refreshInterval time.Duration
	timeNow         func() time.Time

	auditLogger     *AuditLogger
	registrationDir string
	pollInterval    time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
	closeOnce       sync.Once
	syncMu          sync.Mutex

	// mu guards clustersByID, clustersByIssuer, dirClustersByID, and failedClustersByID.
	mu                     sync.RWMutex
	clustersByID           map[string]*ClusterConfig
	clustersByIssuer       map[string]*ClusterConfig
	staticClustersByID     map[string]*ClusterConfig
	staticClustersByIssuer map[string]*ClusterConfig
	dirClustersByID        map[string]*dirClusterState
	failedClustersByID     map[string]*failedClusterState
}

// Option configures a Registry.
type Option func(*Registry)

// WithAuditLogger sets the structured audit logger for cluster registration events.
func WithAuditLogger(l *AuditLogger) Option {
	return func(r *Registry) {
		r.auditLogger = l
	}
}

// WithRegistrationDir sets the directory path for per-cluster registration files.
func WithRegistrationDir(dir string) Option {
	return func(r *Registry) {
		r.registrationDir = dir
	}
}

// WithPollInterval sets the interval for rescanning the registration directory.
func WithPollInterval(d time.Duration) Option {
	return func(r *Registry) {
		if d > 0 {
			r.pollInterval = d
		}
	}
}

// WithHTTPClient sets a custom HTTP client for OIDC discovery and JWKS fetching.
func WithHTTPClient(client *http.Client) Option {
	return func(r *Registry) {
		if client != nil {
			r.httpClient = client
		}
	}
}

// WithUnknownKidRateLimit sets the minimum duration between JWKS refreshes for unknown kids.
func WithUnknownKidRateLimit(d time.Duration) Option {
	return func(r *Registry) {
		if d > 0 {
			r.unknownKidLimit = d
		}
	}
}

// WithRefreshInterval sets the periodic JWKS background refresh interval.
func WithRefreshInterval(d time.Duration) Option {
	return func(r *Registry) {
		if d > 0 {
			r.refreshInterval = d
		}
	}
}

// WithTimeNow overrides time.Now for deterministic testing.
func WithTimeNow(fn func() time.Time) Option {
	return func(r *Registry) {
		if fn != nil {
			r.timeNow = fn
		}
	}
}

// NormalizeIssuer normalizes an issuer URL (trims whitespace and trailing slash).
func NormalizeIssuer(iss string) string {
	return strings.TrimRight(strings.TrimSpace(iss), "/")
}

// NewRegistry initializes a Registry from a slice of ClusterConfigs.
func NewRegistry(clusters []ClusterConfig, opts ...Option) (*Registry, error) {
	r := &Registry{
		clustersByID:           make(map[string]*ClusterConfig),
		clustersByIssuer:       make(map[string]*ClusterConfig),
		staticClustersByID:     make(map[string]*ClusterConfig),
		staticClustersByIssuer: make(map[string]*ClusterConfig),
		dirClustersByID:        make(map[string]*dirClusterState),
		failedClustersByID:     make(map[string]*failedClusterState),
		pollInterval:           2 * time.Second,
		stopCh:                 make(chan struct{}),
		timeNow:                time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}

	var issuerConfigs []jwt.IssuerConfig
	for i := range clusters {
		c := clusters[i]
		if err := c.Validate(); err != nil {
			return nil, err
		}

		if _, exists := r.clustersByID[c.ClusterID]; exists {
			return nil, fmt.Errorf("duplicate cluster ID %q", c.ClusterID)
		}
		cCopy := c
		r.clustersByID[c.ClusterID] = &cCopy
		r.staticClustersByID[c.ClusterID] = &cCopy

		normIss := NormalizeIssuer(c.IssuerURL)
		if _, exists := r.clustersByIssuer[normIss]; exists {
			return nil, fmt.Errorf("duplicate issuer URL %q", c.IssuerURL)
		}
		r.clustersByIssuer[normIss] = &cCopy
		r.staticClustersByIssuer[normIss] = &cCopy

		// Configure JWKS source
		issCfg := jwt.IssuerConfig{
			IssuerURL: c.IssuerURL,
			JWKSFile:  c.JWKSFile,
			JWKSURL:   c.JWKSURL,
		}
		issuerConfigs = append(issuerConfigs, issCfg)
	}

	// Initialize JWKS Cache
	var jwksOpts []jwt.JWKSCacheOption
	if r.httpClient != nil {
		jwksOpts = append(jwksOpts, jwt.WithHTTPClient(r.httpClient))
	}
	if r.unknownKidLimit > 0 {
		jwksOpts = append(jwksOpts, jwt.WithUnknownKidRateLimit(r.unknownKidLimit))
	}
	if r.refreshInterval > 0 {
		jwksOpts = append(jwksOpts, jwt.WithRefreshInterval(r.refreshInterval))
	}
	if r.timeNow != nil {
		jwksOpts = append(jwksOpts, jwt.WithJWKSTimeNow(r.timeNow))
	}

	cache, err := jwt.NewJWKSCache(issuerConfigs, jwksOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS cache: %w", err)
	}
	r.jwksCache = cache

	var verifierOpts []jwt.VerifierOption
	verifierOpts = append(verifierOpts, jwt.WithAudience(CertServerAudience))
	if r.timeNow != nil {
		verifierOpts = append(verifierOpts, jwt.WithTimeNow(r.timeNow))
	}
	r.verifier = jwt.NewVerifier(cache, verifierOpts...)

	// Initial sync of registration directory if configured
	if r.registrationDir != "" {
		if err := r.SyncRegistrationDir(context.Background()); err != nil {
			log.Printf("certserver: initial registration directory sync error: %v", err)
		}
		r.wg.Add(1)
		go r.runDirectoryScanner()
	}

	return r, nil
}

func (r *Registry) runDirectoryScanner() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			if err := r.SyncRegistrationDir(context.Background()); err != nil {
				log.Printf("certserver: registration directory sync error: %v", err)
			}
		}
	}
}

func (r *Registry) audit(method string, clusterID string, decision AuditDecision, statusCode string, reason string) {
	if r.auditLogger == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:  r.timeNow().UTC(),
		Method:     method,
		Identity:   CallerIdentity{ClusterID: clusterID},
		Decision:   decision,
		StatusCode: statusCode,
		Reason:     reason,
	}
	if err := r.auditLogger.Log(entry); err != nil {
		log.Printf("certserver: failed to write audit log entry: %v", err)
	}
}

func (r *Registry) handleDirClusterFailure(clusterID string, rawCluster []byte, rawJWKS []byte, reason string, invalidDirName bool) {
	r.mu.Lock()
	r.failedClustersByID[clusterID] = &failedClusterState{
		clusterBytes:   rawCluster,
		jwksBytes:      rawJWKS,
		invalidDirName: invalidDirName,
	}
	_, wasRegistered := r.dirClustersByID[clusterID]
	r.mu.Unlock()

	method := "RegisterCluster"
	if wasRegistered {
		method = "UpdateCluster"
	}

	r.audit(method, clusterID, DecisionRefused, "InvalidArgument", reason)
	if wasRegistered {
		log.Printf("certserver: validation failed for cluster %q (%s); keeping previous registration active", clusterID, reason)
	} else {
		log.Printf("certserver: validation failed for new cluster %q (%s); skipping", clusterID, reason)
	}
}

func (r *Registry) unregisterMissingDirClusters(foundClusters map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for clusterID, state := range r.dirClustersByID {
		if foundClusters != nil {
			if _, found := foundClusters[clusterID]; found {
				continue
			}
		}

		delete(r.dirClustersByID, clusterID)
		delete(r.clustersByID, clusterID)
		delete(r.clustersByIssuer, NormalizeIssuer(state.config.IssuerURL))
		r.jwksCache.RemoveIssuer(state.config.IssuerURL)

		r.audit("UnregisterCluster", clusterID, DecisionAllowed, "OK", fmt.Sprintf("cluster %q unregistered (directory removed)", clusterID))
		log.Printf("certserver: unregistered cluster %q (directory removed)", clusterID)
	}

	for clusterID := range r.failedClustersByID {
		if foundClusters != nil {
			if _, found := foundClusters[clusterID]; found {
				continue
			}
		}
		delete(r.failedClustersByID, clusterID)
	}
}

// SyncRegistrationDir rescans the registration directory and updates dynamic cluster registrations.
func (r *Registry) SyncRegistrationDir(ctx context.Context) error {
	if r.registrationDir == "" {
		return nil
	}

	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	entries, err := os.ReadDir(r.registrationDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.unregisterMissingDirClusters(nil)
			return nil
		}
		return fmt.Errorf("reading registration directory %s: %w", r.registrationDir, err)
	}

	foundClusters := make(map[string]struct{})

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp") {
			continue
		}

		clusterID := name
		foundClusters[clusterID] = struct{}{}
		clusterDir := filepath.Join(r.registrationDir, clusterID)

		// Check if this cluster directory was already reported as having an invalid name.
		r.mu.RLock()
		failedState, hasFailed := r.failedClustersByID[clusterID]
		r.mu.RUnlock()
		if hasFailed && failedState.invalidDirName {
			continue
		}

		// Validate cluster directory name matches DNS-1123 label rules
		if err := ValidateClusterID(clusterID); err != nil {
			r.handleDirClusterFailure(clusterID, nil, nil, fmt.Sprintf("invalid cluster directory name %q: %v", clusterID, err), true)
			continue
		}

		// 1. Check duplicate cluster ID against static config
		if _, exists := r.staticClustersByID[clusterID]; exists {
			r.audit("RegisterCluster", clusterID, DecisionRefused, "AlreadyExists",
				fmt.Sprintf("cluster %q duplicates static cluster ID", clusterID))
			log.Printf("certserver: cluster %q in registration directory duplicates static config cluster ID; skipping", clusterID)
			continue
		}

		// 2. Read cluster.json and jwks.json
		clusterFile := filepath.Join(clusterDir, "cluster.json")
		jwksFile := filepath.Join(clusterDir, "jwks.json")

		rawCluster, errCluster := os.ReadFile(clusterFile)
		rawJWKS, errJWKS := os.ReadFile(jwksFile)

		// 3. Skip re-validating identical failed files to avoid repetitive log and audit spam
		if hasFailed && bytes.Equal(failedState.clusterBytes, rawCluster) && bytes.Equal(failedState.jwksBytes, rawJWKS) {
			continue
		}

		if errCluster != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("reading %s: %v", clusterFile, errCluster), false)
			continue
		}
		if errJWKS != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("reading %s: %v", jwksFile, errJWKS), false)
			continue
		}

		// Check if neither file has changed since last successful load
		r.mu.RLock()
		existingState, wasRegistered := r.dirClustersByID[clusterID]
		r.mu.RUnlock()

		if wasRegistered && bytes.Equal(existingState.clusterBytes, rawCluster) && bytes.Equal(existingState.jwksBytes, rawJWKS) {
			continue
		}

		// 4. Validate cluster.json
		var cfg ClusterConfig
		if err := json.Unmarshal(rawCluster, &cfg); err != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("parsing cluster.json: %v", err), false)
			continue
		}
		if cfg.ClusterID == "" {
			cfg.ClusterID = clusterID
		} else if cfg.ClusterID != clusterID {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("cluster.json clusterID %q does not match directory name %q", cfg.ClusterID, clusterID), false)
			continue
		}

		if err := cfg.Validate(); err != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("validating cluster config: %v", err), false)
			continue
		}

		if !strings.HasPrefix(cfg.IssuerURL, "https://") {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("issuerURL must use HTTPS: %q", cfg.IssuerURL), false)
			continue
		}

		normIss := NormalizeIssuer(cfg.IssuerURL)
		if staticCluster, exists := r.staticClustersByIssuer[normIss]; exists && staticCluster.ClusterID != clusterID {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("issuerURL %q conflicts with static cluster %q", cfg.IssuerURL, staticCluster.ClusterID), false)
			continue
		}

		r.mu.RLock()
		conflictingCluster := ""
		for otherID, otherState := range r.dirClustersByID {
			if otherID != clusterID && NormalizeIssuer(otherState.config.IssuerURL) == normIss {
				conflictingCluster = otherID
				break
			}
		}
		r.mu.RUnlock()
		if conflictingCluster != "" {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("issuerURL %q conflicts with directory cluster %q", cfg.IssuerURL, conflictingCluster), false)
			continue
		}

		// 5. Validate jwks.json: parses and has at least one usable key
		parsedKeys, err := jwt.ParseJWKS(rawJWKS)
		if err != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("parsing jwks.json: %v", err), false)
			continue
		}
		if len(parsedKeys) == 0 {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, "jwks.json contains no usable keys", false)
			continue
		}

		// 6. Validation succeeded! Update JWKS cache with the in-memory validated bytes
		cfg.JWKSFile = jwksFile

		if err := r.jwksCache.AddOrUpdateIssuer(ctx, jwt.IssuerConfig{
			IssuerURL: cfg.IssuerURL,
			JWKSFile:  cfg.JWKSFile,
			JWKSBytes: rawJWKS,
		}); err != nil {
			r.handleDirClusterFailure(clusterID, rawCluster, rawJWKS, fmt.Sprintf("updating JWKS cache: %v", err), false)
			continue
		}

		// 7. Swap in the validated cluster
		r.mu.Lock()
		delete(r.failedClustersByID, clusterID)
		oldState, existed := r.dirClustersByID[clusterID]
		if existed && NormalizeIssuer(oldState.config.IssuerURL) != normIss {
			delete(r.clustersByIssuer, NormalizeIssuer(oldState.config.IssuerURL))
			r.jwksCache.RemoveIssuer(oldState.config.IssuerURL)
		}
		cfgCopy := cfg
		r.dirClustersByID[clusterID] = &dirClusterState{
			config:       &cfgCopy,
			clusterBytes: rawCluster,
			jwksBytes:    rawJWKS,
		}
		r.clustersByID[clusterID] = &cfgCopy
		r.clustersByIssuer[normIss] = &cfgCopy
		r.mu.Unlock()

		if existed {
			r.audit("UpdateCluster", clusterID, DecisionAllowed, "OK", fmt.Sprintf("cluster %q updated from registration directory", clusterID))
			log.Printf("certserver: updated cluster %q from registration directory", clusterID)
		} else {
			r.audit("RegisterCluster", clusterID, DecisionAllowed, "OK", fmt.Sprintf("cluster %q registered from registration directory", clusterID))
			log.Printf("certserver: registered cluster %q from registration directory", clusterID)
		}
	}

	// 8. Unregister clusters whose directories have been removed
	r.unregisterMissingDirClusters(foundClusters)

	return nil
}

// Close closes the underlying JWKS cache background loops and directory scanner.
func (r *Registry) Close() error {
	r.closeOnce.Do(func() {
		close(r.stopCh)
		r.wg.Wait()
	})
	if r.jwksCache != nil {
		return r.jwksCache.Close()
	}
	return nil
}

// GetCluster returns the cluster configuration for clusterID.
func (r *Registry) GetCluster(clusterID string) (*ClusterConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clustersByID[clusterID]
	return c, ok
}

// GetClusterByIssuer returns the cluster configuration for an issuer URL.
func (r *Registry) GetClusterByIssuer(issuer string) (*ClusterConfig, bool) {
	norm := NormalizeIssuer(issuer)
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clustersByIssuer[norm]
	return c, ok
}

type unverifiedPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
}

func parseUnverifiedPayload(token string) (*unverifiedPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format: expected 3 parts")
	}
	s := strings.TrimRight(parts[1], "=")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding token payload: %w", err)
	}
	var p unverifiedPayload
	if err := json.Unmarshal(bytes.TrimSpace(payloadBytes), &p); err != nil {
		return nil, fmt.Errorf("parsing token payload JSON: %w", err)
	}
	return &p, nil
}

// VerifyToken verifies a ServiceAccount token against the appropriate cluster's JWKS and issuer.
// If requestedClusterID is non-empty, the token's issuer MUST match that cluster's entry.
// Returns the verified CallerIdentity and matching ClusterConfig.
func (r *Registry) VerifyToken(ctx context.Context, token string, requestedClusterID string) (CallerIdentity, *ClusterConfig, error) {
	if strings.TrimSpace(token) == "" {
		return CallerIdentity{}, nil, errors.New("token is empty")
	}

	// 1. Inspect unverified payload to extract issuer
	unverified, err := parseUnverifiedPayload(token)
	if err != nil {
		return CallerIdentity{}, nil, fmt.Errorf("invalid token: %w", err)
	}
	if unverified.Iss == "" {
		return CallerIdentity{}, nil, errors.New("token missing required 'iss' claim")
	}

	var cluster *ClusterConfig

	// 2. Identify and validate target cluster
	if requestedClusterID != "" {
		targetCluster, ok := r.GetCluster(requestedClusterID)
		if !ok {
			return CallerIdentity{}, nil, fmt.Errorf("unknown or unconfigured cluster ID %q", requestedClusterID)
		}
		// "token from cluster A presented as cluster B": iss must match the cluster entry
		if NormalizeIssuer(unverified.Iss) != NormalizeIssuer(targetCluster.IssuerURL) {
			return CallerIdentity{}, nil, fmt.Errorf("token issuer %q does not match cluster %q issuer %q", unverified.Iss, requestedClusterID, targetCluster.IssuerURL)
		}
		cluster = targetCluster
	} else {
		// Lookup cluster by issuer URL
		targetCluster, ok := r.GetClusterByIssuer(unverified.Iss)
		if !ok {
			return CallerIdentity{}, nil, fmt.Errorf("untrusted or unconfigured token issuer: %q", unverified.Iss)
		}
		cluster = targetCluster
	}

	// 3. Perform cryptographic signature, algorithm, audience, and expiration verification
	claims, err := r.verifier.Verify(ctx, token)
	if err != nil {
		return CallerIdentity{}, nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Double-check verified issuer against cluster
	if NormalizeIssuer(claims.Issuer) != NormalizeIssuer(cluster.IssuerURL) {
		return CallerIdentity{}, nil, fmt.Errorf("verified issuer %q does not match cluster %q issuer %q", claims.Issuer, cluster.ClusterID, cluster.IssuerURL)
	}

	// 4. Extract namespace and service account from subject
	ns, sa, err := ParseSubject(claims.Subject)
	if err != nil {
		return CallerIdentity{}, nil, fmt.Errorf("invalid token subject: %w", err)
	}

	identity := CallerIdentity{
		ClusterID:      cluster.ClusterID,
		Namespace:      ns,
		ServiceAccount: sa,
	}

	return identity, cluster, nil
}
