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
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/audit"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

const (
	// ACMEChallengePrefix is the standard URI prefix for ACME HTTP-01 challenges.
	ACMEChallengePrefix = "/.well-known/acme-challenge/"

	// maxTokenLength bounds the maximum length accepted for ACME challenge tokens.
	maxTokenLength = 128

	// DefaultValidatedBindingTTL is the default validity duration for recorded Gateway bindings.
	DefaultValidatedBindingTTL = 24 * time.Hour
)

// RecordValidatedBinding records a validated binding in the binding store for the requester with the specified TTL.
//
// Invariant: a Gateway holds a validated binding for a set of hostnames only after that Gateway
// itself proved that it serves them. Callers must only pass requesters whose domain
// control has been verified.
func RecordValidatedBinding(bindingStore registry.BindingStore, requester Requester, now time.Time, ttl time.Duration) {
	if bindingStore == nil || requester.ClusterID == "" || requester.HostnamesKey == "" {
		return
	}
	bindingStore.RecordValidatedBinding(registry.ValidatedBinding{
		ClusterID:    requester.ClusterID,
		Gateway:      requester.Gateway,
		HostnamesKey: requester.HostnamesKey,
		ValidatedAt:  now,
		ExpiresAt:    now.Add(ttl),
	})
}

// isValidToken reports whether token is non-empty, within length bounds, and composed
// exclusively of base64url characters (RFC 8555 Section 8.3).
func isValidToken(token string) bool {
	if len(token) == 0 || len(token) > maxTokenLength {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// HandlerOption configures the challenge HTTP handler.
type HandlerOption func(*Handler)

// WithCallerFunc configures a caller identification function.
func WithCallerFunc(fn func(*http.Request) string) HandlerOption {
	return func(h *Handler) {
		h.callerFunc = fn
	}
}

// WithRegistry sets the cluster registry for token verification and policy enforcement.
func WithRegistry(reg *registry.Registry) HandlerOption {
	return func(h *Handler) {
		h.registry = reg
	}
}

// WithBindingStore sets the binding store for Gateway binding lookups and validations.
func WithBindingStore(bs registry.BindingStore) HandlerOption {
	return func(h *Handler) {
		h.bindingStore = bs
	}
}

// WithAuditLogger sets the structured audit logger.
func WithAuditLogger(al *registry.AuditLogger) HandlerOption {
	return func(h *Handler) {
		h.auditLogger = al
	}
}

// WithMetrics sets the Prometheus metrics collector.
func WithMetrics(m *metrics.Metrics) HandlerOption {
	return func(h *Handler) {
		h.metrics = m
	}
}

// WithTimeNow overrides time.Now for deterministic testing.
func WithTimeNow(fn func() time.Time) HandlerOption {
	return func(h *Handler) {
		h.timeNow = fn
	}
}

// Handler implements http.Handler to serve HTTP-01 ACME challenge validations.
type Handler struct {
	resolver     ChallengeResolver
	store        Store
	registry     *registry.Registry
	bindingStore registry.BindingStore
	auditLogger  *registry.AuditLogger
	metrics      *metrics.Metrics
	callerFunc   func(*http.Request) string
	timeNow      func() time.Time
}

// NewHandler creates a new ACME HTTP-01 challenge handler using the provided resolver.
func NewHandler(resolver ChallengeResolver, opts ...HandlerOption) *Handler {
	h := &Handler{
		resolver: resolver,
		timeNow:  time.Now,
	}
	if s, ok := resolver.(Store); ok {
		h.store = s
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *Handler) now() time.Time {
	if h.timeNow != nil {
		return h.timeNow()
	}
	return time.Now()
}

func (h *Handler) recordMetric(status string) {
	if h.metrics != nil {
		h.metrics.RecordChallengeRequest(status)
	}
}

// ServeHTTP handles requests for /.well-known/acme-challenge/<token>.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		audit.FromContext(r.Context()).Set("", nil, audit.DecisionRefused, "method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	normHost := NormalizeHost(r.Host)

	if !strings.HasPrefix(r.URL.Path, ACMEChallengePrefix) {
		audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "invalid path prefix")
		http.NotFound(w, r)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, ACMEChallengePrefix)
	if !isValidToken(token) {
		audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "invalid challenge token format")
		http.NotFound(w, r)
		return
	}

	// If registry is configured, enforce data-plane service-account token verification and challenge binding.
	if h.registry != nil {
		authHeader := r.Header.Get("Authorization")
		var bearerToken string
		const prefix = "bearer "
		if strings.HasPrefix(strings.ToLower(authHeader), prefix) {
			bearerToken = strings.TrimSpace(authHeader[len(prefix):])
		}

		if bearerToken == "" {
			audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "missing authorization token")
			h.recordMetric("unauthenticated")
			http.NotFound(w, r)
			return
		}

		identity, _, err := h.registry.VerifyToken(r.Context(), bearerToken, "")
		if err != nil {
			audit.FromContext(r.Context()).SetIdentity(identity)
			audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, fmt.Sprintf("token verification failed: %v", err))
			h.recordMetric("unauthenticated")
			http.NotFound(w, r)
			return
		}
		audit.FromContext(r.Context()).SetIdentity(identity)

		if h.store == nil {
			audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "challenge store not configured")
			http.NotFound(w, r)
			return
		}

		item, err := h.store.Get(r.Context(), token)
		if err != nil {
			audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "challenge token not found")
			h.recordMetric("not_found")
			http.NotFound(w, r)
			return
		}

		// 1. Host match
		if normHost != item.Identifier {
			audit.FromContext(r.Context()).Set(item.Requester.Gateway, []string{normHost}, audit.DecisionRefused, "request host does not match challenge identifier")
			h.recordMetric("host_mismatch")
			http.NotFound(w, r)
			return
		}

		// 2. Expiry check
		now := h.now()
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			if rmErr := h.store.Remove(r.Context(), token); rmErr != nil && !errors.Is(rmErr, ErrNotFound) {
				log.Printf("certserver: failed to remove expired challenge %s: %v", token, rmErr)
			}
			audit.FromContext(r.Context()).Set(item.Requester.Gateway, []string{normHost}, audit.DecisionRefused, "challenge authorization expired")
			h.recordMetric("expired")
			http.NotFound(w, r)
			return
		}

		// 3. Challenge binding check against primary requester or candidate requesters
		authorized := registry.IsAuthorizedForwarder(h.registry, h.bindingStore, item.Requester.ClusterID, item.Requester.Gateway, item.Requester.DataPlaneServiceAccount, identity)
		matchedReq := item.Requester
		if !authorized && len(item.CandidateRequesters) > 0 {
			for _, cand := range item.CandidateRequesters {
				if registry.IsAuthorizedForwarder(h.registry, h.bindingStore, cand.ClusterID, cand.Gateway, cand.DataPlaneServiceAccount, identity) {
					authorized = true
					matchedReq = cand
					break
				}
			}
		}

		if !authorized {
			audit.FromContext(r.Context()).Set(item.Requester.Gateway, []string{normHost}, audit.DecisionRefused, fmt.Sprintf("forwarding identity %s is not authorized for requesting gateway %s in cluster %s", identity, item.Requester.Gateway, item.Requester.ClusterID))
			h.recordMetric("binding_refused")
			http.NotFound(w, r)
			return
		}

		// Challenge binding passed! Record answering identity.
		if recErr := h.store.RecordAnswer(r.Context(), token, identity); recErr != nil {
			log.Printf("certserver: failed to record answering identity for challenge %s: %v", token, recErr)
		}

		audit.FromContext(r.Context()).Set(matchedReq.Gateway, []string{normHost}, audit.DecisionAllowed, "challenge validation succeeded")
		h.recordMetric("success")

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			if _, writeErr := w.Write([]byte(item.KeyAuth)); writeErr != nil {
				log.Printf("certserver: failed to write challenge response: %v", writeErr)
				return
			}
		}
		return
	}

	// Fallback path when no registry is configured (e.g. unauthenticated unit tests)
	caller := ""
	if h.callerFunc != nil {
		caller = h.callerFunc(r)
	}

	keyAuth, err := h.resolver.ResolveChallenge(r.Context(), caller, r.Host, token)
	if err != nil {
		audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionRefused, "challenge resolution failed")
		http.NotFound(w, r)
		return
	}

	audit.FromContext(r.Context()).Set("", []string{normHost}, audit.DecisionAllowed, "challenge resolution succeeded")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		if _, writeErr := w.Write([]byte(keyAuth)); writeErr != nil {
			log.Printf("certserver: failed to write challenge response: %v", writeErr)
			return
		}
	}
}
