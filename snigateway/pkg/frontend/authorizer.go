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

package frontend

import (
	"context"
	"fmt"
	"strings"
)

// ClientIdentity represents the authenticated identity of a connecting client.
type ClientIdentity struct {
	ID            string // Unique identifier, e.g. "<ca-fingerprint>/<cn>"
	CAFingerprint string // Hex-encoded SHA256 of the root CA certificate
	CommonName    string // Client certificate CommonName
}

// Authorizer determines if a client identity is permitted to register the requested hostnames.
type Authorizer interface {
	Authorize(ctx context.Context, identity ClientIdentity, hostnames []string) error
}

// AllowAllAuthorizer allows any client to register any hostname.
type AllowAllAuthorizer struct{}

// Authorize implements Authorizer.
func (a *AllowAllAuthorizer) Authorize(ctx context.Context, identity ClientIdentity, hostnames []string) error {
	return nil
}

// MatchHostnamePattern checks whether a requested hostname matches an allowlist pattern.
//   - An exact pattern "foo.example.com" allows only "foo.example.com".
//   - A wildcard pattern "*.example.com" allows "bar.example.com" and "*.example.com" itself,
//     but not "example.com" or "a.b.example.com" (single-label wildcard semantics).
//   - A pattern of "*" allows any hostname.
func MatchHostnamePattern(pattern, hostname string) bool {
	p := CleanHostname(pattern)
	h := CleanHostname(hostname)
	if p == "" || h == "" {
		return false
	}
	if p == "*" {
		return true
	}
	if p == h {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // e.g. ".example.com"
		if strings.HasSuffix(h, suffix) {
			prefix := h[:len(h)-len(suffix)]
			if len(prefix) > 0 && !strings.Contains(prefix, ".") && prefix != "*" {
				return true
			}
		}
	}
	return false
}

// CAAuthorizer authorizes hostname registrations based on CA fingerprints and allowed hostname patterns.
type CAAuthorizer struct {
	allowedPatterns map[string][]string // CA fingerprint (lowercase hex) -> list of normalized patterns
}

// NewCAAuthorizer creates a new CAAuthorizer with the given mapping of CA fingerprint to allowed patterns.
func NewCAAuthorizer(allowed map[string][]string) *CAAuthorizer {
	normalized := make(map[string][]string)
	for fp, patterns := range allowed {
		fpLower := strings.ToLower(strings.TrimSpace(fp))
		for _, p := range patterns {
			cleanP := CleanHostname(p)
			if cleanP != "" {
				normalized[fpLower] = append(normalized[fpLower], cleanP)
			}
		}
	}
	return &CAAuthorizer{allowedPatterns: normalized}
}

// Authorize checks if all requested hostnames are covered by the allowed patterns for the client's CA.
func (a *CAAuthorizer) Authorize(ctx context.Context, identity ClientIdentity, hostnames []string) error {
	fpLower := strings.ToLower(strings.TrimSpace(identity.CAFingerprint))
	patterns, ok := a.allowedPatterns[fpLower]
	if !ok {
		return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
	}

	var disallowed []string
	for _, rawHost := range hostnames {
		h := CleanHostname(rawHost)
		if h == "" {
			continue
		}
		matched := false
		for _, pattern := range patterns {
			if MatchHostnamePattern(pattern, h) {
				matched = true
				break
			}
		}
		if !matched {
			disallowed = append(disallowed, rawHost)
		}
	}

	if len(disallowed) > 0 {
		return fmt.Errorf("disallowed hostnames: %s", strings.Join(disallowed, ", "))
	}
	return nil
}
