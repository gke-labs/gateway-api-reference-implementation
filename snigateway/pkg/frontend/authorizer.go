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
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
)

// ClientIdentity represents the authenticated identity of a connecting client.
type ClientIdentity struct {
	ID            string    // Unique identifier, e.g. "<ca-fingerprint>/<cn>" or "jwt/<issuer>/<sub>"
	CAFingerprint string    // Hex-encoded SHA256 of the root CA certificate
	CommonName    string    // Client certificate CommonName
	Issuer        string    // Issuer URL if authenticated via JWT
	Subject       string    // Subject (system:serviceaccount:<ns>:<sa>) if authenticated via JWT
	TokenExpiry   time.Time // Token expiration time for lease tracking
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

// SubjectRule grants hostname registration permissions to a Kubernetes ServiceAccount subject.
type SubjectRule struct {
	Issuer         string   // Issuer URL (optional during parse if not specified)
	Namespace      string   // Namespace (e.g. "default")
	ServiceAccount string   // ServiceAccount name (e.g. "my-sa") or "*" for any SA in Namespace
	Patterns       []string // Allowed hostname patterns
}

// ParseSubjectRule parses an entry in the format "[<issuer>|]system:serviceaccount:<ns>:<sa>=<pattern>[,<pattern>...]".
// "<ns>:*" is allowed for the service account part to authorize any ServiceAccount in that namespace.
func ParseSubjectRule(entry string) (SubjectRule, error) {
	subjectPattern, patternsStr, ok := strings.Cut(entry, "=")
	if !ok || subjectPattern == "" || patternsStr == "" {
		return SubjectRule{}, fmt.Errorf("invalid format %q: expected [<issuer>|]system:serviceaccount:<ns>:<sa>=<pattern>[,<pattern>...]", entry)
	}

	var issuer string
	if iss, rest, hasIssuer := strings.Cut(subjectPattern, "|"); hasIssuer {
		issuer = strings.TrimSpace(iss)
		if issuer == "" {
			return SubjectRule{}, fmt.Errorf("invalid format %q: issuer cannot be empty", entry)
		}
		subjectPattern = rest
	}

	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(subjectPattern, prefix) {
		return SubjectRule{}, fmt.Errorf("subject pattern %q must begin with %q", subjectPattern, prefix)
	}

	subRest := strings.TrimPrefix(subjectPattern, prefix)
	ns, sa, ok := strings.Cut(subRest, ":")
	if !ok || ns == "" || sa == "" {
		return SubjectRule{}, fmt.Errorf("subject pattern %q must be in format %s<ns>:<sa> (or <ns>:*)", subjectPattern, prefix)
	}

	var patterns []string
	for _, p := range strings.Split(patternsStr, ",") {
		p = strings.Trim(strings.TrimSpace(p), "'\"")
		if p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		return SubjectRule{}, fmt.Errorf("no patterns specified in %q", entry)
	}

	return SubjectRule{
		Issuer:         issuer,
		Namespace:      ns,
		ServiceAccount: sa,
		Patterns:       patterns,
	}, nil
}

// SubjectAuthorizer authorizes registrations based on JWT ServiceAccount subject rules.
type SubjectAuthorizer struct {
	rules []SubjectRule
}

// NewSubjectAuthorizer creates a SubjectAuthorizer with the provided rules.
func NewSubjectAuthorizer(rules []SubjectRule) *SubjectAuthorizer {
	var cleanRules []SubjectRule
	for _, r := range rules {
		var patterns []string
		for _, p := range r.Patterns {
			if cp := CleanHostname(p); cp != "" {
				patterns = append(patterns, cp)
			}
		}
		if len(patterns) > 0 {
			cleanRules = append(cleanRules, SubjectRule{
				Issuer:         jwt.NormalizeIssuer(r.Issuer),
				Namespace:      strings.TrimSpace(r.Namespace),
				ServiceAccount: strings.TrimSpace(r.ServiceAccount),
				Patterns:       patterns,
			})
		}
	}
	return &SubjectAuthorizer{rules: cleanRules}
}

// Authorize checks if all requested hostnames are covered by matching subject rules.
func (a *SubjectAuthorizer) Authorize(ctx context.Context, identity ClientIdentity, hostnames []string) error {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(identity.Subject, prefix) {
		return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
	}

	subRest := strings.TrimPrefix(identity.Subject, prefix)
	tokenNS, tokenSA, ok := strings.Cut(subRest, ":")
	if !ok || tokenNS == "" || tokenSA == "" {
		return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
	}

	identityIssuer := jwt.NormalizeIssuer(identity.Issuer)

	var allowedPatterns []string
	for _, rule := range a.rules {
		if rule.Issuer != "" && rule.Issuer != identityIssuer {
			continue
		}
		if rule.Namespace == tokenNS && (rule.ServiceAccount == "*" || rule.ServiceAccount == tokenSA) {
			allowedPatterns = append(allowedPatterns, rule.Patterns...)
		}
	}

	if len(allowedPatterns) == 0 {
		return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
	}

	var disallowed []string
	for _, rawHost := range hostnames {
		h := CleanHostname(rawHost)
		if h == "" {
			continue
		}
		matched := false
		for _, pattern := range allowedPatterns {
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

// CombinedAuthorizer routes authorization requests to CAAuthorizer for certificate identities
// and SubjectAuthorizer for JWT identities. A subject rule never widens a certificate rule and vice versa.
type CombinedAuthorizer struct {
	caAuthorizer      Authorizer
	subjectAuthorizer Authorizer
}

// NewCombinedAuthorizer creates a new CombinedAuthorizer.
func NewCombinedAuthorizer(caAuth, subjectAuth Authorizer) *CombinedAuthorizer {
	return &CombinedAuthorizer{
		caAuthorizer:      caAuth,
		subjectAuthorizer: subjectAuth,
	}
}

// Authorize delegates to SubjectAuthorizer for JWT identities and CAAuthorizer for cert identities.
func (a *CombinedAuthorizer) Authorize(ctx context.Context, identity ClientIdentity, hostnames []string) error {
	if identity.Subject != "" {
		if a.subjectAuthorizer == nil {
			return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
		}
		return a.subjectAuthorizer.Authorize(ctx, identity, hostnames)
	}

	if a.caAuthorizer != nil {
		return a.caAuthorizer.Authorize(ctx, identity, hostnames)
	}

	return fmt.Errorf("disallowed hostnames: %s", strings.Join(hostnames, ", "))
}
