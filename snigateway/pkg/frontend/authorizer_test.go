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
	"strings"
	"testing"
)

func TestMatchHostnamePattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		// Wildcard *
		{
			name:     "star matches exact domain",
			pattern:  "*",
			hostname: "example.com",
			want:     true,
		},
		{
			name:     "star matches subdomain",
			pattern:  "*",
			hostname: "foo.bar.example.com",
			want:     true,
		},
		{
			name:     "star matches wildcard hostname",
			pattern:  "*",
			hostname: "*.example.com",
			want:     true,
		},

		// Exact pattern
		{
			name:     "exact match",
			pattern:  "foo.example.com",
			hostname: "foo.example.com",
			want:     true,
		},
		{
			name:     "exact match with case insensitivity and port",
			pattern:  "FOO.EXAMPLE.COM",
			hostname: "foo.example.com:443",
			want:     true,
		},
		{
			name:     "exact pattern mismatch",
			pattern:  "foo.example.com",
			hostname: "bar.example.com",
			want:     false,
		},
		{
			name:     "exact pattern does not match parent domain",
			pattern:  "foo.example.com",
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "exact pattern does not match subdomain",
			pattern:  "foo.example.com",
			hostname: "sub.foo.example.com",
			want:     false,
		},
		{
			name:     "exact pattern does not match wildcard",
			pattern:  "foo.example.com",
			hostname: "*.foo.example.com",
			want:     false,
		},

		// Wildcard pattern *.example.com
		{
			name:     "wildcard pattern matches single-label subdomain",
			pattern:  "*.example.com",
			hostname: "bar.example.com",
			want:     true,
		},
		{
			name:     "wildcard pattern matches wildcard registration itself",
			pattern:  "*.example.com",
			hostname: "*.example.com",
			want:     true,
		},
		{
			name:     "wildcard pattern with port and uppercase",
			pattern:  "*.EXAMPLE.COM",
			hostname: "BAR.EXAMPLE.COM:8443",
			want:     true,
		},
		{
			name:     "wildcard pattern does not match apex domain",
			pattern:  "*.example.com",
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "wildcard pattern does not match multi-label subdomain",
			pattern:  "*.example.com",
			hostname: "a.b.example.com",
			want:     false,
		},
		{
			name:     "wildcard pattern does not match different domain suffix",
			pattern:  "*.example.com",
			hostname: "bar.example.org",
			want:     false,
		},
		{
			name:     "empty pattern or hostname",
			pattern:  "",
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "pattern with empty hostname",
			pattern:  "*.example.com",
			hostname: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchHostnamePattern(tt.pattern, tt.hostname)
			if got != tt.want {
				t.Fatalf("MatchHostnamePattern(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
			}
		})
	}
}

func TestCAAuthorizer(t *testing.T) {
	fpA := "aabbcc112233"
	fpB := "ddeeff445566"

	authorizer := NewCAAuthorizer(map[string][]string{
		fpA: {"*.a.example.com", "a.example.org"},
		fpB: {"*.b.example.com"},
	})

	ctx := t.Context()

	t.Run("authorized single hostname", func(t *testing.T) {
		identity := ClientIdentity{CAFingerprint: fpA, CommonName: "client-a"}
		if err := authorizer.Authorize(ctx, identity, []string{"app.a.example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authorized multiple hostnames across patterns", func(t *testing.T) {
		identity := ClientIdentity{CAFingerprint: fpA, CommonName: "client-a"}
		if err := authorizer.Authorize(ctx, identity, []string{"*.a.example.com", "foo.a.example.com", "a.example.org"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("disallowed hostname for CA", func(t *testing.T) {
		identity := ClientIdentity{CAFingerprint: fpA, CommonName: "client-a"}
		err := authorizer.Authorize(ctx, identity, []string{"app.a.example.com", "app.b.example.com"})
		if err == nil {
			t.Fatal("expected authorization to fail, got nil")
		}
		if !strings.Contains(err.Error(), "disallowed hostnames: app.b.example.com") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("unregistered CA fingerprint", func(t *testing.T) {
		identity := ClientIdentity{CAFingerprint: "unknown-ca", CommonName: "client-unknown"}
		err := authorizer.Authorize(ctx, identity, []string{"app.a.example.com"})
		if err == nil {
			t.Fatal("expected authorization to fail for unknown CA")
		}
		if !strings.Contains(err.Error(), "disallowed hostnames: app.a.example.com") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("wildcard star authorizer", func(t *testing.T) {
		wildcardAuth := NewCAAuthorizer(map[string][]string{
			fpA: {"*"},
		})
		identity := ClientIdentity{CAFingerprint: fpA, CommonName: "client-a"}
		if err := wildcardAuth.Authorize(ctx, identity, []string{"anything.com", "foo.bar.org", "*.sub.net"}); err != nil {
			t.Fatalf("unexpected error with wildcard star authorizer: %v", err)
		}
	})
}

func TestSubjectAuthorizer(t *testing.T) {
	ctx := t.Context()

	rule1, err := ParseSubjectRule("system:serviceaccount:prod:snigateway-agent=*.prod.example.com,app.prod.example.com")
	if err != nil {
		t.Fatalf("ParseSubjectRule failed: %v", err)
	}
	rule2, err := ParseSubjectRule("system:serviceaccount:staging:*=*.staging.example.com")
	if err != nil {
		t.Fatalf("ParseSubjectRule failed: %v", err)
	}

	authorizer := NewSubjectAuthorizer([]SubjectRule{rule1, rule2})

	t.Run("authorized exact SA subject", func(t *testing.T) {
		identity := ClientIdentity{
			ID:      "jwt/https://issuer/system:serviceaccount:prod:snigateway-agent",
			Subject: "system:serviceaccount:prod:snigateway-agent",
		}
		if err := authorizer.Authorize(ctx, identity, []string{"foo.prod.example.com", "app.prod.example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("authorized namespace wildcard <ns>:* rule", func(t *testing.T) {
		identity := ClientIdentity{
			ID:      "jwt/https://issuer/system:serviceaccount:staging:any-agent",
			Subject: "system:serviceaccount:staging:any-agent",
		}
		if err := authorizer.Authorize(ctx, identity, []string{"foo.staging.example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("disallowed hostname for matching subject", func(t *testing.T) {
		identity := ClientIdentity{
			ID:      "jwt/https://issuer/system:serviceaccount:prod:snigateway-agent",
			Subject: "system:serviceaccount:prod:snigateway-agent",
		}
		err := authorizer.Authorize(ctx, identity, []string{"foo.prod.example.com", "disallowed.example.com"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "disallowed hostnames: disallowed.example.com") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("subject not in rules", func(t *testing.T) {
		identity := ClientIdentity{
			ID:      "jwt/https://issuer/system:serviceaccount:other-ns:sa",
			Subject: "system:serviceaccount:other-ns:sa",
		}
		err := authorizer.Authorize(ctx, identity, []string{"foo.prod.example.com"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "disallowed hostnames: foo.prod.example.com") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestCombinedAuthorizer(t *testing.T) {
	ctx := t.Context()

	caAuth := NewCAAuthorizer(map[string][]string{
		"ca1": {"*.ca.example.com"},
	})
	subjRule, _ := ParseSubjectRule("system:serviceaccount:ns1:sa1=*.jwt.example.com")
	subjAuth := NewSubjectAuthorizer([]SubjectRule{subjRule})

	combined := NewCombinedAuthorizer(caAuth, subjAuth)

	t.Run("cert identity uses ca rules", func(t *testing.T) {
		certID := ClientIdentity{CAFingerprint: "ca1", CommonName: "client"}
		if err := combined.Authorize(ctx, certID, []string{"app.ca.example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Must not be allowed for jwt pattern
		if err := combined.Authorize(ctx, certID, []string{"app.jwt.example.com"}); err == nil {
			t.Fatal("expected error: ca rule should not be widened by subject rule")
		}
	})

	t.Run("jwt identity uses subject rules", func(t *testing.T) {
		jwtID := ClientIdentity{Subject: "system:serviceaccount:ns1:sa1"}
		if err := combined.Authorize(ctx, jwtID, []string{"app.jwt.example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Must not be allowed for ca pattern
		if err := combined.Authorize(ctx, jwtID, []string{"app.ca.example.com"}); err == nil {
			t.Fatal("expected error: subject rule should not be widened by ca rule")
		}
	})
}

func TestParseSubjectRule(t *testing.T) {
	t.Run("valid rule without issuer", func(t *testing.T) {
		rule, err := ParseSubjectRule("system:serviceaccount:default:sa=*.example.com,app.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rule.Issuer != "" {
			t.Fatalf("expected empty issuer, got %q", rule.Issuer)
		}
		if rule.Namespace != "default" || rule.ServiceAccount != "sa" {
			t.Fatalf("expected default:sa, got %s:%s", rule.Namespace, rule.ServiceAccount)
		}
		if len(rule.Patterns) != 2 || rule.Patterns[0] != "*.example.com" || rule.Patterns[1] != "app.example.com" {
			t.Fatalf("unexpected patterns: %v", rule.Patterns)
		}
	})

	t.Run("valid rule with issuer", func(t *testing.T) {
		rule, err := ParseSubjectRule("https://kubernetes.default.svc|system:serviceaccount:prod:controller=*.prod.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rule.Issuer != "https://kubernetes.default.svc" {
			t.Fatalf("expected issuer https://kubernetes.default.svc, got %q", rule.Issuer)
		}
		if rule.Namespace != "prod" || rule.ServiceAccount != "controller" {
			t.Fatalf("expected prod:controller, got %s:%s", rule.Namespace, rule.ServiceAccount)
		}
		if len(rule.Patterns) != 1 || rule.Patterns[0] != "*.prod.example.com" {
			t.Fatalf("unexpected patterns: %v", rule.Patterns)
		}
	})

	t.Run("empty issuer with pipe rejected", func(t *testing.T) {
		_, err := ParseSubjectRule("|system:serviceaccount:default:sa=*.example.com")
		if err == nil || !strings.Contains(err.Error(), "issuer cannot be empty") {
			t.Fatalf("expected issuer cannot be empty error, got: %v", err)
		}
	})

	t.Run("missing subject prefix rejected", func(t *testing.T) {
		_, err := ParseSubjectRule("https://issuer|other:sa=*.example.com")
		if err == nil || !strings.Contains(err.Error(), "must begin with") {
			t.Fatalf("expected must begin with prefix error, got: %v", err)
		}
	})
}

func TestSubjectAuthorizer_IssuerScoping(t *testing.T) {
	ctx := t.Context()

	rule1, err := ParseSubjectRule("https://cluster1.example.com|system:serviceaccount:default:controller=*.cluster1.com")
	if err != nil {
		t.Fatalf("ParseSubjectRule failed: %v", err)
	}
	rule2, err := ParseSubjectRule("https://cluster2.example.com/|system:serviceaccount:default:controller=*.cluster2.com")
	if err != nil {
		t.Fatalf("ParseSubjectRule failed: %v", err)
	}

	authorizer := NewSubjectAuthorizer([]SubjectRule{rule1, rule2})

	t.Run("token from cluster2 cannot register cluster1 hostnames", func(t *testing.T) {
		identity := ClientIdentity{
			Issuer:  "https://cluster2.example.com",
			Subject: "system:serviceaccount:default:controller",
		}
		err := authorizer.Authorize(ctx, identity, []string{"app.cluster1.com"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "disallowed hostnames: app.cluster1.com") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("token from cluster1 can register cluster1 hostnames", func(t *testing.T) {
		identity := ClientIdentity{
			Issuer:  "https://cluster1.example.com",
			Subject: "system:serviceaccount:default:controller",
		}
		if err := authorizer.Authorize(ctx, identity, []string{"app.cluster1.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("token from cluster2 can register cluster2 hostnames with normalized issuer trailing slash", func(t *testing.T) {
		identity := ClientIdentity{
			Issuer:  "https://cluster2.example.com",
			Subject: "system:serviceaccount:default:controller",
		}
		if err := authorizer.Authorize(ctx, identity, []string{"app.cluster2.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("token from cluster3 cannot register either", func(t *testing.T) {
		identity := ClientIdentity{
			Issuer:  "https://cluster3.example.com",
			Subject: "system:serviceaccount:default:controller",
		}
		if err := authorizer.Authorize(ctx, identity, []string{"app.cluster1.com"}); err == nil {
			t.Fatal("expected error for cluster3 token")
		}
	})
}
