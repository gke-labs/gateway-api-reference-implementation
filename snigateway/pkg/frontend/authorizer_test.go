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
