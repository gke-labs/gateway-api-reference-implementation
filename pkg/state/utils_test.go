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

package state

import (
	"reflect"
	"testing"
)

func TestIntersectHostnames(t *testing.T) {
	tests := []struct {
		name             string
		routeHostnames   []string
		listenerHostname string
		want             []string
	}{
		{
			name:             "empty route hostnames, empty listener hostname",
			routeHostnames:   []string{},
			listenerHostname: "",
			want:             []string{"*"},
		},
		{
			name:             "empty route hostnames, exact listener hostname",
			routeHostnames:   []string{},
			listenerHostname: "foo.com",
			want:             []string{"foo.com"},
		},
		{
			name:             "empty route hostnames, wildcard listener hostname",
			routeHostnames:   []string{},
			listenerHostname: "*.foo.com",
			want:             []string{"*.foo.com"},
		},
		{
			name:             "exact route hostname matches exact listener hostname",
			routeHostnames:   []string{"foo.com"},
			listenerHostname: "foo.com",
			want:             []string{"foo.com"},
		},
		{
			name:             "exact route hostname mismatches exact listener hostname",
			routeHostnames:   []string{"foo.com"},
			listenerHostname: "bar.com",
			want:             nil,
		},
		{
			name:             "exact route hostname matches wildcard listener hostname",
			routeHostnames:   []string{"a.foo.com"},
			listenerHostname: "*.foo.com",
			want:             []string{"a.foo.com"},
		},
		{
			name:             "wildcard route hostname matches exact listener hostname",
			routeHostnames:   []string{"*.foo.com"},
			listenerHostname: "a.foo.com",
			want:             []string{"a.foo.com"},
		},
		{
			name:             "wildcard route hostname matches wildcard listener hostname (same)",
			routeHostnames:   []string{"*.foo.com"},
			listenerHostname: "*.foo.com",
			want:             []string{"*.foo.com"},
		},
		{
			name:             "wildcard route hostname matches wildcard listener hostname (subset)",
			routeHostnames:   []string{"*.a.foo.com"},
			listenerHostname: "*.foo.com",
			want:             []string{"*.a.foo.com"},
		},
		{
			name:             "wildcard route hostname matches wildcard listener hostname (superset)",
			routeHostnames:   []string{"*.foo.com"},
			listenerHostname: "*.a.foo.com",
			want:             []string{"*.a.foo.com"},
		},
		{
			name:             "multiple route hostnames, some match",
			routeHostnames:   []string{"a.foo.com", "b.bar.com"},
			listenerHostname: "*.foo.com",
			want:             []string{"a.foo.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IntersectHostnames(tt.routeHostnames, tt.listenerHostname); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IntersectHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			origin:  "http://example.com",
			pattern: "http://example.com",
			want:    true,
		},
		{
			name:    "case insensitive host match",
			origin:  "http://ExAmPle.com",
			pattern: "http://example.com",
			want:    true,
		},
		{
			name:    "overlapping wildcard match rejected",
			origin:  "http://foo.com",
			pattern: "http://foo*foo.com",
			want:    false,
		},
		{
			name:    "mismatch scheme",
			origin:  "https://example.com",
			pattern: "http://example.com",
			want:    false,
		},
		{
			name:    "mismatch host",
			origin:  "http://foo.com",
			pattern: "http://bar.com",
			want:    false,
		},
		{
			name:    "wildcard subdomain",
			origin:  "http://foo.example.com",
			pattern: "http://*.example.com",
			want:    true,
		},
		{
			name:    "wildcard subdomain deep",
			origin:  "http://a.b.example.com",
			pattern: "http://*.example.com",
			want:    true,
		},
		{
			name:    "wildcard only host",
			origin:  "http://anything.com",
			pattern: "http://*",
			want:    true,
		},
		{
			name:    "port match",
			origin:  "http://example.com:8080",
			pattern: "http://example.com:8080",
			want:    true,
		},
		{
			name:    "port mismatch",
			origin:  "http://example.com:8080",
			pattern: "http://example.com:8081",
			want:    false,
		},
		{
			name:    "standalone wildcard",
			origin:  "http://example.com",
			pattern: "*",
			want:    true,
		},
		{
			name:    "multiple wildcards regex escaping",
			origin:  "http://a.b.example.com",
			pattern: "http://*.*.example.com",
			want:    true,
		},
		{
			name:    "multiple wildcards regex escaping no dot match",
			origin:  "http://abexample.com",
			pattern: "http://*.*.example.com",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchOrigin(tt.origin, tt.pattern); got != tt.want {
				t.Errorf("MatchOrigin(%q, %q) = %v, want %v", tt.origin, tt.pattern, got, tt.want)
			}
		})
	}
}
