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
	"net/http"
	"regexp"
	"testing"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestMatchRouteOrder(t *testing.T) {
	tests := []struct {
		name         string
		routes       []InternalRoute
		path         string
		expectedRule *InternalRule
	}{
		{
			name: "Exact vs Prefix",
			routes: []InternalRoute{
				{
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-prefix"}},
						},
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchExact,
										Value: "/match/exact",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-exact"}},
						},
					},
				},
			},
			path: "/match/exact",
			expectedRule: &InternalRule{
				Backends: []InternalBackend{{Host: "backend-exact"}},
			},
		},
		{
			name: "Longest Prefix wins",
			routes: []InternalRoute{
				{
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match/prefix",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-short"}},
						},
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match/prefix/one",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-long"}},
						},
					},
				},
			},
			path: "/match/prefix/one/any",
			expectedRule: &InternalRule{
				Backends: []InternalBackend{{Host: "backend-long"}},
			},
		},
		{
			name: "First rule wins on tie",
			routes: []InternalRoute{
				{
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-1"}},
						},
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-2"}},
						},
					},
				},
			},
			path: "/match",
			expectedRule: &InternalRule{
				Backends: []InternalBackend{{Host: "backend-1"}},
			},
		},
		{
			name: "First route wins on tie across routes",
			routes: []InternalRoute{
				{
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-A"}},
						},
					},
				},
				{
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/match",
									},
								},
							},
							Backends: []InternalBackend{{Host: "backend-B"}},
						},
					},
				},
			},
			path: "/match",
			expectedRule: &InternalRule{
				Backends: []InternalBackend{{Host: "backend-A"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", tt.path, nil)
			bestRule, _ := MatchRoute(tt.routes, r)

			if bestRule == nil {
				t.Fatalf("Expected a match, but got nil")
			}

			if len(bestRule.Backends) == 0 || len(tt.expectedRule.Backends) == 0 || bestRule.Backends[0].Host != tt.expectedRule.Backends[0].Host {
				t.Errorf("Expected backend %v, but got %v", tt.expectedRule.Backends, bestRule.Backends)
			}
		})
	}
}

func TestMatchRoute_MethodVsHeaderPrecedence(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("example.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Method: Ptr(gatewayv1.HTTPMethod("PATCH")),
						},
					},
					Backends: []InternalBackend{{Host: "method-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Headers: []InternalHeaderMatch{
								{
									Name:            "version",
									MatchExactValue: "four",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "header-backend"}},
				},
			},
		},
	}

	req, _ := http.NewRequest("PATCH", "http://example.com/", nil)
	req.Header.Set("version", "four")

	rule, _ := MatchRoute(routes, req)
	if rule == nil {
		t.Fatalf("Expected match, got nil")
	}
	if len(rule.Backends) == 0 || rule.Backends[0].Host != "method-backend" {
		t.Errorf("Expected method match (method-backend) to take precedence over header match (header-backend), got %v", rule.Backends)
	}
}

func TestMatchRoute_HeaderMatching(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("example.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Headers: []InternalHeaderMatch{
								{
									Name:            "X-Header-One",
									MatchExactValue: "val1",
								},
								{
									Name:            "X-Header-Two",
									MatchExactValue: "val2",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "two-headers-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Headers: []InternalHeaderMatch{
								{
									Name:            "X-Header-One",
									MatchExactValue: "val1",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "one-header-backend"}},
				},
			},
		},
	}

	// 1. Single header match
	req1, _ := http.NewRequest("GET", "http://example.com/", nil)
	req1.Header.Set("X-Header-One", "val1")
	rule1, _ := MatchRoute(routes, req1)
	if rule1 == nil || len(rule1.Backends) == 0 || rule1.Backends[0].Host != "one-header-backend" {
		t.Errorf("Expected single header match, got %v", rule1)
	}

	// 2. Multiple headers match - more headers win
	req2, _ := http.NewRequest("GET", "http://example.com/", nil)
	req2.Header.Set("x-header-one", "val1") // test case insensitivity
	req2.Header.Set("X-Header-Two", "val2")
	rule2, _ := MatchRoute(routes, req2)
	if rule2 == nil || len(rule2.Backends) == 0 || rule2.Backends[0].Host != "two-headers-backend" {
		t.Errorf("Expected two headers match (more headers win), got %v", rule2)
	}
}

func TestMatchRoute_HostnamePrecedence(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("*.bar.com"),
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "wildcard-bar-backend"}},
				},
			},
		},
		{
			Hostnames: routeHostnamesFromStrings("foo.bar.com"),
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "exact-foo-bar-backend"}},
				},
			},
		},
		{
			Hostnames: routeHostnamesFromStrings("*.foo.bar.com"),
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "longer-wildcard-backend"}},
				},
			},
		},
		{
			Hostnames: routeHostnamesFromStrings("*"),
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "catch-all-backend"}},
				},
			},
		},
	}

	tests := []struct {
		name            string
		host            string
		expectedBackend string
	}{
		{
			name:            "Exact hostname wins over wildcard",
			host:            "foo.bar.com",
			expectedBackend: "exact-foo-bar-backend",
		},
		{
			name:            "Exact hostname wins with port and case insensitivity",
			host:            "FOO.BAR.COM:8080",
			expectedBackend: "exact-foo-bar-backend",
		},
		{
			name:            "Longer wildcard hostname wins over shorter wildcard",
			host:            "test.foo.bar.com",
			expectedBackend: "longer-wildcard-backend",
		},
		{
			name:            "Wildcard hostname matches single prefix",
			host:            "baz.bar.com",
			expectedBackend: "wildcard-bar-backend",
		},
		{
			name:            "Wildcard hostname matches multiple prefix levels",
			host:            "multiple.prefixes.bar.com",
			expectedBackend: "wildcard-bar-backend",
		},
		{
			name:            "Catch-all matches host not matching any wildcard suffix",
			host:            "other.domain.com",
			expectedBackend: "catch-all-backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://"+tt.host+"/", nil)
			rule, _ := MatchRoute(routes, req)
			if rule == nil {
				t.Fatalf("Expected match, got nil")
			}
			if len(rule.Backends) == 0 || rule.Backends[0].Host != tt.expectedBackend {
				t.Errorf("Expected backend %s, got %v", tt.expectedBackend, rule.Backends)
			}
		})
	}
}

func TestMatchRoute_HostnamePrecedenceOverPath(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("*.bar.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/exact-path",
							},
						},
					},
					Backends: []InternalBackend{{Host: "wildcard-host-exact-path-backend"}},
				},
			},
		},
		{
			Hostnames: routeHostnamesFromStrings("foo.bar.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
						},
					},
					Backends: []InternalBackend{{Host: "exact-host-prefix-path-backend"}},
				},
			},
		},
	}

	req, _ := http.NewRequest("GET", "http://foo.bar.com/exact-path", nil)
	rule, _ := MatchRoute(routes, req)
	if rule == nil {
		t.Fatalf("Expected match, got nil")
	}
	if len(rule.Backends) == 0 || rule.Backends[0].Host != "exact-host-prefix-path-backend" {
		t.Errorf("Expected exact hostname match (exact-host-prefix-path-backend) to take precedence over wildcard host match with exact path, got %v", rule.Backends)
	}
}

func TestMatchRoute_OriginalHostnamesPrecedence(t *testing.T) {
	// Both routes attached to the same listener (abc.example.com), so their effective Hostnames are identical.
	// Route 1 was created first (so appears first in slice), but had a wildcard original hostname.
	// Route 2 had an exact original hostname.
	routes := []InternalRoute{
		{
			Hostnames: []RouteHostname{
				NewRouteHostname("abc.example.com", "*.example.com"),
			},
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "older-wildcard-backend"}},
				},
			},
		},
		{
			Hostnames: []RouteHostname{
				NewRouteHostname("abc.example.com", "abc.example.com"),
			},
			Rules: []InternalRule{
				{
					Backends: []InternalBackend{{Host: "newer-exact-backend"}},
				},
			},
		},
	}

	req, _ := http.NewRequest("GET", "http://abc.example.com/", nil)
	rule, _ := MatchRoute(routes, req)
	if rule == nil {
		t.Fatalf("Expected match, got nil")
	}
	if len(rule.Backends) == 0 || rule.Backends[0].Host != "newer-exact-backend" {
		t.Errorf("Expected exact original hostname (newer-exact-backend) to take precedence over wildcard (older-wildcard-backend), got %v", rule.Backends)
	}
}

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.wildcard.org", "third-example.wildcard.org", true},
		{"*.wildcard.org", "fourth-example.wildcard.org", true},
		{"*.wildcard.org", "sub.third.wildcard.org", true},
		{"*.wildcard.org", "wildcard.org", false},
		{"*.wildcard.org", "other.org", false},
		{"*.wildcard.org", "second-example.org", false},
		{"example.org", "example.org", false}, // not a wildcard pattern
	}

	for _, tt := range tests {
		if got := MatchesWildcard(tt.pattern, tt.host); got != tt.want {
			t.Errorf("MatchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestMatchListener(t *testing.T) {
	listeners := []InternalListener{
		{Name: "https", Hostname: "", Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "https-with-hostname", Hostname: "second-example.org", Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "https-with-wildcard-hostname", Hostname: "*.wildcard.org", Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "https-with-hostname-matching-wildcard", Hostname: "fourth-example.wildcard.org", Protocol: gatewayv1.HTTPSProtocolType},
	}

	tests := []struct {
		host      string
		wantName  string
		wantMatch MatchType
	}{
		{host: "example.org", wantName: "https", wantMatch: CatchAllMatch},
		{host: "second-example.org", wantName: "https-with-hostname", wantMatch: ExactMatch},
		{host: "third-example.wildcard.org", wantName: "https-with-wildcard-hostname", wantMatch: WildcardMatch},
		{host: "fourth-example.wildcard.org", wantName: "https-with-hostname-matching-wildcard", wantMatch: ExactMatch},
		{host: "fith-example.wildcard.org", wantName: "https-with-wildcard-hostname", wantMatch: WildcardMatch},
		{host: "unknown-example.org", wantName: "https", wantMatch: CatchAllMatch},
		{host: "", wantName: "https", wantMatch: CatchAllMatch},
	}

	for _, tt := range tests {
		l, matchType := MatchListener(listeners, tt.host)
		if l == nil {
			t.Fatalf("MatchListener(%q) returned nil, want %q", tt.host, tt.wantName)
		}
		if l.Name != tt.wantName {
			t.Errorf("MatchListener(%q) listener name = %q, want %q", tt.host, l.Name, tt.wantName)
		}
		if matchType != tt.wantMatch {
			t.Errorf("MatchListener(%q) matchType = %v, want %v", tt.host, matchType, tt.wantMatch)
		}
	}
}

func TestMatchRoute_QueryParamMatching(t *testing.T) {
	routes := []InternalRoute{
		{
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "animal",
									MatchExactValue: "whale",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "whale-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "animal",
									MatchExactValue: "dolphin",
								},
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "color",
									MatchExactValue: "blue",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "blue-dolphin-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "ANIMAL",
									MatchExactValue: "Whale",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "case-sensitive-whale-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							QueryParams: []InternalQueryParamMatch{
								{
									Type:                        gatewayv1.QueryParamMatchRegularExpression,
									Name:                        "species",
									MatchRegularExpressionValue: regexp.MustCompile("^shark-.*$"),
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "regex-shark-backend"}},
				},
			},
		},
	}

	tests := []struct {
		name            string
		url             string
		expectedBackend string
		expectMatch     bool
	}{
		{
			name:            "Exact query param match",
			url:             "http://example.com/?animal=whale",
			expectedBackend: "whale-backend",
			expectMatch:     true,
		},
		{
			name:            "Exact match with extra irrelevant param",
			url:             "http://example.com/?animal=whale&other=xyz",
			expectedBackend: "whale-backend",
			expectMatch:     true,
		},
		{
			name:            "Multiple query params match",
			url:             "http://example.com/?animal=dolphin&color=blue",
			expectedBackend: "blue-dolphin-backend",
			expectMatch:     true,
		},
		{
			name:        "Multiple query params partially match - should not match",
			url:         "http://example.com/?animal=dolphin&color=red",
			expectMatch: false,
		},
		{
			name:            "Case sensitive match",
			url:             "http://example.com/?ANIMAL=Whale",
			expectedBackend: "case-sensitive-whale-backend",
			expectMatch:     true,
		},
		{
			name:        "Case mismatch - should not match",
			url:         "http://example.com/?animal=Whale",
			expectMatch: false,
		},
		{
			name:            "Regex query param match",
			url:             "http://example.com/?species=shark-hammerhead",
			expectedBackend: "regex-shark-backend",
			expectMatch:     true,
		},
		{
			name:        "Regex query param mismatch",
			url:         "http://example.com/?species=whale-blue",
			expectMatch: false,
		},
		{
			name:            "Repeated query param in request matches first value",
			url:             "http://example.com/?animal=whale&animal=dolphin",
			expectedBackend: "whale-backend",
			expectMatch:     true,
		},
		{
			name:        "Repeated query param where first does not match",
			url:         "http://example.com/?animal=dolphin&animal=whale",
			expectMatch: false,
		},
		{
			name:        "Missing query param",
			url:         "http://example.com/",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			rule, _ := MatchRoute(routes, req)
			if !tt.expectMatch {
				if rule != nil {
					t.Fatalf("Expected no match, got backend %v", rule.Backends)
				}
				return
			}
			if rule == nil {
				t.Fatalf("Expected match, got nil")
			}
			if len(rule.Backends) == 0 || rule.Backends[0].Host != tt.expectedBackend {
				t.Errorf("Expected backend %s, got %v", tt.expectedBackend, rule.Backends)
			}
		})
	}
}

func TestMatchRoute_QueryParamPrecedence(t *testing.T) {
	methodGet := gatewayv1.HTTPMethodGet
	routes := []InternalRoute{
		{
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
						},
					},
					Backends: []InternalBackend{{Host: "no-query-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "animal",
									MatchExactValue: "whale",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "one-query-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "animal",
									MatchExactValue: "whale",
								},
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "color",
									MatchExactValue: "blue",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "two-query-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
							Headers: []InternalHeaderMatch{
								{
									Type:            gatewayv1.HeaderMatchExact,
									Name:            "version",
									MatchExactValue: "v1",
								},
							},
							QueryParams: []InternalQueryParamMatch{
								{
									Type:            gatewayv1.QueryParamMatchExact,
									Name:            "animal",
									MatchExactValue: "whale",
								},
							},
						},
					},
					Backends: []InternalBackend{{Host: "header-wins-backend"}},
				},
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
							Method: &methodGet,
						},
					},
					Backends: []InternalBackend{{Host: "method-wins-backend"}},
				},
			},
		},
	}

	// 1. One query param match wins over zero query param matches
	req1, _ := http.NewRequest("POST", "http://example.com/?animal=whale", nil)
	rule1, _ := MatchRoute(routes, req1)
	if rule1 == nil || len(rule1.Backends) == 0 || rule1.Backends[0].Host != "one-query-backend" {
		t.Errorf("Expected one-query-backend, got %v", rule1)
	}

	// 2. Two query param matches win over one query param match
	req2, _ := http.NewRequest("POST", "http://example.com/?animal=whale&color=blue", nil)
	rule2, _ := MatchRoute(routes, req2)
	if rule2 == nil || len(rule2.Backends) == 0 || rule2.Backends[0].Host != "two-query-backend" {
		t.Errorf("Expected two-query-backend, got %v", rule2)
	}

	// 3. Header match wins over query param match
	req3, _ := http.NewRequest("POST", "http://example.com/?animal=whale&color=blue", nil)
	req3.Header.Set("version", "v1")
	rule3, _ := MatchRoute(routes, req3)
	if rule3 == nil || len(rule3.Backends) == 0 || rule3.Backends[0].Host != "header-wins-backend" {
		t.Errorf("Expected header-wins-backend, got %v", rule3)
	}

	// 4. Method match wins over header / query param matches when header is absent
	req4, _ := http.NewRequest("GET", "http://example.com/?animal=whale&color=blue", nil)
	rule4, _ := MatchRoute(routes, req4)
	if rule4 == nil || len(rule4.Backends) == 0 || rule4.Backends[0].Host != "method-wins-backend" {
		t.Errorf("Expected method-wins-backend, got %v", rule4)
	}
}

func TestMatchRoute_MatchingAcrossRoutes(t *testing.T) {
	// Replicating HTTPRouteMatchingAcrossRoutes conformance test setup
	// Route 1 (matching-part1): example.com, example.net
	//   rule 1: PathPrefix / -> v1
	//   rule 2: Header version: one -> v1
	// Route 2 (matching-part2): example.com
	//   rule 1: PathPrefix /v2 -> v2
	//   rule 2: Header version: two -> v2
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("example.com", "example.net"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{Path: &InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
					},
					Backends: []InternalBackend{{Host: "infra-backend-v1"}},
				},
				{
					Matches: []InternalMatch{
						{
							Headers: []InternalHeaderMatch{
								{Name: "version", MatchExactValue: "one", Type: gatewayv1.HeaderMatchExact},
							},
						},
					},
					Backends: []InternalBackend{{Host: "infra-backend-v1"}},
				},
			},
		},
		{
			Hostnames: routeHostnamesFromStrings("example.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{Path: &InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/v2"}},
					},
					Backends: []InternalBackend{{Host: "infra-backend-v2"}},
				},
				{
					Matches: []InternalMatch{
						{
							Headers: []InternalHeaderMatch{
								{Name: "version", MatchExactValue: "two", Type: gatewayv1.HeaderMatchExact},
							},
						},
					},
					Backends: []InternalBackend{{Host: "infra-backend-v2"}},
				},
			},
		},
	}

	testCases := []struct {
		name        string
		host        string
		path        string
		headerName  string
		headerValue string
		wantBackend string
	}{
		{
			name:        "example.com / -> v1",
			host:        "example.com",
			path:        "/",
			wantBackend: "infra-backend-v1",
		},
		{
			name:        "example.com /example -> v1",
			host:        "example.com",
			path:        "/example",
			wantBackend: "infra-backend-v1",
		},
		{
			name:        "example.net /example -> v1",
			host:        "example.net",
			path:        "/example",
			wantBackend: "infra-backend-v1",
		},
		{
			name:        "example.com /example with Version: one -> v1",
			host:        "example.com",
			path:        "/example",
			headerName:  "Version",
			headerValue: "one",
			wantBackend: "infra-backend-v1",
		},
		{
			name:        "example.com /v2 -> v2",
			host:        "example.com",
			path:        "/v2",
			wantBackend: "infra-backend-v2",
		},
		{
			name:        "example.net /v2 -> v1",
			host:        "example.net",
			path:        "/v2",
			wantBackend: "infra-backend-v1",
		},
		{
			name:        "example.com /v2/example -> v2",
			host:        "example.com",
			path:        "/v2/example",
			wantBackend: "infra-backend-v2",
		},
		{
			name:        "example.com / with Version: two -> v2",
			host:        "example.com",
			path:        "/",
			headerName:  "Version",
			headerValue: "two",
			wantBackend: "infra-backend-v2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://"+tc.host+tc.path, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tc.headerName != "" {
				req.Header.Set(tc.headerName, tc.headerValue)
			}
			rule, _ := MatchRoute(routes, req)
			if rule == nil {
				t.Fatalf("MatchRoute returned nil rule")
			}
			if len(rule.Backends) == 0 || rule.Backends[0].Host != tc.wantBackend {
				t.Errorf("got backend %v, want %s", rule.Backends, tc.wantBackend)
			}
		})
	}
}
