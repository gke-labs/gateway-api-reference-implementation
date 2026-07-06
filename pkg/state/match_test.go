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
							Backend: &InternalBackend{Host: "backend-prefix"},
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
							Backend: &InternalBackend{Host: "backend-exact"},
						},
					},
				},
			},
			path: "/match/exact",
			expectedRule: &InternalRule{
				Backend: &InternalBackend{Host: "backend-exact"},
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
							Backend: &InternalBackend{Host: "backend-short"},
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
							Backend: &InternalBackend{Host: "backend-long"},
						},
					},
				},
			},
			path: "/match/prefix/one/any",
			expectedRule: &InternalRule{
				Backend: &InternalBackend{Host: "backend-long"},
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
							Backend: &InternalBackend{Host: "backend-1"},
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
							Backend: &InternalBackend{Host: "backend-2"},
						},
					},
				},
			},
			path: "/match",
			expectedRule: &InternalRule{
				Backend: &InternalBackend{Host: "backend-1"},
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
							Backend: &InternalBackend{Host: "backend-A"},
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
							Backend: &InternalBackend{Host: "backend-B"},
						},
					},
				},
			},
			path: "/match",
			expectedRule: &InternalRule{
				Backend: &InternalBackend{Host: "backend-A"},
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

			if bestRule.Backend.Host != tt.expectedRule.Backend.Host {
				t.Errorf("Expected backend %s, but got %s", tt.expectedRule.Backend.Host, bestRule.Backend.Host)
			}
		})
	}
}

func TestMatchRoute_MethodVsHeaderPrecedence(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: []string{"example.com"},
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Method: Ptr(gatewayv1.HTTPMethod("PATCH")),
						},
					},
					Backend: &InternalBackend{Host: "method-backend"},
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
					Backend: &InternalBackend{Host: "header-backend"},
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
	if rule.Backend.Host != "method-backend" {
		t.Errorf("Expected method match (method-backend) to take precedence over header match (header-backend), got %s", rule.Backend.Host)
	}
}

func TestMatchRoute_HeaderMatching(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: []string{"example.com"},
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
					Backend: &InternalBackend{Host: "two-headers-backend"},
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
					Backend: &InternalBackend{Host: "one-header-backend"},
				},
			},
		},
	}

	// 1. Single header match
	req1, _ := http.NewRequest("GET", "http://example.com/", nil)
	req1.Header.Set("X-Header-One", "val1")
	rule1, _ := MatchRoute(routes, req1)
	if rule1 == nil || rule1.Backend.Host != "one-header-backend" {
		t.Errorf("Expected single header match, got %v", rule1)
	}

	// 2. Multiple headers match - more headers win
	req2, _ := http.NewRequest("GET", "http://example.com/", nil)
	req2.Header.Set("x-header-one", "val1") // test case insensitivity
	req2.Header.Set("X-Header-Two", "val2")
	rule2, _ := MatchRoute(routes, req2)
	if rule2 == nil || rule2.Backend.Host != "two-headers-backend" {
		t.Errorf("Expected two headers match (more headers win), got %v", rule2)
	}
}
