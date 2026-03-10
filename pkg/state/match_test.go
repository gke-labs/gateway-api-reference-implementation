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
		expectedHost string
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-prefix"}, Weight: 1}},
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-exact"}, Weight: 1}},
						},
					},
				},
			},
			path:         "/match/exact",
			expectedHost: "backend-exact",
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-short"}, Weight: 1}},
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-long"}, Weight: 1}},
						},
					},
				},
			},
			path:         "/match/prefix/one/any",
			expectedHost: "backend-long",
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-1"}, Weight: 1}},
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-2"}, Weight: 1}},
						},
					},
				},
			},
			path:         "/match",
			expectedHost: "backend-1",
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-A"}, Weight: 1}},
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
							Backends: []InternalWeightedBackend{{InternalBackend: InternalBackend{Host: "backend-B"}, Weight: 1}},
						},
					},
				},
			},
			path:         "/match",
			expectedHost: "backend-A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", tt.path, nil)
			bestRule, _ := MatchRoute(tt.routes, r)

			if bestRule == nil {
				t.Fatalf("Expected a match, but got nil")
			}

			if len(bestRule.Backends) == 0 {
				t.Fatalf("Expected backends, but got none")
			}

			if bestRule.Backends[0].Host != tt.expectedHost {
				t.Errorf("Expected backend %s, but got %s", tt.expectedHost, bestRule.Backends[0].Host)
			}
		})
	}
}
