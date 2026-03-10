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

package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestProxyRewrite(t *testing.T) {
	tests := []struct {
		name         string
		rewrite      state.InternalRewrite
		match        *state.InternalMatch
		initialPath  string
		initialHost  string
		expectedPath string
		expectedHost string
	}{
		{
			name: "host rewrite",
			rewrite: state.InternalRewrite{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("new.example.com")),
			},
			initialHost:  "old.example.com",
			expectedHost: "new.example.com",
			initialPath:  "/foo",
			expectedPath: "/foo",
		},
		{
			name: "full path rewrite",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.FullPathHTTPPathModifier,
					Value: "/new-path",
				},
			},
			initialHost:  "example.com",
			expectedHost: "example.com",
			initialPath:  "/old-path",
			expectedPath: "/new-path",
		},
		{
			name: "prefix path rewrite",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.PrefixMatchHTTPPathModifier,
					Value: "/new-prefix",
				},
			},
			match: &state.InternalMatch{
				Path: &state.InternalPathMatch{
					Type:  gatewayv1.PathMatchPathPrefix,
					Value: "/old-prefix",
				},
			},
			initialHost:  "example.com",
			expectedHost: "example.com",
			initialPath:  "/old-prefix/suffix",
			expectedPath: "/new-prefix/suffix",
		},
	}

	p := NewProxy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.initialHost+tt.initialPath, nil)
			req.Host = tt.initialHost

			p.rewrite(req, tt.rewrite, tt.match)

			if req.Host != tt.expectedHost {
				t.Errorf("expected host %s, got %s", tt.expectedHost, req.Host)
			}
			if req.URL.Path != tt.expectedPath {
				t.Errorf("expected path %s, got %s", tt.expectedPath, req.URL.Path)
			}
		})
	}
}
