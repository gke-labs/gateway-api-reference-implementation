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
	"net/http"
	"net/url"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestApplyRewrite(t *testing.T) {
	tests := []struct {
		name        string
		rewrite     state.InternalRewrite
		match       *state.InternalMatch
		initialPath string
		initialHost string
		wantPath    string
		wantHost    string
	}{
		{
			name: "full path rewrite",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.FullPathHTTPPathModifier,
					Value: "/new-path",
				},
			},
			initialPath: "/old-path",
			wantPath:    "/new-path",
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
			initialPath: "/old-prefix/something",
			wantPath:    "/new-prefix/something",
		},
		{
			name: "hostname rewrite",
			rewrite: state.InternalRewrite{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("new.example.com")),
			},
			initialHost: "old.example.com",
			wantHost:    "new.example.com",
		},
		{
			name: "hostname rewrite with port",
			rewrite: state.InternalRewrite{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("new.example.com")),
			},
			initialHost: "old.example.com:8080",
			wantHost:    "new.example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{}
			u, _ := url.Parse("http://example.com" + tt.initialPath)
			r := &http.Request{
				URL:  u,
				Host: tt.initialHost,
			}
			if r.Host == "" {
				r.Host = "example.com"
			}

			p.applyRewrite(r, tt.rewrite, tt.match)

			if r.URL.Path != tt.wantPath && tt.wantPath != "" {
				t.Errorf("applyRewrite() path = %v, want %v", r.URL.Path, tt.wantPath)
			}
			if r.Host != tt.wantHost && tt.wantHost != "" {
				t.Errorf("applyRewrite() host = %v, want %v", r.Host, tt.wantHost)
			}
		})
	}
}
