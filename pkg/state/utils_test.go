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

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsHTTPRoute(t *testing.T) {
	tests := []struct {
		name  string
		group *gatewayv1.Group
		kind  gatewayv1.Kind
		want  bool
	}{
		{
			name:  "nil group, HTTPRoute kind",
			group: nil,
			kind:  "HTTPRoute",
			want:  true,
		},
		{
			name:  "empty group, HTTPRoute kind",
			group: Ptr(gatewayv1.Group("")),
			kind:  "HTTPRoute",
			want:  true,
		},
		{
			name:  "standard group, HTTPRoute kind",
			group: Ptr(gatewayv1.Group("gateway.networking.k8s.io")),
			kind:  "HTTPRoute",
			want:  true,
		},
		{
			name:  "custom group, HTTPRoute kind",
			group: Ptr(gatewayv1.Group("example.com")),
			kind:  "HTTPRoute",
			want:  false,
		},
		{
			name:  "nil group, GRPCRoute kind",
			group: nil,
			kind:  "GRPCRoute",
			want:  false,
		},
		{
			name:  "standard group, TLSRoute kind",
			group: Ptr(gatewayv1.Group("gateway.networking.k8s.io")),
			kind:  "TLSRoute",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHTTPRoute(tt.group, tt.kind); got != tt.want {
				t.Errorf("IsHTTPRoute(%v, %v) = %v, want %v", tt.group, tt.kind, got, tt.want)
			}
		})
	}
}

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

func TestNoPolicyTLSBackendHosts(t *testing.T) {
	httpsProto := "https"
	httpProto := "http"

	rules := []InternalRule{
		{
			// Rule with error should be skipped
			Error: &ErrorState{HTTPMessage: "some error"},
			Backends: []InternalBackend{
				{Host: "err.example.com", AppProtocol: &httpsProto},
			},
		},
		{
			// Rule with backend without policy and backend with policy
			Backends: []InternalBackend{
				{Host: "svc1.example.com", AppProtocol: &httpsProto, TLSConfig: nil},
				{Host: "svc2.example.com", AppProtocol: &httpsProto, TLSConfig: &InternalTLSConfig{Hostname: "svc2.example.com"}},
				{Host: "svc3.example.com", AppProtocol: &httpProto, TLSConfig: nil},
				{Host: "svc1.example.com", AppProtocol: &httpsProto, TLSConfig: nil}, // duplicate
			},
			Mirrors: []InternalMirror{
				{Backend: InternalBackend{Host: "mirror1.example.com", AppProtocol: &httpsProto, TLSConfig: nil}},
				{Backend: InternalBackend{Host: "svc1.example.com", AppProtocol: &httpsProto, TLSConfig: nil}}, // duplicate across backends & mirrors
			},
		},
	}

	got := noPolicyTLSBackendHosts(rules)
	want := []string{"svc1.example.com", "mirror1.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("noPolicyTLSBackendHosts() = %v, want %v", got, want)
	}
}
