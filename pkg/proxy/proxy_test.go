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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func testRouteHostnames(hostnames ...string) []state.RouteHostname {
	out := make([]state.RouteHostname, len(hostnames))
	for i, h := range hostnames {
		out[i] = state.NewRouteHostname(h, h)
	}
	return out
}

func TestProxyRewrite(t *testing.T) {
	tests := []struct {
		name            string
		rewrite         state.InternalRewrite
		match           *state.InternalMatch
		initialPath     string
		initialRawPath  string
		initialHost     string
		expectedPath    string
		expectedRawPath string
		expectedHost    string
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
			name: "full path rewrite with encoded path",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.FullPathHTTPPathModifier,
					Value: "/new-path",
				},
			},
			initialHost:     "example.com",
			expectedHost:    "example.com",
			initialPath:     "/old path",
			initialRawPath:  "/old%20path",
			expectedPath:    "/new-path",
			expectedRawPath: "",
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
		{
			name: "prefix path rewrite strip prefix with subpath",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.PrefixMatchHTTPPathModifier,
					Value: "/",
				},
			},
			match: &state.InternalMatch{
				Path: &state.InternalPathMatch{
					Type:  gatewayv1.PathMatchPathPrefix,
					Value: "/strip-prefix",
				},
			},
			initialHost:  "example.com",
			expectedHost: "example.com",
			initialPath:  "/strip-prefix/three",
			expectedPath: "/three",
		},
		{
			name: "prefix path rewrite strip prefix exact match",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.PrefixMatchHTTPPathModifier,
					Value: "/",
				},
			},
			match: &state.InternalMatch{
				Path: &state.InternalPathMatch{
					Type:  gatewayv1.PathMatchPathPrefix,
					Value: "/strip-prefix",
				},
			},
			initialHost:  "example.com",
			expectedHost: "example.com",
			initialPath:  "/strip-prefix",
			expectedPath: "/",
		},
		{
			name: "prefix path rewrite with missing match (default /)",
			rewrite: state.InternalRewrite{
				Path: &state.InternalPathRewrite{
					Type:  gatewayv1.PrefixMatchHTTPPathModifier,
					Value: "/new-root",
				},
			},
			match:        nil, // simulates omitted match
			initialHost:  "example.com",
			expectedHost: "example.com",
			initialPath:  "/some/path",
			expectedPath: "/new-root/some/path",
		},
		{
			name: "prefix path rewrite with encoded path",
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
			initialHost:     "example.com",
			expectedHost:    "example.com",
			initialPath:     "/old-prefix/some path",
			initialRawPath:  "/old-prefix/some%20path",
			expectedPath:    "/new-prefix/some path",
			expectedRawPath: "",
		},
	}

	p := NewProxy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetPath := tt.initialPath
			if tt.initialRawPath != "" {
				targetPath = tt.initialRawPath
			}
			req := httptest.NewRequest("GET", "http://"+tt.initialHost+targetPath, nil)
			req.Host = tt.initialHost
			if tt.initialRawPath != "" {
				// double check RawPath is set correctly by httptest
				req.URL.RawPath = tt.initialRawPath
			}

			req = p.rewrite(req, tt.rewrite, tt.match)

			if req.Host != tt.expectedHost {
				t.Errorf("expected host %s, got %s", tt.expectedHost, req.Host)
			}
			if req.URL.Path != tt.expectedPath {
				t.Errorf("expected path %s, got %s", tt.expectedPath, req.URL.Path)
			}
			if req.URL.RawPath != tt.expectedRawPath {
				t.Errorf("expected RawPath %q, got %q", tt.expectedRawPath, req.URL.RawPath)
			}
		})
	}
}

func TestProxyModifyHeaders(t *testing.T) {
	tests := []struct {
		name           string
		modifier       gatewayv1.HTTPHeaderFilter
		initialHeaders map[string][]string
		expectedHeader map[string][]string
	}{
		{
			name: "add set and remove headers",
			modifier: gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{
					{Name: "X-Header-Set", Value: "newValue"},
				},
				Add: []gatewayv1.HTTPHeader{
					{Name: "X-Header-Add", Value: "addedValue"},
				},
				Remove: []string{"X-Header-Remove"},
			},
			initialHeaders: map[string][]string{
				"X-Header-Set":    {"oldValue"},
				"X-Header-Add":    {"existingValue"},
				"X-Header-Remove": {"toRemove"},
			},
			expectedHeader: map[string][]string{
				"X-Header-Set": {"newValue"},
				"X-Header-Add": {"existingValue", "addedValue"},
			},
		},
	}

	p := NewProxy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			for k, values := range tt.initialHeaders {
				for _, v := range values {
					req.Header.Add(k, v)
				}
			}

			p.modifyHeaders(req, tt.modifier)

			for k, expectedValues := range tt.expectedHeader {
				actualValues := req.Header[k]
				if len(actualValues) != len(expectedValues) {
					t.Fatalf("expected header %s to have values %v, got %v", k, expectedValues, actualValues)
				}
				for i, ev := range expectedValues {
					if actualValues[i] != ev {
						t.Errorf("expected header %s[%d] to be %q, got %q", k, i, ev, actualValues[i])
					}
				}
			}

			for _, removed := range tt.modifier.Remove {
				if len(req.Header[removed]) > 0 {
					t.Errorf("expected header %s to be removed, but still has values %v", removed, req.Header[removed])
				}
			}
		})
	}
}

func TestProxyRedirect(t *testing.T) {
	tests := []struct {
		name             string
		redirect         state.InternalRedirect
		match            *state.InternalMatch
		initialURL       string
		initialHost      string
		expectedStatus   int
		expectedLocation string
	}{
		{
			name: "303 redirect status code default path and host",
			redirect: state.InternalRedirect{
				StatusCode: state.Ptr(303),
			},
			initialURL:       "http://example.com/see-other",
			initialHost:      "example.com",
			expectedStatus:   303,
			expectedLocation: "http://example.com/see-other",
		},
		{
			name: "307 redirect status code default path and host",
			redirect: state.InternalRedirect{
				StatusCode: state.Ptr(307),
			},
			initialURL:       "http://example.com/temporary",
			initialHost:      "example.com",
			expectedStatus:   307,
			expectedLocation: "http://example.com/temporary",
		},
		{
			name: "308 redirect status code default path and host",
			redirect: state.InternalRedirect{
				StatusCode: state.Ptr(308),
			},
			initialURL:       "http://example.com/permanent",
			initialHost:      "example.com",
			expectedStatus:   308,
			expectedLocation: "http://example.com/permanent",
		},
		{
			name: "302 default status code with hostname redirect",
			redirect: state.InternalRedirect{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("example.org")),
			},
			initialURL:       "http://example.com/hostname-redirect",
			initialHost:      "example.com",
			expectedStatus:   302,
			expectedLocation: "http://example.org/hostname-redirect",
		},
		{
			name: "301 redirect with host and status code",
			redirect: state.InternalRedirect{
				Hostname:   state.Ptr(gatewayv1.PreciseHostname("example.org")),
				StatusCode: state.Ptr(301),
			},
			initialURL:       "http://example.com/host-and-status",
			initialHost:      "example.com",
			expectedStatus:   301,
			expectedLocation: "http://example.org/host-and-status",
		},
		{
			name: "redirect with full path",
			redirect: state.InternalRedirect{
				StatusCode: state.Ptr(302),
				Path: &state.InternalPathRedirect{
					Type:  gatewayv1.FullPathHTTPPathModifier,
					Value: "/full-path-replacement",
				},
			},
			initialURL:       "http://example.com/full/path/original",
			initialHost:      "example.com",
			expectedStatus:   302,
			expectedLocation: "http://example.com/full-path-replacement",
		},
		{
			name: "redirect with prefix path replacement",
			redirect: state.InternalRedirect{
				StatusCode: state.Ptr(302),
				Path: &state.InternalPathRedirect{
					Type:  gatewayv1.PrefixMatchHTTPPathModifier,
					Value: "/replacement-prefix",
				},
			},
			match: &state.InternalMatch{
				Path: &state.InternalPathMatch{
					Type:  gatewayv1.PathMatchPathPrefix,
					Value: "/original-prefix",
				},
			},
			initialURL:       "http://example.com/original-prefix/lemon",
			initialHost:      "example.com",
			expectedStatus:   302,
			expectedLocation: "http://example.com/replacement-prefix/lemon",
		},
		{
			name: "redirect with port override",
			redirect: state.InternalRedirect{
				Port: state.Ptr(gatewayv1.PortNumber(8083)),
			},
			initialURL:       "http://example.com/port",
			initialHost:      "example.com",
			expectedStatus:   302,
			expectedLocation: "http://example.com:8083/port",
		},
		{
			name: "redirect with scheme https and port 443 omitted",
			redirect: state.InternalRedirect{
				Scheme:   state.Ptr("https"),
				Hostname: state.Ptr(gatewayv1.PreciseHostname("example.org")),
				Port:     state.Ptr(gatewayv1.PortNumber(443)),
			},
			initialURL:       "http://example.com/scheme",
			initialHost:      "example.com",
			expectedStatus:   302,
			expectedLocation: "https://example.org/scheme",
		},
		{
			name: "redirect with scheme https and port nil omits port even if request had port 8080",
			redirect: state.InternalRedirect{
				Scheme:   state.Ptr("https"),
				Hostname: state.Ptr(gatewayv1.PreciseHostname("example.org")),
			},
			initialURL:       "http://example.com:8080/scheme",
			initialHost:      "example.com:8080",
			expectedStatus:   302,
			expectedLocation: "https://example.org/scheme",
		},
		{
			name: "redirect with scheme nil inherits request port 8080",
			redirect: state.InternalRedirect{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("example.org")),
			},
			initialURL:       "http://example.com:8080/scheme-nil-and-port-nil",
			initialHost:      "example.com:8080",
			expectedStatus:   302,
			expectedLocation: "http://example.org:8080/scheme-nil-and-port-nil",
		},
		{
			name: "redirect with scheme nil and explicit port 80 omits port 80",
			redirect: state.InternalRedirect{
				Hostname: state.Ptr(gatewayv1.PreciseHostname("example.org")),
				Port:     state.Ptr(gatewayv1.PortNumber(80)),
			},
			initialURL:       "http://example.com:8080/scheme-nil-and-port-80",
			initialHost:      "example.com:8080",
			expectedStatus:   302,
			expectedLocation: "http://example.org/scheme-nil-and-port-80",
		},
		{
			name: "redirect with scheme https and custom port 8443",
			redirect: state.InternalRedirect{
				Scheme:     state.Ptr("https"),
				Hostname:   state.Ptr(gatewayv1.PreciseHostname("foo.example.com")),
				Port:       state.Ptr(gatewayv1.PortNumber(8443)),
				StatusCode: state.Ptr(307),
			},
			initialURL:       "http://example.com/temporary",
			initialHost:      "example.com",
			expectedStatus:   307,
			expectedLocation: "https://foo.example.com:8443/temporary",
		},
	}

	p := NewProxy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.initialURL, nil)
			req.Host = tt.initialHost
			w := httptest.NewRecorder()

			p.redirect(w, req, tt.redirect, tt.match)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}
			location := resp.Header.Get("Location")
			if location != tt.expectedLocation {
				t.Errorf("expected Location %q, got %q", tt.expectedLocation, location)
			}
		})
	}
}

func TestProxyModifyHeadersCaseInsensitive(t *testing.T) {
	modifier := gatewayv1.HTTPHeaderFilter{
		Set: []gatewayv1.HTTPHeader{
			{Name: "X-Header-Set", Value: "header-set"},
		},
		Add: []gatewayv1.HTTPHeader{
			{Name: "X-Header-Add", Value: "header-add"},
			{Name: "X-New-Add", Value: "new-add"},
		},
		Remove: []string{"x-header-remove"},
	}

	header := http.Header{
		"x-header-set":    []string{"original-val-set"},
		"x-header-add":    []string{"original-val-add"},
		"x-header-remove": []string{"original-val-remove"},
		"Another-Header":  []string{"another-header-val"},
	}

	modifyHeaders(header, modifier)

	if got := header.Get("X-Header-Set"); got != "header-set" {
		t.Errorf("expected X-Header-Set to be 'header-set', got %q", got)
	}
	if got := strings.Join(header.Values("X-Header-Add"), ","); got != "original-val-add,header-add" {
		t.Errorf("expected X-Header-Add to be 'original-val-add,header-add', got %q", got)
	}
	if got := header.Get("X-New-Add"); got != "new-add" {
		t.Errorf("expected X-New-Add to be 'new-add', got %q", got)
	}
	if got := header.Get("Another-Header"); got != "another-header-val" {
		t.Errorf("expected Another-Header to be 'another-header-val', got %q", got)
	}
	if got := header.Values("X-Header-Remove"); len(got) > 0 {
		t.Errorf("expected X-Header-Remove to be absent, got %v", got)
	}
	if got := header.Values("x-header-remove"); len(got) > 0 {
		t.Errorf("expected x-header-remove to be absent, got %v", got)
	}
}

func TestProxyResponseHeaderModifier(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Original", "orig")
		w.Header().Set("X-Header-Remove", "remove-me")
		w.Header().Set("X-Header-Set", "old-set")
		w.Header().Add("X-Header-Add", "existing-add")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
					ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Header-Set", Value: "new-set"},
						},
						Add: []gatewayv1.HTTPHeader{
							{Name: "X-Header-Add", Value: "new-add"},
						},
						Remove: []string{"X-Header-Remove"},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Header-Set"); got != "new-set" {
		t.Errorf("expected X-Header-Set to be 'new-set', got %q", got)
	}
	if got := strings.Join(resp.Header.Values("X-Header-Add"), ","); got != "existing-add,new-add" {
		t.Errorf("expected X-Header-Add to be 'existing-add,new-add', got %q", got)
	}
	if got := resp.Header.Get("X-Backend-Original"); got != "orig" {
		t.Errorf("expected X-Backend-Original to be 'orig', got %q", got)
	}
	if got := resp.Header.Values("X-Header-Remove"); len(got) > 0 {
		t.Errorf("expected X-Header-Remove to be absent, got %v", got)
	}
}

func TestProxyBackendHeaderModifiers(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("X-Resp-Original", "resp-orig")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host and port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Rule-Req", Value: "rule-val"},
						},
					},
					ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Rule-Resp", Value: "rule-resp-val"},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Backend-Req", Value: "backend-val"},
								},
							},
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Backend-Resp", Value: "backend-resp-val"},
								},
							},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify request headers received by backend
	if got := receivedHeaders.Get("X-Rule-Req"); got != "rule-val" {
		t.Errorf("expected X-Rule-Req to be 'rule-val', got %q", got)
	}
	if got := receivedHeaders.Get("X-Backend-Req"); got != "backend-val" {
		t.Errorf("expected X-Backend-Req to be 'backend-val', got %q", got)
	}

	// Verify response headers returned to client
	if got := resp.Header.Get("X-Rule-Resp"); got != "rule-resp-val" {
		t.Errorf("expected X-Rule-Resp to be 'rule-resp-val', got %q", got)
	}
	if got := resp.Header.Get("X-Backend-Resp"); got != "backend-resp-val" {
		t.Errorf("expected X-Backend-Resp to be 'backend-resp-val', got %q", got)
	}
	if got := resp.Header.Get("X-Resp-Original"); got != "resp-orig" {
		t.Errorf("expected X-Resp-Original to be 'resp-orig', got %q", got)
	}
}

func TestPickBackend(t *testing.T) {
	t.Run("empty backends", func(t *testing.T) {
		_, err := pickBackend(nil)
		if err == nil {
			t.Errorf("expected error for empty backends, got nil")
		}
	})

	t.Run("all zero weight", func(t *testing.T) {
		backends := []state.InternalBackend{
			{Host: "b1", Weight: 0},
			{Host: "b2", Weight: 0},
		}
		_, err := pickBackend(backends)
		if err == nil {
			t.Errorf("expected error for all zero weight, got nil")
		}
	})

	t.Run("single backend zero weight", func(t *testing.T) {
		backends := []state.InternalBackend{
			{Host: "b1", Weight: 0},
		}
		_, err := pickBackend(backends)
		if err == nil {
			t.Errorf("expected error for single backend with zero weight, got nil")
		}
	})

	t.Run("single backend", func(t *testing.T) {
		backends := []state.InternalBackend{
			{Host: "b1", Weight: 1},
		}
		b, err := pickBackend(backends)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Host != "b1" {
			t.Errorf("expected host b1, got %s", b.Host)
		}
	})
}

func TestProxy_WeightedBackends(t *testing.T) {
	var counts sync.Map
	counts.Store("v1", 0)
	counts.Store("v2", 0)
	counts.Store("v3", 0)

	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := counts.Load("v1")
		counts.Store("v1", v.(int)+1)
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := counts.Load("v2")
		counts.Store("v2", v.(int)+1)
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := counts.Load("v3")
		counts.Store("v3", v.(int)+1)
		w.WriteHeader(http.StatusOK)
	}))
	defer s3.Close()

	u1, _ := url.Parse(s1.URL)
	port1, _ := strconv.Atoi(u1.Port())
	u2, _ := url.Parse(s2.URL)
	port2, _ := strconv.Atoi(u2.Port())
	u3, _ := url.Parse(s3.URL)
	port3, _ := strconv.Atoi(u3.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{Host: u1.Hostname(), Port: int32(port1), Weight: 70},
						{Host: u2.Hostname(), Port: int32(port2), Weight: 30},
						{Host: u3.Hostname(), Port: int32(port3), Weight: 0},
					},
				},
			},
		},
	})

	totalRequests := 1000
	for range totalRequests {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code: %d", w.Result().StatusCode)
		}
	}

	v1Count, _ := counts.Load("v1")
	v2Count, _ := counts.Load("v2")
	v3Count, _ := counts.Load("v3")

	if v3Count.(int) != 0 {
		t.Errorf("expected 0 requests to backend with weight 0, got %d", v3Count.(int))
	}

	v1Pct := float64(v1Count.(int)) / float64(totalRequests)
	v2Pct := float64(v2Count.(int)) / float64(totalRequests)

	// Tolerance of 5% around 0.70 and 0.30
	if v1Pct < 0.60 || v1Pct > 0.80 {
		t.Errorf("expected v1 percentage ~0.70 (+/- 0.10), got %f", v1Pct)
	}
	if v2Pct < 0.20 || v2Pct > 0.40 {
		t.Errorf("expected v2 percentage ~0.30 (+/- 0.10), got %f", v2Pct)
	}
}

func TestProxy_BackendRequestHeaderModifier(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Backend"); got != "infra-backend-v1" {
			t.Errorf("expected Backend header 'infra-backend-v1', got %q", got)
		}
		if got := r.Header.Get("X-Rule-Header"); got != "rule-val" {
			t.Errorf("expected X-Rule-Header 'rule-val', got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	u1, _ := url.Parse(s1.URL)
	port1, _ := strconv.Atoi(u1.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Rule-Header", Value: "rule-val"},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   u1.Hostname(),
							Port:   int32(port1),
							Weight: 10,
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "Backend", Value: "infra-backend-v1"},
								},
							},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", w.Result().StatusCode)
	}
}

func TestProxy_BackendResponseHeaderModifier(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	u1, _ := url.Parse(s1.URL)
	port1, _ := strconv.Atoi(u1.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Rule-Resp", Value: "rule-resp"},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   u1.Hostname(),
							Port:   int32(port1),
							Weight: 1,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Backend-Resp", Value: "backend-resp"},
								},
							},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Rule-Resp"); got != "rule-resp" {
		t.Errorf("expected X-Rule-Resp 'rule-resp', got %q", got)
	}
	if got := resp.Header.Get("X-Backend-Resp"); got != "backend-resp" {
		t.Errorf("expected X-Backend-Resp 'backend-resp', got %q", got)
	}
}

func TestProxy_BackendURLRewrite(t *testing.T) {
	type receivedReq struct {
		path          string
		host          string
		forwardedHost string
	}

	var mu sync.Mutex
	var s1Req, s2Req *receivedReq

	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s1Req = &receivedReq{
			path:          r.URL.Path,
			host:          r.Host,
			forwardedHost: r.Header.Get("X-Forwarded-Host"),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s2Req = &receivedReq{
			path:          r.URL.Path,
			host:          r.Host,
			forwardedHost: r.Header.Get("X-Forwarded-Host"),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	u1, _ := url.Parse(s1.URL)
	port1, _ := strconv.Atoi(u1.Port())
	u2, _ := url.Parse(s2.URL)
	port2, _ := strconv.Atoi(u2.Port())

	t.Run("backend-level rewrite applies to its own backend only", func(t *testing.T) {
		p := NewProxy()
		// Route with two backends: backend 1 has URLRewrite, backend 2 does not.
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Matches: []state.InternalMatch{
							{
								Path: &state.InternalPathMatch{
									Type:  gatewayv1.PathMatchPathPrefix,
									Value: "/api",
								},
							},
						},
						Backends: []state.InternalBackend{
							{
								Host:   u1.Hostname(),
								Port:   int32(port1),
								Weight: 1,
								Rewrite: &state.InternalRewrite{
									Hostname: state.Ptr(gatewayv1.PreciseHostname("b1.example.internal")),
									Path: &state.InternalPathRewrite{
										Type:  gatewayv1.FullPathHTTPPathModifier,
										Value: "/rewritten-b1",
									},
								},
							},
							{
								Host:   u2.Hostname(),
								Port:   int32(port2),
								Weight: 0,
							},
						},
					},
				},
			},
		})

		mu.Lock()
		s1Req, s2Req = nil, nil
		mu.Unlock()

		// Request routed to backend 1 (weight 1 vs weight 0)
		req1 := httptest.NewRequest("GET", "http://original.example.com/api/test", nil)
		req1.Host = "original.example.com"
		w1 := httptest.NewRecorder()
		p.ServeHTTP(w1, req1)

		if w1.Result().StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code for req1: %d", w1.Result().StatusCode)
		}

		mu.Lock()
		gotS1 := s1Req
		gotS2 := s2Req
		mu.Unlock()

		if gotS1 == nil {
			t.Fatalf("expected backend 1 to receive request")
		}
		if gotS2 != nil {
			t.Fatalf("expected backend 2 NOT to receive request")
		}
		if gotS1.path != "/rewritten-b1" {
			t.Errorf("backend 1: expected path '/rewritten-b1', got %q", gotS1.path)
		}
		if gotS1.host != "b1.example.internal" {
			t.Errorf("backend 1: expected host 'b1.example.internal', got %q", gotS1.host)
		}
		if gotS1.forwardedHost != "original.example.com" {
			t.Errorf("backend 1: expected X-Forwarded-Host 'original.example.com', got %q", gotS1.forwardedHost)
		}

		// Now update weights so backend 2 (no rewrite) is chosen
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Matches: []state.InternalMatch{
							{
								Path: &state.InternalPathMatch{
									Type:  gatewayv1.PathMatchPathPrefix,
									Value: "/api",
								},
							},
						},
						Backends: []state.InternalBackend{
							{
								Host:   u1.Hostname(),
								Port:   int32(port1),
								Weight: 0,
								Rewrite: &state.InternalRewrite{
									Hostname: state.Ptr(gatewayv1.PreciseHostname("b1.example.internal")),
									Path: &state.InternalPathRewrite{
										Type:  gatewayv1.FullPathHTTPPathModifier,
										Value: "/rewritten-b1",
									},
								},
							},
							{
								Host:   u2.Hostname(),
								Port:   int32(port2),
								Weight: 1,
							},
						},
					},
				},
			},
		})

		mu.Lock()
		s1Req, s2Req = nil, nil
		mu.Unlock()

		req2 := httptest.NewRequest("GET", "http://original.example.com/api/test", nil)
		req2.Host = "original.example.com"
		w2 := httptest.NewRecorder()
		p.ServeHTTP(w2, req2)

		if w2.Result().StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code for req2: %d", w2.Result().StatusCode)
		}

		mu.Lock()
		gotS1 = s1Req
		gotS2 = s2Req
		mu.Unlock()

		if gotS2 == nil {
			t.Fatalf("expected backend 2 to receive request")
		}
		if gotS1 != nil {
			t.Fatalf("expected backend 1 NOT to receive request")
		}
		if gotS2.path != "/api/test" {
			t.Errorf("backend 2: expected original path '/api/test', got %q", gotS2.path)
		}
		if gotS2.host != "original.example.com" {
			t.Errorf("backend 2: expected original host 'original.example.com', got %q", gotS2.host)
		}
		if gotS2.forwardedHost != "" {
			t.Errorf("backend 2: expected no X-Forwarded-Host, got %q", gotS2.forwardedHost)
		}
	})

	t.Run("backend-level ReplacePrefixMatch rewrite", func(t *testing.T) {
		p := NewProxy()
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Matches: []state.InternalMatch{
							{
								Path: &state.InternalPathMatch{
									Type:  gatewayv1.PathMatchPathPrefix,
									Value: "/prefix",
								},
							},
						},
						Backends: []state.InternalBackend{
							{
								Host:   u1.Hostname(),
								Port:   int32(port1),
								Weight: 1,
								Rewrite: &state.InternalRewrite{
									Path: &state.InternalPathRewrite{
										Type:  gatewayv1.PrefixMatchHTTPPathModifier,
										Value: "/rewritten-prefix",
									},
								},
							},
						},
					},
				},
			},
		})

		mu.Lock()
		s1Req = nil
		mu.Unlock()

		req := httptest.NewRequest("GET", "http://example.com/prefix/original", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code: %d", w.Result().StatusCode)
		}

		mu.Lock()
		got := s1Req
		mu.Unlock()

		if got == nil {
			t.Fatalf("expected backend to receive request")
		}
		if got.path != "/rewritten-prefix/original" {
			t.Errorf("expected path '/rewritten-prefix/original', got %q", got.path)
		}
	})

	t.Run("mirror backend does not receive backend-level rewrite", func(t *testing.T) {
		p := NewProxy()
		mirrorDone := make(chan struct{})
		var mirrorReceivedPath, mirrorReceivedHost string

		mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			mirrorReceivedPath = r.URL.Path
			mirrorReceivedHost = r.Host
			mu.Unlock()
			close(mirrorDone)
			w.WriteHeader(http.StatusOK)
		}))
		defer mirrorServer.Close()

		uMirror, _ := url.Parse(mirrorServer.URL)
		portMirror, _ := strconv.Atoi(uMirror.Port())

		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{
								Host:   u1.Hostname(),
								Port:   int32(port1),
								Weight: 1,
								Rewrite: &state.InternalRewrite{
									Hostname: state.Ptr(gatewayv1.PreciseHostname("primary.example.internal")),
									Path: &state.InternalPathRewrite{
										Type:  gatewayv1.FullPathHTTPPathModifier,
										Value: "/primary-rewritten",
									},
								},
							},
						},
						Mirrors: []state.InternalMirror{
							{
								Backend: state.InternalBackend{
									Host: uMirror.Hostname(),
									Port: int32(portMirror),
								},
								Numerator:   100,
								Denominator: 100,
							},
						},
					},
				},
			},
		})

		mu.Lock()
		s1Req = nil
		mu.Unlock()

		req := httptest.NewRequest("GET", "http://client.example.com/original-path", nil)
		req.Host = "client.example.com"
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("unexpected status code: %d", w.Result().StatusCode)
		}

		select {
		case <-mirrorDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for mirror request")
		}

		mu.Lock()
		primaryGot := s1Req
		mirrorPath := mirrorReceivedPath
		mirrorHost := mirrorReceivedHost
		mu.Unlock()

		if primaryGot == nil {
			t.Fatalf("expected primary backend to receive request")
		}
		if primaryGot.path != "/primary-rewritten" {
			t.Errorf("primary: expected path '/primary-rewritten', got %q", primaryGot.path)
		}
		if primaryGot.host != "primary.example.internal" {
			t.Errorf("primary: expected host 'primary.example.internal', got %q", primaryGot.host)
		}

		// Mirror should receive the unrewritten original path and original host
		if mirrorPath != "/original-path" {
			t.Errorf("mirror: expected original path '/original-path', got %q", mirrorPath)
		}
		if mirrorHost != "client.example.com" {
			t.Errorf("mirror: expected original host 'client.example.com', got %q", mirrorHost)
		}
	})
}

func TestProxy_HTTPSListenerDetectMisdirectedRequests(t *testing.T) {
	// Setup mock backends
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v1")
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()
	u1, _ := url.Parse(s1.URL)
	port1, _ := strconv.Atoi(u1.Port())

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v2")
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()
	u2, _ := url.Parse(s2.URL)
	port2, _ := strconv.Atoi(u2.Port())

	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v3")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3.Close()
	u3, _ := url.Parse(s3.URL)
	port3, _ := strconv.Atoi(u3.Port())

	listeners := []state.InternalListener{
		{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("example.org"),
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/detect-misdirected-requests"},
								},
							},
							Backends: []state.InternalBackend{{Host: u1.Hostname(), Port: int32(port1), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "https-with-hostname",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "second-example.org",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("second-example.org"),
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/detect-misdirected-requests"},
								},
							},
							Backends: []state.InternalBackend{{Host: u2.Hostname(), Port: int32(port2), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "https-with-wildcard-hostname",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "*.wildcard.org",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("*.wildcard.org"),
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/detect-misdirected-requests"},
								},
							},
							Backends: []state.InternalBackend{{Host: u3.Hostname(), Port: int32(port3), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "https-with-hostname-matching-wildcard",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "fourth-example.wildcard.org",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("fourth-example.wildcard.org"),
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/detect-misdirected-requests"},
								},
							},
							Backends: []state.InternalBackend{{Host: u1.Hostname(), Port: int32(port1), Weight: 1}},
						},
					},
				},
			},
		},
	}

	p := NewProxy()
	p.UpdateListeners(listeners)

	cases := []struct {
		serverName  string
		host        string
		wantStatus  int
		wantBackend string
	}{
		{serverName: "example.org", host: "example.org", wantStatus: 200, wantBackend: "v1"},
		{serverName: "example.org", host: "second-example.org", wantStatus: 421},
		{serverName: "example.org", host: "unknown-example.org", wantStatus: 404},

		{serverName: "second-example.org", host: "second-example.org", wantStatus: 200, wantBackend: "v2"},
		{serverName: "second-example.org", host: "example.org", wantStatus: 421},
		{serverName: "second-example.org", host: "unknown-example.org", wantStatus: 421},

		{serverName: "third-example.wildcard.org", host: "third-example.wildcard.org", wantStatus: 200, wantBackend: "v3"},
		{serverName: "third-example.wildcard.org", host: "fith-example.wildcard.org", wantStatus: 200, wantBackend: "v3"},
		{serverName: "third-example.wildcard.org", host: "fourth-example.wildcard.org", wantStatus: 421},
		{serverName: "third-example.wildcard.org", host: "second-example.org", wantStatus: 421},
		{serverName: "third-example.wildcard.org", host: "unknown-example.org", wantStatus: 421},

		{serverName: "fourth-example.wildcard.org", host: "fourth-example.wildcard.org", wantStatus: 200, wantBackend: "v1"},
		{serverName: "fourth-example.wildcard.org", host: "fith-example.wildcard.org", wantStatus: 421},

		{serverName: "unknown-example.org", host: "example.org", wantStatus: 200, wantBackend: "v1"},
		{serverName: "unknown-example.org", host: "unknown-example.org", wantStatus: 404},
	}

	for _, tc := range cases {
		t.Run(tc.serverName+"->"+tc.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tc.host+"/detect-misdirected-requests", nil)
			req.Host = tc.host
			req.TLS = &tls.ConnectionState{
				ServerName: tc.serverName,
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("serverName %q, host %q: status code = %d, want %d", tc.serverName, tc.host, resp.StatusCode, tc.wantStatus)
			}
			if tc.wantBackend != "" {
				if got := resp.Header.Get("X-Backend"); got != tc.wantBackend {
					t.Errorf("serverName %q, host %q: backend = %q, want %q", tc.serverName, tc.host, got, tc.wantBackend)
				}
			}
		})
	}
}

func TestProxyTimeouts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delayStr := r.URL.Query().Get("delay"); delayStr != "" {
			if d, err := time.ParseDuration(delayStr); err == nil {
				time.Sleep(d)
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host and port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	tests := []struct {
		name           string
		timeouts       *state.InternalTimeouts
		respModifier   *gatewayv1.HTTPHeaderFilter
		requestPath    string
		expectedStatus int
		expectRespHead string
	}{
		{
			name: "request completes within request timeout",
			timeouts: &state.InternalTimeouts{
				Request: state.Ptr(200 * time.Millisecond),
			},
			requestPath:    "/test",
			expectedStatus: http.StatusOK,
		},
		{
			name: "request exceeds request timeout",
			timeouts: &state.InternalTimeouts{
				Request: state.Ptr(50 * time.Millisecond),
			},
			requestPath:    "/test?delay=200ms",
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name: "request exceeds backendRequest timeout",
			timeouts: &state.InternalTimeouts{
				BackendRequest: state.Ptr(50 * time.Millisecond),
			},
			requestPath:    "/test?delay=200ms",
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name: "zero duration disables timeout",
			timeouts: &state.InternalTimeouts{
				Request: state.Ptr(0 * time.Second),
			},
			requestPath:    "/test?delay=50ms",
			expectedStatus: http.StatusOK,
		},
		{
			name: "both set - backendRequest timeout exceeded before request timeout",
			timeouts: &state.InternalTimeouts{
				Request:        state.Ptr(200 * time.Millisecond),
				BackendRequest: state.Ptr(50 * time.Millisecond),
			},
			requestPath:    "/test?delay=100ms",
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name: "both set - request timeout exceeded before backendRequest timeout",
			timeouts: &state.InternalTimeouts{
				Request:        state.Ptr(50 * time.Millisecond),
				BackendRequest: state.Ptr(200 * time.Millisecond),
			},
			requestPath:    "/test?delay=100ms",
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name: "timeout applies response header modifier",
			timeouts: &state.InternalTimeouts{
				Request: state.Ptr(50 * time.Millisecond),
			},
			respModifier: &gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{
					{Name: "X-Timeout-Header", Value: "applied"},
				},
			},
			requestPath:    "/test?delay=200ms",
			expectedStatus: http.StatusGatewayTimeout,
			expectRespHead: "applied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			p.UpdateRoutes([]state.InternalRoute{
				{
					Rules: []state.InternalRule{
						{
							Timeouts: tt.timeouts,
							Backends: []state.InternalBackend{
								{
									Host:   host,
									Port:   int32(port),
									Weight: 1,
								},
							},
							ResponseHeaderModifier: tt.respModifier,
						},
					},
				},
			})

			req := httptest.NewRequest("GET", "http://example.com"+tt.requestPath, nil)
			w := httptest.NewRecorder()

			p.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}
			if tt.expectRespHead != "" {
				if got := resp.Header.Get("X-Timeout-Header"); got != tt.expectRespHead {
					t.Errorf("expected X-Timeout-Header %q, got %q", tt.expectRespHead, got)
				}
			}
		})
	}
}

func TestProxyNoBackendRefs(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v1")
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	host, portStr, err := net.SplitHostPort(backendServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	routes := []state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/omitted-no-forward",
							},
						},
					},
					Backends: nil,
				},
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/empty-no-forward",
							},
						},
					},
					Backends: []state.InternalBackend{},
				},
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/forward",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	}

	p := NewProxy()
	p.UpdateRoutes(routes)

	cases := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "omitted backendRefs returns 500",
			path:       "/omitted-no-forward",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "empty backendRefs returns 500",
			path:       "/empty-no-forward",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "valid backend forwards normally",
			path:       "/forward",
			wantStatus: http.StatusOK,
		},
		{
			name:       "unmatched path returns 404",
			path:       "/unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("path %q: status code = %d, want %d", tc.path, resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestProxyCORS(t *testing.T) {
	backendCalled := false
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.Header().Set("X-Backend-Header", "present")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, _ := url.Parse(backendServer.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	allowCredsTrue := true
	allowCredsFalse := false

	ruleCORS := &gatewayv1.HTTPCORSFilter{
		AllowOrigins:     []gatewayv1.CORSOrigin{"https://www.foo.com", "https://*.bar.com"},
		AllowMethods:     []gatewayv1.HTTPMethodWithWildcard{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []gatewayv1.HTTPHeaderName{"x-header-1", "x-header-2"},
		ExposeHeaders:    []gatewayv1.HTTPHeaderName{"x-header-3", "x-header-4"},
		AllowCredentials: &allowCredsTrue,
		MaxAge:           3600,
	}

	wildcardCORS := &gatewayv1.HTTPCORSFilter{
		AllowOrigins:     []gatewayv1.CORSOrigin{"*"},
		AllowMethods:     []gatewayv1.HTTPMethodWithWildcard{"*"},
		AllowHeaders:     []gatewayv1.HTTPHeaderName{"*"},
		AllowCredentials: &allowCredsFalse,
	}

	routes := []state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					CORS: ruleCORS,
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/cors-1",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
				{
					CORS: wildcardCORS,
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/cors-wildcard",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	}

	p := NewProxy()
	p.UpdateRoutes(routes)

	t.Run("preflight exact origin allowed", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("OPTIONS", "http://example.com/cors-1", nil)
		req.Header.Set("Origin", "https://www.foo.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "x-header-1, x-header-2")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if backendCalled {
			t.Errorf("backend should not be called on preflight OPTIONS")
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://www.foo.com" {
			t.Errorf("expected Access-Control-Allow-Origin https://www.foo.com, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("expected Access-Control-Allow-Credentials true, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
			t.Errorf("expected Access-Control-Allow-Methods GET, POST, OPTIONS, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "x-header-1, x-header-2" {
			t.Errorf("expected Access-Control-Allow-Headers x-header-1, x-header-2, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "x-header-3, x-header-4" {
			t.Errorf("expected Access-Control-Expose-Headers x-header-3, x-header-4, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Max-Age"); got != "3600" {
			t.Errorf("expected Access-Control-Max-Age 3600, got %s", got)
		}
	})

	t.Run("preflight wildcard domain origin allowed", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("OPTIONS", "http://example.com/cors-1", nil)
		req.Header.Set("Origin", "https://xpto.www.bar.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if backendCalled {
			t.Errorf("backend should not be called on preflight OPTIONS")
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://xpto.www.bar.com" {
			t.Errorf("expected Access-Control-Allow-Origin https://xpto.www.bar.com, got %s", got)
		}
	})

	t.Run("preflight non-matching origin denied", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("OPTIONS", "http://example.com/cors-1", nil)
		req.Header.Set("Origin", "https://unauthorized.org")
		req.Header.Set("Access-Control-Request-Method", "GET")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if backendCalled {
			t.Errorf("backend should not be called on preflight OPTIONS")
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("expected absent Access-Control-Allow-Origin, got %s", got)
		}
	})

	t.Run("preflight wildcard origin and methods with allowCredentials false", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("OPTIONS", "http://example.com/cors-wildcard", nil)
		req.Header.Set("Origin", "https://anydomain.com:9999")
		req.Header.Set("Access-Control-Request-Method", "PUT")
		req.Header.Set("Access-Control-Request-Headers", "custom-header")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("expected Access-Control-Allow-Origin *, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("expected absent Access-Control-Allow-Credentials, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "PUT" && got != "*" {
			t.Errorf("expected Access-Control-Allow-Methods PUT or *, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "custom-header" && got != "*" {
			t.Errorf("expected Access-Control-Allow-Headers custom-header or *, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Max-Age"); got != "5" {
			t.Errorf("expected default Access-Control-Max-Age 5, got %s", got)
		}
	})

	t.Run("simple request matching origin forwards and sets CORS headers", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("GET", "http://example.com/cors-1", nil)
		req.Header.Set("Origin", "https://www.foo.com")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if !backendCalled {
			t.Errorf("expected backend to be called for simple GET request")
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://www.foo.com" {
			t.Errorf("expected Access-Control-Allow-Origin https://www.foo.com, got %s", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("expected Access-Control-Allow-Credentials true, got %s", got)
		}
		if got := resp.Header.Get("X-Backend-Header"); got != "present" {
			t.Errorf("expected backend response headers to be preserved, got %s", got)
		}
	})

	t.Run("simple request non-matching origin forwards without CORS headers", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest("GET", "http://example.com/cors-1", nil)
		req.Header.Set("Origin", "https://evil.com")

		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if !backendCalled {
			t.Errorf("expected backend to be called")
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("expected absent Access-Control-Allow-Origin, got %s", got)
		}
	})
}

func TestProxyRetries(t *testing.T) {
	var requestCount atomic.Int32
	var failUntil atomic.Int32
	var receivedBodies []string
	var bodyMutex sync.Mutex

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr == nil && len(body) > 0 {
			bodyMutex.Lock()
			receivedBodies = append(receivedBodies, string(body))
			bodyMutex.Unlock()
		}
		reqNum := requestCount.Add(1)
		if reqNum <= failUntil.Load() {
			http.Error(w, "Temporary Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer backendServer.Close()

	u, _ := url.Parse(backendServer.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	p := NewProxy()
	attempts := 3
	backoff := 5 * time.Millisecond
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/retry",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
					Retry: &state.CompiledHTTPRouteRetry{
						Codes:    []int{500},
						Attempts: &attempts,
						Backoff:  &backoff,
					},
				},
			},
		},
	})

	t.Run("succeeds after 2 retries", func(t *testing.T) {
		requestCount.Store(0)
		failUntil.Store(2) // Fails on attempt 0 and 1, succeeds on attempt 2 (1 initial + 2 retries = 3 requests)

		req := httptest.NewRequest("GET", "http://example.com/retry", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if count := requestCount.Load(); count != 3 {
			t.Errorf("expected 3 requests to backend, got %d", count)
		}
	})

	t.Run("fails when retries exceed max attempts", func(t *testing.T) {
		requestCount.Store(0)
		failUntil.Store(10) // Fails more times than max attempts (3 retries = 4 total requests)

		req := httptest.NewRequest("GET", "http://example.com/retry", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", resp.StatusCode)
		}
		if count := requestCount.Load(); count != 4 {
			t.Errorf("expected 4 requests to backend (1 initial + 3 retries), got %d", count)
		}
	})

	t.Run("retries with small body after backend failure", func(t *testing.T) {
		requestCount.Store(0)
		failUntil.Store(1)
		bodyMutex.Lock()
		receivedBodies = nil
		bodyMutex.Unlock()

		req := httptest.NewRequest("POST", "http://example.com/retry", strings.NewReader("small payload"))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Result().StatusCode)
		}
		if count := requestCount.Load(); count != 2 {
			t.Errorf("expected 2 requests to backend, got %d", count)
		}
		bodyMutex.Lock()
		defer bodyMutex.Unlock()
		if len(receivedBodies) != 2 || receivedBodies[0] != "small payload" || receivedBodies[1] != "small payload" {
			t.Errorf("expected both attempts to receive 'small payload', got %v", receivedBodies)
		}
	})
}

func TestProxyRequestBodyStreaming(t *testing.T) {
	testStreaming := func(t *testing.T, retry *state.CompiledHTTPRouteRetry, chunked bool) {
		backendReceivedBytes := make(chan struct{})
		var notifyOnce sync.Once
		var totalBytesReceived atomic.Int64
		var attemptCount atomic.Int32

		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount.Add(1)
			buffer := make([]byte, 64*1024)
			for {
				bytesRead, readErr := r.Body.Read(buffer)
				if bytesRead > 0 {
					totalBytesReceived.Add(int64(bytesRead))
					notifyOnce.Do(func() {
						close(backendReceivedBytes)
					})
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					http.Error(w, readErr.Error(), http.StatusInternalServerError)
					return
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer backendServer.Close()

		backendURL, _ := url.Parse(backendServer.URL)
		host, portString, _ := net.SplitHostPort(backendURL.Host)
		port, _ := strconv.Atoi(portString)

		proxyInstance := NewProxy()
		proxyInstance.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Matches: []state.InternalMatch{
							{
								Path: &state.InternalPathMatch{
									Type:  gatewayv1.PathMatchPathPrefix,
									Value: "/stream",
								},
							},
						},
						Backends: []state.InternalBackend{
							{
								Host:   host,
								Port:   int32(port),
								Weight: 1,
							},
						},
						Retry: retry,
					},
				},
			},
		})

		proxyServer := httptest.NewServer(proxyInstance)
		defer proxyServer.Close()

		totalBodySize := 12 * 1024 * 1024 // 12 MiB, larger than MaxBufferedBodySize (8 MiB)
		pipeReader, pipeWriter := io.Pipe()

		go func() {
			defer pipeWriter.Close()
			firstChunk := make([]byte, 64*1024)
			if _, writeErr := pipeWriter.Write(firstChunk); writeErr != nil {
				return
			}

			if !chunked {
				select {
				case <-backendReceivedBytes:
				case <-time.After(5 * time.Second):
					pipeWriter.CloseWithError(errors.New("timed out waiting for backend to receive first chunk"))
					return
				}
			}

			remainingBytes := totalBodySize - len(firstChunk)
			chunkBuffer := make([]byte, 64*1024)
			for remainingBytes > 0 {
				bytesToWrite := len(chunkBuffer)
				if bytesToWrite > remainingBytes {
					bytesToWrite = remainingBytes
				}
				bytesWritten, writeErr := pipeWriter.Write(chunkBuffer[:bytesToWrite])
				if writeErr != nil {
					return
				}
				remainingBytes -= bytesWritten
			}
		}()

		var memoryBefore, memoryAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&memoryBefore)

		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/stream", pipeReader)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		if chunked {
			request.ContentLength = -1
		} else {
			request.ContentLength = int64(totalBodySize)
		}

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", response.StatusCode)
		}
		if received := totalBytesReceived.Load(); received != int64(totalBodySize) {
			t.Fatalf("expected backend to receive %d bytes, got %d", totalBodySize, received)
		}
		if attempts := attemptCount.Load(); attempts != 1 {
			t.Fatalf("expected exactly 1 attempt, got %d", attempts)
		}

		runtime.GC()
		runtime.ReadMemStats(&memoryAfter)
		heapGrowth := int64(memoryAfter.HeapAlloc) - int64(memoryBefore.HeapAlloc)
		if heapGrowth > 4*1024*1024 {
			t.Errorf("heap growth %d bytes is not well below body size %d bytes", heapGrowth, totalBodySize)
		}
	}

	t.Run("without retries", func(t *testing.T) {
		testStreaming(t, nil, false)
	})

	t.Run("with retries over cap", func(t *testing.T) {
		attempts := 2
		backoff := 5 * time.Millisecond
		testStreaming(t, &state.CompiledHTTPRouteRetry{
			Codes:    []int{500},
			Attempts: &attempts,
			Backoff:  &backoff,
		}, false)
	})

	t.Run("with retries chunked over cap", func(t *testing.T) {
		attempts := 2
		backoff := 5 * time.Millisecond
		testStreaming(t, &state.CompiledHTTPRouteRetry{
			Codes:    []int{500},
			Attempts: &attempts,
			Backoff:  &backoff,
		}, true)
	})
}

func TestProxy_RequestTimeout_SlowBody(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host and port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Timeouts: &state.InternalTimeouts{
						Request: state.Ptr(1 * time.Second),
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	pipeReader, pipeWriter := io.Pipe()
	stopWriter := make(chan struct{})
	go func() {
		defer pipeWriter.Close()
		for {
			select {
			case <-stopWriter:
				return
			default:
			}
			if _, writeErr := pipeWriter.Write([]byte("x")); writeErr != nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	defer close(stopWriter)

	start := time.Now()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/test", pipeReader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected status 504 Gateway Timeout, got %d", resp.StatusCode)
	}
	if duration > 4*time.Second {
		t.Fatalf("expected timeout within a few seconds, took %v", duration)
	}
}

func TestProxy_RequestTimeout_SlowBody_ContentLength(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host and port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Timeouts: &state.InternalTimeouts{
						Request: state.Ptr(1 * time.Second),
					},
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	conn, err := net.DialTimeout("tcp", proxyServer.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer conn.Close()

	// Send raw HTTP/1 request with Content-Length: 100 on direct path
	reqHeaders := fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\n", proxyServer.Listener.Addr().String())
	if _, err := conn.Write([]byte(reqHeaders)); err != nil {
		t.Fatalf("failed to write headers: %v", err)
	}

	start := time.Now()
	stopWriter := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopWriter:
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := conn.Write([]byte("a")); err != nil {
				return
			}
		}
	}()
	defer close(stopWriter)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	duration := time.Since(start)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("expected status 504 Gateway Timeout, got %d", resp.StatusCode)
	}
	if duration > 3*time.Second {
		t.Errorf("expected timeout at about the request timeout (1s), took %v", duration)
	}
}

func TestProxy_BodyReadDeadline(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host and port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	t.Run("client that stalls longer than deadline is disconnected", func(t *testing.T) {
		p := NewProxy()
		p.SetBodyReadTimeout(150 * time.Millisecond)
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{Host: host, Port: int32(port), Weight: 1},
						},
					},
				},
			},
		})

		proxyServer := httptest.NewServer(p)
		defer proxyServer.Close()

		conn, err := net.DialTimeout("tcp", proxyServer.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		// Send headers with Content-Length: 100, then send only 5 bytes and stall
		reqHeaders := fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\nhello", proxyServer.Listener.Addr().String())
		if _, err := conn.Write([]byte(reqHeaders)); err != nil {
			t.Fatalf("failed to write headers: %v", err)
		}

		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestTimeout {
			t.Errorf("expected status 408 Request Timeout, got %d", resp.StatusCode)
		}
		if !resp.Close {
			t.Errorf("expected Connection: close on HTTP/1, got Close=%v", resp.Close)
		}

		// Verify that the server closes the connection
		buf := make([]byte, 1024)
		for {
			_, rerr := reader.Read(buf)
			if rerr != nil {
				break
			}
		}
		elapsed := time.Since(start)

		if elapsed < 80*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("expected connection to be closed around 150ms, elapsed %v", elapsed)
		}
	})

	t.Run("client that stalls longer than deadline with mirror is disconnected", func(t *testing.T) {
		p := NewProxy()
		p.SetBodyReadTimeout(150 * time.Millisecond)
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{Host: host, Port: int32(port), Weight: 1},
						},
						Mirrors: []state.InternalMirror{
							{
								Backend: state.InternalBackend{
									Host:   host,
									Port:   int32(port),
									Weight: 1,
								},
							},
						},
					},
				},
			},
		})

		proxyServer := httptest.NewServer(p)
		defer proxyServer.Close()

		conn, err := net.DialTimeout("tcp", proxyServer.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		// Send headers with Content-Length: 100, then send only 5 bytes and stall on mirrored route
		reqHeaders := fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\nhello", proxyServer.Listener.Addr().String())
		if _, err := conn.Write([]byte(reqHeaders)); err != nil {
			t.Fatalf("failed to write headers: %v", err)
		}

		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestTimeout {
			t.Errorf("expected status 408 Request Timeout, got %d", resp.StatusCode)
		}
		if !resp.Close {
			t.Errorf("expected Connection: close on HTTP/1, got Close=%v", resp.Close)
		}

		// Verify that the server closes the connection
		buf := make([]byte, 1024)
		for {
			_, rerr := reader.Read(buf)
			if rerr != nil {
				break
			}
		}
		elapsed := time.Since(start)

		if elapsed < 80*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("expected connection to be closed around 150ms, elapsed %v", elapsed)
		}
	})

	t.Run("client that stalls longer than deadline with retry is disconnected", func(t *testing.T) {
		p := NewProxy()
		p.SetBodyReadTimeout(150 * time.Millisecond)
		retryAttempts := 2
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{Host: host, Port: int32(port), Weight: 1},
						},
						Retry: &state.CompiledHTTPRouteRetry{
							Codes:    []int{500},
							Attempts: &retryAttempts,
						},
					},
				},
			},
		})

		proxyServer := httptest.NewServer(p)
		defer proxyServer.Close()

		conn, err := net.DialTimeout("tcp", proxyServer.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		// Send headers with Content-Length: 100, then send only 5 bytes and stall on route with retries
		reqHeaders := fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\nhello", proxyServer.Listener.Addr().String())
		if _, err := conn.Write([]byte(reqHeaders)); err != nil {
			t.Fatalf("failed to write headers: %v", err)
		}

		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusRequestTimeout {
			t.Errorf("expected status 408 Request Timeout, got %d", resp.StatusCode)
		}
		if !resp.Close {
			t.Errorf("expected Connection: close on HTTP/1, got Close=%v", resp.Close)
		}

		// Verify that the server closes the connection
		buf := make([]byte, 1024)
		for {
			_, rerr := reader.Read(buf)
			if rerr != nil {
				break
			}
		}
		elapsed := time.Since(start)

		if elapsed < 80*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("expected connection to be closed around 150ms, elapsed %v", elapsed)
		}
	})

	t.Run("HTTP/2 stalled stream gets 408 and connection remains usable", func(t *testing.T) {
		p := NewProxy()
		p.SetBodyReadTimeout(150 * time.Millisecond)
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{Host: host, Port: int32(port), Weight: 1},
						},
					},
				},
			},
		})

		proxyH2cHandler := h2c.NewHandler(p, &http2.Server{})
		proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen for proxy: %v", err)
		}
		defer proxyLn.Close()
		proxySrv := &http.Server{Handler: proxyH2cHandler}
		go proxySrv.Serve(proxyLn)
		defer proxySrv.Close()

		proxyURL := "http://" + proxyLn.Addr().String()

		client := &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			},
		}

		// First request stalls its body
		pipeReader, pipeWriter := io.Pipe()
		stopWriter := make(chan struct{})
		go func() {
			defer pipeWriter.Close()
			_, _ = pipeWriter.Write([]byte("start"))
			select {
			case <-stopWriter:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}()
		defer close(stopWriter)

		req1, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyURL+"/test", pipeReader)
		if err != nil {
			t.Fatalf("failed to create req1: %v", err)
		}
		resp1, err := client.Do(req1)
		if err != nil {
			t.Fatalf("req1 failed: %v", err)
		}
		defer resp1.Body.Close()
		if resp1.StatusCode != http.StatusRequestTimeout {
			t.Errorf("expected 408 Request Timeout for stalled stream, got %d", resp1.StatusCode)
		}

		// Second request on the same client/connection completes successfully
		req2, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyURL+"/test", strings.NewReader("healthy-body"))
		if err != nil {
			t.Fatalf("failed to create req2: %v", err)
		}
		resp2, err := client.Do(req2)
		if err != nil {
			t.Fatalf("req2 failed on shared HTTP/2 connection: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK for subsequent request on same connection, got %d", resp2.StatusCode)
		}
		body2, _ := io.ReadAll(resp2.Body)
		if string(body2) != "healthy-body" {
			t.Errorf("expected body %q, got %q", "healthy-body", string(body2))
		}
	})

	t.Run("client that sends steadily for longer than deadline completes", func(t *testing.T) {
		p := NewProxy()
		p.SetBodyReadTimeout(150 * time.Millisecond)
		p.UpdateRoutes([]state.InternalRoute{
			{
				Rules: []state.InternalRule{
					{
						Backends: []state.InternalBackend{
							{Host: host, Port: int32(port), Weight: 1},
						},
					},
				},
			},
		})

		proxyServer := httptest.NewServer(p)
		defer proxyServer.Close()

		pipeReader, pipeWriter := io.Pipe()
		totalChunks := 8
		go func() {
			defer pipeWriter.Close()
			for i := 0; i < totalChunks; i++ {
				if _, err := pipeWriter.Write([]byte(fmt.Sprintf("chunk-%d\n", i))); err != nil {
					return
				}
				time.Sleep(40 * time.Millisecond)
			}
		}()

		start := time.Now()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/test", pipeReader)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		duration := time.Since(start)
		if err != nil {
			t.Fatalf("expected request to succeed, got error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200 OK, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if duration < 250*time.Millisecond {
			t.Errorf("expected transfer to take longer than deadline (150ms), took %v", duration)
		}
		expectedPrefix := "chunk-0\n"
		if !strings.HasPrefix(string(body), expectedPrefix) {
			t.Errorf("expected response body to contain %q, got %q", expectedPrefix, string(body))
		}
	})
}

func TestProxyWebSocket(t *testing.T) {
	// Backend server that supports HTTP 101 Switching Protocols
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()

			// Write 101 response
			resp := "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Alt-Svc: h2=\":8443\"\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
			conn.Write([]byte(resp))

			// Echo loop
			b := make([]byte, 1024)
			for {
				n, err := buf.Read(b)
				if n > 0 {
					conn.Write(b[:n])
				}
				if err != nil {
					break
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	u, _ := url.Parse(backendServer.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/ws",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:        host,
							Port:        int32(port),
							AppProtocol: state.Ptr("kubernetes.io/ws"),
							Weight:      1,
						},
					},
				},
			},
		},
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Dial TCP to proxyServer and perform WebSocket handshake
	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}
	defer conn.Close()

	handshake := "GET /ws HTTP/1.1\r\n" +
		"Host: " + proxyURL.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := conn.Write([]byte(handshake)); err != nil {
		t.Fatalf("failed to send handshake: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status 101, got %d", resp.StatusCode)
	}
	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != "" {
		t.Errorf("expected no Alt-Svc on WebSocket response, got %q", altSvc)
	}

	// Send message and verify echo
	msg := []byte("Hello WebSocket!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("got %q, want %q", string(buf), string(msg))
	}
}

func TestProxy_ListenerPortMatching(t *testing.T) {
	// Setup mock backends
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v1")
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v2")
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "v3")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3.Close()

	u1, _ := url.Parse(s1.URL)
	u2, _ := url.Parse(s2.URL)
	u3, _ := url.Parse(s3.URL)

	port1, _ := strconv.Atoi(u1.Port())
	port2, _ := strconv.Atoi(u2.Port())
	port3, _ := strconv.Atoi(u3.Port())

	listeners := []state.InternalListener{
		{
			Name:     "listener-1",
			Hostname: "foo.com",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     80,
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("foo.com"),
					Rules: []state.InternalRule{
						{
							Backends: []state.InternalBackend{{Host: u1.Hostname(), Port: int32(port1), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "listener-2",
			Hostname: "foo.com",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     8080,
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("foo.com"),
					Rules: []state.InternalRule{
						{
							Backends: []state.InternalBackend{{Host: u2.Hostname(), Port: int32(port2), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "listener-3",
			Hostname: "bar.com",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     8080,
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("bar.com"),
					Rules: []state.InternalRule{
						{
							Backends: []state.InternalBackend{{Host: u2.Hostname(), Port: int32(port2), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "listener-4",
			Hostname: "foo.com",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     8090,
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("foo.com"),
					Rules: []state.InternalRule{
						{
							Backends: []state.InternalBackend{{Host: u3.Hostname(), Port: int32(port3), Weight: 1}},
						},
					},
				},
			},
		},
		{
			Name:     "listener-5",
			Hostname: "bar.com",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     8090,
			Routes:   nil, // no routes attached
		},
	}

	p := NewProxy()
	p.UpdateListeners(listeners)

	cases := []struct {
		host        string
		wantStatus  int
		wantBackend string
	}{
		{host: "foo.com", wantStatus: 200, wantBackend: "v1"},
		{host: "foo.com:8080", wantStatus: 200, wantBackend: "v2"},
		{host: "bar.com:8080", wantStatus: 200, wantBackend: "v2"},
		{host: "foo.com:8090", wantStatus: 200, wantBackend: "v3"},
		{host: "bar.com:8090", wantStatus: 404},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("host %q: status code = %d, want %d", tc.host, resp.StatusCode, tc.wantStatus)
			}
			if tc.wantBackend != "" {
				if got := resp.Header.Get("X-Backend"); got != tc.wantBackend {
					t.Errorf("host %q: backend = %q, want %q", tc.host, got, tc.wantBackend)
				}
			}
		})
	}
}

func TestProxyRequestMirror(t *testing.T) {
	// 1. Primary backend
	primaryCh := make(chan *http.Request, 10)
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCh <- r
		w.Header().Set("X-Primary-Backend", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("primary response"))
	}))
	defer primaryServer.Close()

	primaryHost, primaryPortStr, _ := net.SplitHostPort(primaryServer.Listener.Addr().String())
	primaryPort, _ := strconv.Atoi(primaryPortStr)

	// 2. Mirror backend 1
	mirror1Ch := make(chan *http.Request, 10)
	mirror1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirror1Ch <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror1Server.Close()

	mirror1Host, mirror1PortStr, _ := net.SplitHostPort(mirror1Server.Listener.Addr().String())
	mirror1Port, _ := strconv.Atoi(mirror1PortStr)

	// 3. Mirror backend 2
	mirror2Ch := make(chan *http.Request, 10)
	mirror2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirror2Ch <- r
		w.WriteHeader(http.StatusInternalServerError) // response does not affect client
	}))
	defer mirror2Server.Close()

	mirror2Host, mirror2PortStr, _ := net.SplitHostPort(mirror2Server.Listener.Addr().String())
	mirror2Port, _ := strconv.Atoi(mirror2PortStr)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Modified-Header", Value: "modified-val"},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   primaryHost,
							Port:   int32(primaryPort),
							Weight: 1,
						},
					},
					Mirrors: []state.InternalMirror{
						{
							Backend: state.InternalBackend{
								Host: mirror1Host,
								Port: int32(mirror1Port),
							},
							Numerator:   100,
							Denominator: 100,
						},
						{
							Backend: state.InternalBackend{
								Host: mirror2Host,
								Port: int32(mirror2Port),
							},
							Numerator:   100,
							Denominator: 100,
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("POST", "http://example.com/test-path?param=1", strings.NewReader("hello mirror"))
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify primary received request with modified header and body
	select {
	case r := <-primaryCh:
		if r.URL.Path != "/test-path" {
			t.Errorf("primary path = %q, want /test-path", r.URL.Path)
		}
		if r.Header.Get("X-Modified-Header") != "modified-val" {
			t.Errorf("primary X-Modified-Header = %q, want modified-val", r.Header.Get("X-Modified-Header"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for primary request")
	}

	// Verify mirror 1 received request with modified header and body
	select {
	case r := <-mirror1Ch:
		if r.URL.Path != "/test-path" {
			t.Errorf("mirror1 path = %q, want /test-path", r.URL.Path)
		}
		if r.Header.Get("X-Modified-Header") != "modified-val" {
			t.Errorf("mirror1 X-Modified-Header = %q, want modified-val", r.Header.Get("X-Modified-Header"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mirror 1 request")
	}

	// Verify mirror 2 received request
	select {
	case r := <-mirror2Ch:
		if r.URL.Path != "/test-path" {
			t.Errorf("mirror2 path = %q, want /test-path", r.URL.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mirror 2 request")
	}
}

func TestProxyRequestMirror_BodyTooLarge(t *testing.T) {
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	primaryHost, primaryPortStr, _ := net.SplitHostPort(primaryServer.Listener.Addr().String())
	primaryPort, _ := strconv.Atoi(primaryPortStr)

	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	mirrorHost, mirrorPortStr, _ := net.SplitHostPort(mirrorServer.Listener.Addr().String())
	mirrorPort, _ := strconv.Atoi(mirrorPortStr)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   primaryHost,
							Port:   int32(primaryPort),
							Weight: 1,
						},
					},
					Mirrors: []state.InternalMirror{
						{
							Backend: state.InternalBackend{
								Host: mirrorHost,
								Port: int32(mirrorPort),
							},
							Numerator:   100,
							Denominator: 100,
						},
					},
				},
			},
		},
	})

	// Body larger than MaxBufferedBodySize limit
	largeBody := bytes.NewReader(bytes.Repeat([]byte("a"), MaxBufferedBodySize+1))
	req := httptest.NewRequest("POST", "http://example.com/test-large", largeBody)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413 (Payload Too Large), got %d", resp.StatusCode)
	}
}

func TestProxy_StripBackendAltSvc(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h2=":8443"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Alt-Svc"); got != "" {
		t.Errorf("expected Alt-Svc header to be stripped, got %q", got)
	}
}

func TestProxy_StripBackendAltSvc_ResponseHeaderModifier(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h2=":8443"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
					ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "Alt-Svc", Value: `h3=":443"`},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	altSvcValues := resp.Header.Values("Alt-Svc")
	if len(altSvcValues) != 1 {
		t.Fatalf("expected exactly 1 Alt-Svc header, got %d: %v", len(altSvcValues), altSvcValues)
	}
	if altSvcValues[0] != `h3=":443"` {
		t.Errorf("expected Alt-Svc %q, got %q", `h3=":443"`, altSvcValues[0])
	}
}

func TestProxy_BuildTransport_BackendTLSPolicy(t *testing.T) {
	p := NewProxy()

	systemWellKnown := gatewayv1.WellKnownCACertificatesSystem
	httpsProto := "https"

	// 1. WellKnownCACertificates: System -> RootCAs == nil && !InsecureSkipVerify
	systemBackend := state.InternalBackend{
		Host:        "backend.example.com",
		Port:        443,
		AppProtocol: &httpsProto,
		TLSConfig: &state.InternalTLSConfig{
			Hostname:                "backend.example.com",
			WellKnownCACertificates: &systemWellKnown,
		},
	}
	trSystem := p.buildTransport(systemBackend)
	httpTrSystem, ok := trSystem.(*http.Transport)
	if !ok || httpTrSystem.TLSClientConfig == nil {
		t.Fatalf("expected *http.Transport with non-nil TLSClientConfig")
	}
	if httpTrSystem.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=false for System well-known CA, got true")
	}
	if httpTrSystem.TLSClientConfig.RootCAs != nil {
		t.Errorf("expected RootCAs == nil for System well-known CA, got %v", httpTrSystem.TLSClientConfig.RootCAs)
	}
	if httpTrSystem.TLSClientConfig.ServerName != "backend.example.com" {
		t.Errorf("expected ServerName 'backend.example.com', got %q", httpTrSystem.TLSClientConfig.ServerName)
	}

	// 2. Invalid policy (no CA certs, not System) -> non-nil empty pool && !InsecureSkipVerify
	invalidBackend := state.InternalBackend{
		Host:        "backend.example.com",
		Port:        443,
		AppProtocol: &httpsProto,
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "backend.example.com",
			CACerts:  nil,
		},
	}
	trInvalid := p.buildTransport(invalidBackend)
	httpTrInvalid, ok := trInvalid.(*http.Transport)
	if !ok || httpTrInvalid.TLSClientConfig == nil {
		t.Fatalf("expected *http.Transport with non-nil TLSClientConfig")
	}
	if httpTrInvalid.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=false for invalid policy, got true")
	}
	if httpTrInvalid.TLSClientConfig.RootCAs == nil {
		t.Errorf("expected non-nil empty RootCAs for invalid policy, got nil")
	} else if len(httpTrInvalid.TLSClientConfig.RootCAs.Subjects()) != 0 {
		t.Errorf("expected 0 certs in RootCAs for invalid policy, got %d", len(httpTrInvalid.TLSClientConfig.RootCAs.Subjects()))
	}
	if httpTrInvalid.TLSClientConfig.ServerName != "backend.example.com" {
		t.Errorf("expected ServerName 'backend.example.com', got %q", httpTrInvalid.TLSClientConfig.ServerName)
	}

	// 3. No BackendTLSPolicy (TLSConfig == nil) -> RootCAs == nil, !InsecureSkipVerify, ServerName == backend.Host
	noPolicyBackend := state.InternalBackend{
		Host:        "backend-svc.default.svc.cluster.local",
		Port:        443,
		AppProtocol: &httpsProto,
		TLSConfig:   nil,
	}
	trNoPolicy := p.buildTransport(noPolicyBackend)
	httpTrNoPolicy, ok := trNoPolicy.(*http.Transport)
	if !ok || httpTrNoPolicy.TLSClientConfig == nil {
		t.Fatalf("expected *http.Transport with non-nil TLSClientConfig")
	}
	if httpTrNoPolicy.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=false for backend without policy, got true")
	}
	if httpTrNoPolicy.TLSClientConfig.RootCAs != nil {
		t.Errorf("expected RootCAs == nil for backend without policy, got %v", httpTrNoPolicy.TLSClientConfig.RootCAs)
	}
	if httpTrNoPolicy.TLSClientConfig.ServerName != "backend-svc.default.svc.cluster.local" {
		t.Errorf("expected ServerName 'backend-svc.default.svc.cluster.local', got %q", httpTrNoPolicy.TLSClientConfig.ServerName)
	}
}

func TestBackendTLS_WithoutPolicy_Verification(t *testing.T) {
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"backend.local", "127.0.0.1"}, nil)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok-from-backend"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("failed to parse server port: %v", err)
	}
	httpsProto := "https"

	p := NewProxy()

	// 1. Backend with appProtocol: https, certificate from unknown CA, and NO policy
	// TLS handshake must fail verification against system roots and return 502 Bad Gateway.
	noPolicyBackend := state.InternalBackend{
		Host:        host,
		Port:        int32(port),
		AppProtocol: &httpsProto,
		Weight:      1,
		TLSConfig:   nil,
	}
	routeNoPolicy := state.InternalRoute{
		Hostnames: testRouteHostnames("test.example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{noPolicyBackend},
			},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{routeNoPolicy})

	reqNoPolicy := httptest.NewRequest("GET", "http://test.example.com/", nil)
	wNoPolicy := httptest.NewRecorder()
	p.ServeHTTP(wNoPolicy, reqNoPolicy)
	if wNoPolicy.Code != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway for untrusted backend cert without policy, got %d", wNoPolicy.Code)
	}

	// Also directly verify via RoundTrip that TLS handshake error is returned
	tr := p.buildTransport(noPolicyBackend)
	reqDirect, err := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host, port), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	_, err = tr.RoundTrip(reqDirect)
	if err == nil {
		t.Errorf("expected RoundTrip to fail certificate verification with unknown CA and no policy, but got nil error")
	}

	// 2. With BackendTLSPolicy naming the CA -> succeeds as today
	withPolicyBackend := state.InternalBackend{
		Host:        host,
		Port:        int32(port),
		AppProtocol: &httpsProto,
		Weight:      1,
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "backend.local",
			CACerts:  [][]byte{serverCAPEM},
		},
	}
	routeWithPolicy := state.InternalRoute{
		Hostnames: testRouteHostnames("test.example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{withPolicyBackend},
			},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{routeWithPolicy})

	reqWithPolicy := httptest.NewRequest("GET", "http://test.example.com/", nil)
	wWithPolicy := httptest.NewRecorder()
	p.ServeHTTP(wWithPolicy, reqWithPolicy)
	if wWithPolicy.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for backend with BackendTLSPolicy naming CA, got %d", wWithPolicy.Code)
	}
	if wWithPolicy.Body.String() != "ok-from-backend" {
		t.Errorf("expected body %q, got %q", "ok-from-backend", wWithPolicy.Body.String())
	}
}

func generateTestCAAndCert(t testing.TB, dnsNames []string, uris []*url.URL) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "backend"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		URIs:         uris,
	}
	srvBytes, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server certificate: %v", err)
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvBytes})
	keyBytes, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("failed to marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("failed to create X509 key pair: %v", err)
	}

	return caPEM, tlsCert
}

func TestBackendTLSPolicy_SubjectAltNamesVerification(t *testing.T) {
	testURI, _ := url.Parse("spiffe://example.com/test-service")
	caPEM, tlsCert := generateTestCAAndCert(t, []string{"dns.backend.local"}, []*url.URL{testURI})

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	tests := []struct {
		name          string
		hostname      string
		sans          []gatewayv1.SubjectAltName
		expectSuccess bool
	}{
		{
			name:     "matching DNS SAN verifies successfully",
			hostname: "dns.backend.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "dns.backend.local"},
			},
			expectSuccess: true,
		},
		{
			name:     "matching URI SAN verifies successfully",
			hostname: "anything.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.URISubjectAltNameType, URI: "spiffe://example.com/test-service"},
			},
			expectSuccess: true,
		},
		{
			name:     "certificate matches SAN but not hostname (hostname is SNI only)",
			hostname: "sni-only.example.com",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "dns.backend.local"},
			},
			expectSuccess: true,
		},
		{
			name:     "mismatched DNS SAN fails handshake",
			hostname: "dns.backend.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "mismatch.backend.local"},
			},
			expectSuccess: false,
		},
		{
			name:     "mismatched URI SAN fails handshake",
			hostname: "anything.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.URISubjectAltNameType, URI: "spiffe://example.com/wrong-service"},
			},
			expectSuccess: false,
		},
		{
			name:     "multiple SANs with one matching verifies successfully",
			hostname: "sni.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "wrong.local"},
				{Type: gatewayv1.URISubjectAltNameType, URI: "spiffe://example.com/test-service"},
			},
			expectSuccess: true,
		},
		{
			name:     "multiple SANs with none matching fails handshake",
			hostname: "sni.local",
			sans: []gatewayv1.SubjectAltName{
				{Type: gatewayv1.HostnameSubjectAltNameType, Hostname: "wrong1.local"},
				{Type: gatewayv1.URISubjectAltNameType, URI: "spiffe://example.com/wrong-service"},
			},
			expectSuccess: false,
		},
	}

	p := NewProxy()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := state.InternalBackend{
				Host:        host,
				Port:        int32(port),
				AppProtocol: &httpsProto,
				TLSConfig: &state.InternalTLSConfig{
					Hostname:        tc.hostname,
					CACerts:         [][]byte{caPEM},
					SubjectAltNames: tc.sans,
				},
			}
			tr := p.buildTransport(backend)
			client := &http.Client{Transport: tr}
			req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host, port), nil)
			resp, err := client.Do(req)

			if tc.expectSuccess {
				if err != nil {
					t.Fatalf("expected request to succeed, got error: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("expected 200 OK, got %d", resp.StatusCode)
				}
			} else {
				if err == nil {
					resp.Body.Close()
					t.Fatalf("expected TLS handshake to fail, but request succeeded with status %d", resp.StatusCode)
				}
			}
		})
	}
}

func TestProxy_H2C_GRPC(t *testing.T) {
	// 1. Setup h2c backend
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("grpc-reply"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "ok")
	})
	backendH2cHandler := h2c.NewHandler(backendHandler, &http2.Server{})
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for backend: %v", err)
	}
	defer backendLn.Close()
	backendSrv := &http.Server{Handler: backendH2cHandler}
	go backendSrv.Serve(backendLn)
	defer backendSrv.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	// 2. Setup Proxy with a matching route to the h2c backend
	p := NewProxy()
	h2cProto := "kubernetes.io/h2c"
	p.UpdateRoutes([]state.InternalRoute{
		{
			Hostnames: testRouteHostnames("example.com"),
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/my.service/Echo",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:        backendHost,
							Port:        int32(backendPort),
							AppProtocol: &h2cProto,
							Weight:      1,
						},
					},
				},
			},
		},
	})

	// 3. Run Proxy over h2c
	proxyH2cHandler := h2c.NewHandler(p, &http2.Server{})
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	defer proxyLn.Close()
	proxySrv := &http.Server{Handler: proxyH2cHandler}
	go proxySrv.Serve(proxyLn)
	defer proxySrv.Close()

	proxyAddr := proxyLn.Addr().String()

	// 4. HTTP/2 Client using h2c (prior knowledge)
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	// Subtest 1: Plain HTTP request matching no route -> HTTP 404
	t.Run("plain HTTP unmatched gets 404", func(t *testing.T) {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/non-existent", proxyAddr), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Host = "example.com"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "404 page not found\n" {
			t.Errorf("expected generic 404 body %q, got %q", "404 page not found\n", string(body))
		}
	})

	// Subtest 2: gRPC request matching no route -> HTTP 200 with grpc-status: 12 (Unimplemented)
	t.Run("gRPC unmatched gets 200 with grpc-status 12", func(t *testing.T) {
		req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/non-existent", proxyAddr), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Host = "example.com"
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/grpc" {
			t.Errorf("expected Content-Type application/grpc, got %q", ct)
		}
		if gs := resp.Header.Get("Grpc-Status"); gs != "12" {
			t.Errorf("expected Grpc-Status 12, got %q", gs)
		}
		if gm := resp.Header.Get("Grpc-Message"); gm != "" {
			t.Errorf("expected empty Grpc-Message by default, got %q", gm)
		}
	})

	// Subtest 3: Matching gRPC request reaches h2c backend
	t.Run("matching gRPC reaches h2c backend", func(t *testing.T) {
		req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/my.service/Echo", proxyAddr), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Host = "example.com"
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if string(body) != "grpc-reply" {
			t.Errorf("expected body 'grpc-reply', got %q", string(body))
		}
		if gs := resp.Trailer.Get("Grpc-Status"); gs != "0" {
			t.Errorf("expected trailer Grpc-Status 0, got %q", gs)
		}
	})
}

func TestBackendTLSPolicy_ClientCertificateAuth(t *testing.T) {
	// 1. Generate server CA and server cert
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	// 2. Generate client CA and client cert
	clientCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client CA key: %v", err)
	}
	clientCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Client Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	clientCABytes, err := x509.CreateCertificate(rand.Reader, clientCATemplate, clientCATemplate, &clientCAKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("failed to create client CA certificate: %v", err)
	}
	clientCACert, err := x509.ParseCertificate(clientCABytes)
	if err != nil {
		t.Fatalf("failed to parse client CA certificate: %v", err)
	}
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCACert)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "my-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, clientCACert, &clientKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})
	clientTLSCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to create client X509 key pair: %v", err)
	}

	// 3. Start test TLS server requiring client auth
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "missing client certificate", http.StatusForbidden)
			return
		}
		if r.TLS.PeerCertificates[0].Subject.CommonName != "my-client" {
			http.Error(w, "wrong client certificate", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	p := NewProxy()

	// Subtest 1: With ClientCert configured -> presents it and succeeds
	t.Run("with client cert presents it and succeeds", func(t *testing.T) {
		backend := state.InternalBackend{
			Host:        host,
			Port:        int32(port),
			AppProtocol: &httpsProto,
			TLSConfig: &state.InternalTLSConfig{
				Hostname:   "backend.local",
				CACerts:    [][]byte{serverCAPEM},
				ClientCert: &clientTLSCert,
			},
		}
		tr := p.buildTransport(backend)
		client := &http.Client{Transport: tr}
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host, port), nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("expected request to succeed, got error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "authenticated" {
			t.Errorf("expected body 'authenticated', got %q", string(body))
		}
	})

	// Subtest 2: Without ClientCert configured -> fails TLS handshake
	t.Run("without client cert fails handshake", func(t *testing.T) {
		backend := state.InternalBackend{
			Host:        host,
			Port:        int32(port),
			AppProtocol: &httpsProto,
			TLSConfig: &state.InternalTLSConfig{
				Hostname:   "backend.local",
				CACerts:    [][]byte{serverCAPEM},
				ClientCert: nil,
			},
		}
		tr := p.buildTransport(backend)
		client := &http.Client{Transport: tr}
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%d/", host, port), nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected TLS handshake to fail, but request succeeded with status %d", resp.StatusCode)
		}
	})
}

func TestBackendTLSPolicy_MissingClientCertID_FailsClosed(t *testing.T) {
	// 1. Generate server CA and server cert
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	// 2. Generate client CA and client cert
	clientCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client CA key: %v", err)
	}
	clientCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Client Test CA 2"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	clientCABytes, err := x509.CreateCertificate(rand.Reader, clientCATemplate, clientCATemplate, &clientCAKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("failed to create client CA certificate: %v", err)
	}
	clientCACert, err := x509.ParseCertificate(clientCABytes)
	if err != nil {
		t.Fatalf("failed to parse client CA certificate: %v", err)
	}
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCACert)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      pkix.Name{CommonName: "my-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, clientCACert, &clientKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})
	clientTLSCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to create client X509 key pair: %v", err)
	}

	// 3. Start test TLS server requiring client auth
	var handshakeCompleted atomic.Bool
	var connectionAttempts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			handshakeCompleted.Store(true)
			return nil
		},
	}
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectionAttempts.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	p := NewProxy()

	// 4. Construct a DataplaneConfig with missing-ID
	missingID := "missing-client-cert-id"
	rule := state.InternalRule{
		Matches: []state.InternalMatch{
			{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
		},
		Backends: []state.InternalBackend{
			{
				Host:        host,
				Port:        int32(port),
				AppProtocol: &httpsProto,
				TLSConfig: &state.InternalTLSConfig{
					Hostname:     "backend.local",
					CACerts:      [][]byte{serverCAPEM},
					ClientCertID: missingID,
				},
				Weight: 1,
			},
		},
	}
	dpConfig := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "default", Name: "test-gw"},
		Routes: []state.InternalRoute{
			{
				Hostnames: testRouteHostnames("backend.local"),
				Rules:     []state.InternalRule{rule},
			},
		},
		Certificates: map[string]state.CertificateData{}, // missingID is absent
	}

	missingData, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal missing-ID config: %v", err)
	}

	// 5. ApplyDataplaneConfig must reject the config
	if err := state.ApplyDataplaneConfig(p, missingData); err == nil {
		t.Fatalf("expected ApplyDataplaneConfig to reject missing-ID config, got nil")
	}

	// 6. Request to that backend fails and no TLS connection is attempted
	req := httptest.NewRequest("GET", "http://backend.local/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected request to unconfigured backend to fail, got 200 OK")
	}
	if handshakeCompleted.Load() {
		t.Fatalf("expected no TLS handshake to complete, but handshake completed")
	}
	if connectionAttempts.Load() != 0 {
		t.Fatalf("expected 0 TLS connection attempts to backend, got %d", connectionAttempts.Load())
	}

	// 7. Verify direct forward also fails closed without completing handshake if ClientCertID is set without ClientCert
	t.Run("direct forward with unpopulated ClientCert fails closed without handshake", func(t *testing.T) {
		handshakeCompleted.Store(false)
		connectionAttempts.Store(0)

		pDirect := NewProxy()
		pDirect.UpdateConfig(nil, []state.InternalRoute{
			{
				Hostnames: testRouteHostnames("backend.local"),
				Rules:     []state.InternalRule{rule},
			},
		})

		reqDirect := httptest.NewRequest("GET", "http://backend.local/", nil)
		recDirect := httptest.NewRecorder()
		pDirect.ServeHTTP(recDirect, reqDirect)

		if recDirect.Code != http.StatusBadGateway {
			t.Fatalf("expected 502 Bad Gateway, got %d", recDirect.Code)
		}
		if handshakeCompleted.Load() {
			t.Fatalf("expected no TLS handshake to complete, but handshake completed")
		}
		if connectionAttempts.Load() != 0 {
			t.Fatalf("expected 0 TLS connection attempts to backend, got %d", connectionAttempts.Load())
		}
	})

	// 8. With valid certificate present in config, applying succeeds and handshake completes
	t.Run("with valid certificate present in config handshake succeeds", func(t *testing.T) {
		handshakeCompleted.Store(false)
		connectionAttempts.Store(0)

		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(clientKey)
		if err != nil {
			t.Fatalf("failed to marshal private key to PKCS#8: %v", err)
		}
		dpConfig.Certificates[missingID] = state.CertificateData{
			Certificate: clientTLSCert.Certificate,
			PrivateKey:  pkcs8Key,
		}

		validData, err := dpConfig.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal valid config: %v", err)
		}
		if err := state.ApplyDataplaneConfig(p, validData); err != nil {
			t.Fatalf("expected ApplyDataplaneConfig to succeed with cert present: %v", err)
		}

		reqValid := httptest.NewRequest("GET", "http://backend.local/", nil)
		recValid := httptest.NewRecorder()
		p.ServeHTTP(recValid, reqValid)

		if recValid.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", recValid.Code, recValid.Body.String())
		}
		if !handshakeCompleted.Load() {
			t.Fatalf("expected TLS handshake to complete successfully")
		}
	})

	// 9. Verify buildBackendTLSConfig backstop fails handshake unconditionally even if backend does not request client certificates
	t.Run("buildBackendTLSConfig backstop fails handshake unconditionally without client auth", func(t *testing.T) {
		noAuthServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		noAuthServer.TLS = &tls.Config{
			Certificates: []tls.Certificate{serverCert},
		}
		noAuthServer.StartTLS()
		defer noAuthServer.Close()

		uNoAuth, err := url.Parse(noAuthServer.URL)
		if err != nil {
			t.Fatalf("failed to parse test server URL: %v", err)
		}
		portNoAuth, _ := strconv.Atoi(uNoAuth.Port())

		missingBackend := state.InternalBackend{
			Host:        uNoAuth.Hostname(),
			Port:        int32(portNoAuth),
			AppProtocol: &httpsProto,
			TLSConfig: &state.InternalTLSConfig{
				Hostname:     "backend.local",
				CACerts:      [][]byte{serverCAPEM},
				ClientCertID: "missing-cert-id",
			},
		}

		tlsCfg := p.buildBackendTLSConfig(missingBackend)
		if tlsCfg.InsecureSkipVerify {
			t.Errorf("expected InsecureSkipVerify to be false in backstop config, got true")
		}

		conn, dialErr := tls.Dial("tcp", noAuthServer.Listener.Addr().String(), tlsCfg)
		if conn != nil {
			conn.Close()
		}
		if dialErr == nil {
			t.Fatalf("expected TLS handshake to fail when ClientCertID is set without ClientCert against backend without client auth")
		}
		if !errors.Is(dialErr, errMissingClientCert) {
			t.Fatalf("expected error %v, got %v", errMissingClientCert, dialErr)
		}
	})

	t.Run("buildBackendTLSConfig backstop fails handshake against backend requiring client auth", func(t *testing.T) {
		missingBackend := state.InternalBackend{
			Host:        host,
			Port:        int32(port),
			AppProtocol: &httpsProto,
			TLSConfig: &state.InternalTLSConfig{
				Hostname:     "backend.local",
				CACerts:      [][]byte{serverCAPEM},
				ClientCertID: "missing-cert-id",
			},
		}

		tlsCfg := p.buildBackendTLSConfig(missingBackend)
		conn, dialErr := tls.Dial("tcp", server.Listener.Addr().String(), tlsCfg)
		if conn != nil {
			conn.Close()
		}
		if dialErr == nil {
			t.Fatalf("expected TLS handshake to fail when ClientCertID is set without ClientCert against backend requiring client auth")
		}
		if !errors.Is(dialErr, errMissingClientCert) {
			t.Fatalf("expected error %v, got %v", errMissingClientCert, dialErr)
		}
	})

	t.Run("backendMissingClientCert helper behavior", func(t *testing.T) {
		b := state.InternalBackend{
			TLSConfig: &state.InternalTLSConfig{
				ClientCertID: "missing-cert",
			},
		}
		if !backendMissingClientCert(b) {
			t.Errorf("expected backendMissingClientCert to be true")
		}

		b.TLSConfig.ClientCert = &clientTLSCert
		if backendMissingClientCert(b) {
			t.Errorf("expected backendMissingClientCert to be false when ClientCert is non-nil")
		}

		b.TLSConfig.ClientCertID = ""
		b.TLSConfig.ClientCert = nil
		if backendMissingClientCert(b) {
			t.Errorf("expected backendMissingClientCert to be false when ClientCertID is empty")
		}

		b.TLSConfig = nil
		if backendMissingClientCert(b) {
			t.Errorf("expected backendMissingClientCert to be false when TLSConfig is nil")
		}
	})
}

func TestServeHTTP_PortlessHostMatching(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	backendHost, backendPortStr, _ := net.SplitHostPort(backendURL.Host)
	backendPort, _ := strconv.Atoi(backendPortStr)
	backendRef := []state.InternalBackend{{Host: backendHost, Port: int32(backendPort), Weight: 1}}

	// Setup listeners representing:
	// - 443 catch-all (Hostname: "")
	// - 8443 exact listener (Hostname: "exact.example.com")
	// - 8443 wildcard listener (Hostname: "*.wildcard.example.com")
	// - 443 shared exact listener (Hostname: "shared.example.com")
	// - 8443 shared exact listener (Hostname: "shared.example.com")
	listeners := []state.InternalListener{
		{
			Name:     "catchall-443",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "",
			Routes: []state.InternalRoute{
				{
					Rules: []state.InternalRule{
						{
							Backends: backendRef,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{{Name: "X-Matched", Value: "443-catchall"}},
							},
						},
					},
				},
			},
		},
		{
			Name:     "exact-8443",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "exact.example.com",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("exact.example.com"),
					Rules: []state.InternalRule{
						{
							Backends: backendRef,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{{Name: "X-Matched", Value: "8443-exact"}},
							},
						},
					},
				},
			},
		},
		{
			Name:     "wildcard-8443",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "*.wildcard.example.com",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("*.wildcard.example.com"),
					Rules: []state.InternalRule{
						{
							Backends: backendRef,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{{Name: "X-Matched", Value: "8443-wildcard"}},
							},
						},
					},
				},
			},
		},
		{
			Name:     "shared-443",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "shared.example.com",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("shared.example.com"),
					Rules: []state.InternalRule{
						{
							Backends: backendRef,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{{Name: "X-Matched", Value: "443-shared"}},
							},
						},
					},
				},
			},
		},
		{
			Name:     "shared-8443",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "shared.example.com",
			Routes: []state.InternalRoute{
				{
					Hostnames: testRouteHostnames("shared.example.com"),
					Rules: []state.InternalRule{
						{
							Backends: backendRef,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{{Name: "X-Matched", Value: "8443-shared"}},
							},
						},
					},
				},
			},
		},
	}

	p := NewProxy()
	p.UpdateListeners(listeners)

	tests := []struct {
		name       string
		serverName string
		host       string
		wantStatus int
		wantMatch  string
	}{
		{
			name:       "port-less Host matching a non-443 exact listener",
			serverName: "exact.example.com",
			host:       "exact.example.com",
			wantStatus: http.StatusOK,
			wantMatch:  "8443-exact",
		},
		{
			name:       "port-less Host matching only a 443 catch-all",
			serverName: "other.example.com",
			host:       "other.example.com",
			wantStatus: http.StatusOK,
			wantMatch:  "443-catchall",
		},
		{
			name:       "port-less Host matching a non-443 wildcard",
			serverName: "foo.wildcard.example.com",
			host:       "foo.wildcard.example.com",
			wantStatus: http.StatusOK,
			wantMatch:  "8443-wildcard",
		},
		{
			name:       "explicit Host: h:8443",
			serverName: "shared.example.com",
			host:       "shared.example.com:8443",
			wantStatus: http.StatusOK,
			wantMatch:  "8443-shared",
		},
		{
			name:       "port-less Host tie breaks to 443",
			serverName: "shared.example.com",
			host:       "shared.example.com",
			wantStatus: http.StatusOK,
			wantMatch:  "443-shared",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tc.host+"/", nil)
			req.Host = tc.host
			req.TLS = &tls.ConnectionState{
				ServerName: tc.serverName,
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
			if got := resp.Header.Get("X-Matched"); got != tc.wantMatch {
				t.Errorf("expected X-Matched %q, got %q", tc.wantMatch, got)
			}
		})
	}
}

func TestProxy_GRPCRoute_HeaderModifiers(t *testing.T) {
	var receivedMu sync.Mutex
	var receivedHeaders http.Header

	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMu.Lock()
		receivedHeaders = r.Header.Clone()
		receivedMu.Unlock()

		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Resp-Original", "orig")
		w.Header().Set("X-Resp-Remove", "to-be-removed")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("grpc-reply"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "ok")
	})
	backendH2cHandler := h2c.NewHandler(backendHandler, &http2.Server{})
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for backend: %v", err)
	}
	defer backendLn.Close()
	backendSrv := &http.Server{Handler: backendH2cHandler}
	go backendSrv.Serve(backendLn)
	defer backendSrv.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	h2cProto := "kubernetes.io/h2c"
	port := gatewayv1.PortNumber(backendPort)
	serviceName := "my.service"
	methodName := "Echo"

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpcroute-modifiers",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &serviceName,
								Method:  &methodName,
							},
						},
					},
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestHeaderModifier,
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Rule-Req-Set", Value: "rule-set-val"},
								},
								Add: []gatewayv1.HTTPHeader{
									{Name: "X-Rule-Req-Add", Value: "rule-add-val"},
								},
								Remove: []string{"X-Rule-Req-Remove"},
							},
						},
						{
							Type: gatewayv1.GRPCRouteFilterResponseHeaderModifier,
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Rule-Resp-Set", Value: "rule-resp-set-val"},
								},
								Add: []gatewayv1.HTTPHeader{
									{Name: "X-Rule-Resp-Add", Value: "rule-resp-add-val"},
								},
								Remove: []string{"X-Resp-Remove"},
							},
						},
					},
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-svc",
									Port: &port,
								},
							},
							Filters: []gatewayv1.GRPCRouteFilter{
								{
									Type: gatewayv1.GRPCRouteFilterRequestHeaderModifier,
									RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "X-Backend-Req-Set", Value: "backend-set-val"},
										},
									},
								},
								{
									Type: gatewayv1.GRPCRouteFilterResponseHeaderModifier,
									ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "X-Backend-Resp-Set", Value: "backend-resp-set-val"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			ObjectMeta: metav1.ObjectMeta{
				Name:      "backend-svc",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Port:        int32(backendPort),
						AppProtocol: &h2cProto,
					},
				},
			},
		},
	}

	compiled := state.CompileGRPCRoute(grpcRoute, services, nil, nil, nil)
	if compiled == nil || len(compiled.Rules) != 1 || len(compiled.Rules[0].Backends) != 1 {
		t.Fatalf("expected compiled GRPCRoute with 1 rule and 1 backend, got %+v", compiled)
	}

	// Direct compiled backend to the live local test server listener
	compiled.Rules[0].Backends[0].Host = backendHost
	compiled.Rules[0].Backends[0].Port = int32(backendPort)

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Hostnames: testRouteHostnames(compiled.Hostnames...),
			Rules:     compiled.Rules,
		},
	})

	proxyH2cHandler := h2c.NewHandler(p, &http2.Server{})
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for proxy: %v", err)
	}
	defer proxyLn.Close()
	proxySrv := &http.Server{Handler: proxyH2cHandler}
	go proxySrv.Serve(proxyLn)
	defer proxySrv.Close()

	proxyAddr := proxyLn.Addr().String()

	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/my.service/Echo", proxyAddr), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Add("X-Rule-Req-Add", "orig-req-val")
	req.Header.Set("X-Rule-Req-Remove", "should-be-deleted")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != "grpc-reply" {
		t.Errorf("expected body 'grpc-reply', got %q", string(body))
	}

	if gs := resp.Trailer.Get("Grpc-Status"); gs != "0" {
		t.Errorf("expected Grpc-Status trailer 0, got %q", gs)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()

	// Verify request headers modified before reaching backend
	if ct := receivedHeaders.Get("Content-Type"); ct != "application/grpc" {
		t.Errorf("expected Content-Type application/grpc, got %q", ct)
	}
	if got := receivedHeaders.Get("X-Rule-Req-Set"); got != "rule-set-val" {
		t.Errorf("expected X-Rule-Req-Set 'rule-set-val', got %q", got)
	}
	reqAddValues := receivedHeaders.Values("X-Rule-Req-Add")
	if len(reqAddValues) != 2 || reqAddValues[0] != "orig-req-val" || reqAddValues[1] != "rule-add-val" {
		t.Errorf("expected X-Rule-Req-Add ['orig-req-val', 'rule-add-val'], got %v", reqAddValues)
	}
	if got := receivedHeaders.Get("X-Rule-Req-Remove"); got != "" {
		t.Errorf("expected X-Rule-Req-Remove to be removed, got %q", got)
	}
	if got := receivedHeaders.Get("X-Backend-Req-Set"); got != "backend-set-val" {
		t.Errorf("expected X-Backend-Req-Set 'backend-set-val', got %q", got)
	}

	// Verify response headers modified before reaching client
	if got := resp.Header.Get("X-Rule-Resp-Set"); got != "rule-resp-set-val" {
		t.Errorf("expected X-Rule-Resp-Set 'rule-resp-set-val', got %q", got)
	}
	if got := resp.Header.Get("X-Rule-Resp-Add"); got != "rule-resp-add-val" {
		t.Errorf("expected X-Rule-Resp-Add 'rule-resp-add-val', got %q", got)
	}
	if got := resp.Header.Get("X-Resp-Remove"); got != "" {
		t.Errorf("expected X-Resp-Remove to be removed, got %q", got)
	}
	if got := resp.Header.Get("X-Backend-Resp-Set"); got != "backend-resp-set-val" {
		t.Errorf("expected X-Backend-Resp-Set 'backend-resp-set-val', got %q", got)
	}
	if got := resp.Header.Get("X-Resp-Original"); got != "orig" {
		t.Errorf("expected X-Resp-Original 'orig', got %q", got)
	}
}

func TestProxy_GRPCRoute_BackendTLSPolicy(t *testing.T) {
	backendCAPEM, backendCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	tests := []struct {
		name       string
		serverALPN []string
		wantStatus int
		wantErr    string
	}{
		{
			name:       "ALPN h2 negotiated",
			serverALPN: []string{"h2"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "ALPN mismatch",
			serverALPN: nil, // server does not configure ALPN, handshake completes without h2
			wantStatus: http.StatusBadGateway,
			wantErr:    "unexpected ALPN protocol",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if te := r.Header.Get("Te"); !strings.EqualFold(te, "trailers") {
					t.Errorf("expected Te header 'trailers', got %q", te)
				}
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("grpc-reply"))
				w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
			})

			backendTLS := &tls.Config{
				Certificates: []tls.Certificate{backendCert},
				NextProtos:   tc.serverALPN,
			}
			backendLn, err := tls.Listen("tcp", "127.0.0.1:0", backendTLS)
			if err != nil {
				t.Fatalf("failed to listen for backend: %v", err)
			}
			defer backendLn.Close()
			backendSrv := &http.Server{Handler: backendHandler}
			if len(tc.serverALPN) > 0 {
				if err := http2.ConfigureServer(backendSrv, &http2.Server{}); err != nil {
					t.Fatalf("failed to configure http2 server: %v", err)
				}
			}
			go backendSrv.Serve(backendLn)
			defer backendSrv.Close()

			backendHost, backendPortStr, err := net.SplitHostPort(backendLn.Addr().String())
			if err != nil {
				t.Fatalf("failed to split host port: %v", err)
			}
			backendPort, err := strconv.Atoi(backendPortStr)
			if err != nil {
				t.Fatalf("failed to parse backend port: %v", err)
			}

			backend := state.InternalBackend{
				Host:        backendHost,
				Port:        int32(backendPort),
				AppProtocol: state.Ptr("https"),
				HTTP2:       true,
				Weight:      1,
				TLSConfig: &state.InternalTLSConfig{
					Hostname: "backend.local",
					CACerts:  [][]byte{backendCAPEM},
				},
			}

			p := NewProxy()
			p.UpdateRoutes([]state.InternalRoute{
				{
					Hostnames: testRouteHostnames("example.com"),
					Rules: []state.InternalRule{
						{Backends: []state.InternalBackend{backend}},
					},
				},
			})

			if tc.wantErr != "" {
				transport := p.buildTransport(backend)
				outReq, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%d/my.service/Echo", backendHost, backendPort), bytes.NewReader([]byte("ping")))
				if err != nil {
					t.Fatalf("failed to create direct request: %v", err)
				}
				outReq.Host = "example.com"
				_, roundTripErr := transport.RoundTrip(outReq)
				if roundTripErr == nil || !strings.Contains(roundTripErr.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErr, roundTripErr)
				}
			}

			req := httptest.NewRequest("POST", "http://example.com/my.service/Echo", bytes.NewReader([]byte("ping")))
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("Te", "trailers")
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
			if tc.wantStatus == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read body: %v", err)
				}
				if string(body) != "grpc-reply" {
					t.Errorf("expected body 'grpc-reply', got %q", string(body))
				}
				if resp.Header.Get("Grpc-Status") != "0" && resp.Trailer.Get("Grpc-Status") != "0" {
					t.Errorf("expected Grpc-Status trailer '0', got header %q trailer %q", resp.Header.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Status"))
				}
			}
		})
	}
}

func TestRemoveHopByHopHeaders_TETrailers(t *testing.T) {
	h := http.Header{
		"Te":         []string{"trailers"},
		"Connection": []string{"close"},
		"Upgrade":    []string{"websocket"},
	}
	removeHopByHopHeaders(h)
	if got := h.Get("Te"); got != "trailers" {
		t.Errorf("expected TE: trailers to be preserved, got %q", got)
	}
	if h.Get("Connection") != "" || h.Get("Upgrade") != "" {
		t.Errorf("expected hop-by-hop headers to be removed, got %v", h)
	}

	hNonTrailers := http.Header{
		"Te": []string{"deflate"},
	}
	removeHopByHopHeaders(hNonTrailers)
	if got := hNonTrailers.Get("Te"); got != "" {
		t.Errorf("expected non-trailers TE to be removed, got %q", got)
	}

	hConnTe := http.Header{
		"Connection": []string{"te"},
		"Te":         []string{"deflate"},
	}
	removeHopByHopHeaders(hConnTe)
	if got := hConnTe.Get("Te"); got != "" {
		t.Errorf("expected TE listed in Connection to be removed, got %q", got)
	}

	hCustom := http.Header{
		"Connection": []string{"X-Custom"},
		"X-Custom":   []string{"v"},
	}
	removeHopByHopHeaders(hCustom)
	if got := hCustom.Get("X-Custom"); got != "" {
		t.Errorf("expected header listed in Connection to be removed, got %q", got)
	}
}

func TestProxy_BackendResponseConnectionHeaderRemoved(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Custom")
		w.Header().Set("X-Custom", "v")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	recorder := httptest.NewRecorder()

	p.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Custom"); got != "" {
		t.Errorf("expected X-Custom to be removed from response, got %q", got)
	}
	if got := resp.Header.Get("Connection"); got != "" {
		t.Errorf("expected Connection to be removed from response, got %q", got)
	}
}

func TestProxy_ClientConnectionHeaderCannotStripFilterAddedHeader(t *testing.T) {
	var receivedHeaders http.Header
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendServer.Close()

	u, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p := NewProxy()
	p.UpdateRoutes([]state.InternalRoute{
		{
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{
							Host:   host,
							Port:   int32(port),
							Weight: 1,
						},
					},
					RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
						Set: []gatewayv1.HTTPHeader{
							{Name: "X-Added", Value: "gateway-value"},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("Connection", "X-Added")
	recorder := httptest.NewRecorder()

	p.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := receivedHeaders.Get("X-Added"); got != "gateway-value" {
		t.Errorf("expected backend to receive X-Added: gateway-value, got %q", got)
	}
	if got := receivedHeaders.Get("Connection"); got != "" {
		t.Errorf("expected Connection header to be stripped, got %q", got)
	}
}

func TestProxy_BackendConnectionReuse(t *testing.T) {
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	var handshakes atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			handshakes.Add(1)
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	p := NewProxy()
	route := state.InternalRoute{
		Hostnames: testRouteHostnames("example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{
					{
						Host:        host,
						Port:        int32(port),
						AppProtocol: &httpsProto,
						Weight:      1,
						TLSConfig: &state.InternalTLSConfig{
							Hostname: "backend.local",
							CACerts:  [][]byte{serverCAPEM},
						},
					},
				},
			},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{route})

	// Request 1
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w1 := httptest.NewRecorder()
	p.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("request 1 failed: status %d", w1.Code)
	}

	// Request 2 to the same TLS backend
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("request 2 failed: status %d", w2.Code)
	}

	if hs := handshakes.Load(); hs != 1 {
		t.Errorf("expected 1 TLS handshake for 2 requests to same backend (connection reuse), got %d", hs)
	}
}

func TestProxy_BackendTransportCachingAndEviction(t *testing.T) {
	httpsProto := "https"
	b1 := state.InternalBackend{
		Host:        "backend1.local",
		Port:        8443,
		AppProtocol: &httpsProto,
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "backend1.local",
		},
	}
	b2 := state.InternalBackend{
		Host:        "backend2.local",
		Port:        8443,
		AppProtocol: &httpsProto,
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "backend2.local",
		},
	}

	p := NewProxy()
	tr1 := p.buildTransport(b1)
	tr2 := p.buildTransport(b1)
	if tr1 != tr2 {
		t.Fatalf("expected buildTransport to return cached transport for same backend")
	}

	trB2 := p.buildTransport(b2)
	if tr1 == trB2 {
		t.Fatalf("expected different transports for different backends")
	}

	// Configure routes with only b1
	route1 := state.InternalRoute{
		Rules: []state.InternalRule{
			{Backends: []state.InternalBackend{b1}},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{route1})

	// b2 should have been evicted
	p.transportsMu.Lock()
	_, b1Cached := p.transports[backendTransportKey(b1)]
	_, b2Cached := p.transports[backendTransportKey(b2)]
	p.transportsMu.Unlock()

	if !b1Cached {
		t.Errorf("expected b1 to remain cached")
	}
	if b2Cached {
		t.Errorf("expected b2 to be evicted")
	}

	// HTTP/2 transport for b1 (via GRPCRoute) should be separate from HTTP/1.1
	b1H2 := b1
	b1H2.HTTP2 = true
	http2Transport := p.buildTransport(b1H2)
	if tr1 == http2Transport {
		t.Fatalf("expected HTTP/1.1 and HTTP/2 transports to be separate")
	}

	// Update routes with only b1H2; b1 HTTP/1.1 transport should be evicted
	p.UpdateRoutes([]state.InternalRoute{
		{Rules: []state.InternalRule{{Backends: []state.InternalBackend{b1H2}}}},
	})

	p.transportsMu.Lock()
	_, b1CachedAfter := p.transports[backendTransportKey(b1)]
	_, b1H2CachedAfter := p.transports[backendTransportKey(b1H2)]
	p.transportsMu.Unlock()

	if b1CachedAfter || !b1H2CachedAfter {
		t.Errorf("expected b1 HTTP/1.1 evicted and b1H2 HTTP/2 retained, got b1=%v, b1H2=%v", b1CachedAfter, b1H2CachedAfter)
	}
}

func TestTLSSessionResumption_HTTPToTLSBackend(t *testing.T) {
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	var mu sync.Mutex
	var resumeStates []bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			mu.Lock()
			resumeStates = append(resumeStates, cs.DidResume)
			mu.Unlock()
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	p := NewProxy()
	b := state.InternalBackend{
		Host:        host,
		Port:        int32(port),
		AppProtocol: &httpsProto,
		Weight:      1,
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "backend.local",
			CACerts:  [][]byte{serverCAPEM},
		},
	}
	route := state.InternalRoute{
		Hostnames: testRouteHostnames("example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{b},
			},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{route})

	// Request 1: triggers first dial
	req1 := httptest.NewRequest("GET", "http://example.com/", nil)
	w1 := httptest.NewRecorder()
	p.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("request 1 failed: status %d, body: %q", w1.Code, w1.Body.String())
	}

	// Close idle connections to force transport to dial a new connection on next request
	p.transportsMu.Lock()
	tr := p.transports[backendTransportKey(b)]
	tr.(*http.Transport).CloseIdleConnections()
	p.transportsMu.Unlock()

	// Request 2: dials new connection, which should resume via ClientSessionCache
	req2 := httptest.NewRequest("GET", "http://example.com/", nil)
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("request 2 failed: status %d, body: %q", w2.Code, w2.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(resumeStates) != 2 {
		t.Fatalf("expected 2 TLS handshakes, got %d", len(resumeStates))
	}
	if resumeStates[0] {
		t.Errorf("connection 1 expected DidResume=false, got true")
	}
	if !resumeStates[1] {
		t.Errorf("connection 2 expected DidResume=true, got false")
	}
}

func TestTLSSessionResumption_TLSRouteReencryptBackend(t *testing.T) {
	serverCAPEM, serverCert := generateTestCAAndCert(t, []string{"reencrypt.backend.local"}, nil)

	var mu sync.Mutex
	var resumeStates []bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			mu.Lock()
			resumeStates = append(resumeStates, cs.DidResume)
			mu.Unlock()
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	u, _ := url.Parse(server.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	targetAddr := fmt.Sprintf("%s:%d", host, port)

	p := NewProxy()
	b := state.InternalBackend{
		Host: host,
		Port: int32(port),
		TLSConfig: &state.InternalTLSConfig{
			Hostname: "reencrypt.backend.local",
			CACerts:  [][]byte{serverCAPEM},
		},
	}

	// Dial 1 via buildBackendTLSConfig
	tlsCfg1 := p.buildBackendTLSConfig(b)
	var d1 net.Dialer
	conn1, err := tls.DialWithDialer(&d1, "tcp", targetAddr, tlsCfg1)
	if err != nil {
		t.Fatalf("dial 1 failed: %v", err)
	}
	req := "GET / HTTP/1.1\r\nHost: reencrypt.backend.local\r\nConnection: close\r\n\r\n"
	if _, err := conn1.Write([]byte(req)); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	_, _ = io.ReadAll(conn1)
	if conn1.ConnectionState().DidResume {
		t.Errorf("dial 1 expected DidResume=false, got true")
	}
	conn1.Close()

	// Dial 2 via buildBackendTLSConfig
	tlsCfg2 := p.buildBackendTLSConfig(b)
	var d2 net.Dialer
	conn2, err := tls.DialWithDialer(&d2, "tcp", targetAddr, tlsCfg2)
	if err != nil {
		t.Fatalf("dial 2 failed: %v", err)
	}
	if _, err := conn2.Write([]byte(req)); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	_, _ = io.ReadAll(conn2)
	if !conn2.ConnectionState().DidResume {
		t.Errorf("dial 2 expected DidResume=true, got false")
	}
	conn2.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(resumeStates) != 2 {
		t.Fatalf("expected 2 server-side handshake events, got %d", len(resumeStates))
	}
	if resumeStates[0] {
		t.Errorf("server handshake 1 expected DidResume=false, got true")
	}
	if !resumeStates[1] {
		t.Errorf("server handshake 2 expected DidResume=true, got false")
	}
}

func BenchmarkProxy_TLSBackend_Handshakes(b *testing.B) {
	serverCAPEM, serverCert := generateTestCAAndCert(b, []string{"bench.backend.local"}, nil)
	var handshakes atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			handshakes.Add(1)
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	u, _ := url.Parse(server.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	httpsProto := "https"

	p := NewProxy()
	route := state.InternalRoute{
		Hostnames: testRouteHostnames("bench.example.com"),
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
				},
				Backends: []state.InternalBackend{
					{
						Host:        host,
						Port:        int32(port),
						AppProtocol: &httpsProto,
						Weight:      1,
						TLSConfig: &state.InternalTLSConfig{
							Hostname: "bench.backend.local",
							CACerts:  [][]byte{serverCAPEM},
						},
					},
				},
			},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{route})

	req := httptest.NewRequest("GET", "http://bench.example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
	}
	b.StopTimer()
	b.ReportMetric(float64(handshakes.Load()), "handshakes")
}

func TestProxy_ClientSessionCacheDynamicSizing_GrowAndShrink(t *testing.T) {
	p := NewProxy()

	// Initial default capacity should be 256
	if cap := p.getClientSessionCache().Capacity(); cap != 256 {
		t.Fatalf("expected initial capacity 256, got %d", cap)
	}

	httpsProto := "https"
	const numBackends = 300
	backends := make([]state.InternalBackend, numBackends)
	for i := 0; i < numBackends; i++ {
		backends[i] = state.InternalBackend{
			Host:        fmt.Sprintf("backend-%d.local", i),
			Port:        8443,
			AppProtocol: &httpsProto,
			TLSConfig: &state.InternalTLSConfig{
				Hostname: fmt.Sprintf("backend-%d.local", i),
			},
		}
	}

	// 1. Grow: Configure routes with 300 distinct TLS backends (exceeding old static bound of 128 and default 256)
	// Capacity should be clamp(2 * 300, 256, 65536) = 600
	route := state.InternalRoute{
		Rules: []state.InternalRule{
			{Backends: backends},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{route})

	cache := p.getClientSessionCache()
	if cap := cache.Capacity(); cap != 600 {
		t.Fatalf("expected grown capacity 600, got %d", cap)
	}

	// Populate sessions for all 300 backends via buildBackendTLSConfig
	for i := 0; i < numBackends; i++ {
		cfg := p.buildBackendTLSConfig(backends[i])
		cfg.ClientSessionCache.Put(fmt.Sprintf("backend-%d.local", i), &tls.ClientSessionState{})
	}

	if cache.Len() != numBackends {
		t.Fatalf("expected cache len %d, got %d", numBackends, cache.Len())
	}

	// Verify resumption cache lookup succeeds for every backend
	for i := 0; i < numBackends; i++ {
		cfg := p.buildBackendTLSConfig(backends[i])
		if _, ok := cfg.ClientSessionCache.Get(fmt.Sprintf("backend-%d.local", i)); !ok {
			t.Fatalf("expected session state present for backend %d", i)
		}
	}

	// 2. Shrink: Update routes with only 50 distinct backends
	// Capacity should shrink to clamp(2 * 50, 256, 65536) = 256
	shrunkRoute := state.InternalRoute{
		Rules: []state.InternalRule{
			{Backends: backends[:50]},
		},
	}
	p.UpdateRoutes([]state.InternalRoute{shrunkRoute})

	if cap := cache.Capacity(); cap != 256 {
		t.Fatalf("expected shrunk capacity 256, got %d", cap)
	}
	if cache.Len() > 256 {
		t.Fatalf("expected cache len <= 256 after shrink, got %d", cache.Len())
	}
	if cache.Len() != 256 {
		t.Fatalf("expected cache len 256 (oldest 44 of the 300 evicted), got %d", cache.Len())
	}
}

func TestProxy_WrapUnwrapSession_NoWriteLock(t *testing.T) {
	p := NewProxy()

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Calling wrapSession and unwrapSession while holding RLock must not deadlock or block
	// since ticketConfig is initialized in NewProxy and accessed concurrently without write locks.
	done := make(chan struct{})
	go func() {
		defer close(done)
		cs := tls.ConnectionState{ServerName: "example.com"}
		ss := &tls.SessionState{}
		ticket, err := p.wrapSession(cs, ss)
		if err != nil {
			t.Errorf("wrapSession failed: %v", err)
			return
		}
		if len(ticket) == 0 {
			t.Errorf("expected non-empty ticket")
			return
		}
		// unwrapSession must not attempt to acquire p.mu.Lock() either.
		_, _ = p.unwrapSession(ticket, cs)
	}()

	select {
	case <-done:
		// Success: neither wrapSession nor unwrapSession contended on p.mu.Lock()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("deadlock: wrapSession or unwrapSession attempted to acquire write lock while read lock was held")
	}
}

func TestProxy_UnmatchedResponses_GenericByDefaultAndDebugFlag(t *testing.T) {
	t.Run("Plain HTTP default returns generic 404", func(t *testing.T) {
		p := NewProxy()
		req := httptest.NewRequest("GET", "http://example.com/unmatched-path", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		expected := "404 page not found\n"
		if string(body) != expected {
			t.Errorf("expected body %q, got %q", expected, string(body))
		}
		if strings.Contains(string(body), "example.com") || strings.Contains(string(body), "/unmatched-path") {
			t.Errorf("generic 404 body reflected client input: %q", string(body))
		}
	})

	t.Run("Plain HTTP debug returns verbose 404", func(t *testing.T) {
		p := NewProxy()
		p.SetDebugErrorResponses(true)
		req := httptest.NewRequest("GET", "http://example.com/unmatched-path", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		expected := "No route for host example.com and path /unmatched-path\n"
		if string(body) != expected {
			t.Errorf("expected body %q, got %q", expected, string(body))
		}
	})

	t.Run("gRPC default returns status 12 without Grpc-Message", func(t *testing.T) {
		p := NewProxy()
		req := httptest.NewRequest("POST", "http://example.com/my.service/Echo", nil)
		req.Header.Set("Content-Type", "application/grpc")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if gs := resp.Header.Get("Grpc-Status"); gs != "12" {
			t.Errorf("expected Grpc-Status 12, got %q", gs)
		}
		if gm := resp.Header.Get("Grpc-Message"); gm != "" {
			t.Errorf("expected empty Grpc-Message by default, got %q", gm)
		}
	})

	t.Run("gRPC debug returns status 12 with Grpc-Message", func(t *testing.T) {
		p := NewProxy()
		p.SetDebugErrorResponses(true)
		req := httptest.NewRequest("POST", "http://example.com/my.service/Echo", nil)
		req.Header.Set("Content-Type", "application/grpc")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if gs := resp.Header.Get("Grpc-Status"); gs != "12" {
			t.Errorf("expected Grpc-Status 12, got %q", gs)
		}
		expectedMsg := "No route for host example.com and path /my.service/Echo"
		if gm := resp.Header.Get("Grpc-Message"); gm != expectedMsg {
			t.Errorf("expected Grpc-Message %q, got %q", expectedMsg, gm)
		}
	})

	t.Run("HTTPS unmatched SNI default returns generic 404", func(t *testing.T) {
		p := NewProxy()
		p.UpdateListeners([]state.InternalListener{
			{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: "allowed.example.com",
			},
		})
		req := httptest.NewRequest("GET", "https://unmatched.example.com/test", nil)
		req.TLS = &tls.ConnectionState{
			ServerName: "unmatched.example.com",
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		expected := "404 page not found\n"
		if string(body) != expected {
			t.Errorf("expected body %q, got %q", expected, string(body))
		}
		if strings.Contains(string(body), "unmatched.example.com") {
			t.Errorf("generic 404 body reflected SNI: %q", string(body))
		}
	})

	t.Run("HTTPS unmatched SNI debug returns verbose 404", func(t *testing.T) {
		p := NewProxy()
		p.SetDebugErrorResponses(true)
		p.UpdateListeners([]state.InternalListener{
			{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: "allowed.example.com",
			},
		})
		req := httptest.NewRequest("GET", "https://unmatched.example.com/test", nil)
		req.TLS = &tls.ConnectionState{
			ServerName: "unmatched.example.com",
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		expected := "No listener for server name unmatched.example.com\n"
		if string(body) != expected {
			t.Errorf("expected body %q, got %q", expected, string(body))
		}
	})
}
