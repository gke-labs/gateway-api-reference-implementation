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
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestForwardedProto(t *testing.T) {
	p := NewProxy()

	tests := []struct {
		name          string
		tls           *tls.ConnectionState
		proto         string
		protoMajor    int
		urlScheme     string
		incomingXFP   string
		expectedProto string
	}{
		{
			name:          "plaintext HTTP request",
			expectedProto: "http",
		},
		{
			name:          "plaintext HTTP request with spoofed client X-Forwarded-Proto",
			incomingXFP:   "https",
			expectedProto: "http",
		},
		{
			name:          "TLS connection",
			tls:           &tls.ConnectionState{},
			expectedProto: "https",
		},
		{
			name:          "TLS connection with spoofed client X-Forwarded-Proto",
			tls:           &tls.ConnectionState{},
			incomingXFP:   "http",
			expectedProto: "https",
		},
		{
			name:          "HTTP/3 via proto string",
			proto:         "HTTP/3",
			protoMajor:    3,
			expectedProto: "https",
		},
		{
			name:          "HTTP/3.0 via proto string",
			proto:         "HTTP/3.0",
			protoMajor:    3,
			expectedProto: "https",
		},
		{
			name:          "HTTPS URL scheme",
			urlScheme:     "https",
			expectedProto: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawURL := "http://example.com/test"
			if tt.urlScheme != "" {
				rawURL = tt.urlScheme + "://example.com/test"
			}
			inReq := httptest.NewRequest("GET", rawURL, nil)
			inReq.TLS = tt.tls
			if tt.proto != "" {
				inReq.Proto = tt.proto
				inReq.ProtoMajor = tt.protoMajor
			}
			if tt.incomingXFP != "" {
				inReq.Header.Set("X-Forwarded-Proto", tt.incomingXFP)
			}

			outReq, _, err := p.buildBackendRequest(t.Context(), inReq, state.InternalBackend{Host: "backend.local", Port: 8080}, nil)
			if err != nil {
				t.Fatalf("buildBackendRequest failed: %v", err)
			}

			if got := outReq.Header.Get("X-Forwarded-Proto"); got != tt.expectedProto {
				t.Errorf("expected X-Forwarded-Proto %q, got %q", tt.expectedProto, got)
			}
		})
	}
}

func TestForwardedHost(t *testing.T) {
	t.Run("with URLRewrite changing hostname", func(t *testing.T) {
		p := NewProxy()
		inReq := httptest.NewRequest("GET", "http://original.example.com/api", nil)
		inReq.Host = "original.example.com"
		inReq.Header.Set("X-Forwarded-Host", "spoofed.example.com")

		// Rewrite hostname
		inReq = p.rewrite(inReq, state.InternalRewrite{
			Hostname: state.Ptr(gatewayv1.PreciseHostname("rewritten.example.com")),
		}, nil)

		outReq, _, err := p.buildBackendRequest(t.Context(), inReq, state.InternalBackend{Host: "backend.local", Port: 8080}, nil)
		if err != nil {
			t.Fatalf("buildBackendRequest failed: %v", err)
		}

		if got := outReq.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
			t.Errorf("expected X-Forwarded-Host %q, got %q", "original.example.com", got)
		}
		if outReq.Host != "rewritten.example.com" {
			t.Errorf("expected outbound Host %q, got %q", "rewritten.example.com", outReq.Host)
		}
	})

	t.Run("without URLRewrite hostname change", func(t *testing.T) {
		p := NewProxy()
		inReq := httptest.NewRequest("GET", "http://example.com/api", nil)
		inReq.Host = "example.com"
		inReq.Header.Set("X-Forwarded-Host", "spoofed.example.com")

		outReq, _, err := p.buildBackendRequest(t.Context(), inReq, state.InternalBackend{Host: "backend.local", Port: 8080}, nil)
		if err != nil {
			t.Fatalf("buildBackendRequest failed: %v", err)
		}

		// When not rewritten, X-Forwarded-Host is omitted and client spoofed value is dropped
		if got := outReq.Header.Get("X-Forwarded-Host"); got != "" {
			t.Errorf("expected X-Forwarded-Host to be omitted, got %q", got)
		}
		if outReq.Host != "example.com" {
			t.Errorf("expected outbound Host %q, got %q", "example.com", outReq.Host)
		}
	})
}

func TestForwardedFor(t *testing.T) {
	tests := []struct {
		name        string
		mode        ForwardedForMode
		remoteAddr  string
		existingXFF []string
		expectedXFF string
	}{
		{
			name:        "append mode: no prior XFF",
			mode:        ForwardedForModeAppend,
			remoteAddr:  "192.0.2.1:54321",
			expectedXFF: "192.0.2.1",
		},
		{
			name:        "append mode: single prior XFF",
			mode:        ForwardedForModeAppend,
			remoteAddr:  "192.0.2.1:54321",
			existingXFF: []string{"203.0.113.1"},
			expectedXFF: "203.0.113.1, 192.0.2.1",
		},
		{
			name:        "append mode: multiple prior XFF values",
			mode:        ForwardedForModeAppend,
			remoteAddr:  "192.0.2.1:54321",
			existingXFF: []string{"198.51.100.1", "203.0.113.1"},
			expectedXFF: "198.51.100.1, 203.0.113.1, 192.0.2.1",
		},
		{
			name:        "append mode: IPv6 remote address",
			mode:        ForwardedForModeAppend,
			remoteAddr:  "[2001:db8::1]:54321",
			existingXFF: []string{"203.0.113.1"},
			expectedXFF: "203.0.113.1, 2001:db8::1",
		},
		{
			name:        "replace mode: client-supplied XFF is dropped",
			mode:        ForwardedForModeReplace,
			remoteAddr:  "192.0.2.1:54321",
			existingXFF: []string{"203.0.113.1, 198.51.100.5"},
			expectedXFF: "192.0.2.1",
		},
		{
			name:        "replace mode: no prior XFF",
			mode:        ForwardedForModeReplace,
			remoteAddr:  "192.0.2.1:54321",
			expectedXFF: "192.0.2.1",
		},
		{
			name:        "replace mode: empty remote addr drops client XFF",
			mode:        ForwardedForModeReplace,
			remoteAddr:  "",
			existingXFF: []string{"203.0.113.1"},
			expectedXFF: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			p.SetForwardedForMode(tt.mode)

			inReq := httptest.NewRequest("GET", "http://example.com/api", nil)
			inReq.RemoteAddr = tt.remoteAddr
			for _, xff := range tt.existingXFF {
				inReq.Header.Add("X-Forwarded-For", xff)
			}

			outReq, _, err := p.buildBackendRequest(t.Context(), inReq, state.InternalBackend{Host: "backend.local", Port: 8080}, nil)
			if err != nil {
				t.Fatalf("buildBackendRequest failed: %v", err)
			}

			if got := outReq.Header.Get("X-Forwarded-For"); got != tt.expectedXFF {
				t.Errorf("expected X-Forwarded-For %q, got %q", tt.expectedXFF, got)
			}
		})
	}
}

func TestForwarded(t *testing.T) {
	tests := []struct {
		name              string
		mode              ForwardedForMode
		remoteAddr        string
		host              string
		tls               *tls.ConnectionState
		existingForwarded []string
		expectedForwarded string
	}{
		{
			name:              "replace mode: client Forwarded is dropped and replaced with gateway values",
			mode:              ForwardedForModeReplace,
			remoteAddr:        "192.0.2.1:54321",
			host:              "example.com",
			existingForwarded: []string{"for=1.1.1.1;host=other"},
			expectedForwarded: "for=192.0.2.1;proto=http;host=example.com",
		},
		{
			name:              "append mode: client element is kept and gateway element is appended",
			mode:              ForwardedForModeAppend,
			remoteAddr:        "192.0.2.1:54321",
			host:              "example.com",
			existingForwarded: []string{"for=1.1.1.1;host=other"},
			expectedForwarded: "for=1.1.1.1;host=other, for=192.0.2.1;proto=http;host=example.com",
		},
		{
			name:              "append mode: no prior Forwarded header",
			mode:              ForwardedForModeAppend,
			remoteAddr:        "192.0.2.1:54321",
			host:              "example.com",
			expectedForwarded: "for=192.0.2.1;proto=http;host=example.com",
		},
		{
			name:              "append mode: IPv6 remote address is quoted and bracketed",
			mode:              ForwardedForModeAppend,
			remoteAddr:        "[2001:db8::1]:54321",
			host:              "example.com",
			existingForwarded: []string{"for=1.1.1.1;host=other"},
			expectedForwarded: "for=1.1.1.1;host=other, for=\"[2001:db8::1]\";proto=http;host=example.com",
		},
		{
			name:              "replace mode: TLS connection sets proto=https",
			mode:              ForwardedForModeReplace,
			remoteAddr:        "192.0.2.1:54321",
			host:              "example.com",
			tls:               &tls.ConnectionState{},
			existingForwarded: []string{"for=1.1.1.1;host=other"},
			expectedForwarded: "for=192.0.2.1;proto=https;host=example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			p.SetForwardedForMode(tt.mode)

			inReq := httptest.NewRequest("GET", "http://"+tt.host+"/api", nil)
			inReq.Host = tt.host
			inReq.RemoteAddr = tt.remoteAddr
			inReq.TLS = tt.tls
			for _, fwd := range tt.existingForwarded {
				inReq.Header.Add("Forwarded", fwd)
			}

			outReq, _, err := p.buildBackendRequest(t.Context(), inReq, state.InternalBackend{Host: "backend.local", Port: 8080}, nil)
			if err != nil {
				t.Fatalf("buildBackendRequest failed: %v", err)
			}

			if got := outReq.Header.Get("Forwarded"); got != tt.expectedForwarded {
				t.Errorf("expected Forwarded %q, got %q", tt.expectedForwarded, got)
			}
		})
	}
}

func TestForwardedHeaders_AllPathsProduceSameHeaders(t *testing.T) {
	type capturedHeaders struct {
		xfp  string
		xfh  string
		xff  string
		host string
	}

	testCases := []struct {
		name          string
		mode          ForwardedForMode
		isTLS         bool
		rewriteHost   string
		clientHost    string
		clientRemote  string
		clientHeaders map[string]string
		wantXFP       string
		wantXFH       string
		wantXFF       string
		wantHost      string
	}{
		{
			name:         "plaintext with rewrite in append mode",
			mode:         ForwardedForModeAppend,
			isTLS:        false,
			rewriteHost:  "rewritten.internal",
			clientHost:   "client.example.com",
			clientRemote: "198.51.100.1:12345",
			clientHeaders: map[string]string{
				"X-Forwarded-For":   "203.0.113.50",
				"X-Forwarded-Proto": "spoofed-proto",
				"X-Forwarded-Host":  "spoofed-host",
			},
			wantXFP:  "http",
			wantXFH:  "client.example.com",
			wantXFF:  "203.0.113.50, 198.51.100.1",
			wantHost: "rewritten.internal",
		},
		{
			name:         "TLS with rewrite in replace mode",
			mode:         ForwardedForModeReplace,
			isTLS:        true,
			rewriteHost:  "secure.internal",
			clientHost:   "secure.example.com",
			clientRemote: "198.51.100.2:12345",
			clientHeaders: map[string]string{
				"X-Forwarded-For":   "203.0.113.99",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "spoofed-host",
			},
			wantXFP:  "https",
			wantXFH:  "secure.example.com",
			wantXFF:  "198.51.100.2",
			wantHost: "secure.internal",
		},
		{
			name:         "plaintext without rewrite in replace mode",
			mode:         ForwardedForModeReplace,
			isTLS:        false,
			clientHost:   "direct.example.com",
			clientRemote: "198.51.100.3:12345",
			clientHeaders: map[string]string{
				"X-Forwarded-For":  "203.0.113.77",
				"X-Forwarded-Host": "spoofed-host",
			},
			wantXFP:  "http",
			wantXFH:  "", // omitted
			wantXFF:  "198.51.100.3",
			wantHost: "direct.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup primary backend
			primaryCh := make(chan capturedHeaders, 1)
			primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCh <- capturedHeaders{
					xfp:  r.Header.Get("X-Forwarded-Proto"),
					xfh:  r.Header.Get("X-Forwarded-Host"),
					xff:  r.Header.Get("X-Forwarded-For"),
					host: r.Host,
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer primaryServer.Close()

			primaryURL, _ := url.Parse(primaryServer.URL)
			primaryPort, _ := strconv.Atoi(primaryURL.Port())

			// 2. Setup mirror backend
			mirrorCh := make(chan capturedHeaders, 1)
			mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mirrorCh <- capturedHeaders{
					xfp:  r.Header.Get("X-Forwarded-Proto"),
					xfh:  r.Header.Get("X-Forwarded-Host"),
					xff:  r.Header.Get("X-Forwarded-For"),
					host: r.Host,
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer mirrorServer.Close()

			mirrorURL, _ := url.Parse(mirrorServer.URL)
			mirrorPort, _ := strconv.Atoi(mirrorURL.Port())

			// 3. Setup websocket backend
			wsCh := make(chan capturedHeaders, 1)
			wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					wsCh <- capturedHeaders{
						xfp:  r.Header.Get("X-Forwarded-Proto"),
						xfh:  r.Header.Get("X-Forwarded-Host"),
						xff:  r.Header.Get("X-Forwarded-For"),
						host: r.Host,
					}
					hj, ok := w.(http.Hijacker)
					if !ok {
						http.Error(w, "hijack not supported", http.StatusInternalServerError)
						return
					}
					conn, _, err := hj.Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					resp := "HTTP/1.1 101 Switching Protocols\r\n" +
						"Upgrade: websocket\r\n" +
						"Connection: Upgrade\r\n\r\n"
					_, _ = conn.Write([]byte(resp))
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer wsServer.Close()

			wsURL, _ := url.Parse(wsServer.URL)
			wsPort, _ := strconv.Atoi(wsURL.Port())

			p := NewProxy()
			p.SetForwardedForMode(tc.mode)

			var rewrite *state.InternalRewrite
			if tc.rewriteHost != "" {
				rewrite = &state.InternalRewrite{
					Hostname: state.Ptr(gatewayv1.PreciseHostname(tc.rewriteHost)),
				}
			}

			// Route for standard forward & mirror
			routeHTTP := state.InternalRoute{
				Rules: []state.InternalRule{
					{
						Matches: []state.InternalMatch{
							{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/http"}},
						},
						Rewrite: rewrite,
						Backends: []state.InternalBackend{
							{Host: primaryURL.Hostname(), Port: int32(primaryPort), Weight: 1},
						},
						Mirrors: []state.InternalMirror{
							{
								Backend:     state.InternalBackend{Host: mirrorURL.Hostname(), Port: int32(mirrorPort), Weight: 1},
								Numerator:   1,
								Denominator: 1,
							},
						},
					},
					{
						Matches: []state.InternalMatch{
							{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/ws"}},
						},
						Rewrite: rewrite,
						Backends: []state.InternalBackend{
							{
								Host:        wsURL.Hostname(),
								Port:        int32(wsPort),
								AppProtocol: state.Ptr("kubernetes.io/ws"),
								Weight:      1,
							},
						},
					},
				},
			}
			p.UpdateRoutes([]state.InternalRoute{routeHTTP})

			// --- Path 1: Standard Forward & Path 2: Mirror ---
			reqHTTP := httptest.NewRequest("GET", "http://"+tc.clientHost+"/http", nil)
			reqHTTP.Host = tc.clientHost
			reqHTTP.RemoteAddr = tc.clientRemote
			if tc.isTLS {
				reqHTTP.TLS = &tls.ConnectionState{}
			}
			for k, v := range tc.clientHeaders {
				reqHTTP.Header.Set(k, v)
			}

			wHTTP := httptest.NewRecorder()
			p.ServeHTTP(wHTTP, reqHTTP)

			var gotForward capturedHeaders
			select {
			case gotForward = <-primaryCh:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for forward request")
			}

			var gotMirror capturedHeaders
			select {
			case gotMirror = <-mirrorCh:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for mirror request")
			}

			// --- Path 3: WebSocket Forward ---
			var proxyServer *httptest.Server
			if tc.isTLS {
				proxyServer = httptest.NewTLSServer(p)
			} else {
				proxyServer = httptest.NewServer(p)
			}
			defer proxyServer.Close()

			proxyURL, _ := url.Parse(proxyServer.URL)
			var conn net.Conn
			var err error
			if tc.isTLS {
				conn, err = tls.Dial("tcp", proxyURL.Host, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, err = net.Dial("tcp", proxyURL.Host)
			}
			if err != nil {
				t.Fatalf("failed to dial proxy for websocket: %v", err)
			}
			defer conn.Close()

			wsHandshake := "GET /ws HTTP/1.1\r\n" +
				"Host: " + tc.clientHost + "\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n"
			for k, v := range tc.clientHeaders {
				wsHandshake += k + ": " + v + "\r\n"
			}
			wsHandshake += "\r\n"

			if _, err := conn.Write([]byte(wsHandshake)); err != nil {
				t.Fatalf("failed to write websocket handshake: %v", err)
			}

			var gotWS capturedHeaders
			select {
			case gotWS = <-wsCh:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for websocket request")
			}

			// Validate Path 1 (Forward)
			if gotForward.xfp != tc.wantXFP {
				t.Errorf("[forward] X-Forwarded-Proto = %q, want %q", gotForward.xfp, tc.wantXFP)
			}
			if gotForward.xfh != tc.wantXFH {
				t.Errorf("[forward] X-Forwarded-Host = %q, want %q", gotForward.xfh, tc.wantXFH)
			}
			if gotForward.xff != tc.wantXFF {
				t.Errorf("[forward] X-Forwarded-For = %q, want %q", gotForward.xff, tc.wantXFF)
			}
			if gotForward.host != tc.wantHost {
				t.Errorf("[forward] Host = %q, want %q", gotForward.host, tc.wantHost)
			}

			// Validate Path 2 (Mirror) matches Forward
			if gotMirror.xfp != gotForward.xfp {
				t.Errorf("[mirror] X-Forwarded-Proto %q != forward %q", gotMirror.xfp, gotForward.xfp)
			}
			if gotMirror.xfh != gotForward.xfh {
				t.Errorf("[mirror] X-Forwarded-Host %q != forward %q", gotMirror.xfh, gotForward.xfh)
			}
			if gotMirror.xff != gotForward.xff {
				t.Errorf("[mirror] X-Forwarded-For %q != forward %q", gotMirror.xff, gotForward.xff)
			}
			if gotMirror.host != gotForward.host {
				t.Errorf("[mirror] Host %q != forward %q", gotMirror.host, gotForward.host)
			}

			// Validate Path 3 (WebSocket) headers
			// Note: For WebSocket over live TCP, RemoteAddr is the local ephemeral port, so verify clientIP was appended/replaced.
			if gotWS.xfp != tc.wantXFP {
				t.Errorf("[websocket] X-Forwarded-Proto = %q, want %q", gotWS.xfp, tc.wantXFP)
			}
			if gotWS.xfh != tc.wantXFH {
				t.Errorf("[websocket] X-Forwarded-Host = %q, want %q", gotWS.xfh, tc.wantXFH)
			}
			if gotWS.host != tc.wantHost {
				t.Errorf("[websocket] Host = %q, want %q", gotWS.host, tc.wantHost)
			}
			if tc.mode == ForwardedForModeReplace {
				// In replace mode, client-supplied XFF is dropped and only 127.0.0.1 is present
				if gotWS.xff != "127.0.0.1" {
					t.Errorf("[websocket] X-Forwarded-For = %q, want 127.0.0.1", gotWS.xff)
				}
			} else {
				// In append mode, client-supplied XFF is preserved and 127.0.0.1 is appended
				if !strings.HasPrefix(gotWS.xff, "203.0.113.50") || !strings.HasSuffix(gotWS.xff, "127.0.0.1") {
					t.Errorf("[websocket] X-Forwarded-For = %q, want to start with 203.0.113.50 and end with 127.0.0.1", gotWS.xff)
				}
			}
		})
	}
}
