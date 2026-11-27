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
	"bytes"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func createTestBackend(t *testing.T, responseBody string) (*httptest.Server, state.InternalBackend) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(server.Close)

	reqHost, reqPortStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse test server address: %v", err)
	}
	reqPort, err := strconv.Atoi(reqPortStr)
	if err != nil {
		t.Fatalf("failed to parse test server port: %v", err)
	}

	return server, state.InternalBackend{
		Host:   reqHost,
		Port:   int32(reqPort),
		Weight: 1,
	}
}

func createTestHTTPRoute(pathPrefix string, backend state.InternalBackend) state.InternalRoute {
	return state.InternalRoute{
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{
						Path: &state.InternalPathMatch{
							Type:  gatewayv1.PathMatchPathPrefix,
							Value: pathPrefix,
						},
					},
				},
				Backends: []state.InternalBackend{backend},
			},
		},
	}
}

func TestProxy_ACMEChallenge_ServedFromDataPlane(t *testing.T) {
	_, backend := createTestBackend(t, "normal route response")
	route := createTestHTTPRoute(ACMEChallengePrefix, backend)
	p := NewProxy()
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "http",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     80,
			Hostname: "example.com",
			Routes:   []state.InternalRoute{route},
		},
	}, []state.InternalRoute{route})

	challengeAuth := "tok-1.keyauth-signature-secret-xyz"

	var logBuf bytes.Buffer
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	klog.InitFlags(fs)
	klog.SetOutput(&logBuf)

	// 1. Without challenges configured, GET /.well-known/acme-challenge/tok-1 falls through to normal route
	request := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); body != "normal route response" {
		t.Fatalf("expected normal route response, got %q", body)
	}

	// 2. Configure pending challenge
	p.UpdateChallenges([]state.HTTP01Challenge{
		{
			Hostname:         "example.com",
			Token:            "tok-1",
			KeyAuthorization: challengeAuth,
		},
	})

	// 3. Exact hostname and token are answered with 200 OK, text/plain, and key authorization
	request = httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recorder = httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "text/plain" {
		t.Errorf("expected Content-Type: text/plain, got %q", contentType)
	}
	if body := recorder.Body.String(); body != challengeAuth {
		t.Errorf("expected body %q, got %q", challengeAuth, body)
	}

	// 4. Another token takes normal routing
	reqOtherToken := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/other-tok", nil)
	recOtherToken := httptest.NewRecorder()
	p.ServeHTTP(recOtherToken, reqOtherToken)
	if recOtherToken.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route on other token, got %d", recOtherToken.Code)
	}
	if body := recOtherToken.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response for other token, got %q", body)
	}

	// 5. A trailing slash takes normal routing
	reqTrailingSlash := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1/", nil)
	recTrailingSlash := httptest.NewRecorder()
	p.ServeHTTP(recTrailingSlash, reqTrailingSlash)
	if recTrailingSlash.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route on trailing slash, got %d", recTrailingSlash.Code)
	}
	if body := recTrailingSlash.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response for trailing slash, got %q", body)
	}

	// 6. An encoded slash in the token takes normal routing
	reqEncodedSlash := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok%2F1", nil)
	recEncodedSlash := httptest.NewRecorder()
	p.ServeHTTP(recEncodedSlash, reqEncodedSlash)
	if recEncodedSlash.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route on encoded slash, got %d", recEncodedSlash.Code)
	}
	if body := recEncodedSlash.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response for encoded slash, got %q", body)
	}

	// 7. POST takes normal routing
	reqPost := httptest.NewRequest(http.MethodPost, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recPost := httptest.NewRecorder()
	p.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route on POST, got %d", recPost.Code)
	}
	if body := recPost.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response for POST, got %q", body)
	}

	// 8. HEAD takes normal routing
	reqHead := httptest.NewRequest(http.MethodHead, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	recHead := httptest.NewRecorder()
	p.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK {
		t.Errorf("expected 200 OK on HEAD from normal route, got %d", recHead.Code)
	}
	if body := recHead.Body.String(); body == challengeAuth {
		t.Errorf("HEAD must not serve challenge body directly")
	}

	// 9. Another hostname is not answered
	reqOtherHost := httptest.NewRequest(http.MethodGet, "http://other.com/.well-known/acme-challenge/tok-1", nil)
	recOtherHost := httptest.NewRecorder()
	p.ServeHTTP(recOtherHost, reqOtherHost)
	if recOtherHost.Body.String() == challengeAuth {
		t.Errorf("expected challenge NOT to be served on different hostname")
	}

	// 10. A TLS request is not answered
	reqTLS := httptest.NewRequest(http.MethodGet, "https://example.com/.well-known/acme-challenge/tok-1", nil)
	reqTLS.TLS = &tls.ConnectionState{}
	recTLS := httptest.NewRecorder()
	p.ServeHTTP(recTLS, reqTLS)
	if recTLS.Body.String() == challengeAuth {
		t.Errorf("expected challenge NOT to be served on TLS request")
	}

	// 11. A Gateway with only an HTTPS listener is not answered
	pHttpsOnly := NewProxy()
	pHttpsOnly.UpdateConfig([]state.InternalListener{
		{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "example.com",
		},
	}, nil)
	pHttpsOnly.UpdateChallenges([]state.HTTP01Challenge{
		{
			Hostname:         "example.com",
			Token:            "tok-1",
			KeyAuthorization: challengeAuth,
		},
	})
	recHttpsOnly := httptest.NewRecorder()
	pHttpsOnly.ServeHTTP(recHttpsOnly, request)
	if recHttpsOnly.Body.String() == challengeAuth {
		t.Errorf("expected challenge NOT to be served when Gateway has only an HTTPS listener")
	}

	// 12. A proxy with no listeners is not answered
	pNoListeners := NewProxy()
	pNoListeners.UpdateChallenges([]state.HTTP01Challenge{
		{
			Hostname:         "example.com",
			Token:            "tok-1",
			KeyAuthorization: challengeAuth,
		},
	})
	recNoListeners := httptest.NewRecorder()
	pNoListeners.ServeHTTP(recNoListeners, request)
	if recNoListeners.Body.String() == challengeAuth {
		t.Errorf("expected challenge NOT to be served when proxy has no listeners")
	}

	// 13. When challenge is dropped, proxy stops answering
	p.UpdateChallenges(nil)
	recDropped := httptest.NewRecorder()
	p.ServeHTTP(recDropped, request)
	if recDropped.Code != http.StatusOK {
		t.Fatalf("expected 200 from normal route, got %d", recDropped.Code)
	}
	if body := recDropped.Body.String(); body != "normal route response" {
		t.Errorf("expected normal route response after challenge dropped, got %q", body)
	}

	// 14. Acceptance Criteria: The key authorization is not logged
	klog.Flush()
	if strings.Contains(logBuf.String(), challengeAuth) {
		t.Errorf("key authorization %q was found in log output: %s", challengeAuth, logBuf.String())
	}
}

func TestApplyDataplaneConfig_Challenges(t *testing.T) {
	p := NewProxy()
	cfg := &state.DataplaneConfig{
		Challenges: []state.HTTP01Challenge{
			{
				Hostname:         "example.com",
				Token:            "tok-1",
				KeyAuthorization: "tok-1.keyauth",
			},
		},
	}
	data, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := state.ApplyDataplaneConfig(p, data); err != nil {
		t.Fatalf("failed to apply dataplane config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok-1", nil)
	rec := httptest.NewRecorder()
	// Without listener, not answered
	p.ServeHTTP(rec, req)
	if rec.Body.String() == "tok-1.keyauth" {
		t.Errorf("expected challenge NOT to be served without listener")
	}

	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "http",
			Protocol: gatewayv1.HTTPProtocolType,
			Port:     80,
			Hostname: "example.com",
		},
	}, nil)

	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "tok-1.keyauth" {
		t.Errorf("expected challenge to be served after listener added, got code %d body %q", rec2.Code, rec2.Body.String())
	}
}
