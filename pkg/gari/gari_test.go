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

package gari

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ControllerName != controller.DefaultControllerName {
		t.Errorf("expected controller name %q, got %q", controller.DefaultControllerName, opts.ControllerName)
	}
	if opts.ProxyAddr != ":8080" {
		t.Errorf("expected proxy addr :8080, got %q", opts.ProxyAddr)
	}
	if opts.ProxyHTTPSAddr != ":8443" {
		t.Errorf("expected proxy https addr :8443, got %q", opts.ProxyHTTPSAddr)
	}
	if opts.ProxyHTTP3Addr != "" {
		t.Errorf("expected proxy http3 addr to be empty by default, got %q", opts.ProxyHTTP3Addr)
	}
	if opts.ProxyHTTP3AdvertisedPort != 0 {
		t.Errorf("expected proxy http3 advertised port to be 0 by default, got %d", opts.ProxyHTTP3AdvertisedPort)
	}
	if opts.MetricsAddr != ":8999" {
		t.Errorf("expected metrics addr :8999, got %q", opts.MetricsAddr)
	}
	if opts.HealthProbeBindAddress != ":8999" {
		t.Errorf("expected probe addr :8999, got %q", opts.HealthProbeBindAddress)
	}
	if opts.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("expected read header timeout 10s, got %v", opts.ReadHeaderTimeout)
	}
	if opts.IdleTimeout != 60*time.Second {
		t.Errorf("expected idle timeout 60s, got %v", opts.IdleTimeout)
	}
	if opts.TCPIdleTimeout != 0 {
		t.Errorf("expected tcp idle timeout 0, got %v", opts.TCPIdleTimeout)
	}
	if opts.TCPMaxConnections != 10000 {
		t.Errorf("expected tcp max connections 10000, got %d", opts.TCPMaxConnections)
	}
	if opts.ForwardedForMode != proxy.ForwardedForModeAppend {
		t.Errorf("expected forwarded for mode %q, got %q", proxy.ForwardedForModeAppend, opts.ForwardedForMode)
	}
}

func TestHealthzAndReadyzHandlers(t *testing.T) {
	s := &Server{}
	readyzHandler, healthzHandler := s.healthzHandlers()
	wrappedHealthz := http.StripPrefix("/healthz", healthzHandler)
	wrappedReadyz := http.StripPrefix("/readyz", readyzHandler)

	// 1. healthz should return 200 "ok"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	wrappedHealthz.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("expected healthz 200 ok, got %d %q", rec.Code, rec.Body.String())
	}

	// 2. readyz before sync should return 500
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	wrappedReadyz.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected readyz 500 before sync, got %d", rec.Code)
	}

	// 3. readyz after sync should return 200 "ok"
	s.proxySynced.Store(true)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	wrappedReadyz.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("expected readyz 200 ok after sync, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMetricsAndHealthServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := &Server{}
	readyzHandler, healthzHandler := s.healthzHandlers()

	ms, err := metricsserver.NewServer(metricsserver.Options{
		BindAddress: fmt.Sprintf("127.0.0.1:%d", port),
		ExtraHandlers: map[string]http.Handler{
			"/healthz":  http.StripPrefix("/healthz", healthzHandler),
			"/healthz/": http.StripPrefix("/healthz", healthzHandler),
			"/readyz":   http.StripPrefix("/readyz", readyzHandler),
			"/readyz/":  http.StripPrefix("/readyz", readyzHandler),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("failed to create metrics server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ms.Start(ctx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	httpClient := &http.Client{Timeout: 2 * time.Second}

	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = httpClient.Get(baseURL + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected /healthz 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected /healthz 'ok', got %q", string(body))
	}

	// Verify /readyz returns 500 before sync
	respReady, err := httpClient.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("failed to get /readyz: %v", err)
	}
	defer respReady.Body.Close()
	if respReady.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected /readyz 500 before sync, got %d", respReady.StatusCode)
	}

	// Mark synced and verify /readyz returns 200 OK
	s.proxySynced.Store(true)
	respReadySynced, err := httpClient.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("failed to get /readyz after sync: %v", err)
	}
	defer respReadySynced.Body.Close()
	if respReadySynced.StatusCode != http.StatusOK {
		t.Errorf("expected /readyz 200 OK after sync, got %d", respReadySynced.StatusCode)
	}
	bodyReady, _ := io.ReadAll(respReadySynced.Body)
	if string(bodyReady) != "ok" {
		t.Errorf("expected /readyz 'ok', got %q", string(bodyReady))
	}

	// Verify /metrics returns 200 OK and Prometheus metrics
	respMetrics, err := httpClient.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("failed to get /metrics: %v", err)
	}
	defer respMetrics.Body.Close()
	if respMetrics.StatusCode != http.StatusOK {
		t.Errorf("expected /metrics 200 OK, got %d", respMetrics.StatusCode)
	}
	metricsBody, _ := io.ReadAll(respMetrics.Body)
	if !strings.Contains(string(metricsBody), "promhttp_metric_handler_requests_total") && !strings.Contains(string(metricsBody), "go_goroutines") {
		t.Errorf("expected prometheus metrics in response, got %s", string(metricsBody[:min(len(metricsBody), 200)]))
	}
}

func TestSamePortOrAddr(t *testing.T) {
	tests := []struct {
		addr1    string
		addr2    string
		expected bool
	}{
		{":8999", ":8999", true},
		{"0.0.0.0:8999", ":8999", true},
		{":8999", "127.0.0.1:8999", true},
		{"127.0.0.1:8999", "127.0.0.1:8999", true},
		{":8999", ":8081", false},
		{":8999", "127.0.0.1:8081", false},
		{"", "", false},
		{"0", "0", false},
		{":0", ":0", false},
		{"127.0.0.1:0", "127.0.0.1:0", false},
	}
	for _, tc := range tests {
		if actual := samePortOrAddr(tc.addr1, tc.addr2); actual != tc.expected {
			t.Errorf("samePortOrAddr(%q, %q) = %v, want %v", tc.addr1, tc.addr2, actual, tc.expected)
		}
	}
}

func TestForwardedForModeOptions(t *testing.T) {
	t.Run("default empty completes to append", func(t *testing.T) {
		opts := Options{}
		if err := opts.complete(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.ForwardedForMode != proxy.ForwardedForModeAppend {
			t.Errorf("expected %q, got %q", proxy.ForwardedForModeAppend, opts.ForwardedForMode)
		}
	})

	t.Run("valid replace mode", func(t *testing.T) {
		opts := Options{ForwardedForMode: proxy.ForwardedForModeReplace}
		if err := opts.complete(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.ForwardedForMode != proxy.ForwardedForModeReplace {
			t.Errorf("expected %q, got %q", proxy.ForwardedForModeReplace, opts.ForwardedForMode)
		}
	})

	t.Run("invalid mode returns error", func(t *testing.T) {
		opts := Options{ForwardedForMode: "invalid-mode"}
		if err := opts.complete(); err == nil {
			t.Fatalf("expected error for invalid forwarded-for-mode, got nil")
		}
	})
}

func TestOptions_SetupWithManagerCalled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	called := false
	opts := DefaultOptions()
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = "default"
	opts.DataplaneGatewayName = "test-gw"
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.Scheme = scheme
	opts.SetupWithManager = func(mgr ctrl.Manager, s *Server) error {
		called = true
		return nil
	}

	skipNameValidation := true
	mgr, err := ctrl.NewManager(&rest.Config{}, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	_, err = NewWithManager(mgr, opts)
	if err != nil {
		t.Fatalf("NewWithManager failed: %v", err)
	}
	if !called {
		t.Errorf("expected SetupWithManager to be called, but was not")
	}
}

func TestOptions_SetupWithManagerServerAccess(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	var serverFromSetup *Server
	opts := DefaultOptions()
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = "default"
	opts.DataplaneGatewayName = "test-gw"
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.Scheme = scheme
	opts.SetupWithManager = func(mgr ctrl.Manager, s *Server) error {
		serverFromSetup = s
		return nil
	}

	skipNameValidation := true
	mgr, err := ctrl.NewManager(&rest.Config{}, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	server, err := NewWithManager(mgr, opts)
	if err != nil {
		t.Fatalf("NewWithManager failed: %v", err)
	}
	if serverFromSetup == nil || serverFromSetup != server {
		t.Fatalf("expected SetupWithManager to receive Server instance, got %v", serverFromSetup)
	}

	// Trigger server.EnqueueGateway directly (should not panic)
	server.EnqueueGateway(types.NamespacedName{Namespace: "default", Name: "test-gw"})
	server.EnqueueGateway(types.NamespacedName{Namespace: "default", Name: "test-gw"})
}

func TestServerCustomHTTPListener(t *testing.T) {
	// Create an in-memory TCP listener
	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpLis.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	opts := Options{
		HTTPListener:   httpLis,
		ProxyHTTPSAddr: "", // disable default HTTPS listener for this test
		Scheme:         DefaultScheme(),
		ControllerName: "custom.io/gateway-controller",
	}

	st := state.NewState()
	p := proxy.NewProxy()

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// Configure a route directly on proxy
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

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	reqURL := "http://" + httpLis.Addr().String() + "/test"

	// Wait briefly for server to accept connections
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(reqURL)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to custom HTTP listener: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("expected 'backend response', got %q", string(body))
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestServerCustomHTTPSListener(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpsLis.Close()

	opts := Options{
		HTTPSListener: httpsLis,
		ProxyAddr:     "", // disable default HTTP listener for this test
		Scheme:        DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	// TLS client that trusts self-signed certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/notfound"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(reqURL)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to custom HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestOnGatewaysUpdateHookAndCustomControllerName(t *testing.T) {
	var mu sync.Mutex
	var lastGateways []*gatewayv1.Gateway
	hookCallCount := 0

	customControllerName := "example.com/custom-controller"

	opts := Options{
		ControllerName: customControllerName,
		OnGatewaysUpdate: func(gateways []*gatewayv1.Gateway) {
			mu.Lock()
			defer mu.Unlock()
			hookCallCount++
			lastGateways = gateways
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)
	opts.Scheme = scheme

	st := state.NewState()
	p := proxy.NewProxy()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "custom-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Hostname: state.Ptr(gatewayv1.Hostname("example.com")),
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
				{
					Name:     "http",
					Hostname: state.Ptr(gatewayv1.Hostname("app.example.com")),
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "custom-class",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(customControllerName),
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "test-gateway",
					},
				},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gari-proxy",
			Namespace: "default",
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, gc, route, svc).
		WithStatusSubresource(gw, gc, route).
		Build()

	st.SetProxy(p)
	st.SetControllerName(customControllerName)
	st.SetOnGatewaysUpdate(opts.OnGatewaysUpdate)
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertHTTPRoute(route)
	st.UpsertService(svc)
	st.Recompute()

	gwReconciler := &controller.GatewayReconciler{
		Client:         fakeClient,
		Scheme:         scheme,
		State:          st,
		ControllerName: customControllerName,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gateway"}}

	_, err := gwReconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if hookCallCount == 0 {
		t.Fatalf("expected OnGatewaysUpdate hook to be called, got 0 calls")
	}

	if len(lastGateways) != 1 {
		t.Fatalf("expected 1 resolved gateway, got %d", len(lastGateways))
	}

	resolved := lastGateways[0]
	if resolved.Name != "test-gateway" || resolved.Namespace != "default" {
		t.Errorf("unexpected gateway name/namespace: %s/%s", resolved.Namespace, resolved.Name)
	}
	if len(resolved.Spec.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(resolved.Spec.Listeners))
	}
	if string(*resolved.Spec.Listeners[0].Hostname) != "example.com" {
		t.Errorf("expected hostname example.com, got %v", *resolved.Spec.Listeners[0].Hostname)
	}
	if string(*resolved.Spec.Listeners[1].Hostname) != "app.example.com" {
		t.Errorf("expected hostname app.example.com, got %v", *resolved.Spec.Listeners[1].Hostname)
	}
}

func TestNewWithManager(t *testing.T) {
	opts := Options{
		RestConfig: &rest.Config{
			Host: "http://localhost:8080",
		},
		MetricsAddr:            "0",
		HealthProbeBindAddress: "0",
	}

	// Verify complete sets defaults
	err := opts.complete()
	if err != nil {
		t.Fatalf("complete returned error: %v", err)
	}
	if opts.ControllerName != controller.DefaultControllerName {
		t.Errorf("expected default controller name, got %s", opts.ControllerName)
	}
	if opts.Scheme == nil {
		t.Errorf("expected scheme to be initialized")
	}
}

func TestHTTP3_DisabledByDefault(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	opts := Options{
		HTTPSListener: httpsLis,
		ProxyAddr:     "",
		// HTTP/3 is disabled (ProxyHTTP3Addr is empty, HTTP3PacketConn is nil)
		Scheme: DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/test"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get(reqURL)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != "" {
		t.Errorf("expected no Alt-Svc header when HTTP/3 is disabled, got %q", altSvc)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_Enabled_AltSvcAndQUICRouting(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP packet conn: %v", err)
	}
	defer h3Conn.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Host", r.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend:" + r.URL.Path))
	}))
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	advertisedPort := 9443

	opts := Options{
		HTTPSListener:            httpsLis,
		HTTP3PacketConn:          h3Conn,
		ProxyHTTP3AdvertisedPort: advertisedPort,
		ProxyAddr:                "",
		Scheme:                   DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	// Configure listeners and routes on proxy
	p.UpdateListeners([]state.InternalListener{
		{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "example.com",
			Port:     443,
			Routes: []state.InternalRoute{
				{
					Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/foo",
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
			},
		},
		{
			Name:     "https-wildcard",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "*.other.com",
			Port:     443,
			Routes: []state.InternalRoute{
				{
					Hostnames: []state.RouteHostname{state.NewRouteHostname("*.other.com", "*.other.com")},
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/bar",
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
			},
		},
	})

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	// 1. Verify Alt-Svc on HTTPS TCP responses
	tcpTr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tcpClient := &http.Client{Transport: tcpTr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/foo"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Host = "example.com"
		resp, err = tcpClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	expectedAltSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, advertisedPort)
	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != expectedAltSvc {
		t.Errorf("expected Alt-Svc %q, got %q", expectedAltSvc, altSvc)
	}

	// 2. Test HTTP/3 (QUIC) requests
	h3Addr := h3Conn.LocalAddr().String()
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, h3Addr, tlsCfg, cfg)
		},
	}
	defer h3Transport.Close()

	h3Client := &http.Client{
		Transport: h3Transport,
		Timeout:   3 * time.Second,
	}

	// Request to example.com/foo
	h3Resp1, err := h3Client.Get("https://example.com/foo")
	if err != nil {
		t.Fatalf("HTTP/3 request to example.com/foo failed: %v", err)
	}
	defer h3Resp1.Body.Close()

	if h3Resp1.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP/3 status 200, got %d", h3Resp1.StatusCode)
	}
	body1, _ := io.ReadAll(h3Resp1.Body)
	if string(body1) != "backend:/foo" {
		t.Errorf("expected body 'backend:/foo', got %q", string(body1))
	}

	// Request to app.other.com/bar (wildcard listener match)
	h3Resp2, err := h3Client.Get("https://app.other.com/bar")
	if err != nil {
		t.Fatalf("HTTP/3 request to app.other.com/bar failed: %v", err)
	}
	defer h3Resp2.Body.Close()

	if h3Resp2.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP/3 status 200, got %d", h3Resp2.StatusCode)
	}
	body2, _ := io.ReadAll(h3Resp2.Body)
	if string(body2) != "backend:/bar" {
		t.Errorf("expected body 'backend:/bar', got %q", string(body2))
	}

	// Request to unmatched path
	h3Resp3, err := h3Client.Get("https://example.com/unknown")
	if err != nil {
		t.Fatalf("HTTP/3 request to example.com/unknown failed: %v", err)
	}
	defer h3Resp3.Body.Close()

	if h3Resp3.StatusCode != http.StatusNotFound {
		t.Errorf("expected HTTP/3 status 404, got %d", h3Resp3.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_TCPCrossProtocolResumption(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend:" + r.URL.Path))
	}))
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP packet conn: %v", err)
	}
	defer h3Conn.Close()

	h3Addr := h3Conn.LocalAddr().String()

	opts := Options{
		HTTPSListener:            httpsLis,
		HTTP3PacketConn:          h3Conn,
		ProxyHTTP3AdvertisedPort: 443,
		ProxyAddr:                "",
		Scheme:                   DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	p.UpdateListeners([]state.InternalListener{
		{
			Name:     "https-resumption",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "example.com",
			Port:     443,
			Routes: []state.InternalRoute{
				{
					Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/foo",
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
			},
		},
	})

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	httpsAddr := httpsLis.Addr().String()

	// Wait for server to start
	for i := 0; i < 20; i++ {
		c, err := net.DialTimeout("tcp", httpsAddr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 1. TCP (HTTPS) -> HTTP/3 cross-protocol resumption
	t.Run("TCP ticket resumes over HTTP/3", func(t *testing.T) {
		sessionCache := tls.NewLRUClientSessionCache(10)

		tcpTr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
				ClientSessionCache: sessionCache,
			},
		}
		tcpClient := &http.Client{Transport: tcpTr, Timeout: 3 * time.Second}

		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/foo", nil)
		req.Host = "example.com"
		respTCP, err := tcpClient.Do(req)
		if err != nil {
			t.Fatalf("TCP request failed: %v", err)
		}
		_, _ = io.ReadAll(respTCP.Body)
		respTCP.Body.Close()
		tcpTr.CloseIdleConnections()

		if respTCP.TLS == nil {
			t.Fatalf("expected non-nil respTCP.TLS")
		}
		if respTCP.TLS.DidResume {
			t.Errorf("expected initial TCP connection DidResume=false, got true")
		}

		h3Transport := &http3.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
				ClientSessionCache: sessionCache,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, h3Addr, tlsCfg, cfg)
			},
		}
		defer h3Transport.Close()

		h3Client := &http.Client{Transport: h3Transport, Timeout: 3 * time.Second}
		respH3, err := h3Client.Get("https://example.com/foo")
		if err != nil {
			t.Fatalf("HTTP/3 request failed: %v", err)
		}
		_, _ = io.ReadAll(respH3.Body)
		respH3.Body.Close()

		if respH3.TLS == nil {
			t.Fatalf("expected non-nil respH3.TLS")
		}
		if !respH3.TLS.DidResume {
			t.Errorf("expected HTTP/3 request to resume from TCP ticket, got DidResume=false")
		}
	})

	// 2. HTTP/3 -> TCP cross-protocol resumption
	t.Run("HTTP/3 ticket resumes over TCP", func(t *testing.T) {
		sessionCache := tls.NewLRUClientSessionCache(10)

		h3Transport := &http3.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
				ClientSessionCache: sessionCache,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, h3Addr, tlsCfg, cfg)
			},
		}
		defer h3Transport.Close()

		h3Client := &http.Client{Transport: h3Transport, Timeout: 3 * time.Second}
		respH3, err := h3Client.Get("https://example.com/foo")
		if err != nil {
			t.Fatalf("HTTP/3 request failed: %v", err)
		}
		_, _ = io.ReadAll(respH3.Body)
		respH3.Body.Close()

		if respH3.TLS == nil {
			t.Fatalf("expected non-nil respH3.TLS")
		}
		if respH3.TLS.DidResume {
			t.Errorf("expected initial HTTP/3 connection DidResume=false, got true")
		}

		tcpTr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
				ClientSessionCache: sessionCache,
			},
		}
		tcpClient := &http.Client{Transport: tcpTr, Timeout: 3 * time.Second}

		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/foo", nil)
		req.Host = "example.com"
		respTCP, err := tcpClient.Do(req)
		if err != nil {
			t.Fatalf("TCP request failed: %v", err)
		}
		_, _ = io.ReadAll(respTCP.Body)
		respTCP.Body.Close()
		tcpTr.CloseIdleConnections()

		if respTCP.TLS == nil {
			t.Fatalf("expected non-nil respTCP.TLS")
		}
		if !respTCP.TLS.DidResume {
			t.Errorf("expected TCP request to resume from HTTP/3 ticket, got DidResume=false")
		}
	})

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_AutomaticAdvertisedPort(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP packet conn: %v", err)
	}
	defer h3Conn.Close()

	h3Port := h3Conn.LocalAddr().(*net.UDPAddr).Port

	opts := Options{
		HTTPSListener:            httpsLis,
		HTTP3PacketConn:          h3Conn,
		ProxyHTTP3AdvertisedPort: 0, // Inferred automatically from HTTP3 listener
		ProxyAddr:                "",
		Scheme:                   DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	tcpTr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tcpClient := &http.Client{Transport: tcpTr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/test"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = tcpClient.Get(reqURL)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	expectedAltSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, h3Port)
	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != expectedAltSvc {
		t.Errorf("expected Alt-Svc %q, got %q", expectedAltSvc, altSvc)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_StripBackendAltSvc(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP packet conn: %v", err)
	}
	defer h3Conn.Close()

	// Backend returns its own Alt-Svc headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Alt-Svc", `h3=":9999"; ma=100`)
		w.Header().Add("Alt-Svc", `h3-29=":9999"; ma=100`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response"))
	}))
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	advertisedPort := 9443

	opts := Options{
		HTTPSListener:            httpsLis,
		HTTP3PacketConn:          h3Conn,
		ProxyHTTP3AdvertisedPort: advertisedPort,
		ProxyAddr:                "",
		Scheme:                   DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	p.UpdateListeners([]state.InternalListener{
		{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "example.com",
			Port:     443,
			Routes: []state.InternalRoute{
				{
					Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/foo",
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
			},
		},
	})

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	tcpTr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tcpClient := &http.Client{Transport: tcpTr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/foo"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Host = "example.com"
		resp, err = tcpClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	expectedAltSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, advertisedPort)
	altSvcValues := resp.Header.Values("Alt-Svc")
	if len(altSvcValues) != 1 {
		t.Fatalf("expected exactly 1 Alt-Svc header, got %d: %v", len(altSvcValues), altSvcValues)
	}
	if altSvcValues[0] != expectedAltSvc {
		t.Errorf("expected Alt-Svc %q, got %q", expectedAltSvc, altSvcValues[0])
	}

	// 2. HTTP/3 response must not carry backend Alt-Svc headers
	h3Addr := h3Conn.LocalAddr().String()
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, h3Addr, tlsCfg, cfg)
		},
	}
	defer h3Transport.Close()

	h3Client := &http.Client{
		Transport: h3Transport,
		Timeout:   3 * time.Second,
	}

	h3Req, _ := http.NewRequest("GET", "https://example.com/foo", nil)
	h3Resp, err := h3Client.Do(h3Req)
	if err != nil {
		t.Fatalf("HTTP/3 request failed: %v", err)
	}
	defer h3Resp.Body.Close()

	if h3Resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP/3 status 200, got %d", h3Resp.StatusCode)
	}
	if altSvc := h3Resp.Header.Get("Alt-Svc"); altSvc != "" {
		t.Errorf("expected no Alt-Svc header on HTTP/3 response, got %q", altSvc)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_Disabled_StripBackendAltSvc(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create HTTPS listener: %v", err)
	}
	defer httpsLis.Close()

	// Backend returns its own Alt-Svc headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Alt-Svc", `h3=":9999"; ma=100`)
		w.Header().Add("Alt-Svc", `h2=":8443"; ma=100`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response"))
	}))
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	opts := Options{
		HTTPSListener: httpsLis,
		ProxyAddr:     "",
		Scheme:        DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	p.UpdateListeners([]state.InternalListener{
		{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Hostname: "example.com",
			Port:     443,
			Routes: []state.InternalRoute{
				{
					Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
					Rules: []state.InternalRule{
						{
							Matches: []state.InternalMatch{
								{
									Path: &state.InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/foo",
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
			},
		},
	})

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	tcpTr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	tcpClient := &http.Client{Transport: tcpTr, Timeout: 2 * time.Second}
	reqURL := "https://" + httpsLis.Addr().String() + "/foo"

	var resp *http.Response
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Host = "example.com"
		resp, err = tcpClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to HTTPS listener: %v", err)
	}
	defer resp.Body.Close()

	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != "" {
		t.Errorf("expected no Alt-Svc header when HTTP/3 is disabled, got %q", altSvc)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestHTTP3_CustomQUICConfig(t *testing.T) {
	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP packet conn: %v", err)
	}
	defer h3Conn.Close()

	opts := Options{
		HTTP3PacketConn: h3Conn,
		HTTP3QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
		},
		ProxyAddr:      "",
		ProxyHTTPSAddr: "",
		Scheme:         DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	h3Addr := h3Conn.LocalAddr().String()
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, h3Addr, tlsCfg, cfg)
		},
	}
	defer h3Transport.Close()

	h3Client := &http.Client{
		Transport: h3Transport,
		Timeout:   3 * time.Second,
	}

	h3Resp, err := h3Client.Get("https://example.com/test")
	if err != nil {
		t.Fatalf("HTTP/3 request with custom QUICConfig failed: %v", err)
	}
	defer h3Resp.Body.Close()

	if h3Resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", h3Resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for proxy shutdown")
	}
}

func TestDataplaneSecretReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	var backendPort int
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	p := proxy.NewProxy()

	gwKey := types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}
	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: int32(backendPort), Weight: 1},
				},
			},
		},
	}

	dpConfig := &state.DataplaneConfig{
		GatewayName: gwKey,
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
		},
		Routes: []state.InternalRoute{route},
	}
	configBytes, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	gwName := "test-gw"
	secretName := singlepod.ResourceNameForGateway(gwName)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
	}

	ctx := t.Context()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      secretName,
		},
	}

	// Reconcile secret
	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res.Requeue {
		t.Errorf("expected no requeue")
	}

	if !server.proxySynced.Load() {
		t.Errorf("expected proxySynced to be true after reconcile")
	}

	// Verify request routing against the proxy
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/ok", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, reqHTTP)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK from proxy, got %d", rec.Code)
	}
	if rec.Body.String() != "backend ok" {
		t.Errorf("expected 'backend ok' body, got %q", rec.Body.String())
	}
}

func TestDataplane_AppliedRevisionEndpoint(t *testing.T) {
	env := testenv.Start(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	secretName := singlepod.ResourceNameForGateway(gwName)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: gwNamespace,
		},
	}
	if err := env.Client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	healthAddr := fmt.Sprintf("127.0.0.1:%d", port)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port for proxy: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()

	opts := DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.HealthProbeBindAddress = healthAddr
	opts.MetricsAddr = healthAddr
	opts.ProxyAddr = proxyAddr
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false
	opts.SkipNameValidation = true

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server to stop")
		}
	})

	healthURL := fmt.Sprintf("http://%s/_gari/applied", healthAddr)
	httpClient := &http.Client{Timeout: 2 * time.Second}

	waitForRevision := func(expectedRev string) {
		t.Helper()
		var lastRevs []string
		pollErr := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			resp, err := httpClient.Get(healthURL)
			if err != nil {
				return false, nil
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return false, nil
			}
			var revs []string
			if err := json.NewDecoder(resp.Body).Decode(&revs); err != nil {
				return false, err
			}
			lastRevs = revs
			if expectedRev == "" {
				return len(revs) == 0, nil
			}
			return slices.Contains(revs, expectedRev), nil
		})
		if pollErr != nil {
			t.Fatalf("timed out waiting for revision %q, last got: %v", expectedRev, lastRevs)
		}
	}

	// 1. Before config is applied: endpoint returns 200 OK with empty revisions list (Gateway appears only after config applied)
	waitForRevision("")

	// 2. Create initial config Secret
	route1 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/v1"}},
				},
				Backends: []state.InternalBackend{
					{Host: "backend-1", Port: 8080, Weight: 1},
				},
			},
		},
	}
	dpConfig1, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 1 failed: %v", err)
	}
	dpConfig1.Revision, err = dpConfig1.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 1 failed: %v", err)
	}
	configBytes1, err := dpConfig1.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig1: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes1,
		},
	}
	if err := env.Client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	// Wait for endpoint to report revision 1
	waitForRevision(dpConfig1.Revision)

	// 3. Update config Secret with new route and verify new revision reported
	route2 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/v2"}},
				},
				Backends: []state.InternalBackend{
					{Host: "backend-2", Port: 8080, Weight: 1},
				},
			},
		},
	}
	dpConfig2, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route2}},
	}, []state.InternalRoute{route2}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 2 failed: %v", err)
	}
	dpConfig2.Revision, err = dpConfig2.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 2 failed: %v", err)
	}
	configBytes2, err := dpConfig2.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig2: %v", err)
	}

	secret.Data[singlepod.DataplaneSecretDataKey] = configBytes2
	if err := env.Client.Update(ctx, secret); err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Wait for endpoint to report revision 2
	waitForRevision(dpConfig2.Revision)

	// 4. Verify security limits:
	// a) Endpoint returns only revision hashes and reveals no Gateway names or namespaces
	resp, err := httpClient.Get(healthURL)
	if err != nil {
		t.Fatalf("failed to GET applied revisions: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if strings.Contains(string(bodyBytes), gwName) || strings.Contains(string(bodyBytes), gwNamespace) {
		t.Errorf("security violation: applied endpoint exposed gateway identity: %s", string(bodyBytes))
	}

	// b) Endpoint must NOT be served on Gateway listener (proxy)
	rec := httptest.NewRecorder()
	proxyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/_gari/applied", nil)
	if err != nil {
		t.Fatalf("failed to create proxy request: %v", err)
	}
	server.Proxy().ServeHTTP(rec, proxyReq)
	if strings.Contains(rec.Body.String(), dpConfig2.Revision) {
		t.Errorf("security violation: proxy listener served revision endpoint: %s", rec.Body.String())
	}
}

func TestDataplaneSecretReconciler_MissingSecretLeavesProxyNotSynced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	p := proxy.NewProxy()
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	gwName := "test-gw"
	secretName := singlepod.ResourceNameForGateway(gwName)

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
	}

	ctx := t.Context()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      secretName,
		},
	}

	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile returned error for missing secret: %v", err)
	}
	if res.Requeue {
		t.Errorf("expected no requeue for missing secret")
	}

	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced to be false when Secret is missing")
	}
}

func TestInProcessDataplanePublisher_RoutesAndCertificates(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	var backendPort int
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	p := proxy.NewProxy()
	publisher := state.NewInProcessDataplanePublisher(p)

	gwKey := types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-gw",
		},
	}
	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: int32(backendPort), Weight: 1},
				},
			},
		},
	}
	listeners := []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
		{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
	}
	certsMap := map[string]*tls.Certificate{
		"https.example.com": &cert,
	}

	dpConfig, err := state.BuildDataplaneConfig(gwKey, listeners, []state.InternalRoute{route}, certsMap, &cert, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}

	ctx := t.Context()
	// Full in-process path: publisher.PublishDataplaneConfig -> serialize -> ApplyDataplaneConfig -> proxy
	if err := publisher.PublishDataplaneConfig(ctx, gw, dpConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	// 1. Assert proxy serves the compiled route
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/ok", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, reqHTTP)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK from proxy, got %d", rec.Code)
	}
	if rec.Body.String() != "backend ok" {
		t.Errorf("expected 'backend ok' body, got %q", rec.Body.String())
	}

	// 2. Assert proxy serves the compiled certificates
	gotCert, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "https.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if gotCert == nil || len(gotCert.Certificate) == 0 {
		t.Fatalf("expected non-nil certificate for https.example.com")
	}
	if len(gotCert.Certificate[0]) != len(cert.Certificate[0]) {
		t.Errorf("certificate length mismatch: got %d, want %d", len(gotCert.Certificate[0]), len(cert.Certificate[0]))
	}

	// 3. Assert default certificate fallback
	defaultCert, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "unrecognized.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate for default cert failed: %v", err)
	}
	if defaultCert == nil {
		t.Errorf("expected default certificate fallback, got nil")
	}
}

func TestInProcessDataplanePublisher_MultipleGatewaysDistinctCertificates(t *testing.T) {
	// Generate distinct self-signed certificates
	certA, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate certA: %v", err)
	}
	certB, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate certB: %v", err)
	}

	if bytes.Equal(certA.Certificate[0], certB.Certificate[0]) {
		t.Fatalf("expected distinct certificates for certA and certB")
	}

	p := proxy.NewProxy()
	publisher := state.NewInProcessDataplanePublisher(p)

	gwA := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw-a",
		},
	}
	gwB := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw-b",
		},
	}

	listenersA := []state.InternalListener{
		{Name: "https-a", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: "a.example.com"},
	}
	certsMapA := map[string]*tls.Certificate{
		"a.example.com": &certA,
	}
	dpConfigA, err := state.BuildDataplaneConfig(
		types.NamespacedName{Namespace: gwA.Namespace, Name: gwA.Name},
		listenersA, nil, certsMapA, &certA, nil,
	)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig gwA failed: %v", err)
	}

	listenersB := []state.InternalListener{
		{Name: "https-b", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: "b.example.com"},
	}
	certsMapB := map[string]*tls.Certificate{
		"b.example.com": &certB,
	}
	dpConfigB, err := state.BuildDataplaneConfig(
		types.NamespacedName{Namespace: gwB.Namespace, Name: gwB.Name},
		listenersB, nil, certsMapB, &certB, nil,
	)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig gwB failed: %v", err)
	}

	ctx := t.Context()
	if err := publisher.Begin(ctx); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if err := publisher.PublishDataplaneConfig(ctx, gwA, dpConfigA); err != nil {
		t.Fatalf("PublishDataplaneConfig gwA failed: %v", err)
	}
	if err := publisher.PublishDataplaneConfig(ctx, gwB, dpConfigB); err != nil {
		t.Fatalf("PublishDataplaneConfig gwB failed: %v", err)
	}
	if err := publisher.Commit(ctx); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Assert each hostname resolves to its own distinct certificate
	gotA, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate for a.example.com failed: %v", err)
	}
	if gotA == nil || !bytes.Equal(gotA.Certificate[0], certA.Certificate[0]) {
		t.Errorf("a.example.com did not resolve to certA")
	}

	gotB, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate for b.example.com failed: %v", err)
	}
	if gotB == nil || !bytes.Equal(gotB.Certificate[0], certB.Certificate[0]) {
		t.Errorf("b.example.com did not resolve to certB")
	}

	if bytes.Equal(gotA.Certificate[0], gotB.Certificate[0]) {
		t.Errorf("expected distinct certificates for a.example.com and b.example.com, but got identical certificates")
	}
}

func TestHTTP_ReadHeaderTimeout_SlowlorisClosed(t *testing.T) {
	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpLis.Close()

	opts := Options{
		HTTPListener:      httpLis,
		ProxyHTTPSAddr:    "",
		ReadHeaderTimeout: 100 * time.Millisecond,
		Scheme:            DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()
	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = server.StartProxyServers(ctx)
	}()

	conn, err := net.DialTimeout("tcp", httpLis.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	// Send partial headers without closing CRLF CRLF (slowloris)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n")); err != nil {
		t.Fatalf("failed to write partial headers: %v", err)
	}

	// Read until connection is closed by server
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	buf := make([]byte, 1024)
	for {
		_, rerr := conn.Read(buf)
		if rerr != nil {
			break
		}
	}
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("expected connection to be closed around 100ms, elapsed %v", elapsed)
	}
}

type stallClientConn struct {
	net.Conn
	firstWriteDone bool
	serverClosed   chan struct{}
}

func (c *stallClientConn) Write(b []byte) (int, error) {
	if !c.firstWriteDone {
		c.firstWriteDone = true
		return c.Conn.Write(b)
	}
	<-c.serverClosed
	return 0, net.ErrClosed
}

func TestHTTPS_TLSStallAfterClientHello_ClosedOnReadHeaderTimeout(t *testing.T) {
	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpsLis.Close()

	opts := Options{
		HTTPSListener:     httpsLis,
		ProxyAddr:         "",
		ReadHeaderTimeout: 150 * time.Millisecond,
		Scheme:            DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()
	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = server.StartProxyServers(ctx)
	}()

	rawConn, err := net.DialTimeout("tcp", httpsLis.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial https listener: %v", err)
	}
	defer rawConn.Close()

	stall := &stallClientConn{
		Conn:         rawConn,
		serverClosed: make(chan struct{}),
	}

	tlsClient := tls.Client(stall, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})

	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		errCh <- tlsClient.Handshake()
	}()

	// Detect when server closes connection
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := rawConn.Read(buf)
			if err != nil {
				select {
				case <-stall.serverClosed:
				default:
					close(stall.serverClosed)
				}
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected stalled TLS handshake to fail, but succeeded")
		}
		if elapsed < 80*time.Millisecond || elapsed > 1500*time.Millisecond {
			t.Errorf("expected TLS handshake stall to be closed around 150ms, elapsed %v", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for stalled TLS connection to be closed")
	}
}

func TestHTTP_IdleTimeout_KeepAliveClosed(t *testing.T) {
	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpLis.Close()

	opts := Options{
		HTTPListener:   httpLis,
		ProxyHTTPSAddr: "",
		IdleTimeout:    150 * time.Millisecond,
		Scheme:         DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()
	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = server.StartProxyServers(ctx)
	}()

	conn, err := net.DialTimeout("tcp", httpLis.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Connection is now idle on keep-alive. Server should close it after IdleTimeout (150ms).
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	for {
		_, rerr := reader.Read(buf)
		if rerr != nil {
			break
		}
	}
	elapsed := time.Since(start)

	if elapsed < 80*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("expected keep-alive connection to close around 150ms, elapsed %v", elapsed)
	}
}

func TestHTTP_SlowProgressingResponseBody_NotCutOff(t *testing.T) {
	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer httpLis.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			_, _ = fmt.Fprintf(w, "chunk-%d\n", i)
			if ok {
				flusher.Flush()
			}
			time.Sleep(40 * time.Millisecond)
		}
	}))
	defer backend.Close()

	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	opts := Options{
		HTTPListener:      httpLis,
		ProxyHTTPSAddr:    "",
		ReadHeaderTimeout: 100 * time.Millisecond, // shorter than total response time (200ms)
		Scheme:            DefaultScheme(),
	}

	st := state.NewState()
	p := proxy.NewProxy()
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

	server := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = server.StartProxyServers(ctx)
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + httpLis.Addr().String() + "/")
	if err != nil {
		t.Fatalf("client.Get failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	expected := "chunk-0\nchunk-1\nchunk-2\nchunk-3\nchunk-4\n"
	if string(bodyBytes) != expected {
		t.Errorf("expected body %q, got %q", expected, string(bodyBytes))
	}
}

func TestGari_HealthProbeReadyz_And_DrainingSentinel(t *testing.T) {
	sentinelDir := t.TempDir()
	sentinelPath := filepath.Join(sentinelDir, "draining")

	opts := DefaultOptions()
	opts.DrainSentinelPath = sentinelPath

	server := &Server{
		opts: opts,
	}

	checker := server.readyzChecker()
	readyzHandler, _ := server.healthzHandlers()
	gariReadyzHandler := http.StripPrefix("/_gari/readyz", readyzHandler)

	// 1. Not synced yet: should return 500
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "/_gari/readyz", nil)
	rr := httptest.NewRecorder()
	gariReadyzHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when not synced, got %d", rr.Code)
	}

	// 2. Mark synced: should return 200 OK
	server.proxySynced.Store(true)
	if err := checker(req); err != nil {
		t.Fatalf("expected nil error when synced and not draining, got %v", err)
	}
	rr = httptest.NewRecorder()
	gariReadyzHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK when synced and not draining, got %d", rr.Code)
	}

	// 3. Write drain sentinel: should return 503 Service Unavailable (draining)
	if err := os.WriteFile(sentinelPath, []byte("draining\n"), 0644); err != nil {
		t.Fatalf("failed to write sentinel file: %v", err)
	}
	if err := checker(req); err == nil || err.Error() != "draining" {
		t.Fatalf("expected draining error, got %v", err)
	}
	rr = httptest.NewRecorder()
	gariReadyzHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when draining, got %d", rr.Code)
	}

	// 4. Remove drain sentinel: should recover to 200 OK
	if err := os.Remove(sentinelPath); err != nil {
		t.Fatalf("failed to remove sentinel file: %v", err)
	}
	if err := checker(req); err != nil {
		t.Fatalf("expected nil error after sentinel removed, got %v", err)
	}
	rr = httptest.NewRecorder()
	gariReadyzHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK after sentinel removed, got %d", rr.Code)
	}
}

func TestDataplane_ListenerOptionsPreservedWhenSecretSyncsBeforeListenerStart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	var backendPort int
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	p := proxy.NewProxy()

	gwKey := types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}
	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: int32(backendPort), Weight: 1},
				},
			},
		},
	}

	dpConfig := &state.DataplaneConfig{
		GatewayName: gwKey,
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
		},
		Routes:                    []state.InternalRoute{route},
		ProxyProtocol:             "enabled",
		ProxyProtocolTrustedCIDRs: []string{"127.0.0.0/8"},
		AllowedSourceCIDRs:        []string{"127.0.0.0/8"},
	}
	configBytes, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	gwName := "test-gw"
	secretName := singlepod.ResourceNameForGateway(gwName)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer httpLis.Close()

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
			HTTPListener:              httpLis,
			ProxyAddr:                 "",
			ProxyHTTPSAddr:            "",
			Scheme:                    scheme,
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
		onConfigUpdate:   server.updateListenerFilters,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// 1. Reconcile Secret BEFORE StartProxyServers is invoked.
	// This simulates a rollout where the config Secret already exists before the new pod's listeners are created.
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      secretName,
		},
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 2. Start proxy servers now (listeners created after secret sync).
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	// 3. Dial listener and send a PROXY v1 header followed by HTTP request.
	conn, err := net.DialTimeout("tcp", httpLis.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial HTTP listener: %v", err)
	}
	defer conn.Close()

	proxyHeader := "PROXY TCP4 203.0.113.195 127.0.0.1 54321 80\r\n"
	httpRequest := "GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(proxyHeader + httpRequest)); err != nil {
		t.Fatalf("failed to write PROXY header and request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend ok" {
		t.Errorf("expected 'backend ok' body, got %q", string(body))
	}

	if receivedXFF != "203.0.113.195" {
		t.Errorf("expected X-Forwarded-For to match PROXY source IP 203.0.113.195, got %q", receivedXFF)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for StartProxyServers to stop")
	}
}

func TestDataplane_HTTPS_ListenerOptionsPreservedWhenSecretSyncsBeforeListenerStart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https backend ok"))
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	var backendPort int
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	p := proxy.NewProxy()

	gwKey := types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}
	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: int32(backendPort), Weight: 1},
				},
			},
		},
	}

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}
	listeners := []state.InternalListener{
		{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Routes: []state.InternalRoute{route}},
	}
	certsMap := map[string]*tls.Certificate{
		"example.com": &cert,
	}
	dpConfig, err := state.BuildDataplaneConfig(gwKey, listeners, []state.InternalRoute{route}, certsMap, &cert, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	dpConfig.ProxyProtocol = "enabled"
	dpConfig.ProxyProtocolTrustedCIDRs = []string{"127.0.0.0/8"}
	dpConfig.AllowedSourceCIDRs = []string{"127.0.0.0/8"}

	configBytes, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	gwName := "test-gw"
	secretName := singlepod.ResourceNameForGateway(gwName)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	httpsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer httpsLis.Close()

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
			HTTPSListener:             httpsLis,
			ProxyAddr:                 "",
			ProxyHTTPSAddr:            "",
			Scheme:                    scheme,
			DefaultCertificate:        &cert,
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
		onConfigUpdate:   server.updateListenerFilters,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// 1. Reconcile Secret before StartProxyServers
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      secretName,
		},
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 2. Start proxy servers
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	// 3. Dial TCP, send PROXY v1 header, then perform TLS handshake
	rawConn, err := net.DialTimeout("tcp", httpsLis.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial HTTPS listener: %v", err)
	}
	defer rawConn.Close()

	proxyHeader := "PROXY TCP4 203.0.113.195 127.0.0.1 54321 443\r\n"
	if _, err := rawConn.Write([]byte(proxyHeader)); err != nil {
		t.Fatalf("failed to write PROXY header: %v", err)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake failed (PROXY header likely not stripped): %v", err)
	}

	// Send HTTP request over TLS
	httpRequest := "GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := tlsConn.Write([]byte(httpRequest)); err != nil {
		t.Fatalf("failed to write HTTP request over TLS: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("failed to read TLS response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for StartProxyServers to stop")
	}
}

func TestDataplane_ListenerOptionsUpdatedDynamicallyAfterListenerStart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	var backendPort int
	_, _ = fmt.Sscanf(backendPortStr, "%d", &backendPort)

	p := proxy.NewProxy()

	gwKey := types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}
	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: int32(backendPort), Weight: 1},
				},
			},
		},
	}

	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer httpLis.Close()

	gwName := "test-gw"
	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
			HTTPListener:              httpLis,
			ProxyAddr:                 "",
			ProxyHTTPSAddr:            "",
			Scheme:                    scheme,
		},
		proxy: p,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// 1. Start proxy servers with initial/empty listener options (PROXY disabled)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartProxyServers(ctx)
	}()

	// Direct dial sending PROXY header should fail with 400 Bad Request because PROXY is not yet enabled
	conn1, err := net.DialTimeout("tcp", httpLis.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	proxyHeader := "PROXY TCP4 203.0.113.195 127.0.0.1 54321 80\r\n"
	httpRequest := "GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn1.Write([]byte(proxyHeader + httpRequest)); err != nil {
		t.Fatalf("failed to write PROXY header and request: %v", err)
	}
	resp1, err := http.ReadResponse(bufio.NewReader(conn1), nil)
	if err != nil {
		t.Fatalf("failed to read response when PROXY is disabled: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when PROXY is disabled, got %d", resp1.StatusCode)
	}
	_ = conn1.Close()

	// 2. Now reconcile Secret enabling PROXY protocol
	dpConfig := &state.DataplaneConfig{
		GatewayName: gwKey,
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
		},
		Routes:                    []state.InternalRoute{route},
		ProxyProtocol:             "enabled",
		ProxyProtocolTrustedCIDRs: []string{"127.0.0.0/8"},
	}
	configBytes, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	secretName := singlepod.ResourceNameForGateway(gwName)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes,
		},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
		onConfigUpdate:   server.updateListenerFilters,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      secretName,
		},
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// 3. Dial again with PROXY header: should now succeed with 200 OK
	conn2, err := net.DialTimeout("tcp", httpLis.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn2.Close()

	if _, err := conn2.Write([]byte(proxyHeader + httpRequest)); err != nil {
		t.Fatalf("failed to write PROXY header: %v", err)
	}
	resp2, err := http.ReadResponse(bufio.NewReader(conn2), nil)
	if err != nil {
		t.Fatalf("failed to read response after dynamic update: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK after enabling PROXY, got %d", resp2.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error from StartProxyServers: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting for StartProxyServers to stop")
	}
}

func TestDataplane_ConcurrentReconcileAndListenerInit(t *testing.T) {
	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      "test-gw",
		},
		proxy: proxy.NewProxy(),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			if err := server.updateListenerFilters(proxyproto.ListenerOptions{
				ProxyProtocol:             "enabled",
				ProxyProtocolTrustedCIDRs: []string{"10.0.0.0/8"},
				AllowedSourceCIDRs:        []string{"0.0.0.0/0"},
			}); err != nil {
				t.Errorf("updateListenerFilters failed: %v", err)
			}
		}(i)
		go func(idx int) {
			defer wg.Done()
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Errorf("net.Listen failed: %v", err)
				return
			}
			defer lis.Close()
			if idx%2 == 0 {
				if _, err := server.initHTTPFilter(lis); err != nil {
					t.Errorf("initHTTPFilter failed: %v", err)
				}
			} else {
				if _, err := server.initHTTPSFilter(lis); err != nil {
					t.Errorf("initHTTPSFilter failed: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	server.filterMu.Lock()
	opts := server.listenerOptionsLocked()
	hasHTTP := server.httpFilter != nil
	hasHTTPS := server.httpsFilter != nil
	server.filterMu.Unlock()

	if opts.ProxyProtocol != "enabled" {
		t.Errorf("expected ProxyProtocol to be enabled, got %q", opts.ProxyProtocol)
	}
	if !hasHTTP {
		t.Errorf("expected httpFilter to be set")
	}
	if !hasHTTPS {
		t.Errorf("expected httpsFilter to be set")
	}
}

func TestDataplane_InvalidCIDRsRejectedAndNotStored(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	p := proxy.NewProxy()

	gwName := "test-gw"
	secretName := singlepod.ResourceNameForGateway(gwName)

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      gwName,
		},
		proxy: p,
	}

	// 1. Initial valid config
	dpConfigValid := &state.DataplaneConfig{
		GatewayName:               types.NamespacedName{Namespace: "test-ns", Name: gwName},
		ProxyProtocol:             "enabled",
		ProxyProtocolTrustedCIDRs: []string{"10.0.0.0/8"},
		AllowedSourceCIDRs:        []string{"10.0.0.0/8"},
	}
	validBytes, err := dpConfigValid.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal valid config: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: validBytes,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       secretName,
		onConfigUpdate:   server.updateListenerFilters,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: secretName},
	}
	if _, err := reconciler.Reconcile(t.Context(), req); err != nil {
		t.Fatalf("initial valid reconcile failed: %v", err)
	}

	// Verify options were stored
	server.filterMu.Lock()
	opts := server.listenerOptionsLocked()
	server.filterMu.Unlock()
	if opts.ProxyProtocol != "enabled" || len(opts.AllowedSourceCIDRs) != 1 || opts.AllowedSourceCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected stored options: %+v", opts)
	}

	// 2. Secret updated with invalid CIDR
	dpConfigInvalid := &state.DataplaneConfig{
		GatewayName:               types.NamespacedName{Namespace: "test-ns", Name: gwName},
		ProxyProtocol:             "enabled",
		ProxyProtocolTrustedCIDRs: []string{"not-a-valid-cidr"},
		AllowedSourceCIDRs:        []string{"invalid-cidr"},
	}
	invalidBytes, err := dpConfigInvalid.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal invalid config: %v", err)
	}

	secret.Data[singlepod.DataplaneSecretDataKey] = invalidBytes
	if err := cl.Update(t.Context(), secret); err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Reconcile should fail with an error
	_, err = reconciler.Reconcile(t.Context(), req)
	if err == nil {
		t.Fatalf("expected Reconcile to fail for invalid CIDR, but succeeded")
	}

	// Verify old valid options are preserved and invalid ones were not stored
	server.filterMu.Lock()
	optsAfter := server.listenerOptionsLocked()
	server.filterMu.Unlock()
	if optsAfter.ProxyProtocol != "enabled" || len(optsAfter.AllowedSourceCIDRs) != 1 || optsAfter.AllowedSourceCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("expected previous valid options to be preserved, got %+v", optsAfter)
	}
}

type fakeGariCertSource struct{}

func (f *fakeGariCertSource) ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (CertificateResult, error) {
	return CertificateResult{Pending: true}, nil
}

func TestCertificateSources_OptionsWiring(t *testing.T) {
	src := &fakeGariCertSource{}
	opts := Options{
		RestConfig: &rest.Config{
			Host: "http://localhost:8080",
		},
		MetricsAddr:            "0",
		HealthProbeBindAddress: "0",
		CertificateSources:     map[string]CertificateSource{"my-source": src},
	}

	err := opts.complete()
	if err != nil {
		t.Fatalf("complete returned error: %v", err)
	}
	if opts.CertificateSources["my-source"] != src {
		t.Errorf("expected CertificateSources[my-source] to be preserved")
	}
}

func TestDataplane_ListenerReadinessAndRevisionReporting(t *testing.T) {
	env := testenv.Start(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "readiness-test-ns"
		gwName      = "readiness-test-gw"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	secretName := singlepod.ResourceNameForGateway(gwName)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: gwNamespace,
		},
	}
	if err := env.Client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	allocatePort := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate free port: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}

	healthAddr := allocatePort()
	proxyAddr := allocatePort()

	opts := DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.HealthProbeBindAddress = healthAddr
	opts.MetricsAddr = healthAddr
	opts.ProxyAddr = proxyAddr
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false
	opts.SkipNameValidation = true

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	unblockHTTP := make(chan struct{})
	server.Proxy().SetListenFunc(func(network, addr string) (net.Listener, error) {
		select {
		case <-unblockHTTP:
			return net.Listen(network, addr)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server to stop")
		}
	})

	httpClient := &http.Client{Timeout: 1 * time.Second}
	readyURL := fmt.Sprintf("http://%s/readyz", healthAddr)
	appliedURL := fmt.Sprintf("http://%s/_gari/applied", healthAddr)

	getAppliedRevisions := func() []string {
		resp, err := httpClient.Get(appliedURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil
		}
		var revs []string
		_ = json.NewDecoder(resp.Body).Decode(&revs)
		return revs
	}

	getReadyzStatus := func() int {
		resp, err := httpClient.Get(readyURL)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// 1. Initial config Secret (Revision 1) with HTTP listener
	route1 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/v1"}},
				},
				Backends: []state.InternalBackend{
					{Host: "backend-1", Port: 8080, Weight: 1},
				},
			},
		},
	}
	dpConfig1, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 1 failed: %v", err)
	}
	dpConfig1.Revision, err = dpConfig1.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 1 failed: %v", err)
	}
	configBytes1, err := dpConfig1.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig1: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes1,
		},
	}
	if err := env.Client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	// Wait until the secret has been applied to proxy (proxySynced is true)
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		return server.proxySynced.Load(), nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for secret to be applied: %v", err)
	}

	// While listener setup is delayed (unblockHTTP not closed):
	// /readyz must fail (500) and /_gari/applied must omit revision 1.
	if code := getReadyzStatus(); code != http.StatusInternalServerError {
		t.Errorf("expected readyz status 500 while listener setup delayed, got %d", code)
	}
	if revs := getAppliedRevisions(); slices.Contains(revs, dpConfig1.Revision) {
		t.Errorf("expected /_gari/applied to omit revision while listener delayed, got %v", revs)
	}

	// Attempting a connection now must fail (connection refused) because HTTP proxy is not listening yet.
	if conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Errorf("expected connection to %s to fail while listener setup delayed", proxyAddr)
	}

	// Unblock HTTP listener setup so listeners can accept connections.
	close(unblockHTTP)

	// Wait for /readyz to return 200 OK and /_gari/applied to include revision 1.
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		return getReadyzStatus() == http.StatusOK && slices.Contains(getAppliedRevisions(), dpConfig1.Revision), nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for readyz OK and revision 1 applied: %v", err)
	}

	// Connection made right after either signal succeeds.
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("connection to %s failed right after ready signal: %v", proxyAddr, err)
	}
	conn.Close()

	// 2. Config change that adds a listener port (TCP port)
	tcpAddr := allocatePort()
	_, tcpPortStr, _ := net.SplitHostPort(tcpAddr)
	tcpPortNum, _ := strconv.Atoi(tcpPortStr)
	tcpPort := gatewayv1.PortNumber(tcpPortNum)

	var tcpReady atomic.Bool
	server.Proxy().SetListenFunc(func(network, addr string) (net.Listener, error) {
		if !tcpReady.Load() {
			return nil, errors.New("listener setup delayed")
		}
		return net.Listen(network, addr)
	})

	dpConfig2, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
		{Name: "tcp", Port: tcpPort, Protocol: gatewayv1.TCPProtocolType},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 2 failed: %v", err)
	}
	dpConfig2.Revision, err = dpConfig2.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 2 failed: %v", err)
	}
	configBytes2, err := dpConfig2.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig2: %v", err)
	}

	secret.Data[singlepod.DataplaneSecretDataKey] = configBytes2
	if err := env.Client.Update(ctx, secret); err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// While the new TCP listener port cannot bind:
	// /readyz must stay 200 OK (still serving applied revision 1) and /_gari/applied keeps listing revision 1.
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		if code := getReadyzStatus(); code != http.StatusOK {
			t.Errorf("expected readyz status 200 while previous revision is served, got %d", code)
		}
		revs := getAppliedRevisions()
		if !slices.Contains(revs, dpConfig1.Revision) {
			t.Errorf("expected previous revision 1 to stay listed, got %v", revs)
		}
		if slices.Contains(revs, dpConfig2.Revision) {
			t.Errorf("expected new revision 2 to be omitted while listener port cannot bind, got %v", revs)
		}
	}

	// Connection to tcpAddr must fail (connection refused)
	if conn, err := net.DialTimeout("tcp", tcpAddr, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Errorf("expected connection to %s to fail while listener port delayed", tcpAddr)
	}

	// Unblock TCP listener setup and trigger re-reconcile
	tcpReady.Store(true)
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations["test/reconcile"] = "1"
	if err := env.Client.Update(ctx, secret); err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Wait for the new revision to appear in /_gari/applied and /readyz to be 200 OK.
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		return getReadyzStatus() == http.StatusOK && slices.Contains(getAppliedRevisions(), dpConfig2.Revision), nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for revision 2: %v", err)
	}

	// Connection made right after either signal succeeds.
	tcpConn, err := net.DialTimeout("tcp", tcpAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("connection to %s failed right after ready signal: %v", tcpAddr, err)
	}
	tcpConn.Close()
}

func TestDataplane_ConfigRemovesListenerAndAddsUnreadyPort(t *testing.T) {
	env := testenv.Start(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "shared-listener-ns"
		gwName      = "shared-listener-gw"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	secretName := singlepod.ResourceNameForGateway(gwName)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: gwNamespace,
		},
	}
	if err := env.Client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	allocatePort := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate free port: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}

	healthAddr := allocatePort()
	proxyAddr := allocatePort()

	opts := DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.HealthProbeBindAddress = healthAddr
	opts.MetricsAddr = healthAddr
	opts.ProxyAddr = proxyAddr
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false
	opts.SkipNameValidation = true

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server to stop")
		}
	})

	httpClient := &http.Client{Timeout: 1 * time.Second}
	readyURL := fmt.Sprintf("http://%s/readyz", healthAddr)
	appliedURL := fmt.Sprintf("http://%s/_gari/applied", healthAddr)

	getAppliedRevisions := func() []string {
		resp, err := httpClient.Get(appliedURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil
		}
		var revs []string
		_ = json.NewDecoder(resp.Body).Decode(&revs)
		return revs
	}

	getReadyzStatus := func() int {
		resp, err := httpClient.Get(readyURL)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// 1. Initial config (Revision 1) with HTTP listener and TCP port 1
	tcpAddr1 := allocatePort()
	_, tcpPortStr1, _ := net.SplitHostPort(tcpAddr1)
	tcpPortNum1, _ := strconv.Atoi(tcpPortStr1)
	tcpPort1 := gatewayv1.PortNumber(tcpPortNum1)

	route1 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/v1"}},
				},
				Backends: []state.InternalBackend{
					{Host: "backend-1", Port: 8080, Weight: 1},
				},
			},
		},
	}
	dpConfig1, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
		{Name: "tcp1", Port: tcpPort1, Protocol: gatewayv1.TCPProtocolType},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 1 failed: %v", err)
	}
	dpConfig1.Revision, err = dpConfig1.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 1 failed: %v", err)
	}
	configBytes1, err := dpConfig1.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig1: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes1,
		},
	}
	if err := env.Client.Create(ctx, secret); err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	// Wait for Revision 1 to be ready and applied
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		return getReadyzStatus() == http.StatusOK && slices.Contains(getAppliedRevisions(), dpConfig1.Revision), nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for revision 1: %v", err)
	}

	// 2. Revision 2: removes TCP port 1, keeps HTTP, and adds TCP port 2 that fails to bind.
	tcpAddr2 := allocatePort()
	_, tcpPortStr2, _ := net.SplitHostPort(tcpAddr2)
	tcpPortNum2, _ := strconv.Atoi(tcpPortStr2)
	tcpPort2 := gatewayv1.PortNumber(tcpPortNum2)

	server.Proxy().SetListenFunc(func(network, addr string) (net.Listener, error) {
		if strings.HasSuffix(addr, tcpPortStr2) {
			return nil, errors.New("port cannot bind")
		}
		return net.Listen(network, addr)
	})

	dpConfig2, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
		{Name: "tcp2", Port: tcpPort2, Protocol: gatewayv1.TCPProtocolType},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 2 failed: %v", err)
	}
	dpConfig2.Revision, err = dpConfig2.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision 2 failed: %v", err)
	}
	configBytes2, err := dpConfig2.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dpConfig2: %v", err)
	}

	secret.Data[singlepod.DataplaneSecretDataKey] = configBytes2
	if err := env.Client.Update(ctx, secret); err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Once the proxy has applied config 2, tcpPort1 is closed.
	// The shared listener between config 1 and config 2 is HTTP.
	// /readyz must stay 200 OK because the shared listener (HTTP) is still served,
	// and /_gari/applied keeps listing revision 1 while revision 2's port cannot bind.
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		if code := getReadyzStatus(); code != http.StatusOK {
			t.Fatalf("expected readyz 200 for shared listeners, got %d", code)
		}
		revs := getAppliedRevisions()
		if !slices.Contains(revs, dpConfig1.Revision) {
			t.Fatalf("expected previous revision 1 to stay listed, got %v", revs)
		}
		if slices.Contains(revs, dpConfig2.Revision) {
			t.Fatalf("expected new revision 2 to be omitted, got %v", revs)
		}
	}
}

func TestController_ReadyAfterGatewayCreated(t *testing.T) {
	env := testenv.Start(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	healthAddr := ln.Addr().String()
	_ = ln.Close()

	opts := DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.DataplaneMode = false
	opts.HealthProbeBindAddress = healthAddr
	opts.MetricsAddr = healthAddr
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false
	opts.SkipNameValidation = true

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server to stop")
		}
	})

	httpClient := &http.Client{Timeout: 1 * time.Second}
	readyURL := fmt.Sprintf("http://%s/readyz", healthAddr)

	// Wait until controller is ready initially
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		resp, err := httpClient.Get(readyURL)
		if err != nil {
			return false, nil
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for controller initial ready: %v", err)
	}

	// Create a Gateway with an HTTP listener
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "controller-mode-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gari",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(ctx, gw); err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Controller mode runs no in-process proxy, so it must stay ready
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		resp, err := httpClient.Get(readyURL)
		if err != nil {
			t.Fatalf("failed to query readyz: %v", err)
		}
		statusCode := resp.StatusCode
		resp.Body.Close()
		if statusCode != http.StatusOK {
			t.Fatalf("expected readyz 200 after Gateway created in controller mode, got %d", statusCode)
		}
	}
}
