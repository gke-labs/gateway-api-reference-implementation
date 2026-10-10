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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ControllerName != controller.DefaultControllerName {
		t.Errorf("expected controller name %q, got %q", controller.DefaultControllerName, opts.ControllerName)
	}
	if opts.ProxyAddr != ":8000" {
		t.Errorf("expected proxy addr :8000, got %q", opts.ProxyAddr)
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
	if opts.MetricsAddr != ":8080" {
		t.Errorf("expected metrics addr :8080, got %q", opts.MetricsAddr)
	}
	if opts.HealthProbeBindAddress != ":8081" {
		t.Errorf("expected probe addr :8081, got %q", opts.HealthProbeBindAddress)
	}
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
					Hostnames: []string{"example.com"},
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
					Hostnames: []string{"*.other.com"},
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
					Hostnames: []string{"example.com"},
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
					Hostnames: []string{"example.com"},
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
		Hostnames: []string{"example.com"},
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

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-gw-gari",
		},
		Data: map[string][]byte{
			"config.json": configBytes,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      "test-gw",
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       "test-gw-gari",
	}

	ctx := t.Context()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      "test-gw-gari",
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

func TestDataplaneSecretReconciler_MissingSecretLeavesProxyNotSynced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	p := proxy.NewProxy()
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := &Server{
		opts: Options{
			DataplaneMode:             true,
			DataplaneGatewayNamespace: "test-ns",
			DataplaneGatewayName:      "test-gw",
		},
		proxy: p,
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            p,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: "test-ns",
		secretName:       "test-gw-gari",
	}

	ctx := t.Context()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "test-ns",
			Name:      "test-gw-gari",
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
