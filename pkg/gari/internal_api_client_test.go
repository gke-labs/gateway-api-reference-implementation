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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testdataplane"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type fakeTokenReviewer struct {
	mu           sync.Mutex
	validTokens  map[string]types.NamespacedName
	rejectTokens bool
}

func (reviewer *fakeTokenReviewer) ReviewToken(ctx context.Context, token string) (string, string, error) {
	reviewer.mu.Lock()
	defer reviewer.mu.Unlock()
	if reviewer.rejectTokens {
		return "", "", errors.New("token rejected by reviewer")
	}
	if namespacedName, ok := reviewer.validTokens[token]; ok {
		return namespacedName.Namespace, namespacedName.Name, nil
	}
	return "", "", errors.New("unrecognized token")
}

func generateTestCA(t *testing.T) []byte {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
}

func generateTestCAAndServerCert(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	caPEM, serverTLSCert, err := testdataplane.GenerateTestCAAndServerCert()
	if err != nil {
		t.Fatalf("testdataplane.GenerateTestCAAndServerCert failed: %v", err)
	}
	return caPEM, serverTLSCert
}

func startTestPushServer(t *testing.T, server *push.Server, addr string, serverTLSCert tls.Certificate, extraServerOptions ...grpc.ServerOption) (string, func()) {
	t.Helper()
	var ln net.Listener
	var err error
	if addr == "" {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		t.Fatalf("failed to listen on %q: %v", addr, err)
	}
	actualAddr := ln.Addr().String()

	serverOptions := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&serverTLSCert)),
		grpc.MaxRecvMsgSize(push.MaxMessageBytes),
		grpc.MaxSendMsgSize(push.MaxMessageBytes),
	}
	serverOptions = append(serverOptions, extraServerOptions...)

	grpcServer := grpc.NewServer(serverOptions...)
	push.RegisterPushServiceServer(grpcServer, server)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- grpcServer.Serve(ln)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			grpcServer.Stop()
			if serveErr := <-serverErr; serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
				t.Errorf("grpcServer.Serve error: %v", serveErr)
			}
		})
	}
	return actualAddr, stop
}

type internalAPITestHarness struct {
	gateway        *gatewayv1.Gateway
	gwKey          types.NamespacedName
	pushServer     *push.Server
	serverAddr     string
	serverCert     tls.Certificate
	stopPushServer func()
	reviewer       *fakeTokenReviewer
	backend        *httptest.Server
	proxyAddr      string
}

func setupInternalAPITest(t *testing.T, initialRevision string) (*internalAPITestHarness, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())

	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
		tokenVal    = "valid-token-1234"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
	}

	reviewer := &fakeTokenReviewer{
		validTokens: map[string]types.NamespacedName{
			tokenVal: {Namespace: gwNamespace, Name: state.ResourceNameForGateway(gwName)},
		},
	}
	pushServer, err := push.NewServer(push.ServerOptions{TokenReviewer: reviewer})
	if err != nil {
		t.Fatalf("push.NewServer failed: %v", err)
	}

	caPEM, serverTLSCert := generateTestCAAndServerCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(tokenVal), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	serverAddr, stopServer := startTestPushServer(t, pushServer, "", serverTLSCert)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("backend response")); writeErr != nil {
			t.Errorf("failed to write backend response: %v", writeErr)
		}
	}))

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	harness := &internalAPITestHarness{
		gateway:        gateway,
		gwKey:          gwKey,
		pushServer:     pushServer,
		serverAddr:     serverAddr,
		serverCert:     serverTLSCert,
		stopPushServer: stopServer,
		reviewer:       reviewer,
		backend:        backend,
		proxyAddr:      proxyAddr,
	}

	if initialRevision != "" {
		harness.publishConfig(ctx, t, initialRevision, backend.Listener.Addr().String(), "")
	}

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = gwNamespace
	options.DataplaneGatewayName = gwName
	options.InternalAPIAddress = serverAddr
	options.InternalAPICAFile = caFile
	options.InternalAPITokenFile = tokenFile
	options.HTTPListener = proxyLn
	options.ProxyAddr = ""
	options.ProxyHTTPSAddr = ""
	options.MetricsAddr = "0"
	options.HealthProbeBindAddress = "0"

	server, err := New(options)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	server.SetInternalAPIClientBackoffForTest(20*time.Millisecond, 100*time.Millisecond)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		if startErr := <-serverErr; startErr != nil && !errors.Is(startErr, context.Canceled) {
			t.Errorf("server.Start error: %v", startErr)
		}
		backend.Close()
		stopServer()
	})

	if initialRevision != "" {
		harness.waitApplied(ctx, t, pushServer, initialRevision, 1)
	}

	return harness, ctx
}

func (h *internalAPITestHarness) requestProxy(ctx context.Context, t *testing.T, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+h.proxyAddr+path, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("failed to close body: %v", closeErr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func (h *internalAPITestHarness) publishConfig(ctx context.Context, t *testing.T, revision, backendAddr string, clientCertID string) {
	t.Helper()
	h.publishConfigOnServer(ctx, t, h.pushServer, revision, backendAddr, clientCertID)
}

func (h *internalAPITestHarness) publishConfigOnServer(ctx context.Context, t *testing.T, targetServer *push.Server, revision, backendAddr string, clientCertID ...string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse backend port: %v", err)
	}

	backend := state.InternalBackend{
		Host:   host,
		Port:   gatewayv1.PortNumber(port),
		Weight: 1,
	}
	if len(clientCertID) > 0 && clientCertID[0] != "" {
		backend.TLSConfig = &state.InternalTLSConfig{ClientCertID: clientCertID[0]}
	}

	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches:  []state.InternalMatch{{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/test"}}},
				Backends: []state.InternalBackend{backend},
			},
		},
	}
	config, err := state.BuildDataplaneConfig(h.gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
	}, []state.InternalRoute{route}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	config.Revision = revision

	if err := targetServer.PublishDataplaneConfig(ctx, h.gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}
}

func (h *internalAPITestHarness) waitApplied(ctx context.Context, t *testing.T, targetServer *push.Server, revision string, wantApplied int) state.PublishResult {
	t.Helper()
	var result state.PublishResult
	err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := targetServer.WaitApplied(ctx, h.gateway, revision)
		if waitErr != nil {
			return false, waitErr
		}
		if wantApplied > 0 && res.Applied == wantApplied {
			result = res
			return true, nil
		}
		if wantApplied == 0 && len(res.Rejections) > 0 {
			result = res
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for revision %q: %v (last result: %+v)", revision, err, result)
	}
	return result
}

// TestInternalAPIClient_ConnectAndApply tests:
//   - The data plane connects, receives its Gateway's config, serves a request through the proxy,
//     and the controller's WaitApplied reports one data plane applied.
//   - A config the proxy rejects produces a Nack, and WaitApplied reports the rejection with the reason.
func TestInternalAPIClient_ConnectAndApply(t *testing.T) {
	harness, ctx := setupInternalAPITest(t, "rev-1")

	// Verify request through proxy
	code, body := harness.requestProxy(ctx, t, "example.com", "/test")
	if code != http.StatusOK || body != "backend response" {
		t.Errorf("got %d %q, want 200 'backend response'", code, body)
	}

	// Reject invalid config with missing cert ID
	harness.publishConfig(ctx, t, "rev-reject", harness.backend.Listener.Addr().String(), "non-existent-cert-id")
	result := harness.waitApplied(ctx, t, harness.pushServer, "rev-reject", 0)
	if result.Applied != 0 || len(result.Rejections) != 1 || !strings.Contains(result.Rejections[0].Reason, "missing from certificates") {
		t.Errorf("unexpected rejections for invalid config: %+v", result)
	}

	// Proxy continues serving the in-memory rev-1 config after rejecting rev-reject
	code, body = harness.requestProxy(ctx, t, "example.com", "/test")
	if code != http.StatusOK || body != "backend response" {
		t.Errorf("got %d %q after rejection, want 200 'backend response'", code, body)
	}
}

// TestInternalAPIClient_SecondConfigAfterChange tests:
// - A second config after a change is applied and acknowledged.
func TestInternalAPIClient_SecondConfigAfterChange(t *testing.T) {
	harness, ctx := setupInternalAPITest(t, "rev-1")

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("backend2 response")); err != nil {
			t.Errorf("failed to write backend2 response: %v", err)
		}
	}))
	defer backend2.Close()

	// Publish second config after a change
	harness.publishConfig(ctx, t, "rev-2", backend2.Listener.Addr().String(), "")
	harness.waitApplied(ctx, t, harness.pushServer, "rev-2", 1)

	// Verify request routing to backend2
	code, body := harness.requestProxy(ctx, t, "example.com", "/test")
	if code != http.StatusOK || body != "backend2 response" {
		t.Errorf("got %d %q, want 200 'backend2 response'", code, body)
	}
}

type interceptedStream struct {
	grpc.ServerStream
	onRecvHello func(hello *push.Hello)
	onSendMsg   func(m any)
}

func (s *interceptedStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	if msg, ok := m.(*push.DataplaneMessage); ok {
		if hello := msg.GetHello(); hello != nil && s.onRecvHello != nil {
			s.onRecvHello(hello)
		}
	}
	return nil
}

func (s *interceptedStream) SendMsg(m any) error {
	if s.onSendMsg != nil {
		s.onSendMsg(m)
	}
	return s.ServerStream.SendMsg(m)
}

// TestInternalAPIClient_ServerStoppedAndStartedAgain tests:
//   - The server is stopped and started again: the data plane keeps serving while disconnected,
//     reconnects, and reports its applied revision in Hello, so the server does not send the same config again.
func TestInternalAPIClient_ServerStoppedAndStartedAgain(t *testing.T) {
	harness, ctx := setupInternalAPITest(t, "rev-1")

	// Stop server 1: stream ends
	harness.stopPushServer()

	// Verify data plane keeps serving while disconnected
	code, body := harness.requestProxy(ctx, t, "example.com", "/test")
	if code != http.StatusOK || body != "backend response" {
		t.Errorf("got %d %q while disconnected, want 200 'backend response'", code, body)
	}

	// Start server 2 on the same address with stream interception
	pushServer2, err := push.NewServer(push.ServerOptions{TokenReviewer: harness.reviewer})
	if err != nil {
		t.Fatalf("push.NewServer 2 failed: %v", err)
	}
	harness.publishConfigOnServer(ctx, t, pushServer2, "rev-1", harness.backend.Listener.Addr().String())

	var helloReceived *push.Hello
	var helloMu sync.Mutex
	var sentConfigs int
	var sendMu sync.Mutex

	interceptor := grpc.StreamServerInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &interceptedStream{
			ServerStream: ss,
			onRecvHello: func(hello *push.Hello) {
				helloMu.Lock()
				helloReceived = hello
				helloMu.Unlock()
			},
			onSendMsg: func(m any) {
				if msg, ok := m.(*push.ControllerMessage); ok && msg.GetConfig() != nil {
					sendMu.Lock()
					sentConfigs++
					sendMu.Unlock()
				}
			},
		}
		return handler(srv, wrapped)
	})

	_, stopServer2 := startTestPushServer(t, pushServer2, harness.serverAddr, harness.serverCert, grpc.StreamInterceptor(interceptor))
	defer stopServer2()

	harness.waitApplied(ctx, t, pushServer2, "rev-1", 1)

	helloMu.Lock()
	gotHello := helloReceived
	helloMu.Unlock()
	if gotHello == nil || gotHello.AppliedRevision != "rev-1" {
		t.Errorf("expected Hello.AppliedRevision = 'rev-1', got %+v", gotHello)
	}

	sendMu.Lock()
	configCount := sentConfigs
	sendMu.Unlock()
	if configCount != 0 {
		t.Errorf("expected server not to send config again, but sent %d configs", configCount)
	}

	code, body = harness.requestProxy(ctx, t, "example.com", "/test")
	if code != http.StatusOK || body != "backend response" {
		t.Errorf("got %d %q after reconnect, want 200 'backend response'", code, body)
	}
}

// TestInternalAPIClient_WrongTrustBundle tests:
// - A wrong trust bundle leaves the data plane with no config and not ready.
func TestInternalAPIClient_WrongTrustBundle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	reviewer := &fakeTokenReviewer{
		validTokens: map[string]types.NamespacedName{
			"valid-token-1234": {Namespace: "test-ns", Name: state.ResourceNameForGateway("test-gw")},
		},
	}
	pushServer, err := push.NewServer(push.ServerOptions{TokenReviewer: reviewer})
	if err != nil {
		t.Fatalf("push.NewServer failed: %v", err)
	}

	_, serverTLSCert := generateTestCAAndServerCert(t)
	serverAddr, stopServer := startTestPushServer(t, pushServer, "", serverTLSCert)
	defer stopServer()

	wrongCAFile := filepath.Join(t.TempDir(), "wrong-ca.crt")
	if err := os.WriteFile(wrongCAFile, generateTestCA(t), 0600); err != nil {
		t.Fatalf("failed to write wrong CA file: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("valid-token-1234"), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "test-ns"
	options.DataplaneGatewayName = "test-gw"
	options.InternalAPIAddress = serverAddr
	options.InternalAPICAFile = wrongCAFile
	options.InternalAPITokenFile = tokenFile
	options.ProxyAddr = ""
	options.ProxyHTTPSAddr = ""
	options.MetricsAddr = "0"
	options.HealthProbeBindAddress = "0"

	server, err := New(options)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	server.SetInternalAPIClientBackoffForTest(20*time.Millisecond, 50*time.Millisecond)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with wrong trust bundle")
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := server.readyzChecker()(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}

	cancel()
	if startErr := <-serverErr; startErr != nil && !errors.Is(startErr, context.Canceled) {
		t.Errorf("server.Start error: %v", startErr)
	}
}

// TestInternalAPIClient_RejectedToken tests:
// - A rejected token leaves the data plane with no config and not ready.
func TestInternalAPIClient_RejectedToken(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	reviewer := &fakeTokenReviewer{rejectTokens: true}
	pushServer, err := push.NewServer(push.ServerOptions{TokenReviewer: reviewer})
	if err != nil {
		t.Fatalf("push.NewServer failed: %v", err)
	}

	caPEM, serverTLSCert := generateTestCAAndServerCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("rejected-token"), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	serverAddr, stopServer := startTestPushServer(t, pushServer, "", serverTLSCert)
	defer stopServer()

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "test-ns"
	options.DataplaneGatewayName = "test-gw"
	options.InternalAPIAddress = serverAddr
	options.InternalAPICAFile = caFile
	options.InternalAPITokenFile = tokenFile
	options.ProxyAddr = ""
	options.ProxyHTTPSAddr = ""
	options.MetricsAddr = "0"
	options.HealthProbeBindAddress = "0"

	server, err := New(options)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	server.SetInternalAPIClientBackoffForTest(20*time.Millisecond, 50*time.Millisecond)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with rejected token")
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := server.readyzChecker()(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}

	cancel()
	if startErr := <-serverErr; startErr != nil && !errors.Is(startErr, context.Canceled) {
		t.Errorf("server.Start error: %v", startErr)
	}
}
