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
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type fakeTokenReviewer struct {
	mu           sync.Mutex
	validTokens  map[string]types.NamespacedName
	rejectTokens bool
}

func (f *fakeTokenReviewer) ReviewToken(ctx context.Context, token string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rejectTokens {
		return "", "", errors.New("token rejected by reviewer")
	}
	if nn, ok := f.validTokens[token]; ok {
		return nn.Namespace, nn.Name, nil
	}
	return "", "", errors.New("unrecognized token")
}

func generateTestCAAndServerCert(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
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
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Internal API Server"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("failed to create X509KeyPair: %v", err)
	}
	return caPEM, serverTLSCert
}

func startTestPushServer(t *testing.T, server *push.Server, addr string, serverTLSCert tls.Certificate) (string, func()) {
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

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&serverTLSCert)),
		grpc.MaxRecvMsgSize(push.MaxMessageBytes),
		grpc.MaxSendMsgSize(push.MaxMessageBytes),
	)
	push.RegisterPushServiceServer(grpcServer, server)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- grpcServer.Serve(ln)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			grpcServer.Stop()
			<-serverErr
		})
	}
	return actualAddr, stop
}

// TestDataplanePushClient_EndToEnd tests criteria 1, 2, 3, and 4:
//   - The data plane connects, receives its Gateway's config, serves a request through the proxy,
//     and the controller's WaitApplied reports one data plane applied.
//   - A config the proxy rejects produces a Nack, and WaitApplied reports the rejection with the reason.
//   - A second config after a change is applied and acknowledged.
//   - The server is stopped and started again: the data plane keeps serving while disconnected,
//     reconnects, and reports its applied revision in Hello, so the server does not send the same config again.
func TestDataplanePushClient_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

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
			tokenVal: {Namespace: gwNamespace, Name: singlepod.ResourceNameForGateway(gwName)},
		},
	}
	pushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
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
	defer stopServer()

	// 1. Upstream backend 1
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend1 response"))
	}))
	defer backend1.Close()

	backend1Host, backend1PortStr, _ := net.SplitHostPort(backend1.Listener.Addr().String())
	backend1Port, _ := strconv.Atoi(backend1PortStr)

	// Proxy listener
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	// Publish initial valid config rev-1
	route1 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/test"}},
				},
				Backends: []state.InternalBackend{
					{Host: backend1Host, Port: gatewayv1.PortNumber(backend1Port), Weight: 1},
				},
			},
		},
	}
	cfg1, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	cfg1.Revision = "rev-1"

	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg1); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-1 failed: %v", err)
	}

	// Start data plane through public entry point gari.New
	opts := DefaultOptions()
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.InternalAPIAddress = serverAddr
	opts.InternalAPICAFile = caFile
	opts.InternalAPITokenFile = tokenFile
	opts.PushClientMinBackoff = 20 * time.Millisecond
	opts.PushClientMaxBackoff = 100 * time.Millisecond
	opts.HTTPListener = proxyLn
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()

	// Criterion 1: Data plane connects, receives config, WaitApplied reports 1 applied.
	var result1 state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, err := pushServer.WaitApplied(ctx, gateway, "rev-1")
		if err != nil {
			return false, err
		}
		if res.Applied == 1 {
			result1 = res
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for WaitApplied rev-1: %v (last result: %+v)", err, result1)
	}

	// Serve request through proxy
	req1, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req1.Host = "example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || string(body1) != "backend1 response" {
		t.Errorf("expected 200 OK 'backend1 response', got %d %q", resp1.StatusCode, string(body1))
	}

	// Criterion 2: A config the proxy rejects produces a Nack and WaitApplied reports the rejection with reason.
	invalidCfg := &state.DataplaneConfig{
		GatewayName: gwKey,
		Revision:    "rev-reject",
		Listeners: []state.InternalListener{
			{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
				Routes: []state.InternalRoute{
					{
						Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
						Rules: []state.InternalRule{
							{
								Backends: []state.InternalBackend{
									{
										Host: "bad-cert-host",
										Port: 8080,
										TLSConfig: &state.InternalTLSConfig{
											ClientCertID: "non-existent-cert-id",
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
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, invalidCfg); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-reject failed: %v", err)
	}

	var resultReject state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, err := pushServer.WaitApplied(ctx, gateway, "rev-reject")
		if err != nil {
			return false, err
		}
		if len(res.Rejections) == 1 {
			resultReject = res
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for WaitApplied rev-reject: %v (last result: %+v)", err, resultReject)
	}
	if resultReject.Applied != 0 {
		t.Errorf("expected Applied=0, got %d", resultReject.Applied)
	}
	if len(resultReject.Rejections) != 1 {
		t.Fatalf("expected 1 rejection, got %d", len(resultReject.Rejections))
	}
	if !strings.Contains(resultReject.Rejections[0].Reason, "missing from certificates") {
		t.Errorf("expected rejection reason to mention 'missing from certificates', got %q", resultReject.Rejections[0].Reason)
	}

	// The data plane keeps serving the config it holds in memory while rejecting new config
	reqStill1, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	reqStill1.Host = "example.com"
	respStill1, err := http.DefaultClient.Do(reqStill1)
	if err != nil {
		t.Fatalf("request through proxy failed after rejection: %v", err)
	}
	bodyStill1, _ := io.ReadAll(respStill1.Body)
	respStill1.Body.Close()
	if respStill1.StatusCode != http.StatusOK || string(bodyStill1) != "backend1 response" {
		t.Errorf("expected 200 OK 'backend1 response' after rejection, got %d %q", respStill1.StatusCode, string(bodyStill1))
	}

	// Criterion 3: A second config after a change is applied and acknowledged.
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend2 response"))
	}))
	defer backend2.Close()

	backend2Host, backend2PortStr, _ := net.SplitHostPort(backend2.Listener.Addr().String())
	backend2Port, _ := strconv.Atoi(backend2PortStr)

	route2 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/test"}},
				},
				Backends: []state.InternalBackend{
					{Host: backend2Host, Port: gatewayv1.PortNumber(backend2Port), Weight: 1},
				},
			},
		},
	}
	cfg2, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route2}},
	}, []state.InternalRoute{route2}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 2 failed: %v", err)
	}
	cfg2.Revision = "rev-2"

	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg2); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-2 failed: %v", err)
	}

	var result2 state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, err := pushServer.WaitApplied(ctx, gateway, "rev-2")
		if err != nil {
			return false, err
		}
		if res.Applied == 1 {
			result2 = res
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for WaitApplied rev-2: %v (last result: %+v)", err, result2)
	}

	// Verify request routing to backend2
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req2.Host = "example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || string(body2) != "backend2 response" {
		t.Errorf("expected 200 OK 'backend2 response', got %d %q", resp2.StatusCode, string(body2))
	}

	// Criterion 4: The server is stopped and started again:
	// - Data plane keeps serving while disconnected.
	// - Reconnects.
	// - Reports its applied revision in Hello, so the server does not send the same config again.
	stopServer()

	// Verify data plane keeps serving while disconnected
	reqDisconnected, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	reqDisconnected.Host = "example.com"
	respDisconnected, err := http.DefaultClient.Do(reqDisconnected)
	if err != nil {
		t.Fatalf("request through proxy failed while disconnected: %v", err)
	}
	bodyDisconnected, _ := io.ReadAll(respDisconnected.Body)
	respDisconnected.Body.Close()
	if respDisconnected.StatusCode != http.StatusOK || string(bodyDisconnected) != "backend2 response" {
		t.Errorf("expected 200 OK 'backend2 response' while disconnected, got %d %q", respDisconnected.StatusCode, string(bodyDisconnected))
	}

	// Create a new server instance to ensure clean state and verify it doesn't need to re-send
	restartedPushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("failed to create restarted push server: %v", err)
	}
	if err := restartedPushServer.PublishDataplaneConfig(ctx, gateway, cfg2); err != nil {
		t.Fatalf("restarted push server publish failed: %v", err)
	}

	// Restart listening on the exact same serverAddr
	_, stopServer2 := startTestPushServer(t, restartedPushServer, serverAddr, serverTLSCert)
	defer stopServer2()

	// WaitApplied for rev-2 should report 1 data plane applied based on Hello.AppliedRevision alone!
	var resultReconnect state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, err := restartedPushServer.WaitApplied(ctx, gateway, "rev-2")
		if err != nil {
			return false, err
		}
		if res.Applied == 1 {
			resultReconnect = res
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for WaitApplied after reconnect: %v (last result: %+v)", err, resultReconnect)
	}
}

// TestDataplanePushClient_WrongTrustBundle tests Criterion 5:
// A wrong trust bundle leaves the data plane with no config and not ready.
func TestDataplanePushClient_WrongTrustBundle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
		tokenVal    = "valid-token-1234"
	)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
	}
	reviewer := &fakeTokenReviewer{
		validTokens: map[string]types.NamespacedName{
			tokenVal: {Namespace: gwNamespace, Name: singlepod.ResourceNameForGateway(gwName)},
		},
	}
	pushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("push.NewServer failed: %v", err)
	}

	_, serverTLSCert := generateTestCAAndServerCert(t)
	// Generate a completely different CA for the client trust bundle
	wrongCAPEM, _ := generateTestCAAndServerCert(t)
	wrongCAFile := filepath.Join(t.TempDir(), "wrong-ca.crt")
	if err := os.WriteFile(wrongCAFile, wrongCAPEM, 0600); err != nil {
		t.Fatalf("failed to write wrong CA file: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(tokenVal), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	serverAddr, stopServer := startTestPushServer(t, pushServer, "", serverTLSCert)
	defer stopServer()

	// Publish valid config
	cfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: gwNamespace, Name: gwName},
		Revision:    "rev-1",
	}
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	opts := DefaultOptions()
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.InternalAPIAddress = serverAddr
	opts.InternalAPICAFile = wrongCAFile
	opts.InternalAPITokenFile = tokenFile
	opts.PushClientMinBackoff = 20 * time.Millisecond
	opts.PushClientMaxBackoff = 50 * time.Millisecond
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()

	// Let client retry a few times
	time.Sleep(150 * time.Millisecond)

	// Verify data plane has no config and is not ready
	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with wrong trust bundle")
	}
	readyzCheck := server.readyzChecker()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := readyzCheck(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}
}

// TestDataplanePushClient_RejectedToken tests Criterion 5:
// A rejected token leaves the data plane with no config and not ready.
func TestDataplanePushClient_RejectedToken(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
		badTokenVal = "rejected-token-xyz"
	)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwNamespace, Name: gwName},
	}
	reviewer := &fakeTokenReviewer{
		rejectTokens: true, // reject all tokens
	}
	pushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("push.NewServer failed: %v", err)
	}

	caPEM, serverTLSCert := generateTestCAAndServerCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(badTokenVal), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	serverAddr, stopServer := startTestPushServer(t, pushServer, "", serverTLSCert)
	defer stopServer()

	// Publish valid config
	cfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: gwNamespace, Name: gwName},
		Revision:    "rev-1",
	}
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	opts := DefaultOptions()
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	opts.InternalAPIAddress = serverAddr
	opts.InternalAPICAFile = caFile
	opts.InternalAPITokenFile = tokenFile
	opts.PushClientMinBackoff = 20 * time.Millisecond
	opts.PushClientMaxBackoff = 50 * time.Millisecond
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()

	// Let client retry a few times
	time.Sleep(150 * time.Millisecond)

	// Verify data plane has no config and is not ready
	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with rejected token")
	}
	readyzCheck := server.readyzChecker()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := readyzCheck(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}
}

// TestDataplanePushClient_FlagsUnset_BehavesAsToday tests Criterion 6:
// With the flags unset, the data plane behaves as it does today (watches Secret).
func TestDataplanePushClient_FlagsUnset_BehavesAsToday(t *testing.T) {
	env := testenv.Start(t)

	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	secretName := singlepod.ResourceNameForGateway(gwName)

	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/ok"}},
				},
				Backends: []state.InternalBackend{
					{Host: "backend-ok", Port: 8080, Weight: 1},
				},
			},
		},
	}
	dpCfg, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
	}, []state.InternalRoute{route}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	dpCfg.Revision = "rev-secret"
	configBytes, err := dpCfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			singlepod.DataplaneSecretDataKey: configBytes,
		},
	}

	cl := fakeclient.NewClientBuilder().WithScheme(env.Scheme).WithObjects(secret).Build()

	opts := DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.DataplaneMode = true
	opts.DataplaneGatewayNamespace = gwNamespace
	opts.DataplaneGatewayName = gwName
	// internal API flags are unset!
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""

	server, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if server.pushClient != nil {
		t.Errorf("expected pushClient to be nil when flags are unset")
	}

	reconciler := &dataplaneSecretReconciler{
		Client:           cl,
		proxy:            server.proxy,
		proxySynced:      &server.proxySynced,
		gatewayNamespace: gwNamespace,
		secretName:       secretName,
		onConfigUpdate:   server.updateListenerFilters,
		onConfigApplied:  server.recordAppliedRevision,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: gwNamespace,
			Name:      secretName,
		},
	}

	res, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res.Requeue {
		t.Errorf("expected no requeue")
	}

	if !server.proxySynced.Load() {
		t.Errorf("expected proxySynced to be true after secret reconcile")
	}
	if revs := server.appliedRevisionsList(); len(revs) != 1 || revs[0] != "rev-secret" {
		t.Errorf("expected applied revisions ['rev-secret'], got %v", revs)
	}
}
