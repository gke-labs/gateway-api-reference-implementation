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
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
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

// TestInternalAPIClient_ConnectAndApply tests:
//   - The data plane connects, receives its Gateway's config, serves a request through the proxy,
//     and the controller's WaitApplied reports one data plane applied.
//   - A config the proxy rejects produces a Nack, and WaitApplied reports the rejection with the reason.
func TestInternalAPIClient_ConnectAndApply(t *testing.T) {
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

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("backend response")); writeErr != nil {
			t.Errorf("failed to write backend response: %v", writeErr)
		}
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}
	backendPort, err := strconv.Atoi(backendPortStr)
	if err != nil {
		t.Fatalf("failed to parse backend port: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	route1 := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/test"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: gatewayv1.PortNumber(backendPort), Weight: 1},
				},
			},
		},
	}
	dataplaneConfig, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	dataplaneConfig.Revision = "rev-1"

	if err := pushServer.PublishDataplaneConfig(ctx, gateway, dataplaneConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-1 failed: %v", err)
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

	var result1 state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer.WaitApplied(ctx, gateway, "rev-1")
		if waitErr != nil {
			return false, waitErr
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

	req1, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req1.Host = "example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if err := resp1.Body.Close(); err != nil {
		t.Errorf("failed to close response body: %v", err)
	}
	if resp1.StatusCode != http.StatusOK || string(body1) != "backend response" {
		t.Errorf("expected 200 OK 'backend response', got %d %q", resp1.StatusCode, string(body1))
	}

	// Reject invalid config with missing cert ID
	invalidConfig := &state.DataplaneConfig{
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
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, invalidConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-reject failed: %v", err)
	}

	var resultReject state.PublishResult
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer.WaitApplied(ctx, gateway, "rev-reject")
		if waitErr != nil {
			return false, waitErr
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

	// Proxy continues serving the in-memory rev-1 config after rejecting rev-reject
	reqStill1, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	reqStill1.Host = "example.com"
	respStill1, err := http.DefaultClient.Do(reqStill1)
	if err != nil {
		t.Fatalf("request through proxy failed after rejection: %v", err)
	}
	bodyStill1, err := io.ReadAll(respStill1.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if err := respStill1.Body.Close(); err != nil {
		t.Errorf("failed to close body: %v", err)
	}
	if respStill1.StatusCode != http.StatusOK || string(bodyStill1) != "backend response" {
		t.Errorf("expected 200 OK 'backend response' after rejection, got %d %q", respStill1.StatusCode, string(bodyStill1))
	}
}

// TestInternalAPIClient_SecondConfigAfterChange tests:
// - A second config after a change is applied and acknowledged.
func TestInternalAPIClient_SecondConfigAfterChange(t *testing.T) {
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

	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("backend1 response")); writeErr != nil {
			t.Errorf("failed to write backend1 response: %v", writeErr)
		}
	}))
	defer backend1.Close()

	backend1Host, backend1PortStr, err := net.SplitHostPort(backend1.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend1 host port: %v", err)
	}
	backend1Port, err := strconv.Atoi(backend1PortStr)
	if err != nil {
		t.Fatalf("failed to parse backend1 port: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

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
	config1, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route1}},
	}, []state.InternalRoute{route1}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 1 failed: %v", err)
	}
	config1.Revision = "rev-1"

	if err := pushServer.PublishDataplaneConfig(ctx, gateway, config1); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-1 failed: %v", err)
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

	go func() {
		_ = server.Start(ctx)
	}()

	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer.WaitApplied(ctx, gateway, "rev-1")
		if waitErr != nil {
			return false, waitErr
		}
		return res.Applied == 1, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for rev-1: %v", err)
	}

	req1, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req1.Host = "example.com"
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("failed to read body 1: %v", err)
	}
	if err := resp1.Body.Close(); err != nil {
		t.Errorf("failed to close body 1: %v", err)
	}
	if resp1.StatusCode != http.StatusOK || string(body1) != "backend1 response" {
		t.Errorf("expected 200 OK 'backend1 response', got %d %q", resp1.StatusCode, string(body1))
	}

	// Publish second config after a change
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("backend2 response")); writeErr != nil {
			t.Errorf("failed to write backend2 response: %v", writeErr)
		}
	}))
	defer backend2.Close()

	backend2Host, backend2PortStr, err := net.SplitHostPort(backend2.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend2 host port: %v", err)
	}
	backend2Port, err := strconv.Atoi(backend2PortStr)
	if err != nil {
		t.Fatalf("failed to parse backend2 port: %v", err)
	}

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
	config2, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route2}},
	}, []state.InternalRoute{route2}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig 2 failed: %v", err)
	}
	config2.Revision = "rev-2"

	if err := pushServer.PublishDataplaneConfig(ctx, gateway, config2); err != nil {
		t.Fatalf("PublishDataplaneConfig rev-2 failed: %v", err)
	}

	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer.WaitApplied(ctx, gateway, "rev-2")
		if waitErr != nil {
			return false, waitErr
		}
		return res.Applied == 1, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for rev-2 applied: %v", err)
	}

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request 2: %v", err)
	}
	req2.Host = "example.com"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("failed to read body 2: %v", err)
	}
	if err := resp2.Body.Close(); err != nil {
		t.Errorf("failed to close body 2: %v", err)
	}
	if resp2.StatusCode != http.StatusOK || string(body2) != "backend2 response" {
		t.Errorf("expected 200 OK 'backend2 response', got %d %q", resp2.StatusCode, string(body2))
	}
}

// wrappedServerStream records Hello messages received and Config messages sent.
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
	pushServer1, err := push.NewServer(push.ServerOptions{
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

	serverAddr, stopServer1 := startTestPushServer(t, pushServer1, "", serverTLSCert)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("backend response")); writeErr != nil {
			t.Errorf("failed to write backend response: %v", writeErr)
		}
	}))
	defer backend.Close()

	backendHost, backendPortStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}
	backendPort, err := strconv.Atoi(backendPortStr)
	if err != nil {
		t.Fatalf("failed to parse backend port: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	route := state.InternalRoute{
		Hostnames: []state.RouteHostname{state.NewRouteHostname("example.com", "example.com")},
		Rules: []state.InternalRule{
			{
				Matches: []state.InternalMatch{
					{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchExact, Value: "/test"}},
				},
				Backends: []state.InternalBackend{
					{Host: backendHost, Port: gatewayv1.PortNumber(backendPort), Weight: 1},
				},
			},
		},
	}
	config, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
	}, []state.InternalRoute{route}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	config.Revision = "rev-1"

	if err := pushServer1.PublishDataplaneConfig(ctx, gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
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

	go func() {
		_ = server.Start(ctx)
	}()

	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer1.WaitApplied(ctx, gateway, "rev-1")
		if waitErr != nil {
			return false, waitErr
		}
		return res.Applied == 1, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for rev-1 applied: %v", err)
	}

	// Stop server 1: stream ends
	stopServer1()

	// Verify data plane keeps serving while disconnected
	reqDisconnected, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request while disconnected: %v", err)
	}
	reqDisconnected.Host = "example.com"
	respDisconnected, err := http.DefaultClient.Do(reqDisconnected)
	if err != nil {
		t.Fatalf("request failed while disconnected: %v", err)
	}
	bodyDisconnected, err := io.ReadAll(respDisconnected.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if err := respDisconnected.Body.Close(); err != nil {
		t.Errorf("failed to close body: %v", err)
	}
	if respDisconnected.StatusCode != http.StatusOK || string(bodyDisconnected) != "backend response" {
		t.Errorf("expected 200 OK while disconnected, got %d %q", respDisconnected.StatusCode, string(bodyDisconnected))
	}

	// Start server 2 on the same address with stream interception
	pushServer2, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("push.NewServer 2 failed: %v", err)
	}
	if err := pushServer2.PublishDataplaneConfig(ctx, gateway, config); err != nil {
		t.Fatalf("pushServer2 PublishDataplaneConfig failed: %v", err)
	}

	var helloReceived *push.Hello
	var helloMu sync.Mutex
	var sentConfigs []*push.ControllerMessage
	var sendMu sync.Mutex

	streamInterceptor := grpc.StreamServerInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &interceptedStream{
			ServerStream: ss,
			onRecvHello: func(hello *push.Hello) {
				helloMu.Lock()
				helloReceived = hello
				helloMu.Unlock()
			},
			onSendMsg: func(m any) {
				if msg, ok := m.(*push.ControllerMessage); ok {
					if msg.GetConfig() != nil {
						sendMu.Lock()
						sentConfigs = append(sentConfigs, msg)
						sendMu.Unlock()
					}
				}
			},
		}
		return handler(srv, wrapped)
	})

	_, stopServer2 := startTestPushServer(t, pushServer2, serverAddr, serverTLSCert, grpc.StreamInterceptor(streamInterceptor))
	defer stopServer2()

	// Wait for data plane to reconnect
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		res, waitErr := pushServer2.WaitApplied(ctx, gateway, "rev-1")
		if waitErr != nil {
			return false, waitErr
		}
		return res.Applied == 1, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for WaitApplied after reconnect: %v", err)
	}

	// Verify Hello contained AppliedRevision: "rev-1"
	helloMu.Lock()
	gotHello := helloReceived
	helloMu.Unlock()
	if gotHello == nil {
		t.Fatalf("expected Hello message on server after reconnect, got nil")
	}
	if gotHello.AppliedRevision != "rev-1" {
		t.Errorf("expected Hello.AppliedRevision = 'rev-1', got %q", gotHello.AppliedRevision)
	}

	// Verify server did NOT send the same config again
	sendMu.Lock()
	configCount := len(sentConfigs)
	sendMu.Unlock()
	if configCount != 0 {
		t.Errorf("expected server not to send config again, but sent %d configs", configCount)
	}

	// Verify proxy still serves requests uninterrupted
	reqAfter, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+proxyAddr+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request after reconnect: %v", err)
	}
	reqAfter.Host = "example.com"
	respAfter, err := http.DefaultClient.Do(reqAfter)
	if err != nil {
		t.Fatalf("request after reconnect failed: %v", err)
	}
	bodyAfter, err := io.ReadAll(respAfter.Body)
	if err != nil {
		t.Fatalf("failed to read body after reconnect: %v", err)
	}
	if err := respAfter.Body.Close(); err != nil {
		t.Errorf("failed to close body: %v", err)
	}
	if respAfter.StatusCode != http.StatusOK || string(bodyAfter) != "backend response" {
		t.Errorf("expected 200 OK after reconnect, got %d %q", respAfter.StatusCode, string(bodyAfter))
	}
}

// TestInternalAPIClient_WrongTrustBundle tests:
// - A wrong trust bundle leaves the data plane with no config and not ready.
func TestInternalAPIClient_WrongTrustBundle(t *testing.T) {
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
	wrongCAPEM := generateTestCA(t)
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

	cfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: gwNamespace, Name: gwName},
		Revision:    "rev-1",
	}
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = gwNamespace
	options.DataplaneGatewayName = gwName
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

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with wrong trust bundle")
	}
	readyzCheck := server.readyzChecker()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := readyzCheck(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}
}

// TestInternalAPIClient_RejectedToken tests:
// - A rejected token leaves the data plane with no config and not ready.
func TestInternalAPIClient_RejectedToken(t *testing.T) {
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
		rejectTokens: true,
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

	cfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: gwNamespace, Name: gwName},
		Revision:    "rev-1",
	}
	if err := pushServer.PublishDataplaneConfig(ctx, gateway, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = gwNamespace
	options.DataplaneGatewayName = gwName
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

	go func() {
		_ = server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	if server.proxySynced.Load() {
		t.Errorf("expected proxySynced=false with rejected token")
	}
	readyzCheck := server.readyzChecker()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	if err := readyzCheck(req); err == nil {
		t.Errorf("expected readyzChecker to return error, got nil")
	}
}

// TestInternalAPIClient_FlagsUnset_BehavesAsToday tests:
// - With the flags unset, the data plane behaves as it does today (watches Secret).
func TestInternalAPIClient_FlagsUnset_BehavesAsToday(t *testing.T) {
	const (
		gwNamespace = "test-ns"
		gwName      = "test-gw"
	)
	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}
	secretName := singlepod.ResourceNameForGateway(gwName)

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add clientgoscheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add gatewayv1 scheme: %v", err)
	}

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
	dataplaneConfig, err := state.BuildDataplaneConfig(gwKey, []state.InternalListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Routes: []state.InternalRoute{route}},
	}, []state.InternalRoute{route}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}
	dataplaneConfig.Revision = "rev-secret"
	configBytes, err := dataplaneConfig.Marshal()
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

	cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = gwNamespace
	options.DataplaneGatewayName = gwName
	// internal API flags are unset!
	options.ProxyAddr = ""
	options.ProxyHTTPSAddr = ""

	server := &Server{
		opts:  options,
		proxy: proxy.NewProxy(),
	}

	if server.internalAPIClient != nil {
		t.Errorf("expected internalAPIClient to be nil when flags are unset")
	}

	reconciler := &dataplaneSecretReconciler{
		Client:               cl,
		gatewayNamespace:     gwNamespace,
		secretName:           secretName,
		applyDataplaneConfig: server.applyDataplaneConfig,
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
