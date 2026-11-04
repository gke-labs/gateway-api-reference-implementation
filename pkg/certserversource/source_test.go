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

package certserversource

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

func generateTestTLSCert(t *testing.T) (*tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"certserver test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to create X509KeyPair: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	tlsCert.Leaf = leaf
	return &tlsCert, leaf
}

type mockCertClient struct {
	getCertFunc func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error)
	closeFunc   func() error
}

func (m *mockCertClient) GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
	return m.getCertFunc(ctx, req)
}

func (m *mockCertClient) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestSource_InputValidation(t *testing.T) {
	mock := &mockCertClient{}
	src := NewSource(mock)
	defer src.Close()

	// 1. Nil gateway / listener
	res, err := src.ResolveCertificates(nil, nil)
	if err != nil || res.FailedReason != gatewayv1.ListenerReasonInvalidCertificateRef {
		t.Errorf("expected InvalidCertificateRef for nil gw/listener, got %+v (err=%v)", res, err)
	}

	// 2. Empty hostname
	emptyHost := gatewayv1.Hostname("")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	res, err = src.ResolveCertificates(gw, &gatewayv1.Listener{Hostname: &emptyHost})
	if err != nil || res.FailedReason != gatewayv1.ListenerReasonInvalidCertificateRef {
		t.Errorf("expected InvalidCertificateRef for empty hostname, got %+v (err=%v)", res, err)
	}

	// 3. Wildcard hostname
	wildcard := gatewayv1.Hostname("*.example.com")
	res, err = src.ResolveCertificates(gw, &gatewayv1.Listener{Hostname: &wildcard})
	if err != nil || res.FailedReason != gatewayv1.ListenerReasonInvalidCertificateRef {
		t.Errorf("expected InvalidCertificateRef for wildcard hostname, got %+v (err=%v)", res, err)
	}
}

func TestSource_NamespaceQualifiedDataPlaneServiceAccount(t *testing.T) {
	reqCh := make(chan *certserverv1.GetCertificateRequest, 1)
	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			select {
			case reqCh <- req:
			default:
			}
			return nil, nil, status.Errorf(codes.Unavailable, "issuance in progress")
		},
	}

	src := NewSource(mock, WithMinBackoff(10*time.Millisecond), WithMaxBackoff(50*time.Millisecond))
	defer src.Close()

	host := gatewayv1.Hostname("app.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "traffic-system",
			Name:      "web-gateway",
		},
	}
	listener := &gatewayv1.Listener{Hostname: &host}

	_, err := src.ResolveCertificates(gw, listener)
	if err != nil {
		t.Fatalf("unexpected error calling ResolveCertificates: %v", err)
	}

	var capturedReq *certserverv1.GetCertificateRequest
	select {
	case capturedReq = <-reqCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for GetCertificate request")
	}

	wantDPSA := fmt.Sprintf("traffic-system/%s", singlepod.ResourceNameForGateway("web-gateway"))
	if got := capturedReq.GetDataPlaneServiceAccount(); got != wantDPSA {
		t.Errorf("GetDataPlaneServiceAccount() = %q, want namespace-qualified %q", got, wantDPSA)
	}

	wantGateway := "traffic-system/web-gateway"
	if got := capturedReq.GetGateway(); got != wantGateway {
		t.Errorf("GetGateway() = %q, want %q", got, wantGateway)
	}
}

func TestSource_NonRetryableError(t *testing.T) {
	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			return nil, nil, status.Errorf(codes.PermissionDenied, "hostname policy refused: domain denied")
		},
	}

	src := NewSource(mock)
	defer src.Close()

	recomputeCh := make(chan struct{}, 10)
	src.SetRecomputeTrigger(func() {
		recomputeCh <- struct{}{}
	})

	host := gatewayv1.Hostname("denied.example.com")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	listener := &gatewayv1.Listener{Hostname: &host}

	// First call -> pending
	res, err := src.ResolveCertificates(gw, listener)
	if err != nil || !res.Pending {
		t.Fatalf("expected Pending=true on initial call, got res=%+v err=%v", res, err)
	}

	// Wait for trigger indicating failure
	select {
	case <-recomputeCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for trigger on permanent error")
	}

	// Second call -> FailedReason reported with message
	res2, err := src.ResolveCertificates(gw, listener)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if res2.FailedReason != gatewayv1.ListenerReasonInvalidCertificateRef {
		t.Errorf("expected InvalidCertificateRef on permanent error, got %v", res2.FailedReason)
	}
	if !strings.Contains(strings.ToLower(res2.FailedMessage), "permission denied") {
		t.Errorf("expected generic permission denied message, got %q", res2.FailedMessage)
	}
}

func TestSource_NonRetryableError_Recovery(t *testing.T) {
	tlsCert, leaf := generateTestTLSCert(t)

	var calls atomic.Int32
	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			idx := calls.Add(1)
			if idx == 1 {
				return nil, nil, status.Errorf(codes.PermissionDenied, "temporary policy denial")
			}
			return tlsCert, leaf, nil
		},
	}

	src := NewSource(mock, WithMinBackoff(10*time.Millisecond), WithMaxBackoff(50*time.Millisecond))
	defer src.Close()

	recomputeCh := make(chan struct{}, 10)
	src.SetRecomputeTrigger(func() {
		select {
		case recomputeCh <- struct{}{}:
		default:
		}
	})

	host := gatewayv1.Hostname("recover.example.com")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	listener := &gatewayv1.Listener{Hostname: &host}

	// 1. Initial call -> pending
	res, err := src.ResolveCertificates(gw, listener)
	if err != nil || !res.Pending {
		t.Fatalf("expected Pending=true, got %+v", res)
	}

	// 2. Wait for first failure trigger
	select {
	case <-recomputeCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for initial failure trigger")
	}

	resFail, err := src.ResolveCertificates(gw, listener)
	if err != nil || resFail.FailedReason != gatewayv1.ListenerReasonInvalidCertificateRef {
		t.Fatalf("expected InvalidCertificateRef, got %+v", resFail)
	}

	// 3. Client retried with capped backoff in background and succeeded!
	select {
	case <-recomputeCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for recovery trigger")
	}

	resSuccess, err := src.ResolveCertificates(gw, listener)
	if err != nil || resSuccess.Pending || len(resSuccess.Certificates) != 1 {
		t.Fatalf("expected recovered certificate, got %+v (err=%v)", resSuccess, err)
	}
}

func TestSource_RefusedRefreshPreservesValidCertificate(t *testing.T) {
	tlsCert, leaf := generateTestTLSCert(t)

	var calls atomic.Int32
	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			idx := calls.Add(1)
			if idx == 1 {
				return tlsCert, leaf, nil
			}
			return nil, nil, status.Errorf(codes.PermissionDenied, "renewal policy refusal")
		},
	}

	simulatedTime := time.Now()
	src := NewSource(mock,
		WithMinBackoff(10*time.Millisecond),
		WithMaxBackoff(50*time.Millisecond),
		WithCheckInterval(50*time.Millisecond),
		WithEvictionPeriod(48*time.Hour),
		WithTimeNow(func() time.Time {
			return simulatedTime
		}),
	)
	defer src.Close()

	recomputeCh := make(chan struct{}, 10)
	src.SetRecomputeTrigger(func() {
		select {
		case recomputeCh <- struct{}{}:
		default:
		}
	})

	host := gatewayv1.Hostname("refresh.example.com")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	listener := &gatewayv1.Listener{Hostname: &host}

	// 1. Initial call -> pending
	res, err := src.ResolveCertificates(gw, listener)
	if err != nil || !res.Pending {
		t.Fatalf("expected Pending=true, got %+v", res)
	}

	// 2. Wait for initial certificate issuance
	select {
	case <-recomputeCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for issuance trigger")
	}

	resCert, err := src.ResolveCertificates(gw, listener)
	if err != nil || len(resCert.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %+v", resCert)
	}

	// 3. Advance time into renewal window, but before expiration
	simulatedTime = simulatedTime.Add(20 * time.Hour)

	// Trigger renewal check
	src.checkAndRefresh()

	// Wait for background renewal attempt (which returns PermissionDenied)
	time.Sleep(100 * time.Millisecond)

	// 4. ResolveCertificates MUST STILL return the valid unexpired certificate!
	resStillValid, err := src.ResolveCertificates(gw, listener)
	if err != nil {
		t.Fatalf("ResolveCertificates returned error: %v", err)
	}
	if len(resStillValid.Certificates) != 1 {
		t.Fatalf("expected valid certificate to be retained during failed refresh, got %+v", resStillValid)
	}
	if resStillValid.FailedReason != "" {
		t.Errorf("expected no FailedReason while cert is unexpired, got %v", resStillValid.FailedReason)
	}
}

func TestSource_Eviction(t *testing.T) {
	tlsCert, leaf := generateTestTLSCert(t)

	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			return tlsCert, leaf, nil
		},
	}

	simulatedTime := time.Now()
	src := NewSource(mock,
		WithEvictionPeriod(100*time.Millisecond),
		WithTimeNow(func() time.Time {
			return simulatedTime
		}),
	)
	defer src.Close()

	recomputeCh := make(chan struct{}, 10)
	src.SetRecomputeTrigger(func() {
		select {
		case recomputeCh <- struct{}{}:
		default:
		}
	})

	host := gatewayv1.Hostname("evict.example.com")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	listener := &gatewayv1.Listener{Hostname: &host}

	// Call ResolveCertificates to insert into cache
	_, _ = src.ResolveCertificates(gw, listener)

	// Wait for initial fetch to finish
	select {
	case <-recomputeCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for fetch")
	}

	src.mu.Lock()
	cacheLenBefore := len(src.cache)
	src.mu.Unlock()
	if cacheLenBefore != 1 {
		t.Fatalf("expected 1 entry in cache, got %d", cacheLenBefore)
	}

	// Advance time past EvictionPeriod without calling ResolveCertificates
	simulatedTime = simulatedTime.Add(200 * time.Millisecond)

	src.checkAndRefresh()

	src.mu.Lock()
	cacheLenAfter := len(src.cache)
	src.mu.Unlock()
	if cacheLenAfter != 0 {
		t.Fatalf("expected inactive entry to be evicted from cache, got %d entries", cacheLenAfter)
	}
}

func TestSource_Eviction_FailingLoopExits(t *testing.T) {
	var rpcCalls atomic.Int32
	mock := &mockCertClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, error) {
			rpcCalls.Add(1)
			return nil, nil, status.Errorf(codes.Unavailable, "issuance permanently broken in test")
		},
	}

	src := NewSource(mock,
		WithMinBackoff(10*time.Millisecond),
		WithMaxBackoff(20*time.Millisecond),
		WithEvictionPeriod(100*time.Millisecond),
		WithCheckInterval(50*time.Millisecond),
	)
	defer src.Close()

	host := gatewayv1.Hostname("failing.example.com")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}}
	listener := &gatewayv1.Listener{Hostname: &host}

	// 1. Initial call triggers background fetchLoop
	res, err := src.ResolveCertificates(gw, listener)
	if err != nil || !res.Pending {
		t.Fatalf("expected initial call to return Pending=true, got %+v (err=%v)", res, err)
	}

	// 2. Stop calling ResolveCertificates and wait for EvictionPeriod to elapse
	time.Sleep(300 * time.Millisecond)

	src.mu.Lock()
	cacheLen := len(src.cache)
	src.mu.Unlock()
	if cacheLen != 0 {
		t.Fatalf("expected failing entry to be evicted after EvictionPeriod, but %d entries remain", cacheLen)
	}

	// 3. Record RPC count, wait longer, and ensure no further RPCs are made
	callsAtEviction := rpcCalls.Load()
	if callsAtEviction == 0 {
		t.Fatalf("expected at least one RPC call before eviction")
	}

	time.Sleep(150 * time.Millisecond)

	callsAfter := rpcCalls.Load()
	if callsAfter != callsAtEviction {
		t.Errorf("expected fetchLoop to have exited with no further RPCs, but calls increased from %d to %d", callsAtEviction, callsAfter)
	}
}
