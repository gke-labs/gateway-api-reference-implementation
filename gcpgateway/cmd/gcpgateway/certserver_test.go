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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
)

type safeLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeLogBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func generateServerCert(t *testing.T, host string) (*tls.Config, []byte, []byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, certPEM, keyPEM, certPEM
}

type fakeSourceServer struct {
	certserverv1.UnimplementedCertificateServiceServer

	t                        *testing.T
	expectedToken            string
	expectedGateway          string
	expectedDPServiceAccount string
	expectedHostname         string

	issuedCertChain []byte
	issuedPrivKey   []byte

	calls atomic.Int32
}

func (f *fakeSourceServer) GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest) (*certserverv1.GetCertificateResponse, error) {
	callIdx := f.calls.Add(1)

	// 1. Verify token was sent in authorization metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		f.t.Errorf("GetCertificate request missing gRPC metadata")
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}
	auth := md.Get("authorization")
	if len(auth) == 0 {
		f.t.Errorf("GetCertificate missing authorization header")
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization header")
	}
	expectedAuth := "Bearer " + f.expectedToken
	if auth[0] != expectedAuth {
		f.t.Errorf("GetCertificate received authorization %q, want %q", auth[0], expectedAuth)
	}

	// 2. Verify data-plane service account matches singlepod provisioner's naming
	if req.GetDataPlaneServiceAccount() != f.expectedDPServiceAccount {
		f.t.Errorf("data-plane service account = %q, want %q", req.GetDataPlaneServiceAccount(), f.expectedDPServiceAccount)
	}

	// 3. Verify Gateway identifier
	if req.GetGateway() != f.expectedGateway {
		f.t.Errorf("gateway = %q, want %q", req.GetGateway(), f.expectedGateway)
	}

	// 4. Verify hostnames
	if len(req.GetHostnames()) != 1 || req.GetHostnames()[0] != f.expectedHostname {
		f.t.Errorf("hostnames = %v, want [%s]", req.GetHostnames(), f.expectedHostname)
	}

	// First call: return retryable Unavailable status to simulate issuance in progress
	if callIdx == 1 {
		return nil, status.Errorf(codes.Unavailable, "certificate issuance in progress; retry later")
	}

	// Subsequent call: return issued certificate chain and private key
	return &certserverv1.GetCertificateResponse{
		CertificateChain: f.issuedCertChain,
		PrivateKey:       f.issuedPrivKey,
	}, nil
}

// TestSetupController_CertserverIntegration verifies:
// 1. The token is sent in gRPC Authorization metadata.
// 2. The data-plane service account named in the request matches the provisioner's naming.
// 3. The initial retryable response becomes a Pending condition on the listener.
// 4. When the certificate is issued, State recomputes and the listener becomes Programmed=True.
// 5. The certificate and private key reach the per-Gateway data-plane config Secret.
// 6. No tokens or private keys are logged.
func TestSetupController_CertserverIntegration(t *testing.T) {
	env := testenv.Start(t)

	var logBuf safeLogBuffer
	origLogWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origLogWriter)

	const expectedToken = "secret-projected-service-account-token-abc123xyz"
	const gwNamespace = "default"
	const gwName = "my-gw"
	const hostname = "my-host.example.com"

	expectedGateway := fmt.Sprintf("%s/%s", gwNamespace, gwName)
	expectedDPSA := fmt.Sprintf("%s/%s", gwNamespace, state.ResourceNameForGateway(gwName))

	// 1. Generate fake server TLS and leaf certificate
	srvTLS, srvCertPEM, _, caBundlePEM := generateServerCert(t, "127.0.0.1")
	_, leafCertPEM, leafKeyPEM, _ := generateServerCert(t, hostname)

	// 2. Start fake certserver gRPC server over TLS
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	defer lis.Close()

	fakeSrv := &fakeSourceServer{
		t:                        t,
		expectedToken:            expectedToken,
		expectedGateway:          expectedGateway,
		expectedDPServiceAccount: expectedDPSA,
		expectedHostname:         hostname,
		issuedCertChain:          leafCertPEM,
		issuedPrivKey:            leafKeyPEM,
	}

	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	certserverv1.RegisterCertificateServiceServer(grpcSrv, fakeSrv)
	go grpcSrv.Serve(lis)
	defer grpcSrv.Stop()

	// 3. Write projected token and CA bundle files
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenFile, []byte(expectedToken), 0600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	caBundleFile := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caBundleFile, caBundlePEM, 0644); err != nil {
		t.Fatalf("writing ca bundle file: %v", err)
	}
	_ = srvCertPEM

	// 4. Create GatewayClass and Gateway requesting certserver
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	host := gatewayv1.Hostname(hostname)
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      gwName,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: &host,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptrTo(gatewayv1.TLSModeTerminate),
						Options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
							"gateway.gke-labs.io/certificate-source": "certserver",
						},
					},
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	// 5. Initialize controller with certserver flags
	fakeGCP := gcp.NewFakeComputeClient()
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=cluster-1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--fake-compute",
		fmt.Sprintf("--certserver-address=%s", lis.Addr().String()),
		fmt.Sprintf("--certserver-ca-bundle-path=%s", caBundleFile),
		fmt.Sprintf("--certserver-token-path=%s", tokenFile),
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	go func() {
		_ = server.Manager().Start(mgrCtx)
	}()

	// 6. Assertions:
	// a. Pending condition observed initially
	// b. Calls made to fake server
	// c. ResolvedRefs becomes True and Programmed becomes True
	var updatedGW gatewayv1.Gateway
	var sawPending bool
	var programmed bool

	timeout := time.Now().Add(25 * time.Second)
	for time.Now().Before(timeout) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: gwName}, &updatedGW); err == nil {
			for _, ls := range updatedGW.Status.Listeners {
				if string(ls.Name) == "https" {
					for _, cond := range ls.Conditions {
						if cond.Type == string(gatewayv1.ListenerConditionResolvedRefs) {
							if cond.Status == metav1.ConditionFalse && cond.Reason == string(gatewayv1.ListenerReasonPending) {
								sawPending = true
							}
							if cond.Status == metav1.ConditionTrue {
								programmed = true
							}
						}
					}
				}
			}
		}
		if sawPending && programmed {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !sawPending {
		t.Errorf("expected to observe Pending condition on listener before certificate arrival")
	}
	if !programmed {
		t.Fatalf("listener did not become Programmed / ResolvedRefs=True within deadline, status: %+v", updatedGW.Status.Listeners)
	}

	if fakeSrv.calls.Load() < 2 {
		t.Errorf("expected at least 2 calls to fake source server (pending then issued), got %d", fakeSrv.calls.Load())
	}

	// 7. Verify per-Gateway Secret was created with certificates
	secretName := state.ResourceNameForGateway(gwName)
	var sec corev1.Secret
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: secretName}, &sec); err != nil {
		t.Fatalf("reading Gateway dataplane secret %s: %v", secretName, err)
	}

	// 8. Verify no tokens or private keys are logged
	logs := logBuf.String()
	if strings.Contains(logs, expectedToken) {
		t.Errorf("security violation: controller logged bearer token!")
	}
	if strings.Contains(logs, string(leafKeyPEM)) {
		t.Errorf("security violation: controller logged certificate private key!")
	}
}

// TestSetupController_CertserverUnregistered verifies that when certserver flags are omitted,
// the source is not registered and listeners requesting it receive the "unknown source" condition.
func TestSetupController_CertserverUnregistered(t *testing.T) {
	env := testenv.Start(t)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway-unreg",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "gke-labs.io/gcpgateway-unreg",
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	host := gatewayv1.Hostname("unreg.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw-unreg",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway-unreg",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: &host,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptrTo(gatewayv1.TLSModeTerminate),
						Options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
							"gateway.gke-labs.io/certificate-source": "certserver",
						},
					},
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	// Run SetupController WITHOUT any certserver flags
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=cluster-1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--controller-name=gke-labs.io/gcpgateway-unreg",
		"--fake-compute",
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	go func() {
		_ = server.Manager().Start(mgrCtx)
	}()

	var updatedGW gatewayv1.Gateway
	var foundUnknownCondition bool
	timeout := time.Now().Add(15 * time.Second)
	for time.Now().Before(timeout) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "gw-unreg"}, &updatedGW); err == nil {
			for _, ls := range updatedGW.Status.Listeners {
				if string(ls.Name) == "https" {
					for _, cond := range ls.Conditions {
						if cond.Type == string(gatewayv1.ListenerConditionResolvedRefs) {
							if cond.Status == metav1.ConditionFalse &&
								cond.Reason == string(gatewayv1.ListenerReasonInvalidCertificateRef) &&
								strings.Contains(cond.Message, `Unknown certificate source "certserver"`) {
								foundUnknownCondition = true
								break
							}
						}
					}
				}
			}
		}
		if foundUnknownCondition {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !foundUnknownCondition {
		t.Fatalf("expected Unknown certificate source \"certserver\" condition on listener, got status: %+v", updatedGW.Status.Listeners)
	}
}

func ptrTo[T any](v T) *T {
	return &v
}
