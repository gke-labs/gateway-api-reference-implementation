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

package spiffe_test

import (
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
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestEnsureCredentials_LifecycleAndHandshake(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-spiffe-creds"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	// 1. Initial run: creates all three objects.
	if err := spiffe.EnsureCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsureCredentials initial run failed: %v", err)
	}

	var authoritySecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("failed to get authority secret: %v", err)
	}
	if len(authoritySecret.Data[spiffe.AuthorityKeyDataKey]) == 0 {
		t.Fatalf("authority secret missing %q", spiffe.AuthorityKeyDataKey)
	}
	if len(authoritySecret.Data[spiffe.AuthorityCertDataKey]) == 0 {
		t.Fatalf("authority secret missing %q", spiffe.AuthorityCertDataKey)
	}

	var bundleConfigMap corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.BundleConfigMapName}, &bundleConfigMap); err != nil {
		t.Fatalf("failed to get bundle configmap: %v", err)
	}
	bundlePEM := bundleConfigMap.Data[spiffe.BundleDataKey]
	if bundlePEM == "" {
		t.Fatalf("bundle configmap missing %q", spiffe.BundleDataKey)
	}

	// Verify authority certificate contents
	authorityCertPEM := authoritySecret.Data[spiffe.AuthorityCertDataKey]
	caBlock, _ := pem.Decode(authorityCertPEM)
	if caBlock == nil {
		t.Fatalf("failed to decode authority cert PEM")
	}
	authorityX509, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse authority certificate: %v", err)
	}
	expectedTrustDomainURI := fmt.Sprintf("spiffe://%s", spiffe.TrustDomain)
	if len(authorityX509.URIs) != 1 {
		t.Fatalf("expected exactly 1 URI SAN in authority certificate, got %d: %v", len(authorityX509.URIs), authorityX509.URIs)
	}
	if authorityX509.URIs[0].String() != expectedTrustDomainURI {
		t.Errorf("expected authority URI %q, got %q", expectedTrustDomainURI, authorityX509.URIs[0].String())
	}
	if strings.HasPrefix(authorityX509.Subject.CommonName, "spiffe://") {
		t.Errorf("authority subject common name must be a plain name, got %q", authorityX509.Subject.CommonName)
	}
	if authorityX509.Subject.CommonName != spiffe.AuthoritySecretName {
		t.Errorf("expected authority subject common name %q, got %q", spiffe.AuthoritySecretName, authorityX509.Subject.CommonName)
	}
	if !authorityX509.IsCA {
		t.Errorf("authority certificate must be a CA")
	}

	var svidSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &svidSecret); err != nil {
		t.Fatalf("failed to get controller SVID secret: %v", err)
	}
	svidCertPEM := svidSecret.Data[spiffe.SVIDCertDataKey]
	svidKeyPEM := svidSecret.Data[spiffe.SVIDKeyDataKey]
	if len(svidCertPEM) == 0 || len(svidKeyPEM) == 0 {
		t.Fatalf("SVID secret missing %q or %q", spiffe.SVIDCertDataKey, spiffe.SVIDKeyDataKey)
	}

	// Verify X.509-SVID certificate contents
	block, _ := pem.Decode(svidCertPEM)
	if block == nil {
		t.Fatalf("failed to decode SVID cert PEM")
	}
	svidX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse SVID certificate: %v", err)
	}

	// Must have expected SPIFFE ID as its only URI name
	expectedSPIFFEID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", spiffe.TrustDomain, testNamespace, spiffe.ControllerServiceAccountName)
	if len(svidX509.URIs) != 1 {
		t.Fatalf("expected exactly 1 URI SAN in SVID, got %d: %v", len(svidX509.URIs), svidX509.URIs)
	}
	if svidX509.URIs[0].String() != expectedSPIFFEID {
		t.Errorf("expected SVID URI %q, got %q", expectedSPIFFEID, svidX509.URIs[0].String())
	}

	// Must have Service DNS names
	expectedDNSNames, err := spiffe.ServiceDNSNames(spiffe.ControllerServiceName, testNamespace)
	if err != nil {
		t.Fatalf("failed to get service DNS names: %v", err)
	}
	for _, expectedName := range expectedDNSNames {
		if !slices.Contains(svidX509.DNSNames, expectedName) {
			t.Errorf("SVID DNS names missing %q, got %v", expectedName, svidX509.DNSNames)
		}
	}

	// Must be leaf: not a CA, digitalSignature, server and client auth
	if svidX509.IsCA {
		t.Errorf("SVID certificate must not be a CA")
	}
	if svidX509.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("SVID certificate must have digitalSignature key usage")
	}
	if !slices.Contains(svidX509.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !slices.Contains(svidX509.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Errorf("SVID certificate missing ServerAuth or ClientAuth ext key usage: %v", svidX509.ExtKeyUsage)
	}

	// 2. TLS Handshake: server uses controller's SVID, client trusts only the bundle.
	serverCert, err := tls.X509KeyPair(svidCertPEM, svidKeyPEM)
	if err != nil {
		t.Fatalf("failed to load keypair: %v", err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM([]byte(bundlePEM)) {
		t.Fatalf("failed to append bundle cert to root pool")
	}

	testServerName := fmt.Sprintf("%s.%s.svc.cluster.local", spiffe.ControllerServiceName, testNamespace)
	runTLSHandshakeTest(t, serverCert, rootCAs, testServerName, true)

	// A client that trusts another authority fails.
	untrustedRootPool := generateUntrustedCAPool(t)
	runTLSHandshakeTest(t, serverCert, untrustedRootPool, testServerName, false)

	// 3. Second run changes none of the three objects.
	initialAuthorityRV := authoritySecret.ResourceVersion
	initialBundleRV := bundleConfigMap.ResourceVersion
	initialSVIDRV := svidSecret.ResourceVersion

	if err := spiffe.EnsureCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsureCredentials second run failed: %v", err)
	}

	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("failed to re-get authority secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.BundleConfigMapName}, &bundleConfigMap); err != nil {
		t.Fatalf("failed to re-get bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &svidSecret); err != nil {
		t.Fatalf("failed to re-get SVID secret: %v", err)
	}

	if authoritySecret.ResourceVersion != initialAuthorityRV {
		t.Errorf("authority secret modified on second run; ResourceVersion changed from %s to %s", initialAuthorityRV, authoritySecret.ResourceVersion)
	}
	if bundleConfigMap.ResourceVersion != initialBundleRV {
		t.Errorf("bundle configmap modified on second run; ResourceVersion changed from %s to %s", initialBundleRV, bundleConfigMap.ResourceVersion)
	}
	if svidSecret.ResourceVersion != initialSVIDRV {
		t.Errorf("SVID secret modified on second run; ResourceVersion changed from %s to %s", initialSVIDRV, svidSecret.ResourceVersion)
	}

	// 4. Run with SVID Secret deleted creates a new SVID that the same client accepts.
	if err := env.Client.Delete(ctx, &svidSecret); err != nil {
		t.Fatalf("failed to delete SVID secret: %v", err)
	}

	if err := spiffe.EnsureCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsureCredentials re-issue run failed: %v", err)
	}

	var newSVIDSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &newSVIDSecret); err != nil {
		t.Fatalf("failed to get re-issued SVID secret: %v", err)
	}
	newSVIDCertPEM := newSVIDSecret.Data[spiffe.SVIDCertDataKey]
	newSVIDKeyPEM := newSVIDSecret.Data[spiffe.SVIDKeyDataKey]
	if string(newSVIDCertPEM) == string(svidCertPEM) {
		t.Errorf("expected newly generated SVID cert PEM to differ from deleted cert PEM")
	}

	newServerCert, err := tls.X509KeyPair(newSVIDCertPEM, newSVIDKeyPEM)
	if err != nil {
		t.Fatalf("failed to load new SVID keypair: %v", err)
	}

	// The same client trusting only the original bundle accepts the new serving certificate
	runTLSHandshakeTest(t, newServerCert, rootCAs, testServerName, true)
}

func TestEnsureCredentials_UnreadableAuthoritySecret(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-unreadable-authority"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	failingClient := &failingGetClient{
		Client:      env.Client,
		failName:    spiffe.AuthoritySecretName,
		injectedErr: errors.New("simulated permission denied reading authority secret"),
	}

	err := spiffe.EnsureCredentials(ctx, failingClient, testNamespace)
	if err == nil {
		t.Fatal("expected error reading authority secret, got nil")
	}
	if !strings.Contains(err.Error(), spiffe.AuthoritySecretName) {
		t.Fatalf("expected error to name %q, got: %v", spiffe.AuthoritySecretName, err)
	}
}

func TestEnsureCredentials_InvalidAuthoritySecret(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-invalid-authority"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	corruptSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spiffe.AuthoritySecretName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			spiffe.AuthorityKeyDataKey:  []byte("not-a-valid-pem-key"),
			spiffe.AuthorityCertDataKey: []byte("not-a-valid-cert"),
		},
	}
	if err := env.Client.Create(ctx, corruptSecret); err != nil {
		t.Fatalf("failed to create corrupted authority secret: %v", err)
	}

	err := spiffe.EnsureCredentials(ctx, env.Client, testNamespace)
	if err == nil {
		t.Fatal("expected error on invalid authority secret, got nil")
	}
	if !strings.Contains(err.Error(), spiffe.AuthoritySecretName) {
		t.Fatalf("expected error to name %q, got: %v", spiffe.AuthoritySecretName, err)
	}
}

func TestEnsureCredentials_AuthoritySecretAlreadyExists(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-authority-already-exists"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	raceClient := &raceOnCreateClient{
		Client: env.Client,
	}

	err := spiffe.EnsureCredentials(ctx, raceClient, testNamespace)
	if err == nil {
		t.Fatal("expected error from EnsureCredentials when authority secret already exists, got nil")
	}
	if !strings.Contains(err.Error(), spiffe.AuthoritySecretName) {
		t.Fatalf("expected error to name %q, got: %v", spiffe.AuthoritySecretName, err)
	}

	// Verify no bundle ConfigMap was created
	var configMap corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.BundleConfigMapName}, &configMap); !apierrors.IsNotFound(err) {
		t.Fatalf("expected ConfigMap %q not to exist, but got err: %v", spiffe.BundleConfigMapName, err)
	}

	// Verify no SVID Secret was created
	var serverSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &serverSecret); !apierrors.IsNotFound(err) {
		t.Fatalf("expected server Secret %q not to exist, but got err: %v", spiffe.ControllerSVIDSecretName, err)
	}
}

func TestServiceDNSNames(t *testing.T) {
	names, err := spiffe.ServiceDNSNames("my-service", "my-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"my-service",
		"my-service.my-ns",
		"my-service.my-ns.svc",
		"my-service.my-ns.svc.cluster.local",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}

	if _, err := spiffe.ServiceDNSNames("", "my-ns"); err == nil {
		t.Fatal("expected error for empty serviceName")
	}
	if _, err := spiffe.ServiceDNSNames("my-service", ""); err == nil {
		t.Fatal("expected error for empty namespace")
	}
}

func TestSPIFFEID(t *testing.T) {
	uri, err := spiffe.SPIFFEID(spiffe.TrustDomain, "ns1", "sa1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri.String() != "spiffe://cluster.local/ns/ns1/sa/sa1" {
		t.Fatalf("got %q, want %q", uri.String(), "spiffe://cluster.local/ns/ns1/sa/sa1")
	}

	if _, err := spiffe.SPIFFEID("", "ns1", "sa1"); err == nil {
		t.Fatal("expected error for empty trustDomain")
	}
	if _, err := spiffe.SPIFFEID(spiffe.TrustDomain, "", "sa1"); err == nil {
		t.Fatal("expected error for empty namespace")
	}
	if _, err := spiffe.SPIFFEID(spiffe.TrustDomain, "ns1", ""); err == nil {
		t.Fatal("expected error for empty serviceAccount")
	}
}

type failingGetClient struct {
	client.Client
	failName    string
	injectedErr error
}

func (c *failingGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key.Name == c.failName {
		return c.injectedErr
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

type raceOnCreateClient struct {
	client.Client
	raceCreated bool
}

func (c *raceOnCreateClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if sec, ok := obj.(*corev1.Secret); ok && sec.Name == spiffe.AuthoritySecretName && !c.raceCreated {
		c.raceCreated = true
		rivalSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      spiffe.AuthoritySecretName,
				Namespace: sec.Namespace,
			},
			Data: map[string][]byte{
				spiffe.AuthorityKeyDataKey:  []byte("rival-ca-key"),
				spiffe.AuthorityCertDataKey: []byte("rival-ca-cert"),
			},
		}
		if err := c.Client.Create(ctx, rivalSecret); err != nil {
			return err
		}
	}
	return c.Client.Create(ctx, obj, opts...)
}

func runTLSHandshakeTest(t *testing.T, serverCert tls.Certificate, rootCAs *x509.CertPool, serverName string, expectSuccess bool) {
	t.Helper()

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		serverDone <- tlsConn.Handshake()
	}()

	clientTLSConfig := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: serverName,
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	clientConn, dialErr := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), clientTLSConfig)

	var handshakeErr error
	if dialErr != nil {
		handshakeErr = dialErr
	} else {
		defer clientConn.Close()
		handshakeErr = clientConn.Handshake()
	}

	<-serverDone

	if expectSuccess && handshakeErr != nil {
		t.Fatalf("expected successful TLS handshake with %q, got: %v", serverName, handshakeErr)
	}
	if !expectSuccess && handshakeErr == nil {
		t.Fatalf("expected TLS handshake to fail, but succeeded with serverName %q", serverName)
	}
}

func generateUntrustedCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "untrusted-ca",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating untrusted cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing untrusted cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
