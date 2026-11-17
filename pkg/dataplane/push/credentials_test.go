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

package push_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestEnsurePushCredentials_LifecycleAndHandshake(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-push-creds"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	// 1. Initial run: creates all three objects
	if err := push.EnsurePushCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsurePushCredentials run 1 failed: %v", err)
	}

	var caSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCASecretName}, &caSecret); err != nil {
		t.Fatalf("failed to get CA secret: %v", err)
	}
	if len(caSecret.Data[push.PushCAKeyDataKey]) == 0 {
		t.Fatalf("CA secret missing %q", push.PushCAKeyDataKey)
	}
	if len(caSecret.Data[push.PushCACertDataKey]) == 0 {
		t.Fatalf("CA secret missing %q", push.PushCACertDataKey)
	}

	// Verify CA certificate has MaxPathLenZero == true
	caCertBlock, _ := pem.Decode(caSecret.Data[push.PushCACertDataKey])
	caParsedCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	if !caParsedCert.IsCA {
		t.Errorf("expected IsCA=true on CA certificate")
	}
	if !caParsedCert.MaxPathLenZero {
		t.Errorf("expected MaxPathLenZero=true on CA certificate to restrict signing to leaf certificates")
	}

	var caConfigMap corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCACertConfigMapName}, &caConfigMap); err != nil {
		t.Fatalf("failed to get CA configmap: %v", err)
	}
	caCertPEM := caConfigMap.Data[push.PushCACertDataKey]
	if caCertPEM == "" {
		t.Fatalf("CA configmap missing %q", push.PushCACertDataKey)
	}

	var serverSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushServerSecretName}, &serverSecret); err != nil {
		t.Fatalf("failed to get server secret: %v", err)
	}
	if serverSecret.Type != corev1.SecretTypeTLS {
		t.Fatalf("expected server secret type %q, got %q", corev1.SecretTypeTLS, serverSecret.Type)
	}
	serverCertPEM := serverSecret.Data[push.PushServerCertDataKey]
	serverKeyPEM := serverSecret.Data[push.PushServerKeyDataKey]
	if len(serverCertPEM) == 0 || len(serverKeyPEM) == 0 {
		t.Fatalf("server secret missing tls.crt or tls.key")
	}

	// 2. Acceptance criterion 1: Complete TLS handshake
	// Server uses serving Secret, client trusts ONLY ConfigMap certificate, server name is push Service DNS name.
	serverPair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Logf("listener close error: %v", closeErr)
		}
	}()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("server conn close error: %v", closeErr)
			}
		}()
		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			acceptErr = tlsConn.Handshake()
		}
		serverDone <- acceptErr
	}()

	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM([]byte(caCertPEM)) {
		t.Fatalf("failed to append CA cert from ConfigMap")
	}

	dnsNames, err := push.PushServiceDNSNames(push.PushServiceName, testNamespace)
	if err != nil {
		t.Fatalf("PushServiceDNSNames failed: %v", err)
	}
	clientTLSConfig := &tls.Config{
		RootCAs:    clientPool,
		ServerName: dnsNames[0],
		MinVersion: tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	clientConn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("client TLS handshake failed: %v", err)
	}
	if closeErr := clientConn.Close(); closeErr != nil {
		t.Fatalf("closing client connection: %v", closeErr)
	}
	if srvErr := <-serverDone; srvErr != nil {
		t.Fatalf("server handshake failed: %v", srvErr)
	}

	// Negative acceptance criterion: Client that trusts another authority fails
	untrustedPool := x509.NewCertPool()
	otherCAPEM := generateOtherCACert(t)
	if !untrustedPool.AppendCertsFromPEM(otherCAPEM) {
		t.Fatalf("failed to append other CA cert")
	}
	untrustedTLSConfig := &tls.Config{
		RootCAs:    untrustedPool,
		ServerName: dnsNames[0],
		MinVersion: tls.VersionTLS12,
	}
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("closing conn from untrusted accept: %v", closeErr)
			}
		}
	}()
	untrustedConn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), untrustedTLSConfig)
	if err == nil {
		_ = untrustedConn.Close()
		t.Fatalf("expected client with untrusted CA to fail, but succeeded")
	}

	// 3. Acceptance criterion 2: A second run changes none of the three objects
	caSecretRV := caSecret.ResourceVersion
	caConfigMapRV := caConfigMap.ResourceVersion
	serverSecretRV := serverSecret.ResourceVersion

	if err := push.EnsurePushCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsurePushCredentials run 2 failed: %v", err)
	}

	var caSecret2 corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCASecretName}, &caSecret2); err != nil {
		t.Fatalf("failed to get CA secret: %v", err)
	}
	var caConfigMap2 corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCACertConfigMapName}, &caConfigMap2); err != nil {
		t.Fatalf("failed to get CA configmap: %v", err)
	}
	var serverSecret2 corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushServerSecretName}, &serverSecret2); err != nil {
		t.Fatalf("failed to get server secret: %v", err)
	}

	if caSecret2.ResourceVersion != caSecretRV {
		t.Errorf("second run changed CA secret ResourceVersion: was %s, now %s", caSecretRV, caSecret2.ResourceVersion)
	}
	if caConfigMap2.ResourceVersion != caConfigMapRV {
		t.Errorf("second run changed CA configmap ResourceVersion: was %s, now %s", caConfigMapRV, caConfigMap2.ResourceVersion)
	}
	if serverSecret2.ResourceVersion != serverSecretRV {
		t.Errorf("second run changed server secret ResourceVersion: was %s, now %s", serverSecretRV, serverSecret2.ResourceVersion)
	}

	// 4. Acceptance criterion 2 (part 2): A run with the serving Secret deleted creates a new serving certificate
	// that the same client accepts.
	if err := env.Client.Delete(ctx, &serverSecret2); err != nil {
		t.Fatalf("failed to delete server secret: %v", err)
	}

	if err := push.EnsurePushCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsurePushCredentials run after server secret deletion failed: %v", err)
	}

	var caSecret3 corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCASecretName}, &caSecret3); err != nil {
		t.Fatalf("failed to get CA secret: %v", err)
	}
	var caConfigMap3 corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCACertConfigMapName}, &caConfigMap3); err != nil {
		t.Fatalf("failed to get CA configmap: %v", err)
	}
	var serverSecret3 corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushServerSecretName}, &serverSecret3); err != nil {
		t.Fatalf("failed to get re-created server secret: %v", err)
	}

	if caSecret3.ResourceVersion != caSecretRV {
		t.Errorf("CA secret was modified during server secret recreation: was %s, now %s", caSecretRV, caSecret3.ResourceVersion)
	}
	if caConfigMap3.ResourceVersion != caConfigMapRV {
		t.Errorf("CA configmap was modified during server secret recreation: was %s, now %s", caConfigMapRV, caConfigMap3.ResourceVersion)
	}

	// Verify the original client still accepts the new serving certificate
	newServerPair, err := tls.X509KeyPair(serverSecret3.Data[push.PushServerCertDataKey], serverSecret3.Data[push.PushServerKeyDataKey])
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed for re-created cert: %v", err)
	}
	newServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{newServerPair},
		MinVersion:   tls.VersionTLS12,
	}
	listener3, err := tls.Listen("tcp", "127.0.0.1:0", newServerTLSConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer func() {
		if closeErr := listener3.Close(); closeErr != nil {
			t.Logf("listener3 close error: %v", closeErr)
		}
	}()

	serverDone3 := make(chan error, 1)
	go func() {
		conn, acceptErr := listener3.Accept()
		if acceptErr != nil {
			serverDone3 <- acceptErr
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("server 3 conn close error: %v", closeErr)
			}
		}()
		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			acceptErr = tlsConn.Handshake()
		}
		serverDone3 <- acceptErr
	}()

	// The original client configuration (trusting caCertPEM from the ConfigMap) connects to new server
	clientConn3, err := tls.DialWithDialer(dialer, "tcp", listener3.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("original client failed to handshake with newly issued server cert: %v", err)
	}
	if closeErr := clientConn3.Close(); closeErr != nil {
		t.Fatalf("closing client connection 3: %v", closeErr)
	}
	if srvErr := <-serverDone3; srvErr != nil {
		t.Fatalf("server 3 handshake failed: %v", srvErr)
	}

	// 5. Near-expiry test: if serving cert is near expiry, EnsurePushCredentials issues a new one
	// using the existing authority.
	expiringPairPEM, err := generateExpiringServerCert(t, caSecret3.Data[push.PushCACertDataKey], caSecret3.Data[push.PushCAKeyDataKey], dnsNames)
	if err != nil {
		t.Fatalf("generateExpiringServerCert: %v", err)
	}
	serverSecret3.Data[push.PushServerCertDataKey] = expiringPairPEM.CertPEM
	serverSecret3.Data[push.PushServerKeyDataKey] = expiringPairPEM.KeyPEM
	if err := env.Client.Update(ctx, &serverSecret3); err != nil {
		t.Fatalf("failed to update server secret with expiring cert: %v", err)
	}

	expiringRV := serverSecret3.ResourceVersion
	if err := push.EnsurePushCredentials(ctx, env.Client, testNamespace); err != nil {
		t.Fatalf("EnsurePushCredentials renewal failed: %v", err)
	}

	var renewedServerSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushServerSecretName}, &renewedServerSecret); err != nil {
		t.Fatalf("failed to get renewed server secret: %v", err)
	}
	if renewedServerSecret.ResourceVersion == expiringRV {
		t.Errorf("expected server secret to be renewed, but ResourceVersion remained %s", expiringRV)
	}

	// CA objects must still be unchanged
	var caSecret4 corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: push.PushCASecretName}, &caSecret4); err != nil {
		t.Fatalf("failed to get CA secret: %v", err)
	}
	if caSecret4.ResourceVersion != caSecretRV {
		t.Errorf("CA secret was modified during renewal: was %s, now %s", caSecretRV, caSecret4.ResourceVersion)
	}

	// Client still trusts the renewed cert
	renewedPair, err := tls.X509KeyPair(renewedServerSecret.Data[push.PushServerCertDataKey], renewedServerSecret.Data[push.PushServerKeyDataKey])
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed for renewed cert: %v", err)
	}
	renewedTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{renewedPair},
		MinVersion:   tls.VersionTLS12,
	}
	listener4, err := tls.Listen("tcp", "127.0.0.1:0", renewedTLSConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer func() {
		if closeErr := listener4.Close(); closeErr != nil {
			t.Logf("listener4 close error: %v", closeErr)
		}
	}()

	serverDone4 := make(chan error, 1)
	go func() {
		conn, acceptErr := listener4.Accept()
		if acceptErr != nil {
			serverDone4 <- acceptErr
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("server 4 conn close error: %v", closeErr)
			}
		}()
		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			acceptErr = tlsConn.Handshake()
		}
		serverDone4 <- acceptErr
	}()

	clientConn4, err := tls.DialWithDialer(dialer, "tcp", listener4.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("client failed to handshake with renewed server cert: %v", err)
	}
	if closeErr := clientConn4.Close(); closeErr != nil {
		t.Fatalf("closing client connection 4: %v", closeErr)
	}
	if srvErr := <-serverDone4; srvErr != nil {
		t.Fatalf("server 4 handshake failed: %v", srvErr)
	}
}

func TestEnsurePushCredentials_NamespaceValidation(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	if err := push.EnsurePushCredentials(ctx, env.Client, ""); err == nil {
		t.Errorf("expected error when namespace is empty, got nil")
	}

	if _, err := push.PushServiceDNSNames(push.PushServiceName, ""); err == nil {
		t.Errorf("expected error when namespace is empty for PushServiceDNSNames, got nil")
	}
}

func TestEnsurePushCredentials_InvalidCAErrors(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-invalid-ca"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	// Case 1: CA Secret exists but private key is corrupted
	corruptSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      push.PushCASecretName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			push.PushCAKeyDataKey:  []byte("not-a-valid-pem-key"),
			push.PushCACertDataKey: []byte("not-a-valid-pem-cert"),
		},
	}
	if err := env.Client.Create(ctx, corruptSecret); err != nil {
		t.Fatalf("failed to create corrupt CA secret: %v", err)
	}

	err := push.EnsurePushCredentials(ctx, env.Client, testNamespace)
	if err == nil {
		t.Fatalf("expected error when CA secret has invalid key, got nil")
	}
	if !strings.Contains(err.Error(), push.PushCASecretName) {
		t.Errorf("expected error to name CA secret %q, got: %v", push.PushCASecretName, err)
	}

	// Case 2: CA Secret exists but key and certificate do not match
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key1Bytes, _ := x509.MarshalECPrivateKey(key1)
	key1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key1Bytes})

	otherCertPEM := generateOtherCACert(t)
	corruptSecret.Data[push.PushCAKeyDataKey] = key1PEM
	corruptSecret.Data[push.PushCACertDataKey] = otherCertPEM
	if err := env.Client.Update(ctx, corruptSecret); err != nil {
		t.Fatalf("failed to update corrupt CA secret: %v", err)
	}

	err = push.EnsurePushCredentials(ctx, env.Client, testNamespace)
	if err == nil {
		t.Fatalf("expected error when CA key does not match cert, got nil")
	}
	if !strings.Contains(err.Error(), push.PushCASecretName) || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("expected error naming secret and mismatch reason, got: %v", err)
	}

	// Case 3: CA Secret exists but certificate has expired
	expiredCertPEM := generateExpiredCACert(t, key1)
	corruptSecret.Data[push.PushCAKeyDataKey] = key1PEM
	corruptSecret.Data[push.PushCACertDataKey] = expiredCertPEM
	if err := env.Client.Update(ctx, corruptSecret); err != nil {
		t.Fatalf("failed to update corrupt CA secret with expired cert: %v", err)
	}

	err = push.EnsurePushCredentials(ctx, env.Client, testNamespace)
	if err == nil {
		t.Fatalf("expected error when CA cert is expired, got nil")
	}
	if !strings.Contains(err.Error(), push.PushCASecretName) || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected error naming secret and expiration reason, got: %v", err)
	}
}

type certPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

func generateExpiringServerCert(t *testing.T, caCertPEM, caKeyPEM []byte, dnsNames []string) (*certPair, error) {
	t.Helper()
	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// NotAfter is in 5 minutes, well within ServerCertNearExpiryMargin (30 days)
	now := time.Now().Add(-1 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99999),
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		DNSNames:              dnsNames,
		NotBefore:             now,
		NotAfter:              now.Add(1*time.Hour + 5*time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &certPair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func generateOtherCACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "other-untrusted-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func generateExpiredCACert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(54321),
		Subject: pkix.Name{
			CommonName: "expired-ca",
		},
		NotBefore:             time.Now().Add(-20 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create expired cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
