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
	"flag"
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

func controllerOptions(namespace string) spiffe.Options {
	return spiffe.Options{
		AuthorityNamespace: namespace,
		Identities: []spiffe.Identity{{
			Namespace:      namespace,
			ServiceAccount: spiffe.ControllerServiceAccountName,
		}},
	}
}

func TestEnsureCredentials_LifecycleAndHandshake(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-spiffe-creds"
	namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	// 1. Initial run: creates all three objects.
	if err := spiffe.EnsureCredentials(ctx, env.Client, controllerOptions(testNamespace)); err != nil {
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

	if err := spiffe.EnsureCredentials(ctx, env.Client, controllerOptions(testNamespace)); err != nil {
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

	if err := spiffe.EnsureCredentials(ctx, env.Client, controllerOptions(testNamespace)); err != nil {
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

func TestEnsureCredentials_MultiNamespaceAndMTLS(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const (
		issuerNamespace = "spiffe-issuer"
		alphaNamespace  = "workload-alpha"
		betaNamespace   = "workload-beta"
	)
	for _, namespace := range []string{issuerNamespace, alphaNamespace, betaNamespace} {
		namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create namespace %s: %v", namespace, err)
		}
	}

	options := spiffe.Options{
		AuthorityNamespace: issuerNamespace,
		Identities: []spiffe.Identity{
			{
				Namespace:      alphaNamespace,
				ServiceAccount: "frontend",
			},
			{
				Namespace:      alphaNamespace,
				ServiceAccount: "worker",
				SecretName:     "worker-tls",
			},
			{
				Namespace:           betaNamespace,
				ServiceAccount:      "backend",
				SecretName:          "backend-tls",
				BundleConfigMapName: "custom-trust-bundle",
				ServiceName:         "backend-api",
			},
		},
	}

	if err := spiffe.EnsureCredentials(ctx, env.Client, options); err != nil {
		t.Fatalf("EnsureCredentials multi-namespace run failed: %v", err)
	}

	// Authority Secret exists only in issuerNamespace.
	var authoritySecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("failed to get authority secret in %s: %v", issuerNamespace, err)
	}
	for _, workloadNamespace := range []string{alphaNamespace, betaNamespace} {
		var unexpectedAuthority corev1.Secret
		if err := env.Client.Get(ctx, client.ObjectKey{Namespace: workloadNamespace, Name: spiffe.AuthoritySecretName}, &unexpectedAuthority); !apierrors.IsNotFound(err) {
			t.Fatalf("expected no authority secret in workload namespace %s, got err: %v", workloadNamespace, err)
		}
	}

	// Each workload namespace receives its trust bundle ConfigMap.
	var alphaBundle, betaBundle corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundle); err != nil {
		t.Fatalf("failed to get alpha bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "custom-trust-bundle"}, &betaBundle); err != nil {
		t.Fatalf("failed to get beta bundle configmap: %v", err)
	}
	if alphaBundle.Data[spiffe.BundleDataKey] != betaBundle.Data[spiffe.BundleDataKey] {
		t.Fatalf("expected identical trust bundle PEM across workload namespaces")
	}

	var frontendSecret, workerSecret, backendSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "frontend-svid"}, &frontendSecret); err != nil {
		t.Fatalf("failed to get frontend SVID secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "worker-tls"}, &workerSecret); err != nil {
		t.Fatalf("failed to get worker SVID secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "backend-tls"}, &backendSecret); err != nil {
		t.Fatalf("failed to get backend SVID secret: %v", err)
	}

	// Verify mTLS between alpha/frontend (client) and beta/backend (server).
	frontendPair, err := tls.X509KeyPair(frontendSecret.Data[spiffe.SVIDCertDataKey], frontendSecret.Data[spiffe.SVIDKeyDataKey])
	if err != nil {
		t.Fatalf("failed to load frontend keypair: %v", err)
	}
	backendPair, err := tls.X509KeyPair(backendSecret.Data[spiffe.SVIDCertDataKey], backendSecret.Data[spiffe.SVIDKeyDataKey])
	if err != nil {
		t.Fatalf("failed to load backend keypair: %v", err)
	}
	alphaRoots := x509.NewCertPool()
	if !alphaRoots.AppendCertsFromPEM([]byte(alphaBundle.Data[spiffe.BundleDataKey])) {
		t.Fatalf("failed to parse alpha bundle")
	}
	betaRoots := x509.NewCertPool()
	if !betaRoots.AppendCertsFromPEM([]byte(betaBundle.Data[spiffe.BundleDataKey])) {
		t.Fatalf("failed to parse beta bundle")
	}

	serverPeerSPIFFE, clientPeerSPIFFE := runMTLSHandshakeTest(
		t,
		backendPair,
		betaRoots,
		frontendPair,
		alphaRoots,
		"backend-api."+betaNamespace+".svc.cluster.local",
	)
	wantClientSPIFFE := fmt.Sprintf("spiffe://%s/ns/%s/sa/frontend", spiffe.TrustDomain, alphaNamespace)
	wantServerSPIFFE := fmt.Sprintf("spiffe://%s/ns/%s/sa/backend", spiffe.TrustDomain, betaNamespace)
	if serverPeerSPIFFE != wantClientSPIFFE {
		t.Errorf("server saw client SPIFFE ID %q, want %q", serverPeerSPIFFE, wantClientSPIFFE)
	}
	if clientPeerSPIFFE != wantServerSPIFFE {
		t.Errorf("client saw server SPIFFE ID %q, want %q", clientPeerSPIFFE, wantServerSPIFFE)
	}

	// Re-running is idempotent across all namespaces.
	authorityRV := authoritySecret.ResourceVersion
	alphaBundleRV := alphaBundle.ResourceVersion
	betaBundleRV := betaBundle.ResourceVersion
	frontendRV := frontendSecret.ResourceVersion
	workerRV := workerSecret.ResourceVersion
	backendRV := backendSecret.ResourceVersion

	if err := spiffe.EnsureCredentials(ctx, env.Client, options); err != nil {
		t.Fatalf("EnsureCredentials idempotent run failed: %v", err)
	}

	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("re-get authority: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundle); err != nil {
		t.Fatalf("re-get alpha bundle: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "custom-trust-bundle"}, &betaBundle); err != nil {
		t.Fatalf("re-get beta bundle: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "frontend-svid"}, &frontendSecret); err != nil {
		t.Fatalf("re-get frontend SVID: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "worker-tls"}, &workerSecret); err != nil {
		t.Fatalf("re-get worker SVID: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "backend-tls"}, &backendSecret); err != nil {
		t.Fatalf("re-get backend SVID: %v", err)
	}

	if authoritySecret.ResourceVersion != authorityRV ||
		alphaBundle.ResourceVersion != alphaBundleRV ||
		betaBundle.ResourceVersion != betaBundleRV ||
		frontendSecret.ResourceVersion != frontendRV ||
		workerSecret.ResourceVersion != workerRV ||
		backendSecret.ResourceVersion != backendRV {
		t.Errorf("expected no ResourceVersion changes on idempotent multi-namespace run")
	}
}

func TestEnsureCredentials_Renewal(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const (
		issuerNamespace = "renew-issuer"
		alphaNamespace  = "renew-alpha"
		betaNamespace   = "renew-beta"
	)
	for _, namespace := range []string{issuerNamespace, alphaNamespace, betaNamespace} {
		namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create namespace %s: %v", namespace, err)
		}
	}

	startTime := time.Now().UTC().Truncate(time.Second)
	alphaIdentity := spiffe.Identity{Namespace: alphaNamespace, ServiceAccount: "alpha"}
	betaIdentity := spiffe.Identity{Namespace: betaNamespace, ServiceAccount: "beta"}

	// Issue alpha at T0.
	if err := spiffe.EnsureCredentials(ctx, env.Client, spiffe.Options{
		AuthorityNamespace: issuerNamespace,
		Now:                func() time.Time { return startTime },
		Identities:         []spiffe.Identity{alphaIdentity},
	}); err != nil {
		t.Fatalf("initial alpha issuance failed: %v", err)
	}

	// Issue beta 180 days later so beta stays well outside the renewal window when alpha nears expiry.
	midTime := startTime.Add(180 * 24 * time.Hour)
	if err := spiffe.EnsureCredentials(ctx, env.Client, spiffe.Options{
		AuthorityNamespace: issuerNamespace,
		Now:                func() time.Time { return midTime },
		Identities:         []spiffe.Identity{alphaIdentity, betaIdentity},
	}); err != nil {
		t.Fatalf("mid-window issuance failed: %v", err)
	}

	var authoritySecret, alphaBefore, betaBefore corev1.Secret
	var alphaBundle corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("get authority: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundle); err != nil {
		t.Fatalf("get alpha bundle: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "alpha-svid"}, &alphaBefore); err != nil {
		t.Fatalf("get alpha SVID: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-svid"}, &betaBefore); err != nil {
		t.Fatalf("get beta SVID: %v", err)
	}

	// At T0 + 350 days, alpha has 15 days left (<= 30 days) while beta has 195 days left.
	renewalTime := startTime.Add(350 * 24 * time.Hour)
	renewalOptions := spiffe.Options{
		AuthorityNamespace: issuerNamespace,
		RenewBefore:        30 * 24 * time.Hour,
		Now:                func() time.Time { return renewalTime },
		Identities:         []spiffe.Identity{alphaIdentity, betaIdentity},
	}
	if err := spiffe.EnsureCredentials(ctx, env.Client, renewalOptions); err != nil {
		t.Fatalf("renewal run failed: %v", err)
	}

	var authorityAfter, alphaAfter, betaAfter corev1.Secret
	var alphaBundleAfter corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authorityAfter); err != nil {
		t.Fatalf("re-get authority: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundleAfter); err != nil {
		t.Fatalf("re-get alpha bundle: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "alpha-svid"}, &alphaAfter); err != nil {
		t.Fatalf("re-get alpha SVID: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-svid"}, &betaAfter); err != nil {
		t.Fatalf("re-get beta SVID: %v", err)
	}

	if authorityAfter.ResourceVersion != authoritySecret.ResourceVersion {
		t.Errorf("authority secret modified during SVID renewal")
	}
	if alphaBundleAfter.ResourceVersion != alphaBundle.ResourceVersion {
		t.Errorf("alpha bundle configmap modified during SVID renewal")
	}
	if betaAfter.ResourceVersion != betaBefore.ResourceVersion {
		t.Errorf("valid beta SVID modified during alpha renewal")
	}
	if alphaAfter.ResourceVersion == alphaBefore.ResourceVersion {
		t.Fatalf("near-expiry alpha SVID was not renewed")
	}
	if string(alphaAfter.Data[spiffe.SVIDCertDataKey]) == string(alphaBefore.Data[spiffe.SVIDCertDataKey]) {
		t.Fatalf("expected renewed alpha certificate PEM to differ")
	}

	block, _ := pem.Decode(alphaAfter.Data[spiffe.SVIDCertDataKey])
	if block == nil {
		t.Fatalf("failed to decode renewed alpha certificate PEM")
	}
	renewedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse renewed alpha certificate: %v", err)
	}
	if !renewedCert.NotAfter.After(renewalTime.Add(300 * 24 * time.Hour)) {
		t.Errorf("expected renewed certificate NotAfter > %v, got %v", renewalTime.Add(300*24*time.Hour), renewedCert.NotAfter)
	}

	// Verify the renewed certificate chains to the original trust bundle.
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM([]byte(alphaBundle.Data[spiffe.BundleDataKey])) {
		t.Fatalf("failed to append bundle cert to root pool")
	}
	if _, err := renewedCert.Verify(x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: renewalTime,
		DNSName:     "alpha." + alphaNamespace + ".svc.cluster.local",
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("renewed certificate failed verification against existing bundle: %v", err)
	}

	// Running again immediately after renewal is idempotent.
	renewedAlphaRV := alphaAfter.ResourceVersion
	if err := spiffe.EnsureCredentials(ctx, env.Client, renewalOptions); err != nil {
		t.Fatalf("post-renewal idempotent run failed: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "alpha-svid"}, &alphaAfter); err != nil {
		t.Fatalf("re-get alpha SVID after idempotent run: %v", err)
	}
	if alphaAfter.ResourceVersion != renewedAlphaRV {
		t.Errorf("renewed alpha SVID modified on immediate re-run")
	}
}

func TestParseIdentityAndBindFlags(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "issuer-ns")
	options := spiffe.DefaultOptions()
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	spiffe.BindFlags(flagSet, &options)

	args := []string{
		"--renew-before=24h",
		"--identity=namespace=ns-a,service-account=app-a",
		"--identity=namespace=ns-b,service-account=app-b,secret=custom-svid,bundle-configmap=custom-bundle,service=app-b-svc",
	}
	if err := flagSet.Parse(args); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	if options.AuthorityNamespace != "issuer-ns" {
		t.Errorf("AuthorityNamespace = %q, want %q", options.AuthorityNamespace, "issuer-ns")
	}
	if options.RenewBefore != 24*time.Hour {
		t.Errorf("RenewBefore = %v, want 24h", options.RenewBefore)
	}
	if len(options.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(options.Identities))
	}
	if options.Identities[0] != (spiffe.Identity{Namespace: "ns-a", ServiceAccount: "app-a"}) {
		t.Errorf("identity[0] = %+v", options.Identities[0])
	}
	wantSecond := spiffe.Identity{
		Namespace:           "ns-b",
		ServiceAccount:      "app-b",
		SecretName:          "custom-svid",
		BundleConfigMapName: "custom-bundle",
		ServiceName:         "app-b-svc",
	}
	if options.Identities[1] != wantSecond {
		t.Errorf("identity[1] = %+v, want %+v", options.Identities[1], wantSecond)
	}

	invalidSpecs := []string{
		"",
		"namespace=ns-a",
		"service-account=app-a",
		"namespace=ns-a,service-account=app-a,unknown=val",
		"namespace=ns-a,namespace=ns-b,service-account=app-a",
		"namespace=,service-account=app-a",
		"not-a-key-value",
	}
	for _, spec := range invalidSpecs {
		if _, err := spiffe.ParseIdentity(spec); err == nil {
			t.Errorf("ParseIdentity(%q) succeeded, want error", spec)
		}
	}
}

func TestEnsureCredentials_ValidationErrors(t *testing.T) {
	ctx := t.Context()

	cases := []struct {
		name    string
		options spiffe.Options
	}{
		{
			name: "missing authority namespace",
			options: spiffe.Options{
				Identities: []spiffe.Identity{{Namespace: "ns-a", ServiceAccount: "sa-a"}},
			},
		},
		{
			name: "missing identities",
			options: spiffe.Options{
				AuthorityNamespace: "issuer",
			},
		},
		{
			name: "negative renew-before",
			options: spiffe.Options{
				AuthorityNamespace: "issuer",
				RenewBefore:        -1 * time.Hour,
				Identities:         []spiffe.Identity{{Namespace: "ns-a", ServiceAccount: "sa-a"}},
			},
		},
		{
			name: "duplicate target secret",
			options: spiffe.Options{
				AuthorityNamespace: "issuer",
				Identities: []spiffe.Identity{
					{Namespace: "ns-a", ServiceAccount: "sa-1", SecretName: "shared-svid"},
					{Namespace: "ns-a", ServiceAccount: "sa-2", SecretName: "shared-svid"},
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := spiffe.EnsureCredentials(ctx, nil, testCase.options); err == nil {
				t.Fatalf("expected error for %s, got nil", testCase.name)
			}
		})
	}
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

	err := spiffe.EnsureCredentials(ctx, failingClient, controllerOptions(testNamespace))
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

	err := spiffe.EnsureCredentials(ctx, env.Client, controllerOptions(testNamespace))
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

	err := spiffe.EnsureCredentials(ctx, raceClient, controllerOptions(testNamespace))
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

func runMTLSHandshakeTest(t *testing.T, serverCert tls.Certificate, serverClientCAs *x509.CertPool, clientCert tls.Certificate, clientRootCAs *x509.CertPool, serverName string) (string, string) {
	t.Helper()

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    serverClientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatalf("failed to start mTLS listener: %v", err)
	}
	defer listener.Close()

	type serverResult struct {
		spiffeID string
		err      error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- serverResult{err: acceptErr}
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			serverDone <- serverResult{err: handshakeErr}
			return
		}
		state := tlsConn.ConnectionState()
		var peerID string
		if len(state.PeerCertificates) > 0 && len(state.PeerCertificates[0].URIs) > 0 {
			peerID = state.PeerCertificates[0].URIs[0].String()
		}
		serverDone <- serverResult{spiffeID: peerID}
	}()

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      clientRootCAs,
		ServerName:   serverName,
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	clientConn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("mTLS client dial failed: %v", err)
	}
	defer clientConn.Close()
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("mTLS client handshake failed: %v", err)
	}

	result := <-serverDone
	if result.err != nil {
		t.Fatalf("mTLS server handshake failed: %v", result.err)
	}

	clientState := clientConn.ConnectionState()
	var serverID string
	if len(clientState.PeerCertificates) > 0 && len(clientState.PeerCertificates[0].URIs) > 0 {
		serverID = clientState.PeerCertificates[0].URIs[0].String()
	}
	return result.spiffeID, serverID
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
