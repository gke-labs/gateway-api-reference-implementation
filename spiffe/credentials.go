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

package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// TrustDomain is the name that all SPIFFE identities in this cluster share.
	TrustDomain = "cluster.local"

	// ClusterDNSDomain is the DNS domain name of the Kubernetes cluster (e.g., "cluster.local").
	ClusterDNSDomain = "cluster.local"

	// AuthorityLifetime is the duration for which the SPIFFE trust domain authority certificate is valid (10 years).
	// We choose 10 years because the authority is an internal cluster trust anchor; rotating the CA
	// requires redistributing the new trust bundle to all workloads across namespaces.
	// A 10-year lifetime ensures the CA does not expire during normal cluster lifecycles while rotation
	// is out of scope.
	AuthorityLifetime = 10 * 365 * 24 * time.Hour

	// SVIDLifetime is the duration for which an X.509-SVID is valid (1 year).
	// We choose 1 year (365 days), standard practice for internal service certificates,
	// providing an appropriate balance between credential freshness and operational stability.
	SVIDLifetime = 365 * 24 * time.Hour

	// DefaultRenewBefore is the default remaining lifetime threshold at or below which
	// an existing X.509-SVID is renewed.
	DefaultRenewBefore = 30 * 24 * time.Hour

	// ControllerServiceAccountName is the ServiceAccount of the controller.
	ControllerServiceAccountName = "gari-controller"

	// ControllerServiceName is the name of the Kubernetes Service exposing the controller.
	ControllerServiceName = "gari-controller"

	// AuthoritySecretName is the name of the Secret holding the trust domain's signing key and certificate.
	// Only the Job is meant to read it. Note that the controller's ClusterRole currently
	// grants cluster-wide get/list/watch on all Secrets, so the controller technically has read access
	// as well; narrowing controller Secret RBAC is an open maintainer follow-up.
	AuthoritySecretName = "gari-spiffe-authority"

	// AuthorityKeyDataKey is the key in the authority Secret holding the PEM-encoded private key.
	AuthorityKeyDataKey = "ca.key"

	// AuthorityCertDataKey is the key in the authority Secret holding the PEM-encoded certificate.
	AuthorityCertDataKey = "ca.crt"

	// BundleConfigMapName is the default name of the ConfigMap holding the trust bundle.
	BundleConfigMapName = "gari-spiffe-bundle"

	// BundleDataKey is the key in the ConfigMap holding the PEM-encoded trust bundle certificate.
	BundleDataKey = "bundle.pem"

	// ControllerSVIDSecretName is the name of the Secret holding the controller's X.509-SVID and key.
	ControllerSVIDSecretName = "gari-controller-svid"

	// SVIDCertDataKey is the key in an SVID Secret holding the PEM-encoded X.509-SVID certificate.
	SVIDCertDataKey = "svid.pem"

	// SVIDKeyDataKey is the key in an SVID Secret holding the PEM-encoded private key.
	SVIDKeyDataKey = "svid_key.pem"
)

// Identity defines a SPIFFE workload identity whose SVID and trust bundle are managed by the credentials Job.
type Identity struct {
	// Namespace is the Kubernetes namespace of the workload.
	Namespace string
	// ServiceAccount is the name of the Kubernetes ServiceAccount for this workload identity.
	ServiceAccount string
	// SecretName is the target SVID Secret name. Defaults to "<ServiceAccount>-svid".
	SecretName string
	// BundleConfigMapName is the target trust bundle ConfigMap name in Namespace. Defaults to BundleConfigMapName.
	BundleConfigMapName string
	// ServiceName is the Kubernetes Service name used for DNS SANs. Defaults to ServiceAccount.
	ServiceName string
}

// Options configures EnsureCredentials.
type Options struct {
	// AuthorityNamespace is the namespace that holds the trust domain authority Secret.
	AuthorityNamespace string
	// RenewBefore renews existing SVIDs whose remaining validity is at or below this duration.
	// Defaults to DefaultRenewBefore when zero.
	RenewBefore time.Duration
	// Now returns the current time. Defaults to time.Now when nil.
	Now func() time.Time
	// Identities lists the workload identities to issue.
	Identities []Identity
}

// SPIFFEID returns the SPIFFE ID URI for a workload ServiceAccount in the given namespace.
func SPIFFEID(trustDomain, namespace, serviceAccount string) (*url.URL, error) {
	if trustDomain == "" {
		return nil, errors.New("trustDomain is required")
	}
	if namespace == "" {
		return nil, errors.New("namespace is required")
	}
	if serviceAccount == "" {
		return nil, errors.New("serviceAccount is required")
	}
	return url.Parse(fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccount))
}

// ServiceClusterDNSName returns the fully qualified cluster DNS name for a Service in the specified namespace
// (e.g., "<serviceName>.<namespace>.svc.cluster.local").
func ServiceClusterDNSName(serviceName, namespace string) (string, error) {
	if namespace == "" {
		return "", errors.New("namespace is required")
	}
	if serviceName == "" {
		return "", errors.New("serviceName is required")
	}
	return fmt.Sprintf("%s.%s.svc.%s", serviceName, namespace, ClusterDNSDomain), nil
}

// ServiceDNSNames returns the list of DNS names for a Service in the specified namespace.
func ServiceDNSNames(serviceName, namespace string) ([]string, error) {
	clusterDNS, err := ServiceClusterDNSName(serviceName, namespace)
	if err != nil {
		return nil, err
	}
	return []string{
		serviceName,
		fmt.Sprintf("%s.%s", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		clusterDNS,
	}, nil
}

type pendingSVID struct {
	identity Identity
	existing *corev1.Secret
}

type authorityMaterial struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
}

// EnsureCredentials reconciles the trust domain authority Secret, per-namespace trust bundle
// ConfigMaps, and per-workload X.509-SVID Secrets described by options.
//
// Invariants:
//   - EnsureCredentials writes the authority signing key Secret only in options.AuthorityNamespace
//     and never copies the private key to workload namespaces.
//   - EnsureCredentials writes each workload's SVID Secret and trust bundle ConfigMap into that
//     workload's namespace.
//   - Re-running EnsureCredentials leaves valid existing objects untouched, creates missing objects
//     using the existing authority, and renews existing SVIDs whose remaining validity is at or
//     below options.RenewBefore.
//   - EnsureCredentials returns an error naming any existing object it cannot read or parse, and
//     any create or update that fails.
func EnsureCredentials(ctx context.Context, kubeClient client.Client, options Options) error {
	resolved, err := resolveOptions(options)
	if err != nil {
		return err
	}
	namespace := resolved.AuthorityNamespace
	now := resolved.Now()

	var authoritySecret corev1.Secret
	hasAuthoritySecret := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: AuthoritySecretName}, &authoritySecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading authority secret %s/%s: %w", namespace, AuthoritySecretName, err)
		}
		hasAuthoritySecret = false
	}

	missingBundles, err := findMissingBundles(ctx, kubeClient, resolved.Identities)
	if err != nil {
		return err
	}
	pendingSVIDs, err := findPendingSVIDs(ctx, kubeClient, resolved.Identities, now, resolved.RenewBefore)
	if err != nil {
		return err
	}

	// If all objects exist and all SVIDs are valid outside the renewal window, change nothing.
	if hasAuthoritySecret && len(missingBundles) == 0 && len(pendingSVIDs) == 0 {
		return nil
	}

	authority, err := ensureAuthority(ctx, kubeClient, namespace, hasAuthoritySecret, &authoritySecret, now)
	if err != nil {
		return err
	}
	if err := createMissingBundles(ctx, kubeClient, missingBundles, authority.certPEM); err != nil {
		return err
	}
	return writePendingSVIDs(ctx, kubeClient, authority, pendingSVIDs, now)
}

func findMissingBundles(ctx context.Context, kubeClient client.Client, identities []Identity) ([]client.ObjectKey, error) {
	missingBundles := make([]client.ObjectKey, 0)
	seenBundles := make(map[client.ObjectKey]bool)
	for _, identity := range identities {
		bundleKey := client.ObjectKey{Namespace: identity.Namespace, Name: identity.BundleConfigMapName}
		if seenBundles[bundleKey] {
			continue
		}
		seenBundles[bundleKey] = true
		var bundleConfigMap corev1.ConfigMap
		if err := kubeClient.Get(ctx, bundleKey, &bundleConfigMap); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("reading bundle configmap %s/%s: %w", bundleKey.Namespace, bundleKey.Name, err)
			}
			missingBundles = append(missingBundles, bundleKey)
			continue
		}
		if bundleConfigMap.Data[BundleDataKey] == "" {
			return nil, fmt.Errorf("bundle configmap %s/%s: missing required key %q", bundleKey.Namespace, bundleKey.Name, BundleDataKey)
		}
	}
	return missingBundles, nil
}

func findPendingSVIDs(ctx context.Context, kubeClient client.Client, identities []Identity, now time.Time, renewBefore time.Duration) ([]pendingSVID, error) {
	pendingSVIDs := make([]pendingSVID, 0, len(identities))
	for _, identity := range identities {
		var existingSecret corev1.Secret
		if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: identity.SecretName}, &existingSecret); err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("reading SVID secret %s/%s: %w", identity.Namespace, identity.SecretName, err)
			}
			pendingSVIDs = append(pendingSVIDs, pendingSVID{identity: identity})
			continue
		}
		certPEM := existingSecret.Data[SVIDCertDataKey]
		if len(certPEM) == 0 {
			return nil, fmt.Errorf("SVID secret %s/%s: missing required certificate %q", identity.Namespace, identity.SecretName, SVIDCertDataKey)
		}
		if len(existingSecret.Data[SVIDKeyDataKey]) == 0 {
			return nil, fmt.Errorf("SVID secret %s/%s: missing required key %q", identity.Namespace, identity.SecretName, SVIDKeyDataKey)
		}
		cert, err := parseCertificatePEM(certPEM)
		if err != nil {
			return nil, fmt.Errorf("SVID secret %s/%s: failed to parse certificate: %w", identity.Namespace, identity.SecretName, err)
		}
		if !cert.NotAfter.After(now.Add(renewBefore)) {
			secretCopy := existingSecret
			pendingSVIDs = append(pendingSVIDs, pendingSVID{identity: identity, existing: &secretCopy})
		}
	}
	return pendingSVIDs, nil
}

func ensureAuthority(ctx context.Context, kubeClient client.Client, namespace string, hasAuthoritySecret bool, authoritySecret *corev1.Secret, now time.Time) (*authorityMaterial, error) {
	if hasAuthoritySecret {
		authorityKeyPEM := authoritySecret.Data[AuthorityKeyDataKey]
		if len(authorityKeyPEM) == 0 {
			return nil, fmt.Errorf("authority secret %s/%s: missing required key %q", namespace, AuthoritySecretName, AuthorityKeyDataKey)
		}
		authorityKey, err := parseECPrivateKeyPEM(authorityKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("authority secret %s/%s: failed to parse private key: %w", namespace, AuthoritySecretName, err)
		}

		authorityCertPEM := authoritySecret.Data[AuthorityCertDataKey]
		if len(authorityCertPEM) == 0 {
			return nil, fmt.Errorf("authority secret %s/%s: missing required certificate %q", namespace, AuthoritySecretName, AuthorityCertDataKey)
		}
		authorityCert, err := parseCertificatePEM(authorityCertPEM)
		if err != nil {
			return nil, fmt.Errorf("authority secret %s/%s: failed to parse certificate: %w", namespace, AuthoritySecretName, err)
		}
		return &authorityMaterial{key: authorityKey, cert: authorityCert, certPEM: authorityCertPEM}, nil
	}

	authorityKey, authorityCert, authorityCertPEM, authorityKeyPEM, err := generateAuthority(now)
	if err != nil {
		return nil, fmt.Errorf("generating authority: %w", err)
	}
	newAuthoritySecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AuthoritySecretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			AuthorityKeyDataKey:  authorityKeyPEM,
			AuthorityCertDataKey: authorityCertPEM,
		},
	}
	if err := kubeClient.Create(ctx, &newAuthoritySecret); err != nil {
		return nil, fmt.Errorf("creating authority secret %s/%s: %w", namespace, AuthoritySecretName, err)
	}
	return &authorityMaterial{key: authorityKey, cert: authorityCert, certPEM: authorityCertPEM}, nil
}

func createMissingBundles(ctx context.Context, kubeClient client.Client, missingBundles []client.ObjectKey, authorityCertPEM []byte) error {
	for _, bundleKey := range missingBundles {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bundleKey.Name,
				Namespace: bundleKey.Namespace,
			},
			Data: map[string]string{
				BundleDataKey: string(authorityCertPEM),
			},
		}
		if err := kubeClient.Create(ctx, &configMap); err != nil {
			return fmt.Errorf("creating bundle configmap %s/%s: %w", bundleKey.Namespace, bundleKey.Name, err)
		}
	}
	return nil
}

func writePendingSVIDs(ctx context.Context, kubeClient client.Client, authority *authorityMaterial, pendingSVIDs []pendingSVID, now time.Time) error {
	for _, item := range pendingSVIDs {
		identity := item.identity
		spiffeID, err := SPIFFEID(TrustDomain, identity.Namespace, identity.ServiceAccount)
		if err != nil {
			return fmt.Errorf("building SPIFFE ID for %s/%s: %w", identity.Namespace, identity.ServiceAccount, err)
		}
		dnsNames, err := ServiceDNSNames(identity.ServiceName, identity.Namespace)
		if err != nil {
			return fmt.Errorf("building service DNS names for %s/%s: %w", identity.Namespace, identity.ServiceName, err)
		}

		svidCertPEM, svidKeyPEM, err := generateSVIDCertificate(authority.cert, authority.key, spiffeID, dnsNames, now)
		if err != nil {
			return fmt.Errorf("generating SVID certificate for %s/%s: %w", identity.Namespace, identity.SecretName, err)
		}
		if item.existing != nil {
			item.existing.Data[SVIDCertDataKey] = svidCertPEM
			item.existing.Data[SVIDKeyDataKey] = svidKeyPEM
			if err := kubeClient.Update(ctx, item.existing); err != nil {
				return fmt.Errorf("updating SVID secret %s/%s: %w", identity.Namespace, identity.SecretName, err)
			}
			continue
		}
		newSVIDSecret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      identity.SecretName,
				Namespace: identity.Namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				SVIDCertDataKey: svidCertPEM,
				SVIDKeyDataKey:  svidKeyPEM,
			},
		}
		if err := kubeClient.Create(ctx, &newSVIDSecret); err != nil {
			return fmt.Errorf("creating SVID secret %s/%s: %w", identity.Namespace, identity.SecretName, err)
		}
	}
	return nil
}

func resolveOptions(options Options) (Options, error) {
	if options.AuthorityNamespace == "" {
		return Options{}, errors.New("authority namespace is required")
	}
	if len(options.Identities) == 0 {
		return Options{}, errors.New("at least one identity is required")
	}
	if options.RenewBefore < 0 {
		return Options{}, errors.New("renew-before duration must not be negative")
	}
	if options.RenewBefore == 0 {
		options.RenewBefore = DefaultRenewBefore
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	seenSecrets := make(map[client.ObjectKey]bool, len(options.Identities))
	resolvedIdentities := make([]Identity, len(options.Identities))
	for i, identity := range options.Identities {
		if identity.Namespace == "" {
			return Options{}, fmt.Errorf("identity %d: namespace is required", i)
		}
		if identity.ServiceAccount == "" {
			return Options{}, fmt.Errorf("identity %d: serviceAccount is required", i)
		}
		if identity.SecretName == "" {
			identity.SecretName = identity.ServiceAccount + "-svid"
		}
		if identity.BundleConfigMapName == "" {
			identity.BundleConfigMapName = BundleConfigMapName
		}
		if identity.ServiceName == "" {
			identity.ServiceName = identity.ServiceAccount
		}
		secretKey := client.ObjectKey{Namespace: identity.Namespace, Name: identity.SecretName}
		if seenSecrets[secretKey] {
			return Options{}, fmt.Errorf("duplicate SVID secret target %s/%s", identity.Namespace, identity.SecretName)
		}
		seenSecrets[secretKey] = true
		resolvedIdentities[i] = identity
	}
	options.Identities = resolvedIdentities
	return options, nil
}

func generateAuthority(now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	trustDomainURI, err := url.Parse(fmt.Sprintf("spiffe://%s", TrustDomain))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing trust domain URI: %w", err)
	}

	notBefore := now.Add(-5 * time.Minute)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "gari-spiffe-authority",
			Organization: []string{"gari"},
		},
		URIs:                  []*url.URL{trustDomainURI},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(AuthorityLifetime),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating authority certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing generated authority certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshaling EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return key, cert, certPEM, keyPEM, nil
}

func generateSVIDCertificate(authorityCert *x509.Certificate, authorityKey *ecdsa.PrivateKey, spiffeID *url.URL, dnsNames []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating SVID key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	notBefore := now.Add(-5 * time.Minute)
	commonName := dnsNames[0]
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"gari"},
		},
		URIs:                  []*url.URL{spiffeID},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(SVIDLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, authorityCert, &key.PublicKey, authorityKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing SVID certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling SVID key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("missing CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKeyPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("missing private key PEM block")
	}
	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("parsed key is not ECDSA")
	}
	return ecKey, nil
}
