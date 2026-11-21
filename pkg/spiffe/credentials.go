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
	"net"
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

	// BundleConfigMapName is the name of the ConfigMap holding the trust bundle.
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

// Identity defines a SPIFFE workload identity whose SVID is managed by the credentials Job.
type Identity struct {
	// ServiceAccount is the name of the Kubernetes ServiceAccount for this workload identity.
	ServiceAccount string

	// SecretName is the name of the Kubernetes Secret holding the issued X.509-SVID and private key.
	SecretName string

	// ServiceName is the name of the Kubernetes Service exposing this workload, used for certificate DNS SANs.
	ServiceName string
}

// Identities is the list of SPIFFE identities managed in the cluster.
// Today, this contains one entry: the controller's ServiceAccount.
var Identities = []Identity{
	{
		ServiceAccount: ControllerServiceAccountName,
		SecretName:     ControllerSVIDSecretName,
		ServiceName:    ControllerServiceName,
	},
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

// EnsureCredentials creates the cluster's SPIFFE credentials in the given namespace.
// It creates:
//  1. A Secret (AuthoritySecretName) holding the trust domain signing key and certificate. Only the Job reads it.
//  2. A ConfigMap (BundleConfigMapName) holding the trust bundle under bundle.pem (no private key).
//  3. An X.509-SVID Secret for each identity in Identities.
//
// Running again is safe and does as little as possible:
//   - Creates only what is missing and signs with the existing authority.
//   - Returns an error naming any existing object it cannot read or parse.
//   - Returns an error naming any create that conflicts or fails.
//   - Does not check lifetimes and does not replace anything that exists.
func EnsureCredentials(ctx context.Context, kubeClient client.Client, namespace string) error {
	if namespace == "" {
		return errors.New("namespace is required")
	}

	var authoritySecret corev1.Secret
	hasAuthoritySecret := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: AuthoritySecretName}, &authoritySecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading authority secret %s/%s: %w", namespace, AuthoritySecretName, err)
		}
		hasAuthoritySecret = false
	}

	var bundleConfigMap corev1.ConfigMap
	hasBundleConfigMap := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: BundleConfigMapName}, &bundleConfigMap); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading bundle configmap %s/%s: %w", namespace, BundleConfigMapName, err)
		}
		hasBundleConfigMap = false
	}

	missingIdentities := make([]Identity, 0, len(Identities))
	for _, identity := range Identities {
		var idSecret corev1.Secret
		if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: identity.SecretName}, &idSecret); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("reading SVID secret %s/%s: %w", namespace, identity.SecretName, err)
			}
			missingIdentities = append(missingIdentities, identity)
		}
	}

	// If all objects exist, change nothing.
	if hasAuthoritySecret && hasBundleConfigMap && len(missingIdentities) == 0 {
		return nil
	}

	var (
		authorityKey     *ecdsa.PrivateKey
		authorityCert    *x509.Certificate
		authorityCertPEM []byte
		authorityKeyPEM  []byte
		err              error
	)

	if hasAuthoritySecret {
		authorityKeyPEM = authoritySecret.Data[AuthorityKeyDataKey]
		if len(authorityKeyPEM) == 0 {
			return fmt.Errorf("authority secret %s/%s: missing required key %q", namespace, AuthoritySecretName, AuthorityKeyDataKey)
		}
		authorityKey, err = parseECPrivateKeyPEM(authorityKeyPEM)
		if err != nil {
			return fmt.Errorf("authority secret %s/%s: failed to parse private key: %w", namespace, AuthoritySecretName, err)
		}

		authorityCertPEM = authoritySecret.Data[AuthorityCertDataKey]
		if len(authorityCertPEM) == 0 {
			return fmt.Errorf("authority secret %s/%s: missing required certificate %q", namespace, AuthoritySecretName, AuthorityCertDataKey)
		}
		authorityCert, err = parseCertificatePEM(authorityCertPEM)
		if err != nil {
			return fmt.Errorf("authority secret %s/%s: failed to parse certificate: %w", namespace, AuthoritySecretName, err)
		}
	} else {
		authorityKey, authorityCert, authorityCertPEM, authorityKeyPEM, err = generateAuthority()
		if err != nil {
			return fmt.Errorf("generating authority: %w", err)
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
			return fmt.Errorf("creating authority secret %s/%s: %w", namespace, AuthoritySecretName, err)
		}
	}

	if !hasBundleConfigMap {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      BundleConfigMapName,
				Namespace: namespace,
			},
			Data: map[string]string{
				BundleDataKey: string(authorityCertPEM),
			},
		}
		if err := kubeClient.Create(ctx, &configMap); err != nil {
			return fmt.Errorf("creating bundle configmap %s/%s: %w", namespace, BundleConfigMapName, err)
		}
	}

	for _, identity := range missingIdentities {
		spiffeID, err := SPIFFEID(TrustDomain, namespace, identity.ServiceAccount)
		if err != nil {
			return fmt.Errorf("building SPIFFE ID for %s: %w", identity.ServiceAccount, err)
		}
		dnsNames, err := ServiceDNSNames(identity.ServiceName, namespace)
		if err != nil {
			return fmt.Errorf("building service DNS names for %s: %w", identity.ServiceName, err)
		}

		svidCertPEM, svidKeyPEM, err := generateSVIDCertificate(authorityCert, authorityKey, spiffeID, dnsNames)
		if err != nil {
			return fmt.Errorf("generating SVID certificate for %s: %w", identity.SecretName, err)
		}
		newSVIDSecret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      identity.SecretName,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				SVIDCertDataKey: svidCertPEM,
				SVIDKeyDataKey:  svidKeyPEM,
			},
		}
		if err := kubeClient.Create(ctx, &newSVIDSecret); err != nil {
			return fmt.Errorf("creating SVID secret %s/%s: %w", namespace, identity.SecretName, err)
		}
	}

	return nil
}

func generateAuthority() (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
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

	now := time.Now().Add(-5 * time.Minute)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "gari-spiffe-authority",
			Organization: []string{"gari"},
		},
		URIs:                  []*url.URL{trustDomainURI},
		NotBefore:             now,
		NotAfter:              now.Add(AuthorityLifetime),
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

func generateSVIDCertificate(authorityCert *x509.Certificate, authorityKey *ecdsa.PrivateKey, spiffeID *url.URL, dnsNames []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating SVID key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now().Add(-5 * time.Minute)
	commonName := dnsNames[0]
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"gari"},
		},
		URIs:                  []*url.URL{spiffeID},
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             now,
		NotAfter:              now.Add(SVIDLifetime),
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
