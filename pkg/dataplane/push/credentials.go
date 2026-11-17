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

package push

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
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CALifetime is the duration for which the push certificate authority certificate is valid (10 years).
	// We choose 10 years because the authority is an internal cluster trust anchor; rotating the CA
	// requires redistributing the new trust bundle to all data planes across workload namespaces.
	// A 10-year lifetime ensures the CA does not expire during normal cluster lifecycles while rotation
	// is out of scope.
	CALifetime = 10 * 365 * 24 * time.Hour

	// ServerCertLifetime is the duration for which the push listener serving certificate is valid (1 year).
	// We choose 1 year (365 days), which follows standard practice for internal service TLS certificates,
	// providing a sensible balance between credential freshness and operational stability.
	ServerCertLifetime = 365 * 24 * time.Hour

	// ServerCertNearExpiryMargin is the window before expiration during which the serving certificate
	// is considered near expiry and will be renewed (30 days).
	// We choose 30 days (~8% of the 1-year lifetime) to provide ample headroom for periodic Job runs,
	// cluster reconcilers, or operator upgrades to issue a replacement certificate before expiry,
	// without regenerating valid certificates unnecessarily on every run.
	ServerCertNearExpiryMargin = 30 * 24 * time.Hour

	// PushServiceName is the name of the Kubernetes Service exposing the push server.
	PushServiceName = "gari-controller-push"

	// PushServicePort is the port exposed by the push Service and bound by the controller.
	PushServicePort = 8443

	// PushCACertConfigMapName is the name of the ConfigMap holding the push CA certificate.
	PushCACertConfigMapName = "gari-controller-push-ca"

	// PushCACertDataKey is the key in the ConfigMap (and CA Secret) holding the PEM-encoded CA certificate.
	PushCACertDataKey = "ca.crt"

	// PushCASecretName is the name of the Secret holding the push CA private key.
	// Only the Job is intended to read this Secret. Note that the controller's ClusterRole currently
	// grants cluster-wide get/list/watch on all Secrets, so the controller technically has read access
	// as well; narrowing controller Secret RBAC is an open maintainer follow-up.
	PushCASecretName = "gari-controller-push-ca-key"

	// PushCAKeyDataKey is the key in the CA Secret holding the PEM-encoded CA private key.
	PushCAKeyDataKey = "ca.key"

	// PushServerSecretName is the name of the Secret of type kubernetes.io/tls holding the serving certificate and key.
	PushServerSecretName = "gari-controller-push-cert"

	// PushServerCertDataKey is the key in the serving Secret holding the PEM-encoded server certificate.
	PushServerCertDataKey = "tls.crt"

	// PushServerKeyDataKey is the key in the serving Secret holding the PEM-encoded server private key.
	PushServerKeyDataKey = "tls.key"
)

// PushServiceDNSNames returns the list of DNS names for the push Service in the specified namespace.
func PushServiceDNSNames(serviceName, namespace string) ([]string, error) {
	if namespace == "" {
		return nil, errors.New("namespace is required")
	}
	if serviceName == "" {
		return nil, errors.New("serviceName is required")
	}
	return []string{
		serviceName,
		fmt.Sprintf("%s.%s", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace),
	}, nil
}

// EnsurePushCredentials creates or renews TLS credentials for the controller's push listener in the given namespace.
// It creates or updates:
//  1. A Secret (PushCASecretName) holding the CA private key and certificate. Only the Job is intended
//     to read it (though the controller's ClusterRole currently has broad Secret read permissions).
//  2. A ConfigMap (PushCACertConfigMapName) holding the CA certificate under ca.crt (no private key).
//  3. A Secret (PushServerSecretName) of type kubernetes.io/tls holding the serving certificate and key.
//
// If the objects exist, the serving certificate is signed by the existing CA, and is not near expiry,
// EnsurePushCredentials changes nothing. If only the serving certificate is missing or near expiry,
// it issues a new one from the existing CA without modifying the CA objects.
// If the authority Secret exists but cannot be read or parsed, its key and certificate do not match,
// or the certificate has expired, an error is returned naming the Secret and the reason.
func EnsurePushCredentials(ctx context.Context, kubeClient client.Client, namespace string) error {
	if namespace == "" {
		return errors.New("namespace is required")
	}

	dnsNames, err := PushServiceDNSNames(PushServiceName, namespace)
	if err != nil {
		return err
	}

	var caSecret corev1.Secret
	hasCASecret := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: PushCASecretName}, &caSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading CA secret %s/%s: %w", namespace, PushCASecretName, err)
		}
		hasCASecret = false
	}

	var caConfigMap corev1.ConfigMap
	hasCAConfigMap := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: PushCACertConfigMapName}, &caConfigMap); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading CA configmap %s/%s: %w", namespace, PushCACertConfigMapName, err)
		}
		hasCAConfigMap = false
	}

	var (
		caKey     *ecdsa.PrivateKey
		caCert    *x509.Certificate
		caCertPEM []byte
		caKeyPEM  []byte
	)

	if hasCASecret {
		caKeyPEM = caSecret.Data[PushCAKeyDataKey]
		if len(caKeyPEM) == 0 {
			return fmt.Errorf("CA secret %s/%s missing required key %q", namespace, PushCASecretName, PushCAKeyDataKey)
		}
		var keyErr error
		caKey, keyErr = parseECPrivateKeyPEM(caKeyPEM)
		if keyErr != nil {
			return fmt.Errorf("CA secret %s/%s: failed to parse private key: %w", namespace, PushCASecretName, keyErr)
		}

		caCertPEM = caSecret.Data[PushCACertDataKey]
		if len(caCertPEM) == 0 && hasCAConfigMap {
			caCertPEM = []byte(caConfigMap.Data[PushCACertDataKey])
		}
		if len(caCertPEM) == 0 {
			return fmt.Errorf("CA secret %s/%s missing required certificate key %q", namespace, PushCASecretName, PushCACertDataKey)
		}
		var certErr error
		caCert, certErr = parseCertificatePEM(caCertPEM)
		if certErr != nil {
			return fmt.Errorf("CA secret %s/%s: failed to parse certificate: %w", namespace, PushCASecretName, certErr)
		}

		if !pubKeyEqual(&caKey.PublicKey, caCert.PublicKey) {
			return fmt.Errorf("CA secret %s/%s: private key does not match certificate public key", namespace, PushCASecretName)
		}
		if !caCert.IsCA {
			return fmt.Errorf("CA secret %s/%s: certificate is not a CA", namespace, PushCASecretName)
		}
		if time.Now().After(caCert.NotAfter) {
			return fmt.Errorf("CA secret %s/%s: certificate expired on %s", namespace, PushCASecretName, caCert.NotAfter.Format(time.RFC3339))
		}
		if time.Now().Before(caCert.NotBefore) {
			return fmt.Errorf("CA secret %s/%s: certificate is not yet valid (NotBefore %s)", namespace, PushCASecretName, caCert.NotBefore.Format(time.RFC3339))
		}

		// Ensure CA ConfigMap exists and matches the valid CA certificate.
		if !hasCAConfigMap || caConfigMap.Data[PushCACertDataKey] != string(caCertPEM) {
			if err := saveConfigMap(ctx, kubeClient, namespace, PushCACertConfigMapName, map[string]string{
				PushCACertDataKey: string(caCertPEM),
			}); err != nil {
				return fmt.Errorf("ensuring CA configmap %s/%s: %w", namespace, PushCACertConfigMapName, err)
			}
		}
	} else {
		// CA secret does not exist; generate a new authority.
		var err error
		caKey, caCert, caCertPEM, caKeyPEM, err = generateCA()
		if err != nil {
			return fmt.Errorf("generating CA: %w", err)
		}

		if err := saveSecret(ctx, kubeClient, namespace, PushCASecretName, corev1.SecretTypeOpaque, map[string][]byte{
			PushCAKeyDataKey:  caKeyPEM,
			PushCACertDataKey: caCertPEM,
		}); err != nil {
			return fmt.Errorf("saving CA secret %s/%s: %w", namespace, PushCASecretName, err)
		}

		if err := saveConfigMap(ctx, kubeClient, namespace, PushCACertConfigMapName, map[string]string{
			PushCACertDataKey: string(caCertPEM),
		}); err != nil {
			return fmt.Errorf("saving CA configmap %s/%s: %w", namespace, PushCACertConfigMapName, err)
		}
	}

	// Check the Serving Secret.
	var serverSecret corev1.Secret
	hasServerSecret := true
	if err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: PushServerSecretName}, &serverSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("reading server secret %s/%s: %w", namespace, PushServerSecretName, err)
		}
		hasServerSecret = false
	}

	validServerCert := false
	if hasServerSecret {
		serverCert, certErr := parseCertificatePEM(serverSecret.Data[PushServerCertDataKey])
		serverKey, keyErr := parseECPrivateKeyPEM(serverSecret.Data[PushServerKeyDataKey])
		if certErr == nil && keyErr == nil && serverCert != nil && serverKey != nil {
			keysMatch := pubKeyEqual(&serverKey.PublicKey, serverCert.PublicKey)
			signatureOK := serverCert.CheckSignatureFrom(caCert) == nil
			notExpired := time.Now().Before(serverCert.NotAfter)
			notNearExpiry := time.Now().Add(ServerCertNearExpiryMargin).Before(serverCert.NotAfter)
			notPremature := time.Now().After(serverCert.NotBefore)

			hasDNSNames := true
			for _, name := range dnsNames {
				if !slices.Contains(serverCert.DNSNames, name) {
					hasDNSNames = false
					break
				}
			}

			if keysMatch && signatureOK && notExpired && notNearExpiry && notPremature && hasDNSNames {
				validServerCert = true
			}
		}
	}

	if validServerCert {
		// Objects exist, serving cert is signed by authority and not near expiry. Change nothing.
		return nil
	}

	// Issue new serving certificate from the existing authority.
	serverCertPEM, serverKeyPEM, err := generateServerCertificate(caCert, caKey, dnsNames)
	if err != nil {
		return fmt.Errorf("generating serving certificate: %w", err)
	}

	if err := saveSecret(ctx, kubeClient, namespace, PushServerSecretName, corev1.SecretTypeTLS, map[string][]byte{
		PushServerCertDataKey: serverCertPEM,
		PushServerKeyDataKey:  serverKeyPEM,
	}); err != nil {
		return fmt.Errorf("saving server secret %s/%s: %w", namespace, PushServerSecretName, err)
	}

	return nil
}

func saveSecret(ctx context.Context, kubeClient client.Client, namespace, name string, secretType corev1.SecretType, data map[string][]byte) error {
	var existing corev1.Secret
	err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &existing)
	if apierrors.IsNotFound(err) {
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: secretType,
			Data: data,
		}
		return kubeClient.Create(ctx, &secret)
	}
	if err != nil {
		return err
	}
	existing.Type = secretType
	existing.Data = data
	return kubeClient.Update(ctx, &existing)
}

func saveConfigMap(ctx context.Context, kubeClient client.Client, namespace, name string, data map[string]string) error {
	var existing corev1.ConfigMap
	err := kubeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &existing)
	if apierrors.IsNotFound(err) {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Data: data,
		}
		return kubeClient.Create(ctx, &configMap)
	}
	if err != nil {
		return err
	}
	existing.Data = data
	return kubeClient.Update(ctx, &existing)
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now().Add(-5 * time.Minute)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "gari-push-ca",
			Organization: []string{"gari"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(CALifetime),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshaling EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return key, cert, certPEM, keyPEM, nil
}

func generateServerCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serving key: %w", err)
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
		DNSNames:              dnsNames,
		NotBefore:             now,
		NotAfter:              now.Add(ServerCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing serving certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling serving key: %w", err)
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

func pubKeyEqual(keyA *ecdsa.PublicKey, keyB any) bool {
	ecB, ok := keyB.(*ecdsa.PublicKey)
	if !ok || ecB == nil || keyA == nil {
		return false
	}
	return keyA.Curve == ecB.Curve && keyA.X.Cmp(ecB.X) == 0 && keyA.Y.Cmp(ecB.Y) == 0
}
