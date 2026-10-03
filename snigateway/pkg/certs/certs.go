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

package certs

import (
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
	"os"
	"path/filepath"
	"time"
)

// CertificatePair holds PEM-encoded certificate and private key.
type CertificatePair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GeneratedCerts holds generated CA, server, and client certificates in memory.
type GeneratedCerts struct {
	CA     CertificatePair
	Server CertificatePair
	Client CertificatePair
}

// GenerateAll generates CA, server cert for serverName, and client cert.
func GenerateAll(serverName string, clientCN string) (*GeneratedCerts, error) {
	if serverName == "" {
		serverName = "snigateway.internal"
	}
	if clientCN == "" {
		clientCN = "snigateway-client"
	}

	// 1. Generate CA key and self-signed certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating CA serial: %w", err)
	}

	now := time.Now().Add(-1 * time.Hour)
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "snigateway-ca",
			Organization: []string{"snigateway"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})
	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})

	// Parse CA cert for signing child certs
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	// 2. Generate Server Certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating server key: %w", err)
	}

	serverSerial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating server serial: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   serverName,
			Organization: []string{"snigateway"},
		},
		DNSNames:              []string{serverName},
		NotBefore:             now,
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverDer, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating server certificate: %w", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDer})
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling server key: %w", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})

	// 3. Generate Client Certificate
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating client key: %w", err)
	}

	clientSerial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating client serial: %w", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName:   clientCN,
			Organization: []string{"snigateway"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientDer, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating client certificate: %w", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDer})
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling client key: %w", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

	return &GeneratedCerts{
		CA: CertificatePair{
			CertPEM: caCertPEM,
			KeyPEM:  caKeyPEM,
		},
		Server: CertificatePair{
			CertPEM: serverCertPEM,
			KeyPEM:  serverKeyPEM,
		},
		Client: CertificatePair{
			CertPEM: clientCertPEM,
			KeyPEM:  clientKeyPEM,
		},
	}, nil
}

// GenerateAndWriteCertificates writes generated certs to target directory.
func GenerateAndWriteCertificates(dir string, serverName string, clientCN string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating certs directory: %w", err)
	}

	certs, err := GenerateAll(serverName, clientCN)
	if err != nil {
		return err
	}

	files := []struct {
		name  string
		data  []byte
		perms os.FileMode
	}{
		{"ca.crt", certs.CA.CertPEM, 0644},
		{"ca.key", certs.CA.KeyPEM, 0600},
		{"server.crt", certs.Server.CertPEM, 0644},
		{"server.key", certs.Server.KeyPEM, 0600},
		{"client.crt", certs.Client.CertPEM, 0644},
		{"client.key", certs.Client.KeyPEM, 0600},
	}

	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, f.data, f.perms); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	return nil
}

// ParseCertificatesFromPEM parses all X.509 certificates from PEM encoded bytes.
func ParseCertificatesFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}
	if len(certificates) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found in PEM")
	}
	return certificates, nil
}

// NewServerTLSConfig creates a *tls.Config for the frontend server requiring mTLS.
func NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert PEM")
	}
	return NewServerTLSConfigWithCertPool(caPool, serverCertPEM, serverKeyPEM)
}

// NewServerTLSConfigWithCertPool creates a *tls.Config for the frontend server requiring mTLS with the given client CA pool.
func NewServerTLSConfigWithCertPool(clientCAPool *x509.CertPool, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing server cert/key: %w", err)
	}

	if clientCAPool == nil {
		clientCAPool = x509.NewCertPool()
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// NewClientTLSConfig creates a *tls.Config for mTLS clients connecting to the frontend.
func NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte, serverName string) (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing client cert/key: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert PEM")
	}

	if serverName == "" {
		serverName = "snigateway.internal"
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
