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

package state

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// CertificateData holds the serialized DER bytes of a TLS certificate chain and PKCS#8 private key.
type CertificateData struct {
	Certificate [][]byte `json:"certificate"`
	PrivateKey  []byte   `json:"privateKey"`
}

const (
	// LabelManagedBy is the Kubernetes label key indicating the managing controller.
	LabelManagedBy = "app.kubernetes.io/managed-by"

	// ManagedByValue is the label value for resources managed by singlepod provisioning.
	ManagedByValue = "gari-singlepod"

	// LabelAppName is the label key identifying the application component.
	LabelAppName = "app.kubernetes.io/name"

	// AppNameValue is the label value identifying data-plane components.
	AppNameValue = "gari-dataplane"

	// LabelGatewayName is the Gateway API label key for the parent Gateway name.
	LabelGatewayName = "gateway.networking.k8s.io/gateway-name"
)

// DataplaneConfig represents the serialized proxy configuration for a single Gateway.
type DataplaneConfig struct {
	GatewayName      types.NamespacedName       `json:"gatewayName"`
	Listeners        []InternalListener         `json:"listeners"`
	Routes           []InternalRoute            `json:"routes"`
	Certificates     map[string]CertificateData `json:"certificates,omitempty"`     // certID -> CertificateData
	HostCertificates map[string]string          `json:"hostCertificates,omitempty"` // hostname -> certID
	DefaultCertID    string                     `json:"defaultCertID,omitempty"`
}

// DataplanePublisher defines the interface for publishing a Gateway's compiled data-plane configuration.
type DataplanePublisher interface {
	PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *DataplaneConfig) error
}

func tlsCertToData(cert *tls.Certificate) (CertificateData, error) {
	if cert == nil {
		return CertificateData{}, nil
	}
	pkBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return CertificateData{}, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	return CertificateData{
		Certificate: cert.Certificate,
		PrivateKey:  pkBytes,
	}, nil
}

func dataToTLSCert(data CertificateData) (*tls.Certificate, error) {
	if len(data.Certificate) == 0 || len(data.PrivateKey) == 0 {
		return nil, nil
	}
	pk, err := x509.ParsePKCS8PrivateKey(data.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}
	cert := &tls.Certificate{
		Certificate: data.Certificate,
		PrivateKey:  pk,
	}
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return cert, nil
}

// BuildDataplaneConfig constructs a DataplaneConfig from listeners, routes, certificates, and default certificate.
func BuildDataplaneConfig(
	gwKey types.NamespacedName,
	listeners []InternalListener,
	routes []InternalRoute,
	certsMap map[string]*tls.Certificate,
	defaultCert *tls.Certificate,
) (*DataplaneConfig, error) {
	cfg := &DataplaneConfig{
		GatewayName:      gwKey,
		Listeners:        listeners,
		Routes:           routes,
		Certificates:     make(map[string]CertificateData),
		HostCertificates: make(map[string]string),
	}

	certIDMap := make(map[*tls.Certificate]string)
	idCounter := 0
	getCertID := func(c *tls.Certificate) (string, error) {
		if c == nil {
			return "", nil
		}
		if id, ok := certIDMap[c]; ok {
			return id, nil
		}
		idCounter++
		id := fmt.Sprintf("cert-%d", idCounter)
		data, err := tlsCertToData(c)
		if err != nil {
			return "", err
		}
		certIDMap[c] = id
		cfg.Certificates[id] = data
		return id, nil
	}

	if defaultCert != nil {
		id, err := getCertID(defaultCert)
		if err != nil {
			return nil, err
		}
		cfg.DefaultCertID = id
	}

	var hosts []string
	for host := range certsMap {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		cert := certsMap[host]
		if cert != nil {
			id, err := getCertID(cert)
			if err != nil {
				return nil, err
			}
			cfg.HostCertificates[host] = id
		}
	}

	return cfg, nil
}

// ExtractCertificates reconstructs the certificates map and default certificate from DataplaneConfig.
func (cfg *DataplaneConfig) ExtractCertificates() (map[string]*tls.Certificate, *tls.Certificate, error) {
	if cfg == nil {
		return nil, nil, nil
	}

	parsedCerts := make(map[string]*tls.Certificate)
	for id, data := range cfg.Certificates {
		tlsCert, err := dataToTLSCert(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate %s: %w", id, err)
		}
		parsedCerts[id] = tlsCert
	}

	certsMap := make(map[string]*tls.Certificate)
	for host, id := range cfg.HostCertificates {
		if cert, ok := parsedCerts[id]; ok {
			certsMap[host] = cert
		}
	}

	var defaultCert *tls.Certificate
	if cfg.DefaultCertID != "" {
		defaultCert = parsedCerts[cfg.DefaultCertID]
	}

	return certsMap, defaultCert, nil
}

// BuildGatewayDataplaneConfig builds a DataplaneConfig for a single compiled Gateway.
func BuildGatewayDataplaneConfig(
	cg *CompiledGateway,
	secrets map[types.NamespacedName]*corev1.Secret,
	refValidator ReferenceGrantValidator,
) (*DataplaneConfig, error) {
	if cg == nil || cg.Gateway == nil {
		return nil, nil
	}
	gwKey := types.NamespacedName{Namespace: cg.Gateway.Namespace, Name: cg.Gateway.Name}
	listeners, routes := BuildProxyConfig([]*CompiledGateway{cg})
	certsMap, defaultCert := ExtractCertificates([]*CompiledGateway{cg}, secrets, refValidator)

	return BuildDataplaneConfig(gwKey, listeners, routes, certsMap, defaultCert)
}

// Marshal serializes DataplaneConfig to JSON.
func (cfg *DataplaneConfig) Marshal() ([]byte, error) {
	return json.Marshal(cfg)
}

// UnmarshalDataplaneConfig deserializes DataplaneConfig from JSON.
func UnmarshalDataplaneConfig(data []byte) (*DataplaneConfig, error) {
	var cfg DataplaneConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
