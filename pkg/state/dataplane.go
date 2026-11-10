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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
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

	// DataPlaneHTTPPort is the default container port for HTTP traffic.
	DataPlaneHTTPPort = 8080

	// DataPlaneHTTPSPort is the default container port for HTTPS/TLS traffic.
	DataPlaneHTTPSPort = 8443

	// DataPlaneHealthProbePort is the container port for health probes and metrics.
	DataPlaneHealthProbePort = 8999
)

// DataplaneConfig represents the serialized proxy configuration for a single Gateway.
type DataplaneConfig struct {
	Revision                  string                     `json:"revision,omitempty"`
	GatewayName               types.NamespacedName       `json:"gatewayName"`
	Listeners                 []InternalListener         `json:"listeners"`
	Routes                    []InternalRoute            `json:"routes"`
	Certificates              map[string]CertificateData `json:"certificates,omitempty"`     // certID -> CertificateData
	HostCertificates          map[string]string          `json:"hostCertificates,omitempty"` // hostname -> certID
	DefaultCertID             string                     `json:"defaultCertID,omitempty"`
	BackendClientCertID       string                     `json:"backendClientCertID,omitempty"`
	AllowedSourceCIDRs        []string                   `json:"allowedSourceCIDRs,omitempty"`
	ProxyProtocol             string                     `json:"proxyProtocol,omitempty"`
	ProxyProtocolTrustedCIDRs []string                   `json:"proxyProtocolTrustedCIDRs,omitempty"`
}

// ComputeRevision computes a deterministic hash of the DataplaneConfig excluding the Revision field.
func (cfg *DataplaneConfig) ComputeRevision() (string, error) {
	if cfg == nil {
		return "", nil
	}
	clone := *cfg
	clone.Revision = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("failed to marshal dataplane config for revision: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// DataplanePublisher defines the interface for publishing a Gateway's compiled data-plane configuration.
type DataplanePublisher interface {
	Begin(ctx context.Context) error
	PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *DataplaneConfig) error
	Commit(ctx context.Context) error
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

// BuildDataplaneConfig constructs a DataplaneConfig from listeners, routes, certificates, default certificate, and backend client certificate.
func BuildDataplaneConfig(
	gwKey types.NamespacedName,
	listeners []InternalListener,
	routes []InternalRoute,
	certsMap map[string]*tls.Certificate,
	defaultCert *tls.Certificate,
	backendClientCert *tls.Certificate,
) (*DataplaneConfig, error) {
	cfg := &DataplaneConfig{
		GatewayName:      gwKey,
		Listeners:        listeners,
		Routes:           routes,
		Certificates:     make(map[string]CertificateData),
		HostCertificates: make(map[string]string),
	}

	certIDMap := make(map[*tls.Certificate]string)
	getCertID := func(c *tls.Certificate) (string, error) {
		if c == nil {
			return "", nil
		}
		if id, ok := certIDMap[c]; ok {
			return id, nil
		}
		data, err := tlsCertToData(c)
		if err != nil {
			return "", err
		}
		var id string
		if len(c.Certificate) > 0 {
			h := sha256.Sum256(c.Certificate[0])
			id = hex.EncodeToString(h[:])
		} else {
			h := sha256.Sum256(data.PrivateKey)
			id = hex.EncodeToString(h[:])
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

	if backendClientCert != nil {
		id, err := getCertID(backendClientCert)
		if err != nil {
			return nil, err
		}
		cfg.BackendClientCertID = id
	}

	if cfg.BackendClientCertID != "" {
		for i := range routes {
			for j := range routes[i].Rules {
				for k := range routes[i].Rules[j].Backends {
					backend := &routes[i].Rules[j].Backends[k]
					if backend.TLSConfig != nil {
						backend.TLSConfig.ClientCertID = cfg.BackendClientCertID
					}
				}
			}
		}
		for i := range listeners {
			for j := range listeners[i].Routes {
				for k := range listeners[i].Routes[j].Rules {
					for l := range listeners[i].Routes[j].Rules[k].Backends {
						backend := &listeners[i].Routes[j].Rules[k].Backends[l]
						if backend.TLSConfig != nil {
							backend.TLSConfig.ClientCertID = cfg.BackendClientCertID
						}
					}
				}
			}
		}
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

	rev, err := cfg.ComputeRevision()
	if err != nil {
		return nil, err
	}
	cfg.Revision = rev

	return cfg, nil
}

// ExtractCertificates reconstructs the certificates map and default certificate from DataplaneConfig.
// ExtractParsedCertificates parses all certificates in DataplaneConfig once, keyed by certID.
func (cfg *DataplaneConfig) ExtractParsedCertificates() (map[string]*tls.Certificate, error) {
	if cfg == nil {
		return nil, nil
	}

	parsedCerts := make(map[string]*tls.Certificate, len(cfg.Certificates))
	for id, data := range cfg.Certificates {
		tlsCert, err := dataToTLSCert(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %s: %w", id, err)
		}
		parsedCerts[id] = tlsCert
	}
	return parsedCerts, nil
}

// ExtractCertificates reconstructs TLS certificates from DataplaneConfig.
func (cfg *DataplaneConfig) ExtractCertificates() (map[string]*tls.Certificate, *tls.Certificate, error) {
	parsedCerts, err := cfg.ExtractParsedCertificates()
	if err != nil {
		return nil, nil, err
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

// ExtractBackendClientCertificate reconstructs the backend client certificate from DataplaneConfig.
func (cfg *DataplaneConfig) ExtractBackendClientCertificate() (*tls.Certificate, error) {
	if cfg == nil || cfg.BackendClientCertID == "" {
		return nil, nil
	}
	data, ok := cfg.Certificates[cfg.BackendClientCertID]
	if !ok {
		return nil, fmt.Errorf("backend client certificate %s not found in certificates map", cfg.BackendClientCertID)
	}
	return dataToTLSCert(data)
}

// BuildGatewayDataplaneConfig builds a DataplaneConfig for a single compiled Gateway.
func BuildGatewayDataplaneConfig(cg *CompiledGateway) (*DataplaneConfig, error) {
	if cg == nil || cg.Gateway == nil {
		return nil, nil
	}
	gwKey := types.NamespacedName{Namespace: cg.Gateway.Namespace, Name: cg.Gateway.Name}
	listeners, routes := BuildProxyConfig([]*CompiledGateway{cg})
	certsMap, defaultCert := ExtractCertificates([]*CompiledGateway{cg})
	backendClientCert := cg.BackendClientCert

	cfg, err := BuildDataplaneConfig(gwKey, listeners, routes, certsMap, defaultCert, backendClientCert)
	if err != nil {
		return nil, err
	}
	if cg.Parameters != nil {
		cfg.AllowedSourceCIDRs = cg.Parameters.AllowedSourceCIDRs
		cfg.ProxyProtocol = cg.Parameters.ProxyProtocol
		cfg.ProxyProtocolTrustedCIDRs = cg.Parameters.ProxyProtocolTrustedCIDRs
	}
	rev, err := cfg.ComputeRevision()
	if err != nil {
		return nil, err
	}
	cfg.Revision = rev
	return cfg, nil
}

// Marshal serializes DataplaneConfig to JSON.
func (cfg *DataplaneConfig) Marshal() ([]byte, error) {
	if cfg != nil && cfg.Revision == "" {
		rev, err := cfg.ComputeRevision()
		if err != nil {
			return nil, err
		}
		cfg.Revision = rev
	}
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

// ProxyConfigUpdater defines the interface needed to apply configuration and certificates to a proxy.
type ProxyConfigUpdater interface {
	UpdateConfig(listeners []InternalListener, routes []InternalRoute)
	UpdateCertificates(certs map[string]*tls.Certificate, defaultCert *tls.Certificate)
}

// ApplyDataplaneConfig deserializes JSON-encoded DataplaneConfig, extracts certificates,
// and applies the configuration and certificates to the proxy updater.
func ApplyDataplaneConfig(updater ProxyConfigUpdater, data []byte) error {
	if updater == nil {
		return nil
	}
	cfg, err := UnmarshalDataplaneConfig(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal dataplane config: %w", err)
	}

	parsedCerts, err := cfg.ExtractParsedCertificates()
	if err != nil {
		return fmt.Errorf("failed to extract certificates: %w", err)
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

	resolveBackendClientCert := func(backend *InternalBackend) error {
		if backend.TLSConfig != nil && backend.TLSConfig.ClientCertID != "" {
			cert, ok := parsedCerts[backend.TLSConfig.ClientCertID]
			if !ok {
				klog.Errorf("gateway %s: backend %s:%d specifies ClientCertID %q which is missing from certificates",
					cfg.GatewayName, backend.Host, backend.Port, backend.TLSConfig.ClientCertID)
				return fmt.Errorf("gateway %s: backend %s:%d specifies ClientCertID %q which is missing from certificates",
					cfg.GatewayName, backend.Host, backend.Port, backend.TLSConfig.ClientCertID)
			}
			backend.TLSConfig.ClientCert = cert
		}
		return nil
	}

	for i := range cfg.Routes {
		for j := range cfg.Routes[i].Rules {
			for k := range cfg.Routes[i].Rules[j].Backends {
				if err := resolveBackendClientCert(&cfg.Routes[i].Rules[j].Backends[k]); err != nil {
					return err
				}
			}
			for k := range cfg.Routes[i].Rules[j].Mirrors {
				if err := resolveBackendClientCert(&cfg.Routes[i].Rules[j].Mirrors[k].Backend); err != nil {
					return err
				}
			}
		}
	}

	for i := range cfg.Listeners {
		for j := range cfg.Listeners[i].Routes {
			for k := range cfg.Listeners[i].Routes[j].Rules {
				for l := range cfg.Listeners[i].Routes[j].Rules[k].Backends {
					if err := resolveBackendClientCert(&cfg.Listeners[i].Routes[j].Rules[k].Backends[l]); err != nil {
						return err
					}
				}
				for l := range cfg.Listeners[i].Routes[j].Rules[k].Mirrors {
					if err := resolveBackendClientCert(&cfg.Listeners[i].Routes[j].Rules[k].Mirrors[l].Backend); err != nil {
						return err
					}
				}
			}
		}
	}

	updater.UpdateConfig(cfg.Listeners, cfg.Routes)
	updater.UpdateCertificates(certsMap, defaultCert)
	return nil
}

// InProcessDataplanePublisher is a DataplanePublisher that serializes DataplaneConfig
// to JSON and applies it to an in-process proxy using ApplyDataplaneConfig.
type InProcessDataplanePublisher struct {
	mu      sync.Mutex
	updater ProxyConfigUpdater
	configs map[types.NamespacedName]*DataplaneConfig
	inBatch bool
	dirty   bool
}

// NewInProcessDataplanePublisher creates a new in-process DataplanePublisher for the given proxy updater.
func NewInProcessDataplanePublisher(updater ProxyConfigUpdater) *InProcessDataplanePublisher {
	return &InProcessDataplanePublisher{
		updater: updater,
		configs: make(map[types.NamespacedName]*DataplaneConfig),
	}
}

// Begin starts a batch of config updates. When in a batch, updates to the proxy
// are deferred until Commit is called.
func (p *InProcessDataplanePublisher) Begin(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inBatch = true
	p.dirty = false
	return nil
}

// PublishDataplaneConfig records the config for a Gateway. If inside a Begin/Commit batch,
// the proxy update is deferred until Commit. Otherwise, it is applied immediately.
func (p *InProcessDataplanePublisher) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *DataplaneConfig) error {
	if p == nil || p.updater == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.dirty = true

	if gw == nil || config == nil {
		if gw != nil {
			delete(p.configs, types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name})
		} else {
			p.configs = make(map[types.NamespacedName]*DataplaneConfig)
		}
	} else {
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		if p.configs == nil {
			p.configs = make(map[types.NamespacedName]*DataplaneConfig)
		}
		p.configs[gwKey] = config
	}

	if !p.inBatch {
		return p.applyLocked()
	}
	return nil
}

// Commit finalizes the batch and applies the merged configuration to the proxy if modified.
func (p *InProcessDataplanePublisher) Commit(ctx context.Context) error {
	if p == nil || p.updater == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inBatch = false
	if !p.dirty {
		return nil
	}
	p.dirty = false
	return p.applyLocked()
}

func (p *InProcessDataplanePublisher) applyLocked() error {
	if len(p.configs) == 0 {
		emptyData, err := (&DataplaneConfig{}).Marshal()
		if err != nil {
			return err
		}
		return ApplyDataplaneConfig(p.updater, emptyData)
	}

	if len(p.configs) == 1 {
		var singleCfg *DataplaneConfig
		for _, cfg := range p.configs {
			singleCfg = cfg
		}
		data, err := singleCfg.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal dataplane config: %w", err)
		}
		return ApplyDataplaneConfig(p.updater, data)
	}

	// Sort Gateway keys for deterministic merging.
	keys := make([]types.NamespacedName, 0, len(p.configs))
	for k := range p.configs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})

	combined := &DataplaneConfig{
		Certificates:     make(map[string]CertificateData),
		HostCertificates: make(map[string]string),
	}
	for _, k := range keys {
		cfg := p.configs[k]
		combined.Listeners = append(combined.Listeners, cfg.Listeners...)
		combined.Routes = append(combined.Routes, cfg.Routes...)
		for certID, certData := range cfg.Certificates {
			combined.Certificates[certID] = certData
		}
		for host, certID := range cfg.HostCertificates {
			combined.HostCertificates[host] = certID
		}
		if combined.DefaultCertID == "" {
			combined.DefaultCertID = cfg.DefaultCertID
		}
	}
	data, err := combined.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal combined dataplane config: %w", err)
	}
	return ApplyDataplaneConfig(p.updater, data)
}

var _ DataplanePublisher = (*InProcessDataplanePublisher)(nil)
