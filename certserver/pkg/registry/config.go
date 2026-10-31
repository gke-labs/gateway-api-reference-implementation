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

package registry

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// ClusterConfig represents a trusted Kubernetes cluster entry in the certserver configuration.
type ClusterConfig struct {
	// ClusterID uniquely identifies the cluster.
	ClusterID string `json:"clusterID"`

	// IssuerURL is the OIDC issuer URL for the cluster's service-account tokens.
	IssuerURL string `json:"issuerURL"`

	// JWKSURL is an optional explicit JWKS URL (for OIDC discovery or direct JWKS endpoint).
	JWKSURL string `json:"jwksURL,omitempty"`

	// JWKSFile is an optional path to a static JWKS file (for clusters whose discovery is not public).
	JWKSFile string `json:"jwksFile,omitempty"`

	// ControllerServiceAccount is the allowed GARI controller service account identity.
	// Can be formatted as "system:serviceaccount:<ns>:<sa>", "<ns>/<sa>", or "<sa>".
	ControllerServiceAccount string `json:"controllerServiceAccount,omitempty"`

	// ControllerNamespace is the allowed GARI controller namespace (if not included in ControllerServiceAccount).
	ControllerNamespace string `json:"controllerNamespace,omitempty"`

	// AllowedHostnames is an optional allow list of hostname patterns (exact names or one leading *. label).
	AllowedHostnames []string `json:"allowedHostnames,omitempty"`

	// DeniedHostnames is an optional deny list of hostname patterns.
	DeniedHostnames []string `json:"deniedHostnames,omitempty"`

	// SharedFrontEndGroup is an optional shared-front-end group membership.
	SharedFrontEndGroup string `json:"sharedFrontEndGroup,omitempty"`

	// GatewaySharedFrontEndGroups is an optional per-Gateway override for shared-front-end group memberships.
	// Maps Gateway identity ("namespace/name" or "name") to group name.
	GatewaySharedFrontEndGroups map[string]string `json:"gatewaySharedFrontEndGroups,omitempty"`
}

// ServerConfig represents the top-level configuration loaded from the server config file.
type ServerConfig struct {
	Clusters []ClusterConfig `json:"clusters"`
}

// ValidateClusterID validates that clusterID is a safe name complying with DNS-1123 label format:
// 1-63 lowercase alphanumeric characters or '-', starting and ending with an alphanumeric character.
func ValidateClusterID(clusterID string) error {
	id := strings.TrimSpace(clusterID)
	if id == "" {
		return errors.New("clusterID is required")
	}
	if len(id) > 63 {
		return fmt.Errorf("clusterID %q exceeds maximum length of 63 characters", id)
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			continue
		}
		if ch == '-' {
			if i == 0 || i == len(id)-1 {
				return fmt.Errorf("clusterID %q cannot start or end with a hyphen", id)
			}
			continue
		}
		return fmt.Errorf("clusterID %q is invalid: must be a DNS-1123 label (lowercase alphanumeric characters or '-', starting and ending with an alphanumeric character)", id)
	}
	return nil
}

// Validate validates the cluster configuration entry.
func (c *ClusterConfig) Validate() error {
	if err := ValidateClusterID(c.ClusterID); err != nil {
		return err
	}
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("cluster %q: issuerURL is required", c.ClusterID)
	}
	if !strings.HasPrefix(c.IssuerURL, "https://") {
		return fmt.Errorf("cluster %q: issuerURL must use HTTPS: %q", c.ClusterID, c.IssuerURL)
	}
	if c.JWKSURL != "" && !strings.HasPrefix(c.JWKSURL, "https://") {
		return fmt.Errorf("cluster %q: jwksURL must use HTTPS: %q", c.ClusterID, c.JWKSURL)
	}

	for _, pattern := range c.AllowedHostnames {
		if err := ValidateHostnamePattern(pattern); err != nil {
			return fmt.Errorf("cluster %q: invalid pattern in allowedHostnames %q: %w", c.ClusterID, pattern, err)
		}
	}
	for _, pattern := range c.DeniedHostnames {
		if err := ValidateHostnamePattern(pattern); err != nil {
			return fmt.Errorf("cluster %q: invalid pattern in deniedHostnames %q: %w", c.ClusterID, pattern, err)
		}
	}

	return nil
}

// LoadServerConfigFile loads and parses a YAML or JSON server configuration file.
func LoadServerConfigFile(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	return ParseServerConfig(data)
}

// ParseServerConfig parses YAML or JSON data into a ServerConfig.
func ParseServerConfig(data []byte) (*ServerConfig, error) {
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse server config: %w", err)
	}

	seenIDs := make(map[string]struct{}, len(cfg.Clusters))
	seenIssuers := make(map[string]string, len(cfg.Clusters))

	for i := range cfg.Clusters {
		c := &cfg.Clusters[i]
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, exists := seenIDs[c.ClusterID]; exists {
			return nil, fmt.Errorf("duplicate clusterID %q", c.ClusterID)
		}
		seenIDs[c.ClusterID] = struct{}{}

		normIss := strings.TrimRight(strings.TrimSpace(c.IssuerURL), "/")
		if existingID, exists := seenIssuers[normIss]; exists {
			return nil, fmt.Errorf("duplicate issuerURL %q in clusters %q and %q", c.IssuerURL, existingID, c.ClusterID)
		}
		seenIssuers[normIss] = c.ClusterID
	}

	return &cfg, nil
}
