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

package dnsconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	// DefaultSecretName is the default Secret name holding DNS data plane config.
	DefaultSecretName = "localgateway-dns"

	// DefaultSecretNamespace is the default namespace holding the DNS config Secret.
	DefaultSecretNamespace = "default"

	// DefaultSecretDataKey is the key in the Secret holding serialized JSON configuration.
	DefaultSecretDataKey = "config.json"
)

// Record represents a published single-label .local DNS name and its resolved IP addresses.
type Record struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// Config represents the complete DNS data plane configuration distributed by the controller.
type Config struct {
	Revision string   `json:"revision"`
	Records  []Record `json:"records"`
}

// ComputeRevision computes a deterministic SHA-256 hash of the records in the config.
func (c *Config) ComputeRevision() (string, error) {
	data, err := json.Marshal(c.Records)
	if err != nil {
		return "", fmt.Errorf("marshaling records for revision: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// Marshal serializes Config to JSON.
func (c *Config) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// Unmarshal deserializes Config from JSON.
func Unmarshal(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling dns config: %w", err)
	}
	return &cfg, nil
}
