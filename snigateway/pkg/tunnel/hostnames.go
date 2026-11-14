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

package tunnel

import (
	"slices"
	"strings"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ExtractHostnames extracts the set of unique SNI hostnames from all HTTPS and TLS listeners
// across the provided Gateways. Listeners without hostnames cannot be routed by SNI and are skipped.
func ExtractHostnames(gateways []*gatewayv1.Gateway) []string {
	seen := make(map[string]bool)
	var hostnames []string

	for _, gateway := range gateways {
		if gateway == nil {
			continue
		}
		for _, listener := range gateway.Spec.Listeners {
			protocol := string(listener.Protocol)
			if !strings.EqualFold(protocol, string(gatewayv1.HTTPSProtocolType)) &&
				!strings.EqualFold(protocol, string(gatewayv1.TLSProtocolType)) {
				continue
			}

			if listener.Hostname == nil || strings.TrimSpace(string(*listener.Hostname)) == "" {
				klog.Infof("Skipping listener %q on Gateway %s/%s: HTTPS/TLS listener has no hostname and cannot be routed by SNI",
					listener.Name, gateway.Namespace, gateway.Name)
				continue
			}

			hostname := strings.ToLower(strings.TrimSpace(string(*listener.Hostname)))
			if !seen[hostname] {
				seen[hostname] = true
				hostnames = append(hostnames, hostname)
			}
		}
	}

	slices.Sort(hostnames)
	return hostnames
}

// ExtractHostnamesFromConfig extracts unique SNI hostnames from HTTPS and TLS listeners in DataplaneConfig.
func ExtractHostnamesFromConfig(config *state.DataplaneConfig) []string {
	if config == nil {
		return nil
	}
	seen := make(map[string]bool)
	var hostnames []string
	for _, listener := range config.Listeners {
		protocol := string(listener.Protocol)
		if !strings.EqualFold(protocol, string(gatewayv1.HTTPSProtocolType)) &&
			!strings.EqualFold(protocol, string(gatewayv1.TLSProtocolType)) {
			continue
		}
		trimmedHostname := strings.TrimSpace(listener.Hostname)
		if trimmedHostname == "" {
			continue
		}
		hostname := strings.ToLower(trimmedHostname)
		if !seen[hostname] {
			seen[hostname] = true
			hostnames = append(hostnames, hostname)
		}
	}
	slices.Sort(hostnames)
	return hostnames
}
