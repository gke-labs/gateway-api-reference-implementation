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

	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ExtractHostnames extracts the set of unique SNI hostnames from all HTTPS, TLS, and HTTP listeners
// across the provided Gateways. Listeners without hostnames cannot be routed by SNI and are skipped.
func ExtractHostnames(gateways []*gatewayv1.Gateway) []string {
	seen := make(map[string]bool)
	var hostnames []string

	for _, gw := range gateways {
		if gw == nil {
			continue
		}
		for _, l := range gw.Spec.Listeners {
			proto := string(l.Protocol)
			if !strings.EqualFold(proto, string(gatewayv1.HTTPSProtocolType)) &&
				!strings.EqualFold(proto, string(gatewayv1.TLSProtocolType)) &&
				!strings.EqualFold(proto, string(gatewayv1.HTTPProtocolType)) {
				continue
			}

			if l.Hostname == nil || strings.TrimSpace(string(*l.Hostname)) == "" {
				klog.Infof("Skipping listener %q on Gateway %s/%s: HTTPS/TLS listener has no hostname and cannot be routed by SNI",
					l.Name, gw.Namespace, gw.Name)
				continue
			}

			h := strings.ToLower(strings.TrimSpace(string(*l.Hostname)))
			if !seen[h] {
				seen[h] = true
				hostnames = append(hostnames, h)
			}
		}
	}

	slices.Sort(hostnames)
	return hostnames
}
