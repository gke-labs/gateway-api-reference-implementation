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

// ExtractHostnames extracts the sorted set of unique SNI hostnames from all accepted,
// non-conflicted HTTPS and TLS effective listeners, covering both Gateway listeners and
// listeners attached through allowed ListenerSets. Listeners without hostnames cannot
// be routed by SNI and are skipped.
func ExtractHostnames(listeners []*state.EffectiveListener) []string {
	seen := make(map[string]bool)
	var hostnames []string

	for _, listener := range listeners {
		if listener == nil || !listener.IsAccepted() || listener.IsConflicted() {
			continue
		}
		protocol := string(listener.Protocol)
		if !strings.EqualFold(protocol, string(gatewayv1.HTTPSProtocolType)) &&
			!strings.EqualFold(protocol, string(gatewayv1.TLSProtocolType)) {
			continue
		}

		if listener.Hostname == nil || strings.TrimSpace(string(*listener.Hostname)) == "" {
			klog.Infof("Skipping listener %q on %s %s/%s: HTTPS/TLS listener has no hostname and cannot be routed by SNI",
				listener.Name, listener.Owner.Kind, listener.Owner.Namespace, listener.Owner.Name)
			continue
		}

		hostname := strings.ToLower(strings.TrimSpace(string(*listener.Hostname)))
		if !seen[hostname] {
			seen[hostname] = true
			hostnames = append(hostnames, hostname)
		}
	}

	slices.Sort(hostnames)
	return hostnames
}
