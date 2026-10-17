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
	"encoding/pem"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// IsHTTPRoute returns true if the group and kind represent an HTTPRoute in Gateway API.
func IsHTTPRoute(group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	g := ValueOf(group)
	return (g == "" || g == gatewayv1.GroupName) && kind == "HTTPRoute"
}

// IsTLSRoute returns true if the group and kind represent a TLSRoute in Gateway API.
func IsTLSRoute(group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	g := ValueOf(group)
	return (g == "" || g == gatewayv1.GroupName) && kind == "TLSRoute"
}

// IsGRPCRoute returns true if the group and kind represent a GRPCRoute in Gateway API.
func IsGRPCRoute(group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	g := ValueOf(group)
	return (g == "" || g == gatewayv1.GroupName) && kind == "GRPCRoute"
}

// IsTCPRoute returns true if the group and kind represent a TCPRoute in Gateway API.
func IsTCPRoute(group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	g := ValueOf(group)
	return (g == "" || g == gatewayv1.GroupName) && kind == "TCPRoute"
}

// IsUDPRoute returns true if the group and kind represent a UDPRoute in Gateway API.
func IsUDPRoute(group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	g := ValueOf(group)
	return (g == "" || g == gatewayv1.GroupName) && kind == "UDPRoute"
}

// IntersectHostnames calculates the intersection of route hostnames and a listener hostname.
func IntersectHostnames(routeHostnames []string, listenerHostname string) []string {
	if listenerHostname == "" || listenerHostname == "*" {
		if len(routeHostnames) == 0 {
			return []string{"*"}
		}
		return routeHostnames
	}

	if len(routeHostnames) == 0 {
		return []string{listenerHostname}
	}

	var result []string
	for _, rh := range routeHostnames {
		if intersection, ok := Intersect(rh, listenerHostname); ok {
			result = append(result, intersection)
		}
	}
	return result
}

// Intersect calculates the intersection of two hostnames, including wildcard support.
func Intersect(h1, h2 string) (string, bool) {
	if h1 == "*" || h1 == "" {
		return h2, true
	}
	if h2 == "*" || h2 == "" {
		return h1, true
	}

	if h1 == h2 {
		return h1, true
	}

	// Wildcard matching
	h1Wild := strings.HasPrefix(h1, "*.")
	h2Wild := strings.HasPrefix(h2, "*.")

	if h1Wild && !h2Wild {
		if strings.HasSuffix(h2, h1[1:]) {
			return h2, true
		}
		return "", false
	}

	if !h1Wild && h2Wild {
		if strings.HasSuffix(h1, h2[1:]) {
			return h1, true
		}
		return "", false
	}

	if h1Wild && h2Wild {
		if strings.HasSuffix(h1, h2[1:]) {
			return h1, true
		}
		if strings.HasSuffix(h2, h1[1:]) {
			return h2, true
		}
		return "", false
	}

	return "", false
}

// ValueOf returns the value of the pointer if it is not nil, otherwise the zero value of the type.
func ValueOf[T any](t *T) T {
	if t == nil {
		var zero T
		return zero
	}
	return *t
}

// Ptr returns a pointer to the given value.
func Ptr[T any](t T) *T {
	return &t
}

// ExtractCACertFromConfigMap extracts and validates PEM-encoded CA certificate data from a ConfigMap's "ca.crt" key.
// Returns the raw PEM bytes if valid, or an error if missing, empty, or not a valid PEM certificate.
func ExtractCACertFromConfigMap(cm *corev1.ConfigMap) ([]byte, error) {
	if cm == nil {
		return nil, fmt.Errorf("ConfigMap is nil")
	}
	var data []byte
	if d, ok := cm.Data["ca.crt"]; ok {
		data = []byte(d)
	} else if d, ok := cm.BinaryData["ca.crt"]; ok {
		data = d
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("ConfigMap %s/%s does not contain 'ca.crt' key or it is empty", cm.Namespace, cm.Name)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ConfigMap %s/%s 'ca.crt' does not contain valid PEM-encoded certificate", cm.Namespace, cm.Name)
	}
	return data, nil
}

// noPolicyTLSBackendHosts inspects compiled rules for backends and mirrors reached over TLS
// (appProtocol: https) without a BackendTLSPolicy, returning their deduplicated hosts.
func noPolicyTLSBackendHosts(rules []InternalRule) []string {
	var hosts []string
	seen := make(map[string]bool)
	for _, rule := range rules {
		if rule.Error != nil {
			continue
		}
		for _, b := range rule.Backends {
			if b.AppProtocol != nil && strings.EqualFold(*b.AppProtocol, "https") && b.TLSConfig == nil {
				if !seen[b.Host] {
					seen[b.Host] = true
					hosts = append(hosts, b.Host)
				}
			}
		}
		for _, m := range rule.Mirrors {
			if m.Backend.AppProtocol != nil && strings.EqualFold(*m.Backend.AppProtocol, "https") && m.Backend.TLSConfig == nil {
				if !seen[m.Backend.Host] {
					seen[m.Backend.Host] = true
					hosts = append(hosts, m.Backend.Host)
				}
			}
		}
	}
	return hosts
}
