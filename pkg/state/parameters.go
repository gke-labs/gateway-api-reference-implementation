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
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

// Supported parameter keys in ConfigMap.
const (
	ParameterKeyServiceType               = "serviceType"
	ParameterKeyExternalTrafficPolicy     = "externalTrafficPolicy"
	ParameterKeyServiceAnnotations        = "serviceAnnotations"
	ParameterKeyAllowedSourceCIDRs        = "allowedSourceCIDRs"
	ParameterKeyProxyProtocol             = "proxyProtocol"
	ParameterKeyProxyProtocolTrustedCIDRs = "proxyProtocolTrustedCIDRs"
	ParameterKeyExternalIP                = "externalIP"
	ParameterKeyClusterID                 = "clusterId"
	ParameterKeyGatewayNamespace          = "gatewayNamespace"
	ParameterKeyGatewayName               = "gatewayName"
	ParameterKeyNEGHTTPS                  = "negHTTPS"
	ParameterKeyNEGHTTP                   = "negHTTP"
	ParameterKeyNEGPrefix                 = "negPrefix"
	ParameterKeyBackendService            = "backendService"
	ParameterKeyACMEChallenge             = "acmeChallenge"
)

// Parameters represents configuration parsed from a ConfigMap for Gateway/GatewayClass.
type Parameters struct {
	ServiceType               corev1.ServiceType
	ExternalTrafficPolicy     corev1.ServiceExternalTrafficPolicy
	ServiceAnnotations        map[string]string
	AllowedSourceCIDRs        []string
	ProxyProtocol             string
	ProxyProtocolTrustedCIDRs []string
	ExternalIP                string
	ClusterID                 string
	GatewayNamespace          string
	GatewayName               string
	NEGHTTPS                  string
	NEGHTTP                   string
	NEGPrefix                 string
	BackendService            string
	ACMEChallenge             string
}

// DefaultParameters returns default parameters (LoadBalancer, Cluster).
func DefaultParameters() *Parameters {
	return &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
		ServiceAnnotations:    make(map[string]string),
	}
}

func parseCIDRList(val, paramKey string) ([]string, error) {
	if val == "" {
		return nil, nil
	}
	parts := strings.Split(val, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q in %s: %w", trimmed, paramKey, err)
		}
		result = append(result, trimmed)
	}
	return result, nil
}

// ValidateComputeResourceName checks that name is a valid Google Cloud Compute
// Engine resource name. Compute Engine names are RFC 1035 labels of 1 to 63
// lowercase letters, digits, or hyphens that start with a letter and end with
// a letter or digit.
func ValidateComputeResourceName(name string) error {
	if validationErrors := validation.IsDNS1035Label(name); len(validationErrors) > 0 {
		return fmt.Errorf("must be a valid Compute resource name: %s", strings.Join(validationErrors, "; "))
	}
	return nil
}

// ParseConfigMapParameters parses and validates parameters from a ConfigMap.
// Unknown keys or invalid values return an error.
func ParseConfigMapParameters(cm *corev1.ConfigMap) (*Parameters, error) {
	if cm == nil {
		return &Parameters{
			ServiceAnnotations: make(map[string]string),
		}, nil
	}

	if len(cm.BinaryData) > 0 {
		for k := range cm.BinaryData {
			return nil, fmt.Errorf("unknown key %q in ConfigMap binaryData", k)
		}
	}

	for k := range cm.Data {
		switch k {
		case ParameterKeyServiceType,
			ParameterKeyExternalTrafficPolicy,
			ParameterKeyServiceAnnotations,
			ParameterKeyAllowedSourceCIDRs,
			ParameterKeyProxyProtocol,
			ParameterKeyProxyProtocolTrustedCIDRs,
			ParameterKeyExternalIP,
			ParameterKeyClusterID,
			ParameterKeyGatewayNamespace,
			ParameterKeyGatewayName,
			ParameterKeyNEGHTTPS,
			ParameterKeyNEGHTTP,
			ParameterKeyNEGPrefix,
			ParameterKeyBackendService,
			ParameterKeyACMEChallenge:
		default:
			return nil, fmt.Errorf("unknown key %q in ConfigMap", k)
		}
	}

	p := &Parameters{
		ServiceAnnotations: make(map[string]string),
	}

	if val, ok := cm.Data[ParameterKeyServiceType]; ok && val != "" {
		switch val {
		case string(corev1.ServiceTypeLoadBalancer):
			p.ServiceType = corev1.ServiceTypeLoadBalancer
		case string(corev1.ServiceTypeClusterIP):
			p.ServiceType = corev1.ServiceTypeClusterIP
		default:
			return nil, fmt.Errorf("invalid serviceType %q: must be LoadBalancer or ClusterIP", val)
		}
	}

	if val, ok := cm.Data[ParameterKeyExternalTrafficPolicy]; ok && val != "" {
		switch val {
		case string(corev1.ServiceExternalTrafficPolicyCluster):
			p.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
		case string(corev1.ServiceExternalTrafficPolicyLocal):
			p.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
		default:
			return nil, fmt.Errorf("invalid externalTrafficPolicy %q: must be Cluster or Local", val)
		}
	}

	if val, ok := cm.Data[ParameterKeyServiceAnnotations]; ok && val != "" {
		var raw any
		if err := yaml.Unmarshal([]byte(val), &raw); err != nil {
			return nil, fmt.Errorf("invalid serviceAnnotations: %w", err)
		}
		if raw != nil {
			rawMap, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid serviceAnnotations: expected YAML/JSON map")
			}
			for k, v := range rawMap {
				strVal, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("invalid serviceAnnotations: value for key %q must be a string", k)
				}
				p.ServiceAnnotations[k] = strVal
			}
		}
	}

	if val, ok := cm.Data[ParameterKeyAllowedSourceCIDRs]; ok && val != "" {
		cidrs, err := parseCIDRList(val, ParameterKeyAllowedSourceCIDRs)
		if err != nil {
			return nil, err
		}
		p.AllowedSourceCIDRs = cidrs
	}

	if val, ok := cm.Data[ParameterKeyProxyProtocol]; ok && val != "" {
		if !strings.EqualFold(val, "enabled") && !strings.EqualFold(val, "disabled") {
			return nil, fmt.Errorf("invalid proxyProtocol %q: must be enabled or disabled", val)
		}
		p.ProxyProtocol = val
	}

	if val, ok := cm.Data[ParameterKeyProxyProtocolTrustedCIDRs]; ok && val != "" {
		cidrs, err := parseCIDRList(val, ParameterKeyProxyProtocolTrustedCIDRs)
		if err != nil {
			return nil, err
		}
		p.ProxyProtocolTrustedCIDRs = cidrs
	}

	if val, ok := cm.Data[ParameterKeyExternalIP]; ok && val != "" {
		trimmed := strings.TrimSpace(val)
		if net.ParseIP(trimmed) == nil {
			return nil, fmt.Errorf("invalid externalIP %q: must be a valid IP address", val)
		}
		p.ExternalIP = trimmed
	}

	if val, ok := cm.Data[ParameterKeyClusterID]; ok {
		p.ClusterID = strings.TrimSpace(val)
	}

	if val, ok := cm.Data[ParameterKeyGatewayNamespace]; ok {
		p.GatewayNamespace = strings.TrimSpace(val)
	}

	if val, ok := cm.Data[ParameterKeyGatewayName]; ok {
		p.GatewayName = strings.TrimSpace(val)
	}

	if val, ok := cm.Data[ParameterKeyNEGHTTPS]; ok {
		p.NEGHTTPS = strings.TrimSpace(val)
	}

	if val, ok := cm.Data[ParameterKeyNEGHTTP]; ok {
		p.NEGHTTP = strings.TrimSpace(val)
	}

	if val, ok := cm.Data[ParameterKeyNEGPrefix]; ok {
		p.NEGPrefix = strings.TrimSpace(val)
	}

	if value, ok := cm.Data[ParameterKeyBackendService]; ok && value != "" {
		trimmed := strings.TrimSpace(value)
		if err := ValidateComputeResourceName(trimmed); err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", ParameterKeyBackendService, value, err)
		}
		p.BackendService = trimmed
	}

	if val, ok := cm.Data[ParameterKeyACMEChallenge]; ok && val != "" {
		v := strings.ToLower(strings.TrimSpace(val))
		if v != "enabled" && v != "disabled" {
			return nil, fmt.Errorf("invalid value %q for %s: must be 'enabled' or 'disabled'", val, ParameterKeyACMEChallenge)
		}
		p.ACMEChallenge = v
	}

	return p, nil
}

// ValidateGatewayClassParametersRef validates a GatewayClass's ParametersReference.
func ValidateGatewayClassParametersRef(ref *gatewayv1.ParametersReference, configMaps map[types.NamespacedName]*corev1.ConfigMap) (*Parameters, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.Group != "" {
		return nil, fmt.Errorf("unsupported group %q: only core group (\"\") is supported", ref.Group)
	}
	if ref.Kind != "ConfigMap" {
		return nil, fmt.Errorf("unsupported kind %q: only ConfigMap is supported", ref.Kind)
	}
	if ref.Namespace == nil || *ref.Namespace == "" {
		return nil, fmt.Errorf("namespace is required for ConfigMap parametersRef")
	}
	if ref.Name == "" {
		return nil, fmt.Errorf("name is required for ConfigMap parametersRef")
	}
	cmKey := types.NamespacedName{Namespace: string(*ref.Namespace), Name: string(ref.Name)}
	var cm *corev1.ConfigMap
	if configMaps != nil {
		cm = configMaps[cmKey]
	}
	if cm == nil {
		return nil, fmt.Errorf("ConfigMap %s/%s not found", cmKey.Namespace, cmKey.Name)
	}
	return ParseConfigMapParameters(cm)
}

// ValidateGatewayParametersRef validates a Gateway's infrastructure LocalParametersReference.
func ValidateGatewayParametersRef(ref *gatewayv1.LocalParametersReference, gwNamespace string, configMaps map[types.NamespacedName]*corev1.ConfigMap) (*Parameters, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.Group != "" {
		return nil, fmt.Errorf("unsupported group %q: only core group (\"\") is supported", ref.Group)
	}
	if ref.Kind != "ConfigMap" {
		return nil, fmt.Errorf("unsupported kind %q: only ConfigMap is supported", ref.Kind)
	}
	if ref.Name == "" {
		return nil, fmt.Errorf("name is required for ConfigMap parametersRef")
	}
	cmKey := types.NamespacedName{Namespace: gwNamespace, Name: string(ref.Name)}
	var cm *corev1.ConfigMap
	if configMaps != nil {
		cm = configMaps[cmKey]
	}
	if cm == nil {
		return nil, fmt.Errorf("ConfigMap %s/%s not found", cmKey.Namespace, cmKey.Name)
	}
	return ParseConfigMapParameters(cm)
}

// MergeParameters merges GatewayClass parameters and Gateway parameters.
// Gateway values override GatewayClass values.
// Defaults:
// - ServiceType: LoadBalancer
// - ExternalTrafficPolicy: Cluster
func MergeParameters(gcParams, gwParams *Parameters) *Parameters {
	res := &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
		ServiceAnnotations:    make(map[string]string),
	}

	if gcParams != nil {
		if gcParams.ServiceType != "" {
			res.ServiceType = gcParams.ServiceType
		}
		if gcParams.ExternalTrafficPolicy != "" {
			res.ExternalTrafficPolicy = gcParams.ExternalTrafficPolicy
		}
		for k, v := range gcParams.ServiceAnnotations {
			res.ServiceAnnotations[k] = v
		}
		if len(gcParams.AllowedSourceCIDRs) > 0 {
			res.AllowedSourceCIDRs = gcParams.AllowedSourceCIDRs
		}
		if gcParams.ProxyProtocol != "" {
			res.ProxyProtocol = gcParams.ProxyProtocol
		}
		if len(gcParams.ProxyProtocolTrustedCIDRs) > 0 {
			res.ProxyProtocolTrustedCIDRs = gcParams.ProxyProtocolTrustedCIDRs
		}
		if gcParams.ExternalIP != "" {
			res.ExternalIP = gcParams.ExternalIP
		}
		if gcParams.ClusterID != "" {
			res.ClusterID = gcParams.ClusterID
		}
		if gcParams.GatewayNamespace != "" {
			res.GatewayNamespace = gcParams.GatewayNamespace
		}
		if gcParams.GatewayName != "" {
			res.GatewayName = gcParams.GatewayName
		}
		if gcParams.NEGHTTPS != "" {
			res.NEGHTTPS = gcParams.NEGHTTPS
		}
		if gcParams.NEGHTTP != "" {
			res.NEGHTTP = gcParams.NEGHTTP
		}
		if gcParams.NEGPrefix != "" {
			res.NEGPrefix = gcParams.NEGPrefix
		}
		if gcParams.BackendService != "" {
			res.BackendService = gcParams.BackendService
		}
		if gcParams.ACMEChallenge != "" {
			res.ACMEChallenge = gcParams.ACMEChallenge
		}
	}

	if gwParams != nil {
		if gwParams.ServiceType != "" {
			res.ServiceType = gwParams.ServiceType
		}
		if gwParams.ExternalTrafficPolicy != "" {
			res.ExternalTrafficPolicy = gwParams.ExternalTrafficPolicy
		}
		for k, v := range gwParams.ServiceAnnotations {
			res.ServiceAnnotations[k] = v
		}
		if len(gwParams.AllowedSourceCIDRs) > 0 {
			res.AllowedSourceCIDRs = gwParams.AllowedSourceCIDRs
		}
		if gwParams.ProxyProtocol != "" {
			res.ProxyProtocol = gwParams.ProxyProtocol
		}
		if len(gwParams.ProxyProtocolTrustedCIDRs) > 0 {
			res.ProxyProtocolTrustedCIDRs = gwParams.ProxyProtocolTrustedCIDRs
		}
		if gwParams.ExternalIP != "" {
			res.ExternalIP = gwParams.ExternalIP
		}
		if gwParams.ClusterID != "" {
			res.ClusterID = gwParams.ClusterID
		}
		if gwParams.GatewayNamespace != "" {
			res.GatewayNamespace = gwParams.GatewayNamespace
		}
		if gwParams.GatewayName != "" {
			res.GatewayName = gwParams.GatewayName
		}
		if gwParams.NEGHTTPS != "" {
			res.NEGHTTPS = gwParams.NEGHTTPS
		}
		if gwParams.NEGHTTP != "" {
			res.NEGHTTP = gwParams.NEGHTTP
		}
		if gwParams.NEGPrefix != "" {
			res.NEGPrefix = gwParams.NEGPrefix
		}
		if gwParams.BackendService != "" {
			res.BackendService = gwParams.BackendService
		}
		if gwParams.ACMEChallenge != "" {
			res.ACMEChallenge = gwParams.ACMEChallenge
		}
	}

	return res
}

// ParametersEqual returns true if two Parameters structs are equal.
func ParametersEqual(a, b *Parameters) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.ServiceType != b.ServiceType {
		return false
	}
	if a.ExternalTrafficPolicy != b.ExternalTrafficPolicy {
		return false
	}
	if !maps.Equal(a.ServiceAnnotations, b.ServiceAnnotations) {
		return false
	}
	if !slices.Equal(a.AllowedSourceCIDRs, b.AllowedSourceCIDRs) {
		return false
	}
	if a.ProxyProtocol != b.ProxyProtocol {
		return false
	}
	if !slices.Equal(a.ProxyProtocolTrustedCIDRs, b.ProxyProtocolTrustedCIDRs) {
		return false
	}
	if a.ExternalIP != b.ExternalIP {
		return false
	}
	if a.ClusterID != b.ClusterID {
		return false
	}
	if a.GatewayNamespace != b.GatewayNamespace {
		return false
	}
	if a.GatewayName != b.GatewayName {
		return false
	}
	if a.NEGHTTPS != b.NEGHTTPS {
		return false
	}
	if a.NEGHTTP != b.NEGHTTP {
		return false
	}
	if a.NEGPrefix != b.NEGPrefix {
		return false
	}
	if a.BackendService != b.BackendService {
		return false
	}
	return a.ACMEChallenge == b.ACMEChallenge
}
