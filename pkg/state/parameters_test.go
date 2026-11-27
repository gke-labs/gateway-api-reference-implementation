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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestParseConfigMapParameters(t *testing.T) {
	t.Run("nil ConfigMap", func(t *testing.T) {
		p, err := ParseConfigMapParameters(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceType != "" || p.ExternalTrafficPolicy != "" || len(p.ServiceAnnotations) != 0 {
			t.Errorf("expected empty parameters, got %+v", p)
		}
	})

	t.Run("empty ConfigMap data", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "params", Namespace: "default"},
			Data:       map[string]string{},
		}
		p, err := ParseConfigMapParameters(cm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceType != "" || p.ExternalTrafficPolicy != "" || len(p.ServiceAnnotations) != 0 {
			t.Errorf("expected empty parameters, got %+v", p)
		}
	})

	t.Run("valid serviceType LoadBalancer and ClusterIP", func(t *testing.T) {
		for _, st := range []corev1.ServiceType{corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeClusterIP} {
			cm := &corev1.ConfigMap{
				Data: map[string]string{ParameterKeyServiceType: string(st)},
			}
			p, err := ParseConfigMapParameters(cm)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", st, err)
			}
			if p.ServiceType != st {
				t.Errorf("expected ServiceType=%s, got %s", st, p.ServiceType)
			}
		}
	})

	t.Run("invalid serviceType", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{ParameterKeyServiceType: "NodePort"},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for NodePort, got nil")
		}
	})

	t.Run("valid externalTrafficPolicy Cluster and Local", func(t *testing.T) {
		for _, policy := range []corev1.ServiceExternalTrafficPolicy{corev1.ServiceExternalTrafficPolicyCluster, corev1.ServiceExternalTrafficPolicyLocal} {
			cm := &corev1.ConfigMap{
				Data: map[string]string{ParameterKeyExternalTrafficPolicy: string(policy)},
			}
			p, err := ParseConfigMapParameters(cm)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", policy, err)
			}
			if p.ExternalTrafficPolicy != policy {
				t.Errorf("expected ExternalTrafficPolicy=%s, got %s", policy, p.ExternalTrafficPolicy)
			}
		}
	})

	t.Run("invalid externalTrafficPolicy", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{ParameterKeyExternalTrafficPolicy: "InvalidPolicy"},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for InvalidPolicy, got nil")
		}
	})

	t.Run("valid serviceAnnotations YAML map", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyServiceAnnotations: "cloud.google.com/neg: '{\"ingress\": true}'\ncustom.io/foo: bar\n",
			},
		}
		p, err := ParseConfigMapParameters(cm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceAnnotations["cloud.google.com/neg"] != `{"ingress": true}` {
			t.Errorf("unexpected cloud.google.com/neg: %q", p.ServiceAnnotations["cloud.google.com/neg"])
		}
		if p.ServiceAnnotations["custom.io/foo"] != "bar" {
			t.Errorf("unexpected custom.io/foo: %q", p.ServiceAnnotations["custom.io/foo"])
		}
	})

	t.Run("valid serviceAnnotations JSON map", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyServiceAnnotations: `{"cloud.google.com/neg": "{\"ingress\": true}"}`,
			},
		}
		p, err := ParseConfigMapParameters(cm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceAnnotations["cloud.google.com/neg"] != `{"ingress": true}` {
			t.Errorf("unexpected cloud.google.com/neg: %q", p.ServiceAnnotations["cloud.google.com/neg"])
		}
	})

	t.Run("valid allowedSourceCIDRs and proxyProtocolTrustedCIDRs", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyAllowedSourceCIDRs:        "35.191.0.0/16, 130.211.0.0/22",
				ParameterKeyProxyProtocol:             "enabled",
				ParameterKeyProxyProtocolTrustedCIDRs: "35.191.0.0/16,130.211.0.0/22",
				ParameterKeyExternalIP:                "34.120.254.10",
				ParameterKeyClusterID:                 "cluster-1",
				ParameterKeyGatewayNamespace:          "prod",
				ParameterKeyGatewayName:               "gw",
				ParameterKeyNEGHTTPS:                  "neg-8443",
				ParameterKeyNEGHTTP:                   "neg-8080",
				ParameterKeyNEGPrefix:                 "gcpgw",
			},
		}
		p, err := ParseConfigMapParameters(cm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(p.AllowedSourceCIDRs) != 2 || p.AllowedSourceCIDRs[0] != "35.191.0.0/16" || p.AllowedSourceCIDRs[1] != "130.211.0.0/22" {
			t.Errorf("unexpected AllowedSourceCIDRs: %v", p.AllowedSourceCIDRs)
		}
		if p.ProxyProtocol != "enabled" {
			t.Errorf("unexpected ProxyProtocol: %s", p.ProxyProtocol)
		}
		if len(p.ProxyProtocolTrustedCIDRs) != 2 || p.ProxyProtocolTrustedCIDRs[0] != "35.191.0.0/16" {
			t.Errorf("unexpected ProxyProtocolTrustedCIDRs: %v", p.ProxyProtocolTrustedCIDRs)
		}
		if p.ExternalIP != "34.120.254.10" {
			t.Errorf("unexpected ExternalIP: %s", p.ExternalIP)
		}
		if p.ClusterID != "cluster-1" || p.GatewayNamespace != "prod" || p.GatewayName != "gw" {
			t.Errorf("unexpected metadata fields: %+v", p)
		}
	})

	t.Run("invalid allowedSourceCIDRs", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyAllowedSourceCIDRs: "invalid-cidr",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for invalid CIDR, got nil")
		}
	})

	t.Run("invalid proxyProtocol", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyProxyProtocol: "unsupported",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for invalid proxyProtocol, got nil")
		}
	})

	t.Run("invalid externalIP", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyExternalIP: "not-an-ip",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for invalid externalIP, got nil")
		}
	})

	t.Run("invalid serviceAnnotations non-map", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyServiceAnnotations: "- item1\n- item2\n",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for list serviceAnnotations, got nil")
		}
	})

	t.Run("invalid serviceAnnotations non-string value", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyServiceAnnotations: "key: 12345",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for non-string value in serviceAnnotations, got nil")
		}
	})

	t.Run("valid backendService", func(t *testing.T) {
		validNames := []string{
			"my-backend-service",
			"a",
			"a" + strings.Repeat("b", 62),
			"my-backend-1\n",
		}
		for _, name := range validNames {
			configMap := &corev1.ConfigMap{
				Data: map[string]string{
					ParameterKeyBackendService: name,
				},
			}
			parsed, err := ParseConfigMapParameters(configMap)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", name, err)
			}
			if parsed.BackendService != strings.TrimSpace(name) {
				t.Errorf("BackendService = %q, want %q", parsed.BackendService, strings.TrimSpace(name))
			}
		}

		emptyConfigMap := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyBackendService: "",
			},
		}
		parsed, err := ParseConfigMapParameters(emptyConfigMap)
		if err != nil {
			t.Fatalf("unexpected error for empty backendService: %v", err)
		}
		if parsed.BackendService != "" {
			t.Errorf("expected empty BackendService, got %q", parsed.BackendService)
		}
	})

	t.Run("invalid backendService", func(t *testing.T) {
		invalidNames := []string{
			"My-Backend",
			"1-backend",
			"-backend",
			"backend-",
			"my_backend",
			"my.backend",
			"projects/my-project/global/backendServices/my-bs",
			"   ",
			"a" + strings.Repeat("b", 63),
		}
		for _, name := range invalidNames {
			configMap := &corev1.ConfigMap{
				Data: map[string]string{
					ParameterKeyBackendService: name,
				},
			}
			if _, err := ParseConfigMapParameters(configMap); err == nil {
				t.Errorf("expected error for invalid backendService %q, got nil", name)
			}
		}
	})

	t.Run("valid ACME challenge setting", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyACMEChallenge: "enabled",
			},
		}
		p, err := ParseConfigMapParameters(cm)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ACMEChallenge != "enabled" {
			t.Errorf("unexpected ACMEChallenge: %s", p.ACMEChallenge)
		}
	})

	t.Run("invalid ACME challenge setting", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				ParameterKeyACMEChallenge: "invalid",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for invalid ACME challenge setting, got nil")
		}
	})

	t.Run("rejected ACME challenge file path parameters", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				"acmeChallengeTokenPath": "/var/run/secrets/token",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for acmeChallengeTokenPath in ConfigMap, got nil")
		}
	})

	t.Run("unknown key in Data", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			Data: map[string]string{
				"unexpectedKey": "value",
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for unknown key in Data, got nil")
		}
	})

	t.Run("non-empty BinaryData", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			BinaryData: map[string][]byte{
				"serviceType": []byte("LoadBalancer"),
			},
		}
		_, err := ParseConfigMapParameters(cm)
		if err == nil {
			t.Fatalf("expected error for non-empty BinaryData, got nil")
		}
	})
}

func TestValidateGatewayClassParametersRef(t *testing.T) {
	ns := gatewayv1.Namespace("default")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-cm"}: {
			Data: map[string]string{
				ParameterKeyServiceType: "ClusterIP",
			},
		},
		{Namespace: "default", Name: "invalid-cm"}: {
			Data: map[string]string{
				"unknownKey": "val",
			},
		},
	}

	t.Run("nil ref", func(t *testing.T) {
		p, err := ValidateGatewayClassParametersRef(nil, configMaps)
		if err != nil || p != nil {
			t.Fatalf("expected nil, nil, got %+v, %v", p, err)
		}
	})

	t.Run("valid ref", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "",
			Kind:      "ConfigMap",
			Namespace: &ns,
			Name:      "valid-cm",
		}
		p, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceType != corev1.ServiceTypeClusterIP {
			t.Errorf("expected ClusterIP, got %s", p.ServiceType)
		}
	})

	t.Run("unsupported group", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "example.com",
			Kind:      "ConfigMap",
			Namespace: &ns,
			Name:      "valid-cm",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for group example.com, got nil")
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "",
			Kind:      "Secret",
			Namespace: &ns,
			Name:      "valid-cm",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for kind Secret, got nil")
		}
	})

	t.Run("missing namespace", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group: "",
			Kind:  "ConfigMap",
			Name:  "valid-cm",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for missing namespace, got nil")
		}
	})

	t.Run("missing name", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "",
			Kind:      "ConfigMap",
			Namespace: &ns,
			Name:      "",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for empty name, got nil")
		}
	})

	t.Run("missing ConfigMap", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "",
			Kind:      "ConfigMap",
			Namespace: &ns,
			Name:      "nonexistent-cm",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for nonexistent ConfigMap, got nil")
		}
	})

	t.Run("invalid ConfigMap contents", func(t *testing.T) {
		ref := &gatewayv1.ParametersReference{
			Group:     "",
			Kind:      "ConfigMap",
			Namespace: &ns,
			Name:      "invalid-cm",
		}
		_, err := ValidateGatewayClassParametersRef(ref, configMaps)
		if err == nil {
			t.Fatalf("expected error for invalid ConfigMap, got nil")
		}
	})
}

func TestValidateGatewayParametersRef(t *testing.T) {
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-cm"}: {
			Data: map[string]string{
				ParameterKeyServiceType: "ClusterIP",
			},
		},
		{Namespace: "default", Name: "invalid-cm"}: {
			Data: map[string]string{
				"unknownKey": "val",
			},
		},
	}

	t.Run("nil ref", func(t *testing.T) {
		p, err := ValidateGatewayParametersRef(nil, "default", configMaps)
		if err != nil || p != nil {
			t.Fatalf("expected nil, nil, got %+v, %v", p, err)
		}
	})

	t.Run("valid ref", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "",
			Kind:  "ConfigMap",
			Name:  "valid-cm",
		}
		p, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ServiceType != corev1.ServiceTypeClusterIP {
			t.Errorf("expected ClusterIP, got %s", p.ServiceType)
		}
	})

	t.Run("unsupported group", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "example.com",
			Kind:  "ConfigMap",
			Name:  "valid-cm",
		}
		_, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err == nil {
			t.Fatalf("expected error for group example.com, got nil")
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "",
			Kind:  "Secret",
			Name:  "valid-cm",
		}
		_, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err == nil {
			t.Fatalf("expected error for kind Secret, got nil")
		}
	})

	t.Run("missing name", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "",
			Kind:  "ConfigMap",
			Name:  "",
		}
		_, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err == nil {
			t.Fatalf("expected error for empty name, got nil")
		}
	})

	t.Run("missing ConfigMap", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "",
			Kind:  "ConfigMap",
			Name:  "nonexistent-cm",
		}
		_, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err == nil {
			t.Fatalf("expected error for nonexistent ConfigMap, got nil")
		}
	})

	t.Run("invalid ConfigMap contents", func(t *testing.T) {
		ref := &gatewayv1.LocalParametersReference{
			Group: "",
			Kind:  "ConfigMap",
			Name:  "invalid-cm",
		}
		_, err := ValidateGatewayParametersRef(ref, "default", configMaps)
		if err == nil {
			t.Fatalf("expected error for invalid ConfigMap, got nil")
		}
	})
}

func TestMergeParameters(t *testing.T) {
	t.Run("defaults when both nil", func(t *testing.T) {
		res := MergeParameters(nil, nil)
		if res.ServiceType != corev1.ServiceTypeLoadBalancer {
			t.Errorf("expected default ServiceType LoadBalancer, got %s", res.ServiceType)
		}
		if res.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster {
			t.Errorf("expected default ExternalTrafficPolicy Cluster, got %s", res.ExternalTrafficPolicy)
		}
		if len(res.ServiceAnnotations) != 0 {
			t.Errorf("expected empty ServiceAnnotations, got %+v", res.ServiceAnnotations)
		}
	})

	t.Run("GatewayClass sets values and Gateway is nil", func(t *testing.T) {
		gc := &Parameters{
			ServiceType:           corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			ServiceAnnotations:    map[string]string{"gc": "1"},
		}
		res := MergeParameters(gc, nil)
		if res.ServiceType != corev1.ServiceTypeLoadBalancer || res.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
			t.Errorf("unexpected: %+v", res)
		}
		if res.ServiceAnnotations["gc"] != "1" {
			t.Errorf("unexpected annotations: %+v", res.ServiceAnnotations)
		}
	})

	t.Run("Gateway overrides GatewayClass", func(t *testing.T) {
		gc := &Parameters{
			ServiceType:           corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			ServiceAnnotations:    map[string]string{"shared": "from-gc", "gc-only": "1"},
		}
		gw := &Parameters{
			ServiceType:           corev1.ServiceTypeClusterIP,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
			ServiceAnnotations:    map[string]string{"shared": "from-gw", "gw-only": "2"},
		}
		res := MergeParameters(gc, gw)
		if res.ServiceType != corev1.ServiceTypeClusterIP {
			t.Errorf("expected ServiceType ClusterIP, got %s", res.ServiceType)
		}
		if res.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster {
			t.Errorf("expected ExternalTrafficPolicy Cluster, got %s", res.ExternalTrafficPolicy)
		}
		if res.ServiceAnnotations["shared"] != "from-gw" {
			t.Errorf("expected shared=from-gw, got %s", res.ServiceAnnotations["shared"])
		}
		if res.ServiceAnnotations["gc-only"] != "1" || res.ServiceAnnotations["gw-only"] != "2" {
			t.Errorf("unexpected annotations: %+v", res.ServiceAnnotations)
		}
	})

	t.Run("Gateway merges CIDRs and GCP fields", func(t *testing.T) {
		gc := &Parameters{
			AllowedSourceCIDRs: []string{"10.0.0.0/8"},
			ClusterID:          "cluster-gc",
		}
		gw := &Parameters{
			AllowedSourceCIDRs:        []string{"35.191.0.0/16"},
			ProxyProtocol:             "enabled",
			ProxyProtocolTrustedCIDRs: []string{"35.191.0.0/16"},
			ExternalIP:                "34.120.254.10",
			ClusterID:                 "cluster-gw",
		}
		res := MergeParameters(gc, gw)
		if len(res.AllowedSourceCIDRs) != 1 || res.AllowedSourceCIDRs[0] != "35.191.0.0/16" {
			t.Errorf("expected gw AllowedSourceCIDRs, got %v", res.AllowedSourceCIDRs)
		}
		if res.ProxyProtocol != "enabled" {
			t.Errorf("expected ProxyProtocol enabled, got %s", res.ProxyProtocol)
		}
		if res.ExternalIP != "34.120.254.10" {
			t.Errorf("expected ExternalIP 34.120.254.10, got %s", res.ExternalIP)
		}
		if res.ClusterID != "cluster-gw" {
			t.Errorf("expected ClusterID cluster-gw, got %s", res.ClusterID)
		}
	})

	t.Run("Gateway merges ACME challenge parameters", func(t *testing.T) {
		gc := &Parameters{
			ACMEChallenge:  "enabled",
			BackendService: "class-backend",
		}
		gw := &Parameters{
			ACMEChallenge:  "disabled",
			BackendService: "gateway-backend",
		}
		res := MergeParameters(gc, gw)
		if res.ACMEChallenge != "disabled" {
			t.Errorf("expected gw ACMEChallenge 'disabled', got %s", res.ACMEChallenge)
		}
		if res.BackendService != "gateway-backend" {
			t.Errorf("expected gw BackendService 'gateway-backend', got %s", res.BackendService)
		}
	})
}

func TestParametersEqual(t *testing.T) {
	p1 := &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
		ServiceAnnotations:    map[string]string{"a": "1"},
		BackendService:        "backend-a",
		ACMEChallenge:         "enabled",
	}
	p2 := &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
		ServiceAnnotations:    map[string]string{"a": "1"},
		BackendService:        "backend-a",
		ACMEChallenge:         "enabled",
	}
	p3 := &Parameters{
		ServiceType:           corev1.ServiceTypeClusterIP,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
		ServiceAnnotations:    map[string]string{"a": "1"},
		BackendService:        "backend-a",
		ACMEChallenge:         "enabled",
	}
	p4 := &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
		ServiceAnnotations:    map[string]string{"a": "1"},
		BackendService:        "backend-a",
		ACMEChallenge:         "disabled",
	}
	p5 := &Parameters{
		ServiceType:           corev1.ServiceTypeLoadBalancer,
		ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
		ServiceAnnotations:    map[string]string{"a": "1"},
		BackendService:        "backend-b",
		ACMEChallenge:         "enabled",
	}

	if !ParametersEqual(p1, p2) {
		t.Errorf("expected p1 == p2")
	}
	if ParametersEqual(p1, p3) {
		t.Errorf("expected p1 != p3")
	}
	if ParametersEqual(p1, p4) {
		t.Errorf("expected p1 != p4 (differing ACME challenge setting)")
	}
	if ParametersEqual(p1, p5) {
		t.Errorf("expected p1 != p5 (differing BackendService)")
	}
	if !ParametersEqual(nil, nil) {
		t.Errorf("expected nil == nil")
	}
	if ParametersEqual(p1, nil) || ParametersEqual(nil, p1) {
		t.Errorf("expected p1 != nil")
	}
}
