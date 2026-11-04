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

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestControllerManifest_RBACCustomResourceDefinitions(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundClusterRole bool
	var foundCRDRule bool

	expectedCRDNames := []string{
		"gatewayclasses.gateway.networking.k8s.io",
		"gateways.gateway.networking.k8s.io",
		"httproutes.gateway.networking.k8s.io",
		"tlsroutes.gateway.networking.k8s.io",
		"grpcroutes.gateway.networking.k8s.io",
		"tcproutes.gateway.networking.k8s.io",
		"udproutes.gateway.networking.k8s.io",
		"backendtlspolicies.gateway.networking.k8s.io",
		"listenersets.gateway.networking.k8s.io",
		"referencegrants.gateway.networking.k8s.io",
	}

	for _, doc := range docs {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			continue
		}
		if role.Kind != "ClusterRole" || role.Name != "gcpgateway-controller" {
			continue
		}
		foundClusterRole = true
		for _, rule := range role.Rules {
			if slices.Contains(rule.APIGroups, "apiextensions.k8s.io") && slices.Contains(rule.Resources, "customresourcedefinitions") {
				foundCRDRule = true
				gotNames := slices.Clone(rule.ResourceNames)
				slices.Sort(gotNames)
				sortedExpected := slices.Clone(expectedCRDNames)
				slices.Sort(sortedExpected)
				if !slices.Equal(gotNames, sortedExpected) {
					t.Errorf("customresourcedefinitions rule must restrict resourceNames to named Gateway API CRDs; got %v, want %v", rule.ResourceNames, expectedCRDNames)
				}
				for _, verb := range []string{"get", "list", "watch"} {
					if !slices.Contains(rule.Verbs, verb) {
						t.Errorf("customresourcedefinitions rule missing required verb %q; got %v", verb, rule.Verbs)
					}
				}
				if len(rule.Verbs) != 3 {
					t.Errorf("expected exactly [get, list, watch] verbs; got %v", rule.Verbs)
				}
			}
		}
	}

	if !foundClusterRole {
		t.Fatalf("gcpgateway-controller ClusterRole not found in %s", manifestPath)
	}
	if !foundCRDRule {
		t.Fatalf("customresourcedefinitions rule not found in gcpgateway-controller ClusterRole")
	}
}

func TestControllerManifest_CertserverDeployment(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundDeploy bool

	for _, doc := range docs {
		var deploy appsv1.Deployment
		if err := yaml.Unmarshal([]byte(doc), &deploy); err != nil {
			continue
		}
		if deploy.Kind != "Deployment" || deploy.Name != "gcpgateway-controller" {
			continue
		}
		foundDeploy = true

		// 1. Verify projected token volume exists
		var foundTokenVol bool
		for _, vol := range deploy.Spec.Template.Spec.Volumes {
			if vol.Name == "certserver-token" {
				if vol.Projected == nil {
					t.Fatalf("expected certserver-token volume to be projected")
				}
				for _, src := range vol.Projected.Sources {
					if src.ServiceAccountToken != nil {
						if src.ServiceAccountToken.Audience != "certserver" {
							t.Errorf("expected audience certserver, got %s", src.ServiceAccountToken.Audience)
						}
						if src.ServiceAccountToken.Path != "token" {
							t.Errorf("expected path token, got %s", src.ServiceAccountToken.Path)
						}
						foundTokenVol = true
					}
				}
			}
		}
		if !foundTokenVol {
			t.Errorf("certserver-token projected volume not found on Deployment")
		}

		// 2. Verify controller container configuration
		if len(deploy.Spec.Template.Spec.Containers) == 0 {
			t.Fatalf("no containers found in Deployment")
		}
		c := deploy.Spec.Template.Spec.Containers[0]

		var foundMount bool
		for _, m := range c.VolumeMounts {
			if m.Name == "certserver-token" && m.MountPath == "/var/run/secrets/tokens/certserver" && m.ReadOnly {
				foundMount = true
			}
		}
		if !foundMount {
			t.Errorf("expected readOnly volumeMount certserver-token at /var/run/secrets/tokens/certserver")
		}

		// 3. Verify arguments
		hasAddr := slices.Contains(c.Args, "--certserver-address=certserver.gateway-system.svc:8443")
		hasCA := slices.Contains(c.Args, "--certserver-ca-bundle-path=/etc/ssl/certs/certserver-ca.crt")
		hasToken := slices.Contains(c.Args, "--certserver-token-path=/var/run/secrets/tokens/certserver/token")

		if !hasAddr {
			t.Errorf("expected --certserver-address in args, got %v", c.Args)
		}
		if !hasCA {
			t.Errorf("expected --certserver-ca-bundle-path in args, got %v", c.Args)
		}
		if !hasToken {
			t.Errorf("expected --certserver-token-path in args, got %v", c.Args)
		}
	}

	if !foundDeploy {
		t.Fatalf("gcpgateway-controller Deployment not found in %s", manifestPath)
	}
}
