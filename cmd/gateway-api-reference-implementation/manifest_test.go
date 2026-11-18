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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// TestControllerManifest_DefaultDeploymentOptIn verifies that the default controller
// manifest is certserver-free so clusters without certserver installed succeed at startup.
func TestControllerManifest_DefaultDeploymentOptIn(t *testing.T) {
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
		if deploy.Kind != "Deployment" || deploy.Name != "gari-controller" {
			continue
		}
		foundDeploy = true

		// 1. Verify default manifest has no certserver volumes (opt-in only)
		for _, vol := range deploy.Spec.Template.Spec.Volumes {
			if vol.Name == "certserver-token" {
				t.Errorf("default manifest must be certserver-free, but found volume %q", vol.Name)
			}
		}

		// 2. Verify controller container configuration
		if len(deploy.Spec.Template.Spec.Containers) == 0 {
			t.Fatalf("no containers found in Deployment")
		}
		c := deploy.Spec.Template.Spec.Containers[0]

		for _, m := range c.VolumeMounts {
			if m.Name == "certserver-token" {
				t.Errorf("default manifest must be certserver-free, but found volumeMount %q", m.Name)
			}
		}

		// 3. Verify arguments: must contain dataplane-image, but NOT certserver flags
		if !slices.Contains(c.Args, "--dataplane-image=$(DATAPLANE_IMAGE)") {
			t.Errorf("expected --dataplane-image=$(DATAPLANE_IMAGE) in args, got %v", c.Args)
		}

		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "--certserver-") {
				t.Errorf("default manifest must be certserver-free, but found arg %q", arg)
			}
		}
	}

	if !foundDeploy {
		t.Fatalf("gari-controller Deployment not found in %s", manifestPath)
	}
}

func TestControllerManifest_RBACCustomResourceDefinitions(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundClusterRole bool
	var foundCRDRule bool

	for _, doc := range docs {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			continue
		}
		if role.Kind != "ClusterRole" || role.Name != "gari-controller" {
			continue
		}
		foundClusterRole = true
		for _, rule := range role.Rules {
			if slices.Contains(rule.APIGroups, "apiextensions.k8s.io") && slices.Contains(rule.Resources, "customresourcedefinitions") {
				foundCRDRule = true
				gotNames := slices.Clone(rule.ResourceNames)
				slices.Sort(gotNames)
				sortedExpected := slices.Clone(controller.GatewayAPICRDNames)
				slices.Sort(sortedExpected)
				if !slices.Equal(gotNames, sortedExpected) {
					t.Errorf("customresourcedefinitions rule must restrict resourceNames to named Gateway API CRDs; got %v, want %v", rule.ResourceNames, controller.GatewayAPICRDNames)
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
		t.Fatalf("gari-controller ClusterRole not found in %s", manifestPath)
	}
	if !foundCRDRule {
		t.Fatalf("customresourcedefinitions rule not found in gari-controller ClusterRole")
	}
}
