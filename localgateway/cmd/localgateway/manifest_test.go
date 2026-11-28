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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
)

func readControllerManifestDocs(t *testing.T) []string {
	t.Helper()
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}
	return strings.Split(string(data), "\n---")
}

func TestControllerManifest_DeploymentContract(t *testing.T) {
	for _, doc := range readControllerManifestDocs(t) {
		var deployment appsv1.Deployment
		if err := yaml.Unmarshal([]byte(doc), &deployment); err != nil || deployment.Kind != "Deployment" || deployment.Name != "localgateway-controller" {
			continue
		}

		podSpec := deployment.Spec.Template.Spec
		if podSpec.HostNetwork {
			t.Errorf("localgateway-controller Deployment must not run with hostNetwork")
		}
		if len(podSpec.Containers) == 0 {
			t.Fatalf("no containers found in localgateway-controller Deployment")
		}
		container := podSpec.Containers[0]
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			if slices.Contains(container.SecurityContext.Capabilities.Add, "NET_BIND_SERVICE") {
				t.Errorf("localgateway-controller must not add NET_BIND_SERVICE capability")
			}
		}

		var dataplaneImage string
		for _, envVar := range container.Env {
			if envVar.Name == "DATAPLANE_IMAGE" {
				dataplaneImage = envVar.Value
			}
		}

		t.Setenv("POD_NAMESPACE", "default")
		expandedArgs := make([]string, len(container.Args))
		for i, arg := range container.Args {
			expandedArgs[i] = strings.ReplaceAll(arg, "$(DATAPLANE_IMAGE)", dataplaneImage)
		}
		options, err := BuildOptions(expandedArgs)
		if err != nil {
			t.Fatalf("BuildOptions failed to parse manifest args %v: %v", expandedArgs, err)
		}
		if options.ControllerName != DefaultControllerName {
			t.Errorf("parsed ControllerName = %q, want %q", options.ControllerName, DefaultControllerName)
		}
		return
	}

	t.Fatalf("localgateway-controller Deployment not found in manifest")
}

func TestControllerManifest_RBACCustomResourceDefinitions(t *testing.T) {
	var foundClusterRole bool
	var foundCRDRule bool

	for _, doc := range readControllerManifestDocs(t) {
		var clusterRole rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &clusterRole); err != nil || clusterRole.Kind != "ClusterRole" || clusterRole.Name != "localgateway-controller" {
			continue
		}
		foundClusterRole = true

		for _, rule := range clusterRole.Rules {
			if !slices.Contains(rule.APIGroups, "apiextensions.k8s.io") || !slices.Contains(rule.Resources, "customresourcedefinitions") {
				continue
			}
			foundCRDRule = true
			gotNames := slices.Clone(rule.ResourceNames)
			slices.Sort(gotNames)
			expectedNames := slices.Clone(controller.GatewayAPICRDNames)
			slices.Sort(expectedNames)
			if !slices.Equal(gotNames, expectedNames) {
				t.Errorf("customresourcedefinitions resourceNames = %v, want %v", rule.ResourceNames, controller.GatewayAPICRDNames)
			}
			if len(rule.Verbs) != 3 || !slices.Contains(rule.Verbs, "get") || !slices.Contains(rule.Verbs, "list") || !slices.Contains(rule.Verbs, "watch") {
				t.Errorf("customresourcedefinitions verbs = %v, want [get list watch]", rule.Verbs)
			}
		}
	}

	if !foundClusterRole {
		t.Fatalf("localgateway-controller ClusterRole not found in manifest")
	}
	if !foundCRDRule {
		t.Fatalf("customresourcedefinitions rule not found in localgateway-controller ClusterRole")
	}
}
