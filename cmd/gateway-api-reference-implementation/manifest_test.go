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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// TestControllerManifest_PushListenerConfiguration verifies that the default controller
// manifest configures the push listener with its SVID and exposes it via a Service.
func TestControllerManifest_PushListenerConfiguration(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var (
		foundDeploy  bool
		foundService bool
	)

	for _, doc := range docs {
		var meta metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}

		if meta.Kind == "Service" {
			var svc corev1.Service
			if err := yaml.Unmarshal([]byte(doc), &svc); err == nil && svc.Name == spiffe.ControllerServiceName {
				foundService = true
				if svc.Spec.Selector["app"] != "gari-controller" {
					t.Errorf("expected Service selector app=gari-controller, got %v", svc.Spec.Selector)
				}
				var foundPort bool
				for _, p := range svc.Spec.Ports {
					if p.Name == "push" && p.Port == 8443 {
						foundPort = true
					}
				}
				if !foundPort {
					t.Errorf("expected Service port name=push, port=8443, got %v", svc.Spec.Ports)
				}
			}
		}

		if meta.Kind == "Deployment" {
			var deploy appsv1.Deployment
			if err := yaml.Unmarshal([]byte(doc), &deploy); err == nil && deploy.Name == "gari-controller" {
				foundDeploy = true

				// Must mount the controller's X.509-SVID Secret
				var foundSVIDVolume bool
				var svidVolName string
				for _, vol := range deploy.Spec.Template.Spec.Volumes {
					if vol.Secret != nil && vol.Secret.SecretName == spiffe.ControllerSVIDSecretName {
						foundSVIDVolume = true
						svidVolName = vol.Name
					}
					// Must NOT mount authority Secret
					if vol.Secret != nil && vol.Secret.SecretName == spiffe.AuthoritySecretName {
						t.Errorf("controller must not mount authority secret %q", spiffe.AuthoritySecretName)
					}
				}
				if !foundSVIDVolume {
					t.Errorf("expected volume for SVID secret %q", spiffe.ControllerSVIDSecretName)
				}

				if len(deploy.Spec.Template.Spec.Containers) == 0 {
					t.Fatalf("no containers found in Deployment")
				}
				c := deploy.Spec.Template.Spec.Containers[0]

				var svidMountPath string
				for _, m := range c.VolumeMounts {
					if m.Name == svidVolName {
						svidMountPath = m.MountPath
					}
				}
				if svidMountPath == "" {
					t.Errorf("expected volumeMount for SVID volume %q", svidVolName)
				}

				// Check push args
				expectedCertFlag := fmt.Sprintf("--push-tls-cert-file=%s/%s", svidMountPath, spiffe.SVIDCertDataKey)
				expectedKeyFlag := fmt.Sprintf("--push-tls-key-file=%s/%s", svidMountPath, spiffe.SVIDKeyDataKey)
				if !slices.Contains(c.Args, "--push-bind-address=:8443") {
					t.Errorf("expected --push-bind-address=:8443 in args, got %v", c.Args)
				}
				if !slices.Contains(c.Args, expectedCertFlag) {
					t.Errorf("expected %s in args, got %v", expectedCertFlag, c.Args)
				}
				if !slices.Contains(c.Args, expectedKeyFlag) {
					t.Errorf("expected %s in args, got %v", expectedKeyFlag, c.Args)
				}

				// Check push container port
				var foundPushPort bool
				for _, p := range c.Ports {
					if p.Name == "push" && p.ContainerPort == 8443 {
						foundPushPort = true
					}
				}
				if !foundPushPort {
					t.Errorf("expected container port name=push, containerPort=8443, got %v", c.Ports)
				}
			}
		}
	}

	if !foundService {
		t.Fatalf("Service %s not found in %s", spiffe.ControllerServiceName, manifestPath)
	}
	if !foundDeploy {
		t.Fatalf("Deployment gari-controller not found in %s", manifestPath)
	}
}
