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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
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

func TestControllerManifest_DeploymentAndInternalAPI(t *testing.T) {
	docs := readControllerManifestDocs(t)

	var foundDeployment bool
	var foundInternalAPIService bool
	var foundCredentialsJob bool

	for _, doc := range docs {
		var deployment appsv1.Deployment
		if err := yaml.Unmarshal([]byte(doc), &deployment); err == nil && deployment.Kind == "Deployment" && deployment.Name == "localgateway-controller" {
			foundDeployment = true
			podSpec := deployment.Spec.Template.Spec

			if podSpec.HostNetwork {
				t.Errorf("localgateway-controller Deployment must not run with hostNetwork")
			}
			if podSpec.DNSPolicy == corev1.DNSClusterFirstWithHostNet {
				t.Errorf("localgateway-controller Deployment must not set dnsPolicy ClusterFirstWithHostNet")
			}

			var foundSVIDVolume bool
			for _, volume := range podSpec.Volumes {
				if volume.Name == "svid" && volume.Secret != nil && volume.Secret.SecretName == spiffe.ControllerSVIDSecretName {
					foundSVIDVolume = true
				}
			}
			if !foundSVIDVolume {
				t.Errorf("expected svid volume referencing Secret %q", spiffe.ControllerSVIDSecretName)
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
			var foundPodNamespace bool
			for _, envVar := range container.Env {
				if envVar.Name == "POD_NAMESPACE" {
					foundPodNamespace = true
				}
				if envVar.Name == "DATAPLANE_IMAGE" {
					dataplaneImage = envVar.Value
				}
			}
			if !foundPodNamespace {
				t.Errorf("expected POD_NAMESPACE env var on controller container")
			}
			if dataplaneImage == "" {
				t.Errorf("expected non-empty DATAPLANE_IMAGE env var on controller container")
			}

			var foundInternalAPIPort bool
			for _, port := range container.Ports {
				if port.ContainerPort == 80 || port.ContainerPort == 5353 {
					t.Errorf("unexpected host-proxy or mDNS port %d on controller container", port.ContainerPort)
				}
				if port.ContainerPort == int32(push.InternalAPIPort) {
					foundInternalAPIPort = true
				}
			}
			if !foundInternalAPIPort {
				t.Errorf("expected internal API containerPort %d", push.InternalAPIPort)
			}

			var foundSVIDMount bool
			for _, mount := range container.VolumeMounts {
				if mount.Name == "svid" && mount.MountPath == "/etc/gari/svid" && mount.ReadOnly {
					foundSVIDMount = true
				}
			}
			if !foundSVIDMount {
				t.Errorf("expected read-only svid volumeMount at /etc/gari/svid")
			}

			// Verify that the manifest args parse cleanly with BuildOptions.
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
		}

		var service corev1.Service
		if err := yaml.Unmarshal([]byte(doc), &service); err == nil && service.Kind == "Service" && service.Name == spiffe.ControllerServiceName {
			foundInternalAPIService = true
			if service.Spec.Selector["app"] != "localgateway-controller" {
				t.Errorf("Service %s selector app = %q, want %q", spiffe.ControllerServiceName, service.Spec.Selector["app"], "localgateway-controller")
			}
			var foundPort bool
			for _, port := range service.Spec.Ports {
				if port.Port == int32(push.InternalAPIPort) {
					foundPort = true
				}
			}
			if !foundPort {
				t.Errorf("Service %s missing port %d", spiffe.ControllerServiceName, push.InternalAPIPort)
			}
		}

		var job batchv1.Job
		if err := yaml.Unmarshal([]byte(doc), &job); err == nil && job.Kind == "Job" && job.Name == "gari-credentials" {
			foundCredentialsJob = true
		}
	}

	if !foundDeployment {
		t.Fatalf("localgateway-controller Deployment not found in manifest")
	}
	if !foundInternalAPIService {
		t.Fatalf("Service %q not found in manifest", spiffe.ControllerServiceName)
	}
	if !foundCredentialsJob {
		t.Fatalf("gari-credentials Job not found in manifest")
	}
}

func TestControllerManifest_RBAC(t *testing.T) {
	docs := readControllerManifestDocs(t)

	var foundClusterRole bool
	var foundCRDRule bool
	var foundDNSRole bool

	hasRule := func(rules []rbacv1.PolicyRule, apiGroup, resource string, requiredVerbs ...string) bool {
		for _, rule := range rules {
			if !slices.Contains(rule.APIGroups, apiGroup) || !slices.Contains(rule.Resources, resource) {
				continue
			}
			allPresent := true
			for _, verb := range requiredVerbs {
				if !slices.Contains(rule.Verbs, verb) {
					allPresent = false
					break
				}
			}
			if allPresent {
				return true
			}
		}
		return false
	}

	for _, doc := range docs {
		var clusterRole rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &clusterRole); err == nil && clusterRole.Kind == "ClusterRole" && clusterRole.Name == "localgateway-controller" {
			foundClusterRole = true

			for _, check := range []struct {
				apiGroup string
				resource string
				verbs    []string
			}{
				{"apps", "deployments", []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
				{"", "serviceaccounts", []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
				{"", "configmaps", []string{"get", "list", "watch", "create", "patch"}},
				{"", "secrets", []string{"get", "list", "watch"}},
				{"", "pods", []string{"get", "list"}},
				{"apps", "replicasets", []string{"get"}},
				{"", "nodes", []string{"get"}},
				{"authentication.k8s.io", "tokenreviews", []string{"create"}},
			} {
				if !hasRule(clusterRole.Rules, check.apiGroup, check.resource, check.verbs...) {
					t.Errorf("localgateway-controller ClusterRole missing rule for apiGroup=%q resource=%q verbs=%v", check.apiGroup, check.resource, check.verbs)
				}
			}

			for _, rule := range clusterRole.Rules {
				if slices.Contains(rule.APIGroups, "apiextensions.k8s.io") && slices.Contains(rule.Resources, "customresourcedefinitions") {
					foundCRDRule = true
					gotNames := slices.Clone(rule.ResourceNames)
					slices.Sort(gotNames)
					sortedExpected := slices.Clone(controller.GatewayAPICRDNames)
					slices.Sort(sortedExpected)
					if !slices.Equal(gotNames, sortedExpected) {
						t.Errorf("customresourcedefinitions resourceNames = %v, want %v", rule.ResourceNames, controller.GatewayAPICRDNames)
					}
					if len(rule.Verbs) != 3 || !slices.Contains(rule.Verbs, "get") || !slices.Contains(rule.Verbs, "list") || !slices.Contains(rule.Verbs, "watch") {
						t.Errorf("customresourcedefinitions verbs = %v, want [get list watch]", rule.Verbs)
					}
				}
			}
		}

		var role rbacv1.Role
		if err := yaml.Unmarshal([]byte(doc), &role); err == nil && role.Kind == "Role" && role.Name == "localgateway-dns-secret" {
			for _, rule := range role.Rules {
				if slices.Contains(rule.APIGroups, "") && slices.Contains(rule.Resources, "secrets") && slices.Contains(rule.ResourceNames, dnsconfig.DefaultConfigSecretName) {
					foundDNSRole = true
				}
			}
		}
	}

	if !foundClusterRole {
		t.Fatalf("localgateway-controller ClusterRole not found in manifest")
	}
	if !foundCRDRule {
		t.Fatalf("customresourcedefinitions rule not found in localgateway-controller ClusterRole")
	}
	if !foundDNSRole {
		t.Fatalf("localgateway-dns-secret Role for Secret %q not found in manifest", dnsconfig.DefaultConfigSecretName)
	}
}
