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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestDNSManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "dns.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var (
		foundSA          bool
		foundRole        bool
		foundRoleBinding bool
		foundDaemonSet   bool
	)

	for _, doc := range docs {
		trimmed := strings.TrimSpace(doc)
		if trimmed == "" {
			continue
		}

		// Check ServiceAccount
		var sa corev1.ServiceAccount
		if err := yaml.Unmarshal([]byte(trimmed), &sa); err == nil && sa.Kind == "ServiceAccount" && sa.Name == "localgateway-dns" {
			foundSA = true
			if sa.Namespace != "default" {
				t.Errorf("ServiceAccount namespace = %q, want 'default'", sa.Namespace)
			}
		}

		// Check Role
		var role rbacv1.Role
		if err := yaml.Unmarshal([]byte(trimmed), &role); err == nil && role.Kind == "Role" && role.Name == "localgateway-dns" {
			foundRole = true
			if role.Namespace != "default" {
				t.Errorf("Role namespace = %q, want 'default'", role.Namespace)
			}
			if len(role.Rules) != 1 {
				t.Fatalf("Role should have exactly 1 rule, got %d", len(role.Rules))
			}
			rule := role.Rules[0]
			if !slices.Equal(rule.APIGroups, []string{""}) {
				t.Errorf("Role rule APIGroups = %v, want ['']", rule.APIGroups)
			}
			if !slices.Equal(rule.Resources, []string{"secrets"}) {
				t.Errorf("Role rule Resources = %v, want ['secrets']", rule.Resources)
			}
			if !slices.Equal(rule.ResourceNames, []string{"localgateway-dns"}) {
				t.Errorf("Role rule ResourceNames = %v, want ['localgateway-dns']", rule.ResourceNames)
			}
			expectedVerbs := []string{"get", "list", "watch"}
			var sortedVerbs = slices.Clone(rule.Verbs)
			slices.Sort(sortedVerbs)
			var sortedExpected = slices.Clone(expectedVerbs)
			slices.Sort(sortedExpected)
			if !slices.Equal(sortedVerbs, sortedExpected) {
				t.Errorf("Role rule Verbs = %v, want %v", rule.Verbs, expectedVerbs)
			}
		}

		// Check RoleBinding
		var rb rbacv1.RoleBinding
		if err := yaml.Unmarshal([]byte(trimmed), &rb); err == nil && rb.Kind == "RoleBinding" && rb.Name == "localgateway-dns" {
			foundRoleBinding = true
			if rb.Namespace != "default" {
				t.Errorf("RoleBinding namespace = %q, want 'default'", rb.Namespace)
			}
			if rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "localgateway-dns" {
				t.Errorf("RoleBinding roleRef = %+v, want Role localgateway-dns", rb.RoleRef)
			}
			if len(rb.Subjects) != 1 || rb.Subjects[0].Kind != "ServiceAccount" || rb.Subjects[0].Name != "localgateway-dns" || rb.Subjects[0].Namespace != "default" {
				t.Errorf("RoleBinding subjects = %+v, want ServiceAccount localgateway-dns in default", rb.Subjects)
			}
		}

		// Check DaemonSet
		var ds appsv1.DaemonSet
		if err := yaml.Unmarshal([]byte(trimmed), &ds); err == nil && ds.Kind == "DaemonSet" && ds.Name == "localgateway-dns" {
			foundDaemonSet = true
			if ds.Namespace != "default" {
				t.Errorf("DaemonSet namespace = %q, want 'default'", ds.Namespace)
			}
			podSpec := ds.Spec.Template.Spec
			if !podSpec.HostNetwork {
				t.Errorf("DaemonSet hostNetwork must be true")
			}
			if podSpec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
				t.Errorf("DaemonSet dnsPolicy = %q, want %q", podSpec.DNSPolicy, corev1.DNSClusterFirstWithHostNet)
			}
			if podSpec.ServiceAccountName != "localgateway-dns" {
				t.Errorf("DaemonSet serviceAccountName = %q, want 'localgateway-dns'", podSpec.ServiceAccountName)
			}
			if podSpec.SecurityContext == nil || podSpec.SecurityContext.RunAsNonRoot == nil || !*podSpec.SecurityContext.RunAsNonRoot {
				t.Errorf("DaemonSet pod SecurityContext.RunAsNonRoot must be true")
			}
			if len(podSpec.Containers) != 1 {
				t.Fatalf("DaemonSet must have exactly 1 container, got %d", len(podSpec.Containers))
			}
			c := podSpec.Containers[0]
			if c.Image != "localgateway-dns:latest" {
				t.Errorf("Container image = %q, want 'localgateway-dns:latest'", c.Image)
			}
			if !slices.Contains(c.Args, "--secret-namespace=default") {
				t.Errorf("Container args must contain --secret-namespace=default, got %v", c.Args)
			}
			if c.SecurityContext == nil {
				t.Fatalf("Container securityContext must not be nil")
			}
			if c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
				t.Errorf("Container SecurityContext.RunAsNonRoot must be true")
			}
			if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
				t.Errorf("Container SecurityContext.AllowPrivilegeEscalation must be false")
			}
			if c.SecurityContext.Capabilities == nil || len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != "ALL" {
				t.Errorf("Container SecurityContext capabilities must drop ALL, got %+v", c.SecurityContext.Capabilities)
			}
		}
	}

	if !foundSA {
		t.Errorf("ServiceAccount localgateway-dns not found in %s", manifestPath)
	}
	if !foundRole {
		t.Errorf("Role localgateway-dns not found in %s", manifestPath)
	}
	if !foundRoleBinding {
		t.Errorf("RoleBinding localgateway-dns not found in %s", manifestPath)
	}
	if !foundDaemonSet {
		t.Errorf("DaemonSet localgateway-dns not found in %s", manifestPath)
	}
}
