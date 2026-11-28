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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func TestParseFlags(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	if _, err := parseFlags([]string{"--identity=namespace=ns-a,service-account=app-a"}); err == nil {
		t.Fatal("expected error when authority namespace and POD_NAMESPACE are both empty")
	}

	t.Setenv("POD_NAMESPACE", "issuer-ns")
	if _, err := parseFlags(nil); err == nil {
		t.Fatal("expected error when no --identity flag is provided")
	}
	if _, err := parseFlags([]string{"--identity=namespace=ns-a,service-account=app-a", "extra"}); err == nil {
		t.Fatal("expected error for unexpected positional argument")
	}

	options, err := parseFlags([]string{
		"--authority-namespace=custom-issuer",
		"--identity=namespace=ns-a,service-account=app-a",
		"--identity=namespace=ns-b,service-account=app-b,secret=custom-svid,bundle-configmap=custom-bundle",
	})
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}
	if options.AuthorityNamespace != "custom-issuer" {
		t.Errorf("AuthorityNamespace = %q, want %q", options.AuthorityNamespace, "custom-issuer")
	}
	if len(options.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(options.Identities))
	}
}

func TestRun_MultiNamespaceAndIdempotent(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const (
		issuerNamespace = "test-gari-issuer"
		alphaNamespace  = "test-gari-alpha"
		betaNamespace   = "test-gari-beta"
	)
	for _, namespace := range []string{issuerNamespace, alphaNamespace, betaNamespace} {
		namespaceObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := env.Client.Create(ctx, namespaceObj); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("failed to create test namespace %s: %v", namespace, err)
		}
	}

	t.Setenv("POD_NAMESPACE", issuerNamespace)
	options, err := parseFlags([]string{
		"--identity=namespace=" + alphaNamespace + ",service-account=alpha-sa",
		"--identity=namespace=" + betaNamespace + ",service-account=beta-sa,secret=beta-custom-svid,bundle-configmap=beta-bundle",
	})
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}

	if err := runWithConfig(ctx, env.Config, options); err != nil {
		t.Fatalf("runWithConfig initial run failed: %v", err)
	}

	var authoritySecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("failed to get authority secret: %v", err)
	}
	var alphaBundle, betaBundle corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundle); err != nil {
		t.Fatalf("failed to get alpha bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-bundle"}, &betaBundle); err != nil {
		t.Fatalf("failed to get beta bundle configmap: %v", err)
	}
	var alphaSVID, betaSVID corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "alpha-sa-svid"}, &alphaSVID); err != nil {
		t.Fatalf("failed to get alpha SVID secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-custom-svid"}, &betaSVID); err != nil {
		t.Fatalf("failed to get beta SVID secret: %v", err)
	}

	// Second run is idempotent.
	authorityRV := authoritySecret.ResourceVersion
	alphaBundleRV := alphaBundle.ResourceVersion
	betaBundleRV := betaBundle.ResourceVersion
	alphaSVIDRV := alphaSVID.ResourceVersion
	betaSVIDRV := betaSVID.ResourceVersion

	if err := runWithConfig(ctx, env.Config, options); err != nil {
		t.Fatalf("runWithConfig second run failed: %v", err)
	}

	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: issuerNamespace, Name: spiffe.AuthoritySecretName}, &authoritySecret); err != nil {
		t.Fatalf("failed to re-get authority secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: spiffe.BundleConfigMapName}, &alphaBundle); err != nil {
		t.Fatalf("failed to re-get alpha bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-bundle"}, &betaBundle); err != nil {
		t.Fatalf("failed to re-get beta bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: alphaNamespace, Name: "alpha-sa-svid"}, &alphaSVID); err != nil {
		t.Fatalf("failed to re-get alpha SVID secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: betaNamespace, Name: "beta-custom-svid"}, &betaSVID); err != nil {
		t.Fatalf("failed to re-get beta SVID secret: %v", err)
	}

	if authoritySecret.ResourceVersion != authorityRV ||
		alphaBundle.ResourceVersion != alphaBundleRV ||
		betaBundle.ResourceVersion != betaBundleRV ||
		alphaSVID.ResourceVersion != alphaSVIDRV ||
		betaSVID.ResourceVersion != betaSVIDRV {
		t.Errorf("expected no ResourceVersion changes on second run")
	}
}

func TestControllerManifest_CredentialsJob(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundJob bool
	var foundRole bool

	for _, doc := range docs {
		var role rbacv1.Role
		if err := yaml.Unmarshal([]byte(doc), &role); err == nil && role.Kind == "Role" && role.Name == "gari-credentials" {
			foundRole = true
			var authorityReadOnly, svidRenewable bool
			for _, rule := range role.Rules {
				if !slices.Contains(rule.Resources, "secrets") {
					continue
				}
				if slices.Equal(rule.ResourceNames, []string{spiffe.AuthoritySecretName}) && slices.Equal(rule.Verbs, []string{"get"}) {
					authorityReadOnly = true
				}
				if slices.Equal(rule.ResourceNames, []string{spiffe.ControllerSVIDSecretName}) &&
					slices.Contains(rule.Verbs, "get") && slices.Contains(rule.Verbs, "update") {
					svidRenewable = true
				}
			}
			if !authorityReadOnly {
				t.Errorf("expected Role to grant get-only access to %s", spiffe.AuthoritySecretName)
			}
			if !svidRenewable {
				t.Errorf("expected Role to grant get and update access to %s for renewal", spiffe.ControllerSVIDSecretName)
			}
		}

		var job batchv1.Job
		if err := yaml.Unmarshal([]byte(doc), &job); err != nil || job.Kind != "Job" || job.Name != "gari-credentials" {
			continue
		}
		foundJob = true

		if job.Spec.Template.Spec.ServiceAccountName != "gari-credentials" {
			t.Errorf("expected serviceAccountName 'gari-credentials', got %q", job.Spec.Template.Spec.ServiceAccountName)
		}
		if len(job.Spec.Template.Spec.Containers) != 1 {
			t.Fatalf("expected exactly 1 container in Job, got %d", len(job.Spec.Template.Spec.Containers))
		}

		container := job.Spec.Template.Spec.Containers[0]
		if container.Image != "gari-credentials:latest" {
			t.Errorf("expected Job image 'gari-credentials:latest', got %q", container.Image)
		}

		var hasPodNamespace bool
		for _, envVar := range container.Env {
			if envVar.Name == "POD_NAMESPACE" && envVar.ValueFrom != nil &&
				envVar.ValueFrom.FieldRef != nil && envVar.ValueFrom.FieldRef.FieldPath == "metadata.namespace" {
				hasPodNamespace = true
			}
		}
		if !hasPodNamespace {
			t.Errorf("expected POD_NAMESPACE env var with fieldRef metadata.namespace in Job container")
		}

		t.Setenv("POD_NAMESPACE", job.Namespace)
		expandedArgs := make([]string, len(container.Args))
		for i, arg := range container.Args {
			expandedArgs[i] = strings.ReplaceAll(arg, "$(POD_NAMESPACE)", job.Namespace)
		}
		options, err := parseFlags(expandedArgs)
		if err != nil {
			t.Fatalf("parseFlags failed on Job args %v: %v", expandedArgs, err)
		}
		if len(options.Identities) != 1 {
			t.Fatalf("expected 1 identity in Job args, got %d", len(options.Identities))
		}
		identity := options.Identities[0]
		if identity.Namespace != job.Namespace || identity.ServiceAccount != spiffe.ControllerServiceAccountName {
			t.Errorf("got identity %+v, want namespace=%q serviceAccount=%q", identity, job.Namespace, spiffe.ControllerServiceAccountName)
		}
	}

	if !foundRole {
		t.Fatalf("gari-credentials Role not found in %s", manifestPath)
	}
	if !foundJob {
		t.Fatalf("gari-credentials Job not found in %s", manifestPath)
	}
}
