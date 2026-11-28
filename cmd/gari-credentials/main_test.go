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
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func TestRun_MissingNamespace(t *testing.T) {
	ctx := t.Context()
	err := runWithConfig(ctx, nil, "")
	if err == nil {
		t.Fatal("expected error when POD_NAMESPACE is empty, got nil")
	}
	if !strings.Contains(err.Error(), "POD_NAMESPACE") {
		t.Fatalf("expected error mentioning POD_NAMESPACE, got %v", err)
	}
}

func TestRun_SuccessAndIdempotent(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const testNamespace = "test-gari-credentials"
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
	if err := env.Client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create test namespace: %v", err)
	}

	if err := runWithConfig(ctx, env.Config, testNamespace); err != nil {
		t.Fatalf("runWithConfig initial run failed: %v", err)
	}

	var authSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.AuthoritySecretName}, &authSecret); err != nil {
		t.Fatalf("failed to get authority secret: %v", err)
	}
	if len(authSecret.Data[spiffe.AuthorityKeyDataKey]) == 0 || len(authSecret.Data[spiffe.AuthorityCertDataKey]) == 0 {
		t.Fatalf("authority secret missing required data keys")
	}

	var bundleCM corev1.ConfigMap
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.BundleConfigMapName}, &bundleCM); err != nil {
		t.Fatalf("failed to get bundle configmap: %v", err)
	}
	if bundleCM.Data[spiffe.BundleDataKey] == "" {
		t.Fatalf("bundle configmap missing %q", spiffe.BundleDataKey)
	}

	var svidSecret corev1.Secret
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &svidSecret); err != nil {
		t.Fatalf("failed to get controller SVID secret: %v", err)
	}
	if len(svidSecret.Data[spiffe.SVIDCertDataKey]) == 0 || len(svidSecret.Data[spiffe.SVIDKeyDataKey]) == 0 {
		t.Fatalf("SVID secret missing required data keys")
	}

	// Second run is idempotent
	authRV := authSecret.ResourceVersion
	bundleRV := bundleCM.ResourceVersion
	svidRV := svidSecret.ResourceVersion

	if err := runWithConfig(ctx, env.Config, testNamespace); err != nil {
		t.Fatalf("runWithConfig second run failed: %v", err)
	}

	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.AuthoritySecretName}, &authSecret); err != nil {
		t.Fatalf("failed to re-get authority secret: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.BundleConfigMapName}, &bundleCM); err != nil {
		t.Fatalf("failed to re-get bundle configmap: %v", err)
	}
	if err := env.Client.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: spiffe.ControllerSVIDSecretName}, &svidSecret); err != nil {
		t.Fatalf("failed to re-get controller SVID secret: %v", err)
	}

	if authSecret.ResourceVersion != authRV {
		t.Errorf("authority secret modified on second run; ResourceVersion changed from %s to %s", authRV, authSecret.ResourceVersion)
	}
	if bundleCM.ResourceVersion != bundleRV {
		t.Errorf("bundle configmap modified on second run; ResourceVersion changed from %s to %s", bundleRV, bundleCM.ResourceVersion)
	}
	if svidSecret.ResourceVersion != svidRV {
		t.Errorf("SVID secret modified on second run; ResourceVersion changed from %s to %s", svidRV, svidSecret.ResourceVersion)
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

	for _, doc := range docs {
		var job batchv1.Job
		if err := yaml.Unmarshal([]byte(doc), &job); err != nil {
			continue
		}
		if job.Kind != "Job" || job.Name != "gari-credentials" {
			continue
		}
		foundJob = true

		if job.Spec.Template.Spec.ServiceAccountName != "gari-credentials" {
			t.Errorf("expected serviceAccountName 'gari-credentials', got %q", job.Spec.Template.Spec.ServiceAccountName)
		}

		if len(job.Spec.Template.Spec.Containers) != 1 {
			t.Fatalf("expected exactly 1 container in Job, got %d", len(job.Spec.Template.Spec.Containers))
		}

		c := job.Spec.Template.Spec.Containers[0]
		if c.Image != "gari-credentials:latest" {
			t.Errorf("expected Job image 'gari-credentials:latest', got %q", c.Image)
		}

		if len(c.Args) != 0 {
			t.Errorf("expected Job container to have no arguments, got %v", c.Args)
		}

		var hasPodNamespace bool
		for _, envVar := range c.Env {
			if envVar.Name == "POD_NAMESPACE" && envVar.ValueFrom != nil &&
				envVar.ValueFrom.FieldRef != nil && envVar.ValueFrom.FieldRef.FieldPath == "metadata.namespace" {
				hasPodNamespace = true
			}
		}
		if !hasPodNamespace {
			t.Errorf("expected POD_NAMESPACE env var with fieldRef metadata.namespace in Job container")
		}
	}

	if !foundJob {
		t.Fatalf("gari-credentials Job not found in %s", manifestPath)
	}
}
