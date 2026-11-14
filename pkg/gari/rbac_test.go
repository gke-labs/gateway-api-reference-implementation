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

package gari_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
	"sigs.k8s.io/yaml"
)

// TestController_NarrowedCRDPermissions verifies that the controller starts, becomes ready,
// detects runtime installation of optional CRDs, and tracks bundle-version updates when running
// with the narrowed RBAC permissions from k8s/controller.yaml (impersonated service account).
func TestController_NarrowedCRDPermissions(t *testing.T) {
	var (
		logMu sync.Mutex
		logs  []string
	)
	logger := funcr.New(func(prefix, args string) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, prefix+" "+args)
	}, funcr.Options{})

	env := testenv.Start(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	deleteIfExists := func(obj client.Object) {
		if err := env.Client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("failed to delete %T %s: %v", obj, obj.GetName(), err)
		}
	}

	// 1. Read and parse RBAC objects from k8s/controller.yaml
	manifestPath := filepath.Join("..", "..", "k8s", "controller.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundRole, foundBinding, foundSA bool

	for _, doc := range docs {
		var typeMeta metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(doc), &typeMeta); err != nil {
			continue
		}
		switch typeMeta.Kind {
		case "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := yaml.Unmarshal([]byte(doc), &sa); err == nil && sa.Name == "gari-controller" {
				foundSA = true
				deleteIfExists(&sa)
				if err := env.Client.Create(ctx, &sa); err != nil && !apierrors.IsAlreadyExists(err) {
					t.Fatalf("failed to create ServiceAccount: %v", err)
				}
			}
		case "ClusterRole":
			var cr rbacv1.ClusterRole
			if err := yaml.Unmarshal([]byte(doc), &cr); err == nil && cr.Name == "gari-controller" {
				foundRole = true
				deleteIfExists(&cr)
				if err := env.Client.Create(ctx, &cr); err != nil && !apierrors.IsAlreadyExists(err) {
					t.Fatalf("failed to create ClusterRole: %v", err)
				}
			}
		case "ClusterRoleBinding":
			var crb rbacv1.ClusterRoleBinding
			if err := yaml.Unmarshal([]byte(doc), &crb); err == nil && crb.Name == "gari-controller" {
				foundBinding = true
				deleteIfExists(&crb)
				if err := env.Client.Create(ctx, &crb); err != nil && !apierrors.IsAlreadyExists(err) {
					t.Fatalf("failed to create ClusterRoleBinding: %v", err)
				}
			}
		}
	}

	if !foundSA || !foundRole || !foundBinding {
		t.Fatalf("expected ServiceAccount, ClusterRole, and ClusterRoleBinding for gari-controller in %s", manifestPath)
	}

	// 2. Remove TLSRoute CRD so it is unserved initially
	tlsCRD := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: controller.TLSRouteCRDName},
	}
	deleteIfExists(tlsCRD)
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		var check apiextensionsv1.CustomResourceDefinition
		err := env.Client.Get(ctx, client.ObjectKey{Name: controller.TLSRouteCRDName}, &check)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for TLSRoute CRD deletion: %v", err)
	}

	// 3. Configure impersonated client for the ServiceAccount
	impersonatedConfig := rest.CopyConfig(env.Config)
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:default:gari-controller",
	}

	impClient, err := client.New(impersonatedConfig, client.Options{Scheme: env.Scheme})
	if err != nil {
		t.Fatalf("failed to create impersonated client: %v", err)
	}

	// Confirm cluster-wide list is forbidden by RBAC
	var crdList apiextensionsv1.CustomResourceDefinitionList
	if err := impClient.List(ctx, &crdList); err == nil {
		t.Fatalf("expected cluster-wide CRD list to be forbidden by RBAC, but got success")
	} else if !apierrors.IsForbidden(err) {
		t.Fatalf("expected 403 Forbidden for cluster-wide CRD list, got: %v", err)
	}

	// 4. Create GatewayClass to exercise controller reconciliation and status
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controller.DefaultControllerName),
		},
	}
	deleteIfExists(gc)
	if err := env.Client.Create(ctx, gc); err != nil {
		t.Fatalf("failed to create GatewayClass: %v", err)
	}

	// 5. Start GARI controller with impersonated config
	skipNameValidation := true
	mgr, err := ctrl.NewManager(impersonatedConfig, ctrl.Options{
		Scheme:  env.Scheme,
		Logger:  logger,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	opts := gari.DefaultOptions()
	opts.RestConfig = impersonatedConfig
	opts.Scheme = env.Scheme
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false

	server, err := gari.NewWithManager(mgr, opts)
	if err != nil {
		t.Fatalf("gari.NewWithManager failed: %v", err)
	}

	go func() {
		if err := server.Manager().Start(ctx); err != nil {
			t.Logf("manager stopped: %v", err)
		}
	}()

	// Verify controller starts and becomes ready: GatewayClass is reconciled with Accepted=True and SupportedVersion=True
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		var updatedGC gatewayv1.GatewayClass
		if err := env.Client.Get(ctx, client.ObjectKey{Name: "reference-class"}, &updatedGC); err != nil {
			return false, nil
		}
		var accepted, supported bool
		for _, c := range updatedGC.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayClassConditionStatusAccepted) && c.Status == metav1.ConditionTrue {
				accepted = true
			}
			if c.Type == string(gatewayv1.GatewayClassConditionStatusSupportedVersion) &&
				c.Status == metav1.ConditionTrue &&
				c.Reason == string(gatewayv1.GatewayClassReasonSupportedVersion) {
				supported = true
			}
		}
		return accepted && supported, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for GatewayClass to become ready with Accepted=True and SupportedVersion=True: %v", err)
	}

	// 6. Install optional Gateway API CRD (TLSRoute) at runtime
	newTLSCRD := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.TLSRouteCRDName,
			Annotations: map[string]string{
				"api-approved.kubernetes.io": "unapproved, test-only",
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "gateway.networking.k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:   "tlsroutes",
				Singular: "tlsroute",
				Kind:     "TLSRoute",
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
						},
					},
				},
			},
		},
	}
	if err := env.Client.Create(ctx, newTLSCRD); err != nil {
		t.Fatalf("failed to create TLSRoute CRD at runtime: %v", err)
	}

	// Verify runtime detection of unserved CRD addition via controller logs
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		logMu.Lock()
		defer logMu.Unlock()
		for _, line := range logs {
			if strings.Contains(line, "Gateway API CRD added for unserved kind; restart controller deployment to serve it") {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for controller to detect runtime TLSRoute installation: %v", err)
	}

	// 7. Pick up bundle-version change at runtime: update Gateway CRD bundle-version to an incompatible version
	mismatchedBV := "v0.0.1"
	var gwCRD apiextensionsv1.CustomResourceDefinition
	if err := env.Client.Get(ctx, client.ObjectKey{Name: controller.GatewayCRDName}, &gwCRD); err != nil {
		t.Fatalf("failed to get Gateway CRD: %v", err)
	}
	if gwCRD.Annotations == nil {
		gwCRD.Annotations = make(map[string]string)
	}
	gwCRD.Annotations[gatewayconsts.BundleVersionAnnotation] = mismatchedBV
	if err := env.Client.Update(ctx, &gwCRD); err != nil {
		t.Fatalf("failed to update Gateway CRD bundle-version annotation: %v", err)
	}

	// Verify controller picks up bundle-version change through public GatewayClass status (SupportedVersion condition changes to UnsupportedVersion)
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		var updatedGC gatewayv1.GatewayClass
		if err := env.Client.Get(ctx, client.ObjectKey{Name: "reference-class"}, &updatedGC); err != nil {
			return false, nil
		}
		for _, c := range updatedGC.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayClassConditionStatusSupportedVersion) &&
				c.Status == metav1.ConditionFalse &&
				c.Reason == string(gatewayv1.GatewayClassReasonUnsupportedVersion) {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for GatewayClass SupportedVersion condition to update to UnsupportedVersion: %v", err)
	}
}
