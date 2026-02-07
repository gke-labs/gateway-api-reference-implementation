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

package e2e

import (
	"io/fs"
	"os"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func TestConformance(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "kind"
	}

	h := NewHarness(t, clusterName)
	h.Setup()

	// 1. Install Gateway API CRDs
	h.InstallGatewayAPI()

	// 2. Deploy Controller
	h.DeployController()

	// 3. Run Conformance Tests
	cfg := h.RESTConfig()

	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("Error adding standard Kubernetes types to scheme: %v", err)
	}
	if err := v1.AddToScheme(s); err != nil {
		t.Fatalf("Error adding apiextensions types to scheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(s); err != nil {
		t.Fatalf("Error adding Gateway API types to scheme: %v", err)
	}

	cl, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatalf("Error creating Kubernetes client: %v", err)
	}

	cSuite, err := suite.NewConformanceTestSuite(suite.ConformanceOptions{
		Client:                     cl,
		GatewayClassName:           "reference-class",
		Debug:                      true,
		CleanupBaseResources:       true,
		EnableAllSupportedFeatures: true,
		ManifestFS:                 []fs.FS{conformance.Manifests},
	})
	if err != nil {
		t.Fatalf("error creating conformance test suite: %v", err)
	}

	selectedTests := []suite.ConformanceTest{
		tests.HTTPRouteSimpleSameNamespace,
		tests.HTTPRouteMatching,
		tests.HTTPRouteExactPathMatching,
	}

	cSuite.Setup(t, selectedTests)

	cSuite.Run(t, selectedTests)
}
