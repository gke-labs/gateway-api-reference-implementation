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
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
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

	crdVersion, isPreviousMinor, err := resolveConformanceCRDs(os.Getenv("CONFORMANCE_CRDS"))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Install Gateway API CRDs
	h.InstallGatewayAPI(crdVersion)

	// 2. Deploy Controller
	h.DeployController()
	h.WaitForGatewayClassStatus("reference-class", 1*time.Minute)

	// When testing on previous minor CRDs, verify SupportedVersion=True before starting conformance suite
	if isPreviousMinor {
		h.WaitForGatewayClassSupportedVersion("reference-class", 1*time.Minute)
	}

	// 3. Run Conformance Tests
	cfg := h.RESTConfig()

	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("Error adding standard Kubernetes types to scheme: %v", err)
	}
	if err := apiextensionsv1.AddToScheme(s); err != nil {
		t.Fatalf("Error adding apiextensions types to scheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(s); err != nil {
		t.Fatalf("Error adding Gateway API v1 types to scheme: %v", err)
	}
	if err := gatewayv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("Error adding Gateway API v1beta1 types to scheme: %v", err)
	}
	if err := gatewayv1alpha2.AddToScheme(s); err != nil {
		t.Fatalf("Error adding Gateway API v1alpha2 types to scheme: %v", err)
	}

	// Also register in the global scheme
	gatewayv1.AddToScheme(scheme.Scheme)
	gatewayv1beta1.AddToScheme(scheme.Scheme)
	gatewayv1alpha2.AddToScheme(scheme.Scheme)

	cl, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatalf("Error creating Kubernetes client: %v", err)
	}

	cSuite, err := suite.NewConformanceTestSuite(suite.ConformanceOptions{
		Client:     cl,
		RestConfig: cfg,
		ConfigurableOptions: suite.ConfigurableOptions{
			AllowCRDsMismatch:    isPreviousMinor,
			GatewayClassName:     "reference-class",
			Debug:                true,
			CleanupBaseResources: true,
			CleanupTestResources: true,
			UsableNetworkAddresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  state.Ptr(gatewayv1.IPAddressType),
					Value: "172.18.255.240",
				},
			},
			UnusableNetworkAddresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  state.Ptr(gatewayv1.IPAddressType),
					Value: "172.18.255.199",
				},
			},
		},
		ManifestFS: []fs.FS{conformance.Manifests},
	})
	if err != nil {
		t.Fatalf("error creating conformance test suite: %v", err)
	}

	if err := validateSkippedTests(skippedTests, tests.ConformanceTests); err != nil {
		t.Fatalf("%v", err)
	}
	if err := validateSkippedTests(previousMinorSkippedTests, tests.ConformanceTests); err != nil {
		t.Fatalf("%v", err)
	}

	var selectedTests []suite.ConformanceTest
	for _, tc := range tests.ConformanceTests {
		if _, skip := skippedTests[tc.ShortName]; skip {
			continue
		}
		if isPreviousMinor {
			if _, skip := previousMinorSkippedTests[tc.ShortName]; skip {
				continue
			}
		}
		selectedTests = append(selectedTests, tc)
	}

	cSuite.Setup(t, selectedTests)

	cSuite.Run(t, selectedTests)
}

// skippedTests contains the ShortName of tests in tests.ConformanceTests to skip,
// along with the reason or tracking issue for skipping each test.
var skippedTests = map[string]struct{}{
	// Suite claims TLSRouteModeTerminate and TLSRouteModeMixed.
	"TLSRouteListenerTerminateNotSupported":        {},
	"TLSRouteListenerMixedTerminationNotSupported": {},

	// fails: BackendTLSPolicy Accepted condition not set when targeted by GRPCRoute
	"BackendTLSPolicyGRPCRoute": {},
	// fails: BackendTLSPolicy Accepted condition not set when targeted by TLSRoute in terminate mode
	"BackendTLSPolicyTLSRouteTerminate": {},
	// fails: Gateway with maximum length name (253 chars) does not become Programmed
	"GatewayNameMaximumLength": {},
	// fails: controller removes foreign conditions from Gateway status
	"GatewayPreserveForeignConditions": {},
	// fails: GRPCRoute exact hostname does not take precedence over older wildcard route
	"GRPCRouteMultipleRoutesAttachmentSameHostnameIntersection": {},
	// fails: HTTPRoute exact/more specific hostname does not take precedence over older wildcard route
	"HTTPRouteMultipleRoutesAttachmentSameHostnameIntersection": {},
}

// previousMinorSkippedTests contains additional tests to skip when running against the previous minor's CRDs,
// along with the reason or tracking issue for skipping each test.
var previousMinorSkippedTests = map[string]struct{}{
	// Gateway API v1.7's suite sends retry.attempts=0, which the v1.6 CRD schema rejects (requires attempts >= 1).
	"HTTPRouteRetry": {},
}

func validateSkippedTests(skipped map[string]struct{}, suiteTests []suite.ConformanceTest) error {
	known := make(map[string]bool, len(suiteTests))
	for _, tc := range suiteTests {
		known[tc.ShortName] = true
	}
	for name := range skipped {
		if !known[name] {
			return fmt.Errorf("skipped test %q does not exist in conformance suite", name)
		}
	}
	return nil
}

func TestSkippedTestsExist(t *testing.T) {
	if err := validateSkippedTests(skippedTests, tests.ConformanceTests); err != nil {
		t.Fatal(err)
	}
	if err := validateSkippedTests(previousMinorSkippedTests, tests.ConformanceTests); err != nil {
		t.Fatal(err)
	}

	testSkip := map[string]struct{}{
		"NonExistentTest": {},
	}
	if err := validateSkippedTests(testSkip, tests.ConformanceTests); err == nil {
		t.Fatal("expected error for non-existent test in skip set, got nil")
	}
}

func resolveConformanceCRDs(selector string) (version string, isPreviousMinor bool, err error) {
	switch selector {
	case "", "current":
		return gatewayconsts.BundleVersion, false, nil
	case "previous-minor":
		return PreviousMinorCRDVersion, true, nil
	default:
		return "", false, fmt.Errorf("unknown CONFORMANCE_CRDS value %q: valid options are empty, \"current\", or \"previous-minor\"", selector)
	}
}

func TestResolveConformanceCRDs(t *testing.T) {
	testCases := []struct {
		selector        string
		expectedVersion string
		expectedPrev    bool
		expectErr       bool
	}{
		{"", gatewayconsts.BundleVersion, false, false},
		{"current", gatewayconsts.BundleVersion, false, false},
		{"previous-minor", PreviousMinorCRDVersion, true, false},
		{"unknown", "", false, true},
	}
	for _, tc := range testCases {
		v, prev, err := resolveConformanceCRDs(tc.selector)
		if (err != nil) != tc.expectErr {
			t.Errorf("selector %q: got err %v, want err %v", tc.selector, err, tc.expectErr)
		}
		if !tc.expectErr {
			if v != tc.expectedVersion || prev != tc.expectedPrev {
				t.Errorf("selector %q: got version %s prev %v, want version %s prev %v", tc.selector, v, prev, tc.expectedVersion, tc.expectedPrev)
			}
		}
	}
}
