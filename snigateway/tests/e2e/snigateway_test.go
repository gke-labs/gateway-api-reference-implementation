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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
)

func TestSNIGateway(t *testing.T) {
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

	// 2. Build images and load into kind
	gitRoot := h.GetGitRoot()
	h.DockerBuild("snigateway:e2e", filepath.Join(gitRoot, "images/snigateway/Dockerfile"), gitRoot)
	h.KindLoad("snigateway:e2e")
	h.DockerBuild("snigateway-frontend:e2e", filepath.Join(gitRoot, "images/snigateway-frontend/Dockerfile"), gitRoot)
	h.KindLoad("snigateway-frontend:e2e")

	// 3. Deploy Backend (Toolbox Server)
	h.DeployBackend()

	// 4. Generate mTLS infrastructure certificates
	infraCerts, err := certs.GenerateAll("snigateway.internal", "snigateway-client")
	if err != nil {
		t.Fatalf("Failed to generate infra certs: %v", err)
	}

	// 5. Deploy snigateway-frontend inside the cluster
	frontendNS := "snigateway-frontend"
	h.DeploySNIGatewayFrontend(frontendNS, infraCerts)
	t.Cleanup(func() {
		h.runCmd("kubectl", "delete", "namespace", frontendNS, "--ignore-not-found")
	})

	// 6. Deploy snigateway controller
	frontendAddr := fmt.Sprintf("snigateway-frontend.%s.svc.cluster.local:443", frontendNS)
	h.DeploySNIGatewayController(infraCerts, frontendAddr)
	t.Cleanup(func() {
		h.runCmd("kubectl", "delete", "deployment", "snigateway-controller", "--namespace=default", "--ignore-not-found")
		h.runCmd("kubectl", "delete", "secret", "snigateway-client-cert", "--namespace=default", "--ignore-not-found")
		h.runCmd("kubectl", "delete", "gatewayclass", "snigateway", "--ignore-not-found")
	})

	// 7. Generate TLS certificates for echo.snigateway.test and echo2.snigateway.test
	echoCertPEM, echoKeyPEM, err := GenerateTestCertificate("echo.snigateway.test", "echo.snigateway.test")
	if err != nil {
		t.Fatalf("Failed to generate echo test cert: %v", err)
	}
	h.CreateTLSSecret("echo-tls-cert", "default", echoCertPEM, echoKeyPEM)
	t.Cleanup(func() {
		h.runCmd("kubectl", "delete", "secret", "echo-tls-cert", "--namespace=default", "--ignore-not-found")
	})

	echo2CertPEM, echo2KeyPEM, err := GenerateTestCertificate("echo2.snigateway.test", "echo2.snigateway.test")
	if err != nil {
		t.Fatalf("Failed to generate echo2 test cert: %v", err)
	}
	h.CreateTLSSecret("echo2-tls-cert", "default", echo2CertPEM, echo2KeyPEM)
	t.Cleanup(func() {
		h.runCmd("kubectl", "delete", "secret", "echo2-tls-cert", "--namespace=default", "--ignore-not-found")
	})

	// 8. Create Gateway and HTTPRoute
	h.KubectlApplyContent(h.SNIGatewayManifest("echo.snigateway.test", "echo-tls-cert"))
	h.KubectlApplyContent(h.SNIHTTPRouteManifest("echo-route", "snigateway-test", "echo.snigateway.test", "backend", 8080))
	t.Cleanup(func() {
		h.runCmd("kubectl", "delete", "httproute", "echo-route", "--namespace=default", "--ignore-not-found")
		h.runCmd("kubectl", "delete", "httproute", "echo2-route", "--namespace=default", "--ignore-not-found")
		h.runCmd("kubectl", "delete", "gateway", "snigateway-test", "--namespace=default", "--ignore-not-found")
	})

	// Wait for controller to reconcile and register
	time.Sleep(5 * time.Second)

	// Assertion 1: Valid SNI request terminates TLS with Gateway cert and reaches backend
	t.Run("Valid SNI reaches backend with Gateway TLS cert", func(t *testing.T) {
		clientPod := "sni-client-valid"
		h.DeletePod(clientPod)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
			"client",
			"--connect-to=" + frontendAddr,
			"--sni=echo.snigateway.test",
			"--insecure",
			"https://echo.snigateway.test/",
		}))
		h.WaitForPodSuccess(clientPod, 1*time.Minute)
		logs := h.GetPodLogs(clientPod)
		t.Logf("Valid client logs: %s", logs)

		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK, got: %s", logs)
		}
		if !strings.Contains(logs, "\"hostname\":\"echo.snigateway.test\"") && !strings.Contains(logs, "\"host\": \"echo.snigateway.test\"") {
			t.Errorf("Expected hostname echo.snigateway.test in response body, got: %s", logs)
		}
		if !strings.Contains(logs, "PeerCertSubjectCN: echo.snigateway.test") && !strings.Contains(logs, "PeerCertDNSNames: echo.snigateway.test") {
			t.Errorf("Expected presented cert to be Gateway listener cert for echo.snigateway.test, got: %s", logs)
		}
		if strings.Contains(logs, "snigateway.internal") {
			t.Errorf("Presented cert should NOT be frontend internal cert, got: %s", logs)
		}
	})

	// Assertion 2: Unregistered SNI hostname is rejected (connection closed)
	t.Run("Unregistered SNI is rejected", func(t *testing.T) {
		clientPod := "sni-client-unregistered"
		h.DeletePod(clientPod)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
			"client",
			"--connect-to=" + frontendAddr,
			"--sni=unregistered.snigateway.test",
			"--insecure",
			"--expect-fail",
			"https://unregistered.snigateway.test/",
		}))
		h.WaitForPodSuccess(clientPod, 1*time.Minute)
		logs := h.GetPodLogs(clientPod)
		t.Logf("Unregistered client logs: %s", logs)

		if !strings.Contains(logs, "Connection rejected as expected") {
			t.Errorf("Expected connection to be rejected, got logs: %s", logs)
		}
	})

	// Assertion 3: Adding a second HTTPS listener hostname to the Gateway makes it routable without restarting
	t.Run("Adding second HTTPS listener dynamically registers and routes", func(t *testing.T) {
		// Update Gateway with two listeners: echo.snigateway.test and echo2.snigateway.test
		h.KubectlApplyContent(h.SNIMultiListenerGatewayManifest())
		h.KubectlApplyContent(h.SNIHTTPRouteManifest("echo2-route", "snigateway-test", "echo2.snigateway.test", "backend", 8080))

		// Wait for reconciliation and registration
		time.Sleep(5 * time.Second)

		clientPod := "sni-client-second"
		h.DeletePod(clientPod)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
			"client",
			"--connect-to=" + frontendAddr,
			"--sni=echo2.snigateway.test",
			"--insecure",
			"https://echo2.snigateway.test/",
		}))
		h.WaitForPodSuccess(clientPod, 1*time.Minute)
		logs := h.GetPodLogs(clientPod)
		t.Logf("Second listener client logs: %s", logs)

		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK for second listener, got: %s", logs)
		}
		if !strings.Contains(logs, "\"hostname\":\"echo2.snigateway.test\"") && !strings.Contains(logs, "\"host\": \"echo2.snigateway.test\"") {
			t.Errorf("Expected hostname echo2.snigateway.test in response body, got: %s", logs)
		}
		if !strings.Contains(logs, "PeerCertSubjectCN: echo2.snigateway.test") && !strings.Contains(logs, "PeerCertDNSNames: echo2.snigateway.test") {
			t.Errorf("Expected presented cert to be Gateway listener cert for echo2.snigateway.test, got: %s", logs)
		}
	})

	// Assertion 4: Hostname outside client CA allowlist cannot be registered and is not routed
	t.Run("Hostname outside client CA allowlist is rejected and not routed", func(t *testing.T) {
		disallowedCertPEM, disallowedKeyPEM, err := GenerateTestCertificate("disallowed.example.com", "disallowed.example.com")
		if err != nil {
			t.Fatalf("Failed to generate disallowed test cert: %v", err)
		}
		h.CreateTLSSecret("disallowed-tls-cert", "default", disallowedCertPEM, disallowedKeyPEM)
		t.Cleanup(func() {
			h.runCmd("kubectl", "delete", "secret", "disallowed-tls-cert", "--namespace=default", "--ignore-not-found")
		})

		h.KubectlApplyContent(h.SNIGatewayManifest("disallowed.example.com", "disallowed-tls-cert"))
		h.KubectlApplyContent(h.SNIHTTPRouteManifest("disallowed-route", "snigateway-test", "disallowed.example.com", "backend", 8080))
		t.Cleanup(func() {
			h.runCmd("kubectl", "delete", "httproute", "disallowed-route", "--namespace=default", "--ignore-not-found")
		})

		// Wait for controller reconciliation attempt
		time.Sleep(5 * time.Second)

		clientPod := "sni-client-disallowed"
		h.DeletePod(clientPod)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
			"client",
			"--connect-to=" + frontendAddr,
			"--sni=disallowed.example.com",
			"--insecure",
			"--expect-fail",
			"https://disallowed.example.com/",
		}))
		h.WaitForPodSuccess(clientPod, 1*time.Minute)
		logs := h.GetPodLogs(clientPod)
		t.Logf("Disallowed client logs: %s", logs)

		if !strings.Contains(logs, "Connection rejected as expected") {
			t.Errorf("Expected connection to disallowed hostname to be rejected, got logs: %s", logs)
		}
	})
}
