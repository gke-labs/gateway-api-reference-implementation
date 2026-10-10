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

	// 6. Deploy snigateway controller with 2 replicas
	frontendAddr := fmt.Sprintf("snigateway-frontend.%s.svc.cluster.local:443", frontendNS)
	h.DeploySNIGatewayController(infraCerts, frontendAddr, 2)
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

	dumpLogsIfFailed := func(currentT *testing.T) {
		if currentT.Failed() || t.Failed() {
			currentT.Log("Dumping snigateway-frontend and snigateway-controller logs on test failure:")
			h.DumpDeploymentLogs(frontendNS, "snigateway-frontend")
			h.DumpDeploymentLogs("default", "snigateway-controller")
		}
	}
	t.Cleanup(func() { dumpLogsIfFailed(t) })

	// Wait for controller replicas to reconcile and register
	time.Sleep(5 * time.Second)

	// Assertion 1: Valid SNI request terminates TLS with Gateway cert and reaches backend, carrying client IP
	t.Run("Valid SNI reaches backend with Gateway TLS cert and real client IP", func(t *testing.T) {
		t.Cleanup(func() { dumpLogsIfFailed(t) })
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
		if !strings.Contains(logs, "X-Forwarded-For") {
			t.Errorf("Expected X-Forwarded-For header containing real client IP in backend response, got: %s", logs)
		}
		clientPodIP := h.GetPodIP(clientPod)
		t.Logf("Client Pod IP: %s", clientPodIP)
		if clientPodIP == "" {
			t.Errorf("Expected non-empty client pod IP")
		} else if !strings.Contains(logs, clientPodIP) {
			t.Errorf("Expected X-Forwarded-For to contain client pod IP %s, got logs: %s", clientPodIP, logs)
		}

		// Verify default auto deployment established QUIC session (UDP works in kind, so auto requires QUIC)
		ctrlLogs := h.WaitForControllerLog("Established QUIC session", 30*time.Second)
		t.Logf("Controller logs for default auto mode: %s", ctrlLogs)
		if strings.Contains(ctrlLogs, "falling back to TCP pool transport") || strings.Contains(ctrlLogs, "Established TCP fallback session") {
			t.Errorf("Auto mode unexpectedly fell back to TCP in default deployment, logs: %s", ctrlLogs)
		}
	})

	// Assertion 2: Unregistered SNI hostname is rejected (connection closed)
	t.Run("Unregistered SNI is rejected", func(t *testing.T) {
		t.Cleanup(func() { dumpLogsIfFailed(t) })
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
		t.Cleanup(func() { dumpLogsIfFailed(t) })
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

		h.KubectlApplyContent(h.SNIGatewayManifestWithName("disallowed-gw", "disallowed.example.com", "disallowed-tls-cert"))
		h.KubectlApplyContent(h.SNIHTTPRouteManifest("disallowed-route", "disallowed-gw", "disallowed.example.com", "backend", 8080))
		t.Cleanup(func() {
			h.runCmd("kubectl", "delete", "httproute", "disallowed-route", "--namespace=default", "--ignore-not-found")
			h.runCmd("kubectl", "delete", "gateway", "disallowed-gw", "--namespace=default", "--ignore-not-found")
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

	// Assertion 5: Running two replicas, force-killing one, and verifying failover with zero client retries
	t.Run("Kill one of two replicas and verify connections keep succeeding with zero retries", func(t *testing.T) {
		t.Cleanup(func() { dumpLogsIfFailed(t) })

		// Find one of the running controller replica pods
		podListOut := h.runCmd("kubectl", "get", "pods", "--namespace=default", "-l", "app=snigateway-controller", "--field-selector=status.phase=Running", "-o", "jsonpath={.items[*].metadata.name}")
		pods := strings.Fields(podListOut)
		if len(pods) < 2 {
			t.Fatalf("expected at least 2 running snigateway-controller pods, got %d: %v", len(pods), pods)
		}

		// Force-kill the first replica so its pooled connections become dead without clean session close
		h.runCmd("kubectl", "delete", "pod", pods[0], "--namespace=default", "--grace-period=0", "--force")

		// Immediately send multiple requests with --retries=0 to verify frontend replay-until-first-byte failover
		for i := 1; i <= 5; i++ {
			clientPod := fmt.Sprintf("sni-client-failover-%d", i)
			h.DeletePod(clientPod)
			h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
				"client",
				"--connect-to=" + frontendAddr,
				"--sni=echo.snigateway.test",
				"--insecure",
				"--retries=0",
				"https://echo.snigateway.test/",
			}))
			h.WaitForPodSuccess(clientPod, 1*time.Minute)
			logs := h.GetPodLogs(clientPod)
			t.Logf("Failover client %d logs: %s", i, logs)

			if !strings.Contains(logs, "Status: 200 OK") {
				t.Errorf("Request %d: Expected 200 OK after killing replica, got: %s", i, logs)
			}
			if !strings.Contains(logs, "\"hostname\":\"echo.snigateway.test\"") && !strings.Contains(logs, "\"host\": \"echo.snigateway.test\"") {
				t.Errorf("Request %d: Expected hostname echo.snigateway.test in response body, got: %s", i, logs)
			}
		}
	})

	// Assertion 6: Deploy controller with explicit --tunnel-transport=tcp and verify connections succeed
	t.Run("Controller with --tunnel-transport=tcp succeeds", func(t *testing.T) {
		t.Cleanup(func() { dumpLogsIfFailed(t) })

		h.DeploySNIGatewayController(infraCerts, frontendAddr, 1, "tcp")

		ctrlLogs := h.WaitForControllerLog("Established TCP pool session", 30*time.Second)
		t.Logf("Controller logs for TCP mode: %s", ctrlLogs)

		clientPod := "sni-client-tcp-mode"
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
		t.Logf("TCP mode client logs: %s", logs)

		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK for TCP mode, got: %s", logs)
		}
	})

	// Assertion 7: Deploy controller with explicit --tunnel-transport=quic and verify connections succeed
	t.Run("Controller with --tunnel-transport=quic succeeds", func(t *testing.T) {
		t.Cleanup(func() { dumpLogsIfFailed(t) })

		h.DeploySNIGatewayController(infraCerts, frontendAddr, 1, "quic")
		ctrlLogsQUIC := h.WaitForControllerLog("Established QUIC session", 30*time.Second)
		t.Logf("Controller logs for QUIC mode: %s", ctrlLogsQUIC)

		clientPod := "sni-client-quic-mode"
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
		t.Logf("QUIC mode client logs: %s", logs)

		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK for QUIC mode, got: %s", logs)
		}
	})

	// Assertion 8: Auto fallback when frontend UDP port is unreachable, with probe recovery when UDP restored
	t.Run("Auto fallback to TCP pool when UDP is unreachable and recovery to QUIC", func(t *testing.T) {
		fallbackNS := "snigateway-frontend-tcp-only"
		t.Cleanup(func() {
			if t.Failed() {
				t.Log("Dumping fallbackNS snigateway-frontend and controller logs on failure:")
				h.DumpDeploymentLogs(fallbackNS, "snigateway-frontend")
				h.DumpDeploymentLogs("default", "snigateway-controller")
			}
		})
		h.DeploySNIGatewayFrontendTCPOnly(fallbackNS, infraCerts)
		t.Cleanup(func() {
			h.runCmd("kubectl", "delete", "namespace", fallbackNS, "--ignore-not-found")
		})

		fallbackAddr := fmt.Sprintf("snigateway-frontend.%s.svc.cluster.local:443", fallbackNS)
		h.DeploySNIGatewayController(infraCerts, fallbackAddr, 1, "auto", "--quic-probe-interval=2s")

		ctrlLogsFB := h.WaitForControllerLog("Established TCP fallback session", 30*time.Second)
		t.Logf("Controller logs during TCP fallback: %s", ctrlLogsFB)
		if !strings.Contains(ctrlLogsFB, "falling back to TCP pool transport") {
			t.Errorf("Expected controller logs to show 'falling back to TCP pool transport', got: %s", ctrlLogsFB)
		}

		clientPod := "sni-client-fallback"
		h.DeletePod(clientPod)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPod, []string{
			"client",
			"--connect-to=" + fallbackAddr,
			"--sni=echo.snigateway.test",
			"--insecure",
			"https://echo.snigateway.test/",
		}))
		h.WaitForPodSuccess(clientPod, 1*time.Minute)
		logs := h.GetPodLogs(clientPod)
		t.Logf("Auto fallback client logs: %s", logs)

		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK for auto fallback mode, got: %s", logs)
		}

		// Now upgrade the frontend service to expose UDP port 443 as well (simulating UDP unblocking)
		h.DeploySNIGatewayFrontend(fallbackNS, infraCerts)

		// Wait for background probe to detect UDP and switch to QUIC:
		// Require "QUIC probe succeeded" followed by a QUIC session being established, and nothing re-establishing TCP fallback after it.
		var ctrlLogsAfterRecovery string
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			logs := h.GetControllerLogs()
			probeIdx := strings.LastIndex(logs, "QUIC probe succeeded")
			quicIdx := strings.LastIndex(logs, "Established QUIC session")
			if probeIdx != -1 && quicIdx > probeIdx {
				ctrlLogsAfterRecovery = logs
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if ctrlLogsAfterRecovery == "" {
			t.Fatalf("Timed out waiting for 'QUIC probe succeeded' followed by 'Established QUIC session'; current logs:\n%s", h.GetControllerLogs())
		}
		t.Logf("Controller logs after probe recovery: %s", ctrlLogsAfterRecovery)

		quicIdx := strings.LastIndex(ctrlLogsAfterRecovery, "Established QUIC session")
		afterQUIC := ctrlLogsAfterRecovery[quicIdx:]
		if strings.Contains(afterQUIC, "Established TCP fallback session") || strings.Contains(afterQUIC, "falling back to TCP pool transport") {
			t.Errorf("Expected nothing re-establishing TCP fallback after QUIC recovery, but found TCP fallback in logs after QUIC session:\n%s", afterQUIC)
		}

		clientPodRecovered := "sni-client-recovered"
		h.DeletePod(clientPodRecovered)
		h.KubectlApplyContent(h.SNIClientPodManifest(clientPodRecovered, []string{
			"client",
			"--connect-to=" + fallbackAddr,
			"--sni=echo.snigateway.test",
			"--insecure",
			"https://echo.snigateway.test/",
		}))
		h.WaitForPodSuccess(clientPodRecovered, 1*time.Minute)
		recLogs := h.GetPodLogs(clientPodRecovered)
		t.Logf("Recovered QUIC client logs: %s", recLogs)

		if !strings.Contains(recLogs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK after probe recovery to QUIC, got: %s", recLogs)
		}
	})
}
