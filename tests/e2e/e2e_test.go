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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

func TestGatewayAPI(t *testing.T) {
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
	h.InstallGatewayAPI(gatewayconsts.BundleVersion)

	// 2. Deploy Controller
	h.DeployController()

	// 3. Deploy Backend (Toolbox Server)
	h.DeployBackend()

	// 4. Create Gateway API Resources
	certPEM, keyPEM, err := GenerateTestCertificate("example.com", "example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}
	h.CreateTLSSecret("gateway-tls-cert", "default", certPEM, keyPEM)

	h.KubectlApplyContent(h.ExampleGatewayManifest())
	gwAddr := h.WaitForGatewayAddress("reference-gateway", "default", 1*time.Minute)

	// 5. Run Client Pod (HTTP)
	clientPodName := "test-client"
	h.DeletePod(clientPodName)

	h.KubectlApplyContent(h.ClientManifest(fmt.Sprintf("http://%s", gwAddr), "example.com"))
	h.WaitForPodSuccess(clientPodName, 1*time.Minute)

	logs := h.GetPodLogs(clientPodName)
	t.Logf("Client logs (HTTP): %s", logs)

	// 6. Verify HTTP
	if !strings.Contains(logs, "Status: 200 OK") || (!strings.Contains(logs, "\"hostname\":\"example.com\"") && !strings.Contains(logs, "\"host\": \"example.com\"")) {
		controllerLogs := h.RunCmd("kubectl", "logs", "deployment/gari-controller", "--namespace=default")
		t.Logf("Controller logs: %s", controllerLogs)
		if !strings.Contains(logs, "Status: 200 OK") {
			t.Errorf("Expected 200 OK, got: %s", logs)
		}
		if !strings.Contains(logs, "\"hostname\":\"example.com\"") && !strings.Contains(logs, "\"host\": \"example.com\"") {
			t.Errorf("Expected hostname example.com in response body, got: %s", logs)
		}
	}

	// 7. Run Client Pod (HTTPS - verify Alt-Svc header and certificate)
	httpsClientPodName := "test-client-https"
	h.DeletePod(httpsClientPodName)

	h.KubectlApplyContent(h.ClientManifestWithArgs(httpsClientPodName, "--insecure", "--sni", "example.com", fmt.Sprintf("https://%s:443", gwAddr), "example.com"))
	h.WaitForPodSuccess(httpsClientPodName, 1*time.Minute)

	httpsLogs := h.GetPodLogs(httpsClientPodName)
	t.Logf("Client logs (HTTPS): %s", httpsLogs)
	if !strings.Contains(httpsLogs, "Status: 200 OK") {
		t.Errorf("Expected HTTPS 200 OK, got: %s", httpsLogs)
	}
	if !strings.Contains(httpsLogs, "Header-Alt-Svc: h3=\":443\"; ma=86400") {
		t.Errorf("Expected Alt-Svc header advertising h3=\":443\"; ma=86400, got: %s", httpsLogs)
	}
	if !strings.Contains(httpsLogs, "PeerCertDNSNames: example.com") {
		t.Errorf("Expected PeerCertDNSNames example.com, got: %s", httpsLogs)
	}

	// 8. Run Client Pod (HTTP/3 over QUIC)
	h3ClientPodName := "test-client-http3"
	h.DeletePod(h3ClientPodName)

	h.KubectlApplyContent(h.ClientManifestWithArgs(h3ClientPodName, "--http3", "--insecure", "--sni", "example.com", fmt.Sprintf("https://%s:443", gwAddr), "example.com"))
	h.WaitForPodSuccess(h3ClientPodName, 1*time.Minute)

	h3Logs := h.GetPodLogs(h3ClientPodName)
	t.Logf("Client logs (HTTP/3): %s", h3Logs)
	if !strings.Contains(h3Logs, "Status: 200 OK") || (!strings.Contains(h3Logs, "\"hostname\":\"example.com\"") && !strings.Contains(h3Logs, "\"host\": \"example.com\"")) {
		t.Errorf("Expected HTTP/3 200 OK with hostname example.com, got: %s", h3Logs)
	}

	// 9. Verify Multi-Gateway Isolation & Deletion Cleanup
	secondGwManifest := `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: second-gateway
  namespace: default
spec:
  gatewayClassName: reference-class
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: second-route
  namespace: default
spec:
  parentRefs:
  - name: second-gateway
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`
	h.KubectlApplyContent(secondGwManifest)
	secondGwAddr := h.WaitForGatewayAddress("second-gateway", "default", 1*time.Minute)
	if secondGwAddr == gwAddr {
		t.Errorf("Expected second Gateway to get distinct address, got same: %s", secondGwAddr)
	}

	// Verify Service, Deployment, ServiceAccount, Role, RoleBinding, and Secret were created for second-gateway
	secondResName := singlepod.ResourceNameForGateway("second-gateway")
	out := h.RunCmd("kubectl", "get", "svc", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(out) != secondResName {
		t.Errorf("Expected Service %s to exist, got: %s", secondResName, out)
	}
	deployOut := h.RunCmd("kubectl", "get", "deployment", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(deployOut) != secondResName {
		t.Errorf("Expected Deployment %s to exist, got: %s", secondResName, deployOut)
	}
	saOut := h.RunCmd("kubectl", "get", "serviceaccount", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(saOut) != secondResName {
		t.Errorf("Expected ServiceAccount %s to exist, got: %s", secondResName, saOut)
	}
	roleOut := h.RunCmd("kubectl", "get", "role", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(roleOut) != secondResName {
		t.Errorf("Expected Role %s to exist, got: %s", secondResName, roleOut)
	}
	rbOut := h.RunCmd("kubectl", "get", "rolebinding", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(rbOut) != secondResName {
		t.Errorf("Expected RoleBinding %s to exist, got: %s", secondResName, rbOut)
	}
	secOut := h.RunCmd("kubectl", "get", "secret", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(secOut) != secondResName {
		t.Errorf("Expected Secret %s to exist, got: %s", secondResName, secOut)
	}

	// Verify gari-dataplane ClusterRole does not exist
	crCheck := runCmdAllowError(h, "kubectl", "get", "clusterrole", "gari-dataplane")
	if !strings.Contains(crCheck, "NotFound") && !strings.Contains(crCheck, "not found") {
		t.Errorf("Expected ClusterRole gari-dataplane to not exist, got: %s", crCheck)
	}

	// Verify GatewayClass has SupportedVersion=True condition
	gcSupportedCond := h.RunCmd("kubectl", "get", "gatewayclass", "reference-class", "-o", "jsonpath={.status.conditions[?(@.type==\"SupportedVersion\")].status}")
	if strings.TrimSpace(gcSupportedCond) != "True" {
		t.Errorf("Expected GatewayClass SupportedVersion=True, got: %s", gcSupportedCond)
	}
	gcSupportedReason := h.RunCmd("kubectl", "get", "gatewayclass", "reference-class", "-o", "jsonpath={.status.conditions[?(@.type==\"SupportedVersion\")].reason}")
	if strings.TrimSpace(gcSupportedReason) != "SupportedVersion" {
		t.Errorf("Expected GatewayClass SupportedVersion reason=SupportedVersion, got: %s", gcSupportedReason)
	}

	// Delete second-gateway and verify Service, Deployment, ServiceAccount, Role, RoleBinding, and Secret are cleaned up
	h.RunCmd("kubectl", "delete", "gateway", "second-gateway", "--namespace=default")
	h.WaitForResourceDeletion("svc", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("deployment", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("serviceaccount", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("role", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("rolebinding", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("secret", secondResName, "default", 30*time.Second)

	// 10. Verify Live Switch between LoadBalancer and ClusterIP via parametersRef ConfigMap
	liveSwitchCM := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: live-switch-params
  namespace: default
data:
  serviceType: LoadBalancer
  externalTrafficPolicy: Local
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: live-switch-gw
  namespace: default
spec:
  gatewayClassName: reference-class
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: live-switch-params
`
	h.KubectlApplyContent(liveSwitchCM)
	liveGwAddr := h.WaitForGatewayAddress("live-switch-gw", "default", 1*time.Minute)
	if liveGwAddr == "" {
		t.Fatalf("Expected live-switch-gw to get an address")
	}

	liveResName := singlepod.ResourceNameForGateway("live-switch-gw")
	svcType := strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.spec.type}"))
	if svcType != "LoadBalancer" {
		t.Errorf("Expected Service type LoadBalancer, got: %s", svcType)
	}
	etp := strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.spec.externalTrafficPolicy}"))
	if etp != "Local" {
		t.Errorf("Expected externalTrafficPolicy Local, got: %s", etp)
	}

	// Switch to ClusterIP through ConfigMap, providing a static address in spec.addresses
	liveSwitchToClusterIP := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: live-switch-params
  namespace: default
data:
  serviceType: ClusterIP
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: live-switch-gw
  namespace: default
spec:
  gatewayClassName: reference-class
  addresses:
  - type: IPAddress
    value: "10.96.0.123"
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: live-switch-params
`
	h.KubectlApplyContent(liveSwitchToClusterIP)

	waitForServiceType := func(expectedType string, timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			st := strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.spec.type}"))
			if st == expectedType {
				return
			}
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Timed out waiting for Service %s to become %s", liveResName, expectedType)
	}

	waitForServiceType("ClusterIP", 30*time.Second)

	svcType = strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.spec.type}"))
	if svcType != "ClusterIP" {
		t.Errorf("Expected Service type ClusterIP after switch, got: %s", svcType)
	}
	etp = strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.spec.externalTrafficPolicy}"))
	if etp != "" {
		t.Errorf("Expected externalTrafficPolicy empty for ClusterIP, got: %s", etp)
	}
	lbIngress := strings.TrimSpace(h.RunCmd("kubectl", "get", "svc", liveResName, "--namespace=default", "-o", "jsonpath={.status.loadBalancer.ingress}"))
	if lbIngress != "" && lbIngress != "[]" {
		t.Errorf("Expected no loadBalancer ingress for ClusterIP Service, got: %s", lbIngress)
	}

	gwStaticAddr := strings.TrimSpace(h.RunCmd("kubectl", "get", "gateway", "live-switch-gw", "--namespace=default", "-o", "jsonpath={.status.addresses[0].value}"))
	if gwStaticAddr != "10.96.0.123" {
		t.Errorf("Expected Gateway status address 10.96.0.123, got: %s", gwStaticAddr)
	}

	// Switch back to LoadBalancer
	h.KubectlApplyContent(liveSwitchCM)
	waitForServiceType("LoadBalancer", 30*time.Second)

	h.RunCmd("kubectl", "delete", "gateway", "live-switch-gw", "--namespace=default")
	h.RunCmd("kubectl", "delete", "configmap", "live-switch-params", "--namespace=default")
	h.WaitForResourceDeletion("svc", liveResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("deployment", liveResName, "default", 30*time.Second)
}

func runCmdAllowError(h *Harness, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		h.T.Logf("Command %s %v returned error (allowed): %v", name, args, err)
	}
	return combined.String()
}
