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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
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

	// Verify the credentials Job created the three SPIFFE objects
	h.RunCmd("kubectl", "get", "secret", "gari-spiffe-authority", "--namespace=default")
	h.RunCmd("kubectl", "get", "configmap", "gari-spiffe-bundle", "--namespace=default")
	h.RunCmd("kubectl", "get", "secret", "gari-controller-svid", "--namespace=default")

	// 3. Deploy Backend (Toolbox Server)
	h.DeployBackend()

	// Verify internal API listener TLS with controller X.509-SVID
	// 1. A client in the cluster that trusts only the trust bundle in the ConfigMap
	// completes a TLS handshake with the internal API Service by its DNS name.
	dnsNames, err := spiffe.ServiceDNSNames(spiffe.ControllerServiceName, "default")
	if err != nil {
		t.Fatalf("Failed to get internal API Service DNS names: %v", err)
	}
	serviceDNS := dnsNames[len(dnsNames)-1]
	targetInternalAPIURL := fmt.Sprintf("https://%s:8443", serviceDNS)

	internalAPIClientPod := "test-internal-api-client"
	h.DeletePod(internalAPIClientPod)
	clientManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: default
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client"]
    args: ["--ca-cert=/etc/spiffe/%s", "--tls-handshake-only", "%s"]
    volumeMounts:
    - name: bundle
      mountPath: /etc/spiffe
      readOnly: true
  volumes:
  - name: bundle
    configMap:
      name: %s
  restartPolicy: Never
`, internalAPIClientPod, spiffe.BundleDataKey, targetInternalAPIURL, spiffe.BundleConfigMapName)

	h.KubectlApplyContent(clientManifest)
	h.WaitForPodSuccess(internalAPIClientPod, 1*time.Minute)
	clientLogs := h.GetPodLogs(internalAPIClientPod)
	t.Logf("Internal API client logs (trusted): %s", clientLogs)
	if !strings.Contains(clientLogs, "TLS handshake succeeded") {
		t.Errorf("Expected TLS handshake to succeed, got: %s", clientLogs)
	}
	for _, expectedDNS := range dnsNames {
		if !strings.Contains(clientLogs, expectedDNS) {
			t.Errorf("Expected peer certificate to contain DNS name %q, got logs: %s", expectedDNS, clientLogs)
		}
	}
	h.DeletePod(internalAPIClientPod)

	// 2. A client that trusts another authority fails.
	untrustedPod := "test-internal-api-client-untrusted"
	h.DeletePod(untrustedPod)

	untrustedCertPEM, untrustedKeyPEM, err := GenerateTestCertificate("other-ca.example.com", "other-ca.example.com")
	if err != nil {
		t.Fatalf("Failed to generate untrusted CA certificate: %v", err)
	}
	untrustedSecretName := "untrusted-ca-secret"
	h.CreateTLSSecret(untrustedSecretName, "default", untrustedCertPEM, untrustedKeyPEM)
	defer h.RunCmd("kubectl", "delete", "secret", untrustedSecretName, "--namespace=default", "--ignore-not-found")

	clientUntrustedManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: default
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client"]
    args: ["--ca-cert=/etc/untrusted/tls.crt", "--expect-fail", "--tls-handshake-only", "%s"]
    volumeMounts:
    - name: untrusted-ca
      mountPath: /etc/untrusted
      readOnly: true
  volumes:
  - name: untrusted-ca
    secret:
      secretName: %s
  restartPolicy: Never
`, untrustedPod, targetInternalAPIURL, untrustedSecretName)

	h.KubectlApplyContent(clientUntrustedManifest)
	h.WaitForPodSuccess(untrustedPod, 1*time.Minute)
	untrustedLogs := h.GetPodLogs(untrustedPod)
	t.Logf("Internal API client logs (untrusted): %s", untrustedLogs)
	if !strings.Contains(untrustedLogs, "TLS connection failed as expected") {
		t.Errorf("Expected TLS handshake with untrusted authority to fail, got: %s", untrustedLogs)
	}
	h.DeletePod(untrustedPod)

	// 4. Create Gateway API Resources
	certPEM, keyPEM, err := GenerateTestCertificate("example.com", "example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}
	h.CreateTLSSecret("gateway-tls-cert", "default", certPEM, keyPEM)

	h.KubectlApplyContent(h.ExampleGatewayManifest())
	gwAddr, gwCreated := h.WaitForGatewayAddress("reference-gateway", "default", 1*time.Minute)

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
	h.logGatewayTiming("default", "reference-gateway", "first successful request", gwCreated)

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

	// Verify that the data-plane ServiceAccount has no RBAC and serves traffic with no Role bound to it
	refResName := state.ResourceNameForGateway("reference-gateway")
	saCheck := h.RunCmd("kubectl", "get", "serviceaccount", refResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(saCheck) != refResName {
		t.Errorf("Expected ServiceAccount %s to exist, got: %s", refResName, saCheck)
	}
	roleCheck := runCmdAllowError(h, "kubectl", "get", "role", refResName, "--namespace=default")
	if !strings.Contains(roleCheck, "NotFound") && !strings.Contains(roleCheck, "not found") {
		t.Errorf("Expected Role %s to not exist (data plane serves traffic with no Role bound to it), got: %s", refResName, roleCheck)
	}
	rbCheck := runCmdAllowError(h, "kubectl", "get", "rolebinding", refResName, "--namespace=default")
	if !strings.Contains(rbCheck, "NotFound") && !strings.Contains(rbCheck, "not found") {
		t.Errorf("Expected RoleBinding %s to not exist (data plane serves traffic with no Role bound to it), got: %s", refResName, rbCheck)
	}
	secCheck := runCmdAllowError(h, "kubectl", "get", "secret", refResName, "--namespace=default")
	if !strings.Contains(secCheck, "NotFound") && !strings.Contains(secCheck, "not found") {
		t.Errorf("Expected Secret %s to not exist, got: %s", refResName, secCheck)
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
	secondGwAddr, _ := h.WaitForGatewayAddress("second-gateway", "default", 1*time.Minute)
	if secondGwAddr == gwAddr {
		t.Errorf("Expected second Gateway to get distinct address, got same: %s", secondGwAddr)
	}

	// Verify Service, Deployment, ServiceAccount, ConfigMap, and Secret were created for second-gateway
	secondResName := state.ResourceNameForGateway("second-gateway")
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
	cmOut := h.RunCmd("kubectl", "get", "configmap", secondResName, "--namespace=default", "-o", "jsonpath={.metadata.name}")
	if strings.TrimSpace(cmOut) != secondResName {
		t.Errorf("Expected ConfigMap %s to exist, got: %s", secondResName, cmOut)
	}

	// Verify no Secret was created for second-gateway
	secOut := runCmdAllowError(h, "kubectl", "get", "secret", secondResName, "--namespace=default")
	if !strings.Contains(secOut, "NotFound") && !strings.Contains(secOut, "not found") {
		t.Errorf("Expected Secret %s to not exist, got: %s", secondResName, secOut)
	}

	// Verify no Role or RoleBinding was created for second-gateway
	roleOut := runCmdAllowError(h, "kubectl", "get", "role", secondResName, "--namespace=default")
	if !strings.Contains(roleOut, "NotFound") && !strings.Contains(roleOut, "not found") {
		t.Errorf("Expected Role %s to not exist, got: %s", secondResName, roleOut)
	}
	rbOut := runCmdAllowError(h, "kubectl", "get", "rolebinding", secondResName, "--namespace=default")
	if !strings.Contains(rbOut, "NotFound") && !strings.Contains(rbOut, "not found") {
		t.Errorf("Expected RoleBinding %s to not exist, got: %s", secondResName, rbOut)
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

	// Delete second-gateway and verify Service, Deployment, ServiceAccount, and ConfigMap are cleaned up
	h.RunCmd("kubectl", "delete", "gateway", "second-gateway", "--namespace=default")
	h.WaitForResourceDeletion("svc", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("deployment", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("serviceaccount", secondResName, "default", 30*time.Second)
	h.WaitForResourceDeletion("configmap", secondResName, "default", 30*time.Second)

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
	liveGwAddr, _ := h.WaitForGatewayAddress("live-switch-gw", "default", 1*time.Minute)
	if liveGwAddr == "" {
		t.Fatalf("Expected live-switch-gw to get an address")
	}

	liveResName := state.ResourceNameForGateway("live-switch-gw")
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

	// 11. Test internal API data-plane config delivery
	t.Log("Testing internal API data-plane config delivery")

	// Read existing bundle ConfigMap data so we can verify the copied ConfigMap
	bundleCMJSON := h.RunCmd("kubectl", "get", "configmap", spiffe.BundleConfigMapName, "--namespace=default", "-o", "json")
	var origBundleCM corev1.ConfigMap
	if err := json.Unmarshal([]byte(bundleCMJSON), &origBundleCM); err != nil {
		t.Fatalf("failed to parse %s ConfigMap JSON: %v", spiffe.BundleConfigMapName, err)
	}
	origBundle := origBundleCM.Data[spiffe.BundleDataKey]
	if origBundle == "" {
		t.Fatalf("expected %s ConfigMap to contain %s", spiffe.BundleConfigMapName, spiffe.BundleDataKey)
	}

	// Cleanup resources when step 11 finishes
	defer func() {
		h.RunCmd("kubectl", "delete", "gateway", "internal-api-gw", "--namespace=default", "--ignore-not-found")
		h.RunCmd("kubectl", "delete", "httproute", "internal-api-route", "--namespace=default", "--ignore-not-found")
		h.RunCmd("kubectl", "patch", "configmap", spiffe.BundleConfigMapName, "--namespace=default",
			"--type=merge", "-p", fmt.Sprintf(`{"data":{"%s":%q}}`, spiffe.BundleDataKey, origBundle))
	}()

	internalAPIGwManifest := `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: internal-api-gw
  namespace: default
spec:
  gatewayClassName: reference-class
  listeners:
  - name: http
    protocol: HTTP
    port: 80
`
	h.KubectlApplyContent(internalAPIGwManifest)

	internalAPIResName := state.ResourceNameForGateway("internal-api-gw")
	h.WaitForDeployment(internalAPIResName, 2*time.Minute)

	// Verify the destination ConfigMap was copied into the Gateway's namespace with the bundle
	gwBundleCMJSON := h.RunCmd("kubectl", "get", "configmap", internalAPIResName, "--namespace=default", "-o", "json")
	var gwBundleCM corev1.ConfigMap
	if err := json.Unmarshal([]byte(gwBundleCMJSON), &gwBundleCM); err != nil {
		t.Fatalf("failed to parse gateway bundle ConfigMap JSON: %v", err)
	}
	if gwBundleCM.Data[spiffe.BundleDataKey] != origBundle {
		t.Errorf("copied bundle ConfigMap data mismatch: expected %q, got %q", origBundle, gwBundleCM.Data[spiffe.BundleDataKey])
	}

	// Verify no Role or RoleBinding was created for this Gateway
	rolesOut := runCmdAllowError(h, "kubectl", "get", "role", internalAPIResName, "--namespace=default")
	if !strings.Contains(rolesOut, "NotFound") && !strings.Contains(rolesOut, "not found") {
		t.Errorf("Expected Role %s to not exist, got: %s", internalAPIResName, rolesOut)
	}
	noRoleBindingOut := runCmdAllowError(h, "kubectl", "get", "rolebinding", internalAPIResName, "--namespace=default")
	if !strings.Contains(noRoleBindingOut, "NotFound") && !strings.Contains(noRoleBindingOut, "not found") {
		t.Errorf("Expected RoleBinding %s to not exist, got: %s", internalAPIResName, noRoleBindingOut)
	}
	noSecretOut := runCmdAllowError(h, "kubectl", "get", "secret", internalAPIResName, "--namespace=default")
	if !strings.Contains(noSecretOut, "NotFound") && !strings.Contains(noSecretOut, "not found") {
		t.Errorf("Expected Secret %s to not exist, got: %s", internalAPIResName, noSecretOut)
	}

	// Update the source bundle ConfigMap and verify the copy updates
	newBundleVal := origBundle + "\n# test-update-marker"
	h.RunCmd("kubectl", "patch", "configmap", spiffe.BundleConfigMapName, "--namespace=default",
		"--type=merge", "-p", fmt.Sprintf(`{"data":{"%s":%q}}`, spiffe.BundleDataKey, newBundleVal))

	pollStart := time.Now()
	for {
		updatedCMJSON := h.RunCmd("kubectl", "get", "configmap", internalAPIResName, "--namespace=default", "-o", "json")
		var updatedCM corev1.ConfigMap
		if err := json.Unmarshal([]byte(updatedCMJSON), &updatedCM); err != nil {
			t.Fatalf("failed to parse updated gateway bundle ConfigMap JSON: %v", err)
		}
		if updatedCM.Data[spiffe.BundleDataKey] == newBundleVal {
			t.Log("Successfully observed updated bundle ConfigMap propagated to Gateway copy")
			break
		}
		if time.Since(pollStart) > 1*time.Minute {
			t.Fatalf("Timed out waiting for bundle update to propagate to %s/%s", "default", internalAPIResName)
		}
		time.Sleep(1 * time.Second)
	}

	// Route traffic through the Gateway to verify the data plane functions
	internalAPIRouteManifest := `
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: internal-api-route
  namespace: default
spec:
  parentRefs:
  - name: internal-api-gw
    namespace: default
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`
	h.KubectlApplyContent(internalAPIRouteManifest)

	// Wait for Gateway to obtain an assigned address
	internalAPIIngressIP, _ := h.WaitForGatewayAddress("internal-api-gw", "default", 2*time.Minute)

	internalAPIClientPodName := "test-client-internal-api"
	h.DeletePod(internalAPIClientPodName)
	h.KubectlApplyContent(h.ClientManifestWithArgs(internalAPIClientPodName, fmt.Sprintf("http://%s", internalAPIIngressIP), "example.com"))
	h.WaitForPodSuccess(internalAPIClientPodName, 1*time.Minute)
	internalAPIClientLogs := h.GetPodLogs(internalAPIClientPodName)
	t.Logf("Client logs (internal-api): %s", internalAPIClientLogs)
	if !strings.Contains(internalAPIClientLogs, "Status: 200 OK") {
		t.Errorf("Expected HTTP 200 OK via internal-api-gw, got: %s", internalAPIClientLogs)
	}
	h.DeletePod(internalAPIClientPodName)

	// Verify data plane Deployment has --internal-api-address
	dataplaneDeployJSON := h.RunCmd("kubectl", "get", "deployment", internalAPIResName, "--namespace=default", "-o", "json")
	var dataplaneDeploy appsv1.Deployment
	if err := json.Unmarshal([]byte(dataplaneDeployJSON), &dataplaneDeploy); err != nil {
		t.Fatalf("failed to parse data-plane Deployment JSON: %v", err)
	}
	if len(dataplaneDeploy.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("expected at least 1 container in data-plane Deployment")
	}
	container := dataplaneDeploy.Spec.Template.Spec.Containers[0]
	var hasInternalAPIAddress bool
	for _, arg := range container.Args {
		if strings.HasPrefix(arg, "--internal-api-address=") {
			hasInternalAPIAddress = true
			break
		}
	}
	if !hasInternalAPIAddress {
		t.Errorf("Expected data-plane container to have --internal-api-address flag, args: %v", container.Args)
	}
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
