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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/certserversource"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const certServerTestHost = "app.test"

func TestCertServerIssuance(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}
	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "kind"
	}

	h := NewHarness(t, clusterName)
	h.Setup()

	t.Cleanup(func() {
		if t.Failed() {
			for _, podName := range []string{"certserver", "pebble"} {
				if output, err := h.RunCommand("kubectl", "logs", "pod/"+podName, "--namespace=default", "--tail=2000"); err == nil && strings.TrimSpace(output) != "" {
					t.Logf("=== %s LOGS ===", strings.ToUpper(podName))
					t.Log(output)
				}
			}
			// Dump controller and data-plane diagnostics before deleting the Gateway and pods.
			h.dumpOnce.Do(h.DumpDiagnostics)
		}
		if _, err := h.RunCommand("kubectl", "delete", "--namespace=default", "--ignore-not-found",
			"httproute/app-route", "gateway/certserver-gw",
			"pod/certserver", "pod/pebble", "service/certserver", "service/pebble",
			"secret/certserver-tls", "secret/pebble-tls",
			"configmap/certserver-config", "configmap/certserver-ca",
			"configmap/pebble-config", "configmap/pebble-ca", "configmap/pebble-root-ca"); err != nil {
			t.Logf("cleanup delete failed: %v", err)
		}
		h.WaitForResourceDeletion("gateway", "certserver-gw", "default", 30*time.Second)
	})

	h.InstallGatewayAPI(gatewayconsts.BundleVersion)
	h.DeployController()
	h.DeployBackend()

	gitRoot := h.GetGitRoot()
	h.DockerBuild("pebble:e2e", filepath.Join(gitRoot, "tests/e2e/pebble/Dockerfile"), gitRoot)
	h.KindLoad("pebble:e2e")
	h.DockerBuild("certserver:e2e", filepath.Join(gitRoot, "images/certserver/Dockerfile"), gitRoot)
	h.KindLoad("certserver:e2e")

	// 1. Deploy Pebble with validation delays disabled and app.test pointing at the Gateway IP.
	createServiceTLSAndCA(t, h, "pebble")
	h.DeletePod("pebble")
	h.KubectlApplyContent(pebbleManifest())
	h.RunCmd("kubectl", "wait", "--namespace=default", "--for=condition=ready", "pod/pebble", "--timeout=2m")

	// 2. Register this cluster with certserver using the API server's OIDC issuer and JWKS.
	oidcRaw := h.RunCmd("kubectl", "get", "--raw", "/.well-known/openid-configuration")
	var oidcConfig struct{ Issuer string }
	if err := json.Unmarshal([]byte(oidcRaw), &oidcConfig); err != nil {
		t.Fatalf("parsing OIDC configuration %q: %v", oidcRaw, err)
	}
	if oidcConfig.Issuer == "" {
		t.Fatalf("OIDC configuration %q has empty issuer", oidcRaw)
	}
	createConfigMapFromFiles(t, h, "certserver-config", map[string]string{
		"clusters.yaml": fmt.Sprintf(`clusters:
- {clusterID: kind, issuerURL: %q, jwksFile: /etc/certserver/config/jwks.json, controllerNamespace: default, controllerServiceAccount: gari-controller, allowedHostnames: [%q]}
`, oidcConfig.Issuer, certServerTestHost),
		"jwks.json": h.RunCmd("kubectl", "get", "--raw", "/openid/v1/jwks"),
	})

	createServiceTLSAndCA(t, h, "certserver")
	h.DeletePod("certserver")
	h.KubectlApplyContent(certServerManifest())
	h.RunCmd("kubectl", "wait", "--namespace=default", "--for=condition=ready", "pod/certserver", "--timeout=2m")

	// 3. Configure gari-controller to connect to certserver with a projected ServiceAccount token.
	controllerPatch := fmt.Sprintf(`[
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--%s=certserver.default.svc.cluster.local:8443"},
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--%s=/etc/gari/certserver-ca/tls.crt"},
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--%s=/var/run/secrets/tokens/certserver/token"},
		{"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "certserver-ca", "mountPath": "/etc/gari/certserver-ca", "readOnly": true}},
		{"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "certserver-token", "mountPath": "/var/run/secrets/tokens/certserver", "readOnly": true}},
		{"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "certserver-ca", "configMap": {"name": "certserver-ca"}}},
		{"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "certserver-token", "projected": {"sources": [{"serviceAccountToken": {"audience": %q, "expirationSeconds": 600, "path": "token"}}]}}}
	]`, certserversource.FlagServerAddress, certserversource.FlagCABundlePath, certserversource.FlagTokenPath, certserversource.TokenAudience)
	h.RunCmd("kubectl", "patch", "deployment", "gari-controller", "--namespace=default", "--type=json", "-p", controllerPatch)
	h.RunCmd("kubectl", "rollout", "status", "deployment/gari-controller", "--namespace=default", "--timeout=2m")

	// 4. Create Gateway (HTTP + HTTPS selecting certserver for app.test) and wait for Programmed=True.
	h.KubectlApplyContent(certServerGatewayManifest())
	gatewayAddress, _ := h.WaitForGatewayAddress("certserver-gw", "default", 2*time.Minute)
	if gatewayAddress != StaticAddressPoolIP {
		t.Fatalf("expected Gateway address %s, got %s", StaticAddressPoolIP, gatewayAddress)
	}
	waitForListenerProgrammed(t, h, "certserver-gw", "default", "https", 2*time.Minute)

	// 5. Fetch Pebble's root CA and verify HTTPS with SNI app.test chains to it.
	createConfigMapFromFiles(t, h, "pebble-root-ca", map[string]string{"root.crt": fetchPebbleRootCA(t, h)})
	httpsLogs := runToolboxWithCA(t, h, "test-certserver-https", "pebble-root-ca", "/etc/pebble-root",
		"--ca-cert=/etc/pebble-root/root.crt", "--sni="+certServerTestHost,
		fmt.Sprintf("https://%s:443", gatewayAddress), certServerTestHost)
	t.Logf("HTTPS client logs: %s", httpsLogs)
	if !strings.Contains(httpsLogs, "Status: 200 OK") {
		t.Errorf("expected Status: 200 OK in HTTPS logs, got: %s", httpsLogs)
	}

	// 6. Verify certserver, controller, and data-plane logs contain no PEM PRIVATE KEY blocks.
	for componentName, args := range map[string][]string{
		"certserver": {"logs", "pod/certserver", "--namespace=default"},
		"controller": {"logs", "deployment/gari-controller", "--namespace=default"},
		"data-plane": {"logs", "--namespace=default", "-l", singlepod.LabelGatewayName + "=certserver-gw", "--all-containers=true"},
	} {
		if strings.Contains(h.RunCmd("kubectl", args...), "PRIVATE KEY") {
			t.Errorf("%s logs contain a PEM PRIVATE KEY block", componentName)
		}
	}
}

func createServiceTLSAndCA(t *testing.T, h *Harness, serviceName string) {
	t.Helper()
	certPEM, keyPEM, err := GenerateTestCertificate(serviceName, serviceName, serviceName+".default.svc", serviceName+".default.svc.cluster.local")
	if err != nil {
		t.Fatalf("generating %s TLS cert: %v", serviceName, err)
	}
	tempDir := t.TempDir()
	certPath, keyPath := filepath.Join(tempDir, "tls.crt"), filepath.Join(tempDir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	h.RunCmd("kubectl", "delete", "secret", serviceName+"-tls", "--namespace=default", "--ignore-not-found")
	h.RunCmd("kubectl", "create", "secret", "tls", serviceName+"-tls", "--namespace=default", "--cert="+certPath, "--key="+keyPath)
	h.RunCmd("kubectl", "delete", "configmap", serviceName+"-ca", "--namespace=default", "--ignore-not-found")
	h.RunCmd("kubectl", "create", "configmap", serviceName+"-ca", "--namespace=default", "--from-file=tls.crt="+certPath)
}

func createConfigMapFromFiles(t *testing.T, h *Harness, name string, files map[string]string) {
	t.Helper()
	tempDir := t.TempDir()
	args := []string{"create", "configmap", name, "--namespace=default"}
	for fileName, content := range files {
		filePath := filepath.Join(tempDir, fileName)
		if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
			t.Fatalf("writing %s: %v", fileName, err)
		}
		args = append(args, "--from-file="+fileName+"="+filePath)
	}
	h.RunCmd("kubectl", "delete", "configmap", name, "--namespace=default", "--ignore-not-found")
	h.RunCmd("kubectl", args...)
}

func waitForListenerProgrammed(t *testing.T, h *Harness, gatewayName, namespace, listenerName string, timeout time.Duration) {
	t.Helper()
	jsonPath := fmt.Sprintf(`jsonpath={.status.listeners[?(@.name=="%s")].conditions[?(@.type=="Programmed")].status}`, listenerName)
	var lastErr error
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(1 * time.Second) {
		output, err := h.RunCommand("kubectl", "get", "gateway", gatewayName, "--namespace", namespace, "-o", jsonPath)
		if err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSpace(output) == "True" {
			return
		}
	}
	t.Fatalf("timed out waiting for Gateway %s/%s listener %q Programmed=True (last error: %v)", namespace, gatewayName, listenerName, lastErr)
}

func fetchPebbleRootCA(t *testing.T, h *Harness) string {
	t.Helper()
	output := runToolboxWithCA(t, h, "fetch-pebble-root", "pebble-ca", "/etc/pebble-ca",
		"--ca-cert=/etc/pebble-ca/tls.crt", "https://pebble.default.svc.cluster.local:15000/roots/0")
	pemStart := strings.Index(output, "-----BEGIN CERTIFICATE-----")
	if pemStart < 0 {
		t.Fatalf("Pebble root CA PEM not found in output: %s", output)
	}
	block, _ := pem.Decode([]byte(output[pemStart:]))
	if block == nil {
		t.Fatalf("decoding Pebble root CA PEM failed")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parsing Pebble root CA cert: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

func runToolboxWithCA(t *testing.T, h *Harness, podName, configMapName, mountPath string, args ...string) string {
	t.Helper()
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshaling toolbox args: %v", err)
	}
	h.DeletePod(podName)
	h.KubectlApplyContent(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: %s, namespace: default}
spec:
  restartPolicy: Never
  containers:
  - {name: toolbox, image: toolbox:e2e, imagePullPolicy: Never, command: ["/app/toolbox", "client"], args: %s, volumeMounts: [{name: ca, mountPath: %s, readOnly: true}]}
  volumes: [{name: ca, configMap: {name: %s}}]
`, podName, string(argsJSON), mountPath, configMapName))
	h.WaitForPodSuccess(podName, 1*time.Minute)
	output := h.GetPodLogs(podName)
	h.DeletePod(podName)
	return output
}

func pebbleManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata: {name: pebble-config, namespace: default}
data:
  pebble-config.json: '{"pebble":{"listenAddress":"0.0.0.0:14000","managementListenAddress":"0.0.0.0:15000","certificate":"/etc/pebble/tls/tls.crt","privateKey":"/etc/pebble/tls/tls.key","httpPort":80,"tlsPort":443}}'
---
apiVersion: v1
kind: Pod
metadata: {name: pebble, namespace: default, labels: {app: pebble}}
spec:
  hostAliases: [{ip: %q, hostnames: [%q]}]
  containers:
  - name: pebble
    image: pebble:e2e
    imagePullPolicy: Never
    args: ["-config", "/etc/pebble/config/pebble-config.json"]
    env: [{name: PEBBLE_VA_NOSLEEP, value: "1"}, {name: PEBBLE_WFE_NONCEREJECT, value: "0"}]
    ports: [{containerPort: 14000}, {containerPort: 15000}]
    readinessProbe: {tcpSocket: {port: 14000}, periodSeconds: 1}
    volumeMounts: [{name: config, mountPath: /etc/pebble/config, readOnly: true}, {name: tls, mountPath: /etc/pebble/tls, readOnly: true}]
  volumes: [{name: config, configMap: {name: pebble-config}}, {name: tls, secret: {secretName: pebble-tls}}]
---
apiVersion: v1
kind: Service
metadata: {name: pebble, namespace: default}
spec: {selector: {app: pebble}, ports: [{name: acme, port: 14000, targetPort: 14000}, {name: mgmt, port: 15000, targetPort: 15000}]}
`, StaticAddressPoolIP, certServerTestHost)
}

func certServerManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: certserver, namespace: default, labels: {app: certserver}}
spec:
  securityContext: {runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532}
  hostAliases: [{ip: %q, hostnames: [%q]}]
  containers:
  - name: certserver
    image: certserver:e2e
    imagePullPolicy: Never
    env: [{name: SSL_CERT_FILE, value: /etc/certserver/pebble-ca/tls.crt}]
    args: [--directory-url=https://pebble.default.svc.cluster.local:14000/dir, --cache-dir=/var/cache/certserver/data, --grpc-listen-addr=:8443, --tls-cert-file=/etc/certserver/tls/tls.crt, --tls-key-file=/etc/certserver/tls/tls.key, --cluster-config-file=/etc/certserver/config/clusters.yaml, --cluster-dir-poll-interval=500ms]
    ports: [{containerPort: 8443}]
    readinessProbe: {tcpSocket: {port: 8443}, periodSeconds: 1}
    volumeMounts: [{name: cache, mountPath: /var/cache/certserver}, {name: config, mountPath: /etc/certserver/config, readOnly: true}, {name: tls, mountPath: /etc/certserver/tls, readOnly: true}, {name: pebble-ca, mountPath: /etc/certserver/pebble-ca, readOnly: true}]
  volumes: [{name: cache, emptyDir: {}}, {name: config, configMap: {name: certserver-config}}, {name: tls, secret: {secretName: certserver-tls}}, {name: pebble-ca, configMap: {name: pebble-ca}}]
---
apiVersion: v1
kind: Service
metadata: {name: certserver, namespace: default}
spec: {selector: {app: certserver}, ports: [{name: grpc, port: 8443, targetPort: 8443}]}
`, StaticAddressPoolIP, certServerTestHost)
}

func certServerGatewayManifest() string {
	return fmt.Sprintf(`apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: certserver-gw, namespace: default}
spec:
  gatewayClassName: reference-class
  addresses: [{type: IPAddress, value: %q}]
  listeners:
  - {name: http, protocol: HTTP, port: 80}
  - {name: https, protocol: HTTPS, port: 443, hostname: %q, tls: {mode: Terminate, options: {%s: %s}}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app-route, namespace: default}
spec: {parentRefs: [{name: certserver-gw}], hostnames: [%q], rules: [{backendRefs: [{name: backend, port: 8080}]}]}
`, StaticAddressPoolIP, certServerTestHost, state.CertificateSourceOptionKey, certserversource.CertificateSourceName, certServerTestHost)
}
