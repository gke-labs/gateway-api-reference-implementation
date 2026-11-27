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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/certserversource"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const (
	certServerTestHost = "app.test"
	certServerStaticIP = "172.18.255.240"
)

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

	// Dump certserver and pebble logs on failure; h.SetupDiagnosticsCleanup()
	// dumps controller logs, data-plane logs, gateways, pods, and events.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, pod := range []string{"certserver", "pebble"} {
			if out, err := h.RunCommand("kubectl", "logs", "pod/"+pod, "--namespace=default", "--tail=2000"); err == nil && strings.TrimSpace(out) != "" {
				t.Logf("=== %s LOGS ===", strings.ToUpper(pod))
				t.Log(out)
			}
		}
	})

	h.InstallGatewayAPI(gatewayconsts.BundleVersion)
	h.DeployController()
	h.DeployBackend()

	gitRoot := h.GetGitRoot()
	h.DockerBuild("pebble:e2e", filepath.Join(gitRoot, "tests/e2e/pebble/Dockerfile"), gitRoot)
	h.KindLoad("pebble:e2e")
	h.DockerBuild("certserver:e2e", filepath.Join(gitRoot, "images/certserver/Dockerfile"), gitRoot)
	h.KindLoad("certserver:e2e")

	// 1. Deploy Pebble with validation delays disabled and app.test -> Gateway IP.
	applyTLSSecretAndCA(t, h, "pebble", "pebble-tls", "pebble-ca")
	h.DeletePod("pebble")
	h.KubectlApplyContent(pebbleManifest())
	h.RunCmd("kubectl", "wait", "--namespace=default", "--for=condition=ready", "pod/pebble", "--timeout=2m")

	// 2. Register this cluster with certserver using the API server's OIDC issuer and JWKS.
	var oidc struct{ Issuer string }
	if raw := h.RunCmd("kubectl", "get", "--raw", "/.well-known/openid-configuration"); json.Unmarshal([]byte(raw), &oidc) != nil || oidc.Issuer == "" {
		t.Fatalf("failed to read OIDC issuer from %q", raw)
	}
	clustersYAML := fmt.Sprintf(`clusters:
- clusterID: kind
  issuerURL: %q
  jwksFile: /etc/certserver/config/jwks.json
  controllerNamespace: default
  controllerServiceAccount: gari-controller
  allowedHostnames: [%q]
`, oidc.Issuer, certServerTestHost)
	applyConfigMapFiles(t, h, "certserver-config", map[string]string{
		"clusters.yaml": clustersYAML,
		"jwks.json":     h.RunCmd("kubectl", "get", "--raw", "/openid/v1/jwks"),
	})

	applyTLSSecretAndCA(t, h, "certserver", "certserver-tls", "certserver-ca")
	h.DeletePod("certserver")
	h.KubectlApplyContent(certServerManifest())
	h.RunCmd("kubectl", "wait", "--namespace=default", "--for=condition=ready", "pod/certserver", "--timeout=2m")

	// 3. Configure gari-controller to connect to certserver with a projected ServiceAccount token.
	h.RunCmd("kubectl", "patch", "deployment", "gari-controller", "--namespace=default", "--type=json", "-p", `[
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--certserver-address=certserver.default.svc.cluster.local:8443"},
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--certserver-ca-bundle-path=/etc/gari/certserver-ca/tls.crt"},
		{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--certserver-token-path=/var/run/secrets/tokens/certserver/token"},
		{"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "certserver-ca", "mountPath": "/etc/gari/certserver-ca", "readOnly": true}},
		{"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "certserver-token", "mountPath": "/var/run/secrets/tokens/certserver", "readOnly": true}},
		{"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "certserver-ca", "configMap": {"name": "certserver-ca"}}},
		{"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "certserver-token", "projected": {"sources": [{"serviceAccountToken": {"audience": "certserver", "expirationSeconds": 600, "path": "token"}}]}}}
	]`)
	h.RunCmd("kubectl", "rollout", "status", "deployment/gari-controller", "--namespace=default", "--timeout=2m")

	// 4. Create Gateway (HTTP + HTTPS selecting certserver for app.test) and wait for Programmed=True.
	h.KubectlApplyContent(certServerGatewayManifest())
	gwAddr := waitForListenerProgrammed(t, h, "certserver-gw", "default", "https", 2*time.Minute)
	if gwAddr != certServerStaticIP {
		t.Fatalf("expected Gateway address %s, got %s", certServerStaticIP, gwAddr)
	}

	// 5. Fetch Pebble's root CA and verify HTTPS with SNI app.test chains to it.
	applyConfigMapFiles(t, h, "pebble-root-ca", map[string]string{"root.crt": fetchPebbleRootCA(t, h)})
	httpsLogs := runToolboxWithCA(t, h, "test-certserver-https", "pebble-root-ca", "/etc/pebble-root",
		"--ca-cert=/etc/pebble-root/root.crt", "--sni="+certServerTestHost,
		fmt.Sprintf("https://%s:443", gwAddr), certServerTestHost)
	t.Logf("HTTPS client logs: %s", httpsLogs)

	for _, want := range []string{"Status: 200 OK", "PeerCertDNSNames: " + certServerTestHost} {
		if !strings.Contains(httpsLogs, want) {
			t.Errorf("expected %q in HTTPS logs, got: %s", want, httpsLogs)
		}
	}
	if !strings.Contains(httpsLogs, `"hostname":"`+certServerTestHost+`"`) && !strings.Contains(httpsLogs, `"host": "`+certServerTestHost+`"`) {
		t.Errorf("expected hostname %s in response body, got: %s", certServerTestHost, httpsLogs)
	}

	// 6. Verify certserver, controller, and data-plane logs hold no private key material.
	for name, args := range map[string][]string{
		"certserver": {"logs", "pod/certserver", "--namespace=default"},
		"controller": {"logs", "deployment/gari-controller", "--namespace=default"},
		"data-plane": {"logs", "--namespace=default", "-l", singlepod.LabelGatewayName + "=certserver-gw", "--all-containers=true"},
	} {
		if strings.Contains(h.RunCmd("kubectl", args...), "PRIVATE KEY") {
			t.Errorf("%s logs contain private key material", name)
		}
	}
}

func applyTLSSecretAndCA(t *testing.T, h *Harness, svcName, secretName, caConfigMap string) {
	t.Helper()
	certPEM, keyPEM, err := GenerateTestCertificate(svcName, svcName, svcName+".default.svc", svcName+".default.svc.cluster.local")
	if err != nil {
		t.Fatalf("generating %s TLS cert: %v", svcName, err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	applyQuiet(t, h.RunCmd("kubectl", "create", "secret", "tls", secretName, "--namespace=default", "--cert="+certPath, "--key="+keyPath, "--dry-run=client", "-o", "yaml"))
	applyConfigMapFiles(t, h, caConfigMap, map[string]string{"tls.crt": string(certPEM)})
}

func applyConfigMapFiles(t *testing.T, h *Harness, name string, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	args := []string{"create", "configmap", name, "--namespace=default", "--dry-run=client", "-o", "yaml"}
	for fname, content := range files {
		p := filepath.Join(dir, fname)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatalf("writing %s: %v", fname, err)
		}
		args = append(args, "--from-file="+fname+"="+p)
	}
	applyQuiet(t, h.RunCmd("kubectl", args...))
}

func applyQuiet(t *testing.T, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply failed: %v: %s", err, string(out))
	}
}

func waitForListenerProgrammed(t *testing.T, h *Harness, gwName, namespace, listenerName string, timeout time.Duration) string {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(1 * time.Second) {
		out, err := h.RunCommand("kubectl", "get", "gateway", gwName, "--namespace", namespace, "-o", "json")
		if err != nil {
			continue
		}
		var gw struct {
			Status struct {
				Addresses []struct{ Value string }
				Listeners []struct {
					Name       string
					Conditions []struct{ Type, Status string }
				}
			}
		}
		if json.Unmarshal([]byte(out), &gw) != nil || len(gw.Status.Addresses) == 0 {
			continue
		}
		for _, l := range gw.Status.Listeners {
			for _, c := range l.Conditions {
				if l.Name == listenerName && c.Type == "Programmed" && c.Status == "True" {
					return strings.TrimSpace(gw.Status.Addresses[0].Value)
				}
			}
		}
	}
	t.Fatalf("timed out waiting for Gateway %s/%s listener %q Programmed=True", namespace, gwName, listenerName)
	return ""
}

func fetchPebbleRootCA(t *testing.T, h *Harness) string {
	t.Helper()
	out := runToolboxWithCA(t, h, "fetch-pebble-root", "pebble-ca", "/etc/pebble-ca",
		"--ca-cert=/etc/pebble-ca/tls.crt", "https://pebble.default.svc.cluster.local:15000/roots/0")
	idx := strings.Index(out, "-----BEGIN CERTIFICATE-----")
	if idx < 0 {
		t.Fatalf("Pebble root CA PEM not found in output: %s", out)
	}
	block, _ := pem.Decode([]byte(out[idx:]))
	if block == nil {
		t.Fatalf("decoding Pebble root CA PEM failed")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parsing Pebble root CA cert: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

func runToolboxWithCA(t *testing.T, h *Harness, pod, configMapName, mountPath string, args ...string) string {
	t.Helper()
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshaling toolbox args: %v", err)
	}
	h.DeletePod(pod)
	h.KubectlApplyContent(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: %s, namespace: default}
spec:
  restartPolicy: Never
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client"]
    args: %s
    volumeMounts: [{name: ca, mountPath: %s, readOnly: true}]
  volumes: [{name: ca, configMap: {name: %s}}]
`, pod, string(argsJSON), mountPath, configMapName))
	h.WaitForPodSuccess(pod, 1*time.Minute)
	out := h.GetPodLogs(pod)
	h.DeletePod(pod)
	return out
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
spec:
  selector: {app: pebble}
  ports: [{name: acme, port: 14000, targetPort: 14000}, {name: mgmt, port: 15000, targetPort: 15000}]
`, certServerStaticIP, certServerTestHost)
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
    args:
    - --directory-url=https://pebble.default.svc.cluster.local:14000/dir
    - --cache-dir=/var/cache/certserver/data
    - --grpc-listen-addr=:8443
    - --tls-cert-file=/etc/certserver/tls/tls.crt
    - --tls-key-file=/etc/certserver/tls/tls.key
    - --cluster-config-file=/etc/certserver/config/clusters.yaml
    - --cluster-dir-poll-interval=500ms
    ports: [{containerPort: 8443}]
    readinessProbe: {tcpSocket: {port: 8443}, periodSeconds: 1}
    volumeMounts:
    - {name: cache, mountPath: /var/cache/certserver}
    - {name: config, mountPath: /etc/certserver/config, readOnly: true}
    - {name: tls, mountPath: /etc/certserver/tls, readOnly: true}
    - {name: pebble-ca, mountPath: /etc/certserver/pebble-ca, readOnly: true}
  volumes: [{name: cache, emptyDir: {}}, {name: config, configMap: {name: certserver-config}}, {name: tls, secret: {secretName: certserver-tls}}, {name: pebble-ca, configMap: {name: pebble-ca}}]
---
apiVersion: v1
kind: Service
metadata: {name: certserver, namespace: default}
spec:
  selector: {app: certserver}
  ports: [{name: grpc, port: 8443, targetPort: 8443}]
`, certServerStaticIP, certServerTestHost)
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
spec:
  parentRefs: [{name: certserver-gw}]
  hostnames: [%q]
  rules: [{backendRefs: [{name: backend, port: 8080}]}]
`, certServerStaticIP, certServerTestHost, state.CertificateSourceOptionKey, certserversource.CertificateSourceName, certServerTestHost)
}
