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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
)

type Harness struct {
	t           *testing.T
	clusterName string
}

func NewHarness(t *testing.T, clusterName string) *Harness {
	return &Harness{
		t:           t,
		clusterName: clusterName,
	}
}

func (h *Harness) Setup() {
	h.t.Logf("Setting up harness for cluster %s", h.clusterName)
	if _, err := exec.LookPath("kind"); err != nil {
		h.t.Fatalf("kind not found: %v", err)
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		h.t.Fatalf("kubectl not found: %v", err)
	}

	clusters := h.runCmd("kind", "get", "clusters")
	exists := false
	for _, cluster := range strings.Split(clusters, "\n") {
		if strings.TrimSpace(cluster) == h.clusterName {
			exists = true
			break
		}
	}

	if !exists {
		h.t.Logf("Creating kind cluster %s", h.clusterName)
		h.runCmd("kind", "create", "cluster", "--name", h.clusterName)
		h.t.Cleanup(func() {
			if os.Getenv("SKIP_CLEANUP") == "" {
				h.t.Logf("Deleting kind cluster %s", h.clusterName)
				h.runCmd("kind", "delete", "cluster", "--name", h.clusterName)
			}
		})
	}

	contextName := "kind-" + h.clusterName
	h.runCmd("kubectl", "config", "use-context", contextName)
	h.runCmd("kubectl", "config", "set-context", "--current", "--namespace=default")

	h.InstallMetallb()
}

func (h *Harness) InstallMetallb() {
	h.t.Log("Installing Metallb")
	h.runCmd("kubectl", "apply", "-f", "https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml")
	h.runCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=available", "deployment/controller", "--timeout=90s")
	h.runCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=ready", "pod", "--selector=app=metallb", "--timeout=90s")

	h.runCmd("docker", "network", "inspect", "kind")
	h.KubectlApplyContentWithRetry(h.MetallbConfigManifest(), 90*time.Second)
}

func (h *Harness) GetGitRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("Failed to get git root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) DockerBuild(tag, dockerfile, context string) {
	h.t.Logf("Building docker image %s", tag)
	h.runCmd("docker", "build", "-t", tag, "-f", dockerfile, context)
}

func (h *Harness) KindLoad(tag string) {
	h.t.Logf("Loading image %s into kind cluster %s", tag, h.clusterName)
	h.runCmd("kind", "load", "docker-image", tag, "--name", h.clusterName)
}

func (h *Harness) KubectlApplyContent(content string) {
	h.t.Logf("Applying kubectl content:\n%s", content)
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("kubectl apply failed: %v\nStderr: %s", err, stderr.String())
	}
}

func (h *Harness) KubectlApplyContentWithRetry(content string, timeout time.Duration) {
	h.t.Logf("Applying kubectl content (with retry):\n%s", content)
	start := time.Now()
	var lastErr error
	var lastStderr string
	for {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(content)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			return
		} else {
			lastErr = err
			lastStderr = stderr.String()
		}

		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for kubectl apply to succeed: %v\nStderr: %s", lastErr, lastStderr)
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *Harness) KubectlApplyFile(path string) {
	h.t.Logf("Applying kubectl file: %s", path)
	h.runCmd("kubectl", "apply", "-f", path)
}

func (h *Harness) WaitForDeployment(name string, timeout time.Duration) {
	h.WaitForDeploymentInNamespace("default", name, timeout)
}

func (h *Harness) WaitForDeploymentInNamespace(namespace, name string, timeout time.Duration) {
	h.t.Logf("Waiting for deployment %s/%s to be ready", namespace, name)
	h.runCmd("kubectl", "wait", "--namespace", namespace, "--for=condition=available", "--timeout="+timeout.String(), "deployment/"+name)
}

func (h *Harness) DeletePod(name string) {
	h.DeletePodInNamespace("default", name)
}

func (h *Harness) DeletePodInNamespace(namespace, name string) {
	h.t.Logf("Deleting pod %s/%s", namespace, name)
	exec.Command("kubectl", "delete", "pod", name, "--namespace", namespace, "--ignore-not-found").Run()
}

func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.WaitForPodSuccessInNamespace("default", name, timeout)
}

func (h *Harness) WaitForPodSuccessInNamespace(namespace, name string, timeout time.Duration) {
	h.t.Logf("Waiting for pod %s/%s to succeed", namespace, name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for pod %s/%s to succeed", namespace, name)
		}

		out, err := exec.Command("kubectl", "get", "pod", name, "--namespace", namespace, "-o", "jsonpath={.status.phase}").Output()
		if err == nil {
			phase := strings.TrimSpace(string(out))
			if phase == "Succeeded" {
				return
			}
			if phase == "Failed" {
				logs := h.GetPodLogsInNamespace(namespace, name)
				h.t.Fatalf("Pod %s/%s failed. Logs:\n%s", namespace, name, logs)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *Harness) GetPodLogs(name string) string {
	return h.GetPodLogsInNamespace("default", name)
}

func (h *Harness) GetPodLogsInNamespace(namespace, name string) string {
	out, err := exec.Command("kubectl", "logs", name, "--namespace", namespace).Output()
	if err != nil {
		h.t.Fatalf("Failed to get pod logs for %s/%s: %v", namespace, name, err)
	}
	return string(out)
}

func (h *Harness) GetControllerPod() string {
	cmd := exec.Command("kubectl", "get", "pods", "--namespace=default", "-l", "app=snigateway-controller", "--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) GetControllerLogs() string {
	ctrlPod := h.GetControllerPod()
	if ctrlPod == "" {
		return ""
	}
	out, err := exec.Command("kubectl", "logs", ctrlPod, "--namespace=default").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func (h *Harness) WaitForControllerLog(expectedSubstring string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		logs := h.GetControllerLogs()
		if strings.Contains(logs, expectedSubstring) {
			return logs
		}
		time.Sleep(500 * time.Millisecond)
	}
	h.t.Fatalf("Timed out after %v waiting for controller log containing %q; current logs:\n%s", timeout, expectedSubstring, h.GetControllerLogs())
	return ""
}

func (h *Harness) GetPodIP(name string) string {
	return h.GetPodIPInNamespace("default", name)
}

func (h *Harness) GetPodIPInNamespace(namespace, name string) string {
	out := h.runCmd("kubectl", "get", "pod", name, "--namespace", namespace, "-o", "jsonpath={.status.podIP}")
	return strings.TrimSpace(out)
}

func (h *Harness) DumpDeploymentLogs(namespace, name string) {
	out, err := exec.Command("kubectl", "logs", "deployment/"+name, "--namespace="+namespace, "--all-containers=true").CombinedOutput()
	if err != nil {
		h.t.Logf("Failed to get deployment logs for %s/%s: %v\nOutput: %s", namespace, name, err, string(out))
		return
	}
	h.t.Logf("=== Logs for deployment %s/%s ===\n%s\n=== End of logs for %s/%s ===", namespace, name, string(out), namespace, name)
}

func (h *Harness) runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("Command %s %v failed: %v\nStdout: %s\nStderr: %s", name, args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func (h *Harness) InstallGatewayAPI() {
	h.t.Log("Installing Gateway API CRDs")
	h.runCmd("kubectl", "apply", "-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/standard-install.yaml")
}

func (h *Harness) BackendManifest() string {
	return `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: default
spec:
  selector:
    app: backend
  ports:
  - port: 8080
    targetPort: 8080
`
}

func (h *Harness) MetallbConfigManifest() string {
	return `
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - 172.18.255.200-172.18.255.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
`
}

func (h *Harness) DeployBackend() {
	h.t.Log("Deploying Backend")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), gitRoot)
	h.KindLoad("toolbox:e2e")

	h.KubectlApplyContent(h.BackendManifest())
	h.WaitForDeployment("backend", 2*time.Minute)
}

func (h *Harness) CreateGenericSecret(name, namespace string, data map[string][]byte) {
	h.t.Logf("Creating secret %s/%s", namespace, name)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\ndata:\n", name, namespace))
	for k, v := range data {
		b.WriteString(fmt.Sprintf("  %s: %s\n", k, base64.StdEncoding.EncodeToString(v)))
	}
	h.KubectlApplyContent(b.String())
}

func (h *Harness) CreateTLSSecret(name, namespace string, certPEM, keyPEM []byte) {
	h.t.Logf("Creating TLS secret %s/%s", namespace, name)
	content := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, name, namespace, base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM))
	h.KubectlApplyContent(content)
}

// GenerateTestCertificate generates a self-signed ECDSA certificate and private key for testing.
func GenerateTestCertificate(commonName string, dnsNames ...string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial: %w", err)
	}

	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}

	now := time.Now().Add(-1 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"snigateway-e2e-test"},
		},
		DNSNames:              dnsNames,
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func (h *Harness) DeploySNIGatewayFrontend(namespace string, infraCerts *certs.GeneratedCerts) {
	h.t.Logf("Deploying snigateway-frontend in namespace %s", namespace)
	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, namespace))

	h.CreateGenericSecret("snigateway-frontend-certs", namespace, map[string][]byte{
		"ca.crt":     infraCerts.CA.CertPEM,
		"server.crt": infraCerts.Server.CertPEM,
		"server.key": infraCerts.Server.KeyPEM,
	})

	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snigateway-frontend
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snigateway-frontend
  template:
    metadata:
      labels:
        app: snigateway-frontend
    spec:
      containers:
      - name: frontend
        image: snigateway-frontend:e2e
        imagePullPolicy: Never
        args:
        - "--client-ca=/etc/snigateway-frontend/certs/ca.crt=*.snigateway.test"
        - "--server-cert=/etc/snigateway-frontend/certs/server.crt"
        - "--server-key=/etc/snigateway-frontend/certs/server.key"
        - "--listen=:443"
        - "--tunnel-listen-udp=:443"
        - "--internal-hostname=snigateway.internal"
        ports:
        - containerPort: 443
          name: https
          protocol: TCP
        - containerPort: 443
          name: https-udp
          protocol: UDP
        volumeMounts:
        - name: frontend-certs
          mountPath: /etc/snigateway-frontend/certs
          readOnly: true
      volumes:
      - name: frontend-certs
        secret:
          secretName: snigateway-frontend-certs
---
apiVersion: v1
kind: Service
metadata:
  name: snigateway-frontend
  namespace: %s
spec:
  selector:
    app: snigateway-frontend
  ports:
  - port: 443
    targetPort: 443
    protocol: TCP
    name: https
  - port: 443
    targetPort: 443
    protocol: UDP
    name: https-udp
`, namespace, namespace))

	h.runCmd("kubectl", "patch", "service", "snigateway-frontend", "--namespace="+namespace, "--type=merge", "-p", `{"spec":{"ports":[{"name":"https","port":443,"protocol":"TCP","targetPort":443},{"name":"https-udp","port":443,"protocol":"UDP","targetPort":443}]}}`)
	h.runCmd("kubectl", "rollout", "status", "deployment/snigateway-frontend", "--namespace="+namespace, "--timeout=2m")
}

func (h *Harness) DeploySNIGatewayFrontendTCPOnly(namespace string, infraCerts *certs.GeneratedCerts) {
	h.t.Logf("Deploying TCP-only snigateway-frontend in namespace %s", namespace)
	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, namespace))

	h.CreateGenericSecret("snigateway-frontend-certs", namespace, map[string][]byte{
		"ca.crt":     infraCerts.CA.CertPEM,
		"server.crt": infraCerts.Server.CertPEM,
		"server.key": infraCerts.Server.KeyPEM,
	})

	h.KubectlApplyContent(fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snigateway-frontend
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snigateway-frontend
  template:
    metadata:
      labels:
        app: snigateway-frontend
    spec:
      containers:
      - name: frontend
        image: snigateway-frontend:e2e
        imagePullPolicy: Never
        args:
        - "--client-ca=/etc/snigateway-frontend/certs/ca.crt=*.snigateway.test"
        - "--server-cert=/etc/snigateway-frontend/certs/server.crt"
        - "--server-key=/etc/snigateway-frontend/certs/server.key"
        - "--listen=:443"
        - "--tunnel-listen-udp=:443"
        - "--internal-hostname=snigateway.internal"
        ports:
        - containerPort: 443
          name: https
          protocol: TCP
        - containerPort: 443
          name: https-udp
          protocol: UDP
        volumeMounts:
        - name: frontend-certs
          mountPath: /etc/snigateway-frontend/certs
          readOnly: true
      volumes:
      - name: frontend-certs
        secret:
          secretName: snigateway-frontend-certs
---
apiVersion: v1
kind: Service
metadata:
  name: snigateway-frontend
  namespace: %s
spec:
  selector:
    app: snigateway-frontend
  ports:
  - port: 443
    targetPort: 443
    protocol: TCP
    name: https
`, namespace, namespace))

	h.runCmd("kubectl", "rollout", "status", "deployment/snigateway-frontend", "--namespace="+namespace, "--timeout=2m")
}

func (h *Harness) DeploySNIGatewayController(infraCerts *certs.GeneratedCerts, frontendAddr string, replicas int, transport ...string) {
	h.t.Logf("Deploying snigateway controller with %d replicas", replicas)
	gitRoot := h.GetGitRoot()

	h.CreateGenericSecret("snigateway-client-cert", "default", map[string][]byte{
		"ca.crt":     infraCerts.CA.CertPEM,
		"client.crt": infraCerts.Client.CertPEM,
		"client.key": infraCerts.Client.KeyPEM,
	})

	h.KubectlApplyFile(filepath.Join(gitRoot, "snigateway/k8s/controller.yaml"))

	transportMode := "auto"
	if len(transport) > 0 && transport[0] != "" {
		transportMode = transport[0]
	}

	extraArgs := ""
	if len(transport) > 1 && transport[1] != "" {
		extraArgs = fmt.Sprintf("\n        - %q", transport[1])
	}

	manifest := fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snigateway-controller
  namespace: default
spec:
  replicas: %d
  selector:
    matchLabels:
      app: snigateway-controller
  template:
    metadata:
      labels:
        app: snigateway-controller
    spec:
      serviceAccountName: snigateway-controller
      containers:
      - name: controller
        image: snigateway:e2e
        imagePullPolicy: Never
        args:
        - "--controller-name=github.com/gke-labs/gateway-api-reference-implementation/snigateway"
        - "--frontend=%s"
        - "--tunnel-transport=%s"
        - "--ca-cert=/etc/snigateway/certs/ca.crt"
        - "--client-cert=/etc/snigateway/certs/client.crt"
        - "--client-key=/etc/snigateway/certs/client.key"%s
        volumeMounts:
        - name: client-certs
          mountPath: /etc/snigateway/certs
          readOnly: true
      volumes:
      - name: client-certs
        secret:
          secretName: snigateway-client-cert
`, replicas, frontendAddr, transportMode, extraArgs)

	h.KubectlApplyContent(manifest)
	h.runCmd("kubectl", "rollout", "status", "deployment/snigateway-controller", "--namespace=default", "--timeout=2m")
}

func (h *Harness) SNIGatewayManifest(hostname, secretName string) string {
	return h.SNIGatewayManifestWithName("snigateway-test", hostname, secretName)
}

func (h *Harness) SNIGatewayManifestWithName(gwName, hostname, secretName string) string {
	return fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: %s
  namespace: default
spec:
  gatewayClassName: snigateway
  listeners:
  - name: https-echo
    protocol: HTTPS
    port: 443
    hostname: %q
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: %s
`, gwName, hostname, secretName)
}

func (h *Harness) SNIMultiListenerGatewayManifest() string {
	return `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: snigateway-test
  namespace: default
spec:
  gatewayClassName: snigateway
  listeners:
  - name: https-echo
    protocol: HTTPS
    port: 443
    hostname: "echo.snigateway.test"
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: echo-tls-cert
  - name: https-echo2
    protocol: HTTPS
    port: 443
    hostname: "echo2.snigateway.test"
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: echo2-tls-cert
`
}

func (h *Harness) SNIHTTPRouteManifest(routeName, gatewayName, hostname, backendService string, backendPort int) string {
	return fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: %s
  namespace: default
spec:
  parentRefs:
  - name: %s
  hostnames: [%q]
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: %s
      port: %d
`, routeName, gatewayName, hostname, backendService, backendPort)
}

func (h *Harness) SNIClientPodManifest(name string, args []string) string {
	var formattedArgs []string
	for _, arg := range args {
		formattedArgs = append(formattedArgs, fmt.Sprintf("%q", arg))
	}
	return fmt.Sprintf(`
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
    command: ["/app/toolbox"]
    args: [%s]
  restartPolicy: Never
`, name, strings.Join(formattedArgs, ", "))
}
