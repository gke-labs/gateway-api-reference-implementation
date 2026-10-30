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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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

	gitRoot := h.GetGitRoot()
	buildBin := filepath.Join(gitRoot, ".build/bin")
	if _, err := os.Stat(buildBin); err != nil {
		if !os.IsNotExist(err) {
			h.t.Logf("checking .build/bin: %v", err)
		}
	} else {
		h.t.Setenv("PATH", buildBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	// Check if kind is installed
	if _, err := exec.LookPath("kind"); err != nil {
		h.t.Fatalf("kind not found: %v", err)
	}
	// Check if kubectl is installed
	if _, err := exec.LookPath("kubectl"); err != nil {
		h.t.Fatalf("kubectl not found: %v", err)
	}

	// Create kind cluster if it doesn't exist
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

	// Ensure we are using the correct context and namespace
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

	// Configure Metallb with a range of IPs from the kind network
	h.runCmd("docker", "network", "inspect", "kind")

	h.KubectlApplyContentWithRetry(h.MetallbConfigManifest(), 90*time.Second)
}

// RESTConfig returns the configuration for talking to the test kind cluster started from this harness.
func (h *Harness) RESTConfig() *rest.Config {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	cfg, err := kubeConfig.ClientConfig()
	if err != nil {
		h.t.Fatalf("Failed to load Kubernetes config: %v", err)
	}
	return cfg
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
	h.runCmd("docker", "buildx", "build", "-t", tag, "-f", dockerfile, context)
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
	h.t.Logf("Waiting for deployment %s to be ready", name)
	h.runCmd("kubectl", "wait", "--namespace", "default", "--for=condition=available", "--timeout="+timeout.String(), "deployment/"+name)
}

func (h *Harness) WaitForGatewayAddress(name, namespace string, timeout time.Duration) string {
	h.t.Logf("Waiting for Gateway %s/%s to have an address assigned", namespace, name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			logs := h.runCmd("kubectl", "logs", "deployment/gari-controller", "--namespace=default")
			h.t.Logf("Controller logs on timeout:\n%s", logs)
			h.t.Fatalf("Timeout waiting for Gateway %s/%s address", namespace, name)
		}

		out, err := exec.Command("kubectl", "get", "gateway", name, "--namespace", namespace, "-o", "jsonpath={.status.addresses[0].value}").Output()
		if err != nil {
			h.t.Logf("waiting for gateway %s/%s address: %v", namespace, name, err)
		} else {
			addr := strings.TrimSpace(string(out))
			if addr != "" {
				h.t.Logf("Gateway %s/%s assigned address: %s", namespace, name, addr)
				return addr
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (h *Harness) WaitForResourceDeletion(kind, name, namespace string, timeout time.Duration) {
	h.t.Logf("Waiting for %s %s/%s to be deleted", kind, namespace, name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for %s %s/%s deletion", kind, namespace, name)
		}

		out, err := exec.Command("kubectl", "get", kind, name, "--namespace", namespace, "-o", "jsonpath={.metadata.name}").Output()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (h *Harness) DeletePod(name string) {
	h.t.Logf("Deleting pod %s", name)
	if err := exec.Command("kubectl", "delete", "pod", name, "--namespace", "default", "--ignore-not-found").Run(); err != nil {
		h.t.Logf("failed to delete pod %s: %v", name, err)
	}
}

func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.t.Logf("Waiting for pod %s to succeed", name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for pod %s to succeed", name)
		}

		out, err := exec.Command("kubectl", "get", "pod", name, "--namespace", "default", "-o", "jsonpath={.status.phase}").Output()
		if err != nil {
			h.t.Logf("waiting for pod %s phase: %v", name, err)
		} else {
			phase := strings.TrimSpace(string(out))
			if phase == "Succeeded" {
				return
			}
			if phase == "Failed" {
				podLogs := h.GetPodLogs(name)
				h.t.Logf("Pod %s logs on failure:\n%s", name, podLogs)
				dataplaneLogs := h.runCmd("kubectl", "logs", "--selector=app.kubernetes.io/managed-by=gari-singlepod", "--namespace=default")
				h.t.Logf("Dataplane logs on failure:\n%s", dataplaneLogs)
				dataplanePods := h.runCmd("kubectl", "get", "pods", "--namespace=default")
				h.t.Logf("All pods on failure:\n%s", dataplanePods)
				h.t.Fatalf("Pod %s failed", name)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *Harness) GetPodLogs(name string) string {
	out, err := exec.Command("kubectl", "logs", name, "--namespace", "default").Output()
	if err != nil {
		h.t.Fatalf("Failed to get pod logs for %s: %v", name, err)
	}
	return string(out)
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
	h.runCmd("kubectl", "apply", "--server-side", "--force-conflicts", "-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/experimental-install.yaml")
}

func (h *Harness) DeployController() {
	h.t.Log("Deploying Controller")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("gari-controller:e2e", filepath.Join(gitRoot, "images/gari-controller/Dockerfile"), gitRoot)
	h.KindLoad("gari-controller:e2e")

	h.KubectlApplyFile(filepath.Join(gitRoot, "k8s/controller.yaml"))
	h.runCmd("kubectl", "set", "image", "deployment/gari-controller", "controller=gari-controller:e2e", "--namespace=default")
	h.runCmd("kubectl", "patch", "deployment", "gari-controller", "-p", `{"spec":{"template":{"spec":{"containers":[{"name":"controller","imagePullPolicy":"Never","args":["--dataplane-image","gari-controller:e2e","--enable-h2c"]}]}}}}`)
	h.runCmd("kubectl", "rollout", "restart", "deployment/gari-controller", "--namespace=default")
	h.runCmd("kubectl", "rollout", "status", "deployment/gari-controller", "--namespace=default", "--timeout=2m")
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
  - 172.18.255.200-172.18.255.239
  - 172.18.255.241-172.18.255.250
---
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: static-address-pool
  namespace: metallb-system
spec:
  addresses:
  - 172.18.255.240-172.18.255.240
  autoAssign: false
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
`
}

func (h *Harness) ExampleGatewayManifest() string {
	return `
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: reference-gateway
  namespace: default
spec:
  gatewayClassName: reference-class
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  - name: https
    protocol: HTTPS
    port: 443
    hostname: "example.com"
    tls:
      mode: Terminate
      certificateRefs:
      - kind: Secret
        name: gateway-tls-cert
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
  namespace: default
spec:
  parentRefs:
  - name: reference-gateway
  hostnames: ["example.com"]
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`
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
			Organization: []string{"gari-e2e-test"},
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

func (h *Harness) ClientManifest(url string, host string) string {
	return h.ClientManifestWithArgs("test-client", url, host)
}

func (h *Harness) ClientManifestWithArgs(name string, args ...string) string {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		h.t.Fatalf("failed to marshal args: %v", err)
	}
	return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client"]
    args: %s
  restartPolicy: Never
`, name, string(argsJSON))
}

func (h *Harness) DeployBackend() {
	h.t.Log("Deploying Backend")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), gitRoot)
	h.KindLoad("toolbox:e2e")

	h.KubectlApplyContent(h.BackendManifest())
	h.WaitForDeployment("backend", 2*time.Minute)
}
