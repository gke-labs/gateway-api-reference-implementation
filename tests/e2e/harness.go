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

	// Configure Metallb with a range of IPs from the kind network
	h.runCmd("docker", "network", "inspect", "kind")

	h.KubectlApplyContent(h.MetallbConfigManifest())
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

func (h *Harness) KubectlApplyFile(path string) {
	h.t.Logf("Applying kubectl file: %s", path)
	h.runCmd("kubectl", "apply", "-f", path)
}

func (h *Harness) WaitForDeployment(name string, timeout time.Duration) {
	h.t.Logf("Waiting for deployment %s to be ready", name)
	h.runCmd("kubectl", "wait", "--namespace", "default", "--for=condition=available", "--timeout="+timeout.String(), "deployment/"+name)
}

func (h *Harness) DeletePod(name string) {
	h.t.Logf("Deleting pod %s", name)
	exec.Command("kubectl", "delete", "pod", name, "--namespace", "default", "--ignore-not-found").Run()
}

func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.t.Logf("Waiting for pod %s to succeed", name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for pod %s to succeed", name)
		}

		out, err := exec.Command("kubectl", "get", "pod", name, "--namespace", "default", "-o", "jsonpath={.status.phase}").Output()
		if err == nil {
			phase := strings.TrimSpace(string(out))
			if phase == "Succeeded" {
				return
			}
			if phase == "Failed" {
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
	h.runCmd("kubectl", "apply", "-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.1.0/standard-install.yaml")
}

func (h *Harness) DeployController() {
	h.t.Log("Deploying Controller")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("gari-controller:e2e", filepath.Join(gitRoot, "Dockerfile"), gitRoot)
	h.KindLoad("gari-controller:e2e")

	h.KubectlApplyFile(filepath.Join(gitRoot, "k8s/controller.yaml"))
	h.runCmd("kubectl", "set", "image", "deployment/gari-controller", "controller=gari-controller:e2e", "--namespace=default")
	h.runCmd("kubectl", "annotate", "deployment/gari-controller", "restartedAt="+time.Now().Format(time.RFC3339), "--namespace=default", "--overwrite")

	h.WaitForDeployment("gari-controller", 2*time.Minute)
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

func (h *Harness) ClientManifest(url string, host string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-client
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client", "%s", "%s"]
  restartPolicy: Never
`, url, host)
}

func (h *Harness) DeployBackend() {
	h.t.Log("Deploying Backend")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))
	h.KindLoad("toolbox:e2e")

	h.KubectlApplyContent(h.BackendManifest())
	h.WaitForDeployment("backend", 2*time.Minute)
}
