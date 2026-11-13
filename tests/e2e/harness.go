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
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

type Harness struct {
	// T is the test context. Exported so embedding test harnesses can access it.
	T *testing.T
	// ClusterName is the kind cluster name. Exported so embedding test harnesses can access it.
	ClusterName string

	setupDiagnosticsOnce sync.Once
	dumpOnce             sync.Once

	gatewayCreationTimestamps sync.Map
}

func NewHarness(t *testing.T, clusterName string) *Harness {
	return &Harness{
		T:           t,
		ClusterName: clusterName,
	}
}

func (h *Harness) Setup() {
	h.T.Logf("Setting up harness for cluster %s", h.ClusterName)
	// Check if kind is installed
	if _, err := exec.LookPath("kind"); err != nil {
		h.T.Fatalf("kind not found: %v", err)
	}
	// Check if kubectl is installed
	if _, err := exec.LookPath("kubectl"); err != nil {
		h.T.Fatalf("kubectl not found: %v", err)
	}

	// Create kind cluster if it doesn't exist
	clusters := h.RunCmd("kind", "get", "clusters")
	exists := false
	for _, cluster := range strings.Split(clusters, "\n") {
		if strings.TrimSpace(cluster) == h.ClusterName {
			exists = true
			break
		}
	}

	if !exists {
		h.T.Logf("Creating kind cluster %s", h.ClusterName)
		h.RunCmd("kind", "create", "cluster", "--name", h.ClusterName)
		h.T.Cleanup(func() {
			if os.Getenv("SKIP_CLEANUP") == "" {
				h.T.Logf("Deleting kind cluster %s", h.ClusterName)
				h.RunCmd("kind", "delete", "cluster", "--name", h.ClusterName)
			}
		})
	}

	h.SetupDiagnosticsCleanup()

	// Ensure we are using the correct context and namespace
	contextName := "kind-" + h.ClusterName
	h.RunCmd("kubectl", "config", "use-context", contextName)
	h.RunCmd("kubectl", "config", "set-context", "--current", "--namespace=default")

	h.InstallMetallb()
}

func (h *Harness) InstallMetallb() {
	h.T.Log("Installing Metallb")
	h.KubectlApplyWithRetry("-f", "https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml")
	h.RunCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=available", "deployment/controller", "--timeout=90s")
	h.RunCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=ready", "pod", "--selector=app=metallb", "--timeout=90s")

	// Configure Metallb with a range of IPs from the kind network
	h.RunCmd("docker", "network", "inspect", "kind")

	h.KubectlApplyContentWithRetry(h.MetallbConfigManifest(), 90*time.Second)
}

// RESTConfig returns the configuration for talking to the test kind cluster started from this harness.
func (h *Harness) RESTConfig() *rest.Config {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	cfg, err := kubeConfig.ClientConfig()
	if err != nil {
		h.T.Fatalf("Failed to load Kubernetes config: %v", err)
	}
	return cfg
}

func (h *Harness) GetGitRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		h.T.Fatalf("Failed to get git root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) DockerBuild(tag, dockerfile, context string) {
	h.T.Logf("Building docker image %s", tag)
	h.RunCmd("docker", "build", "-t", tag, "-f", dockerfile, context)
}

func (h *Harness) KindLoad(tag string) {
	h.T.Logf("Loading image %s into kind cluster %s", tag, h.ClusterName)
	h.RunCmd("kind", "load", "docker-image", tag, "--name", h.ClusterName)
}

func (h *Harness) KubectlApplyContent(content string) {
	h.T.Logf("Applying kubectl content:\n%s", content)
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.T.Fatalf("kubectl apply failed: %v\nStderr: %s", err, stderr.String())
	}
}

func (h *Harness) KubectlApplyContentWithRetry(content string, timeout time.Duration) {
	h.T.Logf("Applying kubectl content (with retry):\n%s", content)
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
			h.T.Fatalf("Timeout waiting for kubectl apply to succeed: %v\nStderr: %s", lastErr, lastStderr)
		}
		time.Sleep(2 * time.Second)
	}
}

func (h *Harness) KubectlApplyFile(path string) {
	h.T.Logf("Applying kubectl file: %s", path)
	h.RunCmd("kubectl", "apply", "-f", path)
}

var applyRetryDelays = []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second}

// KubectlApplyWithRetry runs kubectl apply with the provided arguments, retrying
// with backoff on failure before failing the test.
func (h *Harness) KubectlApplyWithRetry(args ...string) {
	commandArgs := append([]string{"apply"}, args...)
	maxAttempts := len(applyRetryDelays) + 1
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		_, err := h.RunCommand("kubectl", commandArgs...)
		if err == nil {
			return
		}
		lastErr = err
		if attempt < maxAttempts {
			h.T.Logf("kubectl %v failed (attempt %d/%d): %v; retrying...", commandArgs, attempt, maxAttempts, err)
			time.Sleep(applyRetryDelays[attempt-1])
		}
	}
	h.T.Fatalf("kubectl %v failed after %d attempts: %v", commandArgs, maxAttempts, lastErr)
}

// WaitForDeployment waits for a deployment in the default namespace to be ready.
func (h *Harness) WaitForDeployment(name string, timeout time.Duration) {
	h.WaitForDeploymentInNamespace("default", name, timeout)
}

// WaitForDeploymentInNamespace waits for a deployment in the specified namespace to be ready.
// Exported so embedding test harnesses can wait in non-default namespaces.
func (h *Harness) WaitForDeploymentInNamespace(namespace, name string, timeout time.Duration) {
	h.T.Logf("Waiting for deployment %s/%s to be ready", namespace, name)
	h.RunCmd("kubectl", "wait", "--namespace", namespace, "--for=condition=available", "--timeout="+timeout.String(), "deployment/"+name)
}

func (h *Harness) WaitForGatewayClassStatus(name string, timeout time.Duration) {
	h.T.Logf("Waiting for GatewayClass %s to have supportedFeatures populated", name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			logs, err := h.RunCommand("kubectl", "logs", "deployment/gari-controller", "--namespace=default")
			if err != nil {
				h.T.Logf("Failed to get controller logs on timeout: %v", err)
			} else if logs != "" {
				h.T.Logf("Controller logs on timeout:\n%s", logs)
			}
			h.T.Fatalf("Timeout waiting for GatewayClass %s supportedFeatures", name)
		}

		out, err := exec.Command("kubectl", "get", "gatewayclass", name, "-o", "jsonpath={.status.supportedFeatures}").Output()
		if err != nil {
			h.T.Logf("waiting for gatewayclass %s: %v", name, err)
		} else if strings.TrimSpace(string(out)) != "" {
			h.T.Logf("GatewayClass %s has supportedFeatures populated", name)
			return
		}
		time.Sleep(1 * time.Second)
	}
}

// FormatGatewayTiming formats a gateway lifecycle timing log entry.
func FormatGatewayTiming(namespace, name, event string, elapsed time.Duration) string {
	if elapsed < 0 {
		elapsed = 0
	}
	return fmt.Sprintf("gateway %s/%s: %s after %.2fs", namespace, name, event, elapsed.Seconds())
}

// SetGatewayCreationTimestamp stores the creationTimestamp for a Gateway in the harness cache.
func (h *Harness) SetGatewayCreationTimestamp(name, namespace string, creationTimestamp time.Time) {
	h.gatewayCreationTimestamps.Store(namespace+"/"+name, creationTimestamp)
}

// GatewayCreationTimestamp returns the metadata.creationTimestamp for the specified Gateway.
// It returns a cached timestamp if one was recorded during WaitForGatewayAddress,
// or queries the API server directly.
func (h *Harness) GatewayCreationTimestamp(name, namespace string) time.Time {
	if val, ok := h.gatewayCreationTimestamps.Load(namespace + "/" + name); ok {
		return val.(time.Time)
	}
	out, err := exec.Command("kubectl", "get", "gateway", name, "--namespace", namespace, "-o", "jsonpath={.metadata.creationTimestamp}").Output()
	if err != nil {
		h.T.Logf("failed to get gateway %s/%s creationTimestamp: %v", namespace, name, err)
		return time.Time{}
	}
	creationTimestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
	if err != nil {
		h.T.Logf("failed to parse gateway %s/%s creationTimestamp: %v", namespace, name, err)
		return time.Time{}
	}
	h.gatewayCreationTimestamps.Store(namespace+"/"+name, creationTimestamp)
	return creationTimestamp
}

// LogGatewayTiming logs the elapsed time since the Gateway's creationTimestamp.
func (h *Harness) LogGatewayTiming(name, namespace, event string) {
	creationTimestamp := h.GatewayCreationTimestamp(name, namespace)
	if creationTimestamp.IsZero() {
		return
	}
	h.T.Logf("%s", FormatGatewayTiming(namespace, name, event, time.Since(creationTimestamp)))
}

func (h *Harness) WaitForGatewayAddress(name, namespace string, timeout time.Duration) string {
	h.T.Logf("Waiting for Gateway %s/%s to have an address assigned", namespace, name)
	start := time.Now()
	var (
		addr              string
		loggedAddress     bool
		loggedProgrammed  bool
		creationTimestamp time.Time
	)
	for {
		if time.Since(start) > timeout {
			logs, err := h.RunCommand("kubectl", "logs", "deployment/gari-controller", "--namespace=default")
			if err != nil {
				h.T.Logf("Failed to get controller logs on timeout: %v", err)
			} else if logs != "" {
				h.T.Logf("Controller logs on timeout:\n%s", logs)
			}
			h.T.Fatalf("Timeout waiting for Gateway %s/%s address", namespace, name)
		}

		out, err := exec.Command("kubectl", "get", "gateway", name, "--namespace", namespace, "-o", "json").Output()
		if err != nil {
			h.T.Logf("waiting for gateway %s/%s address: %v", namespace, name, err)
		} else {
			var gatewayObj struct {
				Metadata struct {
					CreationTimestamp time.Time `json:"creationTimestamp"`
				} `json:"metadata"`
				Status struct {
					Addresses []struct {
						Value string `json:"value"`
					} `json:"addresses"`
					Conditions []struct {
						Type   string `json:"type"`
						Status string `json:"status"`
					} `json:"conditions"`
				} `json:"status"`
			}
			if err := json.Unmarshal(out, &gatewayObj); err != nil {
				h.T.Logf("failed to parse gateway %s/%s: %v", namespace, name, err)
			} else {
				if !gatewayObj.Metadata.CreationTimestamp.IsZero() {
					creationTimestamp = gatewayObj.Metadata.CreationTimestamp
					h.SetGatewayCreationTimestamp(name, namespace, creationTimestamp)
				}
				if !loggedAddress && len(gatewayObj.Status.Addresses) > 0 && strings.TrimSpace(gatewayObj.Status.Addresses[0].Value) != "" {
					addr = strings.TrimSpace(gatewayObj.Status.Addresses[0].Value)
					loggedAddress = true
					h.T.Logf("Gateway %s/%s assigned address: %s", namespace, name, addr)
					if !creationTimestamp.IsZero() {
						h.LogGatewayTiming(name, namespace, "address assigned")
					}
				}
				if !loggedProgrammed {
					for _, condition := range gatewayObj.Status.Conditions {
						if condition.Type == "Programmed" && condition.Status == "True" {
							loggedProgrammed = true
							if !creationTimestamp.IsZero() {
								h.LogGatewayTiming(name, namespace, "Programmed=True")
							}
							break
						}
					}
				}
				if loggedAddress && loggedProgrammed {
					return addr
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (h *Harness) WaitForGatewayClassSupportedVersion(name string, timeout time.Duration) {
	h.T.Logf("Waiting for GatewayClass %s to have SupportedVersion=True", name)
	start := time.Now()
	var lastErr error
	for {
		if time.Since(start) > timeout {
			out, err := h.RunCommand("kubectl", "get", "gatewayclass", name, "-o", `jsonpath=status={.status.conditions[?(@.type=="SupportedVersion")].status} reason={.status.conditions[?(@.type=="SupportedVersion")].reason} message={.status.conditions[?(@.type=="SupportedVersion")].message}`)
			if err != nil {
				h.T.Logf("failed getting conditions on timeout: %v", err)
			}
			if lastErr != nil {
				h.T.Fatalf("Timeout waiting for GatewayClass %s SupportedVersion=True (last error: %v): %s", name, lastErr, out)
			}
			h.T.Fatalf("Timeout waiting for GatewayClass %s SupportedVersion=True: %s", name, out)
		}

		cmd := exec.Command("kubectl", "get", "gatewayclass", name, "-o", `jsonpath={.status.conditions[?(@.type=="SupportedVersion")].status} {.status.conditions[?(@.type=="SupportedVersion")].reason}`)
		out, err := cmd.Output()
		if err != nil {
			lastErr = err
			h.T.Logf("waiting for GatewayClass %s SupportedVersion condition: %v", name, err)
		} else {
			fields := strings.Fields(strings.TrimSpace(string(out)))
			if len(fields) >= 2 && fields[0] == "True" && fields[1] == "SupportedVersion" {
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (h *Harness) WaitForResourceDeletion(kind, name, namespace string, timeout time.Duration) {
	h.T.Logf("Waiting for %s %s/%s to be deleted", kind, namespace, name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.T.Fatalf("Timeout waiting for %s %s/%s deletion", kind, namespace, name)
		}

		out, err := exec.Command("kubectl", "get", kind, name, "--namespace", namespace, "-o", "jsonpath={.metadata.name}").Output()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// DeletePod deletes a pod in the default namespace, ignoring if not found.
func (h *Harness) DeletePod(name string) {
	h.DeletePodInNamespace("default", name)
}

// DeletePodInNamespace deletes a pod in the specified namespace, ignoring if not found.
// Exported so embedding test harnesses can delete pods in non-default namespaces.
func (h *Harness) DeletePodInNamespace(namespace, name string) {
	h.T.Logf("Deleting pod %s/%s", namespace, name)
	if err := exec.Command("kubectl", "delete", "pod", name, "--namespace", namespace, "--ignore-not-found").Run(); err != nil {
		h.T.Logf("failed to delete pod %s/%s: %v", namespace, name, err)
	}
}

// WaitForPodSuccess waits for a pod in the default namespace to reach the Succeeded phase.
func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.WaitForPodSuccessInNamespace("default", name, timeout)
}

// WaitForPodSuccessInNamespace waits for a pod in the specified namespace to reach the Succeeded phase.
// Exported so embedding test harnesses can wait in non-default namespaces.
func (h *Harness) WaitForPodSuccessInNamespace(namespace, name string, timeout time.Duration) {
	h.T.Logf("Waiting for pod %s/%s to succeed", namespace, name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.T.Fatalf("Timeout waiting for pod %s/%s to succeed", namespace, name)
		}

		out, err := exec.Command("kubectl", "get", "pod", name, "--namespace", namespace, "-o", "jsonpath={.status.phase}").Output()
		if err != nil {
			h.T.Logf("waiting for pod %s/%s phase: %v", namespace, name, err)
		} else {
			phase := strings.TrimSpace(string(out))
			if phase == "Succeeded" {
				return
			}
			if phase == "Failed" {
				podLogs := h.GetPodLogsInNamespace(namespace, name)
				h.T.Logf("Pod %s/%s logs on failure:\n%s", namespace, name, podLogs)
				dataplaneLogs, err := h.RunCommand("kubectl", "logs", "--selector=app.kubernetes.io/managed-by=gari-singlepod", "--namespace="+namespace)
				if err != nil {
					h.T.Logf("Failed to get dataplane logs on failure: %v", err)
				} else if dataplaneLogs != "" {
					h.T.Logf("Dataplane logs on failure:\n%s", dataplaneLogs)
				}
				dataplanePods, err := h.RunCommand("kubectl", "get", "pods", "--namespace="+namespace)
				if err != nil {
					h.T.Logf("Failed to get dataplane pods on failure: %v", err)
				} else if dataplanePods != "" {
					h.T.Logf("All pods on failure:\n%s", dataplanePods)
				}
				h.T.Fatalf("Pod %s/%s failed", namespace, name)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// GetPodLogs returns logs for a pod in the default namespace.
func (h *Harness) GetPodLogs(name string) string {
	return h.GetPodLogsInNamespace("default", name)
}

// GetPodLogsInNamespace returns logs for a pod in the specified namespace.
// Exported so embedding test harnesses can get logs in non-default namespaces.
func (h *Harness) GetPodLogsInNamespace(namespace, name string) string {
	out, err := exec.Command("kubectl", "logs", name, "--namespace", namespace).Output()
	if err != nil {
		h.T.Fatalf("Failed to get pod logs for %s/%s: %v", namespace, name, err)
	}
	return string(out)
}

// GetPodIP returns the IP address of a pod in the default namespace.
func (h *Harness) GetPodIP(name string) string {
	return h.GetPodIPInNamespace("default", name)
}

// GetPodIPInNamespace returns the IP address of a pod in the specified namespace.
// Exported so embedding test harnesses can query pod IP in non-default namespaces.
func (h *Harness) GetPodIPInNamespace(namespace, name string) string {
	out := h.RunCmd("kubectl", "get", "pod", name, "--namespace", namespace, "-o", "jsonpath={.status.podIP}")
	return strings.TrimSpace(out)
}

// RunCommand executes a command and returns its stdout or an error containing stderr.
// Exported so external test harnesses (such as snigateway) can execute commands.
func (h *Harness) RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command %s %v failed: %w\nStdout: %s\nStderr: %s", name, args, err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

// RunCmd executes a command and fails the test if it exits with an error.
// Exported so external test harnesses (such as snigateway) can execute commands.
func (h *Harness) RunCmd(name string, args ...string) string {
	stdout, err := h.RunCommand(name, args...)
	if err != nil {
		h.T.Fatalf("%v", err)
	}
	return stdout
}

// PreviousMinorCRDVersion is the previous minor Gateway API release bundle version supported by the controller.
const PreviousMinorCRDVersion = "v1.6.3"

func (h *Harness) InstallGatewayAPI(version string) {
	h.T.Logf("Installing Gateway API CRDs (%s)", version)
	h.KubectlApplyWithRetry("--server-side", "--force-conflicts", "-f", fmt.Sprintf("https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml", version))
}

func (h *Harness) DeployController() {
	h.T.Log("Deploying Controller")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("gari-controller:e2e", filepath.Join(gitRoot, "images/gari-controller/Dockerfile"), gitRoot)
	h.KindLoad("gari-controller:e2e")

	h.KubectlApplyFile(filepath.Join(gitRoot, "k8s/controller.yaml"))
	h.RunCmd("kubectl", "set", "image", "deployment/gari-controller", "controller=gari-controller:e2e", "--namespace=default")
	h.RunCmd("kubectl", "patch", "deployment", "gari-controller", "-p", `{"spec":{"template":{"spec":{"containers":[{"name":"controller","imagePullPolicy":"Never","args":["--dataplane-image","gari-controller:e2e","--enable-h2c"]}]}}}}`)
	h.RunCmd("kubectl", "rollout", "restart", "deployment/gari-controller", "--namespace=default")
	h.RunCmd("kubectl", "rollout", "status", "deployment/gari-controller", "--namespace=default", "--timeout=2m")
}

// DumpDiagnostics dumps cluster diagnostics on test failure: the Gateways with their status,
// the data-plane Deployments and Pods, recent events, and the controller's log tail.
func (h *Harness) DumpDiagnostics() {
	h.T.Log("=== DUMPING GATEWAYS ===")
	if out, err := h.RunCommand("kubectl", "get", "gateways", "-A", "-o", "yaml"); err != nil {
		h.T.Logf("Failed to get gateways: %v", err)
	} else if strings.TrimSpace(out) != "" {
		h.T.Logf("Gateways:\n%s", out)
	}

	h.T.Log("=== DUMPING DATA-PLANE DEPLOYMENTS AND PODS ===")
	if out, err := h.RunCommand("kubectl", "get", "deployments,pods", "-A", "-l", singlepod.LabelGatewayName, "-o", "wide"); err != nil {
		h.T.Logf("Failed to get data-plane deployments and pods: %v", err)
	} else if strings.TrimSpace(out) != "" {
		h.T.Logf("Data-plane Deployments and Pods:\n%s", out)
	}

	h.T.Log("=== DUMPING RECENT EVENTS ===")
	if out, err := h.RunCommand("kubectl", "get", "events", "-A", "--sort-by=.metadata.creationTimestamp"); err != nil {
		h.T.Logf("Failed to get events: %v", err)
	} else if strings.TrimSpace(out) != "" {
		h.T.Logf("Recent events:\n%s", out)
	}

	h.T.Log("=== DUMPING CONTROLLER LOGS ===")
	logs, err := h.RunCommand("kubectl", "logs", "deployment/gari-controller", "--namespace=default", "--tail=2000")
	if err != nil {
		if sniLogs, sniErr := h.RunCommand("kubectl", "logs", "deployment/snigateway-controller", "--namespace=default", "--tail=2000"); sniErr == nil && strings.TrimSpace(sniLogs) != "" {
			logs = sniLogs
			err = nil
		}
	}
	if err != nil {
		h.T.Logf("Failed to get controller logs: %v", err)
	} else if strings.TrimSpace(logs) != "" {
		h.T.Logf("Controller logs:\n%s", logs)
	}
}

// SetupDiagnosticsCleanup sets up failure cleanup and a pre-timeout timer to dump diagnostics.
// If the test has a deadline, a timer fires ~1 minute before the test binary's timeout panic,
// ensuring cluster diagnostics and controller logs are captured before the test terminates.
func (h *Harness) SetupDiagnosticsCleanup() {
	h.setupDiagnosticsOnce.Do(func() {
		runDump := func() {
			h.dumpOnce.Do(func() {
				h.DumpDiagnostics()
			})
		}

		h.T.Cleanup(func() {
			if h.T.Failed() {
				runDump()
			}
		})

		if deadline, ok := h.T.Deadline(); ok {
			timeRemaining := time.Until(deadline)
			fireIn := timeRemaining - 1*time.Minute
			if fireIn <= 0 && timeRemaining > 0 {
				fireIn = timeRemaining / 2
			}
			if fireIn > 0 {
				timer := time.AfterFunc(fireIn, func() {
					h.T.Log("=== PRE-TIMEOUT DIAGNOSTIC DUMP (firing ~1m before test deadline) ===")
					runDump()
				})
				h.T.Cleanup(func() {
					timer.Stop()
				})
			}
		}
	})
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
	h.T.Logf("Creating TLS secret %s/%s", namespace, name)
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
		h.T.Fatalf("failed to marshal args: %v", err)
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
	h.T.Log("Deploying Backend")
	gitRoot := h.GetGitRoot()
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), gitRoot)
	h.KindLoad("toolbox:e2e")

	h.KubectlApplyContent(h.BackendManifest())
	h.WaitForDeployment("backend", 2*time.Minute)
}
