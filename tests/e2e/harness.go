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
	"os/exec"
	"strings"
	"testing"
	"time"
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

	// Ensure we are using the correct context
	h.runCmd("kubectl", "config", "use-context", "kind-"+h.clusterName)
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
	h.t.Log("Applying kubectl content")
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("kubectl apply failed: %v\nStderr: %s", err, stderr.String())
	}
}

func (h *Harness) WaitForDeployment(name string, timeout time.Duration) {
	h.t.Logf("Waiting for deployment %s to be ready", name)
	h.runCmd("kubectl", "wait", "--for=condition=available", "--timeout="+timeout.String(), "deployment/"+name)
}

func (h *Harness) DeletePod(name string) {
	h.t.Logf("Deleting pod %s", name)
	exec.Command("kubectl", "delete", "pod", name, "--ignore-not-found").Run()
}

func (h *Harness) WaitForPodSuccess(name string, timeout time.Duration) {
	h.t.Logf("Waiting for pod %s to succeed", name)
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			h.t.Fatalf("Timeout waiting for pod %s to succeed", name)
		}

		out, err := exec.Command("kubectl", "get", "pod", name, "-o", "jsonpath={.status.phase}").Output()
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
	out, err := exec.Command("kubectl", "logs", name).Output()
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
