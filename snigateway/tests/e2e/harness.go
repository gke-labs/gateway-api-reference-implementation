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
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	roote2e "github.com/gke-labs/gateway-api-reference-implementation/tests/e2e"
)

type Harness struct {
	*roote2e.Harness
}

func NewHarness(t *testing.T, clusterName string) *Harness {
	return &Harness{
		Harness: roote2e.NewHarness(t, clusterName),
	}
}

// GenerateTestCertificate delegates to root e2e.GenerateTestCertificate.
func GenerateTestCertificate(commonName string, dnsNames ...string) (certPEM, keyPEM []byte, err error) {
	return roote2e.GenerateTestCertificate(commonName, dnsNames...)
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
	h.T.Fatalf("Timed out after %v waiting for controller log containing %q; current logs:\n%s", timeout, expectedSubstring, h.GetControllerLogs())
	return ""
}

func (h *Harness) WaitForGatewayProgrammed(name, namespace string, timeout time.Duration) {
	h.T.Logf("Waiting for Gateway %s/%s to have Programmed=True condition...", namespace, name)
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			h.T.Fatalf("Timeout waiting for Gateway %s/%s to be Programmed=True", namespace, name)
		}
		cmd := exec.Command("kubectl", "get", "gateway", name, "--namespace="+namespace, "-o", "jsonpath={.status.conditions[?(@.type==\"Programmed\")].status}")
		out, err := cmd.Output()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		status := strings.TrimSpace(string(out))
		if status == "True" {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func (h *Harness) WaitForGatewayProgrammedFalse(name, namespace string, timeout time.Duration) (reason string, message string) {
	h.T.Logf("Waiting for Gateway %s/%s to have Programmed=False condition...", namespace, name)
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			h.T.Fatalf("Timeout waiting for Gateway %s/%s to be Programmed=False", namespace, name)
		}
		cmdStatus := exec.Command("kubectl", "get", "gateway", name, "--namespace="+namespace, "-o", "jsonpath={.status.conditions[?(@.type==\"Programmed\")].status}")
		outStatus, err := cmdStatus.Output()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		if strings.TrimSpace(string(outStatus)) == "False" {
			cmdReason := exec.Command("kubectl", "get", "gateway", name, "--namespace="+namespace, "-o", "jsonpath={.status.conditions[?(@.type==\"Programmed\")].reason}")
			outReason, err := cmdReason.Output()
			if err != nil {
				h.T.Logf("Failed getting condition reason: %v", err)
			}
			cmdMsg := exec.Command("kubectl", "get", "gateway", name, "--namespace="+namespace, "-o", "jsonpath={.status.conditions[?(@.type==\"Programmed\")].message}")
			outMsg, err := cmdMsg.Output()
			if err != nil {
				h.T.Logf("Failed getting condition message: %v", err)
			}
			return strings.TrimSpace(string(outReason)), strings.TrimSpace(string(outMsg))
		}
		time.Sleep(1 * time.Second)
	}
}

func (h *Harness) DumpDeploymentLogs(namespace, name string) {
	out, err := exec.Command("kubectl", "logs", "deployment/"+name, "--namespace="+namespace, "--all-containers=true").CombinedOutput()
	if err != nil {
		h.T.Logf("Failed to get deployment logs for %s/%s: %v\nOutput: %s", namespace, name, err, string(out))
		return
	}
	h.T.Logf("=== Logs for deployment %s/%s ===\n%s\n=== End of logs for %s/%s ===", namespace, name, string(out), namespace, name)
}

func (h *Harness) InstallGatewayAPI() {
	h.T.Log("Installing Gateway API CRDs")
	h.KubectlApplyWithRetry("-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml")
}

func (h *Harness) CreateGenericSecret(name, namespace string, data map[string][]byte) {
	h.T.Logf("Creating secret %s/%s", namespace, name)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\ndata:\n", name, namespace))
	for k, v := range data {
		b.WriteString(fmt.Sprintf("  %s: %s\n", k, base64.StdEncoding.EncodeToString(v)))
	}
	h.KubectlApplyContent(b.String())
}

func (h *Harness) DeploySNIGatewayFrontend(namespace string, infraCerts *certs.GeneratedCerts) {
	h.T.Logf("Deploying snigateway-frontend in namespace %s", namespace)
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

	h.RunCmd("kubectl", "patch", "service", "snigateway-frontend", "--namespace="+namespace, "--type=merge", "-p", `{"spec":{"ports":[{"name":"https","port":443,"protocol":"TCP","targetPort":443},{"name":"https-udp","port":443,"protocol":"UDP","targetPort":443}]}}`)
	h.RunCmd("kubectl", "rollout", "status", "deployment/snigateway-frontend", "--namespace="+namespace, "--timeout=2m")
}

func (h *Harness) DeploySNIGatewayFrontendTCPOnly(namespace string, infraCerts *certs.GeneratedCerts) {
	h.T.Logf("Deploying TCP-only snigateway-frontend in namespace %s", namespace)
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

	h.RunCmd("kubectl", "rollout", "status", "deployment/snigateway-frontend", "--namespace="+namespace, "--timeout=2m")
}

func (h *Harness) DeploySNIGatewayController(infraCerts *certs.GeneratedCerts, frontendAddr string, replicas int, transport ...string) {
	h.T.Logf("Deploying snigateway controller with %d replicas", replicas)
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
	h.RunCmd("kubectl", "rollout", "status", "deployment/snigateway-controller", "--namespace=default", "--timeout=2m")
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
