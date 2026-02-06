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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	gitRoot := h.GetGitRoot()

	// 1. Build and load images
	h.DockerBuild("gateway-api-ref:e2e", filepath.Join(gitRoot, "Dockerfile"), gitRoot)
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), filepath.Join(gitRoot, "tests/toolbox"))

	h.KindLoad("gateway-api-ref:e2e")
	h.KindLoad("toolbox:e2e")

	// 2. Install Gateway API CRDs
	h.runCmd("kubectl", "apply", "-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.1.0/standard-install.yaml")

	// 3. Deploy Controller
	controllerManifest := `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gateway-api-ref-controller
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-api-ref-controller
rules:
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["httproutes"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-api-ref-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gateway-api-ref-controller
subjects:
- kind: ServiceAccount
  name: gateway-api-ref-controller
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway-api-ref-controller
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gateway-api-ref-controller
  template:
    metadata:
      labels:
        app: gateway-api-ref-controller
    spec:
      serviceAccountName: gateway-api-ref-controller
      containers:
      - name: controller
        image: gateway-api-ref:e2e
        imagePullPolicy: Never
        args: ["--proxy-bind-address", ":8000"]
        ports:
        - containerPort: 8000
          name: proxy
---
apiVersion: v1
kind: Service
metadata:
  name: gateway-proxy
spec:
  selector:
    app: gateway-api-ref-controller
  ports:
  - port: 80
    targetPort: 8000
`
	h.KubectlApplyContent(controllerManifest)
	h.WaitForDeployment("gateway-api-ref-controller", 2*time.Minute)

	// 4. Deploy Backend (Toolbox Server)
	backendManifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
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
spec:
  selector:
    app: backend
  ports:
  - port: 8080
    targetPort: 8080
`
	h.KubectlApplyContent(backendManifest)
	h.WaitForDeployment("backend", 2*time.Minute)

	// 5. Create Gateway API Resources
	gwResources := `
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: reference-class
spec:
  controllerName: github.com/gke-labs/gateway-api-reference-implementation
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: reference-gateway
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
spec:
  parentRefs:
  - name: reference-gateway
  hostnames: ["example.com"]
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`
	h.KubectlApplyContent(gwResources)
	// Give the controller some time to reconcile
	time.Sleep(5 * time.Second)

	// 6. Run Client Pod
	clientPodName := "test-client"
	h.DeletePod(clientPodName)

	clientManifest := `
apiVersion: v1
kind: Pod
metadata:
  name: test-client
spec:
  containers:
  - name: toolbox
    image: toolbox:e2e
    imagePullPolicy: Never
    command: ["/app/toolbox", "client", "http://gateway-proxy", "example.com"]
  restartPolicy: Never
`
	h.KubectlApplyContent(clientManifest)
	h.WaitForPodSuccess(clientPodName, 1*time.Minute)

	logs := h.GetPodLogs(clientPodName)
	t.Logf("Client logs: %s", logs)

	// 7. Verify
	if !strings.Contains(logs, "Status: 200 OK") {
		t.Errorf("Expected 200 OK, got: %s", logs)
	}
	if !strings.Contains(logs, "\"hostname\":\"example.com\"") {
		t.Errorf("Expected hostname example.com in response body, got: %s", logs)
	}
}
