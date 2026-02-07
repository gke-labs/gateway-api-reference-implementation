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

	// 1. Install Gateway API CRDs
	h.InstallGatewayAPI()

	// 2. Deploy Controller
	h.DeployController()

	// 3. Deploy Backend (Toolbox Server)
	h.DeployBackend()

	// 4. Create Gateway API Resources
	h.KubectlApplyContent(h.ExampleGatewayManifest())
	// Give the controller some time to reconcile
	time.Sleep(5 * time.Second)

	// 5. Run Client Pod
	clientPodName := "test-client"
	h.DeletePod(clientPodName)

	h.KubectlApplyContent(h.ClientManifest("http://gari-proxy", "example.com"))
	h.WaitForPodSuccess(clientPodName, 1*time.Minute)

	logs := h.GetPodLogs(clientPodName)
	t.Logf("Client logs: %s", logs)

	// 6. Verify
	if !strings.Contains(logs, "Status: 200 OK") {
		t.Errorf("Expected 200 OK, got: %s", logs)
	}
	if !strings.Contains(logs, "\"hostname\":\"example.com\"") {
		t.Errorf("Expected hostname example.com in response body, got: %s", logs)
	}
}
