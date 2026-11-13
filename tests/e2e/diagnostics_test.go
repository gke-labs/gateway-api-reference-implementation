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
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSetupDiagnosticsCleanup_PassingTest(t *testing.T) {
	if os.Getenv("TEST_DIAGNOSTICS_PASSING_HELPER") == "1" {
		h := NewHarness(t, "test-cluster")
		h.SetupDiagnosticsCleanup()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupDiagnosticsCleanup_PassingTest$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_DIAGNOSTICS_PASSING_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected helper test to pass, got err: %v\nOutput: %s", err, string(out))
	}
	output := string(out)
	if strings.Contains(output, "=== DUMPING") {
		t.Errorf("expected no diagnostics printed for passing test, got:\n%s", output)
	}
}

func TestSetupDiagnosticsCleanup_FailingTest(t *testing.T) {
	if os.Getenv("TEST_DIAGNOSTICS_FAILING_HELPER") == "1" {
		h := NewHarness(t, "test-cluster")
		h.SetupDiagnosticsCleanup()
		t.Fatal("simulated failure")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupDiagnosticsCleanup_FailingTest$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_DIAGNOSTICS_FAILING_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected helper test to fail, but it exited successfully")
	}
	output := string(out)
	if strings.Count(output, "=== DUMPING GATEWAYS ===") != 1 {
		t.Errorf("expected Gateways dumped exactly once, got:\n%s", output)
	}
	if strings.Count(output, "=== DUMPING DATA-PLANE DEPLOYMENTS AND PODS ===") != 1 {
		t.Errorf("expected data-plane Deployments and Pods dumped exactly once, got:\n%s", output)
	}
	if strings.Count(output, "=== DUMPING RECENT EVENTS ===") != 1 {
		t.Errorf("expected recent events dumped exactly once, got:\n%s", output)
	}
	if strings.Count(output, "=== DUMPING CONTROLLER LOGS ===") != 1 {
		t.Errorf("expected controller logs dumped exactly once, got:\n%s", output)
	}
}

func TestSetupDiagnosticsCleanup_TimeoutTimer(t *testing.T) {
	if os.Getenv("TEST_DIAGNOSTICS_TIMEOUT_HELPER") == "1" {
		h := NewHarness(t, "test-cluster")
		h.SetupDiagnosticsCleanup()
		// Sleep past timeout so pre-deadline timer fires
		time.Sleep(3 * time.Second)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupDiagnosticsCleanup_TimeoutTimer$", "-test.timeout=1s", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_DIAGNOSTICS_TIMEOUT_HELPER=1")
	out, _ := cmd.CombinedOutput()
	output := string(out)
	if !strings.Contains(output, "=== PRE-TIMEOUT DIAGNOSTIC DUMP") {
		t.Errorf("expected pre-timeout diagnostic dump in output, got:\n%s", output)
	}
	if strings.Count(output, "=== DUMPING GATEWAYS ===") != 1 {
		t.Errorf("expected Gateways dumped exactly once on timeout, got:\n%s", output)
	}
}

func TestSetupDiagnosticsCleanup_Idempotent(t *testing.T) {
	h := NewHarness(t, "test-cluster")
	h.SetupDiagnosticsCleanup()
	h.SetupDiagnosticsCleanup()
	h.SetupDiagnosticsCleanup()
}
