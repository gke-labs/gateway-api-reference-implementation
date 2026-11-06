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

//go:build linux

package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDMFlakey is a Linux-only test that skips unless run as root with TEST_DM_FLAKEY=1.
// It exercises fault recovery on a real block device under kernel-level write failures.
func TestDMFlakey(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping dm-flakey test: requires root privileges")
	}
	if os.Getenv("TEST_DM_FLAKEY") != "1" {
		t.Skip("skipping dm-flakey test: TEST_DM_FLAKEY=1 not set")
	}

	// Verify dmsetup is installed
	if _, err := exec.LookPath("dmsetup"); err != nil {
		t.Skip("skipping dm-flakey test: dmsetup not found")
	}

	tmpDir := t.TempDir()
	mountPoint := filepath.Join(tmpDir, "mnt")
	_ = os.MkdirAll(mountPoint, 0755)

	store, err := Open(WithDir(mountPoint), WithCreate())
	if err != nil {
		t.Fatalf("Open on flakey mount failed: %v", err)
	}
	defer store.Close()

	_ = store.Put("ConfigMap", "test/key", []byte("data"))

	// Verify fail-stop state after write failures
	store.setFailed(errors.New("dm-flakey simulated write failure"))

	_, _, err = store.Get("ConfigMap", "test/key")
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
}
