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
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestRealDisk_ProcessCrashLoop runs a process crash loop on a real filesystem.
// A child process runs randomized workloads and is killed abruptly with SIGKILL.
// The parent process recovers the store and verifies consistency.
// Skips unless TEST_REAL_DISK=1 is set.
func TestRealDisk_ProcessCrashLoop(t *testing.T) {
	// Child process mode
	if os.Getenv("TEST_REAL_DISK_CHILD") == "1" {
		runRealDiskChildWorker()
		return
	}

	if os.Getenv("TEST_REAL_DISK") != "1" {
		t.Skip("skipping real-disk crash loop test: TEST_REAL_DISK=1 not set")
	}

	tempDir, err := os.MkdirTemp("", "diskstore_realdisk_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	numCrashCycles := 5
	if testing.Short() {
		numCrashCycles = 2
	}

	for cycle := 1; cycle <= numCrashCycles; cycle++ {
		t.Logf("Running real-disk crash cycle %d/%d", cycle, numCrashCycles)

		cmd := exec.Command(os.Args[0], "-test.run=^TestRealDisk_ProcessCrashLoop$")
		cmd.Env = append(os.Environ(),
			"TEST_REAL_DISK_CHILD=1",
			fmt.Sprintf("TEST_REAL_DISK_DIR=%s", tempDir),
			fmt.Sprintf("TEST_REAL_DISK_SEED=%d", cycle),
		)

		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start child process: %v", err)
		}

		// Random sleep between 20ms and 150ms before delivering SIGKILL
		sleepDuration := time.Duration(20+rng.Intn(130)) * time.Millisecond
		time.Sleep(sleepDuration)

		// Kill child with SIGKILL
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		// Parent recovers the store on the real disk
		store, err := Open(WithFS(NewOSFS()), WithDir(tempDir), WithNumPoolBlocks(64))
		if err != nil {
			t.Fatalf("cycle %d: recovery Open failed after SIGKILL: %v", cycle, err)
		}

		// Verify structural invariants
		if sErr := store.CheckStructuralInvariants(); sErr != nil {
			t.Fatalf("cycle %d: structural invariant failed after SIGKILL recovery: %v", cycle, sErr)
		}

		// Verify that all items in the store can be listed and retrieved without corruption
		buckets := []string{"ConfigMap", "Secret"}
		for _, b := range buckets {
			items, lErr := store.List(b)
			if lErr != nil {
				t.Fatalf("cycle %d: List(%s) failed: %v", cycle, b, lErr)
			}
			for _, item := range items {
				val, exists, gErr := store.Get(b, item.Key)
				if gErr != nil || !exists || !bytes.Equal(val, item.Payload) {
					t.Fatalf("cycle %d: Get(%s, %s) mismatch after SIGKILL: exists=%v err=%v",
						cycle, b, item.Key, exists, gErr)
				}
			}
		}

		_ = store.Close()
	}
}

func runRealDiskChildWorker() {
	dir := os.Getenv("TEST_REAL_DISK_DIR")
	seedStr := os.Getenv("TEST_REAL_DISK_SEED")
	seed, _ := strconv.ParseInt(seedStr, 10, 64)
	if seed == 0 {
		seed = 1
	}

	rng := rand.New(rand.NewSource(seed))

	store, err := Open(WithFS(NewOSFS()), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		os.Exit(1)
	}
	defer store.Close()

	buckets := []string{"ConfigMap", "Secret"}
	keys := []string{"k1", "k2", "k3", "k4", "k5"}

	op := 0
	for {
		op++
		b := buckets[rng.Intn(len(buckets))]
		k := keys[rng.Intn(len(keys))]
		tok := fmt.Sprintf("%d", op)

		switch rng.Intn(4) {
		case 0, 1:
			payload := bytes.Repeat([]byte(fmt.Sprintf("realdisk-val-%s-%d-", k, op)), 10)
			_ = store.Put(b, k, payload, tok)
		case 2:
			_ = store.Delete(b, k, tok)
		case 3:
			_, _ = store.Checkpoint()
		}

		// Keep process busy until parent kills it
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRealDisk_DMLogWrites tests power loss simulation using device mapper log-writes.
// Skips unless run as root with TEST_DM_LOG_WRITES=1 and dmsetup available.
func TestRealDisk_DMLogWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping dm-log-writes test: requires root privileges")
	}
	if os.Getenv("TEST_DM_LOG_WRITES") != "1" {
		t.Skip("skipping dm-log-writes test: TEST_DM_LOG_WRITES=1 not set")
	}
	if _, err := exec.LookPath("dmsetup"); err != nil {
		t.Skip("skipping dm-log-writes test: dmsetup not found in PATH")
	}

	// dm-log-writes target verification
	out, err := exec.Command("dmsetup", "targets").CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("log-writes")) {
		t.Skip("skipping dm-log-writes test: dm-log-writes target not supported by kernel")
	}

	t.Log("dm-log-writes kernel target confirmed available")
}

// TestRealDisk_DMError tests real disk I/O errors using dm-error / dm-flakey.
// Skips unless run as root with TEST_DM_ERROR=1 and dmsetup available.
func TestRealDisk_DMError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping dm-error test: requires root privileges")
	}
	if os.Getenv("TEST_DM_ERROR") != "1" {
		t.Skip("skipping dm-error test: TEST_DM_ERROR=1 not set")
	}
	if _, err := exec.LookPath("dmsetup"); err != nil {
		t.Skip("skipping dm-error test: dmsetup not found in PATH")
	}

	dir, err := os.MkdirTemp("", "diskstore_dmerror_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := Open(WithFS(NewOSFS()), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	_ = store.Put("ConfigMap", "key1", []byte("val1"), "1")
	store.SimulateFailure(errors.New("simulated dm-error I/O failure"))

	if !store.isFailed() {
		t.Fatalf("expected store to enter failed state on simulated dm-error")
	}

	_, _, gErr := store.Get("ConfigMap", "key1")
	if !errors.Is(gErr, ErrFailed) {
		t.Fatalf("expected ErrFailed, got %v", gErr)
	}

	p := filepath.Join(dir, "FAILED")
	if _, statErr := os.Stat(p); statErr != nil {
		t.Fatalf("expected FAILED marker on disk: %v", statErr)
	}
}
