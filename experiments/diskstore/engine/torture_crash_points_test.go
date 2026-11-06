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

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"testing"
)

// TestTorture_CrashPointsAtEveryIO tests crash points enumerated by I/O operation count.
// For a deterministic workload with a fixed seed, it runs once to count total I/O operations,
// then crashes at each operation in turn (or at a distributed sample in short mode) and verifies
// recovery consistency against the reference model.
func TestTorture_CrashPointsAtEveryIO(t *testing.T) {
	seed := int64(505)
	numWorkloadOps := 25

	// Phase 1: Dry run to count total I/O operations
	dryModel, totalIOs := executeWorkloadForCrashTest(t, seed, numWorkloadOps, 0)
	if totalIOs == 0 {
		t.Fatalf("dry run produced 0 I/O operations")
	}

	// Phase 2: Select crash points
	var crashPoints []int64
	if testing.Short() && os.Getenv("TEST_TORTURE_CRASH_POINTS") != "all" {
		// Sample 25 points evenly spaced across 1..totalIOs
		count := 25
		if int64(count) > totalIOs {
			count = int(totalIOs)
		}
		step := float64(totalIOs) / float64(count)
		for i := 1; i <= count; i++ {
			pt := int64(float64(i) * step)
			if pt < 1 {
				pt = 1
			}
			if pt > totalIOs {
				pt = totalIOs
			}
			if len(crashPoints) == 0 || pt > crashPoints[len(crashPoints)-1] {
				crashPoints = append(crashPoints, pt)
			}
		}
	} else {
		// Test every single I/O crash point
		for i := int64(1); i <= totalIOs; i++ {
			crashPoints = append(crashPoints, i)
		}
	}

	for _, cp := range crashPoints {
		t.Run(fmt.Sprintf("CrashIO_%d_of_%d", cp, totalIOs), func(t *testing.T) {
			testCrashAtIO(t, seed, numWorkloadOps, cp, dryModel)
		})
	}
}

func testCrashAtIO(t *testing.T, seed int64, numOps int, targetIO int64, refModel *ReferenceModel) {
	rng := rand.New(rand.NewSource(seed))
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := fmt.Sprintf("crash_io_store_%d_%d", seed, targetIO)

	var store *Engine
	var err error

	// When target IO count is reached, crash filesystem
	faultFS.SetCrashAfterOps(targetIO, func() {
		_ = faultFS.PowerLoss(PowerLossOptions{
			DropUnsynced: true,
			LostMetadata: true,
			Rand:         rng,
		})
	})

	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		// Crashed during initial Open
		if !errors.Is(err, ErrCrashed) {
			t.Fatalf("Open failed with unexpected error at crash point %d: %v", targetIO, err)
		}
		// Recover
		faultFS.ResetCrash()
		recStore, rErr := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
		if rErr != nil {
			t.Fatalf("Recovery failed after crash during initial Open at IO %d: %v", targetIO, rErr)
		}
		_ = recStore.Close()
		return
	}

	buckets := []string{"ConfigMap", "Secret"}
	keys := []string{"ck1", "ck2", "ck3", "ck4", "ck5"}

	crashed := false

	for op := 1; op <= numOps; op++ {
		opType := rng.Intn(6)
		bucket := buckets[rng.Intn(len(buckets))]
		key := keys[rng.Intn(len(keys))]
		token := fmt.Sprintf("t-%d", op)

		switch opType {
		case 0, 1, 2:
			// Put (including oversize payloads to test oversize deletes/overwrites across crash points)
			var payload []byte
			if op%4 == 0 {
				payload = generateAdversarialPayload(rng, key, 3, 64)
			} else {
				payload = bytes.Repeat([]byte(fmt.Sprintf("val-%s-%d-", key, op)), 10)
			}
			pErr := store.Put(bucket, key, payload, token)
			if pErr != nil {
				crashed = true
				break
			}

		case 3:
			// Delete
			dErr := store.Delete(bucket, key, token)
			if dErr != nil {
				crashed = true
				break
			}

		case 4:
			// Checkpoint
			_, chkErr := store.Checkpoint()
			if chkErr != nil {
				crashed = true
				break
			}

		case 5:
			// Sync
			sErr := store.Sync()
			if sErr != nil {
				crashed = true
				break
			}
		}

		if crashed || faultFS.crashed.Load() {
			break
		}
	}

	durableLSN := faultFS.MaxFsyncedLSN()

	// Simulate immediate process termination (faultFS rejects all writes during shutdown)
	_ = store.Close()

	// Clear crash injector for recovery
	faultFS.ResetCrash()

	// Perform crash recovery
	recStore, recErr := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if recErr != nil {
		t.Fatalf("Recovery failed at crash point %d (seed %d): %v\nRepro: %s",
			targetIO, seed, recErr, ReproCommand(seed, int(targetIO)))
	}
	defer recStore.Close()

	// Validate model invariant against subModel
	subModel := &ReferenceModel{
		snapshots:  refModel.snapshots,
		keyHistory: refModel.keyHistory,
	}
	subModel.lastDurableLSN.Store(durableLSN)
	subModel.lastAckLSN.Store(refModel.LastAckLSN())

	subModel.ValidateStore(t, recStore, seed, int(targetIO))

	// Validate structural integrity
	if sErr := recStore.CheckStructuralInvariants(); sErr != nil {
		t.Fatalf("Structural invariant failed after recovery at crash point %d: %v", targetIO, sErr)
	}
}

func executeWorkloadForCrashTest(t *testing.T, seed int64, numOps int, targetCrashIO int64) (*ReferenceModel, int64) {
	rng := rand.New(rand.NewSource(seed))
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := fmt.Sprintf("dry_run_store_%d", seed)

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Dry run Open failed: %v", err)
	}
	defer store.Close()

	model := NewReferenceModel()
	buckets := []string{"ConfigMap", "Secret"}
	keys := []string{"ck1", "ck2", "ck3", "ck4", "ck5"}

	for op := 1; op <= numOps; op++ {
		opType := rng.Intn(6)
		bucket := buckets[rng.Intn(len(buckets))]
		key := keys[rng.Intn(len(keys))]
		token := fmt.Sprintf("t-%d", op)

		switch opType {
		case 0, 1, 2:
			var payload []byte
			if op%4 == 0 {
				payload = generateAdversarialPayload(rng, key, 3, 64)
			} else {
				payload = bytes.Repeat([]byte(fmt.Sprintf("val-%s-%d-", key, op)), 10)
			}
			_ = store.Put(bucket, key, payload, token)
			model.RecordPut(bucket, key, payload, token, store.wal.MaxLSN())
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 3:
			existed := false
			if model.currentData[bucket] != nil {
				_, existed = model.currentData[bucket][key]
			}
			_ = store.Delete(bucket, key, token)
			if existed {
				model.RecordDelete(bucket, key, token, store.wal.MaxLSN())
			}
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 4:
			chkLSN, _ := store.Checkpoint()
			model.RecordCheckpoint(chkLSN)

		case 5:
			_ = store.Sync()
			model.SetLastDurableLSN(store.wal.FsyncedLSN())
		}
	}

	return model, faultFS.TotalIOOps()
}
