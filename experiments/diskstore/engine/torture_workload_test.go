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
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// generateAdversarialPayload creates payloads tailored to torture page allocation and recovery:
// 1. Slotted boundaries (±1 byte)
// 2. Multi-block boundaries (±1 byte) within pool capacity
// 3. Oversize thresholds (> 2 MiB)
// 4. Forged block headers at 0, 512, and 4096 byte offsets
// 5. Incompressible random bytes
// 6. Highly compressible repeating patterns
func generateAdversarialPayload(rng *rand.Rand, key string, mode int, maxPoolBlocks int) []byte {
	kLen := len(key)
	overhead := PageRecordHeaderSize + kLen

	switch mode % 8 {
	case 0:
		// Slotted limit exact boundary
		slottedLimit := MaxSlottedRecordSize - overhead
		delta := rng.Intn(3) - 1 // -1, 0, +1
		sz := slottedLimit + delta
		if sz < 1 {
			sz = 10
		}
		return bytes.Repeat([]byte("s"), sz)

	case 1:
		// Multi-block 2-block boundary (capacity = 2 * 4064)
		mb2Limit := (2 * BlockUsableSize) - overhead
		delta := rng.Intn(3) - 1
		sz := mb2Limit + delta
		if sz < 10 {
			sz = 100
		}
		p := make([]byte, sz)
		rng.Read(p)
		return p

	case 2:
		// Power-of-two multi-block boundary: order 2..maxOrder within pool
		maxOrder := 6
		if maxPoolBlocks > 0 {
			for (1<<maxOrder) >= maxPoolBlocks && maxOrder > 1 {
				maxOrder--
			}
		}
		order := 2
		if maxOrder > 2 {
			order = 2 + rng.Intn(maxOrder-1)
		}
		numBlocks := 1 << order
		mbLimit := (numBlocks * BlockUsableSize) - overhead
		delta := rng.Intn(3) - 1
		sz := mbLimit + delta
		p := make([]byte, sz)
		rng.Read(p)
		return p

	case 3:
		// Oversize threshold boundary (around 512 blocks = 2,080,768 bytes)
		maxCapacity := (MaxMultiBlockCount * BlockUsableSize) - overhead
		delta := rng.Intn(3) - 1
		sz := maxCapacity + delta
		if sz < 1000 {
			sz = 1000
		}
		p := make([]byte, sz)
		rng.Read(p)
		return p

	case 4:
		// 2 MiB boundary
		twoMB := 2 * 1024 * 1024
		sz := twoMB + rng.Intn(5) - 2
		p := make([]byte, sz)
		rng.Read(p)
		return p

	case 5:
		// Well-formed forged block header at offset 0
		sz := BlockSize + rng.Intn(4096)
		p := make([]byte, sz)
		rng.Read(p)
		fakeHdr := BlockHeader{
			LogicalPage: 999999,
			LSN:         888888,
			BlockIndex:  0,
			NumBlocks:   1,
		}
		EncodeBlockHeader(fakeHdr, p)
		FinalizeBlockCRC(p[:BlockSize])
		return p

	case 6:
		// Well-formed forged block header at 512-byte sector boundary
		sz := 512 + BlockSize + rng.Intn(4096)
		p := make([]byte, sz)
		rng.Read(p)
		fakeHdr := BlockHeader{
			LogicalPage: 777777,
			LSN:         666666,
			BlockIndex:  0,
			NumBlocks:   2,
		}
		EncodeBlockHeader(fakeHdr, p[512:512+BlockSize])
		FinalizeBlockCRC(p[512 : 512+BlockSize])
		return p

	default:
		// Small compressible payload
		sz := 50 + rng.Intn(500)
		pattern := []byte(fmt.Sprintf("val-%s-", key))
		repeatCount := (sz / len(pattern)) + 2
		return bytes.Repeat(pattern, repeatCount)[:sz]
	}
}

// TestDiskStoreTorture runs model-based randomized workloads exercising Put, Update across
// page classes, Delete, Replace, Checkpoints, Clean Reopen, Crash and Recovery with rich
// fault models, crash cycles during recovery/checkpoints/rotations/truncations, and structural checks.
func TestDiskStoreTorture(t *testing.T) {
	seeds := []int64{101, 202, 303}
	opsPerSeed := 35

	// Check environment variable overrides for long runs
	if customSeed := os.Getenv("TEST_TORTURE_SEED"); customSeed != "" {
		if s, err := strconv.ParseInt(customSeed, 10, 64); err == nil {
			seeds = []int64{s}
		}
	}

	if customOps := os.Getenv("DISKSTORE_TORTURE_OPS"); customOps != "" {
		if ops, err := strconv.Atoi(customOps); err == nil && ops > 0 {
			opsPerSeed = ops
		}
	}

	duration := time.Duration(0)
	if durStr := os.Getenv("DISKSTORE_TORTURE_DURATION"); durStr != "" {
		if d, err := time.ParseDuration(durStr); err == nil {
			duration = d
		}
	}

	startTime := time.Now()
	seedIdx := 0

	for {
		var seed int64
		if seedIdx < len(seeds) {
			seed = seeds[seedIdx]
			seedIdx++
		} else if duration > 0 && time.Since(startTime) < duration {
			seed = time.Now().UnixNano()
		} else {
			break
		}

		t.Run(fmt.Sprintf("Seed_%d", seed), func(t *testing.T) {
			runTortureWorkload(t, seed, opsPerSeed)
		})

		if duration > 0 && time.Since(startTime) >= duration {
			break
		}
	}
}

func runTortureWorkload(t *testing.T, seed int64, numOps int) {
	rng := rand.New(rand.NewSource(seed))
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := fmt.Sprintf("torture_store_%d", seed)

	// Vary block pool size: occasionally test small buffer pools (down to 32 blocks)
	numPoolBlocks := 128
	if seed%2 == 0 {
		numPoolBlocks = 64
	} else if seed%3 == 0 {
		numPoolBlocks = 32
	}

	store, err := Open(
		WithFS(faultFS),
		WithDir(dir),
		WithNumPoolBlocks(numPoolBlocks),
		WithCompressionCodec(CodecZstd),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()

	model := NewReferenceModel()
	buckets := []string{"ConfigMap", "Secret", "Gateway"}
	keys := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10"}

	// Target single operation reproduction if requested
	targetReproOp := -1
	if reproOpStr := os.Getenv("TEST_TORTURE_OP"); reproOpStr != "" {
		if rop, err := strconv.Atoi(reproOpStr); err == nil {
			targetReproOp = rop
		}
	}

	for op := 1; op <= numOps; op++ {
		if targetReproOp > 0 && op > targetReproOp {
			break
		}

		opType := rng.Intn(10)

		switch opType {
		case 0, 1, 2:
			// 1. Put / Insert
			bucket := buckets[rng.Intn(len(buckets))]
			key := keys[rng.Intn(len(keys))]
			payload := generateAdversarialPayload(rng, key, rng.Intn(8), numPoolBlocks)
			token := fmt.Sprintf("%d", op)

			err := store.Put(bucket, key, payload, token)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Put(%s, %s) failed: %v\nRepro: %s",
					op, seed, bucket, key, err, ReproCommand(seed, op))
			}
			model.RecordPut(bucket, key, payload, token, store.wal.MaxLSN())
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 3:
			// 2. Update with page class change (slotted <-> multi-block <-> oversize)
			bucket := buckets[rng.Intn(len(buckets))]
			key := keys[rng.Intn(len(keys))]
			classChoice := rng.Intn(4)
			var newPayload []byte
			switch classChoice {
			case 0:
				// Slotted (100 bytes)
				newPayload = bytes.Repeat([]byte("small"), 20)
			case 1:
				// Multi-block (8 KB, 2 blocks)
				newPayload = make([]byte, 8*1024)
				rng.Read(newPayload)
			case 2:
				// Multi-block (16 KB, 4 blocks)
				newPayload = make([]byte, 16*1024)
				rng.Read(newPayload)
			default:
				// Slotted exact boundary
				newPayload = generateAdversarialPayload(rng, key, 0, numPoolBlocks)
			}
			token := fmt.Sprintf("%d", op)
			err := store.Put(bucket, key, newPayload, token)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): UpdateClass Put failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			if key == "k4" {
				t.Logf("Op %d: UpdateClass k4 in %s len=%d lsn=%d", op, bucket, len(newPayload), store.wal.MaxLSN())
			}
			model.RecordPut(bucket, key, newPayload, token, store.wal.MaxLSN())
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 4:
			// 3. Delete
			bucket := buckets[rng.Intn(len(buckets))]
			key := keys[rng.Intn(len(keys))]
			token := fmt.Sprintf("%d", op)

			keyExisted := false
			if model.currentData[bucket] != nil {
				_, keyExisted = model.currentData[bucket][key]
			}

			err := store.Delete(bucket, key, token)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Delete failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			if keyExisted {
				model.RecordDelete(bucket, key, token, store.wal.MaxLSN())
			}
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 5:
			// 4. Replace as an indexer would call it (delete missing, put kept, set token)
			bucket := buckets[rng.Intn(len(buckets))]
			itemsToKeep := make(map[string][]byte)
			for i := 0; i < 3; i++ {
				k := keys[rng.Intn(len(keys))]
				itemsToKeep[k] = generateAdversarialPayload(rng, k, rng.Intn(8), numPoolBlocks)
			}
			rvToken := fmt.Sprintf("rv-%d", op)

			// Delete only existing keys not kept
			existingKeys := store.ListKeys(bucket)
			for _, k := range existingKeys {
				if _, keep := itemsToKeep[k]; !keep {
					_ = store.Delete(bucket, k, rvToken)
					model.RecordDelete(bucket, k, rvToken, store.wal.MaxLSN())
				}
			}
			// Put kept keys
			for k, v := range itemsToKeep {
				_ = store.Put(bucket, k, v, rvToken)
				model.RecordPut(bucket, k, v, rvToken, store.wal.MaxLSN())
			}
			model.SetLastDurableLSN(store.wal.FsyncedLSN())

		case 6:
			// 5. Checkpoint
			chkLSN, err := store.Checkpoint()
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Checkpoint failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			model.RecordCheckpoint(chkLSN)

		case 7:
			// 6. Clean close and reopen
			model.SetLastDurableLSN(store.wal.FsyncedLSN())
			if err := store.Close(); err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Clean Close failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			// Orderly close checkpoints
			model.RecordCheckpoint(store.wal.MaxLSN())

			store, err = Open(
				WithFS(faultFS),
				WithDir(dir),
				WithNumPoolBlocks(numPoolBlocks),
				WithCompressionCodec(CodecZstd),
			)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Clean Reopen failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			model.SetLastDurableLSN(store.wal.FsyncedLSN())
			model.ValidateStore(t, store, seed, op)
			model.ValidateCurrent(t, store, seed, op)

		case 8:
			// 7. Crash and Recover with rich fault model
			model.SetLastDurableLSN(store.wal.FsyncedLSN())
			crashOpts := PowerLossOptions{
				DropUnsynced:         rng.Float64() < 0.4,
				RandomSubset:         rng.Float64() < 0.5,
				TearFraction:         rng.Float64() * 0.4,
				LostMetadata:         rng.Float64() < 0.3,
				TruncateUnsyncedSize: rng.Float64() < 0.3,
				Rand:                 rng,
			}
			_ = faultFS.PowerLoss(crashOpts)
			faultFS.SetCrashed(true)
			_ = store.Close()
			faultFS.ResetCrash()

			// Recover
			store, err = Open(
				WithFS(faultFS),
				WithDir(dir),
				WithNumPoolBlocks(numPoolBlocks),
				WithCompressionCodec(CodecZstd),
			)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d (seed %d): Recovery Open failed: %v\nRepro: %s",
					op, seed, err, ReproCommand(seed, op))
			}
			recLSN := model.ValidateStore(t, store, seed, op)
			model.RollbackTo(recLSN)

		case 9:
			// 8. Concurrent reads and List
			var readWg sync.WaitGroup
			for r := 0; r < 4; r++ {
				readWg.Add(1)
				readerSeed := rng.Int63() + int64(r)
				go func(rSeed int64) {
					defer readWg.Done()
					rRng := rand.New(rand.NewSource(rSeed))
					b := buckets[rRng.Intn(len(buckets))]
					k := keys[rRng.Intn(len(keys))]
					val, exists, err := store.Get(b, k)
					if err != nil && !store.isFailed() {
						t.Errorf("concurrent Get(%s, %s) failed: %v", b, k, err)
					}
					if exists && !model.IsValueInHistory(b, k, val) {
						t.Errorf("concurrent Get returned value not in history for %s/%s", b, k)
					}
					_, _ = store.List(b)
				}(readerSeed)
			}
			readWg.Wait()
		}

		// Audit structural invariants after every operation
		if err := store.CheckStructuralInvariants(); err != nil {
			t.Fatalf("TORTURE FAILURE at op %d (seed %d): structural invariant violation: %v\nRepro: %s",
				op, seed, err, ReproCommand(seed, op))
		}
	}

	// Final verification
	model.ValidateCurrent(t, store, seed, numOps)
}

// TestTorture_CrashCycles tests crash points during recovery itself, during a checkpoint,
// during WAL segment rotation, and during truncation.
func TestTorture_CrashCycles(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_crash_cycles_store"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Initial Open failed: %v", err)
	}

	model := NewReferenceModel()

	// Seed data
	for i := 1; i <= 5; i++ {
		key := fmt.Sprintf("cycle-key-%d", i)
		val := bytes.Repeat([]byte(fmt.Sprintf("v-%d-", i)), 100)
		_ = store.Put("ConfigMap", key, val, fmt.Sprintf("%d", i))
		model.RecordPut("ConfigMap", key, val, fmt.Sprintf("%d", i), store.wal.MaxLSN())
	}

	chkLSN, _ := store.Checkpoint()
	model.RecordCheckpoint(chkLSN)

	// Cycle 1: Crash during Checkpoint
	// Inject a crash hook during beforeSync on the heap file
	crashedDuringCheckpoint := false
	faultFS.SetBeforeSync(func(path string) {
		if strings.Contains(path, "heap.db") && !crashedDuringCheckpoint {
			crashedDuringCheckpoint = true
			_ = faultFS.Crash(true, 0)
		}
	})

	_ = store.Put("ConfigMap", "cycle-key-chk", []byte("val-checkpoint-crash"), "10")
	model.RecordPut("ConfigMap", "cycle-key-chk", []byte("val-checkpoint-crash"), "10", store.wal.MaxLSN())
	model.SetLastDurableLSN(store.wal.FsyncedLSN())

	// Attempt checkpoint which triggers crash hook
	_, _ = store.Checkpoint()
	faultFS.SetBeforeSync(nil)
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	// Reopen after crash during checkpoint
	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery after crash during checkpoint failed: %v", err)
	}
	model.SetLastDurableLSN(store.wal.FsyncedLSN())
	recLSN1 := model.ValidateStore(t, store, 1, 100)
	model.RollbackTo(recLSN1)
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure: %v", err)
	}

	// Cycle 2: Crash during WAL segment rotation
	_ = store.Put("ConfigMap", "cycle-key-wal-1", bytes.Repeat([]byte("w"), 2000), "20")
	model.RecordPut("ConfigMap", "cycle-key-wal-1", bytes.Repeat([]byte("w"), 2000), "20", store.wal.MaxLSN())

	crashedDuringWAL := false
	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		if strings.Contains(path, ".wal") && off == 0 && !crashedDuringWAL {
			crashedDuringWAL = true
			_ = faultFS.Crash(false, 0.5)
		}
	})

	// Add more writes to trigger rotation
	_ = store.Put("ConfigMap", "cycle-key-wal-2", bytes.Repeat([]byte("w2"), 2000), "21")
	model.RecordPut("ConfigMap", "cycle-key-wal-2", bytes.Repeat([]byte("w2"), 2000), "21", store.wal.MaxLSN())
	model.SetLastDurableLSN(store.wal.FsyncedLSN())

	faultFS.SetBeforeWriteAt(nil)
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	// Reopen after crash during WAL segment rotation
	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery after crash during WAL rotation failed: %v", err)
	}
	recLSN2 := model.ValidateStore(t, store, 2, 200)
	model.RollbackTo(recLSN2)
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure: %v", err)
	}

	// Cycle 3: Crash during Recovery itself
	// During recovery Open, crash during redo page flush
	_ = store.Put("ConfigMap", "cycle-key-redo", []byte("unflushed-redo-value"), "30")
	model.RecordPut("ConfigMap", "cycle-key-redo", []byte("unflushed-redo-value"), "30", store.wal.MaxLSN())
	model.SetLastDurableLSN(store.wal.FsyncedLSN())
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	crashedDuringRecovery := false
	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		if strings.Contains(path, "heap.db") && !crashedDuringRecovery {
			crashedDuringRecovery = true
			_ = faultFS.Crash(true, 0)
			faultFS.SetWriteError(ErrInjectedFault)
		}
	})

	// This Open will encounter the crash hook and fail
	_, _ = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	faultFS.SetBeforeWriteAt(nil)
	faultFS.SetWriteError(nil)
	faultFS.ResetCrash()

	// Next Open must successfully recover
	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery after crash during recovery failed: %v", err)
	}
	recLSN3 := model.ValidateStore(t, store, 3, 300)
	model.RollbackTo(recLSN3)
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure: %v", err)
	}

	// Cycle 4: Crash during WAL truncation
	// Checkpoint that triggers segment truncation
	_ = store.Put("ConfigMap", "cycle-key-trunc", []byte("val-truncation"), "40")
	model.RecordPut("ConfigMap", "cycle-key-trunc", []byte("val-truncation"), "40", store.wal.MaxLSN())

	crashedDuringTrunc := false
	faultFS.SetBeforeSync(func(path string) {
		if strings.Contains(path, "wal") && !crashedDuringTrunc {
			crashedDuringTrunc = true
			_ = faultFS.Crash(false, 0.2)
		}
	})
	chk4, chkErr := store.Checkpoint()
	faultFS.SetBeforeSync(nil)
	if chkErr == nil && chk4 > 0 {
		model.RecordCheckpoint(chk4)
	}
	model.SetLastDurableLSN(faultFS.MaxFsyncedLSN())
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery after crash during truncation failed: %v", err)
	}
	recLSN4 := model.ValidateStore(t, store, 4, 400)
	model.RollbackTo(recLSN4)
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure: %v", err)
	}

	// Cycle 5: Crash after Delete of an oversize object whose Put was truncated by checkpoint
	// (Simulating crash between Delete WAL append and oversize file removal on disk)
	ovrsKey := "cycle-key-ovrs-del"
	ovrsVal := make([]byte, 2100*1024)
	rand.New(rand.NewSource(55555)).Read(ovrsVal)
	if err := store.Put("ConfigMap", ovrsKey, ovrsVal, "50"); err != nil {
		t.Fatalf("Cycle 5 Put oversize failed: %v", err)
	}
	model.RecordPut("ConfigMap", ovrsKey, ovrsVal, "50", store.wal.MaxLSN())

	// Advance WAL with small records and Checkpoint to truncate the oversize Put record
	for i := 0; i < 5; i++ {
		k := fmt.Sprintf("cycle-k5-pad-%d", i)
		v := []byte("pad")
		if err := store.Put("ConfigMap", k, v, fmt.Sprintf("50-%d", i)); err != nil {
			t.Fatalf("Cycle 5 pad Put failed: %v", err)
		}
		model.RecordPut("ConfigMap", k, v, fmt.Sprintf("50-%d", i), store.wal.MaxLSN())
	}
	chk5, chkErr := store.Checkpoint()
	if chkErr != nil {
		t.Fatalf("Cycle 5 Checkpoint failed: %v", chkErr)
	}
	model.RecordCheckpoint(chk5)

	// Save a copy of the oversize file data on disk before Delete
	qKeyDel := qualifyKey("ConfigMap", ovrsKey)
	ovrsFilePath := dir + "/oversize/" + oversizeFileName(qKeyDel)
	fO, rErr := faultFS.OpenFile(ovrsFilePath, os.O_RDONLY, 0644)
	if rErr != nil {
		t.Fatalf("Cycle 5 OpenFile oversize failed: %v", rErr)
	}
	ovrsSize, _ := fO.Size()
	ovrsFileData := make([]byte, ovrsSize)
	_, _ = fO.ReadAt(ovrsFileData, 0)
	_ = fO.Close()

	// Delete the key, which appends RecordTypeDelete to WAL and removes the file
	if err := store.Delete("ConfigMap", ovrsKey, "51"); err != nil {
		t.Fatalf("Cycle 5 Delete failed: %v", err)
	}
	model.RecordDelete("ConfigMap", ovrsKey, "51", store.wal.MaxLSN())
	if err := store.Sync(); err != nil {
		t.Fatalf("Cycle 5 Sync failed: %v", err)
	}
	model.SetLastDurableLSN(store.wal.FsyncedLSN())

	// Close cleanly, then restore the oversize file on disk to simulate a crash
	// immediately after Delete's WAL append (before file removal on disk)
	_ = store.Close()
	model.RecordCheckpoint(store.wal.MaxLSN())
	fRestore, err := faultFS.OpenFile(ovrsFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("Cycle 5 restore oversize file failed: %v", err)
	}
	if _, err := fRestore.WriteAt(ovrsFileData, 0); err != nil {
		t.Fatalf("Cycle 5 write restored oversize failed: %v", err)
	}
	_ = fRestore.Sync()
	_ = fRestore.Close()

	// Reopen store. Recovery must NOT resurrect the deleted oversize object.
	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery in Cycle 5 failed: %v", err)
	}
	recLSN5 := model.ValidateStore(t, store, 5, 500)
	model.RollbackTo(recLSN5)
	if _, exists, _ := store.Get("ConfigMap", ovrsKey); exists {
		t.Fatalf("Cycle 5 failed: deleted oversize key resurrected after crash recovery!")
	}
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure in Cycle 5: %v", err)
	}

	// Cycle 6: Crash after Overwrite of an oversize object whose Put was truncated by checkpoint
	// (Simulating crash between slotted Put WAL append and oversize file removal on disk)
	updKey := "cycle-key-ovrs-upd"
	updVal := make([]byte, 2100*1024)
	rand.New(rand.NewSource(66666)).Read(updVal)
	if err := store.Put("ConfigMap", updKey, updVal, "60"); err != nil {
		t.Fatalf("Cycle 6 Put oversize failed: %v", err)
	}
	model.RecordPut("ConfigMap", updKey, updVal, "60", store.wal.MaxLSN())

	// Advance WAL with small records and Checkpoint to truncate the oversize Put record
	for i := 0; i < 5; i++ {
		k := fmt.Sprintf("cycle-k6-pad-%d", i)
		v := []byte("pad")
		if err := store.Put("ConfigMap", k, v, fmt.Sprintf("60-%d", i)); err != nil {
			t.Fatalf("Cycle 6 pad Put failed: %v", err)
		}
		model.RecordPut("ConfigMap", k, v, fmt.Sprintf("60-%d", i), store.wal.MaxLSN())
	}
	chk6, chkErr := store.Checkpoint()
	if chkErr != nil {
		t.Fatalf("Cycle 6 Checkpoint failed: %v", chkErr)
	}
	model.RecordCheckpoint(chk6)

	// Save a copy of the oversize file data on disk before Overwrite
	qKeyUpd := qualifyKey("ConfigMap", updKey)
	updFilePath := dir + "/oversize/" + oversizeFileName(qKeyUpd)
	fU, rErr := faultFS.OpenFile(updFilePath, os.O_RDONLY, 0644)
	if rErr != nil {
		t.Fatalf("Cycle 6 OpenFile oversize failed: %v", rErr)
	}
	updSize, _ := fU.Size()
	updFileData := make([]byte, updSize)
	_, _ = fU.ReadAt(updFileData, 0)
	_ = fU.Close()

	// Overwrite the key with a small slotted value
	smallVal := []byte("small-slotted-replacement")
	if err := store.Put("ConfigMap", updKey, smallVal, "61"); err != nil {
		t.Fatalf("Cycle 6 Put small failed: %v", err)
	}
	model.RecordPut("ConfigMap", updKey, smallVal, "61", store.wal.MaxLSN())
	if err := store.Sync(); err != nil {
		t.Fatalf("Cycle 6 Sync failed: %v", err)
	}
	model.SetLastDurableLSN(store.wal.FsyncedLSN())

	// Close cleanly, then restore the older oversize file on disk to simulate a crash
	// immediately after Put's WAL append (before older oversize file removal on disk)
	_ = store.Close()
	model.RecordCheckpoint(store.wal.MaxLSN())
	fRestore2, err := faultFS.OpenFile(updFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("Cycle 6 restore oversize file failed: %v", err)
	}
	if _, err := fRestore2.WriteAt(updFileData, 0); err != nil {
		t.Fatalf("Cycle 6 write restored oversize failed: %v", err)
	}
	_ = fRestore2.Sync()
	_ = fRestore2.Close()

	// Reopen store. Recovery must return the small slotted value, NOT the stale oversize file.
	store, err = Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Recovery in Cycle 6 failed: %v", err)
	}
	recLSN6 := model.ValidateStore(t, store, 6, 600)
	model.RollbackTo(recLSN6)
	actVal, exists, _ := store.Get("ConfigMap", updKey)
	if !exists || !bytes.Equal(actVal, smallVal) {
		t.Fatalf("Cycle 6 failed: expected small slotted value %q, got %q (exists=%v)", string(smallVal), string(actVal), exists)
	}
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("Structural invariant failure in Cycle 6: %v", err)
	}
	_ = store.Close()
}
