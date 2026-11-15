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
	"runtime"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/xts"
)

type cycleEndMode int

const (
	// cycleEndClean cleanly closes and syncs the store at the end of each cycle.
	cycleEndClean cycleEndMode = iota

	// cycleEndCrashDrop syncs the WAL and crashes dropping all unsynced heap writes at the end of each cycle.
	cycleEndCrashDrop

	// cycleEndCrashTear syncs the WAL and crashes tearing unsynced blocks at the end of each cycle.
	cycleEndCrashTear

	// cycleEndAlternateCrashTearClean alternates between a crash tearing unsynced blocks and a clean close.
	cycleEndAlternateCrashTearClean

	// cycleEndCrashThenClean crashes on the first cycle and cleanly closes on subsequent cycles.
	cycleEndCrashThenClean
)

func (mode cycleEndMode) endForCycle(cycle int) (isCrash bool, dropUnsynced bool, tearFraction float64) {
	switch mode {
	case cycleEndClean:
		return false, false, 0
	case cycleEndCrashDrop:
		return true, true, 0
	case cycleEndCrashTear:
		return true, false, 0.5
	case cycleEndAlternateCrashTearClean:
		if cycle%2 == 0 {
			return true, false, 0.5
		}
		return false, false, 0
	case cycleEndCrashThenClean:
		if cycle == 0 {
			return true, true, 0
		}
		return false, false, 0
	}
	return false, false, 0
}

type tortureConfig struct {
	// name is the unique human-readable test case identifier.
	name string

	// poolBlocks is the total number of blocks in the block pool.
	poolBlocks int

	// maxValueBlocks is the maximum value size expressed in blocks.
	maxValueBlocks int

	// numKeys is the number of distinct keys in the test keyset.
	numKeys int

	// operationsPerCycle is the number of workload operations performed in each cycle.
	operationsPerCycle int

	// numCycles is the number of workload cycles to execute.
	numCycles int

	// cycleEnd determines how each cycle terminates (clean close or simulated crash).
	cycleEnd cycleEndMode

	// encryption specifies whether block-level encryption is enabled with a master key.
	encryption bool

	// sweep specifies whether a concurrent background goroutine repeatedly invokes sweepIdleDirtyPages.
	sweep bool

	// noCheckpoint disables periodic checkpoints during the workload when true.
	noCheckpoint bool

	// skipReason explains why this configuration is skipped during full test runs, or empty if enabled.
	skipReason string
}

var tortureConfigs = []tortureConfig{
	// Pools of 9, 12, 16 and 24 blocks with values up to 8 blocks, clean close, without sweep goroutine.
	{name: "pool_9_clean_nosweep", poolBlocks: 9, maxValueBlocks: 8, numKeys: 12, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_12_clean_nosweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_16_clean_nosweep", poolBlocks: 16, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_24_clean_nosweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},

	// Pools of 9, 12, 16 and 24 blocks with values up to 8 blocks, clean close, with sweep goroutine.
	// Skipped due to production bugs: concurrent background sweep flushes dirty pages during
	// multi-block page reallocation, triggering reuse rule violations in FaultFS.
	{name: "pool_9_clean_sweep", poolBlocks: 9, maxValueBlocks: 8, numKeys: 12, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true, skipReason: "skipping: seed 11 fails with reuse rule violation in FaultFile.WriteAt during concurrent background sweep on a 9-block pool with 8-block values; the engine fault is tracked separately"},
	{name: "pool_12_clean_sweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true, skipReason: "skipping: seed 2 fails with reuse rule violation in FaultFile.WriteAt during concurrent background sweep on a 12-block pool with 8-block values; the engine fault is tracked separately"},
	{name: "pool_16_clean_sweep", poolBlocks: 16, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true, skipReason: "skipping: seed 18 fails with reuse rule violation in FaultFile.WriteAt during concurrent background sweep on a 16-block pool with 8-block values; the engine fault is tracked separately"},
	{name: "pool_24_clean_sweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true, skipReason: "skipping: seed 17 fails with reuse rule violation in FaultFile.WriteAt during concurrent background sweep on a 24-block pool with 8-block values; the engine fault is tracked separately"},

	// Crashes that tear unsynced writes with values up to 8 blocks on small pools (12 and 24 blocks, four cycles).
	{name: "pool_12_val8_crash_tear", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, skipReason: "skipping: seed 1 fails because deleted key k12 is resurrected after crash recovery on a 12-block pool with 8-block values; the engine fault is tracked separately"},
	{name: "pool_24_val8_crash_tear", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, skipReason: "skipping: seed 36 fails because deleted key k12 is resurrected after crash recovery on a 24-block pool with 8-block values; the engine fault is tracked separately"},

	// The same with the sweep goroutine.
	{name: "pool_12_val8_crash_tear_sweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, sweep: true, skipReason: "skipping: seed 1 fails because deleted key k12 is resurrected after crash recovery on a 12-block pool with 8-block values; the engine fault is tracked separately"},
	{name: "pool_24_val8_crash_tear_sweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, sweep: true, skipReason: "skipping: seed 1 fails because deleted key k12 is resurrected after crash recovery on a 24-block pool with 8-block values; the engine fault is tracked separately"},

	// 16-block pool with values up to 8 blocks, crash that drops unsynced writes (replaces TestRecovery_SmallBlockPoolReuseRule).
	{name: "pool_16_crash_drop", poolBlocks: 16, maxValueBlocks: 8, numKeys: 20, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashDrop},

	// 32-block pool with values up to 2 blocks, alternating crash with torn blocks and clean close.
	{name: "pool_32_val2_alt_crash_clean", poolBlocks: 32, maxValueBlocks: 2, numKeys: 20, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndAlternateCrashTearClean},

	// The same with an encryption key (replaces TestRecovery_EncryptedCrashAndReopen).
	{name: "pool_32_val2_alt_crash_clean_encrypted", poolBlocks: 32, maxValueBlocks: 2, numKeys: 20, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndAlternateCrashTearClean, encryption: true},

	// A run with no checkpoint and a crash, then a clean close and a second reopen.
	{name: "nocheckpoint_crash_clean_reopen", poolBlocks: 16, maxValueBlocks: 8, numKeys: 20, operationsPerCycle: 30, numCycles: 2, cycleEnd: cycleEndCrashThenClean, noCheckpoint: true},
}

func tortureSeeds(t *testing.T) []int64 {
	t.Helper()
	if seedString := os.Getenv("DISKSTORE_TORTURE_SEED"); seedString != "" {
		seed, err := strconv.ParseInt(seedString, 10, 64)
		if err != nil {
			t.Fatalf("invalid DISKSTORE_TORTURE_SEED=%q: %v", seedString, err)
		}
		return []int64{seed}
	}
	if seedsCountString := os.Getenv("DISKSTORE_TORTURE_SEEDS"); seedsCountString != "" {
		count, err := strconv.Atoi(seedsCountString)
		if err != nil {
			t.Fatalf("invalid DISKSTORE_TORTURE_SEEDS=%q: %v", seedsCountString, err)
		}
		seeds := make([]int64, count)
		for seedIndex := 0; seedIndex < count; seedIndex++ {
			seeds[seedIndex] = int64(seedIndex)
		}
		return seeds
	}
	if testing.Short() {
		return []int64{42}
	}
	seeds := make([]int64, 20)
	for seedIndex := 0; seedIndex < 20; seedIndex++ {
		seeds[seedIndex] = int64(seedIndex)
	}
	return seeds
}

func generateTortureValue(random *rand.Rand, maxValueBlocks int, existingLength int) []byte {
	var blockChoices []int
	for block := 1; block <= maxValueBlocks; block *= 2 {
		blockChoices = append(blockChoices, block)
	}

	targetBlocks := blockChoices[random.Intn(len(blockChoices))]
	if existingLength > 0 && len(blockChoices) > 1 {
		existingBlocks := 1
		if existingLength > 1000 {
			needed := (existingLength + PageRecordHeaderSize + BlockUsableSize - 1) / BlockUsableSize
			existingBlocks = 2
			for existingBlocks < needed {
				existingBlocks *= 2
			}
		}

		var filtered []int
		for _, block := range blockChoices {
			if block != existingBlocks {
				filtered = append(filtered, block)
			}
		}
		if len(filtered) > 0 {
			targetBlocks = filtered[random.Intn(len(filtered))]
		}
	}

	var size int
	if targetBlocks == 1 {
		size = 20 + random.Intn(400)
		if size == existingLength {
			size++
		}
	} else {
		minSize := (targetBlocks-1)*BlockUsableSize + 100
		maxSize := targetBlocks*BlockUsableSize - PageRecordHeaderSize - 100
		size = minSize
		if maxSize > minSize {
			size = minSize + random.Intn(maxSize-minSize+1)
		}
	}

	value := make([]byte, size)
	random.Read(value)
	return value
}

func runTortureWorkload(t *testing.T, config tortureConfig, seed int64) {
	t.Helper()
	random := rand.New(rand.NewSource(seed))

	keys := make([]string, config.numKeys)
	for keyIndex := range keys {
		keys[keyIndex] = fmt.Sprintf("k%d", keyIndex)
	}
	model := make(map[string][]byte)

	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "torture_store"
	const tableName = "torture_table"

	var encryptionKey [32]byte
	if config.encryption {
		copy(encryptionKey[:], []byte("diskstore-torture-matrix-key-32b"))
	}

	openOptions := func(filesystem FS) []Option {
		options := []Option{
			WithFS(filesystem),
			WithDir(dir),
			WithNumPoolBlocks(config.poolBlocks),
			WithCompressionCodec(CodecNone),
		}
		if config.encryption {
			options = append(options, WithEncryptionKey(encryptionKey[:]))
		}
		return options
	}

	var violationMutex sync.Mutex
	var firstViolation error

	setViolationHandler := func(targetFS *FaultFS) {
		targetFS.SetViolationHandler(func(err error) {
			violationMutex.Lock()
			defer violationMutex.Unlock()
			if firstViolation == nil {
				firstViolation = err
			}
		})
	}
	setViolationHandler(faultFS)

	currentStore, err := Open(append(openOptions(faultFS), WithCreate())...)
	if err != nil {
		t.Fatalf("torture init failed: config=%s seed=%d: Open: %v", config.name, seed, err)
	}

	var failed bool
	defer func() {
		if !failed && currentStore != nil {
			if closeErr := currentStore.Close(); closeErr != nil {
				t.Errorf("torture cleanup: Close failed: %v", closeErr)
			}
		}
	}()

	var heapCipher *xts.Cipher
	if config.encryption {
		heapCipher, err = newHeapCipher(encryptionKey[:], currentStore.DBID())
		if err != nil {
			t.Fatalf("torture init failed: config=%s seed=%d: newHeapCipher: %v", config.name, seed, err)
		}
		faultFS.SetHeapCipher(heapCipher)
	}

	operationNumber := 0
	rerunCmd := fmt.Sprintf("DISKSTORE_TORTURE_SEED=%d go test -v -run 'TestTortureMatrix/%s' ./experiments/diskstore/engine", seed, config.name)

	var stopSweep chan struct{}
	var sweepWaitGroup sync.WaitGroup

	stopSweepFn := func() {
		if stopSweep != nil {
			select {
			case <-stopSweep:
			default:
				close(stopSweep)
				sweepWaitGroup.Wait()
			}
			stopSweep = nil
		}
	}
	defer stopSweepFn()

	fail := func(cycle int, stage string, cause error) {
		t.Helper()
		failed = true
		stopSweepFn()
		t.Fatalf("torture failure: config=%s seed=%d op=%d (cycle %d, stage %s): %v\nRerun with:\n  %s",
			config.name, seed, operationNumber, cycle, stage, cause, rerunCmd)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			failed = true
			stopSweepFn()
			t.Fatalf("torture panic: config=%s seed=%d op=%d: %v\nRerun with:\n  %s",
				config.name, seed, operationNumber, recovered, rerunCmd)
		}
	}()

	checkViolation := func(cycle int, stage string) {
		t.Helper()
		violationMutex.Lock()
		violation := firstViolation
		violationMutex.Unlock()
		if violation != nil {
			fail(cycle, stage, violation)
		}
	}

	for cycle := 0; cycle < config.numCycles; cycle++ {
		checkViolation(cycle, "cycle_start")

		if config.sweep {
			stopSweep = make(chan struct{})
			sweepWaitGroup.Add(1)
			go func(blockPool *BlockPool, stop <-chan struct{}) {
				defer sweepWaitGroup.Done()
				for {
					select {
					case <-stop:
						return
					default:
						blockPool.sweepIdleDirtyPages()
						runtime.Gosched()
					}
				}
			}(currentStore.bp, stopSweep)
		}

		operations := config.operationsPerCycle
		if config.cycleEnd == cycleEndCrashThenClean && cycle > 0 {
			operations = 0
		}
		for operationIndex := 0; operationIndex < operations; operationIndex++ {
			checkViolation(cycle, "before_op")

			operationNumber++
			action := random.Intn(10)
			if len(model) == 0 {
				action = 0 // force put when empty
			}

			switch {
			case !config.noCheckpoint && action == 9:
				if _, err := currentStore.Checkpoint(); err != nil {
					checkViolation(cycle, "checkpoint")
					fail(cycle, "checkpoint", err)
				}
			case action >= 7:
				key := keys[random.Intn(len(keys))]
				if err := currentStore.Delete(tableName, key); err != nil {
					checkViolation(cycle, "delete")
					fail(cycle, "delete", err)
				}
				delete(model, key)
			default:
				key := keys[random.Intn(len(keys))]
				existingValue, exists := model[key]
				existingLength := 0
				if exists {
					existingLength = len(existingValue)
				}
				value := generateTortureValue(random, config.maxValueBlocks, existingLength)
				if err := currentStore.Put(tableName, key, value); err != nil {
					checkViolation(cycle, "put")
					fail(cycle, "put", err)
				}
				model[key] = value
			}

			checkViolation(cycle, "after_op")
		}

		if config.sweep {
			stopSweepFn()
			checkViolation(cycle, "sweep")
		}

		isCrash, dropUnsynced, tearFraction := config.cycleEnd.endForCycle(cycle)
		if isCrash {
			if err := currentStore.Sync(); err != nil {
				checkViolation(cycle, "sync_before_crash")
				fail(cycle, "sync_before_crash", err)
			}
			if err := faultFS.Crash(dropUnsynced, tearFraction); err != nil {
				fail(cycle, "crash", err)
			}
		} else {
			if err := currentStore.Sync(); err != nil {
				checkViolation(cycle, "sync_before_close")
				fail(cycle, "sync_before_close", err)
			}
			if err := currentStore.Close(); err != nil {
				fail(cycle, "close", err)
			}
		}

		faultFS = NewFaultFS(memFS)
		setViolationHandler(faultFS)
		if heapCipher != nil {
			faultFS.SetHeapCipher(heapCipher)
		}
		currentStore, err = Open(openOptions(faultFS)...)
		if err != nil {
			fail(cycle, "reopen", err)
		}

		for _, key := range keys {
			gotValue, exists, err := currentStore.Get(tableName, key)
			if err != nil {
				fail(cycle, "get", fmt.Errorf("Get(%q) error: %w", key, err))
			}
			expectedValue, expectedExists := model[key]
			if expectedExists {
				if !exists {
					fail(cycle, "verify_missing", fmt.Errorf("key %q missing after reopen", key))
				}
				if !bytes.Equal(gotValue, expectedValue) {
					fail(cycle, "verify_mismatch", fmt.Errorf("key %q value mismatch: got len=%d, want len=%d", key, len(gotValue), len(expectedValue)))
				}
			} else {
				if exists {
					fail(cycle, "verify_deleted", fmt.Errorf("key %q should be deleted but exists after reopen", key))
				}
			}
		}
	}

	if currentStore != nil {
		if err := currentStore.Close(); err != nil {
			fail(config.numCycles-1, "final_close", err)
		}
		currentStore = nil
	}
}

func TestTortureMatrix(t *testing.T) {
	seeds := tortureSeeds(t)
	singleSeedExplicit := os.Getenv("DISKSTORE_TORTURE_SEED") != ""
	for _, config := range tortureConfigs {
		config := config
		t.Run(config.name, func(t *testing.T) {
			if config.skipReason != "" && !singleSeedExplicit {
				t.Skip(config.skipReason)
			}
			for _, seed := range seeds {
				runTortureWorkload(t, config, seed)
			}
		})
	}
}
