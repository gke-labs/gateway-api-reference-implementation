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
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

	// checkpointInterval specifies the operation interval for periodic checkpoints.
	// When positive, a checkpoint is performed every checkpointInterval operations instead of random checkpoints.
	checkpointInterval int

	// syncAfterOp issues a Sync on the store after each put and delete operation.
	syncAfterOp bool

	// fixedValueSize, when positive, fixes the payload size in bytes for each put operation.
	fixedValueSize int

	// wrapFS optionally wraps the underlying filesystem (e.g. with a measurement wrapper).
	wrapFS func(FS) FS

	// walMaxSegSize overrides DefaultMaxSegmentSize when non-zero.
	walMaxSegSize int64

	// onIO is an optional callback invoked on every WriteAt and Sync operation across all filesystem files.
	// The boolean parameter is true for Sync operations and false for WriteAt operations.
	onIO func(targetFS *FaultFS, path string, isSync bool)

	// stopOnCrash specifies whether the workload loop should stop and return its collected state
	// when a filesystem crash occurs, rather than failing the test.
	stopOnCrash bool

	// skipReason explains why this configuration is skipped during full test runs, or empty if enabled.
	skipReason string
}

// ioPhase represents the database subsystem performing I/O.
type ioPhase int

const (
	// phaseNormal represents regular workload Put and Delete I/O.
	phaseNormal ioPhase = iota

	// phaseCheckpoint represents I/O performed during checkpoint execution.
	phaseCheckpoint

	// phaseSegmentRotation represents I/O performed during WAL segment creation and rotation.
	phaseSegmentRotation

	// phaseRecovery represents I/O performed during crash recovery replay and page flushing.
	phaseRecovery
)

func (phase ioPhase) String() string {
	switch phase {
	case phaseCheckpoint:
		return "checkpoint"
	case phaseSegmentRotation:
		return "wal_segment_rotation"
	case phaseRecovery:
		return "recovery_writes"
	default:
		return "normal"
	}
}

// tortureWorkloadResult contains the execution artifacts, metrics, and model history from a torture workload run.
type tortureWorkloadResult struct {
	// payloadBytesPut is the total bytes of payload written across all Put operations.
	payloadBytesPut int64

	// puts is the count of successful Put operations.
	puts int

	// deletes is the count of successful Delete operations.
	deletes int

	// checkpoints is the count of successful Checkpoint operations.
	checkpoints int

	// totalOps is the total number of workload operations performed.
	totalOps int

	// totalIO is the total number of WriteAt and Sync operations observed during the workload.
	totalIO int

	// ioPhases records the subsystem phase (checkpoint, WAL segment rotation, recovery, or normal)
	// for each sequential I/O operation observed during the baseline run.
	ioPhases []ioPhase

	// history holds sequential snapshots of the model state after each completed operation.
	history []map[string][]byte

	// inFlightModel holds the model state with the currently executing operation applied,
	// representing the state if an in-flight mutation became durable before the crash.
	inFlightModel map[string][]byte

	// lastSyncOp is the index in history corresponding to the most recent returned Sync or Checkpoint.
	lastSyncOp int

	// lastCompletedOp is the index in history corresponding to the most recent returned workload operation.
	lastCompletedOp int

	// memFS is the underlying in-memory filesystem holding the durable storage state.
	memFS *MemFS

	// dbID is the database identifier generated during initialization.
	dbID [16]byte

	// encryptionKey is the 32-byte encryption key used when encryption is enabled.
	encryptionKey [32]byte

	// crashed indicates whether the workload halted due to an injected filesystem crash.
	crashed bool
}

var tortureConfigs = []tortureConfig{
	// Pools of 9, 12, 16 and 24 blocks with values up to 8 blocks, clean close, without sweep goroutine.
	{name: "pool_9_clean_nosweep", poolBlocks: 9, maxValueBlocks: 8, numKeys: 12, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_12_clean_nosweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_16_clean_nosweep", poolBlocks: 16, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},
	{name: "pool_24_clean_nosweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean},

	// Pools of 9, 12, 16 and 24 blocks with values up to 8 blocks, clean close, with sweep goroutine.
	{name: "pool_9_clean_sweep", poolBlocks: 9, maxValueBlocks: 8, numKeys: 12, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true},
	{name: "pool_12_clean_sweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true},
	{name: "pool_16_clean_sweep", poolBlocks: 16, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true},
	{name: "pool_24_clean_sweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 3, cycleEnd: cycleEndClean, sweep: true},

	// Crashes that tear unsynced writes with values up to 8 blocks on small pools (12 and 24 blocks, four cycles).
	{name: "pool_12_val8_crash_tear", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear},
	{name: "pool_24_val8_crash_tear", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear},

	// The same with the sweep goroutine.
	{name: "pool_12_val8_crash_tear_sweep", poolBlocks: 12, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, sweep: true},
	{name: "pool_24_val8_crash_tear_sweep", poolBlocks: 24, maxValueBlocks: 8, numKeys: 15, operationsPerCycle: 25, numCycles: 4, cycleEnd: cycleEndCrashTear, sweep: true},

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

func copyModel(original map[string][]byte) map[string][]byte {
	copied := make(map[string][]byte, len(original))
	for key, value := range original {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		copied[key] = valueCopy
	}
	return copied
}

func runTortureWorkload(t testing.TB, config tortureConfig, seed int64) *tortureWorkloadResult {
	t.Helper()
	var stats tortureWorkloadResult
	random := rand.New(rand.NewSource(seed))

	keys := make([]string, config.numKeys)
	for keyIndex := range keys {
		keys[keyIndex] = fmt.Sprintf("k%d", keyIndex)
	}
	model := make(map[string][]byte)
	history := []map[string][]byte{copyModel(model)}
	lastSyncOp := 0
	lastCompletedOp := 0
	var inFlightModel map[string][]byte

	memFS := NewMemFS()
	var baseFS FS = memFS
	if config.wrapFS != nil {
		baseFS = config.wrapFS(memFS)
	}
	faultFS := NewFaultFS(baseFS)
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
		if config.walMaxSegSize > 0 {
			options = append(options, WithWALMaxSegmentSize(config.walMaxSegSize))
		}
		return options
	}

	var ioCount int
	var ioMutex sync.Mutex
	var ioPhases []ioPhase
	var currentPhase ioPhase = phaseNormal
	seenWALSegments := make(map[string]bool)

	setPhase := func(phase ioPhase) {
		ioMutex.Lock()
		currentPhase = phase
		ioMutex.Unlock()
	}

	installHooks := func(targetFS *FaultFS) {
		if config.onIO == nil {
			return
		}
		targetFS.SetBeforeWriteAt(func(path string, payload []byte, offset int64) {
			ioMutex.Lock()
			ioCount++
			phase := currentPhase
			if strings.HasSuffix(path, ".wal") && !seenWALSegments[path] {
				seenWALSegments[path] = true
				if currentPhase == phaseNormal {
					phase = phaseSegmentRotation
				}
			}
			ioPhases = append(ioPhases, phase)
			ioMutex.Unlock()
			config.onIO(targetFS, path, false)
		})
		targetFS.SetBeforeSync(func(path string) {
			ioMutex.Lock()
			ioCount++
			phase := currentPhase
			if strings.HasSuffix(path, ".wal") && !seenWALSegments[path] {
				seenWALSegments[path] = true
				if currentPhase == phaseNormal {
					phase = phaseSegmentRotation
				}
			}
			ioPhases = append(ioPhases, phase)
			ioMutex.Unlock()
			config.onIO(targetFS, path, true)
		})
	}

	currentStore, err := Open(append(openOptions(faultFS), WithCreate())...)
	if err != nil {
		t.Fatalf("torture init failed: config=%s seed=%d: Open: %v", config.name, seed, err)
	}

	entries, readDirErr := memFS.ReadDir(filepath.Join(dir, "wal"))
	if readDirErr == nil {
		for _, entry := range entries {
			seenWALSegments[filepath.Join(dir, "wal", entry.Name())] = true
		}
	}
	installHooks(faultFS)

	var failed bool
	defer func() {
		if currentStore == nil {
			return
		}
		if failed {
			TestHookFail(currentStore, errors.New("torture test failed"))
			if closeErr := currentStore.Close(); closeErr != nil {
				// Close errors during failed teardown are expected.
			}
			return
		}
		if closeErr := currentStore.Close(); closeErr != nil {
			t.Errorf("torture cleanup: Close failed: %v", closeErr)
		}
	}()

	var heapCipher *xts.Cipher
	if config.encryption {
		heapCipher, err = newHeapCipher(encryptionKey[:], currentStore.DBID())
		if err != nil {
			t.Fatalf("torture init failed: config=%s seed=%d: newHeapCipher: %v", config.name, seed, err)
		}
		faultFS.SetHeapCipher(heapCipher)
		faultFS.SetEncryptionKey(encryptionKey[:])
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

	checkViolation := func(cycle int, stage string) {
		t.Helper()
		if violations := faultFS.Violations(); len(violations) > 0 {
			fail(cycle, stage, violations[0])
		}
	}

	isCrashed := func() bool {
		faultFS.mu.RLock()
		defer faultFS.mu.RUnlock()
		return faultFS.crashed
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
			stats.totalOps++
			action := random.Intn(10)
			if len(model) == 0 {
				action = 0 // force put when empty
			}

			triggerRandomCheckpoint := config.checkpointInterval == 0 && !config.noCheckpoint && action == 9

			switch {
			case triggerRandomCheckpoint:
				inFlightModel = copyModel(model)
				setPhase(phaseCheckpoint)
				err := currentStore.Checkpoint()
				setPhase(phaseNormal)
				if err != nil {
					if config.stopOnCrash && isCrashed() {
						break
					}
					checkViolation(cycle, "checkpoint")
					fail(cycle, "checkpoint", err)
				}
				history = append(history, copyModel(model))
				lastCompletedOp = len(history) - 1
				lastSyncOp = len(history) - 1
				stats.checkpoints++

			case action >= 7:
				key := keys[random.Intn(len(keys))]
				inFlightModel = copyModel(model)
				delete(inFlightModel, key)
				if err := currentStore.Delete(tableName, key); err != nil {
					if config.stopOnCrash && isCrashed() {
						break
					}
					checkViolation(cycle, "delete")
					fail(cycle, "delete", err)
				}
				delete(model, key)
				history = append(history, copyModel(model))
				lastCompletedOp = len(history) - 1
				stats.deletes++

			default:
				key := keys[random.Intn(len(keys))]
				existingValue, exists := model[key]
				existingLength := 0
				if exists {
					existingLength = len(existingValue)
				}
				var value []byte
				if config.fixedValueSize > 0 {
					value = make([]byte, config.fixedValueSize)
					random.Read(value)
				} else {
					value = generateTortureValue(random, config.maxValueBlocks, existingLength)
				}
				inFlightModel = copyModel(model)
				inFlightModel[key] = value
				if err := currentStore.Put(tableName, key, value); err != nil {
					if config.stopOnCrash && isCrashed() {
						break
					}
					checkViolation(cycle, "put")
					fail(cycle, "put", err)
				}
				model[key] = value
				history = append(history, copyModel(model))
				lastCompletedOp = len(history) - 1
				stats.payloadBytesPut += int64(len(value))
				stats.puts++
			}

			if config.syncAfterOp {
				if err := currentStore.Sync(); err != nil {
					if config.stopOnCrash && isCrashed() {
						break
					}
					checkViolation(cycle, "sync_after_op")
					fail(cycle, "sync_after_op", err)
				}
			}

			if config.checkpointInterval > 0 && operationNumber%config.checkpointInterval == 0 {
				inFlightModel = copyModel(model)
				setPhase(phaseCheckpoint)
				err := currentStore.Checkpoint()
				setPhase(phaseNormal)
				if err != nil {
					if config.stopOnCrash && isCrashed() {
						break
					}
					checkViolation(cycle, "checkpoint")
					fail(cycle, "checkpoint", err)
				}
				history = append(history, copyModel(model))
				lastCompletedOp = len(history) - 1
				lastSyncOp = len(history) - 1
				stats.checkpoints++
			}

			if config.stopOnCrash && isCrashed() {
				break
			}
			checkViolation(cycle, "after_op")
		}

		if config.sweep {
			stopSweepFn()
			checkViolation(cycle, "sweep")
		}

		if config.stopOnCrash && isCrashed() {
			break
		}

		isCrash, dropUnsynced, tearFraction := config.cycleEnd.endForCycle(cycle)
		if isCrash {
			inFlightModel = copyModel(model)
			if err := currentStore.Sync(); err != nil {
				if config.stopOnCrash && isCrashed() {
					break
				}
				checkViolation(cycle, "sync_before_crash")
				fail(cycle, "sync_before_crash", err)
			}
			history = append(history, copyModel(model))
			lastCompletedOp = len(history) - 1
			lastSyncOp = len(history) - 1

			if err := faultFS.Crash(dropUnsynced, tearFraction); err != nil {
				fail(cycle, "crash", err)
			}
			// Shut down the abandoned store after a crash to stop its background
			// goroutines (such as wal.bgWriter) and release buffer pool memory.
			// It is safe to close after a crash because TestHookFail marks the
			// engine failed, ensuring Close skips taking a checkpoint and makes
			// no further modifications to the disk state.
			TestHookFail(currentStore, ErrCrashed)
			if closeErr := currentStore.Close(); closeErr != nil {
				// Close errors on a crashed filesystem are expected.
			}
			currentStore = nil
		} else {
			inFlightModel = copyModel(model)
			if err := currentStore.Sync(); err != nil {
				if config.stopOnCrash && isCrashed() {
					break
				}
				checkViolation(cycle, "sync_before_close")
				fail(cycle, "sync_before_close", err)
			}
			history = append(history, copyModel(model))
			lastCompletedOp = len(history) - 1
			lastSyncOp = len(history) - 1

			if err := currentStore.Close(); err != nil {
				checkViolation(cycle, "close")
				fail(cycle, "close", err)
			}
			currentStore = nil
		}
		checkViolation(cycle, "cycle_end")

		faultFS = NewFaultFS(baseFS)
		if heapCipher != nil {
			faultFS.SetHeapCipher(heapCipher)
			faultFS.SetEncryptionKey(encryptionKey[:])
		}
		installHooks(faultFS)

		setPhase(phaseRecovery)
		currentStore, err = Open(openOptions(faultFS)...)
		setPhase(phaseNormal)
		if err != nil {
			if config.stopOnCrash && isCrashed() {
				break
			}
			checkViolation(cycle, "reopen")
			fail(cycle, "reopen", err)
		}
		checkViolation(cycle, "reopen")
		history = append(history, copyModel(model))
		lastCompletedOp = len(history) - 1
		lastSyncOp = len(history) - 1

		if !config.stopOnCrash {
			for _, key := range keys {
				gotValue, exists, getErr := currentStore.Get(tableName, key)
				if getErr != nil {
					fail(cycle, "get", fmt.Errorf("Get(%q) error: %w", key, getErr))
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
	}

	var storeDBID [16]byte
	if currentStore != nil {
		storeDBID = currentStore.DBID()
		if isCrashed() {
			TestHookFail(currentStore, ErrCrashed)
			if closeErr := currentStore.Close(); closeErr != nil {
				// Close errors on a crashed filesystem are expected.
			}
		} else {
			if closeErr := currentStore.Close(); closeErr != nil {
				if config.stopOnCrash && isCrashed() {
					// Injected crash occurred during Close's checkpoint flush.
				} else {
					checkViolation(config.numCycles-1, "final_close")
					fail(config.numCycles-1, "final_close", closeErr)
				}
			}
		}
		currentStore = nil
	}
	checkViolation(config.numCycles-1, "final_close")

	return &tortureWorkloadResult{
		payloadBytesPut: stats.payloadBytesPut,
		puts:            stats.puts,
		deletes:         stats.deletes,
		checkpoints:     stats.checkpoints,
		totalOps:        stats.totalOps,
		totalIO:         ioCount,
		ioPhases:        ioPhases,
		history:         history,
		inFlightModel:   inFlightModel,
		lastSyncOp:      lastSyncOp,
		lastCompletedOp: lastCompletedOp,
		memFS:           memFS,
		dbID:            storeDBID,
		encryptionKey:   encryptionKey,
		crashed:         isCrashed(),
	}
}

type recordingTB struct {
	testing.TB
	failed  bool
	message string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.failed = true
	r.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestTortureWorkload_RecordedViolationFailsRun(t *testing.T) {
	var triggered atomic.Bool
	config := tortureConfig{
		name:               "violation_self_check",
		poolBlocks:         16,
		maxValueBlocks:     2,
		numKeys:            4,
		operationsPerCycle: 5,
		numCycles:          1,
		cycleEnd:           cycleEndClean,
		onIO: func(targetFS *FaultFS, path string, isSync bool) {
			if !triggered.CompareAndSwap(false, true) {
				return
			}
			file, err := targetFS.Create("violation_check.heap")
			if err != nil {
				t.Errorf("Create failed: %v", err)
				return
			}
			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					t.Errorf("Close failed: %v", closeErr)
				}
			}()
			badBlock := makeTestBlock(1, targetFS.MaxFsyncedLSN()+1, 0, 1)
			if _, writeErr := file.WriteAt(badBlock, 0); !errors.Is(writeErr, ErrWriteAheadRuleViolation) {
				t.Errorf("expected ErrWriteAheadRuleViolation, got %v", writeErr)
			}
		},
	}

	recorder := &recordingTB{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTortureWorkload(recorder, config, 0)
	}()
	wg.Wait()

	if !recorder.failed {
		t.Fatalf("expected torture workload to fail when FaultFS records a violation")
	}
	if !strings.Contains(recorder.message, ErrWriteAheadRuleViolation.Error()) {
		t.Fatalf("expected failure message to contain %q, got: %s", ErrWriteAheadRuleViolation.Error(), recorder.message)
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

type versionedValue struct {
	sequence uint64
	exists   bool
	value    []byte
}

// concurrentModel records every key version that the single writer starts or completes.
// Readers and List callers check two invariants against this history:
//  1. Get returns a version from that key's history at or after the latest write
//     completed when Get began, and no later than the latest write started when
//     Get returned.
//  2. List returns a point-in-time snapshot matching one sequence in that same
//     interval across all keys.
type concurrentModel struct {
	mu                sync.Mutex
	startedSequence   uint64
	completedSequence uint64
	history           map[string][]versionedValue
}

func newConcurrentModel(keys []string) *concurrentModel {
	history := make(map[string][]versionedValue, len(keys))
	for _, key := range keys {
		history[key] = []versionedValue{{sequence: 0, exists: false}}
	}
	return &concurrentModel{history: history}
}

func (m *concurrentModel) completed() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completedSequence
}

func (m *concurrentModel) beginWrite(key string, exists bool, value []byte) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startedSequence++
	sequence := m.startedSequence
	m.history[key] = append(m.history[key], versionedValue{sequence: sequence, exists: exists, value: value})
	return sequence
}

func (m *concurrentModel) endWrite(sequence uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completedSequence = sequence
}

func (m *concurrentModel) checkGet(key string, minSequence uint64, gotExists bool, gotValue []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	maxSequence := m.startedSequence
	versions := m.history[key]
	startIndex := len(versions) - 1
	for startIndex > 0 && versions[startIndex].sequence > minSequence {
		startIndex--
	}
	for i := startIndex; i < len(versions) && versions[i].sequence <= maxSequence; i++ {
		if versions[i].exists == gotExists && (!gotExists || bytes.Equal(versions[i].value, gotValue)) {
			return nil
		}
	}
	return fmt.Errorf("Get(%q) returned exists=%v len=%d, outside key history for sequences [%d, %d]",
		key, gotExists, len(gotValue), minSequence, maxSequence)
}

func (m *concurrentModel) checkList(keys []string, minSequence uint64, items []RecordItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	maxSequence := m.startedSequence
	got := make(map[string][]byte, len(items))
	for _, item := range items {
		if _, known := m.history[item.Key]; !known {
			return fmt.Errorf("List returned unknown key %q", item.Key)
		}
		if _, duplicate := got[item.Key]; duplicate {
			return fmt.Errorf("List returned duplicate key %q", item.Key)
		}
		got[item.Key] = item.Payload
	}
	for sequence := minSequence; sequence <= maxSequence; sequence++ {
		matched := true
		for _, key := range keys {
			versions := m.history[key]
			expected := versions[0]
			for i := len(versions) - 1; i >= 0; i-- {
				if versions[i].sequence <= sequence {
					expected = versions[i]
					break
				}
			}
			gotValue, gotExists := got[key]
			if gotExists != expected.exists || (gotExists && !bytes.Equal(gotValue, expected.value)) {
				matched = false
				break
			}
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("List returned %d keys, matching no model state in sequences [%d, %d]",
		len(items), minSequence, maxSequence)
}

func captureGoroutineDump() string {
	for size := 64 * 1024; ; size *= 2 {
		buffer := make([]byte, size)
		if written := runtime.Stack(buffer, true); written < len(buffer) {
			return string(buffer[:written])
		}
	}
}

// runConcurrentTorture runs readers, List callers, one writer, and the
// checkpointer against one engine without injecting faults. When beforeWorkers
// is non-nil, the runner calls it after seeding keys and invokes its returned
// release function after the watchdog fires or on teardown.
func runConcurrentTorture(t testing.TB, seed int64, writerOperations int, stallTimeout time.Duration, beforeWorkers func(*Engine) func()) {
	t.Helper()
	const (
		tableName      = "concurrent_torture_table"
		numKeys        = 32
		maxValueBlocks = 4
		numReaders     = 4
		numListers     = 2
	)
	rerunCommand := fmt.Sprintf("DISKSTORE_TORTURE_SEED=%d go test -race -v -run '^TestConcurrentTorture$' ./experiments/diskstore/engine", seed)
	failRun := func(cause error) {
		t.Helper()
		t.Fatalf("concurrent torture failure: seed=%d: %v\nRerun with:\n  %s", seed, cause, rerunCommand)
	}

	keys := make([]string, numKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d", i)
	}
	model := newConcurrentModel(keys)

	faultFS := NewFaultFS(NewMemFS())
	store, openErr := Open(
		WithFS(faultFS),
		WithDir("concurrent_torture"),
		WithNumPoolBlocks(48),
		WithCompressionCodec(CodecNone),
		WithWALMaxSegmentSize(16*1024),
		WithCreate(),
	)
	if openErr != nil {
		failRun(fmt.Errorf("Open: %w", openErr))
	}

	var failed, abandoned bool
	defer func() {
		if abandoned {
			return
		}
		if failed {
			TestHookFail(store, errors.New("concurrent torture failed"))
			if closeErr := store.Close(); closeErr != nil {
				// Close errors during failed teardown are expected.
			}
			return
		}
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("concurrent torture cleanup: Close failed: %v", closeErr)
		}
	}()

	writerRandom := rand.New(rand.NewSource(seed))
	existingLengths := make(map[string]int, len(keys))
	for _, key := range keys {
		value := generateTortureValue(writerRandom, maxValueBlocks, 0)
		sequence := model.beginWrite(key, true, value)
		if putErr := store.Put(tableName, key, value); putErr != nil {
			failed = true
			failRun(fmt.Errorf("seed Put(%q): %w", key, putErr))
		}
		model.endWrite(sequence)
		existingLengths[key] = len(value)
	}

	var releaseOnce sync.Once
	releaseHook := func() {}
	if beforeWorkers != nil {
		unlock := beforeWorkers(store)
		releaseHook = func() { releaseOnce.Do(unlock) }
		defer releaseHook()
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	firstErr := make(chan error, 1)
	abort := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
		cancel()
	}
	checkHealthy := func(role string) bool {
		if err := store.Err(); err != nil {
			abort(fmt.Errorf("%s observed failed engine: %w", role, err))
			return false
		}
		select {
		case <-store.Failed():
			abort(fmt.Errorf("%s observed failed engine: %w", role, ErrFailed))
			return false
		default:
			return true
		}
	}

	var totalCompleted, writerCompleted atomic.Int64
	var writerFinished atomic.Bool
	var wg sync.WaitGroup

	// Single writer executing Put and Delete operations.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			writerFinished.Store(true)
			cancel()
		}()
		for operationIndex := 1; operationIndex <= writerOperations && ctx.Err() == nil; operationIndex++ {
			key := keys[writerRandom.Intn(len(keys))]
			if writerRandom.Intn(5) == 0 {
				sequence := model.beginWrite(key, false, nil)
				if deleteErr := store.Delete(tableName, key); deleteErr != nil {
					abort(fmt.Errorf("writer op %d Delete(%q): %w", operationIndex, key, deleteErr))
					return
				}
				model.endWrite(sequence)
				delete(existingLengths, key)
			} else {
				value := generateTortureValue(writerRandom, maxValueBlocks, existingLengths[key])
				sequence := model.beginWrite(key, true, value)
				if putErr := store.Put(tableName, key, value); putErr != nil {
					abort(fmt.Errorf("writer op %d Put(%q): %w", operationIndex, key, putErr))
					return
				}
				model.endWrite(sequence)
				existingLengths[key] = len(value)
			}
			if !checkHealthy(fmt.Sprintf("writer op %d", operationIndex)) {
				return
			}
			writerCompleted.Add(1)
			totalCompleted.Add(1)
		}
	}()

	// Concurrent Get readers.
	for readerIndex := 0; readerIndex < numReaders; readerIndex++ {
		wg.Add(1)
		go func(readerSeed int64) {
			defer wg.Done()
			readerRandom := rand.New(rand.NewSource(readerSeed))
			for ctx.Err() == nil {
				key := keys[readerRandom.Intn(len(keys))]
				minSequence := model.completed()
				gotValue, gotExists, getErr := store.Get(tableName, key)
				if getErr != nil {
					abort(fmt.Errorf("Get(%q): %w", key, getErr))
					return
				}
				if checkErr := model.checkGet(key, minSequence, gotExists, gotValue); checkErr != nil {
					abort(checkErr)
					return
				}
				if !checkHealthy("reader") {
					return
				}
				totalCompleted.Add(1)
			}
		}(seed + int64(readerIndex) + 1)
	}

	// Concurrent List callers.
	for listerIndex := 0; listerIndex < numListers; listerIndex++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				minSequence := model.completed()
				items, listErr := store.List(tableName)
				if listErr != nil {
					abort(fmt.Errorf("List: %w", listErr))
					return
				}
				if checkErr := model.checkList(keys, minSequence, items); checkErr != nil {
					abort(checkErr)
					return
				}
				if !checkHealthy("List caller") {
					return
				}
				totalCompleted.Add(1)
			}
		}()
	}

	// Concurrent checkpointer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			if checkpointErr := store.Checkpoint(); checkpointErr != nil {
				abort(fmt.Errorf("Checkpoint: %w", checkpointErr))
				return
			}
			if !checkHealthy("checkpointer") {
				return
			}
			totalCompleted.Add(1)
			runtime.Gosched()
		}
	}()

	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	// Watchdog fails the test with a goroutine dump when no operation completes or the writer stalls.
	ticker := time.NewTicker(min(max(stallTimeout/5, 10*time.Millisecond), 100*time.Millisecond))
	defer ticker.Stop()

	lastTotal, lastWriter := int64(0), int64(0)
	lastTotalTime := time.Now()
	lastWriterTime := lastTotalTime
	var watchdogErr error

watchdogLoop:
	for {
		select {
		case <-workersDone:
			break watchdogLoop
		case now := <-ticker.C:
			total := totalCompleted.Load()
			if total != lastTotal {
				lastTotal, lastTotalTime = total, now
			} else if now.Sub(lastTotalTime) >= stallTimeout {
				watchdogErr = fmt.Errorf("watchdog: no operation completed for %s (total=%d)\n\ngoroutine dump:\n%s",
					stallTimeout, total, captureGoroutineDump())
				break watchdogLoop
			}
			writes := writerCompleted.Load()
			if writes != lastWriter {
				lastWriter, lastWriterTime = writes, now
			} else if !writerFinished.Load() && now.Sub(lastWriterTime) >= stallTimeout {
				watchdogErr = fmt.Errorf("watchdog: writer completed no operation for %s (writes=%d, total=%d)\n\ngoroutine dump:\n%s",
					stallTimeout, writes, total, captureGoroutineDump())
				break watchdogLoop
			}
		}
	}

	if watchdogErr != nil {
		abort(watchdogErr)
		releaseHook()
		grace := 200 * time.Millisecond
		if beforeWorkers != nil {
			grace = 2 * time.Second
		}
		select {
		case <-workersDone:
		case <-time.After(grace):
			abandoned = true
		}
		failed = true
		failRun(watchdogErr)
	}

	select {
	case recordedErr := <-firstErr:
		failed = true
		failRun(recordedErr)
	default:
	}
	if violations := faultFS.Violations(); len(violations) > 0 {
		failed = true
		failRun(violations[0])
	}
	if !checkHealthy("final check") {
		failed = true
		failRun(<-firstErr)
	}
}

func TestConcurrentTorture(t *testing.T) {
	seeds := []int64{0, 1, 2, 3}
	if os.Getenv("DISKSTORE_TORTURE_SEED") != "" || os.Getenv("DISKSTORE_TORTURE_SEEDS") != "" {
		seeds = tortureSeeds(t)
	} else if !testing.Short() {
		seeds = []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			runConcurrentTorture(t, seed, 200, 3*time.Second, nil)
		})
	}
}

func TestConcurrentTorture_WatchdogFires(t *testing.T) {
	holdBlockPoolLock := func(store *Engine) func() {
		store.bp.mu.Lock()
		return store.bp.mu.Unlock
	}

	recorder := &recordingTB{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runConcurrentTorture(recorder, 7, 50, 100*time.Millisecond, holdBlockPoolLock)
	}()
	wg.Wait()

	if !recorder.failed {
		t.Fatalf("expected watchdog to fail concurrent torture run when lock is held")
	}
	for _, want := range []string{"watchdog:", "goroutine ", "DISKSTORE_TORTURE_SEED=7"} {
		if !strings.Contains(recorder.message, want) {
			t.Fatalf("expected failure message to contain %q, got:\n%s", want, recorder.message)
		}
	}
}
