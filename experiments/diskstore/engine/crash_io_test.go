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
	"sync"
	"testing"
)

var crashIOConfigs = []tortureConfig{
	{
		name:               "pool_16_crash_io",
		poolBlocks:         16,
		maxValueBlocks:     8,
		numKeys:            12,
		operationsPerCycle: 20,
		numCycles:          2,
		cycleEnd:           cycleEndCrashDrop,
		walMaxSegSize:      8192,
	},
	{
		name:               "pool_16_crash_io_encrypted",
		poolBlocks:         16,
		maxValueBlocks:     8,
		numKeys:            12,
		operationsPerCycle: 20,
		numCycles:          2,
		cycleEnd:           cycleEndCrashDrop,
		encryption:         true,
		walMaxSegSize:      8192,
	},
}

// checkStoreEqualsModel verifies that the reopened store has exactly the same keys and values
// as the candidate model, and no extra or resurrected deleted keys.
func checkStoreEqualsModel(store *Engine, tableName string, allKeys []string, candidateModel map[string][]byte) (bool, error) {
	for _, key := range allKeys {
		gotValue, exists, getErr := store.Get(tableName, key)
		if getErr != nil {
			return false, fmt.Errorf("Get(%q) error: %w", key, getErr)
		}
		expectedValue, wantExists := candidateModel[key]
		if exists != wantExists {
			return false, nil
		}
		if exists && !bytes.Equal(gotValue, expectedValue) {
			return false, nil
		}
	}
	storeKeys := store.ListKeys(tableName)
	if len(storeKeys) != len(candidateModel) {
		return false, nil
	}
	return true, nil
}

func sampleOperations(totalOperations int, count int, seed int64, checkpointOperations, rotationOperations, recoveryOperations []int) []int {
	if totalOperations <= count {
		result := make([]int, totalOperations)
		for index := 0; index < totalOperations; index++ {
			result[index] = index + 1
		}
		return result
	}

	selected := make(map[int]bool)
	var result []int

	addOperation := func(operationNumber int) {
		if operationNumber >= 1 && operationNumber <= totalOperations && !selected[operationNumber] {
			selected[operationNumber] = true
			result = append(result, operationNumber)
		}
	}

	// Ensure coverage of required phases: checkpoint, WAL segment rotation, and recovery writes.
	if len(checkpointOperations) > 0 {
		addOperation(checkpointOperations[0])
		if len(checkpointOperations) > 1 {
			addOperation(checkpointOperations[len(checkpointOperations)/2])
		}
	}
	if len(rotationOperations) > 0 {
		addOperation(rotationOperations[0])
		if len(rotationOperations) > 1 {
			addOperation(rotationOperations[len(rotationOperations)/2])
		}
	}
	if len(recoveryOperations) > 0 {
		addOperation(recoveryOperations[0])
		if len(recoveryOperations) > 1 {
			addOperation(recoveryOperations[len(recoveryOperations)/2])
		}
	}

	random := rand.New(rand.NewSource(seed))
	permutation := random.Perm(totalOperations)
	for _, index := range permutation {
		if len(result) >= count {
			break
		}
		addOperation(index + 1)
	}

	return result
}

func crashSeeds(t *testing.T) []int64 {
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
		for index := 0; index < count; index++ {
			seeds[index] = int64(index)
		}
		return seeds
	}
	return []int64{42}
}

// The test shows that each target phase was reached as follows:
//
//  1. Crash during a checkpoint:
//     During the baseline workload run, periodic checkpoints flush dirty pages and sync
//     both the heap file and WAL. The test records the checkpoint phase directly around
//     calls to Checkpoint() and asserts that checkpoint I/O operations are reached in
//     the baseline run for the default seed. In short mode, sampleOperations explicitly
//     selects operations from this phase; in long mode, every operation is tested.
//
//  2. Crash during WAL segment rotation:
//     With WithWALMaxSegmentSize set to 8 KiB, appends of multi-block values exceed segment
//     capacity and trigger WAL segment rotation (flushing and syncing the superseded segment,
//     writing the new segment header, and syncing the new segment). The test detects segment
//     rotation whenever an I/O operation targets a previously unseen WAL segment file.
//     The test asserts that rotation operations are reached for the default seed and selects
//     them during sampling.
//
//  3. Crash during recovery's own writes:
//     At the end of Cycle 0, the store crashes with uncheckpointed WAL records. Cycle 1
//     reopens the store, triggering crash recovery. In Open, after WAL replay reconstructs dirty
//     pages, s.cp.FlushPages flushes dirty pages to the heap and syncs it before accepting writes.
//     The test records the recovery phase directly around the reopening call to Open() and
//     asserts that recovery write operations are reached for the default seed and selects
//     them during sampling.
func TestCrashAtEveryIO(t *testing.T) {
	seeds := crashSeeds(t)
	explicitSeed := os.Getenv("DISKSTORE_TORTURE_SEED") != ""
	explicitOpStr := os.Getenv("DISKSTORE_TORTURE_OP")
	var explicitOp int
	if explicitOpStr != "" {
		var parseErr error
		explicitOp, parseErr = strconv.Atoi(explicitOpStr)
		if parseErr != nil {
			t.Fatalf("invalid DISKSTORE_TORTURE_OP=%q: %v", explicitOpStr, parseErr)
		}
	}

	const defaultSeed int64 = 42

	for _, config := range crashIOConfigs {
		config := config
		t.Run(config.name, func(t *testing.T) {
			if config.skipReason != "" && !explicitSeed {
				t.Skip(config.skipReason)
			}
			if testing.Short() && config.encryption && !explicitSeed {
				t.Skip("skipping encrypted crash-io configuration in short mode to keep test runtime fast")
			}

			for _, seed := range seeds {
				// Phase 1: Baseline run to count write and sync operations and identify phases.
				baselineConfig := config
				baselineConfig.stopOnCrash = false
				baselineConfig.onIO = func(targetFS *FaultFS, path string, isSync bool) {
					// onIO hook is installed to enable recording ioPhases in the runner.
				}

				baselineResult := runTortureWorkload(t, baselineConfig, seed)

				var checkpointOperations, rotationOperations, recoveryOperations []int
				for index, phase := range baselineResult.ioPhases {
					operationNumber := index + 1
					switch phase {
					case phaseCheckpoint:
						checkpointOperations = append(checkpointOperations, operationNumber)
					case phaseSegmentRotation:
						rotationOperations = append(rotationOperations, operationNumber)
					case phaseRecovery:
						recoveryOperations = append(recoveryOperations, operationNumber)
					}
				}

				// Verify that baseline covered all three required phases for the default seed.
				if seed == defaultSeed {
					if len(checkpointOperations) == 0 {
						t.Fatalf("baseline did not reach any checkpoint I/O operations (config=%s seed=%d)", config.name, seed)
					}
					if len(rotationOperations) == 0 {
						t.Fatalf("baseline did not reach any WAL segment rotation I/O operations (config=%s seed=%d)", config.name, seed)
					}
					if len(recoveryOperations) == 0 {
						t.Fatalf("baseline did not reach any recovery write I/O operations (config=%s seed=%d)", config.name, seed)
					}
				}

				// Phase 2: Determine operations to test.
				var testOperations []int
				if explicitOp > 0 {
					testOperations = []int{explicitOp}
				} else if testing.Short() {
					testOperations = sampleOperations(baselineResult.totalIO, 25, seed, checkpointOperations, rotationOperations, recoveryOperations)
				} else {
					testOperations = make([]int, baselineResult.totalIO)
					for index := 0; index < baselineResult.totalIO; index++ {
						testOperations[index] = index + 1
					}
				}

				allKeys := make([]string, config.numKeys)
				for index := range allKeys {
					allKeys[index] = fmt.Sprintf("k%d", index)
				}

				for _, crashOperationNumber := range testOperations {
					rerunCommand := fmt.Sprintf("DISKSTORE_TORTURE_SEED=%d DISKSTORE_TORTURE_OP=%d go test -v -run 'TestCrashAtEveryIO/%s' ./experiments/diskstore/engine",
						seed, crashOperationNumber, config.name)

					crashConfig := config
					crashConfig.stopOnCrash = true
					var localIOCount int
					var localIOMutex sync.Mutex
					var localCrashError error

					crashConfig.onIO = func(targetFS *FaultFS, path string, isSync bool) {
						localIOMutex.Lock()
						defer localIOMutex.Unlock()
						localIOCount++
						if localIOCount == crashOperationNumber {
							if crashError := targetFS.Crash(true, 0); crashError != nil {
								localCrashError = crashError
							}
						}
					}

					result := runTortureWorkload(t, crashConfig, seed)
					if localCrashError != nil {
						t.Fatalf("filesystem crash error: config=%s seed=%d crashOp=%d: %v\nRerun with:\n  %s",
							config.name, seed, crashOperationNumber, localCrashError, rerunCommand)
					}

					// Reopen the store on the crashed filesystem state.
					reopenFS := NewFaultFS(result.memFS)
					if config.encryption {
						cipher, cipherErr := newHeapCipher(result.encryptionKey[:], result.dbID)
						if cipherErr != nil {
							t.Fatalf("newHeapCipher failed on reopen: config=%s seed=%d crashOp=%d: %v\nRerun with:\n  %s",
								config.name, seed, crashOperationNumber, cipherErr, rerunCommand)
						}
						reopenFS.SetHeapCipher(cipher)
						reopenFS.SetEncryptionKey(result.encryptionKey[:])
					}

					reopenOptions := []Option{
						WithFS(reopenFS),
						WithDir("torture_store"),
						WithNumPoolBlocks(config.poolBlocks),
						WithCompressionCodec(CodecNone),
					}
					if config.encryption {
						reopenOptions = append(reopenOptions, WithEncryptionKey(result.encryptionKey[:]))
					}
					if config.walMaxSegSize > 0 {
						reopenOptions = append(reopenOptions, WithWALMaxSegmentSize(config.walMaxSegSize))
					}

					reopenedStore, reopenErr := Open(reopenOptions...)
					if reopenErr != nil {
						t.Fatalf("reopen failed after crash at op %d: config=%s seed=%d: %v\nRerun with:\n  %s",
							crashOperationNumber, config.name, seed, reopenErr, rerunCommand)
					}

					// Check that the reopened store equals the model at some point between
					// the last Sync that returned and the last operation that returned,
					// or the model with the in-flight operation applied.
					matched := false
					for step := result.lastSyncOp; step <= result.lastCompletedOp; step++ {
						equal, compareErr := checkStoreEqualsModel(reopenedStore, "torture_table", allKeys, result.history[step])
						if compareErr != nil {
							if closeErr := reopenedStore.Close(); closeErr != nil {
								t.Logf("close error: %v", closeErr)
							}
							t.Fatalf("error checking store against model %d: config=%s seed=%d crashOp=%d: %v\nRerun with:\n  %s",
								step, config.name, seed, crashOperationNumber, compareErr, rerunCommand)
						}
						if equal {
							matched = true
							break
						}
					}

					// If not matched by any completed operation model, check if the in-flight operation
					// took effect before the crash occurred.
					if !matched && result.inFlightModel != nil {
						equal, compareErr := checkStoreEqualsModel(reopenedStore, "torture_table", allKeys, result.inFlightModel)
						if compareErr != nil {
							if closeErr := reopenedStore.Close(); closeErr != nil {
								t.Logf("close error: %v", closeErr)
							}
							t.Fatalf("error checking store against in-flight model: config=%s seed=%d crashOp=%d: %v\nRerun with:\n  %s",
								config.name, seed, crashOperationNumber, compareErr, rerunCommand)
						}
						if equal {
							matched = true
						}
					}

					if !matched {
						var resurrectedKeys []string
						for _, key := range allKeys {
							_, wantExists := result.history[result.lastCompletedOp][key]
							if !wantExists {
								_, exists, getErr := reopenedStore.Get("torture_table", key)
								if getErr == nil && exists {
									resurrectedKeys = append(resurrectedKeys, key)
								}
							}
						}
						if closeErr := reopenedStore.Close(); closeErr != nil {
							t.Logf("close error: %v", closeErr)
						}
						t.Fatalf("store state mismatch after crash at op %d: did not match any model between last Sync (model %d) and last completed op (model %d) nor in-flight model, resurrected deleted keys=%v: config=%s seed=%d\nRerun with:\n  %s",
							crashOperationNumber, result.lastSyncOp, result.lastCompletedOp, resurrectedKeys, config.name, seed, rerunCommand)
					}

					if closeErr := reopenedStore.Close(); closeErr != nil {
						t.Fatalf("close reopenedStore failed: config=%s seed=%d crashOp=%d: %v\nRerun with:\n  %s",
							config.name, seed, crashOperationNumber, closeErr, rerunCommand)
					}
				}
			}
		})
	}
}
