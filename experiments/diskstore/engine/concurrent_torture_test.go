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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type keyVersion struct {
	sequence uint64
	exists   bool
	value    []byte
}

// concurrentModel records every write that the single writer starts and
// completes. Readers and List callers check two invariants against this
// history:
//   - Get returns a version from the key's history at or after the latest
//     write completed when Get began, and no later than the latest write
//     started when Get returned.
//   - List returns a point-in-time snapshot that matches one sequence in
//     that same interval across all keys.
type concurrentModel struct {
	mu        sync.Mutex
	started   uint64
	completed atomic.Uint64
	history   map[string][]keyVersion
}

func (m *concurrentModel) beginWrite(key string, exists bool, value []byte) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started++
	m.history[key] = append(m.history[key], keyVersion{sequence: m.started, exists: exists, value: value})
	return m.started
}

func (m *concurrentModel) matchesAtLocked(key string, sequence uint64, exists bool, value []byte) bool {
	versions := m.history[key]
	version := versions[0]
	for i := len(versions) - 1; i > 0; i-- {
		if versions[i].sequence <= sequence {
			version = versions[i]
			break
		}
	}
	return version.exists == exists && (!exists || bytes.Equal(version.value, value))
}

func (m *concurrentModel) checkGet(key string, startSequence uint64, exists bool, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sequence := startSequence; sequence <= m.started; sequence++ {
		if m.matchesAtLocked(key, sequence, exists, value) {
			return nil
		}
	}
	return fmt.Errorf("Get(%q) returned exists=%v len=%d, outside history for [%d, %d]", key, exists, len(value), startSequence, m.started)
}

func (m *concurrentModel) checkList(keys []string, startSequence uint64, items []RecordItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
nextSequence:
	for sequence := startSequence; sequence <= m.started; sequence++ {
		for _, key := range keys {
			if value, exists := got[key]; !m.matchesAtLocked(key, sequence, exists, value) {
				continue nextSequence
			}
		}
		return nil
	}
	return fmt.Errorf("List returned %d keys, matching no state in [%d, %d]", len(items), startSequence, m.started)
}

// runConcurrentTorture runs readers, List callers, one writer, and the
// checkpointer against one engine without injecting faults. When beforeWorkers
// is non-nil, the runner calls it after seeding keys and calls its returned
// release function when the watchdog fires or during teardown.
func runConcurrentTorture(t testing.TB, seed int64, writerOperations int, stallTimeout time.Duration, beforeWorkers func(*Engine) func()) {
	t.Helper()
	const tableName = "concurrent_torture_table"
	var failed, abandoned bool
	failRun := func(cause error) {
		t.Helper()
		failed = true
		t.Fatalf("concurrent torture failure (seed=%d)\nRerun: DISKSTORE_TORTURE_SEED=%d go test -race -v -run '^TestConcurrentTorture$' ./experiments/diskstore/engine\n%v", seed, seed, cause)
	}

	keys := make([]string, 32)
	model := &concurrentModel{history: make(map[string][]keyVersion, len(keys))}
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d", i)
		model.history[keys[i]] = []keyVersion{{sequence: 0}}
	}

	faultFS := NewFaultFS(NewMemFS())
	store, openErr := Open(WithFS(faultFS), WithDir("concurrent_torture"), WithNumPoolBlocks(48),
		WithCompressionCodec(CodecNone), WithWALMaxSegmentSize(16*1024), WithCreate())
	if openErr != nil {
		failRun(fmt.Errorf("Open: %w", openErr))
	}
	defer func() {
		if abandoned {
			return
		}
		if failed {
			TestHookFail(store, errors.New("concurrent torture failed"))
		}
		if closeErr := store.Close(); closeErr != nil && !failed {
			t.Errorf("concurrent torture cleanup: Close failed: %v", closeErr)
		}
	}()

	writerRandom := rand.New(rand.NewSource(seed))
	existingLengths := make(map[string]int, len(keys))
	applyWrite := func(key string, remove bool) error {
		var value []byte
		if !remove {
			value = generateTortureValue(writerRandom, 4, existingLengths[key])
		}
		sequence := model.beginWrite(key, !remove, value)
		var writeErr error
		if remove {
			writeErr = store.Delete(tableName, key)
			delete(existingLengths, key)
		} else {
			writeErr = store.Put(tableName, key, value)
			existingLengths[key] = len(value)
		}
		if writeErr == nil {
			model.completed.Store(sequence)
		}
		return writeErr
	}
	for _, key := range keys {
		if seedErr := applyWrite(key, false); seedErr != nil {
			failRun(fmt.Errorf("seed Put(%q): %w", key, seedErr))
		}
	}

	var releaseOnce sync.Once
	unlock := func() {}
	if beforeWorkers != nil {
		unlock = beforeWorkers(store)
		defer func() { releaseOnce.Do(unlock) }()
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	firstErr := make(chan error, 1)
	var totalCompleted, writerCompleted atomic.Int64
	var wg sync.WaitGroup
	spawnLoop := func(step func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if stepErr := step(); stepErr != nil {
					select {
					case firstErr <- stepErr:
					default:
					}
					cancel()
					return
				}
				totalCompleted.Add(1)
			}
		}()
	}

	operationIndex := 0
	spawnLoop(func() error {
		operationIndex++
		key := keys[writerRandom.Intn(len(keys))]
		if writeErr := applyWrite(key, writerRandom.Intn(5) == 0); writeErr != nil {
			return fmt.Errorf("writer operation %d (%q): %w", operationIndex, key, writeErr)
		}
		writerCompleted.Add(1)
		if operationIndex >= writerOperations {
			cancel()
		}
		return nil
	})
	for readerIndex := range 4 {
		readerRandom := rand.New(rand.NewSource(seed + int64(readerIndex) + 1))
		spawnLoop(func() error {
			key := keys[readerRandom.Intn(len(keys))]
			startSequence := model.completed.Load()
			gotValue, gotExists, getErr := store.Get(tableName, key)
			if getErr != nil {
				return fmt.Errorf("Get(%q): %w", key, getErr)
			}
			return model.checkGet(key, startSequence, gotExists, gotValue)
		})
	}
	for range 2 {
		spawnLoop(func() error {
			startSequence := model.completed.Load()
			items, listErr := store.List(tableName)
			if listErr != nil {
				return fmt.Errorf("List: %w", listErr)
			}
			return model.checkList(keys, startSequence, items)
		})
	}
	spawnLoop(func() error { runtime.Gosched(); return store.Checkpoint() })

	workersDone := make(chan struct{})
	go func() { wg.Wait(); close(workersDone) }()

	// The watchdog fails the run with a goroutine dump when no operation
	// completes or the writer stops making progress for stallTimeout.
	ticker := time.NewTicker(min(max(stallTimeout/5, 10*time.Millisecond), 100*time.Millisecond))
	defer ticker.Stop()
	lastTotal, lastWrites := int64(0), int64(0)
	lastTotalAt, lastWriteAt := time.Now(), time.Now()
	var stalledErr error
watchdog:
	for {
		select {
		case <-workersDone:
			break watchdog
		case now := <-ticker.C:
			if total := totalCompleted.Load(); total != lastTotal {
				lastTotal, lastTotalAt = total, now
			} else if now.Sub(lastTotalAt) >= stallTimeout {
				stalledErr = fmt.Errorf("watchdog: no operation completed for %s (total=%d)", stallTimeout, total)
				break watchdog
			}
			if writes := writerCompleted.Load(); writes != lastWrites {
				lastWrites, lastWriteAt = writes, now
			} else if writes < int64(writerOperations) && now.Sub(lastWriteAt) >= stallTimeout {
				stalledErr = fmt.Errorf("watchdog: writer made no progress for %s (writes=%d)", stallTimeout, writes)
				break watchdog
			}
		}
	}

	if stalledErr != nil {
		buffer := make([]byte, 1<<20)
		dump := string(buffer[:runtime.Stack(buffer, true)])
		cancel()
		releaseOnce.Do(unlock)
		select {
		case <-workersDone:
		case <-time.After(time.Second):
			abandoned = true
		}
		failRun(fmt.Errorf("%w\n\ngoroutine dump:\n%s", stalledErr, dump))
	}
	select {
	case recordedErr := <-firstErr:
		failRun(recordedErr)
	default:
	}
	if violations := faultFS.Violations(); len(violations) > 0 {
		failRun(violations[0])
	}
	if engineErr := store.Err(); engineErr != nil {
		failRun(fmt.Errorf("engine entered failed state: %w", engineErr))
	}
}

func TestConcurrentTorture(t *testing.T) {
	seeds := []int64{0, 1, 2, 8}
	if os.Getenv("DISKSTORE_TORTURE_SEED") != "" || os.Getenv("DISKSTORE_TORTURE_SEEDS") != "" {
		seeds = tortureSeeds(t)
	} else if !testing.Short() {
		seeds = []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	}
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			runConcurrentTorture(t, seed, 200, 5*time.Second, nil)
		})
	}
}

func TestConcurrentTorture_WatchdogFires(t *testing.T) {
	recorder := &recordingTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConcurrentTorture(recorder, 7, 50, 100*time.Millisecond, func(store *Engine) func() {
			store.bp.mu.Lock()
			return store.bp.mu.Unlock
		})
	}()
	<-done
	if !recorder.failed {
		t.Fatalf("expected watchdog to fail concurrent torture run when lock is held")
	}
	for _, want := range []string{"watchdog:", "goroutine ", "DISKSTORE_TORTURE_SEED=7"} {
		if !strings.Contains(recorder.message, want) {
			t.Fatalf("expected failure message to contain %q, got: %s", want, recorder.message)
		}
	}
}
