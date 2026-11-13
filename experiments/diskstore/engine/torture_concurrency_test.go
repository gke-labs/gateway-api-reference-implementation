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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Watchdog monitors an atomic progress counter and fails the test with a full
// goroutine stack dump if no progress is made within the specified timeout.
type Watchdog struct {
	t         *testing.T
	timeout   time.Duration
	ops       *atomic.Int64
	lastVal   int64
	lastSeen  time.Time
	stopCh    chan struct{}
	doneCh    chan struct{}
	onTimeout func(string)
}

// NewWatchdog creates and starts a progress watchdog.
func NewWatchdog(t *testing.T, ops *atomic.Int64, timeout time.Duration, onTimeout ...func(string)) *Watchdog {
	w := &Watchdog{
		t:        t,
		timeout:  timeout,
		ops:      ops,
		lastSeen: time.Now(),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	if len(onTimeout) > 0 {
		w.onTimeout = onTimeout[0]
	}
	go w.run()
	return w
}

func (w *Watchdog) run() {
	defer close(w.doneCh)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case now := <-ticker.C:
			val := w.ops.Load()
			if val != w.lastVal {
				w.lastVal = val
				w.lastSeen = now
			} else if now.Sub(w.lastSeen) > w.timeout {
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				msg := fmt.Sprintf("WATCHDOG: lack of progress for %v (deadlock detected, ops stalled at %d)\n%s",
					w.timeout, val, buf[:n])
				if w.onTimeout != nil {
					w.onTimeout(msg)
				} else if w.t != nil {
					w.t.Errorf("%s", msg)
				}
				return
			}
		}
	}
}

// Stop terminates the watchdog.
func (w *Watchdog) Stop() {
	close(w.stopCh)
	<-w.doneCh
}

// TestTorture_Concurrency runs many concurrent readers, List callers, a mutating writer,
// a checkpointer, and the background writer under -race.
// Reads must only ever return values from the model's history for that key, and must never
// put the store into the failed state. A watchdog asserts lack of deadlocks.
func TestTorture_Concurrency(t *testing.T) {
	testDuration := 3 * time.Second
	if !testing.Short() {
		testDuration = 8 * time.Second
	}
	if durStr := os.Getenv("DISKSTORE_TORTURE_CONCURRENCY_DURATION"); durStr != "" {
		if d, err := time.ParseDuration(durStr); err == nil {
			testDuration = d
		}
	}

	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "concurrency_torture_store"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(128))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	model := NewReferenceModel()
	buckets := []string{"ConfigMap", "Secret", "Gateway"}
	keys := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"}

	// Pre-populate with initial records
	for _, b := range buckets {
		for _, k := range keys {
			initVal := []byte(fmt.Sprintf("init-%s-%s", b, k))
			if pErr := store.Put(b, k, initVal, "0"); pErr != nil {
				t.Fatalf("initial Put failed: %v", pErr)
			}
			model.RecordPut(b, k, initVal, "0", store.wal.MaxLSN())
		}
	}

	var progressOps atomic.Int64
	watchdog := NewWatchdog(t, &progressOps, 5*time.Second)
	defer watchdog.Stop()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// 1. Many Reader Goroutines (Get)
	numReaders := 8
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(1000 + readerID)))
			for {
				select {
				case <-stopCh:
					return
				default:
				}

				b := buckets[rng.Intn(len(buckets))]
				k := keys[rng.Intn(len(keys))]
				val, exists, gErr := store.Get(b, k)
				if gErr != nil {
					t.Errorf("reader %d: Get(%s, %s) failed: %v", readerID, b, k, gErr)
					return
				}
				if store.isFailed() {
					t.Errorf("reader %d: store unexpectedly entered failed state", readerID)
					return
				}
				if exists && len(val) > 0 {
					if !model.IsValueInHistory(b, k, val) {
						t.Errorf("reader %d: Get(%s, %s) returned invalid corrupted value not in history", readerID, b, k)
						return
					}
				}
				progressOps.Add(1)
			}
		}(r)
	}

	// 2. Concurrent List Callers
	numListCallers := 2
	for l := 0; l < numListCallers; l++ {
		wg.Add(1)
		go func(listerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(2000 + listerID)))
			for {
				select {
				case <-stopCh:
					return
				default:
				}

				b := buckets[rng.Intn(len(buckets))]
				items, lErr := store.List(b)
				if lErr != nil {
					t.Errorf("lister %d: List(%s) failed: %v", listerID, b, lErr)
					return
				}
				for _, item := range items {
					if len(item.Payload) > 0 && !model.IsValueInHistory(b, item.Key, item.Payload) {
						t.Errorf("lister %d: List returned item %s with corrupted value", listerID, item.Key)
						return
					}
				}
				progressOps.Add(1)
				time.Sleep(5 * time.Millisecond)
			}
		}(l)
	}

	// 3. Mutating Writer Goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(3000))
		writerOp := 0
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			writerOp++
			b := buckets[rng.Intn(len(buckets))]
			k := keys[rng.Intn(len(keys))]
			tok := fmt.Sprintf("tok-%d", writerOp)

			action := rng.Intn(4)
			switch action {
			case 0, 1:
				// Put / Update across slotted, multi-block, and oversize
				var payload []byte
				switch rng.Intn(3) {
				case 0:
					payload = bytes.Repeat([]byte(fmt.Sprintf("v-%s-%d-", k, writerOp)), 5)
				case 1:
					payload = make([]byte, 8192)
					rng.Read(payload)
				default:
					payload = bytes.Repeat([]byte("large-val-"), 500)
				}
				model.AddKeyHistory(b, k, payload)
				if pErr := store.Put(b, k, payload, tok); pErr != nil {
					t.Errorf("writer Put(%s, %s) failed: %v", b, k, pErr)
					return
				}
				model.RecordPut(b, k, payload, tok, store.wal.MaxLSN())

			case 2:
				// Delete
				existed := false
				model.mu.RLock()
				if model.currentData[b] != nil {
					_, existed = model.currentData[b][k]
				}
				model.mu.RUnlock()

				if dErr := store.Delete(b, k, tok); dErr != nil {
					t.Errorf("writer Delete(%s, %s) failed: %v", b, k, dErr)
					return
				}
				if existed {
					model.RecordDelete(b, k, tok, store.wal.MaxLSN())
				}

			case 3:
				// Indexer Replace (batch delete + put)
				itemsToKeep := make(map[string][]byte)
				for i := 0; i < 3; i++ {
					selKey := keys[rng.Intn(len(keys))]
					itemsToKeep[selKey] = []byte(fmt.Sprintf("repl-%s-%d", selKey, writerOp))
				}
				currKeys := store.ListKeys(b)
				for _, ck := range currKeys {
					if _, keep := itemsToKeep[ck]; !keep {
						_ = store.Delete(b, ck, tok)
						model.RecordDelete(b, ck, tok, store.wal.MaxLSN())
					}
				}
				for ik, iv := range itemsToKeep {
					model.AddKeyHistory(b, ik, iv)
					_ = store.Put(b, ik, iv, tok)
					model.RecordPut(b, ik, iv, tok, store.wal.MaxLSN())
				}
			}

			progressOps.Add(1)
		}
	}()

	// 4. Background Checkpointer Goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			case <-time.After(50 * time.Millisecond):
			}

			chkLSN, cErr := store.Checkpoint()
			if cErr != nil {
				t.Errorf("concurrent Checkpoint failed: %v", cErr)
				return
			}
			model.RecordCheckpoint(chkLSN)
			progressOps.Add(1)
		}
	}()

	// Run for test duration
	time.Sleep(testDuration)
	close(stopCh)
	wg.Wait()

	// Structural invariant check after concurrent torture
	if sErr := store.CheckStructuralInvariants(); sErr != nil {
		t.Fatalf("Structural invariant failure after concurrency torture: %v", sErr)
	}
}
