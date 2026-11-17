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
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
)

// redoLSNModel tracks which changes to a page are confirmed durable.
// A change is durable when a flush covering it returned before the start of a heap fsync that succeeded.
type redoLSNModel struct {
	// changes lists all mutating LSNs applied to the page in chronological order.
	changes []uint64
	// flushedMaxLSN is the highest LSN covered by a flush that has returned before an fsync starts.
	flushedMaxLSN uint64
	// inFlightFlushLSN is the highest LSN captured by the flush currently in flight, or 0 if none.
	inFlightFlushLSN uint64
	// syncingMaxLSN is the flushedMaxLSN captured at the start of the heap fsync in progress, or 0 if none.
	syncingMaxLSN uint64
	// durableMaxLSN is the highest LSN confirmed durable by a completed heap fsync.
	durableMaxLSN uint64
}

func (model *redoLSNModel) answer() uint64 {
	for _, change := range model.changes {
		if change > model.durableMaxLSN {
			return change
		}
	}
	return 0
}

func (model *redoLSNModel) applyChange(lsn uint64) {
	model.changes = append(model.changes, lsn)
}

func (model *redoLSNModel) applyFlushStart() {
	if len(model.changes) > 0 {
		model.inFlightFlushLSN = model.changes[len(model.changes)-1]
	}
}

func (model *redoLSNModel) applyFlushReturn() {
	if model.inFlightFlushLSN > model.flushedMaxLSN {
		model.flushedMaxLSN = model.inFlightFlushLSN
	}
	model.inFlightFlushLSN = 0
}

func (model *redoLSNModel) applyFsyncStart() {
	model.syncingMaxLSN = model.flushedMaxLSN
}

func (model *redoLSNModel) applyFsyncSucceed() {
	if model.syncingMaxLSN > model.durableMaxLSN {
		model.durableMaxLSN = model.syncingMaxLSN
	}
	model.syncingMaxLSN = 0
}

func (model *redoLSNModel) applyFsyncFail() {
	model.syncingMaxLSN = 0
}

type blockingHeapFile struct {
	// File is the underlying storage file for data blocks.
	File
	// mu protects writeStarted and releaseWrite across goroutines.
	mu sync.Mutex
	// writeStarted is signaled when WriteAt enters, notifying the test that a write is in flight.
	writeStarted chan struct{}
	// releaseWrite blocks WriteAt until closed or signaled, controlling when the write completes.
	releaseWrite chan struct{}
}

func (file *blockingHeapFile) WriteAt(p []byte, off int64) (int, error) {
	file.mu.Lock()
	started := file.writeStarted
	release := file.releaseWrite
	file.mu.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return file.File.WriteAt(p, off)
}

// SyscallConn returns nil because blockingHeapFile wraps an in-memory file without an OS descriptor.
// Returning nil forces DirectIO to fall back to WriteAt/ReadAt, allowing the test to intercept writes.
func (file *blockingHeapFile) SyscallConn() (any, error) {
	return nil, nil
}

type redoEvent int

const (
	eventChange redoEvent = iota
	eventFlushStart
	eventFlushReturn
	eventFsyncStart
	eventFsyncSucceed
	eventFsyncFail
	eventRealloc
)

var redoEventNames = [...]string{
	"change", "flush_start", "flush_return", "fsync_start", "fsync_succeed", "fsync_fail", "realloc",
}

func (event redoEvent) String() string { return redoEventNames[event] }

func runRedoLSNModelSequence(t *testing.T, seqSeed int64, pageID uint64, dbID [16]byte) {
	t.Helper()
	rng := rand.New(rand.NewSource(seqSeed))
	rerunCommand := fmt.Sprintf("DISKSTORE_REDOLSN_SEED=%d go test -v -run TestBlockPool_RedoLSNModel ./experiments/diskstore/engine", seqSeed)

	memFile := &MemFile{}
	blockFile := &blockingHeapFile{File: memFile}
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(blockFile, nil, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 8})

	var flushInFlight, fsyncInFlight bool
	var releaseWrite chan struct{}
	var flushDone chan error

	cleanup := func() {
		if flushInFlight {
			close(releaseWrite)
			<-flushDone
			flushInFlight = false
		}
		blockFile.mu.Lock()
		blockFile.writeStarted = nil
		blockFile.releaseWrite = nil
		blockFile.mu.Unlock()
	}

	var closed bool
	defer func() {
		if !closed {
			cleanup()
			_ = bp.Close()
		}
	}()

	model := &redoLSNModel{}
	var currentLSN uint64 = 1
	var history []string

	pageHandle, err := bp.AllocateNewPage(pageID, 1, currentLSN)
	if err != nil {
		t.Fatalf("seed=%d: initial AllocateNewPage failed: %v\nRerun: %s", seqSeed, err, rerunCommand)
	}
	pageHandle.Unpin()
	model.applyChange(currentLSN)
	history = append(history, fmt.Sprintf("init(lsn=%d)", currentLSN))

	numEvents := 20 + rng.Intn(15)
	for eventIndex := 0; eventIndex < numEvents; eventIndex++ {
		bp.mu.Lock()
		pageDirty := bp.pageTable[pageID] != nil && bp.pageTable[pageID].Dirty
		bp.mu.Unlock()

		// Determine valid candidate events for this step:
		// - A second flush while one is in flight and a reallocation during a flush are
		//   left out because the engine never does either (FlushPage returns early if InFlight
		//   is true, and AllocateNewPage waits for InFlight to clear).
		// - Flush failures are left out because a failed flush puts the engine into its
		//   failed state, after which no subsequent flushes or checkpoints run.
		candidates := []redoEvent{eventChange}
		if !flushInFlight {
			candidates = append(candidates, eventRealloc)
		}
		if pageDirty && !flushInFlight {
			candidates = append(candidates, eventFlushStart)
		}
		if flushInFlight {
			candidates = append(candidates, eventFlushReturn)
		}
		if !fsyncInFlight {
			candidates = append(candidates, eventFsyncStart)
		} else {
			candidates = append(candidates, eventFsyncSucceed, eventFsyncFail)
		}

		chosen := candidates[rng.Intn(len(candidates))]

		switch chosen {
		case eventChange:
			currentLSN++
			bp.MarkDirty(pageID, currentLSN)
			model.applyChange(currentLSN)
			history = append(history, fmt.Sprintf("change(lsn=%d)", currentLSN))

		case eventRealloc:
			currentLSN++
			reallocHandle, reallocErr := bp.AllocateNewPage(pageID, 1, currentLSN)
			if reallocErr != nil {
				t.Fatalf("seed=%d seq=%v:\nAllocateNewPage failed: %v\nRerun: %s", seqSeed, history, reallocErr, rerunCommand)
			}
			reallocHandle.Unpin()
			model.applyChange(currentLSN)
			history = append(history, fmt.Sprintf("realloc(lsn=%d)", currentLSN))

		case eventFlushStart:
			writeStarted := make(chan struct{})
			releaseWrite = make(chan struct{})
			blockFile.mu.Lock()
			blockFile.writeStarted = writeStarted
			blockFile.releaseWrite = releaseWrite
			blockFile.mu.Unlock()

			flushDone = make(chan error, 1)
			flushInFlight = true
			go func() {
				flushDone <- bp.FlushPage(pageID)
			}()
			<-writeStarted
			model.applyFlushStart()
			history = append(history, "flush_start")

		case eventFlushReturn:
			close(releaseWrite)
			flushErr := <-flushDone
			flushInFlight = false
			blockFile.mu.Lock()
			blockFile.writeStarted = nil
			blockFile.releaseWrite = nil
			blockFile.mu.Unlock()
			if flushErr != nil {
				t.Fatalf("seed=%d seq=%v:\nFlushPage failed: %v\nRerun: %s", seqSeed, history, flushErr, rerunCommand)
			}
			model.applyFlushReturn()
			history = append(history, "flush_return")

		case eventFsyncStart:
			bp.startHeapSync()
			fsyncInFlight = true
			model.applyFsyncStart()
			history = append(history, "fsync_start")

		case eventFsyncSucceed:
			if fsyncErr := bp.heapSyncSucceeded(); fsyncErr != nil {
				t.Fatalf("seed=%d seq=%v:\nheapSyncSucceeded failed: %v\nRerun: %s", seqSeed, history, fsyncErr, rerunCommand)
			}
			fsyncInFlight = false
			model.applyFsyncSucceed()
			history = append(history, "fsync_succeed")

		case eventFsyncFail:
			bp.heapSyncFailed()
			fsyncInFlight = false
			model.applyFsyncFail()
			history = append(history, "fsync_fail")
		}

		bp.mu.Lock()
		desc := bp.pageTable[pageID]
		var redoLSN uint64
		if desc != nil {
			redoLSN = desc.RedoLSN
		}
		bp.mu.Unlock()

		dirtyPageTable, _ := bp.DirtyPageTableAndLSN()
		dirtyPageTableLSN := dirtyPageTable[pageID]
		modelAnswer := model.answer()

		if redoLSN != dirtyPageTableLSN {
			t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) != DirtyPageTable entry (%d)\nRerun: %s",
				seqSeed, history, redoLSN, dirtyPageTableLSN, rerunCommand)
		}
		if redoLSN > modelAnswer {
			t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) is above model's answer (%d) (risks truncating WAL before change is durable)\nRerun: %s",
				seqSeed, history, redoLSN, modelAnswer, rerunCommand)
		}
		if redoLSN < modelAnswer {
			t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) is below model's answer (%d) (keeps more log than needed: retains already durable change)\nRerun: %s",
				seqSeed, history, redoLSN, modelAnswer, rerunCommand)
		}
	}

	cleanup()
	closed = true
	if closeErr := bp.Close(); closeErr != nil {
		t.Fatalf("seed=%d: Close failed: %v\nRerun: %s", seqSeed, closeErr, rerunCommand)
	}
}

// TestBlockPool_RedoLSNModel tests that a page's RedoLSN and the dirty page table entry
// equal the earliest non-durable change (or zero) tracked by an independent model
// across random sequences of events.
func TestBlockPool_RedoLSNModel(t *testing.T) {
	numSequences := 3000
	if !testing.Short() {
		numSequences = 30000
	}

	var explicitSeed *int64
	if seedString := os.Getenv("DISKSTORE_REDOLSN_SEED"); seedString != "" {
		parsedSeed, err := strconv.ParseInt(seedString, 10, 64)
		if err != nil {
			t.Fatalf("invalid DISKSTORE_REDOLSN_SEED=%q: %v", seedString, err)
		}
		explicitSeed = &parsedSeed
		numSequences = 1
	}

	masterRNG := rand.New(rand.NewSource(42))
	const pageID uint64 = 1
	var dbID [16]byte
	copy(dbID[:], []byte("redolsn-model-db"))

	for seq := 0; seq < numSequences; seq++ {
		seqSeed := masterRNG.Int63()
		if explicitSeed != nil {
			seqSeed = *explicitSeed
		}
		runRedoLSNModelSequence(t, seqSeed, pageID, dbID)
	}
}
