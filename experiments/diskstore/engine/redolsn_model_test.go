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
	changes          []uint64
	flushedMaxLSN    uint64
	inFlightFlushLSN uint64
	syncingMaxLSN    uint64
	durableMaxLSN    uint64
}

func (m *redoLSNModel) answer() uint64 {
	for _, c := range m.changes {
		if c > m.durableMaxLSN {
			return c
		}
	}
	return 0
}

func (m *redoLSNModel) applyChange(lsn uint64) {
	m.changes = append(m.changes, lsn)
}

func (m *redoLSNModel) applyFlushStart() {
	if len(m.changes) > 0 {
		m.inFlightFlushLSN = m.changes[len(m.changes)-1]
	}
}

func (m *redoLSNModel) applyFlushReturn() {
	if m.inFlightFlushLSN > m.flushedMaxLSN {
		m.flushedMaxLSN = m.inFlightFlushLSN
	}
	m.inFlightFlushLSN = 0
}

func (m *redoLSNModel) applyFsyncStart() {
	m.syncingMaxLSN = m.flushedMaxLSN
}

func (m *redoLSNModel) applyFsyncSucceed() {
	if m.syncingMaxLSN > m.durableMaxLSN {
		m.durableMaxLSN = m.syncingMaxLSN
	}
	m.syncingMaxLSN = 0
}

func (m *redoLSNModel) applyFsyncFail() {
	m.syncingMaxLSN = 0
}

type blockingHeapFile struct {
	File
	mu           sync.Mutex
	writeStarted chan struct{}
	releaseWrite chan struct{}
}

func (b *blockingHeapFile) WriteAt(p []byte, off int64) (int, error) {
	b.mu.Lock()
	started := b.writeStarted
	release := b.releaseWrite
	b.mu.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return b.File.WriteAt(p, off)
}

func (b *blockingHeapFile) SyscallConn() (any, error) { return nil, nil }

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

func (e redoEvent) String() string { return redoEventNames[e] }

// TestBlockPool_RedoLSNModel tests that RedoLSN on each page and DirtyPageTableAndLSN
// precisely match an independent model across random sequences of events.
func TestBlockPool_RedoLSNModel(t *testing.T) {
	numSequences := 3000
	if !testing.Short() {
		numSequences = 30000
	}

	baseSeed := int64(42)
	if s := os.Getenv("DISKSTORE_REDOLSN_SEED"); s != "" {
		if val, err := strconv.ParseInt(s, 10, 64); err == nil {
			baseSeed = val
			numSequences = 1
		}
	}

	masterRNG := rand.New(rand.NewSource(baseSeed))
	const pageID uint64 = 1
	var dbID [16]byte
	copy(dbID[:], []byte("redolsn-model-db"))

	memFile := &MemFile{}
	blockFile := &blockingHeapFile{File: memFile}
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(blockFile, nil, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 8})
	defer func() {
		close(bp.bgStop)
		<-bp.bgDone
	}()

	for seq := 0; seq < numSequences; seq++ {
		seqSeed := masterRNG.Int63()
		rng := rand.New(rand.NewSource(seqSeed))

		bp.mu.Lock()
		bp.pageTable = make(map[uint64]*PageDesc)
		bp.flushedPagesSyncing = make(map[uint64]struct{})
		bp.flushedPagesUnsynced = make(map[uint64]uint64)
		bp.deferredFreesSyncing = nil
		bp.deferredFreesUnsynced = nil
		bp.buddy = NewBuddyAllocator(512)
		bp.freePoolBlocks = bp.freePoolBlocks[:0]
		for i := 0; i < bp.numPoolBlocks; i++ {
			bp.freePoolBlocks = append(bp.freePoolBlocks, i)
		}
		bp.mu.Unlock()

		memFile.mu.Lock()
		memFile.data = memFile.data[:0]
		memFile.mu.Unlock()

		m := &redoLSNModel{}
		var currentLSN uint64 = 1
		var history []string

		h, err := bp.AllocateNewPage(pageID, 1, currentLSN)
		if err != nil {
			t.Fatalf("seq %d (seed=%d): initial AllocateNewPage failed: %v", seq, seqSeed, err)
		}
		h.Unpin()
		m.applyChange(currentLSN)
		history = append(history, fmt.Sprintf("init(lsn=%d)", currentLSN))

		var flushInFlight, fsyncInFlight bool
		var releaseWrite chan struct{}
		var flushDone chan error

		cleanup := func() {
			if flushInFlight {
				close(releaseWrite)
				<-flushDone
				flushInFlight = false
			}
		}

		numEvents := 20 + rng.Intn(15)
		for evIdx := 0; evIdx < numEvents; evIdx++ {
			bp.mu.Lock()
			pageDirty := bp.pageTable[pageID] != nil && bp.pageTable[pageID].Dirty
			bp.mu.Unlock()

			candidates := []redoEvent{eventChange}
			if !flushInFlight {
				candidates = append(candidates, eventRealloc)
			}
			// Flush failures are left out of the random events: a failed flush puts
			// the engine into its failed state, so no subsequent flushes or checkpoints run.
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
				m.applyChange(currentLSN)
				history = append(history, fmt.Sprintf("change(lsn=%d)", currentLSN))

			case eventRealloc:
				currentLSN++
				rh, rErr := bp.AllocateNewPage(pageID, 1, currentLSN)
				if rErr != nil {
					cleanup()
					t.Fatalf("seq %d (seed=%d): AllocateNewPage failed: %v\nseq: %v", seq, seqSeed, rErr, history)
				}
				rh.Unpin()
				m.applyChange(currentLSN)
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
				m.applyFlushStart()
				history = append(history, "flush_start")

			case eventFlushReturn:
				close(releaseWrite)
				fErr := <-flushDone
				flushInFlight = false
				if fErr != nil {
					cleanup()
					t.Fatalf("seq %d (seed=%d): FlushPage failed: %v\nseq: %v", seq, seqSeed, fErr, history)
				}
				m.applyFlushReturn()
				history = append(history, "flush_return")

			case eventFsyncStart:
				bp.startHeapSync()
				fsyncInFlight = true
				m.applyFsyncStart()
				history = append(history, "fsync_start")

			case eventFsyncSucceed:
				if sErr := bp.heapSyncSucceeded(); sErr != nil {
					cleanup()
					t.Fatalf("seq %d (seed=%d): heapSyncSucceeded failed: %v\nseq: %v", seq, seqSeed, sErr, history)
				}
				fsyncInFlight = false
				m.applyFsyncSucceed()
				history = append(history, "fsync_succeed")

			case eventFsyncFail:
				bp.heapSyncFailed()
				fsyncInFlight = false
				m.applyFsyncFail()
				history = append(history, "fsync_fail")
			}

			bp.mu.Lock()
			desc := bp.pageTable[pageID]
			var redoLSN uint64
			if desc != nil {
				redoLSN = desc.RedoLSN
			}
			bp.mu.Unlock()

			dpt, _ := bp.DirtyPageTableAndLSN()
			dptLSN := dpt[pageID]
			modelAns := m.answer()

			if redoLSN != dptLSN {
				cleanup()
				t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) != DirtyPageTable entry (%d)", seqSeed, history, redoLSN, dptLSN)
			}
			if redoLSN > modelAns {
				cleanup()
				t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) is above model's answer (%d) (unsafe: premature truncation risk)", seqSeed, history, redoLSN, modelAns)
			}
			if redoLSN < modelAns {
				cleanup()
				t.Fatalf("seed=%d seq=%v:\nRedoLSN (%d) is below model's answer (%d) (suboptimal: retains unnecessary log)", seqSeed, history, redoLSN, modelAns)
			}
		}

		cleanup()
	}
}
