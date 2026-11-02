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
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestBlockPool_PinAndEviction(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00001"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)

	// Small block pool of 4 pool blocks to test pool block eviction under pressure
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 4})
	defer bp.Close()

	// Append WAL record for LSN 10
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("val1")})

	// Allocate page 1 (1 block)
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	copy(h1.Block(0)[BlockHeaderSize:], []byte("page-1-data"))
	h1.Unpin()

	// Flush page 1 -> writes to disk under write-ahead rule
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}

	// Verify page was written to disk and can be read back after eviction
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.PromoteFlushedToDurable(); err != nil {
		t.Fatalf("PromoteFlushedToDurable failed: %v", err)
	}

	// Allocate 4 new pages (pages 2, 3, 4, 5) to force eviction of page 1 from the 4-block pool
	for i := uint64(2); i <= 5; i++ {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: 10 + i, Key: "k", Payload: []byte("v")})
		h, err := bp.AllocateNewPage(i, 1, 10+i)
		if err != nil {
			t.Fatalf("AllocateNewPage %d failed: %v", i, err)
		}
		h.Unpin()
	}

	// Re-pin page 1 from disk
	loc := h1.Desc.DurableLoc
	h1Reloaded, err := bp.PinPageWithLocation(1, loc, 1)
	if err != nil {
		t.Fatalf("PinPageWithLocation failed: %v", err)
	}
	defer h1Reloaded.Unpin()

	if !bytes.HasPrefix(h1Reloaded.Block(0)[BlockHeaderSize:], []byte("page-1-data")) {
		t.Fatalf("reloaded page data mismatch: %s", string(h1Reloaded.Block(0)[BlockHeaderSize:BlockHeaderSize+12]))
	}
}

func TestBlockPool_MultiBlockPageNonAdjacentPoolBlocks(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00002"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	defer wal.Close()

	heapFile, _ := faultFS.Create("heap.db")
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)

	// Block pool of 16 pool blocks
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	defer bp.Close()

	// Allocate some single block pages first, then free some to create non-adjacent free pool blocks
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 50, Key: "k", Payload: []byte("v")})
	hA, _ := bp.AllocateNewPage(10, 1, 50)
	hB, _ := bp.AllocateNewPage(11, 1, 50)
	hC, _ := bp.AllocateNewPage(12, 1, 50)
	hA.Unpin()
	hB.Unpin()
	hC.Unpin()

	// Allocate a 4-block page (multi-block)
	hMulti, err := bp.AllocateNewPage(20, 4, 50)
	if err != nil {
		t.Fatalf("Allocate multi-block page failed: %v", err)
	}
	defer hMulti.Unpin()

	if len(hMulti.Blocks()) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(hMulti.Blocks()))
	}

	for i := 0; i < 4; i++ {
		copy(hMulti.Block(i)[BlockHeaderSize:], []byte("block-content"))
	}

	// Flush multi-block page
	if err := bp.FlushPage(20); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}
}

// TestBlockPool_InFlightWriteNotPromoted asserts that in-flight page writes are not promoted
// during a checkpoint, satisfying the Reuse Rule.
func TestBlockPool_InFlightWriteNotPromoted(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	// Reuse rule assertion stays enabled
	faultFS.SetAssertReuseRule(true)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00003"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	defer bp.Close()

	// Initial write of page 1 at LSN 10
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("v1")})
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	copy(h1.Block(0)[BlockHeaderSize:], []byte("v1-content"))
	h1.Unpin()

	// Flush and checkpoint to establish initial durable location
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}
	bp.SnapshotFlushedForSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.PromoteFlushedToDurable(); err != nil {
		t.Fatalf("PromoteFlushedToDurable failed: %v", err)
	}

	bp.mu.Lock()
	desc := bp.pageTable[1]
	initialDurableLoc := desc.DurableLoc
	bp.mu.Unlock()

	// Dirty page 1 again at LSN 20
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k1", Payload: []byte("v2")})
	h1Again, err := bp.PinPage(1)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	copy(h1Again.Block(0)[BlockHeaderSize:], []byte("v2-content"))
	h1Again.Unpin()
	bp.MarkDirty(1, 20)

	// Set up hook to pause the second write while it is in flight
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})

	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		select {
		case <-writeStarted:
			// Already triggered
		default:
			close(writeStarted)
			<-releaseWrite
		}
	})

	flushErrCh := make(chan error, 1)
	go func() {
		flushErrCh <- bp.FlushPage(1)
	}()

	// Wait for the write to become in flight
	<-writeStarted

	bp.mu.Lock()
	if !desc.InFlight {
		bp.mu.Unlock()
		close(releaseWrite)
		t.Fatalf("expected desc.InFlight to be true during write")
	}
	bp.mu.Unlock()

	// Checkpoint runs while the write is in flight
	bp.SnapshotFlushedForSync()
	if err := heapFile.Sync(); err != nil {
		close(releaseWrite)
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.PromoteFlushedToDurable(); err != nil {
		close(releaseWrite)
		t.Fatalf("PromoteFlushedToDurable failed: %v", err)
	}

	// Assert that in-flight location was NOT promoted
	bp.mu.Lock()
	if desc.DurableLoc != initialDurableLoc {
		bp.mu.Unlock()
		close(releaseWrite)
		t.Fatalf("in-flight location was promoted to durable! DurableLoc=%d, expected=%d", desc.DurableLoc, initialDurableLoc)
	}
	bp.mu.Unlock()

	// Release in-flight write to complete
	close(releaseWrite)
	if err := <-flushErrCh; err != nil {
		t.Fatalf("FlushPage failed after unblocking write: %v", err)
	}

	// Now that write completed, next checkpoint must promote it safely
	bp.SnapshotFlushedForSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.PromoteFlushedToDurable(); err != nil {
		t.Fatalf("PromoteFlushedToDurable failed: %v", err)
	}

	bp.mu.Lock()
	if desc.DurableLoc == initialDurableLoc {
		bp.mu.Unlock()
		t.Fatalf("expected DurableLoc to be promoted after write completed, still %d", desc.DurableLoc)
	}
	bp.mu.Unlock()
}

func TestBlockPool_BatchedEviction(t *testing.T) {
	dir := t.TempDir()
	fs := NewOSFS()

	var dbID [16]byte
	copy(dbID[:], []byte("evict-batch-test"))

	wal, err := OpenWAL(fs, filepath.Join(dir, "wal"), dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	rawHeap, err := fs.Create(filepath.Join(dir, "heap.db"))
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer rawHeap.Close()

	countingHeap := &countingFileWrapper{File: rawHeap}
	buddy := NewBuddyAllocator(512)

	// Block pool of 32 pool blocks
	bp := NewBlockPool(countingHeap, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 32})
	defer bp.Close()

	// Fill pool with 32 dirty pages
	for i := 1; i <= 32; i++ {
		lsn := uint64(i * 10)
		_ = wal.Append(Record{Type: RecordTypePut, LSN: lsn, Key: fmt.Sprintf("k%d", i), Payload: []byte("val")})
		h, err := bp.AllocateNewPage(uint64(i), 1, lsn)
		if err != nil {
			t.Fatalf("AllocateNewPage %d failed: %v", i, err)
		}
		copy(h.Block(0)[BlockHeaderSize:], []byte(fmt.Sprintf("page-%d-data", i)))
		h.Unpin()
	}

	// Reset write count before triggering eviction
	countingHeap.writeCalls.Store(0)

	// Allocate page 33: requires evicting pages because pool has 0 free pool blocks.
	// acquirePoolBlocksLocked will batch-flush candidate dirty pages in ONE write call.
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 330, Key: "k33", Payload: []byte("val")})
	h33, err := bp.AllocateNewPage(33, 1, 330)
	if err != nil {
		t.Fatalf("AllocateNewPage 33 failed: %v", err)
	}
	h33.Unpin()

	writes := countingHeap.writeCalls.Load()
	if writes != 1 {
		t.Fatalf("expected exactly 1 batched write call during eviction, got %d", writes)
	}

	// Verify page 1 (which was evicted) can be reloaded and matches data
	// First sync heap to establish durable locations
	bp.SnapshotFlushedForSync()
	_ = countingHeap.Sync()
	_ = bp.PromoteFlushedToDurable()

	bp.mu.Lock()
	loc1 := bp.pageTable[1].DurableLoc
	bp.mu.Unlock()

	h1Reloaded, err := bp.PinPageWithLocation(1, loc1, 1)
	if err != nil {
		t.Fatalf("PinPageWithLocation 1 failed: %v", err)
	}
	defer h1Reloaded.Unpin()

	expectedData := []byte("page-1-data")
	actualData := h1Reloaded.Block(0)[BlockHeaderSize : BlockHeaderSize+len(expectedData)]
	if !bytes.Equal(actualData, expectedData) {
		t.Fatalf("reloaded page 1 data mismatch: got %q, want %q", string(actualData), string(expectedData))
	}
}

// TestBlockPool_ConcurrentReuseWhileFlushing tests that AllocateNewPage does not tear down
// or release pool blocks for a page descriptor while a flush is in flight.
func TestBlockPool_ConcurrentReuseWhileFlushing(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-reuse---"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	defer bp.Close()

	// 1. Allocate page 1 and write incarnation 1 data
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("val1")})
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	incarnation1Data := []byte("incarnation-1-data")
	copy(h1.Block(0)[BlockHeaderSize:], incarnation1Data)
	h1.Unpin()
	bp.MarkDirty(1, 10)

	// 2. Hold flushMu so the flush pauses after setting InFlight = true and unlocking bp.mu
	bp.flushMu.Lock()
	flushMuLocked := true
	defer func() {
		if flushMuLocked {
			bp.flushMu.Unlock()
		}
	}()

	flushDone := make(chan error, 1)
	go func() {
		flushDone <- bp.FlushPage(1)
	}()

	// Wait until page 1 is in-flight
	for {
		bp.mu.Lock()
		d := bp.pageTable[1]
		inFlight := d != nil && d.InFlight
		bp.mu.Unlock()
		if inFlight {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// 3. Concurrently reuse page 1 via AllocateNewPage in a separate goroutine
	reuseDone := make(chan struct{})
	var h2 *PageHandle
	var allocErr error
	go func() {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k1", Payload: []byte("val2")})
		h2, allocErr = bp.AllocateNewPage(1, 1, 20)
		close(reuseDone)
	}()

	// Give AllocateNewPage a moment to run.
	// AllocateNewPage must NOT return while the flush is in flight.
	var returnedEarly bool
	select {
	case <-reuseDone:
		returnedEarly = true
	case <-time.After(50 * time.Millisecond):
		// Correct behavior: AllocateNewPage is waiting for flush to complete
	}

	// 4. Release flushMu to let flush complete
	flushMuLocked = false
	bp.flushMu.Unlock()

	if err := <-flushDone; err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}

	<-reuseDone
	if allocErr != nil {
		t.Fatalf("AllocateNewPage failed: %v", allocErr)
	}
	defer h2.Unpin()

	if returnedEarly {
		t.Fatalf("AllocateNewPage returned while flush was in flight; must block until in-flight flush completes")
	}

	// 5. Verify the block written by the flusher contains incarnation 1's data
	flushedLoc := h2.Desc.FlushedLoc
	if flushedLoc == NoBlock {
		t.Fatalf("expected page 1 to retain FlushedLoc after flush completed")
	}
	buf := make([]byte, BlockSize)
	if _, err := heapFile.ReadAt(buf, int64(flushedLoc*BlockSize)); err != nil {
		t.Fatalf("failed to read flushed block at %d: %v", flushedLoc, err)
	}
	gotData := buf[BlockHeaderSize : BlockHeaderSize+len(incarnation1Data)]
	if !bytes.Equal(gotData, incarnation1Data) {
		t.Fatalf("flushed block data mismatch: got %q, want %q", string(gotData), string(incarnation1Data))
	}
}

// TestBlockPool_ConcurrentReuseWhilePinned tests that AllocateNewPage blocks
// and does not tear down pool blocks while a page handle is actively pinned.
func TestBlockPool_ConcurrentReuseWhilePinned(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-reuse2--"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	defer bp.Close()

	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("val1")})
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	// Keep h1 pinned (PinCount = 1)

	reuseDone := make(chan struct{})
	var h2 *PageHandle
	var allocErr error
	go func() {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k1", Payload: []byte("val2")})
		h2, allocErr = bp.AllocateNewPage(1, 1, 20)
		close(reuseDone)
	}()

	select {
	case <-reuseDone:
		t.Fatalf("AllocateNewPage returned while page was pinned")
	case <-time.After(50 * time.Millisecond):
		// Correct behavior: waiting for unpin
	}

	h1.Unpin()

	<-reuseDone
	if allocErr != nil {
		t.Fatalf("AllocateNewPage failed: %v", allocErr)
	}
	h2.Unpin()
}

// TestBlockPool_UnpinStress stresses concurrent Unpin against a waiting AllocateNewPage
// across multiple concurrent pages to ensure no lost wakeups occur when PinCount drops to zero.
func TestBlockPool_UnpinStress(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-unpin---"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 32})
	defer bp.Close()

	const numWorkers = 4
	const iterations = 50

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			pageID := uint64(workerID + 1)
			for i := 0; i < iterations; i++ {
				lsn1 := uint64((workerID*iterations+i)*2 + 10)
				lsn2 := lsn1 + 1
				_ = wal.Append(Record{Type: RecordTypePut, LSN: lsn1, Key: "k", Payload: []byte("v1")})
				_ = wal.Append(Record{Type: RecordTypePut, LSN: lsn2, Key: "k", Payload: []byte("v2")})

				h1, err := bp.AllocateNewPage(pageID, 1, lsn1)
				if err != nil {
					t.Errorf("worker %d iter %d: AllocateNewPage h1 failed: %v", workerID, i, err)
					return
				}

				done := make(chan struct{})
				var h2 *PageHandle
				var allocErr error
				go func() {
					h2, allocErr = bp.AllocateNewPage(pageID, 1, lsn2)
					close(done)
				}()

				time.Sleep(time.Duration(i%5) * 50 * time.Microsecond)
				h1.Unpin()

				select {
				case <-done:
					if allocErr != nil {
						t.Errorf("worker %d iter %d: AllocateNewPage h2 failed: %v", workerID, i, allocErr)
						return
					}
					h2.Unpin()
				case <-time.After(2 * time.Second):
					t.Errorf("worker %d iter %d: lost wakeup: AllocateNewPage hung waiting for Unpin broadcast", workerID, i)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestBlockPool_ConcurrentReusePinnedDuringEvictionFlush tests that AllocateNewPage
// re-checks page idleness after acquirePoolBlocksLocked temporarily releases bp.mu to flush dirty pages.
func TestBlockPool_ConcurrentReusePinnedDuringEvictionFlush(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-evict---"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)
	// Block pool with exactly 2 pool blocks
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 2})
	defer bp.Close()

	// 1. Allocate page 1 (occupies pool block 0)
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("val1")})
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage page 1 failed: %v", err)
	}
	originalPage1Data := []byte("page-1-original-content")
	copy(h1.Block(0)[BlockHeaderSize:], originalPage1Data)
	h1.Unpin()
	bp.MarkDirty(1, 10)

	// 2. Allocate page 2 (occupies pool block 1). Pool is now full of dirty pages.
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 11, Key: "k2", Payload: []byte("val2")})
	h2, err := bp.AllocateNewPage(2, 1, 11)
	if err != nil {
		t.Fatalf("AllocateNewPage page 2 failed: %v", err)
	}
	copy(h2.Block(0)[BlockHeaderSize:], []byte("page-2-dirty-content"))
	h2.Unpin()
	bp.MarkDirty(2, 11)

	// 3. Set up hook on heap write: when acquirePoolBlocksLocked flushes a dirty page,
	// bp.mu is released during WriteAt. In that window, pin page 1.
	var h1Pinned *PageHandle
	pinDone := make(chan struct{})
	var pinOnce sync.Once

	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		pinOnce.Do(func() {
			// Pin page 1 while bp.mu is unlocked during flush
			var pinErr error
			h1Pinned, pinErr = bp.PinPage(1)
			if pinErr != nil {
				t.Errorf("PinPage(1) during eviction flush failed: %v", pinErr)
			}
			close(pinDone)
		})
	})

	// 4. Call AllocateNewPage for page 1 in a separate goroutine.
	// acquirePoolBlocksLocked will flush to free a pool block, triggering the hook which pins page 1.
	allocDone := make(chan struct{})
	var hNew *PageHandle
	var allocErr error
	go func() {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k1", Payload: []byte("val1-v2")})
		hNew, allocErr = bp.AllocateNewPage(1, 1, 20)
		close(allocDone)
	}()

	// Wait until the hook has pinned page 1
	select {
	case <-pinDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for eviction flush hook")
	}

	// AllocateNewPage must NOT return while page 1 is pinned by h1Pinned
	select {
	case <-allocDone:
		t.Fatalf("AllocateNewPage returned while old descriptor was pinned during eviction flush window")
	case <-time.After(50 * time.Millisecond):
		// Correct behavior: AllocateNewPage is waiting on bp.cond
	}

	// Verify pinned handle's content is intact and was not overwritten
	gotData := h1Pinned.Block(0)[BlockHeaderSize : BlockHeaderSize+len(originalPage1Data)]
	if !bytes.Equal(gotData, originalPage1Data) {
		t.Fatalf("pinned page 1 data was corrupted: got %q, want %q", string(gotData), string(originalPage1Data))
	}

	// 5. Release the pin on page 1
	h1Pinned.Unpin()

	// 6. AllocateNewPage must now wake up and succeed
	select {
	case <-allocDone:
		if allocErr != nil {
			t.Fatalf("AllocateNewPage failed: %v", allocErr)
		}
		defer hNew.Unpin()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for AllocateNewPage after unpin")
	}
}

type panickingDirectIO struct {
	DirectIO
}

func (p *panickingDirectIO) Write(f File, off int64, b []byte) error {
	panic("injected panic in direct I/O write")
}

func TestRegression_BlockPoolFlushPanicSafety(t *testing.T) {
	memFS := NewMemFS()
	rawHeapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap.db failed: %v", err)
	}
	defer rawHeapFile.Close()

	buddy := NewBuddyAllocator(512)
	var dbID [16]byte
	bp := NewBlockPool(rawHeapFile, nil, buddy, dbID, BlockPoolOptions{
		NumPoolBlocks: 16,
	})
	bp.directIO = &panickingDirectIO{}
	defer bp.Close()

	h, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	bp.MarkDirty(1, 10)
	h.Unpin()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic from panickingDirectIO")
		}
		if rStr := fmt.Sprint(r); rStr != "injected panic in direct I/O write" {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()

	_ = bp.FlushAllDirty()
}
