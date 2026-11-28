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
	"encoding/binary"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockPool_PinAndEviction(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00001"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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
	loc := h1.Desc.PhysicalBlock
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

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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

// TestBlockPool_InFlightWriteNotPromoted asserts that in-flight page writes do not cause
// superseded durable blocks to be released during a concurrent heap fsync.
func TestBlockPool_InFlightWriteNotPromoted(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	// Reuse rule assertion stays enabled
	faultFS.SetAssertReuseRule(true)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00003"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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

	// Flush and sync to establish initial durable location
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}
	bp.startHeapSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	bp.mu.Lock()
	desc := bp.pageTable[1]
	initialLoc := desc.PhysicalBlock
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

	// Heap sync runs while the write is in flight
	bp.startHeapSync()
	if err := heapFile.Sync(); err != nil {
		close(releaseWrite)
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		close(releaseWrite)
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	// Assert that initial location was NOT freed while write was in flight
	bp.mu.Lock()
	_, initialAllocated := bp.buddy.allocated[initialLoc]
	bp.mu.Unlock()
	if !initialAllocated {
		close(releaseWrite)
		t.Fatalf("initial location %d was prematurely freed while write was in flight!", initialLoc)
	}

	// Release in-flight write to complete
	close(releaseWrite)
	if err := <-flushErrCh; err != nil {
		t.Fatalf("FlushPage failed after unblocking write: %v", err)
	}

	bp.mu.Lock()
	newLoc := desc.PhysicalBlock
	bp.mu.Unlock()
	if newLoc == initialLoc {
		t.Fatalf("expected write to land on new location, still %d", newLoc)
	}

	// Next heap sync makes the new write durable and safely frees the superseded initial location
	bp.startHeapSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	bp.mu.Lock()
	_, initialAllocatedAfter := bp.buddy.allocated[initialLoc]
	bp.mu.Unlock()
	if initialAllocatedAfter {
		t.Fatalf("expected initial location %d to be freed after subsequent sync", initialLoc)
	}
}

func TestBlockPool_BatchedEviction(t *testing.T) {
	dir := t.TempDir()
	fs := NewOSFS()

	var dbID [16]byte
	copy(dbID[:], []byte("evict-batch-test"))

	wal, err := OpenWAL(fs, filepath.Join(dir, "wal"), dbID, 0, WALOptions{})
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
	bp.mu.Lock()
	loc1 := bp.pageTable[1].PhysicalBlock
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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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
	if len(h2.Desc.replacedBlocks) == 0 {
		t.Fatalf("expected page 1 to retain replaced block after flush completed")
	}
	flushedLoc := h2.Desc.replacedBlocks[0]
	if flushedLoc == NoBlock {
		t.Fatalf("expected page 1 to retain valid replaced block after flush completed")
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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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

type blockingDirectIO struct {
	base         DirectIO
	writeStarted chan struct{}
	releaseWrite chan struct{}
}

func (b *blockingDirectIO) Readv(file File, off int64, iov [][]byte) error {
	return b.base.Readv(file, off, iov)
}

func (b *blockingDirectIO) Writev(file File, off int64, iov [][]byte) error {
	return b.base.Writev(file, off, iov)
}

func (b *blockingDirectIO) Write(file File, off int64, buffer []byte) error {
	select {
	case b.writeStarted <- struct{}{}:
	default:
	}
	<-b.releaseWrite
	return b.base.Write(file, off, buffer)
}

func TestRegression_BlockPoolInFlightWait(t *testing.T) {
	memoryFS := NewMemFS()
	rawHeapFile, createErr := memoryFS.Create("heap.db")
	if createErr != nil {
		t.Fatalf("Create heap.db failed: %v", createErr)
	}
	defer rawHeapFile.Close()

	buddy := NewBuddyAllocator(512)
	var databaseID [16]byte
	bp := NewBlockPool(rawHeapFile, nil, buddy, databaseID, BlockPoolOptions{
		NumPoolBlocks: 2,
	})
	defer bp.Close()

	blockingIO := &blockingDirectIO{
		base:         bp.directIO,
		writeStarted: make(chan struct{}, 1),
		releaseWrite: make(chan struct{}),
	}
	bp.directIO = blockingIO

	// Fill pool with 2 dirty pages
	handle1, allocErr1 := bp.AllocateNewPage(1, 1, 10)
	if allocErr1 != nil {
		t.Fatalf("AllocateNewPage 1 failed: %v", allocErr1)
	}
	bp.MarkDirty(1, 10)
	handle1.Unpin()

	handle2, allocErr2 := bp.AllocateNewPage(2, 1, 10)
	if allocErr2 != nil {
		t.Fatalf("AllocateNewPage 2 failed: %v", allocErr2)
	}
	bp.MarkDirty(2, 10)
	handle2.Unpin()

	// Start a flush in the background. The flush will chunk the dirty pages and block in Write.
	flushDone := make(chan error, 1)
	go func() {
		flushDone <- bp.FlushAllDirty()
	}()

	// Wait until the flush is actively writing via direct I/O with all pool blocks in flight.
	<-blockingIO.writeStarted

	// Attempt to allocate while all pool blocks are in flight.
	allocStarted := make(chan struct{})
	allocDone := make(chan struct{})
	var handle3 *PageHandle
	var allocErr error
	go func() {
		close(allocStarted)
		handle3, allocErr = bp.AllocateNewPage(3, 1, 10)
		close(allocDone)
	}()
	<-allocStarted
	runtime.Gosched()

	// Verify the allocation has not returned while the flush is in flight.
	select {
	case <-allocDone:
		t.Fatalf("AllocateNewPage returned while flush was in flight: %v", allocErr)
	default:
	}

	// Release the direct I/O write and confirm the flush completes.
	close(blockingIO.releaseWrite)
	if flushErr := <-flushDone; flushErr != nil {
		t.Fatalf("FlushAllDirty failed: %v", flushErr)
	}

	// The allocation must now wake up and succeed.
	select {
	case <-allocDone:
		if allocErr != nil {
			t.Fatalf("AllocateNewPage failed: %v", allocErr)
		}
		defer handle3.Unpin()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for AllocateNewPage after flush completed")
	}
}

func TestBlockPool_DeferredFreeLists(t *testing.T) {
	isAllocated := func(b *BuddyAllocator, block uint64) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		_, exists := b.allocated[block]
		return exists
	}

	setup := func(t *testing.T) (*BlockPool, *BuddyAllocator) {
		t.Helper()
		memFS := NewMemFS()
		heapFile, err := memFS.Create("heap.db")
		if err != nil {
			t.Fatalf("Create heap file failed: %v", err)
		}
		t.Cleanup(func() { _ = heapFile.Close() })

		buddy := NewBuddyAllocator(512)
		var dbID [16]byte
		bp := NewBlockPool(heapFile, nil, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 4})
		t.Cleanup(func() { _ = bp.Close() })
		return bp, buddy
	}

	deferBlockThroughReplacement := func(t *testing.T, bp *BlockPool, pageID uint64) uint64 {
		h, err := bp.AllocateNewPage(pageID, 1, 10)
		if err != nil {
			t.Fatalf("AllocateNewPage failed: %v", err)
		}
		copy(h.Block(0)[BlockHeaderSize:], []byte("v1"))
		h.Unpin()
		if err := bp.FlushPage(pageID); err != nil {
			t.Fatalf("first FlushPage failed: %v", err)
		}
		bp.mu.Lock()
		origBlock := bp.pageTable[pageID].PhysicalBlock
		bp.mu.Unlock()

		bp.MarkDirty(pageID, 20)
		if err := bp.FlushPage(pageID); err != nil {
			t.Fatalf("replacement FlushPage failed: %v", err)
		}
		return origBlock
	}

	t.Run("unneeded before fsync starts is freed when that fsync succeeds", func(t *testing.T) {
		bp, buddy := setup(t)

		r1 := deferBlockThroughReplacement(t, bp, 1)
		if !isAllocated(buddy, r1) {
			t.Fatalf("expected block %d to be allocated", r1)
		}

		// Fsync starts: unsynced rotates to syncing
		bp.startHeapSync()

		// Run is still not freed
		if !isAllocated(buddy, r1) {
			t.Fatalf("run %d was freed prematurely before fsync succeeded", r1)
		}

		// Fsync succeeds: syncing is freed
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}

		// Run must now be freed
		if isAllocated(buddy, r1) {
			t.Fatalf("run %d should be freed after fsync succeeded", r1)
		}

		// Verify syncing and unsynced are empty
		bp.mu.Lock()
		syncingLen, unsyncedLen := len(bp.deferredFreesSyncing), len(bp.deferredFreesUnsynced)
		bp.mu.Unlock()
		if syncingLen != 0 || unsyncedLen != 0 {
			t.Fatalf("expected syncing=0, unsynced=0, got syncing=%d, unsynced=%d", syncingLen, unsyncedLen)
		}
	})

	t.Run("unneeded while fsync runs is not freed by that fsync and is freed by the next", func(t *testing.T) {
		bp, buddy := setup(t)

		r1 := deferBlockThroughReplacement(t, bp, 1)

		// Fsync 1 starts: r1 moves to syncing, unsynced is empty
		bp.startHeapSync()

		// Defer r2 while fsync 1 is running: r2 appends to unsynced
		r2 := deferBlockThroughReplacement(t, bp, 2)

		// Fsync 1 succeeds: r1 is freed, r2 is not
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}

		if isAllocated(buddy, r1) {
			t.Fatalf("r1 %d should be freed by fsync 1", r1)
		}
		if !isAllocated(buddy, r2) {
			t.Fatalf("r2 %d was freed prematurely by fsync 1", r2)
		}

		// Fsync 2 starts: r2 moves to syncing
		bp.startHeapSync()

		// Fsync 2 succeeds: r2 is freed
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}

		if isAllocated(buddy, r2) {
			t.Fatalf("r2 %d should be freed by fsync 2", r2)
		}
	})

	t.Run("failed fsync frees nothing and next successful fsync frees both generations", func(t *testing.T) {
		bp, buddy := setup(t)

		r1 := deferBlockThroughReplacement(t, bp, 1)

		// Fsync 1 starts: r1 moves to syncing
		bp.startHeapSync()

		// Defer r2 while fsync 1 is running: r2 appends to unsynced
		r2 := deferBlockThroughReplacement(t, bp, 2)

		// Fsync 1 fails: release nothing
		bp.heapSyncFailed()

		// Neither r1 nor r2 is freed
		if !isAllocated(buddy, r1) {
			t.Fatalf("r1 %d was freed despite fsync 1 failure", r1)
		}
		if !isAllocated(buddy, r2) {
			t.Fatalf("r2 %d was freed despite fsync 1 failure", r2)
		}

		// Fsync 2 starts: syncing keeps r1, unsynced (r2) is appended to syncing
		bp.startHeapSync()

		// Fsync 2 succeeds: both r1 and r2 are freed
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}

		if isAllocated(buddy, r1) {
			t.Fatalf("r1 %d should be freed after fsync 2 succeeded", r1)
		}
		if isAllocated(buddy, r2) {
			t.Fatalf("r2 %d should be freed after fsync 2 succeeded", r2)
		}
	})

	t.Run("each run is freed once", func(t *testing.T) {
		bp, buddy := setup(t)

		r1 := deferBlockThroughReplacement(t, bp, 1)
		bp.startHeapSync()
		r2 := deferBlockThroughReplacement(t, bp, 2)
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}
		if isAllocated(buddy, r1) {
			t.Fatalf("r1 %d should be freed after first fsync", r1)
		}
		if !isAllocated(buddy, r2) {
			t.Fatalf("r2 %d should remain allocated before its fsync", r2)
		}

		// Subsequent fsync frees r2:
		bp.startHeapSync()
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded on second fsync failed: %v", err)
		}
		if isAllocated(buddy, r2) {
			t.Fatalf("r2 %d should be freed after second fsync", r2)
		}

		// Next cycle with a third run:
		r3 := deferBlockThroughReplacement(t, bp, 3)
		bp.startHeapSync()
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded failed: %v", err)
		}
		if isAllocated(buddy, r3) {
			t.Fatalf("r3 %d should be freed after third fsync", r3)
		}

		// Once more verify no leftover runs or double frees
		bp.startHeapSync()
		if err := bp.heapSyncSucceeded(); err != nil {
			t.Fatalf("heapSyncSucceeded on empty lists failed (possible double free): %v", err)
		}
	})
}

func TestBlockPool_PageFlushedTwiceBeforeFsyncKeepsFirstRedoLSN(t *testing.T) {
	memFS := NewMemFS()
	heapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer func() {
		if err := heapFile.Close(); err != nil {
			t.Errorf("heapFile.Close failed: %v", err)
		}
	}()

	var dbID [16]byte
	copy(dbID[:], []byte("redo-lsn-test-01"))

	wal, err := OpenWAL(memFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer func() {
		if err := wal.Close(); err != nil {
			t.Errorf("wal.Close failed: %v", err)
		}
	}()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 8})
	defer func() {
		if err := bp.Close(); err != nil {
			t.Errorf("bp.Close failed: %v", err)
		}
	}()

	// 1. First modification at LSN 10
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k", Payload: []byte("v1")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	copy(h1.Block(0)[BlockHeaderSize:], []byte("v1-content"))
	h1.Unpin()

	desc := bp.pageTable[1]
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 after first modification, got %d", desc.RedoLSN)
	}
	if !desc.Dirty {
		t.Fatalf("expected page 1 to be dirty")
	}

	// 2. First flush of page 1
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("first FlushPage failed: %v", err)
	}
	if desc.Dirty {
		t.Fatalf("expected page 1 Dirty to clear after first flush")
	}
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 to be kept across first flush, got %d", desc.RedoLSN)
	}

	// 3. Second modification at LSN 20 before any fsync
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k", Payload: []byte("v2")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}
	h1Again, err := bp.PinPage(1)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	copy(h1Again.Block(0)[BlockHeaderSize:], []byte("v2-content"))
	h1Again.Unpin()
	bp.MarkDirty(1, 20)

	if !desc.Dirty {
		t.Fatalf("expected page 1 to be dirty after second modification")
	}
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 to remain unchanged after second modification, got %d", desc.RedoLSN)
	}

	// 4. Second flush of page 1 before any fsync
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("second FlushPage failed: %v", err)
	}
	if desc.Dirty {
		t.Fatalf("expected page 1 Dirty to clear after second flush")
	}
	// Acceptance criterion: A test that a page flushed twice before any fsync keeps its first RedoLSN.
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 after second flush before fsync, got %d", desc.RedoLSN)
	}

	// 5. Heap fsync occurs and succeeds
	bp.startHeapSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	// 6. After fsync covering both flushes, RedoLSN clears to 0
	if desc.RedoLSN != 0 {
		t.Fatalf("expected RedoLSN=0 after heap sync covering second flush, got %d", desc.RedoLSN)
	}
}

func TestBlockPool_FsyncSucceedsWhileLaterFlushInFlight(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer func() {
		if err := heapFile.Close(); err != nil {
			t.Errorf("heapFile.Close failed: %v", err)
		}
	}()

	var dbID [16]byte
	copy(dbID[:], []byte("redo-inflight-01"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer func() {
		if err := wal.Close(); err != nil {
			t.Errorf("wal.Close failed: %v", err)
		}
	}()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 8})
	defer func() {
		if err := bp.Close(); err != nil {
			t.Errorf("bp.Close failed: %v", err)
		}
	}()

	// 1. Initial modification at LSN 10
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k", Payload: []byte("v1")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	copy(h1.Block(0)[BlockHeaderSize:], []byte("v1-content"))
	h1.Unpin()

	desc := bp.pageTable[1]
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 after first modification, got %d", desc.RedoLSN)
	}

	// 2. Flush page 1 at LSN 10
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("first FlushPage failed: %v", err)
	}
	if desc.Dirty {
		t.Fatalf("expected Dirty to clear after first flush")
	}
	if desc.RedoLSN != 10 {
		t.Fatalf("expected RedoLSN=10 kept across first flush, got %d", desc.RedoLSN)
	}

	// 3. Start a heap fsync (rotates flush of LSN 10 into flushedPagesSyncing)
	bp.startHeapSync()

	// 4. Change page at LSN 20
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k", Payload: []byte("v2")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}
	h1Again, err := bp.PinPage(1)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	copy(h1Again.Block(0)[BlockHeaderSize:], []byte("v2-content"))
	h1Again.Unpin()
	bp.MarkDirty(1, 20)

	// 5. Start a second flush and hold its write in the fault filesystem hook
	secondFlushStarted := make(chan struct{})
	allowSecondFlush := make(chan struct{})
	secondFlushDone := make(chan struct{})
	var secondFlushErr error

	var once sync.Once
	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		if filepath.Base(path) == "heap.db" {
			once.Do(func() {
				close(secondFlushStarted)
				<-allowSecondFlush
			})
		}
	})

	go func() {
		secondFlushErr = bp.FlushPage(1)
		close(secondFlushDone)
	}()

	<-secondFlushStarted

	// Verify the second flush is in flight and covers LSN 20
	bp.mu.Lock()
	if !desc.InFlight || desc.flushingFirstLSN != 20 {
		bp.mu.Unlock()
		t.Fatalf("expected InFlight=true and flushingFirstLSN=20, got InFlight=%v, flushingFirstLSN=%d",
			desc.InFlight, desc.flushingFirstLSN)
	}
	bp.mu.Unlock()

	// 6. Change the page at LSN 30 while the second flush is in flight
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 30, Key: "k", Payload: []byte("v3")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}
	bp.MarkDirty(1, 30)

	bp.mu.Lock()
	if desc.DirtyLSN != 30 {
		bp.mu.Unlock()
		t.Fatalf("expected DirtyLSN=30 for change during in-flight flush, got %d", desc.DirtyLSN)
	}
	bp.mu.Unlock()

	// 7. The fsync succeeds while the second flush is still in flight
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	// 8. Verify RedoLSN is 20 (from flushingFirstLSN), NOT 30 (DirtyLSN)
	bp.mu.Lock()
	if desc.RedoLSN != 20 {
		bp.mu.Unlock()
		t.Fatalf("expected RedoLSN=20 (in-flight flush's first LSN), got %d", desc.RedoLSN)
	}
	bp.mu.Unlock()

	// 9. Verify DirtyPageTableAndLSN reports 20 for the page
	dpt, _ := bp.DirtyPageTableAndLSN()
	if dpt[1] != 20 {
		t.Fatalf("expected DirtyPageTableAndLSN to report 20, got %d", dpt[1])
	}

	// 10. Complete the in-flight flush
	close(allowSecondFlush)
	<-secondFlushDone
	if secondFlushErr != nil {
		t.Fatalf("second FlushPage failed: %v", secondFlushErr)
	}

	bp.mu.Lock()
	if desc.RedoLSN != 20 {
		bp.mu.Unlock()
		t.Fatalf("expected RedoLSN=20 after in-flight flush completes, got %d", desc.RedoLSN)
	}
	bp.mu.Unlock()

	// 11. Next fsync succeeds, advancing RedoLSN to 30 (since change 30 arrived while flush 2 was in flight)
	bp.startHeapSync()
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}

	bp.mu.Lock()
	if desc.RedoLSN != 30 {
		bp.mu.Unlock()
		t.Fatalf("expected RedoLSN=30 after second fsync, got %d", desc.RedoLSN)
	}
	bp.mu.Unlock()
}

// TestBlockPool_DeferredFrees_NoRunDeferredOrFreedTwice asserts that no run is deferred or freed twice.
func TestBlockPool_DeferredFrees_NoRunDeferredOrFreedTwice(t *testing.T) {
	memFS := NewMemFS()
	heapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	var dbID [16]byte
	copy(dbID[:], []byte("no-double-list01"))
	wal, err := OpenWAL(memFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	defer bp.Close()

	assertNoDuplicates := func() {
		t.Helper()
		bp.mu.Lock()
		defer bp.mu.Unlock()
		seen := make(map[uint64]bool)
		for _, blockRun := range bp.deferredFreesUnsynced {
			if seen[blockRun.block] {
				t.Fatalf("block %d deferred more than once in unsynced", blockRun.block)
			}
			seen[blockRun.block] = true
		}
		for _, blockRun := range bp.deferredFreesSyncing {
			if seen[blockRun.block] {
				t.Fatalf("block %d deferred more than once across syncing and unsynced", blockRun.block)
			}
			seen[blockRun.block] = true
		}
	}

	// 1. Allocate and flush page 1
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k", Payload: []byte("val1")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	h1, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	copy(h1.Block(0)[BlockHeaderSize:], []byte("data-1"))
	h1.Unpin()

	// Flush 1: brand new page, no prior block superseded
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}
	bp.mu.Lock()
	loc1 := bp.pageTable[1].PhysicalBlock
	bp.mu.Unlock()
	assertNoDuplicates()

	// Make loc1 durable
	bp.startHeapSync()
	assertNoDuplicates()
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}
	assertNoDuplicates()

	// 2. Reallocate page 1 via AllocateNewPage (carries loc1 forward in replacedBlocks)
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k", Payload: []byte("val2")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	h2, err := bp.AllocateNewPage(1, 1, 20)
	if err != nil {
		t.Fatalf("AllocateNewPage realloc failed: %v", err)
	}
	copy(h2.Block(0)[BlockHeaderSize:], []byte("data-2"))
	h2.Unpin()

	// Before flush of new contents, loc1 must NOT yet be deferred
	bp.mu.Lock()
	for _, blockRun := range bp.deferredFreesUnsynced {
		if blockRun.block == loc1 {
			bp.mu.Unlock()
			t.Fatalf("loc1 %d deferred before replacement flush completed", loc1)
		}
	}
	bp.mu.Unlock()
	assertNoDuplicates()

	// 3. Flush replacement contents: loc1 must now be deferred exactly once
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage replacement failed: %v", err)
	}
	bp.mu.Lock()
	loc2 := bp.pageTable[1].PhysicalBlock
	count := 0
	for _, blockRun := range bp.deferredFreesUnsynced {
		if blockRun.block == loc1 {
			count++
		}
	}
	bp.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected loc1 %d to be deferred exactly once, found %d times", loc1, count)
	}
	assertNoDuplicates()

	// 4. Second flush of same incarnation to loc3: loc2 must be deferred exactly once, loc1 must still appear once
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 30, Key: "k", Payload: []byte("val3")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	bp.MarkDirty(1, 30)
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("second FlushPage failed: %v", err)
	}
	bp.mu.Lock()
	loc1Count := 0
	loc2Count := 0
	for _, blockRun := range bp.deferredFreesUnsynced {
		if blockRun.block == loc1 {
			loc1Count++
		}
		if blockRun.block == loc2 {
			loc2Count++
		}
	}
	bp.mu.Unlock()
	if loc1Count != 1 {
		t.Fatalf("expected loc1 %d to be deferred exactly once, found %d times", loc1, loc1Count)
	}
	if loc2Count != 1 {
		t.Fatalf("expected loc2 %d to be deferred exactly once, found %d times", loc2, loc2Count)
	}
	assertNoDuplicates()

	// 5. Sync releases loc1 and loc2 safely
	bp.startHeapSync()
	assertNoDuplicates()
	if err := bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded freeing loc1 and loc2 failed: %v", err)
	}
	assertNoDuplicates()
}

// TestBlockPool_ConcurrentPinPageDuringEvictionFlush checks that concurrent PinPage
// reloads of evicted pages stay race-free and consistent while eviction flushes
// release bp.mu and one goroutine replaces pages with AllocateNewPage.
func TestBlockPool_ConcurrentPinPageDuringEvictionFlush(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], "bp-pin-race-0001")
	wal, err := OpenWAL(memFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()
	heapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	const (
		numPages         = 12
		numReaders       = 4
		poolBlocks       = numReaders + 2
		writerIterations = 150
		payloadBytes     = 64
	)
	bp := NewBlockPool(heapFile, wal, NewBuddyAllocator(1024), dbID, BlockPoolOptions{NumPoolBlocks: poolBlocks})
	defer bp.Close()

	var zeroPayload [payloadBytes]byte
	buildPayload := func(pageID, lsn uint64) [payloadBytes]byte {
		var payload [payloadBytes]byte
		binary.BigEndian.PutUint64(payload[0:8], pageID)
		binary.BigEndian.PutUint64(payload[8:16], lsn)
		fill := byte(pageID ^ lsn)
		for i := 16; i < payloadBytes; i++ {
			payload[i] = fill + byte(i)
		}
		return payload
	}

	var nextLSN uint64
	allocateAndWrite := func(pageID uint64) error {
		nextLSN++
		lsn := nextLSN
		if err := wal.Append(Record{Type: RecordTypePut, LSN: lsn, Key: fmt.Sprintf("p%d", pageID), Payload: []byte("v")}); err != nil {
			return fmt.Errorf("wal.Append(%d, %d): %w", pageID, lsn, err)
		}
		handle, err := bp.AllocateNewPage(pageID, 1, lsn)
		if err != nil {
			return fmt.Errorf("AllocateNewPage(%d, %d): %w", pageID, lsn, err)
		}
		payload := buildPayload(pageID, lsn)
		handle.Desc.Mu.Lock()
		copy(handle.Block(0)[BlockHeaderSize:BlockHeaderSize+payloadBytes], payload[:])
		handle.Desc.Mu.Unlock()
		handle.Unpin()
		return nil
	}

	// Populate all pages so earlier pages flush and evict before the concurrent phase starts.
	for pageID := uint64(1); pageID <= numPages; pageID++ {
		if err := allocateAndWrite(pageID); err != nil {
			t.Fatalf("initial setup failed: %v", err)
		}
	}

	var writerDone atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer writerDone.Store(true)
		for i := 0; i < writerIterations; i++ {
			if err := allocateAndWrite(uint64((i % numPages) + 1)); err != nil {
				t.Errorf("writer iteration %d failed: %v", i, err)
				return
			}
		}
	}()

	for readerID := 0; readerID < numReaders; readerID++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; !writerDone.Load() || i < numPages*2; i++ {
				pageID := uint64((i % numPages) + 1)
				handle, err := bp.PinPage(pageID)
				if err != nil {
					t.Errorf("reader %d: PinPage(%d) failed: %v", readerID, pageID, err)
					return
				}
				handle.Desc.Mu.RLock()
				blocks := handle.Blocks()
				descriptorLSN := handle.Desc.PageLSN.Load()
				if len(blocks) != 1 {
					t.Errorf("reader %d: PinPage(%d) returned %d blocks, want 1", readerID, pageID, len(blocks))
				} else {
					block := blocks[0]
					headerPageID := binary.BigEndian.Uint64(block[8:16])
					headerLSN := binary.BigEndian.Uint64(block[16:24])
					payload := block[BlockHeaderSize : BlockHeaderSize+payloadBytes]
					expected := buildPayload(pageID, headerLSN)
					if headerPageID != pageID || headerLSN != descriptorLSN {
						t.Errorf("reader %d: page %d header mismatch: page=%d lsn=%d descriptorLSN=%d",
							readerID, pageID, headerPageID, headerLSN, descriptorLSN)
					} else if !bytes.Equal(payload, expected[:]) && !bytes.Equal(payload, zeroPayload[:]) {
						// AllocateNewPage publishes cleared blocks before the writer locks Desc.Mu.
						t.Errorf("reader %d: page %d lsn %d payload mismatch", readerID, pageID, headerLSN)
					}
				}
				handle.Desc.Mu.RUnlock()
				handle.Unpin()
			}
		}(readerID)
	}

	wg.Wait()

	bp.mu.Lock()
	defer bp.mu.Unlock()
	totalAccounted := len(bp.freePoolBlocks)
	for pageID, descriptor := range bp.pageTable {
		if pins := descriptor.PinCount.Load(); pins != 0 {
			t.Fatalf("page %d has PinCount=%d after all handles unpinned, want 0", pageID, pins)
		}
		totalAccounted += len(descriptor.PoolBlocks)
	}
	if totalAccounted != poolBlocks {
		t.Fatalf("pool block accounting mismatch: free+inMemory=%d, want %d", totalAccounted, poolBlocks)
	}
}

func TestBlockPool_FlushAllDirtySkipsPinnedNewPageAndKeepsRedoLSN(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], "bp-skip-pin-0001")

	wal, err := OpenWAL(memFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	bp := NewBlockPool(heapFile, wal, NewBuddyAllocator(512), dbID, BlockPoolOptions{NumPoolBlocks: 8})
	defer bp.Close()

	if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k1", Payload: []byte("v1")}); err != nil {
		t.Fatalf("wal.Append failed: %v", err)
	}

	// Allocate page 1 and keep it pinned before filling it or calling MarkDirty.
	handle, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	if err := bp.FlushAllDirty(); err != nil {
		t.Fatalf("FlushAllDirty while pinned failed: %v", err)
	}

	sizeBeforeMarkDirty, err := heapFile.Size()
	if err != nil {
		t.Fatalf("heapFile.Size failed: %v", err)
	}
	if sizeBeforeMarkDirty != 0 {
		t.Fatalf("FlushAllDirty wrote %d bytes to heap.db while newly allocated page was pinned", sizeBeforeMarkDirty)
	}
	dirtyPageTable, _ := bp.DirtyPageTableAndLSN()
	if dirtyPageTable[1] != 10 {
		t.Fatalf("DirtyPageTable[1] = %d, want 10 so checkpoint holds back redo start", dirtyPageTable[1])
	}

	// Fill the page, call MarkDirty with the same LSN, unpin, and flush.
	payload := []byte("filled-record")
	handle.Desc.Mu.Lock()
	copy(handle.Block(0)[BlockHeaderSize:], payload)
	handle.Desc.Mu.Unlock()
	bp.MarkDirty(1, 10)
	handle.Unpin()

	if err := bp.FlushAllDirty(); err != nil {
		t.Fatalf("FlushAllDirty after unpin failed: %v", err)
	}
	sizeAfterFlush, err := heapFile.Size()
	if err != nil {
		t.Fatalf("heapFile.Size failed: %v", err)
	}
	if sizeAfterFlush != BlockSize {
		t.Fatalf("heap.db size after first flush = %d, want %d", sizeAfterFlush, BlockSize)
	}

	blockBytes := make([]byte, BlockSize)
	if _, err := heapFile.ReadAt(blockBytes, 0); err != nil {
		t.Fatalf("heapFile.ReadAt failed: %v", err)
	}
	header, err := DecodeBlockHeader(blockBytes)
	if err != nil {
		t.Fatalf("DecodeBlockHeader failed: %v", err)
	}
	if header.LogicalPage != 1 || header.LSN != 10 {
		t.Fatalf("flushed header = (page %d, LSN %d), want (page 1, LSN 10)", header.LogicalPage, header.LSN)
	}
	if !bytes.HasPrefix(blockBytes[BlockHeaderSize:], payload) {
		t.Fatalf("flushed block does not contain written payload")
	}

	if err := bp.FlushAllDirty(); err != nil {
		t.Fatalf("second FlushAllDirty failed: %v", err)
	}
	sizeAfterSecondFlush, err := heapFile.Size()
	if err != nil {
		t.Fatalf("heapFile.Size failed: %v", err)
	}
	if sizeAfterSecondFlush != sizeAfterFlush {
		t.Fatalf("second FlushAllDirty wrote extra bytes: size=%d, want %d", sizeAfterSecondFlush, sizeAfterFlush)
	}
}

func TestBlockPool_ConcurrentAllocateAndFlushAllDirty(t *testing.T) {
	memFS := NewMemFS()
	storeDir := "concurrent_alloc_flush"

	store, err := Open(
		WithFS(memFS),
		WithDir(storeDir),
		WithCreate(),
		WithCompressionCodec(CodecNone),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	type testRecord struct {
		key     string
		payload []byte
	}
	const numRecords = 2000
	records := make([]testRecord, numRecords)
	for i := 0; i < numRecords; i++ {
		payloadSize := 5000
		if i%4 == 0 {
			payloadSize = 2000
		}
		records[i] = testRecord{
			key:     fmt.Sprintf("key-%04d", i),
			payload: bytes.Repeat([]byte{byte('a' + (i % 26))}, payloadSize),
		}
	}

	var writerDone atomic.Bool
	var flusherErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !writerDone.Load() {
			if err := store.bp.FlushAllDirty(); err != nil {
				flusherErr = err
				return
			}
		}
	}()

	for _, record := range records {
		if err := store.Put("table", record.key, record.payload); err != nil {
			writerDone.Store(true)
			wg.Wait()
			t.Fatalf("Put %s failed: %v", record.key, err)
		}
	}
	writerDone.Store(true)
	wg.Wait()
	if flusherErr != nil {
		t.Fatalf("FlushAllDirty failed: %v", flusherErr)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Scan the durable heap file to confirm no two durable copies share a (LogicalPage, LSN).
	heapFile, err := memFS.Open(filepath.Join(storeDir, "heap.db"))
	if err != nil {
		t.Fatalf("Open heap.db failed: %v", err)
	}
	defer heapFile.Close()
	heapSize, err := heapFile.Size()
	if err != nil {
		t.Fatalf("Size heap.db failed: %v", err)
	}
	heapBytes := make([]byte, heapSize)
	if _, err := heapFile.ReadAt(heapBytes, 0); err != nil {
		t.Fatalf("ReadAt heap.db failed: %v", err)
	}
	type pageLSNKey struct {
		logicalPage uint64
		lsn         uint64
	}
	durableCopies := make(map[pageLSNKey]uint64)
	for blockIndex := uint64(0); int((blockIndex+1)*BlockSize) <= len(heapBytes); blockIndex++ {
		start := int(blockIndex) * BlockSize
		header, decodeErr := DecodeBlockHeader(heapBytes[start : start+BlockSize])
		if decodeErr != nil || header.BlockIndex != 0 {
			continue
		}
		key := pageLSNKey{logicalPage: header.LogicalPage, lsn: header.LSN}
		if previousBlock, exists := durableCopies[key]; exists {
			t.Fatalf("durable heap holds two copies of page %d at LSN %d: blocks %d and %d",
				header.LogicalPage, header.LSN, previousBlock, blockIndex)
		}
		durableCopies[key] = blockIndex
	}

	reopened, err := Open(WithFS(memFS), WithDir(storeDir))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()
	for _, record := range records {
		got, found, err := reopened.Get("table", record.key)
		if err != nil || !found || !bytes.Equal(got, record.payload) {
			t.Fatalf("Get %s after reopen: found=%v len=%d wantLen=%d err=%v",
				record.key, found, len(got), len(record.payload), err)
		}
	}
}

func decodePageLSNs(data []byte) map[uint64][]uint64 {
	written := make(map[uint64][]uint64)
	for offset := 0; offset+BlockSize <= len(data); offset += BlockSize {
		header, err := DecodeBlockHeader(data[offset : offset+BlockSize])
		if err != nil || header.BlockIndex != 0 {
			continue
		}
		written[header.LogicalPage] = append(written[header.LogicalPage], header.LSN)
	}
	return written
}

func readHeapPageLSNs(t *testing.T, heapFile File) map[uint64][]uint64 {
	t.Helper()
	heapSize, err := heapFile.Size()
	if err != nil {
		t.Fatalf("heapFile.Size failed: %v", err)
	}
	heapBytes := make([]byte, heapSize)
	if heapSize > 0 {
		if _, err := heapFile.ReadAt(heapBytes, 0); err != nil {
			t.Fatalf("heapFile.ReadAt failed: %v", err)
		}
	}
	return decodePageLSNs(heapBytes)
}

func startHeldMultiChunkFlush(t *testing.T, totalPages, blocksPerPage, extraPoolBlocks int) (File, *WAL, *BlockPool, uint64, func() error) {
	t.Helper()
	faultFS := NewFaultFS(NewMemFS())
	var dbID [16]byte
	copy(dbID[:], "bp-chunk-recheck")

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	t.Cleanup(func() {
		if err := wal.Close(); err != nil {
			t.Errorf("wal.Close failed: %v", err)
		}
	})

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	t.Cleanup(func() {
		if err := heapFile.Close(); err != nil {
			t.Errorf("heapFile.Close failed: %v", err)
		}
	})

	pool := NewBlockPool(heapFile, wal, NewBuddyAllocator(1024), dbID, BlockPoolOptions{
		NumPoolBlocks: totalPages*blocksPerPage + extraPoolBlocks,
	})
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("pool.Close failed: %v", err)
		}
	})

	for pageID := uint64(1); pageID <= uint64(totalPages); pageID++ {
		lsn := pageID * 10
		if err := wal.Append(Record{Type: RecordTypePut, LSN: lsn, Key: fmt.Sprintf("k%d", pageID), Payload: []byte("v")}); err != nil {
			t.Fatalf("wal.Append page %d failed: %v", pageID, err)
		}
		handle, err := pool.AllocateNewPage(pageID, blocksPerPage, lsn)
		if err != nil {
			t.Fatalf("AllocateNewPage %d failed: %v", pageID, err)
		}
		handle.Unpin()
	}

	firstChunkStarted := make(chan map[uint64][]uint64, 1)
	releaseFirstChunk := make(chan struct{})
	var holdOnce sync.Once
	faultFS.SetBeforeWriteAt(func(path string, payload []byte, _ int64) {
		if filepath.Base(path) != "heap.db" {
			return
		}
		holdOnce.Do(func() {
			firstChunkStarted <- decodePageLSNs(payload)
			<-releaseFirstChunk
		})
	})

	flushDone := make(chan error, 1)
	go func() {
		flushDone <- pool.FlushAllDirty()
	}()

	var releaseOnce sync.Once
	finishFlush := func() error {
		releaseOnce.Do(func() { close(releaseFirstChunk) })
		return <-flushDone
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseFirstChunk)
			<-flushDone
		})
	})

	firstChunkPages := <-firstChunkStarted
	for pageID := uint64(1); pageID <= uint64(totalPages); pageID++ {
		if len(firstChunkPages[pageID]) == 0 {
			return heapFile, wal, pool, pageID, finishFlush
		}
	}
	t.Fatalf("expected at least one page outside the first chunk (got %d pages)", len(firstChunkPages))
	return nil, nil, nil, 0, nil
}

func TestBlockPool_FlushBatchSkipsPagePinnedBetweenChunks(t *testing.T) {
	// Six 128-block pages total 768 blocks (> MaxBatchBlocks = 512), so
	// FlushAllDirty writes four pages in the first chunk and two in the second.
	const (
		totalPages    = 6
		blocksPerPage = 128
	)
	heapFile, _, pool, pinnedPage, finishFlush := startHeldMultiChunkFlush(t, totalPages, blocksPerPage, 0)

	pinnedHandle, err := pool.PinPage(pinnedPage)
	if err != nil {
		t.Fatalf("PinPage(%d) failed: %v", pinnedPage, err)
	}
	var unpinOnce sync.Once
	unpin := func() { unpinOnce.Do(pinnedHandle.Unpin) }
	defer unpin()

	if err := finishFlush(); err != nil {
		t.Fatalf("FlushAllDirty failed: %v", err)
	}

	written := readHeapPageLSNs(t, heapFile)
	if len(written[pinnedPage]) != 0 {
		t.Fatalf("FlushAllDirty wrote pinned later-chunk page %d to heap.db (LSNs %v)", pinnedPage, written[pinnedPage])
	}
	for pageID := uint64(1); pageID <= totalPages; pageID++ {
		if pageID == pinnedPage {
			continue
		}
		if len(written[pageID]) != 1 || written[pageID][0] != pageID*10 {
			t.Fatalf("page %d written LSNs = %v, want [%d]", pageID, written[pageID], pageID*10)
		}
	}

	dirtyPageTable, _ := pool.DirtyPageTableAndLSN()
	if dirtyPageTable[pinnedPage] != pinnedPage*10 {
		t.Fatalf("DirtyPageTable[%d] = %d, want %d", pinnedPage, dirtyPageTable[pinnedPage], pinnedPage*10)
	}

	// Unpinning the page lets the next FlushAllDirty write it.
	unpin()
	if err := pool.FlushAllDirty(); err != nil {
		t.Fatalf("second FlushAllDirty failed: %v", err)
	}
	writtenAfterUnpin := readHeapPageLSNs(t, heapFile)
	if len(writtenAfterUnpin[pinnedPage]) != 1 || writtenAfterUnpin[pinnedPage][0] != pinnedPage*10 {
		t.Fatalf("page %d written LSNs after unpin = %v, want [%d]", pinnedPage, writtenAfterUnpin[pinnedPage], pinnedPage*10)
	}
}

func TestBlockPool_FlushBatchSkipsPageReplacedBetweenChunks(t *testing.T) {
	const (
		totalPages     = 6
		blocksPerPage  = 128
		replacementLSN = uint64(1000)
	)
	// Leave spare pool blocks so AllocateNewPage does not evict while chunk 1 is held.
	heapFile, wal, pool, replacedPage, finishFlush := startHeldMultiChunkFlush(t, totalPages, blocksPerPage, blocksPerPage)
	if err := wal.Append(Record{Type: RecordTypePut, LSN: replacementLSN, Key: "replaced", Payload: []byte("v2")}); err != nil {
		t.Fatalf("wal.Append replacement failed: %v", err)
	}

	// Replace the later-chunk page while chunk 1 is in flight, then unpin the
	// replacement so only the stale descriptor lacks pool blocks.
	replacementHandle, err := pool.AllocateNewPage(replacedPage, blocksPerPage, replacementLSN)
	if err != nil {
		t.Fatalf("AllocateNewPage replacement for %d failed: %v", replacedPage, err)
	}
	replacementHandle.Unpin()

	if err := finishFlush(); err != nil {
		t.Fatalf("FlushAllDirty failed: %v", err)
	}

	heapSize, err := heapFile.Size()
	if err != nil {
		t.Fatalf("heapFile.Size failed: %v", err)
	}
	wantSize := int64((totalPages - 1) * blocksPerPage * BlockSize)
	if heapSize != wantSize {
		t.Fatalf("heap.db size = %d, want %d (replaced page must not be written)", heapSize, wantSize)
	}
	if written := readHeapPageLSNs(t, heapFile); len(written[replacedPage]) != 0 {
		t.Fatalf("FlushAllDirty wrote replaced page %d to heap.db (LSNs %v)", replacedPage, written[replacedPage])
	}

	if err := pool.FlushAllDirty(); err != nil {
		t.Fatalf("second FlushAllDirty failed: %v", err)
	}
	writtenAfterSecond := readHeapPageLSNs(t, heapFile)
	if len(writtenAfterSecond[replacedPage]) != 1 || writtenAfterSecond[replacedPage][0] != replacementLSN {
		t.Fatalf("replaced page %d written LSNs = %v, want [%d]", replacedPage, writtenAfterSecond[replacedPage], replacementLSN)
	}
}
