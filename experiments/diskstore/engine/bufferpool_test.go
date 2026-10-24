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
	"testing"
)

func TestBufferPool_PinAndEviction(t *testing.T) {
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

	// Small buffer pool of 4 frames to test frame eviction under pressure
	bp := NewBufferPool(heapFile, wal, buddy, dbID, BufferPoolOptions{NumFrames: 4})
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

	// Allocate 4 new pages (pages 2, 3, 4, 5) to force eviction of page 1 from the 4-frame pool
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

func TestBufferPool_MultiBlockPageNonAdjacentFrames(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("bp-test-db-00002"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	defer wal.Close()

	heapFile, _ := faultFS.Create("heap.db")
	defer heapFile.Close()

	buddy := NewBuddyAllocator(512)

	// Buffer pool of 16 frames
	bp := NewBufferPool(heapFile, wal, buddy, dbID, BufferPoolOptions{NumFrames: 16})
	defer bp.Close()

	// Allocate some single block pages first, then free some to create non-adjacent free frames
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

// TestBufferPool_InFlightWriteNotPromoted asserts that in-flight page writes are not promoted
// during a checkpoint, satisfying the Reuse Rule.
func TestBufferPool_InFlightWriteNotPromoted(t *testing.T) {
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
	bp := NewBufferPool(heapFile, wal, buddy, dbID, BufferPoolOptions{NumFrames: 16})
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

func TestBufferPool_BatchedEviction(t *testing.T) {
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

	// Buffer pool of 32 frames
	bp := NewBufferPool(countingHeap, wal, buddy, dbID, BufferPoolOptions{NumFrames: 32})
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

	// Allocate page 33: requires evicting pages because pool has 0 free frames.
	// acquireFramesLocked will batch-flush candidate dirty pages in ONE write call.
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

