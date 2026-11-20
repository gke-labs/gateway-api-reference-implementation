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
	"sync/atomic"
	"syscall"
	"testing"
)

func TestCheckpointer_BasicCheckpoint(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("chk-test-db-0001"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{MaxSegmentSize: 100})
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

	metaFile, err := faultFS.Create("meta.db")
	if err != nil {
		t.Fatalf("Create meta file failed: %v", err)
	}
	defer metaFile.Close()

	checkpointer := NewCheckpointer(bp, heapFile, wal, metaFile, 0, 1)

	// Write 5 records to WAL and dirty 2 pages
	for i := uint64(1); i <= 5; i++ {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: i, Key: "k", Payload: []byte("val")})
	}

	h1, _ := bp.AllocateNewPage(1, 1, 3)
	copy(h1.Block(0)[BlockHeaderSize:], []byte("page1-data"))
	h1.Unpin()

	h2, _ := bp.AllocateNewPage(2, 1, 5)
	copy(h2.Block(0)[BlockHeaderSize:], []byte("page2-data"))
	h2.Unpin()

	// Checkpoint
	chkLSN, err := checkpointer.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	if chkLSN <= 5 {
		t.Fatalf("expected checkpoint LSN > 5, got %d", chkLSN)
	}

	// Verify both pages are now durable and not dirty
	if h1.Desc.Dirty || h2.Desc.Dirty {
		t.Fatalf("pages should not be dirty after checkpoint")
	}
	if h1.Desc.DurableLoc == NoBlock || h2.Desc.DurableLoc == NoBlock {
		t.Fatalf("pages should have durable locations after checkpoint")
	}
}

type countingFileWrapper struct {
	File
	writeCalls atomic.Int64
}

func (c *countingFileWrapper) WriteAt(p []byte, off int64) (int, error) {
	c.writeCalls.Add(1)
	return c.File.WriteAt(p, off)
}

func (c *countingFileWrapper) Writev(off int64, iov [][]byte) error {
	c.writeCalls.Add(1)
	if vw, ok := c.File.(interface {
		Writev(off int64, iov [][]byte) error
	}); ok {
		return vw.Writev(off, iov)
	}
	total := 0
	for _, b := range iov {
		total += len(b)
	}
	combined := make([]byte, total)
	pos := 0
	for _, b := range iov {
		copy(combined[pos:], b)
		pos += len(b)
	}
	_, err := c.File.WriteAt(combined, off)
	return err
}

func (c *countingFileWrapper) SyscallConn() (any, error) {
	conn, err := c.File.SyscallConn()
	if err != nil || conn == nil {
		return nil, err
	}
	rawConn, ok := conn.(syscall.RawConn)
	if !ok {
		return conn, nil
	}
	return &countingRawConn{RawConn: rawConn, counter: &c.writeCalls}, nil
}

type countingRawConn struct {
	syscall.RawConn
	counter *atomic.Int64
}

func (c *countingRawConn) Control(f func(uintptr)) error {
	c.counter.Add(1)
	return c.RawConn.Control(f)
}

func TestCheckpointer_BatchedFlushWriteCallCount(t *testing.T) {
	t.Run("N <= MaxBatchBlocks issues 1 write call", func(t *testing.T) {
		const n = 64
		runCountingCheckpointTest(t, n, 1)
	})

	t.Run("N > MaxBatchBlocks issues ceil(N/MaxBatchBlocks) write calls", func(t *testing.T) {
		const n = 600
		const expectedWrites = int64((n + MaxBatchBlocks - 1) / MaxBatchBlocks) // 2
		runCountingCheckpointTest(t, n, expectedWrites)
	})
}

func runCountingCheckpointTest(t *testing.T, numPages int, expectedWrites int64) {
	dir := t.TempDir()
	fs := NewOSFS()

	var dbID [16]byte
	copy(dbID[:], []byte("cnt-test-db-0001"))

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

	buddyCapacity := uint64(numPages * 2)
	if buddyCapacity < 512 {
		buddyCapacity = 512
	}
	buddy := NewBuddyAllocator(buddyCapacity)
	bp := NewBlockPool(countingHeap, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: numPages + 10})
	defer bp.Close()

	metaFile, err := fs.Create(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("Create meta file failed: %v", err)
	}
	defer metaFile.Close()

	checkpointer := NewCheckpointer(bp, countingHeap, wal, metaFile, 0, 1)

	// Dirty N pages and write WAL records
	for i := 1; i <= numPages; i++ {
		lsn := uint64(i * 10)
		_ = wal.Append(Record{Type: RecordTypePut, LSN: lsn, Key: fmt.Sprintf("k%d", i), Payload: []byte("val")})
		h, err := bp.AllocateNewPage(uint64(i), 1, lsn)
		if err != nil {
			t.Fatalf("AllocateNewPage %d failed: %v", i, err)
		}
		copy(h.Block(0)[BlockHeaderSize:], []byte(fmt.Sprintf("page-%d-content", i)))
		h.Unpin()
	}

	// Reset write count before checkpoint
	countingHeap.writeCalls.Store(0)

	// Perform checkpoint
	if _, err := checkpointer.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	writes := countingHeap.writeCalls.Load()
	if writes != expectedWrites {
		t.Fatalf("expected %d write calls for %d pages, got %d (max batch blocks %d)",
			expectedWrites, numPages, writes, MaxBatchBlocks)
	}

	// Verify all pages are durable, not dirty, and data can be read back
	for i := 1; i <= numPages; i++ {
		bp.mu.Lock()
		desc := bp.pageTable[uint64(i)]
		if desc.Dirty {
			bp.mu.Unlock()
			t.Fatalf("page %d still dirty after checkpoint", i)
		}
		if desc.DurableLoc == NoBlock {
			bp.mu.Unlock()
			t.Fatalf("page %d has no durable location", i)
		}
		bp.mu.Unlock()

		h, err := bp.PinPage(uint64(i))
		if err != nil {
			t.Fatalf("PinPage %d failed: %v", i, err)
		}
		expectedData := []byte(fmt.Sprintf("page-%d-content", i))
		actualData := h.Block(0)[BlockHeaderSize : BlockHeaderSize+len(expectedData)]
		if !bytes.Equal(actualData, expectedData) {
			h.Unpin()
			t.Fatalf("page %d content mismatch: got %q, want %q", i, string(actualData), string(expectedData))
		}
		h.Unpin()
	}
}

func TestCheckpointer_DeferredFreesIntegration(t *testing.T) {
	isAllocated := func(b *BuddyAllocator, block uint64) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		_, exists := b.allocated[block]
		return exists
	}

	t.Run("checkpoint frees unneeded runs from before fsync", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)

		var dbID [16]byte
		copy(dbID[:], []byte("chk-df-test-0001"))

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

		metaFile, err := faultFS.Create("meta.db")
		if err != nil {
			t.Fatalf("Create meta file failed: %v", err)
		}
		defer metaFile.Close()

		checkpointer := NewCheckpointer(bp, heapFile, wal, metaFile, 0, 1)

		// Allocate and flush page 1 to disk
		if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k", Payload: []byte("v1")}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if err := wal.SyncThrough(10); err != nil {
			t.Fatalf("SyncThrough failed: %v", err)
		}
		h1, err := bp.AllocateNewPage(1, 1, 10)
		if err != nil {
			t.Fatalf("AllocateNewPage failed: %v", err)
		}
		copy(h1.Block(0)[BlockHeaderSize:], []byte("v1"))
		h1.Unpin()
		if err := bp.FlushPage(1); err != nil {
			t.Fatalf("first FlushPage failed: %v", err)
		}
		bp.mu.Lock()
		r1 := bp.pageTable[1].PhysicalBlock
		bp.mu.Unlock()

		if _, err := checkpointer.Checkpoint(); err != nil {
			t.Fatalf("initial Checkpoint failed: %v", err)
		}

		// Dirty and flush page 1 again: supersedes and defers r1
		if err := wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k", Payload: []byte("v2")}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if err := wal.SyncThrough(20); err != nil {
			t.Fatalf("SyncThrough failed: %v", err)
		}
		bp.MarkDirty(1, 20)
		if err := bp.FlushPage(1); err != nil {
			t.Fatalf("second FlushPage failed: %v", err)
		}

		// Checkpoint calls startHeapSync, Sync, and heapSyncSucceeded
		if _, err := checkpointer.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint failed: %v", err)
		}

		if isAllocated(buddy, r1) {
			t.Fatalf("run %d should have been freed by checkpoint fsync", r1)
		}
	})

	t.Run("failed heap sync during checkpoint does not free deferred runs", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)

		var dbID [16]byte
		copy(dbID[:], []byte("chk-df-test-0002"))

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

		metaFile, err := faultFS.Create("meta.db")
		if err != nil {
			t.Fatalf("Create meta file failed: %v", err)
		}
		defer metaFile.Close()

		checkpointer := NewCheckpointer(bp, heapFile, wal, metaFile, 0, 1)

		// Allocate and flush page 1 to disk
		if err := wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "k", Payload: []byte("v1")}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if err := wal.SyncThrough(10); err != nil {
			t.Fatalf("SyncThrough failed: %v", err)
		}
		h1, err := bp.AllocateNewPage(1, 1, 10)
		if err != nil {
			t.Fatalf("AllocateNewPage failed: %v", err)
		}
		copy(h1.Block(0)[BlockHeaderSize:], []byte("v1"))
		h1.Unpin()
		if err := bp.FlushPage(1); err != nil {
			t.Fatalf("first FlushPage failed: %v", err)
		}
		bp.mu.Lock()
		r1 := bp.pageTable[1].PhysicalBlock
		bp.mu.Unlock()

		if _, err := checkpointer.Checkpoint(); err != nil {
			t.Fatalf("initial Checkpoint failed: %v", err)
		}

		// Dirty and flush page 1 again: supersedes and defers r1
		if err := wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "k", Payload: []byte("v2")}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if err := wal.SyncThrough(20); err != nil {
			t.Fatalf("SyncThrough failed: %v", err)
		}
		bp.MarkDirty(1, 20)
		if err := bp.FlushPage(1); err != nil {
			t.Fatalf("second FlushPage failed: %v", err)
		}

		// Fail only the heap file's sync
		heapSyncFailedOnce := false
		faultFS.SetBeforeSync(func(path string) {
			if filepath.Base(path) == "heap.db" && !heapSyncFailedOnce {
				faultFS.SetSyncError(fmt.Errorf("simulated heap sync error"))
				heapSyncFailedOnce = true
			} else {
				faultFS.SetSyncError(nil)
			}
		})

		// Checkpoint must fail at heap fsync
		if _, err := checkpointer.Checkpoint(); err == nil {
			t.Fatalf("expected checkpoint to fail on sync error, but it succeeded")
		}

		// Verify r1 was NOT freed because heapSyncFailed was called
		if !isAllocated(buddy, r1) {
			t.Fatalf("run %d was freed despite checkpoint heap sync failure", r1)
		}

		// Next checkpoint must succeed and free r1
		if _, err := checkpointer.Checkpoint(); err != nil {
			t.Fatalf("subsequent checkpoint failed: %v", err)
		}

		if isAllocated(buddy, r1) {
			t.Fatalf("run %d should have been freed after successful checkpoint", r1)
		}
	})
}

func TestCheckpointer_FlushCompletingDuringHeapSync_LostFlushRebuiltFromWAL(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	storeDir := "test_flush_during_fsync"

	store, err := Open(WithFS(faultFS), WithDir(storeDir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// 1. Initial write and checkpoint to establish durable baseline
	if err := store.Put("table", "k1", []byte("v1_initial")); err != nil {
		t.Fatalf("initial Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("initial Checkpoint failed: %v", err)
	}

	// Find the logical page holding k1
	store.keyMu.RLock()
	entry, exists := store.keyIndex[qualifyKey("table", "k1")]
	store.keyMu.RUnlock()
	if !exists {
		t.Fatalf("expected k1 in index")
	}
	pageID := entry.LogicalPage

	// 2. Modify k1 with "v2_updated". This dirties pageID at LSN L1.
	if err := store.Put("table", "k1", []byte("v2_updated")); err != nil {
		t.Fatalf("update Put failed: %v", err)
	}

	store.bp.mu.Lock()
	desc := store.bp.pageTable[pageID]
	if desc == nil {
		store.bp.mu.Unlock()
		t.Fatalf("expected descriptor for page %d", pageID)
	}
	if !desc.Dirty {
		store.bp.mu.Unlock()
		t.Fatalf("expected page %d to be dirty", pageID)
	}
	firstUnsyncedLSN := desc.RedoLSN
	if firstUnsyncedLSN == 0 {
		store.bp.mu.Unlock()
		t.Fatalf("expected RedoLSN > 0 for dirty page %d", pageID)
	}
	store.bp.mu.Unlock()

	// 3. Set up hooks to make the page's flush complete during the checkpoint's heap fsync.
	// We start FlushPage in a goroutine, hold its WriteAt in beforeWriteAt, and release it
	// inside beforeSync when the checkpoint is executing heapFile.Sync().
	flushStarted := make(chan struct{})
	allowFlushFinish := make(chan struct{})
	flushDone := make(chan struct{})
	var flushErr error

	var once sync.Once
	faultFS.SetBeforeWriteAt(func(path string, p []byte, off int64) {
		if filepath.Base(path) == "heap.db" {
			once.Do(func() {
				close(flushStarted)
				<-allowFlushFinish
			})
		}
	})

	go func() {
		flushErr = store.bp.FlushPage(pageID)
		close(flushDone)
	}()

	// Wait until FlushPage has set InFlight=true and is blocked in WriteAt
	<-flushStarted

	// Now set beforeSync for the checkpoint's heapFile.Sync()
	faultFS.SetBeforeSync(func(path string) {
		if filepath.Base(path) == "heap.db" {
			// At this point, checkpoint has captured the DPT snapshot and called startHeapSync().
			// Release the flush so it writes to heap.db and returns during this fsync.
			close(allowFlushFinish)
			<-flushDone
		}
	})

	// 4. Run Checkpoint
	chkLSN, cpErr := store.Checkpoint()
	if cpErr != nil {
		t.Fatalf("Checkpoint failed: %v", cpErr)
	}
	if flushErr != nil {
		t.Fatalf("FlushPage failed: %v", flushErr)
	}

	// 5. Verify acceptance criterion:
	// "The checkpoint's redo start LSN is at or below that page's first un-synced LSN"
	walScanIt, err := NewWALIterator(faultFS, filepath.Join(storeDir, "wal"), store.dbID, chkLSN, WALIteratorOptions{})
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer func() {
		if err := walScanIt.Close(); err != nil {
			t.Errorf("walScanIt.Close failed: %v", err)
		}
	}()

	chkRecord, err := walScanIt.Next()
	if err != nil {
		t.Fatalf("reading checkpoint record failed: %v", err)
	}
	if chkRecord.Type != RecordTypeCheckpoint {
		t.Fatalf("expected RecordTypeCheckpoint, got %v", chkRecord.Type)
	}

	metaFile, err := faultFS.OpenFile(filepath.Join(storeDir, "meta.db"), 0, 0)
	if err != nil {
		t.Fatalf("OpenFile meta.db failed: %v", err)
	}
	var metaBuf [metaFileSize]byte
	if _, err := metaFile.ReadAt(metaBuf[:], 0); err != nil {
		t.Fatalf("ReadAt meta.db failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close meta.db failed: %v", err)
	}
	redoStartLSN, _, _, err := readRecoveryStartPages(metaBuf[:], "meta.db")
	if err != nil {
		t.Fatalf("readRecoveryStartPages failed: %v", err)
	}
	if redoStartLSN > firstUnsyncedLSN {
		t.Fatalf("expected checkpoint redo start LSN <= firstUnsyncedLSN (%d), got %d",
			firstUnsyncedLSN, redoStartLSN)
	}

	// Page descriptor should retain its RedoLSN because its flush completed during fsync (in unsynced generation)
	store.bp.mu.Lock()
	if desc.RedoLSN != firstUnsyncedLSN {
		store.bp.mu.Unlock()
		t.Fatalf("expected page RedoLSN to remain %d, got %d", firstUnsyncedLSN, desc.RedoLSN)
	}
	store.bp.mu.Unlock()

	// 6. Simulate crash dropping un-fsynced heap writes.
	// Since the flush returned during the fsync (after startHeapSync generation rotation),
	// the flush's write is un-fsynced and discarded by the crash.
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// 7. Reopen store on the underlying filesystem and verify recovery rebuilds the page from the WAL
	store2, err := Open(WithFS(NewFaultFS(memFS)), WithDir(storeDir))
	if err != nil {
		t.Fatalf("Open after crash failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Errorf("store2.Close failed: %v", err)
		}
	}()

	val, exists, err := store2.Get("table", "k1")
	if err != nil {
		t.Fatalf("Get after recovery failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected k1 to exist after recovery")
	}
	if !bytes.Equal(val, []byte("v2_updated")) {
		t.Fatalf("expected k1 to be reconstructed to 'v2_updated', got %q", string(val))
	}
}

func TestCheckpointer_AllocateNewPageCarriesDirtyLSNAcrossFsync(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	storeDir := "test_realloc_dirty_lsn"

	store, err := Open(WithFS(faultFS), WithDir(storeDir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// 1. Put a multi-block value and checkpoint to establish durable baseline
	mbVal1 := bytes.Repeat([]byte("a"), 5000)
	if err := store.Put("table", "mb1", mbVal1); err != nil {
		t.Fatalf("initial multi-block Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("initial Checkpoint failed: %v", err)
	}

	store.keyMu.RLock()
	entry, exists := store.keyIndex[qualifyKey("table", "mb1")]
	store.keyMu.RUnlock()
	if !exists {
		t.Fatalf("expected mb1 in index")
	}
	pageID := entry.LogicalPage

	// 2. Replace mb1 with another multi-block value to dirty the page
	mbVal2 := bytes.Repeat([]byte("b"), 5000)
	if err := store.Put("table", "mb1", mbVal2); err != nil {
		t.Fatalf("replace Put failed: %v", err)
	}

	// 3. Start a checkpoint and, while its heap fsync runs:
	//    - delete the key mb1 (dirtied at delete LSN)
	//    - put another multi-block value mb2 that reuses pageID
	var deleteLSN, putLSN uint64
	deleteAndReallocDone := make(chan struct{})
	var opErr error

	faultFS.SetBeforeSync(func(path string) {
		if filepath.Base(path) == "heap.db" {
			// Inside heapFile.Sync(), after FlushAllDirty has flushed pageID and
			// startHeapSync has rotated the flush into flushedPagesSyncing.
			if err := store.Delete("table", "mb1"); err != nil {
				opErr = fmt.Errorf("Delete failed: %w", err)
				close(deleteAndReallocDone)
				return
			}
			deleteLSN = store.wal.MaxLSN()
			mbVal3 := bytes.Repeat([]byte("c"), 5000)
			if err := store.Put("table", "mb2", mbVal3); err != nil {
				opErr = fmt.Errorf("Put mb2 failed: %w", err)
				close(deleteAndReallocDone)
				return
			}
			putLSN = store.wal.MaxLSN()
			close(deleteAndReallocDone)
		}
	})

	chkLSN1, cpErr := store.Checkpoint()
	if cpErr != nil {
		t.Fatalf("Checkpoint failed: %v", cpErr)
	}
	<-deleteAndReallocDone
	if opErr != nil {
		t.Fatalf("concurrent operations during fsync failed: %v", opErr)
	}
	if chkLSN1 == 0 {
		t.Fatalf("expected non-zero checkpoint LSN")
	}
	if deleteLSN == 0 || putLSN == 0 || deleteLSN >= putLSN {
		t.Fatalf("expected deleteLSN (%d) < putLSN (%d)", deleteLSN, putLSN)
	}

	// Verify that pageID was reused for mb2
	store.keyMu.RLock()
	entry2, exists2 := store.keyIndex[qualifyKey("table", "mb2")]
	store.keyMu.RUnlock()
	if !exists2 {
		t.Fatalf("expected mb2 in index")
	}
	if entry2.LogicalPage != pageID {
		t.Fatalf("expected mb2 to reuse page %d, got %d", pageID, entry2.LogicalPage)
	}

	// Verify that after heapSyncSucceeded, pageID's RedoLSN carried forward the
	// DirtyLSN from the delete operation rather than jumping ahead to mb2's Put LSN.
	store.bp.mu.Lock()
	desc := store.bp.pageTable[pageID]
	if desc == nil {
		store.bp.mu.Unlock()
		t.Fatalf("expected descriptor for page %d", pageID)
	}
	redoLSN := desc.RedoLSN
	dirtyLSN := desc.DirtyLSN
	store.bp.mu.Unlock()

	if redoLSN != deleteLSN {
		t.Fatalf("expected page RedoLSN == deleteLSN (%d), got %d (putLSN=%d)", deleteLSN, redoLSN, putLSN)
	}
	if dirtyLSN != deleteLSN {
		t.Fatalf("expected page DirtyLSN == deleteLSN (%d), got %d (putLSN=%d)", deleteLSN, dirtyLSN, putLSN)
	}

	// 4. Second checkpoint records redo start at or below deleteLSN
	faultFS.SetBeforeSync(nil)
	chkLSN2, cpErr2 := store.Checkpoint()
	if cpErr2 != nil {
		t.Fatalf("second Checkpoint failed: %v", cpErr2)
	}

	walScanIt, err := NewWALIterator(faultFS, filepath.Join(storeDir, "wal"), store.dbID, chkLSN2, WALIteratorOptions{})
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer func() {
		if err := walScanIt.Close(); err != nil {
			t.Errorf("walScanIt.Close failed: %v", err)
		}
	}()

	chkRecord, err := walScanIt.Next()
	if err != nil {
		t.Fatalf("reading second checkpoint record failed: %v", err)
	}
	if chkRecord.Type != RecordTypeCheckpoint {
		t.Fatalf("expected RecordTypeCheckpoint, got %v", chkRecord.Type)
	}

	metaFile2, err := faultFS.OpenFile(filepath.Join(storeDir, "meta.db"), 0, 0)
	if err != nil {
		t.Fatalf("OpenFile meta.db failed: %v", err)
	}
	var metaBuf2 [metaFileSize]byte
	if _, err := metaFile2.ReadAt(metaBuf2[:], 0); err != nil {
		t.Fatalf("ReadAt meta.db failed: %v", err)
	}
	if err := metaFile2.Close(); err != nil {
		t.Fatalf("Close meta.db failed: %v", err)
	}
	redoStartLSN2, _, _, err := readRecoveryStartPages(metaBuf2[:], "meta.db")
	if err != nil {
		t.Fatalf("readRecoveryStartPages failed: %v", err)
	}
	if redoStartLSN2 > deleteLSN {
		t.Fatalf("expected second checkpoint redo start LSN <= deleteLSN (%d), got %d (putLSN=%d)",
			deleteLSN, redoStartLSN2, putLSN)
	}

	// 5. Crash and recover
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	store2, err := Open(WithFS(NewFaultFS(memFS)), WithDir(storeDir))
	if err != nil {
		t.Fatalf("Open after crash failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Errorf("store2.Close failed: %v", err)
		}
	}()

	val2, exists, err := store2.Get("table", "mb2")
	if err != nil {
		t.Fatalf("Get mb2 after recovery failed: %v", err)
	}
	if !exists || !bytes.Equal(val2, bytes.Repeat([]byte("c"), 5000)) {
		t.Fatalf("mb2 not correctly recovered")
	}

	_, exists, err = store2.Get("table", "mb1")
	if err != nil {
		t.Fatalf("Get mb1 after recovery failed: %v", err)
	}
	if exists {
		t.Fatalf("expected deleted mb1 to not exist after recovery")
	}
}

// TestCheckpointer_DeterministicDeferredFreesSequence verifies the deterministic sequence:
// 1. Flush a page and checkpoint.
// 2. Dirty it.
// 3. Start a heap fsync.
// 4. Flush the page while the fsync runs.
// 5. Complete the fsync.
// 6. Dirty and flush the page again.
// 7. Allocate and flush another page.
// Assert: No write lands on a block that holds a newest durable copy.
func TestCheckpointer_DeterministicDeferredFreesSequence(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	faultFS.SetAssertReuseRule(true)
	storeDir := "test_deterministic_deferred_frees"

	store, err := Open(WithFS(faultFS), WithDir(storeDir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// 1. Flush a page and checkpoint
	if err := store.Put("table", "k1", []byte("val_v1")); err != nil {
		t.Fatalf("initial Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("initial Checkpoint failed: %v", err)
	}

	store.keyMu.RLock()
	entry, exists := store.keyIndex[qualifyKey("table", "k1")]
	store.keyMu.RUnlock()
	if !exists {
		t.Fatalf("expected k1 in index")
	}
	pageID := entry.LogicalPage

	store.bp.mu.Lock()
	durableLoc0 := store.bp.pageTable[pageID].DurableLoc
	store.bp.mu.Unlock()
	if durableLoc0 == NoBlock {
		t.Fatalf("expected page %d to have a durable location after checkpoint", pageID)
	}

	// 2. Dirty it
	if err := store.Put("table", "k1", []byte("val_v2")); err != nil {
		t.Fatalf("second Put failed: %v", err)
	}

	// 3. Start a heap fsync
	store.bp.SnapshotFlushedForSync()
	store.bp.startHeapSync()

	// 4. Flush the page while the fsync runs
	if err := store.bp.FlushPage(pageID); err != nil {
		t.Fatalf("FlushPage during fsync failed: %v", err)
	}

	store.bp.mu.Lock()
	loc1 := store.bp.pageTable[pageID].PhysicalBlock
	store.bp.mu.Unlock()
	if loc1 == durableLoc0 {
		t.Fatalf("flush of page %d should write to new location, got same %d", pageID, loc1)
	}

	// 5. Complete the fsync
	if err := store.heapFile.Sync(); err != nil {
		store.bp.heapSyncFailed()
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := store.bp.heapSyncSucceeded(); err != nil {
		t.Fatalf("heapSyncSucceeded failed: %v", err)
	}
	if err := store.bp.PromoteFlushedToDurable(); err != nil {
		t.Fatalf("PromoteFlushedToDurable failed: %v", err)
	}

	// Verify durableLoc0 is NOT freed because it was superseded after startHeapSync was called
	store.bp.mu.Lock()
	_, dur0Allocated := store.bp.buddy.allocated[durableLoc0]
	store.bp.mu.Unlock()
	if !dur0Allocated {
		t.Fatalf("durableLoc0 %d was prematurely freed in allocator", durableLoc0)
	}

	// 6. Dirty and flush the page again
	if err := store.Put("table", "k1", []byte("val_v3")); err != nil {
		t.Fatalf("third Put failed: %v", err)
	}
	if err := store.bp.FlushPage(pageID); err != nil {
		t.Fatalf("FlushPage after fsync failed: %v", err)
	}

	store.bp.mu.Lock()
	loc2 := store.bp.pageTable[pageID].PhysicalBlock
	store.bp.mu.Unlock()
	if loc2 == durableLoc0 || loc2 == loc1 {
		t.Fatalf("third flush should write to new location, got %d", loc2)
	}

	// 7. Allocate and flush another page
	const page2ID = 999
	lsn2, err := store.wal.AppendRecord(&Record{Type: RecordTypePut, Key: "k999", Payload: []byte("page-999-content")})
	if err != nil {
		t.Fatalf("Append WAL record for page 999 failed: %v", err)
	}
	if err := store.wal.SyncThrough(lsn2); err != nil {
		t.Fatalf("SyncThrough WAL failed: %v", err)
	}
	h2, err := store.bp.AllocateNewPage(page2ID, 1, lsn2)
	if err != nil {
		t.Fatalf("AllocateNewPage 999 failed: %v", err)
	}
	copy(h2.Block(0)[BlockHeaderSize:], []byte("page-999-content"))
	h2.Unpin()

	// Under Reuse Rule, the write of page 999 must NOT land on durableLoc0
	if err := store.bp.FlushPage(page2ID); err != nil {
		t.Fatalf("FlushPage 999 failed: %v", err)
	}

	store.bp.mu.Lock()
	page2Loc := store.bp.pageTable[page2ID].PhysicalBlock
	store.bp.mu.Unlock()

	// 8. Assert: No write lands on a block that holds a newest durable copy
	if page2Loc == durableLoc0 {
		t.Fatalf("reuse rule violation: page 999 write landed on block %d holding newest durable copy of page %d",
			page2Loc, pageID)
	}
	if page2Loc == loc1 {
		t.Fatalf("reuse rule violation: page 999 write landed on block %d which was not yet durable", page2Loc)
	}

	// Verify durableLoc0 remains allocated in buddy allocator
	store.bp.mu.Lock()
	_, dur0StillAllocated := store.bp.buddy.allocated[durableLoc0]
	store.bp.mu.Unlock()
	if !dur0StillAllocated {
		t.Fatalf("durableLoc0 %d was freed before replacement became durable", durableLoc0)
	}

	// 9. Now run a full checkpoint; fsync will make loc2 durable and release durableLoc0 and loc1
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("final Checkpoint failed: %v", err)
	}

	store.bp.mu.Lock()
	_, dur0After := store.bp.buddy.allocated[durableLoc0]
	_, loc1After := store.bp.buddy.allocated[loc1]
	store.bp.mu.Unlock()
	if dur0After {
		t.Fatalf("durableLoc0 %d should be freed after final checkpoint", durableLoc0)
	}
	if loc1After {
		t.Fatalf("loc1 %d should be freed after final checkpoint", loc1)
	}
}

// TestCheckpointer_PageDeletionDefersOldLocation tests that deleting all records from a page
// writes an empty slotted page whose flush defers the prior on-disk location.
func TestCheckpointer_PageDeletionDefersOldLocation(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	storeDir := "test_deletion_defers"

	store, err := Open(WithFS(faultFS), WithDir(storeDir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if err := store.Put("table", "k1", []byte("val_v1")); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	store.keyMu.RLock()
	pageID := store.keyIndex[qualifyKey("table", "k1")].LogicalPage
	store.keyMu.RUnlock()

	store.bp.mu.Lock()
	loc1 := store.bp.pageTable[pageID].PhysicalBlock
	store.bp.mu.Unlock()

	// Delete k1: slotted page becomes empty and dirty
	if err := store.Delete("table", "k1"); err != nil {
		t.Fatalf("Delete k1 failed: %v", err)
	}

	// Flush dirty pages: writes empty slotted page to a new block and defers loc1
	if err := store.bp.FlushAllDirty(); err != nil {
		t.Fatalf("FlushAllDirty failed: %v", err)
	}

	store.bp.mu.Lock()
	loc2 := store.bp.pageTable[pageID].PhysicalBlock
	deferredCount := 0
	for _, run := range store.bp.deferredFreesUnsynced {
		if run.block == loc1 {
			deferredCount++
		}
	}
	store.bp.mu.Unlock()

	if loc2 == loc1 {
		t.Fatalf("empty page should be written out-of-place to new block, got %d", loc2)
	}
	if deferredCount != 1 {
		t.Fatalf("expected old location %d to be deferred exactly once, got %d", loc1, deferredCount)
	}

	// Checkpoint fsyncs the empty page and frees loc1
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("final Checkpoint failed: %v", err)
	}

	store.bp.mu.Lock()
	_, loc1Allocated := store.bp.buddy.allocated[loc1]
	store.bp.mu.Unlock()
	if loc1Allocated {
		t.Fatalf("old location %d should be freed after checkpoint", loc1)
	}
}
