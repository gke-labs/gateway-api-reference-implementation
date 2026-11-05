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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRecovery_TornMultiBlockPage(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-torn-db-0001"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// 1. Write Version 1 of a multi-block page (LSN 10) and make it durable
	payloadV1 := bytes.Repeat([]byte("v1-payload-"), 1000) // ~11 KB -> 4 blocks
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "large-obj", Payload: payloadV1, Token: "10"})
	_ = wal.Sync()

	mbV1, err := NewMultiBlockPage(1, 10, "large-obj", payloadV1)
	if err != nil {
		t.Fatalf("NewMultiBlockPage v1 failed: %v", err)
	}
	locV1, _ := buddy.Allocate(2) // 4 blocks
	_ = NewDirectIO().Writev(heapFile, int64(locV1*BlockSize), mbV1.Blocks)
	_ = heapFile.Sync()

	// 2. Write Version 2 of the multi-block page (LSN 20) to a new location, but TEAR one of its blocks
	payloadV2 := bytes.Repeat([]byte("v2-payload-"), 1000)
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "large-obj", Payload: payloadV2, Token: "20"})
	_ = wal.Sync()

	mbV2, err := NewMultiBlockPage(1, 20, "large-obj", payloadV2)
	if err != nil {
		t.Fatalf("NewMultiBlockPage v2 failed: %v", err)
	}

	// Corrupt block 2 of V2 (simulate torn write)
	mbV2.Blocks[2][BlockHeaderSize+10] ^= 0xff
	locV2, _ := buddy.Allocate(2)
	_ = NewDirectIO().Writev(heapFile, int64(locV2*BlockSize), mbV2.Blocks)
	_ = heapFile.Sync()

	_ = bp.Close()
	_ = heapFile.Close()
	_ = wal.Close()

	// 3. Run Recovery
	reopenedHeap, _ := faultFS.OpenFile("heap.db", 0, 0)
	defer reopenedHeap.Close()

	res, err := Recover(faultFS, reopenedHeap, "wal_dir", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// Recovery must fall back to Version 1 (LSN 10)
	entry, exists := res.KeyIndex["large-obj"]
	if !exists {
		t.Fatalf("expected large-obj to exist after recovery")
	}
	if entry.LSN != 10 {
		t.Fatalf("expected fallback to LSN 10, got %d", entry.LSN)
	}
}

func TestRecovery_InvalidMagicBlocks(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	faultFS.SetMaxFsyncedLSN(100)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-foreign-db01"))

	heapFile, _ := faultFS.Create("heap.db")

	// Write a valid block
	b1 := make([]byte, BlockSize)
	EncodeBlockHeader(BlockHeader{LogicalPage: 1, LSN: 5, NumBlocks: 1}, b1)
	FinalizeBlockCRC(b1)
	_, _ = heapFile.WriteAt(b1, 0)

	// Write an invalid block (corrupt magic)
	b2 := make([]byte, BlockSize)
	EncodeBlockHeader(BlockHeader{LogicalPage: 2, LSN: 10, NumBlocks: 1}, b2)
	b2[0] = 0xff // invalid magic
	FinalizeBlockCRC(b2)
	_, _ = heapFile.WriteAt(b2, BlockSize)
	_ = heapFile.Sync()

	// Run recovery
	res, err := Recover(faultFS, heapFile, "wal_dir", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// Page 1 should be recovered; invalid magic page 2 must be ignored
	if _, ok := res.PageDescs[1]; !ok {
		t.Fatalf("page 1 should be recovered")
	}
	if _, ok := res.PageDescs[2]; ok {
		t.Fatalf("invalid page 2 should NOT be recovered")
	}
}

func TestRecovery_NoResurrection(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-no-res-db-01"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	cp := NewCheckpointer(bp, heapFile, wal)

	// Add key-1, checkpoint, then delete key-1 and checkpoint again
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 1, Key: "key-1", Payload: []byte("val-1"), Token: "1"})
	h1, _ := bp.AllocateNewPage(1, 1, 1)
	slotted, _ := WrapSlottedPage(h1.Block(0))
	_, _ = slotted.Put("key-1", []byte("val-1"), 1)
	slotted.Finalize()
	h1.Unpin()

	_, _ = cp.Checkpoint()

	// Now delete key-1
	_ = wal.Append(Record{Type: RecordTypeDelete, LSN: 3, Key: "key-1", Token: "3"})
	h1Reload, _ := bp.PinPage(1)
	slottedReload, _ := WrapSlottedPage(h1Reload.Block(0))
	_ = slottedReload.Delete(0, 3)
	slottedReload.Finalize()
	bp.MarkDirty(1, 3)
	h1Reload.Unpin()

	_, _ = cp.Checkpoint()

	_ = bp.Close()
	_ = heapFile.Close()
	_ = wal.Close()

	// Recovery
	reopenedHeap, _ := faultFS.OpenFile("heap.db", 0, 0)
	defer reopenedHeap.Close()

	res, err := Recover(faultFS, reopenedHeap, "wal_dir", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// Invariant: deleted key-1 must NOT resurrect
	if _, exists := res.KeyIndex["key-1"]; exists {
		t.Fatalf("deleted object resurrected after recovery!")
	}
}

func TestRecovery_ForgedHeaders(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-forge-db-001"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// Construct an untrusted payload that contains forged block headers with valid CRCs,
	// high LSN (9999), and target logical page placed at EVERY offset.
	forgedHeader := make([]byte, BlockSize)
	EncodeBlockHeader(BlockHeader{
		LogicalPage: 1,
		LSN:         9999, // higher than any real LSN
		BlockIndex:  0,
		NumBlocks:   1,
	}, forgedHeader)
	FinalizeBlockCRC(forgedHeader)

	// Combine into a multi-block object payload
	var maliciousPayload []byte
	for offset := 0; offset < 20000; offset += 500 {
		maliciousPayload = append(maliciousPayload, forgedHeader...)
	}

	// Store real legitimate object first at LSN 5
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 5, Key: "legit-key", Payload: []byte("legit-val"), Token: "5"})
	h1, _ := bp.AllocateNewPage(1, 1, 5)
	s1, _ := WrapSlottedPage(h1.Block(0))
	_, _ = s1.Put("legit-key", []byte("legit-val"), 5)
	s1.Finalize()
	h1.Unpin()
	_ = bp.FlushPage(1)

	// Now store the malicious object containing forged headers at LSN 10
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "malicious-key", Payload: maliciousPayload, Token: "10"})
	_ = wal.Sync()
	mbPage, err := NewMultiBlockPage(2, 10, "malicious-key", maliciousPayload)
	if err != nil {
		t.Fatalf("NewMultiBlockPage failed: %v", err)
	}

	loc2, _ := buddy.Allocate(CalculateOrder(len(mbPage.Blocks)))
	_ = NewDirectIO().Writev(heapFile, int64(loc2*BlockSize), mbPage.Blocks)
	_ = heapFile.Sync()

	_ = bp.Close()
	_ = heapFile.Close()
	_ = wal.Close()

	// Run Recovery
	reopenedHeap, _ := faultFS.OpenFile("heap.db", 0, 0)
	defer reopenedHeap.Close()

	res, err := Recover(faultFS, reopenedHeap, "wal_dir", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	// Invariant: The forged header with LSN 9999 must NOT be accepted!
	// Logical page 1 must have LSN 5, and legit-key must be intact!
	legitEntry, exists := res.KeyIndex["legit-key"]
	if !exists {
		t.Fatalf("legit-key missing after recovery")
	}
	if legitEntry.LSN != 5 {
		t.Fatalf("forged header accepted! LSN is %d, expected 5", legitEntry.LSN)
	}
}

func TestRecovery_CrashConsistency(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_crash_consistency_store"

	// Model mapping key -> expected payload value
	model := make(map[string]string)

	// Cycle 1: Open fresh store, put initial keys and a large multi-block object, checkpoint
	store, err := Open(WithFS(faultFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Cycle 1 Open failed: %v", err)
	}

	largeVal := bytes.Repeat([]byte("large-payload-bytes-"), 500) // ~10 KB
	_ = store.Put("ConfigMap", "key1", []byte("val1-initial"), "1")
	model["key1"] = "val1-initial"

	_ = store.Put("ConfigMap", "key2", []byte("val2-initial"), "2")
	model["key2"] = "val2-initial"

	_ = store.Put("ConfigMap", "key-large", largeVal, "3")
	model["key-large"] = string(largeVal)

	chk1, err := store.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint 1 failed: %v", err)
	}

	// Update key1 and put key3
	_ = store.Put("ConfigMap", "key1", []byte("val1-updated"), "4")
	model["key1"] = "val1-updated"

	_ = store.Put("ConfigMap", "key3", []byte("val3-initial"), "5")
	model["key3"] = "val3-initial"

	// Checkpoint 2
	chk2, err := store.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint 2 failed: %v", err)
	}
	if chk2 <= chk1 {
		t.Fatalf("checkpoint LSN did not advance: chk2=%d <= chk1=%d", chk2, chk1)
	}

	// Un-checkpointed writes before crash
	_ = store.Put("ConfigMap", "key4", []byte("val4-uncheckpointed"), "6")
	model["key4"] = "val4-uncheckpointed"

	// Simulate crash with tearing of un-fsynced writes
	faultFS.Crash(false, 0.5)
	_ = store.Close()

	// Cycle 2: Reopen store and verify full contents against model
	store2, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Cycle 2 Open failed: %v", err)
	}

	for k, expectedVal := range model {
		val, exists, err := store2.Get("ConfigMap", k)
		if err != nil {
			t.Fatalf("Cycle 2 Get(%s) failed: %v", k, err)
		}
		if !exists {
			t.Fatalf("Cycle 2 Get(%s) missing after recovery", k)
		}
		if string(val) != expectedVal {
			t.Fatalf("Cycle 2 Get(%s) payload mismatch: got %q, want %q", k, string(val), expectedVal)
		}
	}

	// In Cycle 2: Delete key1, update key2, put key5, and Checkpoint 3
	if err := store2.Delete("ConfigMap", "key1"); err != nil {
		t.Fatalf("Delete key1 failed: %v", err)
	}
	delete(model, "key1")

	_ = store2.Put("ConfigMap", "key2", []byte("val2-cycle2"), "7")
	model["key2"] = "val2-cycle2"

	_ = store2.Put("ConfigMap", "key5", []byte("val5-cycle2"), "8")
	model["key5"] = "val5-cycle2"

	_, err = store2.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint 3 failed: %v", err)
	}

	// Crash again with drop of unsynced writes (power loss simulation)
	faultFS.Crash(true, 0)
	_ = store2.Close()

	// Cycle 3: Reopen store again and verify full contents against updated model
	store3, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Cycle 3 Open failed: %v", err)
	}
	defer store3.Close()

	// key1 was deleted; must not exist
	if _, exists, _ := store3.Get("ConfigMap", "key1"); exists {
		t.Fatalf("deleted key1 resurrected after cycle 3 recovery!")
	}

	for k, expectedVal := range model {
		val, exists, err := store3.Get("ConfigMap", k)
		if err != nil {
			t.Fatalf("Cycle 3 Get(%s) failed: %v", k, err)
		}
		if !exists {
			t.Fatalf("Cycle 3 Get(%s) missing after recovery", k)
		}
		if string(val) != expectedVal {
			t.Fatalf("Cycle 3 Get(%s) payload mismatch: got %q, want %q", k, string(val), expectedVal)
		}
	}
}

// TestRegression_Item1_LSNReopenContinuation asserts LSNs continue from recovered max and start a new segment.
func TestRegression_Item1_LSNReopenContinuation(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_reopen_lsn_continuation"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "k1", []byte("v1"), "1")
	_ = store.Put("ConfigMap", "k2", []byte("v2"), "2")
	chkLSN, _ := store.Checkpoint()
	_ = store.Close()

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen Open failed: %v", err)
	}
	defer store2.Close()

	// First Put after reopen must NOT fail with "segment already used" and must have LSN > chkLSN
	if err := store2.Put("ConfigMap", "k3", []byte("v3"), "3"); err != nil {
		t.Fatalf("first Put after reopen failed: %v", err)
	}

	store2.keyMu.RLock()
	entryK3 := store2.keyIndex[qualifyKey("ConfigMap", "k3")]
	store2.keyMu.RUnlock()

	if entryK3.LSN <= chkLSN {
		t.Fatalf("LSN went backwards after reopen: k3 LSN=%d <= checkpoint LSN=%d", entryK3.LSN, chkLSN)
	}
}

// TestRegression_Item2_TornTailAdvance asserts WAL iterator advances across segments after a torn tail.
func TestRegression_Item2_TornTailAdvance(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-torn-test-01"))

	wal, err := OpenWAL(memFS, "wal_dir", dbID, 0, WALOptions{MaxSegmentSize: 4096})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Write records to segment 1 (LSN 1..5)
	for i := uint64(1); i <= 5; i++ {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: i, Key: fmt.Sprintf("k%d", i), Payload: []byte("v")})
	}
	_ = wal.Sync()

	// Write records to segment 2 (LSN 6..10)
	for i := uint64(6); i <= 10; i++ {
		_ = wal.Append(Record{Type: RecordTypePut, LSN: i, Key: fmt.Sprintf("k%d", i), Payload: []byte("v")})
	}
	_ = wal.Sync()
	_ = wal.Close()

	// Corrupt tail of segment 1 (simulate torn crash at tail of seg 1)
	entries, _ := memFS.ReadDir("wal_dir")
	seg1File, _ := memFS.OpenFile(filepath.Join("wal_dir", entries[0].Name()), os.O_RDWR, 0644)
	buf := make([]byte, 200)
	_, _ = seg1File.ReadAt(buf, 200)
	buf[50] ^= 0xff // corrupt record in seg 1
	_, _ = seg1File.WriteAt(buf, 200)
	_ = seg1File.Close()

	// Iterator with expected continuation should advance to segment 2
	it, err := NewWALIterator(memFS, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	var replayed []uint64
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected iterator error: %v", err)
		}
		replayed = append(replayed, rec.LSN)
	}

	// Must have read records from segment 2
	hasSeg2 := false
	for _, lsn := range replayed {
		if lsn >= 6 {
			hasSeg2 = true
			break
		}
	}
	if !hasSeg2 {
		t.Fatalf("iterator failed to advance to segment 2 after torn tail; replayed: %v", replayed)
	}
}

// TestRegression_Item3_RedoAppliesPayload asserts un-checkpointed WAL writes apply to page buffers during redo.
func TestRegression_Item3_RedoAppliesPayload(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_redo_applies_payload"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write keys without checkpointing
	_ = store.Put("ConfigMap", "key-redo-1", []byte("payload-redo-1"), "1")
	_ = store.Put("ConfigMap", "key-redo-2", []byte("payload-redo-2"), "2")

	// Sync WAL so records are durable, but do NOT sync heap
	_ = store.wal.Sync()

	// Simulate crash
	_ = store.Close()

	// Reopen store: recovery must redo the puts onto page buffers
	store2, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen Open failed: %v", err)
	}
	defer store2.Close()

	val1, exists, err := store2.Get("ConfigMap", "key-redo-1")
	if err != nil || !exists || string(val1) != "payload-redo-1" {
		t.Fatalf("key-redo-1 not recovered: exists=%v, val=%q, err=%v", exists, string(val1), err)
	}

	val2, exists, err := store2.Get("ConfigMap", "key-redo-2")
	if err != nil || !exists || string(val2) != "payload-redo-2" {
		t.Fatalf("key-redo-2 not recovered: exists=%v, val=%q, err=%v", exists, string(val2), err)
	}
}

// TestRegression_Item4_HighestLSNKeySelection asserts recovery always picks the copy with the highest LSN.
func TestRegression_Item4_HighestLSNKeySelection(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	faultFS.SetMaxFsyncedLSN(100)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-highest-lsn-"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0)
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// Page 1: holds key at LSN 10
	h1, _ := bp.AllocateNewPage(1, 1, 10)
	s1, _ := WrapSlottedPage(h1.Block(0))
	_, _ = s1.Put("target-key", []byte("older-val"), 10)
	s1.Finalize()
	h1.Unpin()
	_ = bp.FlushPage(1)

	// Page 2: holds key at LSN 20 (newer!)
	h2, _ := bp.AllocateNewPage(2, 1, 20)
	s2, _ := WrapSlottedPage(h2.Block(0))
	_, _ = s2.Put("target-key", []byte("newer-val"), 20)
	s2.Finalize()
	h2.Unpin()
	_ = bp.FlushPage(2)

	_ = heapFile.Sync()
	_ = bp.Close()
	_ = heapFile.Close()
	_ = wal.Close()

	reopenedHeap, _ := faultFS.OpenFile("heap.db", 0, 0)
	defer reopenedHeap.Close()

	res, err := Recover(faultFS, reopenedHeap, "wal_dir", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	entry, exists := res.KeyIndex["target-key"]
	if !exists {
		t.Fatalf("target-key missing from recovered index")
	}
	if entry.LSN != 20 {
		t.Fatalf("recovery chose stale LSN %d instead of highest LSN 20", entry.LSN)
	}
}

func CalculateOrder(numBlocks int) int {
	order := 0
	for (1 << order) < numBlocks {
		order++
	}
	return order
}

// TestCrash_ReuseEmptiedLogicalPage tests that reusing an emptied logical page does not
// violate the reuse rule or resurrect deleted keys after a crash.
func TestCrash_ReuseEmptiedLogicalPage(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	dir := "test_crash_reuse_emptied_page"
	store, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Step 1: Occupy block 0
	_ = store.Put("ConfigMap", "dummy-0", bytes.Repeat([]byte("0"), 3000), "1")
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 0 failed: %v", err)
	}

	// Step 2: Occupy block 1
	_ = store.Put("ConfigMap", "dummy-1", bytes.Repeat([]byte("1"), 3000), "2")
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 1 failed: %v", err)
	}

	// Step 3: Put key1 v1 (small payload) -> goes to page 3, gets block 2
	if err := store.Put("ConfigMap", "key1", []byte("val1-v1"), "3"); err != nil {
		t.Fatalf("Put key1 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint key1 v1 failed: %v", err)
	}

	store.bp.mu.Lock()
	entryK1 := store.keyIndex[qualifyKey("ConfigMap", "key1")]
	v1Loc := store.bp.pageTable[entryK1.LogicalPage].DurableLoc
	store.bp.mu.Unlock()
	t.Logf("key1 v1 on page %d has DurableLoc %d", entryK1.LogicalPage, v1Loc)

	// Step 4: Occupy block 3
	_ = store.Put("ConfigMap", "dummy-3", bytes.Repeat([]byte("3"), 3000), "4")
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 3 failed: %v", err)
	}

	// Step 5: Update key1 v2 (small payload, fits in same page 3).
	// When checkpointed, page 3 is written to block 4. Block 2 is freed!
	if err := store.Put("ConfigMap", "key1", []byte("val1-v2"), "5"); err != nil {
		t.Fatalf("Put key1 v2 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint key1 v2 failed: %v", err)
	}

	store.bp.mu.Lock()
	v2Loc := store.bp.pageTable[entryK1.LogicalPage].DurableLoc
	store.bp.mu.Unlock()
	t.Logf("key1 v2 on page %d has DurableLoc %d", entryK1.LogicalPage, v2Loc)

	// Step 6: Free block 1 by updating dummy-1 so block 1 is the lowest free block
	_ = store.Put("ConfigMap", "dummy-1", bytes.Repeat([]byte("x"), 3000), "6")
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy-1 v2 failed: %v", err)
	}

	// Step 7: Delete key1. The empty page is flushed into the lowest free block (block 1)!
	if err := store.Delete("ConfigMap", "key1"); err != nil {
		t.Fatalf("Delete key1 failed: %v", err)
	}

	// Roll segment so the segment containing key1 and its delete is completed and eligible for truncation
	store.wal.mu.Lock()
	_ = store.wal.createSegmentLocked(store.wal.nextLSN)
	store.wal.mu.Unlock()

	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint delete failed: %v", err)
	}
	// Second checkpoint with clean block pool advances redoStartLSN and truncates completed segment 1
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 2 delete failed: %v", err)
	}

	store.bp.mu.Lock()
	durLoc := store.bp.pageTable[entryK1.LogicalPage].DurableLoc
	store.bp.mu.Unlock()
	t.Logf("empty page %d has DurableLoc %d (v1 was at %d, v2 was at %d)", entryK1.LogicalPage, durLoc, v1Loc, v2Loc)

	// Step 8: Reuse the emptied logical page in the block pool
	_ = store.wal.Append(Record{Type: RecordTypePut, LSN: 50, Key: "new-key", Payload: []byte("new-val")})
	hNew, err := store.bp.AllocateNewPage(entryK1.LogicalPage, 1, 50)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	hNew.Unpin()

	// Step 9: Allocate a new page (filler) and flush it to disk.
	// On main, AllocateNewPage freed durLoc (block 1), so filler page gets block 1 and overwrites it.
	_ = store.wal.Append(Record{Type: RecordTypePut, LSN: 51, Key: "filler", Payload: []byte("filler-val")})
	hFiller, err := store.bp.AllocateNewPage(99, 1, 51)
	if err != nil {
		t.Fatalf("AllocateNewPage 99 failed: %v", err)
	}
	spFiller, err := WrapSlottedPage(hFiller.Block(0))
	if err != nil {
		t.Fatalf("WrapSlottedPage failed: %v", err)
	}
	_, _ = spFiller.Put("filler", []byte("filler-val"), 51)
	spFiller.Finalize()
	hFiller.Unpin()
	store.bp.MarkDirty(99, 51)
	if err := store.bp.FlushPage(99); err != nil {
		t.Fatalf("FlushPage(99) failed: %v", err)
	}

	store.bp.mu.Lock()
	fillerLoc := store.bp.pageTable[99].PhysicalBlock
	store.bp.mu.Unlock()
	t.Logf("filler page 99 was written to block %d (empty page was at %d)", fillerLoc, durLoc)

	// Under the Reuse Rule, the block holding the newest durable copy of page 2 (durLoc)
	// must NOT be reallocated before a newer copy is confirmed durable.
	if fillerLoc == durLoc {
		t.Fatalf("reuse rule violation: durLoc %d was reallocated to filler page before new copy became durable", durLoc)
	}

	// Sync heap so filler write is durable
	_ = store.heapFile.Sync()

	// Step 10: Simulate crash BEFORE the page's new incarnation is flushed/fsynced
	close(store.bp.bgStop)
	<-store.bp.bgDone
	_ = store.heapFile.Close()
	_ = store.wal.Close()

	// Step 11: Reopen store after crash
	store2, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	store2.keyMu.RLock()
	for k, entry := range store2.keyIndex {
		t.Logf("Recovered key: %s (page=%d, slot=%d, LSN=%d)", k, entry.LogicalPage, entry.Slot, entry.LSN)
	}
	store2.keyMu.RUnlock()

	// Deleted key1 must NOT resurrect!
	val, exists, err := store2.Get("ConfigMap", "key1")
	if err != nil {
		t.Fatalf("Get key1 error: %v", err)
	}
	if exists {
		t.Fatalf("deleted key1 resurrected after crash recovery! val=%q", string(val))
	}
}

type reuseRuleTrackingFile struct {
	File
	syncCount                int
	syncsRequiredBeforeReuse int
	initialDurableBlocks     map[uint64]bool
	reusedBeforeSync         bool
}

func (f *reuseRuleTrackingFile) WriteAt(p []byte, off int64) (int, error) {
	blockIdx := uint64(off / BlockSize)
	// Flag writes to initially durable blocks that happen before the redo flush sync.
	if f.syncCount < f.syncsRequiredBeforeReuse && f.initialDurableBlocks[blockIdx] {
		f.reusedBeforeSync = true
	}
	return f.File.WriteAt(p, off)
}

func (f *reuseRuleTrackingFile) Sync() error {
	f.syncCount++
	return f.File.Sync()
}

func TestRegression_RecoveryStep6ReuseRule(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("reuse-rule-test1"))

	wal, err := OpenWAL(memFS, "wal", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	rawHeapFile, err := memFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap.db failed: %v", err)
	}
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(rawHeapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// 1. Create page 1 with 1 block (allocates block 0 in buddy) and make durable
	rec0 := Record{Type: RecordTypePut, Key: "ConfigMap k1", Payload: []byte("val1-initial")}
	lsn0, err := wal.AppendRecord(&rec0)
	if err != nil {
		t.Fatalf("AppendRecord rec0 failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}

	h1, err := bp.AllocateNewPage(1, 1, lsn0)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	slotted := NewSlottedPage(1, lsn0)
	if _, err := slotted.Put("ConfigMap k1", []byte("val1-initial"), lsn0); err != nil {
		t.Fatalf("slotted.Put failed: %v", err)
	}
	copy(h1.Block(0), slotted.buf)
	FinalizeBlockCRC(h1.Block(0))
	bp.MarkDirty(1, lsn0)
	h1.Unpin()

	cp := NewCheckpointer(bp, rawHeapFile, wal)
	if _, err := cp.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	initialBlock := h1.Desc.DurableLoc

	// 2. Append WAL records: page 1 modified, plus multiple new pages
	recP1 := Record{Type: RecordTypePut, Key: "ConfigMap k1", Payload: []byte("val1-updated")}
	if _, err := wal.AppendRecord(&recP1); err != nil {
		t.Fatalf("AppendRecord recP1 failed: %v", err)
	}
	for i := 2; i <= 8; i++ {
		r := Record{Type: RecordTypePut, Key: fmt.Sprintf("ConfigMap k%d", i), Payload: []byte("val-new")}
		if _, err := wal.AppendRecord(&r); err != nil {
			t.Fatalf("AppendRecord r%d failed: %v", i, err)
		}
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}

	if err := bp.Close(); err != nil {
		t.Fatalf("bp.Close failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("wal.Close failed: %v", err)
	}
	if err := rawHeapFile.Close(); err != nil {
		t.Fatalf("rawHeapFile.Close failed: %v", err)
	}

	// 3. Open heap file with tracker to verify no durable block is overwritten before sync
	openedHeap, err := memFS.OpenFile("heap.db", os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	t.Cleanup(func() {
		if err := openedHeap.Close(); err != nil {
			t.Errorf("openedHeap.Close failed: %v", err)
		}
	})

	// Recover syncs the heap file twice: first before WAL replay, and second
	// in Step 6 after flushing redone dirty pages. Superseded blocks must not
	// be reused before that second sync completes.
	const initialFsyncs = 1
	const redoFlushFsyncs = 1
	trackingHeap := &reuseRuleTrackingFile{
		File:                     openedHeap,
		syncsRequiredBeforeReuse: initialFsyncs + redoFlushFsyncs,
		initialDurableBlocks: map[uint64]bool{
			initialBlock: true,
		},
	}

	_, err = Recover(memFS, trackingHeap, "wal", dbID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if trackingHeap.reusedBeforeSync {
		t.Fatalf("Reuse Rule violation: superseded physical block %d was reused/overwritten before heapFile.Sync()", initialBlock)
	}
}
