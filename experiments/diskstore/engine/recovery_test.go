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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestRecovery_TornMultiBlockPage(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	var dbID [16]byte
	copy(dbID[:], []byte("rec-torn-db-0001"))

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// 1. Write Version 1 of a multi-block page (LSN 10) and make it durable
	payloadV1 := bytes.Repeat([]byte("v1-payload-"), 1000) // ~11 KB -> 4 blocks
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 10, Key: "large-obj", Payload: payloadV1})
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
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 20, Key: "large-obj", Payload: payloadV2})
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

	res, err := Recover(faultFS, reopenedHeap, ".", "wal_dir", dbID, RecoveryOptions{})
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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 5, Key: "k", Payload: []byte("v")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

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
	res, err := Recover(faultFS, heapFile, ".", "wal_dir", dbID, RecoveryOptions{})
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

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	heapFile, _ := faultFS.Create("heap.db")
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})
	cp := NewCheckpointer(bp, heapFile, wal)

	// Add key-1, checkpoint, then delete key-1 and checkpoint again
	_ = wal.Append(Record{Type: RecordTypePut, LSN: 1, Key: "key-1", Payload: []byte("val-1")})
	h1, _ := bp.AllocateNewPage(1, 1, 1)
	slotted, _ := WrapSlottedPage(h1.Block(0))
	_, _ = slotted.Put("key-1", []byte("val-1"), 1)
	slotted.Finalize()
	h1.Unpin()

	_, _ = cp.Checkpoint()

	// Now delete key-1
	_ = wal.Append(Record{Type: RecordTypeDelete, LSN: 3, Key: "key-1"})
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

	res, err := Recover(faultFS, reopenedHeap, ".", "wal_dir", dbID, RecoveryOptions{})
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

	wal, _ := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
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
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 5, Key: "legit-key", Payload: []byte("legit-val")}); err != nil {
		t.Fatalf("Append legit failed: %v", err)
	}
	h1, err := bp.AllocateNewPage(1, 1, 5)
	if err != nil {
		t.Fatalf("AllocateNewPage 1 failed: %v", err)
	}
	s1, err := WrapSlottedPage(h1.Block(0))
	if err != nil {
		t.Fatalf("WrapSlottedPage 1 failed: %v", err)
	}
	if _, err := s1.Put("legit-key", []byte("legit-val"), 5); err != nil {
		t.Fatalf("Put legit-key failed: %v", err)
	}
	s1.Finalize()
	h1.Unpin()
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage(1) failed: %v", err)
	}

	// Now store the malicious object containing forged headers at LSN 6
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 6, Key: "malicious-key", Payload: maliciousPayload}); err != nil {
		t.Fatalf("Append malicious failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}
	mbPage, err := NewMultiBlockPage(2, 6, "malicious-key", maliciousPayload)
	if err != nil {
		t.Fatalf("NewMultiBlockPage failed: %v", err)
	}

	loc2, err := buddy.Allocate(CalculateOrder(len(mbPage.Blocks)))
	if err != nil {
		t.Fatalf("buddy.Allocate failed: %v", err)
	}
	if err := NewDirectIO().Writev(heapFile, int64(loc2*BlockSize), mbPage.Blocks); err != nil {
		t.Fatalf("Writev failed: %v", err)
	}
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}

	if err := bp.Close(); err != nil {
		t.Fatalf("bp.Close failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("heapFile.Close failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("wal.Close failed: %v", err)
	}

	// Run Recovery
	reopenedHeap, err := faultFS.OpenFile("heap.db", 0, 0)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	defer func() {
		if err := reopenedHeap.Close(); err != nil {
			t.Errorf("Close reopenedHeap failed: %v", err)
		}
	}()

	res, err := Recover(faultFS, reopenedHeap, ".", "wal_dir", dbID, RecoveryOptions{})
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

func readDBIDFromMeta(fs FS, dir string) ([16]byte, bool, error) {
	metaFile, err := fs.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return [16]byte{}, false, nil
		}
		return [16]byte{}, false, err
	}

	var metaBuf [metaFileSize]byte
	if _, err := metaFile.ReadAt(metaBuf[:], 0); err != nil {
		closeErr := metaFile.Close()
		return [16]byte{}, false, errors.Join(err, closeErr)
	}
	if err := metaFile.Close(); err != nil {
		return [16]byte{}, false, err
	}

	record, err := decodeMetaRecord(metaBuf[:])
	if err != nil {
		return [16]byte{}, false, err
	}
	return record.dbID, true, nil
}

// openStoreOnFaultFS opens a store on a FaultFS, setting the heap cipher on the
// FaultFS so that invariant checks decrypt heap blocks rather than misinterpreting ciphertext.
func openStoreOnFaultFS(faultFS *FaultFS, dir string, key []byte, opts ...Option) (*Engine, error) {
	if len(key) > 0 {
		faultFS.SetEncryptionKey(key)
		dbID, exists, err := readDBIDFromMeta(faultFS, dir)
		if err != nil {
			return nil, err
		}
		if exists {
			cipher, err := newHeapCipher(key, dbID)
			if err != nil {
				return nil, err
			}
			faultFS.SetHeapCipher(cipher)
		}
	}

	openOpts := make([]Option, 0, len(opts)+3)
	openOpts = append(openOpts, WithFS(faultFS), WithDir(dir))
	if len(key) > 0 {
		openOpts = append(openOpts, WithEncryptionKey(key))
	}
	openOpts = append(openOpts, opts...)

	store, err := Open(openOpts...)
	if err != nil {
		return nil, err
	}

	if len(key) > 0 {
		cipher, err := newHeapCipher(key, store.DBID())
		if err != nil {
			closeErr := store.Close()
			return nil, errors.Join(err, closeErr)
		}
		faultFS.SetHeapCipher(cipher)
	}

	return store, nil
}

func TestRecovery_CrashConsistency(t *testing.T) {
	t.Run("Unencrypted", func(t *testing.T) {
		testRecovery_CrashConsistency(t, nil)
	})
	t.Run("Encrypted", func(t *testing.T) {
		var key [32]byte
		for i := range key {
			key[i] = byte(i + 1)
		}
		testRecovery_CrashConsistency(t, key[:])
	})
}

func testRecovery_CrashConsistency(t *testing.T, key []byte) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_crash_consistency_store"

	// Model mapping key -> expected payload value
	model := make(map[string]string)

	// Cycle 1: Open fresh store, put initial keys and a large multi-block object, checkpoint
	store, err := openStoreOnFaultFS(faultFS, dir, key, WithCreate())
	if err != nil {
		t.Fatalf("Cycle 1 Open failed: %v", err)
	}

	largeVal := bytes.Repeat([]byte("large-payload-bytes-"), 500) // ~10 KB
	_ = store.Put("ConfigMap", "key1", []byte("val1-initial"))
	model["key1"] = "val1-initial"

	_ = store.Put("ConfigMap", "key2", []byte("val2-initial"))
	model["key2"] = "val2-initial"

	_ = store.Put("ConfigMap", "key-large", largeVal)
	model["key-large"] = string(largeVal)

	chk1, err := store.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint 1 failed: %v", err)
	}

	// Update key1 and put key3
	_ = store.Put("ConfigMap", "key1", []byte("val1-updated"))
	model["key1"] = "val1-updated"

	_ = store.Put("ConfigMap", "key3", []byte("val3-initial"))
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
	_ = store.Put("ConfigMap", "key4", []byte("val4-uncheckpointed"))
	model["key4"] = "val4-uncheckpointed"
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Simulate crash with tearing of un-fsynced writes
	// Abandon the crashed engine without calling Close() so that nothing is written after the crash.
	if err := faultFS.Crash(false, 0.5); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Cycle 2: Reopen store and verify full contents against model
	faultFS2 := NewFaultFS(memFS)
	store2, err := openStoreOnFaultFS(faultFS2, dir, key)
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

	_ = store2.Put("ConfigMap", "key2", []byte("val2-cycle2"))
	model["key2"] = "val2-cycle2"

	_ = store2.Put("ConfigMap", "key5", []byte("val5-cycle2"))
	model["key5"] = "val5-cycle2"

	_, err = store2.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint 3 failed: %v", err)
	}

	// Crash again with drop of unsynced writes (power loss simulation)
	// Abandon the crashed engine without calling Close() so that nothing is written after the crash.
	if err := faultFS2.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Cycle 3: Reopen store again and verify full contents against updated model
	faultFS3 := NewFaultFS(memFS)
	store3, err := openStoreOnFaultFS(faultFS3, dir, key)
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

	_ = store.Put("ConfigMap", "k1", []byte("v1"))
	_ = store.Put("ConfigMap", "k2", []byte("v2"))
	chkLSN, _ := store.Checkpoint()
	_ = store.Close()

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen Open failed: %v", err)
	}
	defer store2.Close()

	// First Put after reopen must NOT fail with "segment already used" and must have LSN > chkLSN
	if err := store2.Put("ConfigMap", "k3", []byte("v3")); err != nil {
		t.Fatalf("first Put after reopen failed: %v", err)
	}

	store2.keyMu.RLock()
	entryK3 := store2.keyIndex[qualifyKey("ConfigMap", "k3")]
	store2.keyMu.RUnlock()

	if entryK3.LSN <= chkLSN {
		t.Fatalf("LSN went backwards after reopen: k3 LSN=%d <= checkpoint LSN=%d", entryK3.LSN, chkLSN)
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
	_ = store.Put("ConfigMap", "key-redo-1", []byte("payload-redo-1"))
	_ = store.Put("ConfigMap", "key-redo-2", []byte("payload-redo-2"))

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

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 1, Key: "target-key", Payload: []byte("older-val")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := wal.Append(Record{Type: RecordTypePut, LSN: 2, Key: "target-key", Payload: []byte("newer-val")}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	heapFile, err := faultFS.Create("heap.db")
	if err != nil {
		t.Fatalf("Create heap.db failed: %v", err)
	}
	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{NumPoolBlocks: 16})

	// Page 1: holds key at LSN 1
	h1, err := bp.AllocateNewPage(1, 1, 1)
	if err != nil {
		t.Fatalf("AllocateNewPage 1 failed: %v", err)
	}
	s1, err := WrapSlottedPage(h1.Block(0))
	if err != nil {
		t.Fatalf("WrapSlottedPage 1 failed: %v", err)
	}
	if _, err := s1.Put("target-key", []byte("older-val"), 1); err != nil {
		t.Fatalf("Put target-key older failed: %v", err)
	}
	s1.Finalize()
	h1.Unpin()
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage(1) failed: %v", err)
	}

	// Page 2: holds key at LSN 2 (newer!)
	h2, err := bp.AllocateNewPage(2, 1, 2)
	if err != nil {
		t.Fatalf("AllocateNewPage 2 failed: %v", err)
	}
	s2, err := WrapSlottedPage(h2.Block(0))
	if err != nil {
		t.Fatalf("WrapSlottedPage 2 failed: %v", err)
	}
	if _, err := s2.Put("target-key", []byte("newer-val"), 2); err != nil {
		t.Fatalf("Put target-key newer failed: %v", err)
	}
	s2.Finalize()
	h2.Unpin()
	if err := bp.FlushPage(2); err != nil {
		t.Fatalf("FlushPage(2) failed: %v", err)
	}

	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := bp.Close(); err != nil {
		t.Fatalf("bp.Close failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("heapFile.Close failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("wal.Close failed: %v", err)
	}

	reopenedHeap, err := faultFS.OpenFile("heap.db", 0, 0)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	defer func() {
		if err := reopenedHeap.Close(); err != nil {
			t.Errorf("Close reopenedHeap failed: %v", err)
		}
	}()

	res, err := Recover(faultFS, reopenedHeap, ".", "wal_dir", dbID, RecoveryOptions{})
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	entry, exists := res.KeyIndex["target-key"]
	if !exists {
		t.Fatalf("target-key missing from recovered index")
	}
	if entry.LSN != 2 {
		t.Fatalf("recovery chose stale LSN %d instead of highest LSN 2", entry.LSN)
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
	_ = store.Put("ConfigMap", "dummy-0", bytes.Repeat([]byte("0"), 3000))
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 0 failed: %v", err)
	}

	// Step 2: Occupy block 1
	_ = store.Put("ConfigMap", "dummy-1", bytes.Repeat([]byte("1"), 3000))
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 1 failed: %v", err)
	}

	// Step 3: Put key1 v1 (small payload) -> goes to page 3, gets block 2
	if err := store.Put("ConfigMap", "key1", []byte("val1-v1")); err != nil {
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
	_ = store.Put("ConfigMap", "dummy-3", bytes.Repeat([]byte("3"), 3000))
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint dummy 3 failed: %v", err)
	}

	// Step 5: Update key1 v2 (small payload, fits in same page 3).
	// When checkpointed, page 3 is written to block 4. Block 2 is freed!
	if err := store.Put("ConfigMap", "key1", []byte("val1-v2")); err != nil {
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
	_ = store.Put("ConfigMap", "dummy-1", bytes.Repeat([]byte("x"), 3000))
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
	lsnNew := store.wal.NextLSN()
	if err := store.wal.Append(Record{Type: RecordTypePut, LSN: lsnNew, Key: "new-key", Payload: []byte("new-val")}); err != nil {
		t.Fatalf("Append new-key failed: %v", err)
	}
	hNew, err := store.bp.AllocateNewPage(entryK1.LogicalPage, 1, lsnNew)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	hNew.Unpin()

	// Step 9: Allocate a new page (filler) and flush it to disk.
	// On main, AllocateNewPage freed durLoc (block 1), so filler page gets block 1 and overwrites it.
	lsnFiller := store.wal.NextLSN()
	if err := store.wal.Append(Record{Type: RecordTypePut, LSN: lsnFiller, Key: "filler", Payload: []byte("filler-val")}); err != nil {
		t.Fatalf("Append filler failed: %v", err)
	}
	hFiller, err := store.bp.AllocateNewPage(99, 1, lsnFiller)
	if err != nil {
		t.Fatalf("AllocateNewPage 99 failed: %v", err)
	}
	spFiller, err := WrapSlottedPage(hFiller.Block(0))
	if err != nil {
		t.Fatalf("WrapSlottedPage failed: %v", err)
	}
	if _, err := spFiller.Put("filler", []byte("filler-val"), lsnFiller); err != nil {
		t.Fatalf("spFiller.Put failed: %v", err)
	}
	spFiller.Finalize()
	hFiller.Unpin()
	store.bp.MarkDirty(99, lsnFiller)
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
	if err := store.heapFile.Sync(); err != nil {
		t.Fatalf("store.heapFile.Sync failed: %v", err)
	}

	// Step 10: Simulate crash BEFORE the page's new incarnation is flushed/fsynced
	close(store.bp.bgStop)
	<-store.bp.bgDone
	if err := store.heapFile.Close(); err != nil {
		t.Fatalf("store.heapFile.Close failed: %v", err)
	}
	if err := store.wal.Close(); err != nil {
		t.Fatalf("store.wal.Close failed: %v", err)
	}

	// Step 11: Reopen store after crash
	store2, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

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

	wal, err := OpenWAL(memFS, "wal", dbID, 0, WALOptions{})
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

	_, err = Recover(memFS, trackingHeap, ".", "wal", dbID, RecoveryOptions{})
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if trackingHeap.reusedBeforeSync {
		t.Fatalf("Reuse Rule violation: superseded physical block %d was reused/overwritten before heapFile.Sync()", initialBlock)
	}
}

func setupDeletedOversizeStore(t *testing.T, dir string) (*MemFS, string, []byte, [16]byte) {
	t.Helper()
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	oversizeVal := make([]byte, 2100*1024)
	if err := store.Put("ConfigMap", "largeKey", oversizeVal); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}
	for i := 2; i <= 5; i++ {
		if err := store.Put("ConfigMap", fmt.Sprintf("k%d", i), []byte("v")); err != nil {
			t.Fatalf("Put pad failed: %v", err)
		}
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	qKey := qualifyKey("ConfigMap", "largeKey")
	fileName := store.keyIndex[qKey].OversizeFileName
	oversizePath := filepath.Join(dir, "oversize", fileName)

	memFS.mu.RLock()
	oversizeData := append([]byte(nil), memFS.files[oversizePath]...)
	memFS.mu.RUnlock()

	dbID := store.dbID
	if err := store.Delete("ConfigMap", "largeKey"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	return memFS, oversizePath, oversizeData, dbID
}

func TestRegression_OversizeNoResurrectionAcrossCheckpointTruncation(t *testing.T) {
	const dir = "test_oversize_no_resurrect"
	memFS, oversizePath, oversizeData, _ := setupDeletedOversizeStore(t, dir)

	// Restore oversize file to simulate crash after Delete WAL record but before unlink.
	memFS.mu.Lock()
	memFS.files[oversizePath] = oversizeData
	memFS.mu.Unlock()

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("Close failed: %v", closeErr)
		}
	})

	if _, exists, err := store.Get("ConfigMap", "largeKey"); err != nil || exists {
		t.Fatalf("deleted oversize key resurrected after recovery (exists=%v, err=%v)", exists, err)
	}
}

func setupWALSegments(t *testing.T, dir string, numSegs int) (FS, []string) {
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	dbID := store.DBID()
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	walDir := filepath.Join(dir, "wal")
	entries, err := memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, entry := range entries {
		if err := memFS.Remove(filepath.Join(walDir, entry.Name())); err != nil {
			t.Fatalf("Remove failed: %v", err)
		}
	}

	wal, err := OpenWAL(memFS, walDir, dbID, 0, WALOptions{MaxSegmentSize: 80})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	for i := 1; i <= numSegs; i++ {
		record := Record{
			Type:    RecordTypePut,
			LSN:     uint64(i),
			Key:     qualifyKey("ConfigMap", fmt.Sprintf("k%d", i)),
			Payload: append([]byte{byte(CodecNone)}, fmt.Sprintf("val%d", i)...),
		}
		if err := wal.Append(record); err != nil {
			t.Fatalf("Append record %d failed: %v", i, err)
		}
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	entries, err = memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	var paths []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".wal") {
			paths = append(paths, filepath.Join(walDir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) != numSegs {
		t.Fatalf("expected %d segments, got %d", numSegs, len(paths))
	}
	return memFS, paths
}

func TestRecovery_WALCorruptFirstSegment_FailsOpen(t *testing.T) {
	fs, paths := setupWALSegments(t, "test_wal_corrupt_first", 3)
	file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var byteBuffer [1]byte
	if _, err := file.ReadAt(byteBuffer[:], 40); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	byteBuffer[0] ^= 0xff
	if _, err := file.WriteAt(byteBuffer[:], 40); err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = Open(WithFS(fs), WithDir("test_wal_corrupt_first"))
	if !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("expected ErrCorruptWAL, got: %v", err)
	}
}

func TestRecovery_WALTornTailLastSegment_SucceedsOpen(t *testing.T) {
	dir := "test_wal_torn_tail_last"
	fs, paths := setupWALSegments(t, dir, 1)
	file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	size, err := file.Size()
	if err != nil {
		t.Fatalf("Size failed: %v", err)
	}
	tornHeader := []byte{RecordMagic, RecordFormatVersion, byte(RecordTypePut), 0, 0, 0, 0, 10}
	if _, err := file.WriteAt(tornHeader, size); err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	store, err := Open(WithFS(fs), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	val, ok, err := store.Get("ConfigMap", "k1")
	if err != nil || !ok || string(val) != "val1" {
		t.Fatalf("Get k1 mismatch: ok=%v, val=%q, err=%v", ok, string(val), err)
	}
}

func TestRecovery_WALSegmentGap_FailsOpen(t *testing.T) {
	dir := "test_wal_segment_gap"
	fs, paths := setupWALSegments(t, dir, 2)
	gapPath := filepath.Join(filepath.Dir(paths[1]), fmt.Sprintf("%020d.wal", 5))
	if err := fs.Rename(paths[1], gapPath); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	_, err := Open(WithFS(fs), WithDir(dir))
	if !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("expected ErrCorruptWAL, got: %v", err)
	}
}

func TestRecovery_WALCrashAfterRotation_EmptySegment_SucceedsOpen(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_wal_crash_after_rotation"
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("ConfigMap", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// store.Put used LSN 1, Close checkpointed at LSN 2; the next segment file starts at LSN 3.
	nextSeg := filepath.Join(dir, "wal", segmentFileName(3))
	file, err := memFS.Create(nextSeg)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	store2, err := Open(WithFS(memFS), WithDir(dir), WithEraseOnError())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	if store2.Wiped() {
		t.Fatalf("expected store not to be wiped")
	}
	val, ok, err := store2.Get("ConfigMap", "k1")
	if err != nil || !ok || string(val) != "val1" {
		t.Fatalf("Get k1 mismatch: ok=%v, val=%q, err=%v", ok, string(val), err)
	}
}

func TestRecovery_WALRecordLengthExceedsSegment_NoAllocation(t *testing.T) {
	const excessiveLen = 40 * 1024 * 1024 // 40 MiB; passes MaxRecordFieldLength (64 MiB)

	makeHeader := func(lsn uint64) []byte {
		hdr := make([]byte, RecordHeaderSize)
		hdr[0] = RecordMagic
		hdr[1] = RecordFormatVersion
		hdr[2] = byte(RecordTypePut)
		hdr[3] = 0
		binary.BigEndian.PutUint64(hdr[4:12], lsn)
		binary.BigEndian.PutUint64(hdr[12:20], 0)
		binary.BigEndian.PutUint32(hdr[20:24], 0)
		binary.BigEndian.PutUint32(hdr[24:28], uint32(excessiveLen))
		return hdr
	}

	t.Run("earlier segment", func(t *testing.T) {
		dir := "test_wal_record_exceeds_segment_earlier"
		fs, paths := setupWALSegments(t, dir, 2)

		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		size, err := file.Size()
		if err != nil {
			t.Fatalf("Size failed: %v", err)
		}
		if _, err := file.WriteAt(makeHeader(2), size); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		runtime.GC()
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)

		_, err = Open(WithFS(fs), WithDir(dir))

		runtime.ReadMemStats(&memAfter)
		alloc := memAfter.TotalAlloc - memBefore.TotalAlloc

		if !errors.Is(err, ErrCorruptWAL) {
			t.Fatalf("expected ErrCorruptWAL, got: %v", err)
		}
		if alloc >= excessiveLen {
			t.Fatalf("recovery allocated %d bytes (>= %d), expected no buffer of that length", alloc, excessiveLen)
		}
	})

	t.Run("last segment", func(t *testing.T) {
		dir := "test_wal_record_exceeds_segment_last"
		fs, paths := setupWALSegments(t, dir, 1)

		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		size, err := file.Size()
		if err != nil {
			t.Fatalf("Size failed: %v", err)
		}
		if _, err := file.WriteAt(makeHeader(2), size); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		runtime.GC()
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)

		store, err := Open(WithFS(fs), WithDir(dir))

		runtime.ReadMemStats(&memAfter)
		alloc := memAfter.TotalAlloc - memBefore.TotalAlloc

		if err != nil {
			t.Fatalf("expected Open to succeed, got: %v", err)
		}
		defer store.Close()

		val, ok, err := store.Get("ConfigMap", "k1")
		if err != nil || !ok || string(val) != "val1" {
			t.Fatalf("Get k1 mismatch: ok=%v, val=%q, err=%v", ok, string(val), err)
		}
		if alloc >= excessiveLen {
			t.Fatalf("recovery allocated %d bytes (>= %d), expected no buffer of that length", alloc, excessiveLen)
		}
	})
}

func TestRecovery_WALCorruptBelowHeapLSN_FailsOpen(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_wal_corrupt_below_heap"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("ConfigMap", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Corrupt record 1 in the last segment below the heap page LSN.
	segPath := filepath.Join(dir, "wal", segmentFileName(1))
	file, err := memFS.OpenFile(segPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var b [1]byte
	if _, err := file.ReadAt(b[:], int64(SegmentHeaderSize+10)); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("ReadAt failed: %v (file.Close also failed: %v)", err, closeErr)
		}
		t.Fatalf("ReadAt failed: %v", err)
	}
	b[0] ^= 0xff
	if _, err := file.WriteAt(b[:], int64(SegmentHeaderSize+10)); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("WriteAt failed: %v (file.Close also failed: %v)", err, closeErr)
		}
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err == nil {
		if closeErr := store2.Close(); closeErr != nil {
			t.Fatalf("expected ErrCorruptWAL, got nil error; Close also failed: %v", closeErr)
		}
		t.Fatalf("expected ErrCorruptWAL, got nil error")
	}
	if !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("expected ErrCorruptWAL, got: %v", err)
	}
}

func TestRecovery_WALTornTailAboveHeapLSN_SucceedsOpen(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_wal_torn_tail_above_heap"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("ConfigMap", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	// Write k2 (LSN > heap LSN) and sync to WAL
	if err := store.Put("ConfigMap", "k2", []byte("val2")); err != nil {
		t.Fatalf("Put k2 failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Simulate crash and abandon the engine without closing it
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Append torn tail to the last WAL segment above the heap page LSN
	segPath := filepath.Join(dir, "wal", segmentFileName(1))
	file, err := memFS.OpenFile(segPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	size, err := file.Size()
	if err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("Size failed: %v (file.Close also failed: %v)", err, closeErr)
		}
		t.Fatalf("Size failed: %v", err)
	}
	tornHeader := []byte{RecordMagic, RecordFormatVersion, byte(RecordTypePut), 0, 0, 0, 0, 10}
	if _, err := file.WriteAt(tornHeader, size); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("WriteAt failed: %v (file.Close also failed: %v)", err, closeErr)
		}
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := file.Sync(); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("Sync failed: %v (file.Close also failed: %v)", err, closeErr)
		}
		t.Fatalf("Sync failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	store2, err := Open(WithFS(NewFaultFS(memFS)), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	val1, ok1, err := store2.Get("ConfigMap", "k1")
	if err != nil || !ok1 || string(val1) != "val1" {
		t.Fatalf("Get k1 mismatch: ok=%v, val=%q, err=%v", ok1, string(val1), err)
	}
	val2, ok2, err := store2.Get("ConfigMap", "k2")
	if err != nil || !ok2 || string(val2) != "val2" {
		t.Fatalf("Get k2 mismatch: ok=%v, val=%q, err=%v", ok2, string(val2), err)
	}
}

// TestRecovery_UncheckpointedMixReopenTwice tests crashing after a mix of puts, replacements
// and deletes with a checkpoint partway and uncheckpointed writes at the end, reopening to
// compare every key, crashing again straight after the first reopen without calling Close()
// to verify stricter non-checkpointed recovery, and reopening a second time.
func TestRecovery_UncheckpointedMixReopenTwice(t *testing.T) {
	t.Run("Unencrypted", func(t *testing.T) {
		testRecovery_UncheckpointedMixReopenTwice(t, nil)
	})
	t.Run("Encrypted", func(t *testing.T) {
		var key [32]byte
		for i := range key {
			key[i] = byte(i + 42)
		}
		testRecovery_UncheckpointedMixReopenTwice(t, key[:])
	})
}

func testRecovery_UncheckpointedMixReopenTwice(t *testing.T, key []byte) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_uncheckpointed_mix_reopen_twice"

	store, err := openStoreOnFaultFS(faultFS, dir, key, WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	expected := make(map[string][]byte)
	var deletedKeys []string

	// Phase 1: Writes before a checkpoint partway through the workload.
	kPre1 := "pre-chk-slotted-1"
	vPre1 := []byte("val-pre-chk-1")
	if err := store.Put(table, kPre1, vPre1); err != nil {
		t.Fatalf("Put kPre1 failed: %v", err)
	}

	kPre2 := "pre-chk-slotted-2"
	vPre2 := []byte("val-pre-chk-2")
	if err := store.Put(table, kPre2, vPre2); err != nil {
		t.Fatalf("Put kPre2 failed: %v", err)
	}

	kPreMB := "pre-chk-mb"
	vPreMB := bytes.Repeat([]byte("val-pre-chk-mb-"), 500)
	if err := store.Put(table, kPreMB, vPreMB); err != nil {
		t.Fatalf("Put kPreMB failed: %v", err)
	}

	kPreDel := "pre-chk-del"
	vPreDel := []byte("val-pre-chk-del")
	if err := store.Put(table, kPreDel, vPreDel); err != nil {
		t.Fatalf("Put kPreDel failed: %v", err)
	}

	// Checkpoint partway through the workload (truncates WAL prior to checkpoint redo start).
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	// Phase 2: Post-checkpoint mix of puts, replacements (both pre- and post-checkpoint keys),
	// and deletes (both pre- and post-checkpoint keys).

	// Replace pre-checkpoint key kPre1 with new slotted value
	vPre1Replaced := []byte("val-pre-chk-1-replaced")
	if err := store.Put(table, kPre1, vPre1Replaced); err != nil {
		t.Fatalf("Put kPre1 replaced failed: %v", err)
	}
	expected[kPre1] = vPre1Replaced

	// Replace pre-checkpoint key kPre2 with multi-block value
	vPre2MB := bytes.Repeat([]byte("val-pre-chk-2-now-mb-"), 550)
	if err := store.Put(table, kPre2, vPre2MB); err != nil {
		t.Fatalf("Put kPre2 MB replaced failed: %v", err)
	}
	expected[kPre2] = vPre2MB

	// Keep pre-checkpoint multi-block key kPreMB intact
	expected[kPreMB] = vPreMB

	// Delete pre-checkpoint key kPreDel after the checkpoint
	if err := store.Delete(table, kPreDel); err != nil {
		t.Fatalf("Delete kPreDel failed: %v", err)
	}
	deletedKeys = append(deletedKeys, kPreDel)

	// Post-checkpoint new slotted put
	k1 := "slotted-1"
	v1 := []byte("val-slotted-1")
	if err := store.Put(table, k1, v1); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}
	expected[k1] = v1

	// Post-checkpoint slotted put that will be replaced by another slotted value
	k2 := "slotted-replace"
	v2Initial := []byte("val-slotted-2-initial")
	if err := store.Put(table, k2, v2Initial); err != nil {
		t.Fatalf("Put k2 initial failed: %v", err)
	}
	v2Replaced := []byte("val-slotted-2-replaced")
	if err := store.Put(table, k2, v2Replaced); err != nil {
		t.Fatalf("Put k2 replaced failed: %v", err)
	}
	expected[k2] = v2Replaced

	// Post-checkpoint multi-block put (~10KB)
	kMB := "mb-key"
	vMB := bytes.Repeat([]byte("mb-payload-data-"), 600)
	if err := store.Put(table, kMB, vMB); err != nil {
		t.Fatalf("Put mb failed: %v", err)
	}
	expected[kMB] = vMB

	// Post-checkpoint multi-block put replaced by slotted value
	kMBToSlot := "mb-to-slot"
	vMBInitial := bytes.Repeat([]byte("mb-initial-bytes-"), 500)
	if err := store.Put(table, kMBToSlot, vMBInitial); err != nil {
		t.Fatalf("Put mb-to-slot initial failed: %v", err)
	}
	vMBSlotted := []byte("mb-now-slotted-val")
	if err := store.Put(table, kMBToSlot, vMBSlotted); err != nil {
		t.Fatalf("Put mb-to-slot replaced failed: %v", err)
	}
	expected[kMBToSlot] = vMBSlotted

	// Post-checkpoint slotted put replaced by multi-block value
	kSlotToMB := "slot-to-mb"
	vSlotInitial := []byte("slot-initial-val")
	if err := store.Put(table, kSlotToMB, vSlotInitial); err != nil {
		t.Fatalf("Put slot-to-mb initial failed: %v", err)
	}
	vSlotMB := bytes.Repeat([]byte("slot-now-mb-val-"), 550)
	if err := store.Put(table, kSlotToMB, vSlotMB); err != nil {
		t.Fatalf("Put slot-to-mb replaced failed: %v", err)
	}
	expected[kSlotToMB] = vSlotMB

	// Post-checkpoint oversize put (~2.1 MB)
	kOver := "oversize-key"
	vOver := append([]byte("oversize-payload-data"), make([]byte, 2100*1024)...)
	if err := store.Put(table, kOver, vOver); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}
	expected[kOver] = vOver

	// Post-checkpoint oversize put replaced by slotted value
	kOverToSlot := "oversize-to-slot"
	vOverInitial := append([]byte("oversize-initial-data"), make([]byte, 2100*1024)...)
	if err := store.Put(table, kOverToSlot, vOverInitial); err != nil {
		t.Fatalf("Put oversize-to-slot initial failed: %v", err)
	}
	vOverSlotted := []byte("oversize-now-slotted-val")
	if err := store.Put(table, kOverToSlot, vOverSlotted); err != nil {
		t.Fatalf("Put oversize-to-slot replaced failed: %v", err)
	}
	expected[kOverToSlot] = vOverSlotted

	// Post-checkpoint deletes:
	// Delete slotted key
	kDelSlot := "delete-slotted"
	if err := store.Put(table, kDelSlot, []byte("will-be-deleted-slot")); err != nil {
		t.Fatalf("Put delete-slotted failed: %v", err)
	}
	if err := store.Delete(table, kDelSlot); err != nil {
		t.Fatalf("Delete slotted failed: %v", err)
	}
	deletedKeys = append(deletedKeys, kDelSlot)

	// Delete multi-block key
	kDelMB := "delete-mb"
	if err := store.Put(table, kDelMB, bytes.Repeat([]byte("del-mb-bytes-"), 500)); err != nil {
		t.Fatalf("Put delete-mb failed: %v", err)
	}
	if err := store.Delete(table, kDelMB); err != nil {
		t.Fatalf("Delete mb failed: %v", err)
	}
	deletedKeys = append(deletedKeys, kDelMB)

	// Delete oversize key
	kDelOver := "delete-oversize"
	vDelOver := append([]byte("del-oversize-bytes"), make([]byte, 2100*1024)...)
	if err := store.Put(table, kDelOver, vDelOver); err != nil {
		t.Fatalf("Put delete-oversize failed: %v", err)
	}
	if err := store.Delete(table, kDelOver); err != nil {
		t.Fatalf("Delete oversize failed: %v", err)
	}
	deletedKeys = append(deletedKeys, kDelOver)

	// Delete non-existent key
	kDelNonExistent := "never-existed-key"
	if err := store.Delete(table, kDelNonExistent); err != nil {
		t.Fatalf("Delete non-existent failed: %v", err)
	}
	deletedKeys = append(deletedKeys, kDelNonExistent)

	// Fsync WAL so write records are durable, without taking any checkpoint.
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Simulate crash: drop un-fsynced heap page buffers, abandon engine without calling Close()
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	compareKeys := func(s *Engine, reopenName string) {
		t.Helper()
		for k, wantVal := range expected {
			gotVal, exists, err := s.Get(table, k)
			if err != nil {
				t.Fatalf("[%s] Get(%q) returned error: %v", reopenName, k, err)
			}
			if !exists {
				t.Fatalf("[%s] Get(%q) missing key", reopenName, k)
			}
			if !bytes.Equal(gotVal, wantVal) {
				t.Fatalf("[%s] Get(%q) payload mismatch: got len=%d, want len=%d", reopenName, k, len(gotVal), len(wantVal))
			}
		}
		for _, k := range deletedKeys {
			_, exists, err := s.Get(table, k)
			if err != nil {
				t.Fatalf("[%s] Get(%q) deleted key returned error: %v", reopenName, k, err)
			}
			if exists {
				t.Fatalf("[%s] deleted key %q resurrected", reopenName, k)
			}
		}
	}

	// Reopen 1: replays WAL from redo start LSN through apply functions, then flushes pages.
	faultFS2 := NewFaultFS(memFS)
	store2, err := openStoreOnFaultFS(faultFS2, dir, key, WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 1 failed: %v", err)
	}

	compareKeys(store2, "reopen 1")

	// Crash again straight after the first reopen without calling Close() (which would checkpoint).
	// This verifies the stricter case that the flush after replay made pages durable and
	// reopening without writing still preserves all expected keys and tombstoned deletions.
	if err := faultFS2.Crash(true, 0); err != nil {
		t.Fatalf("Crash after reopen 1 failed: %v", err)
	}

	// Reopen 2: reopen without any new writes following the crash.
	faultFS3 := NewFaultFS(memFS)
	store3, err := openStoreOnFaultFS(faultFS3, dir, key, WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 2 failed: %v", err)
	}

	compareKeys(store3, "reopen 2 (post-crash)")

	// After the replaying reopen, write more records, Sync, crash, reopen, Close, and reopen again.
	// On main with its separate redo replay code, a deleted key would resurrect after this sequence.
	kPostReopen1 := "post-reopen-slotted"
	vPostReopen1 := []byte("val-post-reopen-1")
	if err := store3.Put(table, kPostReopen1, vPostReopen1); err != nil {
		t.Fatalf("Put post-reopen 1 failed: %v", err)
	}
	expected[kPostReopen1] = vPostReopen1

	kPostReopenMB := "post-reopen-mb"
	vPostReopenMB := bytes.Repeat([]byte("val-post-reopen-mb-"), 500)
	if err := store3.Put(table, kPostReopenMB, vPostReopenMB); err != nil {
		t.Fatalf("Put post-reopen mb failed: %v", err)
	}
	expected[kPostReopenMB] = vPostReopenMB

	if err := store3.Sync(); err != nil {
		t.Fatalf("Sync on store3 failed: %v", err)
	}

	if err := faultFS3.Crash(true, 0); err != nil {
		t.Fatalf("Crash on store3 failed: %v", err)
	}

	faultFS4 := NewFaultFS(memFS)
	store4, err := openStoreOnFaultFS(faultFS4, dir, key, WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 3 failed: %v", err)
	}

	if err := store4.Close(); err != nil {
		t.Fatalf("store4.Close failed: %v", err)
	}

	faultFS5 := NewFaultFS(memFS)
	store5, err := openStoreOnFaultFS(faultFS5, dir, key, WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 4 failed: %v", err)
	}
	defer func() {
		if err := store5.Close(); err != nil {
			t.Errorf("store5.Close failed: %v", err)
		}
	}()

	// Assert after the last reopen that every expected key matches and every deleted key is absent.
	compareKeys(store5, "final reopen (post-checkpoint)")
}

// TestRecovery_ReplayHeapWriteFailure_NoMarkerAndSucceedsOnReopen verifies that a heap write error
// during WAL replay fails Open without writing a permanent failure marker, and that a subsequent
// Open on a healthy filesystem succeeds and recovers all keys.
func TestRecovery_ReplayHeapWriteFailure_NoMarkerAndSucceedsOnReopen(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_replay_heap_write_failure"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	expected := map[string][]byte{
		"k1":        []byte("val1-initial"),
		"k2":        bytes.Repeat([]byte("val2-mb-"), 500),
		"oversize1": append([]byte("val-over-"), make([]byte, 2100*1024)...),
	}
	for k, v := range expected {
		if err := store.Put(table, k, v); err != nil {
			t.Fatalf("Put %s failed: %v", k, err)
		}
	}

	// Sync WAL without checkpointing so records require replay on recovery.
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Crash to drop un-fsynced heap page buffers.
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Create a new filesystem instance representing the rebooted system with an injected write error
	// so the heap write during replay flush fails.
	faultFS2 := NewFaultFS(memFS)
	injectedErr := errors.New("simulated disk write failure during heap flush")
	faultFS2.SetWriteError(injectedErr)

	// Reopen must fail due to the write error during replay/flush.
	storeFail, err := Open(WithFS(faultFS2), WithDir(dir), WithCompressionCodec(CodecNone))
	if err == nil {
		_ = storeFail.Close()
		t.Fatalf("expected Open to fail due to injected write error, got nil")
	}

	// Crucially, the failed replay must NOT write a failure marker (FAILED).
	failureMarkerPath := filepath.Join(dir, "FAILED")
	if mf, statErr := memFS.Open(failureMarkerPath); statErr == nil {
		_ = mf.Close()
		t.Fatalf("failure marker %s was written during replay failure; should not be present", failureMarkerPath)
	}

	// Reopen on a healthy filesystem (without write errors) must succeed and recover all keys.
	faultFS3 := NewFaultFS(memFS)
	storeRecovered, err := Open(WithFS(faultFS3), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen on healthy filesystem failed: %v", err)
	}
	defer func() {
		if err := storeRecovered.Close(); err != nil {
			t.Errorf("storeRecovered.Close failed: %v", err)
		}
	}()

	for k, wantVal := range expected {
		gotVal, exists, err := storeRecovered.Get(table, k)
		if err != nil {
			t.Fatalf("Get(%q) returned error: %v", k, err)
		}
		if !exists {
			t.Fatalf("Get(%q) missing key after recovery", k)
		}
		if !bytes.Equal(gotVal, wantVal) {
			t.Fatalf("Get(%q) value mismatch: got len=%d, want len=%d", k, len(gotVal), len(wantVal))
		}
	}
}

// TestRecovery_WALRecordEndingAtBlockBoundary_ReopenSucceeds checks that recovery succeeds
// when the last WAL record ends exactly on a block boundary, so the scan reads at an offset
// equal to the file size.
func TestRecovery_WALRecordEndingAtBlockBoundary_ReopenSucceeds(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_wal_record_block_boundary"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"

	// Workload of puts, replacements, and deletes with no checkpoint
	if err := store.Put(table, "key1", []byte("val1-initial")); err != nil {
		t.Fatalf("Put key1 failed: %v", err)
	}
	if err := store.Put(table, "key2", []byte("val2-delete-me")); err != nil {
		t.Fatalf("Put key2 failed: %v", err)
	}
	if err := store.Delete(table, "key2"); err != nil {
		t.Fatalf("Delete key2 failed: %v", err)
	}
	if err := store.Put(table, "key1", []byte("val1-replacement")); err != nil {
		t.Fatalf("Replacement Put key1 failed: %v", err)
	}

	// Calculate payload for a final Put so that wal.appendOff lands exactly on a 4 KiB block boundary.
	store.wal.mu.Lock()
	currentOffset := store.wal.appendOff
	store.wal.mu.Unlock()

	finalKey := "key-boundary"
	qualifiedFinalKey := qualifyKey(table, finalKey)
	recordOverhead := int64(RecordHeaderSize + len(qualifiedFinalKey) + 1) // +1 for CodecNone compression header
	remainder := int64(WALBlockSize) - ((currentOffset + recordOverhead) % int64(WALBlockSize))
	finalPayloadLen := remainder
	finalPayload := bytes.Repeat([]byte("z"), int(finalPayloadLen))

	if err := store.Put(table, finalKey, finalPayload); err != nil {
		t.Fatalf("Put finalKey failed: %v", err)
	}

	// Verify that appendOff is on an exact block boundary
	store.wal.mu.Lock()
	appendOffset := store.wal.appendOff
	store.wal.mu.Unlock()
	if appendOffset%int64(WALBlockSize) != 0 {
		t.Fatalf("expected appendOff to be a multiple of %d, got %d", WALBlockSize, appendOffset)
	}

	// Sync ensures all WAL records are durable. Because appendOff is on a block boundary,
	// no zero-padding is appended and the segment size on disk is exactly appendOff.
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	walFile, err := memFS.Open(filepath.Join(dir, "wal", segmentFileName(1)))
	if err != nil {
		t.Fatalf("Open wal segment failed: %v", err)
	}
	segmentSize, err := walFile.Size()
	walFile.Close()
	if err != nil || segmentSize != appendOffset {
		t.Fatalf("expected segment size %d, got %d (err: %v)", appendOffset, segmentSize, err)
	}

	// Simulate crash without clean close
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Reopen with fresh FaultFS: WAL scan reads at offset == fileSize (appendOffset)
	faultFS2 := NewFaultFS(memFS)
	store2, err := Open(WithFS(faultFS2), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open after crash failed: %v", err)
	}
	defer store2.Close()

	// Verify data integrity
	value1, exists, err := store2.Get(table, "key1")
	if err != nil || !exists || !bytes.Equal(value1, []byte("val1-replacement")) {
		t.Fatalf("key1 mismatch: exists=%v, got=%q, err=%v", exists, string(value1), err)
	}

	_, exists, err = store2.Get(table, "key2")
	if err != nil || exists {
		t.Fatalf("expected deleted key2 to not exist, exists=%v, err=%v", exists, err)
	}

	valueFinal, exists, err := store2.Get(table, finalKey)
	if err != nil || !exists || !bytes.Equal(valueFinal, finalPayload) {
		t.Fatalf("finalKey mismatch: exists=%v, len=%d, err=%v", exists, len(valueFinal), err)
	}
}

func TestRecovery_DamagedHeapBlockAfterCleanClose(t *testing.T) {
	t.Run("Unencrypted", func(t *testing.T) {
		testRecovery_DamagedHeapBlockAfterCleanClose(t, nil)
	})
	t.Run("Encrypted", func(t *testing.T) {
		var key [32]byte
		copy(key[:], []byte("damaged-block-test-key-32bytes-0"))
		testRecovery_DamagedHeapBlockAfterCleanClose(t, key[:])
	})
}

func testRecovery_DamagedHeapBlockAfterCleanClose(t *testing.T, key []byte) {
	memFS := NewMemFS()
	dir := "test_damaged_heap_block_clean_close"

	openOptions := func() []Option {
		options := []Option{WithFS(memFS), WithDir(dir)}
		if len(key) > 0 {
			options = append(options, WithEncryptionKey(key))
		}
		return options
	}

	store, err := Open(append(openOptions(), WithCreate())...)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := store.Put("ConfigMap", "key1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Put("ConfigMap", "key2", []byte("val2")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Change one byte in block 0 of heap.db
	heapPath := filepath.Join(dir, "heap.db")
	heapFile, err := memFS.OpenFile(heapPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	var singleByte [1]byte
	if _, err := heapFile.ReadAt(singleByte[:], 100); err != nil {
		t.Fatalf("ReadAt heap.db failed: %v", err)
	}
	singleByte[0] ^= 0xff
	if _, err := heapFile.WriteAt(singleByte[:], 100); err != nil {
		t.Fatalf("WriteAt heap.db failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("Close heap.db failed: %v", err)
	}

	// Reopen must fail and return an error naming damaged heap block 0
	store2, err := Open(openOptions()...)
	if err == nil {
		if closeErr := store2.Close(); closeErr != nil {
			t.Fatalf("Close failed: %v", closeErr)
		}
		t.Fatalf("expected Open to return error on damaged heap block, but succeeded")
	}
	if !errors.Is(err, ErrDamagedBlock) {
		t.Fatalf("expected ErrDamagedBlock, got %v", err)
	}
	if !strings.Contains(err.Error(), "damaged heap block 0") {
		t.Fatalf("expected error to name damaged heap block 0, got %v", err)
	}
}

func TestRecovery_DamagedMultiBlockAfterCleanClose(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_damaged_multi_block_clean_close"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write multi-block object (~10 KB -> spans 4 blocks: 0, 1, 2, 3)
	largePayload := bytes.Repeat([]byte("multi-block-payload-"), 500)
	if err := store.Put("ConfigMap", "large-key", largePayload); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Change one byte in block 2 of heap.db (offset 2 * 4096 + 100)
	heapPath := filepath.Join(dir, "heap.db")
	heapFile, err := memFS.OpenFile(heapPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	var singleByte [1]byte
	corruptOffset := int64(2*BlockSize + 100)
	if _, err := heapFile.ReadAt(singleByte[:], corruptOffset); err != nil {
		t.Fatalf("ReadAt heap.db failed: %v", err)
	}
	singleByte[0] ^= 0xff
	if _, err := heapFile.WriteAt(singleByte[:], corruptOffset); err != nil {
		t.Fatalf("WriteAt heap.db failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("Close heap.db failed: %v", err)
	}

	// Reopen must fail and return an error naming damaged heap block 2
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err == nil {
		if closeErr := store2.Close(); closeErr != nil {
			t.Fatalf("Close failed: %v", closeErr)
		}
		t.Fatalf("expected Open to return error on damaged multi-block, but succeeded")
	}
	if !errors.Is(err, ErrDamagedBlock) {
		t.Fatalf("expected ErrDamagedBlock, got %v", err)
	}
	if !strings.Contains(err.Error(), "damaged heap block 2") {
		t.Fatalf("expected error to name damaged heap block 2, got %v", err)
	}
}

// TestRecovery_DamagedHeapBlockRepeatedOpenReturnsError verifies that when a heap block is damaged
// after a clean close, repeated Open calls return ErrDamagedBlock each time and leave the heap file untouched.
func TestRecovery_DamagedHeapBlockRepeatedOpenReturnsError(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_damaged_heap_block_repeated_open"

	openOptions := func() []Option {
		return []Option{WithFS(memFS), WithDir(dir)}
	}

	store, err := Open(append(openOptions(), WithCreate())...)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := store.Put("ConfigMap", "key1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Change one byte in block 0 of heap.db
	heapPath := filepath.Join(dir, "heap.db")
	heapFile, err := memFS.OpenFile(heapPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile heap.db failed: %v", err)
	}
	var singleByte [1]byte
	if _, err := heapFile.ReadAt(singleByte[:], 100); err != nil {
		t.Fatalf("ReadAt heap.db failed: %v", err)
	}
	singleByte[0] ^= 0xff
	if _, err := heapFile.WriteAt(singleByte[:], 100); err != nil {
		t.Fatalf("WriteAt heap.db failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("Close heap.db failed: %v", err)
	}

	// Snapshot heap file contents after damage
	heapFileAfterDamage, err := memFS.OpenFile(heapPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile heap.db for snapshot failed: %v", err)
	}
	heapSize, err := heapFileAfterDamage.Size()
	if err != nil {
		t.Fatalf("Size heap.db failed: %v", err)
	}
	damagedHeapSnapshot := make([]byte, heapSize)
	if _, err := heapFileAfterDamage.ReadAt(damagedHeapSnapshot, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt heap.db failed: %v", err)
	}
	if err := heapFileAfterDamage.Close(); err != nil {
		t.Fatalf("Close heapFileAfterDamage failed: %v", err)
	}

	// First Open attempt must return ErrDamagedBlock
	store1, err := Open(openOptions()...)
	if err == nil {
		if closeErr := store1.Close(); closeErr != nil {
			t.Fatalf("Close failed: %v", closeErr)
		}
		t.Fatalf("first Open: expected error on damaged heap block, but succeeded")
	}
	if !errors.Is(err, ErrDamagedBlock) {
		t.Fatalf("first Open: expected ErrDamagedBlock, got %v", err)
	}
	if !strings.Contains(err.Error(), "damaged heap block 0") {
		t.Fatalf("first Open: expected error to name damaged heap block 0, got %v", err)
	}

	// Verify heap file is untouched after first failed Open
	heapFileCheck1, err := memFS.OpenFile(heapPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile heap.db check 1 failed: %v", err)
	}
	heapBytesCheck1 := make([]byte, heapSize)
	if _, err := heapFileCheck1.ReadAt(heapBytesCheck1, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt heap.db check 1 failed: %v", err)
	}
	if err := heapFileCheck1.Close(); err != nil {
		t.Fatalf("Close heapFileCheck1 failed: %v", err)
	}
	if !bytes.Equal(heapBytesCheck1, damagedHeapSnapshot) {
		t.Fatalf("heap file was modified after first failed Open")
	}

	// Second Open attempt must also return ErrDamagedBlock and leave heap file untouched
	store2, err := Open(openOptions()...)
	if err == nil {
		if closeErr := store2.Close(); closeErr != nil {
			t.Fatalf("Close failed: %v", closeErr)
		}
		t.Fatalf("second Open: expected error on damaged heap block, but succeeded")
	}
	if !errors.Is(err, ErrDamagedBlock) {
		t.Fatalf("second Open: expected ErrDamagedBlock, got %v", err)
	}
	if !strings.Contains(err.Error(), "damaged heap block 0") {
		t.Fatalf("second Open: expected error to name damaged heap block 0, got %v", err)
	}

	// Verify heap file is still untouched after second failed Open
	heapFileCheck2, err := memFS.OpenFile(heapPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile heap.db check 2 failed: %v", err)
	}
	heapBytesCheck2 := make([]byte, heapSize)
	if _, err := heapFileCheck2.ReadAt(heapBytesCheck2, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt heap.db check 2 failed: %v", err)
	}
	if err := heapFileCheck2.Close(); err != nil {
		t.Fatalf("Close heapFileCheck2 failed: %v", err)
	}
	if !bytes.Equal(heapBytesCheck2, damagedHeapSnapshot) {
		t.Fatalf("heap file was modified after second failed Open")
	}
}

// TestRecovery_CrashTornBlockReopenCleanCloseReopen verifies that after a crash with torn blocks,
// reopening rebuilds the state from the WAL and zeroes the torn blocks so that a subsequent
// clean close and reopen succeeds with every key readable.
func TestRecovery_CrashTornBlockReopenCleanCloseReopen(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		dir := fmt.Sprintf("test_crash_torn_clean_close_%d", iteration)

		store, err := Open(WithFS(faultFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("iteration %d: Open failed: %v", iteration, err)
		}

		if err := store.Put("ConfigMap", "key1", []byte("val1-initial")); err != nil {
			t.Fatalf("iteration %d: Put key1 failed: %v", iteration, err)
		}
		if err := store.Put("ConfigMap", "key2", []byte("val2-initial")); err != nil {
			t.Fatalf("iteration %d: Put key2 failed: %v", iteration, err)
		}
		if _, err := store.Checkpoint(); err != nil {
			t.Fatalf("iteration %d: Checkpoint failed: %v", iteration, err)
		}

		// Write uncheckpointed keys before crash
		if err := store.Put("ConfigMap", "key3", []byte("val3-uncheckpointed")); err != nil {
			t.Fatalf("iteration %d: Put key3 failed: %v", iteration, err)
		}
		if err := store.Sync(); err != nil {
			t.Fatalf("iteration %d: Sync failed: %v", iteration, err)
		}

		// Simulate crash with tearing of un-fsynced writes
		if err := faultFS.Crash(false, 0.5); err != nil {
			t.Fatalf("iteration %d: Crash failed: %v", iteration, err)
		}

		// Reopen 1: crash recovery rebuilds torn blocks from WAL and zeroes torn blocks
		faultFS2 := NewFaultFS(memFS)
		store2, err := Open(WithFS(faultFS2), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("iteration %d: Reopen 1 failed: %v", iteration, err)
		}

		expected := map[string]string{
			"key1": "val1-initial",
			"key2": "val2-initial",
			"key3": "val3-uncheckpointed",
		}
		for key, expectedValue := range expected {
			value, exists, err := store2.Get("ConfigMap", key)
			if err != nil || !exists || string(value) != expectedValue {
				t.Fatalf("iteration %d: Reopen 1 Get(%s) mismatch: exists=%v, value=%q, err=%v", iteration, key, exists, string(value), err)
			}
		}

		// Clean close
		if err := store2.Close(); err != nil {
			t.Fatalf("iteration %d: Clean close failed: %v", iteration, err)
		}

		// Reopen 2: clean close recovery must succeed with every key readable without reporting old torn blocks as damage
		faultFS3 := NewFaultFS(memFS)
		store3, err := Open(WithFS(faultFS3), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("iteration %d: Reopen 2 after clean close failed: %v", iteration, err)
		}

		for key, expectedValue := range expected {
			value, exists, err := store3.Get("ConfigMap", key)
			if err != nil || !exists || string(value) != expectedValue {
				t.Fatalf("iteration %d: Reopen 2 Get(%s) mismatch: exists=%v, value=%q, err=%v", iteration, key, exists, string(value), err)
			}
		}

		if err := store3.Close(); err != nil {
			t.Fatalf("iteration %d: Close store3 failed: %v", iteration, err)
		}
	}
}

func testTornReplaceDeletedKeyStaysDeleted(t *testing.T, directory string, initialValue []byte, replacementValue []byte) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir(directory), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "ConfigMap"
	targetKey := "target-key"

	// Fill the first slotted page with a dummy record (1800 bytes) so that if
	// initialValue or replacementValue is also a large slotted record (~1800 bytes),
	// it will not fit on the same slotted page and is forced onto a new page.
	dummyValue := bytes.Repeat([]byte("d"), 1800)
	if err := store.Put(table, "dummy-key", dummyValue); err != nil {
		t.Fatalf("Put dummy-key failed: %v", err)
	}

	// 1. Put target key with initial value
	if err := store.Put(table, targetKey, initialValue); err != nil {
		t.Fatalf("Put initial value failed: %v", err)
	}

	// 2. Checkpoint: initial record becomes durable on disk
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	store.keyMu.RLock()
	initialEntry := store.keyIndex[qualifyKey(table, targetKey)]
	store.keyMu.RUnlock()

	// 3. Replace target key with replacement value
	if err := store.Put(table, targetKey, replacementValue); err != nil {
		t.Fatalf("Put replacement value failed: %v", err)
	}

	store.keyMu.RLock()
	replacementEntry := store.keyIndex[qualifyKey(table, targetKey)]
	store.keyMu.RUnlock()

	if replacementEntry.LogicalPage == initialEntry.LogicalPage {
		t.Fatalf("expected replacement to move to a different page, but both are on page %d", initialEntry.LogicalPage)
	}

	// 4. A crash that keeps the replacement page's flush and loses the old page's flush:
	// Flush only the replacement page to the heap file.
	if err := store.bp.FlushPage(replacementEntry.LogicalPage); err != nil {
		t.Fatalf("FlushPage replacement page %d failed: %v", replacementEntry.LogicalPage, err)
	}
	// Sync WAL so the replace record is durable.
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync WAL failed: %v", err)
	}

	// Crash: keeps un-fsynced writes from the replacement page flush, loses the old page's flush.
	if err := faultFS.Crash(false, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// 5. Reopen
	faultFS2 := NewFaultFS(memFS)
	store2, err := Open(WithFS(faultFS2), WithDir(directory), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 1 failed: %v", err)
	}

	// Verify key has the replacement value after first reopen
	retrievedValue, exists, err := store2.Get(table, targetKey)
	if err != nil || !exists || !bytes.Equal(retrievedValue, replacementValue) {
		t.Fatalf("Reopen 1 Get mismatch: exists=%v, val len=%d, err=%v", exists, len(retrievedValue), err)
	}

	// 6. Delete
	if err := store2.Delete(table, targetKey); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := store2.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint store2 failed: %v", err)
	}

	// 7. Clean close (checkpoints again with clean block pool, advancing redoStartLSN)
	if err := store2.Close(); err != nil {
		t.Fatalf("Close store2 failed: %v", err)
	}

	// 8. Reopen
	faultFS3 := NewFaultFS(memFS)
	store3, err := Open(WithFS(faultFS3), WithDir(directory), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 2 failed: %v", err)
	}
	defer store3.Close()

	// The key must stay deleted!
	finalValue, finalExists, err := store3.Get(table, targetKey)
	if err != nil {
		t.Fatalf("Reopen 2 Get error: %v", err)
	}
	if finalExists {
		t.Fatalf("deleted key returned after recovery: got len=%d, value=%q", len(finalValue), string(finalValue))
	}

	// dummy-key must still exist!
	dummyRetrieved, dummyExists, err := store3.Get(table, "dummy-key")
	if err != nil || !dummyExists || !bytes.Equal(dummyRetrieved, dummyValue) {
		t.Fatalf("dummy-key corrupted or missing: exists=%v, err=%v", dummyExists, err)
	}
}

// TestRecovery_TornReplaceDeletedKeyStayDeleted verifies that after a crash that keeps
// a replacement page's flush and loses the old page's flush across all replacement directions
// (multi-block to slotted, slotted to slotted on a different page, and slotted to multi-block),
// reopening the store clears the old page's copy so that a subsequent delete, clean close,
// and reopen leaves the key deleted.
func TestRecovery_TornReplaceDeletedKeyStayDeleted(t *testing.T) {
	multiBlockValue := bytes.Repeat([]byte("multi-block-value-content-"), 400) // ~10 KB -> 4 blocks
	slottedValue1 := bytes.Repeat([]byte("a"), 1800)
	slottedValue2 := bytes.Repeat([]byte("b"), 1800)

	t.Run("MultiBlockToSlotted", func(t *testing.T) {
		testTornReplaceDeletedKeyStaysDeleted(t, "test_torn_replace_mb_to_slotted", multiBlockValue, slottedValue1)
	})

	t.Run("SlottedToSlottedDifferentPage", func(t *testing.T) {
		testTornReplaceDeletedKeyStaysDeleted(t, "test_torn_replace_slotted_to_slotted", slottedValue1, slottedValue2)
	})

	t.Run("SlottedToMultiBlock", func(t *testing.T) {
		testTornReplaceDeletedKeyStaysDeleted(t, "test_torn_replace_slotted_to_mb", slottedValue1, multiBlockValue)
	})
}
