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
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// cloneMemFS creates an independent in-memory copy of an existing MemFS.
func cloneMemFS(src *MemFS) *MemFS {
	dst := NewMemFS()
	src.mu.RLock()
	defer src.mu.RUnlock()
	for name, data := range src.files {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		dst.files[name] = dataCopy
	}
	for dir := range src.directories {
		dst.directories[dir] = true
	}
	return dst
}

// TestRecoverySlot_TearSlotWriteAtByteBoundaries verifies:
// A test writes several positions, tears the slot being written at each byte boundary of
// the write, reopens, and gets the previous position or the new one, never anything else.
func TestRecoverySlot_TearSlotWriteAtByteBoundaries(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_slot_tear"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify initial store created has slot 0 active with recoveryStartLSN 0 and counter 1.
	var initMeta [metaFileSize]byte
	mf, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if _, err := mf.ReadAt(initMeta[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := mf.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	initialLSN, _, _, err := readRecoveryStartSlots(initMeta[:], metaPath)
	if err != nil || initialLSN != 0 {
		t.Fatalf("expected initial recoveryStartLSN 0, got %d (err: %v)", initialLSN, err)
	}

	// Positions to advance through.
	positions := []uint64{10, 25, 55, 120, 300}
	currentPos := uint64(0)
	activeSlot := 0
	activeCounter := uint64(1)

	for _, nextPos := range positions {
		targetSlot := 1 - activeSlot
		nextCounter := activeCounter + 1

		newSlot := recoveryStartSlot{
			recoveryStartLSN: nextPos,
			counter:          nextCounter,
		}
		encoded := encodeRecoveryStartSlot(newSlot)

		slotOffset := metaOffsetRecoverySlot0
		if targetSlot == 1 {
			slotOffset = metaOffsetRecoverySlot1
		}

		// Tear the write at every single byte boundary from 0 to recoveryStartSlotSize (20).
		for byteBoundary := 0; byteBoundary <= recoveryStartSlotSize; byteBoundary++ {
			tornFS := cloneMemFS(memFS)

			// Read current meta.db from tornFS
			metaFile, err := tornFS.OpenFile(metaPath, 0, 0)
			if err != nil {
				t.Fatalf("OpenFile failed at boundary %d: %v", byteBoundary, err)
			}
			var metaBuf [metaFileSize]byte
			if _, err := metaFile.ReadAt(metaBuf[:], 0); err != nil {
				t.Fatalf("ReadAt failed at boundary %d: %v", byteBoundary, err)
			}
			if err := metaFile.Close(); err != nil {
				t.Fatalf("Close failed at boundary %d: %v", byteBoundary, err)
			}

			// Apply partially written slot up to byteBoundary
			copy(metaBuf[slotOffset:slotOffset+byteBoundary], encoded[:byteBoundary])

			// Rewrite meta.db in tornFS
			writeFile, err := tornFS.Create(metaPath)
			if err != nil {
				t.Fatalf("Create failed at boundary %d: %v", byteBoundary, err)
			}
			if _, err := writeFile.WriteAt(metaBuf[:], 0); err != nil {
				t.Fatalf("WriteAt failed at boundary %d: %v", byteBoundary, err)
			}
			if err := writeFile.Close(); err != nil {
				t.Fatalf("Close failed at boundary %d: %v", byteBoundary, err)
			}

			// Reopen store from torn state
			reopened, err := Open(WithFS(tornFS), WithDir(dir), WithCompressionCodec(CodecNone))
			if err != nil {
				t.Fatalf("Open failed at nextPos=%d byteBoundary=%d: %v", nextPos, byteBoundary, err)
			}

			// Verify the active slot on disk in the torn store that Open accepted
			reopenedMetaFile, err := tornFS.OpenFile(metaPath, 0, 0)
			if err != nil {
				t.Fatalf("reopened OpenFile failed: %v", err)
			}
			var tornMeta [metaFileSize]byte
			if _, err := reopenedMetaFile.ReadAt(tornMeta[:], 0); err != nil {
				t.Fatalf("reopened ReadAt failed: %v", err)
			}
			if err := reopenedMetaFile.Close(); err != nil {
				t.Fatalf("reopened Close failed: %v", err)
			}

			gotLSN, _, _, err := readRecoveryStartSlots(tornMeta[:], metaPath)
			if err != nil {
				t.Fatalf("readRecoveryStartSlots failed: %v", err)
			}

			if err := reopened.Close(); err != nil {
				t.Fatalf("reopened.Close failed: %v", err)
			}

			if byteBoundary < recoveryStartSlotSize {
				// Slot write was incomplete or checksum was not yet written/valid.
				// Recovery must fall back to the previous position and never anything else.
				if gotLSN != currentPos {
					t.Fatalf("nextPos=%d byteBoundary=%d: expected previous position %d, got %d",
						nextPos, byteBoundary, currentPos, gotLSN)
				}
			} else {
				// Slot write was fully completed with valid checksum.
				// Recovery must use the new position and never anything else.
				if gotLSN != nextPos {
					t.Fatalf("nextPos=%d byteBoundary=%d: expected new position %d, got %d",
						nextPos, byteBoundary, nextPos, gotLSN)
				}
			}
		}

		// Now write the full slot to the base filesystem to advance the baseline.
		metaFile, err := memFS.OpenFile(metaPath, 0, 0)
		if err != nil {
			t.Fatalf("base OpenFile failed: %v", err)
		}
		var metaBuf [metaFileSize]byte
		if _, err := metaFile.ReadAt(metaBuf[:], 0); err != nil {
			t.Fatalf("base ReadAt failed: %v", err)
		}
		if err := metaFile.Close(); err != nil {
			t.Fatalf("base Close failed: %v", err)
		}

		copy(metaBuf[slotOffset:slotOffset+recoveryStartSlotSize], encoded)

		writeFile, err := memFS.Create(metaPath)
		if err != nil {
			t.Fatalf("base Create failed: %v", err)
		}
		if _, err := writeFile.WriteAt(metaBuf[:], 0); err != nil {
			t.Fatalf("base WriteAt failed: %v", err)
		}
		if err := writeFile.Close(); err != nil {
			t.Fatalf("base Write Close failed: %v", err)
		}

		currentPos = nextPos
		activeSlot = targetSlot
		activeCounter = nextCounter
	}
}

// TestRecoverySlot_CorruptOneSlotAndReopenWithOther_CorruptBothFails verifies:
// A test corrupts one slot and reopens with the other. A test corrupts both and gets the error.
func TestRecoverySlot_CorruptOneSlotAndReopenWithOther_CorruptBothFails(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_slot_corrupt"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write key 1 and checkpoint -> slot 1 written with counter 2
	if err := store.Put("Table", "k1", []byte("v1")); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 1 failed: %v", err)
	}

	// Write key 2 and checkpoint -> slot 0 written with counter 3
	if err := store.Put("Table", "k2", []byte("v2")); err != nil {
		t.Fatalf("Put k2 failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 2 failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read uncorrupted meta.db
	metaFile, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var baseMeta [metaFileSize]byte
	if _, err := metaFile.ReadAt(baseMeta[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close metaFile failed: %v", err)
	}

	slot0, err := decodeRecoveryStartSlot(baseMeta[metaOffsetRecoverySlot0 : metaOffsetRecoverySlot0+recoveryStartSlotSize])
	if err != nil {
		t.Fatalf("decode slot 0 failed: %v", err)
	}
	slot1, err := decodeRecoveryStartSlot(baseMeta[metaOffsetRecoverySlot1 : metaOffsetRecoverySlot1+recoveryStartSlotSize])
	if err != nil {
		t.Fatalf("decode slot 1 failed: %v", err)
	}

	if slot0.recoveryStartLSN == slot1.recoveryStartLSN {
		t.Fatalf("expected different LSNs in slot 0 and slot 1, got %d and %d",
			slot0.recoveryStartLSN, slot1.recoveryStartLSN)
	}

	// Case 1: Corrupt slot 0. Reopen must fall back to slot 1.
	{
		corruptSlot0FS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		corrupted[metaOffsetRecoverySlot0] ^= 0x01 // flip bit in slot 0

		f, err := corruptSlot0FS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		reopened, err := Open(WithFS(corruptSlot0FS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("Open with corrupted slot 0 failed: %v", err)
		}
		val, exists, err := reopened.Get("Table", "k1")
		if err != nil || !exists || string(val) != "v1" {
			t.Fatalf("expected k1 to exist, got val=%s exists=%v err=%v", string(val), exists, err)
		}
		val2, exists2, err := reopened.Get("Table", "k2")
		if err != nil || !exists2 || string(val2) != "v2" {
			t.Fatalf("expected k2 to exist, got val=%s exists=%v err=%v", string(val2), exists2, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}

	// Case 2: Corrupt slot 1. Reopen must use slot 0.
	{
		corruptSlot1FS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		corrupted[metaOffsetRecoverySlot1] ^= 0x01 // flip bit in slot 1

		f, err := corruptSlot1FS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		reopened, err := Open(WithFS(corruptSlot1FS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("Open with corrupted slot 1 failed: %v", err)
		}
		val, exists, err := reopened.Get("Table", "k2")
		if err != nil || !exists || string(val) != "v2" {
			t.Fatalf("expected k2 to exist, got val=%s exists=%v err=%v", string(val), exists, err)
		}
		val1, exists1, err := reopened.Get("Table", "k1")
		if err != nil || !exists1 || string(val1) != "v1" {
			t.Fatalf("expected k1 to exist, got val=%s exists=%v err=%v", string(val1), exists1, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}

	// Case 3: Corrupt BOTH slot 0 and slot 1. Open must return an error naming the file and not guess.
	{
		corruptBothFS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		corrupted[metaOffsetRecoverySlot0] ^= 0x01 // flip bit in slot 0
		corrupted[metaOffsetRecoverySlot1] ^= 0x01 // flip bit in slot 1

		f, err := corruptBothFS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		_, err = Open(WithFS(corruptBothFS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err == nil {
			t.Fatalf("expected Open with both slots corrupt to fail")
		}
		if !strings.Contains(err.Error(), "meta.db") {
			t.Fatalf("expected error to name meta.db, got: %v", err)
		}
		if !strings.Contains(err.Error(), "both recovery start slots corrupt") {
			t.Fatalf("expected error mentioning both recovery start slots corrupt, got: %v", err)
		}
	}
}

// TestRecoverySlot_CrashRecoveryReplaysFromStoredLSN verifies:
// Recovery after a crash starts replay at the stored LSN, reconstructing all state.
func TestRecoverySlot_CrashRecoveryReplaysFromStoredLSN(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_crash_recovery_lsn"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Put initial records and checkpoint to disk
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("chkKey-%d", i)
		val := fmt.Sprintf("chkVal-%d", i)
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	// Write additional uncheckpointed records to WAL and fsync the WAL
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("walKey-%d", i)
		val := fmt.Sprintf("walVal-%d", i)
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put uncheckpointed key failed: %v", err)
		}
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Simulate crash: discard un-fsynced heap blocks and abandon store without clean Close
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Reopen store on the crashed filesystem
	reopenedFS := NewFaultFS(memFS)
	reopened, err := Open(WithFS(reopenedFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open after crash failed: %v", err)
	}
	defer reopened.Close()

	// Verify all checkpointed and replayed records are present
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("chkKey-%d", i)
		val, exists, err := reopened.Get("Table", key)
		if err != nil || !exists || string(val) != fmt.Sprintf("chkVal-%d", i) {
			t.Fatalf("missing or incorrect checkpointed key %s: exists=%v val=%s err=%v", key, exists, string(val), err)
		}
	}
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("walKey-%d", i)
		val, exists, err := reopened.Get("Table", key)
		if err != nil || !exists || string(val) != fmt.Sprintf("walVal-%d", i) {
			t.Fatalf("missing or incorrect replayed key %s: exists=%v val=%s err=%v", key, exists, string(val), err)
		}
	}
}

// TestRecoverySlot_StoreCreatedBeforeChange_Rejected verifies:
// A store created before this change has no slots. Open treats such a store the way it treats
// any store it cannot read (fails without WithEraseOnError, wipes with WithEraseOnError).
func TestRecoverySlot_StoreCreatedBeforeChange_Rejected(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_old_store"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("Table", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read meta.db and rewrite it with version 7 (the version before this change)
	metaFile, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var metaBuf [metaFileSize]byte
	if _, err := metaFile.ReadAt(metaBuf[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Set StoreFormatVersion to 7
	binary.BigEndian.PutUint32(metaBuf[metaOffsetVersion:metaOffsetDBID], 7)
	crc := computeMetaBlockCRC(metaBuf[:])
	binary.BigEndian.PutUint32(metaBuf[metaOffsetCRC:metaFileSize], crc)

	writeFile, err := memFS.Create(metaPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if _, err := writeFile.WriteAt(metaBuf[:], 0); err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := writeFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Open without WithEraseOnError must fail
	_, err = Open(WithFS(memFS), WithDir(dir))
	if err == nil {
		t.Fatalf("expected Open of version 7 store to fail")
	}
	if !strings.Contains(err.Error(), "unsupported store format version: 7") &&
		!strings.Contains(err.Error(), "outdated or corrupt meta file") {
		t.Fatalf("expected error mentioning unsupported version or corrupt meta, got: %v", err)
	}

	// Open with WithEraseOnError must wipe and recreate
	storeWiped, err := Open(WithFS(memFS), WithDir(dir), WithEraseOnError())
	if err != nil {
		t.Fatalf("Open with WithEraseOnError failed: %v", err)
	}
	if !storeWiped.Wiped() {
		t.Fatalf("expected store to report Wiped() == true")
	}
	if err := storeWiped.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
