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

// TestRecoveryPage_TearPageWriteAtByteBoundaries verifies:
// A test writes several positions, tears the page being written at each byte boundary of
// the write, reopens, and gets the previous position or the new one, never anything else.
func TestRecoveryPage_TearPageWriteAtByteBoundaries(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_page_tear"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify initial store created has page 0 active with recoveryStartLSN 0 and counter 1.
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
	initialLSN, _, _, err := readRecoveryStartPages(initMeta[:], metaPath)
	if err != nil || initialLSN != 0 {
		t.Fatalf("expected initial recoveryStartLSN 0, got %d (err: %v)", initialLSN, err)
	}

	// Positions to advance through.
	positions := []uint64{10, 25}
	currentPos := uint64(0)
	activePageIndex := 0
	activeCounter := uint64(1)

	for _, nextPos := range positions {
		targetIndex := (activePageIndex + 1) % metaRecoveryPageCount
		nextCounter := activeCounter + 1

		newRecord := recoveryStartRecord{
			recoveryStartLSN: nextPos,
			counter:          nextCounter,
		}
		encoded := encodeRecoveryPage(newRecord)
		pageOffset := int(recoveryPageOffset(targetIndex))

		// Tear the write at every single byte boundary from 0 to metaRecoveryPageSize (4096).
		for byteBoundary := 0; byteBoundary <= metaRecoveryPageSize; byteBoundary++ {
			tornFS := cloneMemFS(memFS)

			// Read current meta.db from tornFS
			metaFile, err := tornFS.OpenFile(metaPath, 0, 0)
			if err != nil {
				t.Fatalf("OpenFile failed at boundary %d: %v", byteBoundary, err)
			}
			var metaBuffer [metaFileSize]byte
			if _, err := metaFile.ReadAt(metaBuffer[:], 0); err != nil {
				t.Fatalf("ReadAt failed at boundary %d: %v", byteBoundary, err)
			}
			if err := metaFile.Close(); err != nil {
				t.Fatalf("Close failed at boundary %d: %v", byteBoundary, err)
			}

			// Apply partially written page up to byteBoundary
			copy(metaBuffer[pageOffset:pageOffset+byteBoundary], encoded[:byteBoundary])

			// Rewrite meta.db in tornFS
			writeFile, err := tornFS.Create(metaPath)
			if err != nil {
				t.Fatalf("Create failed at boundary %d: %v", byteBoundary, err)
			}
			if _, err := writeFile.WriteAt(metaBuffer[:], 0); err != nil {
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

			// Verify the active page on disk in the torn store that Open accepted
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

			gotLSN, _, _, err := readRecoveryStartPages(tornMeta[:], metaPath)
			if err != nil {
				t.Fatalf("readRecoveryStartPages failed: %v", err)
			}

			if err := reopened.Close(); err != nil {
				t.Fatalf("reopened.Close failed: %v", err)
			}

			if byteBoundary < metaRecoveryPageSize {
				// Page write was incomplete or checksum was not yet valid.
				// Recovery must fall back to the previous position and never anything else.
				if gotLSN != currentPos {
					t.Fatalf("nextPos=%d byteBoundary=%d: expected previous position %d, got %d",
						nextPos, byteBoundary, currentPos, gotLSN)
				}
			} else {
				// Page write was fully completed with valid checksum.
				// Recovery must use the new position and never anything else.
				if gotLSN != nextPos {
					t.Fatalf("nextPos=%d byteBoundary=%d: expected new position %d, got %d",
						nextPos, byteBoundary, nextPos, gotLSN)
				}
			}
		}

		// Now write the full page to the base filesystem to advance the baseline.
		metaFile, err := memFS.OpenFile(metaPath, 0, 0)
		if err != nil {
			t.Fatalf("base OpenFile failed: %v", err)
		}
		var metaBuffer [metaFileSize]byte
		if _, err := metaFile.ReadAt(metaBuffer[:], 0); err != nil {
			t.Fatalf("base ReadAt failed: %v", err)
		}
		if err := metaFile.Close(); err != nil {
			t.Fatalf("base Close failed: %v", err)
		}

		copy(metaBuffer[pageOffset:pageOffset+metaRecoveryPageSize], encoded)

		writeFile, err := memFS.Create(metaPath)
		if err != nil {
			t.Fatalf("base Create failed: %v", err)
		}
		if _, err := writeFile.WriteAt(metaBuffer[:], 0); err != nil {
			t.Fatalf("base WriteAt failed: %v", err)
		}
		if err := writeFile.Close(); err != nil {
			t.Fatalf("base Write Close failed: %v", err)
		}

		currentPos = nextPos
		activePageIndex = targetIndex
		activeCounter = nextCounter
	}
}

// TestRecoveryPage_CorruptOnePage_SeveralPages_AllPages verifies:
// Corrupting one page falls back to the prior valid page.
// Corrupting several pages skips them all and falls back to the newest surviving valid page.
// Corrupting all pages fails with an error naming meta.db.
func TestRecoveryPage_CorruptOnePage_SeveralPages_AllPages(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_page_corrupt"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write 4 keys and checkpoint each time, writing pages 1, 2, 3, 4 with counters 2, 3, 4, 5
	for i := 1; i <= 4; i++ {
		key := fmt.Sprintf("k%d", i)
		val := fmt.Sprintf("v%d", i)
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put %s failed: %v", key, err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint %d failed: %v", i, err)
		}
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

	// Case 1: Corrupt the newest page (page 4). Reopen must fall back to page 3.
	{
		corrupt1FS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		offset := recoveryPageOffset(4)
		corrupted[offset] ^= 0x01 // flip bit in page 4

		f, err := corrupt1FS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		reopened, err := Open(WithFS(corrupt1FS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("Open with corrupted page 4 failed: %v", err)
		}
		for i := 1; i <= 4; i++ {
			key := fmt.Sprintf("k%d", i)
			expected := fmt.Sprintf("v%d", i)
			val, exists, err := reopened.Get("Table", key)
			if err != nil || !exists || string(val) != expected {
				t.Fatalf("key %s: expected %s, got val=%s exists=%v err=%v", key, expected, string(val), exists, err)
			}
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}

	// Case 2: Corrupt several pages (pages 2, 3, and 4). Reopen must skip all three and use page 1.
	{
		corruptSeveralFS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		for _, pageIdx := range []int{2, 3, 4} {
			offset := recoveryPageOffset(pageIdx)
			corrupted[offset] ^= 0x01 // flip bit in page
		}

		f, err := corruptSeveralFS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		reopened, err := Open(WithFS(corruptSeveralFS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("Open with corrupted pages 2, 3, 4 failed: %v", err)
		}
		for i := 1; i <= 4; i++ {
			key := fmt.Sprintf("k%d", i)
			expected := fmt.Sprintf("v%d", i)
			val, exists, err := reopened.Get("Table", key)
			if err != nil || !exists || string(val) != expected {
				t.Fatalf("key %s: expected %s, got val=%s exists=%v err=%v", key, expected, string(val), exists, err)
			}
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}

	// Case 3: Corrupt all 8 pages. Open must fail with an error naming meta.db without guessing.
	{
		corruptAllFS := cloneMemFS(memFS)
		corrupted := make([]byte, metaFileSize)
		copy(corrupted, baseMeta[:])
		for pageIdx := 0; pageIdx < metaRecoveryPageCount; pageIdx++ {
			offset := recoveryPageOffset(pageIdx)
			corrupted[offset] ^= 0x01 // flip bit in every page
		}

		f, err := corruptAllFS.Create(metaPath)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, err := f.WriteAt(corrupted, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		_, err = Open(WithFS(corruptAllFS), WithDir(dir), WithCompressionCodec(CodecNone))
		if err == nil {
			t.Fatalf("expected Open with all pages corrupt to fail")
		}
		if !strings.Contains(err.Error(), "meta.db") {
			t.Fatalf("expected error to name meta.db, got: %v", err)
		}
		if !strings.Contains(err.Error(), "no valid recovery start page found in ring") {
			t.Fatalf("expected error mentioning no valid recovery start page, got: %v", err)
		}
	}
}

// TestRecoveryPage_Block0UnchangedAfterManyCheckpoints verifies:
// meta.db's header in block 0 is written once at creation and remains byte-for-byte unchanged
// across many checkpoints that cycle through the recovery ring.
func TestRecoveryPage_Block0UnchangedAfterManyCheckpoints(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_block0_unchanged"
	metaPath := filepath.Join(dir, "meta.db")

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Read initial block 0 from meta.db
	metaFile, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var initialBlock0 [metaBlockSize]byte
	if _, err := metaFile.ReadAt(initialBlock0[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Execute 25 checkpoints with mutations to cycle through the 8-page ring multiple times.
	for i := 0; i < 25; i++ {
		key := fmt.Sprintf("k-%d", i)
		val := fmt.Sprintf("v-%d", i)
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put failed at step %d: %v", i, err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint failed at step %d: %v", i, err)
		}
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read block 0 again and verify byte-for-byte identity
	metaFileAfter, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile after checkpoints failed: %v", err)
	}
	var currentBlock0 [metaBlockSize]byte
	if _, err := metaFileAfter.ReadAt(currentBlock0[:], 0); err != nil {
		t.Fatalf("ReadAt after checkpoints failed: %v", err)
	}
	if err := metaFileAfter.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !bytes.Equal(initialBlock0[:], currentBlock0[:]) {
		t.Fatalf("block 0 changed after 25 checkpoints; expected byte-for-byte identical")
	}
}

// TestRecoveryPage_ReplayFromOlderRecordWithTruncation verifies:
// If the latest recovery page is damaged and Open uses an older record, its LSN is earlier
// than the point where the log was truncated. Everything before the truncation point is already
// durable in the heap, so replay starts from the first record the log still has, with no error.
func TestRecoveryPage_ReplayFromOlderRecordWithTruncation(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_older_record_truncation"
	metaPath := filepath.Join(dir, "meta.db")

	// Use WALBlockSize (4 KiB) as segment size so writes roll into new segments and truncate.
	store, err := Open(
		WithFS(memFS),
		WithDir(dir),
		WithCreate(),
		WithCompressionCodec(CodecNone),
		WithWALMaxSegmentSize(int64(WALBlockSize)),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write batch 1 and checkpoint
	for i := 0; i < 15; i++ {
		key := fmt.Sprintf("batch1-key-%03d", i)
		val := fmt.Sprintf("batch1-val-%03d-%s", i, strings.Repeat("x", 200))
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put batch 1 failed: %v", err)
		}
	}
	if err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 1 failed: %v", err)
	}

	// Write batch 2 and checkpoint
	for i := 0; i < 15; i++ {
		key := fmt.Sprintf("batch2-key-%03d", i)
		val := fmt.Sprintf("batch2-val-%03d-%s", i, strings.Repeat("y", 200))
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put batch 2 failed: %v", err)
		}
	}
	if err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 2 failed: %v", err)
	}

	// Write batch 3 and checkpoint
	for i := 0; i < 15; i++ {
		key := fmt.Sprintf("batch3-key-%03d", i)
		val := fmt.Sprintf("batch3-val-%03d-%s", i, strings.Repeat("z", 200))
		if err := store.Put("Table", key, []byte(val)); err != nil {
			t.Fatalf("Put batch 3 failed: %v", err)
		}
	}
	if err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 3 failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read meta.db and find the newest active page
	metaFile, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var metaBuffer [metaFileSize]byte
	if _, err := metaFile.ReadAt(metaBuffer[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	newestLSN, newestIdx, newestCounter, err := readRecoveryStartPages(metaBuffer[:], metaPath)
	if err != nil {
		t.Fatalf("readRecoveryStartPages failed: %v", err)
	}
	if newestCounter <= 1 {
		t.Fatalf("expected counter > 1 after checkpoints, got %d", newestCounter)
	}

	// Verify that WAL was indeed truncated and does not contain segment 1
	walDir := filepath.Join(dir, "wal")
	entries, err := memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir wal failed: %v", err)
	}
	hasTruncatedSeg := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".wal") {
			base := strings.TrimSuffix(entry.Name(), ".wal")
			var segLSN uint64
			if _, err := fmt.Sscanf(base, "%d", &segLSN); err == nil {
				if segLSN == 1 {
					t.Fatalf("expected WAL segment 1 to be truncated, but it is still present in %v", entries)
				}
				if segLSN > 1 {
					hasTruncatedSeg = true
				}
			}
		}
	}
	if !hasTruncatedSeg {
		t.Fatalf("expected WAL segments to rotate and truncate earlier segments, but found: %v", entries)
	}

	// Damage the newest recovery page in meta.db
	corrupted := make([]byte, metaFileSize)
	copy(corrupted, metaBuffer[:])
	newestOffset := recoveryPageOffset(newestIdx)
	corrupted[newestOffset] ^= 0x01 // bit flip in newest page

	writeFile, err := memFS.Create(metaPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if _, err := writeFile.WriteAt(corrupted, 0); err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := writeFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify that readRecoveryStartPages now returns an older LSN
	olderLSN, olderIdx, olderCounter, err := readRecoveryStartPages(corrupted, metaPath)
	if err != nil {
		t.Fatalf("readRecoveryStartPages on corrupted meta failed: %v", err)
	}
	if olderIdx == newestIdx {
		t.Fatalf("expected older index different from newestIdx %d", newestIdx)
	}
	if olderCounter >= newestCounter {
		t.Fatalf("expected olderCounter (%d) < newestCounter (%d)", olderCounter, newestCounter)
	}
	if olderLSN >= newestLSN {
		t.Fatalf("expected older record's LSN (%d) to be below newest record's LSN (%d)", olderLSN, newestLSN)
	}

	// Reopen store. Open must fall back to the older recovery record, start replay from
	// the first surviving WAL record without error, and preserve all data.
	reopened, err := Open(
		WithFS(memFS),
		WithDir(dir),
		WithCompressionCodec(CodecNone),
		WithWALMaxSegmentSize(int64(WALBlockSize)),
	)
	if err != nil {
		t.Fatalf("Open after newest page damage failed: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("reopened.Close failed: %v", err)
		}
	}()

	// Verify all records across all batches exist and have expected contents
	for i := 0; i < 15; i++ {
		key1 := fmt.Sprintf("batch1-key-%03d", i)
		expected1 := fmt.Sprintf("batch1-val-%03d-%s", i, strings.Repeat("x", 200))
		val, exists, err := reopened.Get("Table", key1)
		if err != nil || !exists || string(val) != expected1 {
			t.Fatalf("batch 1 key %s missing or corrupt: exists=%v val_len=%d err=%v", key1, exists, len(val), err)
		}

		key2 := fmt.Sprintf("batch2-key-%03d", i)
		expected2 := fmt.Sprintf("batch2-val-%03d-%s", i, strings.Repeat("y", 200))
		val, exists, err = reopened.Get("Table", key2)
		if err != nil || !exists || string(val) != expected2 {
			t.Fatalf("batch 2 key %s missing or corrupt: exists=%v val_len=%d err=%v", key2, exists, len(val), err)
		}

		key3 := fmt.Sprintf("batch3-key-%03d", i)
		expected3 := fmt.Sprintf("batch3-val-%03d-%s", i, strings.Repeat("z", 200))
		val, exists, err = reopened.Get("Table", key3)
		if err != nil || !exists || string(val) != expected3 {
			t.Fatalf("batch 3 key %s missing or corrupt: exists=%v val_len=%d err=%v", key3, exists, len(val), err)
		}
	}
}

// TestRecoveryPage_CrashRecoveryReplaysFromStoredLSN verifies:
// Recovery after a crash starts replay at the stored LSN, reconstructing all state.
func TestRecoveryPage_CrashRecoveryReplaysFromStoredLSN(t *testing.T) {
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

	if err := store.Checkpoint(); err != nil {
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
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("reopened.Close failed: %v", err)
		}
	}()

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

// TestRecoveryPage_StoreCreatedBeforeChange_Rejected verifies:
// A store created before this change has no recovery pages (e.g. short 4 KiB file or older version).
// Open treats such a store the way it treats any store it cannot read (fails without WithEraseOnError,
// wipes with WithEraseOnError).
func TestRecoveryPage_StoreCreatedBeforeChange_Rejected(t *testing.T) {
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

	// Read meta.db and rewrite it as a 4 KiB file with version 7 (the layout before this change)
	metaFile, err := memFS.OpenFile(metaPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var oldMeta [metaBlockSize]byte
	if _, err := metaFile.ReadAt(oldMeta[:], 0); err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Set StoreFormatVersion to 7 and recompute CRC over the 4 KiB block
	binary.BigEndian.PutUint32(oldMeta[metaOffsetVersion:metaOffsetDBID], 7)
	checksum := computeMetaBlockCRC(oldMeta[:])
	binary.BigEndian.PutUint32(oldMeta[metaOffsetCRC:metaBlockSize], checksum)

	writeFile, err := memFS.Create(metaPath)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if _, err := writeFile.WriteAt(oldMeta[:], 0); err != nil {
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
	if !strings.Contains(err.Error(), "outdated or corrupt meta file") {
		t.Fatalf("expected error mentioning outdated or corrupt meta, got: %v", err)
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
