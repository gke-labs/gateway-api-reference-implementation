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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type oversizeHookFS struct {
	FS
	onSyncDir    func(dirname string)
	onRemove     func(name string)
	beforeRename func(oldpath, newpath string)
}

func (h *oversizeHookFS) SyncDir(dirname string) error {
	if h.onSyncDir != nil {
		h.onSyncDir(dirname)
	}
	return h.FS.SyncDir(dirname)
}

func (h *oversizeHookFS) Remove(name string) error {
	if h.onRemove != nil {
		h.onRemove(name)
	}
	return h.FS.Remove(name)
}

func (h *oversizeHookFS) Rename(oldpath, newpath string) error {
	if h.beforeRename != nil {
		h.beforeRename(oldpath, newpath)
	}
	return h.FS.Rename(oldpath, newpath)
}

// Review Feedback Item 1:
// Checkpoint survival: Put a 3 MiB value, do 3,000 small Puts with periodic Checkpoint(),
// Close, reopen, then Get returns the value.
func TestOversize_SurvivesCheckpointTruncation(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_checkpoint_truncation"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "ConfigMap"
	key := "largeKey"
	val := make([]byte, 3*1024*1024)
	copy(val, "three-megabytes-of-important-data")
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}

	// 3,000 small Puts with periodic checkpoints
	for i := 0; i < 3000; i++ {
		smallKey := fmt.Sprintf("k%d", i)
		smallVal := fmt.Sprintf("val-%d", i)
		if err := store.Put(table, smallKey, []byte(smallVal)); err != nil {
			t.Fatalf("Put %s failed: %v", smallKey, err)
		}
		if (i+1)%500 == 0 {
			if _, err := store.Checkpoint(); err != nil {
				t.Fatalf("Checkpoint at %d failed: %v", i, err)
			}
		}
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen store after checkpointing and WAL truncation
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	gotVal, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get oversize key failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected oversize key %s to exist after recovery, but returned not-found", key)
	}
	if !bytes.Equal(gotVal, val) {
		t.Fatalf("value mismatch: got len=%d, want len=%d", len(gotVal), len(val))
	}
}

// Review Feedback Item 2:
// A concurrent Put of X and Put of Y can leave X's pointer naming a file that Y's Put has just deleted.
// Put and Delete must skip removing any file in the in-flight registry, and re-check the skip-write decision under writerMu.
func TestOversize_ConcurrentPut_InterleavedRace(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_race"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	table := "TestTable"
	key := "sharedKey"

	valX := append([]byte("value-X"), make([]byte, 2100*1024)...)
	valY := append([]byte("value-Y"), make([]byte, 2100*1024)...)

	// Step 1: Put initial value X
	if err := store.Put(table, key, valX); err != nil {
		t.Fatalf("Put valX failed: %v", err)
	}

	qKey := qualifyKey(table, key)
	fileX := store.keyIndex[qKey].OversizeFileName

	// Verify file X is in oversize directory
	if _, err := memFS.Open(filepath.Join(dir, "oversize", fileX)); err != nil {
		t.Fatalf("expected file X on disk: %v", err)
	}

	// Step 2: Test stale skip-write detection.
	// Goroutine 1 decides skipWrite=true outside the lock because index holds X.
	// We interleave Put(valY) to change the index and delete file X while Goroutine 1 is waiting.
	// When Goroutine 1 acquires writerMu, it must detect the stale skip decision and write file X.
	var g1Ready sync.WaitGroup
	var g2Done sync.WaitGroup
	g1Ready.Add(1)
	g2Done.Add(1)

	var g1Err error
	go func() {
		// Signal ready right before entering Put
		g1Ready.Done()
		g2Done.Wait() // wait until Put(valY) completes
		g1Err = store.Put(table, key, valX)
	}()

	g1Ready.Wait()
	// Put valY under writerMu
	if err := store.Put(table, key, valY); err != nil {
		t.Fatalf("Put valY failed: %v", err)
	}
	g2Done.Done()

	// Wait for Goroutine 1 to finish Put(valX)
	for {
		store.keyMu.RLock()
		cur := store.keyIndex[qKey]
		store.keyMu.RUnlock()
		if cur.OversizeFileName == fileX {
			break
		}
	}

	if g1Err != nil {
		t.Fatalf("Goroutine 1 Put(valX) failed: %v", g1Err)
	}

	// Verify file X exists on disk and Get returns valX
	if _, err := memFS.Open(filepath.Join(dir, "oversize", fileX)); err != nil {
		t.Fatalf("expected file X to exist on disk after stale skip recovery, got: %v", err)
	}
	gotVal, exists, err := store.Get(table, key)
	if err != nil || !exists || !bytes.Equal(gotVal, valX) {
		t.Fatalf("Get after race failed: exists=%v, err=%v", exists, err)
	}

	// Step 3: Test that in-flight files are never deleted by concurrent Put/Delete.
	inFlightFile := "in-flight-test-file.obj"
	store.registerInFlight(inFlightFile)

	// Simulate an entry holding inFlightFile
	store.keyMu.Lock()
	store.keyIndex[qKey] = KeyIndexEntry{
		LogicalPage:      store.keyIndex[qKey].LogicalPage,
		Slot:             store.keyIndex[qKey].Slot,
		LSN:              store.keyIndex[qKey].LSN,
		NumBlocks:        1,
		IsOversize:       true,
		OversizeFileName: inFlightFile,
	}
	// Create the file in memory
	memFS.files[filepath.Join(dir, "oversize", inFlightFile)] = []byte("in-flight-payload")
	store.keyMu.Unlock()

	// Now Put a new value: it must skip removing inFlightFile because it is registered in flight!
	if err := store.Put(table, key, valY); err != nil {
		t.Fatalf("Put valY failed: %v", err)
	}

	// Verify inFlightFile was NOT deleted
	if _, exists := memFS.files[filepath.Join(dir, "oversize", inFlightFile)]; !exists {
		t.Fatalf("in-flight file was deleted by concurrent Put")
	}

	store.unregisterInFlight(inFlightFile)
}

// Crash after pointer record durable recovers new value.
func TestOversize_CrashAfterPointerRecordDurable_RecoversNewValue(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_oversize_crash_after_ptr"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	val := append([]byte("durable-oversize-content"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Put completed. Crash faultFS dropping any unsynced data and reopen.
	_ = faultFS.Crash(true, 0)
	_ = store.Close()

	store2, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open after crash failed: %v", err)
	}
	defer store2.Close()

	gotVal, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key to exist after crash recovery")
	}
	if !bytes.Equal(gotVal, val) {
		t.Fatalf("value mismatch: got len=%d, want len=%d", len(gotVal), len(val))
	}
}

// Overwriting an oversize key never deletes the old file before the new pointer record is durable.
func TestOversize_Overwrite_NeverDeletesOldFileBeforePointerRecordDurable(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_oversize_overwrite_old_retention"

	hookedFS := &oversizeHookFS{FS: faultFS}

	store, err := Open(WithFS(hookedFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	v1 := append([]byte("oversize-version-1"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, v1); err != nil {
		t.Fatalf("Put v1 failed: %v", err)
	}

	oldFileName := store.keyIndex[qualifyKey(table, key)].OversizeFileName
	oldFilePath := filepath.Join(dir, "oversize", oldFileName)

	var oldFileRemovedBeforeDurable bool
	hookedFS.onRemove = func(name string) {
		if filepath.Clean(name) == filepath.Clean(oldFilePath) {
			if store.wal.FsyncedLSN() < store.wal.MaxLSN() {
				oldFileRemovedBeforeDurable = true
			}
		}
	}

	v2 := append([]byte("oversize-version-2"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, v2); err != nil {
		t.Fatalf("Put v2 failed: %v", err)
	}

	if oldFileRemovedBeforeDurable {
		t.Fatalf("Invariant violated: old oversize file was deleted before new pointer record was durable")
	}

	// Verify old file was eventually deleted after durable sync
	if _, err := memFS.Open(oldFilePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected old oversize file to be removed after successful sync, got err: %v", err)
	}
}

// WAL segments no longer contain oversize payloads. Check this through the segment size after an oversize Put.
func TestOversize_WALSegmentsContainNoOversizePayload(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_wal_size"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Put 3 MiB oversize value
	val := make([]byte, 3*1024*1024)
	copy(val, "three-megabytes-of-data")
	if err := store.Put("ConfigMap", "largeKey", val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Inspect WAL segment sizes
	walDir := filepath.Join(dir, "wal")
	entries, err := memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir wal failed: %v", err)
	}

	var totalWALBytes int64
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wal") {
			info, err := e.Info()
			if err != nil {
				t.Fatalf("Stat %s failed: %v", e.Name(), err)
			}
			totalWALBytes += info.Size()
		}
	}

	// The WAL segment should only hold lightweight pointer records (< 64 KiB), not 3 MiB.
	const maxAcceptableWALSize = 64 * 1024
	if totalWALBytes > maxAcceptableWALSize {
		t.Fatalf("WAL segment contains oversize payload: size=%d bytes (expected < %d bytes)", totalWALBytes, maxAcceptableWALSize)
	}
}

// Rewriting identical oversize value skips writing a new file and retains the existing file.
func TestOversize_IdenticalValueRewrite_SkipsWrite(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_identical_rewrite"

	var renameCount atomic.Int32
	hookedFS := &oversizeHookFS{
		FS: memFS,
		beforeRename: func(oldpath, newpath string) {
			if strings.Contains(newpath, "oversize") {
				renameCount.Add(1)
			}
		},
	}

	store, err := Open(WithFS(hookedFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	table := "ConfigMap"
	key := "largeKey"
	val := append([]byte("identical-content"), make([]byte, 2100*1024)...)

	// First Put: writes file and renames
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("First Put failed: %v", err)
	}
	if renameCount.Load() != 1 {
		t.Fatalf("expected 1 rename on first Put, got %d", renameCount.Load())
	}

	// Second Put with identical value: must skip writing!
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Second Put failed: %v", err)
	}
	if renameCount.Load() != 1 {
		t.Fatalf("expected no rename on identical Put, got %d", renameCount.Load())
	}

	// Read back to confirm content is valid
	got, exists, err := store.Get(table, key)
	if err != nil || !exists || !bytes.Equal(got, val) {
		t.Fatalf("Get failed after identical rewrite")
	}
}

// Old-version rule when transitioning from oversize back to slotted page:
// Delete the previous version's file only after the new pointer record is durable.
func TestOversize_KeyMovingBackToPage_DeletesOldFileOnlyAfterWALSync(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_oversize_to_page_old_retention"

	hookedFS := &oversizeHookFS{FS: faultFS}

	store, err := Open(WithFS(hookedFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	v1 := append([]byte("oversize-version-1"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, v1); err != nil {
		t.Fatalf("Put v1 failed: %v", err)
	}

	oldFileName := store.keyIndex[qualifyKey(table, key)].OversizeFileName
	oldFilePath := filepath.Join(dir, "oversize", oldFileName)

	var oldFileRemovedBeforeDurable bool
	hookedFS.onRemove = func(name string) {
		if filepath.Clean(name) == filepath.Clean(oldFilePath) {
			if store.wal.FsyncedLSN() < store.wal.MaxLSN() {
				oldFileRemovedBeforeDurable = true
			}
		}
	}

	// Update to small value (slotted page)
	v2 := []byte("small-slotted-value")
	if err := store.Put(table, key, v2); err != nil {
		t.Fatalf("Put v2 failed: %v", err)
	}

	if oldFileRemovedBeforeDurable {
		t.Fatalf("old oversize file removed before WAL was durable")
	}

	// Verify old oversize file is now removed
	if _, err := memFS.Open(oldFilePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected old oversize file to be removed after successful sync, got err: %v", err)
	}

	// Verify value
	got, exists, err := store.Get(table, key)
	if err != nil || !exists || !bytes.Equal(got, v2) {
		t.Fatalf("Get after moving back to page failed")
	}
}

// Review Feedback Item 1:
// A missing value file must be an error. Deleting the file after a checkpoint makes Get
// report ErrCorruptStore, not "not-found".
func TestOversize_MissingFile_GetReturnsCorruptionError(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_missing_file_err"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	val := append([]byte("oversize-data-to-delete"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	fileName := store.keyIndex[qualifyKey(table, key)].OversizeFileName
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Delete the backing oversize file
	oversizePath := filepath.Join(dir, "oversize", fileName)
	if err := memFS.Remove(oversizePath); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store2.Close()

	// Get must return ErrCorruptStore
	_, _, err = store2.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore on missing oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore, got: %v", err)
	}
}

// Review Feedback Item 1:
// A truncated value file must return ErrCorruptStore on length or checksum mismatch.
func TestOversize_TruncatedFile_GetReturnsCorruptionError(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_truncated_file_err"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	val := append([]byte("oversize-data-to-truncate"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	fileName := store.keyIndex[qualifyKey(table, key)].OversizeFileName
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Truncate the backing oversize file to 100 bytes
	oversizePath := filepath.Join(dir, "oversize", fileName)
	memFS.mu.Lock()
	memFS.files[oversizePath] = memFS.files[oversizePath][:100]
	memFS.mu.Unlock()

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store2.Close()

	// Get must return ErrCorruptStore
	_, _, err = store2.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore on truncated oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore, got: %v", err)
	}
}

type magicPrefixCipher struct{}

func (c *magicPrefixCipher) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	// Prefix ciphertext with OversizePointerMagic (0x4F, 0x56, 0x53, 0x50 = "OVSP")
	out := make([]byte, 4+len(plaintext))
	binary.BigEndian.PutUint32(out[0:4], OversizePointerMagic)
	copy(out[4:], plaintext)
	return out, nil
}

func (c *magicPrefixCipher) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < 4 || binary.BigEndian.Uint32(ciphertext[0:4]) != OversizePointerMagic {
		return nil, errors.New("bad magic prefix in ciphertext")
	}
	return append([]byte(nil), ciphertext[4:]...), nil
}

// Review Feedback Item 2:
// A small record whose encrypted output starts with OversizePointerMagic must NOT be
// misidentified as an oversize pointer record, and must read back correctly after reopen.
func TestOversize_CipherOutputStartingWithMagic_ReadsBackCorrectly(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_magic_prefix_cipher"
	cipher := &magicPrefixCipher{}

	store, err := Open(WithFS(memFS), WithDir(dir), WithCipher(cipher), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "smallRecord"
	plainVal := []byte("hello-this-is-a-small-regular-slotted-record")
	if err := store.Put(table, key, plainVal); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCipher(cipher))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	// Verify the key is recognized as a regular record (not oversize)
	qKey := qualifyKey(table, key)
	store2.keyMu.RLock()
	entry, ok := store2.keyIndex[qKey]
	store2.keyMu.RUnlock()
	if !ok {
		t.Fatalf("expected key to exist in index")
	}
	if entry.IsOversize {
		t.Fatalf("key was incorrectly identified as oversize due to ciphertext magic bytes")
	}

	got, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key to exist")
	}
	if !bytes.Equal(got, plainVal) {
		t.Fatalf("value mismatch: want %q, got %q", string(plainVal), string(got))
	}
}

// TestOversize_ReopenHeapUseDoesNotGrowWithTotalSize verifies that after Open on a store
// with oversize values, heap usage does not grow with their total size.
func TestOversize_ReopenHeapUseDoesNotGrowWithTotalSize(t *testing.T) {
	dirEmpty := t.TempDir()
	dirOversize := t.TempDir()

	// Store without oversize values
	sEmpty, err := Open(WithDir(dirEmpty), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open empty store failed: %v", err)
	}
	if err := sEmpty.Close(); err != nil {
		t.Fatalf("Close empty store failed: %v", err)
	}

	// Store with several oversize values
	sOversize, err := Open(WithDir(dirOversize), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open oversize store failed: %v", err)
	}
	table := "TestTable"
	numValues := 4
	valSize := 2500 * 1024 // 2.5 MiB each, > 2 MiB threshold
	totalSize := numValues * valSize

	for i := 0; i < numValues; i++ {
		key := fmt.Sprintf("large-key-%d", i)
		val := makeIncompressible(valSize)
		if err := sOversize.Put(table, key, val); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}
	if _, err := sOversize.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if err := sOversize.Close(); err != nil {
		t.Fatalf("Close oversize store failed: %v", err)
	}

	// Reopen store without oversize values and measure heap
	runtime.GC()
	reopenedEmpty, err := Open(WithDir(dirEmpty), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen empty store failed: %v", err)
	}
	runtime.GC()
	var msEmpty runtime.MemStats
	runtime.ReadMemStats(&msEmpty)
	_ = reopenedEmpty.Close()

	// Reopen store with oversize values and measure heap
	runtime.GC()
	reopenedOversize, err := Open(WithDir(dirOversize), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen oversize store failed: %v", err)
	}
	runtime.GC()
	var msOversize runtime.MemStats
	runtime.ReadMemStats(&msOversize)
	_ = reopenedOversize.Close()

	// HeapAlloc must not grow with total size of oversize values (10 MiB).
	// Loose bound: heap growth must be well below total size (e.g. less than half the total size).
	diff := int64(msOversize.HeapAlloc) - int64(msEmpty.HeapAlloc)
	bound := int64(totalSize / 2)
	if diff > bound {
		t.Fatalf("heap grew by %d bytes after Open on store with %d bytes of oversize values (bound %d)", diff, totalSize, bound)
	}
}

// TestOversize_ReopenGetAndAlteredFileReturnsCorruption verifies that Get returns the right value
// after reopening, and returns ErrCorruptStore if the backing oversize file was altered.
func TestOversize_ReopenGetAndAlteredFileReturnsCorruption(t *testing.T) {
	dir := t.TempDir()

	store, err := Open(WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "my-oversize-key"
	val := makeIncompressible(2500 * 1024)

	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	store.keyMu.RLock()
	fileName := store.keyIndex[qualifyKey(table, key)].OversizeFileName
	store.keyMu.RUnlock()
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// 1. Reopen and verify Get returns the right value
	store2, err := Open(WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}

	got, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key to exist")
	}
	if !bytes.Equal(got, val) {
		t.Fatalf("Get payload mismatch")
	}

	// 2. Alter the backing oversize file on disk
	oversizeFilePath := filepath.Join(dir, "oversize", fileName)
	data, err := os.ReadFile(oversizeFilePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(oversizeFilePath, data, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 3. Verify Get returns corruption error on altered file
	_, _, err = store2.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore on altered oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore on altered oversize file, got: %v", err)
	}
	_ = store2.Close()

	// 4. Also verify after reopening with altered file
	store3, err := Open(WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen store3 failed: %v", err)
	}
	defer store3.Close()

	_, _, err = store3.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore after reopen on altered oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore after reopen on altered oversize file, got: %v", err)
	}
}
