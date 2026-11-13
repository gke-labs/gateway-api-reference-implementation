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
	removeErr    func(name string) error
	beforeRename func(oldpath, newpath string)
	renameErr    func(oldpath, newpath string) error
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
	if h.removeErr != nil {
		if err := h.removeErr(name); err != nil {
			return err
		}
	}
	return h.FS.Remove(name)
}

func (h *oversizeHookFS) Rename(oldpath, newpath string) error {
	if h.beforeRename != nil {
		h.beforeRename(oldpath, newpath)
	}
	if h.renameErr != nil {
		if err := h.renameErr(oldpath, newpath); err != nil {
			return err
		}
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

// TestOversize_ReopenHeapUseDoesNotGrowWithTotalSize verifies that after Put and Get
// on a store with oversize values, heap usage does not grow with their total size.
func TestOversize_ReopenHeapUseDoesNotGrowWithTotalSize(t *testing.T) {
	dirEmpty := t.TempDir()
	dirOversize := t.TempDir()

	// Store without oversize values
	sEmpty, err := Open(WithDir(dirEmpty), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open empty store failed: %v", err)
	}

	// Store with several oversize values: 8 values of 3 MiB = 24 MiB total
	sOversize, err := Open(WithDir(dirOversize), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open oversize store failed: %v", err)
	}
	table := "TestTable"
	numValues := 8
	valSize := 3 * 1024 * 1024 // 3 MiB each
	totalSize := numValues * valSize

	for i := 0; i < numValues; i++ {
		key := fmt.Sprintf("large-key-%d", i)
		val := makeIncompressible(valSize)
		if err := sOversize.Put(table, key, val); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}
	// Get every oversize value on the active store
	for i := 0; i < numValues; i++ {
		key := fmt.Sprintf("large-key-%d", i)
		got, exists, err := sOversize.Get(table, key)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if !exists || len(got) != valSize {
			t.Fatalf("Get returned invalid result: exists=%v, len=%d", exists, len(got))
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
	if err := reopenedEmpty.Close(); err != nil {
		t.Fatalf("Close reopened empty store failed: %v", err)
	}
	if err := sEmpty.Close(); err != nil {
		t.Fatalf("Close empty store failed: %v", err)
	}

	// Reopen store with oversize values, Get every oversize value, and measure heap
	runtime.GC()
	reopenedOversize, err := Open(WithDir(dirOversize), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen oversize store failed: %v", err)
	}
	for i := 0; i < numValues; i++ {
		key := fmt.Sprintf("large-key-%d", i)
		got, exists, err := reopenedOversize.Get(table, key)
		if err != nil {
			t.Fatalf("Get after reopen failed: %v", err)
		}
		if !exists || len(got) != valSize {
			t.Fatalf("Get after reopen returned invalid result: exists=%v, len=%d", exists, len(got))
		}
	}
	runtime.GC()
	var msOversize runtime.MemStats
	runtime.ReadMemStats(&msOversize)
	if err := reopenedOversize.Close(); err != nil {
		t.Fatalf("Close reopened oversize store failed: %v", err)
	}

	// HeapAlloc must not grow with total size of oversize values (24 MiB).
	// Loose bound: heap growth must be well below total size (e.g. less than half the total size).
	diff := int64(msOversize.HeapAlloc) - int64(msEmpty.HeapAlloc)
	bound := int64(totalSize / 2)
	if diff > bound {
		t.Fatalf("heap grew by %d bytes after Put and Get of %d bytes of oversize values (bound %d)", diff, totalSize, bound)
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
	// Also put a healthy small key to verify engine is not failed for healthy keys
	if err := store.Put(table, "healthy-key", []byte("healthy-payload")); err != nil {
		t.Fatalf("Put healthy key failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
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

	// 2. Find the backing oversize file by listing the oversize directory
	entries, err := os.ReadDir(filepath.Join(dir, "oversize"))
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	var fileName string
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			fileName = entry.Name()
			break
		}
	}
	if fileName == "" {
		t.Fatalf("no oversize file found in oversize directory")
	}

	// Alter the backing oversize file on disk
	oversizeFilePath := filepath.Join(dir, "oversize", fileName)
	data, err := os.ReadFile(oversizeFilePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(oversizeFilePath, data, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 3. Verify Get returns corruption error on altered file, but does not fail the engine
	_, _, err = store2.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore on altered oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore on altered oversize file, got: %v", err)
	}
	if store2.isFailed() {
		t.Fatalf("engine unexpectedly entered failed state for corrupted oversize file")
	}

	// Healthy key can still be retrieved
	healthyVal, healthyExists, healthyErr := store2.Get(table, "healthy-key")
	if healthyErr != nil || !healthyExists || string(healthyVal) != "healthy-payload" {
		t.Fatalf("expected healthy key to still be readable, got exists=%v err=%v", healthyExists, healthyErr)
	}

	if err := store2.Close(); err != nil {
		t.Fatalf("Close store2 failed: %v", err)
	}

	// 4. Also verify after reopening with altered file
	store3, err := Open(WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen store3 failed: %v", err)
	}

	_, _, err = store3.Get(table, key)
	if err == nil {
		t.Fatalf("expected ErrCorruptStore after reopen on altered oversize file, got nil")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore after reopen on altered oversize file, got: %v", err)
	}
	if store3.isFailed() {
		t.Fatalf("engine unexpectedly entered failed state on store3 for corrupted oversize file")
	}

	if err := store3.Close(); err != nil {
		t.Fatalf("Close store3 failed: %v", err)
	}
}

// TestOversize_ConcurrentReadersWriter_NoError verifies that concurrent readers
// observe no errors while a writer replaces, deletes and re-puts, or alternates oversize values.
func TestOversize_ConcurrentReadersWriter_NoError(t *testing.T) {
	runTest := func(t *testing.T, writerFunc func(store *Engine, table, key string, stopCh <-chan struct{})) {
		dir := t.TempDir()
		store, err := Open(WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer func() {
			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}
		}()

		table := "ConcurrentTable"
		key := "target-key"

		// Initial seed value: oversize
		initialVal := makeIncompressible(2500 * 1024)
		if err := store.Put(table, key, initialVal); err != nil {
			t.Fatalf("initial Put failed: %v", err)
		}

		stopCh := make(chan struct{})
		errCh := make(chan error, 100)
		var wg sync.WaitGroup

		// 4 concurrent readers
		for r := 0; r < 4; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopCh:
						return
					default:
						_, _, err := store.Get(table, key)
						if err != nil {
							select {
							case errCh <- err:
							default:
							}
							return
						}
					}
				}
			}()
		}

		// Run writer
		writerFunc(store, table, key, stopCh)
		close(stopCh)
		wg.Wait()

		close(errCh)
		for readErr := range errCh {
			t.Fatalf("reader observed error during concurrent writes: %v", readErr)
		}
	}

	t.Run("ReplaceOversizeWithValue", func(t *testing.T) {
		runTest(t, func(store *Engine, table, key string, stopCh <-chan struct{}) {
			for i := 0; i < 50; i++ {
				val := makeIncompressible((2100 + (i%5)*100) * 1024)
				if err := store.Put(table, key, val); err != nil {
					t.Fatalf("Put failed: %v", err)
				}
			}
		})
	})

	t.Run("DeleteAndRePut", func(t *testing.T) {
		runTest(t, func(store *Engine, table, key string, stopCh <-chan struct{}) {
			val := makeIncompressible(2500 * 1024)
			for i := 0; i < 50; i++ {
				if err := store.Delete(table, key); err != nil {
					t.Fatalf("Delete failed: %v", err)
				}
				if err := store.Put(table, key, val); err != nil {
					t.Fatalf("Put failed: %v", err)
				}
			}
		})
	})

	t.Run("AlternateOversizeAndSmall", func(t *testing.T) {
		runTest(t, func(store *Engine, table, key string, stopCh <-chan struct{}) {
			oversizeVal := makeIncompressible(2500 * 1024)
			smallVal := []byte("small-slotted-payload")
			for i := 0; i < 50; i++ {
				var val []byte
				if i%2 == 0 {
					val = smallVal
				} else {
					val = oversizeVal
				}
				if err := store.Put(table, key, val); err != nil {
					t.Fatalf("Put failed: %v", err)
				}
			}
		})
	})
}

// A test through Open: write an oversize value, crash after the file is durable but before
// its pointer record (fault-injecting filesystem), reopen. The orphan is quarantined to lost+found,
// and the key keeps its previous value.
func TestOversize_Recovery_CrashBeforePointerRecord_QuarantinesOrphanAndPreservesPreviousValue(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	hookFS := &oversizeHookFS{FS: faultFS}
	dir := "test_oversize_recovery_orphan"

	store, err := Open(WithFS(hookFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	prevVal := []byte("previous-durable-value")
	if err := store.Put(table, key, prevVal); err != nil {
		t.Fatalf("Put prevVal failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	oversizeVal := append([]byte("orphan-oversize-content"), make([]byte, 2100*1024)...)
	oversizeDir := filepath.Join(dir, "oversize")

	var crashed bool
	var orphanFileName string
	doneCh := make(chan struct{})
	hookFS.onSyncDir = func(dirname string) {
		if filepath.Clean(dirname) == filepath.Clean(oversizeDir) && !crashed {
			crashed = true
			entries, _ := memFS.ReadDir(oversizeDir)
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".obj") {
					orphanFileName = e.Name()
				}
			}
			_ = faultFS.Crash(true, 0)
			close(doneCh)
			runtime.Goexit()
		}
	}

	go func() {
		_ = store.Put(table, key, oversizeVal)
	}()

	<-doneCh

	if orphanFileName == "" {
		t.Fatalf("expected orphan file to have been created before crash")
	}

	// Stop the store without allowing new writes to complete
	_ = store.Close()

	orphanPath := filepath.Join(oversizeDir, orphanFileName)
	if f, err := memFS.Open(orphanPath); err != nil {
		t.Fatalf("expected orphan file %s to exist on disk before recovery: %v", orphanPath, err)
	} else if err := f.Close(); err != nil {
		t.Fatalf("close orphan file failed: %v", err)
	}

	store2, err := Open(WithFS(hookFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen after crash failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Fatalf("store2.Close failed: %v", err)
		}
	}()

	// Orphan file must no longer reside in oversize/
	if f, err := memFS.Open(orphanPath); err == nil {
		_ = f.Close()
		t.Fatalf("expected orphan file %s to be moved out of oversize directory, but it exists", orphanPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected orphan file %s to not exist in oversize dir, got err: %v", orphanPath, err)
	}

	// Orphan file must be quarantined in lost+found
	lostDir := filepath.Join(oversizeDir, "lost+found")
	lostEntries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	var foundQuarantined bool
	for _, entry := range lostEntries {
		if strings.HasPrefix(entry.Name(), orphanFileName) {
			foundQuarantined = true
			break
		}
	}
	if !foundQuarantined {
		t.Fatalf("expected orphan file %s to be quarantined in %s", orphanFileName, lostDir)
	}

	gotVal, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get key failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key %s to exist with previous value", key)
	}
	if !bytes.Equal(gotVal, prevVal) {
		t.Fatalf("value mismatch: got %q, want %q", string(gotVal), string(prevVal))
	}
}

// A test: a referenced file is never quarantined by the startup pass.
func TestOversize_Recovery_ReferencedFileNeverQuarantinedByStartupPass(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_referenced_not_quarantined"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	k1 := "key1"
	v1 := append([]byte("oversize-data-1"), make([]byte, 2100*1024)...)
	if err := store.Put(table, k1, v1); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}

	k2 := "key2"
	v2 := append([]byte("oversize-data-2"), make([]byte, 2200*1024)...)
	if err := store.Put(table, k2, v2); err != nil {
		t.Fatalf("Put k2 failed: %v", err)
	}

	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	oversizeDir := filepath.Join(dir, "oversize")
	entries, err := memFS.ReadDir(oversizeDir)
	if err != nil {
		t.Fatalf("ReadDir oversize failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 oversize files, got %d", len(entries))
	}

	var paths []string
	for _, entry := range entries {
		paths = append(paths, filepath.Join(oversizeDir, entry.Name()))
	}

	for _, p := range paths {
		f, err := memFS.Open(p)
		if err != nil {
			t.Fatalf("expected oversize file %s to exist: %v", p, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close oversize file failed: %v", err)
		}
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	syncCountBefore := memFS.DirSyncCount(oversizeDir)

	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Fatalf("store2.Close failed: %v", err)
		}
	}()

	// SyncDir on oversize directory should only happen when files were quarantined
	syncCountAfter := memFS.DirSyncCount(oversizeDir)
	if syncCountAfter != syncCountBefore {
		t.Fatalf("expected no SyncDir when no files quarantined, but sync count increased from %d to %d", syncCountBefore, syncCountAfter)
	}

	for _, p := range paths {
		f, err := memFS.Open(p)
		if err != nil {
			t.Fatalf("referenced oversize file %s was moved by recovery startup pass: %v", p, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close oversize file failed: %v", err)
		}
	}

	// lost+found should have no quarantined files
	lostDir := filepath.Join(oversizeDir, "lost+found")
	if lostEntries, err := memFS.ReadDir(lostDir); err == nil && len(lostEntries) > 0 {
		t.Fatalf("expected no files in lost+found, got %d", len(lostEntries))
	}

	got1, exists1, err := store2.Get(table, k1)
	if err != nil || !exists1 || !bytes.Equal(got1, v1) {
		t.Fatalf("Get k1 failed or value mismatch: exists=%v, err=%v", exists1, err)
	}
	got2, exists2, err := store2.Get(table, k2)
	if err != nil || !exists2 || !bytes.Equal(got2, v2) {
		t.Fatalf("Get k2 failed or value mismatch: exists=%v, err=%v", exists2, err)
	}
}

// A test for a pointer that only the WAL holds: write an oversize value, call Sync,
// crash with the fault-injecting filesystem before any checkpoint, and reopen.
// The file is still there and the value reads back.
func TestOversize_Recovery_WALOnlyPointer_ReferencedFileNeverQuarantined(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "test_oversize_wal_only_pointer"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "walOnlyKey"
	val := append([]byte("wal-only-oversize-content"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Sync fsyncs WAL records without checkpointing or flushing heap pages
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	oversizeDir := filepath.Join(dir, "oversize")
	entries, err := memFS.ReadDir(oversizeDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 oversize file in directory, got %d (err: %v)", len(entries), err)
	}
	oversizePath := filepath.Join(oversizeDir, entries[0].Name())

	// Crash drops un-fsynced heap data before any checkpoint.
	// Abandon the crashed engine without calling Close() so that nothing is written after the crash.
	if err := faultFS.Crash(true, 0); err != nil {
		t.Fatalf("Crash failed: %v", err)
	}

	// Reopen store: pointer must be recovered from WAL redo replay, and recovery
	// startup pass must never quarantine this referenced file.
	store2, err := Open(WithFS(faultFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Fatalf("store2.Close failed: %v", err)
		}
	}()

	f, err := memFS.Open(oversizePath)
	if err != nil {
		t.Fatalf("referenced oversize file %s was moved by recovery: %v", oversizePath, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close oversize file failed: %v", err)
	}

	gotVal, exists, err := store2.Get(table, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key %s to exist after WAL replay", key)
	}
	if !bytes.Equal(gotVal, val) {
		t.Fatalf("value mismatch: got len=%d, want len=%d", len(gotVal), len(val))
	}
}

// A test with a filesystem whose Rename returns an error when quarantining an unreferenced file:
// Open must fail rather than operating on a failing filesystem.
func TestOversize_Recovery_QuarantineError_FailsOpen(t *testing.T) {
	memFS := NewMemFS()
	hookFS := &oversizeHookFS{FS: memFS}
	dir := "test_oversize_quarantine_err_fails_open"

	store, err := Open(WithFS(hookFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Create an unreferenced orphan file
	orphanPath := filepath.Join(dir, "oversize", "orphan.obj")
	f, err := memFS.OpenFile(orphanPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if _, err := f.WriteAt([]byte("orphan-payload"), 0); err != nil {
		_ = f.Close()
		t.Fatalf("WriteAt orphan file failed: %v", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatalf("Sync orphan file failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close orphan file failed: %v", err)
	}

	// Inject quarantine rename error
	injectedErr := errors.New("simulated disk error on rename to quarantine")
	hookFS.renameErr = func(oldpath, newpath string) error {
		if filepath.Clean(oldpath) == filepath.Clean(orphanPath) {
			return injectedErr
		}
		return nil
	}

	// Reopen must fail
	store2, err := Open(WithFS(hookFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err == nil {
		if closeErr := store2.Close(); closeErr != nil {
			t.Errorf("store2.Close failed: %v", closeErr)
		}
		t.Fatalf("expected Open to fail when Rename fails, got nil error")
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected Open to return injected quarantine error, got: %v", err)
	}
}

// Recovery startup pass quarantines orphaned previous-version files and leftover temp files.
func TestOversize_Recovery_QuarantinesOldVersionAndTempOrphans(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_old_and_temp_orphans"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "TestTable"
	key := "targetKey"
	v1 := append([]byte("oversize-v1"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, v1); err != nil {
		t.Fatalf("Put v1 failed: %v", err)
	}

	oversizeDir := filepath.Join(dir, "oversize")
	entriesV1, err := memFS.ReadDir(oversizeDir)
	if err != nil || len(entriesV1) != 1 {
		t.Fatalf("expected 1 oversize file after v1, got %d (err: %v)", len(entriesV1), err)
	}
	oldFileName := entriesV1[0].Name()
	oldFilePath := filepath.Join(oversizeDir, oldFileName)

	v2 := append([]byte("oversize-v2"), make([]byte, 2100*1024)...)
	if err := store.Put(table, key, v2); err != nil {
		t.Fatalf("Put v2 failed: %v", err)
	}

	entriesV2, err := memFS.ReadDir(oversizeDir)
	if err != nil || len(entriesV2) != 1 {
		t.Fatalf("expected 1 oversize file after v2, got %d (err: %v)", len(entriesV2), err)
	}
	newFilePath := filepath.Join(oversizeDir, entriesV2[0].Name())

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Recreate the old file on disk (simulating removal having been skipped or interrupted before deletion)
	oldF, err := memFS.OpenFile(oldFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
	if err != nil {
		t.Fatalf("failed to create old file: %v", err)
	}
	if _, err := oldF.WriteAt(v1, 0); err != nil {
		_ = oldF.Close()
		t.Fatalf("WriteAt old file failed: %v", err)
	}
	if err := oldF.Sync(); err != nil {
		_ = oldF.Close()
		t.Fatalf("Sync old file failed: %v", err)
	}
	if err := oldF.Close(); err != nil {
		t.Fatalf("Close old file failed: %v", err)
	}

	// Also create a leftover temp file in oversize dir
	tempFileName := ".tmp-fake-orphan-12345"
	tempPath := filepath.Join(oversizeDir, tempFileName)
	tempF, err := memFS.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tempF.WriteAt([]byte("partial temp bytes"), 0); err != nil {
		_ = tempF.Close()
		t.Fatalf("WriteAt temp file failed: %v", err)
	}
	if err := tempF.Sync(); err != nil {
		_ = tempF.Close()
		t.Fatalf("Sync temp file failed: %v", err)
	}
	if err := tempF.Close(); err != nil {
		t.Fatalf("Close temp file failed: %v", err)
	}

	// Reopen store through Open
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Fatalf("store2.Close failed: %v", err)
		}
	}()

	// Verify old file is gone from oversize/
	if f, err := memFS.Open(oldFilePath); err == nil {
		_ = f.Close()
		t.Fatalf("expected old file %s to be moved by recovery, but it exists in oversize/", oldFilePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected old file %s to not exist in oversize/, got err: %v", oldFilePath, err)
	}

	// Verify temp file is gone from oversize/
	if f, err := memFS.Open(tempPath); err == nil {
		_ = f.Close()
		t.Fatalf("expected temp file %s to be moved by recovery, but it exists in oversize/", tempPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected temp file %s to not exist in oversize/, got err: %v", tempPath, err)
	}

	// Verify both were quarantined in lost+found
	lostDir := filepath.Join(oversizeDir, "lost+found")
	lostEntries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	var foundOld, foundTemp bool
	for _, e := range lostEntries {
		if strings.HasPrefix(e.Name(), oldFileName) {
			foundOld = true
		}
		if strings.HasPrefix(e.Name(), tempFileName) {
			foundTemp = true
		}
	}
	if !foundOld || !foundTemp {
		t.Fatalf("expected old file and temp file to be quarantined in %s; foundOld=%v, foundTemp=%v", lostDir, foundOld, foundTemp)
	}

	// Verify new file is intact
	if f, err := memFS.Open(newFilePath); err != nil {
		t.Fatalf("expected new file %s to be intact, got err: %v", newFilePath, err)
	} else if err := f.Close(); err != nil {
		t.Fatalf("Close new file failed: %v", err)
	}

	// Verify value reads back as v2
	gotVal, exists, err := store2.Get(table, key)
	if err != nil || !exists || !bytes.Equal(gotVal, v2) {
		t.Fatalf("Get key failed: exists=%v, err=%v", exists, err)
	}
}

// TestOversize_Recovery_QuarantineBoundsApplied verifies that unreferenced oversize files
// quarantined to lost+found are bounded by QuarantineOptions.
func TestOversize_Recovery_QuarantineBoundsApplied(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_quarantine_bounds"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate(),
		WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2, MinQuarantinedRetention: -1}))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	oversizeDir := filepath.Join(dir, "oversize")
	if err := memFS.MkdirAll(oversizeDir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create 3 unreferenced files
	for i := 1; i <= 3; i++ {
		p := filepath.Join(oversizeDir, fmt.Sprintf("orphan-%d.obj", i))
		f, err := memFS.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile %s failed: %v", p, err)
		}
		if _, err := f.WriteAt([]byte(fmt.Sprintf("orphan-%d", i)), 0); err != nil {
			_ = f.Close()
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			t.Fatalf("Sync failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	}

	// Reopen with MaxQuarantinedFiles = 2
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone),
		WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2, MinQuarantinedRetention: -1}))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer func() {
		if err := store2.Close(); err != nil {
			t.Fatalf("store2.Close failed: %v", err)
		}
	}()

	lostDir := filepath.Join(oversizeDir, "lost+found")
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected exactly 2 quarantined files in lost+found (bounded by MaxQuarantinedFiles), got %d", len(entries))
	}
}
