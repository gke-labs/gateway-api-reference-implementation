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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func openExternalStore(t *testing.T, fs FS, dir string, config ExternalLogConfig, extraOptions ...Option) *Engine {
	t.Helper()
	options := make([]Option, 0, 4+len(extraOptions))
	if fs != nil {
		options = append(options, WithFS(fs))
	}
	options = append(options, WithDir(dir), WithExternalLog(config))
	options = append(options, extraOptions...)
	store, err := Open(options...)
	if err != nil {
		t.Fatalf("Open(%s) failed: %v", dir, err)
	}
	return store
}

func closeStore(t *testing.T, store *Engine) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func assertNoWALFilesMemFS(t *testing.T, memFS *MemFS, dir string) {
	t.Helper()
	memFS.mu.RLock()
	defer memFS.mu.RUnlock()
	prefix := filepath.Clean(dir)
	for path := range memFS.files {
		if strings.HasPrefix(path, prefix) && (strings.HasSuffix(path, ".wal") || strings.Contains(path, string(filepath.Separator)+"wal"+string(filepath.Separator))) {
			t.Fatalf("unexpected WAL file created in external-log mode: %s", path)
		}
	}
	walDir := filepath.Join(prefix, "wal")
	if memFS.directories[walDir] {
		t.Fatalf("unexpected wal directory created in external-log mode: %s", walDir)
	}
}

func makeIncompressiblePayload(size int) []byte {
	payload := make([]byte, size)
	state := uint64(0x9e3779b97f4a7c15)
	for index := range payload {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		payload[index] = byte(state)
	}
	return payload
}

func TestExternalLog_ModeEnforcement(t *testing.T) {
	t.Run("requires DurableLSN", func(t *testing.T) {
		memFS := NewMemFS()
		if _, err := Open(WithFS(memFS), WithDir("missing_durable"), WithCreate(), WithExternalLog(ExternalLogConfig{})); err == nil {
			t.Fatalf("expected Open to fail when DurableLSN is nil")
		}
		if _, err := Open(WithFS(memFS), WithDir("wait_only"), WithCreate(), WithExternalLog(ExternalLogConfig{
			WaitDurable: func(uint64) error { return nil },
		})); err == nil {
			t.Fatalf("expected Open to fail when DurableLSN is nil even if WaitDurable is set")
		}
	})

	t.Run("external-log mode rejects Put, Delete, and Sync", func(t *testing.T) {
		memFS := NewMemFS()
		var watermark atomic.Uint64
		store := openExternalStore(t, memFS, "ext_mode", ExternalLogConfig{DurableLSN: watermark.Load}, WithCreate())
		defer closeStore(t, store)

		if err := store.Put("t", "k1", []byte("v1")); !errors.Is(err, ErrExternalLogMode) {
			t.Fatalf("expected ErrExternalLogMode from Put, got: %v", err)
		}
		if err := store.Delete("t", "k1"); !errors.Is(err, ErrExternalLogMode) {
			t.Fatalf("expected ErrExternalLogMode from Delete, got: %v", err)
		}
		if err := store.Sync(); !errors.Is(err, ErrExternalLogMode) {
			t.Fatalf("expected ErrExternalLogMode from Sync, got: %v", err)
		}
		if got := store.WALBytesWritten(); got != 0 {
			t.Fatalf("expected WALBytesWritten == 0 in external-log mode, got %d", got)
		}
		assertNoWALFilesMemFS(t, memFS, "ext_mode")
	})

	t.Run("local-WAL mode rejects ApplyPut and ApplyDelete", func(t *testing.T) {
		memFS := NewMemFS()
		store, err := Open(WithFS(memFS), WithDir("wal_mode"), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer closeStore(t, store)

		if err := store.ApplyPut("t", "k1", []byte("v1"), 1); !errors.Is(err, ErrLocalWALMode) {
			t.Fatalf("expected ErrLocalWALMode from ApplyPut, got: %v", err)
		}
		if err := store.ApplyDelete("t", "k1", 1); !errors.Is(err, ErrLocalWALMode) {
			t.Fatalf("expected ErrLocalWALMode from ApplyDelete, got: %v", err)
		}
	})
}

func TestExternalLog_MonotonicPositionsAndMutations(t *testing.T) {
	memFS := NewMemFS()
	var watermark atomic.Uint64
	watermark.Store(100)

	store := openExternalStore(
		t,
		memFS,
		"ext_mono",
		ExternalLogConfig{DurableLSN: watermark.Load},
		WithCreate(),
		WithCompressionCodec(CodecNone),
	)
	defer closeStore(t, store)

	// Reject LSN 0 without advancing Position.
	if err := store.ApplyPut("t", "k1", []byte("zero"), 0); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for LSN 0, got: %v", err)
	}
	if store.Position() != 0 {
		t.Fatalf("expected Position 0 after rejected put, got %d", store.Position())
	}

	if err := store.ApplyPut("t", "k1", []byte("v1"), 5); err != nil {
		t.Fatalf("ApplyPut LSN 5 failed: %v", err)
	}
	if store.Position() != 5 {
		t.Fatalf("expected Position 5, got %d", store.Position())
	}

	// Reject duplicate and regressing positions without failing the engine.
	if err := store.ApplyPut("t", "k1", []byte("dup"), 5); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for duplicate LSN 5, got: %v", err)
	}
	if err := store.ApplyPut("t", "k2", []byte("old"), 3); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for older LSN 3, got: %v", err)
	}
	if err := store.ApplyDelete("t", "k1", 5); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for delete at LSN 5, got: %v", err)
	}

	value, exists, err := store.Get("t", "k1")
	if err != nil || !exists || string(value) != "v1" {
		t.Fatalf("unexpected Get(k1): value=%q exists=%v err=%v", value, exists, err)
	}

	// Deleting a nonexistent key still advances Position.
	if err := store.ApplyDelete("t", "nonexistent", 7); err != nil {
		t.Fatalf("ApplyDelete nonexistent at LSN 7 failed: %v", err)
	}
	if store.Position() != 7 {
		t.Fatalf("expected Position 7 after delete of nonexistent key, got %d", store.Position())
	}
	if err := store.ApplyPut("t", "k2", []byte("bad"), 7); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN at LSN 7, got: %v", err)
	}

	multiBlockValue := bytes.Repeat([]byte("multi-block-ext-"), 400)
	if err := store.ApplyPut("t", "k1", []byte("v1-updated"), 10); err != nil {
		t.Fatalf("ApplyPut overwrite k1 failed: %v", err)
	}
	if err := store.ApplyPut("t", "k2", multiBlockValue, 11); err != nil {
		t.Fatalf("ApplyPut multi-block k2 failed: %v", err)
	}
	if err := store.ApplyDelete("t", "k1", 12); err != nil {
		t.Fatalf("ApplyDelete k1 failed: %v", err)
	}

	if _, exists, err := store.Get("t", "k1"); err != nil || exists {
		t.Fatalf("expected k1 deleted, got exists=%v err=%v", exists, err)
	}
	gotMultiBlock, exists, err := store.Get("t", "k2")
	if err != nil || !exists || !bytes.Equal(gotMultiBlock, multiBlockValue) {
		t.Fatalf("multi-block Get(k2) mismatch: exists=%v err=%v", exists, err)
	}

	assertNoWALFilesMemFS(t, memFS, "ext_mono")
}

func TestExternalLog_WriteAheadRule(t *testing.T) {
	t.Run("ErrNotDurable is transient and Checkpoint succeeds once watermark advances", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		var watermark atomic.Uint64
		watermark.Store(5)
		faultFS.SetMaxFsyncedLSN(5)

		store := openExternalStore(
			t,
			faultFS,
			"wal_rule_transient",
			ExternalLogConfig{DurableLSN: watermark.Load},
			WithCreate(),
			WithCompressionCodec(CodecNone),
		)
		defer closeStore(t, store)

		if err := store.ApplyPut("t", "k1", []byte("v1"), 10); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}

		// Checkpoint fails with ErrNotDurable while watermark (5) lags page LSN (10).
		if err := store.Checkpoint(); !errors.Is(err, ErrNotDurable) {
			t.Fatalf("expected ErrNotDurable on Checkpoint when watermark < page LSN, got: %v", err)
		}
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("unexpected FaultFS rule violations: %v", violations)
		}
		memFS.mu.RLock()
		heapLen := len(memFS.files[filepath.Join("wal_rule_transient", "heap.db")])
		memFS.mu.RUnlock()
		if heapLen != 0 {
			t.Fatalf("expected heap.db to remain empty when flush blocked by watermark, got %d bytes", heapLen)
		}

		// The store must remain healthy and accept reads and further writes.
		value, exists, err := store.Get("t", "k1")
		if err != nil || !exists || string(value) != "v1" {
			t.Fatalf("store became unusable after transient ErrNotDurable: value=%q exists=%v err=%v", value, exists, err)
		}
		if err := store.ApplyPut("t", "k2", []byte("v2"), 12); err != nil {
			t.Fatalf("ApplyPut after transient ErrNotDurable failed: %v", err)
		}

		// Advancing the watermark allows Checkpoint to flush and advance meta.db.
		watermark.Store(12)
		faultFS.SetMaxFsyncedLSN(12)
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 1 failed after advancing watermark: %v", err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 2 failed after advancing watermark: %v", err)
		}
		if store.RecoveryPosition() != 12 {
			t.Fatalf("expected RecoveryPosition 12, got %d", store.RecoveryPosition())
		}
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("unexpected FaultFS rule violations after checkpoint: %v", violations)
		}
	})

	t.Run("metadata-only checkpoint checks watermark and succeeds once watermark advances", func(t *testing.T) {
		memFS := NewMemFS()
		var watermark atomic.Uint64
		watermark.Store(5)

		store := openExternalStore(
			t,
			memFS,
			"wal_rule_nodirty",
			ExternalLogConfig{DurableLSN: watermark.Load},
			WithCreate(),
		)
		defer closeStore(t, store)

		if err := store.ApplyDelete("t", "missing", 10); err != nil {
			t.Fatalf("ApplyDelete failed: %v", err)
		}
		if err := store.Checkpoint(); !errors.Is(err, ErrNotDurable) {
			t.Fatalf("expected ErrNotDurable when advancing meta.db past watermark, got: %v", err)
		}
		if store.RecoveryPosition() != 0 {
			t.Fatalf("expected RecoveryPosition to stay 0, got %d", store.RecoveryPosition())
		}

		watermark.Store(10)
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint failed after watermark advanced: %v", err)
		}
		if store.RecoveryPosition() != 10 {
			t.Fatalf("expected RecoveryPosition 10, got %d", store.RecoveryPosition())
		}
	})

	t.Run("blocking WaitDurable waits before heap writes", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		var watermark atomic.Uint64
		waitStarted := make(chan struct{})
		releaseWait := make(chan struct{})
		var waitedLSN atomic.Uint64

		store := openExternalStore(
			t,
			faultFS,
			"wal_rule_wait",
			ExternalLogConfig{
				DurableLSN: watermark.Load,
				WaitDurable: func(lsn uint64) error {
					if lsn > watermark.Load() {
						waitedLSN.Store(lsn)
						close(waitStarted)
						<-releaseWait
					}
					if lsn > watermark.Load() {
						return ErrNotDurable
					}
					return nil
				},
			},
			WithCreate(),
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
		)

		if err := store.ApplyPut("t", "k1", []byte("v1"), 10); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}

		checkpointDone := make(chan error, 1)
		go func() {
			checkpointDone <- store.Checkpoint()
		}()

		<-waitStarted
		if got := waitedLSN.Load(); got != 10 {
			t.Fatalf("expected WaitDurable(10), got WaitDurable(%d)", got)
		}

		watermark.Store(10)
		faultFS.SetMaxFsyncedLSN(10)
		close(releaseWait)

		if err := <-checkpointDone; err != nil {
			t.Fatalf("Checkpoint failed after durability released: %v", err)
		}
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("FaultFS detected rule violations: %v", violations)
		}
		closeStore(t, store)
		assertNoWALFilesMemFS(t, memFS, "wal_rule_wait")
	})

	t.Run("oversize replacement does not block on WaitDurable when watermark lags", func(t *testing.T) {
		memFS := NewMemFS()
		var watermark atomic.Uint64
		watermark.Store(1)
		var waitCalled atomic.Bool

		store := openExternalStore(
			t,
			memFS,
			"wal_rule_oversize",
			ExternalLogConfig{
				DurableLSN: watermark.Load,
				WaitDurable: func(lsn uint64) error {
					waitCalled.Store(true)
					if lsn > watermark.Load() {
						return ErrNotDurable
					}
					return nil
				},
			},
			WithCreate(),
			WithCompressionCodec(CodecNone),
			WithQuarantine(QuarantineOptions{SweepInterval: -1}),
		)

		oversizeValue := makeIncompressiblePayload((MaxBatchBlocks + 8) * BlockSize)
		if err := store.ApplyPut("blobs", "b1", oversizeValue, 1); err != nil {
			t.Fatalf("ApplyPut oversize LSN 1 failed: %v", err)
		}
		store.keyMu.RLock()
		firstFile := store.keyIndex[qualifyKey("blobs", "b1")].OversizeFileName
		store.keyMu.RUnlock()

		// Overwrite at LSN 2 while DurableLSN is still 1: must not call WaitDurable
		// and must leave firstFile intact on disk.
		if err := store.ApplyPut("blobs", "b1", []byte("small"), 2); err != nil {
			t.Fatalf("ApplyPut overwrite LSN 2 failed: %v", err)
		}
		if waitCalled.Load() {
			t.Fatalf("ApplyPut must not invoke blocking WaitDurable under writerMu")
		}
		openedFirst, err := memFS.Open(filepath.Join("wal_rule_oversize", "oversize", firstFile))
		if err != nil {
			t.Fatalf("expected superseded oversize file to remain when watermark lags: %v", err)
		}
		if err := openedFirst.Close(); err != nil {
			t.Fatalf("failed to close oversize file: %v", err)
		}

		// Overwrite another oversize value at LSN 4 when DurableLSN >= 4: unlinks immediately.
		watermark.Store(4)
		if err := store.ApplyPut("blobs", "b2", oversizeValue, 3); err != nil {
			t.Fatalf("ApplyPut oversize LSN 3 failed: %v", err)
		}
		store.keyMu.RLock()
		secondFile := store.keyIndex[qualifyKey("blobs", "b2")].OversizeFileName
		store.keyMu.RUnlock()
		if err := store.ApplyDelete("blobs", "b2", 4); err != nil {
			t.Fatalf("ApplyDelete oversize LSN 4 failed: %v", err)
		}
		if _, err := memFS.Open(filepath.Join("wal_rule_oversize", "oversize", secondFile)); !os.IsNotExist(err) {
			t.Fatalf("expected superseded oversize file to be unlinked when durable, got err=%v", err)
		}

		closeStore(t, store)
	})
}

func TestExternalLog_ReopenAndCheckpoints(t *testing.T) {
	t.Run("clean close and reopen preserves data, position, and meta.db recovery position", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		dir := "ext_reopen_clean"
		var watermark atomic.Uint64

		store := openExternalStore(
			t,
			faultFS,
			dir,
			ExternalLogConfig{DurableLSN: watermark.Load},
			WithCreate(),
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
		)

		expected := make(map[string][]byte)
		lsn := uint64(0)
		applyPut := func(key string, value []byte) {
			t.Helper()
			lsn++
			watermark.Store(lsn)
			faultFS.SetMaxFsyncedLSN(lsn)
			if err := store.ApplyPut("items", key, value, lsn); err != nil {
				t.Fatalf("ApplyPut(%s, %d) failed: %v", key, lsn, err)
			}
			expected[key] = bytes.Clone(value)
		}

		for index := 0; index < 30; index++ {
			key := "k-" + string(rune('a'+(index%26))) + "-" + string(rune('0'+(index/26)))
			value := bytes.Repeat([]byte{byte('a' + (index % 26))}, 1500)
			applyPut(key, value)
		}

		// Two checkpoints flush dirty pages and advance meta.db to lsn.
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 1 failed: %v", err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 2 failed: %v", err)
		}
		checkpointPosition := store.RecoveryPosition()
		if checkpointPosition != lsn {
			t.Fatalf("expected RecoveryPosition %d after second checkpoint, got %d", lsn, checkpointPosition)
		}
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("FaultFS detected rule violations: %v", violations)
		}
		closeStore(t, store)
		assertNoWALFilesMemFS(t, memFS, dir)

		reopened := openExternalStore(
			t,
			memFS,
			dir,
			ExternalLogConfig{DurableLSN: watermark.Load},
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
		)
		defer closeStore(t, reopened)

		if reopened.Position() != lsn {
			t.Fatalf("expected Position %d after reopen, got %d", lsn, reopened.Position())
		}
		if reopened.RecoveryPosition() != checkpointPosition {
			t.Fatalf("expected RecoveryPosition %d after reopen, got %d", checkpointPosition, reopened.RecoveryPosition())
		}
		for key, want := range expected {
			got, exists, err := reopened.Get("items", key)
			if err != nil || !exists || !bytes.Equal(got, want) {
				t.Fatalf("key %s mismatch after reopen: exists=%v err=%v", key, exists, err)
			}
		}

		// Monotonic position enforcement continues from recovered position.
		if err := reopened.ApplyPut("items", "next", []byte("bad"), lsn); !errors.Is(err, ErrNonMonotonicLSN) {
			t.Fatalf("expected ErrNonMonotonicLSN at LSN %d, got: %v", lsn, err)
		}
		lsn++
		watermark.Store(lsn)
		if err := reopened.ApplyPut("items", "next", []byte("ok"), lsn); err != nil {
			t.Fatalf("ApplyPut at LSN %d failed: %v", lsn, err)
		}
		assertNoWALFilesMemFS(t, memFS, dir)
	})

	t.Run("unclean reopen returns an error", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_unclean"
		var watermark atomic.Uint64
		watermark.Store(5)

		store := openExternalStore(t, memFS, dir, ExternalLogConfig{DurableLSN: watermark.Load}, WithCreate())
		if err := store.ApplyPut("t", "k1", []byte("v1"), 5); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}
		crashedFS := cloneMemFS(memFS)
		closeStore(t, store)

		if _, err := Open(WithFS(crashedFS), WithDir(dir), WithExternalLog(ExternalLogConfig{
			DurableLSN: watermark.Load,
		})); err == nil {
			t.Fatalf("expected error reopening uncleanly closed external-log store")
		}
	})

	t.Run("reopen fails when DurableLSN lags MaxHeapLSN or metadata-only recoveryStartLSN", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_lagging_watermark"
		var watermark atomic.Uint64
		watermark.Store(30)

		store := openExternalStore(t, memFS, dir, ExternalLogConfig{DurableLSN: watermark.Load}, WithCreate())
		if err := store.ApplyPut("t", "k1", []byte("v1"), 10); err != nil {
			t.Fatalf("ApplyPut LSN 10 failed: %v", err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 1 failed: %v", err)
		}
		// Advance Position to 30 via a metadata-only delete so recoveryStartLSN (30) > MaxHeapLSN (10).
		if err := store.ApplyDelete("t", "nonexistent", 30); err != nil {
			t.Fatalf("ApplyDelete LSN 30 failed: %v", err)
		}
		closeStore(t, store)

		// Watermark 5 < MaxHeapLSN (10): must fail.
		watermark.Store(5)
		if _, err := Open(WithFS(memFS), WithDir(dir), WithExternalLog(ExternalLogConfig{
			DurableLSN: watermark.Load,
		})); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore when DurableLSN < MaxHeapLSN, got: %v", err)
		}

		// Watermark 20 >= MaxHeapLSN (10) but < recoveryStartLSN (30): must fail.
		watermark.Store(20)
		if _, err := Open(WithFS(memFS), WithDir(dir), WithExternalLog(ExternalLogConfig{
			DurableLSN: watermark.Load,
		})); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore when DurableLSN < recoveryStartLSN, got: %v", err)
		}

		// Watermark 30 covers both MaxHeapLSN and recoveryStartLSN: succeeds.
		watermark.Store(30)
		reopened := openExternalStore(t, memFS, dir, ExternalLogConfig{DurableLSN: watermark.Load})
		defer closeStore(t, reopened)
		if reopened.Position() != 30 {
			t.Fatalf("expected Position 30, got %d", reopened.Position())
		}
	})
}

func TestExternalLog_EncryptedOversizeAndOSFSNoWAL(t *testing.T) {
	dir := t.TempDir()
	key, err := NewEncryptionKey()
	if err != nil {
		t.Fatalf("NewEncryptionKey failed: %v", err)
	}
	var watermark atomic.Uint64
	watermark.Store(2)

	store := openExternalStore(
		t,
		nil,
		dir,
		ExternalLogConfig{DurableLSN: watermark.Load},
		WithCreate(),
		WithEncryptionKey(key),
		WithCompressionCodec(CodecZstd),
	)

	oversizeValue := makeIncompressiblePayload((MaxBatchBlocks + 32) * BlockSize)
	if err := store.ApplyPut("blobs", "b1", oversizeValue, 1); err != nil {
		t.Fatalf("ApplyPut oversize failed: %v", err)
	}
	if err := store.ApplyPut("blobs", "small", []byte("hello encrypted external log"), 2); err != nil {
		t.Fatalf("ApplyPut small failed: %v", err)
	}
	closeStore(t, store)

	// Verify no wal/ directory or .wal files exist on the real OS filesystem.
	if _, err := os.Stat(filepath.Join(dir, "wal")); !os.IsNotExist(err) {
		t.Fatalf("expected no wal directory on OSFS, got err=%v", err)
	}
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.HasSuffix(path, ".wal") {
			t.Fatalf("found unexpected .wal file on OSFS: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	reopened := openExternalStore(
		t,
		nil,
		dir,
		ExternalLogConfig{DurableLSN: watermark.Load},
		WithEncryptionKey(key),
		WithCompressionCodec(CodecZstd),
	)
	defer closeStore(t, reopened)

	gotOversize, exists, err := reopened.Get("blobs", "b1")
	if err != nil || !exists || !bytes.Equal(gotOversize, oversizeValue) {
		t.Fatalf("Get(b1) mismatch: exists=%v err=%v", exists, err)
	}
	gotSmall, exists, err := reopened.Get("blobs", "small")
	if err != nil || !exists || string(gotSmall) != "hello encrypted external log" {
		t.Fatalf("Get(small) mismatch: value=%q exists=%v err=%v", gotSmall, exists, err)
	}
}
