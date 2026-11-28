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
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// memExternalStream simulates an authoritative external redo stream in memory.
type memExternalStream struct {
	mu               sync.Mutex
	records          []ExternalRecord
	durableLSN       atomic.Uint64
	replayStartLSNs  []uint64
	waitDurableCalls []uint64
	faultFS          *FaultFS
}

func (stream *memExternalStream) appendPut(table, key string, payload []byte, lsn uint64) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.records = append(stream.records, ExternalRecord{
		Type:    RecordTypePut,
		LSN:     lsn,
		Table:   table,
		Key:     key,
		Payload: bytes.Clone(payload),
	})
}

func (stream *memExternalStream) appendDelete(table, key string, lsn uint64) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.records = append(stream.records, ExternalRecord{
		Type:  RecordTypeDelete,
		LSN:   lsn,
		Table: table,
		Key:   key,
	})
}

func (stream *memExternalStream) setDurable(lsn uint64) {
	stream.durableLSN.Store(lsn)
	if stream.faultFS != nil {
		stream.faultFS.SetMaxFsyncedLSN(lsn)
	}
}

func (stream *memExternalStream) durable() uint64 {
	return stream.durableLSN.Load()
}

func (stream *memExternalStream) waitDurable(lsn uint64) error {
	stream.mu.Lock()
	stream.waitDurableCalls = append(stream.waitDurableCalls, lsn)
	stream.mu.Unlock()
	if durable := stream.durableLSN.Load(); lsn > durable {
		return ErrNotDurable
	}
	return nil
}

func (stream *memExternalStream) openReplay(startLSN uint64) (ExternalLogIterator, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.replayStartLSNs = append(stream.replayStartLSNs, startLSN)
	var tail []ExternalRecord
	for _, rec := range stream.records {
		if rec.LSN >= startLSN {
			tail = append(tail, rec)
		}
	}
	return &memExternalIterator{records: tail}, nil
}

func (stream *memExternalStream) config() ExternalLogConfig {
	return ExternalLogConfig{
		WaitDurable: stream.waitDurable,
		DurableLSN:  stream.durable,
		OpenReplay:  stream.openReplay,
	}
}

type memExternalIterator struct {
	records []ExternalRecord
	idx     int
	closed  bool
}

func (it *memExternalIterator) Next() (ExternalRecord, error) {
	if it.closed {
		return ExternalRecord{}, io.ErrClosedPipe
	}
	if it.idx >= len(it.records) {
		return ExternalRecord{}, io.EOF
	}
	rec := it.records[it.idx]
	it.idx++
	return rec, nil
}

func (it *memExternalIterator) Close() error {
	it.closed = true
	return nil
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

func TestExternalLog_ModeEnforcement(t *testing.T) {
	t.Run("requires WaitDurable or DurableLSN", func(t *testing.T) {
		memFS := NewMemFS()
		_, err := Open(WithFS(memFS), WithDir("bad_cfg"), WithCreate(), WithExternalLog(ExternalLogConfig{}))
		if err == nil {
			t.Fatalf("expected Open to fail when neither WaitDurable nor DurableLSN is set")
		}
	})

	t.Run("external-log mode rejects Put, Delete, Sync", func(t *testing.T) {
		memFS := NewMemFS()
		stream := &memExternalStream{}
		store, err := Open(WithFS(memFS), WithDir("ext_mode"), WithCreate(), WithExternalLog(stream.config()))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

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
		defer store.Close()

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
	stream := &memExternalStream{}
	stream.setDurable(100)

	store, err := Open(
		WithFS(memFS),
		WithDir("ext_mono"),
		WithCreate(),
		WithCompressionCodec(CodecNone),
		WithExternalLog(stream.config()),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// LSN 0 is rejected.
	if err := store.ApplyPut("t", "k1", []byte("zero"), 0); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for LSN 0, got: %v", err)
	}
	if store.Position() != 0 {
		t.Fatalf("expected Position 0 after rejected put, got %d", store.Position())
	}

	// Apply initial puts at LSN 5 and LSN 10.
	if err := store.ApplyPut("t", "k1", []byte("v1"), 5); err != nil {
		t.Fatalf("ApplyPut LSN 5 failed: %v", err)
	}
	if store.Position() != 5 {
		t.Fatalf("expected Position 5, got %d", store.Position())
	}

	// Duplicate and regressing positions are rejected without failing the engine.
	if err := store.ApplyPut("t", "k1", []byte("dup"), 5); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for duplicate LSN 5, got: %v", err)
	}
	if err := store.ApplyPut("t", "k2", []byte("old"), 3); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for older LSN 3, got: %v", err)
	}
	if err := store.ApplyDelete("t", "k1", 5); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN for delete at LSN 5, got: %v", err)
	}

	// Verify k1 still holds "v1" and engine is healthy.
	val, exists, err := store.Get("t", "k1")
	if err != nil || !exists || string(val) != "v1" {
		t.Fatalf("unexpected Get(k1): val=%q exists=%v err=%v", val, exists, err)
	}

	// ApplyDelete of a non-existent key advances Position.
	if err := store.ApplyDelete("t", "nonexistent", 7); err != nil {
		t.Fatalf("ApplyDelete nonexistent at LSN 7 failed: %v", err)
	}
	if store.Position() != 7 {
		t.Fatalf("expected Position 7 after delete of nonexistent key, got %d", store.Position())
	}
	if err := store.ApplyPut("t", "k2", []byte("bad"), 7); !errors.Is(err, ErrNonMonotonicLSN) {
		t.Fatalf("expected ErrNonMonotonicLSN at LSN 7, got: %v", err)
	}

	// Overwrite k1, add multi-block k2, then delete k1.
	multiVal := bytes.Repeat([]byte("multi-block-ext-"), 400)
	if err := store.ApplyPut("t", "k1", []byte("v1-updated"), 10); err != nil {
		t.Fatalf("ApplyPut overwrite k1 failed: %v", err)
	}
	if err := store.ApplyPut("t", "k2", multiVal, 11); err != nil {
		t.Fatalf("ApplyPut multi-block k2 failed: %v", err)
	}
	if err := store.ApplyDelete("t", "k1", 12); err != nil {
		t.Fatalf("ApplyDelete k1 failed: %v", err)
	}

	if _, exists, err := store.Get("t", "k1"); err != nil || exists {
		t.Fatalf("expected k1 deleted, got exists=%v err=%v", exists, err)
	}
	gotMulti, exists, err := store.Get("t", "k2")
	if err != nil || !exists || !bytes.Equal(gotMulti, multiVal) {
		t.Fatalf("multi-block Get(k2) mismatch: exists=%v err=%v", exists, err)
	}

	assertNoWALFilesMemFS(t, memFS, "ext_mono")
}

func TestExternalLog_WriteAheadRule(t *testing.T) {
	t.Run("flush refuses when page LSN exceeds durable watermark", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		var watermark atomic.Uint64
		watermark.Store(5)
		faultFS.SetMaxFsyncedLSN(5)

		store, err := Open(
			WithFS(faultFS),
			WithDir("wal_rule_refuse"),
			WithCreate(),
			WithCompressionCodec(CodecNone),
			WithExternalLog(ExternalLogConfig{
				DurableLSN: watermark.Load,
			}),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

		if err := store.ApplyPut("t", "k1", []byte("v1"), 10); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}

		// Checkpoint tries to flush page with LSN 10 while durable watermark is 5.
		err = store.Checkpoint()
		if !errors.Is(err, ErrNotDurable) {
			t.Fatalf("expected ErrNotDurable on Checkpoint when watermark < page LSN, got: %v", err)
		}

		// FaultFS must report no write-ahead rule violation because the write was blocked before touching heap.db.
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("unexpected FaultFS rule violations: %v", violations)
		}
		// heap.db must remain empty because the dirty page was never written.
		memFS.mu.RLock()
		heapLen := len(memFS.files[filepath.Join("wal_rule_refuse", "heap.db")])
		memFS.mu.RUnlock()
		if heapLen != 0 {
			t.Fatalf("expected heap.db to remain empty when flush blocked by watermark, got %d bytes", heapLen)
		}
	})

	t.Run("checkpoint with no dirty pages still checks durable watermark", func(t *testing.T) {
		memFS := NewMemFS()
		var watermark atomic.Uint64
		watermark.Store(5)

		store, err := Open(
			WithFS(memFS),
			WithDir("wal_rule_nodirty"),
			WithCreate(),
			WithExternalLog(ExternalLogConfig{
				DurableLSN: watermark.Load,
			}),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

		// Deleting a non-existent key advances Position without dirtying any page.
		if err := store.ApplyDelete("t", "missing", 10); err != nil {
			t.Fatalf("ApplyDelete failed: %v", err)
		}
		err = store.Checkpoint()
		if !errors.Is(err, ErrNotDurable) {
			t.Fatalf("expected ErrNotDurable when advancing meta.db past watermark, got: %v", err)
		}
		if store.RecoveryPosition() != 0 {
			t.Fatalf("expected RecoveryPosition to stay 0, got %d", store.RecoveryPosition())
		}
	})

	t.Run("blocking WaitDurable waits before heap writes under eviction pressure", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		stream := &memExternalStream{faultFS: faultFS}

		waitStarted := make(chan struct{})
		releaseWait := make(chan struct{})
		var waitedLSN atomic.Uint64

		store, err := Open(
			WithFS(faultFS),
			WithDir("wal_rule_wait"),
			WithCreate(),
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
			WithExternalLog(ExternalLogConfig{
				WaitDurable: func(lsn uint64) error {
					if lsn > stream.durable() {
						waitedLSN.Store(lsn)
						close(waitStarted)
						<-releaseWait
					}
					return stream.waitDurable(lsn)
				},
				DurableLSN: stream.durable,
				OpenReplay: stream.openReplay,
			}),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		// Apply a put whose LSN is not yet durable.
		stream.appendPut("t", "k1", []byte("v1"), 10)
		if err := store.ApplyPut("t", "k1", []byte("v1"), 10); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}

		// Start Checkpoint in a goroutine; it must block in WaitDurable until we advance durability.
		cpDone := make(chan error, 1)
		go func() {
			cpDone <- store.Checkpoint()
		}()

		// Wait until WaitDurable is entered for LSN 10.
		<-waitStarted
		if got := waitedLSN.Load(); got != 10 {
			t.Fatalf("expected WaitDurable(10), got WaitDurable(%d)", got)
		}

		// Advance durability and release the wait.
		stream.setDurable(10)
		close(releaseWait)

		if err := <-cpDone; err != nil {
			t.Fatalf("Checkpoint failed after durability released: %v", err)
		}
		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("FaultFS detected rule violations: %v", violations)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		assertNoWALFilesMemFS(t, memFS, "wal_rule_wait")
	})
}

func TestExternalLog_CrashAndRecovery(t *testing.T) {
	t.Run("unflushed writes recover from external stream", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_crash_unflushed"
		stream := &memExternalStream{}

		store, err := Open(
			WithFS(memFS),
			WithDir(dir),
			WithCreate(),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		applyPut := func(lsn uint64, table, key string, val []byte) {
			t.Helper()
			stream.appendPut(table, key, val, lsn)
			stream.setDurable(lsn)
			if err := store.ApplyPut(table, key, val, lsn); err != nil {
				t.Fatalf("ApplyPut(%s, %d) failed: %v", key, lsn, err)
			}
		}
		applyDelete := func(lsn uint64, table, key string) {
			t.Helper()
			stream.appendDelete(table, key, lsn)
			stream.setDurable(lsn)
			if err := store.ApplyDelete(table, key, lsn); err != nil {
				t.Fatalf("ApplyDelete(%s, %d) failed: %v", key, lsn, err)
			}
		}

		multiVal := bytes.Repeat([]byte("multi-recover-"), 500)
		applyPut(1, "pods", "p1", []byte("v1"))
		applyPut(2, "pods", "p2", []byte("v2"))
		applyPut(3, "pods", "p-multi", multiVal)
		applyPut(4, "pods", "p1", []byte("v1-v2"))
		applyDelete(5, "pods", "p2")

		// Simulate crash by cloning the filesystem without calling Close.
		crashedFS := cloneMemFS(memFS)
		_ = store.Close()

		reopened, err := Open(
			WithFS(crashedFS),
			WithDir(dir),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("reopen failed: %v", err)
		}
		defer reopened.Close()

		if len(stream.replayStartLSNs) != 1 || stream.replayStartLSNs[0] != 1 {
			t.Fatalf("expected OpenReplay to start at 1, got %v", stream.replayStartLSNs)
		}
		if reopened.Position() != 5 {
			t.Fatalf("expected Position 5 after recovery, got %d", reopened.Position())
		}

		v1, exists, err := reopened.Get("pods", "p1")
		if err != nil || !exists || string(v1) != "v1-v2" {
			t.Fatalf("Get(p1): got %q exists=%v err=%v", v1, exists, err)
		}
		if _, exists, err := reopened.Get("pods", "p2"); err != nil || exists {
			t.Fatalf("expected p2 deleted after recovery, got exists=%v err=%v", exists, err)
		}
		vMulti, exists, err := reopened.Get("pods", "p-multi")
		if err != nil || !exists || !bytes.Equal(vMulti, multiVal) {
			t.Fatalf("Get(p-multi) mismatch: exists=%v err=%v", exists, err)
		}

		// Monotonic enforcement continues from recovered position 5.
		if err := reopened.ApplyPut("pods", "p3", []byte("bad"), 5); !errors.Is(err, ErrNonMonotonicLSN) {
			t.Fatalf("expected ErrNonMonotonicLSN at LSN 5, got: %v", err)
		}
		if err := reopened.ApplyPut("pods", "p3", []byte("ok"), 6); err != nil {
			t.Fatalf("ApplyPut at LSN 6 failed: %v", err)
		}

		assertNoWALFilesMemFS(t, crashedFS, dir)
	})

	t.Run("resumes replay from durable meta.db recovery position after checkpoints and evictions", func(t *testing.T) {
		memFS := NewMemFS()
		faultFS := NewFaultFS(memFS)
		dir := "ext_crash_checkpoint"
		stream := &memExternalStream{faultFS: faultFS}

		store, err := Open(
			WithFS(faultFS),
			WithDir(dir),
			WithCreate(),
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		expected := make(map[string][]byte)
		lsn := uint64(0)
		applyPut := func(key string, val []byte) {
			t.Helper()
			lsn++
			stream.appendPut("items", key, val, lsn)
			stream.setDurable(lsn)
			if err := store.ApplyPut("items", key, val, lsn); err != nil {
				t.Fatalf("ApplyPut(%s, %d) failed: %v", key, lsn, err)
			}
			expected[key] = bytes.Clone(val)
		}
		applyDelete := func(key string) {
			t.Helper()
			lsn++
			stream.appendDelete("items", key, lsn)
			stream.setDurable(lsn)
			if err := store.ApplyDelete("items", key, lsn); err != nil {
				t.Fatalf("ApplyDelete(%s, %d) failed: %v", key, lsn, err)
			}
			delete(expected, key)
		}

		// Write enough records to trigger pool evictions and flushes.
		for i := 0; i < 30; i++ {
			val := bytes.Repeat([]byte{byte('a' + (i % 26))}, 1500)
			applyPut("k-"+string(rune('a'+(i%26)))+"-"+string(rune('0'+(i/26))), val)
		}

		// Two checkpoints: first flushes dirty pages and clears RedoLSN; second advances
		// meta.db's recovery position to the current max applied LSN (30).
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 1 failed: %v", err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint 2 failed: %v", err)
		}
		checkpointPos := store.RecoveryPosition()
		if checkpointPos != lsn {
			t.Fatalf("expected RecoveryPosition %d after second checkpoint, got %d", lsn, checkpointPos)
		}

		// Apply additional mutations after the checkpoint (overwrites, deletes, new keys, multi-block).
		applyPut("k-a-0", []byte("overwritten-after-cp"))
		applyDelete("k-b-0")
		applyPut("k-new-multi", bytes.Repeat([]byte("tail-multi-"), 600))
		for i := 0; i < 10; i++ {
			applyPut("k-tail-"+string(rune('0'+i)), bytes.Repeat([]byte("tail-"), 300))
		}

		if violations := faultFS.Violations(); len(violations) > 0 {
			t.Fatalf("FaultFS detected rule violations before crash: %v", violations)
		}

		// Simulate crash without Close.
		crashedFS := cloneMemFS(memFS)
		_ = store.Close()

		reopened, err := Open(
			WithFS(crashedFS),
			WithDir(dir),
			WithNumPoolBlocks(16),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("reopen after crash failed: %v", err)
		}
		defer reopened.Close()

		if len(stream.replayStartLSNs) != 1 || stream.replayStartLSNs[0] != checkpointPos {
			t.Fatalf("expected OpenReplay to resume at meta.db position %d, got %v", checkpointPos, stream.replayStartLSNs)
		}
		if reopened.Position() != lsn {
			t.Fatalf("expected Position %d after recovery, got %d", lsn, reopened.Position())
		}

		for k, want := range expected {
			got, exists, err := reopened.Get("items", k)
			if err != nil || !exists || !bytes.Equal(got, want) {
				t.Fatalf("key %s mismatch after recovery: exists=%v err=%v", k, exists, err)
			}
		}
		if _, exists, err := reopened.Get("items", "k-b-0"); err != nil || exists {
			t.Fatalf("expected deleted key k-b-0 to stay absent, got exists=%v err=%v", exists, err)
		}
		assertNoWALFilesMemFS(t, crashedFS, dir)
	})

	t.Run("superseded page copy cleared during external-log replay", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_superseded"
		stream := &memExternalStream{}

		store, err := Open(
			WithFS(memFS),
			WithDir(dir),
			WithCreate(),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		// LSN 1: Put small k1 on slotted page 1, then flush and sync page 1.
		stream.appendPut("t", "k1", []byte("small-v1"), 1)
		stream.setDurable(1)
		if err := store.ApplyPut("t", "k1", []byte("small-v1"), 1); err != nil {
			t.Fatalf("ApplyPut LSN 1 failed: %v", err)
		}
		if err := store.cp.FlushPages(); err != nil {
			t.Fatalf("FlushPages after LSN 1 failed: %v", err)
		}

		// LSN 2: Replace k1 with a multi-block value on page 2.
		// Flush ONLY page 2 so page 1 on disk still carries the old copy of k1 (superseded copy).
		bigVal := bytes.Repeat([]byte("big-v2-"), 1000)
		stream.appendPut("t", "k1", bigVal, 2)
		stream.setDurable(2)
		if err := store.ApplyPut("t", "k1", bigVal, 2); err != nil {
			t.Fatalf("ApplyPut LSN 2 failed: %v", err)
		}
		store.keyMu.RLock()
		page2 := store.keyIndex[qualifyKey("t", "k1")].LogicalPage
		store.keyMu.RUnlock()
		if err := store.bp.FlushPage(page2); err != nil {
			t.Fatalf("FlushPage(page2) failed: %v", err)
		}
		if err := store.heapFile.Sync(); err != nil {
			t.Fatalf("heapFile.Sync failed: %v", err)
		}

		// Crash with page 1 still holding old LSN 1 copy and page 2 holding LSN 2 copy.
		crashedFS := cloneMemFS(memFS)
		_ = store.Close()

		reopened, err := Open(
			WithFS(crashedFS),
			WithDir(dir),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("reopen failed: %v", err)
		}

		got, exists, err := reopened.Get("t", "k1")
		if err != nil || !exists || !bytes.Equal(got, bigVal) {
			t.Fatalf("expected big-v2 after recovery, got exists=%v err=%v", exists, err)
		}

		// Delete k1 at LSN 3, close cleanly, and reopen: the old copy on page 1 must have been cleared.
		stream.appendDelete("t", "k1", 3)
		stream.setDurable(3)
		if err := reopened.ApplyDelete("t", "k1", 3); err != nil {
			t.Fatalf("ApplyDelete LSN 3 failed: %v", err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		reopened2, err := Open(
			WithFS(crashedFS),
			WithDir(dir),
			WithCompressionCodec(CodecNone),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("reopen2 failed: %v", err)
		}
		defer reopened2.Close()

		if _, exists, err := reopened2.Get("t", "k1"); err != nil || exists {
			t.Fatalf("superseded copy resurrected after delete: exists=%v err=%v", exists, err)
		}
	})

	t.Run("lost tail detection fails recovery when external log lags heap", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_lost_tail"
		stream := &memExternalStream{}

		store, err := Open(
			WithFS(memFS),
			WithDir(dir),
			WithCreate(),
			WithExternalLog(stream.config()),
		)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		stream.appendPut("t", "k1", []byte("v1"), 20)
		stream.setDurable(20)
		if err := store.ApplyPut("t", "k1", []byte("v1"), 20); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}
		if err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint failed: %v", err)
		}
		crashedFS := cloneMemFS(memFS)
		_ = store.Close()

		// Case 1: DurableLSN reports 10 < maxHeapLSN (20).
		stream.setDurable(10)
		if _, err := Open(WithFS(crashedFS), WithDir(dir), WithExternalLog(stream.config())); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore when DurableLSN < maxHeapLSN, got: %v", err)
		}

		// Case 2: DurableLSN is nil, and OpenReplay ends below maxHeapLSN (20).
		truncatedStream := &memExternalStream{}
		truncatedStream.appendPut("t", "k1", []byte("stale"), 10)
		truncatedStream.setDurable(10)
		_, err = Open(
			WithFS(crashedFS),
			WithDir(dir),
			WithExternalLog(ExternalLogConfig{
				WaitDurable: truncatedStream.waitDurable,
				OpenReplay:  truncatedStream.openReplay,
			}),
		)
		if !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore when replay ends below maxHeapLSN, got: %v", err)
		}
	})

	t.Run("unclean crash without OpenReplay fails recovery, clean close without OpenReplay succeeds", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "ext_no_replay"
		stream := &memExternalStream{}

		store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithExternalLog(stream.config()))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		stream.appendPut("t", "k1", []byte("v1"), 5)
		stream.setDurable(5)
		if err := store.ApplyPut("t", "k1", []byte("v1"), 5); err != nil {
			t.Fatalf("ApplyPut failed: %v", err)
		}

		// Unclean crash without OpenReplay must fail.
		crashedFS := cloneMemFS(memFS)
		if _, err := Open(WithFS(crashedFS), WithDir(dir), WithExternalLog(ExternalLogConfig{
			DurableLSN: stream.durable,
		})); err == nil {
			t.Fatalf("expected error opening uncleanly closed store without OpenReplay")
		}

		// Clean close without OpenReplay succeeds.
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		reopened, err := Open(WithFS(memFS), WithDir(dir), WithExternalLog(ExternalLogConfig{
			DurableLSN: stream.durable,
		}))
		if err != nil {
			t.Fatalf("reopen after clean close failed: %v", err)
		}
		defer reopened.Close()

		val, exists, err := reopened.Get("t", "k1")
		if err != nil || !exists || string(val) != "v1" {
			t.Fatalf("unexpected Get(k1): val=%q exists=%v err=%v", val, exists, err)
		}
	})
}

func TestExternalLog_EncryptedOversizeAndOSFSNoWAL(t *testing.T) {
	dir := t.TempDir()
	key, err := NewEncryptionKey()
	if err != nil {
		t.Fatalf("NewEncryptionKey failed: %v", err)
	}
	stream := &memExternalStream{}

	store, err := Open(
		WithDir(dir),
		WithCreate(),
		WithEncryptionKey(key),
		WithCompressionCodec(CodecZstd),
		WithExternalLog(stream.config()),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Build an incompressible payload > 2 MiB to trigger oversize file storage even under zstd.
	oversizeVal := make([]byte, (MaxBatchBlocks+32)*BlockSize)
	state := uint64(0x9e3779b97f4a7c15)
	for i := range oversizeVal {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		oversizeVal[i] = byte(state)
	}

	stream.appendPut("blobs", "b1", oversizeVal, 1)
	stream.setDurable(1)
	if err := store.ApplyPut("blobs", "b1", oversizeVal, 1); err != nil {
		t.Fatalf("ApplyPut oversize failed: %v", err)
	}
	stream.appendPut("blobs", "small", []byte("hello encrypted external log"), 2)
	stream.setDurable(2)
	if err := store.ApplyPut("blobs", "small", []byte("hello encrypted external log"), 2); err != nil {
		t.Fatalf("ApplyPut small failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify zero .wal files and no wal/ directory exist on real OS filesystem.
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

	// Simulate an additional tail oversize record not yet applied before reopen.
	oversizeVal2 := bytes.Clone(oversizeVal)
	oversizeVal2[0] ^= 0xff
	stream.appendPut("blobs", "b2", oversizeVal2, 3)
	stream.setDurable(3)

	reopened, err := Open(
		WithDir(dir),
		WithEncryptionKey(key),
		WithCompressionCodec(CodecZstd),
		WithExternalLog(stream.config()),
	)
	if err != nil {
		t.Fatalf("reopen encrypted external-log store failed: %v", err)
	}
	defer reopened.Close()

	got1, exists, err := reopened.Get("blobs", "b1")
	if err != nil || !exists || !bytes.Equal(got1, oversizeVal) {
		t.Fatalf("Get(b1) mismatch: exists=%v err=%v", exists, err)
	}
	got2, exists, err := reopened.Get("blobs", "b2")
	if err != nil || !exists || !bytes.Equal(got2, oversizeVal2) {
		t.Fatalf("Get(b2) replayed oversize mismatch: exists=%v err=%v", exists, err)
	}
	gotSmall, exists, err := reopened.Get("blobs", "small")
	if err != nil || !exists || string(gotSmall) != "hello encrypted external log" {
		t.Fatalf("Get(small) mismatch: val=%q exists=%v err=%v", gotSmall, exists, err)
	}
}
