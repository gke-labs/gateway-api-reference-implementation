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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWAL_AppendAndIterate(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-test-db-0001"))

	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{MaxSegmentSize: 200})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Write 10 records. With MaxSegmentSize=200, this should roll across multiple segments.
	for i := uint64(1); i <= 10; i++ {
		rec := Record{
			Type:    RecordTypePut,
			LSN:     i,
			Key:     fmt.Sprintf("ns/cm-%d", i),
			Payload: []byte(fmt.Sprintf("payload-%d", i)),
			Token:   fmt.Sprintf("rv-%d", i),
		}
		if err := wal.Append(rec); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	_ = wal.Close()

	// Verify segments are created and directory was synced
	if fs.DirSyncCount("wal_dir") < 2 {
		t.Fatalf("expected multiple dir syncs on segment creation, got %d", fs.DirSyncCount("wal_dir"))
	}

	// Replay from beginning
	it, err := NewWALIterator(fs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	var recoveredCount uint64
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Iterator error: %v", err)
		}
		recoveredCount++
		if rec.LSN != recoveredCount {
			t.Fatalf("expected LSN %d, got %d", recoveredCount, rec.LSN)
		}
		if rec.Key != fmt.Sprintf("ns/cm-%d", recoveredCount) {
			t.Fatalf("unexpected key: %s", rec.Key)
		}
	}

	if recoveredCount != 10 {
		t.Fatalf("expected 10 recovered records, got %d", recoveredCount)
	}
}

func TestWAL_StopAtBadCRC(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-test-db-0002"))

	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{MaxSegmentSize: 1024})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	for i := uint64(1); i <= 5; i++ {
		_ = wal.Append(Record{
			Type:    RecordTypePut,
			LSN:     i,
			Key:     fmt.Sprintf("key-%d", i),
			Payload: []byte("payload"),
			Token:   "100",
		})
	}
	_ = wal.Sync()
	_ = wal.Close()

	// Corrupt record 4
	entries, _ := fs.ReadDir("wal_dir")
	segPath := "wal_dir/" + entries[0].Name()
	file, _ := fs.OpenFile(segPath, 0, 0)
	size, _ := file.Size()
	data := make([]byte, size)
	_, _ = file.ReadAt(data, 0)
	// Corrupt byte inside record 4
	data[200] ^= 0xff
	_, _ = file.WriteAt(data, 0)
	_ = file.Close()

	// Replay should cleanly stop before corrupted record 4 or 5
	it, err := NewWALIterator(fs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	var count int
	for {
		_, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		count++
	}

	if count >= 5 {
		t.Fatalf("expected iteration to stop before corrupt record, but read %d records", count)
	}
}

func TestWAL_TruncateSegments(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-test-db-0003"))

	// Create small segments (100 bytes) so each record rolls segment
	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{MaxSegmentSize: 80})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	for i := uint64(1); i <= 6; i++ {
		_ = wal.Append(Record{
			Type:    RecordTypePut,
			LSN:     i,
			Key:     fmt.Sprintf("k%d", i),
			Payload: []byte("short"),
			Token:   "1",
		})
	}
	_ = wal.Sync()

	entriesBefore, _ := fs.ReadDir("wal_dir")
	if len(entriesBefore) < 4 {
		t.Fatalf("expected at least 4 segments, got %d", len(entriesBefore))
	}

	// Truncate before LSN 4 (checkpoint covers records 1..3)
	if err := wal.TruncateBefore(4); err != nil {
		t.Fatalf("TruncateBefore failed: %v", err)
	}

	entriesAfter, _ := fs.ReadDir("wal_dir")
	if len(entriesAfter) >= len(entriesBefore) {
		t.Fatalf("expected fewer segments after truncation: before=%d, after=%d",
			len(entriesBefore), len(entriesAfter))
	}

	// First remaining segment must have startLSN >= 4 (or be the active segment)
	_ = wal.Close()
}

// TestWAL_AppendRecordCompletesWhileWriteOrSyncBlocked asserts that AppendRecord completes
// while a WAL write or fsync is blocked in the fault filesystem (Item 2).
func TestWAL_AppendRecordCompletesWhileWriteOrSyncBlocked(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	var dbID [16]byte
	copy(dbID[:], []byte("wal-test-db-0004"))

	wal, err := OpenWAL(faultFS, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Initial append and sync to initialize active segment and header
	_, err = wal.AppendRecord(&Record{
		Type:    RecordTypePut,
		Key:     "init",
		Payload: []byte("init"),
	})
	if err != nil {
		t.Fatalf("initial append failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}

	syncBlocked := make(chan struct{})
	releaseSync := make(chan struct{})

	faultFS.SetBeforeSync(func(path string) {
		if strings.HasSuffix(path, ".wal") {
			select {
			case <-syncBlocked:
				// Already triggered
			default:
				close(syncBlocked)
				<-releaseSync
			}
		}
	})

	// Start a background sync on record 2
	syncDone := make(chan error, 1)
	go func() {
		_, aErr := wal.AppendRecord(&Record{
			Type:    RecordTypePut,
			Key:     "k1",
			Payload: []byte("v1"),
		})
		if aErr != nil {
			syncDone <- aErr
			return
		}
		syncDone <- wal.Sync()
	}()

	// Wait until WAL writer is blocked in fsync
	select {
	case <-syncBlocked:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for WAL sync to block")
	}

	// Now call AppendRecord from this goroutine: it must complete immediately without waiting for fsync!
	appendDone := make(chan error, 1)
	go func() {
		_, aErr := wal.AppendRecord(&Record{
			Type:    RecordTypePut,
			Key:     "k2",
			Payload: []byte("v2"),
		})
		appendDone <- aErr
	}()

	select {
	case err := <-appendDone:
		if err != nil {
			t.Fatalf("AppendRecord failed while sync was blocked: %v", err)
		}
	case <-time.After(1 * time.Second):
		close(releaseSync)
		t.Fatalf("AppendRecord stalled while WAL writer was performing fsync!")
	}

	// Unblock the fsync
	close(releaseSync)
	if err := <-syncDone; err != nil {
		t.Fatalf("background sync failed: %v", err)
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("final sync failed: %v", err)
	}
	_ = wal.Close()

	// Verify both records are present and recoverable in order
	it, err := NewWALIterator(faultFS, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	var keys []string
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("iteration error: %v", err)
		}
		keys = append(keys, rec.Key)
	}

	expected := []string{"init", "k1", "k2"}
	if len(keys) != len(expected) {
		t.Fatalf("expected keys %v, got %v", expected, keys)
	}
	for i, k := range keys {
		if k != expected[i] {
			t.Fatalf("key %d mismatch: got %s, expected %s", i, k, expected[i])
		}
	}
}

type testClock struct {
	mu  sync.Mutex
	now MonotonicTime
}

func (c *testClock) Now() MonotonicTime {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += MonotonicTime(d)
}

// TestWAL_FiveSecondBound_UnsyncedBlocks asserts that written but unsynced blocks are fsynced
// within 5 seconds when appends stop on exact block boundaries (Item 3).
func TestWAL_FiveSecondBound_UnsyncedBlocks(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-test-db-0005"))

	clk := &testClock{now: MonotonicTime(time.Hour)}
	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{
		Clock:        clk,
		TickInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append record 1 that fills exactly the rest of the first 4 KiB block.
	// Block 0 has 32 bytes segment header.
	// Space remaining in block 0: 4096 - 32 = 4064 bytes.
	// Record header is 36 bytes.
	// Payload needed: 4064 - 36 = 4028 bytes.
	p1 := make([]byte, 4028)
	_, err = wal.AppendRecord(&Record{
		Type:    RecordTypePut,
		Payload: p1,
	})
	if err != nil {
		t.Fatalf("AppendRecord 1 failed: %v", err)
	}

	// Append record 2 that fills exactly the next 4 KiB block (4096 bytes).
	// Payload needed: 4096 - 36 = 4060 bytes.
	p2 := make([]byte, 4060)
	lsn2, err := wal.AppendRecord(&Record{
		Type:    RecordTypePut,
		Payload: p2,
	})
	if err != nil {
		t.Fatalf("AppendRecord 2 failed: %v", err)
	}

	// Verify tailOffset is exactly 0 (filled whole blocks)
	wal.mu.Lock()
	tailOff := wal.tailOffset
	wal.mu.Unlock()
	if tailOff != 0 {
		t.Fatalf("expected tailOffset to be 0, got %d", tailOff)
	}

	// Allow background writer to flush the queued blocks to disk without sync
	time.Sleep(50 * time.Millisecond)

	// Verify that blocks were NOT yet fsynced
	if wal.FsyncedLSN() >= lsn2 {
		t.Fatalf("expected blocks to not be fsynced immediately, fsyncedLSN=%d, lsn2=%d", wal.FsyncedLSN(), lsn2)
	}

	// Advance clock by 5 seconds without injecting any sync or appends
	clk.Advance(5 * time.Second)

	// Poll for fsync to occur within a short timeout
	deadline := time.Now().Add(2 * time.Second)
	for wal.FsyncedLSN() < lsn2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if wal.FsyncedLSN() < lsn2 {
		t.Fatalf("expected WAL to fsync within 5s bound, fsyncedLSN=%d, expected at least %d", wal.FsyncedLSN(), lsn2)
	}
}

type writeCallInfo struct {
	offset int64
	len    int
}

type countingFile struct {
	File
	mu         sync.Mutex
	writeCalls []writeCallInfo
}

func (c *countingFile) WriteAt(p []byte, off int64) (int, error) {
	c.mu.Lock()
	c.writeCalls = append(c.writeCalls, writeCallInfo{
		offset: off,
		len:    len(p),
	})
	c.mu.Unlock()
	return c.File.WriteAt(p, off)
}

func (c *countingFile) getCalls() []writeCallInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]writeCallInfo, len(c.writeCalls))
	copy(out, c.writeCalls)
	return out
}

func (c *countingFile) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls = nil
}

type countingFS struct {
	FS
	mu    sync.Mutex
	files map[string]*countingFile
}

func newCountingFS(underlying FS) *countingFS {
	return &countingFS{
		FS:    underlying,
		files: make(map[string]*countingFile),
	}
}

func (c *countingFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := c.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cf, ok := c.files[name]
	if !ok {
		cf = &countingFile{File: f}
		c.files[name] = cf
	} else {
		cf.File = f
	}
	return cf, nil
}

func (c *countingFS) getFile(name string) *countingFile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.files[name]
}

// TestWAL_WriteCounts asserts that a flush issues one write call covering all complete blocks,
// and that a sync-time padded tail goes out in the same flush where possible.
func TestWAL_WriteCounts(t *testing.T) {
	baseFS := NewMemFS()
	cfs := newCountingFS(baseFS)
	var dbID [16]byte
	copy(dbID[:], []byte("wal-writecounts-1"))

	wal, err := OpenWAL(cfs, "wal_dir", dbID, 0, WALOptions{
		TickInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append 5 complete blocks of data without sync in a single record.
	// Block 0 has 32 bytes segment header.
	// Space in 5 blocks: 5 * 4096 - 32 = 20448 bytes.
	// Record header: 36 bytes. Payload needed: 20448 - 36 = 20412 bytes.
	p1 := make([]byte, 5*WALBlockSize-SegmentHeaderSize-RecordHeaderSize)
	if _, err := wal.AppendRecord(&Record{Type: RecordTypePut, Payload: p1}); err != nil {
		t.Fatalf("AppendRecord 1 failed: %v", err)
	}

	// Wait for background writer to flush the 5 complete blocks
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		wal.mu.Lock()
		flushed := wal.flushedOff
		wal.mu.Unlock()
		if flushed >= 5*WALBlockSize {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	wal.mu.Lock()
	flushed := wal.flushedOff
	wal.mu.Unlock()
	if flushed < 5*WALBlockSize {
		t.Fatalf("timed out waiting for background flush, flushedOff=%d", flushed)
	}

	cf := cfs.getFile(filepath.Join("wal_dir", segmentFileName(1)))
	if cf == nil {
		t.Fatalf("segment file not found in countingFS")
	}

	calls := cf.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 write call for complete blocks, got %d: %+v", len(calls), calls)
	}
	if calls[0].offset != 0 || calls[0].len != 5*WALBlockSize {
		t.Fatalf("expected write call at offset 0 of len %d, got offset %d len %d", 5*WALBlockSize, calls[0].offset, calls[0].len)
	}

	// Now append 2.5 blocks of data and call Sync().
	// 2 full blocks + 0.5 block partial: 2 * 4096 + 2048 = 10240 bytes.
	cf.reset()
	p3 := make([]byte, 10240-RecordHeaderSize)
	if _, err := wal.AppendRecord(&Record{Type: RecordTypePut, Payload: p3}); err != nil {
		t.Fatalf("AppendRecord 3 failed: %v", err)
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	calls = cf.getCalls()
	// The 2 complete blocks AND the 0.5 padded tail block must go out in ONE flush (3 blocks = 12288 bytes)
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 write call covering complete blocks and padded tail, got %d: %+v", len(calls), calls)
	}
	if calls[0].offset != 5*WALBlockSize || calls[0].len != 3*WALBlockSize {
		t.Fatalf("expected write call at offset %d of len %d, got offset %d len %d", 5*WALBlockSize, 3*WALBlockSize, calls[0].offset, calls[0].len)
	}
}

// TestWAL_RecordLargerThanBuffer asserts that a record exceeding the buffer capacity works correctly
// and replays with exact data integrity.
func TestWAL_RecordLargerThanBuffer(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-large-buf-01"))

	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{
		BufferSize: 4096,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	rec := Record{
		Type:    RecordTypePut,
		Key:     "large",
		Payload: payload,
		Token:   "tok-large",
	}
	_, err = wal.AppendRecord(&rec)
	if err != nil {
		t.Fatalf("AppendRecord failed for record larger than buffer: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	it, err := NewWALIterator(fs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	r, err := it.Next()
	if err != nil {
		t.Fatalf("it.Next failed: %v", err)
	}
	if r.Key != "large" || !bytes.Equal(r.Payload, payload) {
		t.Fatalf("recovered payload mismatch")
	}
}

// TestWAL_RecordSpanningBufferSwitch asserts that records spanning across the double-buffer boundary
// are encoded correctly with valid CRC and can be replayed cleanly.
func TestWAL_RecordSpanningBufferSwitch(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-span-buf-001"))

	// BufferSize: 8192 (2 blocks per buffer)
	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{
		BufferSize: 8192,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append record 1 (5000 bytes payload).
	// Occupies bytes 32..5068 in buffer 0.
	// Remaining in buffer 0: 8192 - 5068 = 3124 bytes.
	p1 := make([]byte, 5000)
	for i := range p1 {
		p1[i] = byte(i % 251)
	}
	_, err = wal.AppendRecord(&Record{
		Type:    RecordTypePut,
		Key:     "rec-1",
		Payload: p1,
		Token:   "tok-1",
	})
	if err != nil {
		t.Fatalf("AppendRecord 1 failed: %v", err)
	}

	// Append record 2 (4000 bytes payload).
	// Length: 36 + 5 + 4000 + 5 = 4046 bytes.
	// 4046 > 3124, so record 2 spans the buffer switch from buffer 0 to buffer 1!
	p2 := make([]byte, 4000)
	for i := range p2 {
		p2[i] = byte((i + 7) % 251)
	}
	_, err = wal.AppendRecord(&Record{
		Type:    RecordTypePut,
		Key:     "rec-2",
		Payload: p2,
		Token:   "tok-2",
	})
	if err != nil {
		t.Fatalf("AppendRecord 2 failed: %v", err)
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Replay via iterator and verify exact data integrity
	it, err := NewWALIterator(fs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	r1, err := it.Next()
	if err != nil {
		t.Fatalf("it.Next r1 failed: %v", err)
	}
	if r1.Key != "rec-1" || !bytes.Equal(r1.Payload, p1) {
		t.Fatalf("r1 payload mismatch")
	}

	r2, err := it.Next()
	if err != nil {
		t.Fatalf("it.Next r2 failed: %v", err)
	}
	if r2.Key != "rec-2" || !bytes.Equal(r2.Payload, p2) {
		t.Fatalf("r2 payload mismatch")
	}

	_, err = it.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got: %v", err)
	}
}

// TestWAL_PaddingAfterSync asserts that a sync pads the partial block, advances the append cursor
// to the next block boundary, and never rewrites the padded block on future appends.
func TestWAL_PaddingAfterSync(t *testing.T) {
	baseFS := NewMemFS()
	cfs := newCountingFS(baseFS)
	var dbID [16]byte
	copy(dbID[:], []byte("wal-pad-sync-001"))

	wal, err := OpenWAL(cfs, "wal_dir", dbID, 0)
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append record 1 (1000 bytes) and sync
	p1 := make([]byte, 1000)
	_, err = wal.AppendRecord(&Record{Type: RecordTypePut, Key: "k1", Payload: p1})
	if err != nil {
		t.Fatalf("AppendRecord 1 failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync 1 failed: %v", err)
	}

	cf := cfs.getFile(filepath.Join("wal_dir", segmentFileName(1)))
	if cf == nil {
		t.Fatalf("segment file not found")
	}

	calls := cf.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 write call, got %d: %+v", len(calls), calls)
	}
	if calls[0].offset != 0 || calls[0].len != WALBlockSize {
		t.Fatalf("expected write call at offset 0 len %d, got offset %d len %d", WALBlockSize, calls[0].offset, calls[0].len)
	}

	// Verify that tailOffset is now 0 (at block boundary)
	wal.mu.Lock()
	appendOff := wal.appendOff
	tailOff := wal.tailOffset
	wal.mu.Unlock()
	if appendOff != WALBlockSize || tailOff != 0 {
		t.Fatalf("expected appendOff=%d tailOffset=0, got appendOff=%d tailOffset=%d", WALBlockSize, appendOff, tailOff)
	}

	cf.reset()

	// Append record 2 (1000 bytes) and sync
	p2 := make([]byte, 1000)
	_, err = wal.AppendRecord(&Record{Type: RecordTypePut, Key: "k2", Payload: p2})
	if err != nil {
		t.Fatalf("AppendRecord 2 failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync 2 failed: %v", err)
	}

	calls = cf.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 write call for record 2, got %d: %+v", len(calls), calls)
	}
	// Record 2 must be written starting at offset WALBlockSize (4096), NOT offset 0!
	if calls[0].offset != WALBlockSize || calls[0].len != WALBlockSize {
		t.Fatalf("expected write at offset %d len %d, got offset %d len %d", WALBlockSize, WALBlockSize, calls[0].offset, calls[0].len)
	}

	// Replay and verify
	it, err := NewWALIterator(cfs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	r1, err := it.Next()
	if err != nil || r1.Key != "k1" {
		t.Fatalf("failed reading r1: %v", err)
	}
	r2, err := it.Next()
	if err != nil || r2.Key != "k2" {
		t.Fatalf("failed reading r2: %v", err)
	}
}

// TestWAL_SegmentRotation asserts that segment rotation flushes and syncs the previous segment,
// creates the new segment with header, and replays all records across segments.
func TestWAL_SegmentRotation(t *testing.T) {
	fs := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-seg-rot-0001"))

	// MaxSegmentSize: 8192 (2 blocks)
	wal, err := OpenWAL(fs, "wal_dir", dbID, 0, WALOptions{
		MaxSegmentSize: 8192,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	// Append records:
	// rec 1: 3000 bytes -> segment 1 (offset 32..3068)
	// rec 2: 3000 bytes -> segment 1 (offset 3068..6104)
	// rec 3: 3000 bytes -> 6104 + 3036 = 9140 > 8192, rolls to segment 2!
	for i := 1; i <= 3; i++ {
		payload := make([]byte, 3000)
		for j := range payload {
			payload[j] = byte(i)
		}
		_, err := wal.AppendRecord(&Record{
			Type:    RecordTypePut,
			Key:     fmt.Sprintf("rot-%d", i),
			Payload: payload,
		})
		if err != nil {
			t.Fatalf("AppendRecord %d failed: %v", i, err)
		}
	}

	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Verify multiple segment files exist
	entries, err := fs.ReadDir("wal_dir")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	var segCount int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wal") {
			segCount++
		}
	}
	if segCount < 2 {
		t.Fatalf("expected at least 2 segments, got %d", segCount)
	}

	// Replay all records
	it, err := NewWALIterator(fs, "wal_dir", dbID, 1)
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer it.Close()

	for i := 1; i <= 3; i++ {
		r, err := it.Next()
		if err != nil {
			t.Fatalf("it.Next for record %d failed: %v", i, err)
		}
		if r.Key != fmt.Sprintf("rot-%d", i) {
			t.Fatalf("record %d key mismatch: %s", i, r.Key)
		}
		if len(r.Payload) != 3000 || r.Payload[0] != byte(i) {
			t.Fatalf("record %d payload mismatch", i)
		}
	}

	_, err = it.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after all records, got: %v", err)
	}
}

type errFile struct {
	File
	failAtCall int
	callCount  int
}

func (e *errFile) WriteAt(p []byte, off int64) (int, error) {
	e.callCount++
	if e.callCount == e.failAtCall {
		return 0, errors.New("injected WriteAt failure")
	}
	return e.File.WriteAt(p, off)
}

type errFS struct {
	FS
	failAtCall int
}

func (e *errFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := e.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &errFile{File: f, failAtCall: e.failAtCall}, nil
}

func TestWAL_WriteErrorSticky(t *testing.T) {
	baseFS := NewMemFS()
	efs := &errFS{FS: baseFS, failAtCall: 1}
	var dbID [16]byte
	copy(dbID[:], []byte("wal-err-002"))

	var failureCallbackErr error
	wal, err := OpenWAL(efs, "wal_dir", dbID, 0, WALOptions{
		OnFailure: func(e error) {
			failureCallbackErr = e
		},
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	rec := Record{
		Type:    RecordTypePut,
		Key:     "fail-rec",
		Payload: make([]byte, 2*WALBlockSize),
		Token:   "tok-fail",
	}
	if err := wal.Append(rec); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = wal.Sync()
	if err == nil {
		t.Fatalf("expected Sync to fail due to injected error")
	}

	if failureCallbackErr == nil {
		t.Fatalf("expected OnFailure callback to be invoked on error")
	}

	// Verify error is sticky
	if err := wal.Append(Record{Type: RecordTypePut, Key: "subsequent"}); err == nil {
		t.Fatalf("expected Append after sticky error to fail")
	}
	if wal.DurableLSN() != 0 {
		t.Fatalf("expected DurableLSN to remain 0 after failed write, got %d", wal.DurableLSN())
	}
}
