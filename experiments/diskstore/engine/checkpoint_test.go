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
	bp := NewBufferPool(heapFile, wal, buddy, dbID, BufferPoolOptions{NumFrames: 16})
	defer bp.Close()

	checkpointer := NewCheckpointer(bp, heapFile, wal)

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
	if vw, ok := c.File.(interface{ Writev(off int64, iov [][]byte) error }); ok {
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
	t.Run("N <= VectorLimit issues 1 write call", func(t *testing.T) {
		const n = 64
		runCountingCheckpointTest(t, n, 1)
	})

	t.Run("N > VectorLimit issues ceil(N/VectorLimit) write calls", func(t *testing.T) {
		const n = 1050
		const expectedWrites = int64((n + MaxVectorLimit - 1) / MaxVectorLimit) // 2
		runCountingCheckpointTest(t, n, expectedWrites)
	})
}

func runCountingCheckpointTest(t *testing.T, numPages int, expectedWrites int64) {
	dir := t.TempDir()
	fs := NewOSFS()

	var dbID [16]byte
	copy(dbID[:], []byte("cnt-test-db-0001"))

	wal, err := OpenWAL(fs, filepath.Join(dir, "wal"), dbID, 0)
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
	bp := NewBufferPool(countingHeap, wal, buddy, dbID, BufferPoolOptions{NumFrames: numPages + 10})
	defer bp.Close()

	checkpointer := NewCheckpointer(bp, countingHeap, wal)

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
		t.Fatalf("expected %d write calls for %d pages, got %d (vector limit %d)",
			expectedWrites, numPages, writes, MaxVectorLimit)
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

