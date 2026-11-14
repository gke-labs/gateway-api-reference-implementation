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
	"fmt"
	"sync"
)

// Checkpointer coordinates non-blocking checkpoints between the block pool, heap file, and WAL.
type Checkpointer struct {
	bp       *BlockPool
	heapFile File
	wal      *WAL
	mu       sync.Mutex
}

// NewCheckpointer creates a new Checkpointer.
func NewCheckpointer(bp *BlockPool, heapFile File, wal *WAL) *Checkpointer {
	return &Checkpointer{
		bp:       bp,
		heapFile: heapFile,
		wal:      wal,
	}
}

// FlushPages flushes all dirty pages to the heap file, fsyncs the heap, and promotes
// flushed locations to durable under the reuse rule without appending a checkpoint
// record to the WAL.
func (c *Checkpointer) FlushPages() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.flushPagesLocked()
}

func (c *Checkpointer) flushPagesLocked() error {
	// Flush dirty pages to disk under write-ahead rule
	if err := c.bp.FlushAllDirty(); err != nil {
		return fmt.Errorf("failed to flush dirty pages: %w", err)
	}

	// Record locations flushed before fsync begins (Reuse Rule / Item 11)
	c.bp.SnapshotFlushedForSync()

	// Fsync heap file
	if err := c.heapFile.Sync(); err != nil {
		return fmt.Errorf("failed to fsync heap file: %w", err)
	}

	// Promote flushed locations to durable (frees superseded locations)
	if err := c.bp.PromoteFlushedToDurable(); err != nil {
		return fmt.Errorf("failed to promote flushed pages: %w", err)
	}

	return nil
}

// Checkpoint performs a non-blocking checkpoint:
// 1. Snapshot dirty pages and capture current max LSN at snapshot time.
// 2. Flush dirty pages to new physical locations (out-of-place write).
// 3. Snapshot flushed locations before heap fsync begins (Reuse Rule).
// 4. Fsync heap file.
// 5. Promote pre-sync flushed locations to durable; free older superseded durable locations.
// 6. Append checkpoint record to WAL giving redo start LSN.
// 7. Fsync WAL.
// 8. Truncate eligible WAL segments strictly prior to redo start LSN.
func (c *Checkpointer) Checkpoint() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Determine redo start LSN from dirty page table snapshot at start of checkpoint
	dpt, snapshotLSN := c.bp.DirtyPageTableAndLSN()
	var redoStartLSN uint64

	for _, dirtyLSN := range dpt {
		if redoStartLSN == 0 || dirtyLSN < redoStartLSN {
			redoStartLSN = dirtyLSN
		}
	}
	if redoStartLSN == 0 {
		// When dirty page table is empty, redo start must be the LSN at the time
		// the dirty page table was snapshotted (Item 14).
		redoStartLSN = snapshotLSN
	}

	// 2-5. Flush dirty pages, sync heap file, and promote flushed locations
	if err := c.flushPagesLocked(); err != nil {
		return 0, fmt.Errorf("checkpoint failed to flush dirty pages: %w", err)
	}

	// 6. Append checkpoint record to WAL, assigning LSN under WAL lock
	chkRec := Record{
		Type:         RecordTypeCheckpoint,
		RedoStartLSN: redoStartLSN,
	}
	chkLSN, err := c.wal.AppendRecord(&chkRec)
	if err != nil {
		return 0, fmt.Errorf("checkpoint failed to write WAL record: %w", err)
	}

	// 7. Fsync WAL
	if err := c.wal.Sync(); err != nil {
		return 0, fmt.Errorf("checkpoint failed to fsync WAL: %w", err)
	}

	// 8. Truncate finished WAL segments prior to redoStartLSN
	if err := c.wal.TruncateBefore(redoStartLSN); err != nil {
		return 0, fmt.Errorf("checkpoint failed to truncate WAL: %w", err)
	}

	return chkLSN, nil
}
