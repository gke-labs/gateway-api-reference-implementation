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
	wal      Log
	// metaFile is the open handle to meta.db used to update recovery start pages.
	metaFile File
	// mu serializes concurrent checkpoints and protects activePageIndex and pageCounter.
	mu sync.Mutex

	// activePageIndex is the 0..7 index of the page in the recovery ring holding the latest valid record.
	activePageIndex int

	// pageCounter is the monotonic write counter in the latest valid record.
	pageCounter uint64
}

// NewCheckpointer creates a new Checkpointer.
func NewCheckpointer(bp *BlockPool, heapFile File, wal Log, metaFile File, activePageIndex int, pageCounter uint64) *Checkpointer {
	return &Checkpointer{
		bp:              bp,
		heapFile:        heapFile,
		wal:             wal,
		metaFile:        metaFile,
		activePageIndex: activePageIndex,
		pageCounter:     pageCounter,
	}
}

func (c *Checkpointer) writeRecoveryPageLocked(redoStartLSN uint64) error {
	targetIndex := (c.activePageIndex + 1) % metaRecoveryPageCount
	nextCounter := c.pageCounter + 1

	record := recoveryStartRecord{
		recoveryStartLSN: redoStartLSN,
		counter:          nextCounter,
	}
	encoded := encodeRecoveryPage(record)

	offset := recoveryPageOffset(targetIndex)
	if _, err := c.metaFile.WriteAt(encoded, offset); err != nil {
		return fmt.Errorf("failed to write recovery page to meta.db: %w", err)
	}

	if err := c.metaFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync meta.db after writing recovery page: %w", err)
	}

	c.activePageIndex = targetIndex
	c.pageCounter = nextCounter
	return nil
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
	c.bp.startHeapSync()

	// Fsync heap file
	if err := c.heapFile.Sync(); err != nil {
		// A failed fsync releases no blocks to protect older durable copies.
		// The blocks remain held in deferredFreesSyncing for a future successful fsync.
		// If the engine enters its failed state, it writes the FAILED marker, and the next
		// Open erases the store when WithEraseOnError is set, or returns "store requires erase"
		// when it is not. The allocator is rebuilt from block headers only after a crash that leaves no marker.
		c.bp.heapSyncFailed()
		return fmt.Errorf("failed to fsync heap file: %w", err)
	}

	if err := c.bp.heapSyncSucceeded(); err != nil {
		return fmt.Errorf("failed to free deferred blocks: %w", err)
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
// 6. Write recovery start LSN page to meta.db and fsync meta.db.
// 7. Append checkpoint record to WAL as a completion marker and to advance the WAL LSN.
// 8. Fsync WAL.
// 9. Truncate eligible WAL segments strictly prior to redo start LSN.
func (c *Checkpointer) Checkpoint() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Determine redo start LSN from dirty page table snapshot at start of checkpoint
	dpt, snapshotLSN := c.bp.DirtyPageTableAndLSN()
	var redoStartLSN uint64

	for _, redoLSN := range dpt {
		if redoStartLSN == 0 || redoLSN < redoStartLSN {
			redoStartLSN = redoLSN
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

	// 6. Write the recovery start LSN page to meta.db only after the heap fsync completes,
	// and then fsync meta.db.
	// The heap fsync must precede the meta.db fsync: if the order were reversed and
	// meta.db were fsynced first, a crash before the heap fsync completes would leave
	// meta.db pointing to a recovery start LSN whose corresponding heap pages are not
	// durable on disk. Recovery would then start replay at the advanced LSN, skipping
	// replay of unpersisted changes and causing silent data loss.
	// The stored LSN is safe because when dirty pages exist, it is the smallest RedoLSN
	// across all unpersisted pages and the heap flush has synced the log past it; when no
	// dirty pages exist, it is MaxLSN (snapshotLSN) reflecting that all earlier changes are durable.
	if err := c.writeRecoveryPageLocked(redoStartLSN); err != nil {
		return 0, fmt.Errorf("checkpoint failed to write recovery start page to meta.db: %w", err)
	}

	// 7. Append checkpoint record to WAL, assigning LSN under WAL lock
	chkRec := Record{
		Type: RecordTypeCheckpoint,
	}
	chkLSN, err := c.wal.AppendRecord(&chkRec)
	if err != nil {
		return 0, fmt.Errorf("checkpoint failed to write WAL record: %w", err)
	}

	// 8. Fsync WAL
	if err := c.wal.Sync(); err != nil {
		return 0, fmt.Errorf("checkpoint failed to fsync WAL: %w", err)
	}

	// 9. Truncate finished WAL segments prior to redoStartLSN
	if err := c.wal.TruncateBefore(redoStartLSN); err != nil {
		return 0, fmt.Errorf("checkpoint failed to truncate WAL: %w", err)
	}

	return chkLSN, nil
}
