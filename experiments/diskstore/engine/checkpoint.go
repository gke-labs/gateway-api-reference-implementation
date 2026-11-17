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
	metaFile File
	mu       sync.Mutex

	activeSlot       int    // 0 or 1: index of slot holding latest valid recovery position
	slotCounter      uint64 // counter in the latest valid slot
	hasActiveSlot    bool   // true if at least one valid slot exists
	recoveryStartLSN uint64 // current recovery start LSN
}

// NewCheckpointer creates a new Checkpointer.
func NewCheckpointer(bp *BlockPool, heapFile File, wal Log, metaFile ...File) *Checkpointer {
	var mf File
	if len(metaFile) > 0 {
		mf = metaFile[0]
	}
	return &Checkpointer{
		bp:         bp,
		heapFile:   heapFile,
		wal:        wal,
		metaFile:   mf,
		activeSlot: 1, // default so first write targets slot 0
	}
}

func (c *Checkpointer) initRecoverySlot(activeSlot int, slotCounter uint64, hasActive bool, recoveryStartLSN uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeSlot = activeSlot
	c.slotCounter = slotCounter
	c.hasActiveSlot = hasActive
	c.recoveryStartLSN = recoveryStartLSN
}

// RecoveryStartLSN returns the latest recovery start LSN written to meta.db.
func (c *Checkpointer) RecoveryStartLSN() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recoveryStartLSN
}

func (c *Checkpointer) writeRecoverySlotLocked(redoStartLSN uint64) error {
	if c.metaFile == nil {
		return nil
	}

	targetSlot := 0
	nextCounter := uint64(1)
	if c.hasActiveSlot {
		targetSlot = 1 - c.activeSlot
		nextCounter = c.slotCounter + 1
	}

	slot := recoveryStartSlot{
		recoveryStartLSN: redoStartLSN,
		counter:          nextCounter,
	}
	encoded := encodeRecoveryStartSlot(slot)

	offset := int64(metaOffsetRecoverySlot0)
	if targetSlot == 1 {
		offset = int64(metaOffsetRecoverySlot1)
	}

	if _, err := c.metaFile.WriteAt(encoded, offset); err != nil {
		return fmt.Errorf("failed to write recovery slot to meta.db: %w", err)
	}

	if err := c.metaFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync meta.db after writing recovery slot: %w", err)
	}

	c.activeSlot = targetSlot
	c.slotCounter = nextCounter
	c.hasActiveSlot = true
	c.recoveryStartLSN = redoStartLSN
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
// 6. Append checkpoint record to WAL giving redo start LSN.
// 7. Fsync WAL.
// 8. Truncate eligible WAL segments strictly prior to redo start LSN.
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

	// Write the recovery start LSN slot to meta.db only after the heap fsync completes,
	// and then fsync meta.db.
	// The heap fsync must precede the meta.db fsync: if the order were reversed and
	// meta.db were fsynced first, a crash before the heap fsync completes would leave
	// meta.db pointing to a recovery start LSN whose corresponding heap pages are not
	// durable on disk. Recovery would then start replay at the advanced LSN, skipping
	// replay of unpersisted changes and causing silent data loss.
	if c.metaFile != nil {
		if err := c.writeRecoverySlotLocked(redoStartLSN); err != nil {
			return 0, fmt.Errorf("checkpoint failed to write recovery start slot to meta.db: %w", err)
		}
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
