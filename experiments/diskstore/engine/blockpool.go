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
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	// DefaultBlockPoolBlocks is 1024 blocks = 4 MiB.
	DefaultBlockPoolBlocks = 1024

	// MaxBatchBlocks is the maximum number of blocks in a flush batch (512 blocks = 2 MiB = 1 << MaxOrder).
	MaxBatchBlocks = 1 << MaxOrder

	// NoBlock is a sentinel representing an unassigned block location.
	NoBlock uint64 = ^uint64(0)
)

var (
	// ErrBlockPoolFull is returned when all pool blocks are pinned and cannot be evicted.
	ErrBlockPoolFull = errors.New("block pool is full of pinned pages")

	// ErrPageNotFound indicates the page is neither in memory nor has a location on disk.
	ErrPageNotFound = errors.New("page not found")
)

// PageDesc holds metadata and pool block mappings for a logical page in the block pool.
type PageDesc struct {
	LogicalPage uint64
	NumBlocks   int
	PoolBlocks  []int // Non-adjacent pool blocks in the arena

	PinCount   atomic.Int32
	Dirty      bool
	DirtyLSN   uint64        // ARIES: first LSN that dirtied page since last flush
	PageLSN    atomic.Uint64 // latest LSN that modified this page
	DirtyTime  time.Time     // Timestamp when page became dirty
	LastAccess time.Time     // Timestamp for LRU eviction tracking

	PhysicalBlock     uint64 // currently known disk location
	FlushedLoc        uint64 // location written since last heap fsync
	FlushedBeforeSync uint64 // location written before current heap fsync started
	DurableLoc        uint64 // location confirmed durable by heap fsync

	InFlight bool // true when a direct I/O flush is active for this page

	Mu sync.RWMutex // Per-page latch for safe read/write access to pool block data
}

// PageHandle is held by callers while accessing a pinned page.
type PageHandle struct {
	pool *BlockPool
	Desc *PageDesc
}

// Blocks returns byte slices for each block in this page.
func (h *PageHandle) Blocks() [][]byte {
	blocks := make([][]byte, len(h.Desc.PoolBlocks))
	for i, pbID := range h.Desc.PoolBlocks {
		start := pbID * BlockSize
		blocks[i] = h.pool.arena[start : start+BlockSize]
	}
	return blocks
}

// Block returns the byte slice for a specific block index.
func (h *PageHandle) Block(i int) []byte {
	pbID := h.Desc.PoolBlocks[i]
	start := pbID * BlockSize
	return h.pool.arena[start : start+BlockSize]
}

// Unpin releases the caller's pin on the page.
func (h *PageHandle) Unpin() {
	if h.Desc.PinCount.Add(-1) == 0 && h.pool != nil && h.pool.cond != nil {
		h.pool.mu.Lock()
		h.pool.cond.Broadcast()
		h.pool.mu.Unlock()
	}
}

// BlockPool manages a fixed-size arena of 4 KiB pool blocks with direct I/O, out-of-place writes,
// and write-ahead rule enforcement.
// Lock hierarchy: bp.mu (pool-wide mutex) -> desc.Mu (per-page latch). Never acquire bp.mu while holding desc.Mu.
type BlockPool struct {
	file     File
	wal      *WAL
	buddy    *BuddyAllocator
	directIO DirectIO
	cipher   Cipher
	dbID     [16]byte

	numPoolBlocks int
	arena         []byte // Pointer-free byte arena aligned to 4096 bytes

	// mu guards freePoolBlocks, pageTable, and onFailure.
	mu sync.Mutex

	// cond uses mu. It is broadcast when an in-flight flush completes or when
	// a page handle's pin count drops to zero. Waiters re-check whether the
	// target page descriptor has finished flushing (InFlight == false) and has
	// released all pins (PinCount == 0).
	cond *sync.Cond

	freePoolBlocks []int
	pageTable      map[uint64]*PageDesc // logicalPage -> PageDesc
	onFailure      func(error)

	stagingBuf []byte     // Pointer-free aligned 2 MiB staging buffer for direct I/O flushes
	flushMu    sync.Mutex // Serializes staging buffer usage and direct I/O heap writes

	bgStop chan struct{}
	bgDone chan struct{}
}

// BlockPoolOptions configures the BlockPool.
type BlockPoolOptions struct {
	NumPoolBlocks int
	Cipher        Cipher
	OnFailure     func(error)
}

// NewBlockPool initializes a fixed-size block pool backed by a single pointer-free byte arena.
func NewBlockPool(file File, wal *WAL, buddy *BuddyAllocator, dbID [16]byte, opts ...BlockPoolOptions) *BlockPool {
	numPoolBlocks := DefaultBlockPoolBlocks
	var cipher Cipher
	var onFailure func(error)
	if len(opts) > 0 {
		if opts[0].NumPoolBlocks > 0 {
			numPoolBlocks = opts[0].NumPoolBlocks
		}
		cipher = opts[0].Cipher
		onFailure = opts[0].OnFailure
	}

	// Allocate pointer-free byte arena aligned to 4096 bytes without mmap
	totalBytes := numPoolBlocks * BlockSize
	raw := make([]byte, totalBytes+BlockSize)
	rawPtr := uintptr(unsafe.Pointer(&raw[0]))
	alignedPtr := (rawPtr + uintptr(BlockSize-1)) &^ uintptr(BlockSize-1)
	offset := int(alignedPtr - rawPtr)
	arena := raw[offset : offset+totalBytes]

	freePoolBlocks := make([]int, numPoolBlocks)
	for i := 0; i < numPoolBlocks; i++ {
		freePoolBlocks[i] = i
	}

	stagingBuf := AllocateAlignedBlock(MaxBatchBlocks * BlockSize)

	bp := &BlockPool{
		file:           file,
		wal:            wal,
		buddy:          buddy,
		directIO:       NewDirectIO(),
		cipher:         cipher,
		dbID:           dbID,
		numPoolBlocks:  numPoolBlocks,
		arena:          arena,
		freePoolBlocks: freePoolBlocks,
		stagingBuf:     stagingBuf,
		pageTable:      make(map[uint64]*PageDesc),
		onFailure:      onFailure,
		bgStop:         make(chan struct{}),
		bgDone:         make(chan struct{}),
	}
	bp.cond = sync.NewCond(&bp.mu)

	go bp.backgroundIdleSweep()
	return bp
}

func (bp *BlockPool) SetOnFailure(fn func(error)) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.onFailure = fn
}

func (bp *BlockPool) fail(err error) {
	if bp.onFailure != nil {
		bp.onFailure(err)
	}
}

// backgroundIdleSweep sweeps pages that have been dirty and idle for > 1 minute.
// Runs every 10 seconds (no 20ms busy flushing).
func (bp *BlockPool) backgroundIdleSweep() {
	defer close(bp.bgDone)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-bp.bgStop:
			return
		case <-ticker.C:
			bp.sweepIdleDirtyPages()
		}
	}
}

func (bp *BlockPool) sweepIdleDirtyPages() {
	bp.mu.Lock()
	now := time.Now()
	lowWatermark := bp.numPoolBlocks / 5
	var toFlush []*PageDesc
	for _, desc := range bp.pageTable {
		if desc.Dirty && desc.PinCount.Load() == 0 && !desc.InFlight && len(desc.PoolBlocks) > 0 {
			if now.Sub(desc.DirtyTime) >= time.Minute || len(bp.freePoolBlocks) < lowWatermark {
				toFlush = append(toFlush, desc)
				if len(toFlush) >= 16 {
					break
				}
			}
		}
	}
	if len(toFlush) == 0 {
		bp.mu.Unlock()
		return
	}

	var err error
	if len(toFlush) == 1 {
		err = bp.flushPageUnlocked(toFlush[0])
	} else {
		err = bp.flushBatchUnlocked(toFlush)
	}
	bp.mu.Unlock()

	if err != nil {
		bp.fail(fmt.Errorf("background idle sweep failed: %w", err))
		return
	}
}

// PinPage pins an existing page in the block pool, loading it from disk if necessary.
func (bp *BlockPool) PinPage(logicalPage uint64) (*PageHandle, error) {
	bp.mu.Lock()
	desc, exists := bp.pageTable[logicalPage]
	if !exists {
		bp.mu.Unlock()
		return nil, ErrPageNotFound
	}

	if len(desc.PoolBlocks) > 0 {
		desc.PinCount.Add(1)
		desc.LastAccess = time.Now()
		bp.mu.Unlock()
		return &PageHandle{pool: bp, Desc: desc}, nil
	}

	// Page was evicted from memory pool blocks; reload from disk
	readBlock := desc.PhysicalBlock
	if readBlock == NoBlock {
		readBlock = desc.DurableLoc
	}
	if readBlock == NoBlock {
		bp.mu.Unlock()
		return nil, ErrPageNotFound
	}

	poolBlocks, err := bp.acquirePoolBlocksLocked(desc.NumBlocks)
	if err != nil {
		bp.mu.Unlock()
		return nil, err
	}

	desc.PoolBlocks = poolBlocks
	desc.PinCount.Store(1)
	desc.LastAccess = time.Now()

	iov := make([][]byte, desc.NumBlocks)
	for i, pbID := range poolBlocks {
		start := pbID * BlockSize
		iov[i] = bp.arena[start : start+BlockSize]
	}

	if err := bp.directIO.Readv(bp.file, int64(readBlock*BlockSize), iov); err != nil {
		bp.freePoolBlocks = append(bp.freePoolBlocks, poolBlocks...)
		desc.PoolBlocks = nil
		desc.PinCount.Store(0)
		bp.mu.Unlock()
		return nil, fmt.Errorf("failed to read page %d from disk block %d: %w", logicalPage, readBlock, err)
	}

	// Verify block headers
	for i := 0; i < desc.NumBlocks; i++ {
		hdr, err := DecodeBlockHeader(iov[i])
		if err != nil || hdr.LogicalPage != logicalPage || hdr.BlockIndex != uint32(i) {
			bp.freePoolBlocks = append(bp.freePoolBlocks, poolBlocks...)
			desc.PoolBlocks = nil
			desc.PinCount.Store(0)
			bp.mu.Unlock()
			return nil, fmt.Errorf("corrupt block in page %d", logicalPage)
		}
		desc.PageLSN.Store(hdr.LSN)
	}

	bp.mu.Unlock()
	return &PageHandle{pool: bp, Desc: desc}, nil
}

// LoadPageDescs registers recovered page descriptors into the page table.
func (bp *BlockPool) LoadPageDescs(descs map[uint64]*PageDesc) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	for k, v := range descs {
		bp.pageTable[k] = v
	}
}

// PageLSN returns the latest LSN of the specified logical page and whether it exists in the page table.
func (bp *BlockPool) PageLSN(logicalPage uint64) (uint64, bool) {
	bp.mu.Lock()
	desc, exists := bp.pageTable[logicalPage]
	bp.mu.Unlock()
	if !exists || desc == nil {
		return 0, false
	}
	return desc.PageLSN.Load(), true
}

// PinPageWithLocation pins a page, loading from disk at physicalBlock if not currently in memory.
func (bp *BlockPool) PinPageWithLocation(logicalPage uint64, physicalBlock uint64, numBlocks int) (*PageHandle, error) {
	bp.mu.Lock()
	desc, exists := bp.pageTable[logicalPage]
	if !exists {
		desc = &PageDesc{
			LogicalPage:       logicalPage,
			NumBlocks:         numBlocks,
			PhysicalBlock:     physicalBlock,
			FlushedLoc:        NoBlock,
			FlushedBeforeSync: NoBlock,
			DurableLoc:        physicalBlock,
			LastAccess:        time.Now(),
		}
		bp.pageTable[logicalPage] = desc
	}
	bp.mu.Unlock()
	return bp.PinPage(logicalPage)
}

// AllocateNewPage creates a new page in the block pool with freshly acquired pool blocks.
func (bp *BlockPool) AllocateNewPage(logicalPage uint64, numBlocks int, lsn uint64) (*PageHandle, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Wait until any in-flight flush finishes and all pins are released on the existing descriptor.
	for {
		oldDesc := bp.pageTable[logicalPage]
		if oldDesc == nil {
			break
		}
		if !oldDesc.InFlight && oldDesc.PinCount.Load() == 0 {
			break
		}
		bp.cond.Wait()
	}

	poolBlocks, err := bp.acquirePoolBlocksLocked(numBlocks)
	if err != nil {
		return nil, err
	}

	// Re-check idleness because acquirePoolBlocksLocked may have temporarily released bp.mu
	// to flush dirty pages. Loop on cond.Wait() while keeping the acquired pool blocks until
	// the old descriptor is idle, and hold bp.mu without releasing it through the teardown.
	for {
		oldDesc := bp.pageTable[logicalPage]
		if oldDesc == nil {
			break
		}
		if !oldDesc.InFlight && oldDesc.PinCount.Load() == 0 {
			break
		}
		bp.cond.Wait()
	}

	var oldDurableLoc uint64 = NoBlock
	var oldFlushedBeforeSync uint64 = NoBlock
	var oldFlushedLoc uint64 = NoBlock

	if oldDesc := bp.pageTable[logicalPage]; oldDesc != nil {
		if len(oldDesc.PoolBlocks) > 0 {
			bp.freePoolBlocks = append(bp.freePoolBlocks, oldDesc.PoolBlocks...)
			oldDesc.PoolBlocks = nil
		}

		// Defer freeing the old durable location until the new copy is promoted to durable,
		// fulfilling the Reuse Rule.
		oldDurableLoc = oldDesc.DurableLoc
		oldFlushedBeforeSync = oldDesc.FlushedBeforeSync
		oldFlushedLoc = oldDesc.FlushedLoc

		oldDesc.DurableLoc = NoBlock
		oldDesc.FlushedBeforeSync = NoBlock
		oldDesc.FlushedLoc = NoBlock
		oldDesc.PhysicalBlock = NoBlock
	}

	now := time.Now()
	desc := &PageDesc{
		LogicalPage:       logicalPage,
		NumBlocks:         numBlocks,
		PoolBlocks:        poolBlocks,
		Dirty:             true,
		DirtyLSN:          lsn,
		DirtyTime:         now,
		LastAccess:        now,
		PhysicalBlock:     NoBlock,
		FlushedLoc:        oldFlushedLoc,
		FlushedBeforeSync: oldFlushedBeforeSync,
		DurableLoc:        oldDurableLoc,
	}
	desc.PageLSN.Store(lsn)
	desc.PinCount.Store(1)

	// Clear pool blocks and encode initial block headers
	for i, pbID := range poolBlocks {
		start := pbID * BlockSize
		blk := bp.arena[start : start+BlockSize]
		clearBytes(blk)
		hdr := BlockHeader{
			LogicalPage: logicalPage,
			LSN:         lsn,
			BlockIndex:  uint32(i),
			NumBlocks:   uint32(numBlocks),
		}
		EncodeBlockHeader(hdr, blk)
	}

	bp.pageTable[logicalPage] = desc
	return &PageHandle{pool: bp, Desc: desc}, nil
}

// FreePage releases the pool blocks and disk locations for a discarded or cleared logical page.
func (bp *BlockPool) FreePage(logicalPage uint64) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	for {
		desc, exists := bp.pageTable[logicalPage]
		if !exists || desc == nil {
			return
		}
		if !desc.InFlight && desc.PinCount.Load() == 0 {
			if len(desc.PoolBlocks) > 0 {
				bp.freePoolBlocks = append(bp.freePoolBlocks, desc.PoolBlocks...)
				desc.PoolBlocks = nil
			}
			if desc.DurableLoc != NoBlock {
				if err := bp.buddy.Free(desc.DurableLoc); err != nil && bp.onFailure != nil {
					bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free durable block %d: %w", desc.DurableLoc, err))
				}
				desc.DurableLoc = NoBlock
			}
			if desc.FlushedLoc != NoBlock && desc.FlushedLoc != desc.DurableLoc {
				if err := bp.buddy.Free(desc.FlushedLoc); err != nil && bp.onFailure != nil {
					bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free flushed block %d: %w", desc.FlushedLoc, err))
				}
				desc.FlushedLoc = NoBlock
			}
			if desc.PhysicalBlock != NoBlock && desc.PhysicalBlock != desc.DurableLoc && desc.PhysicalBlock != desc.FlushedLoc {
				if err := bp.buddy.Free(desc.PhysicalBlock); err != nil && bp.onFailure != nil {
					bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free physical block %d: %w", desc.PhysicalBlock, err))
				}
				desc.PhysicalBlock = NoBlock
			}
			delete(bp.pageTable, logicalPage)
			return
		}
		bp.cond.Wait()
	}
}

// acquirePoolBlocksLocked acquires count pool blocks, evicting clean pages first by LRU, then flushing dirty pages.
func (bp *BlockPool) acquirePoolBlocksLocked(count int) ([]int, error) {
	for len(bp.freePoolBlocks) < count {
		// Pass 1: Evict clean, unpinned pages first by oldest LastAccess (zero disk I/O)
		var bestClean *PageDesc
		for _, desc := range bp.pageTable {
			if len(desc.PoolBlocks) > 0 && desc.PinCount.Load() == 0 && !desc.Dirty && !desc.InFlight {
				if bestClean == nil || desc.LastAccess.Before(bestClean.LastAccess) {
					bestClean = desc
				}
			}
		}
		if bestClean != nil {
			bp.freePoolBlocks = append(bp.freePoolBlocks, bestClean.PoolBlocks...)
			bestClean.PoolBlocks = nil
			continue
		}

		// Pass 2: Flush unpinned dirty pages in a batch outside lock (routine cleaning should batch)
		lowWatermark := bp.numPoolBlocks / 5
		targetPoolBlocks := count - len(bp.freePoolBlocks)
		if replenish := lowWatermark - len(bp.freePoolBlocks); replenish > targetPoolBlocks {
			targetPoolBlocks = replenish
		}
		if targetPoolBlocks > 64 {
			targetPoolBlocks = 64
		}
		if targetPoolBlocks < 1 {
			targetPoolBlocks = 1
		}

		var candidates []*PageDesc
		hasInFlight := false
		for _, desc := range bp.pageTable {
			if len(desc.PoolBlocks) > 0 {
				if desc.InFlight {
					hasInFlight = true
				}
				if desc.PinCount.Load() == 0 && desc.Dirty && !desc.InFlight {
					candidates = append(candidates, desc)
				}
			}
		}
		if len(candidates) == 0 {
			if hasInFlight {
				// Waiting is safe because flushBlockRunUnlocked clears InFlight and
				// broadcasts on bp.cond on both success and failure with bp.mu held,
				// waking this waiter to re-check candidate pages.
				bp.cond.Wait()
				continue
			}
			return nil, ErrBlockPoolFull
		}

		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].LastAccess.Before(candidates[j].LastAccess)
		})

		batchPoolBlocks := 0
		var toEvict []*PageDesc
		for _, desc := range candidates {
			toEvict = append(toEvict, desc)
			batchPoolBlocks += len(desc.PoolBlocks)
			if batchPoolBlocks >= targetPoolBlocks {
				break
			}
		}

		var flushErr error
		if len(toEvict) == 1 {
			flushErr = bp.flushPageUnlocked(toEvict[0])
		} else {
			flushErr = bp.flushBatchUnlocked(toEvict)
		}
		if flushErr != nil {
			return nil, flushErr
		}

		// Immediately evict pool blocks of the newly cleaned pages
		for _, desc := range toEvict {
			if !desc.Dirty && desc.PinCount.Load() == 0 && !desc.InFlight && len(desc.PoolBlocks) > 0 {
				bp.freePoolBlocks = append(bp.freePoolBlocks, desc.PoolBlocks...)
				desc.PoolBlocks = nil
			}
		}
	}

	allocated := make([]int, count)
	for i := 0; i < count; i++ {
		allocated[i] = bp.freePoolBlocks[len(bp.freePoolBlocks)-1]
		bp.freePoolBlocks = bp.freePoolBlocks[:len(bp.freePoolBlocks)-1]
	}
	return allocated, nil
}

// MarkDirty flags a page as modified with the given LSN.
// Lock hierarchy: called outside desc.Mu or after desc.Mu is released.
func (bp *BlockPool) MarkDirty(logicalPage uint64, lsn uint64) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if desc, exists := bp.pageTable[logicalPage]; exists {
		if !desc.Dirty {
			desc.Dirty = true
			desc.DirtyLSN = lsn
			desc.DirtyTime = time.Now()
		}
		desc.PageLSN.Store(lsn)
	}
}

// FlushPageLocked flushes desc to disk while holding bp.mu.
func (bp *BlockPool) FlushPageLocked(desc *PageDesc) error {
	return bp.flushPageUnlocked(desc)
}

// FlushPage flushes a dirty page to disk under the write-ahead rule and out-of-place write rule.
func (bp *BlockPool) FlushPage(logicalPage uint64) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	desc, exists := bp.pageTable[logicalPage]
	if !exists || !desc.Dirty {
		return nil
	}
	return bp.flushPageUnlocked(desc)
}

// flushPageUnlocked flushes desc to disk, releasing bp.mu during direct I/O.
// Must be called with bp.mu held; returns with bp.mu held.
func (bp *BlockPool) flushPageUnlocked(desc *PageDesc) error {
	if !desc.Dirty || desc.InFlight || len(desc.PoolBlocks) == 0 {
		return nil
	}
	return bp.flushBlockRunUnlocked([]*PageDesc{desc})
}

// flushBatchUnlocked flushes a batch of pages to disk in contiguous block runs with a single direct write per block run,
// releasing bp.mu during direct I/O and WAL sync.
// Must be called with bp.mu held; returns with bp.mu held.
func (bp *BlockPool) flushBatchUnlocked(batch []*PageDesc) error {
	var valid []*PageDesc
	for _, desc := range batch {
		if desc.Dirty && !desc.InFlight && len(desc.PoolBlocks) > 0 {
			valid = append(valid, desc)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	// Chunk the batch so each block run is at most MaxBatchBlocks (512 blocks = 1 << MaxOrder)
	for len(valid) > 0 {
		chunkTotalBlocks := 0
		chunkEnd := 0
		for chunkEnd < len(valid) {
			nextBlocks := valid[chunkEnd].NumBlocks
			if chunkEnd > 0 && chunkTotalBlocks+nextBlocks > MaxBatchBlocks {
				break
			}
			chunkTotalBlocks += nextBlocks
			chunkEnd++
		}

		chunk := valid[:chunkEnd]
		valid = valid[chunkEnd:]

		if err := bp.flushBlockRunUnlocked(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (bp *BlockPool) flushBlockRunUnlocked(chunk []*PageDesc) error {
	orders := make([]int, len(chunk))
	pageLSNs := make([]uint64, len(chunk))
	var maxLSN uint64
	totalBlocks := 0

	for i, desc := range chunk {
		order := 0
		for (1 << order) < desc.NumBlocks {
			order++
		}
		orders[i] = order
		lsn := desc.PageLSN.Load()
		pageLSNs[i] = lsn
		if lsn > maxLSN {
			maxLSN = lsn
		}
		totalBlocks += 1 << order
	}

	// Allocate contiguous block run from buddy allocator under bp.mu
	locs, err := bp.buddy.AllocateBatch(orders)
	if err != nil {
		return fmt.Errorf("failed to allocate contiguous disk blocks for batch of %d pages: %w", len(chunk), err)
	}

	startBlock := locs[0]
	for _, l := range locs {
		if l < startBlock {
			startBlock = l
		}
	}

	// Mark all pages in chunk as InFlight and pin them under bp.mu
	for _, desc := range chunk {
		desc.InFlight = true
		desc.PinCount.Add(1)
	}

	// Release pool mutex so concurrent operations can access other pages in memory
	bp.mu.Unlock()

	// Acquire flush mutex to copy into the shared aligned staging buffer and issue direct I/O write
	bp.flushMu.Lock()

	for i, desc := range chunk {
		desc.Mu.Lock()
		blockOffset := locs[i] - startBlock
		for j, pbID := range desc.PoolBlocks {
			srcStart := pbID * BlockSize
			blk := bp.arena[srcStart : srcStart+BlockSize]
			hdr := BlockHeader{
				LogicalPage: desc.LogicalPage,
				LSN:         pageLSNs[i],
				BlockIndex:  uint32(j),
				NumBlocks:   uint32(desc.NumBlocks),
			}
			EncodeBlockHeader(hdr, blk)
			FinalizeBlockCRC(blk)

			destStart := int(blockOffset+uint64(j)) * BlockSize
			copy(bp.stagingBuf[destStart:destStart+BlockSize], blk)
		}
		desc.Mu.Unlock()
	}

	// Sync WAL once per batch through maxLSN
	var syncErr error
	if bp.wal != nil && maxLSN > 0 {
		syncErr = bp.wal.SyncThrough(maxLSN)
	}

	// Single direct I/O write for the entire contiguous block run
	var writeErr error
	if syncErr == nil {
		totalBytes := int64(totalBlocks * BlockSize)
		writeErr = bp.directIO.Write(bp.file, int64(startBlock*BlockSize), bp.stagingBuf[:totalBytes])
	}

	bp.flushMu.Unlock()

	// Re-acquire pool mutex
	bp.mu.Lock()

	for _, desc := range chunk {
		desc.InFlight = false
		desc.PinCount.Add(-1)
	}
	bp.cond.Broadcast()

	flushErr := errors.Join(syncErr, writeErr)
	if flushErr != nil {
		// Reclaim allocated blocks on failure
		var freeErrs []error
		for _, loc := range locs {
			if freeErr := bp.buddy.Free(loc); freeErr != nil {
				freeErrs = append(freeErrs, freeErr)
			}
		}
		if len(freeErrs) > 0 {
			flushErr = errors.Join(flushErr, fmt.Errorf("failed to free batch blocks on flush failure: %w", errors.Join(freeErrs...)))
		}
		if bp.onFailure != nil {
			bp.onFailure(flushErr)
		}
		return flushErr
	}

	// Update page locations and free superseded flushed locations
	for i, desc := range chunk {
		newLoc := locs[i]
		oldFlushed := desc.FlushedLoc
		desc.FlushedLoc = newLoc
		desc.PhysicalBlock = newLoc

		if oldFlushed != NoBlock && oldFlushed != desc.DurableLoc && oldFlushed != desc.FlushedBeforeSync {
			if err := bp.buddy.Free(oldFlushed); err != nil && bp.onFailure != nil {
				bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free superseded flushed block %d: %w", oldFlushed, err))
			}
		}
		if desc.PageLSN.Load() == pageLSNs[i] {
			desc.Dirty = false
		}
	}

	return nil
}

// FlushAllDirty flushes all dirty pages currently in the block pool.
func (bp *BlockPool) FlushAllDirty() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	var toFlush []*PageDesc
	for _, desc := range bp.pageTable {
		if desc.Dirty && len(desc.PoolBlocks) > 0 && !desc.InFlight {
			toFlush = append(toFlush, desc)
		}
	}

	return bp.flushBatchUnlocked(toFlush)
}

// SnapshotFlushedForSync records all currently flushed locations before a heap fsync starts.
// This fulfills the Reuse Rule: only locations written before the fsync began may be promoted to durable.
func (bp *BlockPool) SnapshotFlushedForSync() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	for _, desc := range bp.pageTable {
		if !desc.InFlight && desc.FlushedLoc != NoBlock {
			desc.FlushedBeforeSync = desc.FlushedLoc
		}
	}
}

// PromoteFlushedToDurable promotes only locations that were flushed before the heap fsync began.
// Frees any superseded durable locations to the buddy allocator according to the Reuse Rule.
func (bp *BlockPool) PromoteFlushedToDurable() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	var errs []error
	for _, desc := range bp.pageTable {
		if desc.FlushedBeforeSync != NoBlock {
			if desc.DurableLoc != NoBlock && desc.DurableLoc != desc.FlushedBeforeSync {
				// Old durable copy is now superseded and can be safely reused
				if err := bp.buddy.Free(desc.DurableLoc); err != nil {
					errs = append(errs, fmt.Errorf("page %d DurableLoc=%d (FlushedBeforeSync=%d): %w", desc.LogicalPage, desc.DurableLoc, desc.FlushedBeforeSync, err))
				}
			}
			desc.DurableLoc = desc.FlushedBeforeSync
			if desc.FlushedLoc == desc.FlushedBeforeSync {
				desc.FlushedLoc = NoBlock
			}
			desc.FlushedBeforeSync = NoBlock
		}
	}
	return errors.Join(errs...)
}

// DirtyPageTableAndLSN returns a map of logicalPage -> dirtyLSN and the current max LSN at snapshot time.
func (bp *BlockPool) DirtyPageTableAndLSN() (map[uint64]uint64, uint64) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	dpt := make(map[uint64]uint64)
	for pID, desc := range bp.pageTable {
		if desc.Dirty && desc.DirtyLSN > 0 {
			dpt[pID] = desc.DirtyLSN
		}
	}
	maxLSN := uint64(0)
	if bp.wal != nil {
		maxLSN = bp.wal.MaxLSN()
	}
	return dpt, maxLSN
}

// Close stops the background writer and flushes dirty pages.
func (bp *BlockPool) Close() error {
	close(bp.bgStop)
	<-bp.bgDone

	return bp.FlushAllDirty()
}
