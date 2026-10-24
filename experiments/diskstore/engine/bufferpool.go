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
	// DefaultBufferPoolFrames is 1024 frames = 4 MiB.
	DefaultBufferPoolFrames = 1024

	// NoBlock is a sentinel representing an unassigned block location.
	NoBlock uint64 = ^uint64(0)
)

var (
	// ErrBufferPoolFull is returned when all frames are pinned and cannot be evicted.
	ErrBufferPoolFull = errors.New("buffer pool is full of pinned pages")

	// ErrPageNotFound indicates the page is neither in memory nor has a location on disk.
	ErrPageNotFound = errors.New("page not found")
)

// PageDesc holds metadata and frame mappings for a logical page in the buffer pool.
type PageDesc struct {
	LogicalPage uint64
	NumBlocks   int
	FrameIDs    []int // Non-adjacent frames in the arena

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

	Mu sync.RWMutex // Per-page latch for safe read/write access to frame data
}

// PageHandle is held by callers while accessing a pinned page.
type PageHandle struct {
	pool *BufferPool
	Desc *PageDesc
}

// Blocks returns byte slices for each block in this page.
func (h *PageHandle) Blocks() [][]byte {
	blocks := make([][]byte, len(h.Desc.FrameIDs))
	for i, fID := range h.Desc.FrameIDs {
		start := fID * BlockSize
		blocks[i] = h.pool.arena[start : start+BlockSize]
	}
	return blocks
}

// Block returns the byte slice for a specific block index.
func (h *PageHandle) Block(i int) []byte {
	fID := h.Desc.FrameIDs[i]
	start := fID * BlockSize
	return h.pool.arena[start : start+BlockSize]
}

// Unpin releases the caller's pin on the page.
func (h *PageHandle) Unpin() {
	h.Desc.PinCount.Add(-1)
}

// BufferPool manages a fixed-size arena of 4 KiB frames with direct I/O, out-of-place writes,
// and write-ahead rule enforcement.
// Lock hierarchy: bp.mu (pool-wide mutex) -> desc.Mu (per-page latch). Never acquire bp.mu while holding desc.Mu.
type BufferPool struct {
	file      File
	wal       *WAL
	buddy     *BuddyAllocator
	directIO  DirectIO
	cipher    Cipher
	dbID      [16]byte
	mu        sync.Mutex
	onFailure func(error)

	numFrames  int
	arena      []byte // Pointer-free byte arena aligned to 4096 bytes
	freeFrames []int

	pageTable map[uint64]*PageDesc // logicalPage -> PageDesc

	bgStop chan struct{}
	bgDone chan struct{}
}

// BufferPoolOptions configures the BufferPool.
type BufferPoolOptions struct {
	NumFrames int
	Cipher    Cipher
	OnFailure func(error)
}

// NewBufferPool initializes a fixed-size buffer pool backed by a single pointer-free byte arena.
func NewBufferPool(file File, wal *WAL, buddy *BuddyAllocator, dbID [16]byte, opts ...BufferPoolOptions) *BufferPool {
	numFrames := DefaultBufferPoolFrames
	var cipher Cipher
	var onFailure func(error)
	if len(opts) > 0 {
		if opts[0].NumFrames > 0 {
			numFrames = opts[0].NumFrames
		}
		cipher = opts[0].Cipher
		onFailure = opts[0].OnFailure
	}

	// Allocate pointer-free byte arena aligned to 4096 bytes without mmap
	totalBytes := numFrames * BlockSize
	raw := make([]byte, totalBytes+BlockSize)
	rawPtr := uintptr(unsafe.Pointer(&raw[0]))
	alignedPtr := (rawPtr + uintptr(BlockSize-1)) &^ uintptr(BlockSize-1)
	offset := int(alignedPtr - rawPtr)
	arena := raw[offset : offset+totalBytes]

	freeFrames := make([]int, numFrames)
	for i := 0; i < numFrames; i++ {
		freeFrames[i] = i
	}

	bp := &BufferPool{
		file:       file,
		wal:        wal,
		buddy:      buddy,
		directIO:   NewDirectIO(),
		cipher:     cipher,
		dbID:       dbID,
		numFrames:  numFrames,
		arena:      arena,
		freeFrames: freeFrames,
		pageTable:  make(map[uint64]*PageDesc),
		onFailure:  onFailure,
		bgStop:     make(chan struct{}),
		bgDone:     make(chan struct{}),
	}

	go bp.backgroundIdleSweep()
	return bp
}

func (bp *BufferPool) SetOnFailure(fn func(error)) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.onFailure = fn
}

func (bp *BufferPool) fail(err error) {
	if bp.onFailure != nil {
		bp.onFailure(err)
	}
}

// backgroundIdleSweep sweeps pages that have been dirty and idle for > 1 minute.
// Runs every 10 seconds (no 20ms busy flushing).
func (bp *BufferPool) backgroundIdleSweep() {
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

func (bp *BufferPool) sweepIdleDirtyPages() {
	bp.mu.Lock()
	now := time.Now()
	lowWatermark := bp.numFrames / 5
	var toFlush []*PageDesc
	for _, desc := range bp.pageTable {
		if desc.Dirty && desc.PinCount.Load() == 0 && !desc.InFlight && len(desc.FrameIDs) > 0 {
			if now.Sub(desc.DirtyTime) >= time.Minute || len(bp.freeFrames) < lowWatermark {
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

// PinPage pins an existing page in the buffer pool, loading it from disk if necessary.
func (bp *BufferPool) PinPage(logicalPage uint64) (*PageHandle, error) {
	bp.mu.Lock()
	desc, exists := bp.pageTable[logicalPage]
	if !exists {
		bp.mu.Unlock()
		return nil, ErrPageNotFound
	}

	if len(desc.FrameIDs) > 0 {
		desc.PinCount.Add(1)
		desc.LastAccess = time.Now()
		bp.mu.Unlock()
		return &PageHandle{pool: bp, Desc: desc}, nil
	}

	// Page was evicted from memory frames; reload from disk
	readBlock := desc.PhysicalBlock
	if readBlock == NoBlock {
		readBlock = desc.DurableLoc
	}
	if readBlock == NoBlock {
		bp.mu.Unlock()
		return nil, ErrPageNotFound
	}

	frameIDs, err := bp.acquireFramesLocked(desc.NumBlocks)
	if err != nil {
		bp.mu.Unlock()
		return nil, err
	}

	desc.FrameIDs = frameIDs
	desc.PinCount.Store(1)
	desc.LastAccess = time.Now()

	iov := make([][]byte, desc.NumBlocks)
	for i, fID := range frameIDs {
		start := fID * BlockSize
		iov[i] = bp.arena[start : start+BlockSize]
	}

	if err := bp.directIO.Readv(bp.file, int64(readBlock*BlockSize), iov); err != nil {
		bp.freeFrames = append(bp.freeFrames, frameIDs...)
		desc.FrameIDs = nil
		desc.PinCount.Store(0)
		bp.mu.Unlock()
		return nil, fmt.Errorf("failed to read page %d from disk block %d: %w", logicalPage, readBlock, err)
	}

	// Verify block headers
	for i := 0; i < desc.NumBlocks; i++ {
		hdr, err := DecodeBlockHeader(iov[i])
		if err != nil || hdr.LogicalPage != logicalPage || hdr.BlockIndex != uint32(i) {
			bp.freeFrames = append(bp.freeFrames, frameIDs...)
			desc.FrameIDs = nil
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
func (bp *BufferPool) LoadPageDescs(descs map[uint64]*PageDesc) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	for k, v := range descs {
		bp.pageTable[k] = v
	}
}

// PinPageWithLocation pins a page, loading from disk at physicalBlock if not currently in memory.
func (bp *BufferPool) PinPageWithLocation(logicalPage uint64, physicalBlock uint64, numBlocks int) (*PageHandle, error) {
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

// AllocateNewPage creates a new page in the buffer pool with freshly acquired frames.
func (bp *BufferPool) AllocateNewPage(logicalPage uint64, numBlocks int, lsn uint64) (*PageHandle, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Item 4: Reusing a logical page must release previous frames and disk blocks!
	if oldDesc, exists := bp.pageTable[logicalPage]; exists && oldDesc != nil {
		if len(oldDesc.FrameIDs) > 0 {
			bp.freeFrames = append(bp.freeFrames, oldDesc.FrameIDs...)
			oldDesc.FrameIDs = nil
		}
		if oldDesc.DurableLoc != NoBlock {
			if err := bp.buddy.Free(oldDesc.DurableLoc); err != nil && bp.onFailure != nil {
				bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free old durable block %d: %w", oldDesc.DurableLoc, err))
			}
			oldDesc.DurableLoc = NoBlock
		}
		if oldDesc.FlushedLoc != NoBlock && oldDesc.FlushedLoc != oldDesc.DurableLoc {
			if err := bp.buddy.Free(oldDesc.FlushedLoc); err != nil && bp.onFailure != nil {
				bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free old flushed block %d: %w", oldDesc.FlushedLoc, err))
			}
			oldDesc.FlushedLoc = NoBlock
		}
		if oldDesc.PhysicalBlock != NoBlock && oldDesc.PhysicalBlock != oldDesc.DurableLoc && oldDesc.PhysicalBlock != oldDesc.FlushedLoc {
			if err := bp.buddy.Free(oldDesc.PhysicalBlock); err != nil && bp.onFailure != nil {
				bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free old physical block %d: %w", oldDesc.PhysicalBlock, err))
			}
			oldDesc.PhysicalBlock = NoBlock
		}
	}

	frameIDs, err := bp.acquireFramesLocked(numBlocks)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	desc := &PageDesc{
		LogicalPage:       logicalPage,
		NumBlocks:         numBlocks,
		FrameIDs:          frameIDs,
		Dirty:             true,
		DirtyLSN:          lsn,
		DirtyTime:         now,
		LastAccess:        now,
		PhysicalBlock:     NoBlock,
		FlushedLoc:        NoBlock,
		FlushedBeforeSync: NoBlock,
		DurableLoc:        NoBlock,
	}
	desc.PageLSN.Store(lsn)
	desc.PinCount.Store(1)

	// Clear frames and encode initial block headers
	for i, fID := range frameIDs {
		start := fID * BlockSize
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

// FreePage releases the frames and disk locations for a discarded or cleared logical page.
func (bp *BufferPool) FreePage(logicalPage uint64) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if desc, exists := bp.pageTable[logicalPage]; exists && desc != nil {
		if len(desc.FrameIDs) > 0 {
			bp.freeFrames = append(bp.freeFrames, desc.FrameIDs...)
			desc.FrameIDs = nil
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
	}
}

// acquireFramesLocked acquires count frames, evicting clean pages first by LRU, then flushing dirty pages.
func (bp *BufferPool) acquireFramesLocked(count int) ([]int, error) {
	for len(bp.freeFrames) < count {
		// Pass 1: Evict clean, unpinned pages first by oldest LastAccess (zero disk I/O)
		var bestClean *PageDesc
		for _, desc := range bp.pageTable {
			if len(desc.FrameIDs) > 0 && desc.PinCount.Load() == 0 && !desc.Dirty && !desc.InFlight {
				if bestClean == nil || desc.LastAccess.Before(bestClean.LastAccess) {
					bestClean = desc
				}
			}
		}
		if bestClean != nil {
			bp.freeFrames = append(bp.freeFrames, bestClean.FrameIDs...)
			bestClean.FrameIDs = nil
			continue
		}

		// Pass 2: Flush unpinned dirty pages in a batch outside lock (routine cleaning should batch)
		lowWatermark := bp.numFrames / 5
		targetFrames := count - len(bp.freeFrames)
		if replenish := lowWatermark - len(bp.freeFrames); replenish > targetFrames {
			targetFrames = replenish
		}
		if targetFrames > 64 {
			targetFrames = 64
		}
		if targetFrames < 1 {
			targetFrames = 1
		}

		var candidates []*PageDesc
		for _, desc := range bp.pageTable {
			if len(desc.FrameIDs) > 0 && desc.PinCount.Load() == 0 && desc.Dirty && !desc.InFlight {
				candidates = append(candidates, desc)
			}
		}
		if len(candidates) == 0 {
			return nil, ErrBufferPoolFull
		}

		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].LastAccess.Before(candidates[j].LastAccess)
		})

		batchFrames := 0
		var toEvict []*PageDesc
		for _, desc := range candidates {
			toEvict = append(toEvict, desc)
			batchFrames += len(desc.FrameIDs)
			if batchFrames >= targetFrames {
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

		// Immediately evict frames of the newly cleaned pages
		for _, desc := range toEvict {
			if !desc.Dirty && desc.PinCount.Load() == 0 && !desc.InFlight && len(desc.FrameIDs) > 0 {
				bp.freeFrames = append(bp.freeFrames, desc.FrameIDs...)
				desc.FrameIDs = nil
			}
		}
	}

	allocated := make([]int, count)
	for i := 0; i < count; i++ {
		allocated[i] = bp.freeFrames[len(bp.freeFrames)-1]
		bp.freeFrames = bp.freeFrames[:len(bp.freeFrames)-1]
	}
	return allocated, nil
}

// MarkDirty flags a page as modified with the given LSN.
// Lock hierarchy: called outside desc.Mu or after desc.Mu is released.
func (bp *BufferPool) MarkDirty(logicalPage uint64, lsn uint64) {
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
func (bp *BufferPool) FlushPageLocked(desc *PageDesc) error {
	return bp.flushPageUnlocked(desc)
}

// FlushPage flushes a dirty page to disk under the write-ahead rule and out-of-place write rule.
func (bp *BufferPool) FlushPage(logicalPage uint64) error {
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
func (bp *BufferPool) flushPageUnlocked(desc *PageDesc) error {
	if !desc.Dirty || desc.InFlight || len(desc.FrameIDs) == 0 {
		return nil
	}

	pageLSN := desc.PageLSN.Load()

	// Allocate new location from buddy allocator under bp.mu
	order := 0
	for (1 << order) < desc.NumBlocks {
		order++
	}

	newLoc, err := bp.buddy.Allocate(order)
	if err != nil {
		return fmt.Errorf("failed to allocate disk block for page %d: %w", desc.LogicalPage, err)
	}

	desc.InFlight = true
	desc.PinCount.Add(1)

	desc.Mu.Lock()
	iov := make([][]byte, desc.NumBlocks)
	for i, fID := range desc.FrameIDs {
		start := fID * BlockSize
		blk := bp.arena[start : start+BlockSize]
		hdr := BlockHeader{
			LogicalPage: desc.LogicalPage,
			LSN:         pageLSN,
			BlockIndex:  uint32(i),
			NumBlocks:   uint32(desc.NumBlocks),
		}
		EncodeBlockHeader(hdr, blk)
		FinalizeBlockCRC(blk)

		// Copy into aligned direct I/O buffer to prevent data races with concurrent writers
		buf := AllocateAlignedBlock(BlockSize)
		copy(buf, blk)
		iov[i] = buf
	}
	desc.Mu.Unlock()

	// Release pool mutex during I/O
	bp.mu.Unlock()

	var syncErr error
	if bp.wal != nil {
		syncErr = bp.wal.SyncThrough(pageLSN)
	}

	var writeErr error
	if syncErr == nil {
		writeErr = bp.directIO.Writev(bp.file, int64(newLoc*BlockSize), iov)
	}

	// Re-acquire pool mutex
	bp.mu.Lock()
	desc.InFlight = false
	desc.PinCount.Add(-1)

	flushErr := errors.Join(syncErr, writeErr)
	if flushErr != nil {
		// Attempt to reclaim the newly allocated block so it is not leaked in-memory.
		// If Free fails, we do not panic because:
		// 1. The primary failure (flushErr) is already propagated to the caller and
		//    bp.onFailure transitions the store into a terminal failed state (ErrFailed),
		//    terminating further mutating operations.
		// 2. The BuddyAllocator is an in-memory structure that is never persisted directly.
		//    On restart, the allocator is reconstructed from scratch by scanning valid pages
		//    in the heap file (MarkAllocated). Since newLoc was never successfully flushed or
		//    checkpointed, it will naturally be reclaimed as free space during recovery.
		if freeErr := bp.buddy.Free(newLoc); freeErr != nil {
			flushErr = errors.Join(flushErr, fmt.Errorf("failed to free allocated block %d on flush failure: %w", newLoc, freeErr))
		}
		if bp.onFailure != nil {
			bp.onFailure(flushErr)
		}
		return flushErr
	}

	oldFlushed := desc.FlushedLoc
	desc.FlushedLoc = newLoc
	desc.PhysicalBlock = newLoc

	if oldFlushed != NoBlock && oldFlushed != desc.DurableLoc && oldFlushed != desc.FlushedBeforeSync {
		if err := bp.buddy.Free(oldFlushed); err != nil && bp.onFailure != nil {
			bp.onFailure(fmt.Errorf("buddy allocator corruption: failed to free superseded flushed block %d: %w", oldFlushed, err))
		}
	}
	if desc.PageLSN.Load() == pageLSN {
		desc.Dirty = false
	}
	return nil
}

// flushBatchUnlocked flushes a batch of pages to disk in contiguous extents with vectored writes,
// releasing bp.mu during direct I/O and WAL sync.
// Must be called with bp.mu held; returns with bp.mu held.
func (bp *BufferPool) flushBatchUnlocked(batch []*PageDesc) error {
	var valid []*PageDesc
	for _, desc := range batch {
		if desc.Dirty && !desc.InFlight && len(desc.FrameIDs) > 0 {
			valid = append(valid, desc)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if len(valid) == 1 {
		return bp.flushPageUnlocked(valid[0])
	}

	// Sort pages by NumBlocks descending to guarantee natural alignment for buddy allocation
	// without any holes or fragmentation between pages in the contiguous extent.
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].NumBlocks > valid[j].NumBlocks
	})

	// Chunk the batch so each extent and vectored write respects MaxVectorLimit
	for len(valid) > 0 {
		chunkTotalBlocks := 0
		chunkEnd := 0
		for chunkEnd < len(valid) {
			nextBlocks := valid[chunkEnd].NumBlocks
			if chunkEnd > 0 && chunkTotalBlocks+nextBlocks > MaxVectorLimit {
				break
			}
			chunkTotalBlocks += nextBlocks
			chunkEnd++
		}

		chunk := valid[:chunkEnd]
		valid = valid[chunkEnd:]

		if len(chunk) == 1 {
			if err := bp.flushPageUnlocked(chunk[0]); err != nil {
				return err
			}
			continue
		}

		if err := bp.flushSingleExtentBatchUnlocked(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (bp *BufferPool) flushSingleExtentBatchUnlocked(chunk []*PageDesc) error {
	orders := make([]int, len(chunk))
	pageLSNs := make([]uint64, len(chunk))
	var maxLSN uint64

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
	}

	// Allocate contiguous extent from buddy allocator
	locs, err := bp.buddy.AllocateBatch(orders)
	if err != nil {
		return fmt.Errorf("failed to allocate contiguous disk blocks for batch of %d pages: %w", len(chunk), err)
	}

	// Mark all pages in chunk as InFlight and pin them
	for _, desc := range chunk {
		desc.InFlight = true
		desc.PinCount.Add(1)
	}

	// Prepare iov buffers under per-page latch desc.Mu
	var allIOV [][]byte
	for i, desc := range chunk {
		desc.Mu.Lock()
		for j, fID := range desc.FrameIDs {
			start := fID * BlockSize
			blk := bp.arena[start : start+BlockSize]
			hdr := BlockHeader{
				LogicalPage: desc.LogicalPage,
				LSN:         pageLSNs[i],
				BlockIndex:  uint32(j),
				NumBlocks:   uint32(desc.NumBlocks),
			}
			EncodeBlockHeader(hdr, blk)
			FinalizeBlockCRC(blk)

			buf := AllocateAlignedBlock(BlockSize)
			copy(buf, blk)
			allIOV = append(allIOV, buf)
		}
		desc.Mu.Unlock()
	}

	// Release pool mutex during I/O
	bp.mu.Unlock()

	// Sync WAL once per batch through maxLSN
	var syncErr error
	if bp.wal != nil && maxLSN > 0 {
		syncErr = bp.wal.SyncThrough(maxLSN)
	}

	// Vectored write for the entire contiguous extent
	var writeErr error
	if syncErr == nil {
		startBlock := locs[0]
		writeErr = bp.directIO.Writev(bp.file, int64(startBlock*BlockSize), allIOV)
	}

	// Re-acquire pool mutex
	bp.mu.Lock()

	for _, desc := range chunk {
		desc.InFlight = false
		desc.PinCount.Add(-1)
	}

	flushErr := errors.Join(syncErr, writeErr)
	if flushErr != nil {
		// Reclaim allocated blocks on failure
		var freeErrs []error
		for _, loc := range locs {
			if fErr := bp.buddy.Free(loc); fErr != nil {
				freeErrs = append(freeErrs, fErr)
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

// FlushAllDirty flushes all dirty pages currently in the buffer pool.
func (bp *BufferPool) FlushAllDirty() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	var toFlush []*PageDesc
	for _, desc := range bp.pageTable {
		if desc.Dirty && len(desc.FrameIDs) > 0 && !desc.InFlight {
			toFlush = append(toFlush, desc)
		}
	}

	return bp.flushBatchUnlocked(toFlush)
}

// SnapshotFlushedForSync records all currently flushed locations before a heap fsync starts.
// This fulfills the Reuse Rule: only locations written before the fsync began may be promoted to durable.
func (bp *BufferPool) SnapshotFlushedForSync() {
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
func (bp *BufferPool) PromoteFlushedToDurable() error {
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
func (bp *BufferPool) DirtyPageTableAndLSN() (map[uint64]uint64, uint64) {
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
func (bp *BufferPool) Close() error {
	close(bp.bgStop)
	<-bp.bgDone

	return bp.FlushAllDirty()
}
