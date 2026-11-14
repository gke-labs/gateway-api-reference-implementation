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
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// KeyIndexEntry maps an object key to its location in a logical page.
type KeyIndexEntry struct {
	LogicalPage      uint64
	Slot             uint32
	LSN              uint64
	NumBlocks        int
	IsOversize       bool
	OversizeFileName string
}

// RecoveryResult contains the state reconstructed after a crash scan and log replay.
type RecoveryResult struct {
	DBID              [16]byte
	PageDescs         map[uint64]*PageDesc
	Buddy             *BuddyAllocator
	KeyIndex          map[string]KeyIndexEntry
	EmptyLogicalPages []uint64
	MaxLSN            uint64
	NextLogicalPage   uint64
}

type candidatePageCopy struct {
	logicalPage uint64
	lsn         uint64
	startBlock  uint64
	numBlocks   int
}

type chunkBlockReader struct {
	file       File
	totalSize  int64
	chunkSize  int64
	chunkBuf   []byte
	chunkStart int64
	chunkLen   int64
}

func newChunkBlockReader(file File, totalSize int64) *chunkBlockReader {
	chunkSize := int64(256 * 1024) // 256 KiB chunk = 64 blocks
	if chunkSize > totalSize {
		chunkSize = totalSize
	}
	return &chunkBlockReader{
		file:       file,
		totalSize:  totalSize,
		chunkSize:  chunkSize,
		chunkBuf:   make([]byte, chunkSize),
		chunkStart: -1,
	}
}

func (r *chunkBlockReader) ReadBlock(b uint64) ([]byte, error) {
	off := int64(b * BlockSize)
	if off+BlockSize > r.totalSize {
		return nil, io.EOF
	}

	if r.chunkStart >= 0 && off >= r.chunkStart && off+BlockSize <= r.chunkStart+r.chunkLen {
		localOff := off - r.chunkStart
		return r.chunkBuf[localOff : localOff+BlockSize], nil
	}

	// Fetch new chunk
	r.chunkStart = off
	toRead := r.chunkSize
	if r.chunkStart+toRead > r.totalSize {
		toRead = r.totalSize - r.chunkStart
	}

	n, err := r.file.ReadAt(r.chunkBuf[:toRead], r.chunkStart)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	r.chunkLen = int64(n)
	if r.chunkLen < BlockSize {
		return nil, io.EOF
	}

	return r.chunkBuf[0:BlockSize], nil
}

// RecoveryOptions configures crash recovery.
type RecoveryOptions struct {
	// Quarantine configures quarantine bounding and retention for lost+found directories.
	Quarantine QuarantineOptions
}

// Recover scans the heap file, filters out foreign and torn copies, replays the WAL from
// the last checkpoint's redo start, rebuilds the in-memory indexes and allocator state,
// and quarantines unreferenced oversize files.
func Recover(fs FS, heapFile File, storeDir string, walDir string, dbID [16]byte, options RecoveryOptions) (*RecoveryResult, error) {
	// Item 10: Fsync every existing WAL segment and walDir before trusting them
	entries, err := fs.ReadDir(walDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".wal") {
				segPath := filepath.Join(walDir, entry.Name())
				f, openErr := fs.Open(segPath)
				if openErr != nil {
					return nil, fmt.Errorf("failed to open WAL segment %s for fsync: %w", entry.Name(), openErr)
				}
				syncErr := f.Sync()
				closeErr := f.Close()
				if err := errors.Join(syncErr, closeErr); err != nil {
					return nil, fmt.Errorf("failed to fsync WAL segment %s: %w", entry.Name(), err)
				}
			}
		}
		if err := fs.SyncDir(walDir); err != nil {
			return nil, fmt.Errorf("failed to fsync WAL directory: %w", err)
		}
	}

	// Fsync heap file before recovery
	if err := heapFile.Sync(); err != nil {
		return nil, fmt.Errorf("failed to fsync heap file before recovery: %w", err)
	}

	size, err := heapFile.Size()
	if err != nil {
		return nil, fmt.Errorf("failed to get heap file size: %w", err)
	}

	totalBlocks := uint64(size / BlockSize)
	if totalBlocks < 512 {
		totalBlocks = 512
	}
	buddy := NewBuddyAllocator(totalBlocks)
	reader := newChunkBlockReader(heapFile, size)

	// Step 1: Scan physical blocks in heap file sequentially to find valid candidate page copies
	bestCandidates := make(map[uint64]candidatePageCopy) // logicalPage -> candidatePageCopy

	b := uint64(0)
	for b < uint64(size/BlockSize) {
		blockBuf, err := reader.ReadBlock(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read error reading block %d: %w", b, err)
		}

		hdr, err := DecodeBlockHeader(blockBuf)
		if err != nil {
			// Check if real error vs normal corrupt/non-block bytes
			if !errors.Is(err, ErrInvalidBlockMagic) && !errors.Is(err, ErrInvalidBlockVersion) && !errors.Is(err, ErrBlockCRCMismatch) {
				return nil, fmt.Errorf("corrupt block decode error at block %d: %w", b, err)
			}
			b++
			continue
		}

		if hdr.BlockIndex != 0 || hdr.NumBlocks == 0 {
			b++
			continue
		}

		numBlocks := int(hdr.NumBlocks)
		if b%uint64(numBlocks) != 0 || b+uint64(numBlocks) > uint64(size/BlockSize) {
			b++
			continue
		}

		// Verify candidate page run
		valid := true
		for k := 0; k < numBlocks; k++ {
			kbBuf, err := reader.ReadBlock(b + uint64(k))
			if err != nil {
				if errors.Is(err, io.EOF) {
					valid = false
					break
				}
				return nil, fmt.Errorf("read error reading block %d: %w", b+uint64(k), err)
			}

			kHdr, err := DecodeBlockHeader(kbBuf)
			if err != nil || kHdr.LogicalPage != hdr.LogicalPage || kHdr.LSN != hdr.LSN ||
				kHdr.BlockIndex != uint32(k) || kHdr.NumBlocks != hdr.NumBlocks {
				valid = false
				break
			}
		}

		if valid {
			cand := candidatePageCopy{
				logicalPage: hdr.LogicalPage,
				lsn:         hdr.LSN,
				startBlock:  b,
				numBlocks:   numBlocks,
			}
			existing, exists := bestCandidates[hdr.LogicalPage]
			if !exists || cand.lsn > existing.lsn {
				bestCandidates[hdr.LogicalPage] = cand
			}
			b += uint64(numBlocks)
		} else {
			b++
		}
	}

	// Step 2: Mark blocks of winning candidates as allocated in the buddy allocator
	pageDescs := make(map[uint64]*PageDesc)
	var maxRecoveredLogicalPage uint64
	var maxHeapLSN uint64

	for logicalPage, cand := range bestCandidates {
		if cand.lsn > maxHeapLSN {
			maxHeapLSN = cand.lsn
		}
		order := 0
		for (1 << order) < cand.numBlocks {
			order++
		}
		if err := buddy.MarkAllocated(cand.startBlock, order); err != nil {
			return nil, fmt.Errorf("failed to mark block %d allocated during recovery: %w", cand.startBlock, err)
		}

		desc := &PageDesc{
			LogicalPage:       logicalPage,
			NumBlocks:         cand.numBlocks,
			PhysicalBlock:     cand.startBlock,
			FlushedLoc:        NoBlock,
			FlushedBeforeSync: NoBlock,
			DurableLoc:        cand.startBlock,
		}
		desc.PageLSN.Store(cand.lsn)
		pageDescs[logicalPage] = desc

		if logicalPage > maxRecoveredLogicalPage {
			maxRecoveredLogicalPage = logicalPage
		}
	}

	// Step 3: Scan recovered pages to rebuild key index and empty page list
	// Item 4: Always keep the copy with the highest LSN when a key appears multiple times.
	// Sort winning candidates by physical block so chunkBlockReader scans disk sequentially.
	keyIndex := make(map[string]KeyIndexEntry)
	var emptyPages []uint64

	var sortedCandidates []candidatePageCopy
	for _, cand := range bestCandidates {
		sortedCandidates = append(sortedCandidates, cand)
	}
	sort.Slice(sortedCandidates, func(i, j int) bool {
		return sortedCandidates[i].startBlock < sortedCandidates[j].startBlock
	})

	for _, cand := range sortedCandidates {
		logicalPage := cand.logicalPage
		blocks := make([][]byte, cand.numBlocks)
		for i := 0; i < cand.numBlocks; i++ {
			bBytes, err := reader.ReadBlock(cand.startBlock + uint64(i))
			if err != nil {
				return nil, fmt.Errorf("failed to read block %d for page %d: %w", cand.startBlock+uint64(i), logicalPage, err)
			}
			blocks[i] = make([]byte, BlockSize)
			copy(blocks[i], bBytes)
		}

		if cand.numBlocks == 1 {
			slotted, err := WrapSlottedPage(blocks[0])
			if err != nil {
				return nil, fmt.Errorf("failed to wrap recovered slotted page %d: %w", logicalPage, err)
			}
			if slotted.ActiveSlotsCount() == 0 {
				emptyPages = append(emptyPages, logicalPage)
			} else {
				for s := uint32(0); s < uint32(slotted.NumSlots()); s++ {
					k, val, recLSN, isOversize, err := slotted.GetWithFlag(s)
					if err != nil {
						if errors.Is(err, ErrSlotNotFound) {
							continue
						}
						return nil, fmt.Errorf("failed to get slot %d from page %d: %w", s, logicalPage, err)
					}
					existing, exists := keyIndex[k]
					if !exists || recLSN > existing.LSN {
						entry := KeyIndexEntry{
							LogicalPage: logicalPage,
							Slot:        s,
							LSN:         recLSN,
							NumBlocks:   1,
							IsOversize:  isOversize,
						}
						if isOversize {
							_, _, fileName, decodeErr := DecodeOversizePointer(val)
							if decodeErr != nil {
								return nil, fmt.Errorf("failed to decode oversize pointer in page %d slot %d: %w", logicalPage, s, decodeErr)
							}
							entry.OversizeFileName = fileName
						}
						keyIndex[k] = entry
					}
				}
			}
		} else {
			k, _, recLSN, err := DecodeMultiBlockPage(blocks)
			if err != nil {
				return nil, fmt.Errorf("failed to decode recovered multi-block page %d: %w", logicalPage, err)
			}
			if k != "" { // Active record (not tombstone)
				existing, exists := keyIndex[k]
				if !exists || recLSN > existing.LSN {
					keyIndex[k] = KeyIndexEntry{
						LogicalPage: logicalPage,
						Slot:        0,
						LSN:         recLSN,
						NumBlocks:   cand.numBlocks,
					}
				}
			} else {
				emptyPages = append(emptyPages, logicalPage)
			}
		}
	}

	// Step 4: Scan WAL to find the last checkpoint's redo start LSN
	var redoStartLSN uint64 = 1
	var maxWAL_LSN uint64

	walScanIt, err := NewWALIterator(fs, walDir, dbID, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAL scan iterator: %w", err)
	}
	for {
		rec, err := walScanIt.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error during WAL scan: %w", err)
		}
		if rec.LSN > maxWAL_LSN {
			maxWAL_LSN = rec.LSN
		}
		if rec.Type == RecordTypeCheckpoint && rec.RedoStartLSN > 0 {
			redoStartLSN = rec.RedoStartLSN
		}
	}
	if closeErr := walScanIt.Close(); closeErr != nil {
		return nil, fmt.Errorf("failed to close WAL scan iterator: %w", closeErr)
	}

	// Under the write-ahead rule, a heap page with LSN L can only be on disk
	// if the WAL was fsynced through L. If WAL replay ends below the highest
	// page LSN found in the heap, records that the engine acknowledged are
	// missing, which indicates provable corruption rather than an unacknowledged torn tail.
	if maxWAL_LSN < maxHeapLSN {
		return nil, fmt.Errorf("%w: WAL replay ended at LSN %d below highest heap page LSN %d", ErrCorruptWAL, maxWAL_LSN, maxHeapLSN)
	}

	// Step 5: Full Redo Replay from redoStartLSN (Item 3)
	// For any Put/Delete newer than the page on disk, physically apply the mutation to page buffers.
	redoPages := make(map[uint64][]byte)       // logicalPage -> 4096-byte buffer
	redoMBPages := make(map[uint64][][]byte)   // logicalPage -> slice of 4096-byte buffers
	dirtyLogicalPages := make(map[uint64]bool) // logical pages modified during redo

	emptyTracker := newEmptyPageTracker(emptyPages)

	deleteSlotForRedo := func(pageID uint64, slot uint32, lsn uint64) error {
		desc, inPages := pageDescs[pageID]
		if inPages && desc != nil && desc.PageLSN.Load() >= lsn {
			return nil
		}
		var pageBuf []byte
		if buf, ok := redoPages[pageID]; ok {
			pageBuf = buf
		} else if inPages && desc != nil && desc.PhysicalBlock != NoBlock {
			pageBuf = AllocateAlignedBlock(BlockSize)
			if _, err := heapFile.ReadAt(pageBuf, int64(desc.PhysicalBlock*BlockSize)); err != nil {
				return fmt.Errorf("failed to read page %d for slot delete redo: %w", pageID, err)
			}
		} else {
			return nil
		}
		if len(pageBuf) == BlockSize {
			slotted, wrapErr := WrapSlottedPage(pageBuf)
			if wrapErr != nil {
				return fmt.Errorf("failed to wrap page %d for slot delete redo: %w", pageID, wrapErr)
			}
			delErr := slotted.Delete(slot, lsn)
			if delErr != nil && !errors.Is(delErr, ErrSlotNotFound) {
				return fmt.Errorf("failed to delete slot %d for redo: %w", slot, delErr)
			}
			slotted.Finalize()
			redoPages[pageID] = pageBuf
			delete(redoMBPages, pageID)
			dirtyLogicalPages[pageID] = true
			if inPages && desc != nil {
				desc.PageLSN.Store(lsn)
			}
			if delErr == nil && slotted.ActiveSlotsCount() == 0 {
				emptyTracker.Add(pageID)
			}
		}
		return nil
	}

	clearMultiBlockPageForRedo := func(pageID uint64, lsn uint64) error {
		desc, inPages := pageDescs[pageID]
		if inPages && desc != nil && desc.PageLSN.Load() >= lsn {
			return nil
		}
		tombstone := AllocateAlignedBlock(BlockSize)
		hdr := BlockHeader{LogicalPage: pageID, LSN: lsn, NumBlocks: 1}
		EncodeBlockHeader(hdr, tombstone)
		FinalizeBlockCRC(tombstone)
		redoPages[pageID] = tombstone
		delete(redoMBPages, pageID)
		dirtyLogicalPages[pageID] = true
		if inPages && desc != nil {
			desc.PageLSN.Store(lsn)
			desc.NumBlocks = 1
		}
		emptyTracker.Add(pageID)
		return nil
	}

	cleanOldLocationForRedo := func(entry KeyIndexEntry, qKey string, lsn uint64) error {
		if entry.NumBlocks == 1 {
			return deleteSlotForRedo(entry.LogicalPage, entry.Slot, lsn)
		}
		return clearMultiBlockPageForRedo(entry.LogicalPage, lsn)
	}

	walRedoIt, err := NewWALIterator(fs, walDir, dbID, redoStartLSN)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAL redo iterator: %w", err)
	}
	for {
		rec, err := walRedoIt.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error during WAL redo: %w", err)
		}
		if rec.LSN > maxWAL_LSN {
			maxWAL_LSN = rec.LSN
		}

		// Apply Put or PutPointer
		if rec.Type == RecordTypePut || rec.Type == RecordTypePutPointer {
			existing, inIndex := keyIndex[rec.Key]
			if inIndex {
				desc, inPages := pageDescs[existing.LogicalPage]
				if inPages && desc != nil && desc.PageLSN.Load() >= rec.LSN {
					continue // Target page already reflects this or newer write
				}
			}

			isPointer := rec.Type == RecordTypePutPointer
			var oversizeFileName string
			if isPointer {
				_, _, fName, decodeErr := DecodeOversizePointer(rec.Payload)
				if decodeErr != nil {
					return nil, fmt.Errorf("%w: failed to decode oversize pointer: %v", ErrCorruptStore, decodeErr)
				}
				oversizeFileName = fName
			}

			// Apply mutation to page buffer
			if CanFitInSlottedPage(len(rec.Key), len(rec.Payload)) {
				// 1-block slotted page
				var targetPage uint64
				if inIndex && pageDescs[existing.LogicalPage] != nil && pageDescs[existing.LogicalPage].NumBlocks == 1 {
					targetPage = existing.LogicalPage
				} else if p, ok := emptyTracker.Pop(); ok {
					targetPage = p
				} else {
					maxRecoveredLogicalPage++
					targetPage = maxRecoveredLogicalPage
				}

				var pageBuf []byte
				if buf, ok := redoPages[targetPage]; ok {
					pageBuf = buf
				} else if desc, ok := pageDescs[targetPage]; ok && desc.PhysicalBlock != NoBlock {
					pageBuf = AllocateAlignedBlock(BlockSize)
					if _, err := heapFile.ReadAt(pageBuf, int64(desc.PhysicalBlock*BlockSize)); err != nil {
						return nil, fmt.Errorf("failed to read page %d for redo: %w", targetPage, err)
					}
				} else {
					pageBuf = AllocateAlignedBlock(BlockSize)
					hdr := BlockHeader{
						LogicalPage: targetPage,
						LSN:         rec.LSN,
						NumBlocks:   1,
					}
					EncodeBlockHeader(hdr, pageBuf)
				}

				slotted, wrapErr := WrapSlottedPage(pageBuf)
				if wrapErr != nil {
					return nil, fmt.Errorf("failed to wrap page for redo: %w", wrapErr)
				}
				if inIndex && targetPage == existing.LogicalPage && existing.NumBlocks == 1 {
					if delErr := slotted.Delete(existing.Slot, rec.LSN); delErr != nil && !errors.Is(delErr, ErrSlotNotFound) {
						return nil, fmt.Errorf("failed to delete slot for redo: %w", delErr)
					}
				}
				slotIdx, err := slotted.PutWithFlag(rec.Key, rec.Payload, rec.LSN, isPointer)
				if err != nil {
					// Page full during redo: if old record was on targetPage, finalize old page
					if inIndex && targetPage == existing.LogicalPage && existing.NumBlocks == 1 {
						slotted.Finalize()
						redoPages[targetPage] = pageBuf
						delete(redoMBPages, targetPage)
						dirtyLogicalPages[targetPage] = true
						if desc, ok := pageDescs[targetPage]; ok && desc != nil {
							desc.PageLSN.Store(rec.LSN)
						}
						if slotted.ActiveSlotsCount() == 0 {
							emptyTracker.Add(targetPage)
						}
					}

					// Allocate next page
					var ok bool
					if targetPage, ok = emptyTracker.Pop(); !ok {
						maxRecoveredLogicalPage++
						targetPage = maxRecoveredLogicalPage
					}
					pageBuf = AllocateAlignedBlock(BlockSize)
					hdr := BlockHeader{LogicalPage: targetPage, LSN: rec.LSN, NumBlocks: 1}
					EncodeBlockHeader(hdr, pageBuf)
					slotted, wrapErr = WrapSlottedPage(pageBuf)
					if wrapErr != nil {
						return nil, fmt.Errorf("failed to wrap new page for redo: %w", wrapErr)
					}
					slotIdx, err = slotted.PutWithFlag(rec.Key, rec.Payload, rec.LSN, isPointer)
					if err != nil {
						return nil, fmt.Errorf("failed to put record into new page during redo: %w", err)
					}
				}
				slotted.Finalize()

				redoPages[targetPage] = pageBuf
				delete(redoMBPages, targetPage)
				dirtyLogicalPages[targetPage] = true

				if inIndex && (targetPage != existing.LogicalPage || existing.NumBlocks > 1) {
					if err := cleanOldLocationForRedo(existing, rec.Key, rec.LSN); err != nil {
						return nil, err
					}
				}

				keyIndex[rec.Key] = KeyIndexEntry{
					LogicalPage:      targetPage,
					Slot:             slotIdx,
					LSN:              rec.LSN,
					NumBlocks:        1,
					IsOversize:       isPointer,
					OversizeFileName: oversizeFileName,
				}
				if desc, ok := pageDescs[targetPage]; ok {
					desc.PageLSN.Store(rec.LSN)
					desc.NumBlocks = 1
				} else {
					d := &PageDesc{
						LogicalPage:       targetPage,
						NumBlocks:         1,
						PhysicalBlock:     NoBlock,
						FlushedLoc:        NoBlock,
						FlushedBeforeSync: NoBlock,
						DurableLoc:        NoBlock,
					}
					d.PageLSN.Store(rec.LSN)
					pageDescs[targetPage] = d
				}
			} else {
				// Multi-block page
				if inIndex && !existing.IsOversize {
					if err := cleanOldLocationForRedo(existing, rec.Key, rec.LSN); err != nil {
						return nil, err
					}
				}

				var targetPage uint64
				var ok bool
				if targetPage, ok = emptyTracker.Pop(); !ok {
					maxRecoveredLogicalPage++
					targetPage = maxRecoveredLogicalPage
				}

				mb, err := NewMultiBlockPage(targetPage, rec.LSN, rec.Key, rec.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to build multi-block page for redo: %w", err)
				}
				for _, b := range mb.Blocks {
					FinalizeBlockCRC(b)
				}
				redoMBPages[targetPage] = mb.Blocks
				delete(redoPages, targetPage)
				dirtyLogicalPages[targetPage] = true

				keyIndex[rec.Key] = KeyIndexEntry{
					LogicalPage: targetPage,
					Slot:        0,
					LSN:         rec.LSN,
					NumBlocks:   len(mb.Blocks),
				}
				if desc, ok := pageDescs[targetPage]; ok {
					desc.PageLSN.Store(rec.LSN)
					desc.NumBlocks = len(mb.Blocks)
				} else {
					d := &PageDesc{
						LogicalPage:       targetPage,
						NumBlocks:         len(mb.Blocks),
						PhysicalBlock:     NoBlock,
						FlushedLoc:        NoBlock,
						FlushedBeforeSync: NoBlock,
						DurableLoc:        NoBlock,
					}
					d.PageLSN.Store(rec.LSN)
					pageDescs[targetPage] = d
				}
			}
		}

		// Apply Delete
		if rec.Type == RecordTypeDelete {
			existing, inIndex := keyIndex[rec.Key]
			if inIndex {
				if err := cleanOldLocationForRedo(existing, rec.Key, rec.LSN); err != nil {
					return nil, err
				}
				delete(keyIndex, rec.Key)
			}
		}
	}
	if closeErr := walRedoIt.Close(); closeErr != nil {
		return nil, fmt.Errorf("failed to close WAL redo iterator: %w", closeErr)
	}

	// Step 6: Flush any pages modified by redo replay to heapFile and fsync
	var supersededLocs []uint64
	for pID := range dirtyLogicalPages {
		desc := pageDescs[pID]
		oldLoc := desc.PhysicalBlock
		order := 0
		for (1 << order) < desc.NumBlocks {
			order++
		}
		newLoc, err := buddy.Allocate(order)
		if err != nil {
			return nil, fmt.Errorf("failed to allocate heap block for redone page %d: %w", pID, err)
		}
		if oldLoc != NoBlock {
			supersededLocs = append(supersededLocs, oldLoc)
		}
		desc.PhysicalBlock = newLoc
		desc.DurableLoc = newLoc
		desc.FlushedLoc = NoBlock

		if desc.NumBlocks == 1 {
			buf := redoPages[pID]
			if _, err := heapFile.WriteAt(buf, int64(newLoc*BlockSize)); err != nil {
				return nil, fmt.Errorf("failed to write redone page %d to heap: %w", pID, err)
			}
		} else {
			blocks := redoMBPages[pID]
			for i, b := range blocks {
				if _, err := heapFile.WriteAt(b, int64((newLoc+uint64(i))*BlockSize)); err != nil {
					return nil, fmt.Errorf("failed to write redone block %d of page %d: %w", i, pID, err)
				}
			}
		}
	}

	if len(dirtyLogicalPages) > 0 {
		if err := heapFile.Sync(); err != nil {
			return nil, fmt.Errorf("failed to sync heap file after redo: %w", err)
		}
		// Defer freeing superseded blocks until after heapFile.Sync succeeds (reuse rule).
		// Until the sync, the superseded block holds the only durable copy of the page.
		for _, loc := range supersededLocs {
			if err := buddy.Free(loc); err != nil {
				return nil, fmt.Errorf("failed to free superseded block %d during redo: %w", loc, err)
			}
		}
	}

	// Step 7: Recovery quarantines every file in oversize/ that no recovered pointer names
	// to lost+found.
	// The key index at this point holds every durable pointer, from heap pages and from
	// WAL redo, and the engine accepts no writes until Open returns, so no file here
	// can belong to a write in progress. The pass moves any unreferenced file in the
	// directory, whatever its name, to lost+found (bounded by QuarantineOptions) and leaves
	// subdirectories.
	//
	// If quarantining an unreferenced file, pruning lost+found, or syncing the directories
	// fails, recovery aborts and Open fails. Failing fast prevents operating on an unhealthy
	// filesystem that cannot quarantine obsolete data or make directory updates durable.
	getReferenced := func() map[string]bool {
		referenced := make(map[string]bool)
		for _, entry := range keyIndex {
			if entry.IsOversize && entry.OversizeFileName != "" {
				referenced[entry.OversizeFileName] = true
			}
		}
		return referenced
	}
	if _, err := quarantineUnreferencedOversizeFiles(context.Background(), fs, storeDir, getReferenced, options.Quarantine, 0); err != nil {
		return nil, fmt.Errorf("failed to quarantine unreferenced oversize files: %w", err)
	}

	return &RecoveryResult{
		DBID:              dbID,
		PageDescs:         pageDescs,
		Buddy:             buddy,
		KeyIndex:          keyIndex,
		EmptyLogicalPages: emptyTracker.Pages(),
		MaxLSN:            maxWAL_LSN,
		NextLogicalPage:   maxRecoveredLogicalPage + 1,
	}, nil
}
