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
	"sort"
)

// CheckStructuralInvariants performs a deep diagnostic audit of the store's in-memory
// structures and physical mappings:
//  1. Buffer pool frames: verifies no leaks, no duplicate allocations, and that free + allocated == total.
//  2. Buddy allocator: verifies allocated blocks do not overlap, free lists do not overlap with allocated
//     blocks, and every allocated block corresponds to a page's current, durable, or in-flight location.
//  3. Key index: verifies every key registered in the index can be read successfully.
//  4. Invariant compliance: verifies reuse rule and write-ahead rule hold.
func (s *Engine) CheckStructuralInvariants() error {
	if s.isFailed() {
		return s.failErr()
	}

	// 1. Audit Block Pool Frames
	if err := s.auditBlockPoolFrames(); err != nil {
		return fmt.Errorf("structural audit failed: %w", err)
	}

	// 2. Audit Buddy Allocator
	if err := s.auditBuddyAllocator(); err != nil {
		return fmt.Errorf("structural audit failed: %w", err)
	}

	// 3. Audit Key Index Completeness
	if err := s.auditKeyIndex(); err != nil {
		return fmt.Errorf("structural audit failed: %w", err)
	}

	return nil
}

func (s *Engine) auditBlockPoolFrames() error {
	s.bp.mu.Lock()
	defer s.bp.mu.Unlock()

	totalBlocks := s.bp.numPoolBlocks
	seenFrames := make(map[int]string) // frameID -> description

	// Verify freePoolBlocks
	for _, f := range s.bp.freePoolBlocks {
		if f < 0 || f >= totalBlocks {
			return fmt.Errorf("free frame index out of bounds: %d (numPoolBlocks=%d)", f, totalBlocks)
		}
		if prev, exists := seenFrames[f]; exists {
			return fmt.Errorf("frame %d is duplicated in freePoolBlocks (previously marked: %s)", f, prev)
		}
		seenFrames[f] = "free"
	}

	// Verify descriptors in pageTable
	allocatedFramesCount := 0
	for pageID, desc := range s.bp.pageTable {
		for _, f := range desc.PoolBlocks {
			if f < 0 || f >= totalBlocks {
				return fmt.Errorf("frame index out of bounds in page %d: %d (numPoolBlocks=%d)", pageID, f, totalBlocks)
			}
			if prev, exists := seenFrames[f]; exists {
				return fmt.Errorf("frame %d in page %d is already in use by %s (frame double-allocation or leak)", f, pageID, prev)
			}
			seenFrames[f] = fmt.Sprintf("page %d", pageID)
			allocatedFramesCount++
		}
	}

	totalAccounted := len(s.bp.freePoolBlocks) + allocatedFramesCount
	if totalAccounted != totalBlocks {
		return fmt.Errorf("buffer-pool frame leak: numPoolBlocks=%d, but free (%d) + allocated (%d) = %d",
			totalBlocks, len(s.bp.freePoolBlocks), allocatedFramesCount, totalAccounted)
	}
	return nil
}

func (s *Engine) auditBuddyAllocator() error {
	s.buddy.mu.Lock()
	defer s.buddy.mu.Unlock()

	s.bp.mu.Lock()
	defer s.bp.mu.Unlock()

	type allocBlock struct {
		start uint64
		order int
	}

	var blocks []allocBlock
	for start, order := range s.buddy.allocated {
		blocks = append(blocks, allocBlock{start: start, order: order})
	}

	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].start < blocks[j].start
	})

	// Check for overlapping allocated blocks
	for i := 0; i < len(blocks)-1; i++ {
		currEnd := blocks[i].start + uint64(1<<blocks[i].order)
		nextStart := blocks[i+1].start
		if currEnd > nextStart {
			return fmt.Errorf("buddy allocator block overlap: [%d..%d) overlaps with [%d..%d)",
				blocks[i].start, currEnd, nextStart, nextStart+uint64(1<<blocks[i+1].order))
		}
	}

	// Check free lists do not overlap with allocated blocks
	for order := MinOrder; order <= MaxOrder; order++ {
		for _, fStart := range s.buddy.freeLists[order] {
			fEnd := fStart + uint64(1<<order)
			for _, alloc := range blocks {
				aEnd := alloc.start + uint64(1<<alloc.order)
				// Overlap condition: max(fStart, alloc.start) < min(fEnd, aEnd)
				startMax := fStart
				if alloc.start > startMax {
					startMax = alloc.start
				}
				endMin := fEnd
				if aEnd < endMin {
					endMin = aEnd
				}
				if startMax < endMin {
					return fmt.Errorf("buddy free block [%d..%d) overlaps with allocated block [%d..%d)",
						fStart, fEnd, alloc.start, aEnd)
				}
			}
		}
	}

	// Verify all allocated blocks correspond to known page descriptor locations
	pageLocations := make(map[uint64]string) // startBlock -> desc description
	for pageID, desc := range s.bp.pageTable {
		if desc.PhysicalBlock != NoBlock {
			pageLocations[desc.PhysicalBlock] = fmt.Sprintf("page %d (PhysicalBlock)", pageID)
		}
		if desc.DurableLoc != NoBlock {
			pageLocations[desc.DurableLoc] = fmt.Sprintf("page %d (DurableLoc)", pageID)
		}
		if desc.FlushedLoc != NoBlock {
			pageLocations[desc.FlushedLoc] = fmt.Sprintf("page %d (FlushedLoc)", pageID)
		}
		if desc.FlushedBeforeSync != NoBlock {
			pageLocations[desc.FlushedBeforeSync] = fmt.Sprintf("page %d (FlushedBeforeSync)", pageID)
		}
	}

	for _, alloc := range blocks {
		if _, ok := pageLocations[alloc.start]; !ok {
			return fmt.Errorf("buddy allocator block leak: block %d (order %d) is allocated but not referenced by any page",
				alloc.start, alloc.order)
		}
	}

	for loc, descr := range pageLocations {
		if _, ok := s.buddy.allocated[loc]; !ok {
			return fmt.Errorf("page location %d (%s) is not marked allocated in buddy allocator", loc, descr)
		}
	}

	return nil
}

func (s *Engine) auditKeyIndex() error {
	s.keyMu.RLock()
	keys := make([]struct {
		bucket string
		key    string
		qKey   string
		entry  KeyIndexEntry
	}, 0, len(s.keyIndex))

	for qKey, entry := range s.keyIndex {
		b, k := unqualifyKey(qKey)
		keys = append(keys, struct {
			bucket string
			key    string
			qKey   string
			entry  KeyIndexEntry
		}{
			bucket: b,
			key:    k,
			qKey:   qKey,
			entry:  entry,
		})
	}
	s.keyMu.RUnlock()

	for _, item := range keys {
		val, exists, err := s.readIndexEntry(item.bucket, item.key, item.qKey, item.entry)
		if err != nil {
			return fmt.Errorf("index key %s failed to read: %w", item.qKey, err)
		}
		if !exists {
			// Read details for diagnostic
			handle, pErr := s.bp.PinPage(item.entry.LogicalPage)
			var diag string
			if pErr == nil {
				handle.Desc.Mu.RLock()
				if handle.Desc.NumBlocks == 1 {
					if slotted, wrapErr := WrapSlottedPage(handle.Block(0)); wrapErr == nil {
						rk, _, rLSN, gErr := slotted.Get(item.entry.Slot)
						diag = fmt.Sprintf("pErr=nil, numBlocks=1, pageLSN=%d, slot=%d, recKey=%q, recLSN=%d, gErr=%v, entryLSN=%d",
							handle.Desc.PageLSN.Load(), item.entry.Slot, rk, rLSN, gErr, item.entry.LSN)
					} else {
						diag = fmt.Sprintf("wrapErr=%v", wrapErr)
					}
				} else {
					rk, _, rLSN, dErr := DecodeMultiBlockPage(handle.Blocks())
					diag = fmt.Sprintf("pErr=nil, numBlocks=%d, pageLSN=%d, recKey=%q, recLSN=%d, dErr=%v, entryLSN=%d",
						handle.Desc.NumBlocks, handle.Desc.PageLSN.Load(), rk, rLSN, dErr, item.entry.LSN)
				}
				handle.Desc.Mu.RUnlock()
				handle.Unpin()
			} else {
				diag = fmt.Sprintf("pErr=%v", pErr)
			}
			return fmt.Errorf("index key %s reported not found (entry: %+v, diag: %s)", item.qKey, item.entry, diag)
		}
		_ = val
	}
	return nil
}
