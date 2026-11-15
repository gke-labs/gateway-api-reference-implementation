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
	"io"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/xts"
)

// ErrDamagedBlock is returned by Open after a clean close when a written block fails its check.
var ErrDamagedBlock = errors.New("damaged heap block")

// isZeroBlock reports whether every byte in blockBuffer is zero, identifying never-written
// blocks without treating them as torn or damaged.
func isZeroBlock(blockBuffer []byte) bool {
	for _, byteValue := range blockBuffer {
		if byteValue != 0 {
			return false
		}
	}
	return true
}

// KeyIndexEntry maps an object key to its location in a logical page.
type KeyIndexEntry struct {
	LogicalPage      uint64
	Slot             uint32
	LSN              uint64
	NumBlocks        int
	IsOversize       bool
	OversizeFileName string
}

// RecoveryResult contains the state reconstructed after a crash scan.
type RecoveryResult struct {
	DBID              [16]byte
	PageDescs         map[uint64]*PageDesc
	Buddy             *BuddyAllocator
	KeyIndex          map[string]KeyIndexEntry
	EmptyLogicalPages []uint64
	// SupersededPages maps a qualified key to older page copies discovered on disk
	// where that key appeared on more than one page. replayWAL consumes it to clear
	// each older page at the first record whose LSN is above the older page's LSN.
	SupersededPages map[string][]KeyIndexEntry
	MaxLSN          uint64
	NextLogicalPage uint64
	RedoStartLSN    uint64
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
	// heapCipher is the AES-256-XTS cipher used for heap block decryption during recovery.
	// A nil cipher means the store is not encrypted.
	heapCipher *xts.Cipher
}

func newChunkBlockReader(file File, totalSize int64, heapCipher *xts.Cipher) *chunkBlockReader {
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
		heapCipher: heapCipher,
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

	if r.heapCipher != nil {
		chunkStartBlock := uint64(r.chunkStart / BlockSize)
		numBlocksInChunk := int(r.chunkLen / BlockSize)
		for i := 0; i < numBlocksInChunk; i++ {
			blockData := r.chunkBuf[i*BlockSize : (i+1)*BlockSize]
			if isZeroBlock(blockData) {
				continue
			}
			decryptHeapBlock(blockData, blockData, chunkStartBlock+uint64(i), r.heapCipher)
		}
	}

	return r.chunkBuf[0:BlockSize], nil
}

// RecoveryOptions configures crash recovery.
type RecoveryOptions struct {
	// Quarantine configures quarantine bounding and retention for lost+found directories.
	Quarantine QuarantineOptions
	// HeapCipher is the AES-256-XTS cipher used for decrypting heap blocks during recovery.
	// A nil cipher means the store is not encrypted.
	HeapCipher *xts.Cipher
	// ClosedCleanly indicates whether the store was shut down cleanly. When set, any non-zero
	// block that fails checksum or header validation is reported as ErrDamagedBlock rather
	// than treated as a torn write from a crash.
	ClosedCleanly bool
	// EncryptionKey is the 32-byte master key used for decrypting WAL segments during recovery.
	EncryptionKey []byte
}

// Recover scans the heap file, filters out foreign and torn copies, finds the WAL redo start LSN,
// and rebuilds the in-memory indexes and allocator state.
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

	reader := newChunkBlockReader(heapFile, size, options.HeapCipher)

	// Step 1: Scan physical blocks in heap file sequentially to find valid candidate page copies
	bestCandidates := make(map[uint64]candidatePageCopy) // logicalPage -> candidatePageCopy

	var tornBlocks []uint64
	addTornBlock := func(blockNumber uint64) {
		if len(tornBlocks) > 0 && tornBlocks[len(tornBlocks)-1] == blockNumber {
			return
		}
		tornBlocks = append(tornBlocks, blockNumber)
	}

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
			if isZeroBlock(blockBuf) {
				b++
				continue
			}
			if options.ClosedCleanly {
				return nil, fmt.Errorf("%w %d: %w", ErrDamagedBlock, b, err)
			}
			// Check if real error vs normal corrupt/non-block bytes
			if !errors.Is(err, ErrInvalidBlockMagic) && !errors.Is(err, ErrInvalidBlockVersion) && !errors.Is(err, ErrBlockCRCMismatch) {
				return nil, fmt.Errorf("corrupt block decode error at block %d: %w", b, err)
			}
			addTornBlock(b)
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
				if options.ClosedCleanly && err != nil && !isZeroBlock(kbBuf) {
					return nil, fmt.Errorf("%w %d: %w", ErrDamagedBlock, b+uint64(k), err)
				}
				if err != nil && !isZeroBlock(kbBuf) {
					addTornBlock(b + uint64(k))
				}
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

	// Zero blocks rejected as torn so invalid blocks do not linger in free space across a subsequent clean close.
	if len(tornBlocks) > 0 {
		directIO := NewDirectIO()
		zeroBlock := AllocateAlignedBlock(BlockSize)
		for _, blockNumber := range tornBlocks {
			if err := directIO.Write(heapFile, int64(blockNumber*BlockSize), zeroBlock); err != nil {
				return nil, fmt.Errorf("failed to zero torn heap block %d: %w", blockNumber, err)
			}
		}
		if err := heapFile.Sync(); err != nil {
			return nil, fmt.Errorf("failed to fsync heap file after zeroing torn blocks: %w", err)
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
	// Older copies on other pages are tracked as superseded so that WAL redo can clear
	// them even if the key's current page is already up to date.
	// Sort winning candidates by physical block so chunkBlockReader scans disk sequentially.
	keyIndex := make(map[string]KeyIndexEntry)
	supersededPages := make(map[string][]KeyIndexEntry)
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
					existing, exists := keyIndex[k]
					if !exists {
						keyIndex[k] = entry
					} else if existing.LogicalPage == logicalPage {
						if recLSN > existing.LSN {
							keyIndex[k] = entry
						}
					} else if recLSN > existing.LSN {
						supersededPages[k] = append(supersededPages[k], existing)
						keyIndex[k] = entry
					} else {
						supersededPages[k] = append(supersededPages[k], entry)
					}
				}
			}
		} else {
			k, _, recLSN, err := DecodeMultiBlockPage(blocks)
			if err != nil {
				return nil, fmt.Errorf("failed to decode recovered multi-block page %d: %w", logicalPage, err)
			}
			if k != "" { // Active record (not tombstone)
				entry := KeyIndexEntry{
					LogicalPage: logicalPage,
					Slot:        0,
					LSN:         recLSN,
					NumBlocks:   cand.numBlocks,
				}
				existing, exists := keyIndex[k]
				if !exists {
					keyIndex[k] = entry
				} else if existing.LogicalPage == logicalPage {
					if recLSN > existing.LSN {
						keyIndex[k] = entry
					}
				} else if recLSN > existing.LSN {
					supersededPages[k] = append(supersededPages[k], existing)
					keyIndex[k] = entry
				} else {
					supersededPages[k] = append(supersededPages[k], entry)
				}
			} else {
				emptyPages = append(emptyPages, logicalPage)
			}
		}
	}

	// Step 4: Scan WAL to find the last checkpoint's redo start LSN
	var redoStartLSN uint64 = 1
	var maxWAL_LSN uint64

	walScanIt, err := NewWALIterator(fs, walDir, dbID, 1, WALIteratorOptions{
		EncryptionKey: options.EncryptionKey,
	})
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

	return &RecoveryResult{
		DBID:              dbID,
		PageDescs:         pageDescs,
		Buddy:             buddy,
		KeyIndex:          keyIndex,
		EmptyLogicalPages: emptyPages,
		SupersededPages:   supersededPages,
		MaxLSN:            maxWAL_LSN,
		NextLogicalPage:   maxRecoveredLogicalPage + 1,
		RedoStartLSN:      redoStartLSN,
	}, nil
}
