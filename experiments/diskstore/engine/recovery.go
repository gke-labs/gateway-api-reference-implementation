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
	"os"
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
	// where that key appeared on more than one page. replay consumes it to clear
	// each older page at the first record whose LSN is above the older page's LSN.
	SupersededPages map[string][]KeyIndexEntry
	MaxLSN          uint64
	MaxHeapLSN      uint64
	NextLogicalPage uint64
	RedoStartLSN    uint64
	// RedoStartPosition records the segment and byte offset of the first WAL record
	// at or after RedoStartLSN found during recovery, or nil when no such record exists.
	RedoStartPosition *LogPosition
}

// candidateRecord holds the key index metadata extracted from one active record
// during the Step 1 heap scan without retaining the record payload.
type candidateRecord struct {
	// key is the qualified table/key string stored in the record.
	key string
	// oversizeFileName is the backing .obj file name when isOversize is true.
	oversizeFileName string
	// lsn is the WAL log sequence number recorded inside the record.
	lsn uint64
	// slot is the slotted-page slot index, or 0 for multi-block records.
	slot uint32
	// isOversize reports whether the record stores an oversize pointer instead of inline bytes.
	isOversize bool
}

// candidatePageCopy tracks the highest-LSN valid on-disk copy of a logical page
// found during the Step 1 heap scan together with the metadata Step 3 needs.
type candidatePageCopy struct {
	// logicalPage identifies the logical page recovered from the block headers.
	logicalPage uint64
	// lsn is the highest page LSN observed in the block headers of this copy.
	lsn uint64
	// startBlock is the starting 4 KiB physical block index of this copy in heap.db.
	startBlock uint64
	// records holds the active records extracted from this copy during Step 1.
	records []candidateRecord
	// decodeErr stores any record-decoding error encountered while extracting this copy,
	// deferred until Step 3 so a losing copy's error does not fail recovery.
	decodeErr error
	// numBlocks is the power-of-two block count of this copy (1 for slotted, 2..512 for multi-block).
	numBlocks int
	// empty reports whether this copy holds zero active records and belongs in EmptyLogicalPages.
	empty bool
}

// extractSlottedPageRecords reads only the key index metadata from a 1-block slotted page
// without retaining the page buffer or record payloads.
func extractSlottedPageRecords(blockBuffer []byte, logicalPage uint64) ([]candidateRecord, bool, error) {
	slotted, err := WrapSlottedPage(blockBuffer)
	if err != nil {
		return nil, false, fmt.Errorf("failed to wrap recovered slotted page %d: %w", logicalPage, err)
	}
	activeCount := slotted.ActiveSlotsCount()
	if activeCount == 0 {
		return nil, true, nil
	}
	records := make([]candidateRecord, 0, activeCount)
	for slot := uint32(0); slot < uint32(slotted.NumSlots()); slot++ {
		key, value, recordLSN, isOversize, err := slotted.GetWithFlag(slot)
		if err != nil {
			if errors.Is(err, ErrSlotNotFound) {
				continue
			}
			return nil, false, fmt.Errorf("failed to get slot %d from page %d: %w", slot, logicalPage, err)
		}
		record := candidateRecord{
			key:        key,
			slot:       slot,
			lsn:        recordLSN,
			isOversize: isOversize,
		}
		if isOversize {
			_, _, fileName, decodeErr := DecodeOversizePointer(value)
			if decodeErr != nil {
				return nil, false, fmt.Errorf("failed to decode oversize pointer in page %d slot %d: %w", logicalPage, slot, decodeErr)
			}
			record.oversizeFileName = fileName
		}
		records = append(records, record)
	}
	return records, false, nil
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
	EncryptionKey EncryptionKey
	// RecoveryStartLSN is the start LSN for recovery read from meta.db.
	// When non-zero, recovery replays the log starting from this LSN.
	RecoveryStartLSN uint64
	// ExternalLog skips fsyncing and scanning local .wal files during recovery.
	ExternalLog bool
}

// Recover scans the heap file, filters out foreign and torn copies, finds the WAL redo start LSN,
// and rebuilds the in-memory indexes and allocator state.
func Recover(fs FS, heapFile File, storeDir string, walDir string, dbID [16]byte, options RecoveryOptions) (*RecoveryResult, error) {
	if !options.ExternalLog {
		// Item 10: Fsync every existing WAL segment and walDir before trusting them
		entries, err := fs.ReadDir(walDir)
		if err != nil {
			if !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("failed to read WAL directory: %w", err)
			}
		} else {
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

	totalHeapBlocks := uint64(size / BlockSize)
	b := uint64(0)
	for b < totalHeapBlocks {
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
		if b%uint64(numBlocks) != 0 || b+uint64(numBlocks) > totalHeapBlocks {
			b++
			continue
		}

		existing, exists := bestCandidates[hdr.LogicalPage]
		isNewer := !exists || hdr.LSN > existing.lsn

		if numBlocks == 1 {
			if isNewer {
				records, empty, decodeErr := extractSlottedPageRecords(blockBuf, hdr.LogicalPage)
				bestCandidates[hdr.LogicalPage] = candidatePageCopy{
					logicalPage: hdr.LogicalPage,
					lsn:         hdr.LSN,
					startBlock:  b,
					numBlocks:   1,
					records:     records,
					empty:       empty,
					decodeErr:   decodeErr,
				}
			}
			b++
			continue
		}

		// Multi-block candidate: capture the record header and key bytes from block 0
		// while validating the remaining blocks in a single forward pass.
		var multiBlockKey []byte
		var keyCopied int
		var multiBlockLSN uint64
		var multiBlockDecodeErr error
		if isNewer {
			keyLen, payloadLen, recordLSN, headerErr := decodeMultiBlockRecordHeader(blockBuf)
			if headerErr != nil {
				multiBlockDecodeErr = fmt.Errorf("failed to decode recovered multi-block page %d: %w", hdr.LogicalPage, headerErr)
			} else if int64(PageRecordHeaderSize)+int64(keyLen)+int64(payloadLen) > int64(numBlocks)*BlockUsableSize {
				multiBlockDecodeErr = fmt.Errorf("failed to decode recovered multi-block page %d: truncated multi-block page", hdr.LogicalPage)
			} else {
				multiBlockLSN = recordLSN
				if keyLen > 0 {
					multiBlockKey = make([]byte, keyLen)
					keyCopied = copy(multiBlockKey, blockBuf[BlockHeaderSize+PageRecordHeaderSize:BlockSize])
				}
			}
		}

		// Verify the remaining blocks of the candidate page run.
		// Invariants:
		//  1. Every validated block k >= 1 has a valid CRC and BlockIndex == k (never 0),
		//     so no validated block in [b+1, b+k-1] can start another valid page or be torn.
		//  2. On failure at block b+k, the scan advances directly to b+k (or b+k+1 when
		//     b+k itself failed header decoding). Because block b+k is still in the chunk
		//     reader buffer, the scan moves strictly forward and reads every heap block once.
		valid := true
		nextBlock := b + uint64(numBlocks)
		for k := 1; k < numBlocks; k++ {
			kbBuf, err := reader.ReadBlock(b + uint64(k))
			if err != nil {
				if errors.Is(err, io.EOF) {
					valid = false
					nextBlock = b + uint64(k)
					break
				}
				return nil, fmt.Errorf("read error reading block %d: %w", b+uint64(k), err)
			}

			kHdr, err := DecodeBlockHeader(kbBuf)
			if err != nil || kHdr.LogicalPage != hdr.LogicalPage || kHdr.LSN != hdr.LSN ||
				kHdr.BlockIndex != uint32(k) || kHdr.NumBlocks != hdr.NumBlocks {
				if err != nil {
					if !isZeroBlock(kbBuf) {
						if options.ClosedCleanly {
							return nil, fmt.Errorf("%w %d: %w", ErrDamagedBlock, b+uint64(k), err)
						}
						if !errors.Is(err, ErrInvalidBlockMagic) && !errors.Is(err, ErrInvalidBlockVersion) && !errors.Is(err, ErrBlockCRCMismatch) {
							return nil, fmt.Errorf("corrupt block decode error at block %d: %w", b+uint64(k), err)
						}
						addTornBlock(b + uint64(k))
					}
					nextBlock = b + uint64(k) + 1
				} else {
					nextBlock = b + uint64(k)
				}
				valid = false
				break
			}

			if keyCopied < len(multiBlockKey) {
				keyCopied += copy(multiBlockKey[keyCopied:], kbBuf[BlockHeaderSize:BlockSize])
			}
		}

		if valid && isNewer {
			cand := candidatePageCopy{
				logicalPage: hdr.LogicalPage,
				lsn:         hdr.LSN,
				startBlock:  b,
				numBlocks:   numBlocks,
				decodeErr:   multiBlockDecodeErr,
			}
			if multiBlockDecodeErr == nil {
				if len(multiBlockKey) > 0 {
					cand.records = []candidateRecord{{
						key:  string(multiBlockKey),
						slot: 0,
						lsn:  multiBlockLSN,
					}}
				} else {
					cand.empty = true
				}
			}
			bestCandidates[hdr.LogicalPage] = cand
		}
		b = nextBlock
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
			LogicalPage:   logicalPage,
			NumBlocks:     cand.numBlocks,
			PhysicalBlock: cand.startBlock,
		}
		desc.PageLSN.Store(cand.lsn)
		pageDescs[logicalPage] = desc

		if logicalPage > maxRecoveredLogicalPage {
			maxRecoveredLogicalPage = logicalPage
		}
	}

	// Step 3: Build the key index and empty-page list from winning candidates in
	// start-block order so EmptyLogicalPages, SupersededPages, and any decode error
	// are deterministic across runs. Step 1 already extracted each candidate's key
	// metadata during the heap scan, so Step 3 reads no heap blocks.
	// Item 4: Always keep the copy with the highest LSN when a key appears multiple times.
	// Older copies on other pages are tracked as superseded so that WAL redo can clear
	// them even if the key's current page is already up to date.
	keyIndex := make(map[string]KeyIndexEntry)
	supersededPages := make(map[string][]KeyIndexEntry)
	var emptyPages []uint64

	sortedCandidates := make([]candidatePageCopy, 0, len(bestCandidates))
	for _, cand := range bestCandidates {
		sortedCandidates = append(sortedCandidates, cand)
	}
	bestCandidates = nil
	sort.Slice(sortedCandidates, func(i, j int) bool {
		return sortedCandidates[i].startBlock < sortedCandidates[j].startBlock
	})

	for _, cand := range sortedCandidates {
		logicalPage := cand.logicalPage
		if cand.decodeErr != nil {
			return nil, cand.decodeErr
		}
		if cand.empty {
			emptyPages = append(emptyPages, logicalPage)
			continue
		}
		for _, record := range cand.records {
			entry := KeyIndexEntry{
				LogicalPage:      logicalPage,
				Slot:             record.slot,
				LSN:              record.lsn,
				NumBlocks:        cand.numBlocks,
				IsOversize:       record.isOversize,
				OversizeFileName: record.oversizeFileName,
			}
			existing, exists := keyIndex[record.key]
			if !exists {
				keyIndex[record.key] = entry
			} else if existing.LogicalPage == logicalPage {
				if record.lsn > existing.LSN {
					keyIndex[record.key] = entry
				}
			} else if record.lsn > existing.LSN {
				supersededPages[record.key] = append(supersededPages[record.key], existing)
				keyIndex[record.key] = entry
			} else {
				supersededPages[record.key] = append(supersededPages[record.key], entry)
			}
		}
	}

	// Step 4: Scan WAL to find maxWAL_LSN and verify the write-ahead rule.
	// Recovery takes its start LSN from meta.db only; it does not read checkpoint records.
	redoStartLSN := options.RecoveryStartLSN
	if redoStartLSN == 0 {
		redoStartLSN = 1
	}
	var maxWAL_LSN uint64
	var redoStartPosition *LogPosition

	if !options.ExternalLog {
		walScanIterator, err := NewWALIterator(fs, walDir, dbID, 1, WALIteratorOptions{
			EncryptionKey: options.EncryptionKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create WAL scan iterator: %w", err)
		}
		for {
			rec, err := walScanIterator.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("error during WAL scan: %w", err)
			}
			if redoStartPosition == nil && rec.LSN >= redoStartLSN {
				position := walScanIterator.lastRecordPosition
				redoStartPosition = &position
			}
			if rec.LSN > maxWAL_LSN {
				maxWAL_LSN = rec.LSN
			}
		}
		if closeErr := walScanIterator.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to close WAL scan iterator: %w", closeErr)
		}

		// Under the write-ahead rule, a heap page with LSN L can only be on disk
		// if the WAL was fsynced through L. If WAL replay ends below the highest
		// page LSN found in the heap, records that the engine acknowledged are
		// missing, which indicates provable corruption rather than an unacknowledged torn tail.
		if maxWAL_LSN < maxHeapLSN {
			return nil, fmt.Errorf("%w: WAL replay ended at LSN %d below highest heap page LSN %d", ErrCorruptWAL, maxWAL_LSN, maxHeapLSN)
		}
	}

	return &RecoveryResult{
		DBID:              dbID,
		PageDescs:         pageDescs,
		Buddy:             buddy,
		KeyIndex:          keyIndex,
		EmptyLogicalPages: emptyPages,
		SupersededPages:   supersededPages,
		MaxLSN:            maxWAL_LSN,
		MaxHeapLSN:        maxHeapLSN,
		NextLogicalPage:   maxRecoveredLogicalPage + 1,
		RedoStartLSN:      redoStartLSN,
		RedoStartPosition: redoStartPosition,
	}, nil
}

// replay replays records from a LogIterator through the write path apply functions.
// Replay holds writerMu throughout, and appends nothing to the log.
//
// Replay skips a record when the page that holds the key carries that LSN or a newer one,
// because a page image at LSN L holds every record up to L that touched it, and a record
// that replay applies again leaves the key with the same value.
// When recovery finds a key on more than one page, replay clears the older copy at the
// first record for that key whose LSN is above the older page's LSN, even when the key's
// current page is up to date.
//
// Iterator Errors and End-of-Log:
// The provided LogIterator may return the following errors from Next:
//   - io.EOF: indicates the end of the log or an unacknowledged torn write at the active log tail.
//     Replay treats io.EOF as normal completion, stops iteration, and closes the iterator.
//   - An error wrapping ErrCorruptWAL: indicates corruption, checksum mismatch, or an unexpected
//     gap in earlier completed segments or log positions. Replay aborts immediately, closes
//     the iterator, and returns the error.
//   - Any other I/O or decode error: replay aborts immediately, closes the iterator, and returns
//     the error.
func (s *Engine) replay(iterator LogIterator, superseded map[string][]KeyIndexEntry) error {
	s.writerMu.Lock()
	defer s.writerMu.Unlock()

	for {
		rec, err := iterator.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.Join(fmt.Errorf("error during redo replay: %w", err), iterator.Close())
		}

		s.keyMu.RLock()
		existing, inIndex := s.keyIndex[rec.Key]
		s.keyMu.RUnlock()

		// Replay applies each page's part of a record by that page's own LSN:
		// an older superseded page is cleared when its LSN is below the record's,
		// even when the key's current page is already up to date.
		if oldEntries := superseded[rec.Key]; len(oldEntries) > 0 {
			var remaining []KeyIndexEntry
			for _, oldEntry := range oldEntries {
				oldLSN, ok := s.bp.PageLSN(oldEntry.LogicalPage)
				if ok && oldLSN < rec.LSN {
					if oldEntry.NumBlocks > 1 {
						if err := s.clearLogicalPageLocked(oldEntry.LogicalPage, rec.LSN); err != nil {
							return errors.Join(err, iterator.Close())
						}
					} else {
						// When the older copy is an oversize pointer, replay removes the slot
						// and leaves the old oversize file for the quarantine pass.
						if err := s.deleteSlotFromPageLocked(oldEntry.LogicalPage, oldEntry.Slot, rec.LSN); err != nil {
							return errors.Join(err, iterator.Close())
						}
					}
				} else {
					remaining = append(remaining, oldEntry)
				}
			}
			if len(remaining) > 0 {
				superseded[rec.Key] = remaining
			} else {
				delete(superseded, rec.Key)
			}
		}

		// Replay skips a record when the page that holds the key carries that LSN
		// or a newer one, because a page image at LSN L holds every record up to L
		// that touched it, and a record that replay applies again leaves the key
		// with the same value.
		if inIndex {
			if pageLSN, ok := s.bp.PageLSN(existing.LogicalPage); ok && pageLSN >= rec.LSN {
				continue
			}
		}

		switch rec.Type {
		case RecordTypePut, RecordTypePutPointer:
			isOversize := rec.Type == RecordTypePutPointer
			if err := s.applyPutLocked(rec.Key, rec.Payload, rec.LSN, isOversize); err != nil {
				return errors.Join(err, iterator.Close())
			}

		case RecordTypeDelete:
			if !inIndex {
				continue
			}
			if err := s.applyDeleteLocked(rec.Key, rec.LSN); err != nil {
				return errors.Join(err, iterator.Close())
			}
		}
	}

	if err := iterator.Close(); err != nil {
		return fmt.Errorf("failed to close redo iterator: %w", err)
	}
	return nil
}

// replayWAL builds a LogIterator from s.wal starting at redoStartLSN and passes it to replay.
func (s *Engine) replayWAL(redoStartLSN uint64, redoStartPosition *LogPosition, superseded map[string][]KeyIndexEntry) error {
	walRedoIterator, err := s.wal.NewIterator(redoStartLSN, redoStartPosition)
	if err != nil {
		return fmt.Errorf("failed to create WAL redo iterator: %w", err)
	}
	return s.replay(walRedoIterator, superseded)
}

// ExternalRecord represents a logical mutation yielded by an external log during recovery replay.
type ExternalRecord struct {
	Type    RecordType
	LSN     uint64
	Table   string
	Key     string
	Payload []byte
}

// ExternalLogIterator reads logical mutations forward in strictly increasing LSN order.
type ExternalLogIterator interface {
	io.Closer
	Next() (ExternalRecord, error)
}

type externalReplayIterator struct {
	engine  *Engine
	inner   ExternalLogIterator
	lastLSN uint64
}

func (it *externalReplayIterator) Next() (Record, error) {
	externalRecord, err := it.inner.Next()
	if err != nil {
		return Record{}, err
	}
	if externalRecord.LSN == 0 || externalRecord.LSN <= it.lastLSN {
		return Record{}, fmt.Errorf("%w: got %d, previous %d", ErrNonMonotonicLSN, externalRecord.LSN, it.lastLSN)
	}
	it.lastLSN = externalRecord.LSN
	qualifiedKey := qualifyKey(externalRecord.Table, externalRecord.Key)

	switch externalRecord.Type {
	case RecordTypeDelete:
		return Record{Type: RecordTypeDelete, LSN: externalRecord.LSN, Key: qualifiedKey}, nil
	case RecordTypePut:
		if len(qualifiedKey) > 65535 {
			return Record{}, ErrObjectOversize
		}
		stored, err := it.engine.compress(externalRecord.Payload)
		if err != nil {
			return Record{}, err
		}
		if fitsInMultiBlockPage(len(qualifiedKey), len(stored)) {
			return Record{Type: RecordTypePut, LSN: externalRecord.LSN, Key: qualifiedKey, Payload: stored}, nil
		}
		it.engine.keyMu.RLock()
		existing, inIndex := it.engine.keyIndex[qualifiedKey]
		it.engine.keyMu.RUnlock()
		if inIndex {
			if pageLSN, ok := it.engine.bp.PageLSN(existing.LogicalPage); ok && pageLSN >= externalRecord.LSN {
				return Record{Type: RecordTypePutPointer, LSN: externalRecord.LSN, Key: qualifiedKey}, nil
			}
		}
		pointerPayload, fileName, err := it.engine.writeOversizePointer(qualifiedKey, stored)
		if err != nil {
			return Record{}, err
		}
		it.engine.unregisterInFlight(fileName)
		return Record{Type: RecordTypePutPointer, LSN: externalRecord.LSN, Key: qualifiedKey, Payload: pointerPayload}, nil
	default:
		return Record{}, fmt.Errorf("%w: unsupported external record type %d", ErrCorruptRecord, externalRecord.Type)
	}
}

func (it *externalReplayIterator) Close() error {
	return it.inner.Close()
}

// replayExternal adapts an ExternalLogIterator into a LogIterator and replays it through replay.
func (s *Engine) replayExternal(iterator ExternalLogIterator, superseded map[string][]KeyIndexEntry) (uint64, error) {
	adapted := &externalReplayIterator{engine: s, inner: iterator}
	if err := s.replay(adapted, superseded); err != nil {
		return 0, err
	}
	return adapted.lastLSN, nil
}
