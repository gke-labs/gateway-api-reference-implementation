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
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

var (
	// ErrReuseRuleViolation is returned when a write violates the reuse rule.
	ErrReuseRuleViolation = errors.New("reuse rule violation: attempt to overwrite newest durable copy of a page")

	// ErrWriteAheadRuleViolation is returned when a heap write violates the write-ahead rule.
	ErrWriteAheadRuleViolation = errors.New("write-ahead rule violation: page written before WAL fsynced through page LSN")

	// ErrCrashed is returned when a write, sync, rename, or remove is attempted after a simulated crash.
	ErrCrashed = errors.New("filesystem crashed")
)

const (
	// DefaultBlockSize is 4 KiB.
	DefaultBlockSize = 4096

	// BlockMagicValue is "GARIDSTR" in big endian uint64.
	BlockMagicValue uint64 = 0x4741524944535452
)

// DurablePageRange tracks the physical block range and LSN of the newest durable copy of a logical page.
type DurablePageRange struct {
	StartBlock uint64
	NumBlocks  uint32
	LSN        uint64
}

// FaultFS wraps an FS to intercept writes, assert storage invariants, and simulate crashes.
type FaultFS struct {
	underlying FS
	mu         sync.RWMutex
	files      map[string]*FaultFile

	maxFsyncedLSN atomic.Uint64

	assertReuseRule      bool
	assertWriteAheadRule bool

	writeErr error
	syncErr  error

	beforeWriteAt func(path string, p []byte, off int64)
	beforeSync    func(path string)

	crashed bool
}

// NewFaultFS creates a new FaultFS wrapping an underlying FS.
func NewFaultFS(underlying FS) *FaultFS {
	return &FaultFS{
		underlying:           underlying,
		files:                make(map[string]*FaultFile),
		assertReuseRule:      true,
		assertWriteAheadRule: true,
	}
}

// SetMaxFsyncedLSN sets the highest LSN that has been fsynced in the WAL.
func (f *FaultFS) SetMaxFsyncedLSN(lsn uint64) {
	for {
		curr := f.maxFsyncedLSN.Load()
		if lsn <= curr || f.maxFsyncedLSN.CompareAndSwap(curr, lsn) {
			break
		}
	}
}

// MaxFsyncedLSN returns the highest LSN that has been fsynced in the WAL.
func (f *FaultFS) MaxFsyncedLSN() uint64 {
	return f.maxFsyncedLSN.Load()
}

// SetAssertReuseRule enables or disables the reuse rule assertion.
func (f *FaultFS) SetAssertReuseRule(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assertReuseRule = enabled
}

// SetAssertWriteAheadRule enables or disables the write-ahead rule assertion.
func (f *FaultFS) SetAssertWriteAheadRule(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assertWriteAheadRule = enabled
}

// SetWriteError sets an error to be returned on subsequent writes.
func (f *FaultFS) SetWriteError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeErr = err
}

// SetSyncError sets an error to be returned on subsequent syncs.
func (f *FaultFS) SetSyncError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncErr = err
}

// SetBeforeWriteAt sets a callback invoked before WriteAt execution.
func (f *FaultFS) SetBeforeWriteAt(fn func(path string, p []byte, off int64)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeWriteAt = fn
}

// SetBeforeSync sets a callback invoked before Sync execution.
func (f *FaultFS) SetBeforeSync(fn func(path string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeSync = fn
}

func (f *FaultFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f.mu.RLock()
	crashed := f.crashed
	f.mu.RUnlock()
	if crashed && (flag&(os.O_WRONLY|os.O_CREATE|os.O_TRUNC) != 0) {
		return nil, ErrCrashed
	}

	cleaned := cleanPath(name)
	file, err := f.underlying.OpenFile(cleaned, flag, perm)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	ff, exists := f.files[cleaned]
	if !exists {
		var newErr error
		ff, newErr = newFaultFile(f, cleaned, file)
		if newErr != nil {
			closeErr := file.Close()
			return nil, errors.Join(newErr, closeErr)
		}
		if f.crashed {
			ff.crashed = true
		}
		f.files[cleaned] = ff
	} else {
		ff.underlying = file
		ff.closed = false
		if f.crashed {
			ff.crashed = true
		}
	}
	return ff, nil
}

func (f *FaultFS) Create(name string) (File, error) {
	f.mu.RLock()
	crashed := f.crashed
	f.mu.RUnlock()
	if crashed {
		return nil, ErrCrashed
	}
	return f.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, StoreFileMode)
}

func (f *FaultFS) Open(name string) (File, error) {
	return f.OpenFile(name, os.O_RDONLY, 0)
}

func (f *FaultFS) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.crashed {
		return ErrCrashed
	}
	delete(f.files, cleanPath(name))
	return f.underlying.Remove(name)
}

func (f *FaultFS) Rename(oldpath, newpath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.crashed {
		return ErrCrashed
	}
	oldClean := cleanPath(oldpath)
	newClean := cleanPath(newpath)
	if ff, exists := f.files[oldClean]; exists {
		f.files[newClean] = ff
		delete(f.files, oldClean)
	}
	return f.underlying.Rename(oldpath, newpath)
}

func (f *FaultFS) MkdirAll(path string, perm os.FileMode) error {
	return f.underlying.MkdirAll(path, perm)
}

func (f *FaultFS) ReadDir(dirname string) ([]os.DirEntry, error) {
	return f.underlying.ReadDir(dirname)
}

func (f *FaultFS) SyncDir(dirname string) error {
	f.mu.RLock()
	crashed := f.crashed
	f.mu.RUnlock()
	if crashed {
		return ErrCrashed
	}
	return f.underlying.SyncDir(dirname)
}

// Crash simulates a crash across all files in this filesystem.
// If dropUnsynced is true, all un-fsynced writes are discarded.
// If tearFraction > 0, randomly tears un-fsynced blocks.
func (f *FaultFS) Crash(dropUnsynced bool, tearFraction float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crashed = true
	var errs []error
	for _, ff := range f.files {
		if err := ff.Crash(dropUnsynced, tearFraction); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FaultFile intercepts reads, writes, and syncs on a specific file.
type FaultFile struct {
	fs         *FaultFS
	name       string
	underlying File
	mu         sync.RWMutex

	durableData   []byte
	pendingData   []byte
	pendingBlocks map[uint64]bool

	// Map of logicalPage -> newest durable range (heap files only)
	durablePages map[uint64]DurablePageRange

	isHeapFile bool
	isWALFile  bool
	closed     bool
	crashed    bool
}

func (f *FaultFile) isCrashed() bool {
	f.fs.mu.RLock()
	fsCrashed := f.fs.crashed
	f.fs.mu.RUnlock()

	f.mu.RLock()
	fileCrashed := f.crashed
	f.mu.RUnlock()

	return fsCrashed || fileCrashed
}

func newFaultFile(fs *FaultFS, name string, underlying File) (*FaultFile, error) {
	base := filepath.Base(name)
	isHeap := filepath.Ext(name) == ".db" || filepath.Ext(name) == ".heap" || base == "heap.db"
	isWAL := filepath.Ext(name) == ".wal"

	// Read initial contents from underlying file
	size, err := underlying.Size()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying file size: %w", err)
	}
	initial := make([]byte, size)
	if size > 0 {
		if _, err := underlying.ReadAt(initial, 0); err != nil {
			return nil, fmt.Errorf("failed to read underlying file: %w", err)
		}
	}

	ff := &FaultFile{
		fs:            fs,
		name:          name,
		underlying:    underlying,
		durableData:   bytes.Clone(initial),
		pendingData:   bytes.Clone(initial),
		pendingBlocks: make(map[uint64]bool),
		durablePages:  make(map[uint64]DurablePageRange),
		isHeapFile:    isHeap,
		isWALFile:     isWAL,
	}

	if isHeap && len(initial) > 0 {
		ff.rebuildDurablePagesLocked()
	}
	return ff, nil
}

func (f *FaultFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= int64(len(f.pendingData)) {
		return 0, os.ErrNotExist
	}
	n := copy(p, f.pendingData[off:])
	return n, nil
}

func (f *FaultFile) WriteAt(p []byte, off int64) (int, error) {
	if f.isCrashed() {
		return 0, ErrCrashed
	}

	f.fs.mu.RLock()
	writeErr := f.fs.writeErr
	assertReuse := f.fs.assertReuseRule
	assertWAL := f.fs.assertWriteAheadRule
	maxFsyncedLSN := f.fs.MaxFsyncedLSN()
	beforeWriteAt := f.fs.beforeWriteAt
	f.fs.mu.RUnlock()

	if beforeWriteAt != nil {
		beforeWriteAt(f.name, p, off)
		if f.isCrashed() {
			return 0, ErrCrashed
		}
		f.fs.mu.RLock()
		writeErr = f.fs.writeErr
		f.fs.mu.RUnlock()
	}

	if writeErr != nil {
		return 0, writeErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if off < 0 {
		return 0, errors.New("negative offset")
	}

	// If this is a heap file, assert Reuse Rule and Write-Ahead Rule
	if f.isHeapFile {
		startBlock := uint64(off / DefaultBlockSize)
		numBlocksInWrite := (len(p) + DefaultBlockSize - 1) / DefaultBlockSize

		for i := 0; i < numBlocksInWrite; i++ {
			bIdx := startBlock + uint64(i)
			blockOff := i * DefaultBlockSize
			blockEnd := blockOff + DefaultBlockSize
			if blockEnd > len(p) {
				blockEnd = len(p)
			}
			blockBytes := p[blockOff:blockEnd]

			// Parse block header if at least HeaderSize bytes
			if len(blockBytes) >= BlockHeaderSize {
				if blockBytes[0] == BlockMagic && blockBytes[1] == FormatVersion {
					lsn := binary.BigEndian.Uint64(blockBytes[16:24])

					// Assert Write-Ahead Rule:
					// Before writing any page whose LSN is L, log must be fsynced through L.
					if assertWAL && lsn > maxFsyncedLSN {
						panic(fmt.Sprintf("%v: page LSN %d > max fsynced WAL LSN %d (block %d)",
							ErrWriteAheadRuleViolation, lsn, maxFsyncedLSN, bIdx))
					}
				}
			}

			// Assert Reuse Rule:
			// The location holding a page's newest durable (fsynced) copy must never be overwritten.
			if assertReuse {
				for pageID, durable := range f.durablePages {
					if bIdx >= durable.StartBlock && bIdx < durable.StartBlock+uint64(durable.NumBlocks) {
						panic(fmt.Sprintf("%v: writing to block %d which holds durable copy of page %d (LSN %d, blocks [%d..%d))",
							ErrReuseRuleViolation, bIdx, pageID, durable.LSN, durable.StartBlock, durable.StartBlock+uint64(durable.NumBlocks)))
					}
				}
			}

			f.pendingBlocks[bIdx] = true
		}
	}

	reqLen := int(off) + len(p)
	if reqLen > len(f.pendingData) {
		expanded := make([]byte, reqLen)
		copy(expanded, f.pendingData)
		f.pendingData = expanded
	}
	copy(f.pendingData[off:], p)

	// Write through to underlying
	_, err := f.underlying.WriteAt(p, off)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (f *FaultFile) Sync() error {
	if f.isCrashed() {
		return ErrCrashed
	}

	f.fs.mu.RLock()
	syncErr := f.fs.syncErr
	beforeSync := f.fs.beforeSync
	f.fs.mu.RUnlock()

	if beforeSync != nil {
		beforeSync(f.name)
		if f.isCrashed() {
			return ErrCrashed
		}
		f.fs.mu.RLock()
		syncErr = f.fs.syncErr
		f.fs.mu.RUnlock()
	}

	if syncErr != nil {
		return syncErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Commit pending writes to durable state
	f.durableData = bytes.Clone(f.pendingData)
	f.pendingBlocks = make(map[uint64]bool)

	// Update durable pages index if heap file
	if f.isHeapFile {
		f.rebuildDurablePagesLocked()
	}

	// Update MaxFsyncedLSN if WAL file
	if f.isWALFile {
		f.updateMaxFsyncedWAL_LSNLocked()
	}

	return f.underlying.Sync()
}

func (f *FaultFile) rebuildDurablePagesLocked() {
	f.durablePages = make(map[uint64]DurablePageRange)
	totalBlocks := len(f.durableData) / DefaultBlockSize

	type candidatePage struct {
		startBlock  uint64
		logicalPage uint64
		lsn         uint64
		numBlocks   uint32
	}

	// Scan durable blocks for valid page copies
	b := 0
	for b < totalBlocks {
		blockStart := b * DefaultBlockSize
		blockBytes := f.durableData[blockStart : blockStart+DefaultBlockSize]
		hdr, err := DecodeBlockHeader(blockBytes)
		if err != nil || hdr.BlockIndex != 0 || hdr.NumBlocks == 0 || b+int(hdr.NumBlocks) > totalBlocks {
			b++
			continue
		}

		numBlocks := int(hdr.NumBlocks)
		valid := true
		for k := 0; k < numBlocks; k++ {
			kbStart := (b + k) * DefaultBlockSize
			kbBytes := f.durableData[kbStart : kbStart+DefaultBlockSize]
			kHdr, err := DecodeBlockHeader(kbBytes)
			if err != nil || kHdr.LogicalPage != hdr.LogicalPage || kHdr.LSN != hdr.LSN ||
				kHdr.BlockIndex != uint32(k) || kHdr.NumBlocks != hdr.NumBlocks {
				valid = false
				break
			}
		}

		if valid {
			cand := candidatePage{
				startBlock:  uint64(b),
				logicalPage: hdr.LogicalPage,
				lsn:         hdr.LSN,
				numBlocks:   hdr.NumBlocks,
			}
			existing, exists := f.durablePages[hdr.LogicalPage]
			if !exists || cand.lsn > existing.LSN {
				f.durablePages[hdr.LogicalPage] = DurablePageRange{
					StartBlock: cand.startBlock,
					NumBlocks:  cand.numBlocks,
					LSN:        cand.lsn,
				}
			}
			b += numBlocks
		} else {
			b++
		}
	}
}

func (f *FaultFile) updateMaxFsyncedWAL_LSNLocked() {
	if len(f.durableData) < SegmentHeaderSize {
		return
	}
	offset := SegmentHeaderSize
	var maxLSN uint64
	for offset+RecordHeaderSize <= len(f.durableData) {
		if f.durableData[offset] == 0 {
			// Zero padding in block: skip to next 4 KiB block boundary
			nextBlock := ((offset / DefaultBlockSize) + 1) * DefaultBlockSize
			if nextBlock <= offset || nextBlock >= len(f.durableData) {
				break
			}
			offset = nextBlock
			continue
		}

		r, err := DecodeRecord(bytes.NewReader(f.durableData[offset:]))
		if err != nil {
			break
		}
		if r.LSN > maxLSN {
			maxLSN = r.LSN
		}
		keyBytes := len([]byte(r.Key))
		payloadBytes := len(r.Payload)
		offset += RecordHeaderSize + keyBytes + payloadBytes
	}

	if maxLSN > 0 {
		f.fs.SetMaxFsyncedLSN(maxLSN)
	}
}

// Crash simulates a crash on this file.
func (f *FaultFile) Crash(dropUnsynced bool, tearFraction float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.crashed = true

	if f.closed {
		return nil
	}

	if dropUnsynced {
		// Discard pending writes; revert to durable data
		f.pendingData = bytes.Clone(f.durableData)
		f.pendingBlocks = make(map[uint64]bool)
		truncErr := f.underlying.Truncate(int64(len(f.durableData)))
		_, writeErr := f.underlying.WriteAt(f.durableData, 0)
		syncErr := f.underlying.Sync()
		return errors.Join(truncErr, writeErr, syncErr)
	}

	if tearFraction > 0 && len(f.pendingBlocks) > 0 {
		// Partially write or tear random pending blocks
		for bIdx := range f.pendingBlocks {
			r := rand.Float64()
			if r < tearFraction {
				// Tear block: corrupt random bytes or write only half block
				start := int(bIdx) * DefaultBlockSize
				if start+DefaultBlockSize <= len(f.pendingData) {
					// Corrupt last 128 bytes of block
					for k := 0; k < 128; k++ {
						f.pendingData[start+DefaultBlockSize-1-k] ^= 0xff
					}
				}
			}
		}
	}

	// Write current crashed image to underlying and sync
	truncErr := f.underlying.Truncate(int64(len(f.pendingData)))
	_, writeErr := f.underlying.WriteAt(f.pendingData, 0)
	syncErr := f.underlying.Sync()
	return errors.Join(truncErr, writeErr, syncErr)
}

func (f *FaultFile) Truncate(size int64) error {
	if f.isCrashed() {
		return ErrCrashed
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if size < 0 {
		return errors.New("negative size")
	}
	if int(size) < len(f.pendingData) {
		f.pendingData = f.pendingData[:size]
	} else if int(size) > len(f.pendingData) {
		expanded := make([]byte, size)
		copy(expanded, f.pendingData)
		f.pendingData = expanded
	}
	return f.underlying.Truncate(size)
}

func (f *FaultFile) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return f.underlying.Close()
}

func (f *FaultFile) Size() (int64, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return int64(len(f.pendingData)), nil
}

func (f *FaultFile) SyscallConn() (any, error) {
	return f.underlying.SyscallConn()
}
