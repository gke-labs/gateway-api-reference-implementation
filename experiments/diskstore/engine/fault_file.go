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
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrReuseRuleViolation is returned when a write violates the reuse rule.
	ErrReuseRuleViolation = errors.New("reuse rule violation: attempt to overwrite newest durable copy of a page")

	// ErrWriteAheadRuleViolation is returned when a heap write violates the write-ahead rule.
	ErrWriteAheadRuleViolation = errors.New("write-ahead rule violation: page written before WAL fsynced through page LSN")

	// ErrCrashed is returned when an I/O operation is attempted after or during a simulated crash point.
	ErrCrashed = errors.New("simulated crash during I/O operation")

	// ErrInjectedFault is returned when an I/O fault is explicitly injected.
	ErrInjectedFault = errors.New("injected I/O error")
)

const (
	// DefaultBlockSize is 4 KiB.
	DefaultBlockSize = 4096

	// SectorSize is 512 bytes (standard disk sector granularity for torn writes).
	SectorSize = 512

	// BlockMagicValue is "GARIDSTR" in big endian uint64.
	BlockMagicValue uint64 = 0x4741524944535452
)

// DurablePageRange tracks the physical block range and LSN of the newest durable copy of a logical page.
type DurablePageRange struct {
	StartBlock uint64
	NumBlocks  uint32
	LSN        uint64
}

// PowerLossOptions configures power loss simulation parameters.
type PowerLossOptions struct {
	DropUnsynced         bool
	RandomSubset         bool
	TearFraction         float64
	LostMetadata         bool
	TruncateUnsyncedSize bool
	Rand                 *rand.Rand
}

// FaultFS wraps an FS to intercept writes, assert storage invariants, and simulate crashes.
type FaultFS struct {
	underlying FS
	mu         sync.RWMutex
	files      map[string]*FaultFile

	maxFsyncedLSN atomic.Uint64

	assertReuseRule      bool
	assertWriteAheadRule bool

	readErr          error
	readErrSticky    bool
	writeErr         error
	writeErrSticky   bool
	syncErr          error
	syncErrSticky    bool
	dirSyncErr       error
	dirSyncErrSticky bool
	skipSync         bool

	shortReadLimit  int
	shortWriteLimit int

	staleBlocks map[string]map[uint64][]byte // path -> blockIdx -> stale block data

	// Lost metadata tracking: directory operations not yet confirmed by SyncDir
	pendingFileCreations map[string]bool   // path -> true
	pendingFileRemovals  map[string][]byte // path -> prior durable content
	pendingRenames       map[string]string // newPath -> oldPath

	// Operation counting for crash point enumeration
	totalIOOps      atomic.Int64
	crashAfterOps   atomic.Int64
	onCrashAfterOps func()
	crashed         atomic.Bool

	beforeWriteAt func(path string, p []byte, off int64)
	beforeSync    func(path string)
}

// NewFaultFS creates a new FaultFS wrapping an underlying FS.
func NewFaultFS(underlying FS) *FaultFS {
	return &FaultFS{
		underlying:           underlying,
		files:                make(map[string]*FaultFile),
		assertReuseRule:      true,
		assertWriteAheadRule: true,
		pendingFileCreations: make(map[string]bool),
		pendingFileRemovals:  make(map[string][]byte),
		pendingRenames:       make(map[string]string),
	}
}

// checkCrash checks if the operation count has reached the crash threshold.
func (f *FaultFS) checkCrash() error {
	ops := f.totalIOOps.Add(1)
	threshold := f.crashAfterOps.Load()
	if threshold > 0 && ops >= threshold {
		if f.crashed.CompareAndSwap(false, true) {
			f.mu.RLock()
			cb := f.onCrashAfterOps
			f.mu.RUnlock()
			if cb != nil {
				cb()
			}
		}
		return ErrCrashed
	}
	if f.crashed.Load() {
		return ErrCrashed
	}
	return nil
}

// TotalIOOps returns the total number of intercepted I/O operations.
func (f *FaultFS) TotalIOOps() int64 {
	return f.totalIOOps.Load()
}

// ResetCrash resets the crash state and operation counter.
func (f *FaultFS) ResetCrash() {
	f.totalIOOps.Store(0)
	f.crashAfterOps.Store(0)
	f.crashed.Store(false)
}

// SetCrashAfterOps sets a target I/O operation count at which to simulate a crash.
func (f *FaultFS) SetCrashAfterOps(count int64, fn func()) {
	f.crashAfterOps.Store(count)
	f.mu.Lock()
	f.onCrashAfterOps = fn
	f.mu.Unlock()
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

// SetWriteError sets an error to be returned on subsequent writes (sticky).
func (f *FaultFS) SetWriteError(err error) {
	f.SetWriteErrorSticky(err, true)
}

// SetWriteErrorSticky sets an error to be returned on writes with sticky flag.
func (f *FaultFS) SetWriteErrorSticky(err error, sticky bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeErr = err
	f.writeErrSticky = sticky
}

// SetReadError sets an error to be returned on subsequent reads (sticky).
func (f *FaultFS) SetReadError(err error) {
	f.SetReadErrorSticky(err, true)
}

// SetReadErrorSticky sets an error to be returned on reads with sticky flag.
func (f *FaultFS) SetReadErrorSticky(err error, sticky bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readErr = err
	f.readErrSticky = sticky
}

// SetSyncError sets an error to be returned on subsequent syncs (sticky).
func (f *FaultFS) SetSyncError(err error) {
	f.SetSyncErrorSticky(err, true)
}

// SetSyncErrorSticky sets an error to be returned on syncs with sticky flag.
func (f *FaultFS) SetSyncErrorSticky(err error, sticky bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncErr = err
	f.syncErrSticky = sticky
}

// SetDirSyncError sets an error to be returned on subsequent directory syncs.
func (f *FaultFS) SetDirSyncError(err error, sticky bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirSyncErr = err
	f.dirSyncErrSticky = sticky
}

// SetSkipSync enables or disables skipping fsync commitments to durable state.
func (f *FaultFS) SetSkipSync(skip bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skipSync = skip
}

// SetShortRead limits the maximum number of bytes returned by ReadAt.
func (f *FaultFS) SetShortRead(maxBytes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shortReadLimit = maxBytes
}

// SetShortWrite limits the maximum number of bytes written by WriteAt.
func (f *FaultFS) SetShortWrite(maxBytes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shortWriteLimit = maxBytes
}

// SetStaleBlock configures a stale page block to be returned on reads for a specific path and block index.
func (f *FaultFS) SetStaleBlock(path string, blockIdx uint64, staleData []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleaned := cleanPath(path)
	if f.staleBlocks == nil {
		f.staleBlocks = make(map[string]map[uint64][]byte)
	}
	if f.staleBlocks[cleaned] == nil {
		f.staleBlocks[cleaned] = make(map[uint64][]byte)
	}
	f.staleBlocks[cleaned][blockIdx] = bytes.Clone(staleData)
}

// ClearStaleBlocks clears all registered stale blocks.
func (f *FaultFS) ClearStaleBlocks() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staleBlocks = nil
}

// CorruptBlock introduces a bit flip in the block at blockIdx for the specified file.
func (f *FaultFS) CorruptBlock(path string, blockIdx uint64, byteOffset int, mask byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleaned := cleanPath(path)
	ff, exists := f.files[cleaned]
	if !exists {
		return fmt.Errorf("file not found: %s", cleaned)
	}
	ff.mu.Lock()
	defer ff.mu.Unlock()
	off := int(blockIdx*DefaultBlockSize) + byteOffset
	if off >= len(ff.pendingData) {
		return fmt.Errorf("offset %d out of range (size %d)", off, len(ff.pendingData))
	}
	ff.pendingData[off] ^= mask
	if off < len(ff.durableData) {
		ff.durableData[off] ^= mask
	}
	_, err := ff.underlying.WriteAt(ff.pendingData[off:off+1], int64(off))
	if err != nil {
		uFile, oErr := f.underlying.OpenFile(cleaned, os.O_RDWR, 0644)
		if oErr != nil {
			return errors.Join(err, oErr)
		}
		_, err = uFile.WriteAt(ff.pendingData[off:off+1], int64(off))
		sErr := uFile.Sync()
		cErr := uFile.Close()
		return errors.Join(err, sErr, cErr)
	}
	return ff.underlying.Sync()
}

// CorruptWALRecord introduces a bit flip in the WAL record with recordLSN in the given WAL file.
func (f *FaultFS) CorruptWALRecord(path string, recordLSN uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleaned := cleanPath(path)
	ff, exists := f.files[cleaned]
	if !exists {
		return fmt.Errorf("file not found: %s", cleaned)
	}
	ff.mu.Lock()
	defer ff.mu.Unlock()

	data := ff.pendingData
	if len(data) < SegmentHeaderSize {
		return errors.New("WAL file too short for header")
	}
	offset := SegmentHeaderSize
	for offset+RecordHeaderSize <= len(data) {
		if data[offset] == 0 {
			nextBlock := ((offset / DefaultBlockSize) + 1) * DefaultBlockSize
			if nextBlock <= offset || nextBlock >= len(data) {
				break
			}
			offset = nextBlock
			continue
		}
		r, err := DecodeRecord(bytes.NewReader(data[offset:]))
		if err != nil {
			break
		}
		recLen := RecordHeaderSize + len(r.Key) + len(r.Payload) + len(r.Token)
		if r.LSN == recordLSN {
			corruptOff := offset + RecordHeaderSize
			if len(r.Payload) > 0 {
				corruptOff = offset + RecordHeaderSize + len(r.Key)
			}
			data[corruptOff] ^= 0xff
			if corruptOff < len(ff.durableData) {
				ff.durableData[corruptOff] ^= 0xff
			}
			_, wErr := ff.underlying.WriteAt(data[corruptOff:corruptOff+1], int64(corruptOff))
			if wErr != nil {
				uFile, oErr := f.underlying.OpenFile(cleaned, os.O_RDWR, 0644)
				if oErr != nil {
					return errors.Join(wErr, oErr)
				}
				_, wErr = uFile.WriteAt(data[corruptOff:corruptOff+1], int64(corruptOff))
				sErr := uFile.Sync()
				cErr := uFile.Close()
				return errors.Join(wErr, sErr, cErr)
			}
			return ff.underlying.Sync()
		}
		offset += recLen
	}
	return fmt.Errorf("record with LSN %d not found in %s", recordLSN, cleaned)
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
	if err := f.checkCrash(); err != nil {
		return nil, err
	}

	cleaned := cleanPath(name)
	file, err := f.underlying.OpenFile(cleaned, flag, perm)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if flag&os.O_CREATE != 0 {
		if _, exists := f.files[cleaned]; !exists {
			f.pendingFileCreations[cleaned] = true
		}
	}

	ff, exists := f.files[cleaned]
	if !exists {
		var newErr error
		ff, newErr = newFaultFile(f, cleaned, file)
		if newErr != nil {
			closeErr := file.Close()
			return nil, errors.Join(newErr, closeErr)
		}
		f.files[cleaned] = ff
	} else {
		ff.underlying = file
	}
	return ff, nil
}

func (f *FaultFS) Create(name string) (File, error) {
	return f.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, StoreFileMode)
}

func (f *FaultFS) Open(name string) (File, error) {
	return f.OpenFile(name, os.O_RDONLY, 0)
}

func (f *FaultFS) Remove(name string) error {
	if err := f.checkCrash(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	cleaned := cleanPath(name)
	if ff, exists := f.files[cleaned]; exists {
		ff.mu.RLock()
		f.pendingFileRemovals[cleaned] = bytes.Clone(ff.durableData)
		ff.mu.RUnlock()
	}
	delete(f.files, cleaned)
	return f.underlying.Remove(name)
}

func (f *FaultFS) Rename(oldpath, newpath string) error {
	if err := f.checkCrash(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	oldClean := cleanPath(oldpath)
	newClean := cleanPath(newpath)
	f.pendingRenames[newClean] = oldClean
	if ff, exists := f.files[oldClean]; exists {
		f.files[newClean] = ff
		delete(f.files, oldClean)
	}
	return f.underlying.Rename(oldpath, newpath)
}

func (f *FaultFS) MkdirAll(path string, perm os.FileMode) error {
	if err := f.checkCrash(); err != nil {
		return err
	}
	return f.underlying.MkdirAll(path, perm)
}

func (f *FaultFS) ReadDir(dirname string) ([]os.DirEntry, error) {
	if err := f.checkCrash(); err != nil {
		return nil, err
	}
	return f.underlying.ReadDir(dirname)
}

func (f *FaultFS) SyncDir(dirname string) error {
	if err := f.checkCrash(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.dirSyncErr != nil {
		err := f.dirSyncErr
		if !f.dirSyncErrSticky {
			f.dirSyncErr = nil
		}
		return err
	}

	cleanedDir := cleanPath(dirname)
	// Commit pending directory metadata changes for this directory
	for path := range f.pendingFileCreations {
		if cleanPath(filepath.Dir(path)) == cleanedDir {
			delete(f.pendingFileCreations, path)
		}
	}
	for path := range f.pendingFileRemovals {
		if cleanPath(filepath.Dir(path)) == cleanedDir {
			delete(f.pendingFileRemovals, path)
		}
	}
	for newPath := range f.pendingRenames {
		if cleanPath(filepath.Dir(newPath)) == cleanedDir {
			delete(f.pendingRenames, newPath)
		}
	}

	return f.underlying.SyncDir(dirname)
}

// SetCrashed marks the filesystem as crashed or not crashed.
// When crashed is true, all subsequent I/O operations return ErrCrashed.
func (f *FaultFS) SetCrashed(crashed bool) {
	f.crashed.Store(crashed)
}

// PowerLoss simulates a power outage or hardware reset.
// Pending writes in the device's volatile write cache may be dropped, reordered, or torn.
// Non-fsynced directory metadata changes are lost if LostMetadata is true.
func (f *FaultFS) PowerLoss(opts PowerLossOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if opts.Rand == nil {
		opts.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	if opts.LostMetadata {
		// Revert non-fsynced file creations
		for path := range f.pendingFileCreations {
			if rErr := f.underlying.Remove(path); rErr != nil && !os.IsNotExist(rErr) {
				return rErr
			}
			delete(f.files, path)
		}
		f.pendingFileCreations = make(map[string]bool)

		// Revert non-fsynced file removals
		for path, durableContent := range f.pendingFileRemovals {
			file, err := f.underlying.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			if _, wErr := file.WriteAt(durableContent, 0); wErr != nil {
				cErr := file.Close()
				return errors.Join(wErr, cErr)
			}
			if sErr := file.Sync(); sErr != nil {
				cErr := file.Close()
				return errors.Join(sErr, cErr)
			}
			if cErr := file.Close(); cErr != nil {
				return cErr
			}
		}
		f.pendingFileRemovals = make(map[string][]byte)

		// Revert non-fsynced renames
		for newPath, oldPath := range f.pendingRenames {
			if rErr := f.underlying.Rename(newPath, oldPath); rErr != nil && !os.IsNotExist(rErr) {
				return rErr
			}
			if ff, exists := f.files[newPath]; exists {
				f.files[oldPath] = ff
				delete(f.files, newPath)
			}
		}
		f.pendingRenames = make(map[string]string)
	}

	var errs []error
	for _, ff := range f.files {
		ff.mu.Lock()
		if err := ff.powerLossLocked(opts); err != nil {
			errs = append(errs, err)
		}
		ff.mu.Unlock()
	}
	return errors.Join(errs...)
}

// ProcessCrash simulates a process death where OS buffer cache survives and is flushed to disk.
func (f *FaultFS) ProcessCrash() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for _, ff := range f.files {
		ff.mu.Lock()
		truncErr := ff.underlying.Truncate(int64(len(ff.pendingData)))
		_, writeErr := ff.underlying.WriteAt(ff.pendingData, 0)
		syncErr := ff.underlying.Sync()
		ff.mu.Unlock()
		if err := errors.Join(truncErr, writeErr, syncErr); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Crash simulates a crash across all files in this filesystem.
// If dropUnsynced is true, all un-fsynced writes are discarded.
// If tearFraction > 0, randomly tears un-fsynced blocks.
func (f *FaultFS) Crash(dropUnsynced bool, tearFraction float64) error {
	return f.PowerLoss(PowerLossOptions{
		DropUnsynced: dropUnsynced,
		TearFraction: tearFraction,
	})
}

// FaultFile intercepts reads, writes, and syncs on a specific file.
type FaultFile struct {
	fs         *FaultFS
	name       string
	underlying File
	mu         sync.RWMutex

	durableData    []byte
	pendingData    []byte
	pendingBlocks  map[uint64]bool
	pendingSectors map[uint64]bool

	// Map of logicalPage -> newest durable range (heap files only)
	durablePages map[uint64]DurablePageRange

	isHeapFile bool
	isWALFile  bool
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
		fs:             fs,
		name:           name,
		underlying:     underlying,
		durableData:    bytes.Clone(initial),
		pendingData:    bytes.Clone(initial),
		pendingBlocks:  make(map[uint64]bool),
		pendingSectors: make(map[uint64]bool),
		durablePages:   make(map[uint64]DurablePageRange),
		isHeapFile:     isHeap,
		isWALFile:      isWAL,
	}

	if isHeap && len(initial) > 0 {
		ff.rebuildDurablePagesLocked()
	}
	return ff, nil
}

func (f *FaultFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.fs.checkCrash(); err != nil {
		return 0, err
	}

	f.fs.mu.Lock()
	readErr := f.fs.readErr
	if readErr != nil && !f.fs.readErrSticky {
		f.fs.readErr = nil
	}
	shortRead := f.fs.shortReadLimit
	staleMap := f.fs.staleBlocks[f.name]
	f.fs.mu.Unlock()

	if readErr != nil {
		return 0, readErr
	}

	if shortRead > 0 && len(p) > shortRead {
		p = p[:shortRead]
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if off < 0 {
		return 0, errors.New("negative offset")
	}

	// Check for injected stale block read
	if staleMap != nil {
		bIdx := uint64(off / DefaultBlockSize)
		if staleData, ok := staleMap[bIdx]; ok && len(staleData) > 0 {
			blockOff := int(off % DefaultBlockSize)
			if blockOff < len(staleData) {
				n := copy(p, staleData[blockOff:])
				return n, nil
			}
		}
	}

	if off >= int64(len(f.pendingData)) {
		return 0, io.EOF
	}
	n := copy(p, f.pendingData[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *FaultFile) WriteAt(p []byte, off int64) (int, error) {
	if err := f.fs.checkCrash(); err != nil {
		return 0, err
	}

	f.fs.mu.Lock()
	writeErr := f.fs.writeErr
	if writeErr != nil && !f.fs.writeErrSticky {
		f.fs.writeErr = nil
	}
	assertReuse := f.fs.assertReuseRule
	assertWAL := f.fs.assertWriteAheadRule
	maxFsyncedLSN := f.fs.MaxFsyncedLSN()
	beforeWriteAt := f.fs.beforeWriteAt
	shortWrite := f.fs.shortWriteLimit
	f.fs.mu.Unlock()

	if beforeWriteAt != nil {
		beforeWriteAt(f.name, p, off)
	}

	if writeErr != nil {
		return 0, writeErr
	}

	if shortWrite > 0 && len(p) > shortWrite {
		p = p[:shortWrite]
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

	// Track pending 512-byte sectors
	startSec := uint64(off / SectorSize)
	endSec := uint64((off + int64(len(p)) + SectorSize - 1) / SectorSize)
	for s := startSec; s < endSec; s++ {
		f.pendingSectors[s] = true
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
	if err := f.fs.checkCrash(); err != nil {
		return err
	}

	f.fs.mu.Lock()
	syncErr := f.fs.syncErr
	if syncErr != nil && !f.fs.syncErrSticky {
		f.fs.syncErr = nil
	}
	beforeSync := f.fs.beforeSync
	f.fs.mu.Unlock()

	if beforeSync != nil {
		beforeSync(f.name)
	}

	if syncErr != nil {
		return syncErr
	}

	f.fs.mu.RLock()
	skipSync := f.fs.skipSync
	f.fs.mu.RUnlock()

	if skipSync {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Commit pending writes to durable state
	f.durableData = bytes.Clone(f.pendingData)
	f.pendingBlocks = make(map[uint64]bool)
	f.pendingSectors = make(map[uint64]bool)

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

// powerLossLocked executes power loss simulation on this file while f.mu is held.
func (f *FaultFile) powerLossLocked(opts PowerLossOptions) error {
	if opts.TruncateUnsyncedSize && len(f.pendingData) > len(f.durableData) {
		f.pendingData = f.pendingData[:len(f.durableData)]
	}

	if opts.DropUnsynced {
		f.pendingData = bytes.Clone(f.durableData)
		f.pendingBlocks = make(map[uint64]bool)
		f.pendingSectors = make(map[uint64]bool)
	} else if opts.RandomSubset && len(f.pendingSectors) > 0 {
		// Reorder/subset: randomly revert some pending 512-byte sectors to durable
		for sIdx := range f.pendingSectors {
			if opts.Rand != nil && opts.Rand.Float64() < 0.5 {
				secStart := int(sIdx * SectorSize)
				secEnd := secStart + SectorSize
				if secStart < len(f.durableData) {
					dEnd := secEnd
					if dEnd > len(f.durableData) {
						dEnd = len(f.durableData)
					}
					copy(f.pendingData[secStart:dEnd], f.durableData[secStart:dEnd])
				} else if secStart < len(f.pendingData) {
					pEnd := secEnd
					if pEnd > len(f.pendingData) {
						pEnd = len(f.pendingData)
					}
					clear(f.pendingData[secStart:pEnd])
				}
			}
		}
	}

	if opts.TearFraction > 0 && len(f.pendingSectors) > 0 {
		// Randomly tear 512-byte sectors
		for sIdx := range f.pendingSectors {
			if opts.Rand != nil && opts.Rand.Float64() < opts.TearFraction {
				secStart := int(sIdx * SectorSize)
				if secStart+SectorSize <= len(f.pendingData) {
					// Corrupt last 64 bytes of the sector
					for k := 0; k < 64; k++ {
						f.pendingData[secStart+SectorSize-1-k] ^= 0xff
					}
				}
			}
		}
	}

	// Write crashed image to underlying and sync
	truncErr := f.underlying.Truncate(int64(len(f.pendingData)))
	_, writeErr := f.underlying.WriteAt(f.pendingData, 0)
	syncErr := f.underlying.Sync()

	f.pendingBlocks = make(map[uint64]bool)
	f.pendingSectors = make(map[uint64]bool)

	if f.isHeapFile {
		f.rebuildDurablePagesLocked()
	}
	if f.isWALFile {
		f.updateMaxFsyncedWAL_LSNLocked()
	}

	return errors.Join(truncErr, writeErr, syncErr)
}

// Crash simulates a crash on this file.
func (f *FaultFile) Crash(dropUnsynced bool, tearFraction float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.powerLossLocked(PowerLossOptions{
		DropUnsynced: dropUnsynced,
		TearFraction: tearFraction,
	})
}

func (f *FaultFile) Truncate(size int64) error {
	if err := f.fs.checkCrash(); err != nil {
		return err
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
	return f.underlying.Close()
}

func (f *FaultFile) Size() (int64, error) {
	if err := f.fs.checkCrash(); err != nil {
		return 0, err
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	return int64(len(f.pendingData)), nil
}

func (f *FaultFile) SyscallConn() (any, error) {
	return f.underlying.SyscallConn()
}
