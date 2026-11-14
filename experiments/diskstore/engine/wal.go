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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	// WALMagic is "WAL1" in big endian.
	WALMagic uint32 = 0x57414C31

	// WALVersion is 1.
	WALVersion uint32 = 1

	// SegmentHeaderSize is 32 bytes: Magic(4) + Version(4) + Reserved(8) + DBID(16).
	SegmentHeaderSize = 32

	// DefaultMaxSegmentSize is 16 MiB.
	DefaultMaxSegmentSize = 16 * 1024 * 1024

	// WALBlockSize is 4 KiB block alignment for direct I/O WAL writes.
	WALBlockSize = 4096

	// DefaultWALBufferSize is 1 MiB.
	DefaultWALBufferSize = 1024 * 1024
)

var (
	// ErrRecordTooLarge is returned when a record exceeds the WAL buffer capacity.
	ErrRecordTooLarge = errors.New("record exceeds WAL buffer size")

	// ErrCorruptWAL indicates corruption in a WAL segment outside the torn tail.
	ErrCorruptWAL = errors.New("corrupt WAL")
)

// MonotonicTime represents an opaque monotonic timestamp in nanoseconds.
// It is 8 bytes, lightweight, and prevents calling non-monotonic wall-clock functions.
type MonotonicTime int64

// IsZero reports whether m represents the zero timestamp.
func (m MonotonicTime) IsZero() bool {
	return m == 0
}

// Sub returns the duration elapsed between m and earlier timestamp other.
func (m MonotonicTime) Sub(other MonotonicTime) time.Duration {
	return time.Duration(m - other)
}

// Clock abstracts current monotonic time for deterministic testing.
type Clock interface {
	Now() MonotonicTime
}

var processStart = time.Now()

type realClock struct{}

func (realClock) Now() MonotonicTime {
	// time.Since utilizes the monotonic clock reading present in processStart and time.Now().
	// We add 1 nanosecond so valid readings are non-zero, allowing IsZero()
	// to cleanly distinguish an uninitialized timestamp from a valid reading.
	return MonotonicTime(time.Since(processStart)) + 1
}

// WAL manages appending, syncing, and segment lifecycle of the write-ahead log.
type WAL struct {
	fs   FS
	dir  string
	dbID [16]byte

	appendMu sync.Mutex // Serializes record appenders so records are never interleaved
	mu       sync.Mutex // Protects buffer state, offsets, and coordination with background writer

	bufSize int       // buffer capacity (e.g. 1 MiB), multiple of WALBlockSize
	bufs    [2][]byte // two aligned buffers for contiguous double-buffering

	activeFile     File
	activePath     string
	activeStartLSN uint64

	appendOff  int64 // physical file offset in active segment where next record appends
	flushedOff int64 // physical file offset in active segment up to which data has been written to disk

	nextLSN         uint64 // Next monotonic LSN to allocate under mu
	lastAppendedLSN uint64 // Highest LSN successfully written to buffer
	maxLSN          atomic.Uint64
	fsyncedLSN      atomic.Uint64 // Highest LSN covered by fdatasync
	maxSegSize      int64
	quarantine      QuarantineOptions
	createdLSNs     map[uint64]bool // Asserts never reuse/recycle segment file names

	writing   bool
	writeCond *sync.Cond
	syncCond  *sync.Cond

	clock              Clock
	tickInterval       time.Duration
	oldestUnsyncedTime MonotonicTime
	tailBlockOpenTime  MonotonicTime

	wakeCh        chan struct{}
	bgStop        chan struct{}
	bgDone        chan struct{}
	stickyErr     error
	onFailure     func(error)
	closed        bool
	syncRequested bool
}

// WALOptions configures a WAL instance.
type WALOptions struct {
	MaxSegmentSize int64
	OnFailure      func(error)
	Clock          Clock
	TickInterval   time.Duration
	BufferSize     int
	Quarantine     QuarantineOptions
}

// OpenWAL opens or creates a WAL in the given directory.
func OpenWAL(fs FS, dir string, dbID [16]byte, initialLSN uint64, opts ...WALOptions) (*WAL, error) {
	if err := fs.MkdirAll(dir, StoreDirMode); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}
	if err := fs.SyncDir(dir); err != nil {
		return nil, fmt.Errorf("failed to sync WAL directory: %w", err)
	}

	maxSegSize := int64(DefaultMaxSegmentSize)
	bufSize := DefaultWALBufferSize
	var qOpts QuarantineOptions
	var onFailure func(error)
	var clock Clock = realClock{}
	var tickInterval time.Duration
	if len(opts) > 0 {
		if opts[0].MaxSegmentSize > 0 {
			maxSegSize = opts[0].MaxSegmentSize
		}
		qOpts = opts[0].Quarantine
		if opts[0].BufferSize > 0 {
			bufSize = opts[0].BufferSize
			if bufSize < WALBlockSize {
				bufSize = WALBlockSize
			}
			if rem := bufSize % WALBlockSize; rem != 0 {
				bufSize += WALBlockSize - rem
			}
		}
		onFailure = opts[0].OnFailure
		if opts[0].Clock != nil {
			clock = opts[0].Clock
		}
		if opts[0].TickInterval > 0 {
			tickInterval = opts[0].TickInterval
		}
	}

	lostDir := filepath.Join(dir, "lost+found")
	if qOpts.Dir == "" {
		qOpts.Dir = lostDir
	}

	w := &WAL{
		fs:              fs,
		dir:             dir,
		dbID:            dbID,
		bufSize:         bufSize,
		bufs:            [2][]byte{AllocateAlignedBlock(bufSize), AllocateAlignedBlock(bufSize)},
		maxSegSize:      maxSegSize,
		quarantine:      qOpts,
		createdLSNs:     make(map[uint64]bool),
		nextLSN:         initialLSN + 1,
		lastAppendedLSN: initialLSN,
		clock:           clock,
		tickInterval:    tickInterval,
		wakeCh:          make(chan struct{}, 1),
		bgStop:          make(chan struct{}),
		bgDone:          make(chan struct{}),
		onFailure:       onFailure,
	}
	w.syncCond = sync.NewCond(&w.mu)
	w.writeCond = sync.NewCond(&w.mu)

	// Scan existing segments to record used start LSNs
	segments, err := w.listSegments()
	if err != nil {
		return nil, err
	}

	var abandoned []string
	for _, seg := range segments {
		if seg.startLSN > initialLSN {
			abandoned = append(abandoned, seg.name)
			continue
		}
		w.createdLSNs[seg.startLSN] = true
	}
	if _, err := quarantineFiles(context.Background(), w.fs, w.dir, abandoned, w.quarantine, false); err != nil {
		return nil, fmt.Errorf("failed to quarantine abandoned segments: %w", err)
	}

	w.maxLSN.Store(initialLSN)
	w.fsyncedLSN.Store(initialLSN)

	go w.bgWriter()

	return w, nil
}

type segmentMeta struct {
	path     string
	name     string
	startLSN uint64
	size     int64
}

func (w *WAL) listSegments() ([]segmentMeta, error) {
	entries, err := w.fs.ReadDir(w.dir)
	if err != nil {
		return nil, err
	}

	var segments []segmentMeta
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".wal")
		lsn, err := strconv.ParseUint(base, 10, 64)
		if err != nil {
			continue // ignore non-matching names
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		segments = append(segments, segmentMeta{
			path:     filepath.Join(w.dir, entry.Name()),
			name:     entry.Name(),
			startLSN: lsn,
			size:     info.Size(),
		})
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].startLSN < segments[j].startLSN
	})
	return segments, nil
}

func segmentFileName(startLSN uint64) string {
	return fmt.Sprintf("%020d.wal", startLSN)
}

func (w *WAL) bgWriter() {
	defer close(w.bgDone)

	tickInterval := 100 * time.Millisecond
	if w.tickInterval > 0 {
		tickInterval = w.tickInterval
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.bgStop:
			w.flushQueueAndSync(true)
			return
		case <-w.wakeCh:
			w.flushQueueAndSync(false)
		case <-ticker.C:
			w.flushQueueAndSync(false)
		}
	}
}

func (w *WAL) setStickyErrLocked(err error) {
	if w.stickyErr == nil && err != nil {
		w.stickyErr = err
		if w.onFailure != nil {
			w.onFailure(err)
		}
		w.syncCond.Broadcast()
		w.writeCond.Broadcast()
	}
}

func stringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func (w *WAL) zeroRangeInBuffer(start, end int64) {
	curr := start
	for curr < end {
		chunk := curr / int64(w.bufSize)
		bufIdx := chunk % 2
		startInBuf := int(curr % int64(w.bufSize))
		chunkEnd := (chunk + 1) * int64(w.bufSize)
		if chunkEnd > end {
			chunkEnd = end
		}
		lenToZero := int(chunkEnd - curr)
		clearBytes(w.bufs[bufIdx][startInBuf : startInBuf+lenToZero])
		curr = chunkEnd
	}
}

type writeSlice struct {
	offset int64
	data   []byte
}

func (w *WAL) collectWriteSlices(endOff int64) []writeSlice {
	var slices []writeSlice
	currOff := w.flushedOff
	for currOff < endOff {
		chunk := currOff / int64(w.bufSize)
		bufIdx := chunk % 2
		startInBuf := int(currOff % int64(w.bufSize))
		chunkEnd := (chunk + 1) * int64(w.bufSize)
		if chunkEnd > endOff {
			chunkEnd = endOff
		}
		lenToWrite := int(chunkEnd - currOff)
		slices = append(slices, writeSlice{
			offset: currOff,
			data:   w.bufs[bufIdx][startInBuf : startInBuf+lenToWrite],
		})
		currOff = chunkEnd
	}
	return slices
}

// flushQueueAndSync flushes queued blocks and syncs without holding w.mu during I/O.
func (w *WAL) flushQueueAndSync(isStop bool) {
	w.mu.Lock()
	if w.stickyErr != nil {
		w.mu.Unlock()
		return
	}

	now := w.clock.Now()
	timeoutSync := !w.oldestUnsyncedTime.IsZero() && now.Sub(w.oldestUnsyncedTime) >= 5*time.Second
	doSync := isStop || w.syncRequested || timeoutSync

	for w.writing {
		w.writeCond.Wait()
		if w.stickyErr != nil {
			w.mu.Unlock()
			return
		}
	}

	if w.activeFile == nil {
		w.mu.Unlock()
		return
	}

	if !doSync && (w.appendOff/int64(WALBlockSize)) == (w.flushedOff/int64(WALBlockSize)) {
		w.mu.Unlock()
		return
	}

	if doSync && w.appendOff%int64(WALBlockSize) != 0 {
		paddedEnd := ((w.appendOff / int64(WALBlockSize)) + 1) * int64(WALBlockSize)
		w.zeroRangeInBuffer(w.appendOff, paddedEnd)
		w.appendOff = paddedEnd
		w.tailBlockOpenTime = 0
	}

	var endOff int64
	var targetLSN uint64
	if doSync {
		endOff = w.appendOff
		targetLSN = w.lastAppendedLSN
	} else {
		endOff = (w.appendOff / int64(WALBlockSize)) * int64(WALBlockSize)
	}

	if endOff <= w.flushedOff && !doSync {
		w.mu.Unlock()
		return
	}

	slices := w.collectWriteSlices(endOff)
	syncFile := w.activeFile
	w.writing = true
	w.mu.Unlock()

	var writeErr error
	for _, ws := range slices {
		if _, err := syncFile.WriteAt(ws.data, ws.offset); err != nil {
			writeErr = fmt.Errorf("failed to write WAL block at offset %d: %w", ws.offset, err)
			break
		}
	}

	var syncErr error
	if writeErr == nil && doSync && syncFile != nil {
		if err := syncFile.Sync(); err != nil {
			syncErr = fmt.Errorf("failed to fsync WAL segment: %w", err)
		}
	}

	w.mu.Lock()
	w.writing = false

	flushErr := errors.Join(writeErr, syncErr)
	if flushErr != nil {
		w.setStickyErrLocked(flushErr)
		w.mu.Unlock()
		return
	}

	if endOff > w.flushedOff {
		w.flushedOff = endOff
	}
	w.writeCond.Broadcast()

	if doSync {
		if targetLSN > w.fsyncedLSN.Load() {
			w.fsyncedLSN.Store(targetLSN)
		}
		if w.fsyncedLSN.Load() >= w.lastAppendedLSN && w.appendOff == w.flushedOff {
			w.syncRequested = false
			w.oldestUnsyncedTime = 0
			w.tailBlockOpenTime = 0
		}
		w.syncCond.Broadcast()
	}
	w.mu.Unlock()
}

// flushQueueAndSyncDirectLocked flushes and syncs synchronously while w.mu is held.
func (w *WAL) flushQueueAndSyncDirectLocked(doSync bool) error {
	if w.stickyErr != nil {
		return w.stickyErr
	}
	if w.activeFile == nil {
		return nil
	}

	if doSync && w.appendOff%int64(WALBlockSize) != 0 {
		paddedEnd := ((w.appendOff / int64(WALBlockSize)) + 1) * int64(WALBlockSize)
		w.zeroRangeInBuffer(w.appendOff, paddedEnd)
		w.appendOff = paddedEnd
		w.tailBlockOpenTime = 0
	}

	var endOff int64
	var targetLSN uint64
	if doSync {
		endOff = w.appendOff
		targetLSN = w.lastAppendedLSN
	} else {
		endOff = (w.appendOff / int64(WALBlockSize)) * int64(WALBlockSize)
	}

	slices := w.collectWriteSlices(endOff)
	for _, ws := range slices {
		if _, err := w.activeFile.WriteAt(ws.data, ws.offset); err != nil {
			w.setStickyErrLocked(fmt.Errorf("failed to write WAL block at offset %d: %w", ws.offset, err))
			return w.stickyErr
		}
	}

	if endOff > w.flushedOff {
		w.flushedOff = endOff
	}

	if doSync {
		if err := w.activeFile.Sync(); err != nil {
			w.setStickyErrLocked(fmt.Errorf("failed to fsync WAL segment: %w", err))
			return w.stickyErr
		}
		if targetLSN > w.fsyncedLSN.Load() {
			w.fsyncedLSN.Store(targetLSN)
		}
		w.oldestUnsyncedTime = 0
		w.tailBlockOpenTime = 0
		w.syncRequested = false
		w.syncCond.Broadcast()
	}
	w.writeCond.Broadcast()
	return nil
}

// createSegmentLocked creates a new immutable WAL segment named by starting LSN.
// Invariant: Never reuse or recycle a segment file name. Fsync the directory after creation.
func (w *WAL) createSegmentLocked(startLSN uint64) error {
	if w.createdLSNs[startLSN] {
		return fmt.Errorf("invariant violation: segment file name for LSN %d already used", startLSN)
	}

	// Flush and sync existing active segment before rolling
	if w.activeFile != nil {
		for w.writing {
			w.writeCond.Wait()
			if w.stickyErr != nil {
				return w.stickyErr
			}
		}
		if err := w.flushQueueAndSyncDirectLocked(true); err != nil {
			return err
		}
		if err := w.activeFile.Close(); err != nil {
			return fmt.Errorf("failed to close superseded active segment: %w", err)
		}
		w.activeFile = nil
	}

	name := segmentFileName(startLSN)
	path := filepath.Join(w.dir, name)

	openFlags := os.O_RDWR | os.O_CREATE | DirectIOOpenFlag()
	f, err := w.fs.OpenFile(path, openFlags, StoreFileMode)
	if err != nil {
		if DirectIOOpenFlag() != 0 {
			GlobalMetrics.DirectIOFallbackCount.Add(1)
		}
		// Fallback without DirectIOOpenFlag if not supported by FS
		f, err = w.fs.OpenFile(path, os.O_RDWR|os.O_CREATE, StoreFileMode)
		if err != nil {
			return fmt.Errorf("failed to create WAL segment %s: %w", name, err)
		}
	}

	// Fsync the directory after creating a segment
	if err := w.fs.SyncDir(w.dir); err != nil {
		closeErr := f.Close()
		return errors.Join(fmt.Errorf("failed to fsync directory after segment creation: %w", err), closeErr)
	}

	w.activeFile = f
	w.activePath = path
	w.activeStartLSN = startLSN
	w.flushedOff = 0
	w.appendOff = SegmentHeaderSize
	w.oldestUnsyncedTime = 0
	w.tailBlockOpenTime = 0
	w.createdLSNs[startLSN] = true

	// Write segment header into buffer 0 at offset 0..32
	clearBytes(w.bufs[0][:SegmentHeaderSize])
	binary.BigEndian.PutUint32(w.bufs[0][0:4], WALMagic)
	binary.BigEndian.PutUint32(w.bufs[0][4:8], WALVersion)
	// bytes 8..16 zeroed
	copy(w.bufs[0][16:32], w.dbID[:])

	return nil
}

// NextLSN increments and returns the next 64-bit monotonic LSN.
func (w *WAL) NextLSN() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	lsn := w.nextLSN
	w.nextLSN++
	if lsn > w.maxLSN.Load() {
		w.maxLSN.Store(lsn)
	}
	return lsn
}

// MaxLSN returns the current maximum allocated LSN.
func (w *WAL) MaxLSN() uint64 {
	return w.maxLSN.Load()
}

// FsyncedLSN returns the maximum LSN that has been fsynced.
func (w *WAL) FsyncedLSN() uint64 {
	return w.fsyncedLSN.Load()
}

// DurableLSN returns the maximum LSN confirmed durable by fdatasync.
func (w *WAL) DurableLSN() uint64 {
	return w.fsyncedLSN.Load()
}

// Append appends a record to the WAL.
// No fsync is performed on commit.
func (w *WAL) Append(r Record) error {
	_, err := w.AppendRecord(&r)
	return err
}

// AppendRecord appends a record to the WAL, assigning LSN under WAL lock if LSN == 0.
func (w *WAL) AppendRecord(r *Record) (uint64, error) {
	w.appendMu.Lock()
	defer w.appendMu.Unlock()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stickyErr != nil {
		return 0, w.stickyErr
	}
	if w.closed {
		return 0, errors.New("wal is closed")
	}

	if r.LSN == 0 {
		r.LSN = w.nextLSN
		w.nextLSN++
	} else if r.LSN >= w.nextLSN {
		w.nextLSN = r.LSN + 1
	}
	if r.LSN > w.maxLSN.Load() {
		w.maxLSN.Store(r.LSN)
	}

	keyBytes := stringToBytes(r.Key)
	payloadBytes := r.Payload
	keyLen := len(keyBytes)
	payloadLen := len(payloadBytes)
	recLen := RecordHeaderSize + keyLen + payloadLen

	now := w.clock.Now()
	if w.oldestUnsyncedTime.IsZero() {
		w.oldestUnsyncedTime = now
	}

	// If no active file or record exceeds segment size, roll segment
	if w.activeFile == nil || w.appendOff+int64(recLen) > w.maxSegSize {
		if err := w.createSegmentLocked(r.LSN); err != nil {
			return 0, err
		}
	}

	if w.tailBlockOpenTime.IsZero() {
		w.tailBlockOpenTime = now
	}

	// Format record header into 32-byte stack buffer and compute CRC incrementally
	var hdr [RecordHeaderSize]byte
	hdr[0] = RecordMagic
	hdr[1] = RecordFormatVersion
	hdr[2] = byte(r.Type)
	hdr[3] = 0 // reserved
	binary.BigEndian.PutUint64(hdr[4:12], r.LSN)
	binary.BigEndian.PutUint64(hdr[12:20], r.RedoStartLSN)
	binary.BigEndian.PutUint32(hdr[20:24], uint32(keyLen))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(payloadLen))
	// bytes 28..32 are zero for CRC calculation

	crc := crc32.Update(0, castagnoliTable, hdr[:])
	if keyLen > 0 {
		crc = crc32.Update(crc, castagnoliTable, keyBytes)
	}
	if payloadLen > 0 {
		crc = crc32.Update(crc, castagnoliTable, payloadBytes)
	}
	binary.BigEndian.PutUint32(hdr[28:32], crc)

	copyToRing := func(p []byte) error {
		for len(p) > 0 {
			chunk := w.appendOff / int64(w.bufSize)
			bufIdx := chunk % 2
			startInBuf := int(w.appendOff % int64(w.bufSize))

			if chunk >= 2 {
				requiredFlushedOff := (chunk - 1) * int64(w.bufSize)
				for w.flushedOff < requiredFlushedOff {
					if w.stickyErr != nil {
						return w.stickyErr
					}
					if w.closed {
						return errors.New("wal is closed")
					}
					select {
					case w.wakeCh <- struct{}{}:
					default:
					}
					w.writeCond.Wait()
				}
			}

			space := w.bufSize - startInBuf
			toCopy := len(p)
			if toCopy > space {
				toCopy = space
			}
			copy(w.bufs[bufIdx][startInBuf:startInBuf+toCopy], p[:toCopy])
			p = p[toCopy:]
			w.appendOff += int64(toCopy)

			if w.appendOff%int64(w.bufSize) == 0 {
				select {
				case w.wakeCh <- struct{}{}:
				default:
				}
			}
		}
		return nil
	}

	if err := copyToRing(hdr[:]); err != nil {
		return 0, err
	}
	if keyLen > 0 {
		if err := copyToRing(keyBytes); err != nil {
			return 0, err
		}
	}
	if payloadLen > 0 {
		if err := copyToRing(payloadBytes); err != nil {
			return 0, err
		}
	}

	w.lastAppendedLSN = r.LSN

	return r.LSN, nil
}

// Sync flushes and fsyncs the active WAL file.
func (w *WAL) Sync() error {
	w.mu.Lock()
	targetLSN := w.lastAppendedLSN
	w.mu.Unlock()
	return w.SyncThrough(targetLSN)
}

// SyncThrough ensures that the WAL is fsynced at least through the given LSN.
// This fulfills the write-ahead rule: before writing any page with LSN L, the log must be fsynced through L.
func (w *WAL) SyncThrough(lsn uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for {
		if w.stickyErr != nil {
			return w.stickyErr
		}
		if w.fsyncedLSN.Load() >= lsn {
			return nil
		}
		if w.fsyncedLSN.Load() >= w.lastAppendedLSN && w.appendOff == w.flushedOff {
			// All appended WAL records are already fsynced
			return nil
		}
		w.syncRequested = true
		select {
		case w.wakeCh <- struct{}{}:
		default:
		}
		w.syncCond.Wait()
	}
}

// Flush flushes all buffered records and fsyncs the WAL.
func (w *WAL) Flush() error {
	w.mu.Lock()
	targetLSN := w.lastAppendedLSN
	w.mu.Unlock()
	return w.SyncThrough(targetLSN)
}

// TruncateBefore removes whole completed segment files whose records are all strictly prior to oldestNeededLSN.
// Finished segments are deleted only when fully covered by a completed checkpoint.
func (w *WAL) TruncateBefore(oldestNeededLSN uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	segments, err := w.listSegments()
	if err != nil {
		return err
	}

	// Never delete the active segment
	var deletedAny bool
	for i := 0; i < len(segments)-1; i++ {
		nextStart := segments[i+1].startLSN
		// If next segment starts at or before oldestNeededLSN, this whole segment is strictly before oldestNeededLSN
		if nextStart <= oldestNeededLSN {
			if err := w.fs.Remove(segments[i].path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete truncated segment %s: %w", segments[i].name, err)
			}
			deletedAny = true
		}
	}

	if deletedAny {
		return w.fs.SyncDir(w.dir)
	}
	return nil
}

// Close closes the WAL and flushes remaining writes.
func (w *WAL) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.syncCond.Broadcast()
	w.writeCond.Broadcast()
	close(w.bgStop)
	w.mu.Unlock()

	<-w.bgDone

	w.mu.Lock()
	defer w.mu.Unlock()

	var errs []error
	if w.activeFile != nil {
		syncErr := w.activeFile.Sync()
		closeErr := w.activeFile.Close()
		w.activeFile = nil
		if syncErr != nil || closeErr != nil {
			errs = append(errs, errors.Join(syncErr, closeErr))
		}
	}
	if w.stickyErr != nil {
		errs = append(errs, w.stickyErr)
	}
	return errors.Join(errs...)
}

// WALIterator replays records across segment files starting from a given LSN.
//
// Invariants:
//  1. The WAL appends records only to the last segment, and LSNs increase by one across segments.
//  2. The engine acknowledges a Put only after it fsyncs the WAL through that record's LSN.
//  3. The engine fsyncs a segment before it creates the next one (createSegmentLocked).
//
// The engine organizes the WAL as a sequence of segments and appends records only to the last one.
// LSNs increase by one across segments without gaps.
//
// The engine acknowledges a Put only after it fsyncs the WAL through that record's LSN. After a
// crash, the storage device may lose or corrupt records that the engine wrote after its last fsync.
// That is the torn tail. The iterator safely drops that tail because the engine never acknowledged
// those records to a caller.
//
// Before creating a new segment in createSegmentLocked, the engine flushes and fsyncs the active
// segment. Therefore, the engine makes every segment except the last fully durable before it accepts
// any subsequent writes, so only the last segment can hold a torn tail.
//
// Because the engine makes earlier segments durable before rotation, any bad record (torn data, CRC
// failure, decode failure, implausible field length, or LSN gap) in an earlier segment indicates
// corruption of acknowledged data. Similarly, a subsequent segment that does not start at the expected
// LSN indicates missing acknowledged data. In either case, the iterator returns ErrCorruptWAL and halts
// recovery. In the last segment, a bad record indicates an unacknowledged tail, so the iterator treats
// it as the end of the log and returns io.EOF.
//
// In createSegmentLocked, the engine creates and fsyncs a new segment file before it flushes the
// segment header. A crash during that window leaves an empty or headerless last segment on disk. The
// iterator treats that empty or headerless file in the last segment as the end of the log, allowing
// recovery to succeed and preserve acknowledged records.
//
// The limitation: the iterator cannot distinguish corruption inside the fsynced portion of the last
// segment from a torn tail, so it drops that corrupted record and any records following it.
type WALIterator struct {
	fs          FS
	segments    []segmentMeta
	dbID        [16]byte
	currSegIdx  int
	currFile    File
	currOffset  int64
	currSegSize int64 // Cached size of currFile; a segment's size doesn't change while recovery reads it.
	startLSN    uint64
	expectedLSN uint64
	done        bool
}

// NewWALIterator creates an iterator to replay records from startLSN.
func NewWALIterator(fs FS, dir string, dbID [16]byte, startLSN uint64) (*WALIterator, error) {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var segments []segmentMeta
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".wal")
		lsn, err := strconv.ParseUint(base, 10, 64)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		segments = append(segments, segmentMeta{
			path:     filepath.Join(dir, entry.Name()),
			name:     entry.Name(),
			startLSN: lsn,
			size:     info.Size(),
		})
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].startLSN < segments[j].startLSN
	})

	// Find the segment that could contain startLSN
	startIdx := 0
	for i, seg := range segments {
		if seg.startLSN <= startLSN {
			startIdx = i
		} else {
			break
		}
	}

	it := &WALIterator{
		fs:          fs,
		segments:    segments,
		dbID:        dbID,
		currSegIdx:  startIdx - 1,
		startLSN:    startLSN,
		expectedLSN: 0,
	}

	// Advance to first valid segment
	if err := it.nextSegment(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return it, nil
}

func (it *WALIterator) nextSegment() error {
	if it.currFile != nil {
		if err := it.currFile.Close(); err != nil {
			return err
		}
		it.currFile = nil
		it.currSegSize = 0
	}

	it.currSegIdx++
	if it.currSegIdx >= len(it.segments) {
		it.done = true
		return io.EOF
	}

	seg := it.segments[it.currSegIdx]
	file, err := it.fs.Open(seg.path)
	if err != nil {
		return err
	}

	// Read and verify segment header: Magic(4) + Version(4) + Reserved(8) + DBID(16)
	header := make([]byte, SegmentHeaderSize)
	n, readErr := file.ReadAt(header, 0)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		closeErr := file.Close()
		it.done = true
		return errors.Join(fmt.Errorf("read error reading segment header in %s: %w", seg.name, readErr), closeErr)
	}

	if n < SegmentHeaderSize {
		closeErr := file.Close()
		it.done = true
		if !it.isLastSegment() {
			// Not the last segment, so this is corruption; see WALIterator.
			return errors.Join(fmt.Errorf("%w: corrupt segment header in %s", ErrCorruptWAL, seg.name), closeErr)
		}
		// A crash right after rotation can leave an empty or headerless last segment; see WALIterator.
		if closeErr != nil {
			return closeErr
		}
		return io.EOF
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	ver := binary.BigEndian.Uint32(header[4:8])
	if magic != WALMagic || ver != WALVersion || !bytes.Equal(header[16:32], it.dbID[:]) {
		closeErr := file.Close()
		it.done = true
		if !it.isLastSegment() {
			// Not the last segment, so this is corruption; see WALIterator.
			return errors.Join(fmt.Errorf("%w: foreign or invalid segment header in %s", ErrCorruptWAL, seg.name), closeErr)
		}
		// An invalid header in the last segment ends the log; see WALIterator.
		if closeErr != nil {
			return closeErr
		}
		return io.EOF
	}

	size, sizeErr := file.Size()
	if sizeErr != nil {
		closeErr := file.Close()
		it.done = true
		return errors.Join(fmt.Errorf("read error getting segment size in %s: %w", seg.name, sizeErr), closeErr)
	}

	it.currFile = file
	it.currOffset = int64(SegmentHeaderSize)
	it.currSegSize = size
	return nil
}

// Next reads the next valid record in sequence.
// Honors startLSN and drops unacknowledged torn tails in the last segment.
// Returns ErrCorruptWAL on corruption in non-tail segments or segment LSN gaps.
func (it *WALIterator) Next() (Record, error) {
	if it.done {
		return Record{}, io.EOF
	}

	for {
		if it.currFile == nil {
			return Record{}, io.EOF
		}

		// Read record header at currOffset
		hdr := make([]byte, RecordHeaderSize)
		n, err := it.currFile.ReadAt(hdr, it.currOffset)

		// Check if at clean EOF of segment
		if err == io.EOF && n == 0 {
			if advErr := it.advanceSegment(); advErr != nil {
				return Record{}, advErr
			}
			continue
		}

		// Check for real read I/O error
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			it.done = true
			return Record{}, fmt.Errorf("read error reading record header at offset %d: %w", it.currOffset, err)
		}

		// Check for zero-padded block. Every record starts with non-zero RecordMagic,
		// so a zero byte where a record should start must be padding.
		if n > 0 && hdr[0] == 0 {
			// Skip zero padding to next 4 KiB block boundary within this segment
			nextBlock := ((it.currOffset / WALBlockSize) + 1) * WALBlockSize
			if nextBlock < it.currSegSize {
				it.currOffset = nextBlock
				continue
			}
			// Reached end of blocks in this segment
			if advErr := it.advanceSegment(); advErr != nil {
				return Record{}, advErr
			}
			continue
		}

		if n < RecordHeaderSize {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: torn record header at offset %d in segment %s", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name)
			}
			return Record{}, io.EOF
		}

		keyLen := binary.BigEndian.Uint32(hdr[20:24])
		payloadLen := binary.BigEndian.Uint32(hdr[24:28])
		// Stop a corrupted length field from triggering a huge allocation.
		if keyLen > MaxRecordFieldLength || payloadLen > MaxRecordFieldLength {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: record field length exceeds limit at offset %d in segment %s", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name)
			}
			return Record{}, io.EOF
		}

		totalRecordLen := RecordHeaderSize + int(keyLen) + int(payloadLen)

		if int64(totalRecordLen) > it.currSegSize-it.currOffset {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: torn record body at offset %d in segment %s", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name)
			}
			return Record{}, io.EOF
		}

		recordBytes := make([]byte, totalRecordLen)
		n, err = it.currFile.ReadAt(recordBytes, it.currOffset)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			it.done = true
			return Record{}, fmt.Errorf("read error reading record body at offset %d: %w", it.currOffset, err)
		}

		if n < totalRecordLen {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: torn record body at offset %d in segment %s", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name)
			}
			return Record{}, io.EOF
		}

		rec, decodeErr := DecodeRecord(bytes.NewReader(recordBytes))
		if decodeErr != nil {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: decode record at offset %d in segment %s: %w", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name, decodeErr)
			}
			return Record{}, io.EOF
		}

		// If startLSN was specified, skip records prior to startLSN
		if it.startLSN > 0 && rec.LSN < it.startLSN {
			it.currOffset += int64(totalRecordLen)
			continue
		}

		// Check LSN contiguity
		if it.expectedLSN > 0 && rec.LSN != it.expectedLSN {
			it.done = true
			if !it.isLastSegment() {
				// Not the last segment, so this is corruption; see WALIterator.
				return Record{}, fmt.Errorf("%w: LSN gap at offset %d in segment %s: expected %d, got %d", ErrCorruptWAL, it.currOffset, it.segments[it.currSegIdx].name, it.expectedLSN, rec.LSN)
			}
			return Record{}, io.EOF
		}

		it.expectedLSN = rec.LSN + 1
		it.currOffset += int64(totalRecordLen)
		return rec, nil
	}
}

// isLastSegment reports whether the current segment is the last segment in the log.
func (it *WALIterator) isLastSegment() bool {
	return it.currSegIdx >= len(it.segments)-1
}

// advanceSegment advances the iterator to the next segment file.
// If no later segment exists, it marks the iterator done and returns io.EOF.
// If a later segment exists but does not start at expectedLSN, it returns an error wrapping ErrCorruptWAL.
func (it *WALIterator) advanceSegment() error {
	if it.isLastSegment() {
		it.done = true
		return io.EOF
	}

	nextSeg := it.segments[it.currSegIdx+1]
	if err := it.nextSegment(); err != nil {
		it.done = true
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		if errors.Is(err, ErrCorruptWAL) {
			return err
		}
		return fmt.Errorf("%w: failed to advance to next segment %s: %w", ErrCorruptWAL, nextSeg.name, err)
	}

	if it.expectedLSN > 0 && nextSeg.startLSN != it.expectedLSN {
		it.done = true
		// Next segment does not start at expected LSN, so this is corruption; see WALIterator.
		return fmt.Errorf("%w: segment %s starts at LSN %d, expected %d", ErrCorruptWAL, nextSeg.name, nextSeg.startLSN, it.expectedLSN)
	}

	return nil
}

// Close closes the iterator.
func (it *WALIterator) Close() error {
	if it.currFile != nil {
		err := it.currFile.Close()
		it.currFile = nil
		it.currSegSize = 0
		return err
	}
	return nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
