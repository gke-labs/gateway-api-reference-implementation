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
	mu   sync.Mutex

	bufSize int       // buffer capacity (e.g. 1 MiB), multiple of WALBlockSize
	bufs    [2][]byte // two aligned buffers for contiguous double-buffering

	activeFile     File
	activePath     string
	activeStartLSN uint64

	appendOff  int64 // physical file offset in active segment where next record appends
	flushedOff int64 // physical file offset in active segment up to which data has been written to disk
	tailOffset int   // current offset within 4 KiB block (0..4095) for inspection

	nextLSN         uint64 // Next monotonic LSN to allocate under mu
	lastAppendedLSN uint64 // Highest LSN successfully written to buffer
	maxLSN          atomic.Uint64
	fsyncedLSN      atomic.Uint64 // Highest LSN covered by fdatasync
	maxSegSize      int64
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
}

// OpenWAL opens or creates a WAL in the given directory.
func OpenWAL(fs FS, dir string, dbID [16]byte, initialLSN uint64, opts ...WALOptions) (*WAL, error) {
	if err := fs.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}
	if err := fs.SyncDir(dir); err != nil {
		return nil, fmt.Errorf("failed to sync WAL directory: %w", err)
	}

	maxSegSize := int64(DefaultMaxSegmentSize)
	bufSize := DefaultWALBufferSize
	var onFailure func(error)
	var clock Clock = realClock{}
	var tickInterval time.Duration
	if len(opts) > 0 {
		if opts[0].MaxSegmentSize > 0 {
			maxSegSize = opts[0].MaxSegmentSize
		}
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

	w := &WAL{
		fs:              fs,
		dir:             dir,
		dbID:            dbID,
		bufSize:         bufSize,
		bufs:            [2][]byte{AllocateAlignedBlock(bufSize), AllocateAlignedBlock(bufSize)},
		maxSegSize:      maxSegSize,
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

	for _, seg := range segments {
		w.createdLSNs[seg.startLSN] = true
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

func (w *WAL) writeBytesToBuffer(off int64, p []byte) {
	for len(p) > 0 {
		bufIdx := (off / int64(w.bufSize)) % 2
		startInBuf := int(off % int64(w.bufSize))
		toCopy := w.bufSize - startInBuf
		if toCopy > len(p) {
			toCopy = len(p)
		}
		copy(w.bufs[bufIdx][startInBuf:startInBuf+toCopy], p[:toCopy])
		p = p[toCopy:]
		off += int64(toCopy)
	}
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
		w.tailOffset = 0
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
	w.writeCond.Broadcast()

	flushErr := errors.Join(writeErr, syncErr)
	if flushErr != nil {
		w.setStickyErrLocked(flushErr)
		w.mu.Unlock()
		return
	}

	if endOff > w.flushedOff {
		w.flushedOff = endOff
	}

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
		w.tailOffset = 0
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
	f, err := w.fs.OpenFile(path, openFlags, 0644)
	if err != nil {
		if DirectIOOpenFlag() != 0 {
			GlobalMetrics.DirectIOFallbackCount.Add(1)
		}
		// Fallback without DirectIOOpenFlag if not supported by FS
		f, err = w.fs.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to create WAL segment %s: %w", name, err)
		}
	}

	// Fsync the directory after creating a segment
	if err := w.fs.SyncDir(w.dir); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to fsync directory after segment creation: %w", err)
	}

	w.activeFile = f
	w.activePath = path
	w.activeStartLSN = startLSN
	w.flushedOff = 0
	w.appendOff = SegmentHeaderSize
	w.tailOffset = SegmentHeaderSize
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

	keyLen := len(r.Key)
	payloadLen := len(r.Payload)
	tokenLen := len(r.Token)
	recLen := RecordHeaderSize + keyLen + payloadLen + tokenLen

	now := w.clock.Now()
	if w.oldestUnsyncedTime.IsZero() {
		w.oldestUnsyncedTime = now
	}

	for {
		if w.stickyErr != nil {
			return 0, w.stickyErr
		}
		if w.closed {
			return 0, errors.New("wal is closed")
		}

		// If no active file or record exceeds segment size, roll segment
		if w.activeFile == nil || w.appendOff+int64(recLen) > w.maxSegSize {
			if err := w.createSegmentLocked(r.LSN); err != nil {
				return 0, err
			}
		}

		if recLen > w.bufSize {
			if w.writing {
				w.writeCond.Wait()
				continue
			}
			break
		}

		startChunk := w.appendOff / int64(w.bufSize)
		endChunk := (w.appendOff + int64(recLen) - 1) / int64(w.bufSize)

		needWait := false
		for chunk := startChunk; chunk <= endChunk; chunk++ {
			if chunk >= 2 {
				requiredFlushedOff := (chunk - 1) * int64(w.bufSize)
				if w.flushedOff < requiredFlushedOff {
					needWait = true
					break
				}
			}
		}

		if !needWait {
			break
		}

		select {
		case w.wakeCh <- struct{}{}:
		default:
		}
		w.writeCond.Wait()
	}

	if w.tailBlockOpenTime.IsZero() {
		w.tailBlockOpenTime = now
	}

	// Format record header into 36-byte stack buffer
	var hdr [RecordHeaderSize]byte
	hdr[0] = RecordMagic
	hdr[1] = RecordFormatVersion
	hdr[2] = byte(r.Type)
	hdr[3] = 0 // reserved
	binary.BigEndian.PutUint64(hdr[4:12], r.LSN)
	binary.BigEndian.PutUint64(hdr[12:20], r.RedoStartLSN)
	binary.BigEndian.PutUint32(hdr[20:24], uint32(keyLen))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(payloadLen))
	binary.BigEndian.PutUint32(hdr[28:32], uint32(tokenLen))
	// bytes 32..36 are zero for CRC calculation

	if recLen > w.bufSize {
		// Record exceeds buffer capacity: compute CRC incrementally and stream through double buffers
		h := crc32.Update(0, castagnoliTable, hdr[:])
		if keyLen > 0 {
			h = crc32.Update(h, castagnoliTable, []byte(r.Key))
		}
		if payloadLen > 0 {
			h = crc32.Update(h, castagnoliTable, r.Payload)
		}
		if tokenLen > 0 {
			h = crc32.Update(h, castagnoliTable, []byte(r.Token))
		}
		binary.BigEndian.PutUint32(hdr[32:36], h)

		for w.writing {
			w.writeCond.Wait()
			if w.stickyErr != nil {
				return 0, w.stickyErr
			}
		}
		if err := w.flushQueueAndSyncDirectLocked(false); err != nil {
			return 0, err
		}

		appendPiece := func(p []byte) error {
			for len(p) > 0 {
				bufIdx := (w.appendOff / int64(w.bufSize)) % 2
				startInBuf := int(w.appendOff % int64(w.bufSize))
				toCopy := w.bufSize - startInBuf
				if toCopy > len(p) {
					toCopy = len(p)
				}
				copy(w.bufs[bufIdx][startInBuf:startInBuf+toCopy], p[:toCopy])
				p = p[toCopy:]
				w.appendOff += int64(toCopy)

				if w.appendOff%int64(w.bufSize) == 0 {
					chunkStart := w.appendOff - int64(w.bufSize)
					slice := w.bufs[bufIdx]
					if _, err := w.activeFile.WriteAt(slice, chunkStart); err != nil {
						w.setStickyErrLocked(fmt.Errorf("failed to write WAL chunk at %d: %w", chunkStart, err))
						return w.stickyErr
					}
					w.flushedOff = w.appendOff
				}
			}
			return nil
		}

		if err := appendPiece(hdr[:]); err != nil {
			return 0, err
		}
		if keyLen > 0 {
			if err := appendPiece([]byte(r.Key)); err != nil {
				return 0, err
			}
		}
		if payloadLen > 0 {
			if err := appendPiece(r.Payload); err != nil {
				return 0, err
			}
		}
		if tokenLen > 0 {
			if err := appendPiece([]byte(r.Token)); err != nil {
				return 0, err
			}
		}
	} else {
		recStartOff := w.appendOff
		startChunk := recStartOff / int64(w.bufSize)
		endChunk := (recStartOff + int64(recLen) - 1) / int64(w.bufSize)

		if startChunk == endChunk {
			bufIdx := startChunk % 2
			startInBuf := int(recStartOff % int64(w.bufSize))
			dest := w.bufs[bufIdx][startInBuf : startInBuf+recLen]
			copy(dest[0:36], hdr[:])
			copy(dest[36:36+keyLen], r.Key)
			copy(dest[36+keyLen:36+keyLen+payloadLen], r.Payload)
			copy(dest[36+keyLen+payloadLen:recLen], r.Token)
			crc := crc32.Checksum(dest, castagnoliTable)
			binary.BigEndian.PutUint32(dest[32:36], crc)
		} else {
			w.writeBytesToBuffer(recStartOff, hdr[:])
			if keyLen > 0 {
				w.writeBytesToBuffer(recStartOff+36, []byte(r.Key))
			}
			if payloadLen > 0 {
				w.writeBytesToBuffer(recStartOff+36+int64(keyLen), r.Payload)
			}
			if tokenLen > 0 {
				w.writeBytesToBuffer(recStartOff+36+int64(keyLen)+int64(payloadLen), []byte(r.Token))
			}
			buf1 := w.bufs[startChunk%2][recStartOff%int64(w.bufSize) : w.bufSize]
			len2 := recLen - len(buf1)
			buf2 := w.bufs[endChunk%2][0 : len2]
			crc := crc32.Update(0, castagnoliTable, buf1)
			crc = crc32.Update(crc, castagnoliTable, buf2)
			var crcBuf [4]byte
			binary.BigEndian.PutUint32(crcBuf[:], crc)
			w.writeBytesToBuffer(recStartOff+32, crcBuf[:])
		}

		w.appendOff += int64(recLen)
	}
	w.tailOffset = int(w.appendOff % int64(WALBlockSize))
	w.lastAppendedLSN = r.LSN

	select {
	case w.wakeCh <- struct{}{}:
	default:
	}

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
type WALIterator struct {
	fs          FS
	segments    []segmentMeta
	dbID        [16]byte
	currSegIdx  int
	currFile    File
	currOffset  int64
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
	}

	it.currSegIdx++
	if it.currSegIdx >= len(it.segments) {
		it.done = true
		return io.EOF
	}

	seg := it.segments[it.currSegIdx]
	f, err := it.fs.Open(seg.path)
	if err != nil {
		return err
	}

	// Read and verify segment header: Magic(4) + Version(4) + Reserved(8) + DBID(16)
	header := make([]byte, SegmentHeaderSize)
	if _, err := f.ReadAt(header, 0); err != nil {
		return errors.Join(fmt.Errorf("corrupt segment header in %s: %w", seg.name, err), f.Close())
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	ver := binary.BigEndian.Uint32(header[4:8])
	if magic != WALMagic || ver != WALVersion || !bytes.Equal(header[16:32], it.dbID[:]) {
		return errors.Join(fmt.Errorf("foreign or invalid segment header in %s", seg.name), f.Close())
	}

	it.currFile = f
	it.currOffset = int64(SegmentHeaderSize)
	return nil
}

// Next reads the next valid record in sequence.
// Honors startLSN and properly handles torn tails when later segments exist.
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
			if segErr := it.nextSegment(); segErr != nil {
				return Record{}, io.EOF
			}
			continue
		}

		// Check for real read I/O error
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			it.done = true
			return Record{}, fmt.Errorf("read error reading record header at offset %d: %w", it.currOffset, err)
		}

		// Check for zero-padded block or torn header
		isZeroPadding := true
		for _, b := range hdr[:n] {
			if b != 0 {
				isZeroPadding = false
				break
			}
		}

		if isZeroPadding {
			// Check if we can skip zero padding to the next 4 KiB block boundary within this segment
			nextBlock := ((it.currOffset / WALBlockSize) + 1) * WALBlockSize
			size, sizeErr := it.currFile.Size()
			if sizeErr == nil && nextBlock < size {
				it.currOffset = nextBlock
				continue
			}
			// Reached end of blocks in this segment: check if next segment starts at expected LSN
			if it.canAdvanceToNextSegment() {
				if segErr := it.nextSegment(); segErr != nil {
					it.done = true
					return Record{}, io.EOF
				}
				continue
			}
			it.done = true
			return Record{}, io.EOF
		}

		if n < RecordHeaderSize {
			// Torn header: check if next segment starts at expected LSN
			if it.canAdvanceToNextSegment() {
				if segErr := it.nextSegment(); segErr != nil {
					it.done = true
					return Record{}, io.EOF
				}
				continue
			}
			// Otherwise, this is the true end of the log
			it.done = true
			return Record{}, io.EOF
		}

		keyLen := binary.BigEndian.Uint32(hdr[20:24])
		payloadLen := binary.BigEndian.Uint32(hdr[24:28])
		tokenLen := binary.BigEndian.Uint32(hdr[28:32])
		totalRecordLen := RecordHeaderSize + int(keyLen) + int(payloadLen) + int(tokenLen)

		recordBytes := make([]byte, totalRecordLen)
		n, err = it.currFile.ReadAt(recordBytes, it.currOffset)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			it.done = true
			return Record{}, fmt.Errorf("read error reading record body at offset %d: %w", it.currOffset, err)
		}

		if n < totalRecordLen {
			// Torn record body: check if next segment starts at expected LSN
			if it.canAdvanceToNextSegment() {
				if segErr := it.nextSegment(); segErr != nil {
					it.done = true
					return Record{}, io.EOF
				}
				continue
			}
			it.done = true
			return Record{}, io.EOF
		}

		rec, decodeErr := DecodeRecord(bytes.NewReader(recordBytes))
		if decodeErr != nil {
			// Corrupt record or bad CRC: check if next segment starts at expected LSN
			if it.canAdvanceToNextSegment() {
				if segErr := it.nextSegment(); segErr != nil {
					it.done = true
					return Record{}, io.EOF
				}
				continue
			}
			it.done = true
			return Record{}, io.EOF
		}

		// If startLSN was specified, skip records prior to startLSN
		if it.startLSN > 0 && rec.LSN < it.startLSN {
			it.currOffset += int64(totalRecordLen)
			continue
		}

		// Check LSN contiguity
		if it.expectedLSN > 0 && rec.LSN != it.expectedLSN {
			// LSN gap: check if next segment can continue
			if it.canAdvanceToNextSegment() {
				if segErr := it.nextSegment(); segErr != nil {
					it.done = true
					return Record{}, io.EOF
				}
				continue
			}
			it.done = true
			return Record{}, io.EOF
		}

		it.expectedLSN = rec.LSN + 1
		it.currOffset += int64(totalRecordLen)
		return rec, nil
	}
}

// canAdvanceToNextSegment checks if a later segment exists starting at expectedLSN.
func (it *WALIterator) canAdvanceToNextSegment() bool {
	if it.currSegIdx+1 < len(it.segments) {
		nextSeg := it.segments[it.currSegIdx+1]
		if it.expectedLSN == 0 || nextSeg.startLSN == it.expectedLSN {
			return true
		}
	}
	return false
}

// Close closes the iterator.
func (it *WALIterator) Close() error {
	if it.currFile != nil {
		err := it.currFile.Close()
		it.currFile = nil
		return err
	}
	return nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
