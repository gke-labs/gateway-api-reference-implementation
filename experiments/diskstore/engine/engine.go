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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrFailed is returned when the engine has entered the failed state due to corruption or I/O error.
	ErrFailed = errors.New("engine failed")

	// ErrKeyNotFound indicates the requested key does not exist.
	ErrKeyNotFound = errors.New("key not found")

	// ErrStopScan can be returned by a Scan callback to abort scanning early without error.
	ErrStopScan = errors.New("stop scan")

	// ErrDecrypt indicates a failure during payload decryption.
	ErrDecrypt = errors.New("payload decryption failed")

	// ErrCorruptStore indicates corruption in the store state or referenced files.
	ErrCorruptStore = errors.New("store corruption")
)

// TestHookFail is an internal hook used by tests to trigger the failed state without exposing a method on Engine.
var TestHookFail = func(e *Engine, err error) {
	e.setFailed(err)
}

func qualifyKey(tableName, key string) string {
	return tableName + "\x00" + key
}

func unqualifyKey(qualified string) (string, string) {
	parts := strings.SplitN(qualified, "\x00", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", qualified
}

// Options configures an Engine instance.
type Options struct {
	Dir           string
	FS            FS
	Cipher        Cipher
	NumPoolBlocks int
	AutoDelete    bool
	Clock         Clock
	Create        bool
	EraseOnError  bool

	CompressionCodec CompressionCodec
	MaxObjectSize    int

	// MaxQuarantinedFiles is the maximum number of quarantined files kept in each
	// lost+found directory. When exceeded, the oldest files are removed.
	// If <= 0, DefaultMaxQuarantinedFiles is used.
	MaxQuarantinedFiles int

	// MinQuarantinedRetention is the minimum retention duration for quarantined files.
	// Files younger than this retention are not deleted even when MaxQuarantinedFiles is exceeded.
	// If == 0, DefaultMinQuarantinedRetention (7 days) is used. If < 0, minimum retention is disabled.
	MinQuarantinedRetention time.Duration

	compressionCodecSet bool
}

// Option is a functional option for configuring an Engine.
type Option func(*Options)

// WithCreate specifies that Open should create a new database when no store files exist.
// Without it, Open returns an error if there is no existing database.
// When Dir is empty, Open creates a temporary store, which implies WithCreate.
func WithCreate() Option {
	return func(o *Options) {
		o.Create = true
	}
}

// WithEraseOnError enables erasing the store and starting fresh when an unreadable,
// outdated, or corrupt meta file, orphaned store files, or failure markers are detected.
// Erasing destroys data, which suits a cache that can rebuild from its source,
// but not every caller can do that. Without it, Open returns an error describing
// the issue without modifying existing files.
func WithEraseOnError() Option {
	return func(o *Options) {
		o.EraseOnError = true
	}
}

// WithClock sets the Clock used for WAL timing.
func WithClock(clock Clock) Option {
	return func(o *Options) {
		o.Clock = clock
	}
}

// WithCompressionCodec sets the compression algorithm to use (CodecNone, CodecZstd).
func WithCompressionCodec(codec CompressionCodec) Option {
	return func(o *Options) {
		o.CompressionCodec = codec
		o.compressionCodecSet = true
	}
}

// WithMaxObjectSize sets the maximum uncompressed object size accepted during decompression.
func WithMaxObjectSize(size int) Option {
	return func(o *Options) {
		o.MaxObjectSize = size
	}
}

// WithDir sets the directory for engine files.
func WithDir(dir string) Option {
	return func(o *Options) {
		o.Dir = dir
	}
}

// WithFS sets the filesystem implementation (e.g. for fault injection).
func WithFS(fs FS) Option {
	return func(o *Options) {
		o.FS = fs
	}
}

// WithCipher sets the cipher for payload encryption.
func WithCipher(cipher Cipher) Option {
	return func(o *Options) {
		o.Cipher = cipher
	}
}

// WithNumPoolBlocks sets the block pool block count.
func WithNumPoolBlocks(n int) Option {
	return func(o *Options) {
		o.NumPoolBlocks = n
	}
}

// WithBlockPoolSize sets the block pool size in bytes (rounded to 4096-byte blocks).
func WithBlockPoolSize(bytes int) Option {
	return func(o *Options) {
		blocks := bytes / 4096
		if blocks < 16 {
			blocks = 16
		}
		o.NumPoolBlocks = blocks
	}
}

// WithAutoDelete specifies whether to delete the directory on Close.
func WithAutoDelete(autoDelete bool) Option {
	return func(o *Options) {
		o.AutoDelete = autoDelete
	}
}

// WithMaxQuarantinedFiles sets the maximum number of quarantined files kept in each
// lost+found directory. When the bound is exceeded, the oldest quarantined files are deleted.
// If n <= 0, DefaultMaxQuarantinedFiles is used.
func WithMaxQuarantinedFiles(n int) Option {
	return func(o *Options) {
		o.MaxQuarantinedFiles = n
	}
}

// WithMinQuarantinedRetention sets the minimum retention duration for quarantined files.
// Files younger than this retention are not deleted even when MaxQuarantinedFiles is exceeded.
// If d == 0, DefaultMinQuarantinedRetention is used. If d < 0, retention duration check is disabled.
func WithMinQuarantinedRetention(d time.Duration) Option {
	return func(o *Options) {
		o.MinQuarantinedRetention = d
	}
}

// emptyPageTracker manages free logical page identifiers. It maintains a slice for LIFO
// reuse order and a set for O(1) membership checks to prevent duplicate additions.
type emptyPageTracker struct {
	pages []uint64
	set   map[uint64]bool
}

func newEmptyPageTracker(initial []uint64) *emptyPageTracker {
	t := &emptyPageTracker{
		pages: make([]uint64, 0, len(initial)),
		set:   make(map[uint64]bool, len(initial)),
	}
	for _, p := range initial {
		t.Add(p)
	}
	return t
}

func (t *emptyPageTracker) Add(pageID uint64) {
	if !t.set[pageID] {
		t.set[pageID] = true
		t.pages = append(t.pages, pageID)
	}
}

func (t *emptyPageTracker) Pop() (uint64, bool) {
	if len(t.pages) == 0 {
		return 0, false
	}
	p := t.pages[len(t.pages)-1]
	t.pages = t.pages[:len(t.pages)-1]
	delete(t.set, p)
	return p, true
}

func (t *emptyPageTracker) Contains(pageID uint64) bool {
	return t.set[pageID]
}

func (t *emptyPageTracker) Pages() []uint64 {
	return t.pages
}

// Engine coordinates the write-ahead log, heap file, block pool, buddy allocator,
// in-memory index, payload encryption, and crash consistency mechanisms.
type Engine struct {
	fs         FS
	dir        string
	dbID       [16]byte
	isTemp     bool
	autoDelete bool

	cipher           Cipher
	compressionCodec CompressionCodec
	maxObjectSize    int

	quarantine QuarantineOptions

	heapFile File
	wal      *WAL
	buddy    *BuddyAllocator
	bp       *BlockPool
	cp       *Checkpointer

	writerMu sync.RWMutex // Single writer: serializes Put, Delete; RLock for point-in-time Scan/List

	keyMu           sync.RWMutex
	keyIndex        map[string]KeyIndexEntry // tableQualifiedKey -> KeyIndexEntry
	oversizeObjects map[string][]byte        // tableQualifiedKey -> payload

	inFlightMu       sync.Mutex
	inFlightOversize map[string]int
	inFlightSeq      atomic.Uint64

	// Free logical page allocations and tracking; guarded by writerMu
	emptyPages        *emptyPageTracker
	nextLogicalPage   uint64
	activeSlottedPage uint64

	failMu    sync.RWMutex
	failedCh  chan struct{}
	failedErr error
	wiped     bool

	closed   atomic.Bool
	closedCh chan struct{}
}

func removeDirRecursive(fs FS, dir string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range entries {
		sub := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := removeDirRecursive(fs, sub); err != nil {
				errs = append(errs, err)
			}
		}
		if err := fs.Remove(sub); err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := fs.Remove(dir); err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func wipeStoreFiles(fs FS, dir string) error {
	var errs []error

	// Remove known store files (excluding FAILED marker)
	for _, name := range []string{"meta.db", "heap.db"} {
		p := filepath.Join(dir, name)
		if err := fs.Remove(p); err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("failed to remove %s: %w", p, err))
		}
	}

	// Remove known store subdirectories recursively only
	for _, name := range []string{"wal", "oversize"} {
		targetDir := filepath.Join(dir, name)
		if err := removeDirRecursive(fs, targetDir); err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("failed to remove %s: %w", targetDir, err))
		}
	}

	if err := fs.SyncDir(dir); err != nil {
		errs = append(errs, fmt.Errorf("failed to sync store dir before removing marker: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// Remove failure marker LAST, only after all store files are removed and synced
	markerPath := filepath.Join(dir, "FAILED")
	if err := fs.Remove(markerPath); err != nil && !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove failure marker %s: %w", markerPath, err)
	}

	if err := fs.SyncDir(dir); err != nil {
		return fmt.Errorf("failed to sync store dir after removing marker: %w", err)
	}

	return nil
}

var (
	// ErrStoreEncrypted is returned when opening an encrypted store without a cipher.
	ErrStoreEncrypted = errors.New("store is encrypted: cipher option required")

	// ErrStoreNotEncrypted is returned when opening an unencrypted store with a cipher.
	ErrStoreNotEncrypted = errors.New("store is not encrypted: cipher option provided")
)

const (
	// StoreFileMode is the file mode used when creating store files (0600).
	// Store files can hold Secret payloads, unencrypted when no cipher is configured,
	// so other users on the node should not be able to read them.
	StoreFileMode os.FileMode = 0600

	// StoreDirMode is the directory mode used when creating store directories, including lost+found (0700).
	StoreDirMode os.FileMode = 0700

	// metaMagic identifies valid meta.db files ("META").
	metaMagic uint32 = 0x4D455441

	// metaFlagEncrypted indicates that the store was created with an active encryption cipher.
	metaFlagEncrypted uint64 = 1 << 0

	// StoreFormatVersion is the format version recorded in meta.db.
	// Version 1 did not record a version and stored uncompressed values without a codec byte.
	// Version 2 records this version in meta.db and prefixes each stored value with a codec byte.
	// Version 3 removes resourceVersion (token) handling from WAL records and the engine.
	// Version 4 records whether the store was created with a cipher in meta.db.
	// Version 5 makes meta.db a 4 KiB checksummed record with room for new fields.
	// Version 6 stores oversize values in separate files and logs only pointers in the WAL.
	StoreFormatVersion uint32 = 6

	// metaFileSize is the fixed size of meta.db (one 4 KiB block).
	metaFileSize = BlockSize

	metaOffsetMagic    = 0
	metaOffsetVersion  = 4
	metaOffsetDBID     = 8
	metaOffsetFlags    = 24
	metaOffsetReserved = 32
	metaOffsetCRC      = 4092
)

// metaRecord represents the decoded contents of meta.db.
//
// The engine writes meta.db once, when it creates the store, fsyncs it, and never
// rewrites it. Because the engine never rewrites meta.db after creation, a torn
// write can only happen before the store holds data.
//
// Binary layout of meta.db (4096 bytes / one 4 KiB block):
//   - Bytes 0..4:     Magic (0x4D455441, "META")
//   - Bytes 4..8:     StoreFormatVersion (uint32)
//   - Bytes 8..24:    Database ID (16 bytes)
//   - Bytes 24..32:   Flags (uint64, bit 0: encrypted flag)
//   - Bytes 32..4092: Reserved bytes (must be zero under current StoreFormatVersion)
//   - Bytes 4092..4096: CRC32C (uint32 over full 4096-byte block with CRC field zeroed)
//
// New fields take reserved bytes and bump StoreFormatVersion.
type metaRecord struct {
	dbID      [16]byte
	version   uint32
	encrypted bool
}

func encodeMetaRecord(record metaRecord) []byte {
	buffer := make([]byte, metaFileSize)
	binary.BigEndian.PutUint32(buffer[metaOffsetMagic:metaOffsetVersion], metaMagic)
	binary.BigEndian.PutUint32(buffer[metaOffsetVersion:metaOffsetDBID], record.version)
	copy(buffer[metaOffsetDBID:metaOffsetFlags], record.dbID[:])
	var flags uint64
	if record.encrypted {
		flags |= metaFlagEncrypted
	}
	binary.BigEndian.PutUint64(buffer[metaOffsetFlags:metaOffsetReserved], flags)

	crc := crc32.Checksum(buffer, castagnoliTable)
	binary.BigEndian.PutUint32(buffer[metaOffsetCRC:metaFileSize], crc)
	return buffer
}

func decodeMetaRecord(buffer []byte) (metaRecord, error) {
	if len(buffer) != metaFileSize {
		return metaRecord{}, errors.New("invalid meta file size")
	}

	storedCRC := binary.BigEndian.Uint32(buffer[metaOffsetCRC:metaFileSize])
	var zeroCRC [4]byte
	crc := crc32.Update(0, castagnoliTable, buffer[:metaOffsetCRC])
	actualCRC := crc32.Update(crc, castagnoliTable, zeroCRC[:])
	if storedCRC != actualCRC {
		return metaRecord{}, errors.New("meta file CRC mismatch")
	}

	magic := binary.BigEndian.Uint32(buffer[metaOffsetMagic:metaOffsetVersion])
	if magic != metaMagic {
		return metaRecord{}, errors.New("invalid meta file magic")
	}

	version := binary.BigEndian.Uint32(buffer[metaOffsetVersion:metaOffsetDBID])
	if version != StoreFormatVersion {
		return metaRecord{}, fmt.Errorf("unsupported store format version: %d", version)
	}

	flags := binary.BigEndian.Uint64(buffer[metaOffsetFlags:metaOffsetReserved])
	if flags&^metaFlagEncrypted != 0 {
		return metaRecord{}, errors.New("unknown meta flags")
	}

	for _, b := range buffer[metaOffsetReserved:metaOffsetCRC] {
		if b != 0 {
			return metaRecord{}, errors.New("non-zero reserved bytes in meta file")
		}
	}

	var record metaRecord
	copy(record.dbID[:], buffer[metaOffsetDBID:metaOffsetFlags])
	record.version = version
	record.encrypted = (flags & metaFlagEncrypted) != 0
	return record, nil
}

// isEncrypted reports whether c represents an active encryption cipher.
func isEncrypted(c Cipher) bool {
	if c == nil {
		return false
	}
	switch c.(type) {
	case NoopCipher, *NoopCipher:
		return false
	default:
		return true
	}
}

// Open opens or initializes an Engine in dir.
func Open(opts ...Option) (*Engine, error) {
	options := Options{
		FS:                      NewOSFS(),
		Cipher:                  NoopCipher{},
		NumPoolBlocks:           DefaultBlockPoolBlocks,
		AutoDelete:              false,
		CompressionCodec:        CodecZstd,
		MaxObjectSize:           DefaultMaxObjectSize,
		MaxQuarantinedFiles:     DefaultMaxQuarantinedFiles,
		MinQuarantinedRetention: DefaultMinQuarantinedRetention,
	}
	for _, opt := range opts {
		opt(&options)
	}
	if !options.compressionCodecSet && options.CompressionCodec == 0 {
		options.CompressionCodec = CodecZstd
	}
	if options.MaxObjectSize <= 0 {
		options.MaxObjectSize = DefaultMaxObjectSize
	}
	if options.MaxQuarantinedFiles <= 0 {
		options.MaxQuarantinedFiles = DefaultMaxQuarantinedFiles
	}
	if options.MinQuarantinedRetention == 0 {
		options.MinQuarantinedRetention = DefaultMinQuarantinedRetention
	}

	dir := options.Dir
	isTemp := false
	if dir == "" {
		tmpDir, err := os.MkdirTemp("", "gari-diskstore-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp diskstore dir: %w", err)
		}
		dir = tmpDir
		isTemp = true
		options.AutoDelete = true
		options.Create = true
	}

	// Check for failure marker from a prior failed instance
	markerPath := filepath.Join(dir, "FAILED")
	wiped := false
	needsErase := false
	eraseReason := ""
	markerFile, markerErr := options.FS.OpenFile(markerPath, os.O_RDONLY, 0)
	if markerErr == nil {
		if closeErr := markerFile.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to close failure marker: %w", closeErr)
		}
		needsErase = true
		eraseReason = "failure marker"
	} else if !os.IsNotExist(markerErr) && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to check failure marker: %w", markerErr)
	}

	metaPath := filepath.Join(dir, "meta.db")
	heapPath := filepath.Join(dir, "heap.db")
	walDir := filepath.Join(dir, "wal")
	oversizeDir := filepath.Join(dir, "oversize")

	var dbID [16]byte
	isNewStore := false

	if needsErase {
		isNewStore = true
	} else {
		// Read or generate database ID and verify store format version
		metaFile, err := options.FS.OpenFile(metaPath, os.O_RDWR, StoreFileMode)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
				// meta.db does not exist. Check if orphaned store files exist (heap.db, wal/, or oversize/)
				hasOrphaned := false
				hf, openErr := options.FS.OpenFile(heapPath, os.O_RDONLY, 0)
				if openErr == nil {
					if closeErr := hf.Close(); closeErr != nil {
						return nil, fmt.Errorf("failed to close heap.db check file: %w", closeErr)
					}
					hasOrphaned = true
				} else if !os.IsNotExist(openErr) && !errors.Is(openErr, os.ErrNotExist) {
					return nil, fmt.Errorf("failed to check heap.db: %w", openErr)
				}

				wEntries, readDirErr := options.FS.ReadDir(walDir)
				if readDirErr == nil {
					if len(wEntries) > 0 {
						hasOrphaned = true
					}
				} else if !os.IsNotExist(readDirErr) && !errors.Is(readDirErr, os.ErrNotExist) {
					return nil, fmt.Errorf("failed to check wal directory: %w", readDirErr)
				}

				oEntries, readDirErr := options.FS.ReadDir(oversizeDir)
				if readDirErr == nil {
					if len(oEntries) > 0 {
						hasOrphaned = true
					}
				} else if !os.IsNotExist(readDirErr) && !errors.Is(readDirErr, os.ErrNotExist) {
					return nil, fmt.Errorf("failed to check oversize directory: %w", readDirErr)
				}
				if hasOrphaned {
					needsErase = true
					eraseReason = "orphaned store files"
				}

				isNewStore = true
			} else {
				if !options.EraseOnError {
					return nil, err
				}
				needsErase = true
				eraseReason = "unreadable meta file"
				isNewStore = true
			}
		} else {
			// meta.db exists. Read dbID and store format version.
			metaBuffer := make([]byte, metaFileSize)
			bytesRead, readErr := metaFile.ReadAt(metaBuffer, 0)
			if closeErr := metaFile.Close(); closeErr != nil {
				return nil, fmt.Errorf("failed to close meta file: %w", closeErr)
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				if !options.EraseOnError {
					return nil, fmt.Errorf("failed to read meta file: %w", readErr)
				}
				needsErase = true
				eraseReason = fmt.Sprintf("unreadable meta file: %v", readErr)
				isNewStore = true
			} else if bytesRead < metaFileSize {
				needsErase = true
				eraseReason = fmt.Sprintf("outdated or corrupt meta file: short read (%d bytes, expected %d)", bytesRead, metaFileSize)
				isNewStore = true
			} else {
				record, decodeErr := decodeMetaRecord(metaBuffer)
				if decodeErr != nil {
					// Outdated format version or corrupt meta file:
					// wipe the store and initialize a fresh database if EraseOnError is set.
					needsErase = true
					eraseReason = fmt.Sprintf("outdated or corrupt meta file: %v", decodeErr)
					isNewStore = true
				} else {
					copy(dbID[:], record.dbID[:])
					storeEncrypted := record.encrypted
					optEncrypted := isEncrypted(options.Cipher)
					if storeEncrypted && !optEncrypted {
						return nil, ErrStoreEncrypted
					}
					if !storeEncrypted && optEncrypted {
						return nil, ErrStoreNotEncrypted
					}
				}
			}
		}
	}

	if needsErase {
		if !options.EraseOnError {
			return nil, fmt.Errorf("store requires erase: %s", eraseReason)
		}
		if wipeErr := wipeStoreFiles(options.FS, dir); wipeErr != nil {
			return nil, fmt.Errorf("failed to wipe store files after %s: %w", eraseReason, wipeErr)
		}
		wiped = true
		isNewStore = true
	}

	if isNewStore && !wiped && !options.Create {
		return nil, fmt.Errorf("database does not exist: %w", os.ErrNotExist)
	}

	if options.Create || wiped {
		if err := options.FS.MkdirAll(dir, StoreDirMode); err != nil {
			return nil, fmt.Errorf("failed to create store dir: %w", err)
		}
		if err := options.FS.SyncDir(dir); err != nil {
			return nil, fmt.Errorf("failed to sync store dir: %w", err)
		}
	}

	if err := options.FS.MkdirAll(oversizeDir, StoreDirMode); err != nil {
		return nil, fmt.Errorf("failed to create oversize directory: %w", err)
	}

	if isNewStore {
		if _, randErr := io.ReadFull(rand.Reader, dbID[:]); randErr != nil {
			return nil, fmt.Errorf("failed to generate DB ID: %w", randErr)
		}
		metaFile, err := options.FS.Create(metaPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create meta file: %w", err)
		}
		metaBuffer := encodeMetaRecord(metaRecord{
			dbID:      dbID,
			version:   StoreFormatVersion,
			encrypted: isEncrypted(options.Cipher),
		})
		if _, writeErr := metaFile.WriteAt(metaBuffer, 0); writeErr != nil {
			closeErr := metaFile.Close()
			return nil, errors.Join(writeErr, closeErr)
		}
		if err := metaFile.Sync(); err != nil {
			closeErr := metaFile.Close()
			return nil, errors.Join(fmt.Errorf("failed to sync meta file: %w", err), closeErr)
		}
		if err := metaFile.Close(); err != nil {
			return nil, fmt.Errorf("failed to close meta file: %w", err)
		}
	}

	// Open heap file with direct I/O flag
	openFlags := os.O_RDWR | os.O_CREATE | DirectIOOpenFlag()
	heapFile, err := options.FS.OpenFile(heapPath, openFlags, StoreFileMode)
	if err != nil {
		if DirectIOOpenFlag() != 0 {
			GlobalMetrics.DirectIOFallbackCount.Add(1)
		}
		// Fallback without O_DIRECT if filesystem doesn't support it (e.g. tmpfs)
		heapFile, err = options.FS.OpenFile(heapPath, os.O_RDWR|os.O_CREATE, StoreFileMode)
		if err != nil {
			return nil, fmt.Errorf("failed to open heap file: %w", err)
		}
	}
	if err := options.FS.SyncDir(dir); err != nil {
		closeErr := heapFile.Close()
		return nil, errors.Join(fmt.Errorf("failed to sync directory after meta and heap file creation: %w", err), closeErr)
	}

	// Apply platform specific flags (e.g. F_NOCACHE on Darwin)
	conn, connErr := heapFile.SyscallConn()
	if connErr != nil {
		GlobalMetrics.DirectIOFallbackCount.Add(1)
	} else if conn != nil {
		if rawConn, ok := conn.(interface{ Control(func(uintptr)) error }); ok {
			var ctrlErr error
			if controlErr := rawConn.Control(func(fd uintptr) {
				ctrlErr = applyPlatformDirectIOFlags(fd)
			}); controlErr != nil || ctrlErr != nil {
				GlobalMetrics.DirectIOFallbackCount.Add(1)
			}
		}
	}

	s := &Engine{
		fs:               options.FS,
		dir:              dir,
		dbID:             dbID,
		isTemp:           isTemp,
		autoDelete:       options.AutoDelete,
		cipher:           options.Cipher,
		compressionCodec: options.CompressionCodec,
		maxObjectSize:    options.MaxObjectSize,
		quarantine: QuarantineOptions{
			MaxQuarantinedFiles:     options.MaxQuarantinedFiles,
			MinQuarantinedRetention: options.MinQuarantinedRetention,
		},
		heapFile:         heapFile,
		keyIndex:         make(map[string]KeyIndexEntry),
		oversizeObjects:  make(map[string][]byte),
		inFlightOversize: make(map[string]int),
		emptyPages:       newEmptyPageTracker(nil),
		failedCh:         make(chan struct{}),
		closedCh:         make(chan struct{}),
		wiped:            wiped,
		nextLogicalPage:  1,
	}

	walQuarantine := s.quarantine
	walQuarantine.Dir = filepath.Join(walDir, "lost+found")

	if isNewStore {
		wal, err := OpenWAL(options.FS, walDir, dbID, 0, WALOptions{
			OnFailure:  s.setFailed,
			Clock:      options.Clock,
			Quarantine: walQuarantine,
		})
		if err != nil {
			closeErr := heapFile.Close()
			return nil, errors.Join(fmt.Errorf("failed to open WAL: %w", err), closeErr)
		}
		s.wal = wal
		s.buddy = NewBuddyAllocator(512)
		s.bp = NewBlockPool(heapFile, wal, s.buddy, dbID, BlockPoolOptions{
			NumPoolBlocks: options.NumPoolBlocks,
			Cipher:        options.Cipher,
			OnFailure:     s.setFailed,
		})
		s.cp = NewCheckpointer(s.bp, heapFile, wal)
	} else {
		// Existing store: perform crash recovery scan and WAL redo replay
		recoveryRes, err := Recover(options.FS, heapFile, dir, walDir, dbID)
		if err != nil {
			closeErr := heapFile.Close()
			return nil, errors.Join(fmt.Errorf("recovery failed: %w", err), closeErr)
		}

		s.buddy = recoveryRes.Buddy
		s.keyIndex = recoveryRes.KeyIndex
		s.emptyPages = newEmptyPageTracker(recoveryRes.EmptyLogicalPages)
		s.nextLogicalPage = recoveryRes.NextLogicalPage
		if s.nextLogicalPage == 0 {
			s.nextLogicalPage = 1
		}

		// Item 1: LSNs continue from recovered maximum, new segment starts at maxLSN + 1
		wal, err := OpenWAL(options.FS, walDir, dbID, recoveryRes.MaxLSN, WALOptions{
			OnFailure:  s.setFailed,
			Clock:      options.Clock,
			Quarantine: walQuarantine,
		})
		if err != nil {
			closeErr := heapFile.Close()
			return nil, errors.Join(fmt.Errorf("failed to open WAL: %w", err), closeErr)
		}
		s.wal = wal

		s.bp = NewBlockPool(heapFile, wal, s.buddy, dbID, BlockPoolOptions{
			NumPoolBlocks: options.NumPoolBlocks,
			Cipher:        options.Cipher,
			OnFailure:     s.setFailed,
		})
		s.bp.LoadPageDescs(recoveryRes.PageDescs)
		s.cp = NewCheckpointer(s.bp, heapFile, wal)
	}

	return s, nil
}

func (s *Engine) registerInFlight(names ...string) {
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	for _, name := range names {
		if name != "" {
			s.inFlightOversize[name]++
		}
	}
}

func (s *Engine) unregisterInFlight(names ...string) {
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	for _, name := range names {
		if name != "" {
			s.inFlightOversize[name]--
			if s.inFlightOversize[name] <= 0 {
				delete(s.inFlightOversize, name)
			}
		}
	}
}

func (s *Engine) isInFlight(name string) bool {
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	return s.inFlightOversize[name] > 0
}

// Oversize file lifecycle invariants:
//  1. Delete only after the pointer is durable: the engine fsyncs the WAL through the
//     record's LSN before deleting any previous version's file so crash recovery can
//     always find the previous version if the new record is not yet durable.
//  2. Register before creating: the writer registers the target file name in the in-flight
//     registry before creating it on disk so other operations observe it as active.
//  3. Skip in-flight files: the writer checks the in-flight registry under writerMu and
//     skips deleting any file that is currently being written.
func (s *Engine) removeOversizeFileByName(fileName string) error {
	if fileName == "" {
		return nil
	}
	p := filepath.Join(s.dir, "oversize", fileName)
	if err := s.fs.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to remove oversize file %s: %w", p, err)
	}
	if err := s.fs.SyncDir(filepath.Join(s.dir, "oversize")); err != nil {
		return fmt.Errorf("failed to sync oversize dir: %w", err)
	}
	return nil
}

func (s *Engine) writeOversizeValueFile(qualifiedKey string, payload []byte) (string, error) {
	dir := filepath.Join(s.dir, "oversize")
	if err := s.fs.MkdirAll(dir, StoreDirMode); err != nil {
		return "", fmt.Errorf("failed to create oversize dir: %w", err)
	}

	fileName := OversizeFileName(qualifiedKey, payload)
	finalPath := filepath.Join(dir, fileName)

	tempName := fmt.Sprintf(".tmp-%s-%d", fileName, s.inFlightSeq.Add(1))
	tempPath := filepath.Join(dir, tempName)

	s.registerInFlight(tempName, fileName)

	cleanup := func(cause error) error {
		removeErr := s.fs.Remove(tempPath)
		s.unregisterInFlight(tempName, fileName)
		return errors.Join(cause, removeErr)
	}

	tempFile, err := s.fs.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
	if err != nil {
		return "", cleanup(fmt.Errorf("failed to create temp oversize file: %w", err))
	}

	if _, err := tempFile.WriteAt(payload, 0); err != nil {
		closeErr := tempFile.Close()
		return "", cleanup(errors.Join(fmt.Errorf("failed to write temp oversize file: %w", err), closeErr))
	}

	if err := tempFile.Sync(); err != nil {
		closeErr := tempFile.Close()
		return "", cleanup(errors.Join(fmt.Errorf("failed to sync temp oversize file: %w", err), closeErr))
	}

	if err := tempFile.Close(); err != nil {
		return "", cleanup(fmt.Errorf("failed to close temp oversize file: %w", err))
	}

	if err := s.fs.Rename(tempPath, finalPath); err != nil {
		return "", cleanup(fmt.Errorf("failed to rename temp oversize file to final: %w", err))
	}

	if err := s.fs.SyncDir(dir); err != nil {
		return "", cleanup(fmt.Errorf("failed to sync oversize dir: %w", err))
	}

	s.unregisterInFlight(tempName)
	return fileName, nil
}

// setFailed transitions the engine into the permanent failed state and notifies listeners.
func (s *Engine) setFailed(err error) {
	if err == nil {
		return
	}
	s.failMu.Lock()
	if s.failedErr == nil {
		s.failedErr = fmt.Errorf("%w: %v", ErrFailed, err)
		close(s.failedCh)
		if markerErr := s.writeFailureMarker(err); markerErr != nil {
			s.failedErr = fmt.Errorf("%w (marker error: %v)", s.failedErr, markerErr)
		}
	}
	s.failMu.Unlock()
}

func (s *Engine) writeFailureMarker(err error) error {
	markerPath := filepath.Join(s.dir, "FAILED")
	f, openErr := s.fs.OpenFile(markerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
	if openErr != nil {
		return openErr
	}
	var errs []error
	if _, writeErr := f.WriteAt([]byte(err.Error()+"\n"), 0); writeErr != nil {
		errs = append(errs, writeErr)
	}
	if syncErr := f.Sync(); syncErr != nil {
		errs = append(errs, syncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		errs = append(errs, closeErr)
	}
	if syncDirErr := s.fs.SyncDir(s.dir); syncDirErr != nil {
		errs = append(errs, syncDirErr)
	}
	return errors.Join(errs...)
}

func (s *Engine) isFailed() bool {
	s.failMu.RLock()
	defer s.failMu.RUnlock()
	return s.failedErr != nil
}

func (s *Engine) failErr() error {
	s.failMu.RLock()
	defer s.failMu.RUnlock()
	if s.failedErr != nil {
		return s.failedErr
	}
	return ErrFailed
}

// Failed returns a channel that is closed when the engine enters the failed state.
func (s *Engine) Failed() <-chan struct{} {
	return s.failedCh
}

// Closed returns a channel that is closed when the engine is closed.
func (s *Engine) Closed() <-chan struct{} {
	return s.closedCh
}

// Err returns the sticky failure error, or nil if the engine is healthy.
func (s *Engine) Err() error {
	s.failMu.RLock()
	defer s.failMu.RUnlock()
	return s.failedErr
}

// Wiped returns true if the engine wiped a corrupt/failed database during Open.
func (s *Engine) Wiped() bool {
	return s.wiped
}

// DBID returns the store's unique database ID.
func (s *Engine) DBID() [16]byte {
	return s.dbID
}

// Cipher returns the configured cipher.
func (s *Engine) Cipher() Cipher {
	return s.cipher
}

// Path returns the store directory.
func (s *Engine) Path() string {
	return s.dir
}

// DirectIOFallbackCount returns the number of times direct I/O could not be used and fell back to buffered I/O.
func (s *Engine) DirectIOFallbackCount() int64 {
	return GlobalMetrics.DirectIOFallbackCount.Load()
}

// CompressionCodec returns the engine's configured compression algorithm.
func (s *Engine) CompressionCodec() CompressionCodec {
	return s.compressionCodec
}

// MaxObjectSize returns the maximum uncompressed object size accepted during decompression.
func (s *Engine) MaxObjectSize() int {
	return s.maxObjectSize
}

func (s *Engine) compress(payload []byte) ([]byte, error) {
	return compressValue(payload, s.compressionCodec, s.maxObjectSize)
}

func (s *Engine) decompress(data []byte) ([]byte, error) {
	return decompressValue(data, s.maxObjectSize)
}

func (s *Engine) putRecordIntoSlottedPageLocked(qKey string, payload []byte, lsn uint64, existing KeyIndexEntry, inIndex bool, isOversize bool) (uint64, uint32, error) {
	var targetPage uint64
	if inIndex && existing.NumBlocks == 1 && existing.LogicalPage != 0 {
		targetPage = existing.LogicalPage
	} else if s.activeSlottedPage != 0 {
		targetPage = s.activeSlottedPage
	} else if p, ok := s.emptyPages.Pop(); ok {
		targetPage = p
		s.activeSlottedPage = targetPage
	} else {
		targetPage = s.nextLogicalPage
		s.nextLogicalPage++
		s.activeSlottedPage = targetPage
	}

	handle, err := s.bp.PinOrAllocatePage(targetPage, 1, lsn)
	if err != nil {
		return 0, 0, err
	}

	handle.Desc.Mu.Lock()
	slotted, err := WrapSlottedPage(handle.Block(0))
	if err != nil {
		handle.Desc.Mu.Unlock()
		handle.Unpin()
		return 0, 0, err
	}

	slotIdx, err := slotted.PutWithFlag(qKey, payload, lsn, isOversize)
	if err == nil {
		if inIndex && targetPage == existing.LogicalPage && existing.NumBlocks == 1 && slotIdx != existing.Slot {
			if delErr := slotted.Delete(existing.Slot, lsn); delErr != nil && !errors.Is(delErr, ErrSlotNotFound) {
				handle.Desc.Mu.Unlock()
				handle.Unpin()
				return 0, 0, delErr
			}
		}
	} else if errors.Is(err, ErrPageFull) {
		handle.Desc.Mu.Unlock()
		handle.Unpin()

		// Allocate next slotted page
		if p, ok := s.emptyPages.Pop(); ok {
			targetPage = p
		} else {
			targetPage = s.nextLogicalPage
			s.nextLogicalPage++
		}
		s.activeSlottedPage = targetPage

		handle, err = s.bp.AllocateNewPage(targetPage, 1, lsn)
		if err != nil {
			return 0, 0, err
		}

		handle.Desc.Mu.Lock()
		slotted, err = WrapSlottedPage(handle.Block(0))
		if err != nil {
			handle.Desc.Mu.Unlock()
			handle.Unpin()
			return 0, 0, err
		}
		slotIdx, err = slotted.PutWithFlag(qKey, payload, lsn, isOversize)
		if err != nil {
			handle.Desc.Mu.Unlock()
			handle.Unpin()
			return 0, 0, err
		}
	} else {
		handle.Desc.Mu.Unlock()
		handle.Unpin()
		return 0, 0, err
	}

	slotted.Finalize()
	handle.Desc.Mu.Unlock()
	s.bp.MarkDirty(targetPage, lsn)
	handle.Unpin()

	// If old record was on a different page, delete its slot or clear its page
	if inIndex && (targetPage != existing.LogicalPage || existing.NumBlocks > 1) {
		if existing.NumBlocks == 1 && existing.LogicalPage != 0 {
			if delErr := s.deleteSlotFromPageLocked(existing.LogicalPage, existing.Slot, lsn); delErr != nil {
				return 0, 0, delErr
			}
		} else if existing.NumBlocks > 1 {
			if clrErr := s.clearLogicalPageLocked(existing.LogicalPage, lsn); clrErr != nil {
				return 0, 0, clrErr
			}
		}
	}

	return targetPage, slotIdx, nil
}

// Put writes an object to the engine, encrypting if a cipher is configured.
func (s *Engine) Put(tableName, key string, payload []byte) error {
	if s.isFailed() {
		return s.failErr()
	}

	qKey := qualifyKey(tableName, key)

	// Validate key length: a key over 65535 bytes cannot fit in the 16-bit key length field.
	if len(qKey) > 65535 {
		return ErrObjectOversize
	}

	// Compress payload
	compressed, err := s.compress(payload)
	if err != nil {
		s.setFailed(err)
		return s.failErr()
	}

	// Encrypt payload if cipher is configured
	toStore := compressed
	if s.cipher != nil {
		ad := AdditionalData(tableName, key)
		encrypted, err := s.cipher.Encrypt(compressed, ad)
		if err != nil {
			s.setFailed(err)
			return s.failErr()
		}
		toStore = encrypted
	}

	// Handle oversize object: records exceeding 512-block multi-block capacity persist to disk under oversize directory
	if !fitsInMultiBlockPage(len(qKey), len(toStore)) {
		fileName := OversizeFileName(qKey, toStore)
		checksum := OversizeHash(qKey, toStore)

		s.keyMu.RLock()
		existing, inIndex := s.keyIndex[qKey]
		s.keyMu.RUnlock()

		skipWrite := inIndex && existing.IsOversize && existing.OversizeFileName == fileName
		if !skipWrite {
			if _, err := s.writeOversizeValueFile(qKey, toStore); err != nil {
				return err
			}
		}

		s.writerMu.Lock()
		defer s.writerMu.Unlock()

		if !skipWrite {
			defer s.unregisterInFlight(fileName)
		}

		if s.isFailed() {
			return s.failErr()
		}

		s.keyMu.RLock()
		existing, inIndex = s.keyIndex[qKey]
		s.keyMu.RUnlock()

		// Re-check the skip decision under writerMu lock.
		// If the index changed while waiting for the lock, write the file now.
		if skipWrite && (!inIndex || !existing.IsOversize || existing.OversizeFileName != fileName) {
			if _, err := s.writeOversizeValueFile(qKey, toStore); err != nil {
				return err
			}
			defer s.unregisterInFlight(fileName)
		}

		var oldOversizeFile string
		if inIndex && existing.IsOversize && existing.OversizeFileName != fileName {
			oldOversizeFile = existing.OversizeFileName
		}

		ptrPayload := EncodeOversizePointer(uint64(len(toStore)), checksum, fileName)
		rec := Record{
			Type:    RecordTypePutPointer,
			Key:     qKey,
			Payload: ptrPayload,
		}
		lsn, err := s.wal.AppendRecord(&rec)
		if err != nil {
			s.setFailed(err)
			return s.failErr()
		}

		targetPage, slotIdx, putErr := s.putRecordIntoSlottedPageLocked(qKey, ptrPayload, lsn, existing, inIndex, true)
		if putErr != nil {
			s.setFailed(putErr)
			return s.failErr()
		}

		s.keyMu.Lock()
		wasOversize := inIndex && existing.IsOversize
		s.keyIndex[qKey] = KeyIndexEntry{
			LogicalPage:      targetPage,
			Slot:             slotIdx,
			LSN:              lsn,
			NumBlocks:        1,
			IsOversize:       true,
			OversizeFileName: fileName,
		}
		s.oversizeObjects[qKey] = bytes.Clone(toStore)
		if !wasOversize {
			GlobalMetrics.OversizeObjectsCount.Add(1)
		}
		s.keyMu.Unlock()

		// Invariants 1 & 3: delete only after durable; skip files being written in flight (see removeOversizeFileByName).
		if oldOversizeFile != "" && !s.isInFlight(oldOversizeFile) {
			if err := s.wal.SyncThrough(lsn); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
			if err := s.removeOversizeFileByName(oldOversizeFile); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
		}

		return nil
	}

	s.writerMu.Lock()
	defer s.writerMu.Unlock()

	if s.isFailed() {
		return s.failErr()
	}

	s.keyMu.RLock()
	existing, inIndex := s.keyIndex[qKey]
	s.keyMu.RUnlock()

	var oldOversizeFile string
	if inIndex && existing.IsOversize {
		oldOversizeFile = existing.OversizeFileName
	}

	// Append record to WAL, assigning LSN under WAL lock
	rec := Record{
		Type:    RecordTypePut,
		Key:     qKey,
		Payload: toStore,
	}
	lsn, err := s.wal.AppendRecord(&rec)
	if err != nil {
		s.setFailed(err)
		return s.failErr()
	}

	// Transition from oversize to standard page
	if oldOversizeFile != "" {
		s.keyMu.Lock()
		delete(s.oversizeObjects, qKey)
		GlobalMetrics.OversizeObjectsCount.Add(-1)
		s.keyMu.Unlock()
	}

	// Check if this object fits in a 1-block slotted page
	if CanFitInSlottedPage(len(qKey), len(toStore)) {
		targetPage, slotIdx, putErr := s.putRecordIntoSlottedPageLocked(qKey, toStore, lsn, existing, inIndex, false)
		if putErr != nil {
			s.setFailed(putErr)
			return s.failErr()
		}

		s.keyMu.Lock()
		s.keyIndex[qKey] = KeyIndexEntry{
			LogicalPage: targetPage,
			Slot:        slotIdx,
			LSN:         lsn,
			NumBlocks:   1,
		}
		s.keyMu.Unlock()
	} else {
		// Multi-block page
		numBlocks, err := CalculateMultiBlockCount(len(qKey), len(toStore))
		if err != nil {
			return err
		}

		// If replacing an existing slotted or multi-block record, clean up old location (Item 15)
		if inIndex {
			if existing.NumBlocks == 1 {
				if err := s.deleteSlotFromPageLocked(existing.LogicalPage, existing.Slot, lsn); err != nil {
					s.setFailed(err)
					return s.failErr()
				}
			} else if existing.NumBlocks > 1 {
				if err := s.clearLogicalPageLocked(existing.LogicalPage, lsn); err != nil {
					s.setFailed(err)
					return s.failErr()
				}
			}
		}

		var targetPage uint64
		if p, ok := s.emptyPages.Pop(); ok {
			targetPage = p
		} else {
			targetPage = s.nextLogicalPage
			s.nextLogicalPage++
		}

		mbPage, err := NewMultiBlockPage(targetPage, lsn, qKey, toStore)
		if err != nil {
			s.setFailed(err)
			return s.failErr()
		}

		handle, err := s.bp.AllocateNewPage(targetPage, numBlocks, lsn)
		if err != nil {
			s.setFailed(err)
			return s.failErr()
		}

		handle.Desc.Mu.Lock()
		for i, b := range mbPage.Blocks {
			FinalizeBlockCRC(b)
			copy(handle.Block(i), b)
		}
		handle.Desc.Mu.Unlock()
		s.bp.MarkDirty(targetPage, lsn)
		handle.Unpin()

		s.keyMu.Lock()
		s.keyIndex[qKey] = KeyIndexEntry{
			LogicalPage: targetPage,
			Slot:        0,
			LSN:         lsn,
			NumBlocks:   numBlocks,
		}
		s.keyMu.Unlock()
	}

	// Invariants 1 & 3: delete only after durable; skip files being written in flight (see removeOversizeFileByName).
	if oldOversizeFile != "" && !s.isInFlight(oldOversizeFile) {
		if err := s.wal.SyncThrough(lsn); err != nil {
			s.setFailed(err)
			return s.failErr()
		}
		if err := s.removeOversizeFileByName(oldOversizeFile); err != nil {
			s.setFailed(err)
			return s.failErr()
		}
	}

	return nil
}

func (s *Engine) deleteSlotFromPageLocked(pageID uint64, slotIdx uint32, lsn uint64) error {
	handle, err := s.bp.PinPage(pageID)
	if err != nil {
		return fmt.Errorf("failed to pin page %d for slot deletion: %w", pageID, err)
	}
	handle.Desc.Mu.Lock()
	slotted, wrapErr := WrapSlottedPage(handle.Block(0))
	if wrapErr != nil {
		handle.Desc.Mu.Unlock()
		handle.Unpin()
		return fmt.Errorf("failed to wrap page %d: %w", pageID, wrapErr)
	}
	delErr := slotted.Delete(slotIdx, lsn)
	if delErr != nil && !errors.Is(delErr, ErrSlotNotFound) {
		handle.Desc.Mu.Unlock()
		handle.Unpin()
		return fmt.Errorf("failed to delete slot %d from page %d: %w", slotIdx, pageID, delErr)
	}
	slotted.Finalize()
	// Only add to emptyPages if a slot was successfully deleted and the page
	// transitioned to having zero active slots. If slotted.Delete returned ErrSlotNotFound,
	// no slot was removed and the page was already empty or unchanged.
	// emptyPageTracker maintains an O(1) set alongside the slice to prevent
	// duplicate entries by construction.
	if delErr == nil && slotted.ActiveSlotsCount() == 0 {
		s.emptyPages.Add(pageID)
		if s.activeSlottedPage == pageID {
			s.activeSlottedPage = 0
		}
	}
	handle.Desc.Mu.Unlock()
	s.bp.MarkDirty(pageID, lsn)
	handle.Unpin()
	return nil
}

// clearLogicalPageLocked writes a tombstone to clear a superseded or deleted multi-block page (Items 15, 16).
func (s *Engine) clearLogicalPageLocked(logicalPage uint64, lsn uint64) error {
	handle, err := s.bp.PinPage(logicalPage)
	if err != nil {
		return fmt.Errorf("failed to pin multi-block page %d for clearing: %w", logicalPage, err)
	}
	handle.Desc.Mu.Lock()
	tombstone := make([]byte, BlockSize)
	hdr := BlockHeader{LogicalPage: logicalPage, LSN: lsn, NumBlocks: 1}
	EncodeBlockHeader(hdr, tombstone)
	FinalizeBlockCRC(tombstone)
	copy(handle.Block(0), tombstone)
	handle.Desc.Mu.Unlock()
	s.bp.MarkDirty(logicalPage, lsn)
	handle.Unpin()
	// A multi-block page holds exactly one record and is only cleared when that record
	// is deleted or moved to a different page. emptyPageTracker maintains an O(1) set
	// alongside the slice to ensure by construction that a page is added at most once.
	s.emptyPages.Add(logicalPage)
	return nil
}

// Get retrieves an object by table and key, decrypting if a cipher is configured.
func (s *Engine) Get(tableName, key string) ([]byte, bool, error) {
	if s.isFailed() {
		return nil, false, s.failErr()
	}

	qKey := qualifyKey(tableName, key)

	for attempt := 0; attempt < 4; attempt++ {
		s.keyMu.RLock()
		entry, exists := s.keyIndex[qKey]
		s.keyMu.RUnlock()

		if !exists {
			return nil, false, nil
		}

		val, matched, err := s.readIndexEntry(tableName, key, qKey, entry)
		if matched {
			return val, true, nil
		}
		if entry.IsOversize {
			if err != nil {
				return nil, false, err
			}
			return nil, false, nil
		}
		if err != nil && (errors.Is(err, ErrDecrypt) || s.isFailed()) {
			return nil, false, err
		}

		// Optimistic read mismatched or failed to pin. Check if a concurrent writer modified the index.
		s.keyMu.RLock()
		curEntry, stillExists := s.keyIndex[qKey]
		s.keyMu.RUnlock()
		if !stillExists || curEntry.LSN != entry.LSN || curEntry.LogicalPage != entry.LogicalPage {
			runtime.Gosched()
			continue // Concurrent modification, retry!
		}
		// Index entry hasn't changed, but record didn't match or pin failed. Fall back to locked read.
		break
	}

	// Under sustained write contention, optimistic retries can repeatedly lose races.
	// Fall back to acquiring writerMu.RLock(), which writers exclude, ensuring readers
	// always make progress.
	s.writerMu.RLock()
	defer s.writerMu.RUnlock()
	return s.getLocked(tableName, key)
}

// getLocked retrieves an object assuming s.writerMu.RLock() is held by the caller.
// Under writerMu.RLock(), concurrent writes and deletes are excluded, ensuring that
// the key index and page records cannot be invalidated during the read.
func (s *Engine) getLocked(tableName, key string) ([]byte, bool, error) {
	if s.isFailed() {
		return nil, false, s.failErr()
	}

	qKey := qualifyKey(tableName, key)

	s.keyMu.RLock()
	entry, exists := s.keyIndex[qKey]
	s.keyMu.RUnlock()

	if !exists {
		return nil, false, nil
	}

	val, matched, err := s.readIndexEntry(tableName, key, qKey, entry)
	if err != nil {
		if errors.Is(err, ErrDecrypt) {
			return nil, false, err
		}
		s.setFailed(err)
		return nil, false, s.failErr()
	}
	if !matched {
		if entry.IsOversize {
			return nil, false, nil
		}
		s.setFailed(fmt.Errorf("corruption/stale read detected for %s: expected LSN %d", key, entry.LSN))
		return nil, false, s.failErr()
	}

	return val, true, nil
}

// readIndexEntry reads the record corresponding to entry, verifies its key and LSN,
// and decrypts/decompresses the payload. It returns matched=true when the record
// was found and matched entry, or matched=false if the record did not match or could
// not be read due to page conflict.
func (s *Engine) readIndexEntry(tableName, key, qKey string, entry KeyIndexEntry) ([]byte, bool, error) {
	if entry.IsOversize {
		s.keyMu.RLock()
		data, ok := s.oversizeObjects[qKey]
		s.keyMu.RUnlock()
		if !ok {
			handle, err := s.bp.PinPage(entry.LogicalPage)
			if err != nil {
				return nil, false, fmt.Errorf("failed to pin page %d for key %s: %w", entry.LogicalPage, key, err)
			}
			handle.Desc.Mu.RLock()
			var rawPtr []byte
			var isSlotOversize bool
			slotted, wrapErr := WrapSlottedPage(handle.Block(0))
			if wrapErr == nil {
				var raw []byte
				_, raw, _, isSlotOversize, err = slotted.GetWithFlag(entry.Slot)
				if err == nil {
					rawPtr = bytes.Clone(raw)
				}
			} else {
				err = wrapErr
			}
			handle.Desc.Mu.RUnlock()
			handle.Unpin()

			if err != nil || !isSlotOversize {
				return nil, false, fmt.Errorf("%w: missing or invalid oversize slot %d on page %d: %v", ErrCorruptStore, entry.Slot, entry.LogicalPage, err)
			}

			expectedLen, expectedChecksum, fileName, decodeErr := DecodeOversizePointer(rawPtr)
			if decodeErr != nil {
				return nil, false, fmt.Errorf("%w: failed to decode oversize pointer: %v", ErrCorruptStore, decodeErr)
			}

			p := filepath.Join(s.dir, "oversize", fileName)
			f, openErr := s.fs.Open(p)
			if openErr != nil {
				return nil, false, fmt.Errorf("%w: missing oversize file %s: %v", ErrCorruptStore, fileName, openErr)
			}
			sz, sizeErr := f.Size()
			if sizeErr != nil {
				closeErr := f.Close()
				return nil, false, fmt.Errorf("%w: failed to get size of oversize file %s: %v", ErrCorruptStore, fileName, errors.Join(sizeErr, closeErr))
			}
			if uint64(sz) != expectedLen {
				closeErr := f.Close()
				return nil, false, errors.Join(fmt.Errorf("%w: oversize file %s size mismatch (want %d, got %d)", ErrCorruptStore, fileName, expectedLen, sz), closeErr)
			}
			fileData := make([]byte, sz)
			if _, readErr := f.ReadAt(fileData, 0); readErr != nil && !errors.Is(readErr, io.EOF) {
				closeErr := f.Close()
				return nil, false, fmt.Errorf("%w: failed to read oversize file %s: %v", ErrCorruptStore, fileName, errors.Join(readErr, closeErr))
			}
			if closeErr := f.Close(); closeErr != nil {
				return nil, false, fmt.Errorf("%w: failed to close oversize file %s: %v", ErrCorruptStore, fileName, closeErr)
			}

			actualChecksum := OversizeHash(qKey, fileData)
			if actualChecksum != expectedChecksum {
				return nil, false, fmt.Errorf("%w: corrupt oversize file %s (checksum mismatch)", ErrCorruptStore, fileName)
			}

			data = fileData
			s.keyMu.Lock()
			s.oversizeObjects[qKey] = bytes.Clone(data)
			s.keyMu.Unlock()
		}
		res := bytes.Clone(data)
		if s.cipher != nil {
			ad := AdditionalData(tableName, key)
			decrypted, err := s.cipher.Decrypt(res, ad)
			if err != nil {
				return nil, false, fmt.Errorf("%w: %v", ErrDecrypt, err)
			}
			res = decrypted
		}
		decompressed, err := s.decompress(res)
		if err != nil {
			s.setFailed(err)
			return nil, false, s.failErr()
		}
		return decompressed, true, nil
	}

	handle, err := s.bp.PinPage(entry.LogicalPage)
	if err != nil {
		return nil, false, fmt.Errorf("failed to pin page %d for key %s: %w", entry.LogicalPage, key, err)
	}

	handle.Desc.Mu.RLock()
	var recKey string
	var recPayload []byte
	var recLSN uint64

	if handle.Desc.NumBlocks == 1 {
		slotted, wrapErr := WrapSlottedPage(handle.Block(0))
		if wrapErr == nil {
			var raw []byte
			recKey, raw, recLSN, err = slotted.Get(entry.Slot)
			if err == nil {
				recPayload = bytes.Clone(raw)
			}
		} else {
			err = wrapErr
		}
	} else {
		var raw []byte
		recKey, raw, recLSN, err = DecodeMultiBlockPage(handle.Blocks())
		if err == nil {
			recPayload = bytes.Clone(raw)
		}
	}
	handle.Desc.Mu.RUnlock()
	handle.Unpin()

	if err != nil || recKey != qKey || recLSN != entry.LSN {
		return nil, false, nil
	}

	if s.cipher != nil {
		ad := AdditionalData(tableName, key)
		decrypted, err := s.cipher.Decrypt(recPayload, ad)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrDecrypt, err)
		}
		recPayload = decrypted
	}

	decompressed, err := s.decompress(recPayload)
	if err != nil {
		s.setFailed(err)
		return nil, false, s.failErr()
	}

	return decompressed, true, nil
}

// Delete removes an object by key.
func (s *Engine) Delete(tableName, key string) error {
	if s.isFailed() {
		return s.failErr()
	}

	s.writerMu.Lock()
	defer s.writerMu.Unlock()

	qKey := qualifyKey(tableName, key)

	s.keyMu.Lock()
	entry, exists := s.keyIndex[qKey]
	if !exists {
		s.keyMu.Unlock()
		return nil
	}
	delete(s.keyIndex, qKey)
	if entry.IsOversize {
		delete(s.oversizeObjects, qKey)
		GlobalMetrics.OversizeObjectsCount.Add(-1)
	}
	s.keyMu.Unlock()

	rec := Record{
		Type: RecordTypeDelete,
		Key:  qKey,
	}
	lsn, err := s.wal.AppendRecord(&rec)
	if err != nil {
		s.setFailed(err)
		return s.failErr()
	}

	if entry.IsOversize {
		if entry.NumBlocks == 1 && entry.LogicalPage != 0 {
			if err := s.deleteSlotFromPageLocked(entry.LogicalPage, entry.Slot, lsn); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
		}

		// Invariants 1 & 3: delete only after durable; skip files being written in flight (see removeOversizeFileByName).
		if entry.OversizeFileName != "" && !s.isInFlight(entry.OversizeFileName) {
			if err := s.wal.SyncThrough(lsn); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
			if err := s.removeOversizeFileByName(entry.OversizeFileName); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
		}
	} else {
		if entry.NumBlocks == 1 {
			if err := s.deleteSlotFromPageLocked(entry.LogicalPage, entry.Slot, lsn); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
		} else {
			if err := s.clearLogicalPageLocked(entry.LogicalPage, lsn); err != nil {
				s.setFailed(err)
				return s.failErr()
			}
		}
	}

	return nil
}

// Scan provides a point-in-time consistent iteration of all objects in a table.
// It acquires writerMu.RLock() so concurrent writes/deletes do not mutate the view.
// Plaintext bytes are supplied to fn; if fn returns an error (or ErrStopScan), scanning stops.
func (s *Engine) Scan(tableName string, fn func(key string, value []byte) error) error {
	if s.isFailed() {
		return s.failErr()
	}

	s.writerMu.RLock()
	defer s.writerMu.RUnlock()

	s.keyMu.RLock()
	prefix := tableName + "\x00"
	var keys []string
	for qKey := range s.keyIndex {
		if strings.HasPrefix(qKey, prefix) {
			_, userKey := unqualifyKey(qKey)
			keys = append(keys, userKey)
		}
	}
	s.keyMu.RUnlock()

	sort.Strings(keys)

	for _, userKey := range keys {
		val, exists, err := s.getLocked(tableName, userKey)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := fn(userKey, val); err != nil {
			if errors.Is(err, ErrStopScan) {
				return nil
			}
			return err
		}
	}
	return nil
}

// ListKeys returns all keys currently present in the key index for a specific table (or all tables if omitted).
func (s *Engine) ListKeys(tableName ...string) []string {
	if s.isFailed() {
		return nil
	}

	s.keyMu.RLock()
	defer s.keyMu.RUnlock()

	var prefix string
	if len(tableName) > 0 && tableName[0] != "" {
		prefix = tableName[0] + "\x00"
	}

	keys := make([]string, 0, len(s.keyIndex))
	for k := range s.keyIndex {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			_, userKey := unqualifyKey(k)
			keys = append(keys, userKey)
		}
	}
	sort.Strings(keys)
	return keys
}

// RecordItem holds a key and payload returned from List().
type RecordItem struct {
	Key     string
	Payload []byte
}

// List returns a point-in-time consistent view of all objects in the table.
func (s *Engine) List(tableName string) ([]RecordItem, error) {
	var items []RecordItem
	err := s.Scan(tableName, func(k string, v []byte) error {
		items = append(items, RecordItem{Key: k, Payload: v})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// Sync ensures that all appended WAL records are flushed to disk and fsynced.
func (s *Engine) Sync() error {
	if s.isFailed() {
		return s.failErr()
	}
	if err := s.wal.Sync(); err != nil {
		s.setFailed(err)
		return s.failErr()
	}
	return nil
}

// Flush flushes all buffered WAL records to disk and fsynced.
func (s *Engine) Flush() error {
	if s.isFailed() {
		return s.failErr()
	}
	if err := s.wal.Flush(); err != nil {
		s.setFailed(err)
		return s.failErr()
	}
	return nil
}

// Checkpoint performs a non-blocking checkpoint.
func (s *Engine) Checkpoint() (uint64, error) {
	if s.isFailed() {
		return 0, s.failErr()
	}

	chkLSN, err := s.cp.Checkpoint()
	if err != nil {
		s.setFailed(err)
		return 0, s.failErr()
	}
	return chkLSN, nil
}

// Close flushes and shuts down engine components.
func (s *Engine) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.closedCh)

	var errs []error
	// If not failed, checkpoint on close to truncate WAL and speed up reopen
	if !s.isFailed() && s.cp != nil {
		if _, err := s.cp.Checkpoint(); err != nil {
			errs = append(errs, err)
		}
	}

	if s.bp != nil {
		if err := s.bp.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.heapFile != nil {
		if err := s.heapFile.Sync(); err != nil {
			errs = append(errs, err)
		}
		if err := s.heapFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.wal != nil {
		if err := s.wal.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if s.autoDelete {
		if err := os.RemoveAll(s.dir); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
