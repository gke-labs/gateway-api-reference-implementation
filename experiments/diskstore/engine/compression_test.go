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
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func makeRepetitivePayload(size int) []byte {
	pattern := []byte("ConfigMap data with structured fields: key=value, metadata=informer; ")
	b := make([]byte, size)
	for i := 0; i < size; i += len(pattern) {
		copy(b[i:], pattern)
	}
	return b
}

func makeRandomPayload(size int) []byte {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return b
}

// TestCompression_RawFallbackAndSavingsRule tests that compressible values are stored compressed
// with codec and uncompressed length recorded, while incompressible values or values failing
// the 10% savings rule are stored raw with CodecNone.
func TestCompression_RawFallbackAndSavingsRule(t *testing.T) {
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir("test_compress_raw_fallback"), WithCompressionCodec(CodecZstd), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// 1. Compressible value (8000 bytes)
	compressibleVal := makeRepetitivePayload(8000)
	if err := store.Put("ConfigMap", "cm-compressed", compressibleVal); err != nil {
		t.Fatalf("Put compressible failed: %v", err)
	}

	qKey := qualifyKey("ConfigMap", "cm-compressed")
	entry := store.keyIndex[qKey]
	h, err := store.bp.PinPage(entry.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	var storedPayload []byte
	if entry.NumBlocks == 1 {
		sp, _ := WrapSlottedPage(h.Block(0))
		_, storedPayload, _, _ = sp.Get(entry.Slot)
	} else {
		_, storedPayload, _, _ = DecodeMultiBlockPage(h.Blocks())
	}
	h.Unpin()

	if len(storedPayload) < compressionHeaderSize {
		t.Fatalf("stored payload too short: %d", len(storedPayload))
	}
	if storedPayload[0] != byte(CodecZstd) {
		t.Fatalf("expected codec byte %d (CodecZstd), got %d", CodecZstd, storedPayload[0])
	}
	recordedLen := binary.BigEndian.Uint32(storedPayload[1:5])
	if recordedLen != 8000 {
		t.Fatalf("expected recorded uncompressed length 8000, got %d", recordedLen)
	}
	if len(storedPayload) >= 8000 {
		t.Fatalf("expected compressed size to be smaller than 8000, got %d", len(storedPayload))
	}

	got, exists, err := store.Get("ConfigMap", "cm-compressed")
	if err != nil || !exists || !bytes.Equal(got, compressibleVal) {
		t.Fatalf("Get returned invalid payload")
	}

	// 2. Incompressible value (5000 random bytes)
	incompressibleVal := makeRandomPayload(5000)
	if err := store.Put("ConfigMap", "cm-raw-above-thresh", incompressibleVal); err != nil {
		t.Fatalf("Put incompressible failed: %v", err)
	}

	qKeyRaw := qualifyKey("ConfigMap", "cm-raw-above-thresh")
	entryRaw := store.keyIndex[qKeyRaw]
	hRaw, err := store.bp.PinPage(entryRaw.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	var storedRawPayload []byte
	if entryRaw.NumBlocks == 1 {
		sp, _ := WrapSlottedPage(hRaw.Block(0))
		_, storedRawPayload, _, _ = sp.Get(entryRaw.Slot)
	} else {
		_, storedRawPayload, _, _ = DecodeMultiBlockPage(hRaw.Blocks())
	}
	hRaw.Unpin()

	if storedRawPayload[0] != byte(CodecNone) {
		t.Fatalf("expected codec byte %d (CodecNone) for incompressible data, got %d", CodecNone, storedRawPayload[0])
	}
	if !bytes.Equal(storedRawPayload[1:], incompressibleVal) {
		t.Fatalf("stored raw payload mismatch")
	}

	gotRaw, exists, err := store.Get("ConfigMap", "cm-raw-above-thresh")
	if err != nil || !exists || !bytes.Equal(gotRaw, incompressibleVal) {
		t.Fatalf("Get incompressible returned invalid payload")
	}

	// 3. Compressible small value (2000 bytes) is now compressed
	smallVal := makeRepetitivePayload(2000)
	if err := store.Put("ConfigMap", "cm-small", smallVal); err != nil {
		t.Fatalf("Put small failed: %v", err)
	}

	qKeySmall := qualifyKey("ConfigMap", "cm-small")
	entrySmall := store.keyIndex[qKeySmall]
	hSmall, err := store.bp.PinPage(entrySmall.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	var storedSmallPayload []byte
	spSmall, _ := WrapSlottedPage(hSmall.Block(0))
	_, storedSmallPayload, _, _ = spSmall.Get(entrySmall.Slot)
	hSmall.Unpin()

	if storedSmallPayload[0] != byte(CodecZstd) {
		t.Fatalf("expected codec byte %d (CodecZstd) for compressible small data, got %d", CodecZstd, storedSmallPayload[0])
	}
	if len(storedSmallPayload) >= 2000 {
		t.Fatalf("expected compressed size to be smaller than 2000, got %d", len(storedSmallPayload))
	}

	gotSmall, exists, err := store.Get("ConfigMap", "cm-small")
	if err != nil || !exists || !bytes.Equal(gotSmall, smallVal) {
		t.Fatalf("Get small returned invalid payload")
	}

	// 4. Tiny compressible value (64 bytes) fails 10% savings rule and falls back to CodecNone
	tinyVal := makeRepetitivePayload(64)
	if err := store.Put("ConfigMap", "cm-tiny", tinyVal); err != nil {
		t.Fatalf("Put tiny failed: %v", err)
	}

	qKeyTiny := qualifyKey("ConfigMap", "cm-tiny")
	entryTiny := store.keyIndex[qKeyTiny]
	hTiny, err := store.bp.PinPage(entryTiny.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	var storedTinyPayload []byte
	spTiny, _ := WrapSlottedPage(hTiny.Block(0))
	_, storedTinyPayload, _, _ = spTiny.Get(entryTiny.Slot)
	hTiny.Unpin()

	if storedTinyPayload[0] != byte(CodecNone) {
		t.Fatalf("expected codec byte %d (CodecNone) for tiny data failing 10%% rule, got %d", CodecNone, storedTinyPayload[0])
	}
	if !bytes.Equal(storedTinyPayload[1:], tinyVal) {
		t.Fatalf("stored tiny payload mismatch")
	}

	gotTiny, exists, err := store.Get("ConfigMap", "cm-tiny")
	if err != nil || !exists || !bytes.Equal(gotTiny, tinyVal) {
		t.Fatalf("Get tiny returned invalid payload")
	}
}

// TestCompression_RoundTripAllCodecs tests round-trips for CodecNone and CodecZstd
// at sizes across every page-class boundary.
func TestCompression_RoundTripAllCodecs(t *testing.T) {
	codecs := []struct {
		name  string
		codec CompressionCodec
	}{
		{"none", CodecNone},
		{"zstd", CodecZstd},
	}

	testSizes := []int{
		500, 3990, 4000, 4010,
		8040, 8060,
		16170, 16190,
		32420, 32450,
		64940, 64960,
		129960, 129980,
		260000, 260030,
		520100, 520130,
		1040300, 1040320,
		2080000, 2100000,
	}

	cipher, err := NewEphemeralAESGCMCipher()
	if err != nil {
		t.Fatalf("cipher creation failed: %v", err)
	}

	for _, tc := range codecs {
		t.Run(tc.name, func(t *testing.T) {
			memFS := NewMemFS()
			store, err := Open(
				WithFS(memFS),
				WithDir("test_roundtrip_"+tc.name),
				WithCompressionCodec(tc.codec),
				WithCipher(cipher),
				WithCreate(),
			)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer store.Close()

			for _, size := range testSizes {
				key := fmt.Sprintf("key-size-%d", size)
				payload := makeRepetitivePayload(size)

				if err := store.Put("Bucket", key, payload); err != nil {
					t.Fatalf("Put failed for size %d (codec %s): %v", size, tc.name, err)
				}

				got, exists, err := store.Get("Bucket", key)
				if err != nil || !exists {
					t.Fatalf("Get failed for size %d (codec %s): exists=%v, err=%v", size, tc.name, exists, err)
				}
				if len(got) != size || !bytes.Equal(got, payload) {
					t.Fatalf("round-trip payload mismatch for size %d (codec %s)", size, tc.name)
				}
			}
		})
	}
}

// TestCompression_PayloadExceedingMaxObjectSize_StoredRawAndReadable asserts that payloads exceeding
// MaxObjectSize are stored uncompressed with CodecNone rather than rejected or failing on read.
func TestCompression_PayloadExceedingMaxObjectSize_StoredRawAndReadable(t *testing.T) {
	memFS := NewMemFS()
	const customMaxObjSize = 5000
	store, err := Open(
		WithFS(memFS),
		WithDir("test_max_object_size_fallback"),
		WithCompressionCodec(CodecZstd),
		WithMaxObjectSize(customMaxObjSize),
		WithCreate(),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// 7,000 bytes is compressible, but exceeds MaxObjectSize (5000).
	// compressValue must store it uncompressed with CodecNone rather than compressing it,
	// so that Get on read back will never reject it.
	largePayload := makeRepetitivePayload(7000)
	if err := store.Put("ConfigMap", "large-cm", largePayload); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	entry := store.keyIndex[qualifyKey("ConfigMap", "large-cm")]
	h, err := store.bp.PinPage(entry.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	var stored []byte
	if entry.NumBlocks == 1 {
		sp, _ := WrapSlottedPage(h.Block(0))
		_, stored, _, _ = sp.Get(entry.Slot)
	} else {
		_, stored, _, _ = DecodeMultiBlockPage(h.Blocks())
	}
	h.Unpin()

	if stored[0] != byte(CodecNone) {
		t.Fatalf("expected CodecNone for payload exceeding MaxObjectSize, got %d", stored[0])
	}
	if !bytes.Equal(stored[1:], largePayload) {
		t.Fatalf("stored payload mismatch")
	}

	// Read must succeed without error
	got, exists, err := store.Get("ConfigMap", "large-cm")
	if err != nil || !exists {
		t.Fatalf("Get failed: exists=%v, err=%v", exists, err)
	}
	if !bytes.Equal(got, largePayload) {
		t.Fatalf("retrieved payload does not match original")
	}
}

// TestEngine_OldFormatVersion_WipedOnOpen verifies that opening a store written before format versioning
// (or with an incompatible version) wipes the store and reports Wiped().
func TestEngine_OldFormatVersion_WipedOnOpen(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_old_format_store"

	// 1. Simulate an old store written in version 1 (where meta.db only contained a 16-byte DB ID)
	_ = memFS.MkdirAll(dir, 0755)
	metaPath := filepath.Join(dir, "meta.db")
	f, err := memFS.Create(metaPath)
	if err != nil {
		t.Fatalf("Create meta.db failed: %v", err)
	}
	oldDBID := make([]byte, 16)
	_, _ = rand.Read(oldDBID)
	_, _ = f.WriteAt(oldDBID, 0)
	_ = f.Close()

	// Add dummy heap file to simulate existing old data
	hf, err := memFS.Create(filepath.Join(dir, "heap.db"))
	if err != nil {
		t.Fatalf("Create heap.db failed: %v", err)
	}
	_, _ = hf.WriteAt([]byte("dummy old heap content"), 0)
	_ = hf.Close()

	// 2. Open store: Open must detect missing format version, wipe the store, and report Wiped()
	store, err := Open(WithFS(memFS), WithDir(dir), WithEraseOnError())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if !store.Wiped() {
		t.Fatalf("expected Wiped() == true for store with old 16-byte meta.db format")
	}

	// Verify meta.db has been rewritten with 20 bytes containing StoreFormatVersion
	metaF, err := memFS.Open(metaPath)
	if err != nil {
		t.Fatalf("Open meta.db failed: %v", err)
	}
	sz, _ := metaF.Size()
	if sz != int64(metaFileSize) {
		t.Fatalf("expected meta.db size %d after wipe, got %d", metaFileSize, sz)
	}
	buf := make([]byte, metaFileSize)
	_, _ = metaF.ReadAt(buf, 0)
	_ = metaF.Close()
	ver := binary.BigEndian.Uint32(buf[16:20])
	if ver != StoreFormatVersion {
		t.Fatalf("expected StoreFormatVersion %d, got %d", StoreFormatVersion, ver)
	}

	// Verify fresh store can write and read normally
	if err := store.Put("ConfigMap", "fresh-key", []byte("fresh-val")); err != nil {
		t.Fatalf("Put on wiped store failed: %v", err)
	}
	val, exists, err := store.Get("ConfigMap", "fresh-key")
	if err != nil || !exists || !bytes.Equal(val, []byte("fresh-val")) {
		t.Fatalf("Get on wiped store failed")
	}

	// 3. Reopening the store must NOT wipe it
	_ = store.Close()
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer store2.Close()
	if store2.Wiped() {
		t.Fatalf("expected Wiped() == false on reopening store")
	}
	val2, exists2, err := store2.Get("ConfigMap", "fresh-key")
	if err != nil || !exists2 || !bytes.Equal(val2, []byte("fresh-val")) {
		t.Fatalf("Get after reopen failed")
	}
}

// TestCompression_PageClassReduction verifies that an object moves to a smaller page class
// when compressed.
func TestCompression_PageClassReduction(t *testing.T) {
	const objectSize = 10240 // 10 KB ConfigMap
	payload := makeRepetitivePayload(objectSize)

	// 1. Uncompressed store
	memFSNone := NewMemFS()
	storeNone, err := Open(WithFS(memFSNone), WithDir("test_pageclass_none"), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open none failed: %v", err)
	}
	defer storeNone.Close()

	if err := storeNone.Put("ConfigMap", "cm-10k", payload); err != nil {
		t.Fatalf("Put none failed: %v", err)
	}
	entryNone := storeNone.keyIndex[qualifyKey("ConfigMap", "cm-10k")]

	// 2. Compressed store (zstd)
	memFSZstd := NewMemFS()
	storeZstd, err := Open(WithFS(memFSZstd), WithDir("test_pageclass_zstd"), WithCompressionCodec(CodecZstd), WithCreate())
	if err != nil {
		t.Fatalf("Open zstd failed: %v", err)
	}
	defer storeZstd.Close()

	if err := storeZstd.Put("ConfigMap", "cm-10k", payload); err != nil {
		t.Fatalf("Put zstd failed: %v", err)
	}
	entryZstd := storeZstd.keyIndex[qualifyKey("ConfigMap", "cm-10k")]

	t.Logf("10 KB object: uncompressed NumBlocks=%d, zstd NumBlocks=%d", entryNone.NumBlocks, entryZstd.NumBlocks)

	// 10 KB uncompressed requires a 4-block page (16 KiB)
	if entryNone.NumBlocks != 4 {
		t.Fatalf("expected uncompressed 10 KB object to require 4 blocks, got %d", entryNone.NumBlocks)
	}

	// 10 KB repetitive payload compresses to ~250 bytes, fitting in a 1-block slotted page
	if entryZstd.NumBlocks >= entryNone.NumBlocks {
		t.Fatalf("expected compressed object to move to smaller page class: got %d blocks, uncompressed %d blocks",
			entryZstd.NumBlocks, entryNone.NumBlocks)
	}
	if entryZstd.NumBlocks != 1 {
		t.Fatalf("expected compressed 10 KB object to fit in 1 block, got %d", entryZstd.NumBlocks)
	}

	// Verify Get returns exact original 10 KB
	got, exists, err := storeZstd.Get("ConfigMap", "cm-10k")
	if err != nil || !exists || !bytes.Equal(got, payload) {
		t.Fatalf("Get returned invalid payload")
	}
}

// TestCompression_RecoveryWALReplay verifies that recovery replays WAL records of compressed objects
// without decompressing, reconstructing identical pages and producing identical Get results.
func TestCompression_RecoveryWALReplay(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_compress_recovery"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	p1 := makeRepetitivePayload(8000)
	p2 := makeRepetitivePayload(16000)
	p3 := makeRepetitivePayload(2000)

	_ = store.Put("ConfigMap", "cm-1", p1)
	_ = store.Put("ConfigMap", "cm-2", p2)
	_ = store.Put("ConfigMap", "cm-3", p3)

	// Ensure WAL records are durable, but do not checkpoint
	if err := store.wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}

	// Simulate crash
	_ = store.Close()

	// Reopen store: crash recovery replays WAL redo onto page buffers
	storeRecovered, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer storeRecovered.Close()

	for key, want := range map[string][]byte{"cm-1": p1, "cm-2": p2, "cm-3": p3} {
		got, exists, err := storeRecovered.Get("ConfigMap", key)
		if err != nil || !exists {
			t.Fatalf("Get %s failed: exists=%v, err=%v", key, exists, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch for %s after recovery redo", key)
		}
	}
}

// TestCompression_Rejection_Direct tests rejection of corrupt decompression inputs directly.
func TestCompression_Rejection_Direct(t *testing.T) {
	const maxObjSize = 1000

	// 1. Recorded length exceeds maxObjectSize
	corruptLen := make([]byte, 10)
	corruptLen[0] = byte(CodecZstd)
	binary.BigEndian.PutUint32(corruptLen[1:5], uint32(maxObjSize+1))
	_, err := decompressValue(corruptLen, maxObjSize)
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("expected ErrObjectTooLarge, got %v", err)
	}

	// 2. Mismatch between recorded and actual length
	enc := zstdEncoderPool.Get().(*zstd.Encoder)
	compressed10 := enc.EncodeAll([]byte("0123456789"), nil)
	zstdEncoderPool.Put(enc)

	mismatchBuf := make([]byte, 5+len(compressed10))
	mismatchBuf[0] = byte(CodecZstd)
	binary.BigEndian.PutUint32(mismatchBuf[1:5], 20) // Claims 20 bytes, actual is 10
	copy(mismatchBuf[5:], compressed10)
	_, err = decompressValue(mismatchBuf, maxObjSize)
	if !errors.Is(err, ErrCorruptCompression) {
		t.Fatalf("expected ErrCorruptCompression for length mismatch, got %v", err)
	}

	// 3. Truncated data
	_, err = decompressValue([]byte{}, maxObjSize)
	if !errors.Is(err, ErrCorruptCompression) {
		t.Fatalf("expected ErrCorruptCompression for empty data, got %v", err)
	}

	_, err = decompressValue([]byte{byte(CodecZstd), 0, 0}, maxObjSize)
	if !errors.Is(err, ErrCorruptCompression) {
		t.Fatalf("expected ErrCorruptCompression for header truncated, got %v", err)
	}

	// Truncated zstd stream
	truncatedZstd := make([]byte, 5+len(compressed10)/2)
	truncatedZstd[0] = byte(CodecZstd)
	binary.BigEndian.PutUint32(truncatedZstd[1:5], 10)
	copy(truncatedZstd[5:], compressed10[:len(compressed10)/2])
	_, err = decompressValue(truncatedZstd, maxObjSize)
	if !errors.Is(err, ErrCorruptCompression) {
		t.Fatalf("expected ErrCorruptCompression for truncated stream, got %v", err)
	}

	// 4. Unknown codec byte (including reserved codec bytes 2 and 3)
	for _, unknown := range [][]byte{{0x02, 0x01}, {0x03, 0x01}, {0x77, 0x01}} {
		_, err = decompressValue(unknown, maxObjSize)
		if !errors.Is(err, ErrCorruptCompression) {
			t.Fatalf("expected ErrCorruptCompression for unknown codec 0x%02x, got %v", unknown[0], err)
		}
	}
}

// TestCompression_Rejection_StoreState verifies that encountering corruption during Get
// puts the store into the failed state without panicking or allocating large buffers.
func TestCompression_Rejection_StoreState(t *testing.T) {
	testCases := []struct {
		name          string
		corruptBuffer func() []byte
	}{
		{
			name: "length_exceeds_max",
			corruptBuffer: func() []byte {
				buf := make([]byte, 10)
				buf[0] = byte(CodecZstd)
				binary.BigEndian.PutUint32(buf[1:5], uint32(DefaultMaxObjectSize+1000))
				return buf
			},
		},
		{
			name: "length_mismatch",
			corruptBuffer: func() []byte {
				enc := zstdEncoderPool.Get().(*zstd.Encoder)
				compressed := enc.EncodeAll([]byte("hello world"), nil)
				zstdEncoderPool.Put(enc)
				buf := make([]byte, 5+len(compressed))
				buf[0] = byte(CodecZstd)
				binary.BigEndian.PutUint32(buf[1:5], 9999) // Claims 9999, actual is 11
				copy(buf[5:], compressed)
				return buf
			},
		},
		{
			name: "truncated_data",
			corruptBuffer: func() []byte {
				return []byte{byte(CodecZstd), 0x00, 0x10}
			},
		},
		{
			name: "unknown_codec",
			corruptBuffer: func() []byte {
				return []byte{0xcc, 0x01, 0x02, 0x03}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			memFS := NewMemFS()
			store, err := Open(WithFS(memFS), WithDir("test_reject_"+tc.name), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer store.Close()

			// Write a normal record first
			_ = store.Put("ConfigMap", "corrupt-cm", []byte("placeholder"))

			// Delete existing slot and put corruptPayload with matching key and LSN
			entry := store.keyIndex[qualifyKey("ConfigMap", "corrupt-cm")]
			handle, err := store.bp.PinPage(entry.LogicalPage)
			if err != nil {
				t.Fatalf("PinPage failed: %v", err)
			}
			handle.Desc.Mu.Lock()
			sp, _ := WrapSlottedPage(handle.Block(0))
			_ = sp.Delete(entry.Slot, entry.LSN)
			corruptPayload := tc.corruptBuffer()
			slotIdx, putErr := sp.Put(qualifyKey("ConfigMap", "corrupt-cm"), corruptPayload, entry.LSN)
			if putErr != nil {
				t.Fatalf("sp.Put failed: %v", putErr)
			}
			handle.Desc.Mu.Unlock()
			handle.Unpin()

			store.keyIndex[qualifyKey("ConfigMap", "corrupt-cm")] = KeyIndexEntry{
				LogicalPage: entry.LogicalPage,
				Slot:        slotIdx,
				LSN:         entry.LSN,
				NumBlocks:   1,
			}

			// Get must fail and transition store to failed state
			_, _, err = store.Get("ConfigMap", "corrupt-cm")
			if err == nil {
				t.Fatalf("expected Get to fail on corruption, but succeeded")
			}
			if !errors.Is(err, ErrFailed) {
				t.Fatalf("expected ErrFailed, got %v", err)
			}

			// Store must be in failed state
			if !store.isFailed() {
				t.Fatalf("store is not in failed state")
			}
			select {
			case <-store.Failed():
			default:
				t.Fatalf("store.Failed() channel is not closed")
			}

			// Subsequent operations must return ErrFailed
			if err := store.Put("ConfigMap", "new-key", []byte("val")); !errors.Is(err, ErrFailed) {
				t.Fatalf("expected ErrFailed from Put on failed store, got %v", err)
			}
		})
	}
}

func getStoredPayload(t *testing.T, store *Engine, bucket, key string) []byte {
	t.Helper()
	qKey := qualifyKey(bucket, key)
	store.keyMu.RLock()
	entry, exists := store.keyIndex[qKey]
	store.keyMu.RUnlock()
	if !exists {
		t.Fatalf("key %s not found in keyIndex", qKey)
	}
	if entry.IsOversize {
		store.keyMu.RLock()
		data := bytes.Clone(store.oversizeObjects[qKey])
		store.keyMu.RUnlock()
		return data
	}
	h, err := store.bp.PinPage(entry.LogicalPage)
	if err != nil {
		t.Fatalf("PinPage failed: %v", err)
	}
	defer h.Unpin()
	var stored []byte
	if entry.NumBlocks == 1 {
		sp, err := WrapSlottedPage(h.Block(0))
		if err != nil {
			t.Fatalf("WrapSlottedPage failed: %v", err)
		}
		_, stored, _, _ = sp.Get(entry.Slot)
	} else {
		_, stored, _, _ = DecodeMultiBlockPage(h.Blocks())
	}
	return stored
}

// TestCompression_RoundTripSizesAndReopen tests round-trip Put/Get and close/reopen for value sizes
// 0, 1, 64, 500, 1000, 4000, 4001, and 20000 bytes, with both compressible and incompressible content.
// Compressible values of 500 bytes or more must be stored with CodecZstd, and incompressible values with CodecNone.
func TestCompression_RoundTripSizesAndReopen(t *testing.T) {
	sizes := []int{0, 1, 64, 500, 1000, 4000, 4001, 20000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Compressible_%dB", size), func(t *testing.T) {
			memFS := NewMemFS()
			dir := fmt.Sprintf("test_rt_comp_%d", size)
			store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			payload := makeRepetitivePayload(size)
			key := fmt.Sprintf("key-%d", size)
			if err := store.Put("bucket", key, payload); err != nil {
				t.Fatalf("Put failed: %v", err)
			}

			stored := getStoredPayload(t, store, "bucket", key)
			if size >= 500 {
				if stored[0] != byte(CodecZstd) {
					t.Fatalf("expected CodecZstd (%d) for compressible size %d, got %d", CodecZstd, size, stored[0])
				}
			} else {
				if stored[0] != byte(CodecNone) {
					t.Fatalf("expected CodecNone (%d) for small compressible size %d (10%% rule), got %d", CodecNone, size, stored[0])
				}
			}

			got, exists, err := store.Get("bucket", key)
			if err != nil || !exists || !bytes.Equal(got, payload) {
				t.Fatalf("Get returned invalid payload: exists=%v, err=%v", exists, err)
			}

			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			// Reopen and verify
			store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd))
			if err != nil {
				t.Fatalf("Reopen failed: %v", err)
			}
			defer store2.Close()

			got2, exists2, err := store2.Get("bucket", key)
			if err != nil || !exists2 || !bytes.Equal(got2, payload) {
				t.Fatalf("Get after reopen returned invalid payload: exists=%v, err=%v", exists2, err)
			}
		})

		t.Run(fmt.Sprintf("Incompressible_%dB", size), func(t *testing.T) {
			memFS := NewMemFS()
			dir := fmt.Sprintf("test_rt_incomp_%d", size)
			store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			payload := makeRandomPayload(size)
			key := fmt.Sprintf("key-%d", size)
			if err := store.Put("bucket", key, payload); err != nil {
				t.Fatalf("Put failed: %v", err)
			}

			stored := getStoredPayload(t, store, "bucket", key)
			if stored[0] != byte(CodecNone) {
				t.Fatalf("expected CodecNone (%d) for incompressible size %d, got %d", CodecNone, size, stored[0])
			}

			got, exists, err := store.Get("bucket", key)
			if err != nil || !exists || !bytes.Equal(got, payload) {
				t.Fatalf("Get returned invalid payload: exists=%v, err=%v", exists, err)
			}

			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			// Reopen and verify
			store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecZstd))
			if err != nil {
				t.Fatalf("Reopen failed: %v", err)
			}
			defer store2.Close()

			got2, exists2, err := store2.Get("bucket", key)
			if err != nil || !exists2 || !bytes.Equal(got2, payload) {
				t.Fatalf("Get after reopen returned invalid payload: exists=%v, err=%v", exists2, err)
			}
		})
	}
}

// TestCompression_ReopenUncompressedSmallValues verifies that stores written with uncompressed
// small values remain fully readable when reopened by an engine configured with CodecZstd.
func TestCompression_ReopenUncompressedSmallValues(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_uncompressed_small"

	// 1. Write store with CodecNone (simulating legacy stores or uncompressed writes)
	store1, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open with CodecNone failed: %v", err)
	}

	testPayloads := map[string][]byte{
		"small-0":    makeRepetitivePayload(0),
		"small-1":    makeRepetitivePayload(1),
		"small-64":   makeRepetitivePayload(64),
		"small-500":  makeRepetitivePayload(500),
		"small-1000": makeRepetitivePayload(1000),
		"small-2000": makeRepetitivePayload(2000),
		"small-4000": makeRepetitivePayload(4000),
	}

	for k, v := range testPayloads {
		if err := store1.Put("bucket", k, v); err != nil {
			t.Fatalf("Put %s failed: %v", k, err)
		}
		// Confirm it was written as CodecNone
		stored := getStoredPayload(t, store1, "bucket", k)
		if stored[0] != byte(CodecNone) {
			t.Fatalf("expected stored codec CodecNone for %s, got %d", k, stored[0])
		}
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// 2. Reopen with default options (which enables CodecZstd)
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	if store2.CompressionCodec() != CodecZstd {
		t.Fatalf("expected default compression codec CodecZstd, got %v", store2.CompressionCodec())
	}

	// 3. Read back all legacy uncompressed small values
	for k, expected := range testPayloads {
		got, exists, err := store2.Get("bucket", k)
		if err != nil {
			t.Fatalf("Get %s failed: %v", k, err)
		}
		if !exists {
			t.Fatalf("key %s does not exist after reopen", k)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("payload mismatch for %s after reopen", k)
		}
	}

	// 4. Verify new writes in the reopened store compress small compressible payloads
	newPayload := makeRepetitivePayload(500)
	if err := store2.Put("bucket", "new-small-500", newPayload); err != nil {
		t.Fatalf("Put new small payload failed: %v", err)
	}

	storedNew := getStoredPayload(t, store2, "bucket", "new-small-500")
	if storedNew[0] != byte(CodecZstd) {
		t.Fatalf("expected CodecZstd for new write in reopened store, got %d", storedNew[0])
	}

	gotNew, exists, err := store2.Get("bucket", "new-small-500")
	if err != nil || !exists || !bytes.Equal(gotNew, newPayload) {
		t.Fatalf("Get new-small-500 failed: exists=%v, err=%v", exists, err)
	}
}
