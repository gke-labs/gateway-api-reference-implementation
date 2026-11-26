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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func readRawOversizeFile(t *testing.T, fs FS, path string) []byte {
	t.Helper()
	file, err := fs.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(%s) failed: %v", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) failed: %v", path, closeErr)
		}
	}()
	size, err := file.Size()
	if err != nil {
		t.Fatalf("Size(%s) failed: %v", path, err)
	}
	raw := make([]byte, size)
	n, err := file.ReadAt(raw, 0)
	if (err != nil && !errors.Is(err, io.EOF)) || int64(n) != size {
		t.Fatalf("ReadAt(%s) failed: n=%d size=%d err=%v", path, n, size, err)
	}
	return raw
}

// TestOversizeEncryption_NoPlaintextAndRandomFileName verifies that an encrypted
// oversize file contains no plaintext, is padded to a 4 KiB boundary, uses a random
// file name not derived from the value, does not skip identical rewrites, derives
// distinct per-file keys, and reads back with exact unpadded length across reopen.
func TestOversizeEncryption_NoPlaintextAndRandomFileName(t *testing.T) {
	memFS := NewMemFS()
	var renameCount atomic.Int32
	hookFS := &oversizeHookFS{
		FS: memFS,
		beforeRename: func(oldpath, newpath string) {
			if strings.Contains(newpath, "oversize") {
				renameCount.Add(1)
			}
		},
	}
	dir := "test_oversize_enc_no_plaintext"

	var key [32]byte
	copy(key[:], []byte("oversize-enc-test-master-key-32b"))

	store, err := Open(
		WithFS(hookFS),
		WithDir(dir),
		WithEncryptionKey(key[:]),
		WithCompressionCodec(CodecNone),
		WithCreate(),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "SecretBlobs"
	keyName := "confidential-oversize-key-001"
	marker := []byte("super-secret-oversize-plaintext-payload-9876543210")

	// Non-4KiB-aligned length so zero padding of the last 4 KiB unit is exercised.
	// With CodecNone, stored payload is 1 byte (codec) + len(val).
	val := bytes.Repeat(marker, (2100*1024)/len(marker)+1)
	val = append(val, []byte("-tail-137-bytes")...)
	if (len(val)+1)%BlockSize == 0 {
		val = append(val, 'x')
	}

	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	qKey := qualifyKey(table, keyName)
	store.keyMu.RLock()
	entry1 := store.keyIndex[qKey]
	store.keyMu.RUnlock()
	if !entry1.IsOversize {
		t.Fatalf("expected key to be stored as oversize")
	}

	storedBytes := append([]byte{byte(CodecNone)}, val...)
	deterministicKeyValName := OversizeFileName(qKey, storedBytes)
	valHash := sha256.Sum256(storedBytes)
	deterministicValName := fmt.Sprintf("%x.obj", valHash)

	if entry1.OversizeFileName == deterministicKeyValName {
		t.Fatalf("encrypted oversize file name %q matches deterministic key+value hash", entry1.OversizeFileName)
	}
	if entry1.OversizeFileName == deterministicValName {
		t.Fatalf("encrypted oversize file name %q matches deterministic value hash", entry1.OversizeFileName)
	}

	filePath1 := filepath.Join(dir, "oversize", entry1.OversizeFileName)
	raw1 := readRawOversizeFile(t, memFS, filePath1)

	expectedPaddedLen := paddedOversizeSize(uint64(len(storedBytes)))
	if uint64(len(raw1)) != expectedPaddedLen {
		t.Fatalf("encrypted oversize file size = %d, want padded size %d (unpadded %d)", len(raw1), expectedPaddedLen, len(storedBytes))
	}
	if uint64(len(raw1)) <= uint64(len(storedBytes)) {
		t.Fatalf("expected padded size %d > unpadded size %d", len(raw1), len(storedBytes))
	}
	if bytes.Contains(raw1, marker) {
		t.Fatalf("encrypted oversize file exposes plaintext marker bytes")
	}
	if bytes.Contains(raw1, []byte(keyName)) {
		t.Fatalf("encrypted oversize file exposes key in plaintext")
	}
	if bytes.Contains(raw1, []byte(table)) {
		t.Fatalf("encrypted oversize file exposes table name in plaintext")
	}

	// Rewriting the exact same key and value in an encrypted store must NOT skip the write
	// and must generate a fresh random file name.
	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("identical rewrite Put failed: %v", err)
	}
	if got := renameCount.Load(); got != 2 {
		t.Fatalf("expected identical rewrite in encrypted store to write a new file (renames=2), got %d", got)
	}
	store.keyMu.RLock()
	entry2 := store.keyIndex[qKey]
	store.keyMu.RUnlock()
	if entry2.OversizeFileName == entry1.OversizeFileName {
		t.Fatalf("identical rewrite reused file name %q; expected fresh random identifier", entry2.OversizeFileName)
	}
	if _, err := memFS.Open(filePath1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected replaced oversize file %s to be deleted after durable rewrite, got err: %v", filePath1, err)
	}

	// Put the identical value under a second key: must produce a distinct random file name
	// and distinct ciphertext because each file derives its own key.
	keyName2 := "confidential-oversize-key-002"
	if err := store.Put(table, keyName2, val); err != nil {
		t.Fatalf("Put second key failed: %v", err)
	}
	store.keyMu.RLock()
	entryOther := store.keyIndex[qualifyKey(table, keyName2)]
	store.keyMu.RUnlock()
	if entryOther.OversizeFileName == entry2.OversizeFileName {
		t.Fatalf("two keys shared encrypted oversize file name %q", entryOther.OversizeFileName)
	}
	raw2 := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", entry2.OversizeFileName))
	rawOther := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", entryOther.OversizeFileName))
	if bytes.Equal(raw2, rawOther) {
		t.Fatalf("two encrypted oversize files with identical plaintext produced identical ciphertext")
	}

	// Put an oversize value whose stored length (1-byte codec + len) is an exact multiple of 4 KiB.
	alignedKey := "aligned-oversize-key"
	alignedVal := make([]byte, 2100*1024-1) // storedBytes = 2100*1024 = 525 * 4096
	copy(alignedVal, marker)
	if err := store.Put(table, alignedKey, alignedVal); err != nil {
		t.Fatalf("Put aligned value failed: %v", err)
	}
	store.keyMu.RLock()
	alignedEntry := store.keyIndex[qualifyKey(table, alignedKey)]
	store.keyMu.RUnlock()
	rawAligned := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", alignedEntry.OversizeFileName))
	if len(rawAligned) != 2100*1024 {
		t.Fatalf("4 KiB-aligned stored oversize file size = %d, want %d", len(rawAligned), 2100*1024)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopening with the wrong key must fail with ErrInvalidKey.
	var wrongKey [32]byte
	copy(wrongKey[:], key[:])
	wrongKey[0] ^= 0xff
	if _, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(wrongKey[:])); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey with wrong key, got: %v", err)
	}

	// Reopening with the correct key must read back every oversize value with exact unpadded bytes.
	reopened, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Errorf("reopened.Close failed: %v", closeErr)
		}
	}()

	for _, tc := range []struct {
		key  string
		want []byte
	}{
		{key: keyName, want: val},
		{key: keyName2, want: val},
		{key: alignedKey, want: alignedVal},
	} {
		got, exists, err := reopened.Get(table, tc.key)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", tc.key, err)
		}
		if !exists {
			t.Fatalf("Get(%s) not found after reopen", tc.key)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("Get(%s) mismatch: got len=%d, want len=%d", tc.key, len(got), len(tc.want))
		}
	}
}

// TestOversizeEncryption_UnitIndexTweakBinding verifies that swapping two 4 KiB units
// in an encrypted oversize file fails decryption/checksum verification on read.
func TestOversizeEncryption_UnitIndexTweakBinding(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_enc_tweak_binding"

	var key [32]byte
	copy(key[:], []byte("oversize-tweak-binding-key-32byt"))

	store, err := Open(
		WithFS(memFS),
		WithDir(dir),
		WithEncryptionKey(key[:]),
		WithCompressionCodec(CodecNone),
		WithCreate(),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("Close failed: %v", closeErr)
		}
	}()

	table := "TestTable"
	keyName := "tweak-key"
	// Identical plaintext blocks at unit 1 and unit 2; swapping their ciphertext must fail
	// because each unit is encrypted with its unit index as the AES-XTS tweak.
	val := make([]byte, 2100*1024-1)
	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	store.keyMu.RLock()
	fileName := store.keyIndex[qualifyKey(table, keyName)].OversizeFileName
	store.keyMu.RUnlock()

	filePath := filepath.Join(dir, "oversize", fileName)
	file, err := memFS.OpenFile(filePath, os.O_RDWR, StoreFileMode)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	unit1 := make([]byte, BlockSize)
	unit2 := make([]byte, BlockSize)
	if _, err := file.ReadAt(unit1, BlockSize); err != nil {
		_ = file.Close()
		t.Fatalf("ReadAt unit 1 failed: %v", err)
	}
	if _, err := file.ReadAt(unit2, 2*BlockSize); err != nil {
		_ = file.Close()
		t.Fatalf("ReadAt unit 2 failed: %v", err)
	}
	if bytes.Equal(unit1, unit2) {
		_ = file.Close()
		t.Fatalf("identical plaintext units produced identical ciphertext; tweak not applied")
	}
	if _, err := file.WriteAt(unit2, BlockSize); err != nil {
		_ = file.Close()
		t.Fatalf("WriteAt swapped unit 1 failed: %v", err)
	}
	if _, err := file.WriteAt(unit1, 2*BlockSize); err != nil {
		_ = file.Close()
		t.Fatalf("WriteAt swapped unit 2 failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, _, err = store.Get(table, keyName)
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore after swapping 4 KiB units, got: %v", err)
	}
}

// TestOversizeEncryption_WithZstdCompression verifies that oversize values written with
// both Zstd compression and block-level encryption round-trip across reopen with no plaintext on disk.
func TestOversizeEncryption_WithZstdCompression(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_enc_zstd"

	var key [32]byte
	copy(key[:], []byte("oversize-zstd-enc-master-key-32b"))

	store, err := Open(
		WithFS(memFS),
		WithDir(dir),
		WithEncryptionKey(key[:]),
		WithCompressionCodec(CodecZstd),
		WithCreate(),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table := "CompressedSecrets"
	keyName := "zstd-oversize-key"
	val := makeIncompressible(MaxPayloadCapacity + 10*1024 + 77)
	marker := []byte("zstd-secret-oversize-marker-value")
	copy(val, marker)

	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	store.keyMu.RLock()
	entry := store.keyIndex[qualifyKey(table, keyName)]
	store.keyMu.RUnlock()
	if !entry.IsOversize {
		t.Fatalf("expected incompressible value to be stored as oversize")
	}

	raw := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", entry.OversizeFileName))
	if len(raw)%BlockSize != 0 {
		t.Fatalf("expected encrypted oversize file size to be multiple of %d, got %d", BlockSize, len(raw))
	}
	if bytes.Contains(raw, marker) {
		t.Fatalf("encrypted oversize file exposed marker in plaintext")
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	reopened, err := Open(
		WithFS(memFS),
		WithDir(dir),
		WithEncryptionKey(key[:]),
		WithCompressionCodec(CodecZstd),
	)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Errorf("reopened.Close failed: %v", closeErr)
		}
	}()

	got, exists, err := reopened.Get(table, keyName)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key to exist after reopen")
	}
	if !bytes.Equal(got, val) {
		t.Fatalf("value mismatch: got len=%d, want len=%d", len(got), len(val))
	}
}

// TestOversize_ChangedByteFailsChecksumOnRead verifies that flipping a byte in an oversize
// value file fails checksum/integrity verification on read, with encryption both on and off.
func TestOversize_ChangedByteFailsChecksumOnRead(t *testing.T) {
	runOversizeEncryptionModes(t, func(t *testing.T, encKey []byte) {
		memFS := NewMemFS()
		dir := "test_oversize_changed_byte"

		openStore := func(create bool) *Engine {
			opts := []Option{
				WithFS(memFS),
				WithDir(dir),
				WithCompressionCodec(CodecNone),
			}
			if len(encKey) > 0 {
				opts = append(opts, WithEncryptionKey(encKey))
			}
			if create {
				opts = append(opts, WithCreate())
			}
			s, err := Open(opts...)
			if err != nil {
				t.Fatalf("Open(create=%v) failed: %v", create, err)
			}
			return s
		}

		store := openStore(true)
		table := "TestTable"
		healthyKey := "healthy-small-key"
		healthyVal := []byte("healthy-value")
		if err := store.Put(table, healthyKey, healthyVal); err != nil {
			t.Fatalf("Put healthyKey failed: %v", err)
		}

		// Non-4KiB-aligned payload so an encrypted file has non-empty zero padding at the end.
		val := make([]byte, 2100*1024+123)
		for i := range val {
			val[i] = byte(i % 251)
		}

		flipOffsets := []struct {
			name   string
			offset func(fileSize int64) int64
		}{
			{name: "first_byte", offset: func(int64) int64 { return 0 }},
			{name: "middle_byte", offset: func(sz int64) int64 { return sz / 2 }},
			{name: "last_payload_byte", offset: func(int64) int64 { return int64(len(val)) }}, // 1-byte codec + len(val) - 1
		}
		if len(encKey) > 0 {
			flipOffsets = append(flipOffsets, struct {
				name   string
				offset func(fileSize int64) int64
			}{
				name:   "padding_tail_byte",
				offset: func(sz int64) int64 { return sz - 1 },
			})
		}

		for _, tc := range flipOffsets {
			keyName := "corrupt-" + tc.name
			if err := store.Put(table, keyName, val); err != nil {
				t.Fatalf("Put(%s) failed: %v", keyName, err)
			}
			store.keyMu.RLock()
			fileName := store.keyIndex[qualifyKey(table, keyName)].OversizeFileName
			store.keyMu.RUnlock()

			filePath := filepath.Join(dir, "oversize", fileName)
			file, err := memFS.OpenFile(filePath, os.O_RDWR, StoreFileMode)
			if err != nil {
				t.Fatalf("OpenFile(%s) failed: %v", filePath, err)
			}
			sz, err := file.Size()
			if err != nil {
				_ = file.Close()
				t.Fatalf("Size failed: %v", err)
			}
			off := tc.offset(sz)
			var b [1]byte
			if _, err := file.ReadAt(b[:], off); err != nil {
				_ = file.Close()
				t.Fatalf("ReadAt(%d) failed: %v", off, err)
			}
			b[0] ^= 0xff
			if _, err := file.WriteAt(b[:], off); err != nil {
				_ = file.Close()
				t.Fatalf("WriteAt(%d) failed: %v", off, err)
			}
			if err := file.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			_, _, err = store.Get(table, keyName)
			if !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("%s: expected ErrCorruptStore on Get, got: %v", tc.name, err)
			}
			if store.isFailed() {
				t.Fatalf("%s: engine must not enter failed state on oversize checksum mismatch", tc.name)
			}
		}

		// Healthy key remains readable while store is open.
		gotHealthy, exists, err := store.Get(table, healthyKey)
		if err != nil || !exists || !bytes.Equal(gotHealthy, healthyVal) {
			t.Fatalf("healthy key Get failed: exists=%v err=%v", exists, err)
		}

		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen and verify corrupted oversize files still fail checksum on read.
		reopened := openStore(false)
		defer func() {
			if closeErr := reopened.Close(); closeErr != nil {
				t.Errorf("reopened.Close failed: %v", closeErr)
			}
		}()

		for _, tc := range flipOffsets {
			keyName := "corrupt-" + tc.name
			_, _, err := reopened.Get(table, keyName)
			if !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("%s after reopen: expected ErrCorruptStore, got: %v", tc.name, err)
			}
		}

		gotHealthy, exists, err = reopened.Get(table, healthyKey)
		if err != nil || !exists || !bytes.Equal(gotHealthy, healthyVal) {
			t.Fatalf("healthy key Get after reopen failed: exists=%v err=%v", exists, err)
		}
	})
}

// TestOversize_TruncatedAndMissingFileFailOnRead verifies that truncated or missing oversize
// files fail Get with ErrCorruptStore with encryption both on and off.
func TestOversize_TruncatedAndMissingFileFailOnRead(t *testing.T) {
	runOversizeEncryptionModes(t, func(t *testing.T, encKey []byte) {
		memFS := NewMemFS()
		dir := "test_oversize_trunc_missing"

		opts := []Option{
			WithFS(memFS),
			WithDir(dir),
			WithCompressionCodec(CodecNone),
			WithCreate(),
		}
		if len(encKey) > 0 {
			opts = append(opts, WithEncryptionKey(encKey))
		}
		store, err := Open(opts...)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer func() {
			if closeErr := store.Close(); closeErr != nil {
				t.Errorf("Close failed: %v", closeErr)
			}
		}()

		table := "TestTable"
		val := append([]byte("trunc-missing-payload"), make([]byte, 2100*1024)...)

		if err := store.Put(table, "truncated", val); err != nil {
			t.Fatalf("Put truncated failed: %v", err)
		}
		if err := store.Put(table, "missing", val); err != nil {
			t.Fatalf("Put missing failed: %v", err)
		}

		store.keyMu.RLock()
		truncFile := store.keyIndex[qualifyKey(table, "truncated")].OversizeFileName
		missingFile := store.keyIndex[qualifyKey(table, "missing")].OversizeFileName
		store.keyMu.RUnlock()

		// Truncate to a whole 4 KiB block smaller than expected to exercise both unaligned and block-aligned truncation.
		truncPath := filepath.Join(dir, "oversize", truncFile)
		f, err := memFS.OpenFile(truncPath, os.O_RDWR, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		if err := f.Truncate(BlockSize * 10); err != nil {
			_ = f.Close()
			t.Fatalf("Truncate failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		if err := memFS.Remove(filepath.Join(dir, "oversize", missingFile)); err != nil {
			t.Fatalf("Remove failed: %v", err)
		}

		if _, _, err := store.Get(table, "truncated"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore for truncated oversize file, got: %v", err)
		}
		if _, _, err := store.Get(table, "missing"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("expected ErrCorruptStore for missing oversize file, got: %v", err)
		}
	})
}
