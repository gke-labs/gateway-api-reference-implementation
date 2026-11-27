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
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func singleOversizeFileName(t *testing.T, fs FS, dir string) string {
	t.Helper()
	entries, err := fs.ReadDir(filepath.Join(dir, "oversize"))
	if err != nil {
		t.Fatalf("ReadDir(oversize) failed: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".obj") {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 .obj file in oversize/, got %d (%v)", len(names), names)
	}
	return names[0]
}

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
// oversize file contains no plaintext, uses a random name not derived from the
// value, writes a fresh file on identical rewrite, and reads back across reopen.
func TestOversizeEncryption_NoPlaintextAndRandomFileName(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_enc_no_plaintext"
	var key [32]byte
	copy(key[:], []byte("oversize-enc-test-master-key-32b"))

	store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	table, keyName := "SecretBlobs", "confidential-oversize-key"
	marker := []byte("super-secret-oversize-plaintext-payload-9876543210")
	// Non-4KiB-aligned stored length exercises zero padding of the last 4 KiB unit.
	val := append(bytes.Repeat(marker, (2100*1024)/len(marker)+1), []byte("-tail")...)
	if (len(val)+1)%BlockSize == 0 {
		val = append(val, 'x')
	}

	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	name1 := singleOversizeFileName(t, memFS, dir)
	stored := append([]byte{byte(CodecNone)}, val...)
	if name1 == OversizeFileName(qualifyKey(table, keyName), stored) {
		t.Fatalf("encrypted oversize file name %q matches deterministic hash", name1)
	}

	raw := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", name1))
	if want := paddedOversizeSize(uint64(len(stored))); uint64(len(raw)) != want {
		t.Fatalf("encrypted file size = %d, want padded %d", len(raw), want)
	}
	if bytes.Contains(raw, marker) {
		t.Fatalf("encrypted oversize file exposes plaintext marker bytes")
	}

	// Identical rewrite in an encrypted store must not skip writing and must pick a new name.
	if err := store.Put(table, keyName, val); err != nil {
		t.Fatalf("identical rewrite Put failed: %v", err)
	}
	if name2 := singleOversizeFileName(t, memFS, dir); name2 == name1 {
		t.Fatalf("identical rewrite reused file name %q; expected fresh random identifier", name2)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	reopened, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	got, exists, err := reopened.Get(table, keyName)
	if err != nil || !exists || !bytes.Equal(got, val) {
		t.Fatalf("Get after reopen mismatch: exists=%v len=%d want=%d err=%v", exists, len(got), len(val), err)
	}
}

// TestOversize_ChangedByteFailsChecksumOnRead verifies that corrupting an oversize
// value file fails checksum/integrity verification on read, covering encrypted and
// unencrypted value bytes, encrypted padding bytes, and swapped 4 KiB units (tweak binding).
func TestOversize_ChangedByteFailsChecksumOnRead(t *testing.T) {
	flipByte := func(offset func(fileSize int64) int64) func(t *testing.T, f File, sz int64) {
		return func(t *testing.T, f File, sz int64) {
			off := offset(sz)
			var b [1]byte
			if _, err := f.ReadAt(b[:], off); err != nil {
				t.Fatalf("ReadAt(%d) failed: %v", off, err)
			}
			b[0] ^= 0xff
			if _, err := f.WriteAt(b[:], off); err != nil {
				t.Fatalf("WriteAt(%d) failed: %v", off, err)
			}
		}
	}
	swapUnits := func(t *testing.T, f File, _ int64) {
		unit1, unit2 := make([]byte, BlockSize), make([]byte, BlockSize)
		if _, err := f.ReadAt(unit1, BlockSize); err != nil {
			t.Fatalf("ReadAt unit 1 failed: %v", err)
		}
		if _, err := f.ReadAt(unit2, 2*BlockSize); err != nil {
			t.Fatalf("ReadAt unit 2 failed: %v", err)
		}
		if bytes.Equal(unit1, unit2) {
			t.Fatalf("identical plaintext units produced identical ciphertext; tweak not applied")
		}
		if _, err := f.WriteAt(unit2, BlockSize); err != nil {
			t.Fatalf("WriteAt unit 1 failed: %v", err)
		}
		if _, err := f.WriteAt(unit1, 2*BlockSize); err != nil {
			t.Fatalf("WriteAt unit 2 failed: %v", err)
		}
	}

	cases := []struct {
		name      string
		encrypted bool
		corrupt   func(t *testing.T, f File, sz int64)
	}{
		{name: "unencrypted_value_byte", encrypted: false, corrupt: flipByte(func(sz int64) int64 { return sz / 2 })},
		{name: "encrypted_value_byte", encrypted: true, corrupt: flipByte(func(sz int64) int64 { return sz / 2 })},
		{name: "encrypted_padding_byte", encrypted: true, corrupt: flipByte(func(sz int64) int64 { return sz - 1 })},
		{name: "encrypted_swapped_units", encrypted: true, corrupt: swapUnits},
	}

	// Non-4KiB-aligned zero-filled value: gives non-empty padding tail and identical
	// plaintext in units 1 and 2 so swapping them tests unit-index tweak binding.
	val := make([]byte, 2100*1024+123)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memFS := NewMemFS()
			dir := "test_oversize_corrupt_" + tc.name
			opts := []Option{WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithCreate()}
			if tc.encrypted {
				var key [32]byte
				copy(key[:], []byte("oversize-corrupt-test-key-32byte"))
				opts = append(opts, WithEncryptionKey(key[:]))
			}
			store, err := Open(opts...)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer store.Close()

			if err := store.Put("TestTable", "k", val); err != nil {
				t.Fatalf("Put failed: %v", err)
			}

			path := filepath.Join(dir, "oversize", singleOversizeFileName(t, memFS, dir))
			f, err := memFS.OpenFile(path, os.O_RDWR, StoreFileMode)
			if err != nil {
				t.Fatalf("OpenFile failed: %v", err)
			}
			sz, err := f.Size()
			if err != nil {
				_ = f.Close()
				t.Fatalf("Size failed: %v", err)
			}
			tc.corrupt(t, f, sz)
			if err := f.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			if _, _, err := store.Get("TestTable", "k"); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("expected ErrCorruptStore, got: %v", err)
			}
			if store.isFailed() {
				t.Fatalf("engine must not enter failed state on oversize checksum mismatch")
			}
		})
	}
}

// TestOversizeEncryption_WithZstdCompression shows that compression runs before
// oversize encryption (and decryption before decompression), so the pointer length
// and SHA-256 checksum cover the compressed bytes rather than the raw input.
func TestOversizeEncryption_WithZstdCompression(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_enc_zstd"
	var key [32]byte
	copy(key[:], []byte("oversize-zstd-enc-master-key-32b"))

	store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCompressionCodec(CodecZstd), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	val := makeIncompressible(MaxPayloadCapacity + 10*1024 + 77)
	marker := []byte("zstd-secret-oversize-marker-value")
	copy(val, marker)
	if err := store.Put("CompressedSecrets", "k", val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	raw := readRawOversizeFile(t, memFS, filepath.Join(dir, "oversize", singleOversizeFileName(t, memFS, dir)))
	if len(raw)%BlockSize != 0 {
		t.Fatalf("expected file size to be multiple of %d, got %d", BlockSize, len(raw))
	}
	if bytes.Contains(raw, marker) {
		t.Fatalf("encrypted oversize file exposed marker in plaintext")
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	reopened, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCompressionCodec(CodecZstd))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	got, exists, err := reopened.Get("CompressedSecrets", "k")
	if err != nil || !exists || !bytes.Equal(got, val) {
		t.Fatalf("Get after reopen mismatch: exists=%v len=%d want=%d err=%v", exists, len(got), len(val), err)
	}
}
