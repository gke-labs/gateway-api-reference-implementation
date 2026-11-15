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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestWALEncryption_PlaintextNotExposedInWAL verifies that a WAL segment contains
// none of the keys or values in plaintext, while the 32-byte segment header stays in plaintext.
func TestWALEncryption_PlaintextNotExposedInWAL(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_wal_enc_plaintext"

	var key [32]byte
	copy(key[:], []byte("wal-enc-test-master-key-32bytes-"))

	store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	testData := []struct {
		table string
		key   string
		value []byte
	}{
		{
			table: "SecretCredentials",
			key:   "secret-token-wal-001",
			value: []byte("super-confidential-wal-password-xyz-98765"),
		},
		{
			table: "ProtectedSessions",
			key:   "session-bearer-wal-admin",
			value: []byte("jwt-bearer-token-wal-payload-alpha-beta-gamma"),
		},
		{
			table: "LargeWALPayloads",
			key:   "multi-block-wal-key-payload",
			value: bytes.Repeat([]byte("wal-confidential-repeated-segment-data-"), 200), // ~8 KiB spans multiple blocks
		},
	}

	for _, entry := range testData {
		if err := store.Put(entry.table, entry.key, entry.value); err != nil {
			t.Fatalf("Put(%s, %s) failed: %v", entry.table, entry.key, err)
		}
	}

	// Sync WAL to guarantee blocks are fsynced to disk
	if err := store.wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}
	dbID := store.dbID

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read raw WAL segment file(s) from disk
	walDir := filepath.Join(dir, "wal")
	entries, err := memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir wal failed: %v", err)
	}

	var walFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".wal") {
			walFiles = append(walFiles, filepath.Join(walDir, entry.Name()))
		}
	}
	if len(walFiles) == 0 {
		t.Fatalf("expected at least one WAL segment file")
	}

	for _, walPath := range walFiles {
		file, err := memFS.OpenFile(walPath, 0, 0)
		if err != nil {
			t.Fatalf("OpenFile %s failed: %v", walPath, err)
		}
		size, err := file.Size()
		if err != nil {
			file.Close()
			t.Fatalf("Size failed: %v", err)
		}
		if size < WALBlockSize {
			file.Close()
			t.Fatalf("WAL segment %s size %d is less than WALBlockSize %d", walPath, size, WALBlockSize)
		}
		rawBytes := make([]byte, size)
		if _, err := file.ReadAt(rawBytes, 0); err != nil {
			file.Close()
			t.Fatalf("ReadAt %s failed: %v", walPath, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// 1. Verify 32-byte segment header stays in plaintext
		magic := binary.BigEndian.Uint32(rawBytes[0:4])
		if magic != WALMagic {
			t.Errorf("segment %s header magic mismatch: got 0x%08x, want 0x%08x", walPath, magic, WALMagic)
		}
		version := binary.BigEndian.Uint32(rawBytes[4:8])
		if version != WALVersion {
			t.Errorf("segment %s header version mismatch: got %d, want %d", walPath, version, WALVersion)
		}
		if !bytes.Equal(rawBytes[16:32], dbID[:]) {
			t.Errorf("segment %s header dbID mismatch: got %x, want %x", walPath, rawBytes[16:32], dbID)
		}

		// 2. Verify none of the keys or values appear in plaintext anywhere in the WAL file
		for _, entry := range testData {
			if bytes.Contains(rawBytes, []byte(entry.key)) {
				t.Errorf("WAL segment %s exposes key in plaintext: %q", walPath, entry.key)
			}
			if bytes.Contains(rawBytes, entry.value) {
				t.Errorf("WAL segment %s exposes value in plaintext for key: %q", walPath, entry.key)
			}
		}
	}

	// 3. Reopen the encrypted store and verify all data can be decrypted and read
	reopenedStore, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]))
	if err != nil {
		t.Fatalf("reopening store with encryption key failed: %v", err)
	}
	defer reopenedStore.Close()

	for _, entry := range testData {
		value, exists, err := reopenedStore.Get(entry.table, entry.key)
		if err != nil {
			t.Fatalf("Get(%s, %s) error: %v", entry.table, entry.key, err)
		}
		if !exists {
			t.Fatalf("Get(%s, %s) key not found", entry.table, entry.key)
		}
		if !bytes.Equal(value, entry.value) {
			t.Fatalf("Get(%s, %s) value mismatch: got %d bytes, want %d bytes", entry.table, entry.key, len(value), len(entry.value))
		}
	}
}

// setupEncryptedWALSegments creates numSegments WAL segments with encryption and returns the FS and segment paths.
func setupEncryptedWALSegments(t *testing.T, dir string, numSegments int, key []byte) (FS, []string, [16]byte) {
	t.Helper()
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("enc-wal-dbid-001"))

	walDir := filepath.Join(dir, "wal")
	wal, err := OpenWAL(memFS, walDir, dbID, 0, WALOptions{
		MaxSegmentSize: 80,
		EncryptionKey:  key,
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	for i := 1; i <= numSegments; i++ {
		record := Record{
			Type:    RecordTypePut,
			LSN:     uint64(i),
			Key:     qualifyKey("ConfigMap", fmt.Sprintf("k%d", i)),
			Payload: append([]byte{byte(CodecNone)}, fmt.Sprintf("val%d", i)...),
		}
		if err := wal.Append(record); err != nil {
			t.Fatalf("Append record %d failed: %v", i, err)
		}
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	entries, err := memFS.ReadDir(walDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	var paths []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".wal") {
			paths = append(paths, filepath.Join(walDir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) != numSegments {
		t.Fatalf("expected %d segments, got %d", numSegments, len(paths))
	}
	return memFS, paths, dbID
}

// TestWALEncryption_TornLastBlockInActiveSegment_EndsLog verifies that a torn
// last block in the active (last) segment ends the log cleanly and permits recovery.
func TestWALEncryption_TornLastBlockInActiveSegment_EndsLog(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("active-torn-test-key-32bytes-000"))

	t.Run("truncated last block mid-write", func(t *testing.T) {
		dir := "test_wal_enc_torn_truncated"
		fs, paths, dbID := setupEncryptedWALSegments(t, dir, 1, key[:])

		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		size, err := file.Size()
		if err != nil {
			file.Close()
			t.Fatalf("Size failed: %v", err)
		}

		// Simulate torn write by appending 500 bytes of torn block data at end of active segment
		tornBytes := make([]byte, 500)
		for i := range tornBytes {
			tornBytes[i] = byte(i ^ 0xaa)
		}
		if _, err := file.WriteAt(tornBytes, size); err != nil {
			file.Close()
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Recovery iterator should replay the valid record 1 and end the log cleanly on the torn tail
		iterator, err := NewWALIterator(fs, filepath.Join(dir, "wal"), dbID, 1, WALIteratorOptions{
			EncryptionKey: key[:],
		})
		if err != nil {
			t.Fatalf("NewWALIterator failed: %v", err)
		}
		defer iterator.Close()

		record, err := iterator.Next()
		if err != nil {
			t.Fatalf("expected record 1, got error: %v", err)
		}
		if record.LSN != 1 {
			t.Fatalf("expected LSN 1, got %d", record.LSN)
		}

		// Next record must hit EOF due to the torn tail
		_, err = iterator.Next()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF on torn last block in active segment, got: %v", err)
		}
	})

	t.Run("corrupted ciphertext in last block", func(t *testing.T) {
		dir := "test_wal_enc_torn_corrupt_tail"
		fs, paths, dbID := setupEncryptedWALSegments(t, dir, 1, key[:])

		// Corrupt bytes in the encrypted records section (beyond the 32-byte header)
		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		var corruptedByte [1]byte
		if _, err := file.ReadAt(corruptedByte[:], 40); err != nil {
			file.Close()
			t.Fatalf("ReadAt failed: %v", err)
		}
		corruptedByte[0] ^= 0xff
		if _, err := file.WriteAt(corruptedByte[:], 40); err != nil {
			file.Close()
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// In the last (active) segment, corrupted data ends the log cleanly
		iterator, err := NewWALIterator(fs, filepath.Join(dir, "wal"), dbID, 1, WALIteratorOptions{
			EncryptionKey: key[:],
		})
		if err != nil {
			t.Fatalf("NewWALIterator failed: %v", err)
		}
		defer iterator.Close()

		_, err = iterator.Next()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF on corrupted active segment tail, got: %v", err)
		}
	})
}

// TestWALEncryption_DamagedBlockInClosedSegment_FailsOpen verifies that a damaged
// block in a closed segment fails with ErrCorruptWAL.
func TestWALEncryption_DamagedBlockInClosedSegment_FailsOpen(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("closed-corrupt-test-key-32bytes-"))

	dir := "test_wal_enc_damaged_closed"
	fs, paths, dbID := setupEncryptedWALSegments(t, dir, 3, key[:])

	// Damage block 0 in the first segment (closed segment, paths[0]) at ciphertext offset 40
	file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	var corruptedByte [1]byte
	if _, err := file.ReadAt(corruptedByte[:], 40); err != nil {
		file.Close()
		t.Fatalf("ReadAt failed: %v", err)
	}
	corruptedByte[0] ^= 0xff
	if _, err := file.WriteAt(corruptedByte[:], 40); err != nil {
		file.Close()
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// WALIterator on closed segment must return ErrCorruptWAL
	iterator, err := NewWALIterator(fs, filepath.Join(dir, "wal"), dbID, 1, WALIteratorOptions{
		EncryptionKey: key[:],
	})
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer iterator.Close()

	_, err = iterator.Next()
	if !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("expected ErrCorruptWAL on damaged block in closed segment, got: %v", err)
	}
}

// TestWALEncryption_DamagedRecordLength_NoExcessiveAllocation verifies that a damaged
// record length cannot make recovery allocate more than the existing bound.
func TestWALEncryption_DamagedRecordLength_NoExcessiveAllocation(t *testing.T) {
	const excessiveLength = 40 * 1024 * 1024 // 40 MiB; passes MaxRecordFieldLength (64 MiB)

	var key [32]byte
	copy(key[:], []byte("damaged-len-test-key-32bytes-000"))

	t.Run("earlier closed segment", func(t *testing.T) {
		dir := "test_damaged_len_earlier"
		fs, paths, dbID := setupEncryptedWALSegments(t, dir, 2, key[:])

		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		rawBlock := make([]byte, WALBlockSize)
		if _, err := file.ReadAt(rawBlock, 0); err != nil {
			file.Close()
			t.Fatalf("ReadAt failed: %v", err)
		}

		segmentCipher, err := newWALSegmentCipher(key[:], dbID, 1)
		if err != nil {
			file.Close()
			t.Fatalf("newWALSegmentCipher failed: %v", err)
		}

		plaintextBlock := make([]byte, WALBlockSize)
		segmentCipher.Decrypt(plaintextBlock, rawBlock, 0)
		// Overwrite the payload length in the record header at SegmentHeaderSize (offset 32)
		binary.BigEndian.PutUint32(plaintextBlock[SegmentHeaderSize+24:SegmentHeaderSize+28], uint32(excessiveLength))

		encryptedBlock := make([]byte, WALBlockSize)
		segmentCipher.Encrypt(encryptedBlock, plaintextBlock, 0)
		copy(encryptedBlock[:SegmentHeaderSize], rawBlock[:SegmentHeaderSize])

		if _, err := file.WriteAt(encryptedBlock, 0); err != nil {
			file.Close()
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		iterator, err := NewWALIterator(fs, filepath.Join(dir, "wal"), dbID, 1, WALIteratorOptions{
			EncryptionKey: key[:],
		})
		if err != nil {
			t.Fatalf("NewWALIterator failed: %v", err)
		}
		defer iterator.Close()

		// The iterator rejects the record whose length exceeds the segment size before allocating
		_, err = iterator.Next()
		if !errors.Is(err, ErrCorruptWAL) {
			t.Fatalf("expected ErrCorruptWAL on earlier segment with damaged record length, got: %v", err)
		}
	})

	t.Run("last active segment", func(t *testing.T) {
		dir := "test_damaged_len_last"
		fs, paths, dbID := setupEncryptedWALSegments(t, dir, 1, key[:])

		file, err := fs.OpenFile(paths[0], os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		rawBlock := make([]byte, WALBlockSize)
		if _, err := file.ReadAt(rawBlock, 0); err != nil {
			file.Close()
			t.Fatalf("ReadAt failed: %v", err)
		}

		segmentCipher, err := newWALSegmentCipher(key[:], dbID, 1)
		if err != nil {
			file.Close()
			t.Fatalf("newWALSegmentCipher failed: %v", err)
		}

		plaintextBlock := make([]byte, WALBlockSize)
		segmentCipher.Decrypt(plaintextBlock, rawBlock, 0)
		binary.BigEndian.PutUint32(plaintextBlock[SegmentHeaderSize+24:SegmentHeaderSize+28], uint32(excessiveLength))

		encryptedBlock := make([]byte, WALBlockSize)
		segmentCipher.Encrypt(encryptedBlock, plaintextBlock, 0)
		copy(encryptedBlock[:SegmentHeaderSize], rawBlock[:SegmentHeaderSize])

		if _, err := file.WriteAt(encryptedBlock, 0); err != nil {
			file.Close()
			t.Fatalf("WriteAt failed: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		iterator, err := NewWALIterator(fs, filepath.Join(dir, "wal"), dbID, 1, WALIteratorOptions{
			EncryptionKey: key[:],
		})
		if err != nil {
			t.Fatalf("NewWALIterator failed: %v", err)
		}
		defer iterator.Close()

		// In the last (active) segment, the damaged record length is treated as a torn tail and ends the log
		_, err = iterator.Next()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF on active segment with damaged record length, got: %v", err)
		}
	})
}

// TestWALEncryption_BlockPositionTweakBinding verifies that relocating a WAL block
// to a different offset fails decryption due to AES-XTS tweak mismatch.
func TestWALEncryption_BlockPositionTweakBinding(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_wal_enc_tweak_binding"

	var key [32]byte
	copy(key[:], []byte("tweak-binding-key-32bytes-000000"))

	var dbID [16]byte
	copy(dbID[:], []byte("tweak-bind-db-01"))

	walDir := filepath.Join(dir, "wal")
	wal, err := OpenWAL(memFS, walDir, dbID, 0, WALOptions{
		EncryptionKey: key[:],
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}

	// Write enough data to span multiple 4 KiB blocks
	largeValue := bytes.Repeat([]byte("tweak-binding-test-data-block---"), 256) // 8192 bytes
	record := Record{
		Type:    RecordTypePut,
		LSN:     1,
		Key:     qualifyKey("ConfigMap", "large-key"),
		Payload: append([]byte{byte(CodecNone)}, largeValue...),
	}
	if err := wal.Append(record); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	segPath := filepath.Join(walDir, segmentFileName(1))
	file, err := memFS.OpenFile(segPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	size, err := file.Size()
	if err != nil {
		file.Close()
		t.Fatalf("Size failed: %v", err)
	}
	if size < 3*WALBlockSize {
		file.Close()
		t.Fatalf("expected segment size >= %d, got %d", 3*WALBlockSize, size)
	}

	// Read block 1 (offset 4096) and block 2 (offset 8192)
	block1 := make([]byte, WALBlockSize)
	block2 := make([]byte, WALBlockSize)
	if _, err := file.ReadAt(block1, WALBlockSize); err != nil {
		file.Close()
		t.Fatalf("ReadAt block 1 failed: %v", err)
	}
	if _, err := file.ReadAt(block2, 2*WALBlockSize); err != nil {
		file.Close()
		t.Fatalf("ReadAt block 2 failed: %v", err)
	}

	// Swap block 1 and block 2 on disk
	if _, err := file.WriteAt(block2, WALBlockSize); err != nil {
		file.Close()
		t.Fatalf("WriteAt swapped block 1 failed: %v", err)
	}
	if _, err := file.WriteAt(block1, 2*WALBlockSize); err != nil {
		file.Close()
		t.Fatalf("WriteAt swapped block 2 failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reading the segment with swapped blocks must fail CRC verification or record decode
	iterator, err := NewWALIterator(memFS, walDir, dbID, 1, WALIteratorOptions{
		EncryptionKey: key[:],
	})
	if err != nil {
		t.Fatalf("NewWALIterator failed: %v", err)
	}
	defer iterator.Close()

	// Since this is the active (last) segment, damaged/swapped block ends the log
	_, err = iterator.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on swapped block in active segment, got: %v", err)
	}
}
