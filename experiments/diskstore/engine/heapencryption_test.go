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
	"path/filepath"
	"testing"
)

// TestHeapEncryption_PlaintextNotExposedAfterCheckpoint verifies that after writes
// and a checkpoint, the heap file contains none of the keys, values, or table names in plaintext.
func TestHeapEncryption_PlaintextNotExposedAfterCheckpoint(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_enc_heap_plaintext"

	var key [32]byte
	copy(key[:], []byte("heap-enc-test-master-key-32bytes"))

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
			table: "SecretTableAlpha",
			key:   "secret-key-001",
			value: []byte("super-secret-password-xyz-12345"),
		},
		{
			table: "ConfidentialUsers",
			key:   "user-admin-creds",
			value: []byte("token-bearer-secret-session-abc"),
		},
		{
			table: "LargeObjects",
			key:   "multi-block-confidential",
			value: bytes.Repeat([]byte("confidential-payload-segment-"), 350), // multi-block
		},
	}

	for _, td := range testData {
		if err := store.Put(td.table, td.key, td.value); err != nil {
			t.Fatalf("Put(%s, %s) failed: %v", td.table, td.key, err)
		}
	}

	// Checkpoint flushes dirty pages to the heap file
	if err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read the raw heap file from disk
	heapPath := filepath.Join(dir, "heap.db")
	heapFile, err := memFS.OpenFile(heapPath, 0, 0)
	if err != nil {
		t.Fatalf("failed to open heap file: %v", err)
	}
	defer heapFile.Close()

	heapSize, err := heapFile.Size()
	if err != nil {
		t.Fatalf("failed to get heap file size: %v", err)
	}
	if heapSize == 0 {
		t.Fatalf("heap file is empty after checkpoint")
	}

	heapBytes := make([]byte, heapSize)
	if _, err := heapFile.ReadAt(heapBytes, 0); err != nil {
		t.Fatalf("failed to read heap file: %v", err)
	}

	// Verify none of the table names, keys, or values appear in plaintext anywhere in heap.db
	for _, td := range testData {
		if bytes.Contains(heapBytes, []byte(td.table)) {
			t.Errorf("heap file exposes table name in plaintext: %q", td.table)
		}
		if bytes.Contains(heapBytes, []byte(td.key)) {
			t.Errorf("heap file exposes key in plaintext: %q", td.key)
		}
		if bytes.Contains(heapBytes, td.value) {
			t.Errorf("heap file exposes value in plaintext for key: %q", td.key)
		}
	}

	// Reopen with the encryption key and verify data can be decrypted and read
	store2, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]))
	if err != nil {
		t.Fatalf("reopening encrypted store failed: %v", err)
	}
	defer store2.Close()

	for _, td := range testData {
		val, exists, err := store2.Get(td.table, td.key)
		if err != nil {
			t.Fatalf("Get(%s, %s) error: %v", td.table, td.key, err)
		}
		if !exists {
			t.Fatalf("Get(%s, %s) key not found", td.table, td.key)
		}
		if !bytes.Equal(val, td.value) {
			t.Fatalf("Get(%s, %s) payload mismatch", td.table, td.key)
		}
	}
}

// TestHeapEncryption_BlockCopiedToAnotherPositionFailsCRC32C verifies that
// when a heap block is copied to another position, reading it fails the CRC32C check
// because the tweak mismatch in AES-XTS decrypts into unpredictable bytes.
func TestHeapEncryption_BlockCopiedToAnotherPositionFailsCRC32C(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_enc_block_relocation"

	var key [32]byte
	copy(key[:], []byte("heap-enc-reloc-key-32bytes-00000"))

	var dbID [16]byte
	copy(dbID[:], []byte("db-reloc-test-01"))

	wal, err := OpenWAL(memFS, filepath.Join(dir, "wal"), dbID, 0, WALOptions{})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	heapFile, err := memFS.Create(filepath.Join(dir, "heap.db"))
	if err != nil {
		t.Fatalf("Create heap file failed: %v", err)
	}
	defer heapFile.Close()

	heapCipher, err := newHeapCipher(key[:], dbID)
	if err != nil {
		t.Fatalf("newHeapCipher failed: %v", err)
	}

	buddy := NewBuddyAllocator(512)
	bp := NewBlockPool(heapFile, wal, buddy, dbID, BlockPoolOptions{
		NumPoolBlocks: 16,
		HeapCipher:    heapCipher,
	})

	// 1. Allocate page 1 and write data
	h, err := bp.AllocateNewPage(1, 1, 10)
	if err != nil {
		t.Fatalf("AllocateNewPage failed: %v", err)
	}
	testPayload := []byte("payload-inside-block-for-crc-test")
	copy(h.Block(0)[BlockHeaderSize:], testPayload)
	h.Unpin()

	// 2. Flush page to disk
	if err := bp.FlushPage(1); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}

	origLoc := h.Desc.PhysicalBlock
	if origLoc == NoBlock {
		t.Fatalf("page has NoBlock physical location after flush")
	}

	// 3. Read the encrypted 4 KiB block from disk at origLoc
	origBlockBytes := make([]byte, BlockSize)
	if _, err := heapFile.ReadAt(origBlockBytes, int64(origLoc*BlockSize)); err != nil {
		t.Fatalf("failed to read original block: %v", err)
	}

	// 4. Copy the block to a different physical block position (origLoc + 1)
	relocLoc := origLoc + 1
	if _, err := heapFile.WriteAt(origBlockBytes, int64(relocLoc*BlockSize)); err != nil {
		t.Fatalf("failed to write copied block at %d: %v", relocLoc, err)
	}
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}

	// 5. Attempt to read the relocated block through PinPageWithLocation
	_, err = bp.PinPageWithLocation(2, relocLoc, 1)
	if err == nil {
		t.Fatalf("expected PinPageWithLocation on relocated block to fail CRC32C, but succeeded")
	}
	if !errors.Is(err, ErrBlockCRCMismatch) {
		t.Fatalf("expected ErrBlockCRCMismatch on relocated block read, got: %v", err)
	}

	// 6. Test in Recover scan: zero out the original block and verify Recover discards the relocated block as torn
	zeroBlock := make([]byte, BlockSize)
	if _, err := heapFile.WriteAt(zeroBlock, int64(origLoc*BlockSize)); err != nil {
		t.Fatalf("failed to zero out original block: %v", err)
	}
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}

	reopenedHeap, err := memFS.OpenFile(filepath.Join(dir, "heap.db"), 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	defer reopenedHeap.Close()

	res, err := Recover(memFS, reopenedHeap, dir, filepath.Join(dir, "wal"), dbID, RecoveryOptions{
		HeapCipher: heapCipher,
	})
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	// Relocated block must fail CRC32C and be treated as torn; page 1 or 2 must not be recovered
	if _, exists := res.PageDescs[1]; exists {
		t.Fatalf("relocated page 1 was accepted during recovery!")
	}
	if _, exists := res.PageDescs[2]; exists {
		t.Fatalf("relocated page 2 was accepted during recovery!")
	}
}

// TestHeapEncryption_ErrorMessagesAndWrapping verifies that the encrypted and not-encrypted errors
// match ErrStoreEncrypted and ErrStoreNotEncrypted.
func TestHeapEncryption_ErrorMessagesAndWrapping(t *testing.T) {
	memFS := NewMemFS()
	var key [32]byte
	copy(key[:], []byte("err-msg-test-key-32bytes-0000000"))

	// 1. Create store with key
	keyDir := "key_encrypted_store"
	store, err := Open(WithFS(memFS), WithDir(keyDir), WithEncryptionKey(key[:]), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen without key: must fail with ErrStoreEncrypted
	_, err = Open(WithFS(memFS), WithDir(keyDir))
	if err == nil {
		t.Fatalf("expected Open without key to fail")
	}
	if !errors.Is(err, ErrStoreEncrypted) {
		t.Fatalf("expected ErrStoreEncrypted, got: %v", err)
	}

	// 2. Create unencrypted store
	unencDir := "unencrypted_store"
	unencStore, err := Open(WithFS(memFS), WithDir(unencDir), WithCreate())
	if err != nil {
		t.Fatalf("Open unencrypted failed: %v", err)
	}
	if err := unencStore.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen unencrypted store with key: must fail with ErrStoreNotEncrypted
	_, err = Open(WithFS(memFS), WithDir(unencDir), WithEncryptionKey(key[:]))
	if err == nil {
		t.Fatalf("expected Open with key to fail on unencrypted store")
	}
	if !errors.Is(err, ErrStoreNotEncrypted) {
		t.Fatalf("expected ErrStoreNotEncrypted, got: %v", err)
	}
}

// TestHeapEncryption_NeverWrittenZeroBlocksTreatedAsTorn verifies that never-written
// zero blocks in an encrypted store's heap file decrypt to pseudorandom bytes that fail
// checks and are treated as torn by recovery.
func TestHeapEncryption_NeverWrittenZeroBlocksTreatedAsTorn(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_zero_blocks_torn"

	var key [32]byte
	copy(key[:], []byte("zero-blocks-test-key-32bytes-000"))

	store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := store.Put("Table", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Append 16 never-written blocks of zeros (64 KiB) to simulate pre-allocation / file growth
	heapPath := filepath.Join(dir, "heap.db")
	heapFile, err := memFS.OpenFile(heapPath, 0, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	origSize, err := heapFile.Size()
	if err != nil {
		t.Fatalf("Size failed: %v", err)
	}
	zeroBlocks := make([]byte, 16*BlockSize)
	if _, err := heapFile.WriteAt(zeroBlocks, origSize); err != nil {
		t.Fatalf("WriteAt zero blocks failed: %v", err)
	}
	if err := heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("heapFile.Close failed: %v", err)
	}

	// Reopen store: recovery must treat decrypted zero blocks as torn and succeed
	store2, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(key[:]))
	if err != nil {
		t.Fatalf("Reopen with trailing zero blocks failed: %v", err)
	}
	defer store2.Close()

	val, exists, err := store2.Get("Table", "k1")
	if err != nil || !exists || string(val) != "val1" {
		t.Fatalf("Get mismatch: val=%s, exists=%v, err=%v", string(val), exists, err)
	}
}
