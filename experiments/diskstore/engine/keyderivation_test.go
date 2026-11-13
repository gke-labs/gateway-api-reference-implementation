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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestKeyDerivation_FixedVectors(t *testing.T) {
	var callerKey [32]byte
	for i := range callerKey {
		callerKey[i] = byte(i + 1)
	}
	var dbID [16]byte
	for i := range dbID {
		dbID[i] = byte(0xa0 + i)
	}

	tests := []struct {
		name     string
		derive   func() ([]byte, error)
		expected string
	}{
		{
			name: "HeapKey",
			derive: func() ([]byte, error) {
				return deriveHeapKey(callerKey[:], dbID)
			},
			expected: "0aef6cfacd3b790ac61edeb8b1d67cc1cc170a1fcd589ece0b7570a2bb1462444a8f180f5e673d68dd6d45d72ff672988641e6ee94edf664dfc9bf8bcee2ca64",
		},
		{
			name: "WALKey_0",
			derive: func() ([]byte, error) {
				return deriveWALKey(callerKey[:], dbID, 0)
			},
			expected: "02125f34fff64846c913267fb85b6c4a3fd74ee3d07fccd73f1eaddd2c4bf84a7d8c721cd3eddf7d9fbe1d63082d39d4d25c91554d514447607aae594fa35d35",
		},
		{
			name: "WALKey_100",
			derive: func() ([]byte, error) {
				return deriveWALKey(callerKey[:], dbID, 100)
			},
			expected: "e7c914c6ea008d5c219a54c494ea233c595b33fbc7bf52b9672ad0579703fdbef30497d774ba51b6b9fa4c2c54fb042dae254c148686cd59e3eaa79c5b2bbe3f",
		},
		{
			name: "OversizeKey",
			derive: func() ([]byte, error) {
				return deriveOversizeKey(callerKey[:], dbID, "testfile.ovs")
			},
			expected: "088c0c701c1803ed1d8c45ee4ba6948e4fb5c9490cbbdc96f8e2c9d10ac6065bf28238eb38c4c40bfa32199ec69a254513d43f7f9451598162e46dce1c44f030",
		},
		{
			name: "KeyCheckKey",
			derive: func() ([]byte, error) {
				return deriveKeyCheckKey(callerKey[:], dbID)
			},
			expected: "8de1e536b4679526a4ca0c382e532d3b35c744efe7bbb459952b413b44e647d5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.derive()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tc.expected {
				t.Errorf("mismatch:\n got: %s\nwant: %s", gotHex, tc.expected)
			}
		})
	}

	t.Run("KeyCheckToken", func(t *testing.T) {
		token, err := computeKeyCheckToken(callerKey[:], dbID)
		if err != nil {
			t.Fatalf("computeKeyCheckToken failed: %v", err)
		}
		expectedTokenHex := "c55d592dc1bace383e80f485969048fce91bd5f66117138402e8937bca489ac0"
		if hex.EncodeToString(token[:]) != expectedTokenHex {
			t.Errorf("token mismatch:\n got: %s\nwant: %s", hex.EncodeToString(token[:]), expectedTokenHex)
		}

		// verifyKeyCheckToken with correct key
		if err := verifyKeyCheckToken(callerKey[:], dbID, token); err != nil {
			t.Errorf("verifyKeyCheckToken failed for valid key: %v", err)
		}

		// verifyKeyCheckToken with wrong key
		var wrongKey [32]byte
		copy(wrongKey[:], callerKey[:])
		wrongKey[0] ^= 0x01
		if err := verifyKeyCheckToken(wrongKey[:], dbID, token); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("expected ErrInvalidKey for wrong key, got: %v", err)
		}

		// verifyKeyCheckToken with wrong token
		var wrongToken [32]byte
		copy(wrongToken[:], token[:])
		wrongToken[0] ^= 0x01
		if err := verifyKeyCheckToken(callerKey[:], dbID, wrongToken); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("expected ErrInvalidKey for wrong token, got: %v", err)
		}
	})
}

func TestKeyDerivation_InvalidKeyLengths(t *testing.T) {
	var dbID [16]byte
	invalidKeys := [][]byte{
		nil,
		{},
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}

	for _, k := range invalidKeys {
		expectedErr := fmt.Sprintf("encryption key must be %d bytes, got %d", MasterKeySize, len(k))
		checkErr := func(name string, err error) {
			if err == nil {
				t.Errorf("%s: expected error for len=%d, got nil", name, len(k))
			} else if errors.Is(err, ErrInvalidKey) {
				t.Errorf("%s: error must not wrap ErrInvalidKey, got %v", name, err)
			} else if !strings.Contains(err.Error(), expectedErr) {
				t.Errorf("%s: expected error containing %q, got %v", name, expectedErr, err)
			}
		}

		_, err := deriveHeapKey(k, dbID)
		checkErr("deriveHeapKey", err)
		_, err = deriveWALKey(k, dbID, 1)
		checkErr("deriveWALKey", err)
		_, err = deriveOversizeKey(k, dbID, "file")
		checkErr("deriveOversizeKey", err)
		_, err = deriveKeyCheckKey(k, dbID)
		checkErr("deriveKeyCheckKey", err)
		_, err = computeKeyCheckToken(k, dbID)
		checkErr("computeKeyCheckToken", err)
		var token [keyCheckTokenSize]byte
		err = verifyKeyCheckToken(k, dbID, token)
		checkErr("verifyKeyCheckToken", err)
	}
}

func TestKeyDerivation_ContextUniqueness(t *testing.T) {
	callerKey := make([]byte, 32)
	for i := range callerKey {
		callerKey[i] = byte(i + 42)
	}
	var dbID [16]byte
	for i := range dbID {
		dbID[i] = byte(i + 7)
	}

	heapKey, _ := deriveHeapKey(callerKey, dbID)
	walKey1, _ := deriveWALKey(callerKey, dbID, 1)
	walKey2, _ := deriveWALKey(callerKey, dbID, 2)
	ovsKey1, _ := deriveOversizeKey(callerKey, dbID, "file1")
	ovsKey2, _ := deriveOversizeKey(callerKey, dbID, "file2")
	checkKey, _ := deriveKeyCheckKey(callerKey, dbID)

	keys := map[string][]byte{
		"heap":     heapKey,
		"wal1":     walKey1,
		"wal2":     walKey2,
		"ovs1":     ovsKey1,
		"ovs2":     ovsKey2,
		"keycheck": checkKey,
	}

	for n1, k1 := range keys {
		for n2, k2 := range keys {
			if n1 != n2 && bytes.Equal(k1, k2) {
				t.Fatalf("key collision between %s and %s", n1, n2)
			}
		}
	}
}

type recoveryTrackingFS struct {
	FS
	heapOpened bool
	walOpened  bool
}

func (t *recoveryTrackingFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	if strings.Contains(name, "heap.db") {
		t.heapOpened = true
	}
	if strings.Contains(name, "wal") && strings.HasSuffix(name, ".wal") {
		t.walOpened = true
	}
	return t.FS.OpenFile(name, flag, perm)
}

func TestEngine_BlockEncryption_OpenKeyVerification(t *testing.T) {
	var validKey [32]byte
	for i := range validKey {
		validKey[i] = byte(i + 1)
	}
	var wrongKey [32]byte
	copy(wrongKey[:], validKey[:])
	wrongKey[0] ^= 0xff

	t.Run("RightKeyOpensStore", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_enc_store"

		store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Put("Table1", "key1", []byte("secret_payload")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Sync(); err != nil {
			t.Fatalf("Sync failed: %v", err)
		}
		dbID := store.DBID()
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen with the right key
		store2, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]))
		if err != nil {
			t.Fatalf("reopening with right key failed: %v", err)
		}
		defer store2.Close()

		if store2.DBID() != dbID {
			t.Fatalf("DBID mismatch after reopen: got %v, want %v", store2.DBID(), dbID)
		}
		val, exists, err := store2.Get("Table1", "key1")
		if err != nil || !exists || string(val) != "secret_payload" {
			t.Fatalf("Get mismatch: val=%s, exists=%v, err=%v", string(val), exists, err)
		}
	})

	t.Run("WrongKeyReturnsErrInvalidKey", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_enc_wrong_key"

		store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Put("Table1", "key1", []byte("data")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen with wrong key without EraseOnError
		_, err = Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(wrongKey[:]))
		if err == nil {
			t.Fatalf("expected Open with wrong key to fail, but succeeded")
		}
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got: %v", err)
		}
	})

	t.Run("FlagMismatches", func(t *testing.T) {
		memFS := NewMemFS()

		// 1. Encrypted store opened without key
		encDir := "flag_enc_store"
		store, err := Open(WithFS(memFS), WithDir(encDir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Put("Table", "k", []byte("v")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Opening without key must return ErrStoreEncrypted
		_, err = Open(WithFS(memFS), WithDir(encDir))
		if !errors.Is(err, ErrStoreEncrypted) {
			t.Fatalf("expected ErrStoreEncrypted, got: %v", err)
		}

		// Even with WithEraseOnError, it must not wipe and still return ErrStoreEncrypted
		_, err = Open(WithFS(memFS), WithDir(encDir), WithEraseOnError())
		if !errors.Is(err, ErrStoreEncrypted) {
			t.Fatalf("expected ErrStoreEncrypted with WithEraseOnError, got: %v", err)
		}

		// 2. Unencrypted store opened with key
		unencDir := "flag_unenc_store"
		unencStore, err := Open(WithFS(memFS), WithDir(unencDir), WithCreate())
		if err != nil {
			t.Fatalf("Open unencrypted failed: %v", err)
		}
		if err := unencStore.Put("Table", "k", []byte("plain")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := unencStore.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Opening with key must return ErrStoreNotEncrypted
		_, err = Open(WithFS(memFS), WithDir(unencDir), WithEncryptionKey(validKey[:]))
		if !errors.Is(err, ErrStoreNotEncrypted) {
			t.Fatalf("expected ErrStoreNotEncrypted, got: %v", err)
		}

		// Even with WithEraseOnError, it must not wipe and still return ErrStoreNotEncrypted
		_, err = Open(WithFS(memFS), WithDir(unencDir), WithEncryptionKey(validKey[:]), WithEraseOnError())
		if !errors.Is(err, ErrStoreNotEncrypted) {
			t.Fatalf("expected ErrStoreNotEncrypted with WithEraseOnError, got: %v", err)
		}
	})

	t.Run("WrongKeyNeverReachesRecoveryAndFilesUnchanged", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_recovery_guard"

		store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Put("Table1", "key1", []byte("payload1")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if _, err := store.Checkpoint(); err != nil {
			t.Fatalf("Checkpoint failed: %v", err)
		}
		if err := store.Put("Table1", "key2", []byte("payload2")); err != nil {
			t.Fatalf("Put 2 failed: %v", err)
		}
		if err := store.Sync(); err != nil {
			t.Fatalf("Sync failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Snapshot all files before attempting open with wrong key
		memFS.mu.RLock()
		snapshot := make(map[string][]byte, len(memFS.files))
		for k, v := range memFS.files {
			snapshot[k] = bytes.Clone(v)
		}
		memFS.mu.RUnlock()

		tracker := &recoveryTrackingFS{FS: memFS}

		// Attempt open with wrong key
		_, err = Open(WithFS(tracker), WithDir(dir), WithEncryptionKey(wrongKey[:]))
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got: %v", err)
		}

		// Verify recovery was never reached
		if tracker.heapOpened {
			t.Fatalf("recovery read heap.db despite invalid key")
		}
		if tracker.walOpened {
			t.Fatalf("recovery read wal files despite invalid key")
		}

		// Verify all files are unchanged
		memFS.mu.RLock()
		defer memFS.mu.RUnlock()
		if len(memFS.files) != len(snapshot) {
			t.Fatalf("file count changed: before=%d, after=%d", len(snapshot), len(memFS.files))
		}
		for name, expectedBytes := range snapshot {
			actualBytes, exists := memFS.files[name]
			if !exists {
				t.Fatalf("file %s was removed after failed open", name)
			}
			if !bytes.Equal(actualBytes, expectedBytes) {
				t.Fatalf("file %s was modified after failed open with wrong key", name)
			}
		}
	})

	t.Run("WrongKeyWithEraseOnErrorWipes", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_erase_on_key_error"

		store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Put("Table1", "key1", []byte("payload1")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen with wrong key and WithEraseOnError
		store2, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(wrongKey[:]), WithEraseOnError())
		if err != nil {
			t.Fatalf("Open with wrong key and WithEraseOnError failed: %v", err)
		}
		defer store2.Close()

		if !store2.Wiped() {
			t.Fatalf("expected store to be wiped on wrong key with WithEraseOnError")
		}

		// Fresh store should have 0 keys from old store
		_, exists, err := store2.Get("Table1", "key1")
		if err != nil || exists {
			t.Fatalf("expected key1 to not exist after wipe, exists=%v, err=%v", exists, err)
		}

		// Can write with new key
		if err := store2.Put("Table1", "newkey", []byte("newval")); err != nil {
			t.Fatalf("Put on wiped store failed: %v", err)
		}
	})

	t.Run("InvalidKeyLengthRejected", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_invalid_len"

		for _, badLen := range []int{16, 24, 31, 33, 64} {
			badKey := make([]byte, badLen)
			_, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(badKey), WithCreate())
			if err == nil {
				t.Fatalf("expected error for key length %d, got nil", badLen)
			}
			if errors.Is(err, ErrInvalidKey) {
				t.Fatalf("error must not wrap ErrInvalidKey for key length %d, got: %v", badLen, err)
			}
			expectedMsg := fmt.Sprintf("encryption key must be %d bytes, got %d", MasterKeySize, badLen)
			if !strings.Contains(err.Error(), expectedMsg) {
				t.Fatalf("expected error %q, got: %v", expectedMsg, err)
			}
		}
	})

	t.Run("Interaction_StoreWithKey_OpenedWithCipherOnly", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_key_store_cipher_open"

		store, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithCreate())
		if err != nil {
			t.Fatalf("Open with key failed: %v", err)
		}
		if err := store.Put("Table", "k", []byte("v")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		cipher, err := NewEphemeralAESGCMCipher()
		if err != nil {
			t.Fatalf("NewEphemeralAESGCMCipher failed: %v", err)
		}

		// Reopen with only WithCipher: must return an error stating encryption key option is required,
		// and NOT say "cipher option required".
		_, err = Open(WithFS(memFS), WithDir(dir), WithCipher(cipher))
		if err == nil {
			t.Fatalf("expected Open with only cipher to fail on key-encrypted store")
		}
		expectedErr := "store is encrypted with a key: encryption key option required"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("expected error containing %q, got: %v", expectedErr, err)
		}
		if strings.Contains(err.Error(), "cipher option required") {
			t.Fatalf("error should not mention 'cipher option required', got: %v", err)
		}
	})

	t.Run("Interaction_StoreWithCipher_OpenedWithKey", func(t *testing.T) {
		memFS := NewMemFS()
		dir := "test_cipher_store_key_open"

		cipher, err := NewEphemeralAESGCMCipher()
		if err != nil {
			t.Fatalf("NewEphemeralAESGCMCipher failed: %v", err)
		}

		store, err := Open(WithFS(memFS), WithDir(dir), WithCipher(cipher), WithCreate())
		if err != nil {
			t.Fatalf("Open with cipher failed: %v", err)
		}
		if err := store.Put("Table", "k", []byte("v")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Reopen with WithEncryptionKey without WithEraseOnError: must fail with ErrInvalidKey
		_, err = Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]))
		if err == nil {
			t.Fatalf("expected Open with key to fail on cipher-only store")
		}
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got: %v", err)
		}

		// Reopen with WithEncryptionKey and WithEraseOnError: must erase and recreate store
		store2, err := Open(WithFS(memFS), WithDir(dir), WithEncryptionKey(validKey[:]), WithEraseOnError())
		if err != nil {
			t.Fatalf("Open with key and WithEraseOnError failed: %v", err)
		}
		defer store2.Close()

		if !store2.Wiped() {
			t.Fatalf("expected store to be wiped when opening cipher-only store with key and WithEraseOnError")
		}
		_, exists, err := store2.Get("Table", "k")
		if err != nil || exists {
			t.Fatalf("expected key to be wiped, exists=%v, err=%v", exists, err)
		}
	})
}
