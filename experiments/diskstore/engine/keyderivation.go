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
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strconv"
)

const (
	// MasterKeySize is the expected length of the caller's encryption key in bytes (32 bytes / 256 bits).
	MasterKeySize = 32

	// derivedBlockKeySize is the length of derived stream keys for AES-256-XTS (64 bytes / 512 bits).
	derivedBlockKeySize = 64

	// keyCheckKeySize is the length of the derived key used for the HMAC-SHA256 key check token (32 bytes / 256 bits).
	keyCheckKeySize = 32

	// keyCheckTokenSize is the length of the HMAC-SHA256 key check token recorded in meta.db (32 bytes).
	keyCheckTokenSize = 32
)

// deriveHeapKey derives the 512-bit AES-XTS key for heap blocks from the caller's key.
func deriveHeapKey(key []byte, dbID [16]byte) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/heap", derivedBlockKeySize)
}

// deriveWALKey derives the 512-bit AES-XTS key for a WAL segment starting at segmentStartLSN from the caller's key.
func deriveWALKey(key []byte, dbID [16]byte, segmentStartLSN uint64) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/wal/"+strconv.FormatUint(segmentStartLSN, 10), derivedBlockKeySize)
}

// deriveOversizeKey derives the 512-bit AES-XTS key for an oversize value file from the caller's key.
func deriveOversizeKey(key []byte, dbID [16]byte, filename string) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/oversize/"+filename, derivedBlockKeySize)
}

// deriveKeyCheckKey derives the 256-bit key used to compute the key-check token from the caller's key.
func deriveKeyCheckKey(key []byte, dbID [16]byte) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/keycheck", keyCheckKeySize)
}

// computeKeyCheckToken computes the HMAC-SHA256 token of the database ID using the derived key-check key.
func computeKeyCheckToken(key []byte, dbID [16]byte) ([keyCheckTokenSize]byte, error) {
	k, err := deriveKeyCheckKey(key, dbID)
	if err != nil {
		return [keyCheckTokenSize]byte{}, err
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(dbID[:])
	var token [keyCheckTokenSize]byte
	copy(token[:], mac.Sum(nil))
	return token, nil
}

// verifyKeyCheckToken verifies that the caller's key matches expectedToken for the database ID.
func verifyKeyCheckToken(key []byte, dbID [16]byte, expectedToken [keyCheckTokenSize]byte) error {
	token, err := computeKeyCheckToken(key, dbID)
	if err != nil {
		return err
	}
	if !hmac.Equal(token[:], expectedToken[:]) {
		return ErrInvalidKey
	}
	return nil
}

func deriveKey(key []byte, dbID [16]byte, info string, length int) ([]byte, error) {
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", MasterKeySize, len(key))
	}
	return hkdf.Key(sha256.New, key, dbID[:], info, length)
}

// Suppress unused linter warnings until subsequent block encryption PRs (#1202, #1203, #1204) wire them into the engine.
var (
	_ = deriveHeapKey
	_ = deriveWALKey
	_ = deriveOversizeKey
)
