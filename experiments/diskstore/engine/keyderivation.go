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
	"strconv"
)

const (
	// MasterKeySize is the expected length of the master encryption key in bytes (32 bytes / 256 bits).
	MasterKeySize = 32

	// DerivedBlockKeySize is the length of derived stream keys for AES-256-XTS (64 bytes / 512 bits).
	DerivedBlockKeySize = 64

	// KeyCheckKeySize is the length of the derived key used for the HMAC-SHA256 key check token (32 bytes / 256 bits).
	KeyCheckKeySize = 32

	// KeyCheckTokenSize is the length of the HMAC-SHA256 key check token recorded in meta.db (32 bytes).
	KeyCheckTokenSize = 32
)

// DeriveHeapKey derives the 512-bit AES-XTS key for heap blocks.
func DeriveHeapKey(masterKey []byte, dbID [16]byte) ([]byte, error) {
	return deriveKey(masterKey, dbID, "diskstore/heap", DerivedBlockKeySize)
}

// DeriveWALKey derives the 512-bit AES-XTS key for a WAL segment starting at segmentStartLSN.
func DeriveWALKey(masterKey []byte, dbID [16]byte, segmentStartLSN uint64) ([]byte, error) {
	return deriveKey(masterKey, dbID, "diskstore/wal/"+strconv.FormatUint(segmentStartLSN, 10), DerivedBlockKeySize)
}

// DeriveOversizeKey derives the 512-bit AES-XTS key for an oversize value file.
func DeriveOversizeKey(masterKey []byte, dbID [16]byte, filename string) ([]byte, error) {
	return deriveKey(masterKey, dbID, "diskstore/oversize/"+filename, DerivedBlockKeySize)
}

// DeriveKeyCheckKey derives the 256-bit key used to compute the key-check token.
func DeriveKeyCheckKey(masterKey []byte, dbID [16]byte) ([]byte, error) {
	return deriveKey(masterKey, dbID, "diskstore/keycheck", KeyCheckKeySize)
}

// ComputeKeyCheckToken computes the HMAC-SHA256 token of the database ID using the derived key-check key.
func ComputeKeyCheckToken(masterKey []byte, dbID [16]byte) ([32]byte, error) {
	key, err := DeriveKeyCheckKey(masterKey, dbID)
	if err != nil {
		return [32]byte{}, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(dbID[:])
	var token [32]byte
	copy(token[:], mac.Sum(nil))
	return token, nil
}

// VerifyKeyCheckToken verifies that masterKey matches expectedToken for the database ID.
func VerifyKeyCheckToken(masterKey []byte, dbID [16]byte, expectedToken [32]byte) error {
	token, err := ComputeKeyCheckToken(masterKey, dbID)
	if err != nil {
		return err
	}
	if !hmac.Equal(token[:], expectedToken[:]) {
		return ErrInvalidKey
	}
	return nil
}

func deriveKey(masterKey []byte, dbID [16]byte, info string, length int) ([]byte, error) {
	if len(masterKey) != MasterKeySize {
		return nil, ErrInvalidKey
	}
	return hkdf.Key(sha256.New, masterKey, dbID[:], info, length)
}
