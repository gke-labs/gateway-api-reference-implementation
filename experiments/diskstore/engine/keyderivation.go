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
	"crypto/aes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strconv"

	"golang.org/x/crypto/xts"
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

// EncryptionKey is the caller's master key for block-level encryption.
// The engine derives the heap, WAL and key-check keys from it.
// Code must not log it or put it in an error.
type EncryptionKey []byte

// String returns a fixed placeholder so that a stray %v or %s does not expose sensitive key material.
func (EncryptionKey) String() string {
	return "<redacted>"
}

// deriveHeapKey derives the 512-bit AES-XTS key for heap blocks from the caller's key.
func deriveHeapKey(key EncryptionKey, dbID [16]byte) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/heap", derivedBlockKeySize)
}

// deriveWALKey derives the 512-bit AES-XTS key for a WAL segment starting at segmentStartLSN from the caller's key.
func deriveWALKey(key EncryptionKey, dbID [16]byte, segmentStartLSN uint64) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/wal/"+strconv.FormatUint(segmentStartLSN, 10), derivedBlockKeySize)
}

// deriveOversizeKey derives the 512-bit AES-XTS key for an oversize value file from the caller's key.
func deriveOversizeKey(key EncryptionKey, dbID [16]byte, filename string) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/oversize/"+filename, derivedBlockKeySize)
}

// deriveKeyCheckKey derives the 256-bit key used to compute the key-check token from the caller's key.
func deriveKeyCheckKey(key EncryptionKey, dbID [16]byte) ([]byte, error) {
	return deriveKey(key, dbID, "diskstore/keycheck", keyCheckKeySize)
}

// computeKeyCheckToken computes the HMAC-SHA256 token of the database ID using the derived key-check key.
func computeKeyCheckToken(key EncryptionKey, dbID [16]byte) ([keyCheckTokenSize]byte, error) {
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
func verifyKeyCheckToken(key EncryptionKey, dbID [16]byte, expectedToken [keyCheckTokenSize]byte) error {
	token, err := computeKeyCheckToken(key, dbID)
	if err != nil {
		return err
	}
	if !hmac.Equal(token[:], expectedToken[:]) {
		return ErrInvalidKey
	}
	return nil
}

// newHeapCipher creates an AES-256-XTS cipher for heap blocks using the derived heap key.
func newHeapCipher(key EncryptionKey, dbID [16]byte) (*xts.Cipher, error) {
	heapKey, err := deriveHeapKey(key, dbID)
	if err != nil {
		return nil, err
	}
	return xts.NewCipher(aes.NewCipher, heapKey)
}

// newWALSegmentCipher creates an AES-256-XTS cipher for a WAL segment starting at startLSN using the derived WAL key.
func newWALSegmentCipher(key EncryptionKey, dbID [16]byte, startLSN uint64) (*xts.Cipher, error) {
	if len(key) == 0 {
		return nil, nil
	}
	walKey, err := deriveWALKey(key, dbID, startLSN)
	if err != nil {
		return nil, err
	}
	return xts.NewCipher(aes.NewCipher, walKey)
}

// newOversizeCipher creates an AES-256-XTS cipher for an oversize value file using the derived oversize key.
func newOversizeCipher(key EncryptionKey, dbID [16]byte, filename string) (*xts.Cipher, error) {
	if len(key) == 0 {
		return nil, nil
	}
	oversizeKey, err := deriveOversizeKey(key, dbID, filename)
	if err != nil {
		return nil, err
	}
	return xts.NewCipher(aes.NewCipher, oversizeKey)
}

// paddedOversizeSize returns length rounded up to a 4 KiB (BlockSize) boundary.
func paddedOversizeSize(length uint64) uint64 {
	if length == 0 {
		return 0
	}
	rem := length % BlockSize
	if rem == 0 {
		return length
	}
	return length + (BlockSize - rem)
}

// encryptOversizeFile encrypts payload in 4 KiB units using AES-256-XTS with the unit index as the tweak,
// zero-padding the final unit to a 4 KiB boundary, and writes the ciphertext to dst.
func encryptOversizeFile(dst File, payload []byte, cipher *xts.Cipher) error {
	const chunkUnits = 64
	chunkBuf := make([]byte, chunkUnits*BlockSize)
	totalUnits := paddedOversizeSize(uint64(len(payload))) / BlockSize
	for unit := uint64(0); unit < totalUnits; {
		nUnits := totalUnits - unit
		if nUnits > chunkUnits {
			nUnits = chunkUnits
		}
		chunkBytes := int(nUnits) * BlockSize
		buf := chunkBuf[:chunkBytes]
		start := int(unit) * BlockSize
		end := start + chunkBytes
		if end <= len(payload) {
			copy(buf, payload[start:end])
		} else {
			copied := copy(buf, payload[start:])
			clear(buf[copied:])
		}
		for i := uint64(0); i < nUnits; i++ {
			unitSlice := buf[i*BlockSize : (i+1)*BlockSize]
			cipher.Encrypt(unitSlice, unitSlice, unit+i)
		}
		if _, err := dst.WriteAt(buf, int64(unit*BlockSize)); err != nil {
			return err
		}
		unit += nUnits
	}
	return nil
}

// decryptOversizeBytes decrypts data in place in 4 KiB units using AES-256-XTS with the unit index
// as the tweak, verifies that any trailing padding bytes beyond expectedLen are zero, and returns
// the unpadded slice of length expectedLen.
func decryptOversizeBytes(data []byte, expectedLen uint64, cipher *xts.Cipher) ([]byte, error) {
	if len(data)%BlockSize != 0 || expectedLen > uint64(len(data)) || uint64(len(data)) != paddedOversizeSize(expectedLen) {
		return nil, fmt.Errorf("%w: invalid encrypted oversize size %d for length %d", ErrCorruptStore, len(data), expectedLen)
	}
	numUnits := uint64(len(data)) / BlockSize
	for unit := uint64(0); unit < numUnits; unit++ {
		unitSlice := data[unit*BlockSize : (unit+1)*BlockSize]
		cipher.Decrypt(unitSlice, unitSlice, unit)
	}
	for _, b := range data[expectedLen:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: non-zero padding in encrypted oversize file", ErrCorruptStore)
		}
	}
	return data[:expectedLen], nil
}

// encryptHeapBlock encrypts a 4 KiB heap block with AES-256-XTS using blockNum as tweak.
func encryptHeapBlock(dst, src []byte, blockNum uint64, cipher *xts.Cipher) {
	if cipher != nil {
		cipher.Encrypt(dst, src, blockNum)
	} else if &dst[0] != &src[0] {
		copy(dst, src)
	}
}

// decryptHeapBlock decrypts a 4 KiB heap block with AES-256-XTS using blockNum as tweak.
func decryptHeapBlock(dst, src []byte, blockNum uint64, cipher *xts.Cipher) {
	if cipher != nil {
		cipher.Decrypt(dst, src, blockNum)
	} else if &dst[0] != &src[0] {
		copy(dst, src)
	}
}

func deriveKey(key EncryptionKey, dbID [16]byte, info string, length int) ([]byte, error) {
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", MasterKeySize, len(key))
	}
	return hkdf.Key(sha256.New, []byte(key), dbID[:], info, length)
}
