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

// Package xts implements AES-XTS as specified in IEEE 1619 without ciphertext
// stealing.
//
// XTS encrypts fixed-size disk sectors and does not authenticate data. Sector
// inputs must be multiples of the 16-byte AES block size.
package xts

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"unsafe"
)

// blockSize is the AES block size in bytes.
const blockSize = aes.BlockSize

// encryptBlocks and decryptBlocks run the per-sector loops. Platform-specific
// init functions may replace them with assembly implementations when the CPU
// supports hardware AES instructions.
var (
	encryptBlocks = encryptBlocksGeneric
	decryptBlocks = decryptBlocksGeneric
)

// Cipher holds the expanded AES key schedules for AES-XTS encryption and
// decryption. Multiple goroutines may call Encrypt and Decrypt on the same
// Cipher concurrently.
type Cipher struct {
	dataCipher  cipher.Block
	tweakCipher cipher.Block
}

// NewCipher creates an AES-XTS Cipher from key. IEEE 1619 defines AES-XTS for
// 128-bit and 256-bit AES keys only, so key must be 32 or 64 bytes. NewCipher
// uses the first half of key for data blocks and the second half for tweaks.
func NewCipher(key []byte) (*Cipher, error) {
	switch len(key) {
	case 32, 64:
	default:
		return nil, fmt.Errorf("xts: invalid key size %d", len(key))
	}

	halfKeySize := len(key) / 2
	dataCipher, err := aes.NewCipher(key[:halfKeySize])
	if err != nil {
		return nil, err
	}
	tweakCipher, err := aes.NewCipher(key[halfKeySize:])
	if err != nil {
		return nil, err
	}
	return &Cipher{
		dataCipher:  dataCipher,
		tweakCipher: tweakCipher,
	}, nil
}

// Encrypt encrypts a sector from src into dst using sectorNum as the 64-bit
// little-endian tweak. The length of src must be a multiple of 16 bytes, and
// dst must be at least as long as src. The buffers dst and src must overlap
// either completely or not at all.
func (c *Cipher) Encrypt(dst, src []byte, sectorNum uint64) {
	validateBuffers(dst, src)
	if len(src) == 0 {
		return
	}
	encryptBlocks(c, dst[:len(src)], src, sectorNum)
}

// Decrypt decrypts a sector from src into dst using sectorNum as the 64-bit
// little-endian tweak. The length of src must be a multiple of 16 bytes, and
// dst must be at least as long as src. The buffers dst and src must overlap
// either completely or not at all.
func (c *Cipher) Decrypt(dst, src []byte, sectorNum uint64) {
	validateBuffers(dst, src)
	if len(src) == 0 {
		return
	}
	decryptBlocks(c, dst[:len(src)], src, sectorNum)
}

func validateBuffers(dst, src []byte) {
	if len(dst) < len(src) {
		panic("xts: destination is smaller than source")
	}
	if len(src)%blockSize != 0 {
		panic("xts: input is not a multiple of the block size")
	}
	if len(src) > 0 && inexactOverlap(dst[:len(src)], src) {
		panic("xts: invalid buffer overlap")
	}
}

// inexactOverlap reports whether non-empty slices x and y share memory at any
// non-corresponding index. It uses unsafe.Pointer to match
// golang.org/x/crypto/xts's overlap panic because the standard library's
// alias.InexactOverlap helper is internal.
func inexactOverlap(x, y []byte) bool {
	if &x[0] == &y[0] {
		return false
	}
	return uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
