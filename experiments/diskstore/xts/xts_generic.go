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

package xts

import "encoding/binary"

// gf128Feedback is the low byte of the GF(2^128) irreducible polynomial
// x^128 + x^7 + x^2 + x + 1 used for XTS tweak doubling.
const gf128Feedback = 0x87

// encryptBlocksGeneric encrypts one or more 16-byte blocks from src into dst
// using pure Go 64-bit word operations.
//
// Invariants enforced by callers: len(dst) == len(src), len(src) > 0,
// len(src)%blockSize == 0, and dst and src do not partially overlap.
func encryptBlocksGeneric(c *Cipher, dst, src []byte, sectorNum uint64) {
	// Read the first source block before reusing dst[:blockSize] to encrypt the
	// initial tweak. Reusing dst avoids heap-allocating a local tweak array
	// across the cipher.Block interface call and preserves src when dst and src
	// are the same slice.
	blockLow := binary.LittleEndian.Uint64(src[0:8])
	blockHigh := binary.LittleEndian.Uint64(src[8:16])
	tweakLow, tweakHigh := initTweak(c, dst, sectorNum)

	for {
		// Bounds-check hint so the compiler eliminates checks on the slice
		// accesses below.
		_ = dst[15]
		binary.LittleEndian.PutUint64(dst[0:8], blockLow^tweakLow)
		binary.LittleEndian.PutUint64(dst[8:16], blockHigh^tweakHigh)
		c.dataCipher.Encrypt(dst[:blockSize], dst[:blockSize])
		binary.LittleEndian.PutUint64(dst[0:8], binary.LittleEndian.Uint64(dst[0:8])^tweakLow)
		binary.LittleEndian.PutUint64(dst[8:16], binary.LittleEndian.Uint64(dst[8:16])^tweakHigh)

		src = src[blockSize:]
		if len(src) == 0 {
			return
		}
		dst = dst[blockSize:]
		tweakLow, tweakHigh = mul2(tweakLow, tweakHigh)
		_ = src[15]
		blockLow = binary.LittleEndian.Uint64(src[0:8])
		blockHigh = binary.LittleEndian.Uint64(src[8:16])
	}
}

// decryptBlocksGeneric decrypts one or more 16-byte blocks from src into dst
// using pure Go 64-bit word operations.
//
// Invariants enforced by callers: len(dst) == len(src), len(src) > 0,
// len(src)%blockSize == 0, and dst and src do not partially overlap.
func decryptBlocksGeneric(c *Cipher, dst, src []byte, sectorNum uint64) {
	blockLow := binary.LittleEndian.Uint64(src[0:8])
	blockHigh := binary.LittleEndian.Uint64(src[8:16])
	tweakLow, tweakHigh := initTweak(c, dst, sectorNum)

	for {
		_ = dst[15]
		binary.LittleEndian.PutUint64(dst[0:8], blockLow^tweakLow)
		binary.LittleEndian.PutUint64(dst[8:16], blockHigh^tweakHigh)
		c.dataCipher.Decrypt(dst[:blockSize], dst[:blockSize])
		binary.LittleEndian.PutUint64(dst[0:8], binary.LittleEndian.Uint64(dst[0:8])^tweakLow)
		binary.LittleEndian.PutUint64(dst[8:16], binary.LittleEndian.Uint64(dst[8:16])^tweakHigh)

		src = src[blockSize:]
		if len(src) == 0 {
			return
		}
		dst = dst[blockSize:]
		tweakLow, tweakHigh = mul2(tweakLow, tweakHigh)
		_ = src[15]
		blockLow = binary.LittleEndian.Uint64(src[0:8])
		blockHigh = binary.LittleEndian.Uint64(src[8:16])
	}
}

func initTweak(c *Cipher, scratch []byte, sectorNum uint64) (uint64, uint64) {
	_ = scratch[15]
	binary.LittleEndian.PutUint64(scratch[0:8], sectorNum)
	binary.LittleEndian.PutUint64(scratch[8:16], 0)
	c.tweakCipher.Encrypt(scratch[:blockSize], scratch[:blockSize])
	return binary.LittleEndian.Uint64(scratch[0:8]), binary.LittleEndian.Uint64(scratch[8:16])
}

// mul2 multiplies the 128-bit tweak (low, high) by x in GF(2^128) modulo
// x^128 + x^7 + x^2 + x + 1.
func mul2(low, high uint64) (uint64, uint64) {
	carry := uint64(int64(high) >> 63)
	newHigh := (high << 1) | (low >> 63)
	newLow := (low << 1) ^ (carry & gf128Feedback)
	return newLow, newHigh
}
