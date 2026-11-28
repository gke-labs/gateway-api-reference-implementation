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
	"crypto/cipher"
	"testing"

	diskstorexts "github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/xts"
	"golang.org/x/crypto/xts"
)

func BenchmarkBlockCipher4KiB(b *testing.B) {
	key64 := make([]byte, derivedBlockKeySize)
	for i := range key64 {
		key64[i] = byte(i)
	}
	src := make([]byte, BlockSize)
	dst := make([]byte, BlockSize)

	xtsCipher, err := xts.NewCipher(aes.NewCipher, key64)
	if err != nil {
		b.Fatalf("xts.NewCipher: %v", err)
	}
	diskstoreXTSCipher, err := diskstorexts.NewCipher(key64)
	if err != nil {
		b.Fatalf("diskstorexts.NewCipher: %v", err)
	}
	aesBlock, err := aes.NewCipher(key64[:MasterKeySize])
	if err != nil {
		b.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		b.Fatalf("cipher.NewGCM: %v", err)
	}

	b.Run("XTS_Encrypt", func(b *testing.B) {
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			xtsCipher.Encrypt(dst, src, uint64(i))
		}
	})

	b.Run("XTS_Decrypt", func(b *testing.B) {
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			xtsCipher.Decrypt(dst, src, uint64(i))
		}
	})

	b.Run("DiskstoreXTS_Encrypt", func(b *testing.B) {
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			diskstoreXTSCipher.Encrypt(dst, src, uint64(i))
		}
	})

	b.Run("DiskstoreXTS_Decrypt", func(b *testing.B) {
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			diskstoreXTSCipher.Decrypt(dst, src, uint64(i))
		}
	})

	b.Run("AES256_CTR", func(b *testing.B) {
		iv := make([]byte, aes.BlockSize)
		stream := cipher.NewCTR(aesBlock, iv)
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			stream.XORKeyStream(dst, src)
		}
	})

	b.Run("AES256_GCM_Seal", func(b *testing.B) {
		nonce := make([]byte, gcm.NonceSize())
		out := make([]byte, 0, BlockSize+gcm.Overhead())
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			out = gcm.Seal(out[:0], nonce, src, nil)
		}
	})

	b.Run("AES256_GCM_Open", func(b *testing.B) {
		nonce := make([]byte, gcm.NonceSize())
		sealed := gcm.Seal(nil, nonce, src, nil)
		out := make([]byte, 0, BlockSize)
		b.SetBytes(BlockSize)
		for i := 0; i < b.N; i++ {
			var openErr error
			out, openErr = gcm.Open(out[:0], nonce, sealed, nil)
			if openErr != nil {
				b.Fatalf("gcm.Open: %v", openErr)
			}
		}
	})
}
