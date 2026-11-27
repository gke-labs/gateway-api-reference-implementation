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

package xts_test

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"math"
	"sync"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/xts"
	referencexts "golang.org/x/crypto/xts"
)

func decodeHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return decoded
}

// TestIEEE1619TestVectors checks Encrypt and Decrypt against IEEE P1619/D16
// Annex B test vectors and OpenSSL-verified AES-256-XTS vectors.
func TestIEEE1619TestVectors(t *testing.T) {
	vectors := []struct {
		name       string
		key        string
		sector     uint64
		plaintext  string
		ciphertext string
	}{
		{
			name:       "IEEE1619_Vector10_AES256",
			key:        "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592",
			sector:     0xff,
			plaintext:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			ciphertext: "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151",
		},
		{
			name:       "OpenSSL_AES256_DistinctKeys",
			key:        "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222",
			sector:     0x3333333333,
			plaintext:  "4444444444444444444444444444444444444444444444444444444444444444",
			ciphertext: "e622334f184bbce129a25b2ac76b3d92abf98e22df5bdd15af471f3db8946a85",
		},
		{
			name:       "OpenSSL_AES256_MaxSector",
			key:        "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592",
			sector:     math.MaxUint64,
			plaintext:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ciphertext: "6d4d5df16d900b3609d1138dfd0641e75ef7036175bcd4dc1260e2b3288035e8",
		},
		{
			name:       "IEEE1619_Vector1_AES128",
			key:        "0000000000000000000000000000000000000000000000000000000000000000",
			sector:     0,
			plaintext:  "0000000000000000000000000000000000000000000000000000000000000000",
			ciphertext: "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
		},
		{
			name:       "IEEE1619_Vector2_AES128",
			key:        "1111111111111111111111111111111122222222222222222222222222222222",
			sector:     0x3333333333,
			plaintext:  "4444444444444444444444444444444444444444444444444444444444444444",
			ciphertext: "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
		},
		{
			name:       "IEEE1619_Vector3_AES128",
			key:        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
			sector:     0x3333333333,
			plaintext:  "4444444444444444444444444444444444444444444444444444444444444444",
			ciphertext: "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
		},
		{
			name:       "IEEE1619_Vector4_AES128",
			key:        "2718281828459045235360287471352631415926535897932384626433832795",
			sector:     0,
			plaintext:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			ciphertext: "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
		},
		{
			name:       "IEEE1619_Vector5_AES128",
			key:        "2718281828459045235360287471352631415926535897932384626433832795",
			sector:     1,
			plaintext:  "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
			ciphertext: "264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee59d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c994c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a74079a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee383b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefbd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b1147e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb6275aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad62844bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			cipher, err := xts.NewCipher(decodeHex(t, vector.key))
			if err != nil {
				t.Fatalf("NewCipher: %v", err)
			}

			plaintext := decodeHex(t, vector.plaintext)
			expectedCiphertext := decodeHex(t, vector.ciphertext)

			ciphertext := make([]byte, len(plaintext))
			cipher.Encrypt(ciphertext, plaintext, vector.sector)
			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Fatalf("Encrypt mismatch: got %x, want %x", ciphertext, expectedCiphertext)
			}

			decrypted := make([]byte, len(ciphertext))
			cipher.Decrypt(decrypted, ciphertext, vector.sector)
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt mismatch: got %x, want %x", decrypted, plaintext)
			}

			// Verify in-place Encrypt and Decrypt when dst and src are the same slice.
			inPlace := append([]byte(nil), plaintext...)
			cipher.Encrypt(inPlace, inPlace, vector.sector)
			if !bytes.Equal(inPlace, expectedCiphertext) {
				t.Fatalf("in-place Encrypt mismatch: got %x, want %x", inPlace, expectedCiphertext)
			}
			cipher.Decrypt(inPlace, inPlace, vector.sector)
			if !bytes.Equal(inPlace, plaintext) {
				t.Fatalf("in-place Decrypt mismatch: got %x, want %x", inPlace, plaintext)
			}
		})
	}
}

func TestNewCipherInvalidKeySize(t *testing.T) {
	invalidSizes := []int{0, 1, 16, 24, 31, 33, 47, 49, 63, 65, 128}
	for _, size := range invalidSizes {
		if _, err := xts.NewCipher(make([]byte, size)); err == nil {
			t.Errorf("NewCipher(len=%d) succeeded, want error", size)
		}
	}
}

func TestBufferValidationPanics(t *testing.T) {
	cipher, err := xts.NewCipher(make([]byte, 64))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	assertPanics := func(t *testing.T, name string, call func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		call()
	}

	shared := make([]byte, 64)
	cases := []struct {
		name string
		dst  []byte
		src  []byte
	}{
		{name: "ShortDestination", dst: make([]byte, 16), src: make([]byte, 32)},
		{name: "NonMultipleOfBlockSize", dst: make([]byte, 17), src: make([]byte, 17)},
		{name: "OverlapDestinationAfterSource", dst: shared[16:48], src: shared[0:32]},
		{name: "OverlapDestinationBeforeSource", dst: shared[0:32], src: shared[16:48]},
		{name: "OverlapUnaligned", dst: shared[1:33], src: shared[0:32]},
	}

	for _, testCase := range cases {
		assertPanics(t, "Encrypt/"+testCase.name, func() {
			cipher.Encrypt(testCase.dst, testCase.src, 0)
		})
		assertPanics(t, "Decrypt/"+testCase.name, func() {
			cipher.Decrypt(testCase.dst, testCase.src, 0)
		})
	}

	// Empty input and adjacent non-overlapping slices must not panic.
	cipher.Encrypt(nil, nil, 0)
	cipher.Decrypt(nil, nil, 0)
	cipher.Encrypt(shared[32:64], shared[0:32], 1)
	cipher.Decrypt(shared[0:32], shared[32:64], 1)
}

func TestConcurrentUse(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := xts.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	reference, err := referencexts.NewCipher(aes.NewCipher, key)
	if err != nil {
		t.Fatalf("referencexts.NewCipher: %v", err)
	}

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			plaintext := make([]byte, 4096)
			for i := range plaintext {
				plaintext[i] = byte(worker + i)
			}
			expected := make([]byte, len(plaintext))
			reference.Encrypt(expected, plaintext, uint64(worker))

			ciphertext := make([]byte, len(plaintext))
			decrypted := make([]byte, len(plaintext))
			for range 32 {
				cipher.Encrypt(ciphertext, plaintext, uint64(worker))
				if !bytes.Equal(ciphertext, expected) {
					t.Errorf("worker %d: Encrypt mismatch", worker)
					return
				}
				cipher.Decrypt(decrypted, ciphertext, uint64(worker))
				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("worker %d: Decrypt mismatch", worker)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
}

// FuzzCipher compares Encrypt and Decrypt with golang.org/x/crypto/xts across
// random keys, sector numbers, and lengths, including in-place operation where
// dst and src are the same slice.
func FuzzCipher(f *testing.F) {
	seedData := func(length int) []byte {
		data := make([]byte, length)
		for i := range data {
			data[i] = byte(i*31 + 7)
		}
		return data
	}
	seedKey := func(length int, start byte) []byte {
		key := make([]byte, length)
		for i := range key {
			key[i] = start + byte(i)
		}
		return key
	}

	f.Add(uint8(0), seedKey(32, 0), uint64(0), seedData(0))
	f.Add(uint8(0), seedKey(32, 1), uint64(1), seedData(16))
	f.Add(uint8(1), seedKey(48, 2), uint64(0xff), seedData(48))
	f.Add(uint8(2), seedKey(64, 3), uint64(0x3333333333), seedData(512))
	f.Add(uint8(2), seedKey(64, 4), uint64(math.MaxUint64), seedData(4096))
	f.Add(uint8(2), seedKey(64, 5), uint64(42), seedData(8192))

	validKeySizes := [3]int{32, 48, 64}

	f.Fuzz(func(t *testing.T, keySizeSelector uint8, rawKey []byte, sectorNum uint64, rawData []byte) {
		key := make([]byte, validKeySizes[keySizeSelector%3])
		copy(key, rawKey)

		plaintextLength := (len(rawData) / aes.BlockSize) * aes.BlockSize
		plaintext := rawData[:plaintextLength]
		originalPlaintext := append([]byte(nil), plaintext...)

		gotCipher, err := xts.NewCipher(key)
		if err != nil {
			t.Fatalf("xts.NewCipher(len=%d): %v", len(key), err)
		}
		referenceCipher, err := referencexts.NewCipher(aes.NewCipher, key)
		if err != nil {
			t.Fatalf("referencexts.NewCipher(len=%d): %v", len(key), err)
		}

		// Disjoint buffers.
		gotCiphertext := make([]byte, plaintextLength)
		referenceCiphertext := make([]byte, plaintextLength)
		gotCipher.Encrypt(gotCiphertext, plaintext, sectorNum)
		referenceCipher.Encrypt(referenceCiphertext, plaintext, sectorNum)
		if !bytes.Equal(gotCiphertext, referenceCiphertext) {
			t.Fatalf("Encrypt mismatch for keyLen=%d sector=%d len=%d", len(key), sectorNum, plaintextLength)
		}
		if !bytes.Equal(plaintext, originalPlaintext) {
			t.Fatalf("Encrypt modified src slice")
		}

		gotPlaintext := make([]byte, plaintextLength)
		referencePlaintext := make([]byte, plaintextLength)
		gotCipher.Decrypt(gotPlaintext, gotCiphertext, sectorNum)
		referenceCipher.Decrypt(referencePlaintext, referenceCiphertext, sectorNum)
		if !bytes.Equal(gotPlaintext, referencePlaintext) {
			t.Fatalf("Decrypt mismatch against reference for keyLen=%d sector=%d len=%d", len(key), sectorNum, plaintextLength)
		}
		if !bytes.Equal(gotPlaintext, originalPlaintext) {
			t.Fatalf("Decrypt did not recover plaintext for keyLen=%d sector=%d len=%d", len(key), sectorNum, plaintextLength)
		}

		// In-place buffers where dst and src are the same slice.
		inPlace := append([]byte(nil), originalPlaintext...)
		gotCipher.Encrypt(inPlace, inPlace, sectorNum)
		if !bytes.Equal(inPlace, referenceCiphertext) {
			t.Fatalf("in-place Encrypt mismatch for keyLen=%d sector=%d len=%d", len(key), sectorNum, plaintextLength)
		}
		gotCipher.Decrypt(inPlace, inPlace, sectorNum)
		if !bytes.Equal(inPlace, originalPlaintext) {
			t.Fatalf("in-place Decrypt mismatch for keyLen=%d sector=%d len=%d", len(key), sectorNum, plaintextLength)
		}

		// Oversized destination buffer must leave trailing bytes untouched.
		wideDestination := bytes.Repeat([]byte{0xaa}, plaintextLength+aes.BlockSize)
		gotCipher.Encrypt(wideDestination, plaintext, sectorNum)
		if !bytes.Equal(wideDestination[:plaintextLength], referenceCiphertext) {
			t.Fatalf("oversized destination Encrypt mismatch")
		}
		if !bytes.Equal(wideDestination[plaintextLength:], bytes.Repeat([]byte{0xaa}, aes.BlockSize)) {
			t.Fatalf("oversized destination Encrypt overwrote trailing bytes")
		}
	})
}
