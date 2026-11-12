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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Cipher defines an interface for authenticated symmetric payload encryption and decryption.
// Additional authenticated data (additionalData) binds the ciphertext to its table and key
// so a ciphertext cannot be transplanted or read under a different key.
type Cipher interface {
	Encrypt(plaintext []byte, additionalData []byte) ([]byte, error)
	Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error)
}

// AdditionalData formats the AEAD additional authenticated data from table name and object key.
func AdditionalData(tableName, key string) []byte {
	return []byte(tableName + "/" + key)
}

// NoopCipher passes data through without encryption.
type NoopCipher struct{}

func (NoopCipher) Encrypt(plaintext []byte, _ []byte) ([]byte, error) {
	return plaintext, nil
}

func (NoopCipher) Decrypt(ciphertext []byte, _ []byte) ([]byte, error) {
	return ciphertext, nil
}

// AESGCMCipher implements Cipher using AES-256 in GCM mode.
type AESGCMCipher struct {
	aead cipher.AEAD
}

// NewEphemeralAESGCMCipher creates a new AES-256-GCM cipher with a random in-memory key.
func NewEphemeralAESGCMCipher() (*AESGCMCipher, error) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random AES-256 key: %w", err)
	}
	return NewAESGCMCipher(key)
}

// NewAESGCMCipher creates an AES-GCM cipher with the given key (must be 16, 24, or 32 bytes).
func NewAESGCMCipher(key []byte) (*AESGCMCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}
	return &AESGCMCipher{aead: gcm}, nil
}

// Encrypt encrypts plaintext using AES-GCM with a fresh random nonce and binds additionalData.
func (c *AESGCMCipher) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Decrypt verifies and decrypts ciphertext using AES-GCM with additionalData.
func (c *AESGCMCipher) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short: missing nonce")
	}
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, data, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}
	return plaintext, nil
}
