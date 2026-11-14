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
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"unsafe"
)

const (
	// BlockSize is the fixed 4 KiB size of every heap block.
	BlockSize = 4096

	// BlockHeaderSize is the fixed 32-byte header size at the beginning of every block.
	BlockHeaderSize = 32

	// BlockUsableSize is the usable payload capacity per block (4064 bytes).
	BlockUsableSize = BlockSize - BlockHeaderSize

	// BlockMagic is the magic byte identifying valid diskstore blocks ('G' = 0x47).
	BlockMagic uint8 = 0x47

	// FormatVersion is 1.
	FormatVersion uint8 = 1
)

var (
	// ErrInvalidBlockMagic indicates the block magic number does not match.
	ErrInvalidBlockMagic = errors.New("invalid block magic number")

	// ErrInvalidBlockVersion indicates an unsupported block format version.
	ErrInvalidBlockVersion = errors.New("unsupported block format version")

	// ErrBlockCRCMismatch indicates block CRC32C verification failed.
	ErrBlockCRCMismatch = errors.New("block CRC32C checksum mismatch")
)

// BlockHeader represents the self-describing 32-byte header on every 4 KiB block.
// Layout (32 bytes):
// Bytes 0..1:   Magic (1B) + Version (1B)
// Bytes 2..3:   Reserved (2B)
// Bytes 4..7:   CRC32C (4B)
// Bytes 8..15:  LogicalPage (8B)
// Bytes 16..23: LSN (8B)
// Bytes 24..27: BlockIndex (4B)
// Bytes 28..31: NumBlocks (4B)
type BlockHeader struct {
	Magic       uint8  // 1 byte (0x47)
	Version     uint8  // 1 byte (1)
	LogicalPage uint64 // 8 bytes (logical page number)
	LSN         uint64 // 8 bytes (log sequence number)
	BlockIndex  uint32 // 4 bytes (block index within its page: 0..NumBlocks-1)
	NumBlocks   uint32 // 4 bytes (total blocks in this page: power of 2 from 1 to 512)
	CRC32C      uint32 // 4 bytes (CRC32C over entire 4096 bytes with CRC field zeroed)
}

// EncodeBlockHeader writes the header into the first 32 bytes of blockBuf.
// It zeroes the CRC field (bytes 4..8) so CRC32C can be computed over blockBuf.
func EncodeBlockHeader(hdr BlockHeader, blockBuf []byte) {
	if len(blockBuf) < BlockHeaderSize {
		panic("block buffer too short for header")
	}

	blockBuf[0] = BlockMagic
	blockBuf[1] = FormatVersion
	blockBuf[2] = 0
	blockBuf[3] = 0

	// Zero CRC field
	blockBuf[4] = 0
	blockBuf[5] = 0
	blockBuf[6] = 0
	blockBuf[7] = 0

	binary.BigEndian.PutUint64(blockBuf[8:16], hdr.LogicalPage)
	binary.BigEndian.PutUint64(blockBuf[16:24], hdr.LSN)
	binary.BigEndian.PutUint32(blockBuf[24:28], hdr.BlockIndex)
	binary.BigEndian.PutUint32(blockBuf[28:32], hdr.NumBlocks)
}

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// FinalizeBlockCRC computes CRC32C over the entire 4096 bytes of blockBuf and stores it at bytes 4..8.
func FinalizeBlockCRC(blockBuf []byte) uint32 {
	if len(blockBuf) != BlockSize {
		panic(fmt.Sprintf("invalid block size for CRC finalization: %d", len(blockBuf)))
	}
	blockBuf[4] = 0
	blockBuf[5] = 0
	blockBuf[6] = 0
	blockBuf[7] = 0

	crc := crc32.Checksum(blockBuf, castagnoliTable)
	binary.BigEndian.PutUint32(blockBuf[4:8], crc)
	return crc
}

// DecodeBlockHeader parses and validates the 32-byte header of blockBuf.
// It verifies CRC32C, magic, and version.
func DecodeBlockHeader(blockBuf []byte) (BlockHeader, error) {
	if len(blockBuf) < BlockSize {
		return BlockHeader{}, errors.New("block buffer shorter than 4096 bytes")
	}

	storedCRC := binary.BigEndian.Uint32(blockBuf[4:8])

	// Verify CRC over byte ranges on either side of the CRC field without allocating a copy
	var zeroCRC [4]byte
	crc := crc32.Update(0, castagnoliTable, blockBuf[:4])
	crc = crc32.Update(crc, castagnoliTable, zeroCRC[:])
	actualCRC := crc32.Update(crc, castagnoliTable, blockBuf[8:BlockSize])

	if storedCRC != actualCRC {
		return BlockHeader{}, ErrBlockCRCMismatch
	}

	magic := blockBuf[0]
	if magic != BlockMagic {
		return BlockHeader{}, ErrInvalidBlockMagic
	}

	ver := blockBuf[1]
	if ver != FormatVersion {
		return BlockHeader{}, ErrInvalidBlockVersion
	}

	logicalPage := binary.BigEndian.Uint64(blockBuf[8:16])
	lsn := binary.BigEndian.Uint64(blockBuf[16:24])
	blockIndex := binary.BigEndian.Uint32(blockBuf[24:28])
	numBlocks := binary.BigEndian.Uint32(blockBuf[28:32])

	return BlockHeader{
		Magic:       magic,
		Version:     ver,
		LogicalPage: logicalPage,
		LSN:         lsn,
		BlockIndex:  blockIndex,
		NumBlocks:   numBlocks,
		CRC32C:      storedCRC,
	}, nil
}

// AllocateAlignedBlock allocates a slice of size bytes aligned to a 4096-byte boundary.
func AllocateAlignedBlock(size int) []byte {
	raw := make([]byte, size+BlockSize)
	rawPtr := uintptr(unsafe.Pointer(&raw[0]))
	alignedPtr := (rawPtr + uintptr(BlockSize-1)) &^ uintptr(BlockSize-1)
	offset := int(alignedPtr - rawPtr)
	return raw[offset : offset+size]
}
