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
)

const (
	// SlottedPageMetaSize is 8 bytes: NumSlots(2) + FreeStart(2) + FreeEnd(2) + Flags(2).
	SlottedPageMetaSize = 8

	// SlotEntrySize is 4 bytes: Offset(2) + Length(2).
	SlotEntrySize = 4

	// PageRecordHeaderSize is 14 bytes: KeyLen(2) + PayloadLen(4) + LSN(8).
	PageRecordHeaderSize = 14

	// BlockLSNOffset is offset 16 in BlockHeader.
	BlockLSNOffset = 16

	// MaxMultiBlockCount is 512 blocks (2 MiB).
	MaxMultiBlockCount = 512

	// MaxPayloadCapacity is the maximum size of an object payload that fits in 512 blocks.
	MaxPayloadCapacity = (MaxMultiBlockCount * BlockUsableSize) - 32

	// MaxSlottedRecordSize is the maximum record length (header + key + payload) that can fit in an empty slotted page.
	// BlockSize (4096) - BlockHeaderSize (32) - SlottedPageMetaSize (8) - SlotEntrySize (4) = 4052 bytes.
	MaxSlottedRecordSize = BlockSize - BlockHeaderSize - SlottedPageMetaSize - SlotEntrySize
)

// SlottedRecordSize returns the total record size in a slotted page for the given key and payload lengths.
func SlottedRecordSize(keyLen, payloadLen int) int {
	return PageRecordHeaderSize + keyLen + payloadLen
}

// CanFitInSlottedPage reports whether a record with keyLen and payloadLen can fit in an empty slotted page.
func CanFitInSlottedPage(keyLen, payloadLen int) bool {
	if keyLen < 0 || payloadLen < 0 || keyLen > 65535 {
		return false
	}
	return SlottedRecordSize(keyLen, payloadLen) <= MaxSlottedRecordSize
}

// fitsInMultiBlockPage reports whether a record with keyLen and payloadLen can fit
// within the maximum multi-block page capacity (512 blocks = 2,080,768 bytes).
func fitsInMultiBlockPage(keyLen, payloadLen int) bool {
	if keyLen < 0 || payloadLen < 0 || keyLen > 65535 {
		return false
	}
	return PageRecordHeaderSize+keyLen+payloadLen <= MaxMultiBlockCount*BlockUsableSize
}

var (
	// ErrPageFull indicates the slotted page cannot accommodate the record.
	ErrPageFull = errors.New("slotted page is full")

	// ErrSlotNotFound indicates the specified slot does not exist or has been deleted.
	ErrSlotNotFound = errors.New("slot not found")

	// ErrObjectOversize indicates the object exceeds the maximum multi-block page capacity (2 MiB).
	ErrObjectOversize = errors.New("object exceeds maximum page size")
)

// SlottedPage manages in-place slot layout for small records inside a 1-block (4096-byte) page.
type SlottedPage struct {
	buf []byte // Exactly 4096 bytes
}

// NewSlottedPage initializes a blank slotted page buffer with headers.
func NewSlottedPage(logicalPage, lsn uint64) *SlottedPage {
	buf := make([]byte, BlockSize)
	hdr := BlockHeader{
		LogicalPage: logicalPage,
		LSN:         lsn,
		BlockIndex:  0,
		NumBlocks:   1,
	}
	EncodeBlockHeader(hdr, buf)

	// Slotted metadata at BlockHeaderSize (32)
	binary.BigEndian.PutUint16(buf[BlockHeaderSize:BlockHeaderSize+2], 0)                                     // NumSlots = 0
	binary.BigEndian.PutUint16(buf[BlockHeaderSize+2:BlockHeaderSize+4], BlockHeaderSize+SlottedPageMetaSize) // FreeStart = 40
	binary.BigEndian.PutUint16(buf[BlockHeaderSize+4:BlockHeaderSize+6], uint16(BlockSize))                   // FreeEnd = 4096
	binary.BigEndian.PutUint16(buf[BlockHeaderSize+6:BlockHeaderSize+8], 0)                                   // Flags

	return &SlottedPage{buf: buf}
}

// WrapSlottedPage wraps an existing 4096-byte buffer.
func WrapSlottedPage(buf []byte) (*SlottedPage, error) {
	if len(buf) != BlockSize {
		return nil, errors.New("invalid slotted page buffer size")
	}
	// If uninitialized (freeEnd == 0), initialize metadata
	if binary.BigEndian.Uint16(buf[BlockHeaderSize+4:BlockHeaderSize+6]) == 0 {
		binary.BigEndian.PutUint16(buf[BlockHeaderSize:BlockHeaderSize+2], 0)                                     // NumSlots = 0
		binary.BigEndian.PutUint16(buf[BlockHeaderSize+2:BlockHeaderSize+4], BlockHeaderSize+SlottedPageMetaSize) // FreeStart = 40
		binary.BigEndian.PutUint16(buf[BlockHeaderSize+4:BlockHeaderSize+6], uint16(BlockSize))                   // FreeEnd = 4096
		binary.BigEndian.PutUint16(buf[BlockHeaderSize+6:BlockHeaderSize+8], 0)                                   // Flags
	}
	return &SlottedPage{buf: buf}, nil
}

// Buffer returns the underlying 4096-byte slice.
func (p *SlottedPage) Buffer() []byte {
	return p.buf
}

func (p *SlottedPage) numSlots() uint16 {
	return binary.BigEndian.Uint16(p.buf[BlockHeaderSize : BlockHeaderSize+2])
}

func (p *SlottedPage) setNumSlots(n uint16) {
	binary.BigEndian.PutUint16(p.buf[BlockHeaderSize:BlockHeaderSize+2], n)
}

func (p *SlottedPage) freeStart() uint16 {
	return binary.BigEndian.Uint16(p.buf[BlockHeaderSize+2 : BlockHeaderSize+4])
}

func (p *SlottedPage) setFreeStart(off uint16) {
	binary.BigEndian.PutUint16(p.buf[BlockHeaderSize+2:BlockHeaderSize+4], off)
}

func (p *SlottedPage) freeEnd() uint16 {
	return binary.BigEndian.Uint16(p.buf[BlockHeaderSize+4 : BlockHeaderSize+6])
}

func (p *SlottedPage) setFreeEnd(off uint16) {
	binary.BigEndian.PutUint16(p.buf[BlockHeaderSize+4:BlockHeaderSize+6], off)
}

const (
	// SlotFlagOversize is bit 15 of the slot offset, indicating an oversize pointer record.
	SlotFlagOversize uint16 = 0x8000
)

func (p *SlottedPage) slot(idx uint16) (offset uint16, length uint16, isOversize bool) {
	pos := BlockHeaderSize + SlottedPageMetaSize + int(idx)*SlotEntrySize
	rawOff := binary.BigEndian.Uint16(p.buf[pos : pos+2])
	offset = rawOff &^ SlotFlagOversize
	isOversize = (rawOff & SlotFlagOversize) != 0
	length = binary.BigEndian.Uint16(p.buf[pos+2 : pos+4])
	return offset, length, isOversize
}

func (p *SlottedPage) setSlot(idx uint16, offset, length uint16, isOversize bool) {
	pos := BlockHeaderSize + SlottedPageMetaSize + int(idx)*SlotEntrySize
	if isOversize {
		offset |= SlotFlagOversize
	}
	binary.BigEndian.PutUint16(p.buf[pos:pos+2], offset)
	binary.BigEndian.PutUint16(p.buf[pos+2:pos+4], length)
}

// NumSlots returns the number of slots in this slotted page.
func (p *SlottedPage) NumSlots() uint16 {
	return p.numSlots()
}

// ActiveSlotsCount returns the number of non-tombstone slots.
func (p *SlottedPage) ActiveSlotsCount() int {
	var count int
	n := p.numSlots()
	for i := uint16(0); i < n; i++ {
		_, l, _ := p.slot(i)
		if l > 0 {
			count++
		}
	}
	return count
}

// Put inserts or updates a record. It maintains stable slot numbers:
// if a tombstone slot exists, it reuses it; otherwise it appends a new slot.
// If space is fragmented, it compacts the page internally.
func (p *SlottedPage) Put(key string, payload []byte, lsn uint64) (uint32, error) {
	return p.PutWithFlag(key, payload, lsn, false)
}

// PutWithFlag inserts or updates a record with an explicit oversize flag.
func (p *SlottedPage) PutWithFlag(key string, payload []byte, lsn uint64, isOversize bool) (uint32, error) {
	keyBytes := []byte(key)
	if len(keyBytes) > 65535 {
		return 0, ErrPageFull
	}
	recLen := PageRecordHeaderSize + len(keyBytes) + len(payload) // KeyLen(2) + ValLen(4) + LSN(8) + Key + Payload

	numSlots := p.numSlots()

	// Check if we can reuse an existing deleted (tombstone) slot
	slotIdx := uint16(0xffff)
	for i := uint16(0); i < numSlots; i++ {
		off, l, _ := p.slot(i)
		if off == 0 && l == 0 {
			slotIdx = i
			break
		}
	}

	slotHeaderCost := 0
	if slotIdx == 0xffff {
		slotHeaderCost = SlotEntrySize
	}

	availableFreeSpace := int(p.freeEnd()) - int(p.freeStart())
	if availableFreeSpace < 0 {
		availableFreeSpace = 0
	}
	if availableFreeSpace < recLen+slotHeaderCost {
		// Try compaction first
		p.Compact()
		availableFreeSpace = int(p.freeEnd()) - int(p.freeStart())
		if availableFreeSpace < 0 {
			availableFreeSpace = 0
		}
		if availableFreeSpace < recLen+slotHeaderCost {
			return 0, ErrPageFull
		}
	}

	// Allocate from bottom
	newFreeEnd := p.freeEnd() - uint16(recLen)
	p.setFreeEnd(newFreeEnd)

	// Write payload record at newFreeEnd
	off := int(newFreeEnd)
	binary.BigEndian.PutUint16(p.buf[off:off+2], uint16(len(keyBytes)))
	binary.BigEndian.PutUint32(p.buf[off+2:off+6], uint32(len(payload)))
	binary.BigEndian.PutUint64(p.buf[off+6:off+14], lsn)
	copy(p.buf[off+14:off+14+len(keyBytes)], keyBytes)
	copy(p.buf[off+14+len(keyBytes):off+recLen], payload)

	if slotIdx == 0xffff {
		slotIdx = numSlots
		p.setNumSlots(numSlots + 1)
		p.setFreeStart(p.freeStart() + SlotEntrySize)
	}

	p.setSlot(slotIdx, newFreeEnd, uint16(recLen), isOversize)

	// Update page LSN
	binary.BigEndian.PutUint64(p.buf[BlockLSNOffset:BlockLSNOffset+8], lsn)

	return uint32(slotIdx), nil
}

// Get retrieves a record by slot index.
func (p *SlottedPage) Get(slotIdx uint32) (key string, payload []byte, lsn uint64, err error) {
	key, payload, lsn, _, err = p.GetWithFlag(slotIdx)
	return key, payload, lsn, err
}

// GetWithFlag retrieves a record by slot index along with its oversize flag.
func (p *SlottedPage) GetWithFlag(slotIdx uint32) (key string, payload []byte, lsn uint64, isOversize bool, err error) {
	if slotIdx >= uint32(p.numSlots()) {
		return "", nil, 0, false, ErrSlotNotFound
	}
	off, l, isOversize := p.slot(uint16(slotIdx))
	if off == 0 || l == 0 || int(off)+int(l) > len(p.buf) {
		return "", nil, 0, false, ErrSlotNotFound
	}

	recBytes := p.buf[off : off+l]
	if len(recBytes) < 14 {
		return "", nil, 0, false, ErrSlotNotFound
	}
	keyLen := binary.BigEndian.Uint16(recBytes[0:2])
	payloadLen := binary.BigEndian.Uint32(recBytes[2:6])
	lsn = binary.BigEndian.Uint64(recBytes[6:14])
	if 14+int(keyLen)+int(payloadLen) > len(recBytes) {
		return "", nil, 0, false, ErrSlotNotFound
	}
	key = string(recBytes[14 : 14+keyLen])
	payload = recBytes[14+keyLen : 14+int(keyLen)+int(payloadLen)]

	return key, payload, lsn, isOversize, nil
}

// Delete marks a slot as tombstone (offset=0, length=0).
// Invariant: Slot numbers within a slotted page stay stable.
func (p *SlottedPage) Delete(slotIdx uint32, lsn uint64) error {
	if slotIdx >= uint32(p.numSlots()) {
		return ErrSlotNotFound
	}
	p.setSlot(uint16(slotIdx), 0, 0, false)
	binary.BigEndian.PutUint64(p.buf[BlockLSNOffset:BlockLSNOffset+8], lsn)
	return nil
}

// Compact shifts all active records downward to 4096, defragmenting dead space.
// Invariant: Slot numbers stay stable during compaction.
func (p *SlottedPage) Compact() {
	numSlots := p.numSlots()
	freeStart := BlockHeaderSize + SlottedPageMetaSize + int(numSlots)*SlotEntrySize
	temp := make([]byte, BlockSize)

	// Copy page header and metadata
	copy(temp[:freeStart], p.buf[:freeStart])

	newFreeEnd := int(BlockSize)
	for i := uint16(0); i < numSlots; i++ {
		off, l, isOversize := p.slot(i)
		if off == 0 || l == 0 {
			continue // tombstone
		}
		newFreeEnd -= int(l)
		if newFreeEnd < freeStart {
			// Out of space!
			newFreeEnd = freeStart
			break
		}
		copy(temp[newFreeEnd:newFreeEnd+int(l)], p.buf[off:off+l])

		// Update slot offset in temp
		pos := BlockHeaderSize + SlottedPageMetaSize + int(i)*SlotEntrySize
		offVal := uint16(newFreeEnd)
		if isOversize {
			offVal |= SlotFlagOversize
		}
		binary.BigEndian.PutUint16(temp[pos:pos+2], offVal)
		binary.BigEndian.PutUint16(temp[pos+2:pos+4], l)
	}

	binary.BigEndian.PutUint16(temp[BlockHeaderSize+2:BlockHeaderSize+4], uint16(freeStart))
	binary.BigEndian.PutUint16(temp[BlockHeaderSize+4:BlockHeaderSize+6], uint16(newFreeEnd))
	copy(p.buf, temp)
}

// Finalize updates CRC32C over the slotted page.
func (p *SlottedPage) Finalize() {
	FinalizeBlockCRC(p.buf)
}

// CalculateMultiBlockCount determines the power-of-two number of blocks (2..512) needed for a key and payload.
//
// Multi-block allocations start at 2 blocks (order 1) rather than 1 block (order 0)
// because the engine and crash recovery treat NumBlocks == 1 as a slotted page (see recovery.go
// cand.numBlocks == 1 branch, and engine.go Get). With the exact slotted record limit of 4052 bytes,
// a record of 4053–4064 bytes would otherwise fit in 1 usable block (4064 bytes) and receive
// NumBlocks == 1, causing recovery and Get to misread the multi-block page as a slotted page.
func CalculateMultiBlockCount(keyLen, payloadLen int) (int, error) {
	if !fitsInMultiBlockPage(keyLen, payloadLen) {
		return 0, ErrObjectOversize
	}

	neededBytes := PageRecordHeaderSize + keyLen + payloadLen
	neededBlocks := (neededBytes + BlockUsableSize - 1) / BlockUsableSize
	pow2 := 2
	for pow2 < neededBlocks {
		pow2 *= 2
	}
	if pow2 > MaxMultiBlockCount {
		return 0, ErrObjectOversize
	}
	return pow2, nil
}

// MultiBlockPage represents a power-of-two run of blocks holding a single large record.
type MultiBlockPage struct {
	Blocks [][]byte // Exactly numBlocks slices, each 4096 bytes
}

// NewMultiBlockPage creates and encodes a multi-block page holding a single large record at slot 0.
func NewMultiBlockPage(logicalPage, lsn uint64, key string, payload []byte) (*MultiBlockPage, error) {
	keyBytes := []byte(key)
	if len(keyBytes) > 65535 {
		return nil, ErrObjectOversize
	}

	numBlocks, err := CalculateMultiBlockCount(len(keyBytes), len(payload))
	if err != nil {
		return nil, err
	}

	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blocks[i] = make([]byte, BlockSize)
		hdr := BlockHeader{
			LogicalPage: logicalPage,
			LSN:         lsn,
			BlockIndex:  uint32(i),
			NumBlocks:   uint32(numBlocks),
		}
		EncodeBlockHeader(hdr, blocks[i])
	}

	// Serialize record across blocks:
	// Record: KeyLen(2) + PayloadLen(4) + LSN(8) + Key + Payload
	recMeta := make([]byte, PageRecordHeaderSize+len(keyBytes))
	binary.BigEndian.PutUint16(recMeta[0:2], uint16(len(keyBytes)))
	binary.BigEndian.PutUint32(recMeta[2:6], uint32(len(payload)))
	binary.BigEndian.PutUint64(recMeta[6:14], lsn)
	copy(recMeta[14:], keyBytes)

	// Stream recMeta + payload into blocks[0..numBlocks-1][32:4096]
	currBlock := 0
	currOffset := BlockHeaderSize

	writeBytes := func(data []byte) error {
		written := 0
		for written < len(data) {
			if currBlock >= len(blocks) {
				return ErrObjectOversize
			}
			avail := BlockSize - currOffset
			toWrite := len(data) - written
			if toWrite > avail {
				toWrite = avail
			}
			copy(blocks[currBlock][currOffset:currOffset+toWrite], data[written:written+toWrite])
			written += toWrite
			currOffset += toWrite
			if currOffset == BlockSize {
				currBlock++
				currOffset = BlockHeaderSize
			}
		}
		return nil
	}

	if err := writeBytes(recMeta); err != nil {
		return nil, err
	}
	if err := writeBytes(payload); err != nil {
		return nil, err
	}

	// Finalize CRC for every block in the multi-block page
	for _, b := range blocks {
		FinalizeBlockCRC(b)
	}

	return &MultiBlockPage{Blocks: blocks}, nil
}

// DecodeMultiBlockPage extracts the single record from blocks.
func DecodeMultiBlockPage(blocks [][]byte) (key string, payload []byte, lsn uint64, err error) {
	if len(blocks) == 0 {
		return "", nil, 0, errors.New("empty multi-block page")
	}

	// Read metadata from block 0
	b0 := blocks[0]
	if len(b0) < BlockHeaderSize+14 {
		return "", nil, 0, errors.New("block 0 too short")
	}

	keyLen := binary.BigEndian.Uint16(b0[BlockHeaderSize : BlockHeaderSize+2])
	payloadLen := binary.BigEndian.Uint32(b0[BlockHeaderSize+2 : BlockHeaderSize+6])
	lsn = binary.BigEndian.Uint64(b0[BlockHeaderSize+6 : BlockHeaderSize+14])

	totalMetaLen := 14 + int(keyLen)
	metaBuf := make([]byte, totalMetaLen)

	// Read across usable block segments
	currBlock := 0
	currOffset := BlockHeaderSize

	readBytes := func(dst []byte) error {
		read := 0
		for read < len(dst) {
			if currBlock >= len(blocks) {
				return errors.New("truncated multi-block page")
			}
			avail := BlockSize - currOffset
			toRead := len(dst) - read
			if toRead > avail {
				toRead = avail
			}
			copy(dst[read:read+toRead], blocks[currBlock][currOffset:currOffset+toRead])
			read += toRead
			currOffset += toRead
			if currOffset == BlockSize {
				currBlock++
				currOffset = BlockHeaderSize
			}
		}
		return nil
	}

	if err := readBytes(metaBuf); err != nil {
		return "", nil, 0, err
	}

	key = string(metaBuf[14:])
	payload = make([]byte, payloadLen)
	if err := readBytes(payload); err != nil {
		return "", nil, 0, err
	}

	return key, payload, lsn, nil
}
