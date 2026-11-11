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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

var (
	// ErrCorruptRecord indicates that a WAL record has an invalid magic or version.
	ErrCorruptRecord = errors.New("corrupt record")

	// ErrBadCRC indicates a CRC32C checksum mismatch in a WAL record.
	ErrBadCRC = errors.New("record CRC mismatch")
)

// RecordType defines the operation type of a WAL log record.
type RecordType uint8

const (
	RecordTypePut        RecordType = 1
	RecordTypeDelete     RecordType = 2
	RecordTypeCheckpoint RecordType = 3
	RecordTypePutPointer RecordType = 4
)

const (
	// OversizePointerMagic identifies an oversize pointer record stored in a slotted page or WAL.
	OversizePointerMagic uint32 = 0x4F565350
)

// IsOversizePointer reports whether the payload is an oversize pointer record.
func IsOversizePointer(data []byte) bool {
	return len(data) >= 44 && binary.BigEndian.Uint32(data[0:4]) == OversizePointerMagic
}

// OversizeHash returns the SHA-256 hash of key combined with payload.
func OversizeHash(key string, payload []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write(payload)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// OversizeFileName returns the hex-encoded SHA-256 hash of key and payload with .obj suffix.
func OversizeFileName(key string, payload []byte) string {
	sum := OversizeHash(key, payload)
	return fmt.Sprintf("%x.obj", sum)
}

// EncodeOversizePointer serializes an oversize value pointer record payload:
// magic (4 bytes) + length (8 bytes) + checksum (32 bytes) + fileName.
func EncodeOversizePointer(length uint64, checksum [32]byte, fileName string) []byte {
	buf := make([]byte, 44+len(fileName))
	binary.BigEndian.PutUint32(buf[0:4], OversizePointerMagic)
	binary.BigEndian.PutUint64(buf[4:12], length)
	copy(buf[12:44], checksum[:])
	copy(buf[44:], fileName)
	return buf
}

// DecodeOversizePointer deserializes an oversize value pointer record payload.
func DecodeOversizePointer(data []byte) (length uint64, checksum [32]byte, fileName string, err error) {
	if !IsOversizePointer(data) {
		return 0, [32]byte{}, "", errors.New("invalid oversize pointer payload")
	}
	length = binary.BigEndian.Uint64(data[4:12])
	copy(checksum[:], data[12:44])
	fileName = string(data[44:])
	if len(fileName) == 0 {
		return 0, [32]byte{}, "", errors.New("empty oversize file name")
	}
	return length, checksum, fileName, nil
}

const (
	// RecordMagic identifies valid log records ('R').
	RecordMagic byte = 0x52

	// RecordFormatVersion is 2.
	RecordFormatVersion byte = 2

	// RecordHeaderSize is 32 bytes:
	// Magic(1) + Version(1) + Type(1) + Reserved(1) + LSN(8) + RedoStartLSN(8) + KeyLen(4) + PayloadLen(4) + CRC32C(4)
	RecordHeaderSize = 32

	// MaxRecordFieldLength is a sanity check limit (64 MiB).
	MaxRecordFieldLength = 64 * 1024 * 1024
)

// Record represents a single write-ahead log record.
type Record struct {
	Type         RecordType
	LSN          uint64
	RedoStartLSN uint64 // Redo start LSN for Checkpoint records
	Key          string
	Payload      []byte
	CRC32C       uint32
}

// EncodeRecord serializes a record into binary format with a valid CRC32C.
func EncodeRecord(r Record) []byte {
	keyBytes := []byte(r.Key)

	totalLen := RecordHeaderSize + len(keyBytes) + len(r.Payload)
	buf := make([]byte, totalLen)

	buf[0] = RecordMagic
	buf[1] = RecordFormatVersion
	buf[2] = byte(r.Type)
	buf[3] = 0 // reserved

	binary.BigEndian.PutUint64(buf[4:12], r.LSN)
	binary.BigEndian.PutUint64(buf[12:20], r.RedoStartLSN)
	binary.BigEndian.PutUint32(buf[20:24], uint32(len(keyBytes)))
	binary.BigEndian.PutUint32(buf[24:28], uint32(len(r.Payload)))

	// Zero CRC field before calculation
	buf[28] = 0
	buf[29] = 0
	buf[30] = 0
	buf[31] = 0

	off := RecordHeaderSize
	copy(buf[off:], keyBytes)
	off += len(keyBytes)
	copy(buf[off:], r.Payload)

	// Compute CRC32C over header + body
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write(buf)
	crc := h.Sum32()

	binary.BigEndian.PutUint32(buf[28:32], crc)
	return buf
}

// DecodeRecord reads and validates a single record from reader.
func DecodeRecord(r io.Reader) (Record, error) {
	header := make([]byte, RecordHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Record{}, err
	}

	magic := header[0]
	ver := header[1]
	if magic != RecordMagic || ver != RecordFormatVersion {
		return Record{}, fmt.Errorf("%w: invalid record magic or version (got magic 0x%02x, ver 0x%02x)", ErrCorruptRecord, magic, ver)
	}

	recType := RecordType(header[2])
	lsn := binary.BigEndian.Uint64(header[4:12])
	redoStartLSN := binary.BigEndian.Uint64(header[12:20])
	keyLen := binary.BigEndian.Uint32(header[20:24])
	payloadLen := binary.BigEndian.Uint32(header[24:28])
	storedCRC := binary.BigEndian.Uint32(header[28:32])

	if keyLen > MaxRecordFieldLength || payloadLen > MaxRecordFieldLength {
		return Record{}, fmt.Errorf("%w: field length exceeds limit", ErrCorruptRecord)
	}

	bodyLen := int(keyLen) + int(payloadLen)
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return Record{}, fmt.Errorf("%w: incomplete record body", ErrCorruptRecord)
	}

	// Verify CRC
	headerCopy := make([]byte, RecordHeaderSize)
	copy(headerCopy, header)
	headerCopy[28] = 0
	headerCopy[29] = 0
	headerCopy[30] = 0
	headerCopy[31] = 0

	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write(headerCopy)
	_, _ = h.Write(body)
	actualCRC := h.Sum32()

	if storedCRC != actualCRC {
		return Record{}, ErrBadCRC
	}

	key := string(body[:keyLen])
	payload := body[keyLen : keyLen+payloadLen]

	return Record{
		Type:         recType,
		LSN:          lsn,
		RedoStartLSN: redoStartLSN,
		Key:          key,
		Payload:      payload,
		CRC32C:       storedCRC,
	}, nil
}
