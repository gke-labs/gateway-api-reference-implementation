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
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecord_EncodeDecode(t *testing.T) {
	orig := Record{
		Type:         RecordTypePut,
		LSN:          105,
		RedoStartLSN: 90,
		Key:          "default/my-configmap",
		Payload:      []byte("sample payload data 12345"),
	}

	encoded := EncodeRecord(orig)
	decoded, err := DecodeRecord(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("DecodeRecord failed: %v", err)
	}

	if decoded.Type != orig.Type ||
		decoded.LSN != orig.LSN ||
		decoded.RedoStartLSN != orig.RedoStartLSN ||
		decoded.Key != orig.Key ||
		!bytes.Equal(decoded.Payload, orig.Payload) {
		t.Fatalf("decoded record does not match original: got %+v, want %+v", decoded, orig)
	}
}

func TestRecord_BadCRC(t *testing.T) {
	orig := Record{
		Type:    RecordTypePut,
		LSN:     1,
		Key:     "test/key",
		Payload: []byte("data"),
	}

	encoded := EncodeRecord(orig)
	// Corrupt payload byte
	encoded[len(encoded)-1] ^= 0xff

	_, err := DecodeRecord(bytes.NewReader(encoded))
	if !errors.Is(err, ErrBadCRC) {
		t.Fatalf("expected ErrBadCRC, got %v", err)
	}
}

func TestRecord_TornRecord(t *testing.T) {
	orig := Record{
		Type: RecordTypeDelete,
		LSN:  2,
		Key:  "test/key",
	}

	encoded := EncodeRecord(orig)
	// Truncate encoded bytes
	short := encoded[:len(encoded)-5]

	_, err := DecodeRecord(bytes.NewReader(short))
	if err == nil {
		t.Fatalf("expected error on truncated record, got nil")
	}
}

func TestRecord_RejectsOldFormatVersion(t *testing.T) {
	orig := Record{
		Type:    RecordTypePut,
		LSN:     1,
		Key:     "test/key",
		Payload: []byte("data"),
	}

	encoded := EncodeRecord(orig)
	// Set version byte to 1 (old WAL record version)
	encoded[1] = 1

	_, err := DecodeRecord(bytes.NewReader(encoded))
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("expected ErrCorruptRecord for old format version, got %v", err)
	}
}

func TestEngine_RejectsOldStoreFormatVersion(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_old_store_format_version"

	if err := memFS.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create meta.db with previous StoreFormatVersion (version 6)
	metaPath := filepath.Join(dir, "meta.db")
	metaFile, err := memFS.Create(metaPath)
	if err != nil {
		t.Fatalf("Create meta.db failed: %v", err)
	}
	var oldDBID [16]byte
	copy(oldDBID[:], []byte("old-db-id-000001"))
	metaBuffer := encodeMetaRecord(metaRecord{
		dbID:    oldDBID,
		version: StoreFormatVersion - 1, // previous StoreFormatVersion
	})
	if _, err := metaFile.WriteAt(metaBuffer, 0); err != nil {
		t.Fatalf("WriteAt meta.db failed: %v", err)
	}
	if err := metaFile.Close(); err != nil {
		t.Fatalf("Close meta.db failed: %v", err)
	}

	// Write dummy heap file to simulate existing database
	heapFile, err := memFS.Create(filepath.Join(dir, "heap.db"))
	if err != nil {
		t.Fatalf("Create heap.db failed: %v", err)
	}
	if _, err := heapFile.WriteAt([]byte("dummy old heap data"), 0); err != nil {
		t.Fatalf("WriteAt heap.db failed: %v", err)
	}
	if err := heapFile.Close(); err != nil {
		t.Fatalf("Close heap.db failed: %v", err)
	}

	// 1. Without WithEraseOnError, Open must fail with an outdated store error
	_, err = Open(WithFS(memFS), WithDir(dir))
	if err == nil {
		t.Fatalf("expected Open without WithEraseOnError to fail on old store version")
	}
	if !strings.Contains(err.Error(), "outdated or corrupt meta file") {
		t.Fatalf("expected error to contain 'outdated or corrupt meta file', got: %v", err)
	}

	// 2. With WithEraseOnError, Open must erase the store and report Wiped() == true
	store, err := Open(WithFS(memFS), WithDir(dir), WithEraseOnError())
	if err != nil {
		t.Fatalf("Open with WithEraseOnError failed: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close failed: %v", err)
		}
	})

	if !store.Wiped() {
		t.Fatalf("expected Wiped() == true when opening old store version with WithEraseOnError")
	}

	// Verify meta.db has been rewritten with current StoreFormatVersion
	readMetaFile, err := memFS.Open(metaPath)
	if err != nil {
		t.Fatalf("Open meta.db failed: %v", err)
	}
	t.Cleanup(func() {
		if err := readMetaFile.Close(); err != nil {
			t.Errorf("readMetaFile.Close failed: %v", err)
		}
	})
	var readBuffer [metaFileSize]byte
	if _, err := readMetaFile.ReadAt(readBuffer[:], 0); err != nil {
		t.Fatalf("ReadAt meta.db failed: %v", err)
	}
	record, err := decodeMetaRecord(readBuffer[:])
	if err != nil {
		t.Fatalf("decodeMetaRecord failed: %v", err)
	}
	if record.version != StoreFormatVersion {
		t.Fatalf("expected StoreFormatVersion %d after wipe, got %d", StoreFormatVersion, record.version)
	}
}
