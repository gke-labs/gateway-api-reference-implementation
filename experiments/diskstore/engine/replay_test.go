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
	"fmt"
	"io"
	"testing"
)

// memLogIterator is an in-memory LogIterator not backed by WAL files or segments.
type memLogIterator struct {
	records []Record
	idx     int
	tailErr error
	closed  bool
}

var _ LogIterator = (*memLogIterator)(nil)

func (m *memLogIterator) Next() (Record, error) {
	if m.closed {
		return Record{}, io.ErrClosedPipe
	}
	if m.idx >= len(m.records) {
		if m.tailErr != nil {
			return Record{}, m.tailErr
		}
		return Record{}, io.EOF
	}
	rec := m.records[m.idx]
	m.idx++
	return rec, nil
}

func (m *memLogIterator) Close() error {
	m.closed = true
	return nil
}

func encodeNonePayload(data []byte) []byte {
	return append([]byte{byte(CodecNone)}, data...)
}

// TestReplay_NonWALIterator verifies that replay drives state reconstruction from an iterator
// not backed by WAL files, correctly applying puts, replacements, multi-block records, and deletes.
func TestReplay_NonWALIterator(t *testing.T) {
	fs := NewMemFS()
	dir := "test_replay_non_wal"

	store, err := Open(WithFS(fs), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	table := "ConfigMap"
	k1 := qualifyKey(table, "key1")
	k2 := qualifyKey(table, "key2")
	kMulti := qualifyKey(table, "key-multi")

	rawMultiPayload := bytes.Repeat([]byte("large-payload-block-data-"), 300) // ~7.5 KiB (multi-block)

	records := []Record{
		{Type: RecordTypePut, LSN: 10, Key: k1, Payload: encodeNonePayload([]byte("val1-initial"))},
		{Type: RecordTypePut, LSN: 11, Key: k2, Payload: encodeNonePayload([]byte("val2-delete-me"))},
		{Type: RecordTypePut, LSN: 12, Key: kMulti, Payload: encodeNonePayload(rawMultiPayload)},
		{Type: RecordTypePut, LSN: 13, Key: k1, Payload: encodeNonePayload([]byte("val1-overwritten"))},
		{Type: RecordTypeDelete, LSN: 14, Key: k2},
	}

	it := &memLogIterator{records: records}
	superseded := make(map[string][]KeyIndexEntry)

	if err := store.replay(it, superseded); err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if !it.closed {
		t.Fatalf("expected iterator to be closed after replay")
	}

	// Verify in-memory store contents before post-replay flush
	v1, exists, err := store.Get(table, "key1")
	if err != nil {
		t.Fatalf("Get key1 failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key1 to exist")
	}
	if string(v1) != "val1-overwritten" {
		t.Fatalf("expected key1 to be %q, got %q", "val1-overwritten", string(v1))
	}

	_, exists, err = store.Get(table, "key2")
	if err != nil {
		t.Fatalf("Get key2 failed: %v", err)
	}
	if exists {
		t.Fatalf("expected deleted key2 to not exist")
	}

	vMulti, exists, err := store.Get(table, "key-multi")
	if err != nil {
		t.Fatalf("Get key-multi failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key-multi to exist")
	}
	if !bytes.Equal(vMulti, rawMultiPayload) {
		t.Fatalf("multi-block payload mismatch")
	}

	// Flush pages to verify pages modified by replay flush cleanly to heap blocks
	if err := store.cp.FlushPages(); err != nil {
		t.Fatalf("FlushPages failed: %v", err)
	}

	// Verify store contents after post-replay flush
	v1After, exists, err := store.Get(table, "key1")
	if err != nil {
		t.Fatalf("Get key1 after flush failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key1 to exist after flush")
	}
	if string(v1After) != "val1-overwritten" {
		t.Fatalf("expected key1 to be %q after flush, got %q", "val1-overwritten", string(v1After))
	}

	vMultiAfter, exists, err := store.Get(table, "key-multi")
	if err != nil {
		t.Fatalf("Get key-multi after flush failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key-multi to exist after flush")
	}
	if !bytes.Equal(vMultiAfter, rawMultiPayload) {
		t.Fatalf("multi-block payload mismatch after flush")
	}
}

// TestReplay_NonWALIterator_SkipsOlderRecords verifies that replay skips records whose LSN
// is older than or equal to the page's current LSN.
func TestReplay_NonWALIterator_SkipsOlderRecords(t *testing.T) {
	fs := NewMemFS()
	dir := "test_replay_skip_older"

	store, err := Open(WithFS(fs), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	table := "ConfigMap"
	k := qualifyKey(table, "key1")

	// Apply an initial newer record (LSN 50)
	it1 := &memLogIterator{
		records: []Record{
			{Type: RecordTypePut, LSN: 50, Key: k, Payload: encodeNonePayload([]byte("val-new"))},
		},
	}
	if err := store.replay(it1, make(map[string][]KeyIndexEntry)); err != nil {
		t.Fatalf("replay it1 failed: %v", err)
	}

	// Replay older records (LSN 40, LSN 50) which must be skipped
	it2 := &memLogIterator{
		records: []Record{
			{Type: RecordTypePut, LSN: 40, Key: k, Payload: encodeNonePayload([]byte("val-old-40"))},
			{Type: RecordTypePut, LSN: 50, Key: k, Payload: encodeNonePayload([]byte("val-old-50"))},
		},
	}
	if err := store.replay(it2, make(map[string][]KeyIndexEntry)); err != nil {
		t.Fatalf("replay it2 failed: %v", err)
	}

	val, exists, err := store.Get(table, "key1")
	if err != nil {
		t.Fatalf("Get key1 failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected key1 to exist")
	}
	if string(val) != "val-new" {
		t.Fatalf("expected %q, got %q", "val-new", string(val))
	}
}

// TestReplay_NonWALIterator_SupersededPages verifies that replay clears older superseded
// page copies when replaying a record with a higher LSN, even when the key's current page
// is already up to date.
func TestReplay_NonWALIterator_SupersededPages(t *testing.T) {
	fs := NewMemFS()
	dir := "test_replay_superseded"

	store, err := Open(WithFS(fs), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	table := "ConfigMap"
	kOld := qualifyKey(table, "key-dummy-old")
	kWin := qualifyKey(table, "key-dummy-win")
	kSup := qualifyKey(table, "key-superseded")

	// 1. Create page 1 with LSN 5 via multi-block kOld
	rawMulti := bytes.Repeat([]byte("superseded-mb-data-"), 300)
	it1 := &memLogIterator{
		records: []Record{
			{Type: RecordTypePut, LSN: 5, Key: kOld, Payload: encodeNonePayload(rawMulti)},
		},
	}
	if err := store.replay(it1, make(map[string][]KeyIndexEntry)); err != nil {
		t.Fatalf("replay it1 failed: %v", err)
	}
	store.keyMu.RLock()
	oldMBEntry := store.keyIndex[kOld]
	store.keyMu.RUnlock()

	// 2. Create page 2 with LSN 25 via multi-block kWin
	it2 := &memLogIterator{
		records: []Record{
			{Type: RecordTypePut, LSN: 25, Key: kWin, Payload: encodeNonePayload(rawMulti)},
		},
	}
	if err := store.replay(it2, make(map[string][]KeyIndexEntry)); err != nil {
		t.Fatalf("replay it2 failed: %v", err)
	}
	store.keyMu.RLock()
	winMBEntry := store.keyIndex[kWin]
	store.keyMu.RUnlock()

	// Associate kSup with winning page 2, and track page 1 as superseded
	store.keyMu.Lock()
	store.keyIndex[kSup] = KeyIndexEntry{
		LogicalPage: winMBEntry.LogicalPage,
		LSN:         25,
		NumBlocks:   winMBEntry.NumBlocks,
	}
	store.keyMu.Unlock()

	superseded := map[string][]KeyIndexEntry{
		kSup: {
			{
				LogicalPage: oldMBEntry.LogicalPage,
				LSN:         5,
				NumBlocks:   oldMBEntry.NumBlocks,
			},
		},
	}

	// 3. Replay a record for kSup at LSN 15.
	// Current page for kSup has LSN 25 >= 15, so kSup's current page is skipped.
	// But older page 1 has LSN 5 < 15, so the older entry on page 1 must be cleared.
	it3 := &memLogIterator{
		records: []Record{
			{Type: RecordTypePut, LSN: 15, Key: kSup, Payload: encodeNonePayload([]byte("v-intermediate"))},
		},
	}
	if err := store.replay(it3, superseded); err != nil {
		t.Fatalf("replay it3 failed: %v", err)
	}

	// Verify superseded entry was consumed and cleared
	if len(superseded[kSup]) != 0 {
		t.Fatalf("expected superseded entry to be cleared, still has %d", len(superseded[kSup]))
	}

	// Verify kSup still points to page 2 (not modified by LSN 15 record)
	store.keyMu.RLock()
	currEntry := store.keyIndex[kSup]
	store.keyMu.RUnlock()
	if currEntry.LogicalPage != winMBEntry.LogicalPage || currEntry.LSN != 25 {
		t.Fatalf("expected kSup to remain on winning page %d at LSN 25, got page %d LSN %d",
			winMBEntry.LogicalPage, currEntry.LogicalPage, currEntry.LSN)
	}
}

// TestReplay_NonWALIterator_Errors verifies error handling during replay:
// - Clean end-of-log / torn tail via io.EOF succeeds.
// - ErrCorruptWAL aborts replay, closes the iterator, and returns an error wrapping ErrCorruptWAL.
// - Other I/O errors abort replay and close the iterator.
func TestReplay_NonWALIterator_Errors(t *testing.T) {
	t.Run("clean EOF ends replay cleanly", func(t *testing.T) {
		fs := NewMemFS()
		store, err := Open(WithFS(fs), WithDir("test_eof"), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

		it := &memLogIterator{tailErr: io.EOF}
		if err := store.replay(it, make(map[string][]KeyIndexEntry)); err != nil {
			t.Fatalf("expected nil error on io.EOF, got: %v", err)
		}
		if !it.closed {
			t.Fatalf("expected iterator to be closed")
		}
	})

	t.Run("ErrCorruptWAL aborts replay and returns wrapped error", func(t *testing.T) {
		fs := NewMemFS()
		store, err := Open(WithFS(fs), WithDir("test_corrupt"), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

		it := &memLogIterator{
			records: []Record{
				{Type: RecordTypePut, LSN: 1, Key: qualifyKey("T", "k1"), Payload: encodeNonePayload([]byte("v1"))},
			},
			tailErr: fmt.Errorf("%w: bad CRC in segment 0", ErrCorruptWAL),
		}

		err = store.replay(it, make(map[string][]KeyIndexEntry))
		if err == nil {
			t.Fatalf("expected ErrCorruptWAL error, got nil")
		}
		if !errors.Is(err, ErrCorruptWAL) {
			t.Fatalf("expected errors.Is(err, ErrCorruptWAL) to be true, got: %v", err)
		}
		if !it.closed {
			t.Fatalf("expected iterator to be closed on error")
		}
	})

	t.Run("IO error aborts replay and closes iterator", func(t *testing.T) {
		fs := NewMemFS()
		store, err := Open(WithFS(fs), WithDir("test_io_err"), WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer store.Close()

		expectedErr := errors.New("network stream disconnected")
		it := &memLogIterator{
			tailErr: expectedErr,
		}

		err = store.replay(it, make(map[string][]KeyIndexEntry))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected errors.Is(err, expectedErr) to be true, got: %v", err)
		}
		if !it.closed {
			t.Fatalf("expected iterator to be closed on error")
		}
	})
}
