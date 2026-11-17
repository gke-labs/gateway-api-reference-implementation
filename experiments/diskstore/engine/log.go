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

import "io"

// Log abstracts the append-only write-ahead log relied upon by the engine.
// Implementations preserve monotonically increasing LSN ordering.
type Log interface {
	io.Closer

	// AppendRecord appends a record to the log. If r.LSN is zero, the log assigns
	// the next monotonic 64-bit sequence number (LSN) and records it on r.LSN.
	// The assigned LSN is returned. Appending stages the record in the log buffer;
	// durability requires a subsequent sync covering the record's LSN.
	AppendRecord(r *Record) (uint64, error)

	// SyncThrough ensures that all records with LSN <= lsn are flushed and durable.
	// For this interface, durable means records survive process crashes and power loss;
	// for the WAL it is a local fsync. If lsn is already durable, SyncThrough returns
	// nil without blocking. The engine relies on this for the write-ahead rule: a heap
	// page with LSN P is never flushed to disk until the log confirms durability through P.
	SyncThrough(lsn uint64) error

	// Sync flushes all buffered records and makes them durable with an fsync.
	// When Sync returns, all appended records have been written and made durable
	// on storage (for the WAL, via a local fsync). Records survive process crashes,
	// operating system crashes, and node power loss. The engine calls Sync on
	// Engine.Sync and Engine.Flush when persistence is requested, and during checkpoints
	// to ensure the checkpoint record and earlier operations are durable before
	// truncating finished log segments.
	Sync() error

	// MaxLSN reports the highest LSN appended to the log.
	// The engine uses this during checkpoints to determine the redo start LSN
	// when no dirty pages lag in memory.
	MaxLSN() uint64

	// DurableLSN reports the maximum LSN confirmed durable on storage,
	// where all records at or below the returned LSN have been synced.
	DurableLSN() uint64

	// NewIterator creates an iterator to read records forward in sequence starting
	// from startLSN. The iterator yields records in increasing LSN order beginning
	// at or after startLSN. Unacknowledged torn writes in the active log tail are
	// treated as end-of-log (io.EOF), whereas corruption or unexpected gaps in earlier
	// completed segments return ErrCorruptWAL.
	NewIterator(startLSN uint64) (LogIterator, error)

	// TruncateBefore drops completed log records or segments prior to oldestNeededLSN.
	// Records with LSN < oldestNeededLSN covered by a completed checkpoint may be
	// purged to reclaim space. Active log segments or records needed for recovery
	// (LSN >= oldestNeededLSN) are retained.
	TruncateBefore(oldestNeededLSN uint64) error
}

// LogIterator reads records sequentially forward from a log.
type LogIterator interface {
	io.Closer

	// Next reads the next valid record in sequence. Returns io.EOF when no further
	// records remain, or an error wrapping ErrCorruptWAL if unrecoverable corruption
	// or a gap is detected.
	Next() (Record, error)
}
