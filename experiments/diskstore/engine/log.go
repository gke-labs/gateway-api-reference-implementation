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
// Implementations must strictly preserve monotonically increasing LSN ordering.
type Log interface {
	io.Closer

	// AppendRecord appends a record to the log.
	// Contract: If r.LSN is zero, the log assigns the next strictly monotonic
	// 64-bit sequence number (LSN) and records it on r.LSN. The assigned LSN is
	// returned. An append guarantees that the record is staged in the log buffer,
	// but durability is not guaranteed until SyncThrough covers the record's LSN.
	AppendRecord(r *Record) (uint64, error)

	// SyncThrough ensures that all records with LSN <= lsn are flushed and fsynced
	// to durable storage.
	// Contract: When SyncThrough returns nil, all changes through lsn are guaranteed
	// to survive process crashes or abrupt node power loss. If lsn has already
	// been fsynced, SyncThrough returns nil immediately without blocking.
	// The engine relies on this for the write-ahead rule: a heap page with LSN P
	// is never flushed to disk until the log confirms durability through P.
	SyncThrough(lsn uint64) error

	// DurableLSN reports the maximum LSN confirmed durable on storage.
	// Contract: All records at or below the returned LSN have been fsynced.
	// The engine uses this watermark to determine recovery progress and snapshot
	// boundaries when no dirty pages lag in memory.
	DurableLSN() uint64

	// NewIterator creates an iterator to read records forward in sequence starting
	// from startLSN.
	// Contract: The iterator yields records in strictly increasing LSN order beginning
	// at or after startLSN. Unacknowledged torn writes in the active log tail are
	// safely treated as end-of-log (io.EOF), whereas corruption or unexpected gaps
	// in earlier completed segments must return ErrCorruptWAL.
	NewIterator(startLSN uint64) (LogIterator, error)

	// TruncateBefore drops completed log records or segments strictly prior to
	// oldestNeededLSN.
	// Contract: Records with LSN < oldestNeededLSN that are covered by a completed
	// checkpoint may be purged to reclaim disk space. Active log segments or any
	// records needed for recovery (LSN >= oldestNeededLSN) must not be deleted.
	TruncateBefore(oldestNeededLSN uint64) error
}

// LogIterator reads records sequentially forward from a log.
type LogIterator interface {
	io.Closer

	// Next reads the next valid record in sequence.
	// Contract: Returns io.EOF when no further records remain. Returns an error
	// wrapping ErrCorruptWAL if unrecoverable corruption or gap is detected.
	Next() (Record, error)
}
