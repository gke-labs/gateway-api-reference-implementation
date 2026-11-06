# Design: Disk-Store Engine

This document describes the architecture, terminology, on-disk formats, storage invariants, recovery process, and concurrency model of the disk-store engine (`experiments/diskstore/engine`).
For benchmark results and performance measurements, see [diskstore-experiment.md](../../../docs/diskstore-experiment.md).

## Terminology

The engine uses the following terms:

- **Block.** The 4 KiB unit, sized to match the disk. A block lives on disk, in the heap file at a block number, and may also be resident in memory in the block pool. A heap block starts with a 32-byte header carrying the logical page number, LSN, its index within the page, the page's block count, and a CRC32C checksum.
- **Block pool.** The fixed-size, pointer-free in-memory arena of blocks. A resident page occupies one pool block per page block, and those pool blocks do not need to be adjacent.
- **Pool block.** One 4 KiB block in that arena.
- **Page.** The logical unit, identified by a logical page number. It is either a slotted page (one block holding many small records, each in a record slot) or a multi-block page ($2^k$ blocks holding one large record). The engine writes pages out of place, so a logical page moves between block numbers over time.
- **Block run.** A contiguous, aligned run of blocks allocated by the buddy allocator. A multi-block page always occupies one block run, and a flush batch writes several pages into one block run.
- **Record slot.** An entry in a slotted page's directory. "Slot" is used only in this sense.
- **WAL terms:**
  - **Segment.** An append-only log file named by its starting 64-bit LSN, formatted as a 20-digit zero-padded decimal number with a `.wal` extension. The engine appends records to the active segment. In accordance with invariant 4, once a 4 KiB block within a segment is fsynced to disk, the engine never rewrites that block.
  - **Record.** A single log entry recording an operation, such as a write, deletion, or checkpoint.
  - **LSN.** A 64-bit monotonically increasing Log Sequence Number.
  - **Durable LSN.** The highest LSN confirmed flushed and fsynced to disk.

## On-Disk Formats

The engine defines binary layouts for heap blocks, slotted pages, multi-block pages, WAL segment headers, and WAL records. All multi-byte integers use big-endian encoding.

### Block Header

Every 4 KiB heap block begins with a 32-byte header. The header makes each block self-describing on disk:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic (1B)  |  Version (1B) |          Reserved (2B)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          CRC32C (4B)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Logical Page Number (8B)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Log Sequence Number - LSN (8B)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Block Index (4B)        |        Num Blocks (4B)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The header fields contain the following values:
- **Magic (1 byte):** The constant `0x47` (ASCII `'G'`).
- **Version (1 byte):** The constant `1`.
- **Reserved (2 bytes):** Zero padding for 4-byte boundary alignment.
- **CRC32C (4 bytes):** Castagnoli CRC32C checksum computed over the full 4096-byte block with bytes 4 through 7 zeroed.
- **Logical Page Number (8 bytes):** The logical page identifier for this block.
- **LSN (8 bytes):** The log sequence number of the most recent modification to this page.
- **Block Index (4 bytes):** The index of this block within the page, ranging from 0 to `NumBlocks - 1`.
- **Num Blocks (4 bytes):** The total count of blocks in the page. This value is 1 for a slotted page and a power of two from 2 to 512 for a multi-block page.

Each block provides 4064 bytes of usable data space (`BlockSize - BlockHeaderSize`).

### Slotted Page

A slotted page occupies a single 4 KiB block. It stores multiple small records, each assigned to a record slot.

The slotted page layout divides the 4096 bytes into four sections:
1. **Block Header (bytes 0 to 31):** The standard 32-byte block header.
2. **Page Metadata (bytes 32 to 39):**
   - `NumSlots` (2 bytes): Total number of record slots allocated in the directory.
   - `FreeStart` (2 bytes): Byte offset where free space for new record slots starts. It begins at byte 40.
   - `FreeEnd` (2 bytes): Byte offset where free space for new payloads ends. It begins at byte 4096.
   - `Flags` (2 bytes): Reserved flags.
3. **Slot Directory (byte 40 to FreeStart):** An array of 4-byte record slot entries. Each entry contains:
   - `Offset` (2 bytes): Byte offset of the record payload.
   - `Length` (2 bytes): Length of the record payload.
   The slot directory grows upward toward `FreeEnd`.
4. **Record Payloads (FreeEnd to byte 4096):** Record payloads grow downward from byte 4096 toward `FreeStart`.

Each record payload contains:
- `KeyLen` (2 bytes): Length of the key string.
- `PayloadLen` (4 bytes): Length of the value payload.
- `LSN` (8 bytes): Modification LSN for this record.
- `Key`: Raw bytes of the key string.
- `Payload`: Raw or compressed value bytes.

When a record is deleted, the engine sets `Offset` and `Length` to zero in that record slot. This tombstone keeps record slot numbers stable. The engine reuses tombstone record slots for subsequent inserts.

When active payloads fragment space, the engine compacts the page. Compaction slides all active payloads down toward byte 4096 and updates slot offsets in place. Record slot indices remain unchanged during compaction. When all records in a slotted page are deleted, `NumSlots` remains in place, but active record slots drop to zero. The engine then recycles the page as an empty logical page.

### Multi-Block Page

A multi-block page stores a single large record across a power-of-two block run ($2^k$ blocks, from 2 to 512 blocks, up to 2 MiB, as produced by `CalculateMultiBlockCount`).

The format distributes the record across the block run:
- Every block in the run begins with the 32-byte block header. Each block header carries the page's logical page number, LSN, total block count ($2^k$), and individual block index ($0$ through $2^k - 1$).
- The record header, key, and payload are written as one continuous stream starting at byte 32 of block 0 and continuing through the usable section (bytes 32 to 4095) of each successive block in the run:
  - `KeyLen` (2 bytes): Length of the key string.
  - `PayloadLen` (4 bytes): Length of the value payload.
  - `LSN` (8 bytes): Modification LSN.
  - `Key`: Raw bytes of the key string.
  - `Payload`: Raw or compressed value bytes.
  Because the engine writes this data as a single continuous stream, both the key and the payload can cross block boundaries.
- The in-memory key index maps the record to its logical page number and record slot 0.

### Record Placement

The engine stores each record in one of three locations based on the full record size (record header, key, and stored payload):

- **Slotted page:** A record goes into a slotted page if it fits in an empty one (up to 4052 bytes of usable record space).
- **Multi-block page:** Otherwise, if the record fits across 512 blocks (up to 2 MiB), it goes into a power-of-two multi-block page spanning 2 to 512 blocks. A 1-block multi-block page is not allowed because recovery treats any block with a block count of 1 as a slotted page.
- **Oversize store:** Otherwise, records exceeding 512 blocks bypass the block heap and reside in the oversize store, written as individual files (one file per key) in the `oversize/` directory.

Record placement depends on the stored size after compression and payload encryption. An update to an existing key may compress differently or change payload size, allowing the record to move between page types or into the oversize store. When a key moves to a different page type or storage location on an update, the engine must clear its previous location (deleting the old slot, writing an empty page tombstone, or removing the old oversize file) to prevent stale data from lingering or resurrecting.

### WAL Segment Header

Every WAL segment file begins with a 32-byte header:

```
+---------------+---------------+---------------+---------------------------------------+
|  Magic (4B)   |  Version (4B) | Reserved (8B) |           Database ID (16B)           |
|   "WAL1"      |      0x1      |  0x00 padding |     Random 128-bit store identifier   |
+---------------+---------------+---------------+---------------------------------------+
```

The header contains:
- **Magic (4 bytes):** The constant `0x57414C31` (ASCII `"WAL1"`).
- **Version (4 bytes):** The integer `1`.
- **Reserved (8 bytes):** Zero padding for alignment.
- **Database ID (16 bytes):** The unique 128-bit identifier of the store.

### WAL Record

Each WAL record contains a 32-byte header followed by variable-length fields:

```
+-----------+-----------+-----------+---------------+-----------+-------------------+-------------+----------------+------------+
| Magic(1B) |Format(1B) | Type (1B) | Reserved (1B) |  LSN (8B) | RedoStartLSN (8B) | KeyLen (4B) | PayloadLen (4B)| CRC32C(4B) |
+-----------+-----------+-----------+---------------+-----------+-------------------+-------------+----------------+------------+
| Key bytes (KeyLen) ...                    | Payload bytes (PayloadLen) ...                         |
+-------------------------------------------+--------------------------------------------------------+
```

The record fields contain:
- **Magic (1 byte):** The constant `0x52` (ASCII `'R'`).
- **Format Version (1 byte):** The integer `2`.
- **Operation Type (1 byte):** The operation code:
  - `1`: `Put`
  - `2`: `Delete`
  - `3`: `Checkpoint`
- **Reserved (1 byte):** Zero padding.
- **LSN (8 bytes):** The monotonically assigned log sequence number.
- **RedoStartLSN (8 bytes):** The starting LSN for WAL redo replay. This field is populated on Checkpoint records.
- **KeyLen (4 bytes):** Length of the key in bytes.
- **PayloadLen (4 bytes):** Length of the payload in bytes.
- **CRC32C (4 bytes):** Castagnoli CRC32C checksum computed over the record header and body with the CRC field zeroed.
- **Body:** The key bytes and payload bytes.

## Invariants

The engine maintains the following invariants:

### 1. The Write-Ahead Rule

Before the engine writes any page with LSN $L$ to the heap file, the WAL must be fsynced through at least LSN $L$.

This rule prevents disk inconsistency across crashes. If a host loses power after the heap file receives a page write, the WAL on disk will contain all log records up to that page's state. Crash recovery will never encounter heap data that outruns durable log history.

A page write waits until the WAL is durable through that page's LSN. When flushing a batch of pages, the engine waits once, for the highest LSN in the batch.

### 2. The Reuse Rule

The disk location holding a page's newest durable (fsynced) copy must never be overwritten. Older locations become free for reuse only after a newer copy is confirmed durable by a heap file fsync.

Because the engine writes pages out of place, each flush writes a modified page to a newly allocated block run on disk. The engine cannot immediately release the page's prior disk location to the allocator:
- If a crash occurs before the heap file fsync completes, recovery relies on the older durable location. Overwriting or recycling that location prematurely risks data loss.
- Only after the heap file fsync confirms that the new copy is durable does the engine release the superseded location back to the allocator for reuse.

To coordinate concurrent flushes and fsyncs, the engine distinguishes three stages of a page's disk location:
1. **Flushed:** Written to a new disk location, but not yet confirmed durable by a heap fsync.
2. **Syncing:** Snapshotted at the start of an active heap fsync.
3. **Durable:** Confirmed durable by a completed heap fsync.

The engine applies the reuse rule through the following lifecycle:
- **Flushing:** When a dirty page flushes, it writes to a new disk location. If the page previously wrote to an intermediate un-synced location, the engine frees that intermediate location immediately, unless that location is currently syncing. Keeping syncing locations allocated prevents newer flushes from releasing disk blocks that the ongoing fsync is making durable.
- **Syncing and Promotion:** When syncing the heap file, the engine snapshots completed flushed locations for all pages that do not have a flush in flight. Skipping pages with an in-flight flush is safe because not promoting is always conservative: the page retains its older durable location on disk until a subsequent sync. Once the heap fsync completes, the engine promotes the snapshotted locations to durable and frees any superseded older locations to the allocator.
- **Crash Recovery:** If the system crashes before a heap fsync completes, recovery restores the previous durable copy.

### 3. Natural Alignment of Block Runs

Every block run of order $k$ ($2^k$ blocks) allocated by the buddy allocator begins at a block number that is a multiple of $2^k$.

The engine maintains natural alignment for two reasons:
1. **Identifying page starts:** The recovery scanner can tell where a page starts only from alignment. Because every block in a multi-block page carries a self-describing header, inner blocks of a larger run or leftover payload bytes could otherwise masquerade as the start of a smaller page. Enforcing natural alignment rejects misidentified starts immediately and ensures candidate runs do not cross allocation boundaries.
2. **Buddy allocator operations:** The buddy allocator requires natural alignment to split larger block runs and merge adjacent buddy runs. Allocator reconstruction during recovery marks winning runs as allocated, and unaligned block numbers would corrupt the allocator's tree structure.

### 4. Immutability of Fsynced WAL Blocks

The engine never rewrites a WAL block once it has been fsynced to disk.

When syncing the active WAL segment to disk, the write cursor may not align with a 4 KiB block boundary. The engine pads the remainder of the block with zeros and writes it to disk. Subsequent appends begin at the next 4 KiB block boundary, and the engine never writes to the padded block again.

This rule protects acknowledged records against torn writes during crashes. If the engine rewrote partially filled blocks on subsequent syncs, a power failure during a later write could corrupt records that earlier callers already confirmed as durable. Padding to the next block boundary ensures that fsynced blocks remain immutable on disk. During recovery, the WAL iterator recognizes trailing zeros in a block as padding and advances to the next 4 KiB block boundary.

### 5. Retention of Logical Page Numbers

The engine never discards a logical page number when its contents are deleted.

Because the engine writes pages out of place, older copies of a page remain on disk at their former physical block locations until the allocator reuses and overwrites those blocks. If the engine discarded a logical page number upon deletion without writing an empty page to disk, those older copies would still reside in the heap file. During crash recovery, the scan would discover the older copy, observe that it carries the highest known LSN for that abandoned page number, and resurrect the deleted records.

To prevent resurrection, deleting all records from a page writes an empty page carrying the deletion's newer LSN. Recovery then finds the empty page, recognizes that its LSN supersedes all earlier copies, and ignores the stale data. The engine retains empty page numbers and reuses them for future allocations, ensuring that every logical page maintains an unbroken, monotonically increasing LSN history on disk.

## Recovery

Recovery reconstructs database state after a restart or crash by scanning the self-describing heap file and replaying recent WAL records:

- **Self-describing block scan:** Because every heap block header carries its logical page number, block index, total block count, LSN, and CRC checksum, recovery does not depend on a central catalog or page table on disk. Recovery scans the heap file sequentially to discover all valid block runs.
- **Newest valid copy wins:** When out-of-place writes or power failures leave multiple copies of a logical page on disk, recovery checks block integrity and checksums across the entire run. Any torn, partial, or corrupt writes are discarded. For each logical page number, the valid candidate run with the highest LSN wins. Stale and torn copies are harmless because the reuse rule ensures the previous durable copy remains intact on disk until a newer write has completed and fsynced.
- **Allocator and index reconstruction:** Once the winning block runs are selected, the engine reconstructs the buddy allocator state by marking all winning blocks as allocated. All remaining blocks in the file become free for new allocations. The engine then populates the in-memory key index from the active records in the winning pages and restores empty logical page numbers to the empty list.
- **Idempotent WAL redo replay:** Recovery locates the most recent checkpoint in the WAL to determine the redo starting LSN. Redo replays log records forward from that point. For each record, recovery compares the record's LSN against the recovered page's LSN. If the page already reflects an LSN equal to or greater than the log record, the engine skips the record. This per-page LSN check makes redo idempotent, safely handling crashes that occurred mid-checkpoint or mid-flush.
- **Flush before serving:** Any pages modified during WAL redo replay are marked dirty and flushed to newly allocated heap locations. The heap file is fsynced to make those pages durable, and superseded locations are freed before the engine begins serving client traffic.

Recovery relies on the core invariants to guarantee consistency:
- The **write-ahead rule** ensures that redo history in the WAL always covers any page modifications found on disk.
- The **reuse rule** guarantees that an incomplete or torn flush never destroys the valid prior copy of a page.
- **Natural alignment** enables the scan to identify page boundaries and rebuild allocator free lists without metadata corruption.
- **Immutability of fsynced WAL blocks** ensures that acknowledged log records remain intact across crashes.
- **Retention of logical page numbers** ensures that empty page records supersede older on-disk copies and prevent deleted records from resurrecting.

## Concurrency

The engine coordinates concurrent operations through four design choices:

### Single-Writer Mutation

The engine serializes mutating operations (`Put`, `Delete`). A single active writer simplifies transaction management, page allocation, and WAL ordering. It avoids the need for undo logs, distributed multi-page latching protocols, or multi-version concurrency control in the storage engine.

### Concurrent Readers and Scans

- **Point lookups (`Get`):** Lookups run concurrently with write operations. A reader looks up the target record in the in-memory index, pins the referenced page in the block pool, and reads the record under a shared per-page latch.
- **Range scans (`Scan`, `List`):** Iterations acquire a shared view of the engine, preventing concurrent writes from altering index state during traversal. This provides callers with a consistent point-in-time view of the data.

### Non-Blocking Checkpointing

The checkpointer runs concurrently with user writes. It does not serialize behind the engine writer lock. Instead, the checkpointer snapshots dirty page state and flushed locations under brief block pool synchronization, flushes dirty pages itself while writes continue, invokes heap fsync, and appends a checkpoint record to the WAL.

### Synchronization Boundaries

The engine separates synchronization across four distinct layers to prevent deadlocks and contention:

1. **In-Memory Index:** The key index protects mappings from keys to page and slot locations. Index synchronization is strictly innermost. Callers never perform disk I/O, allocate blocks, or acquire page latches while holding index synchronization.
2. **Block Pool vs. Page Data:** The block pool separates pool management from page content access. Callers acquire pool synchronization only to look up, pin, or unpin a page descriptor. Callers release pool synchronization before acquiring a per-page latch to read or modify page bytes. Callers never acquire pool synchronization while holding a per-page latch. This allows concurrent operations to access distinct pages in memory without contending on the pool.
3. **Flushing and Direct I/O:** Page flushing marks descriptors in-flight and releases pool synchronization before copying data into the staging buffer and writing to disk. Direct I/O writes to the heap file proceed without blocking access to other resident pages in the pool.
4. **WAL Appends and Syncing:** The WAL serializes incoming records to preserve strictly monotonic LSN assignment. Log buffer management and background flushes operate independently from page table latches.
