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

The engine defines binary layouts for database metadata (`meta.db`), heap blocks, slotted pages, multi-block pages, WAL segment headers, and WAL records. All multi-byte integers use big-endian encoding.

### Database Metadata (`meta.db`)

The database metadata file (`meta.db`) is a fixed-size 4 KiB (4096-byte) record initialized when a store is created:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (4B)           |      StoreFormatVersion (4B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Database ID (16B)                       |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Flags (8B)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     KeyCheckToken (32B)                       |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Reserved (4028B)                        |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          CRC32C (4B)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The fields contain the following values:
- **Magic (4 bytes):** The constant `0x4D455441` (ASCII `"META"`).
- **StoreFormatVersion (4 bytes):** The store format version recorded by the engine (`StoreFormatVersion`).
- **Database ID (16 bytes):** Unique 16-byte identifier for the database instance.
- **Flags (8 bytes):** Store flags. Bit 0 indicates whether the store was created with an encryption cipher (`metaFlagEncrypted`). Bits 1 through 63 are reserved and must be zero.
- **KeyCheckToken (32 bytes):** An HMAC-SHA256 of the database ID computed using a key derived from the master key with context `"diskstore/keycheck"`. In an unencrypted store, this field is zero. Adding this field takes 32 reserved bytes and bumps `StoreFormatVersion`.
- **Reserved (4028 bytes):** Reserved space written as zeroes. New fields take reserved bytes and bump `StoreFormatVersion`. Reserved bytes that aren't zero under the current version are rejected as an error.
- **CRC32C (4 bytes):** Castagnoli CRC32C checksum computed over the full 4096-byte block with the CRC field zeroed.

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

### Oversize Values

For records exceeding 512 blocks (about 2 MiB after compression), only the value bytes live in a dedicated file in the `oversize/` directory. The heap stores each oversize key's pointer as a small record in the heap pages, in place of the value:

- **Value file first.** The engine writes the value payload to a file in the `oversize/` directory before acquiring the writer lock. In an unencrypted store, the file name is the SHA-256 hash of the key combined with the stored (compressed) value bytes. In an encrypted store, the engine names each oversize file with a random identifier. The engine encrypts the value in 4 KiB units using AES-256-XTS with the unit index as the tweak and a key derived for that file. XTS requires whole 16-byte cipher blocks, so the engine pads the final 4 KiB unit with zeros to a 4 KiB boundary. The unpadded value length resides in the pointer record. Using a random identifier avoids leaking hashes of plaintext contents to callers who can list directory entries. Because each write generates a fresh random identifier, the skip-identical-rewrite rule does not apply to encrypted stores; every oversize write creates and fsyncs a new file. In an unencrypted store, the engine skips writing only when the key's current durable pointer already names this file, because that file was verified when it was written or during recovery. Finding an unreferenced file on disk with that name is not sufficient to skip writing, because a crash could have left a torn orphan that was never fully written or fsynced. In every other case, the engine writes the value through a temporary file, fsyncs the file, renames it into place over any existing file, and fsyncs the `oversize/` directory before taking the writer lock. Atomic rename ensures that any torn orphan with the same name is replaced. Writing and syncing the value file outside the writer lock keeps large disk transfers off the critical path for other writes.
- **Pointer record.** The heap stores the pointer as a small record in the heap pages, in place of the value. The record holds the value file name, the unpadded value length, and a 32-byte SHA-256 checksum of the stored (compressed) value bytes. Checkpointing preserves pointers because they are heap records. Checkpoints, WAL replay, and compaction handle the pointer like any other small record. The WAL record for an oversize `Put` carries the same pointer instead of the value payload, so redo replay can rebuild the heap record if the engine crashes before flushing the heap page. The pointer record format changes to include the 32-byte checksum field in all stores. In an unencrypted store, the file name already reflects that checksum. In an encrypted store, the checksum in the pointer record verifies the decrypted file contents during reads and recovery, because XTS does not authenticate ciphertext. This avoids carrying multi-megabyte payloads in the WAL, and the engine writes the payload once instead of twice.
- **Old-version retention.** When a key is updated with a different value, the engine deletes the previous version's file only after the new pointer record is durable in the WAL. This mirrors the heap's reuse rule. If a crash interrupts the write before the new pointer is fsynced, recovery still relies on the previous version's file. When rewritten with an identical value, the existing file is retained and never deleted, provided the key's current durable pointer already names this file; otherwise, the engine writes a replacement file through a temporary file and renames it into place.
- **Recovery.** Recovery decides which files are live from the pointers in the recovered heap plus the replayed WAL, and deletes only files that neither references. Recovery verifies the length and checksum of every referenced file. A missing or corrupt file that a durable pointer references indicates store corruption.
- **Periodic garbage collection.** A long-running store cannot rely on the next restart to remove orphan files. A background sweep lists the `oversize/` directory periodically, such as during checkpointing, and deletes files that no live record points to. The sweep must never delete a file whose pointer record has not yet been appended to the WAL. A `Put` adds the file name (and any temporary file name) to an in-memory in-flight registry before creating the file, and removes it after the pointer record is appended or the `Put` fails. This registry also covers replacement writes when an unverified orphan file already exists. The sweep inspects this registry under the writer lock before deleting any unreferenced file. Registering before creation prevents a sweep from running between file creation and registration. Relying on an explicit registry rather than a minimum file age ensures that correctness does not depend on timing. Each sweep costs one directory listing.
- **Trade-offs.** An oversize `Put` with a new value (or replacing an unverified file) costs a file fsync, a directory fsync, and the WAL fsync. Rewriting an identical value whose durable pointer is already confirmed costs only the WAL fsync. Orphan files can exist between a crash and the next recovery or garbage collection sweep. In return, the WAL avoids multi-megabyte records, the payload is written once instead of twice, and other writes do not wait behind payload fsyncs.

### Record Placement

The engine stores each record in one of three locations based on the full record size (record header, key, and stored payload):

- **Slotted page:** A record goes into a slotted page if it fits in an empty one (up to 4052 bytes of usable record space).
- **Multi-block page:** Otherwise, if the record fits across 512 blocks (up to 2 MiB), it goes into a power-of-two multi-block page spanning 2 to 512 blocks. A 1-block multi-block page is not allowed because recovery treats any block with a block count of 1 as a slotted page.
- **Oversize store:** Otherwise, for records exceeding 512 blocks, value bytes reside in individual files under the `oversize/` directory, while heap pages and WAL records hold pointer records to them.

Record placement depends on the stored size after compression. An update to an existing key may compress differently or change payload size, allowing the record to move between page types or into the oversize store. When a key moves to a different page type or storage location on an update, the engine must clear its previous location (deleting the old slot, writing an empty page tombstone, or deleting the old oversize file once the replacement record is durable) to prevent stale data from lingering or resurrecting.

### WAL Segment Header

Every WAL segment file begins with a 32-byte header in plaintext:

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

The segment header remains in plaintext in all stores. Recovery reads the segment header before reading log records, extracting the database ID to derive the WAL encryption key.

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

## Block-Level Encryption

A copy of the store's files reveals no keys, values, or table names without the encryption key. The design protects data at rest against offline exposure, such as copied backups and disk snapshots. File modes (0600 for files and 0700 for directories) remain the first protection on the host, and encryption covers copies that file modes do not reach. The design does not detect deliberate modification of the files by an attacker with write access to storage.

The engine executes encryption and decryption at the block I/O boundary in the block pool. The pool encrypts each full 4 KiB block with AES-256-XTS when flushing it to disk, and decrypts the full 4 KiB block when reading it into the pool. Because AES-XTS transforms fixed-size blocks without ciphertext expansion, encrypted stores use the exact same block layout as unencrypted stores (`BlockUsableSize = 4064`). Nothing in a block stays in plaintext. The cipher transforms all 4096 bytes, including the page header, logical page number, LSN, and CRC32C. Layers above the block pool—such as slotted pages, multi-block pages, the key index, `Get`, and `Put`—operate on plaintext in memory and do not manage ciphers or keys. This block-level scheme replaces the previous per-value cipher, per-value nonces, and per-record associated data.

### Key Derivation

The caller provides a 32-byte master key. The engine derives separate 512-bit keys (two 256-bit keys for AES-256-XTS) using HKDF-SHA256. The HKDF derivation uses the store's 16-byte database ID as the salt, the caller's 32-byte master key as the secret input key material, and a domain separation string as the context info:
- **Heap key:** Derived with context string `"diskstore/heap"`.
- **WAL segment keys:** Derived per segment with context string `"diskstore/wal/" + segmentStartLSN`.
- **Oversize keys:** Derived per file with context string `"diskstore/oversize/" + filename`.
- **Key check key:** A 256-bit key derived with context string `"diskstore/keycheck"`, used to compute the HMAC-SHA256 token in `meta.db`.

Deriving separate keys for each container file and segment ensures that the same tweak in two files or segments never shares an encryption key, because every derivation context string is unique across the store.

### Tweaks and Positional Binding

AES-XTS requires a 128-bit tweak for each 4 KiB block. The engine assigns tweaks from block positions:
- **Heap blocks:** The tweak is the 64-bit physical block number in the heap file.
- **WAL blocks:** The tweak is the block index within the segment: `BlockOffset / BlockSize`.
- **Oversize files:** The tweak is the 4 KiB unit index within the oversize file.

Because each file or segment uses a distinct derived key and positions within each file are distinct, every `(key, tweak)` pair names exactly one position in the store.

### Execution Boundaries

The crypto transform runs at the direct I/O boundary:
- **Heap blocks:** The pool decrypts 4 KiB heap blocks during read before inserting them into pool descriptors, and encrypts them from the staging buffer during flushes.
- **WAL blocks:** The engine encrypts each whole 4 KiB WAL block before writing to disk and decrypts each block when reading segments during recovery. Direct I/O pads the log buffer to a 4 KiB boundary only on sync. The WAL has no per-block header.
- **Oversize value files:** The engine encrypts oversize files in 4 KiB units using AES-256-XTS with the unit index as the tweak and the file's derived key. The engine pads the final unit with zeros to a 4 KiB boundary, and the pointer record stores the exact value length. The engine generates a random identifier for the file name, preventing directory listings from revealing guessed values. The skip-identical-rewrite rule does not apply to encrypted oversize files.

### Startup and Key Verification

`meta.db` records whether the creator encrypted the store. If a caller provides a cipher for a store written without one, `Open` fails closed and returns `ErrStoreNotEncrypted`. If a caller opens an encrypted store without providing a cipher, `Open` fails closed and returns `ErrStoreEncrypted`. For an encrypted store, `meta.db` stores an HMAC-SHA256 token of the database ID under the key-check key. `Open` computes the expected HMAC-SHA256 token and verifies it before recovery reads any block from disk. If key verification fails, `Open` returns `ErrInvalidKey`. The caller's `WithEraseOnError` option decides the next action. For kubecache, which generates an ephemeral key per process, a key mismatch is the normal condition across restarts, triggering store erasure and cache reconstruction from the API server.

### Integrity

The Castagnoli CRC32C checksum in the plaintext page header provides the sole integrity check for heap blocks. If a block is moved to a different physical position, torn during a crash, or changed on disk, AES-XTS decrypts the block into unpredictable bytes that fail the CRC32C check. This check detects storage corruption and torn writes; it is not cryptographic authentication. The WAL maintains its existing per-record CRC32C checksums and torn-tail rule. For oversize files, the SHA-256 checksum recorded in the heap pointer record validates the decrypted file contents.

### Recovery

Recovery scans physical heap blocks sequentially and decrypts each block using its physical block number as the tweak before inspecting its header. Callers must provide the cipher key to `Open` before recovery starts. The engine verifies the key against the token in `meta.db` before recovery begins, ensuring that a wrong key fails `Open` immediately rather than causing recovery to misinterpret corrupted blocks as torn writes, open an empty store, and overwrite older durable data. Once the key is verified, recovery treats any block that fails CRC32C verification as a torn write and discards it. The heap file grows by extending file size, so it can contain unwritten blocks of zeros. In an encrypted store, decrypting a block of zeros produces pseudorandom bytes that fail the magic, version, and CRC32C checks; recovery treats never-written zero blocks like torn blocks and discards them. The torn-write and newest-copy-wins rules then operate on decrypted candidate blocks with valid checksums. For WAL blocks, an invalid record checksum in the active segment ends the log as a torn tail, whereas an invalid checksum in a closed segment indicates corruption. Any trailing zero padding at the end of an extended WAL segment similarly decrypts to invalid record bytes that end the log under the torn-tail rule.

### Memory Residency

The block pool holds decrypted plaintext pages in memory. Anyone who can inspect process memory can read cached values, just as they can read the encryption key today. The engine protects data at rest on disk, not against local process memory inspection.

### What an Observer Can Learn

Block-level encryption protects record keys, values, table names, slotted-page headers, and internal page LSNs on disk. However, several storage properties remain visible:
- **File names:** WAL segment file names reveal segment start LSNs.
- **File sizes:** The size of the heap file, WAL segments, and oversize value files remain visible. An oversize file's size closely reflects its value payload size.
- **Changed pieces:** AES-XTS is deterministic. Someone who reads the files at two times learns which 16-byte pieces of a block changed.
- **Block tampering:** Someone who can write the files can restore an older copy of a block, or scramble a block, which the CRC32C check then rejects during read or recovery.

### Cost and Measurement

Every block pool miss decrypts a 4 KiB block, and every flush encrypts one. AES-XTS performance in Go is currently unmeasured on this storage engine. When the implementation lands, the existing benchmark suite `TestDiskStore_Versus_BBolt_MeasurementSuite` in `experiments/diskstore/kubecache/bench_test.go` will measure write throughput, read latency, and recovery time under AES-XTS block-level encryption.

### Future Work: Authenticated Encryption

Authenticated block encryption requires storing a cryptographic nonce and authentication tag for each block. These fields can live inside each block, which reduces `BlockUsableSize`, or outside the blocks, such as next to each page's entry in a page map. Authenticated encryption remains future work and is not part of this design.

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

### 6. Old-Version Retention for Oversize Values

The engine deletes the file holding an older version of an oversize value only after a WAL fsync confirms that the replacement pointer record is durable.

This rule mirrors the heap's reuse rule (Invariant 2). When an update changes a value, the file name changes and the engine writes a new file. If the system crashes before the engine fsyncs the new pointer record to the WAL, crash recovery relies on the previous durable pointer and its backing value file. Deleting the previous file before the new pointer record is durable risks data loss across a crash. The engine skips writing and retains the existing file only when the key's current durable pointer already names that file. In every other case—even if a file with that name already exists, such as an unfsynced or torn orphan from an earlier crash—the write path writes the value through a temporary file, fsyncs it, and renames it into place so the orphan is replaced.

### 7. In-Flight Protection for Oversize Garbage Collection

The background garbage collector never deletes an oversize value file before the engine appends the pointer record to the WAL.

Because the engine writes and fsyncs the value file before acquiring the writer lock and appending the pointer record to the WAL, newly created value files exist on disk before any log record references them. A `Put` adds the file name (and any temporary file name) to an in-memory in-flight registry before creating the file, and removes it after the pointer record is appended or the `Put` fails. This in-flight registry also covers replacement writes when replacing an unverified or torn orphan file. The background sweep inspects this registry under the writer lock before deleting any unreferenced file from the `oversize/` directory. Registering before creation prevents a sweep from running between file creation and registration. Relying on an explicit registry rather than a minimum file age ensures that garbage collection correctness does not depend on timing or clock stability.

### 8. Heap Storage of Oversize Pointers

The engine stores each oversize value's pointer record in a heap page, never solely in the WAL.

Checkpoints truncate WAL segments based on dirty heap pages. As checkpoints advance, the engine discards older WAL records. Storing the pointer record in the heap ensures that checkpointing preserves the pointer, because the pointer is a heap record. Checkpointing, page flushing, and compaction handle the pointer like any other small record. The WAL record for an oversize `Put` carries the same pointer, so redo replay can rebuild the heap record if a crash occurs before the page flushes.

### 9. The Block-Binding Rule

The engine binds every encrypted block to its container file and physical location by using the block position as the AES-XTS tweak and verifying the plaintext CRC32C checksum.

When the block pool flushes a heap block, it encrypts the block using the physical block number as the tweak under the heap key derived from the database ID. When writing a WAL block, the engine encrypts the block using its block index within the segment as the tweak under the segment key derived from the database ID and segment start LSN. When writing an oversize file unit, the engine encrypts the unit using the unit index as the tweak under the file's derived key. The read path decrypts the block with the same derived key and tweak, then validates the plaintext CRC32C checksum. If a block is moved to a different offset or file, the tweak mismatch causes AES-XTS to decrypt the block into unpredictable bytes that fail the CRC32C check. This rule detects accidental block displacement and corruption across the store.

### 10. The Fail-Closed Rule

The engine refuses to open a store if the configured cipher conflicts with the store's recorded encryption state or fails key verification, and treats corrupted blocks as torn.

During `Open`, the engine reads the encryption flag recorded in `meta.db`. If a caller provides a cipher for an unencrypted store, `Open` returns `ErrStoreNotEncrypted`. If a caller opens an encrypted store without providing a cipher, `Open` returns `ErrStoreEncrypted`. For an encrypted store, `meta.db` stores an HMAC-SHA256 key-check token. `Open` computes and verifies this token under the derived key-check key before recovery reads any block. If verification fails, `Open` returns `ErrInvalidKey`. This prevents a wrong key from causing recovery to treat all encrypted blocks as torn and opening an empty store that overwrites existing data. The configured `WithEraseOnError` option determines whether the caller receives `ErrInvalidKey` or erases the store (the expected restart behavior for kubecache's ephemeral per-process keys). During recovery with a verified key, a checksum failure in a closed WAL segment represents corruption, and `Open` fails as well. The engine treats invalid heap blocks and active WAL segment tail blocks as torn writes and discards them. During steady-state reads, any block that fails CRC32C verification returns an error and transitions the engine into its sticky failed state. The CRC32C check detects storage corruption, accidental block displacement, and torn writes with an error detection probability of roughly $1 - 2^{-32}$.

## Recovery

Recovery reconstructs database state after a restart or crash by scanning the self-describing heap file and replaying recent WAL records:

- **Self-describing block scan:** Because every heap block header carries its logical page number, block index, total block count, LSN, and CRC checksum, recovery does not depend on a central catalog or page table on disk. In an encrypted store, recovery decrypts each 4 KiB block using its physical block number as the tweak before inspecting the header. If a block fails CRC32C verification, recovery treats it as torn. Recovery scans the heap file sequentially to discover all valid block runs.
- **Newest valid copy wins:** When out-of-place writes or power failures leave multiple copies of a logical page on disk, recovery checks block integrity and checksums across the entire run. Any torn, partial, or corrupt writes are discarded. For each logical page number, the valid candidate run with the highest LSN wins. Stale and torn copies are harmless because the reuse rule ensures the previous durable copy remains intact on disk until a newer write has completed and fsynced.
- **Allocator and index reconstruction:** Once the winning block runs are selected, the engine reconstructs the buddy allocator state by marking all winning blocks as allocated. All remaining blocks in the file become free for new allocations. The engine then populates the in-memory key index from the active records in the winning pages and restores empty logical page numbers to the empty list.
- **Idempotent WAL redo replay:** Recovery locates the most recent checkpoint in the WAL to determine the redo starting LSN. Redo replays log records forward from that point. For each record, recovery compares the record's LSN against the recovered page's LSN. If the page already reflects an LSN equal to or greater than the log record, the engine skips the record. This per-page LSN check makes redo idempotent, safely handling crashes that occurred mid-checkpoint or mid-flush.
- **Flush before serving:** Any pages modified during WAL redo replay are marked dirty and flushed to newly allocated heap locations. The heap file is fsynced to make those pages durable, and superseded locations are freed before the engine begins serving client traffic.
- **Oversize value reconciliation:** Recovery decides which files are live from the pointers in the recovered heap plus the replayed WAL, and deletes only files that neither references. Recovery validates the length and checksum of every referenced file. A missing or corrupt file that a durable pointer references indicates store corruption.

Recovery relies on the core invariants to guarantee consistency:
- The **write-ahead rule** ensures that redo history in the WAL always covers any page modifications found on disk.
- The **reuse rule** guarantees that an incomplete or torn flush never destroys the valid prior copy of a page.
- **Natural alignment** enables the scan to identify page boundaries and rebuild allocator free lists without metadata corruption.
- **Immutability of fsynced WAL blocks** ensures that acknowledged log records remain intact across crashes.
- **Retention of logical page numbers** ensures that empty page records supersede older on-disk copies and prevent deleted records from resurrecting.
- The **old-version rule**, **in-flight protection**, and **heap pointer storage** ensure that valid oversize value files remain intact across crashes, checkpoints, and background sweeps.
- The **block-binding rule** (Invariant 9) ensures that blocks moved to different physical positions decrypt to pseudorandom bytes and fail checksum verification.
- The **fail-closed rule** (Invariant 10) ensures that mismatched cipher configurations, key verification failures, and checksum failures in closed WAL segments abort startup.

## Concurrency

The engine coordinates concurrent operations through four design choices:

### Single-Writer Mutation

The engine serializes mutating operations (`Put`, `Delete`). A single active writer simplifies transaction management, page allocation, and WAL ordering. It avoids the need for undo logs, distributed multi-page latching protocols, or multi-version concurrency control in the storage engine. For oversize values, the engine writes and fsyncs the value file before taking the writer lock, keeping large disk transfers off the critical write path.

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
