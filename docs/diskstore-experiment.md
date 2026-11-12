# Experiment: Write-Ahead Log + Block Pool Disk Store for Informer Objects

## Executive Summary

This experiment evaluates a custom, pure Go disk-backed store under `experiments/diskstore` designed specifically for Kubernetes informer caches. It replaces the `bbolt` prototype from `experiments/bboltcache` to solve two critical architectural limitations:

1. **The `mmap` Problem:** In `bbolt`, reading disk pages relies on memory-mapped files (`mmap`). Operating system page faults block the underlying OS thread transparently without the Go runtime's knowledge. This blocks Go goroutine scheduling, delays stop-the-world garbage collection pauses, and inflates container memory accounting (Process RSS and cgroup memory limits).
2. **The Durability vs. Performance Dilemma:** In `bbolt`, running with `NoSync: true` can silently serve corrupted or rolled-back data following a kernel writeback error, while running with `NoSync: false` causes synchronous fsync calls on every commit, reducing throughput to single-digit operations per second.

The new `DiskStore` architecture introduces:
- A sequential **Write-Ahead Log (WAL)** using 64-bit monotonic LSNs and immutable segment files with directory fsyncing.
- A **heap file composed of self-describing 4 KiB blocks**, each protected by a 32-byte header with a Castagnoli CRC32C checksum.
- An **out-of-place write strategy** enforcing the **Reuse Rule** (locations holding the newest durable copy of a page are never overwritten) and the **Write-Ahead Rule** (WAL is fsynced through a page's LSN before the page is written to disk).
- A **buddy allocator** over 4 KiB blocks that prefers the lowest available location, enabling automatic tail truncation of the heap file.
- A **fixed-size block pool** of 4 KiB pool blocks allocated once as a single pointer-free byte arena with zero `mmap`, performing direct I/O via `O_DIRECT` on Linux (and `F_NOCACHE` on Darwin) through `unix.Preadv` and `unix.Pwritev`.
- **Non-blocking checkpoints** with ARIES dirty page tracking and WAL segment truncation.
- Full compatibility with `k8s.io/client-go/tools/cache.Indexer`.

### Key Empirical Results (Mixed Realistic Corpus: 10,000 Objects, 10 KB Payloads)

*Measured on Linux 6.6 amd64 with direct I/O enabled and an 8 MiB (2,048-block) block pool in isolated benchmark processes.*

| Architecture | Heap In-Use | Process RSS | Heap File | WAL Size | Total Disk | Write Throughput | Recovery Time | Warm Recompute (10 refs) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **In-Memory Informer** (Status Quo) | 115.70 MB | 176.91 MB | - | - | 0 MB (RAM) | 9,646 op/s | N/A | 11 µs |
| **BBolt Store** (`mmap` + `NoSync`) | 0.65 MB | 154.30 MB | 144.25 MB | 0.00 MB | 144.25 MB | 3,651 op/s | 12.0 ms | 12 µs |
| **DiskStore (Uncompressed)** | 13.54 MB | 45.77 MB | 156.25 MB | 3.65 MB | 159.90 MB | 2,177 op/s | 565.0 ms | 146 µs |
| **DiskStore (zstd)** | **13.73 MB** | **48.11 MB** | **78.12 MB** | 14.50 MB | **92.62 MB** | **2,318 op/s** | **340.0 ms** | **152 µs** |

- **In-Memory Informer Baseline:** The standard in-memory cache retains all objects in RAM, consuming **115.70 MB Go heap** and **176.91 MB Process RSS** for 10,000 objects (~100 MB data).
- **RSS Reduction:** `DiskStore (zstd)` consumes **48.11 MB Process RSS**, achieving a **72.8% reduction compared to In-Memory** (176.91 MB) and a **68.8% reduction compared to BBolt** (154.30 MB) by avoiding kernel page-cache amplification from `mmap`.
- **Heap Footprint:** `DiskStore` holds only index structures and block pool pointers in heap, consuming **13.73 MB Go heap**, an **88.1% reduction** compared to In-Memory.
- **Disk Footprint Reduction by Data Type:**
  - **Configuration text (JSON):** `zstd` reduces on-disk storage by **82.3%** (8.51 MB vs. 47.95 MB uncompressed; Heap file: 4.88 MB vs. 39.06 MB) and doubles write throughput (4,974 op/s vs. 2,549 op/s).
  - **TLS material (x509 PEM):** `zstd` reduces on-disk storage by **66.4%** (16.14 MB vs. 48.01 MB uncompressed; Heap file: 9.77 MB vs. 39.06 MB).
  - **Random bytes:** Incompressible data triggers the 10% threshold rule and stores raw without compression expansion (47.96 MB across all codecs).
  - **Mixed realistic corpus:** `zstd` reduces the physical heap file by **50.0%** (78.12 MB vs. 156.25 MB).
- **Heap File vs. WAL Size Dynamics:** On the mixed corpus, the physical heap file size drops by half with zstd (78.12 MB vs. 156.25 MB uncompressed). The 14.50 MB WAL file reflects the unrolled active segment under the 16 MiB rollover threshold after 3 finished segments (48 MB) were truncated at checkpoint.
- **Zero Mmap Overhead:** Because direct I/O bypasses the operating system page cache and block pool memory is bounded to a fixed arena, container memory accounting remains flat and predictable under load.
- **Fast Startup & Recovery:** The sequential scan in physical block order reconstructs the store state across the mixed corpus in **340 ms**.

---

## Layered Architecture: Engine and Kubernetes Cache Adapter

To maintain separation of concerns and avoid exposing Kubernetes dependencies to low-level storage routines, the implementation is split into two packages under `experiments/diskstore`:

### 1. Core Database Engine (`experiments/diskstore/engine`)

The engine provides a byte-oriented key-value store with crash consistency, bounded memory usage, and no dependencies on `k8s.io/...`:
- **Data abstraction:** All keys and values are processed as raw byte slices (`[]byte`) partitioned across tables.
- **Operations:** Supports `Open`, `Put(table, key, value)`, `Delete(table, key)`, `Get(table, key)`, point-in-time consistent `Scan(table, fn)`, `Flush`, `Sync`, `Checkpoint`, and `Close`.
- **Payload encryption:** If a cipher is configured, encryption and decryption occur inside the engine using the table and key as authenticated additional data.
- **Sticky error state and notifications:** Once an unrecoverable error occurs (such as an fsync failure or page corruption), the engine transitions permanently into a failed state where all subsequent calls return `ErrFailed`. Callers receive asynchronous notification via `Err()` and `Failed() <-chan struct{}`.
- **Failure marker:** Upon entering the failed state, the engine writes a `FAILED` marker file to the storage directory. If a subsequent `Open` encounters this marker, it wipes the directory, reports the wipe via `Wiped() bool`, and initializes a fresh database with a new ID.

### 2. Kubernetes Adapter (`experiments/diskstore/kubecache`)

The adapter implements client-go's `cache.Indexer` on top of the engine:
- **Object serialization:** Handles conversion between `runtime.Object` instances and raw bytes using protobuf or JSON codecs (`ObjectCodec`).
- **Secondary indexes:** Maintains index functions and index tables (`Indexers`, `Indices`) in memory, reconstructing them on startup via `engine.Scan`.
- **ResourceVersion tracking:** Persists the Kubernetes `resourceVersion` and watch bookmarks to a reserved table in the engine.
- **Fail-fast policy:** Holds the unified error policy required to safely back client-go informer caches with persistent storage.

---

## Fail-Fast Error Policy and Trade-offs

### The Problem with Partial Informer Failures

client-go's cache interfaces are designed around in-memory hash maps that assume storage never fails:
- Read methods such as `List() []any` and `ListKeys() []string` provide no error return in their signatures.
- The reflector logs errors from `Add`, `Update`, and `Delete` via `utilruntime.HandleError` but continues watching without retrying the failed cache write.
- Secondary indexing functions in `threadSafeMap` panic when an index function returns an error.

If a disk-backed cache logs an error or returns partial data during a read, the reflector continues processing events while the local cache drifts silently out of sync with the Kubernetes apiserver. This desynchronization can lead to stale routing state, missing endpoints, or incorrect gateway configuration.

### Error Handling Policy

The adapter enforces a single fail-fast policy across all operations:
1. **Mandatory fatal handler:** Construction of `Indexer` requires an `OnFatal func(error)` callback. The provided `DefaultOnFatal` logs the error at error level and exits the process (`os.Exit(1)`).
2. **Unified trigger conditions:** `OnFatal` is invoked (via `sync.Once` to ensure execution exactly once) upon:
   - Any engine error returned from `Put`, `Delete`, `Get`, `Scan`, or `Sync`;
   - Asynchronous engine failure notifications delivered via `engine.Failed()`;
   - Object serialization or deserialization failures;
   - Decryption failures;
   - Index-function errors returned by registered secondary indexers.
3. **No partial results:** Methods without error returns (`List`, `ListKeys`) and methods with error returns (`ByIndex`) discard any accumulated items and return empty results if an error occurs mid-traversal. If the fatal handler does not terminate the process (as in unit test harnesses), subsequent operations continue to return errors or empty results.

### Trade-offs

- **Process restarts vs. silent divergence:** Halting the process when storage fails relies on the pod supervisor (kubelet) to restart the container. The restarted container wipes corrupted state (if marked as failed) and relists all objects from the apiserver. This incurs startup latency and apiserver load during relisting, but prevents controllers from operating on partial or inconsistent state.
- **Simplicity vs. in-flight retry:** The fail-fast model avoids complex in-memory staging queues, retry loops, or multi-version rollback mechanisms in the cache layer.

---

## Architecture and On-Disk Formats

### 1. Write-Ahead Log (WAL)

The write-ahead log records all state changes prior to page modification.

#### Segment File Lifecycle
- Log segments are named strictly by their starting 64-bit LSN, zero-padded to 20 decimal digits (e.g. `00000000000000000001.wal`).
- **Never reuse or recycle segment file names:** Every segment name is unique and monotonically ordered.
- After creating any new segment file, the parent directory is immediately fsynced (`fsync(dir)`).
- Finished segments are closed and become immutable artifacts suitable for remote archiving.
- Segments are truncated (deleted) only when fully covered by a completed checkpoint (i.e. strictly before the checkpoint's redo start LSN).

#### Segment Header (32 bytes)
Every WAL segment starts with a 32-byte header with 8 bytes of zero padding after the version:
```
+---------------+---------------+---------------+---------------------------------------+
|  Magic (4B)   |  Version (4B) | Reserved (8B) |           Database ID (16B)           |
|   "WAL1"      |      0x1      |  0x00 padding |     Random 128-bit store identifier   |
+---------------+---------------+---------------+---------------------------------------+
```

#### Record Format (36 bytes + dynamic payload)
Log records encode operations (`Put = 1`, `Delete = 2`, `Checkpoint = 3`). The record header is aligned on a 4-byte boundary, with explicit magic, format version, operation type, and reserved bytes preceding the 64-bit and 32-bit fields:
```
+-----------+-----------+-----------+---------------+-----------+-------------------+-------------+----------------+-------------+------------+
| Magic(1B) |Format(1B) | Type (1B) | Reserved (1B) |  LSN (8B) | RedoStartLSN (8B) | KeyLen (4B) | PayloadLen (4B)| RVLen (4B)  | CRC32C(4B) |
+-----------+-----------+-----------+---------------+-----------+-------------------+-------------+----------------+-------------+------------+
| Key bytes (KeyLen) ...                    | Payload bytes (PayloadLen) ...        | ResourceVersion bytes (RVLen) ...           |
+-------------------------------------------+---------------------------------------+---------------------------------------------+
```
- Monotonic 64-bit LSNs never reset during the lifetime of the store.
- CRC32C is computed with Castagnoli polynomial over the entire record with the CRC field zeroed.
- Checkpoint records specify the `RedoStartLSN` determining the point from which WAL redo must begin.

---

### 2. Heap File of Self-Describing 4 KiB Blocks

The heap file is organized into discrete 4096-byte blocks.

#### Block Header Layout (32 bytes)
**Every single 4 KiB block** begins with a compact 32-byte header layout:
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
- Usable data area per block: `4096 - 32 = 4064 bytes`.
- The Database ID is not duplicated on individual page blocks (it resides in WAL segment headers and store metadata), saving 32 bytes per 4 KiB block.
- CRC32C is stored in the first 8-byte row and computed over all 4096 bytes with bytes 4–8 zeroed.

#### Slotted Page (1 Block = 4096 Bytes)
Small records share a 1-block slotted page:
- **Header:** Bytes 0–32: `BlockHeader`.
- **Metadata:** Bytes 32–40: `NumSlots (2B)`, `FreeStart (2B)`, `FreeEnd (2B)`, `Flags (2B)`.
- **Slot Directory:** Bytes 40 onwards: array of slots `{ Offset uint16, Length uint16 }`.
- **Stable Slot IDs:** When records are deleted, their slot entry is marked as a tombstone (`Offset = 0, Length = 0`). The slot index remains reserved until reused by a new record.
- **Defragmentation / Compaction:** Active payloads grow downwards from byte 4096. Compaction slides all active payloads to the end of the block and updates slot offsets, maintaining original slot indices without renumbering.
- **Empty Pages:** Emptied pages are written with `NumSlots = 0`. Logical page IDs are never discarded; empty logical pages are recycled first.

#### Multi-Block Page (Power-of-Two Blocks: 2 to 512 Blocks = up to 2 MiB)
Large objects span power-of-two contiguous physical blocks:
- **Every single block** in the run contains the 32-byte `BlockHeader` with `BlockIndex = i`, `NumBlocks = N`, and the page's `LogicalPage` and `LSN`.
- Block 0 stores the record header: `KeyLen (2B)`, `PayloadLen (4B)`, `LSN (8B)`, `Key`.
- Payload bytes stream across the usable payload section (`block[32:4096]`) of blocks `0` through `N-1`.
- Objects larger than 2 MiB are classified as oversize, kept in memory, counted in `OversizeObjectsCount`, and written without failing.

---

### 3. Value Compression and Page Class Selection

To conserve disk space and reduce multi-block power-of-two page allocation overhead, the engine compresses every value, whatever its size, whenever compression helps:

- **Compression Scope:** Only object values are compressed. Object keys, WAL record headers, and physical 4 KiB block headers remain uncompressed.
- **Supported Codecs:**
  - `CodecNone (0x00)`: Value stored raw without compression.
  - `CodecZstd (0x01)`: Value compressed using pure Go `zstd` at its fastest level (`zstd.SpeedFastest`, roughly level 1). zstd is the sole supported compression codec.
  - Codec bytes `0x02` and `0x03` are reserved for future codecs.
- **Evaluation of S2 and Snappy:** During development, S2 and Snappy were evaluated alongside zstd. zstd produced the smallest output for every data type. For example, the WAL, which stores exact compressed bytes, held 3.62 MB for zstd versus 6.46 MB for S2 and 5.85 MB for Snappy on configuration text. Because zstd provided superior compression ratio and comparable throughput across all workloads, S2 and Snappy were dropped to keep the engine minimal with a single well-supported algorithm.
- **On-Disk Value Record Format:**
  - Stored raw (`CodecNone`): `[Codec (1B)][Raw Payload Bytes...]`
  - Stored compressed (`CodecZstd`): `[Codec (1B)][Uncompressed Length uint32 Big-Endian (4B)][Compressed Stream Bytes...]`
- **Store Format Version in `meta.db`:** `meta.db` records a 4-byte `StoreFormatVersion` (version 3) alongside the 16-byte database ID. On `Open`, if `meta.db` is missing the format version (as in version 1 stores written prior to value compression) or contains a mismatched version, `Open` returns an error unless `WithEraseOnError()` is set. When configured with `WithEraseOnError()`, the engine wipes the store via the existing wipe path and reports `Wiped()`. Because the store functions as a cache, starting fresh and relisting ensures data consistency without misreading legacy unversioned payloads.
- **Universal Compression (No Arbitrary Threshold):** Every value is passed through the configured codec regardless of size. This unifies the write path: whether a value lands in a 1-block slotted page or a multi-block page depends entirely on its stored (compressed) size.
- **10% Savings Rule:** If an object's compressed size is not at least about 10% smaller than the raw payload (`compressedLen * 10 <= rawLen * 9`), the value is stored raw with `CodecNone` to avoid compression framing overhead and growth for tiny or incompressible data.
- **Consistency Between Writes and Reads:** Reads must not reject what writes accepted. `compressValue` stores any payload larger than `MaxObjectSize` uncompressed with `CodecNone`, ensuring that large payloads accepted on write are read back without error, while `decompressValue` protects against decompression bombs from untrusted or corrupted inputs.
- **Page Class Selection from Compressed Size:** The page class (1-block slotted page vs. power-of-two multi-block page) is selected using the compressed payload length. An object that is 10 KB uncompressed drops from a 4-block page (16 KiB) to a 1-block slotted page (4 KiB) after compression.
- **Compress Once, Write Same Bytes Twice:** Both the WAL record and heap page store the compressed (and optionally encrypted) payload. This cuts log segment volume in half for large objects and avoids decompressing during WAL redo replay.
- **Ordering with Encryption:** Compression runs before authenticated symmetric encryption (`compress -> encrypt -> toStore`). Ciphertext does not compress; decrypting before decompressing ensures confidentiality.
- **Bound Decompression & Corruption Resistance:** Every compressed record records its 32-bit uncompressed length. The engine rejects any record whose recorded length exceeds `MaxObjectSize` (default 64 MiB) prior to memory allocation or decompressor invocation. After decompression, the engine verifies that the output length matches the recorded length. Length mismatches, truncated byte streams, and unknown codec bytes are treated as corruption, transitioning the engine into the permanent failed state without panicking or allocating large buffers.
- **Pooled Encoders and Decoders:** zstd encoders and decoders are expensive to allocate and are reused via `sync.Pool`. Decoders configure `zstd.WithDecodeAllCapLimit(true)` to enforce bounded memory allocation even on malformed inputs.

---

### 4. Out-Of-Place Writes and Buddy Allocation

#### Storage Invariants
1. **Reuse Rule:** The disk location holding a page's newest *durable* (fsynced) copy must never be overwritten. Older copies become free for reuse only after a newer copy has been fsynced to disk. Blocks written since the last fsync are tracked in memory and may be freed immediately if superseded.
2. **Write-Ahead Rule:** Before writing any page with LSN `L` to the heap file, the WAL must be fsynced through `L`.

#### Buddy Allocator & Tail File Truncation
- Manages block ranges in powers-of-two (order 0 = 1 block, order 9 = 512 blocks).
- Always allocates the **lowest available free location** across all eligible orders, packing active pages towards the beginning of the file.
- When the tail of the heap file empties, `TruncateTail()` invokes `ftruncate()` to shrink the physical file.

---

### 5. Block Pool and Direct I/O Engine

- **Fixed-Size Arena:** A single contiguous `[]byte` slice aligned to 4096 bytes without using `mmap`. Because Go slices of primitive types contain no pointers, the Go runtime garbage collector skips scanning the arena.
- **Direct I/O:**
  - On Linux: opened with `O_DIRECT`. Reads and writes use `unix.Preadv` and `unix.Pwritev` via `SyscallConn.Control()`, ensuring zero kernel page-cache copying.
  - On macOS: opened with `F_NOCACHE` via `unix.FcntlInt` for test execution.
- **Non-Adjacent Pool Blocks:** Multi-block pages in memory can occupy non-adjacent pool blocks. `DirectIO.Writev` and `DirectIO.Readv` transfer all pool blocks in a single vectored system call.
- **Background Cleaner:** A background goroutine flushes unpinned dirty pages under the write-ahead rule to keep clean pool blocks available for foreground allocations.

---

## Crash Consistency and Recovery Algorithm

```
                           +--------------------------+
                           |  Crash Recovery Trigger  |
                           +--------------------------+
                                        |
                                        v
                           +--------------------------+
                           |  Physical 4 KiB Block    |
                           |  Scan of Heap File       |
                           +--------------------------+
                                        |
                  +---------------------+---------------------+
                  |                                           |
                  v                                           v
       [Valid Header & CRC32C]                 [Invalid Magic/Ver or Corrupt]
                  |                                           |
                  v                                           v
       +-----------------------+                         (Discarded)
       | Group Blocks into     |
       | Candidate Page Runs   |
       +-----------------------+
                  |
        +---------+---------+
        |                   |
        v                   v
   [Complete Page]      [Torn / Missing Block]
        |                   |
        v                   v
   (Keep Candidate)     (Ignore Candidate, Fallback)
        |
        v
   +---------------------------------------+
   | For each Logical Page:                |
   | Select Candidate with Highest LSN     |
   +---------------------------------------+
        |
        v
   +---------------------------------------+
   | Reconstruct Buddy Allocator Bitmap    |
   | and In-Memory Key Index               |
   +---------------------------------------+
        |
        v
   +---------------------------------------+
   | Scan WAL for Last Checkpoint Record   |
   | (Determine RedoStartLSN)              |
   +---------------------------------------+
        |
        v
   +---------------------------------------+
   | Replay WAL from RedoStartLSN          |
   | Apply only if Record LSN > Page LSN   |
   +---------------------------------------+
        |
        v
   +---------------------------------------+
   | Report Last Recovered ResourceVersion |
   +---------------------------------------+
```

### Recovery Steps
1. **Physical Block Scan:** Reads the heap file in sequential 256 KiB chunks. For every 4 KiB block, validates `BlockMagic` (0x47), format version (1), and Castagnoli CRC32C.
2. **Candidate Filtering:** Validates that candidate pages form complete buddy runs of `NumBlocks` with matching `LogicalPage`, `LSN`, and sequential `BlockIndex` from `0` to `NumBlocks - 1`. If any block in a run is missing, torn, or invalid, the candidate is discarded, and recovery falls back to the previous durable copy.
3. **Winner Selection:** For each logical page number, the candidate copy with the maximum LSN is chosen.
4. **Index Rebuilding:**
   - Slotted pages are inspected: active slots populate the key index `(logicalPage, slot, LSN)`, always selecting the highest LSN across pages, and empty pages (`NumSlots = 0`) are registered in `emptyLogicalPages`.
   - Multi-block pages populate slot 0.
   - Allocated blocks are marked in the buddy allocator.
5. **WAL Redo Replay:**
   - Identifies the last checkpoint record to find `RedoStartLSN`.
   - Iterates records from `RedoStartLSN` to EOF. Replay stops at the first record with a corrupted CRC or non-contiguous LSN, or advances across segments if a newer segment starts at the expected LSN.
   - For each record, if `record.LSN > page.LSN`, the modification is applied directly to the page buffer and persisted to disk.
6. **Watch Resumption:** The highest recovered `ResourceVersion` is reported so reflectors can resume watches without re-listing.

---

## Threat Model: Forged Block Headers

### The Threat
An informer object contains untrusted user data. A malicious user could submit a Kubernetes ConfigMap or Secret whose data payload contains bytes crafted to look like a valid block header:
- Valid `BlockMagic` (`0x47`) and version `1`
- A forged target `LogicalPage`
- An artificially high `LSN` (e.g. `999999`)
- A valid Castagnoli CRC32C checksum

If a recovery scanner were tricked into accepting this payload as a valid block header, the malicious object could overwrite or resurrect arbitrary database pages after a crash.

### Architectural Guarantee
Recovery never trusts bytes that object payloads control:
1. **Strict 4 KiB Block Boundary Alignment:** The recovery engine only parses block headers at exact 4096-byte boundaries (`offset % 4096 == 0`).
2. **Per-Block Header Isolation:** In `DiskStore`, **every 4096-byte block on disk** starts with the store's 32-byte `BlockHeader` written by the storage engine, validated with a Castagnoli CRC32C checksum.
3. **Payload Containment:**
   - In slotted pages: payload bytes are stored inside slot records within `block[40:4096]`.
   - In multi-block pages: payload bytes are partitioned across `block[32:4096]`.
   - **Payload bytes are never written at byte offset 0 of any 4 KiB block on disk.**
4. **Empirical Verification:** The test `TestRecovery_ForgedHeaders` constructs multi-block payloads containing valid forged block headers with high LSNs placed at every offset. Upon crash recovery, the store correctly recognizes genuine headers at block boundaries, verifies the genuine payload, and rejects any forged header.

---

## Comparison with BBolt and In-Memory Informer

### Detailed Benchmark Results Across Realistic Workloads

*Measured on Linux 6.6 amd64 with direct I/O enabled and an 8 MiB (2,048-block) block pool in isolated benchmark processes.*

#### 1. Configuration Text (JSON) (2,500 objects, ~10 KB each)

```
====================================================================================================================================================================
COMPARATIVE BENCHMARK: Configuration Text (JSON) (2500 objects, ~10 KB each)
====================================================================================================================================================================
Storage Engine           | Heap In-Use  | Process RSS  | Heap File    | WAL Size   | Total Disk   | Write Time   | Write Thruput  | Recovery  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
In-Memory Informer       |      28.52 MB |      61.07 MB |          - |        - | 0 MB (RAM) |       0.28 s |       8788 op/s |          -
BBolt (mmap + NoSync)    |       0.23 MB |      51.80 MB |   48.09 MB |  0.00 MB |   48.09 MB |       0.65 s |       3830 op/s |   12.00 ms
DiskStore (None)         |      10.02 MB |      37.29 MB |   39.06 MB |  8.88 MB |   47.95 MB |       0.98 s |       2549 op/s |  138.00 ms
DiskStore (zstd)         |       9.82 MB |      33.60 MB |    4.88 MB |  3.62 MB |    8.51 MB |       0.50 s |       4974 op/s |   40.00 ms
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
Recompute Latency Comparison:
  In-Memory Informer     :         0 refs =   0.00 µs |   10 refs =   7.00 µs | 1000 refs =   253.00 µs
  BBolt (mmap + NoSync)   (Cold): 0 refs =   8.00 µs |   10 refs = 171.00 µs | 1000 refs = 19007.00 µs
  BBolt (mmap + NoSync)   (Warm): 0 refs =   0.00 µs |   10 refs =   7.00 µs | 1000 refs =   540.00 µs
  DiskStore (None)        (Cold): 0 refs =   0.00 µs |   10 refs = 2708.00 µs | 1000 refs = 273908.00 µs
  DiskStore (None)        (Warm): 0 refs =   0.00 µs |   10 refs =  86.00 µs | 1000 refs = 262657.00 µs
  DiskStore (zstd)        (Cold): 0 refs =   0.00 µs |   10 refs =  261.00 µs | 1000 refs = 15659.00 µs
  DiskStore (zstd)        (Warm): 0 refs =   0.00 µs |   10 refs =  151.00 µs | 1000 refs = 14490.00 µs
====================================================================================================================================================================
```

#### 2. TLS Material (x509 PEM) (2,500 objects, ~10 KB each)

```
====================================================================================================================================================================
COMPARATIVE BENCHMARK: TLS Material (x509 PEM) (2500 objects, ~10 KB each)
====================================================================================================================================================================
Storage Engine           | Heap In-Use  | Process RSS  | Heap File    | WAL Size   | Total Disk   | Write Time   | Write Thruput  | Recovery  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
In-Memory Informer       |      30.02 MB |      60.59 MB |          - |        - | 0 MB (RAM) |       0.43 s |       5848 op/s |          -
BBolt (mmap + NoSync)    |       0.30 MB |      52.27 MB |   48.05 MB |  0.00 MB |   48.05 MB |       0.76 s |       3304 op/s |   12.00 ms
DiskStore (None)         |       9.90 MB |      37.63 MB |   39.06 MB |  8.95 MB |   48.01 MB |       1.11 s |       2252 op/s |  145.00 ms
DiskStore (zstd)         |      10.09 MB |      39.78 MB |    9.77 MB |  6.38 MB |   16.14 MB |       0.81 s |       3087 op/s |   55.00 ms
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
Recompute Latency Comparison:
  In-Memory Informer     :         0 refs =   0.00 µs |   10 refs =  11.00 µs | 1000 refs =   259.00 µs
  BBolt (mmap + NoSync)   (Cold): 0 refs =   7.00 µs |   10 refs = 162.00 µs | 1000 refs = 20114.00 µs
  BBolt (mmap + NoSync)   (Warm): 0 refs =   0.00 µs |   10 refs =   7.00 µs | 1000 refs =   618.00 µs
  DiskStore (None)        (Cold): 0 refs =   0.00 µs |   10 refs = 2790.00 µs | 1000 refs = 265489.00 µs
  DiskStore (None)        (Warm): 0 refs =   0.00 µs |   10 refs = 118.00 µs | 1000 refs = 264233.00 µs
  DiskStore (zstd)        (Cold): 0 refs =   0.00 µs |   10 refs = 2153.00 µs | 1000 refs = 156466.00 µs
  DiskStore (zstd)        (Warm): 0 refs =   0.00 µs |   10 refs =  206.00 µs | 1000 refs =  23203.00 µs
====================================================================================================================================================================
```

#### 3. Random Incompressible Bytes (2,500 objects, ~10 KB each)

```
====================================================================================================================================================================
COMPARATIVE BENCHMARK: Random Incompressible Bytes (2500 objects, ~10 KB each)
====================================================================================================================================================================
Storage Engine           | Heap In-Use  | Process RSS  | Heap File    | WAL Size   | Total Disk   | Write Time   | Write Thruput  | Recovery  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
In-Memory Informer       |      27.43 MB |      43.07 MB |          - |        - | 0 MB (RAM) |       0.06 s |      42401 op/s |          -
BBolt (mmap + NoSync)    |       0.22 MB |      51.82 MB |   48.06 MB |  0.00 MB |   48.06 MB |       0.36 s |       7034 op/s |   12.00 ms
DiskStore (None)         |       9.47 MB |      37.33 MB |   39.06 MB |  8.90 MB |   47.96 MB |       0.66 s |       3785 op/s |  145.00 ms
DiskStore (zstd)         |       9.48 MB |      40.71 MB |   39.06 MB |  8.90 MB |   47.96 MB |       0.69 s |       3634 op/s |  162.00 ms
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
Recompute Latency Comparison:
  In-Memory Informer     :         0 refs =   0.00 µs |   10 refs =  10.00 µs | 1000 refs =   234.00 µs
  BBolt (mmap + NoSync)   (Cold): 0 refs =   8.00 µs |   10 refs = 301.00 µs | 1000 refs = 19433.00 µs
  BBolt (mmap + NoSync)   (Warm): 0 refs =   0.00 µs |   10 refs =   6.00 µs | 1000 refs =   548.00 µs
  DiskStore (None)        (Cold): 0 refs =   0.00 µs |   10 refs = 2803.00 µs | 1000 refs = 269474.00 µs
  DiskStore (None)        (Warm): 0 refs =   0.00 µs |   10 refs = 132.00 µs | 1000 refs = 264048.00 µs
  DiskStore (zstd)        (Cold): 0 refs =   0.00 µs |   10 refs = 2636.00 µs | 1000 refs = 340338.00 µs
  DiskStore (zstd)        (Warm): 0 refs =   0.00 µs |   10 refs =   81.00 µs | 1000 refs = 301167.00 µs
====================================================================================================================================================================
```

#### 4. Mixed Realistic Corpus (10,000 objects, ~100 MB data)

```
====================================================================================================================================================================
COMPARATIVE BENCHMARK: Mixed Realistic Corpus (10000 objects, ~10 KB each)
====================================================================================================================================================================
Storage Engine           | Heap In-Use  | Process RSS  | Heap File    | WAL Size   | Total Disk   | Write Time   | Write Thruput  | Recovery  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
In-Memory Informer       |     115.70 MB |     176.91 MB |          - |        - | 0 MB (RAM) |       1.04 s |       9646 op/s |          -
BBolt (mmap + NoSync)    |       0.65 MB |     154.30 MB |  144.25 MB |  0.00 MB |  144.25 MB |       2.74 s |       3651 op/s |   12.00 ms
DiskStore (None)         |      13.54 MB |      45.77 MB |  156.25 MB |  3.65 MB |  159.90 MB |       4.59 s |       2177 op/s |  565.00 ms
DiskStore (zstd)         |      13.73 MB |      48.11 MB |   78.12 MB | 14.50 MB |   92.62 MB |       4.31 s |       2318 op/s |  340.00 ms
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
Recompute Latency Comparison:
  In-Memory Informer     :         0 refs =   0.00 µs |   10 refs =  11.00 µs | 1000 refs =   306.00 µs
  BBolt (mmap + NoSync)   (Cold): 0 refs =   3.00 µs |   10 refs = 216.00 µs | 1000 refs = 19329.00 µs
  BBolt (mmap + NoSync)   (Warm): 0 refs =   0.00 µs |   10 refs =  12.00 µs | 1000 refs =   590.00 µs
  DiskStore (None)        (Cold): 0 refs =   0.00 µs |   10 refs = 5149.00 µs | 1000 refs = 410326.00 µs
  DiskStore (None)        (Warm): 0 refs =   0.00 µs |   10 refs = 146.00 µs | 1000 refs = 396606.00 µs
  DiskStore (zstd)        (Cold): 0 refs =   0.00 µs |   10 refs = 3477.00 µs | 1000 refs = 354856.00 µs
  DiskStore (zstd)        (Warm): 0 refs =   0.00 µs |   10 refs = 152.00 µs | 1000 refs =  18088.00 µs
====================================================================================================================================================================
```

### Analysis of Trade-offs

1. **Why Compression Accelerates Write Throughput:**
   - Uncompressed storage writes 4 physical blocks for every 10 KB object. For 10,000 objects, that totals 40,000 blocks written through an 8 MiB (2,048-block) block pool. The block pool experiences continuous pool block eviction and dirty page writeback.
   - The engine issues one write call per WAL block, and one write call per page during flushes.
   - When values compress, objects fit within single-block slotted pages or smaller multi-block allocations (e.g. 1 or 2 blocks). The reduced working set fits within the block pool without continuous eviction churn. Fewer pages and fewer blocks reduce the number of write system calls, which accelerates write throughput.
   - Batched writes would raise the uncompressed baseline; that architectural enhancement is tracked separately.

2. **Heap Usage and Memory Isolation:**
   - When measured in isolated processes, the In-Memory Informer retains the full dataset in RAM, consuming **115.70 MB Go heap** and **176.91 MB Process RSS** for 10,000 objects.
   - `DiskStore` holds only index keys and block pool descriptors in RAM, keeping Go heap at **13.73 MB** (an 88.1% reduction) and Process RSS at **48.11 MB** (a 72.8% reduction compared to In-Memory, and a 68.8% reduction compared to BBolt's 154.30 MB).
   - Closing the engine signals its `Closed()` channel, which terminates the adapter's failure-watch goroutine. This releases references to the engine and its block-pool arena, preventing memory retention across engine lifecycles.

3. **Codec Selection: zstd as Default vs. Evaluation of S2 and Snappy:**
   - **Configuration Text (JSON):** `zstd` produces the smallest disk footprint (**8.51 MB**, an 82.3% reduction; Heap file: **4.88 MB** vs. **39.06 MB**). S2 (**16.23 MB**) and Snappy (**15.62 MB**) required almost double the storage. Because the WAL records exact compressed payloads, zstd log stream volume was **3.62 MB**, compared to **6.46 MB** for S2 and **5.85 MB** for Snappy.
   - **TLS Material (x509 PEM):** `zstd` achieved the highest compression ratio (**16.14 MB**, a 66.4% reduction; Heap file: **9.77 MB** vs. **39.06 MB**), outperforming S2 (**17.83 MB**) and Snappy (**18.35 MB**).
   - **Incompressible Random Bytes:** When compressed output fails the 10% savings threshold, the engine falls back to raw storage (`CodecNone`), consuming identical disk space (**47.96 MB**) with identical write throughput (~3,600–3,700 op/s).
   - **Rationale for Dropping S2 and Snappy:** Because zstd achieved superior compression ratios on all data types with fast execution speeds, S2 and Snappy added unnecessary code surface and format variants without operational benefit. Only zstd is supported for compression.

4. **Heap File vs. WAL Size Dynamics:**
   - Across the 10,000 mixed corpus, physical heap file storage drops by half with zstd (**78.12 MB**, down from **156.25 MB** uncompressed).
   - The total directory size on disk includes both the heap file and remaining WAL segments. The WAL file size of **14.50 MB** reflects the active segment under the 16 MiB rollover threshold after earlier finished segments were deleted upon checkpointing.

5. **Process RSS & Container Memory Limits:**
   - `BBolt` resident set size reaches **154.30 MB** on the 10,000 mixed object workload because operating system page caching retains mmap pages in the container cgroup.
   - `DiskStore` caps Process RSS at **48.11 MB** by using direct I/O and a fixed 8 MiB block pool arena, avoiding kernel page-cache amplification.

6. **Crash Recovery Time:**
   - On compressible configuration text, `DiskStore (zstd)` recovers in **40 ms**, compared to **138 ms** uncompressed. On the 10,000 mixed corpus, recovery completes in **340 ms**, compared to **565 ms** uncompressed. Replaying WAL redo records copies compressed bytes directly into pages without decompression, minimizing recovery latency.

7. **Broad Read Isolation and Locking Trade-offs (`List` vs Concurrent Writers):**
   - **Point-in-Time Consistency:** `DiskStore.List(tableName)` acquires `s.writerMu.RLock()` for the duration of the broad table read and object decoding. This provides point-in-time consistency across the table: concurrent writes (`Put`) or deletions (`Delete`) cannot mutate page contents, renumber slots during compaction, or modify the key index while objects are being retrieved and decoded.
   - **Scope and Trade-off Analysis:** Because `writerMu` is store-wide, holding `writerMu.RLock()` stalls writes to every table for the duration of a `List` while all objects in the table are iterated and decoded into memory. An alternative architecture would provide non-blocking concurrency via per-page versioning or multi-version concurrency control (MVCC); however, MVCC introduces additional memory overhead, garbage collection complexity, and page table churn. The trade-off is that writes stall for the duration of a `List`, in exchange for a consistent view without per-page versioning.
   - **Alignment with Informer Access Patterns:** GARI consumes these caches through informer event handlers and doesn't call `List` on them, so broad reads mostly happen at startup and relist. Other controllers may differ in their access patterns, so workloads that frequently invoke `List` concurrently with active write streams would experience write stalls under this locking model.

8. **Universal Value Compression: Small Objects & Realistic Corpus Evaluation:**
   - **Background:** Previously, the engine compressed values only if they exceeded `DefaultCompressionThreshold` (4000 bytes, matching the 1-block slotted page capacity). However, most Kubernetes objects in informer caches are smaller than 4000 bytes once `managedFields` are stripped. Removing the threshold and passing every value through the configured codec (`zstd`) unifies the write path. Values whose compressed form is not at least about 10% smaller than the raw payload (`compressedLen * 10 <= rawLen * 9`) are stored raw with `CodecNone`, protecting incompressible or tiny inputs from expanding.
   - **Evaluation Environment:**
     - Machine: AMD EPYC 9B14 (60 vCPUs), Linux 6.6 amd64
     - Go Version: go1.27.3 linux/amd64
     - Corpus: 10,000 objects built from real Kubernetes objects: Gateway API conformance manifests (Gateways, HTTPRoutes with status, Services, Policies), EndpointSlices with 12 endpoints, Secrets with real x509 certificate chains, random base64 Secrets, and ConfigMaps (average 1,911 B per object, 18.22 MB raw JSON).

   - **Isolated Compression CPU Cost (`compressValue` Benchmark):**
     Measuring `compressValue` alone without storage or I/O overhead:

     | Object / Size | Raw Size | Stored Codec | `compressValue` Latency | Allocs | Throughput |
     | :--- | :--- | :--- | :--- | :--- | :--- |
     | **HTTPRoute** | 1,563 B | `CodecZstd` (~470 B) | 8,598 ns/op | 2 allocs/op | 181.8 MB/s |
     | **EndpointSlice** | 3,737 B | `CodecZstd` (~542 B) | 10,489 ns/op | 2 allocs/op | 356.3 MB/s |
     | **TLSSecret (x509 PEM chain)** | 2,595 B | `CodecZstd` (~1,588 B) | 13,400 ns/op | 2 allocs/op | 195.3 MB/s |
     | **RandomSecret (base64)** | 3,963 B | `CodecNone` (fallback) | 5,186 ns/op | 3 allocs/op | 764.2 MB/s |
     | **ConfigMap** | 691 B | `CodecZstd` (~444 B) | 6,268 ns/op | 2 allocs/op | 110.2 MB/s |
     | **100 B (Compressible)** | 100 B | `CodecZstd` (86 B) | 3,630 ns/op | 2 allocs/op | 27.6 MB/s |
     | **100 B (Incompressible)** | 100 B | `CodecNone` (fallback) | 634 ns/op | 3 allocs/op | 157.8 MB/s |
     | **500 B (Compressible)** | 500 B | `CodecZstd` (89 B) | 3,915 ns/op | 2 allocs/op | 127.7 MB/s |
     | **1 KB (Compressible)** | 1,024 B | `CodecZstd` (89 B) | 3,551 ns/op | 2 allocs/op | 288.4 MB/s |
     | **4 KB (Compressible)** | 4,096 B | `CodecZstd` (88 B) | 5,104 ns/op | 2 allocs/op | 802.5 MB/s |

   - **Put Micro-benchmarks on Corpus Objects and Fixed Sizes:**
     Latency (`ns/op`) and allocations (`allocs/op`) of `Engine.Put`, measured by overwriting a fixed keyset in a warmed-up store to isolate CPU write cost without store-growth or direct I/O flush artifacts:

     | Benchmark Case | Before (Threshold = 4000 B) | After (Universal Compression) | Change |
     | :--- | :--- | :--- | :--- |
     | **Corpus: HTTPRoute (1.5 KB)** | 1,589 ns/op (5 allocs/op) | 8,973 ns/op (6 allocs/op) | +7,384 ns/op (matches ~8.6 µs `compressValue`) |
     | **Corpus: EndpointSlice (3.7 KB)** | 3,283 ns/op (9 allocs/op) | 10,555 ns/op (6 allocs/op) | +7,272 ns/op (matches ~10.5 µs `compressValue`) |
     | **Corpus: TLSSecret (2.6 KB)** | 2,755 ns/op (9 allocs/op) | 14,272 ns/op (6 allocs/op) | +11,517 ns/op (matches ~13.4 µs `compressValue`) |
     | **Corpus: RandomSecret (4.0 KB)** | 3,606 ns/op (9 allocs/op) | 6,368 ns/op (11 allocs/op) | +2,762 ns/op (matches ~5.2 µs raw fallback) |
     | **Corpus: ConfigMap (0.7 KB)** | 1,256 ns/op (5 allocs/op) | 7,773 ns/op (6 allocs/op) | +6,517 ns/op (matches ~6.3 µs `compressValue`) |
     | **Size: 100 B Compressible** | 1,139 ns/op (5 allocs/op) | 4,459 ns/op (6 allocs/op) | +291% latency (+3,320 ns) |
     | **Size: 100 B Incompressible** | 1,127 ns/op (5 allocs/op) | 1,840 ns/op (7 allocs/op) | +63% latency (+713 ns, 10% rule fallback) |
     | **Size: 500 B Compressible** | 1,204 ns/op (5 allocs/op) | 4,588 ns/op (6 allocs/op) | +281% latency (+3,384 ns) |
     | **Size: 500 B Incompressible** | 1,171 ns/op (5 allocs/op) | 2,218 ns/op (7 allocs/op) | +89% latency (+1,047 ns, 10% rule fallback) |
     | **Size: 1 KB Compressible** | 1,369 ns/op (5 allocs/op) | 4,874 ns/op (6 allocs/op) | +256% latency (+3,505 ns) |
     | **Size: 1 KB Incompressible** | 1,324 ns/op (5 allocs/op) | 2,785 ns/op (7 allocs/op) | +110% latency (+1,461 ns, 10% rule fallback) |
     | **Size: 4 KB Compressible** | 5,455 ns/op (6 allocs/op) | 5,436 ns/op (6 allocs/op) | -0.3% latency (already compressed under old threshold) |
     | **Size: 4 KB Incompressible** | 8,946 ns/op (15 allocs/op) | 9,195 ns/op (15 allocs/op) | +2.8% latency (already attempted under old threshold) |

   - **Realistic Corpus Heap-File and Disk Footprint (10,000 objects, 18.22 MB raw JSON):**

     | Metric | Before (Threshold = 4000 B) | After (Universal Compression) | Change |
     | :--- | :--- | :--- | :--- |
     | **Heap File (`heap.db`)** | 21.91 MB (22,978,560 B) | 10.46 MB (10,973,184 B) | **-52.2%** (-12.01 MB) |
     | **WAL Total Size** | 18.78 MB | 9.56 MB | **-49.1%** (-9.22 MB) |
     | **Total On-Disk Footprint** | 40.69 MB | 20.02 MB | **-50.8%** (-20.67 MB) |
     | **Write Stream Duration** | 50.2 ms (199,200 op/s) | 112.5 ms (88,900 op/s) | +62.3 ms (+124% CPU time, ~6.2 µs/write) |
     | **Slotted Pages Allocated** | 5,610 pages | 2,679 pages | **-52.2%** (-2,931 pages) |
     | **Average Slotted Page Density** | 1.78 records/page | 3.73 records/page | **+110%** (+1.95 records/page) |

   - **Trade-off Analysis:**
     1. **Disk Space vs. CPU Time:** Compressing every value reduces heap-file size by 52.2% and WAL size by 49.1% on the realistic 1–4 KB corpus, with higher write stream duration (112.5 ms vs 50.2 ms, or 11.2 µs vs 5.0 µs per write). The delta (~6.2 µs per write) corresponds to the CPU time spent in `compressValue`.
     2. **Small Objects Pay Compression Overhead:** For tiny payloads (such as 100 B), compression adds ~3.3 µs per write (+291% latency) for little space benefit. When payloads cannot compress by at least 10%, the 10% savings rule falls back to raw storage, but still incurs ~0.7 µs of compression attempt overhead.
     3. **Slotted Page Density and Block Pool Residency:** On the 10,000-object corpus, compression increases average record density from 1.78 to 3.73 records per slotted page, reducing allocated slotted pages from 5,610 to 2,679 (-52.2%). In an engine configured with the default 4,096-block arena (`DefaultBlockPoolBlocks = 4096`), all 2,679 compressed slotted pages reside simultaneously in the block pool, whereas the 5,610 uncompressed pages exceed the 4,096-block capacity during ingestion.
     4. **No New Threshold Needed:** The 10% savings rule prevents incompressible or tiny values from expanding on disk without introducing an arbitrary threshold.

---

## Conclusion

The `DiskStore` prototype proves that a write-ahead log combined with a self-describing 4 KiB block heap file, value compression, and fixed-size direct I/O block pool successfully resolves the `mmap` and durability flaws of `bbolt`. It provides:
- **82.3% lower disk usage** on configuration text (JSON) and **66.4% lower disk usage** on TLS material with zstd value compression.
- **72.8% lower memory footprint (RSS)** than In-Memory Informer and **68.8% lower RSS** than BBolt on mixed realistic workloads.
- **2x higher write throughput** on configuration text through reduced block pool eviction churn.
- **Strict crash consistency** with out-of-place writes and the Reuse Rule.
- **Automatic detection and wipe of legacy unversioned stores** via `meta.db` store format versioning.
- **Resilience against untrusted payload forgery and corrupt decompression inputs**.
- **Full `cache.Indexer` conformance**.
