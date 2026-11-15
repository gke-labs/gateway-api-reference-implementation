# Informer Storage Engine Benchmarks: DiskStore vs BBolt vs In-Memory

This document records comparative benchmark measurements between the in-memory Informer, BBolt (`experiments/bboltcache`), and DiskStore / kubecache (`experiments/diskstore`), gathered on a single machine using shared harnesses.

## Environment

- **Date:** 2026-11-10
- **Commit:** commit 17a3ca2 plus this change
- **Machine:** AMD EPYC 9B14 (60 vCPUs, 235 GiB RAM, Linux 6.12.110+ x86_64)
- **Go Version:** `go1.27.3 linux/amd64`

---

## 1. Watch Ingestion Comparison (`TestWatchMemoryComparison`)

### Methodology
Evaluates streaming watch event ingestion of 10 KB ConfigMaps across three engines run in isolated worker subprocesses:
- **Stock Informer:** `client-go` `tools/cache.NewInformerWithOptions` (in-memory).
- **bbolt WatchLoop:** `bboltcache.BBoltIndexer` backed by bbolt (`NoSync: true`, `NoFreelistSync: true`, hybrid codec) driven by `WatchLoop`.
- **kubecache WatchLoop:** `kubecache.Indexer` backed by `engine.Open` (zstd compression, 8 MiB pool, hybrid codec) driven by `WatchLoop`.

### Results

| Watch Pipeline | Objects | Peak Heap | Steady Heap | Steady RSS | Bytes/Obj | Ingestion Rate | Disk Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Stock Informer | 1,000 | 20.9 MB | 10.9 MB | 55.0 MB | 11,408 B | 7,723 op/s | - |
| bbolt WatchLoop | 1,000 | 6.0 MB | 0.1 MB | 51.2 MB | 90 B | 4,962 op/s | 16.0 MB |
| kubecache WatchLoop | 1,000 | 35.6 MB | 12.5 MB | 62.9 MB | 13,080 B | 6,875 op/s | 3.4 MB |
| Stock Informer | 10,000 | 186.6 MB | 108.5 MB | 221.8 MB | 11,380 B | 7,385 op/s | - |
| bbolt WatchLoop | 10,000 | 10.2 MB | 0.5 MB | 171.7 MB | 49 B | 5,578 op/s | 144.2 MB |
| kubecache WatchLoop | 10,000 | 45.4 MB | 15.5 MB | 78.2 MB | 1,625 B | 8,590 op/s | 33.9 MB |
| Stock Informer | 50,000 | 905.7 MB | 541.4 MB | 957.4 MB | 11,353 B | 8,272 op/s | - |
| bbolt WatchLoop | 50,000 | 12.9 MB | 1.4 MB | 180.2 MB | 30 B | 5,886 op/s | 641.1 MB |
| kubecache WatchLoop | 50,000 | 72.1 MB | 27.4 MB | 107.1 MB | 574 B | 8,301 op/s | 105.1 MB |

---

## 2. Storage & Recompute Measurement Suite (`TestDiskStore_Versus_BBolt_MeasurementSuite`)

### Methodology
Evaluates isolated worker subprocesses across four 10 KB object corpora:
1. **Config Text (JSON):** 2,500 objects (~24.4 MB raw)
2. **TLS Material (PEM):** 2,500 objects (~24.4 MB raw)
3. **Random Incompressible Bytes:** 2,500 objects (~24.4 MB raw)
4. **Mixed Realistic Corpus:** 10,000 objects (~97.7 MB raw)

Engines evaluated:
- **In-Memory Informer:** Standard `tools/cache.Indexer`.
- **BBolt (`mmap` + `NoSync`):** `bboltcache.BBoltIndexer` with ephemeral AES-GCM encryption.
- **DiskStore (None):** Uncompressed DiskStore with default 8 MiB block pool (2,048 blocks).
- **DiskStore (zstd):** Zstd-compressed DiskStore with default 8 MiB block pool (2,048 blocks).
- **DiskStore (None, 64 MB pool):** Uncompressed DiskStore with 64 MiB block pool (16,384 blocks) sized to retain the 1,000-object working set in memory.

### Storage, Memory & Write Performance

| Corpus | Storage Engine | Heap In-Use | Process RSS | Heap File | WAL Size | Total Disk | Write Throughput | Recovery |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config Text (2.5k)** | In-Memory Informer | 28.64 MB | 80.77 MB | - | - | 0 MB (RAM) | 8,529 op/s | - |
| | BBolt (mmap + NoSync) | 0.24 MB | 72.47 MB | 48.07 MB | 0.00 MB | 48.07 MB | 4,083 op/s | 4.8 ms |
| | DiskStore (None) | 14.27 MB | 65.41 MB | 39.81 MB | 8.87 MB | 48.68 MB | 5,866 op/s | 170 ms |
| | DiskStore (zstd) | 14.24 MB | 67.64 MB | 4.89 MB | 3.61 MB | 8.50 MB | 6,851 op/s | 43 ms |
| | DiskStore (None, 64 MB pool) | 73.59 MB | 148.55 MB | 39.08 MB | 8.86 MB | 47.94 MB | 6,605 op/s | 166 ms |
| **TLS Material (2.5k)** | In-Memory Informer | 30.12 MB | 81.50 MB | - | - | 0 MB (RAM) | 5,715 op/s | - |
| | BBolt (mmap + NoSync) | 0.30 MB | 74.99 MB | 48.06 MB | 0.00 MB | 48.06 MB | 3,253 op/s | 3.4 ms |
| | DiskStore (None) | 14.25 MB | 67.65 MB | 39.81 MB | 8.93 MB | 48.75 MB | 4,511 op/s | 161 ms |
| | DiskStore (zstd) | 14.46 MB | 70.06 MB | 9.77 MB | 6.38 MB | 16.15 MB | 4,356 op/s | 58 ms |
| | DiskStore (None, 64 MB pool) | 72.98 MB | 150.97 MB | 39.08 MB | 8.92 MB | 48.00 MB | 4,524 op/s | 166 ms |
| **Random Bytes (2.5k)** | In-Memory Informer | 27.34 MB | 61.66 MB | - | - | 0 MB (RAM) | 42,162 op/s | - |
| | BBolt (mmap + NoSync) | 0.24 MB | 70.72 MB | 48.06 MB | 0.00 MB | 48.06 MB | 7,658 op/s | 3.2 ms |
| | DiskStore (None) | 13.38 MB | 66.28 MB | 39.81 MB | 8.89 MB | 48.70 MB | 13,767 op/s | 159 ms |
| | DiskStore (zstd) | 13.45 MB | 68.90 MB | 39.81 MB | 8.89 MB | 48.70 MB | 11,136 op/s | 155 ms |
| | DiskStore (None, 64 MB pool) | 69.76 MB | 149.74 MB | 39.08 MB | 8.88 MB | 47.95 MB | 14,196 op/s | 347 ms |
| **Mixed Corpus (10k)** | In-Memory Informer | 115.98 MB | 207.12 MB | - | - | 0 MB (RAM) | 9,199 op/s | - |
| | BBolt (mmap + NoSync) | 0.72 MB | 175.63 MB | 144.25 MB | 0.00 MB | 144.25 MB | 4,023 op/s | 14 ms |
| | DiskStore (None) | 17.82 MB | 75.84 MB | 157.81 MB | 3.55 MB | 161.36 MB | 5,603 op/s | 538 ms |
| | DiskStore (zstd) | 17.91 MB | 78.53 MB | 121.93 MB | 14.46 MB | 136.39 MB | 5,450 op/s | 379 ms |
| | DiskStore (None, 64 MB pool) | 76.28 MB | 182.09 MB | 159.08 MB | 3.53 MB | 162.61 MB | 4,699 op/s | 524 ms |

### Recompute Read Latency

| Corpus | Storage Engine | Cold (0 refs) | Warm (0 refs) | Cold (10 refs) | Warm (10 refs) | Cold (1000 refs) | Warm (1000 refs) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config Text** | In-Memory Informer | 0 µs | 0 µs | 6 µs | 6 µs | 290 µs | 290 µs |
| | BBolt (mmap + NoSync) | 4 µs | 0 µs | 143 µs | 8 µs | 21 ms | 978 µs |
| | DiskStore (None) | 0 µs | 0 µs | 3.0 ms | 177 µs | 302 ms | 293 ms |
| | DiskStore (zstd) | 0 µs | 0 µs | 263 µs | 195 µs | 16 ms | 16 ms |
| | DiskStore (None, 64 MB pool) | 0 µs | 0 µs | 226 µs | 85 µs | 11 ms | 19 ms |
| **TLS Material** | In-Memory Informer | 0 µs | 0 µs | 8 µs | 8 µs | 256 µs | 256 µs |
| | BBolt (mmap + NoSync) | 3 µs | 0 µs | 122 µs | 6 µs | 18 ms | 555 µs |
| | DiskStore (None) | 0 µs | 0 µs | 3.4 ms | 111 µs | 286 ms | 281 ms |
| | DiskStore (zstd) | 0 µs | 0 µs | 2.0 ms | 211 µs | 162 ms | 21 ms |
| | DiskStore (None, 64 MB pool) | 0 µs | 0 µs | 159 µs | 128 µs | 12 ms | 15 ms |
| **Random Bytes** | In-Memory Informer | 0 µs | 0 µs | 9 µs | 9 µs | 254 µs | 254 µs |
| | BBolt (mmap + NoSync) | 3 µs | 0 µs | 146 µs | 7 µs | 20 ms | 530 µs |
| | DiskStore (None) | 0 µs | 0 µs | 2.9 ms | 104 µs | 285 ms | 282 ms |
| | DiskStore (zstd) | 0 µs | 0 µs | 2.9 ms | 81 µs | 272 ms | 274 ms |
| | DiskStore (None, 64 MB pool) | 0 µs | 0 µs | 200 µs | 116 µs | 11 ms | 13 ms |
| **Mixed Corpus** | In-Memory Informer | 0 µs | 0 µs | 13 µs | 13 µs | 359 µs | 359 µs |
| | BBolt (mmap + NoSync) | 3 µs | 0 µs | 167 µs | 11 µs | 20 ms | 598 µs |
| | DiskStore (None) | 0 µs | 0 µs | 2.6 ms | 104 µs | 373 ms | 380 ms |
| | DiskStore (zstd) | 0 µs | 0 µs | 2.6 ms | 149 µs | 348 ms | 21 ms |
| | DiskStore (None, 64 MB pool) | 0 µs | 0 µs | 5.3 ms | 94 µs | 423 ms | 26 ms |

---

## 3. Scope Differences and What the Harness Leaves Out

- **Block Pool Size and Warm Read Latencies:** The test suite configures DiskStore with a default 8 MiB block pool (2,048 blocks). When 1,000 uncompressed 10 KB objects (~10 MB working set) are read, they exceed this 8 MiB pool. During warm recomputes of 1,000 references, earlier pool blocks are evicted before reuse, forcing direct disk I/O on every lookup (~280–380 ms). When objects compress with zstd, the 1,000-object working set fits within the 8 MiB pool, reducing warm read latency to ~16–21 ms. Similarly, when DiskStore runs with a 64 MiB pool (16,384 blocks), the uncompressed working set remains in memory, reducing warm read latency from ~380 ms to ~19–26 ms.
- **Recovery Measurement:** Recovery values measure clean store reopen duration. For DiskStore, this measures `engine.Open`, which reads the checkpoint and scans physical blocks in the heap file to rebuild internal allocator and index tables (~40–538 ms). For BBolt, this measures `bbolt.Open`, which opens the file and creates its memory map without scanning or rebuilding index state (~3.2–14 ms).
- **Recompute Read Cost in Watch Harness:** `TestWatchMemoryComparison` measures watch event ingestion rate and idle memory usage; it does not measure recompute lookups against the ingested objects.
- **Encryption Settings:**
  - `TestWatchMemoryComparison` runs without payload encryption for both BBolt and kubecache (`NoopCipher` / no cipher).
  - `TestDiskStore_Versus_BBolt_MeasurementSuite` enables ephemeral AES-GCM encryption (`EphemeralAESGCMCipher`) for both BBolt and DiskStore.
  - Stock / In-Memory Informer stores plain Go structs in memory without encryption in both harnesses.
- **Caching Semantics under Recompute:** In the measurement suite, BBolt reads use `bboltcache.LazyResolver`, which memoizes deserialized Go object pointers across recomputes by `key@resourceVersion` and evicts unreferenced entries via `FinishRecompute()`. DiskStore reads in the suite call `GetByKey` directly on `kubecache.Indexer`, deserializing and decrypting from disk / block pool on each lookup unless cached by the caller.
- **Memory Classification & Accounting:** BBolt data pages reside in the operating system page cache via `mmap` (`file` memory in cgroup v2, reclaimable under kernel memory pressure), resulting in small Go heap usage but higher process RSS under load. DiskStore uses direct I/O with a bounded block pool arena, keeping RSS bounded while tracking secondary index keys in Go heap (`anon`).

---

## 4. Engine Write Volume and Amplification (`TestWriteMeasurement`)

### Methodology

Evaluates bytes handed to the filesystem, write operation counts, and sync operations in `experiments/diskstore/engine` using the seeded model-checked workload runner (`runTortureWorkload`) over 2,000 operations across 20 keys with clean closes:
- **Test Command:**
  ```bash
  DISKSTORE_MEASURE=1 go test -v -run ^TestWriteMeasurement$ ./experiments/diskstore/engine
  ```
- **Machine & Environment:** AMD EPYC 9B14 (60 vCPUs, 235 GiB RAM, Linux 6.12.110+ x86_64, `go1.27.4 linux/amd64`).
- **Filesystem Wrapper:** In-memory filesystem (`NewMemFS()`) wrapped by a test wrapper (`measureFS`), tracking write bytes, write calls, and fsync calls separated by file kind (`heap`, `wal`, `oversize`, `other`).
- **Engine Configuration:** Uncompressed store (`WithCompressionCodec(CodecNone)`), block pool of 4,096 blocks (16 MiB) sized large enough to hold all 20 keys without buffer eviction.
- **Workload & Durability Modes:** 2,000 operations (Puts and Deletes) using seed 42. Evaluated for value sizes of 256 bytes, 2 KiB, 16 KiB, and 256 KiB across three durability modes:
  1. *No Checkpoint:* No intermediate checkpoints or syncs; modifications are flushed and synced only on clean close.
  2. *Checkpoint / 1k ops:* Store checkpoints every 1,000 operations, flushing dirty pages to the heap file, syncing the heap, appending a checkpoint record, and syncing the WAL.
  3. *Sync after each op:* Store calls `Sync()` after every put and delete operation.
  Each case concludes with a clean close, reopens the store, and verifies durable contents against the in-memory model map.

### What the Numbers Leave Out

These measurements record bytes handed to the filesystem layer via `File.WriteAt` calls and explicit `File.Sync` operations. They count filesystem-level I/O, not what physical storage devices write:
- **Underlying File System Journaling & Metadata:** Ext4, XFS, and ZFS perform journaling, allocation bitmap updates, and inode metadata updates that add writes not tracked here.
- **Device Flash Translation Layer (FTL) & Block Geometry:** Solid-state drives write in flash-page units (typically 4–16 KiB) and erase in flash-block units (several megabytes). Internal FTL garbage collection and wear leveling cause physical device write amplification that depends on drive firmware, wear, and over-provisioning.
- **Operating System Page Cache:** In non-direct I/O environments, operating system page cache buffering may coalesce or defer flushes before physical syncs.

### Results

| Value Size | Durability Mode | Payload Put | WAL Bytes | Heap Bytes | Oversize Bytes | Write Ratio | Syncs / Op |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 256 B | No Checkpoint | 357,120 B | 454,656 B | 20,480 B | 0 B | 1.34 | 0.0075 |
| 256 B | Checkpoint / 1k ops | 357,120 B | 466,944 B | 32,768 B | 0 B | 1.41 | 0.0100 |
| 256 B | Sync after each op | 357,120 B | 7,409,664 B | 20,480 B | 0 B | 20.82 | 0.9105 |
| 2 KiB | No Checkpoint | 2,820,096 B | 2,920,448 B | 98,304 B | 0 B | 1.07 | 0.0075 |
| 2 KiB | Checkpoint / 1k ops | 2,820,096 B | 2,928,640 B | 167,936 B | 0 B | 1.10 | 0.0100 |
| 2 KiB | Sync after each op | 2,820,096 B | 7,430,144 B | 98,304 B | 0 B | 2.67 | 0.9130 |
| 16 KiB | No Checkpoint | 23,166,976 B | 23,269,376 B | 819,200 B | 0 B | 1.04 | 0.0080 |
| 16 KiB | Checkpoint / 1k ops | 23,166,976 B | 23,277,568 B | 1,245,184 B | 0 B | 1.06 | 0.0105 |
| 16 KiB | Sync after each op | 23,166,976 B | 30,613,504 B | 819,200 B | 0 B | 1.36 | 0.9155 |
| 256 KiB | No Checkpoint | 370,671,616 B | 370,814,976 B | 13,107,200 B | 0 B | 1.04 | 0.0250 |
| 256 KiB | Checkpoint / 1k ops | 370,671,616 B | 370,827,264 B | 19,922,944 B | 0 B | 1.05 | 0.0210 |
| 256 KiB | Sync after each op | 370,671,616 B | 378,179,584 B | 13,107,200 B | 0 B | 1.06 | 0.9400 |

### Analysis & Comparison to Minimum Write Volume

The smallest possible write volume for durable storage in a write-ahead logged engine is one WAL record for each modification and one page flush for each changed page.

What the comparison shows and what it doesn't: the WAL carries each payload once plus framing, and heap writes depend on how often pages are flushed, which this workload makes rare.

- **WAL Framing Overhead:** Each WAL record includes a 32-byte record header (`RecordHeaderSize`), table name, key string, and CRC32 checksum. For 256 B values in buffered modes, this fixed framing overhead accounts for the 1.34–1.41 write ratio. As value size increases to 2 KiB, 16 KiB, and 256 KiB, payload bytes dominate the WAL records, keeping WAL write volume within 1% to 4% of payload bytes put.
- **Durability Modes and Heap Flushes:** The workload without sync calls `Sync` only at checkpoints or close, so it makes nothing durable until a checkpoint or close. In that setting, with no checkpoint, 1,395 puts of 256 bytes wrote 20,480 bytes to the heap, because the resident pages were flushed once at close. Checkpointing every 1,000 operations flushes dirty pages at each checkpoint boundary, increasing heap write volume from 20,480 B to 32,768 B for 256 B values, and from 13,107,200 B to 19,922,944 B for 256 KiB values.
- **Per-Operation Sync and WAL Block Padding:** In the "Sync after each op" mode, `Sync()` is called after each operation to make every modification immediately durable. Because WAL syncs pad unaligned trailing blocks with zeros up to the 4,096-byte boundary (`WALBlockSize`) before fsyncing, small 256 B puts write a full 4 KiB block per operation. This produces 7,409,664 bytes written to the WAL for 357,120 bytes of payload (a write ratio of 20.82 and 0.9105 syncs per operation). At 2 KiB values, block padding produces a 2.67 ratio. At 16 KiB and 256 KiB, values span multiple full blocks (4 and 64 blocks respectively), so trailing padding represents a much smaller fraction of total writes (ratios of 1.36 and 1.06).
- **WAL Segment Rollover:** The default WAL segment size is 16 MiB (`DefaultMaxSegmentSize`). For 256 KiB values, accumulating ~370 MB of writes causes segment rollover every 16 MiB, which explains the 0.0210–0.0250 syncs per operation observed even without explicit per-operation syncs.
