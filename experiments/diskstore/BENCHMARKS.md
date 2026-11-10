# Informer Storage Engine Benchmarks: DiskStore vs BBolt vs In-Memory

This document records comparative benchmark measurements between the in-memory Informer, BBolt (`experiments/bboltcache`), and DiskStore / kubecache (`experiments/diskstore`), gathered from a single machine using shared harnesses.

## Environment

- **Date:** 2026-11-10
- **Commit:** `17a3ca24d0a7edec6ea88fd1788380c4b50d6f77`
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
| Stock Informer | 1,000 | 21.1 MB | 10.9 MB | 55.6 MB | 11,414 B | 7,712 op/s | - |
| bbolt WatchLoop | 1,000 | 6.3 MB | 0.1 MB | 52.9 MB | 95 B | 5,223 op/s | 16.0 MB |
| kubecache WatchLoop | 1,000 | 35.0 MB | 12.5 MB | 64.4 MB | 13,074 B | 7,735 op/s | 3.4 MB |
| Stock Informer | 10,000 | 173.5 MB | 108.5 MB | 213.0 MB | 11,379 B | 8,292 op/s | - |
| bbolt WatchLoop | 10,000 | 8.2 MB | 0.4 MB | 171.8 MB | 40 B | 5,581 op/s | 144.2 MB |
| kubecache WatchLoop | 10,000 | 42.8 MB | 15.5 MB | 77.4 MB | 1,624 B | 8,433 op/s | 33.9 MB |
| Stock Informer | 50,000 | 842.9 MB | 541.4 MB | 895.9 MB | 11,353 B | 8,520 op/s | - |
| bbolt WatchLoop | 50,000 | 12.6 MB | 2.1 MB | 214.7 MB | 44 B | 5,983 op/s | 673.1 MB |
| kubecache WatchLoop | 50,000 | 71.1 MB | 27.4 MB | 109.0 MB | 574 B | 8,513 op/s | 105.1 MB |

---

## 2. Storage & Recompute Measurement Suite (`TestDiskStore_Versus_BBolt_MeasurementSuite`)

### Methodology
Evaluates isolated worker subprocesses across four 10 KB object corpora:
1. **Config Text (JSON):** 2,500 objects (~24.4 MB raw)
2. **TLS Material (PEM):** 2,500 objects (~24.4 MB raw)
3. **Random Incompressible Bytes:** 2,500 objects (~24.4 MB raw)
4. **Mixed Realistic Corpus:** 10,000 objects (~97.7 MB raw)

Engines: In-Memory Informer, BBolt (`mmap` + `NoSync`), DiskStore (None), and DiskStore (zstd).

### Storage, Memory & Write Performance

| Corpus | Storage Engine | Heap In-Use | Process RSS | Heap File | WAL Size | Total Disk | Write Throughput | Recovery |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config Text (2.5k)** | In-Memory Informer | 28.65 MB | 83.18 MB | - | - | 0 MB (RAM) | 7,356 op/s | - |
| | BBolt (mmap + NoSync) | 0.34 MB | 72.92 MB | 48.06 MB | 0.00 MB | 48.06 MB | 3,134 op/s | 12.00 ms |
| | DiskStore (None) | 14.42 MB | 63.46 MB | 39.81 MB | 8.87 MB | 48.68 MB | 4,577 op/s | 224.00 ms |
| | DiskStore (zstd) | 14.05 MB | 65.05 MB | 4.89 MB | 3.61 MB | 8.50 MB | 4,460 op/s | 43.00 ms |
| **TLS Material (2.5k)** | In-Memory Informer | 30.08 MB | 82.10 MB | - | - | 0 MB (RAM) | 4,806 op/s | - |
| | BBolt (mmap + NoSync) | 0.42 MB | 73.64 MB | 48.06 MB | 0.00 MB | 48.06 MB | 2,851 op/s | 12.00 ms |
| | DiskStore (None) | 14.22 MB | 67.02 MB | 39.81 MB | 8.93 MB | 48.75 MB | 3,494 op/s | 164.00 ms |
| | DiskStore (zstd) | 14.62 MB | 70.54 MB | 9.77 MB | 6.39 MB | 16.16 MB | 3,752 op/s | 55.00 ms |
| **Random Bytes (2.5k)** | In-Memory Informer | 27.34 MB | 61.64 MB | - | - | 0 MB (RAM) | 43,052 op/s | - |
| | BBolt (mmap + NoSync) | 0.23 MB | 71.38 MB | 48.06 MB | 0.00 MB | 48.06 MB | 7,914 op/s | 12.00 ms |
| | DiskStore (None) | 13.45 MB | 66.64 MB | 39.81 MB | 8.89 MB | 48.70 MB | 13,537 op/s | 191.00 ms |
| | DiskStore (zstd) | 13.30 MB | 68.45 MB | 39.81 MB | 8.89 MB | 48.70 MB | 8,652 op/s | 150.00 ms |
| **Mixed Corpus (10k)** | In-Memory Informer | 115.89 MB | 204.77 MB | - | - | 0 MB (RAM) | 6,499 op/s | - |
| | BBolt (mmap + NoSync) | 0.73 MB | 174.55 MB | 144.24 MB | 0.00 MB | 144.24 MB | 2,914 op/s | 12.00 ms |
| | DiskStore (None) | 17.90 MB | 74.79 MB | 157.81 MB | 3.55 MB | 161.36 MB | 5,138 op/s | 535.00 ms |
| | DiskStore (zstd) | 17.98 MB | 77.44 MB | 121.94 MB | 14.47 MB | 136.41 MB | 5,196 op/s | 363.00 ms |

### Recompute Read Latency

| Corpus | Storage Engine | Cold (0 refs) | Warm (0 refs) | Cold (10 refs) | Warm (10 refs) | Cold (1000 refs) | Warm (1000 refs) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config Text** | In-Memory Informer | 0.00 µs | 0.00 µs | 7.00 µs | 7.00 µs | 264.00 µs | 264.00 µs |
| | BBolt (mmap + NoSync) | 6.00 µs | 1.00 µs | 213.00 µs | 13.00 µs | 25,948.00 µs | 1,057.00 µs |
| | DiskStore (None) | 0.00 µs | 0.00 µs | 2,679.00 µs | 142.00 µs | 350,186.00 µs | 349,699.00 µs |
| | DiskStore (zstd) | 0.00 µs | 0.00 µs | 313.00 µs | 203.00 µs | 21,069.00 µs | 22,934.00 µs |
| **TLS Material** | In-Memory Informer | 0.00 µs | 0.00 µs | 12.00 µs | 12.00 µs | 326.00 µs | 326.00 µs |
| | BBolt (mmap + NoSync) | 5.00 µs | 0.00 µs | 228.00 µs | 11.00 µs | 30,768.00 µs | 593.00 µs |
| | DiskStore (None) | 0.00 µs | 0.00 µs | 2,467.00 µs | 110.00 µs | 319,323.00 µs | 357,399.00 µs |
| | DiskStore (zstd) | 0.00 µs | 0.00 µs | 1,665.00 µs | 253.00 µs | 156,554.00 µs | 21,462.00 µs |
| **Random Bytes** | In-Memory Informer | 0.00 µs | 0.00 µs | 12.00 µs | 12.00 µs | 298.00 µs | 298.00 µs |
| | BBolt (mmap + NoSync) | 4.00 µs | 0.00 µs | 148.00 µs | 7.00 µs | 21,894.00 µs | 668.00 µs |
| | DiskStore (None) | 0.00 µs | 0.00 µs | 2,450.00 µs | 96.00 µs | 266,254.00 µs | 267,108.00 µs |
| | DiskStore (zstd) | 0.00 µs | 0.00 µs | 2,493.00 µs | 102.00 µs | 304,889.00 µs | 274,332.00 µs |
| **Mixed Corpus** | In-Memory Informer | 0.00 µs | 0.00 µs | 17.00 µs | 17.00 µs | 370.00 µs | 370.00 µs |
| | BBolt (mmap + NoSync) | 4.00 µs | 0.00 µs | 170.00 µs | 8.00 µs | 29,936.00 µs | 1,289.00 µs |
| | DiskStore (None) | 0.00 µs | 0.00 µs | 2,644.00 µs | 117.00 µs | 375,783.00 µs | 375,908.00 µs |
| | DiskStore (zstd) | 0.00 µs | 0.00 µs | 2,624.00 µs | 199.00 µs | 339,330.00 µs | 22,915.00 µs |

---

## 3. Scope Differences and What the Harness Leaves Out

- **Recompute Read Cost in Watch Harness:** `TestWatchMemoryComparison` measures only watch stream ingestion throughput and steady-state idle memory footprint; it does not measure recompute lookups against the ingested objects.
- **Encryption Settings:**
  - `TestWatchMemoryComparison` runs without payload encryption for both BBolt and kubecache (`NoopCipher` / no cipher).
  - `TestDiskStore_Versus_BBolt_MeasurementSuite` enables ephemeral AES-GCM encryption (`EphemeralAESGCMCipher`) for both BBolt and DiskStore.
  - Stock / In-Memory Informer stores plain Go structs in memory without encryption in both harnesses.
- **Caching Semantics under Recompute:** In the measurement suite, BBolt reads use `bboltcache.LazyResolver`, which memoizes deserialized Go object pointers across recomputes by `key@resourceVersion` and evicts unreferenced entries via `FinishRecompute()`. DiskStore reads in the suite call `GetByKey` directly on `kubecache.Indexer`, deserializing and decrypting from disk / block pool on each lookup unless cached by the caller.
- **Memory Classification & Accounting:** BBolt data pages reside in the kernel page cache via `mmap` (`file` memory in cgroup v2, reclaimable under kernel memory pressure), resulting in minimal Go heap usage but higher process RSS under load. DiskStore uses direct I/O with an 8 MiB block pool arena, keeping RSS bounded while tracking secondary index keys in Go heap (`anon`).
