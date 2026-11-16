# Design: A Stream as the Store's Redo Log

This document designs the integration of the disk-store engine (`experiments/diskstore/engine`) as the relational local index for structured data streams in `gke-labs/in-cluster-storage` (`docs/structured-data-streams.md`, `docs/streams.md`, `pkg/sds`), as an alternative to SQLite. In this architecture, the stream is the authoritative change log, and the engine maintains a queryable local projection with no log of its own.

## Terminology

- **Stream:** An ordered, append-only log of opaque payloads managed by the Streams service (`pkg/wal/client.Stream`, `docs/streams.md#overview`).
- **Stream position (`stream_seq`):** A strictly increasing 64-bit integer assigned to each record in a stream by its single writer (`docs/streams.md#wire--storage-formats`).
- **Local index:** A queryable projection maintaining table rows at a known stream position (`pkg/sds.LocalIndex`, `docs/structured-data-streams.md#the-local-index-concept`).
- **Page LSN:** The stream position of the most recent change applied to a 4 KiB heap page.
- **Recovery position:** The lowest stream position such that every earlier change is confirmed durable on disk across all pages.

## 1. The Two Arrangements

We consider two arrangements for integrating the engine with a stream:
1. **Engine keeps a log behind an interface:** The engine maintains its existing write-ahead log contract, and a stream acts as one log implementation. The engine writes records to the stream and controls checkpoints.
2. **Stream is the redo log, engine has no log of its own:** Callers commit changes to the stream first. The engine applies committed changes directly to heap pages as a projection and records the stream position reached, writing no WAL of its own.

We recommend building **arrangement 2** first. Structured data streams define the stream as the single source of truth (`docs/structured-data-streams.md#overview`). Arrangement 1 reverses this relationship, forces the engine to own stream record framing, and causes double-logging. In `experiments/diskstore/BENCHMARKS.md`, local WAL writes add a 1.04x to 20.82x write amplification over payload bytes. Arrangement 2 writes no local WAL records, enables multiple projection replicas to tail the same stream, and directly implements `pkg/sds.LocalIndex`.

## 2. Invariants for the Engine with No Log of Its Own

### Positions and LSNs
A page's LSN is the 64-bit stream position (`stream_seq`) of the last change applied to it. The engine requires stream positions to be strictly increasing 64-bit unsigned integers assigned by a single writer (`docs/streams.md#overview`).
When the engine has no log of its own, derivations from LSNs change as follows:
- **WAL segment names (`%020d.wal`):** Eliminated. The engine creates no local WAL files.
- **Per-segment encryption keys (`diskstore/wal/<LSN>`):** Eliminated. Stream records are encrypted at the stream transport layer (`docs/structured-data-streams.md#encryption`). The engine only derives heap keys (`diskstore/heap`) and oversize keys (`diskstore/oversize/<filename>`).
- **Lost-tail check (`maxWAL_LSN < maxHeapLSN`):** Replaced by a stream watermark check. Recovery reads the stream's tail sequence from `Stream.Watermarks()` (`docs/streams.md#durability-levels--watermarks`). If `streamTailLSN < maxHeapLSN`, recovery aborts with an error because the stream lost committed records or the heap outran the log.

### Write-Ahead Rule
Before the engine applies a change in memory, the change must reach `Local` durability (written and fsynced on the client node) or `Witness` durability (fsynced to the central buffer) in the stream (`docs/streams.md#durability-levels--watermarks`). Before the engine flushes a page with LSN `P` to the heap file, position `P` must be durable in the stream (`stream.Wait(ctx, P, level, false)`). When flushing a batch of dirty pages, the engine waits once for the highest LSN in the batch. Crash recovery does not encounter heap pages that outrun durable stream history because the engine waits for stream durability before flushing.

### Recovery Rule
Recovery reconstructs state in two stages without reading a local WAL:
1. **Heap scan:** Recovery scans the heap file sequentially in 4 KiB blocks. Each block header stores its logical page number, block index, total blocks, LSN, and Castagnoli CRC32C checksum (`design.md#block-header`). For each logical page number, the valid candidate block run with the highest LSN wins, discarding torn or superseded writes. Recovery rebuilds the buddy allocator by marking winning blocks allocated and freeing the rest.
2. **Stream replay:** Recovery reads the durable `recoveryPosition` stored in `meta.db` and replays the stream forward from `recoveryPosition` using `Stream.Tail(ctx, recoveryPosition)` (`docs/streams.md#client-api-reference`).

The recovery position is the lowest stream position such that every earlier change is present in a durable page on disk. The engine avoids overwriting data in place, but storing `recoveryPosition` requires updating `meta.db` after each heap fsync. To prevent torn writes from corrupting metadata, the engine allocates two alternating position slots in `meta.db`'s reserved space (which has 4028 reserved bytes). Each slot holds an incrementing generation counter, the 64-bit `recoveryPosition`, and a Castagnoli CRC32C checksum. The engine writes to the slot with the older generation counter only after the heap fsync that it describes has completed, and then fsyncs `meta.db`. During recovery, the engine inspects both slots. If both are valid, the slot with the higher generation counter wins. If the newer slot is damaged by a crash, its checksum fails; recovery discards the damaged slot and uses the older valid slot. Falling back to the older slot is safe because replaying from an earlier position is idempotent.

### Idempotent Replay and Superseded Copies
Replay in the engine is logical: it applies put and delete operations for keys (`applyPutLocked`, `applyDeleteLocked`) and skips records when the page holding the key carries an LSN equal to or newer than the record's LSN.
When a put moves an existing key from page A to page B at position `S` (e.g. when page A is full), it writes the key to page B and deletes it from page A. If a crash occurs before both pages are synced, the superseded-copies rule handles the outcome:
- **B flushed and A not:** Page B contains the key with LSN `S`, while page A retains an older image with LSN `L_A < S` still holding the key. The heap scan finds the key on both pages; `keyIndex` indexes the newer copy on page B and records the superseded copy on page A. Because page A had an un-synced modification at `S`, by definition `recoveryPosition <= S`, so record `S` is inside the replayed range. When replay reaches `S`, it sees page B already carries LSN `S`, but the superseded-copies rule clears the stale copy on page A.
- **A flushed and B not:** Page A flushed its deletion with LSN `S`, while page B retains an older copy with LSN `L_B < S` (or unwritten blocks). The key is absent from page A and absent from page B's recovered state. Because page B had an un-synced change at `S`, `recoveryPosition <= S`. Replay reaches record `S` and applies the put logically, inserting the key into page B.
- **Later delete flushed while put was not:** The key moved from page A to page B at `S_1` and was deleted at `S_2 > S_1`. If page B flushed the deletion at `S_2` but page A's write at `S_1` did not flush, page A's un-synced modification keeps `recoveryPosition <= S_1`. Replay starts at or before `S_1`, clears the copy on page A at `S_1`, and executes the deletion at `S_2`, leaving no resurrecting copy on page A.

### Deferred Frees Protect Durable Copies
Under deferred block frees (`design.md#deferred-block-frees`), blocks that no page uses any more wait for a heap fsync that started after their replacement was written. The engine releases unneeded blocks to the buddy allocator only after that heap fsync succeeds. If a crash occurs before the fsync completes, volatile allocator state is lost and the prior durable copy remains allocated and intact on disk. If a replacement write tore, Castagnoli CRC32C verification fails and the heap scan selects the intact prior durable copy.

## 3. Atomic Batches

`ApplyBatch` applies a slice of row changes and advances `Position` in one commit (`pkg/sds.LocalIndex`). In Streams, multi-row operations share a `tx_id` and commit via `TxCommit` (`docs/structured-data-streams.md#transactions`).
- **Readers during apply:** `Get` reads optimistically without taking `writerMu.RLock()` and retries on conflict, ensuring writers do not block point lookups; only `Scan` and `List` take `writerMu.RLock()`. Because `Get` does not hold the lock, a point lookup can observe half of a batch while `ApplyBatch` executes.
- **Atomic visibility as a gap:** Providing atomic batch visibility to point lookups requires either:
  1. *Taking `writerMu.RLock()` in `Get`:* Serializes point lookups behind `ApplyBatch`. Gives up optimistic, non-blocking reads and introduces read-write contention.
  2. *Position-based versioned reads:* Readers specify a position to read at, using the stream position as the version. Readers only observe records stamped at or before their requested version. This matches the multi-version note in the engine design (`design.md#single-writer-mutation`) and aligns with the unapplied overlay in `sds/view` (`docs/structured-data-streams.md#the-local-index-concept`), which shields readers from uncommitted applier batches.
- **Partially flushed batches:** If a crash occurs after some pages in a batch flushed to disk but before others flushed, recovery restarts replay from `recoveryPosition`. The per-page LSN check skips pages that already contain batch changes and applies changes to lagging pages, restoring batch atomicity without an undo log.

## 4. Position and SetPosition

- **`Position()`:** Returns the stream position applied in memory and visible to readers.
- **`SetPosition(pos)`:** Sets the in-memory applied position, used when initializing an index or skipping non-table stream events.
- **Relation to recovery position:** `Position()` is volatile in memory. The recovery position in `meta.db` is durable on disk and lags `Position()` by un-synced dirty page flushes. On restart, replay starts from the durable recovery position and rolls forward to the stream head, restoring `Position()` in memory.

## 5. Snapshots

- **Production:** To publish a snapshot at position `P` (`pkg/sds.Snapshotter`), the engine flushes all dirty pages up to `P`, invokes a heap fsync to advance the durable recovery position to `P`, and uploads `heap.db`, `meta.db`, and referenced `oversize/` files to object storage under `streams/<stream-id>/snapshots/diskstore/<position 20 digits>` (`docs/structured-data-streams.md#layer-3-projections-as-snapshots`).
- **Restore:** `RestoreSnapshot` downloads the snapshot directory, opens the engine, and reconstructs index and buddy state from heap block headers. Replay resumes from `P` via `Stream.Tail(ctx, P)`.
- **Missing prerequisites:**
  1. A read-only snapshot handle or copy-on-write freeze so writes continue during upload (`design.md#read-only-mode`).
  2. Snapshot archive packaging for the multi-file directory layout.
  3. Storing the in-band type registry (`pkg/sds/record.Registry`) in snapshot metadata.
  4. Integration with `pkg/objectstore.Backend` (`docs/streams.md#permanent-object-storage-archiving-gcs--s3`).

## 6. What the Engine Lacks Next to SQLite

- **Key-ordered prefix scans:** SQLite scans B-tree indexes natively. The engine uses an in-memory hash map (`keyIndex: map[string]KeyIndexEntry`) and sorts keys on each scan. *Does not block v1:* filtering and sorting in-memory keys satisfies `Scan` semantics for small-to-medium datasets. An ordered tree (e.g. Adaptive Radix Tree) is a future optimization.
- **Secondary indexes:** SQLite maintains arbitrary column indexes. The engine only indexes primary keys (`tableName\x00key`). *Does not block v1:* `LocalIndex` only requires primary-key lookups (`Get`) and primary-key prefix scans (`Scan`).
- **Type registry:** SQLite defines SQL column schemas. The engine stores raw bytes. *Does not block v1:* SDS encodes rows as raw protobuf payloads (`docs/structured-data-streams.md#tables-are-the-applications-messages`); the engine can store the registry in a reserved metadata table.
- **Large values:** Streams enforce record size limits. SDS offloads values to a content-addressed blob store referenced by SHA-256 (`docs/structured-data-streams.md#value-types`). *Does not block v1:* large objects are externalized before reaching the stream.
- **Transaction rollback:** SQLite supports statement-level rollbacks. The engine has no undo log. *Does not block v1:* the stream only delivers committed transactions.

## 7. The Cache Use Stays

The Kubernetes cache (`experiments/diskstore/kubecache`) has no stream and runs standalone. It retains its local WAL.
To avoid duplicate redo logic, the engine abstracts redo replay over a record iterator (`iter.Seq2[uint64, Record]`). For kubecache, the iterator reads local `.wal` segment files. For the stream projection, the iterator reads from `Stream.Tail`. Both pass records through the same per-page LSN check, `applyPutLocked`, and `applyDeleteLocked` functions. There is one redo path, not two.

## 8. Failure Handling

When the engine detects corrupt blocks or fatal I/O errors, it transitions to a sticky failed state (`engine.go: setFailed`), rejects both reads and writes, and writes a `FAILED` marker.
In SDS, the stream and object snapshots are authoritative (`docs/structured-data-streams.md#layer-3-projections-as-snapshots`). When a projection fails, `pkg/sds.IsUnrecoverable` reports true. The runtime discards the corrupt store directory, downloads the latest snapshot from object storage, and catches up by tailing the stream. The engine's fail-fast policy triggers this rebuild.

## 9. Costs and Risks

### What Is Gained
- **Reduced local log write amplification:** In `experiments/diskstore/BENCHMARKS.md`, `TestWriteMeasurement` (measured on AMD EPYC 9B14 using an in-memory filesystem tracking bytes handed to the filesystem via `File.WriteAt` and `File.Sync` calls across 2,000 operations) showed that per-operation WAL syncs write 7,409,664 bytes to disk for 357,120 bytes of 256 B payloads (a 20.82x write ratio) due to 4 KiB block padding. Checkpointing every 1,000 ops wrote 1.41x payload bytes. Using the stream as the redo log writes no local WAL records; the engine hands only heap page flushes to the filesystem (20,480 to 32,768 bytes for 2,000 ops).
- **Shared durability:** Log replication, witness durability, and object archival are offloaded to Streams (`docs/streams.md#overview`).
- **Multiple projections:** Multiple local indexes can tail the same stream independently without write contention.

### What Is Given Up
- **External dependency:** Mutations and restarts depend on the Streams buffer service. Network interruptions stall writes.
- **Network recovery latency:** Replaying un-synced tail records requires network transfers via `Stream.Tail`. Streams client nodes retain recent uncompacted records in local segments (`docs/streams.md#key-components`), but `docs/streams.md` does not specify whether local clients can replay directly from node storage without contacting `wal-buffer`. We list this as an open question for `in-cluster-storage`.
- **Flush coordination:** Heap page flushes must coordinate with stream durability watermarks.

## 10. Open Choices for the Maintainer

1. **Durability watermark for page flushes:**
   - *Choice:* Require `Local` vs `Witness` watermark before flushing dirty pages.
   - *Recommendation:* Require `Witness`.
   - *Gives up:* Adds 2–10 ms network round-trip latency to flushes (`docs/streams.md#durability-levels--watermarks`), but ensures the cluster witness confirms log order before pages reach local disk, preventing state divergence if a node fails.
2. **Durable recovery position storage:**
   - *Choice:* Store alternating slots in `meta.db` reserved header vs a dedicated `checkpoint.db` file.
   - *Recommendation:* Store in `meta.db`.
   - *Gives up:* Consumes reserved bytes in `meta.db` and bumps `StoreFormatVersion`. In return, it avoids creating an extra file and extra directory fsyncs on every sync.
3. **Prefix scan implementation:**
   - *Choice:* Filter and sort in-memory keys vs introducing an ordered index.
   - *Recommendation:* Filter and sort in memory for v1; add an ordered tree later if benchmarks require it.
   - *Gives up:* Optimal scan latency on large key sets ($O(N \log N)$ vs $O(K)$), but avoids changing index structures for the first version.
4. **Where the adapter lives:**
   - *Choice:* Place `sds.LocalIndex` in this repository (e.g. `experiments/diskstore/sds`) vs in `in-cluster-storage` (e.g. `pkg/sds/projection/diskstore`) importing the engine.
   - *Recommendation:* Place the adapter in `in-cluster-storage`.
   - *Gives up:* Cross-repo development requires consuming engine releases in `in-cluster-storage`, but keeps this module independent of `in-cluster-storage` dependencies.

## 11. Implementation Steps

We propose migrating the engine in five small pull requests:
1. **Abstract the log interface:** Place the five WAL calls (`AppendRecord`, `SyncThrough`, `DurableLSN`, `NewIterator`, `TruncateBefore`) behind a `Log` interface in `engine`, with `*WAL` as the sole implementation.
   - *Verification:* All unit and torture tests in `engine` pass with zero behavioral change.
2. **Durable position in `meta.db`:** Add alternating `RecoveryPosition` slots with generation counters and CRC32C to `meta.db`'s reserved space, updated at heap sync boundaries.
   - *Verification:* Unit tests verify that recovery reads `RecoveryPosition` after partial flushes without inspecting WAL checkpoint records, and falls back if the newer slot is torn.
3. **Decouple recovery replay:** Refactor `recovery.go` to accept an abstract record iterator, sharing the logical record replay and superseded-copies rule between local WAL segments and external streams.
   - *Verification:* Existing crash recovery and torture test suites pass without regression.
4. **Add external-log engine mode:** Add a `NoLog` option to `engine.Open` that skips creating WAL files, accepts external LSNs on mutations, and enforces the write-ahead rule against an external watermark.
   - *Verification:* Unit tests verify engine mutations, dirty page flushes, and recovery against an in-memory stream without `.wal` files.
5. **Implement `sds.LocalIndex`:** Implement the `LocalIndex` adapter in `in-cluster-storage` (or `experiments/diskstore/sds`), implementing `Position`, `SetPosition`, `ApplyBatch`, `Get`, and `Scan`.
   - *Verification:* Run the `pkg/sds` conformance suite against the diskstore adapter, verifying behavior matches SQLite.
