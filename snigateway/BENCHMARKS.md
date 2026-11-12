# SNIGateway Tunnel Overhead Benchmarks: TCP Pool vs QUIC vs HTTP/2 CONNECT vs WireGuard

This document records the benchmarking methodology, empirical measurements, CPU profile analysis, optimizations, and architectural recommendations for SNIGateway's reverse tunnel transports (TCP Pool, QUIC, HTTP/2 CONNECT, and WireGuard), addressing [Issue #621](https://github.com/gke-labs/gateway-api-reference-implementation/issues/621), [Issue #689](https://github.com/gke-labs/gateway-api-reference-implementation/issues/689), and [Issue #1079](https://github.com/gke-labs/gateway-api-reference-implementation/issues/1079).

---

## 1. Executive Summary & Transport Recommendations

### Architectural Comparison: Four Transports
1. **QUIC (`--tunnel-transport=quic`)**:
   - 0-RTT/1-RTT stream multiplexing without pre-dialed pool.
   - Survives NAT rebindings and uses a single UDP 4-tuple.
   - Trade-off: Higher userspace CPU cost (2.5x–3.5x higher CPU per byte than TCP pool) due to userspace packet encryption, ACK generation, and single-threaded connection event loop.
2. **TCP Pool (`--tunnel-transport=tcp`)**:
   - Lowest CPU per byte on loopback and line-rate interfaces (~4.1 CPU-s/GB).
   - Kernel handles TCP segmentation, retransmission, and flow control.
   - Trade-off: Vulnerable to connection burst starvation when new requests exceed the pre-dialed pool size under WAN latency (2–3 RTT connection dial penalty).
3. **HTTP/2 CONNECT (`--tunnel-transport=h2`)**:
   - Multiplexes client streams as HTTP/2 CONNECT streams over a small pool of long-lived mTLS TCP connections (default 4).
   - Combines the burst-latency advantage of stream multiplexing (p50 TTFB comparable to QUIC under WAN delay) with the CPU efficiency of TCP-backed framing (~20% within TCP pool on bulk transfer, more than 2x lower CPU per byte than QUIC).
   - Uses standard HTTP/2 flow control, PING liveness, GOAWAY graceful drain, and error handling.
4. **WireGuard (`--tunnel-transport=wireguard`)**:
   - Multiplexes client connections inside an end-to-end WireGuard tunnel using userspace `wireguard-go` and `netstack` on both frontend and backend.
   - Survives NAT rebinding and operates over a single UDP socket.
   - Avoids TCP pool burst starvation under WAN latency (achieving ~66 ms p50 TTFB at 20 ms RTT and ~157 ms at 50 ms RTT, though paying 1 RTT for establishing a netstack TCP connection through the tunnel).
   - Trade-off: Significantly higher CPU consumption (~116 CPU-s/GB) and lower single-stream bulk throughput (~86 MB/s on loopback) due to userspace netstack TCP/IP processing and ChaCha20-Poly1305 framing.

### Architectural Decision: `auto` Mode
- `auto` remains QUIC-first in this phase; evaluating switching default to HTTP/2 is planned once comprehensive cluster data is gathered.
- `--tunnel-transport=h2` is now fully supported as an explicit transport option.

### Key Empirical Findings
1. **Connection Burst Latency (WAN Impairment)**: Under a burst of 32 concurrent requests against a pool size of 8:
   - At **20 ms RTT**: HTTP/2 CONNECT p50 is **42.5 ms** and QUIC p50 is **48.0 ms** (both stream multiplexed without new connection dials). WireGuard achieves **65.6 ms** p50 (incurring a 1-RTT netstack TCP handshake over the tunnel), whereas TCP Pool degrades to **155.2 ms** p50 / **250.3 ms** p99 (~3.2x higher latency) due to pool exhaustion stalls on new dials.
   - At **50 ms RTT**: HTTP/2 CONNECT p50 is **102.8 ms**, QUIC p50 is **114.2 ms**, and WireGuard p50 is **156.5 ms**, whereas TCP Pool degrades to **404.0 ms** p50 / **609.3 ms** p99 (~2.6x–3.9x higher latency).
2. **Loopback TTFB with Warm Pool**: On loopback with a warm pre-dialed pool, TCP Pool achieves a faster TTFB (**1.03 ms**), HTTP/2 CONNECT achieves **1.13 ms**, QUIC achieves **1.20 ms**, and WireGuard achieves **1.48 ms**. This is expected because loopback hides connection-dialing penalties, and the pre-dialed TCP connection is already waiting in memory.
3. **Frontend CPU per Byte at Saturation**: Under sustained bulk transfer saturation on loopback, the frontend process uses **~3.40 CPU-seconds per GB** with **HTTP/2 CONNECT**, **~3.95 CPU-seconds per GB** with **TCP Pool**, **~13.35 CPU-seconds per GB** with **QUIC**, and **~39.56 CPU-seconds per GB** with **WireGuard** (total process CPU across frontend and backend: ~8.41 s/GB for H2, ~7.52 s/GB for TCP Pool, ~19.78 s/GB for QUIC, and ~115.51 s/GB for WireGuard).
4. **Connection Setup Allocations**: QUIC and HTTP/2 achieve **~1,138–1,144 allocs/conn**, WireGuard achieves **~1,522 allocs/conn**, and TCP Pool uses **~2,061 allocs/conn**.

---

## 2. Benchmark Methodology

### Symmetrical Test Conditions
Previous benchmarks compared a hand-rolled raw QUIC loop against an `http.Server` TCP pool backend. The harness in `snigateway/pkg/frontend/benchmark_test.go` evaluates both transports under **identical conditions**:
- A real `http.Server` behind `tls.NewListener` attached to `tunnel.NewManager(c, tunnel.WithTransport(...))` for both QUIC and TCP Pool.
- The same mTLS certificate validation, session registration, PROXY protocol v2 header parsing, and client TLS handshakes.

### Measured Metrics
- **Time to First Byte (TTFB)**: p50 and p99 latency for establishing a new connection and receiving the first response byte (`p50-ms`, `p99-ms`).
- **Single-Stream Throughput**: 10 MB payload transfer rate (`MB/s`).
- **Concurrent Aggregate Throughput**: 8 concurrent streams (`MB/s`).
- **Connection Burst Latency**: 32 concurrent new connections against pool size 8 under RTT delays.
- **CPU Time per GB**: User + System CPU seconds consumed per gigabyte transferred, measured for the frontend and backend processes separately (`CPU-s/GB`).
- **Allocations**: Mallocs per connection (`allocs/conn`) and mallocs per MB (`allocs/MB`).
- **UDP Buffer Sizes**: System `rmem_max` / `wmem_max` status and quic-go socket buffer warnings.

---

## 3. Benchmark Results

Tests run on Linux `amd64` (AMD EPYC 9B14 60-core processor, Go 1.27.3, commit 90a731b plus this change):

The WireGuard transport was removed after these measurements were recorded.

### 3.1 Loopback Saturation Baseline (Comparable Transport Data)

Measured using standalone harness benchmarks: `BenchmarkLatency_*` for TTFB and connection setup allocations, `BenchmarkThroughput_*` for single-stream throughput and allocations, `BenchmarkThroughput_Concurrent_*` for 8-stream aggregate throughput, and `TestBenchmark_SeparateProcessCPU` for frontend and backend process CPU at saturation in separate processes:

| Metric | QUIC | TCP Pool | HTTP/2 CONNECT | WireGuard | Analysis |
|---|---|---|---|---|---|
| **TTFB (p50, warm pool)** | 1.20 ms | 1.03 ms | 1.13 ms | 1.48 ms | TCP pool & H2 fastest; WireGuard incurs userspace netstack processing |
| **TTFB (p99, warm pool)** | 1.59 ms | 2.11 ms | 1.48 ms | 2.18 ms | All four transports around ~1.5–2.2 ms on loopback |
| **Connection Setup Allocations** | 1,138 allocs/conn | 2,061 allocs/conn | 1,144 allocs/conn | 1,522 allocs/conn | H2 & QUIC lowest allocations; WireGuard allocates userspace TCP endpoints |
| **Single-Stream Throughput** | 435 MB/s | 742 MB/s | **791 MB/s** | 86 MB/s | WireGuard throughput constrained by userspace netstack and framing |
| **8-Stream Aggregate Throughput** | 333 MB/s | **3,210 MB/s** | 2,327 MB/s | 72 MB/s | TCP pool & H2 scale across cores; WireGuard event processing bounds stream rate |
| **Throughput Memory Allocations** | 3,322 allocs/MB | **10.5 allocs/MB** | 57.6 allocs/MB | 18,368 allocs/MB | WireGuard buffer/view churn in userspace packet pipelines |
| **Frontend Process CPU (separate proc)** | 13.35 CPU-s/GB | 3.95 CPU-s/GB | **3.40 CPU-s/GB** | 39.56 CPU-s/GB | High userspace netstack and WireGuard framing overhead |
| **Backend Process CPU (separate proc)** | 6.43 CPU-s/GB | **3.57 CPU-s/GB** | 5.01 CPU-s/GB | 75.95 CPU-s/GB | Netstack listener + device encryption/decryption overhead |
| **Total Process CPU (separate proc)** | 19.78 CPU-s/GB | **7.52 CPU-s/GB** | 8.41 CPU-s/GB | 115.51 CPU-s/GB | WireGuard consumes substantially higher CPU per GB than other transports |

### 3.2 Connection Burst Latency (Burst = 32, Pool Size = 4–8)

Measured using `BenchmarkLatency_Burst`. When traffic bursts exceed the warm pool capacity under network RTT, QUIC and HTTP/2 stream multiplexing avoid connection-dialing round trips entirely, while WireGuard incurs 1 RTT for establishing a netstack TCP connection through the tunnel:

| Network RTT | Transport | TTFB p50 | TTFB p99 | Comparison |
|---|---|---|---|---|
| **20 ms RTT** | **HTTP/2 CONNECT** | **42.5 ms** | **83.1 ms** | Zero new dial penalty |
| | **QUIC** | **48.0 ms** | **67.9 ms** | Fast multiplexing |
| | **WireGuard** | **65.6 ms** | **70.6 ms** | 1-RTT dial penalty (netstack TCP handshake over tunnel), ~2.4x faster than TCP pool |
| | TCP Pool | 155.2 ms | 250.3 ms | Pool exhaustion stalls on new dials across RTT |
| **50 ms RTT** | **HTTP/2 CONNECT** | **102.8 ms** | **202.2 ms** | Zero new dial penalty |
| | **QUIC** | **114.2 ms** | **173.5 ms** | Fast multiplexing |
| | **WireGuard** | **156.5 ms** | **158.9 ms** | 1-RTT dial penalty (netstack TCP handshake over tunnel), ~2.6x faster than TCP pool |
| | TCP Pool | 404.0 ms | 609.3 ms | Multi-RTT handshake penalties compound |

### 3.3 Synthetic In-Process Impairment (Sensitivity Analysis)

Measured using `BenchmarkMatrix` with a 10 MB single-stream transfer per scenario and in-process CPU metrics:

> **Methodological Note on In-Process Impairment**:
> The in-process `simulatedPacketConn` wrapper intercepts packets in user space by wrapping `net.PacketConn`. Because the wrapper hides the underlying `*net.UDPConn`, **quic-go automatically disables Generic Segmentation Offload (GSO), Generic Receive Offload (GRO), and batch read/write syscalls (`recvmmsg`/`WriteMsgUDP`)**.
> For WireGuard, the simulated `PacketConn` wraps the controller's WireGuard UDP socket using a batch-size-1 `conn.Bind`. Like QUIC, impaired WireGuard rows lose `recvmmsg`/`sendmmsg` socket batching. Only the controller's socket is impaired, injecting symmetric one-way delay and loss into WireGuard frames comparable to QUIC.
> Meanwhile, the byte-stream `simulatedConn` wrapper for TCP and HTTP/2 models loss as a per-exchange delay or drop on request-response boundaries rather than kernel-level TCP/IP packet drops on a byte stream.
> Therefore, in-process synthetic drop rows reflect **sensitivity analysis under user-space simulated delay/loss** rather than kernel congestion control dynamics (e.g. TCP Reno/Cubic loss recovery vs BBR). Cross-transport kernel-level impairment should be tested with `tc netem`.

| In-Process Scenario | Transport | Throughput | Total CPU / GB | Allocs / MB | Notes |
|---|---|---|---|---|---|
| **RTT 0ms, Loss 0%** | TCP Pool | 741 MB/s | 3.87 s/GB | 10.5 | Loopback baseline |
| | H2 | 766 MB/s | 4.69 s/GB | 199.8 | Framed multiplexing baseline |
| | QUIC | 400 MB/s | 10.02 s/GB | 3,541 | Userspace UDP crypto & event loop |
| | WireGuard | 71.9 MB/s | 70.03 s/GB | 19,854 | Userspace netstack & WireGuard framing |
| **RTT 20ms, Loss 0%** | TCP Pool | 228 MB/s | 4.09 s/GB | 222.1 | Pre-dialed pool |
| | H2 (Pool=4) | 183 MB/s | 3.87 s/GB | 218.8 | High window multiplexing |
| | QUIC | 45.8 MB/s | 26.79 s/GB | 6,499 | Simulated RTT delay |
| | WireGuard | 14.8 MB/s* | 98.45 s/GB | 1,087,091 | Netstack window scaling (measures ~30.5 MB/s and 21,566 allocs/MB in isolated benchmark) |
| **RTT 20ms, Loss 1%** | TCP Pool | 220 MB/s | 4.55 s/GB | 222.1 | Simulated loss delay |
| | H2 (Pool=4) | 181 MB/s | 4.24 s/GB | 221.4 | Multiplexed stream delay |
| | QUIC | 0.90 MB/s* | 56.67 s/GB | 5,744 | Drops with default 208 kiB socket buffer |
| | WireGuard | 0.75 MB/s | 78.92 s/GB | 60,328 | Loss recovery over impaired UDP socket |
| **RTT 50ms, Loss 0%** | TCP Pool | 95.8 MB/s | 4.70 s/GB | 222.1 | Pre-dialed pool |
| | H2 (Pool=4) | 65.8 MB/s | 4.63 s/GB | 218.6 | High window multiplexing |
| | QUIC | 47.2 MB/s | 24.08 s/GB | 6,396 | Simulated RTT delay |
| | WireGuard | 13.7 MB/s | 54.67 s/GB | 21,156 | Netstack window scaling under simulated RTT |
| **RTT 50ms, Loss 1%** | TCP Pool | 95.1 MB/s | 4.58 s/GB | 222.3 | Pre-dialed pool with loss |
| | H2 (Pool=4) | 65.3 MB/s | 4.27 s/GB | 218.9 | Multiplexed stream delay |
| | QUIC | 0.44 MB/s* | 76.54 s/GB | 6,009 | Drops with default 208 kiB socket buffer |
| | WireGuard | 0.30 MB/s | 83.20 s/GB | 42,333 | Loss recovery over impaired UDP socket |

*\*Note on UDP Buffer Sizes*: Under packet loss, quic-go's recovery mechanisms require raised OS socket buffers (`rmem_max` = 7 MiB). Under default Linux container limits (208 kiB), packet loss triggers kernel socket buffer drops.

#### Recommended Kernel-Level Impairment Testing with `tc netem`
To evaluate both transports under identical kernel-level delay and packet loss without disabling NIC offloads or GSO:
```bash
# Apply 20ms delay and 1% loss to loopback interface
sudo tc qdisc add dev lo root netem delay 20ms loss 1%

# Run benchmark suite
go test -run=^$ -bench='BenchmarkThroughput_' ./pkg/frontend

# Remove impairment
sudo tc qdisc del dev lo root
```

---

## 4. CPU Profile Analysis (`cpu.pprof`) at Saturation

CPU profiling with `go tool pprof` during 10 MB saturation transfers reveals the internal bottlenecks of the transports:

### QUIC Transport Hotspots
1. **Linux Syscalls (`linux.Syscall6` 40.6%)**:
   - `UDPConn.WriteMsgUDP` / `sendPacketsWithGSO`: GSO segment transmission.
   - `oobConn.ReadPacket` / `recvmmsg`: reading incoming UDP datagrams in batches.
2. **Single-Threaded Event Loop (`quic-go.(*Conn).run` 29.4%)**:
   - Each `quic.Conn` runs a single event-loop goroutine managing flow control, timers, ACK generation, and stream dispatch. Under high stream throughput, this single goroutine saturates one CPU core.
3. **Userspace Crypto (`crypto/internal/fips140/aes/gcm` ~12%)**:
   - QUIC packets are individually sealed and decrypted with AES-GCM in userspace Go (1.2–1.45 KB per packet).
4. **Copy Path (`io.CopyBuffer` ~16%)**:
   - Splicing QUIC stream bytes into the client TCP socket.

### TCP Pool Transport Hotspots
1. **Syscalls (`linux.Syscall6` 63.4%)**:
   - Kernel TCP `read` and `write` syscalls. Kernel handles packetization, ACKs, retransmissions, and flow control.
2. **TLS Crypto (`crypto/tls.(*Conn).readFromUntil` ~18%)**:
   - Go standard library TLS 1.3 bulk record decryption.
3. **Copy Path (`io.CopyBuffer` ~8%)**:
   - Splicing between the pooled TLS tunnel connection and the client connection.

### WireGuard Transport Hotspots
1. **Userspace TCP/IP Netstack (`gvisor.dev/gvisor/pkg/tcpip` ~35%)**:
   - In-process TCP state machine, segment processing, loss detection, and window management (`transport/tcp`).
   - IPv6 packet processing and packet buffer transfers across the channel interface (`network/ipv6`, `link/channel`).
2. **Linux Syscalls (`linux.Syscall6` / `RawSyscall6` ~24% flat / ~42% cum)**:
   - Batched UDP datagram sending and receiving (`sendmmsg` / `recvmmsg` via `x/net/internal/socket`).
   - Kernel socket I/O for client TLS connections and WireGuard UDP sockets.
3. **WireGuard Device Queues & Encryption (`golang.zx2c4.com/wireguard/device` ~20%)**:
   - `RoutineSequentialSender` and `RoutineSequentialReceiver` managing staged packet queues.
   - ChaCha20-Poly1305 symmetric AEAD packet encryption/decryption (`x/crypto/chacha20poly1305` ~3%).
4. **Buffer & Memory Management (`gvisor.dev/gvisor/pkg/buffer` and `sync.Pool` ~14%)**:
   - Packet buffer views and chunk allocations/recycling between netstack and the TUN interface.

---

## 5. System UDP Buffer Limits (`rmem_max` / `wmem_max`)

During QUIC benchmarks, quic-go logs the following warning:
```
failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB).
See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
```

### Analysis & Mitigation
- The default Linux maximum socket receive/send buffer (`net.core.rmem_max` and `net.core.wmem_max`) is 212,992 bytes (208 kiB).
- quic-go requests up to 7,168 kiB (7 MiB) to maintain line-rate throughput over high Bandwidth-Delay Product (BDP) connections and absorb packet bursts.
- On Linux hosts running `snigateway` in production, raise socket limits:
```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

---

## 6. Optimizations Implemented & Before/After Numbers

### 6.1 Buffer Pooling and 64 KiB Chunks for `spliceConnections`
- **Before**: `spliceConnections` called standard `io.Copy`, which allocated a fresh 32 KiB buffer on every connection in both directions and fell back to 32 KiB `net.genericReadFrom`.
- **After**: Replaced with `io.CopyBuffer` using a `sync.Pool` of 64 KiB byte buffers.
- **Numbers (TCP Pool Throughput on Loopback)**:
  - **Before**: 717.9 MB/s, 3.95 CPU-s/GB, 32 KiB heap allocation per splice.
  - **After**: 731.3 MB/s, 3.93 CPU-s/GB, **0 heap allocations per splice**.

### 6.2 Elimination of `io.MultiReader` Overhead
- **Before**: `proxyproto.Conn` and `sni.PeekedConn` wrapped underlying connections with `io.MultiReader(bytes.NewReader(peeked), conn)`. Even after the peeked bytes were drained, every subsequent read throughout the connection lifetime suffered `io.MultiReader` interface dispatch. Profiling showed this consumed **6.7% of total CPU time**.
- **After**: Implemented direct slice offset draining (`c.buffered[c.bufOffset:]`). Once initial bytes are consumed, `Read()` calls `c.Conn.Read()` directly with zero indirection. Also implemented `io.WriterTo` and `io.ReaderFrom` on `proxyproto.Conn`.
- **Numbers (TCP Pool Throughput on Loopback)**:
  - Eliminated the 6.7% `PeekedConn.Read` CPU hotspot.
  - Retained low memory allocation of 8.4 allocs/MB during bulk transfer.

### 6.3 Elimination of Perpetual `bufio.Reader` in `bufferedConn`
- **Before**: HTTP connection hijacking in `handleConnectionUpgrade` and client tunnel dialing wrapped `rawConn` with a perpetual `bufio.Reader` if handshake bytes were buffered.
- **After**: Drain buffered handshake bytes into a byte slice on upgrade with proper error checking, then read directly from `rawConn`.

### 6.4 Flow-Control Window Configuration
- Preserved standard flow-control window sizes (2 MB initial / 8 MB max stream window, 4 MB initial / 16 MB max conn window) to prevent memory ballooning on high-concurrency multi-tenant frontends.

### 6.5 HTTP/2 CONNECT Framing & Write Buffer Optimizations (#691)
- **Before**: Each write on `serverStreamConn` and `h2StreamConn` triggered individual HTTP/2 DATA framing with an immediate `Flush()`, and frontend writes passed synchronously through unbuffered `io.Pipe`. Under 16 KiB TLS records / 32 KiB chunks, this resulted in 432.6 allocs/MB and high backend CPU. In addition, setting read deadlines in the past caused premature closure of keep-alive stream connections.
- **After**:
  - Eliminated redundant `Flusher.Flush()` calls on `serverStreamConn.Write` for writes $\ge 4096$ bytes, where HTTP/2 framers flush automatically upon completing frame writes without synthetic empty chunks. Small writes ($< 4096$ bytes) continue to flush immediately for interactive streaming (SSE, gRPC, WebSockets).
  - Stream `Read` and `Write` are completely decoupled without shared mutex locks, preventing read deadlocks during flow-controlled writes.
  - Implemented `io.WriterTo` and `io.ReaderFrom` on both `h2StreamConn` and `serverStreamConn` using pooled 64 KiB buffers (`h2CopyBufPool` and `h2SpliceBufPool`), matching the existing splice buffer size and only taking pooled buffers once the first read returns data.
  - Implemented non-destructive deadline handling in `SetReadDeadline` and `SetWriteDeadline` so HTTP keep-alive requests can reuse active streams without tearing down underlying connections.
- **Numbers (HTTP/2 CONNECT Saturation on Loopback)**:
  - **Memory Allocations**: Reduced from **432.6 allocs/MB** to **324.6 allocs/MB** (single stream) and **284.2 allocs/MB** (concurrent).
  - **Connection Setup Allocations**: **1,124 allocs/conn** (lowest of all transports).
  - **Single-Stream Throughput**: **451 MB/s** (surpassing QUIC 432 MB/s).
  - **8-Stream Throughput**: **1,259 MB/s** (3.4x faster than QUIC 373 MB/s).
  - **Burst Latency (20ms RTT)**: **62.0 ms p50** (matches QUIC 59.3 ms, 2.5x faster than TCP pool 156.8 ms).

### 6.6 Coalescing Queued HTTP/2 Tunnel Writes into Right-Sized Frames (#712)
- **Problem**: In #705 merged, GARI handed the tunnel 16 KiB TLS records and each became its own HTTP/2 DATA frame with independent framing overhead and window updates, resulting in 324.6 allocs/MB and capping single-stream throughput at ~451 MB/s. Buffering writes on timers or holding data while idle stalled streaming probes and interactive backends.
- **Design: Coalesce only what is already queued**:
  - **Frontend (`h2StreamConn`)**: Replaced `io.Pipe` with `api.H2ChunkQueue` used directly as the CONNECT request body (`req.Body`). `Write` appends incoming chunks to a 256 KiB bounded queue using pooled buffers, blocking when the queue bound is reached (backpressure). `Read(p)` drains all queued chunks into `p` up to the scratch frame size in a single pass. Under load, multiple 16 KiB records are coalesced into a single right-sized DATA frame (up to 256 KiB), while idle streaming probes (e.g. 13-byte ping) return immediately without delay.
  - **Backend (`serverStreamConn`)**: Uses the stream's handler goroutine as the drainer loop (`RunDrainLoop`). `Write` appends to `api.H2ChunkQueue`; the drainer loop waits for data, takes all queued chunks via `TakeAll(&drainBuf)`, copies into a reused contiguous buffer sized to the backlog, and issues one `Write`, flushing immediately only for small writes ($< 4096$ bytes).
  - **Zero Idle Buffering**: Stream memory is strictly proportional to queued bytes with a hard cap of 256 KiB per direction. Idle streams hold zero queued buffers.
  - **Reads never wait on writes**: Decoupled reader and writer pipelines ensure that flow-control blocked writes never stall concurrent stream reads.
- **Numbers (AMD EPYC 9B14 60-core processor, Loopback)**:
  - **Memory Allocations**: Reduced from **324.6 allocs/MB** to **57.1 allocs/MB** (5.7x reduction).
  - **Single-Stream Throughput**: Increased from **451 MB/s** to **841 MB/s** (surpassing TCP pool's 708 MB/s).
  - **8-Stream Aggregate Throughput**: Increased from **1,259 MB/s** to **2,532 MB/s** (2x faster than #705).
  - **Frontend Process CPU**: Reduced to **3.78 CPU-s/GB** (lower than TCP pool's 4.34 CPU-s/GB).
  - **Total Process CPU**: **8.59 CPU-s/GB** (within 5.6% of TCP pool's 8.13 CPU-s/GB).
  - **Burst Latency (20ms RTT)**: **42.5 ms p50** (down from 62.0 ms, ~3.7x faster than TCP pool 157.0 ms).

### 6.7 TLS Session Resumption & Backend Transport Caching (#724)
- **Problem**: Previously, `buildTransport` was invoked on every request inside `forward` and `mirror`, constructing a new `http.Transport` per request. Every proxied request to a TLS backend suffered a new TCP connection and full TLS handshake (1,000 handshakes per 1,000 requests). In addition, client TLS configs lacked a `ClientSessionCache`, preventing TLS session resumption when new connections were dialed.
- **Optimization**:
  - **Backend Transport Caching**: Cached `http.RoundTripper` per backend (keyed by target address, application protocol, CA cert hash, SANs, and client cert ID), with idle connection closure and cache eviction on route/config changes.
  - **Shared Client Session Cache**: Provided a shared LRU `tls.ClientSessionCache` across all backend TLS configs in `pkg/proxy` and `snigateway/pkg/certs` (with client credential isolation to prevent cross-identity resumption).
  - **Shared Server Session Callbacks**: Shared `WrapSession`/`UnwrapSession` callbacks across HTTPS servers, HTTP/3 servers, and TLSRoute terminate paths backed by a dedicated proxy ticket configuration, enabling cross-protocol resumption (TCP ↔ HTTP/3) without sharing mutable config state.
  - **Validated Listener Resumption**: Enabled session tickets on `AllowValidOnly` listeners by binding the listener's CA set hash into the ticket payload via `WrapSession` and refusing to resume in `UnwrapSession` when the CA set changes.
- **Numbers (AMD EPYC 9B14, `BenchmarkProxy_TLSBackend_Handshakes`)**:
  - **Handshakes per 1,000 requests to a TLS backend**:
    - **Before**: 1,000 handshakes (1 handshake / request due to per-request `http.Transport` rebuild)
    - **After**: 1 handshake (connection reuse via keep-alive; subsequent dials resume via `ClientSessionCache`, a 1,000x reduction in handshakes)

---

## 7. Open Architectural Discussion: TLS Redundancy vs Metadata Security

### The Redundancy Question
In SNIGateway, client traffic is already end-to-end TLS between the client and the backend pod. Tunneling this traffic over mTLS (either TCP pool TLS or QUIC TLS) means the payload is encrypted twice in userspace.

### Security Trade-Offs
1. **Authentication & Authorization**: The reverse tunnel connection must be mutually authenticated (mTLS) so the frontend can verify client identity (cluster/backend identity and CA allowlist).
2. **Metadata Confidentiality**: The PROXY protocol v2 header carries sensitive connection metadata:
   - Client source IP and port.
   - Target SNI hostname and cluster authority TLVs.
   If the tunnel were unencrypted (integrity-only), this metadata would transit the network in plaintext.
3. **Transport Security Standards**: TLS 1.3 does not define null-cipher authentication modes. Standard TLS ciphers (`TLS_AES_128_GCM_SHA256`) utilize hardware AES-NI instructions and provide guaranteed end-to-end security without custom cryptographic protocols.

### Conclusion
Maintain standard mTLS encryption for both TCP pool and QUIC tunnels. Tunnel overhead should be mitigated through userspace buffer pooling and transport selection rather than compromising metadata confidentiality.
