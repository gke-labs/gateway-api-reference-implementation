# Design: Kernel WireGuard Data Path for SNIGateway

## Context

Benchmarks in [snigateway/BENCHMARKS.md](../BENCHMARKS.md) measured SNIGateway's userspace WireGuard transport (`wireguard-go` device with gVisor's `netstack`). On loopback, userspace WireGuard reached ~86 MB/s bulk throughput at ~116 CPU-s/GB—roughly a tenth of the throughput of the TCP pool and HTTP/2 transports at 14× their CPU per gigabyte. Profiling showed that ~35% of CPU was consumed by netstack's userspace TCP/IP state machine and ~20% by `wireguard-go`'s device queues and crypto.

WireGuard is an attractive reverse-tunnel transport because it provides packet encapsulation and encryption over a single UDP socket, resembling L4 load balancers like Google's Maglev (GRE) and Facebook's Katran (IP-in-IP), but with native encryption. Moving the WireGuard device and TCP stack into the Linux kernel eliminates netstack and userspace crypto overhead. This document details the kernel WireGuard design, privilege trade-offs, fallback semantics, an intermediate TUN option, and a measurement plan before deciding whether WireGuard should become the default transport (#1077).

## 1. Data Path

The kernel data path replaces `wireguard-go` and `netstack` with native Linux `wireguard` network interfaces (e.g. `wg0`) managed via netlink. Traffic inside the tunnel uses the Linux kernel's TCP stack.

```
Frontend (Kernel TCP & WireGuard)                   Controller (Kernel TCP & WireGuard)
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│ Client Conn ──► DialTCP(peerIP) │                 │ ListenTCP(peerIP:51821)         │
│                      │          │                 │         ▲                       │
│             [Kernel TCP Stack]  │                 │ [Kernel TCP Stack]              │
│                      │          │                 │         ▲                       │
│                 [dev wg0]       │                 │     [dev wg0]                   │
│                      │          │                 │         ▲                       │
│             Kernel WireGuard    │                 │  Kernel WireGuard               │
│             (encaps & encrypt)  │                 │  (decrypt & decap)              │
│                      │          │                 │         ▲                       │
└──────────────────────┼──────────┘                 └─────────┼───────────────────────┘
                       │                                      │
                       └────── UDP Datagrams (port 51820) ────┘
```

- **Interface & Peer Configuration**:
  - The frontend and controller create a kernel link of type `wireguard` using rtnetlink (for example, via `vishvananda/netlink`).
  - Device keys, listening UDP ports, peer public keys, endpoints, and allowed IPs are configured via netlink using `golang.zx2c4.com/wireguard/wgctrl`.
- **Tunnel IP Addressing & Routes**:
  - Tunnels use an IPv6 Unique Local Address (ULA) prefix. Hardcoding `fd00::/64` violates RFC 4193 (which requires a pseudo-random 40-bit Global ID) and risks colliding with an operator's existing internal networks. Instead, the prefix is generated per frontend following RFC 4193 (e.g. `fdxx:xxxx:xxxx:1::/64`) or made explicitly configurable via `--wireguard-prefix`.
  - **Frontend**: Assigns `<prefix>::1/64` to `wg0` and adds a route for `<prefix>::/64 dev wg0`. For each registered session, the frontend configures a WireGuard peer with `AllowedIPs = <peer-ip>/128`.
  - **Controller**: When establishing a session, the controller generates an ephemeral X25519 keypair and requests an address via `WireGuardExchange`. The frontend allocates `<peer-ip>/128` (e.g. `<prefix>::2/128`). The controller assigns `<peer-ip>/128` to `wg0`, adds a route to `<prefix>::1/128 dev wg0`, and configures the frontend peer with `AllowedIPs = <prefix>::/64` (or `<frontend-ip>/128`) and a persistent keepalive of 25 seconds.
- **Listen and Dial Roles**:
  - **Controller listens**: The controller binds a standard Go listener to the kernel TCP stack inside the tunnel: `net.Listen("tcp", "[<peer-ip>]:51821")`. Inbound connections are accepted by the kernel and dispatched to GARI's proxy handler.
  - **Frontend dials**: When a client connects on `:443` matching a registered SNI hostname, the frontend dials the backend's kernel TCP socket: `net.DialTCP("tcp", nil, &net.TCPAddr{IP: peerIP, Port: 51821})`.
  - After dialing, the frontend writes the PROXY protocol v2 header and splices client traffic. Because both client and tunnel sockets reside in the kernel, data transfer leverages OS socket buffers and zero-copy splicing (`splice(2)`) without traversing userspace netstack channel copies.

## 2. Privileges & Security Posture

Kernel WireGuard requires elevated privileges to create network links, assign addresses, and manipulate routes:

- **Required Capabilities**:
  - **In-cluster Controller**: Needs `CAP_NET_ADMIN` in the pod's network namespace to create `wg0`, configure IP addresses, and set kernel routing tables.
  - **Frontend**: Needs `CAP_NET_ADMIN` (or root) on the host or container network namespace to create `wg0` and manage peer routes via netlink.
- **Kernel Requirements**: Linux kernel 5.6 or later (which includes in-tree WireGuard support), or earlier kernels with the out-of-tree `wireguard.ko` module loaded.
- **Comparison with Existing Transports**:
  - Today's TCP pool transport runs entirely in userspace with zero Linux capabilities. Controller pods run under the Kubernetes `restricted` Pod Security Standard as non-root (`runAsUser: 65532`).
- **Pod Security Standards (PSS)**:
  - `CAP_NET_ADMIN` is disallowed by both the `restricted` and `baseline` PSS levels (baseline only permits default unprivileged capabilities plus `NET_BIND_SERVICE`). Running the controller pod with kernel WireGuard requires the namespace to be configured with the `privileged` PSS level, or granted an explicit namespace exemption.
- **Scope of `CAP_NET_ADMIN`**:
  - In a standard deployment where the pod does not use `hostNetwork`, `CAP_NET_ADMIN` is scoped strictly to the pod's own network namespace. It allows manipulating only the pod's own interfaces (`wg0`, `eth0`), routes, and iptables/nftables rules; it does not grant permissions to modify the host node's network interfaces, host routing tables, or node-level firewall rules.
- **Trade-off for the Maintainer**:
  - Kernel WireGuard offers significant potential CPU reductions and throughput gains by offloading crypto and TCP processing to the kernel.
  - What is given up is the zero-privilege security boundary: controller pods require `CAP_NET_ADMIN` and a `privileged` PSS level (or namespace exemption), expand exposure to host kernel network vulnerabilities, and introduce a host kernel version dependency.

## 3. Fallback Strategy

To balance operational predictability with ease of deployment, fallback behavior depends on configuration:

- **Explicit Mode (`--tunnel-transport=kernel-wireguard`) -> Fail Clearly**:
  - When an operator explicitly configures kernel WireGuard, the controller and frontend must fail fast at startup if prerequisites are unmet (missing `CAP_NET_ADMIN`, netlink permission denied, or `wireguard` link type unsupported by the kernel).
  - Silent fallback in explicit mode would mask configuration errors and silently drop the system into a high-CPU userspace transport without the operator's knowledge.
- **Automatic Mode (`--tunnel-transport=auto` or `wireguard`) -> Graceful Fallback**:
  - If kernel WireGuard is evaluated as part of the default or auto-selected transport suite, the controller probes kernel WireGuard support at startup by attempting a netlink link creation in its network namespace.
  - If the probe returns `EPERM` or `ENODEV`/`EOPNOTSUPP`, the controller logs an explanatory warning (specifying the missing capability or kernel module) and falls back to HTTP/2 CONNECT (or userspace `wireguard-go` + `netstack`), ensuring unprivileged clusters continue operating cleanly.

## 4. Intermediate Option: `wireguard-go` with a Kernel TUN Device

An intermediate architectural option couples `wireguard-go` with a Linux kernel TUN device (`tun.CreateTUN("wg0", mtu)`) rather than gVisor's netstack:

- **How it Works**: `wireguard-go` manages packet encryption and encapsulation in userspace, but passes raw IP packets to the kernel via `/dev/net/tun`. The controller and frontend bind and dial standard kernel TCP sockets on the TUN interface.
- **Why Measure It**: In [BENCHMARKS.md](../BENCHMARKS.md), netstack accounted for ~35% of saturation CPU, while `wireguard-go` device queues and ChaCha20-Poly1305 accounted for ~20%. Measuring this intermediate option isolates how much CPU cost stems from netstack's userspace TCP/IP implementation versus WireGuard userspace encryption.
- **Trade-offs**: Still requires `CAP_NET_ADMIN` (or permissions on `/dev/net/tun`) to create the TUN device, but does not require in-tree kernel WireGuard module support.

## 5. Measurement Plan

To evaluate kernel WireGuard and the TUN option against existing transports (TCP pool, HTTP/2), benchmarks must run using the established harness in `snigateway/pkg/frontend/benchmark_test.go`:

- **Execution Environment (By Hand)**:
  - Kernel WireGuard and TUN devices require elevated privileges and host network manipulation that are disallowed in standard unprivileged CI runners.
  - Measurements will run **by hand** on a dedicated Linux bare-metal or VM benchmark environment (or via a manually triggered, privileged CI job / script under `dev/tasks/`).
- **Isolation via Network Namespaces**:
  - The harness must execute frontend and backend processes in separate Linux network namespaces (e.g. `ip netns add fe_ns` and `ip netns add be_ns`) linked by a virtual ethernet pair (`veth-fe` <-> `veth-be`).
  - This ensures that both sides can configure distinct `wg0` interfaces, IP addresses, and routing tables without interface name collisions or polluting the host's root network namespace.
- **Metrics to Collect**:
  - Single-stream and 8-stream throughput (MB/s).
  - Process CPU seconds per GB (measuring frontend and backend separately via `getrusage`).
  - Warm-pool TTFB and burst connection latency (p50/p99) under simulated RTT delays using `tc netem` on the `veth` pair.
