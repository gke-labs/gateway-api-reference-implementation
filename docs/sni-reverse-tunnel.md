# Example Accelerator: SNI Front-End with Reverse Tunnels

This document describes the design of the SNI reverse tunnel proxy (`snigateway`), which serves as an example of the "fallback + acceleration" model described in [docs/accelerated-operations.md](accelerated-operations.md) — albeit one based around **functionality offload** (offloading public ingress routing and connection termination) rather than performance offload.

In this model, a lightweight SNI proxy (`snigateway-frontend`) runs on a front-end node (e.g. a public VM or edge node), while clusters located in private networks, behind firewalls, or behind NAT reverse-tunnel the TLS services they want to expose to it.

## Motivation

Exposing a cluster to the internet normally needs a LoadBalancer Service, a
cloud load balancer, or inbound firewall rules to the nodes. Many
environments (home labs, edge sites, clusters behind NAT, dev clusters) have
none of these, but can easily run one small machine with a public address.

The front-end node does not need to understand HTTP, Gateway API, or
certificates. It only needs to:

1. accept TLS connections and read the SNI hostname from the ClientHello, and
2. forward the raw connection to whichever cluster announced that hostname.

## How it works

```
client ──TLS──► front-end node (snigateway-frontend) ══QUIC tunnel stream (or TCP pool) (PROXY v2)══► GARI in cluster ──► backends
                 reads SNI only                                                                         terminates TLS,
                 manages sessions, transports & failover                                                does all routing
```

1. **Announce.** GARI looks at the Gateway listeners it serves (HTTPS/TLS
   listeners with hostnames, and attached routes) and works out the set of
   SNI hostnames the cluster wants to receive.
2. **Backend Sessions & Registration.** The in-cluster controller connects to `snigateway-frontend` at `snigateway.internal` using mTLS (authenticated via a trusted CA).
   - Over **QUIC** (default in `auto` and `quic` modes), the backend opens a QUIC connection with ALPN `snigateway-tunnel/1`. The first stream is the control stream, carrying the session protocol (`SessionResponse` and `RegistrationRequest`). Registrations are scoped to sessions and automatically cleaned up when the QUIC connection ends.
   - Over **TCP** (`tcp` mode or fallback), the backend establishes an HTTP mTLS session (`GET /v1/session`) and registers hostnames (`PUT /v1/registration`).
3. **Tunnel Transports: QUIC & TCP Pool.**
   - **QUIC Stream Multiplexing:** Client connections are tunnelled over lightweight, 0-RTT bidirectional QUIC streams multiplexed inside the single mTLS QUIC connection. There is no head-of-line blocking between streams, no pre-dialed pool to manage, and connections survive backend IP address changes via QUIC connection migration.
   - **Warm Pre-Dialed TCP Pool:** When using TCP transport, each backend maintains a warm pool of $N$ idle pre-dialed mTLS reverse tunnel connections (`POST /v1/tunnel` with `Upgrade: snigateway-tunnel`).
   - **Auto Fallback & Probing:** In `auto` mode (default), the backend tries QUIC first. If UDP is blocked or unreachable, it falls back to the TCP pool, periodically probes QUIC in the background (default 30s), and automatically switches back to QUIC when available without dropping existing connections.
4. **Route by SNI & Activation with PROXY Protocol v2.** When a client connects to the front-end node on `:443`, the SNI proxy peeks at the TLS ClientHello without consuming stream bytes and looks up matching sessions in the registration table (exact matches win over wildcards). The frontend establishes a tunnel connection to a matching session (opening a QUIC stream or popping a pooled TCP connection), writes a PROXY protocol v2 header carrying the real client IP, destination IP, and `PP2_TYPE_AUTHORITY` SNI TLV, writes the peeked ClientHello bytes, and waits for the backend's first response byte.
5. **Health Checking & Failover.** The PROXY header write and response check provide zero-overhead health checking:
   - **Replay until first byte:** If a stream or pooled connection fails or is unresponsive, the frontend drops it and replays the PROXY header and buffered ClientHello to another session (on the same or another healthy replica).
   - **Load balancing:** Connections are distributed across active sessions registered for the hostname.
6. **Terminate in the cluster.** GARI terminates TLS using the certificates
   from the Gateway listener, and then applies normal Gateway API routing. The backend tunnel listener exposes real client IP addresses via `RemoteAddr()`, ensuring correct `X-Forwarded-For` header population.

As the Gateway configuration changes, GARI updates its announcements.

## Transport Tuning

The QUIC transport is tuned for high-bandwidth, high-latency links and rapid NAT traversal:
- **Keepalive period:** 15s (`DefaultQUICKeepAlivePeriod`) to prevent UDP NAT state expiration.
- **Max idle timeout:** 30s (`DefaultQUICMaxIdleTimeout`).
- **Stream receive window:** 2 MB initial / 8 MB max.
- **Connection receive window:** 4 MB initial / 16 MB max.
- **Concurrent streams:** Up to 10,000 concurrent streams (`DefaultQUICMaxIncomingStreams`).
- **GSO (Generic Segmentation Offload):** Enabled automatically on platforms that support UDP GSO.

## Encryption & Security

The client's TLS session goes end-to-end to GARI in the cluster, so the front-end node and the reverse tunnel only ever see ciphertext. The only plaintext they see is the SNI hostname, which is already visible to any on-path observer (absent Encrypted Client Hello). The front-end node never holds private keys for routed domains.

Management operations (`snigateway.internal`) require **mutual TLS (mTLS)**: the front-end verifies client certificates signed by our trusted CAs, ensuring only authorized clusters can register hostnames and claim tunnels. Authorization rules can restrict specific CA fingerprints to designated domain patterns (e.g. `*.team-a.example.com`).

## Relationship to acceleration

This example sits at the "steering" end of acceleration. The front-end
offloads connection acceptance and SNI-level demultiplexing, and GARI
remains the full implementation behind it. It is the simplest case to start
with because it needs no understanding of L7 features at all. Later
accelerated implementations can take on more (for example, terminating TLS
and handling simple HTTPRoutes at the edge), with GARI as the fallback for
everything else.

It also exercises the embedding model: the in-cluster tunnel client is a
small program that embeds GARI. It uses a GARI hook point to learn the
resolved listeners and hostnames, announces them to the front-end, and hands
the tunnelled connections to the embedded GARI proxy. The front-end itself
stays a simple, separate SNI proxy.

## Implementation (`snigateway`)

The `snigateway` module contains the frontend and supporting packages:
- `snigateway/cmd/snigateway-frontend`: The frontend server binary with `generate-certs` subcommand.
- `snigateway/cmd/snigateway`: In-cluster controller binary embedding GARI and reverse-tunnel client with `--tunnel-pool-size`.
- `snigateway/pkg/proxyproto`: PROXY protocol v2 header encoding/decoding and `PP2_TYPE_AUTHORITY` TLV support.
- `snigateway/pkg/sni`: TLS ClientHello sniffing and parsing.
- `snigateway/pkg/frontend`: Registration table, session management, warm pool transport, and failover splicing.
- `snigateway/pkg/certs`: In-memory and on-disk CA/server/client certificate generation.
- `snigateway/pkg/client`: Reusable client library for in-cluster controllers.
- `snigateway/pkg/tunnel`: Tunnel listener, hostname extraction from Gateways, and pool connection manager.
- `snigateway/k8s/`: Kubernetes manifests (RBAC, GatewayClass, Deployment, example Gateway/Route).
