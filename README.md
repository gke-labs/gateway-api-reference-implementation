# gateway-api-reference-implementation

A minimal implementation of the Gateway API.

## Goals

The goal of this project is to create a simple, pure Go implementation of the [Gateway API](https://gateway-api.sigs.k8s.io/).

- **Reference Implementation**: This project aims to be a reference implementation rather than a high-performance one. It prioritizes clarity and correctness over speed.
- **Full Feature Support**: We want to support all Gateway API features.
- **Fallback Model**: We are exploring a model where this reference implementation can serve as a fallback for specialized implementations for configurations they cannot accelerate. See [docs/accelerated-operations.md](docs/accelerated-operations.md).
- **Pure Go**: The implementation should be written in pure Go.

## Features

### HTTP/3 (QUIC) Support

GARI supports serving HTTP/3 over QUIC on HTTPS listeners. Gateway API models HTTPS listeners, and GARI can serve the same hostnames, TLS certificates, and HTTPRoutes over both TCP (HTTP/1.1 and HTTP/2) and QUIC (HTTP/3).

HTTP/3 is opt-in and disabled by default.

#### Configuration Options

- **CLI Flags**:
  - `--proxy-http3-bind-address`: UDP address to bind for HTTP/3 (e.g. `:8443`). If empty, HTTP/3 is disabled.
  - `--proxy-http3-advertised-port`: Port advertised in the `Alt-Svc` header on HTTPS (TCP) responses (e.g. `443`). If `0`, the port is inferred from the bind address.

- **Programmatic Options (`pkg/gari.Options`)**:
  - `ProxyHTTP3Addr`: The UDP address string to bind for HTTP/3.
  - `ProxyHTTP3AdvertisedPort`: The port number advertised in `Alt-Svc` headers.
  - `HTTP3PacketConn`: A custom `net.PacketConn` to use for the HTTP/3 server (overriding `ProxyHTTP3Addr`).
  - `HTTP3QUICConfig`: An optional `*quic.Config` for fine-grained QUIC tuning (e.g., MTU / initial packet size).

When HTTP/3 is enabled, HTTPS (TCP) responses automatically include an `Alt-Svc: h3=":<advertised-port>"; ma=86400` header so compatible clients can discover and upgrade to HTTP/3.

### HTTP and HTTPS Support

- **Slow and Idle Client Bounds**:
  - `ReadHeaderTimeout` (default: 10s, configurable via `--read-header-timeout`): Bounds the time allowed to read HTTP request headers and bounds TLS handshakes. Protects against slowloris attacks and stalled TLS handshakes.
  - `IdleTimeout` (default: 60s, configurable via `--idle-timeout`): Maximum amount of time to wait for the next request when keep-alives are enabled. Also sets QUIC `MaxIdleTimeout` for HTTP/3 when not explicitly specified in `HTTP3QUICConfig`.
  - `ReadTimeout` / `WriteTimeout` (default: 0 / disabled, configurable via `--read-timeout` / `--write-timeout`): Unset by default to preserve long-lived streams and slow-progressing response bodies.
- **Forwarded Headers and Trust Policy**:
  Outbound requests across all HTTP forwarding paths (standard forwarding, WebSocket upgrades, and request mirrors) are stamped with consistent forwarded headers:
  - `X-Forwarded-Proto`: Set to `https` when the client connection used TLS or HTTP/3, and `http` for plaintext requests. Any client-supplied value is untrusted and replaced.
  - `X-Forwarded-Host`: When a route applies a `URLRewrite` that modifies the hostname, `X-Forwarded-Host` carries the original pre-rewrite `Host` requested by the client, while the outbound `Host` header carries the rewritten hostname. When no hostname rewrite occurs, `X-Forwarded-Host` is omitted (and any client-supplied `X-Forwarded-Host` is stripped) because the outbound `Host` header already carries the authoritative client `Host`.
  - `X-Forwarded-For`:
    - `append` mode (default): Appends the immediate client IP to any existing `X-Forwarded-For` header. In edge deployments facing untrusted clients, only the rightmost entry added by GARI is trustworthy; earlier entries may have been forged unless GARI is behind an upstream trusted proxy.
    - `replace` mode (`--forwarded-for-mode=replace`): Drops any client-supplied `X-Forwarded-For` header and sets `X-Forwarded-For` solely to the immediate client IP. This ensures backends only receive verified client IPs when GARI is the edge proxy (first hop).
- **Backend TLS Verification**:
  When reaching a backend over TLS:
  - **With a `BackendTLSPolicy`**: The backend TLS certificate is validated against the configured `caCertificateRefs` (or system roots when `wellKnownCACertificates: System`), validating `hostname` and any configured `subjectAltNames`.
  - **Without a `BackendTLSPolicy` (`appProtocol: https`)**: GARI verifies backend certificates against system trust roots by default, setting `ServerName` to the backend Service's cluster DNS name (`<service>.<namespace>.svc.cluster.local`). In-cluster backends using self-signed certificates will fail verification until a `BackendTLSPolicy` names their CA. The route's `ResolvedRefs` condition status message informs the user that system trust roots are being used.
- **All-in-One Mode Limitation**: In all-in-one mode where multiple Gateways share a single controller and proxy process, two Gateways cannot share the same port and hostname for HTTP, HTTPS, or TLS listeners. Hostnames are first-come-first-served across Gateways (by creation timestamp precedence): the first Gateway wins, and any subsequent Gateway listener requesting the same port and hostname reports `Programmed=False` with reason `HostnameConflict` (or `PortUnavailable` for hostname-less listeners). Per-Gateway data plane mode (`singlepod`) is the recommended and conformance path.

### TCP Support (TCPRoute)

GARI supports `TCPRoute` routing raw TCP traffic on dedicated listener ports.

- **Per-Port Listeners & Splicing**: TCP listeners open individual accept sockets per distinct listener port and splice bidirectional TCP traffic to resolved backends immediately upon connection establishment without waiting for client data (safe for backends that speak first).
- **Connection Lifecycle & Limits**: Connections can optionally expire after an idle timeout on the splice (default off / 0s, configurable via `--tcp-idle-timeout`) and are capped per listener (default 10000, configurable via `--tcp-max-connections`). New connections exceeding the cap are refused and closed immediately without evicting active connections.
- **Weighted Routing**: Traffic is distributed across configured backendRefs according to weight; backends with weight `0` receive no traffic.
- **Per-Gateway Data Plane (Default / Conformance)**: In standard deployment (`singlepod`), each Gateway runs its own data plane Deployment and LoadBalancer Service mapping TCP listener ports directly to matching container ports without collapsing onto shared proxy ports.
- **Multiple Attached TCPRoutes**: Because raw TCP has no hostnames or paths to demultiplex on, when multiple TCPRoutes attach to the same TCP listener, only the oldest route's backends receive traffic. Subsequent routes targeting the same listener report `Accepted=True` and contribute to the listener's `attachedRoutes` count, but carry no traffic.
- **All-in-One Mode Limitation**: In all-in-one mode where multiple Gateways share a single controller and proxy process, two Gateways cannot both bind the same TCP port. The first Gateway (by creation timestamp precedence) wins, and any subsequent Gateway listener requesting the same port reports `Programmed=False` with reason `PortUnavailable`. Per-Gateway data plane mode (`singlepod`) is the recommended and conformance path.

### UDP Support (UDPRoute)

GARI supports `UDPRoute` routing UDP datagram traffic on dedicated listener ports.

- **Per-Port Listeners & Client-Address Sessions**: UDP listeners open a `net.PacketConn` per distinct listener port. Sessions are keyed by client address (`IP:port`); the first datagram from a client selects a backend according to configured weights, establishes a connected UDP socket, and forwards subsequent datagrams from that client to the same backend.
- **Weighted Routing**: Traffic is distributed across configured backendRefs according to weight; backends with weight `0` receive no traffic.
- **Session Lifecycle & Limits**: Sessions expire after an idle timeout (default 60s, configurable via `--udp-idle-timeout`) and are capped per listener (default 10000, configurable via `--udp-max-sessions`). New clients exceeding the cap are dropped without evicting active sessions.
- **Per-Gateway Data Plane (Default / Conformance)**: In standard deployment (`singlepod`), each Gateway runs its own data plane Deployment and LoadBalancer Service mapping UDP listener ports directly to matching container ports.
- **Reserved Port**: UDP port 8443 is reserved for HTTP/3; listeners specifying UDP 8443 report `Conflicted=True` with `ProtocolConflict`.
- **All-in-One Mode Limitation**: In all-in-one mode, the first Gateway wins a UDP port; subsequent Gateways requesting the same port report `Programmed=False` with reason `PortUnavailable`.

### Configuration Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--read-header-timeout` | `10s` | Maximum duration allowed to read request headers and complete TLS handshakes on HTTP and HTTPS servers. |
| `--idle-timeout` | `60s` | Maximum duration to wait for the next request on keep-alive connections (and QUIC `MaxIdleTimeout` for HTTP/3). |
| `--read-timeout` | `0s` (disabled) | Maximum duration for reading the entire request, including body. |
| `--write-timeout` | `0s` (disabled) | Maximum duration before timing out response writes. |
| `--tcp-max-connections` | `10000` | Maximum number of concurrent TCP connections per listener. |
| `--tcp-idle-timeout` | `0s` (disabled) | Idle timeout for spliced TCP connections. |
| `--udp-max-sessions` | `10000` | Maximum number of concurrent UDP sessions per listener. |
| `--udp-idle-timeout` | `60s` | Idle timeout for UDP sessions. |
| `--forwarded-for-mode` | `append` | How to handle `X-Forwarded-For`: `append` (default) or `replace`. |
| `--proxy-bind-address` | `:8000` | Address the proxy binds to for HTTP. |
| `--proxy-https-bind-address` | `:8443` | Address the proxy binds to for HTTPS. |
| `--proxy-http3-bind-address` | `""` (disabled) | UDP address the proxy binds to for HTTP/3. |
| `--proxy-http3-advertised-port` | `0` (inferred) | Port advertised in the `Alt-Svc` header for HTTP/3. |

## Contributing

This project is licensed under the [Apache 2.0 License](LICENSE).

We welcome contributions! Please see [docs/contributing.md](docs/contributing.md) for more information.

We follow [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

## Disclaimer

This is not an officially supported Google product.

This project is not eligible for the Google Open Source Software Vulnerability Rewards Program.