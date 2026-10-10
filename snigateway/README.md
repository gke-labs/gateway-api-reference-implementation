# SNIGateway

`snigateway` provides a lightweight, pure Go SNI proxy and reverse-tunnel solution for exposing in-cluster TLS services via an external front-end node without terminating TLS for routed services.

## Overview

The `snigateway` architecture consists of two main components:
1. **`snigateway-frontend`**: Runs on a publicly accessible frontend node (e.g. edge node, VPS, or public VM):
   - Listens on TCP and UDP ports (e.g. `:443`).
   - Peeks at the TLS ClientHello of incoming connections to determine the requested SNI hostname without consuming stream bytes.
   - If the SNI hostname is `snigateway.internal`, it serves the mTLS management API and QUIC reverse tunnel listeners (`snigateway-tunnel/1` ALPN).
   - Manages session-scoped hostname registrations and routes across both QUIC streams and pooled TCP connections.
   - Sends PROXY protocol v2 headers (with `PP2_TYPE_AUTHORITY` SNI TLV) on activated connections, carrying real client source/dest IPs.
   - Implements replay-until-first-byte health checking and failover across healthy backend replicas.
2. **`snigateway` (Controller)**: Runs inside a Kubernetes cluster (e.g. home lab, edge site, private network):
   - Embeds GARI (`pkg/gari`) in-process.
   - Connects to frontend via QUIC (default in `--tunnel-transport=auto` and `quic`) or pre-dialed TCP pool (`--tunnel-transport=tcp` with `--tunnel-pool-size`).
   - Automatically falls back from QUIC to TCP pool if UDP is blocked/unreachable, and probes to recover back to QUIC gracefully.
   - Uses GARI's `OnGatewaysUpdate` hook to dynamically register SNI hostnames for its HTTPS/TLS listeners.
   - Feeds reverse-tunnelled connections to GARI's HTTPS proxy server via a custom tunnel `net.Listener`, parsing PROXY v2 headers to expose real client IPs.

---

## Building Container Images

Container images for `snigateway` and `snigateway-frontend` are built from the repository root:

```bash
# In-cluster controller
docker build -f images/snigateway/Dockerfile -t snigateway:latest .

# External frontend proxy
docker build -f images/snigateway-frontend/Dockerfile -t snigateway-frontend:latest .
```

Or using `ap`:

```bash
go run github.com/gke-labs/gke-labs-infra/ap@latest build //...
```

Both images are based on `distroless/static-debian12` and run as an unprivileged non-root user (`65532:65532`).

---

## End-to-End Walkthrough

### 1. Generate Certificates

Generate the CA, server certificate (`snigateway.internal`), and client certificate/key:

**Using Go:**
```bash
go run ./cmd/snigateway-frontend generate-certs --dir certs
```

**Or using Docker:**
```bash
docker run --rm -v $(pwd)/certs:/certs snigateway-frontend:latest generate-certs --dir /certs
```

This generates:
- `ca.crt` / `ca.key`: Self-signed CA
- `server.crt` / `server.key`: Server certificate for `snigateway.internal`
- `client.crt` / `client.key`: Client certificate for mTLS authentication

---

### 2. Run `snigateway-frontend`

Choose one of the following deployment methods depending on your environment. Use `--client-ca` to specify client CA certificate paths and their allowed hostname patterns (e.g. `--client-ca=/path/to/ca.crt='*.example.com,app.example.org'`). If no `--client-ca` flags are provided, `--ca-cert` is used with unrestricted registration (`*`).

#### Option A: Local Development (`go run`)

```bash
go run ./cmd/snigateway-frontend \
  --listen ":8443" \
  --client-ca certs/ca.crt=* \
  --server-cert certs/server.crt \
  --server-key certs/server.key
```

#### Option B: Docker Container

Because the container runs as a non-root user (`65532:65532`), binding to privileged port `:443` inside the container directly requires extra capabilities. We recommend running the container with `--listen :8443` and using Docker port mapping `-p 443:8443`:

```bash
docker run -d \
  --name snigateway-frontend \
  -p 443:8443/tcp \
  -p 443:8443/udp \
  -v $(pwd)/certs:/certs:ro \
  snigateway-frontend:latest \
  --listen :8443 \
  --tunnel-listen-udp :8443 \
  --client-ca /certs/ca.crt=* \
  --server-cert /certs/server.crt \
  --server-key /certs/server.key
```

Alternatively, if running with `--network host` or directly binding `:443`, grant `NET_BIND_SERVICE`:

```bash
docker run -d \
  --name snigateway-frontend \
  --network host \
  --cap-add=NET_BIND_SERVICE \
  -v $(pwd)/certs:/certs:ro \
  snigateway-frontend:latest \
  --listen :443 \
  --client-ca /certs/ca.crt=* \
  --server-cert /certs/server.crt \
  --server-key /certs/server.key
```

#### Option C: Production Linux VM (systemd)

For running on a standalone public Linux VM, see [deploy/frontend/README.md](deploy/frontend/README.md) for full instructions and a systemd unit configuration that uses `CAP_NET_BIND_SERVICE` to bind port `443` securely as a non-root system user.

---

### 3. Create the Client Certificate Secret in Kubernetes

Create a Kubernetes Secret in the cluster containing the CA and client credentials generated in Step 1:

```bash
kubectl create secret generic snigateway-client-cert \
  --from-file=ca.crt=certs/ca.crt \
  --from-file=client.crt=certs/client.crt \
  --from-file=client.key=certs/client.key
```

---

### 4. Deploy `snigateway` Controller

#### Using the Dev Task (Kind / Local Cluster)

To automatically build the image, load it into a local Kind cluster, install the Gateway API CRDs, and apply the controller manifests:

```bash
KUBERNETES_CLUSTER=kind dev/tasks/deploy-snigateway-to-kube
```

#### Manual Deployment

Deploy the controller RBAC, GatewayClass, and Deployment:

```bash
kubectl apply -f snigateway/k8s/controller.yaml
```

Update the `--frontend` argument in `snigateway/k8s/controller.yaml` (or via `kubectl edit deployment snigateway-controller`) to point to the address (`<host-or-ip>:443`) of your `snigateway-frontend` instance.

---

### 5. Create Gateway, HTTPRoute, and Backend

Create a Gateway with an HTTPS listener and TLS certificate, and attach an HTTPRoute:

```bash
# Create TLS secret for your domain (e.g. app.example.com)
kubectl create secret tls example-tls-cert \
  --cert=path/to/app.example.com.crt \
  --key=path/to/app.example.com.key

# Apply example Gateway and HTTPRoute
kubectl apply -f snigateway/k8s/example.yaml
```

---

### 6. Test with `curl`

Send an HTTPS request through the frontend node:

```bash
curl --resolve app.example.com:443:<frontend-ip> https://app.example.com/
```

The TLS handshake will be routed through the reverse tunnel and terminated inside the cluster by GARI.

---

## Components & Packages

- `snigateway/cmd/snigateway-frontend`: Frontend server binary with `generate-certs` subcommand.
- `snigateway/cmd/snigateway`: In-cluster controller binary embedding GARI and reverse-tunnel client with `--tunnel-pool-size`.
- `snigateway/deploy/frontend/`: Systemd unit and VM deployment guide for `snigateway-frontend`.
- `snigateway/pkg/proxyproto`: PROXY protocol v2 header encoding/decoding and `PP2_TYPE_AUTHORITY` TLV support.
- `snigateway/pkg/sni`: TLS ClientHello sniffing and parsing.
- `snigateway/pkg/frontend`: Registration table, session management, warm pool transport, and failover splicing.
- `snigateway/pkg/certs`: In-memory and on-disk CA/server/client certificate generation.
- `snigateway/pkg/client`: Reusable client library for mTLS API and reverse-tunnel dialbacks.
- `snigateway/pkg/tunnel`: Tunnel listener, hostname extraction from Gateways, and pool connection manager.
- `snigateway/k8s/`: Kubernetes manifests (RBAC, GatewayClass, Deployment, example Gateway/Route).
