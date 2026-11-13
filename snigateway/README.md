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

Choose one of the following deployment methods depending on your environment. Use `--client-ca` to specify client CA certificate paths and their allowed hostname patterns (e.g. `--client-ca=certs/ca.crt=*.example.com`). If no `--client-ca` flags are provided, `--ca-cert` is used with unrestricted registration (`*`).

#### Option A: Local Development (`go run`)

```bash
go run ./cmd/snigateway-frontend \
  --listen ":8443" \
  --client-ca certs/ca.crt=*.example.com \
  --server-cert certs/server.crt \
  --server-key certs/server.key
```

> **Note (Development only)**: You may specify `--client-ca certs/ca.crt=*` as a dev-only option to accept any hostname; in a multi-tenant deployment, this allow-all setting lets any backend take over any hostname.

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
  --client-ca /certs/ca.crt=*.example.com \
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
  --client-ca /certs/ca.crt=*.example.com \
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

### Alternative: ServiceAccount Token Authentication (Projected Volumes & JWKS)

Instead of provisioning client certificates and private keys, you can authenticate registrations using projected Kubernetes `ServiceAccount` tokens verified via JWKS:

- **Zero cluster credentials on frontend**: The frontend verifies tokens offline using JWKS (via public OIDC discovery or a local JWKS file).
- **Automatic rotation**: Kubelet rotates projected tokens at 80% of token lifetime. `snigateway` re-reads `--token-file` on every session start, registration, and tunnel dial without restarting the pod.
- **Registration Leases**: Registrations under a token are valid until the token's `exp` (capped at 24h). The client re-registers before expiry; lapsed registrations are dropped and idle sessions are closed.

#### 1. Configure `snigateway-frontend`

Run `snigateway-frontend` with `--jwt-issuer` and `--client-subject` (only one `--jwt-issuer` is supported):

##### GKE Clusters (Public OIDC Discovery)
On GKE, the cluster issuer serves `/.well-known/openid-configuration` and JWKS publicly:

```bash
snigateway-frontend \
  --listen :443 \
  --server-cert certs/server.crt \
  --server-key certs/server.key \
  --jwt-issuer "https://container.googleapis.com/v1/projects/PROJECT/locations/LOCATION/clusters/CLUSTER" \
  --jwt-audience "snigateway" \
  --client-subject "system:serviceaccount:default:snigateway-controller=*.example.com"
```

##### Non-GKE Clusters (Static JWKS File)
For clusters without public OIDC discovery, supply the cluster's JWKS public keys file using `--jwt-jwks-file`:

```bash
snigateway-frontend \
  --listen :443 \
  --server-cert certs/server.crt \
  --server-key certs/server.key \
  --jwt-issuer "https://kubernetes.default.svc" \
  --jwt-jwks-file "/etc/snigateway/cluster-jwks.json" \
  --jwt-audience "snigateway" \
  --client-subject "system:serviceaccount:prod:*=*.prod.example.com"
```

> **Note**: `snigateway-frontend` supports only one `--jwt-issuer`. In `--client-subject`, `<ns>:*` can be used to authorize any ServiceAccount in that namespace.

#### 2. Pod Spec with Projected ServiceAccount Token

Mount the projected token volume with `audience: snigateway` and pass `--token-file` to `snigateway`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snigateway-controller
spec:
  template:
    spec:
      serviceAccountName: snigateway-controller
      containers:
      - name: snigateway
        image: gari-controller:latest
        args:
        - --frontend=frontend.example.com:443
        - --ca-cert=/etc/snigateway/ca.crt
        - --token-file=/var/run/secrets/tokens/snigateway-token
        volumeMounts:
        - name: ca-cert
          mountPath: /etc/snigateway
          readOnly: true
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
      volumes:
      - name: ca-cert
        secret:
          secretName: snigateway-ca
      - name: token
        projected:
          sources:
          - serviceAccountToken:
              path: snigateway-token
              audience: snigateway
              expirationSeconds: 3600
```

When `--token-file` is specified, `--client-cert` and `--client-key` are optional.

---

### 4. Deploy `snigateway` Controller

Before deploying the controller, complete these prerequisites:

1. Install the Gateway API CRDs. For example, run:
   ```bash
   kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
   ```
2. Create the target namespace if it does not already exist, and create the `snigateway-client-cert` Secret in that namespace as shown in Step 3.
3. Set the `--frontend` argument in `snigateway/k8s/controller.yaml` to the address (`<host-or-ip>:443`) of your `snigateway-frontend` instance. `controller.yaml` ships with `--frontend=snigateway-frontend.example.com:443`. Deployment tools apply the manifest as written.

#### Using `ap deploy`

In these commands, `ap` is shorthand for `go run github.com/gke-labs/gke-labs-infra/ap@latest`.

Target the file `snigateway/k8s/controller.yaml`, not the `snigateway` directory. Deploying the directory also applies `snigateway/k8s/example.yaml`, which creates an example Secret, Service, Gateway, and HTTPRoute.

`ap deploy` does not install the Gateway API CRDs. It also does not create the `snigateway-client-cert` Secret in the target namespace.

When you pass `-n <namespace>`, `ap deploy` rewrites `metadata.namespace` on the ServiceAccount and Deployment. It also updates the ServiceAccount subject namespace in the ClusterRoleBinding. The target namespace must already exist in the cluster.

To deploy to a cluster using the cluster's BuildKit daemon without a local Docker daemon, run this example command:

```bash
ap deploy snigateway/k8s/controller.yaml -n <namespace> --cluster <context> --buildkit-host k8s
```

Passing `--buildkit-host k8s` builds the image on the cluster's BuildKit service and pushes it to the registry.

To deploy to a local kind cluster, run this example command:

```bash
ap deploy snigateway/k8s/controller.yaml --cluster=kind://<name>
```

#### Manual Deployment

`snigateway/k8s/controller.yaml` sets `namespace: default` on the ServiceAccount, Deployment, and ClusterRoleBinding subject. To deploy into another namespace with `kubectl`, edit those namespace fields in `controller.yaml` first.

To deploy the manifests directly using `kubectl`, run:

```bash
kubectl apply -f snigateway/k8s/controller.yaml
```

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
