# Deploying `snigateway-frontend` on a VM

This guide explains how to deploy `snigateway-frontend` on a standalone Linux VM (such as an edge VPS or cloud instance) with a public IP address.

## Prerequisites

- A Linux VM running kernel 5.6 or later (in-tree WireGuard support) with a public IPv4 or IPv6 address.
- Root or `sudo` access on the VM.
- Go toolchain (if building from source) or Docker (if running as a container).
- Firewall permissions allowing inbound TCP on port `443` and inbound UDP on the WireGuard port (default `51820/udp`). Kernel WireGuard is the only tunnel transport and there is no fallback; networks that block UDP to this port cannot use `snigateway`.

---

## Deployment Steps

### 1. Install the Binary or Container

#### Option A: Build and Install from Source

From the repository root on the VM:

```bash
cd snigateway
go build -o /usr/local/bin/snigateway-frontend ./cmd/snigateway-frontend
```

Ensure `/usr/local/bin/snigateway-frontend` is executable:

```bash
chmod 755 /usr/local/bin/snigateway-frontend
```

#### Option B: Run via Docker Container

If using Docker, you can run the `snigateway-frontend` container image. Note that the container runs as a non-root user (`65532:65532`). A container that runs this image needs `NET_ADMIN` added, or it can't start (file capabilities like `cap_net_admin+ep` on the binary require `NET_ADMIN` in the bounding set, and in Kubernetes require `capabilities: {add: [NET_ADMIN]}` and `allowPrivilegeEscalation: true` because file capabilities do not apply under no-new-privileges). In addition, ensure the WireGuard UDP tunnel port (default `51820/udp`) is published.

To run with port mapping:

```bash
docker run -d \
  --name snigateway-frontend \
  --restart always \
  --cap-add=NET_ADMIN \
  -p 443:8443 \
  -p 51820:51820/udp \
  -v /etc/snigateway:/etc/snigateway:ro \
  snigateway-frontend:latest \
  --listen :8443 \
  --client-ca /etc/snigateway/ca.crt=*.example.com \
  --server-cert /etc/snigateway/server.crt \
  --server-key /etc/snigateway/server.key
```

Or with `--network host` and capabilities:

```bash
docker run -d \
  --name snigateway-frontend \
  --restart always \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_BIND_SERVICE \
  -v /etc/snigateway:/etc/snigateway:ro \
  snigateway-frontend:latest \
  --listen :443 \
  --client-ca /etc/snigateway/ca.crt=*.example.com \
  --server-cert /etc/snigateway/server.crt \
  --server-key /etc/snigateway/server.key
```

---

### 2. Generate mTLS Certificates

Run the `generate-certs` subcommand to generate the CA, server certificate for `snigateway.internal`, and client certificate/key:

```bash
mkdir -p /etc/snigateway
/usr/local/bin/snigateway-frontend generate-certs --dir /etc/snigateway
```

This creates:
- `ca.crt`, `ca.key`: The shared Certificate Authority.
- `server.crt`, `server.key`: Server certificate for `snigateway.internal`.
- `client.crt`, `client.key`: Client credentials for in-cluster `snigateway` controller authentication.

Secure the generated certificate and key files:

```bash
chmod 600 /etc/snigateway/*.key
chmod 644 /etc/snigateway/*.crt
```

> **Note**: Copy `ca.crt`, `client.crt`, and `client.key` securely to your Kubernetes cluster to create the `snigateway-client-cert` secret.

---

### 3. Create Dedicated User and Install systemd Service

Create a dedicated system user `snigateway`:

```bash
useradd -r -s /bin/false -d /var/empty snigateway
chown -R snigateway:snigateway /etc/snigateway
```

Copy the systemd service file to `/etc/systemd/system/`:

```bash
cp snigateway-frontend.service /etc/systemd/system/snigateway-frontend.service
```

The systemd service grants `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN` so the unprivileged `snigateway` user can bind port `443` and create and configure the kernel WireGuard interface (`wg0`). Without `CAP_NET_ADMIN`, `snigateway-frontend` fails to start.

Two WireGuard flags can be added to `ExecStart` if the defaults do not fit your environment:

- `--wireguard-listen-port` (default `51820`): UDP port for the kernel WireGuard interface. Setting `0` is refused because WireGuard is the only tunnel transport.
- `--wireguard-prefix` (optional): IPv6 `/64` prefix for tunnel addresses (the frontend uses `<prefix>::1` and allocates addresses inside the prefix to connected controllers). If omitted, an RFC 4193 ULA `/64` prefix is generated at startup. A new prefix on restart is fine because controllers re-exchange keys when they reconnect.

Reload systemd, enable, and start the service:

```bash
systemctl daemon-reload
systemctl enable --now snigateway-frontend
```

Verify service status and logs:

```bash
systemctl status snigateway-frontend
journalctl -u snigateway-frontend -f
```

---

### 4. Open Ports 443/TCP and 51820/UDP on Firewall

Ensure inbound TCP port `443` and inbound UDP port `51820` (or the port set by `--wireguard-listen-port`) are open on your VM and cloud provider firewall:

- **UFW (Ubuntu/Debian)**:
  ```bash
  ufw allow 443/tcp
  ufw allow 51820/udp
  ```
- **Firewalld (RHEL/CentOS/Fedora)**:
  ```bash
  firewall-cmd --permanent --add-port=443/tcp
  firewall-cmd --permanent --add-port=51820/udp
  firewall-cmd --reload
  ```
- **Cloud Firewall**: In your cloud console (GCP / AWS / Azure), add ingress firewall rules permitting `443/tcp` and `51820/udp` from `0.0.0.0/0` (or restrict `51820/udp` to your cluster's egress IPs).

---

### 5. Verify the WireGuard Tunnel

Check that the `wg0` interface exists:

```bash
ip link show wg0
```

Once an in-cluster `snigateway` controller connects, inspect the interface with `wg` (from `wireguard-tools`):

```bash
sudo wg show wg0
```

Confirm three things in the output:
- The `wg0` interface is present and listening on your configured UDP port (default `51820`).
- A `peer:` entry appears for each connected controller with its allocated `/128` IPv6 address under `allowed ips`.
- `latest handshake` appears and updates (the controller sends a persistent keepalive every 25 seconds), confirming bidirectional UDP traffic through the firewall.

---

### 6. Point DNS to the VM

Create DNS `A` (and/or `AAAA`) records for your domains pointing to the public IP address of your frontend VM:

- `app.example.com` -> `<VM_PUBLIC_IP>`
- `*.example.com` -> `<VM_PUBLIC_IP>` (optional, for wildcard routing)

Once the in-cluster `snigateway` controller connects to the frontend, HTTPS requests sent to `https://app.example.com` will be multiplexed across the reverse tunnel and served by your Kubernetes workloads. To also accept plaintext HTTP requests and route them by `Host` header (e.g. for HTTP-to-HTTPS redirects or ACME HTTP-01 challenges), specify `--listen-http :80`.
