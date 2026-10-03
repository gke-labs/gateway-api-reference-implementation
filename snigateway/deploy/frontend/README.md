# Deploying `snigateway-frontend` on a VM

This guide explains how to deploy `snigateway-frontend` on a standalone Linux VM (such as an edge VPS or cloud instance) with a public IP address.

## Prerequisites

- A Linux VM with a public IPv4 or IPv6 address.
- Root or `sudo` access on the VM.
- Go toolchain (if building from source) or Docker (if running as a container).
- Firewall permissions allowing inbound TCP traffic on port 443.

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

If using Docker, you can run the `snigateway-frontend` container image. Note that the container runs as a non-root user (`65532:65532`). To bind to port 443 on the host, use either `--network host` with capability `NET_BIND_SERVICE`, or port mapping `-p 443:8443` with `--listen :8443`:

```bash
docker run -d \
  --name snigateway-frontend \
  --restart always \
  -p 443:8443 \
  -v /etc/snigateway:/etc/snigateway:ro \
  snigateway-frontend:latest \
  --listen :8443 \
  --client-ca /etc/snigateway/ca.crt=* \
  --server-cert /etc/snigateway/server.crt \
  --server-key /etc/snigateway/server.key
```

Or with `--network host` and `--cap-add=NET_BIND_SERVICE`:

```bash
docker run -d \
  --name snigateway-frontend \
  --restart always \
  --network host \
  --cap-add=NET_BIND_SERVICE \
  -v /etc/snigateway:/etc/snigateway:ro \
  snigateway-frontend:latest \
  --listen :443 \
  --client-ca /etc/snigateway/ca.crt=* \
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

The systemd service utilizes `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` to allow the unprivileged `snigateway` user to bind directly to privileged port `443`.

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

### 4. Open Port 443 on Firewall

Ensure port 443 is open for inbound TCP connections on your VM and cloud provider firewall:

- **UFW (Ubuntu/Debian)**:
  ```bash
  ufw allow 443/tcp
  ```
- **Firewalld (RHEL/CentOS/Fedora)**:
  ```bash
  firewall-cmd --permanent --add-port=443/tcp
  firewall-cmd --reload
  ```
- **Cloud Firewall**: In your cloud console (GCP / AWS / Azure), add an ingress firewall rule permitting TCP port 443 from `0.0.0.0/0`.

---

### 5. Point DNS to the VM

Create DNS `A` (and/or `AAAA`) records for your domains pointing to the public IP address of your frontend VM:

- `app.example.com` -> `<VM_PUBLIC_IP>`
- `*.example.com` -> `<VM_PUBLIC_IP>` (optional, for wildcard routing)

Once the in-cluster `snigateway` controller connects to the frontend, HTTPS requests sent to `https://app.example.com` will be multiplexed across the reverse tunnel and served by your Kubernetes workloads.
