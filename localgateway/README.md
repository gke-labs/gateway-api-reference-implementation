# localgateway

`localgateway` is a Gateway API implementation designed for homelabs and local environments. It embeds the Gateway API Reference Implementation (GARI) as an **all-in-one controller and in-process proxy** running with `hostNetwork: true`.

It is purpose-built to serve single-label `.local` hostnames (such as `grafana.local` or `vault.local`) over HTTP directly from the Kubernetes host network, without requiring cloud load balancers or per-Gateway pod provisioning.

## Architecture

- **All-in-One `hostNetwork` Pod:** Operates as a single pod with `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet`.
- **In-Process Data Plane:** The HTTP proxy runs directly within the controller process and binds to the host's HTTP port (`:80` by default). No separate data-plane Deployments or Services are provisioned.
- **Hostname Rules:**
  - Valid hostnames must be single-label `.local` domains (exactly `<label>.local`, where `<label>` conforms to RFC 1123 DNS label rules).
  - Multi-label `.local` names (e.g. `a.b.local`), foreign domains (e.g. `example.com`), wildcards (`*.local`), and empty hostnames are rejected with condition `Accepted=False` (`Reason: UnsupportedValue`) and `Programmed=False` (`Reason: Invalid`).
  - Standard Gateway API listener/route hostname intersection naturally restricts attached HTTPRoutes to the listener's `.local` hostname.
- **HTTP Only:** `localgateway` currently supports HTTP listeners only. HTTPS/TLS listeners are rejected with condition `Accepted=False` (`Reason: UnsupportedProtocol`) and `Programmed=False` (`Reason: Invalid`).
- **LAN Address Provider:** Populates the node's LAN IPv4 and IPv6 addresses into `Gateway.status.addresses` via `--interface` or Node `InternalIP`.
- **mDNS Publishing from the Data Plane:**
  - Built-in pure-Go mDNS responder based on `golang.org/x/net/dns/dnsmessage`.
  - Automatically publishes served `.local` hostnames on the LAN over mDNS (multicast UDP `224.0.0.251:5353` and `[ff02::fb]:5353`), so devices on the network resolve `grafana.local` to the gateway with no manual DNS configuration.
  - **Port 5353 Ownership:** `localgateway` owns UDP port 5353 on the node. Any host `avahi-daemon` or systemd-resolved mDNS must be stopped or bound elsewhere; `localgateway` will fail clearly at startup if port 5353 is already taken.
  - **RFC 6762 Probing & Conflict Detection:** Probes before claiming a name. If another host on the LAN already responds to the name, `localgateway` stops the claim, reports `Published=False` and `Conflicted=True` with reason `HostnameConflict` on the listener status, and periodically retries.
  - **Lifecycle Management:** Sends unsolicited mDNS announcements when claiming a name, re-announces when interface addresses change, and sends goodbye (TTL 0) packets when a listener or Gateway is deleted and during graceful shutdown.
  - **Status Reporting:** Provides a `Published` condition on each listener indicating whether its hostname is published, probing, in conflict, or rejected.
- **Privileged Port 80 on hostNetwork:** The container image has `cap_net_bind_service=+ep` set on the binary, allowing non-root UID 65532 to bind port 80 when the container spec includes capability `NET_BIND_SERVICE`. If running in environments where the container runtime does not grant file capabilities, running as root (`runAsUser: 0`) is also supported.
- **Auxiliary Port (8999):** The auxiliary port (8999 by default) exposes readiness and Prometheus metrics without authentication, so on a shared LAN restrict it with a host firewall rule (it exposes no configuration or secrets).

---

## Homelab Quickstart

### 1. Prerequisites

- A standard Kubernetes cluster (kubeadm, kind, etc.).
- Standard Gateway API CRDs installed:
  ```bash
  kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
  ```

### 2. Deploy localgateway

Deploy the controller, RBAC, and `GatewayClass`:
```bash
kubectl apply -f k8s/controller.yaml
```

Verify that the `GatewayClass` is registered and accepted:
```bash
kubectl get gatewayclass localgateway
```

### 3. Create a Gateway and HTTPRoute

Create an example Gateway serving `grafana.local`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: homelab-gateway
  namespace: default
spec:
  gatewayClassName: localgateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    hostname: grafana.local
```

Deploy your application Service and attach an HTTPRoute:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: grafana-route
  namespace: default
spec:
  parentRefs:
  - name: homelab-gateway
  hostnames:
  - grafana.local
  rules:
  - backendRefs:
    - name: grafana-service
      port: 3000
```

Apply the manifests:
```bash
kubectl apply -f gateway.yaml
kubectl apply -f route.yaml
```

### 4. Verify Gateway Status

Inspect the Gateway status to verify that the listener is accepted and programmed, and node LAN addresses are assigned:
```bash
kubectl get gateway homelab-gateway -o yaml
```

### 5. Test Access

Send an HTTP request directly to the node's LAN IP with the configured `.local` host header:
```bash
curl -v -H "Host: grafana.local" http://<NODE_LAN_IP>/
```

---

## Configuration Flags

| Flag | Default | Description |
|---|---|---|
| `--controller-name` | `github.com/gke-labs/gateway-api-reference-implementation/localgateway` | GatewayClass controller name managed by this instance |
| `--proxy-bind-address` | `:80` | Host network address and port for the HTTP proxy |
| `--mdns-port` | `5353` | UDP port for mDNS responder |
| `--interface` | `""` | Network interface to read LAN IP(s) from (e.g. `eth0`). If unset, node addresses are used. |
| `--node-name` | `$NODE_NAME` | Kubernetes node name for resolving fallback LAN addresses |
| `--metrics-bind-address` | `:8999` | Address for Prometheus metrics |
| `--health-probe-bind-address` | `:8999` | Address for `/readyz` and `/healthz` health probes |
| `--leader-elect` | `false` | Enable leader election |
