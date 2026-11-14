# Design: localgateway Split into Controller, Data Plane, and DNS

## Summary

This document specifies the split of `localgateway` from an all-in-one host-network pod into three decoupled components:

1. **Controller**: Reconciles Gateway API resources and Secrets, provisions per-Gateway data planes, and compiles data-plane configurations. It runs as a standard in-cluster Deployment without host networking and never exposes ports outside the cluster.
2. **Gateway data plane**: Serves client traffic on the LAN using the reference implementation's standard per-Gateway data-plane pod (`--dataplane-mode`). It receives and holds only its own Gateway's configuration.
3. **DNS**: Runs a standalone mDNS responder daemon with host networking. It answers multicast queries for single-label `.local` domains on the LAN without reading Secrets.

**The Core Rule**: No Secret-reading process listens on the host network.

## 1. LAN Exposure: Host Ports vs. Host Networking

The data plane exposes HTTP (port 80) and HTTPS (port 443) to clients on the local network:

- **Host ports (`hostPort`)**: The pod runs in the standard pod network namespace (`hostNetwork: false`). The Deployment maps host ports 80 and 443 to unprivileged container ports (8080 and 8443). The node's CNI portmap plugin forwards incoming LAN traffic directly to the container ports. The container runs as an unprivileged user without `NET_BIND_SERVICE` or root privileges, and the host network stack remains isolated from the proxy process.
- **Host networking (`hostNetwork: true`)**: The pod runs directly in the host network namespace. The proxy process binds directly to host interfaces on ports 80 and 443. Because ports 80 and 443 are privileged (< 1024), the container requires `securityContext.capabilities.add: [NET_BIND_SERVICE]` (and `allowPrivilegeEscalation: true`) or UID 0. Host networking grants the container access to all host network interfaces. Because the data plane reads its own TLS certificate Secret, host networking places a Secret-holding process directly onto the host network.

The trade-offs and recommendation follow. Host networking avoids CNI portmap overhead and works without CNI port-forwarding support, but grants host network access to the container, requires elevated capabilities, and compromises the network boundary around Secrets. Host ports require CNI portmap support, but preserve network namespace isolation, require no container capabilities, and uphold Secret isolation. The choice between host ports and host networking is the maintainer's; the recommendation is host ports.

## 2. Several Gateways on One Node

Per-Gateway data-plane pods cannot bind conflicting host ports on a single node:

- **One Gateway per port**: The first Gateway scheduled on a node claims host ports 80 and 443. The Kubernetes scheduler rejects scheduling subsequent data-plane pods that request the same host ports on that node (`HostPortConflict`).
- **An address per Gateway**: Each Gateway binds a distinct secondary IP address on the host network. This requires automated LAN IP allocation and host interface configuration rarely available in homelab environments.
- **Documented limit**: Document a limit of one Gateway per node for standard ports. Multi-node clusters distribute Gateways across nodes using pod anti-affinity.

The trade-offs and recommendation follow. An address per Gateway allows multiple Gateways per node on ports 80 and 443, but adds IP management complexity. One Gateway per port enforces first-come, first-served allocation natively via kube-scheduler, while a documented limit clarifies operational boundaries. The choice is the maintainer's; the recommendation is one Gateway per port with a documented limit of one standard Gateway per node. When a second Gateway cannot schedule due to port collisions, the controller reports `Programmed=False` with reason `AddressNotUsable` on the Gateway and `PortUnavailable` on its listeners.

## 3. Component RBAC and Secret Isolation

Each component receives scoped RBAC:

- **Controller**:
  - `gateway.networking.k8s.io`: `gateways`, `gatewayclasses`, `httproutes`, `referencegrants` (`get`, `list`, `watch`, `update`, `patch`).
  - `gateway.networking.k8s.io`: `gateways/status`, `gatewayclasses/status`, `httproutes/status` (`update`, `patch`).
  - `core`: `secrets` (`get`, `list`, `watch` to read referenced TLS certificates; `create`, `update`, `patch` for per-Gateway config Secrets).
  - `core`: `services`, `namespaces`, `configmaps`, `nodes` (`get`, `list`, `watch`).
  - `apps`: `deployments` (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`).
  - `core`, `rbac.authorization.k8s.io`: `serviceaccounts`, `roles`, `rolebindings` (`create`, `update`, `patch`, `delete`).
  - `coordination.k8s.io`: `leases` (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`).
- **Gateway Data Plane**:
  - `core`: `secrets` (`get`, `list`, `watch`) restricted by `resourceNames: ["<gateway-name>"]` in its own namespace.
  - Because Kubernetes RBAC does not authorize `list` and `watch` requests on Secrets with `resourceNames` alone, the data plane reads its Secret the way the reference implementation does today: running under a per-Gateway ServiceAccount with its informer cache restricted by a `metadata.name=<gateway-name>` field selector. The API server authorizes the filtered list and watch calls against the Role's resource name rule, and the data plane receives no access to other Secrets. The design keeps this approach.
- **DNS (mDNS Responder)**:
  - `gateway.networking.k8s.io`: `gateways` (`get`, `list`, `watch`).
  - `core`: `nodes` (`get`, `list`, `watch`).
  - The DNS component holds no RBAC permissions for Secrets. It reads published hostnames from `spec.listeners[*].hostname` and target LAN addresses from `status.addresses`.

## 4. What the Data Plane Holds

The data plane holds only its compiled `DataplaneConfig` loaded from its dedicated per-Gateway Secret (`config.json`). This configuration carries:

- HTTP and HTTPS routing tables (paths, headers, query parameters, backend references).
- TLS certificates and private keys for its own Gateway's listeners.
- Local proxy filter settings (timeouts, client IP preservation).

The data plane cannot read Secrets belonging to other Gateways or other namespaces, has no API access to Gateway API objects, and cannot access host network sockets when using host ports.

## 5. Addresses and Readiness

The architecture reuses the reference implementation's `singlepod.AddressProvider`:

- **Address resolution**: The controller discovers the node's LAN IPv4 and IPv6 addresses via the assigned node's `InternalIP` or configured interface, and publishes them to `Gateway.status.addresses`.
- **Readiness**: When the Gateway reports `Programmed` follows the reference implementation's provider.

## 6. What Is Removed

Splitting the architecture removes the following items:

- The in-process proxy running inside the controller manager.
- The monolithic `localgateway` Deployment running with `hostNetwork: true`.
- The in-process address provider (`localgateway/pkg/address/address_provider.go`) that assumed co-located proxies and reported ready without data-plane health verification.
- In-process mDNS wiring hooks in the controller (`WirePublisher`, `OnGatewaysUpdate`, and `GatewayStatusHook` coupling in `localgateway/cmd/localgateway/main.go`).
