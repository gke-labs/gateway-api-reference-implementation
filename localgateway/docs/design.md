# Design: localgateway Split into Controller, Data Plane, and DNS

## Summary

This document specifies the split of `localgateway` from an all-in-one host-network pod into three decoupled components:

1. **Controller**: Reconciles Gateway API resources and Secrets, provisions per-Gateway data planes, and compiles data-plane configurations. It runs as a standard in-cluster Deployment without host networking and never exposes ports outside the cluster.
2. **Gateway data plane**: Serves client traffic on the LAN using the reference implementation's standard per-Gateway data-plane pod (`--dataplane-mode`). It receives and holds only its own Gateway's configuration.
3. **DNS**: Runs a standalone mDNS responder daemon with host networking as a data plane. It answers multicast queries for single-label `.local` domains on the LAN, reading only the `localgateway-dns` Secret and watching no Gateways. Its Role names only this one object; because the component runs with host networking, it gets the smallest permission that works.

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
  - `core`: `secrets` (`get`, `list`, `watch`) restricted by `resourceNames: ["localgateway-dns"]`.
  - The DNS component is a data plane. The controller computes the DNS records and publishes them in one Secret, `localgateway-dns`, and the DNS component reads that one Secret and nothing else. It watches no Gateways. Because the component runs with host networking, its Role names only this one object so it gets the smallest permission that works.

## 4. What the Data Plane Holds

The data plane holds only its compiled `DataplaneConfig` loaded from its dedicated per-Gateway Secret (`config.json`). This configuration carries:

- HTTP and HTTPS routing tables (paths, headers, query parameters, backend references).
- TLS certificates and private keys for its own Gateway's listeners.
- Local proxy filter settings (timeouts, client IP preservation).

The data plane cannot read Secrets belonging to other Gateways or other namespaces, has no API access to Gateway API objects, and cannot access host network sockets when using host ports.

## 5. Addresses and Readiness: HostPortAddressProvider

The architecture decouples host-port data-plane provisioning from the reference implementation's default provisioner (`pkg/provisioning/singlepod`). A dedicated address provider, `HostPortAddressProvider`, lives in the `localgateway` module and manages host-port data planes.

### 5.1 Architecture & The Seam

`singlepod.AddressProvider` manages single-replica data-plane infrastructure for a Gateway. By default, it provisions a ServiceAccount, Role, RoleBinding, Secret ownership checks, a Deployment, and a LoadBalancer Service whose ingress address populates `Gateway.status.addresses`.

`HostPortAddressProvider` wraps `singlepod.AddressProvider` rather than decomposing `singlepod` into exported building blocks:

- **Why wrapping**: `singlepod` encapsulates per-Gateway RBAC (`ServiceAccount`, `Role`, `RoleBinding`), `Secret` ownership checks, server-side apply (SSA) field management (`FieldManager`), background revision probing, and base container flags (`--dataplane-mode`). Exposing exported building blocks (`ReconcileServiceAccount`, `ReconcileRole`, `ApplyDeployment`, etc.) would leak singlepod's internal orchestration order and error handling. Wrapping maintains singlepod's integrity as a cohesive provisioning engine while delegating host-port specifics to `HostPortAddressProvider`.
- **Comparison with `gcpgateway`**: `gcpgateway` customizes `singlepod` through narrow options (`WithExtraReadinessGates`, `WithPreStopCommand`, `WithExtraVolumes`, `WithTerminationGracePeriodSeconds`). This fits `gcpgateway` because it operates within the standard Service-backed architecture (using `ClusterIP` Services) and delegates cloud load balancing to an external controller. `HostPortAddressProvider` fundamentally diverges from the Service model by binding directly to node host ports, eliminating the Service, enforcing zero-surge rolling updates, and discovering addresses from the scheduled Node.

To support this without embedding host-port knowledge inside `singlepod`, `singlepod` exposes two general-purpose extension hooks:

1. **`WithNoService()`**: Instructs `singlepod` to bypass the creation and reconciliation of `corev1.Service`. When active, `singlepod` checks for any existing Service owned by the Gateway and deletes it, ensuring clean migration when switching provisioning modes.
2. **`WithDeploymentMutator(fn func(deploy *appsv1ac.DeploymentApplyConfiguration, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error)`**: Invoked immediately before `singlepod` applies the Deployment apply configuration. The hook allows the caller to mutate container ports, pod template specs, and deployment strategies before server-side apply.

`HostPortAddressProvider` implements `controller.AddressProvider`, `controller.AddressReadinessProvider`, `controller.AddressTypeProvider`, and `controller.AddressWatcher`. When reconciling a Gateway:
1. It validates listener ports (rejecting conflicting listener configurations before modifying infrastructure).
2. It delegates underlying resource provisioning (RBAC, Secret check, Deployment apply) to the wrapped `singlepod.AddressProvider` configured with `WithNoService()` and the mutator hook.
3. It performs uncached queries against the API server to locate the scheduled data-plane pod and its Node.
4. It computes the Gateway's addresses from the Node's `NodeInternalIP`s and reports readiness based on pod scheduling and Deployment availability.

### 5.2 What Moves: Mapping the Eight `useHostPorts` Branches

All eight `useHostPorts` branches on `main` move out of `pkg/provisioning/singlepod` into `localgateway`:

| Branch on `main` | Original Location in `singlepod/address_provider.go` | Original Behavior | Destination in `localgateway` / `singlepod` |
|---|---|---|---|
| **1. Configuration Option & Struct Field** | Lines 179, 237 (`WithHostPorts()`, `useHostPorts bool`) | Enabled host-port mode on `singlepod.AddressProvider`. | **Removed** from `singlepod`. Replaced by generic options `WithNoService()` and `WithDeploymentMutator()`. `HostPortAddressProvider` lives in `localgateway`. |
| **2. Listener Port Validation** | Line 708 (`if p.useHostPorts`) | Enforced at most one HTTP and at most one HTTPS/TLS port, returning `AddressNotUsable`. | **Moves to `HostPortAddressProvider.GatewayAddressesWithReadiness`**. Validates listeners before calling `singlepod`. Rejects multiple HTTP or HTTPS listeners immediately with `Ready=False`, reason `AddressNotUsable`, and message `"host ports allow one HTTP and one HTTPS port"`. |
| **3. Container Port Mapping** | Line 727 (`if p.useHostPorts`) | Mapped listeners to container ports (8080 HTTP, 8443 HTTPS/TLS, direct TCP/UDP) with `HostPort: int32(port)`, added HTTP/3 UDP host port, and skipped reserved ports. | **Moves to `HostPortAddressProvider` Deployment mutator hook**. Injects container ports with `HostPort` set to the listener port, maps container ports to unprivileged proxy ports, configures HTTP/3 UDP, and skips reserved ports via `state.IsReservedDataPlanePort`. |
| **4. Rolling Update Strategy** | Line 903 (`if p.useHostPorts`) | Set `RollingUpdate` with `maxSurge: 0` and `maxUnavailable: 1` to prevent port collision deadlocks during rollouts on single-node clusters. | **Moves to `HostPortAddressProvider` Deployment mutator hook**. Mutates `deploy.Spec.Strategy` to `RollingUpdate` with `maxSurge: 0` and `maxUnavailable: 1`. |
| **5. Service Deletion on Switch** | Line 939 (`if p.useHostPorts`) | Deleted existing owned Service if found during reconciliation. | **Moves to `singlepod` under `WithNoService()`**. When Service provisioning is disabled, `singlepod` deletes any existing owned Service to guarantee clean transitions away from LoadBalancer/ClusterIP mode. |
| **6. Skip Service Creation** | Line 1005 (`if !p.useHostPorts && len(svcPorts) > 0`) | Bypassed `corev1.Service` construction and apply. | **Moves to `singlepod` under `WithNoService()`**. When active, `singlepod` skips all Service apply logic. |
| **7. Readiness and Address Stub** | Line 1053 (`if p.useHostPorts`) | Returned `nil` addresses and `Ready=False` with reason `AddressNotAssigned`. | **Replaced by `HostPortAddressProvider` address resolution**. Incorporates the node lookup logic from PR #1415: discovers the scheduled pod, queries its Node, extracts internal IPs, and reports `Programmed=True` when the Deployment is ready. |
| **8. Supported Address Types** | Line 1203 (`if p.useHostPorts`) | Returned `nil` so requested `spec.addresses` were rejected with `UnsupportedAddress`. | **Moves to `HostPortAddressProvider.SupportedAddressTypes()`**. Returns `nil`. `singlepod.SupportedAddressTypes()` unconditionally returns `[IPAddressType, HostnameAddressType]`. |

### 5.3 The Address Rule

Each Gateway has one data-plane Deployment with one replica (`replicas: 1`). During a rollout or a node reschedule, two pods can temporarily coexist: the terminating old pod and the newly scheduled pod.

#### Pod Selection Invariants

`HostPortAddressProvider` selects the active pod from `corev1.PodList` using strict precedence rules:

1. **Phase filtering**: Ignore pods in `PodFailed` or `PodSucceeded` phase (e.g., evicted pods).
2. **Owner verification**: Verify that the pod belongs to the Gateway's Deployment through owner references. The pod's controller must be a `ReplicaSet` whose controller is the Gateway's Deployment UID. Unowned pods or pods owned by unrelated ReplicaSets are rejected to prevent label spoofing.
3. **Non-terminating over terminating**: A pod without a `DeletionTimestamp` (`DeletionTimestamp == nil`) takes precedence over a terminating pod (`DeletionTimestamp != nil`). The terminating pod is draining connections and shutting down; the non-terminating pod is the target of the rollout.
4. **Scheduled over unscheduled**: A pod assigned to a node (`Spec.NodeName != ""`) takes precedence over a pod waiting to be scheduled (`Spec.NodeName == ""`).
5. **Newer over older**: If two candidate pods share the same deletion and scheduling status, the pod with the later `CreationTimestamp` is selected.

#### Address and Status Reporting

The Gateway reports addresses and readiness based on the selected pod:

- **When the pod has an assigned node**:
  - The provider reads the assigned Node (`selectedPod.Spec.NodeName`) and collects all addresses with type `corev1.NodeInternalIP`.
  - The addresses are sorted (IPv4 before IPv6, then numerically) and deduplicated.
  - If the Deployment is not yet ready (`ReadyReplicas == 0` and `AvailableReplicas == 0`), the Gateway reports the node's internal addresses, but sets condition `Programmed=False` with reason `Pending` and message `"Waiting for data-plane deployment to become available"`.
  - When the Deployment has at least one ready replica (`ReadyReplicas > 0` or `AvailableReplicas > 0`), the Gateway reports the node's internal addresses with condition `Programmed=True` and reason `Programmed`.
- **While the pod has no node**:
  - When no pod exists, or when the selected pod is unscheduled (`Spec.NodeName == ""`):
  - The Gateway reports **zero addresses** (`addresses: []`).
  - The Gateway sets condition `Programmed=False` with reason `AddressNotAssigned` and message `"Waiting for data-plane deployment to become available"` (or `"Waiting for node address to be assigned to host-port Gateway"` if the Deployment is ready).
  - **Reason**: Without an assigned node, no host port is bound on any node. Reporting a stale node's address would direct LAN traffic to a node where the data plane is absent or terminating.

### 5.4 Update Triggers, Node Lookups, and RBAC Isolation

#### What Triggers an Update

When a data-plane pod moves to another node:

- The controller watches `appsv1.Deployment` using `handler.EnqueueRequestForOwner(..., &gatewayv1.Gateway{})`.
- The controller does **not** maintain informers or watches for all Pods or Nodes in the cluster.
- When the data-plane pod is scheduled, terminates, or reschedules onto another node, the Kubernetes Deployment controller observes the ReplicaSet and Pod status transitions and updates the Deployment's status (`ReadyReplicas`, `AvailableReplicas`).
- This Deployment status update fires the Deployment watch and enqueues the owning Gateway for reconciliation.

#### API Reads for Node Discovery

During reconciliation, `HostPortAddressProvider` reads from the API server using the direct, uncached API reader (`mgr.GetAPIReader()`):

1. **`PodList`**: Lists pods in the Gateway's namespace matching labels `LabelGatewayName` and `LabelAppName`.
2. **`ReplicaSet`**: Reads the candidate pod's controller ReplicaSet by name to verify owner references back to the Deployment.
3. **`Node`**: Reads the assigned Node object directly by name (`selectedPod.Spec.NodeName`) to inspect `status.addresses`.

Using `client.Reader` (uncached GET/LIST) guarantees that the controller does not initialize cluster-wide informers or caches for Pods, ReplicaSets, and Nodes, keeping memory usage minimal.

#### Scoped RBAC Permissions

Permissions are scoped strictly to the component that needs them:

- **`localgateway-controller`** (`localgateway/k8s/controller.yaml`): Holds read access to Pods, ReplicaSets, and Nodes:
  - `core`: `pods` (`get`, `list`)
  - `apps`: `replicasets` (`get`)
  - `core`: `nodes` (`get`, `list`, `watch`)
  - `apps`: `deployments` (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`)
  - `core`: `secrets`, `serviceaccounts`, `roles`, `rolebindings` (per-Gateway data-plane provisioning)
- **`gari-controller`** (`k8s/controller.yaml`): The default reference implementation controller provisions standard LoadBalancer Services. It requires **no** access to `pods`, `replicasets`, or `nodes`. With host ports removed from `singlepod`, the default ClusterRole remains free of Pod and Node permissions.

### 5.5 Port Conflicts Between Gateways

Host ports are node-scoped resources. Port conflicts occur in two scenarios:

#### Intra-Gateway Listener Conflict

A single Gateway configures multiple listeners on conflicting ports (e.g., two HTTP listeners on ports 80 and 8080, or two HTTPS listeners on ports 443 and 8443):

- `HostPortAddressProvider` rejects this before calling `singlepod`.
- It reports condition `Programmed=False` with reason `AddressNotUsable` and message `"host ports allow one HTTP and one HTTPS port"`.
- It reports listener condition `Programmed=False` with reason `PortUnavailable` (or `Conflicted=True`).
- No Deployment is created for the invalid configuration.

#### Inter-Gateway Node Port Collision

Two Gateways request the same host port (e.g., both request port 80 or port 443):

- **Multi-node cluster**: `kube-scheduler` detects `HostPortConflict` on the node running the first Gateway's data-plane pod and schedules the second Gateway's pod onto a different node where the host port is free. Both Gateways become `Programmed=True`, each advertising its assigned node's LAN IP address.
- **Single-node cluster (or all nodes occupied)**:
  - The first Gateway schedules successfully, binds the host port, and reports `Programmed=True` with the node's LAN IP.
  - The second Gateway's pod cannot be scheduled. `kube-scheduler` emits a `FailedScheduling` warning Event on the pod (`0/1 nodes are available: 1 node(s) didn't have free ports for the requested pod ports`).
  - The second Gateway's Deployment has `ReadyReplicas: 0`, and the pod has `Spec.NodeName: ""`.
  - `HostPortAddressProvider` reports `Programmed=False` with reason `AddressNotAssigned` and zero addresses.
  - When port collision prevents scheduling, the controller reports `Programmed=False` with reason `AddressNotUsable` on the Gateway and `PortUnavailable` on its listeners.

### 5.6 Order of Work and Fate of PR #1415

Implementation proceeds in small, sequential steps with one idea each:

- **Step 1: Generic Extension Hooks in `singlepod` (Planned)**:
  - Add `WithNoService()` option to `singlepod.AddressProvider` to bypass Service creation and delete existing owned Services.
  - Add `WithDeploymentMutator()` option to `singlepod.AddressProvider` to allow callers to mutate the `appsv1ac.DeploymentApplyConfiguration` before server-side apply.
  - Add unit tests in `pkg/provisioning/singlepod` verifying that `WithNoService()` and `WithDeploymentMutator()` function without any host-port logic inside `singlepod`.
- **Step 2: Implement `HostPortAddressProvider` in `localgateway` (Planned)**:
  - Create `HostPortAddressProvider` in `localgateway/pkg/address/` wrapping `singlepod.AddressProvider`.
  - Implement listener validation (one HTTP, one HTTPS port limit).
  - Implement the Deployment mutator hook (container ports with `HostPort`, HTTP/3 UDP, `RollingUpdate` with `maxSurge: 0`, `maxUnavailable: 1`).
  - Implement address resolution and pod selection via uncached `client.Reader` (porting the logic from PR #1415: owner verification through ReplicaSet, node lookup, `NodeInternalIP` sorting and deduplication).
  - Implement `SupportedAddressTypes() nil` and watch registration.
  - Add unit tests for `HostPortAddressProvider` in `localgateway`.
- **Step 3: Update `localgateway` RBAC and Wiring (Planned)**:
  - Update `localgateway/k8s/controller.yaml` to grant `localgateway-controller` read access to `pods`, `replicasets`, and `nodes`.
  - Wire `HostPortAddressProvider` into `localgateway/cmd/localgateway/main.go`.
- **Step 4: Clean Up `pkg/provisioning/singlepod` (Planned)**:
  - Remove `WithHostPorts()`, the `useHostPorts bool` field, and all remaining `if p.useHostPorts` branches from `pkg/provisioning/singlepod/address_provider.go`.
  - Remove host-port specific test cases from `pkg/provisioning/singlepod/address_provider_test.go`.

#### Fate of Pull Request #1415

- Pull request #1415 ("singlepod: with host ports, the Gateway's address follows the data-plane pod's node") is **closed without merging** (superseded).
- The node-lookup, pod-selection, and unit-test logic from PR #1415 is not discarded; it is ported directly into `localgateway/pkg/address/` in Step 2.
- The RBAC additions in PR #1415 that granted `pods`, `nodes`, and `replicasets` permissions to `gari-controller` in `k8s/controller.yaml` are abandoned, preserving least-privilege security on the default controller.

### 5.7 Open Questions for the Maintainer

1. **Package Placement within `localgateway`**: Should `HostPortAddressProvider` reside in `localgateway/pkg/address/` (replacing the old in-process address provider currently scheduled for removal) or in a dedicated subpackage such as `localgateway/pkg/hostport/`?
2. **Mutator Hook Granularity in `singlepod`**: Does the maintainer prefer a single `WithDeploymentMutator(func(*appsv1ac.DeploymentApplyConfiguration, *gatewayv1.Gateway, []*state.EffectiveListener) error)` covering container ports and deployment strategy, or two narrower hooks: `WithPodTemplateMutator(...)` and `WithDeploymentStrategy(...)`?
3. **Pod-to-Deployment Verification Strictness**: PR #1415 performs an uncached `reader.Get` on the ReplicaSet to trace owner references from Pod -> ReplicaSet -> Deployment UID. Should `HostPortAddressProvider` retain this check, or is matching Gateway labels (`LabelGatewayName` and `LabelAppName`) sufficient given that data-plane pods run under a dedicated per-Gateway ServiceAccount?
4. **Fallback for Nodes without `NodeInternalIP`**: If a cluster node provides only `NodeExternalIP` (e.g., bare-metal or single-interface edge nodes without an internal IP distinction), should `HostPortAddressProvider` fall back to `NodeExternalIP` or strictly require `NodeInternalIP`?
5. **Default Multi-Node Pod Anti-Affinity**: In multi-node clusters, should `HostPortAddressProvider` inject a soft or hard `podAntiAffinity` (matching `LabelAppName`) into the Deployment pod template to encourage Kubernetes to schedule Gateways onto distinct nodes automatically, or should node placement be left entirely to cluster administrators via annotations?

## 6. What Is Removed

Splitting the architecture removes the following items:

- The in-process proxy running inside the controller manager.
- The monolithic `localgateway` Deployment running with `hostNetwork: true`.
- The in-process address provider (`localgateway/pkg/address/address_provider.go`) that assumed co-located proxies and reported ready without data-plane health verification.
- In-process mDNS wiring hooks in the controller (`WirePublisher`, `OnGatewaysUpdate`, and `GatewayStatusHook` coupling in `localgateway/cmd/localgateway/main.go`).
- The `WithHostPorts` option, `useHostPorts` field, and all host-port branches in `pkg/provisioning/singlepod` (moved to `localgateway/pkg/address.HostPortAddressProvider`).
