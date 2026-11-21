# Design: gcpgateway — GARI with Zonal NEGs behind Layer-4 Google Cloud Load Balancing

## Summary

This document describes the architecture and design of **gcpgateway**: a GARI variant for Kubernetes clusters running on Google Cloud (Google Kubernetes Engine, and kOps or self-managed clusters on Google Compute Engine).

In this architecture:
- Data-plane pods are registered directly as endpoints in **zonal Network Endpoint Groups (NEGs)** (`GCE_VM_IP_PORT`) behind a **layer-4** Google Cloud load balancer (global external proxy Network Load Balancer using a Target TCP Proxy).
- The Google Cloud load balancer operates purely at Layer 4: it does not terminate TLS, holds no certificates, and manages no URL maps. Its sole responsibility is to provide a globally distributed, Anycast static external IP address and forward raw TCP streams to backend pods.
- GARI runs inside the cluster, terminates client TLS, and handles all Gateway API routing (HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute), header transformations, and policy enforcement.
- Client source IP addresses are preserved across the layer-4 proxy using **PROXY protocol v1**, which GARI parses on its HTTP and HTTPS listeners strictly when received from **trusted Google Front End (GFE) source CIDRs**.
- Data-plane listeners enforce **dual CIDR filtering**: only admitting connections from the load balancer CIDRs, and only accepting PROXY headers from trusted GFE CIDRs.
- Rolling updates are protected by a **Pod Readiness Gate** (`gcpgateway.gke-labs.io/load-balancer-ready`) verified against `compute.backendServices.getHealth`. To prevent circular deadlocks, endpoint attachment is decided based on the Pod's **`ContainersReady`** condition.
- Each Gateway has its own dedicated front-end load balancer and zonal NEGs with a unified, 63-character-safe naming scheme incorporating namespace and deterministic hashing. Conflicting Gateway claims are resolved deterministically following Gateway API oldest-timestamp conventions.
- This follows the same architectural pattern as `snigateway` (a dumb front-end proxy coupled with a smart in-cluster GARI data-plane), utilizing native Google Cloud load balancing infrastructure as the front door.

```
                      Internet Clients
                             │
                             ▼  (TCP: 443 / 80)
┌─────────────────────────────────────────────────────────────┐
│          Google Cloud Global External Proxy NLB             │
│  - Global Static IPv4 Anycast Address                       │
│  - Global Forwarding Rule                                   │
│  - Target TCP Proxy (--proxy-header=PROXY_V1)               │
│  - Backend Services (CONNECTION balancing mode)             │
└──────────────┬──────────────────────────────┬───────────────┘
               │ (TCP + PROXY v1 header)      │
               ▼                              ▼
      ┌─────────────────┐            ┌─────────────────┐
      │ Zonal NEG       │            │ Zonal NEG       │
      │ (us-central1-a) │            │ (us-central1-b) │
      └────────┬────────┘            └────────┬────────┘
               │                              │
               ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Kubernetes Cluster (VPC-Native)                │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ gcpgateway Data-Plane Pod (Zone: us-central1-a)     │   │
│   │  - Listeners: 8443 (HTTPS), 8080 (HTTP)             │   │
│   │  - Dual CIDR Gate: only accept from 35.191/16, etc. │   │
│   │  - Strips PROXY v1, recovers real Client IP         │   │
│   │  - GARI terminates TLS, evaluates HTTPRoutes        │   │
│   │  - Dedicated Health Check: 8999 (/_gari/readyz)     │   │
│   │  - Readiness Gate: gcpgateway.../load-balancer-ready│   │
│   │  - Local-only pre-stop drain trigger via sentinel   │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │                              │
│                              ▼                              │
│                  Backend Application Pods                   │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ gcpgateway Controller                               │   │
│   │  - Embeds GARI Controller + NEG Registrar           │   │
│   │  - Attaches pods when ContainersReady == True       │   │
│   │  - Polls backendServices.getHealth -> Sets Gate     │   │
│   │  - Deterministic conflict resolution (oldest wins)  │   │
│   │  - Split Workload Identity Roles (NEG vs Operator)  │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Architectural Decisions & Constraints

The key architectural decisions governing `gcpgateway` are:

### 1. Separate Go Module (`gcpgateway/`)
To preserve GARI's core principle of zero cloud-provider SDK dependencies in the root module, `gcpgateway` lives in its own Go module at `gcpgateway/` (mirroring `snigateway/`):
- Dedicated `gcpgateway/go.mod` requiring the Google Cloud Compute API client (`google.golang.org/api/compute/v1` and `cloud.google.com/go/compute/apiv1`).
- Root module remains pure Go, importing only standard library and standard Kubernetes/Gateway API libraries.
- A local `gcpgateway/go.work` linking `.` and `..` enables seamless local development and multi-module integration.

### 2. Dedicated Kubernetes ServiceAccount & Workload Identity
The `gcpgateway` controller runs under its own Kubernetes ServiceAccount (KSA), e.g., `gcpgateway-controller`.
- Permissions to interact with the Compute Engine API are granted via Google Cloud **Workload Identity Federation for GKE** (or instance metadata / service account keys for non-GKE clusters) split across two least-privilege custom IAM roles:
  - `gcpgatewayNegRegistrar` (Runtime Controller Role): Used by the controller in the cluster to inspect NEGs and backend services, attach/detach endpoints, and query health.
  - `gcpgatewayOperatorHelper` (Provisioning Helper Role): Used by operators or CI/CD pipelines executing `gcpgatewayctl frontend create` and `gcpgatewayctl frontend delete` with full load balancer management permissions.
- Only the controller communicates with the Google Cloud Compute API; data-plane pods run completely unprivileged without cloud credentials.

### 3. Layer 4 Only; GARI Decrypts TLS
The front end is a **global external proxy Network Load Balancer** utilizing a **Target TCP Proxy** (`target-tcp-proxies`):
- Front-end port 443 routes to data-plane port 8443; front-end port 80 routes to data-plane port 8080.
- Each front-end port uses a dedicated backend service configured with protocol `TCP` and `CONNECTION` balancing mode.
- Backends attached to each backend service are zonal `GCE_VM_IP_PORT` NEGs (one per zone in the cluster's region).
- **No TLS certificates, SSL policies, or URL maps exist on the cloud load balancer.** GARI in the cluster terminates TLS, inspects SNI, applies Gateway API certificates, and routes traffic.

### 4. Client IP Preservation via PROXY Protocol v1 with Dual CIDR Filtering
Because the Google Target TCP Proxy terminates client TCP connections and initiates a new TCP connection to the backend pod, the raw IP packet arriving at the pod has a Google Front End (GFE) source IP.
- The Target TCP Proxy is configured with `--proxy-header=PROXY_V1`.
- GARI's root data plane implements generic, opt-in PROXY protocol support (supporting both PROXY v1 text and PROXY v2 binary formats).
- **Dual CIDR Security Mandate**:
  1. `allowedSourceCIDRs`: Listeners drop connections from any source IP outside the configured CIDR list (`35.191.0.0/16, 130.211.0.0/22`). Direct connections from unauthorized cluster workloads or VPC hosts are rejected immediately at the socket level.
  2. `proxyProtocolTrustedCIDRs`: PROXY headers are strictly parsed only from trusted GFE CIDRs (`35.191.0.0/16, 130.211.0.0/22`), preventing client IP spoofing.
- This is configured per Gateway via the existing `parametersRef` ConfigMap mechanism.

### 5. Operator-Owned Infrastructure via gcpgatewayctl
Infrastructure setup and teardown are performed by the Go admin tool `gcpgatewayctl` (`gcpgateway/cmd/gcpgatewayctl`):
- Reserves a global static IPv4 address.
- Creates an HTTP health check on port **8999** with a unique, distinctive request path **`/_gari/readyz`** (preventing false positives from other services).
- Creates zonal NEGs (`GCE_VM_IP_PORT`) in each zone of the cluster's region using a unified naming scheme `{prefix}-{hash}-{port}` (strictly guaranteeing <= 63 characters).
- Creates the backend service(s) with `CONNECTION` balancing mode, connection draining, and attaches the zonal NEGs.
- Creates the Target TCP Proxy with `--proxy-header=PROXY_V1`.
- Creates the global forwarding rule(s) binding the static IP to the Target TCP Proxy.
- Creates VPC ingress firewall rules admitting traffic from `35.191.0.0/16` and `130.211.0.0/22` to pod ports `8443`, `8080`, and `8999`.
- The tool is idempotent and prints the parameters required for the Gateway's `parametersRef` ConfigMap.
- Teardown is performed in exact reverse dependency order via `gcpgatewayctl frontend delete`, verifying metadata ownership before deleting each resource.

### 6. Controller Attaches and Detaches Endpoints Only
The `gcpgateway` controller does not create, modify, or delete Google Cloud Load Balancer resources, forwarding rules, backend services, or NEGs.
- The operator owns the cloud infrastructure lifecycle.
- The controller only dynamically attaches and detaches pod IP/port endpoints to the pre-existing zonal NEGs.
- This restricts the controller's required IAM permissions to endpoint-level operations and health status queries.

### 7. Per-Gateway Dedicated NEGs & Deterministic Conflict Resolution
- **Per-Gateway Identity**: Each `Gateway` has its own front-end load balancer and its own distinct set of zonal NEGs. The NEG names are specified in the Gateway's parameters ConfigMap.
- **Deterministic Conflict Resolution**: If multiple Gateways configure conflicting NEGs, the controller resolves conflicts deterministically: the Gateway with the **oldest `creationTimestamp`** wins (ties broken alphabetically by `namespace/name`). Conflicting later Gateways receive `Accepted=False` with Reason `ConflictingParameters`.
- **Multi-Cluster Safety**: Resource names incorporate a deterministic hash, allowing multiple clusters within the same GCP project to attach their own NEGs to a shared backend service without collision. Strict isolation between clusters can be enforced using GCP IAM Conditions when each cluster uses a distinct `--neg-prefix` (e.g., `--neg-prefix=gcpgw-${CLUSTER_ID}-`).

---

## Component Architecture & Registration Flow

### Binaries and Deployment Topology

`gcpgateway` compiles into a single multi-purpose binary:
1. **Controller Mode (`gcpgateway`)**:
   Runs as a Kubernetes Deployment in the controller namespace. It embeds GARI's controller-runtime manager (using the `singlepod` address provider) and starts the **NEG Registrar**. It serves the internal API over TLS to push configuration directly to data planes.
2. **Data-Plane Mode (`gcpgateway --dataplane-mode`)**:
   Runs as per-Gateway data-plane pods provisioned by GARI's `singlepod` address provider. It serves HTTP (8080), HTTPS (8443), and the health check (8999). Each data plane receives its dynamic route configuration directly from the controller's internal API over an authenticated TLS stream, using the controller's trust bundle mounted from a ConfigMap and an audience-bound projected ServiceAccount token.
3. **Pre-Stop Hook Mode (`gcpgateway hook pre-stop`)**:
   Invoked by Kubernetes as the pod `lifecycle.preStop` hook. It triggers local draining (via local sentinel file `/var/run/gcpgateway/draining`) and sleeps for the backend service draining timeout in pure Go.

### Provisioning Data-Plane Infrastructure

Data-plane Deployments and Services are provisioned using GARI's standard `singlepod` provisioning engine:
- The Gateway references a `ConfigMap` via `spec.infrastructure.parametersRef` specifying `serviceType: ClusterIP`.
- The singlepod provisioner creates a `ClusterIP` Service and a data-plane `Deployment`.
- **Readiness Gate Injection**: The singlepod provisioner injects the Pod Readiness Gate `gcpgateway.gke-labs.io/load-balancer-ready` into `spec.readinessGates`.
- **Internal API Configuration**: The provisioner mounts the trust bundle ConfigMap and a projected ServiceAccount token into the data-plane pod, passing `--internal-api-address`, `--internal-api-ca-file`, and `--internal-api-token-file` so the data plane receives configuration pushed from the controller rather than reading Secrets from the Kubernetes API.
- Kubernetes creates an `EndpointSlice` (`discovery.k8s.io/v1`) for the Service, tracking each data-plane pod's IP, node, and readiness status.

### The NEG Registrar Reconciliation Loop

The NEG Registrar runs inside the `gcpgateway` controller process and executes the following workflow:

```
                  ┌──────────────────────────────┐
                  │    EndpointSlice & Pod Watch │
                  │   (kubernetes.io/service-    │
                  │    name: <gateway-name>)     │
                  └──────────────┬───────────────┘
                                 │ Pod Add / Update / Delete
                                 ▼
                  ┌──────────────────────────────┐
                  │      Endpoint Evaluator      │
                  │ - Pod ContainersReady == True│  <-- Evaluates ContainersReady
                  │ - Not Terminating?           │      (Avoids deadlock with gate)
                  │ - Resolve Node VM & Zone     │
                  │ - Apply Flapping Hysteresis  │
                  └──────────────┬───────────────┘
                                 │
                 ┌───────────────┴───────────────┐
   ContainersReady == True       │               │ ContainersReady == False
   & NOT attached                │               │ or TERMINATING & attached
                 ▼                               ▼
  ┌──────────────────────────────┐ ┌──────────────────────────────┐
  │ Compute API:                 │ │ Compute API:                 │
  │ attachNetworkEndpoints       │ │ detachNetworkEndpoints       │
  │ {instance, ipAddress, port}  │ │ {instance, ipAddress, port}  │
  └──────────────┬───────────────┘ └──────────────┬───────────────┘
                 │                               │
                 ▼                               │
  ┌──────────────────────────────┐               │
  │ Compute API:                 │               │
  │ backendServices.getHealth    │               │
  │ Poll until HEALTHY           │               │
  └──────────────┬───────────────┘               │
                 │                               │
                 ▼                               │
  ┌──────────────────────────────┐               │
  │ Patch Pod Status:            │               │
  │ load-balancer-ready = True   │               │
  │ -> Pod becomes fully Ready   │               │
  └──────────────┬───────────────┘               │
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
                  ┌──────────────────────────────┐
                  │    Gateway Status Sync       │
                  │ - Attached & Healthy > 0?    │
                  │   -> Programmed = True       │
                  │ - Rollout Stalled?           │
                  │   -> Programmed = False      │
                  └──────────────────────────────┘
```

#### Step 1: Endpoint & Node Resolution (Preventing Deadlock)
1. The registrar watches `EndpointSlices` matching the data-plane Service (`kubernetes.io/service-name: <gateway-name>`) and watches the backing `Pod` objects directly (or resolves them via `endpoint.TargetRef`).
2. **Deadlock Prevention Rule**:
   Under Kubernetes readiness gate rules, a Pod's overall `Ready` condition (and therefore `endpoint.Conditions.Ready` in the EndpointSlice) **remains `False`** until all registered readiness gates (`gcpgateway.gke-labs.io/load-balancer-ready`) are set to `True`.
   If the registrar waited for `Conditions.Ready == true` before attaching endpoints, a circular deadlock would occur: the pod would never attach, `backendServices.getHealth` would never test it, and the readiness gate would never flip to `True`.
   Therefore, **attachment eligibility is evaluated strictly against the Pod's `ContainersReady` condition**:
   - `ContainersReady == True` (all containers in the pod passed their local startup/readiness probes).
   - `deletionTimestamp == nil` (pod is not scheduled for deletion).
   - `endpoint.Conditions.Terminating != true`.
3. The registrar resolves the node's GCP zone and Compute Engine instance name:
   - **Zone**: Read from node label `topology.kubernetes.io/zone` (fallback: `failure-domain.beta.kubernetes.io/zone` or `endpoint.Zone`).
   - **Instance Name**: Extracted from `node.spec.providerID` (format `gce://<project-id>/<zone>/<instance-name>`), falling back to `node.metadata.name` (which matches the GCE VM name on GKE and GCE).

#### Step 2: Zonal NEG Endpoint Synchronization
1. The registrar queries the current endpoints in the zonal NEG using `compute.networkEndpointGroups.listNetworkEndpoints`.
2. **Endpoints to Attach**: Pods whose application containers are ready (`ContainersReady == True`), not terminating (`deletionTimestamp == nil`), and not currently present in the zonal NEG.
   The registrar issues:
   ```http
   POST https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/networkEndpointGroups/{negName}/attachNetworkEndpoints
   ```
   Body:
   ```json
   {
     "networkEndpoints": [
       {
         "instance": "projects/{project}/zones/{zone}/instances/{instanceName}",
         "ipAddress": "{podIP}",
         "port": 8443
       }
     ]
   }
   ```
   (And port `8080` if HTTP port 80 is exposed).
3. **Endpoints to Detach**:
   - Pods terminating (`deletionTimestamp != nil` or `Terminating == True`): **immediate detachment**.
   - Running pods that lose container readiness (`ContainersReady == False`): subject to **flapping hysteresis** (15 seconds) before detachment.
   The registrar issues:
   ```http
   POST https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/networkEndpointGroups/{negName}/detachNetworkEndpoints
   ```
   Body:
   ```json
   {
     "networkEndpoints": [
       {
         "instance": "projects/{project}/zones/{zone}/instances/{instanceName}",
         "ipAddress": "{podIP}",
         "port": 8443
       }
     ]
   }
   ```
4. **Operation Polling & Debouncing**:
   Attachment and detachment API calls return a Compute Engine `Operation`. The registrar awaits operation completion (using `compute.zoneOperations.get`) and batches multiple pod changes occurring within a 500ms debounce window.

#### Step 3: Health Verification and Readiness Gate Activation
Once attachment completes:
1. The registrar periodically polls `compute.backendServices.getHealth` for the corresponding backend service and zonal NEG.
2. When the backend service reports the endpoint status as `HEALTHY`:
3. The controller patches the Pod's status conditions via the Kubernetes API:
   ```json
   {
     "status": {
       "conditions": [
         {
           "type": "gcpgateway.gke-labs.io/load-balancer-ready",
           "status": "True",
           "reason": "EnrolledInLoadBalancer",
           "message": "Endpoint attached to zonal NEG and reported HEALTHY by Google Cloud backend service",
           "lastTransitionTime": "2026-10-23T12:00:00Z"
         }
       ]
     }
   }
   ```
4. Kubernetes now evaluates the pod's readiness gates as satisfied, transitions the pod's top-level `Ready` condition to `True`, and marks `endpoint.Conditions.Ready = true` in the EndpointSlice, allowing Kubernetes rolling update progression.

---

## NEG Naming, Ownership, & Conflict Resolution

### Per-Gateway NEG Identity & Hash-Based Naming Scheme

In `gcpgateway`, **each Gateway has its own front-end load balancer and its own dedicated set of zonal NEGs**.
Sharing a single set of NEGs across multiple Gateways in a cluster is strictly forbidden: doing so would cause connections to one Gateway's public IP to be routed to another Gateway's data-plane pods, which do not have its routes, hostnames, or TLS certificates.

#### Naming Scheme (Configured Prefix Plus Hash)
Following the maintainer's direction:
- **Names are the configured prefix plus an 8-character hash**: for example, `gcpgw-<8-char-hash>-<suffix>`.
- The 8-character hash is computed from `cluster_id/namespace/gateway_name`:
  `hash = sha256(f"{cluster_id}/{namespace}/{gateway_name}").hexdigest()[:8]`
- **No readable cluster, namespace, or Gateway names are encoded in the resource name**, and no truncation logic is used.
- Example names:
  - Zonal NEG (HTTPS): `gcpgw-9df5ee22-8443`
  - Zonal NEG (HTTP): `gcpgw-9df5ee22-8080`
  - Backend Service (HTTPS): `gcpgw-9df5ee22-bs-443`
  - Backend Service (HTTP): `gcpgw-9df5ee22-bs-80`
  - Target TCP Proxy (HTTPS): `gcpgw-9df5ee22-proxy-443`
  - Target TCP Proxy (HTTP): `gcpgw-9df5ee22-proxy-80`
  - Forwarding Rule (HTTPS): `gcpgw-9df5ee22-fr-443`
  - Health Check: `gcpgw-9df5ee22-hc`
  - Static IP: `gcpgw-9df5ee22-ip`
  - Firewall Rule: `gcpgw-9df5ee22-allow-gfe`

Total name length is always under 25 characters, safely well below Google Cloud's 63-character limit without requiring any truncation logic.

#### Identity via Resource Description Metadata
NEGs in Google Cloud do not support resource labels. Therefore, **identity lives in metadata on each GCP resource**, stored as JSON in the resource `description` field, as GKE's NEG controller does:
```json
{
  "cluster-id": "cluster-1",
  "namespace": "default",
  "gateway-name": "my-gateway",
  "port": 8443
}
```

#### Metadata-Based Matching and Ownership Protection
- **The controller lists by prefix and matches by metadata**: It lists every NEG with the configured prefix and manages only those whose metadata matches its own cluster ID and the Gateway being reconciled.
- The controller **never infers ownership from the resource name**.
- Any NEG with the prefix but missing, unparseable, or foreign metadata is logged and **never mutated, attached, detached, or pruned**.
- The `gcpgatewayctl frontend create` command writes this identical metadata, and `gcpgatewayctl frontend delete` deletes only resources whose metadata matches.

### Deterministic Conflict Resolution (Gateway API Conventions)

The parameters ConfigMap passed via `parametersRef` specifies the NEG naming pattern:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gcpgateway-params-my-gateway
  namespace: default
data:
  serviceType: ClusterIP
  allowedSourceCIDRs: "35.191.0.0/16,130.211.0.0/22"
  proxyProtocol: "enabled"
  proxyProtocolTrustedCIDRs: "35.191.0.0/16,130.211.0.0/22"
  externalIP: "34.120.254.10"
  negPrefix: "gcpgw-cluster-1-default-my-gateway"
  clusterId: "cluster-1"
  gatewayNamespace: "default"
  gatewayName: "my-gateway"
```

When multiple Gateways in the cluster configure or resolve to conflicting NEG names:
1. **Oldest Timestamp Wins**: The controller follows standard Gateway API conflict resolution: the Gateway with the **oldest `metadata.creationTimestamp`** wins.
2. **Deterministic Tie-Breaking**: If `creationTimestamp` is identical, ties are broken alphabetically by `metadata.namespace + "/" + metadata.name`.
3. **Condition Assignment**:
   - The winning Gateway receives `Accepted=True`.
   - Any conflicting later Gateway receives:
     - `Accepted=False`
     - Reason: `ConflictingParameters`
     - Message: `Zonal NEGs conflict with older Gateway '<winning-namespace>/<winning-name>'. Each Gateway must use a unique set of NEGs.`
4. **Dynamic Recomputation**: The conflict state is evaluated across the current live set of Gateways on every reconciliation pass, guaranteeing deterministic behavior across controller restarts and leader elections.

### Multi-Cluster Shared Frontend & Cluster Isolation

In multi-cluster topologies, an operator can attach NEGs from multiple clusters to a single shared backend service (e.g. for global failover or cross-region traffic distribution):

```
                       ┌─────────────────────────────┐
                       │   Backend Service (:443)    │
                       └──────────────┬──────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            │                                                   │
            ▼                                                   ▼
┌───────────────────────────────┐                   ┌───────────────────────────────┐
│ Zonal NEGs: Cluster A         │                   │ Zonal NEGs: Cluster B         │
│ gcpgw-clusterA-default-gw-8443│                   │ gcpgw-clusterB-default-gw-8443│
│ (us-central1-a, b, c)         │                   │ (us-central1-a, b, c)         │
└───────────┬───────────────────┘                   └───────────┬───────────────────┘
            │                                                   │
            ▼                                                   ▼
┌───────────────────────────────┐                   ┌───────────────────────────────┐
│ Cluster A Data-Plane Pods     │                   │ Cluster B Data-Plane Pods     │
│ Managed by Cluster A Registrar│                   │ Managed by Cluster B Registrar│
└───────────────────────────────┘                   └───────────────────────────────┘
```

#### Isolation Model
- **Convention-based Isolation**: By default, each cluster's controller restricts its API queries and mutations strictly to NEGs matching its configured prefix and owned according to its description metadata.
- **Cryptographic IAM Conditions**: Strict isolation between clusters sharing a GCP project can be enforced via GCP IAM Conditions when each cluster uses a distinct `--neg-prefix` (see Note on IAM Conditions and Multi-Cluster Isolation below).

---

## Readiness, Connection Draining, & Rolling Updates

### Health Checking Architecture

Google Cloud health check probers verify backend health by connecting directly to the pod IP.

| Setting | Value | Rationale |
| --- | --- | --- |
| **Protocol** | HTTP | Plain HTTP GET check; lightweight and reliable. |
| **Port Specification** | `USE_FIXED_PORT` (`--port=8999`) | Probes port 8999 regardless of the serving ports (8443/8080). |
| **Request Path** | `/_gari/readyz` | Distinct, rare probe path avoiding false positives from other services. |
| **Prober Source CIDRs** | `35.191.0.0/16`, `130.211.0.0/22` | Standard Google Cloud health check IP ranges. |
| **Check Interval / Timeout** | `5s` / `5s` | Responsive failure detection. |
| **Healthy / Unhealthy Threshold**| `2` / `2` | Fast convergence without flapping. |

#### Why a Distinct Request Path (`/_gari/readyz`) is Used
Using a common path like `/readyz` or `/healthz` risks a false-positive if the health check accidentally reaches a non-GARI container (for example, if a node IP or port is recycled or if an internal workload responds 200 on port 8999).
By using the distinctive path **`/_gari/readyz`**:
- The prober is guaranteed to validate genuine GARI data planes.
- Other applications that happen to answer `/readyz` or `/` on port 8999 will return 404 to Google Cloud probers, preventing traffic from being misrouted to unready or unrelated pods.

#### Why Port 8999 is Decoupled from Traffic Ports
In `gcpgateway`, port 8443 (HTTPS) expects TLS handshakes and PROXY protocol headers, and port 8080 expects PROXY protocol headers.
Google Cloud HTTP health check probers do **not** send PROXY protocol v1 headers and do not speak TLS to backend HTTP checks.
By binding the health probe handler to port **8999**:
- Health checks run standard HTTP on port 8999 without PROXY protocol encapsulation.
- Data listeners on 8443 and 8080 strictly require and parse PROXY headers from GFE CIDRs.
- Health checks never fail due to PROXY protocol framing or TLS handshake mismatches.
- GARI's `/_gari/readyz` handler returns `200 OK` only when the data plane has received and applied its Gateway routing configuration (`proxySynced == true`) and is NOT in draining mode.

### Safe Rolling Updates via Pod Readiness Gate

#### The Problem: Premature Pod Termination
In standard Kubernetes Deployments, rolling updates terminate old replicas as soon as new replicas pass their container readiness probe.
However, container readiness only indicates that the pod's local processes have started. At that instant:
1. The new pod is not yet attached to the Google Cloud zonal NEG.
2. Even after attachment, Google Cloud load balancers require 10–30 seconds for health check probers to report `HEALTHY`.
3. If attachment fails (due to IAM errors, quota limits, or missing zonal NEGs), the new pod will NEVER receive traffic.
If Kubernetes terminates old pods before new pods are actively enrolled and healthy on Google Cloud, external client traffic is dropped and the Gateway goes down!

#### The Solution: `gcpgateway.gke-labs.io/load-balancer-ready`
To eliminate this failure mode, data-plane pods include a **Pod Readiness Gate**:

```yaml
spec:
  readinessGates:
  - conditionType: "gcpgateway.gke-labs.io/load-balancer-ready"
```

Under Kubernetes pod readiness rules:
- A pod is **NOT Ready** until its container probes pass AND all registered `readinessGates` have status `True`.
- The controller monitors new data-plane pods, attaches them to zonal NEGs once `ContainersReady == True`, and polls `compute.backendServices.getHealth`.
- Only when `backendServices.getHealth` returns `HEALTHY` does the controller patch the pod condition:
  `gcpgateway.gke-labs.io/load-balancer-ready = True`.
- Only then does Kubernetes mark the pod `Ready=True` and proceed with terminating an old replica.

#### Behavior when Readiness Gate Never Becomes True (Stalled Rollout)
If NEG attachment fails (e.g. `PERMISSION_DENIED`, quota exceeded, or `NEGNotFound`) or if health checks fail to reach port 8999:
- The readiness gate remains `False`.
- The Deployment rollout **stalls safely**: Kubernetes will NOT terminate the existing, healthy old pods. Existing traffic continues to be served without downtime!
- The controller detects the stalled pod and surfaces it directly on the Gateway status:
  ```yaml
  conditions:
  - type: Programmed
    status: "False"
    reason: RolloutStalled
    message: "Data-plane pod 'gw-my-gw-xxxx' is not ready in Google Cloud load balancer: backendServices.getHealth reported UNHEALTHY. Existing pods remain active."
  ```

### Termination & Graceful Draining Sequence

To guarantee zero dropped requests during rolling updates, pod rescheduling, or node draining, connection draining is actively coordinated between Google Cloud and the pod:

```
Time  Event                                 Action
 │
 0s   Pod Termination Initiated             Kubernetes marks Pod terminating.
 │                                          EndpointSlice marks Ready=false, Terminating=true.
 │
 0s   preStop Hook Executes in Pod          Kubernetes invokes: gcpgateway hook pre-stop --drain-seconds=35
 │                                          Hook writes local sentinel file /var/run/gcpgateway/draining.
 │                                          /_gari/readyz immediately returns HTTP 503 Service Unavailable ("draining").
 │
 1s   Registrar Detaches Endpoint           Controller calls compute.networkEndpointGroups.detachNetworkEndpoints.
 │                                          Google Cloud Backend Service enters connection draining.
 │
 10s  Health Check Fails on LB              GCP prober receives 2 consecutive 503s on /_gari/readyz.
 │                                          GCP load balancer marks backend UNHEALTHY.
 │                                          GCP ceases sending any new connections to this Pod IP.
 │
 1-35s Connection Drain in Progress         In-flight TCP connections continue to be processed by GARI.
 │                                          Hook process sleeps in pure Go for 35s.
 │
 35s  preStop Hook Finishes                 Hook process exits (code 0).
 │                                          Kubernetes sends SIGTERM to main gcpgateway container process.
 │
 36s  Graceful GARI Shutdown                GARI initiates srv.Shutdown(ctx), closes listeners,
 │                                          and finishes remaining requests within 5s shutdown timeout.
 │
 37s  Container Exits                       Pod terminates cleanly with 0 dropped connections.
```

#### Dual-Channel Fast Cutoff
Notice that the pod stops receiving new connections via two complementary channels in parallel:
1. **API Detach**: The controller calls `detachNetworkEndpoints` upon detecting `Terminating=true` in the EndpointSlice.
2. **Proactive Health Probe Failure**: The `preStop` hook immediately flags the data-plane process to return HTTP 503 on `/_gari/readyz`. Google Cloud's health check probers detect this within 10 seconds and mark the backend UNHEALTHY, cutting off new connections from the load balancer perspective even before the Compute Engine API operation finishes.

#### Local-Only Drain Trigger via Sentinel File
Because port 8999 is opened by the VPC firewall to Google load-balancer ranges, **no external HTTP endpoint (such as `/_gari/drain`) is exposed over port 8999**. Exposing an unauthenticated drain trigger over a network port would introduce a denial-of-service risk.

Instead, the drain trigger is strictly **local to the pod**:
1. An `emptyDir` in-memory volume is mounted at `/var/run/gcpgateway` in the data-plane container.
2. When Kubernetes triggers `lifecycle.preStop`, it runs:
   ```yaml
   lifecycle:
     preStop:
       exec:
         command: ["/gcpgateway", "hook", "pre-stop", "--drain-seconds=35"]
   ```
3. `gcpgateway hook pre-stop`:
   - Writes a sentinel file: `/var/run/gcpgateway/draining`.
   - The health check handler on port 8999 inspects the presence of this file on every probe request. If the file exists, it immediately returns `503 Service Unavailable`.
   - The hook process sleeps for 35 seconds in pure Go (`time.Sleep(35 * time.Second)`).
   - Exits with status 0.
4. This completely avoids shipping `/bin/sleep` or shell utilities in the container image and prevents any external entity from triggering draining.

### Readiness Flapping & Hysteresis Protection

Detaching a pod from a zonal NEG on every momentary `ContainersReady=false` event causes severe problems:
- Compute Engine API has rate limits on zonal operations.
- Flapping back and forth exhausts GCP quotas and produces connection churn.
- Re-attaching requires full health check convergence (10–30s).

`gcpgateway` implements **readiness flapping hysteresis** combined with request debouncing:

1. **Terminating vs Flapping Classification**:
   - **Terminating Pods (`deletionTimestamp != nil` or `conditions.Terminating == true`)**: Detached immediately. Terminating pods never wait for hysteresis.
   - **Running Pods with Transient `ContainersReady=false`**: Subject to a **15-second hysteresis window**.
2. **Hysteresis Workflow**:
   - When a running pod transitions from `ContainersReady=True` to `ContainersReady=False`:
     - The controller does NOT immediately detach the pod from the NEG. Instead, it marks the pod as `pending-detach` with a timestamp.
     - Meanwhile, Google Cloud's external health check prober (`/_gari/readyz`) will independently fail within 10 seconds and mark the endpoint `UNHEALTHY` on the load balancer, pausing traffic without modifying the NEG membership!
     - If the pod recovers to `ContainersReady=True` within 15 seconds, the `pending-detach` state is canceled with zero Compute Engine API calls made.
     - If the pod remains unready for more than 15 seconds, the controller issues `detachNetworkEndpoints`.
3. **500ms Debounce Window**:
   All pending attach and detach operations are coalesced into a 500ms debounce buffer to batch mutations into a single API request per zone.

---

## PROXY Protocol & Trust Model

### Threat Model: PROXY Protocol Spoofing

The PROXY protocol (v1 text specification) prepends an ASCII string to incoming TCP connections:
```
PROXY TCP4 203.0.113.195 34.120.254.10 54321 443\r\n
```
When enabled, the receiving server parses this header, strips it from the stream, and replaces the connection's `RemoteAddr` with the client address specified in the header (`203.0.113.195`).

**Vulnerability**:
If a server accepts PROXY protocol headers from *any* connection, any client able to connect to the pod's IP (e.g., an unauthorized pod inside the cluster or a compromised workload on the VPC) can prepend an arbitrary PROXY header, spoofing any IP address (such as `127.0.0.1` or internal corporate IPs) to bypass authentication, IP allowlists, or rate limits.

### Defense-in-Depth Solution: Dual CIDR Filtering

`gcpgateway` enforces a multi-layer trust model:

```
                        Incoming Connection
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │ Layer 1: VPC Ingress Firewall Rule           │
         │ Only allow TCP: 8443, 8080, 8999 from:       │
         │   35.191.0.0/16, 130.211.0.0/22              │
         └──────────────────────┬───────────────────────┘
                                │ Allowed
                                ▼
         ┌──────────────────────────────────────────────┐
         │ Layer 2: GARI Listener Connection Gate       │
         │ Is conn.RemoteAddr() in allowedSourceCIDRs?  │
         │ (Configured as: 35.191.0.0/16, 130.211.0.0/22│
         └──────────────┬───────────────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          │ YES                       │ NO
          ▼                           ▼
┌───────────────────────────┐ ┌───────────────────────────┐
│ Proceed to Layer 3        │ │ Immediately Close Conn    │
│                           │ │ conn.Close()              │
└─────────────┬─────────────┘ └───────────────────────────┘
              │
              ▼
┌────────────────────────────────────────────────────────┐
│ Layer 3: GARI PROXY Protocol Trust Gate                │
│ Is conn.RemoteAddr() in proxyProtocolTrustedCIDRs?     │
│ (Configured as: 35.191.0.0/16, 130.211.0.0/22)         │
└─────────────┬──────────────────────────────────────────┘
              │
          ┌───┴───────────────────────┐
          │ YES                       │ NO
          ▼                           ▼
┌───────────────────────────┐ ┌───────────────────────────┐
│ Parse PROXY v1/v2 Header  │ │ Do NOT parse PROXY header │
│ Override RemoteAddr to    │ │ Retain real RemoteAddr    │
│ Client IP from header     │ │                           │
└───────────────────────────┘ └───────────────────────────┘
```

1. **Layer 1: VPC Firewall Rules**:
   VPC firewall rules deny direct ingress to data-plane ports `8443`, `8080`, and `8999` from general VPC or external sources, admitting traffic only from the Google Front End (GFE) proxy CIDRs (`35.191.0.0/16` and `130.211.0.0/22`).
2. **Layer 2: Listener Connection Gate (`allowedSourceCIDRs`)**:
   When GARI accepts a TCP connection on its HTTP (8080) or HTTPS (8443) listener:
   - It inspects `conn.RemoteAddr()`.
   - If `allowedSourceCIDRs` is set, and the remote IP does not fall within the configured list, the connection is **immediately closed** (`conn.Close()`) before any TLS handshake or HTTP processing occurs.
   - For `gcpgateway`, this is configured to `35.191.0.0/16, 130.211.0.0/22`. No in-cluster or lateral VPC connection can interact with the server listeners.
3. **Layer 3: PROXY Protocol Trust Gate (`proxyProtocolTrustedCIDRs`)**:
   - If the remote IP is within `proxyProtocolTrustedCIDRs`, the listener wraps the connection in a PROXY protocol reader, parses the PROXY header, and updates `RemoteAddr()` to the client IP.
   - For `gcpgateway`, this is also configured to `35.191.0.0/16, 130.211.0.0/22`.
4. **Root Module Implementation**:
   - Implemented as a reusable, pure Go package in the root module (`pkg/proxyproto` or `pkg/proxy/listener`).
   - Supports both PROXY v1 (ASCII) and PROXY v2 (binary).
   - Zero external cloud dependencies.
   - Usable behind any Layer 4 proxy (Google Cloud Target TCP Proxy, AWS NLB, HAProxy, etc.).

---

## VPC-Native Networking Requirement

Zonal NEGs with `GCE_VM_IP_PORT` endpoints function by programming Google Cloud's software-defined networking (Andromeda) to route packets directly to individual IP addresses in the VPC.

### Requirement
- The Kubernetes cluster **must be VPC-native** (using GCE Alias IP ranges).
- On GKE: Clusters created with `--enable-ip-alias` (standard and default for modern GKE).
- On kOps / self-managed GCE: Clusters configured with GCE IP-alias networking (`networking: gce`).

### Failure Behavior on Non-VPC-Native Clusters
In non-VPC-native clusters (e.g., overlay networks using Calico VXLAN or Flannel without alias IPs):
- Pod IPs belong to an overlay CIDR that is completely unknown to the Google Cloud VPC routing fabric.
- When `attachNetworkEndpoints` is called with an overlay pod IP, the Compute Engine API rejects the request with an error:
  `INVALID_IP_ADDRESS: IP address <pod-ip> does not belong to the instance's network interface subnetwork`.
- Even if attachment were allowed, GFE packets sent to the overlay IP would be dropped by the VPC fabric.

### Controller Detection & Gateway Condition
`gcpgateway` will not silently fail or hang. If a pod IP does not match the node's alias IP range or if `attachNetworkEndpoints` returns an invalid IP address error:
- The controller logs an error indicating the cluster is not VPC-native.
- The Gateway status condition is updated to:
  ```yaml
  conditions:
  - type: Programmed
    status: "False"
    reason: UnsupportedCluster
    message: "Cluster is not VPC-native; pod IP 10.244.1.5 is not an alias IP on instance node-1. gcpgateway requires VPC-native clusters with alias IP ranges."
  ```
- Fallback to instance groups is explicitly **out of scope**.

---

## Gateway Status & Conditions

### Address Reporting

`Gateway.status.addresses` reports the global static external IP of the Google Cloud Load Balancer:
- Resolved from `Gateway.spec.addresses` (type `IPAddress`) if specified.
- If not present in `spec.addresses`, resolved from the `parametersRef` ConfigMap key `externalIP`.
- If neither is provided, `Programmed=False` with reason `AddressNotAssigned`.

### Readiness & Programmed Condition Logic

In standard singlepod `ClusterIP` mode, `Programmed=True` is reported as soon as the Deployment's local replicas become available.
In `gcpgateway`, this is insufficient: if data-plane pods are ready locally in Kubernetes but have not yet been attached to Google Cloud zonal NEGs, the load balancer has 0 backends and all external client traffic will fail (returning TCP connection refused / reset).

Therefore, `gcpgateway` enforces strict end-to-end readiness:
1. `Programmed=False` (Reason: `WaitingForDataPlane` or `WaitingForEndpoints`) while data-plane pods are starting or awaiting NEG attachment.
2. The controller issues `attachNetworkEndpoints` and waits for operation completion.
3. The controller verifies that at least one ready data-plane replica is confirmed attached and reported `HEALTHY` by `backendServices.getHealth`.
4. Only then does the controller mark:
   - `Programmed=True`
   - Reason: `Programmed`
   - Message: `Ready data-plane pods attached to zonal NEGs and passing health checks behind Google Cloud Load Balancer`

### Condition State Table

| Condition Type | Status | Reason | Message / Trigger |
| --- | --- | --- | --- |
| `Accepted` | `True` | `Accepted` | Gateway spec and parametersConfigMap are valid. |
| `Accepted` | `False` | `InvalidParameters` | Parameters ConfigMap missing or contains invalid keys/values. |
| `Accepted` | `False` | `ConflictingParameters` | Configured NEGs are already claimed by an older active Gateway in the cluster. |
| `Programmed` | `False` | `AddressNotAssigned` | Neither `spec.addresses` nor parameters ConfigMap provides external static IP. |
| `Programmed` | `False` | `WaitingForDataPlane` | Data-plane Deployment has 0 available/ready replicas. |
| `Programmed` | `False` | `WaitingForEndpoints` | Ready pods exist, but attachment to zonal NEGs or health check convergence is in-flight. |
| `Programmed` | `False` | `RolloutStalled` | New data-plane pod failed to become healthy on load balancer; rollout halted to protect old pods. |
| `Programmed` | `True` | `Programmed` | Ready data-plane pods confirmed attached to zonal NEGs and passing health checks. |
| `Programmed` | `False` | `EndpointAttachmentFailed` | Compute Engine API error during `attachNetworkEndpoints`. |
| `Programmed` | `False` | `NEGNotFound` | Zonal NEG does not exist in the zone where pod is scheduled. |
| `Programmed` | `False` | `UnsupportedCluster` | Pod IP is not a VPC alias IP (cluster is not VPC-native). |

---

## Failure Modes & Resilience

### 1. Compute API Errors
- **403 Forbidden / `PERMISSION_DENIED`**:
  - Cause: Custom IAM role missing one of the required permissions, or Workload Identity binding incorrect.
  - Action: Registrar logs the full API response and updates Gateway status: `Programmed=False`, Reason: `PermissionDenied`, Message: `Compute API permission denied on networkEndpointGroups. Ensure custom IAM role 'gcpgatewayNegRegistrar' is bound to KSA`.
- **429 / Quota Exceeded**:
  - Cause: Exceeded rate limits for zonal mutations or exceeded max endpoints per NEG (standard quota: 5,000 endpoints per zonal NEG).
  - Action: Registrar applies exponential backoff with full jitter; reports `Programmed=False`, Reason: `QuotaExceeded`.
- **Transient 5xx / Network Failures**:
  - Handled via automatic retry with exponential backoff.

### 2. Pods Without Alias IPs (Non-VPC-Native)
- **Cause**: Cluster uses overlay networking without VPC alias IPs.
- **Action**: Compute Engine API returns `INVALID_IP_ADDRESS`. Registrar marks `Programmed=False`, Reason: `UnsupportedCluster`, and skips re-attempting until pod IP changes.

### 3. Zone Without a NEG
- **Cause**: Data-plane pod is scheduled in a zone (e.g. `us-central1-f`) where the operator script did not create a NEG (e.g., regional GKE cluster spanning zones not covered during setup).
- **Detection**: Compute API call `networkEndpointGroups.get` or `attachNetworkEndpoints` returns HTTP 404 `resourceNotFound`.
- **Action**:
  - The registrar marks `Programmed=False`, Reason: `NEGNotFound`, Message: `Zonal NEG for Gateway not found in zone us-central1-f. Ensure front-end script has created NEGs across all active cluster zones.`
  - The controller avoids crashlooping and continues managing endpoints in zones where NEGs exist.

### 4. Orphaned Endpoints & Ungraceful Termination
- **Cause**: Node hard crash, power failure, or kubelet ungraceful eviction prevents Kubernetes from executing the graceful termination sequence.
- **Detection**: Google Cloud health prober fails on `/_gari/readyz`, marking the endpoint UNHEALTHY on the load balancer within 10 seconds.
- **Resolution**:
  - The registrar runs a periodic background reconciliation loop (e.g., every 60 seconds).
  - It lists all endpoints in the zonal NEGs (`compute.networkEndpointGroups.listNetworkEndpoints`) and compares them against live `EndpointSlices`.
  - Any endpoint in the NEG that does not correspond to a live, ready pod in the cluster is automatically detached via `detachNetworkEndpoints`.

---

## Verified IAM Permissions & Workload Identity Setup

### Why Two Custom IAM Roles Are Required

To uphold least privilege, `gcpgateway` cleanly separates permissions into **two custom IAM roles** based on operational boundaries:

1. **`gcpgatewayNegRegistrar` (Runtime Controller Role)**:
   Used by the controller in the cluster. It can **only** inspect NEGs and backend services, attach/detach endpoints, and query health. It cannot create or destroy infrastructure.
2. **`gcpgatewayOperatorHelper` (Provisioning Helper Role)**:
   Used by operators or CI/CD pipelines executing `gcpgatewayctl frontend create` and `gcpgatewayctl frontend delete`.
   Permissions across addresses, health checks, NEGs, backend services, target TCP proxies, forwarding rules, and firewall rules.

Splitting runtime registration from infrastructure provisioning ensures that in-cluster controller credentials cannot modify or delete cloud load balancing infrastructure (addresses, health checks, forwarding rules, firewalls, etc.).

> **Note on IAM Conditions and Multi-Cluster Isolation**:
> Because resource names use `<prefix>-<8-char-hash>-<suffix>` without readable cluster names, a name-based IAM Condition (e.g. `resource.name.startsWith(...)`) **cannot** separate multiple clusters sharing the same GCP project unless each cluster is configured with a unique prefix (e.g., `--neg-prefix=gcpgw-cluster1-`). If multiple clusters share a project, configure distinct prefixes per cluster to achieve IAM resource separation.

In Google Cloud IAM:
- `compute.networkEndpointGroups.*` permissions are authorized against **Network Endpoint Group** resources (`projects/.../networkEndpointGroups/...`).
- `compute.instances.use` is authorized against **Compute Engine Instance (VM)** resources (`projects/.../zones/.../instances/...`).
- `compute.zoneOperations.get` is authorized against **Zone Operation** resources (`projects/.../zones/.../operations/...`).
- `compute.backendServices.get` is authorized against **Backend Service** resources (`projects/.../global/backendServices/...`) (and also authorizes `getHealth`).

| Custom Role | Permissions | Target Resource Type | IAM Condition Support |
| --- | --- | --- | --- |
| **`gcpgatewayNegRegistrar`** | `compute.networkEndpointGroups.get`<br>`compute.networkEndpointGroups.list`<br>`compute.networkEndpointGroups.use`<br>`compute.networkEndpointGroups.attachNetworkEndpoints`<br>`compute.networkEndpointGroups.detachNetworkEndpoints`<br>`compute.instances.use`<br>`compute.backendServices.get`<br>`compute.zoneOperations.get` | Network Endpoint Groups, Compute Engine Instances (VMs), Backend Services, Zone Operations | Scoped by prefix if prefixes differ per cluster (`${PREFIX}-*`) |
| **`gcpgatewayOperatorHelper`** | Full load balancer management (`compute.addresses.*`, `compute.healthChecks.*`, `compute.networkEndpointGroups.*`, `compute.backendServices.*`, `compute.targetTcpProxies.*`, `compute.forwardingRules.*`, `compute.firewalls.*`) | All front-end resources | Provisioning helper for operators |

*Note: The controller does NOT require `compute.networkEndpointGroups.create`, `compute.backendServices.create`, `compute.forwardingRules.*`, or `compute.firewalls.*`.*

### Kubernetes RBAC Requirements for Controller
In addition to standard Gateway API permissions, the `gcpgateway` controller requires:
- `discovery.k8s.io`: `endpointslices`: `["get", "list", "watch"]`
- `core`: `pods`: `["get", "list", "watch"]`
- `core`: `pods/status`: `["get", "patch", "update"]` (for updating `gcpgateway.gke-labs.io/load-balancer-ready`)
- `core`: `nodes`: `["get", "list", "watch"]` (for resolving VM instance and zone)

### Workload Identity Configuration (GKE)

#### 1. Create the Custom IAM Role
```bash
gcloud iam roles create gcpgatewayNegRegistrar \
    --project="${PROJECT_ID}" \
    --title="GARI gcpgateway NEG Registrar" \
    --description="Authorizes gcpgateway controller to register endpoints and check health" \
    --stage="GA" \
    --permissions="compute.networkEndpointGroups.get,compute.networkEndpointGroups.list,compute.networkEndpointGroups.use,compute.networkEndpointGroups.attachNetworkEndpoints,compute.networkEndpointGroups.detachNetworkEndpoints,compute.instances.use,compute.backendServices.get,compute.zoneOperations.get"
```

#### 2. Bind the Custom Role to the Kubernetes ServiceAccount
```bash
# 1. Create the Google Service Account (GSA) and bind the role:
gcloud iam service-accounts create "${GSA_NAME}" \
    --project="${PROJECT_ID}" \
    --display-name="gcpgateway Controller Service Account"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="projects/${PROJECT_ID}/roles/gcpgatewayNegRegistrar"

# 2. Bind Workload Identity between the GSA and Kubernetes Service Account (KSA):
gcloud iam service-accounts add-iam-policy-binding \
    "${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --project="${PROJECT_ID}" \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[${KSA_NAMESPACE}/${KSA_NAME}]"
```

### Setup for Non-GKE Clusters (kOps / GCE)
For non-GKE clusters running on Google Compute Engine:
1. **Compute Engine Node Service Account**: Grant the runtime custom role (`gcpgatewayNegRegistrar`) to the GCE service account attached to the worker node VM instances (`<vm-sa>@${PROJECT_ID}.iam.gserviceaccount.com`). The controller inherits credentials transparently via the GCE instance metadata service.
2. **Workload Identity Federation for External OIDC**: If the cluster has an external OIDC issuer, configure a Workload Identity Pool and Provider in Google Cloud IAM, mapping the KSA token to the GCP principal.

---

## Front-End Administration Tool Specification (`gcpgatewayctl`)

Administrative tasks for infrastructure setup and teardown are performed by `gcpgatewayctl`, a Go command-line tool implemented in `gcpgateway/cmd/gcpgatewayctl`:
- `gcpgatewayctl frontend create`: Idempotent setup of the layer-4 load balancer, health checks, firewall rules, and zonal NEGs.
- `gcpgatewayctl frontend delete`: Clean teardown of all provisioned Google Cloud resources in reverse dependency order.

### Why Go

1. **Code Reuse**: Directly reuses the controller's Go packages (`gcpgateway/pkg/metadata`) for deterministic 63-character naming hashes and JSON metadata descriptions.
2. **Type Safety & Stable API**: Uses the typed Google Compute Engine API (`google.golang.org/api/compute/v1`) with Application Default Credentials (ADC), eliminating fragile CLI argument parsing and `gcloud` dependency.
3. **Least Privilege & Testability**: Defines a dedicated `AdminClient` interface (`gcpgateway/pkg/admin`) separate from the controller's runtime `ComputeClient`, backed by an in-memory test fake (`FakeAdminClient`).

### Command-Line Arguments & Flags

Both `frontend create` and `frontend delete` bind flags directly to `FrontendConfig`:
- `--project`: Google Cloud project ID (required).
- `--region`: Compute region (required).
- `--network`: VPC Network name (default: `default`).
- `--subnet`: VPC Subnet name (default: `default`).
- `--cluster-id`: Kubernetes cluster identifier (default: `cluster-1`).
- `--namespace`: Gateway namespace (default: `default`).
- `--gateway-name`: Gateway resource name (default: `my-gateway`).
- `--prefix`: Resource name prefix (default: `gcpgw`).
- `--zones`: Comma-separated list of zones in the region (defaults to querying region zones).
- `--draining-timeout`: Connection draining timeout in seconds (default: `35`).
- `--dry-run`: Prints the planned operations without making any Compute API calls.

### `gcpgatewayctl frontend create` Workflow

1. **Resolve Zones**: Uses `--zones` if provided, otherwise queries `compute.Zones.List` for the region.
2. **Global Static IP**: Reserves a global external IPv4 address named `{prefix}-{hash}-ip`.
3. **HTTP Health Check**: Creates a global HTTP health check named `{prefix}-{hash}-hc` on port 8999 with request path `/_gari/readyz`.
4. **Ingress Firewall Rule**: Creates an ingress rule named `{prefix}-{hash}-allow-gfe` allowing TCP ports 8443, 8080, and 8999 from Google Front End (GFE) proxy CIDRs (`35.191.0.0/16, 130.211.0.0/22`).
5. **Zonal NEGs**: Creates one `GCE_VM_IP_PORT` NEG per zone per port (8443 and 8080) with JSON description metadata encoding cluster ID, namespace, gateway name, and port.
6. **Backend Services**: Creates global TCP backend services (`EXTERNAL_MANAGED`) with connection draining, attaches health check, and attaches all zonal NEGs as backends.
7. **Target TCP Proxies**: Creates target TCP proxies with `PROXY_V1` header enabled.
8. **Forwarding Rules**: Creates global forwarding rules on ports 443 and 80 routing to the target proxies.
9. **Manifest Generation**: Prints the static IP address and ready-to-apply ConfigMap and Gateway manifests.

### `gcpgatewayctl frontend delete` Workflow

Deletes resources in exact reverse dependency order:
1. Global Forwarding Rules (`fr-443`, `fr-80`).
2. Target TCP Proxies (`proxy-443`, `proxy-80`).
3. Backend Services (`bs-443`, `bs-80`).
4. Zonal NEGs in each zone (`8443`, `8080`).
5. Health Check (`hc`).
6. Firewall Rule (`allow-gfe`).
7. Static IP reservation (`ip`).

Before deleting any resource, `gcpgatewayctl` inspects its description metadata to verify ownership (`cluster-id`, `namespace`, `gateway-name`). If metadata does not match or is absent, the resource is skipped to protect foreign infrastructure. Resources that are already gone are tolerated cleanly.

---

## Proposed Implementation Issues (Dependency Ordered)

Below is the proposed breakdown of work into small, focused, incremental issues. Each issue builds upon previous issues and includes clear acceptance criteria.

```
┌────────────────────────────────────────────────────────┐
│ Issue 1: Root Module PROXY Protocol & Dual CIDR Filter │
│ (Generic v1/v2 parser, allowedSourceCIDRs, trust check)│
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Issue 2: gcpgateway Module Skeleton & Container Build  │
│ (Separate go.mod, go.work, main.go, hook pre-stop)     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Issue 3: NEG Registrar Core Engine                     │
│ (ContainersReady, Node resolver, getHealth, Gate Patch)│
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Issue 4: Gateway Readiness & Status Synchronization    │
│ (Programmed condition, deterministic conflict resol.)  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Issue 5: Front-End Provisioning & Teardown Go Admin    │
│ (gcpgatewayctl frontend create/delete, AdminClient)    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Issue 6: Documentation, Manifests, and End-to-End Test │
│ (RBAC, GatewayClass, sample guides, e2e test harness)  │
└───────────────────────────┘
```

---

### Issue 1: Generic PROXY protocol v1/v2 support with dual CIDR filtering in root module

- **Scope**: Root module (`pkg/`). Pure Go implementation without cloud SDK dependencies.
- **Tasks**:
  1. Add PROXY protocol v1 (ASCII text) decoding support alongside existing v2 support in `pkg/proxyproto/` (or move/refactor from `snigateway/pkg/proxyproto`).
  2. Implement dual-layer CIDR filtering in `net.Listener` wrapper:
     - `allowedSourceCIDRs`: Drop connections from any remote IP not in this list immediately upon accept (`conn.Close()`).
     - `proxyProtocolTrustedCIDRs`: Only parse PROXY headers if `conn.RemoteAddr()` is in this list; rewrite client remote address.
  3. Extend `pkg/state/parameters.go` to parse `allowedSourceCIDRs`, `proxyProtocol: "enabled"`, and `proxyProtocolTrustedCIDRs`.
  4. Wire listener filtering into GARI's HTTP (8080) and HTTPS (8443) server listeners.
  5. Add health probe path customization support in GARI to serve `/_gari/readyz` alongside local drain sentinel file detection.
- **Acceptance Criteria**:
  - Unit tests verify PROXY v1 text decoding (`PROXY TCP4 ...`, `PROXY TCP6 ...`, `PROXY UNKNOWN ...`).
  - Unit tests verify connections from unauthorized CIDRs are rejected immediately.
  - Unit tests verify PROXY headers sent from untrusted IPs are rejected or ignored, preventing address spoofing.
  - Unit tests verify `X-Forwarded-For` and HTTP request `RemoteAddr` reflect the PROXY header client IP when received from trusted CIDRs.
  - Zero cloud provider dependencies added to root `go.mod`.

---

### Issue 2: Module skeleton `gcpgateway/` with build, test, and container packaging

- **Scope**: Create the `gcpgateway/` module directory structure.
- **Tasks**:
  1. Initialize `gcpgateway/go.mod` requiring root module (`replace github.com/gke-labs/gateway-api-reference-implementation => ../`) and Google Compute Engine SDKs (`google.golang.org/api/compute/v1`).
  2. Create `gcpgateway/go.work` linking `.` and `..`.
  3. Create `gcpgateway/cmd/gcpgateway/main.go` supporting:
     - Controller mode (default): embeds GARI manager, registers `gcpgateway` controller name.
     - Data-plane mode (`--dataplane-mode`): runs GARI data-plane server.
     - Pre-stop hook mode (`hook pre-stop --drain-seconds=N`): writes local sentinel file `/var/run/gcpgateway/draining` and sleeps in pure Go.
  4. Add `images/gcpgateway/Dockerfile`.
  5. Add test scripts and ensure `ap test`, `ap lint`, and `ap build` execute cleanly across the workspace.
- **Acceptance Criteria**:
  - `go build ./...` succeeds inside `gcpgateway/`.
  - Binary starts in controller mode, data-plane mode, and hook mode.
  - `gcpgateway hook pre-stop` successfully creates sentinel file, switches probe response to 503, and sleeps cleanly.
  - Root `go.mod` remains untouched.

---

### Issue 3: NEG Registrar core engine: EndpointSlice watcher, Node resolver, getHealth, and Readiness Gate

- **Scope**: Package `gcpgateway/pkg/neg/`.
- **Tasks**:
  1. Implement Compute Engine API client wrapper with exponential backoff and batching for `attachNetworkEndpoints`, `detachNetworkEndpoints`, and `backendServices.getHealth`.
  2. Implement `EndpointSlice` and `Pod` watcher resolving data-plane pods.
  3. Implement Node resolver extracting GCE instance name and zone (`topology.kubernetes.io/zone`, `node.spec.providerID`).
  4. Implement endpoint attachment loop evaluating pod **`ContainersReady == True`** (avoiding readiness gate deadlock), `deletionTimestamp == nil`, and not terminating.
  5. Implement detachment loop with:
     - Immediate detach for terminating pods (`deletionTimestamp != nil`).
     - 15-second flapping hysteresis for non-terminating pods with transient `ContainersReady=false`.
     - 500ms debounce batching window.
  6. Inject Pod Readiness Gate `gcpgateway.gke-labs.io/load-balancer-ready` and pre-stop hook into data-plane pod template lifecycle via singlepod options.
  7. Implement health check poller calling `backendServices.getHealth` and patching Pod condition `gcpgateway.gke-labs.io/load-balancer-ready = True` when healthy.
  8. Add periodic reconciliation loop (60s) to prune orphaned endpoints.
- **Acceptance Criteria**:
  - Unit tests verify that a newly created pod with `ContainersReady=True` but gated `Ready=False` (due to pending readiness gate) is attached to the zonal NEG without deadlocking.
  - Unit tests verify unready non-terminating pods observe hysteresis before detach, while terminating pods detach immediately.
  - Unit tests verify Pod Readiness Gate is patched to `True` only after `backendServices.getHealth` returns `HEALTHY`.
  - Unit tests verify 63-character-safe NEG naming with hash truncation.
  - Unit tests verify graceful handling of Compute API errors (403, 404, 429).

---

### Issue 4: Gateway status, readiness synchronization, and deterministic conflict resolution

- **Scope**: `gcpgateway/pkg/status/` and controller integration.
- **Tasks**:
  1. Implement address resolution reporting the external static IP from `spec.addresses` or parameters ConfigMap.
  2. Implement deterministic conflict resolution following Gateway API conventions: oldest `creationTimestamp` wins, breaking ties by `namespace/name`. Conflicting later Gateways receive `Accepted=False`, Reason: `ConflictingParameters`.
  3. Implement condition evaluator holding `Programmed=False` (`WaitingForDataPlane` / `WaitingForEndpoints`) until ready pods are confirmed attached to zonal NEGs and passing health checks.
  4. Surface error conditions with clear diagnostic messages:
     - `RolloutStalled`: New pod failed to become healthy on load balancer; rollout halted.
     - `UnsupportedCluster`: Pod IP is not a VPC alias IP.
     - `NEGNotFound`: Zonal NEG missing in scheduled pod's zone.
     - `PermissionDenied`: IAM permission failure on Compute API.
- **Acceptance Criteria**:
  - Conflicting Gateways targeting the same NEGs are resolved deterministically (oldest wins), rejecting later Gateways with `Accepted=False`.
  - Gateway reports `Programmed=False` while pods are starting or awaiting health checks.
  - Gateway reports `Programmed=True` once at least one ready pod is attached in zonal NEGs and healthy.
  - Clear condition messages tested for stalled rollouts, missing NEGs, and non-alias IPs.

---

### Issue 5: Front-end provisioning and teardown Go admin tool (`gcpgatewayctl`)

- **Scope**: `gcpgateway/cmd/gcpgatewayctl/` and `gcpgateway/pkg/admin/`.
- **Tasks**:
  1. Implement `gcpgatewayctl frontend create` in Go to provision static IP, health check on 8999 with path `/_gari/readyz`, zonal NEGs across all regional zones with 63-character-safe deterministic naming (`metadata.ResourceName`), backend services with `CONNECTION` mode and connection draining, target TCP proxies with `PROXY_V1`, forwarding rules, and firewall rules using the typed Compute API and ADC.
  2. Ensure complete idempotency (describe first, create only missing, report existing).
  3. Implement `gcpgatewayctl frontend delete` to cleanly delete all provisioned cloud resources in reverse dependency order, validating description metadata ownership.
  4. Print ready-to-apply ConfigMap and Gateway YAML manifests with `allowedSourceCIDRs`, `proxyProtocolTrustedCIDRs`, and discrete NEG names.
- **Acceptance Criteria**:
  - Unit tests with `FakeAdminClient` validating create from empty, idempotent create, create with partial resources, delete, delete with missing resources, error handling, and dry-run making no calls.
  - Tests verify names and NEG descriptions match controller `pkg/metadata` conventions.
  - Passes `go vet` and `go test -race`.

---

### Issue 6: Documentation, deployment manifests, and end-to-end testing

- **Scope**: `gcpgateway/k8s/`, `gcpgateway/README.md`, `tests/`.
- **Tasks**:
  1. Add Kubernetes manifests: `GatewayClass`, RBAC (`ClusterRole`, `ClusterRoleBinding`, `ServiceAccount` with `pods/status` patch permissions), and controller `Deployment`.
  2. Write comprehensive `gcpgateway/README.md` and user guide with step-by-step Workload Identity commands, including the split custom roles (`gcpgatewayNegRegistrar` and `gcpgatewayOperatorHelper`) and IAM Conditions.
  3. Add integration / e2e test suite testing the registrar against simulated/mock GCE APIs or live cluster, verifying rolling updates with simulated health check delays and failures.
- **Acceptance Criteria**:
  - Documentation clearly walks an operator through setup from zero to passing HTTPS traffic.
  - Manifests deploy cleanly to a test cluster.
  - All CI presubmits (`ap test`, `ap lint`) pass.
