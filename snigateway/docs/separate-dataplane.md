# Design Note: Running the Data Plane as a Separate Process in SNIGateway

## Context

The reference implementation is removing all-in-one mode so that every user runs the per-Gateway data-plane code path (#1247). SNIGateway currently embeds the reference implementation controller and proxy in a single process, feeding reverse-tunnel connections from `snigateway-frontend` directly into an in-process proxy listener. This note evaluates whether SNIGateway can stop running the proxy in-process and split into a separate controller and data-plane process.

## 1. Where the Tunnel Ends

In a split architecture, the reverse tunnel must end in the data-plane process. The data plane terminates TLS, parses PROXY protocol v2 headers, evaluates HTTP routing, and proxies requests to backend pods; the controller handles only control-plane reconciliation. Terminating the tunnel in the controller would require re-proxying raw traffic to data-plane pods across the cluster network, defeating the purpose of the split. The process that dials the frontend and accepts reverse-tunnel connections must therefore be the data plane itself.

The data-plane process would need:
- **Tunnel client:** The reverse-tunnel client logic (`snigateway/pkg/client` and `snigateway/pkg/tunnel` manager and listener) to dial the frontend and accept connections.
- **Frontend address:** The address of `snigateway-frontend` (`--frontend`) and the management TLS ServerName (`--internal-hostname`).
- **Credentials:** The CA certificate (`--ca-cert`) to verify the frontend, and either a client certificate/key pair (`--client-cert`/`--client-key`) or a projected ServiceAccount token (`--token-file`) for mTLS authentication.
- **Credential distribution:** In Kubernetes, the controller must ensure these credentials are mounted into each per-Gateway data-plane pod, either via a projected volume or by copying the credential Secret into tenant namespaces.

## 2. Registration

Today, the controller registers hostnames with the frontend from its compiled state using GARI's `OnGatewaysUpdate` hook.

After a split, the **data-plane process** must register hostnames with the frontend:
- **Session ownership:** In SNIGateway, registrations on `snigateway-frontend` are scoped to an active tunnel session ID (`sessionID`) created during the mTLS handshake. Because the data plane establishes and maintains the reverse-tunnel session, only the data plane holds the active session ID. Having the controller register would require an out-of-band IPC channel or status field for each data-plane pod to report its dynamic session ID back to the controller.
- **Learning hostnames:** In GARI's per-Gateway data-plane architecture, the controller compiles state and publishes a `DataplaneConfig` to a per-Gateway Secret (`config.json`). The data-plane process watches this Secret, extracts the SNI hostnames from the configured HTTPS and TLS listeners, and calls `PUT /v1/registration` on the frontend whenever its configuration updates.

## 3. Addresses and Readiness

- **Gateway Addresses:** The reported address is the public address of `snigateway-frontend` (configured statically via `--frontend` or `--gateway-address`). The controller writes this address into `Gateway.status.addresses` directly without querying the data plane.
- **Readiness (`Programmed` condition):** Today the in-process controller inspects in-memory tunnel state (`tunnelState.IsConnected()` and `tunnelState.HasRegisteredHostnames()`). In a split, the controller cannot observe tunnel state directly.
- **Readiness propagation:** The data-plane process exposes an HTTP readiness probe on its health port (e.g. `:8081/readyz`) that succeeds only after its tunnel session is connected and its hostnames are registered with the frontend. The controller watches data-plane Pod readiness (reusing GARI's singlepod readiness observation logic) and sets `Programmed=True` once the data-plane pod becomes ready.

## 4. Size and Scope

- **What needs to be added:**
  - A custom data-plane binary and container image packaging `pkg/tunnel` alongside GARI's data-plane proxy.
  - A custom provisioner in the controller to deploy per-Gateway Deployments with tunnel flags, credential volume mounts, and readiness probes (omitting standard `LoadBalancer` Services).
  - RBAC expansions and credential distribution logic allowing the controller to manage Deployments and Secrets across tenant namespaces and ensure data-plane pods can authenticate to the frontend.
  - Estimated additions: ~400–600 lines of Go, updated manifests, a new Dockerfile/image packaging, and expanded RBAC.
- **What can be deleted:**
  - In-process proxy wiring in `snigateway/cmd/snigateway/main.go` (~60 lines: `gariOpts.HTTPSListener`, `gariOpts.OnGatewaysUpdate`, and in-process `gari.Run`).
  - `snigateway/pkg/tunnel/address_provider.go` in-process state-watcher logic (~250 lines).

## 5. Verdict and Recommendation

**Verdict: Not worth it for a demo.** Splitting SNIGateway is feasible only as a larger change. It introduces multi-process orchestration, custom container images, and credential distribution into tenant namespaces for what is explicitly a frozen demo illustrating SNI reverse tunneling.

**Smallest way to keep the demo working:** Retain SNIGateway as a single-process binary, but decouple it from GARI's multi-Gateway `AllInOneMode`. The maintainer's goal is eliminating multi-Gateway port and hostname conflict merging in `pkg/state`. SNIGateway only needs to serve a single Gateway: compile that Gateway using GARI's per-Gateway compiler, pass the resulting `DataplaneConfig` directly to an in-process `pkg/proxy.Server`, and feed tunnel connections to it. This keeps the demo self-contained in a single pod with zero provisioner complexity while eliminating any dependency on all-in-one state merging.

**Recommendation:** Do not split SNIGateway into separate controller and data-plane processes. Keep it as a single-process demo that runs an in-process proxy for a single Gateway using the per-Gateway `DataplaneConfig`.
