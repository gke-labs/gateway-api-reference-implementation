# Design: Generic HTTPRoute ExtensionRef via Envoy ext_proc Status Discovery

## Context and Goals

Gateway API provides the `ExtensionRef` filter on `HTTPRoute` rules so operators can attach implementation-specific or experimental behaviors without encoding configuration in annotations. Supporting each third-party extension CRD directly in GARI would couple the controller and data plane to external schemas and release cycles.

This document defines a generic extension mechanism for GARI. An `HTTPRoute` references any Kubernetes object through `filters[].type: ExtensionRef`. The referenced object publishes a Kubernetes `Service` and port in its `status` that implements Envoy's `ext_proc` gRPC protocol (`envoy.service.ext_proc.v3.ExternalProcessor`). GARI discovers the endpoint from `status`, enforces cluster trust boundaries, compiles the target into `DataplaneConfig`, and invokes `ext_proc` from `pkg/proxy`.

This design complements in-process path-template redirects (which handle declarative redirects without an extra network hop) by letting arbitrary out-of-process extensions implement custom redirects, `?go-get=1` HTML responses, header enrichment, or policy checks without teaching GARI their CRD schemas.

### Terms

- **Extension object:** The Kubernetes object named by an `HTTPRoute` filter's `extensionRef` (`LocalObjectReference`). It lives in the same namespace as the referencing `HTTPRoute`.
- **Extension controller:** The third-party controller that reconciles an extension object's `spec` and writes its `ext_proc` endpoint into `status`.
- **External processor (`ext_proc`):** A gRPC server implementing `envoy.service.ext_proc.v3.ExternalProcessor` that inspects and mutates HTTP requests or returns immediate HTTP responses.
- **Discovery hop:** The reference from an extension object's `status` to a Kubernetes `Service` and port.

### Non-Goals for Phase 1

- Request or response body streaming over `ext_proc`. Phase 1 covers request headers only.
- Re-evaluating route matching after `ext_proc` mutates headers (`clear_route_cache`).
- `ExtensionRef` filters on `backendRefs[].filters` or `GRPCRoute`. Both can adopt this contract later.

## Design Invariants

- **Service-only addressing.** The controller accepts only a Kubernetes `Service` name, optional namespace, and numeric port from an extension object's `status`. It rejects raw IPs, hostnames, URLs, and `ExternalName` Services so an extension cannot direct data planes to metadata servers, loopback addresses, or external hosts.
- **Two-hop namespace authorization.** An `HTTPRoute` references only extension objects in its own namespace (`LocalObjectReference`). If the extension object's `status` points to a `Service` in another namespace, the controller requires a `ReferenceGrant` in the `Service`'s namespace authorizing the extension object's `GroupKind` and namespace.
- **No wildcard CRD RBAC.** The controller watches an extension `GroupVersionKind` only when cluster RBAC grants `get`, `list`, and `watch` for that resource. When RBAC is missing, the controller reports `ResolvedRefs=False` on the referencing `HTTPRoute` rather than failing startup or crashing.
- **Fail-closed default.** When an `ExtensionRef` fails resolution during compilation, the matched rule returns HTTP `500`. When an `ext_proc` call fails at request time, `pkg/proxy` fails closed unless the extension explicitly opts into `FailOpen`.
- **Bounded request-path work.** Every `ext_proc` call runs under a bounded per-call timeout clamped by the rule's `timeouts.request` deadline. The proxy also caps `ImmediateResponse` body sizes and header mutation counts.
- **No API server calls on the data plane.** The controller resolves extension targets into `State` and pushes them in `DataplaneConfig`. Data planes do not query the Kubernetes API server.

## 1. Discovery Contract

### 1.1 Extension Object Status Schema

An extension CRD opts into GARI discovery by publishing `status.externalProcessor`. GARI reads only `metadata`, `status.conditions`, and `status.externalProcessor`, and ignores `spec`.

```yaml
status:
  conditions:
    - type: Ready
      status: "True"
      observedGeneration: 3
  externalProcessor:
    serviceRef:
      name: k8s-redirect-extproc
      namespace: redirect-system # optional; defaults to the extension object's namespace
      port: 9001                 # required; 1..65535
    processingMode:
      requestHeaders: Send       # Send (default) or Skip
      responseHeaders: Skip      # Skip (default); Send deferred to Phase 2
    failureMode: FailClosed      # FailClosed (default) or FailOpen
    timeout: 200ms               # optional Go duration; default 200ms, max 5s
```

Field rules:

- **`serviceRef` (required):** `name` and numeric `port` (`1` to `65535`) are required. `namespace` defaults to the extension object's namespace. The `Service` must exist in cluster state, must not be `ExternalName`, and must declare the referenced port. The controller resolves it to its cluster DNS name (`<service>.<namespace>.svc.cluster.local`) and port.
- **`processingMode` (optional):** Defaults to `requestHeaders: Send` and `responseHeaders: Skip`. Phase 1 rejects `responseHeaders: Send` and any body or trailer modes so extensions cannot silently assume body inspection is active.
- **`failureMode` (optional):** `FailClosed` (default) or `FailOpen`. Unknown values fail validation.
- **`timeout` (optional):** Positive Go duration, defaulting to `200ms`. Values above the controller ceiling (`5s` default) fail validation rather than being silently truncated.
- **Readiness:** If `status.conditions` contains `type: Ready`, GARI requires `status: "True"`. If `Ready` is `"False"` or `"Unknown"`, the extension is not ready. If no `Ready` condition is present, GARI treats the extension as ready once `status.externalProcessor.serviceRef` is valid and the target `Service` exists.

**Trade-off on `observedGeneration`.** Requiring `observedGeneration == metadata.generation` would return `500` on live routes briefly whenever an operator edits an extension `spec` before its controller reconciles. Checking `Ready=True` without failing on stale `observedGeneration` avoids rollout blips, at the cost of serving the prior processor configuration until the extension controller updates `status` or marks `Ready=False`.

**Beyond the Gateway API specification:** Gateway API leaves `ExtensionRef` semantics implementation-specific and defines no status discovery contract. The `status.externalProcessor` schema is a GARI convention designed to stay small enough to align with an upstream standard later.

### 1.2 Per-Object Context for Shared Processors

One `ext_proc` Deployment commonly serves many extension objects across namespaces. To identify which object triggered a request without one `Service` per object, `pkg/proxy` attaches a protobuf `Struct` in `ProcessingRequest.attributes` under `"gateway.gke-labs.io/ext_proc"` containing the extension's `group`, `kind`, `namespace`, and `name`, plus the `HTTPRoute`'s `namespace`, `name`, and rule name. Because the data plane constructs these attributes from `DataplaneConfig`, untrusted HTTP clients cannot spoof them. An `ext_proc` server should trust these attributes only when it authenticates the data plane over mTLS (Section 2.2).

### 1.3 Watching Arbitrary Referenced Objects

GARI compiles route statuses and per-Gateway `DataplaneConfig` snapshots from a central `State` (`pkg/state`), compatible with the incremental dependency model in `docs/incremental-state.md`.

Two approaches exist for reading arbitrary extension CRDs:

1. **On-demand API `Get` during reconcile.** Avoids dynamic informers, but misses push updates when an extension controller updates `status.externalProcessor` or toggles `Ready`, requiring polling.
2. **Ref-counted dynamic unstructured informers (`client-go/dynamic`).** When `State` sees an `HTTPRoute` referencing `(group, kind)`, the controller resolves the resource via the `RESTMapper` and starts a dynamic informer. When the reference count drops to zero, the controller stops the informer after a short grace period (for example, `30s`) to avoid thrashing during route updates.

**Decision:** Use ref-counted dynamic unstructured informers with a status-only cache transform.

Each informer strips `spec` and unrelated fields before caching, keeping only `metadata`, `status.conditions`, and `status.externalProcessor`. This bounds controller memory even when third-party CRDs carry large specs. Informer events feed compact parsed targets into `State` so compilation stays pure and deterministic.

Lifecycle edge cases:

- **CRD not installed:** The controller records the `GroupKind` as unserved instead of failing. When `CRDView` (`pkg/controller/crdview.go`) observes CRD changes, it retries unserved `GroupKind`s.
- **RBAC `403 Forbidden`:** The controller records a per-`GroupKind` watch error in `State` and backs off rather than crashing the manager.
- **CRD removed:** The controller stops the informer, clears cached targets for that `GroupKind`, marks it unserved, and triggers `State` to recompute on the next state sync.

### 1.4 HTTPRoute Conditions (`Accepted` and `ResolvedRefs`)

GARI separates structural route validity (`Accepted`) from reference resolution (`ResolvedRefs`). When resolution fails, `Accepted` remains `True` (assuming valid structure and parent attachment), `ResolvedRefs` becomes `False`, and the rule returns HTTP `500`.

| Scenario | `Accepted` | `ResolvedRefs` | Reason | Proxy Behavior |
| --- | --- | --- | --- | --- |
| `type: ExtensionRef` with missing `extensionRef`, `kind`, or `name` | `False` | unchanged | `UnsupportedValue` | Rule returns `500` |
| `ExtensionRef` combined with `RequestRedirect` in the same rule | `False` | unchanged | `IncompatibleFilters` | Rule returns `500` |
| Extension CRD not installed | `True` | `False` | `InvalidKind` | Rule returns `500` |
| Controller lacks RBAC (`403 Forbidden`) to watch extension GVK | `True` | `False` | `RefNotPermitted` | Rule returns `500` |
| Extension object missing in `HTTPRoute` namespace | `True` | `False` | `BackendNotFound` | Rule returns `500` |
| Extension object exists, `status.externalProcessor` missing or `Ready=False` | `True` | `False` | `ExtensionRefNotReady` | Rule returns `500` |
| Malformed `status.externalProcessor` (port, timeout, mode, or `ExternalName`) | `True` | `False` | `InvalidExtensionRef` | Rule returns `500` |
| Cross-namespace `serviceRef` lacks matching `ReferenceGrant` | `True` | `False` | `RefNotPermitted` | Rule returns `500` |
| Target `Service` or declared port missing | `True` | `False` | `BackendNotFound` | Rule returns `500` |
| Target `Service` has an invalid `BackendTLSPolicy` | `True` | `False` | `BackendTLSPolicy` error | Rule returns `500` |
| Valid and ready extension | `True` | `True` | `ResolvedRefs` | Invokes `ext_proc` |

**Beyond the Gateway API specification:** Gateway API v1 defines `InvalidKind`, `RefNotPermitted`, and `BackendNotFound` for `ResolvedRefs`, and `UnsupportedValue` and `IncompatibleFilters` for `Accepted`, but defines no reasons for an existing extension object that is not ready or has invalid discovery status. GARI uses `ExtensionRefNotReady` and `InvalidExtensionRef` for those cases and reuses `BackendNotFound` for missing extension objects to stay compatible with conformance tooling.

An `HTTPRoute` rule with an `ExtensionRef` filter and no `backendRefs` is valid because extensions such as redirectors and `?go-get=1` responders answer directly with `ImmediateResponse`.

## 2. Security and Trust Boundaries

### 2.1 Namespace Scoping, ReferenceGrant, and SSRF Prevention

Discovery creates a two-hop reference chain: `HTTPRoute` (namespace `A`) -> extension object (namespace `A`, enforced by `LocalObjectReference`) -> `Service` (namespace `A` or shared namespace `B`). Without controls on the second hop, a tenant able to write `status` could point `serviceRef` at arbitrary cluster Services, metadata IPs, or external hosts.

GARI enforces four controls:

1. **Service-only resolution, no `ExternalName`.** The controller resolves `serviceRef` against its `Services` cache and rejects `ExternalName` Services so DNS CNAME indirection cannot escape the cluster.
2. **Cross-namespace `ReferenceGrant` on the discovery hop.** When `serviceRef.namespace` matches the extension object's namespace, the controller permits the reference without a `ReferenceGrant`. Otherwise, it requires a `ReferenceGrant` in `serviceRef.namespace` matching `from: { group: <extension-group>, kind: <extension-kind>, namespace: <extension-namespace> }` and `to: { group: "", kind: "Service", name: <serviceRef.name> }`.

   Authorizing the extension CRD's `GroupKind` as `from`, rather than `HTTPRoute`, prevents privilege bleed. If the grant instead authorized `HTTPRoute`, any `HTTPRoute` in that namespace could also place the `ext_proc` Service directly in `backendRefs` and proxy untrusted client traffic to the internal gRPC server. GARI's `ReferenceGrant` validator already matches arbitrary `from.GroupKind` values.
3. **Explicit RBAC opt-in.** The controller `ClusterRole` in `k8s/controller.yaml` keeps narrowed permissions and does not grant wildcard `*/*` reads. Cluster administrators opt in an extension CRD by installing an aggregated `ClusterRole` labeled `rbac.authorization.k8s.io/aggregate-to-gari-controller: "true"` granting `get`, `list`, and `watch` on that resource.
4. **Status subresource expectation.** Extension CRDs should enable `subresources.status: {}` and restrict `*/status` write RBAC to the extension controller so route authors cannot forge `status.externalProcessor`.

### 2.2 TLS, mTLS, and SPIFFE Alignment

GARI's workload identity direction uses SPIFFE X.509-SVIDs under the `cluster.local` trust domain (`spiffe/`). Today, `singlepod` provisions a per-Gateway `ServiceAccount` and mounts the cluster SPIFFE trust bundle ConfigMap (`gari-spiffe-bundle`, key `bundle.pem`). Multi-namespace SVID issuance (the generalized `spiffe/` Job, and later `certserver`) extends this to arbitrary workloads and per-Gateway data planes.

The controller decides TLS and SPIFFE mode for each `ext_proc` target from its own configuration and cluster policies, and encodes that choice into `DataplaneConfig`:

1. **Server verification (`BackendTLSPolicy` or SPIFFE bundle).**
   - If a `BackendTLSPolicy` targets the `ext_proc` `Service` (and optional port `sectionName`), the controller compiles that policy just like an HTTP backend, supporting custom CA ConfigMaps, system roots, hostname verification, and URI SAN checks (`spiffe://cluster.local/ns/<ns>/sa/<sa>`).
   - Otherwise, if the controller enables cleartext `ext_proc` (`--allow-insecure-ext-proc`, default `false`) and the `Service` port declares `appProtocol: kubernetes.io/h2c` (or `h2c`), the data plane dials plaintext HTTP/2.
   - Otherwise, when the controller runs with SPIFFE trust enabled (so data-plane pods receive the cluster SPIFFE trust bundle), the controller configures TLS verification against that trust bundle and the `Service`'s cluster DNS name. If none of these apply, compilation rejects the target rather than downgrading to plaintext.
2. **Client authentication (mTLS).**
   - When a `Gateway` configures `spec.tls.backend.clientCertificateRef`, `pkg/proxy` presents that client certificate on TLS `ext_proc` connections as well.
   - Once multi-namespace SPIFFE issuance provisions per-Gateway SVIDs, `pkg/proxy` presents the Gateway's X.509-SVID (`spiffe://cluster.local/ns/<gw-ns>/sa/<gw-sa>`) as the default client certificate on SPIFFE-verified `ext_proc` connections. The `ext_proc` server can then authorize callers by peer SPIFFE ID in the TLS handshake without calling `TokenReview` on the request path.

**Trade-off:** Requiring TLS by default adds setup for local development. Gating `h2c` behind both Service `appProtocol` and an explicit controller flag (`--allow-insecure-ext-proc`) keeps production secure while allowing simple local and test setups.

### 2.3 Timeouts, Failure Modes, and Resource Limits

- **Per-call timeout:** Each call runs with a deadline of `min(extension.timeout, remaining rule timeouts.request)`. Default is `200ms`; controller cap is `5s`.
- **Fail-closed default (`FailClosed`):** Deadlines return HTTP `504 Gateway Timeout`. Transport errors, gRPC errors, unexpected EOF, or malformed responses return HTTP `502 Bad Gateway` (or `500` for invalid header mutations). The proxy logs diagnostic details (including `ImmediateResponse.details`) and does not expose internal gRPC errors to clients unless debug error responses are enabled.
- **Fail-open (`FailOpen`):** Active only when `status.externalProcessor.failureMode` is `FailOpen`. On timeout or transport/protocol error, the proxy logs the failure, discards partial mutations from that filter, and continues evaluating subsequent filters and backends. Auth and policy extensions should not use `FailOpen`.
- **Response and header bounds:** The proxy caps `ImmediateResponse.body` at `1 MiB` (via gRPC receive limit and length check), caps header mutations per response (for example, 100), validates header names and values against RFC 9110 rules to prevent CRLF injection, and rejects hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Upgrade`, `Proxy-Connection`, `TE`) in `HeaderMutation`.

## 3. Data-Plane Execution (`pkg/proxy`)

### 3.1 Protocol Surface and Dependency Trade-off

Envoy's `ext_proc` service exposes one bidirectional streaming RPC: `Process(stream ProcessingRequest) returns (stream ProcessingResponse)`.

Two options exist for Go protobuf types: importing `github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3` (exact upstream types, but pulls a large transitive dependency graph into `go.mod`) or generating wire-compatible stubs from the minimal `ext_proc` v3 `.proto` subset using `ap tool protoc` (keeps `go.mod` lean while remaining wire-compatible with standard Envoy `ext_proc` servers in any language). Open Questions tracks this choice; the runtime behavior is identical.

### 3.2 Phase 1 Execution: Headers-Only vs Body Streaming

Phase 1 runs **request headers only**:

1. `pkg/proxy` opens a `Process` stream on the pooled gRPC connection for the target `Service`.
2. It sends one `ProcessingRequest` carrying `request_headers` (`:method`, `:scheme`, `:authority`, `:path` with raw query, lowercased incoming HTTP headers using `raw_value`, and `end_of_stream`) plus the `"gateway.gke-labs.io/ext_proc"` attributes `Struct`, then closes the send side immediately.
3. It reads one `ProcessingResponse` and closes the stream.

**Why headers-only first:** Redirects, `?go-get=1` HTML responses, auth checks, and header or path rewrites need only request headers. Deferring body streaming avoids memory buffering, preserves streaming responses (SSE, WebSockets, and chunked bodies), and avoids bidirectional flow-control complexity until a concrete use case requires body inspection.

### 3.3 Handling `ProcessingResponse`

- **`ImmediateResponse`:** Validates the status code (`100` to `599`), builds response headers from `headers` (`set_headers` and `remove_headers`), strips hop-by-hop headers, applies rule-level `CORS` and `ResponseHeaderModifier`, writes the status and `body`, and short-circuits remaining filters, mirrors, and backends. This covers both `301`/`302`/`307`/`308` redirects (`Location` header) and synthetic responses such as `?go-get=1` HTML (`200 OK`).
- **`RequestHeadersResponse`:**
  - `CONTINUE` proceeds. `pkg/proxy` rejects `CONTINUE_AND_REPLACE` in Phase 1 because body streaming is disabled.
  - `remove_headers` deletes matching headers case-insensitively and rejects attempts to remove pseudo-headers.
  - `set_headers` honors `append_action` (`APPEND_IF_EXISTS_OR_ADD`, `OVERWRITE_IF_EXISTS_OR_ADD` default, `ADD_IF_ABSENT`, `OVERWRITE_IF_EXISTS`).
  - `:path` mutation updates the request path and raw query after validating it starts with `/`, contains no CR/LF, and passes path normalization.
  - `:authority` mutation updates the request `Host` header and marks the host as explicitly rewritten for backend forwarding.
  - `pkg/proxy` rejects `:method` and `:scheme` mutations in Phase 1 to prevent request smuggling or protocol mismatch.
  - `pkg/proxy` ignores `clear_route_cache` in Phase 1 because route selection is final.

### 3.4 Request-Processing Pipeline and Filter Ordering

For a matched `HTTPRoute` rule, the data plane executes stages in this order:

1. **CORS preflight:** Answers `OPTIONS` preflight requests first, matching existing behavior.
2. **Compiled rule errors and static redirects:** Returns HTTP `500` for unresolved rules or answers static `RequestRedirect` rules. The compiler rejects combining `ExtensionRef` and `RequestRedirect` in the same rule (`IncompatibleFilters`).
3. **Client connection-header stripping:** Strips hop-by-hop headers named by the client's `Connection` header so clients cannot strip gateway- or filter-added headers.
4. **`ExtensionRef` chain (declaration order):** Invokes each `ext_proc` filter sequentially. Any `ImmediateResponse` applies rule-level `CORS` and `ResponseHeaderModifier`, writes the response, and terminates processing. Otherwise, header and `:path`/`:authority` mutations take effect before the next filter runs.
5. **Rule-level `URLRewrite` and `RequestHeaderModifier`:** Applies built-in request mutations after `ext_proc`.
6. **Request mirroring:** Mirrors requests using the post-`ext_proc` headers and path, and skips mirroring if `ext_proc` returned an `ImmediateResponse`.
7. **Backend forwarding:** Selects a backend, applies backend-level filters, and forwards the request. If a rule has no `backendRefs` and all `ext_proc` filters return `CONTINUE` without an `ImmediateResponse`, the proxy returns HTTP `500`.

**Trade-off:** Running `ExtensionRef` filters before `URLRewrite` and `RequestHeaderModifier` ensures redirectors and auth filters see the normalized client path and host, and prevents an extension from stripping gateway-enforced `RequestHeaderModifier` headers. The trade-off is that a route cannot place `RequestHeaderModifier` before `ExtensionRef` to pass metadata to `ext_proc`; instead, `ext_proc` receives structured extension and route identity through `ProcessingRequest.attributes`.

### 3.5 Connection Pooling, Reload Eviction, and Certificate Wiring

- **Connection reuse:** `pkg/proxy` pools one gRPC client connection per distinct `(host, port, TLS configuration)` target so each HTTP request opens a lightweight HTTP/2 stream rather than a new TCP/TLS connection.
- **Eviction on config reload:** Whenever the data plane applies a new `DataplaneConfig`, it closes and evicts pooled gRPC connections no longer referenced by any active rule.
- **Certificate deduplication:** `DataplaneConfig` reuses its content-addressed certificate map to wire Gateway backend client certificates into `ext_proc` TLS configurations without duplicating key material.

## 4. Validation Scenario: `k8s.io` Vanity Redirector

The `k8s.io` vanity redirector workload requires ordered path-capture redirects and `?go-get=1` Go import HTML on the same Gateway and hostnames:

- Ordered captures: `git.k8s.io/<repo>` (`^/([^/]*)/?$`) before `git.k8s.io/<repo>/<path>` (`^/([^/]*)/(.*)$`)
- Optional suffix captures: `sbom.k8s.io/<ver>/release.sig` -> `https://dl.k8s.io/release/<ver>/kubernetes-release.spdx.sig`
- Capture into pre-encoded query strings: `go.k8s.io/owners/<user>` -> `https://cs.k8s.io/?q=<user>&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=`
- Captures across path and `#fragment`: `rel.k8s.io/v1.32/retro` -> `https://github.com/kubernetes/sig-release/tree/master/releases/release-1.32/links.md#retro`
- Trailing-slash sensitivity: `ci-test.k8s.io/e2e/` vs `ci-test.k8s.io/e2e/file`
- `?go-get=1` HTML (`<meta name="go-import" ...>`) coexisting with redirects on `HTTPRoute`

An out-of-process extension runs a shared `ext_proc` Service (`redirect-system/k8s-redirect-extproc:9001` with a SPIFFE SVID) and watches custom `VanityRedirect` and `GoGetResponder` CRDs, publishing `status.externalProcessor` (Section 1.1) on each object. GARI knows nothing about those CRD specs. A cluster administrator grants GARI read RBAC via an aggregated `ClusterRole`, and `redirect-system` authorizes the discovery hop via a `ReferenceGrant`:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-vanity-redirect-discovery
  namespace: redirect-system
spec:
  from:
    - group: redirect.k8s.io
      kind: VanityRedirect
      namespace: k8s-io
    - group: redirect.k8s.io
      kind: GoGetResponder
      namespace: k8s-io
  to:
    - group: ""
      kind: Service
      name: k8s-redirect-extproc
```

Two coexistence patterns work cleanly on `HTTPRoute`:

**Pattern A: `HTTPRoute` query-parameter precedence routes `?go-get=1` separately.** Because Gateway API ranks rules with query-parameter matches ahead of path-only rules, `?go-get=1` hits either a standard `Service` backend or a `GoGetResponder` `ExtensionRef` returning `ImmediateResponse` (`200 OK` HTML), while all other paths hit `VanityRedirect` returning ordered `ImmediateResponse` (`301`/`302` + `Location`):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: git-k8s-io
  namespace: k8s-io
spec:
  parentRefs: [{ name: k8s-io-gateway }]
  hostnames: [git.k8s.io]
  rules:
    - name: go-get
      matches:
        - path: { type: PathPrefix, value: / }
          queryParams: [{ name: go-get, value: "1" }]
      filters:
        - type: ExtensionRef
          extensionRef: { group: redirect.k8s.io, kind: GoGetResponder, name: k8s-go-get }
    - name: vanity-redirects
      matches:
        - path: { type: PathPrefix, value: / }
      filters:
        - type: ExtensionRef
          extensionRef: { group: redirect.k8s.io, kind: VanityRedirect, name: git-k8s-io }
```

**Pattern B: Single `ext_proc` with fallback `backendRefs`.** For hostnames serving both redirects and static files, the rule includes both `ExtensionRef` and `backendRefs`. The processor returns `ImmediateResponse` for `?go-get=1` or matched redirects, and returns `CONTINUE` for unmatched paths so GARI forwards them to the fallback backend.

## 5. Implementation Breakdown

Each follow-up issue represents one idea (~200 non-test lines each), ordered by dependency:

1. **Issue 1 — Status parsing and `HTTPRoute` `ExtensionRef` compilation (`pkg/state`).**
   - Goal: Parse `status.externalProcessor` and `Ready` conditions from unstructured objects, resolve `Service` targets with `ExternalName` rejection, enforce two-hop `ReferenceGrant` and `BackendTLSPolicy`, and compute `Accepted`/`ResolvedRefs` conditions.
   - Acceptance: Unit tests cover every condition row in Section 1.4, including rules without `backendRefs`.
2. **Issue 2 — Dynamic unstructured watch manager (`pkg/controller`).**
   - Goal: Watch referenced `(group, kind)` resources on demand with status-only cache transforms, ref-counted teardown, `CRDView` integration for runtime CRD install/uninstall, and graceful `403 Forbidden` reporting into `State`.
   - Acceptance: Integration tests verify live status updates, post-startup CRD installation, watch cleanup, and `403 Forbidden` isolation.
3. **Issue 3 — Headers-only `ext_proc` v3 client and connection pool (`pkg/proxy`).**
   - Goal: Add the `envoy.service.ext_proc.v3.ExternalProcessor` client, pooled gRPC connections with TLS/SPIFFE verification, per-call deadlines, `ImmediateResponse` size/status caps, and `HeaderMutation` validation.
   - Acceptance: Unit tests against an in-process fake `ext_proc` server verify `ImmediateResponse`, header/`:path`/`:authority` mutations, timeouts, and malformed responses.
4. **Issue 4 — `DataplaneConfig` serialization and proxy pipeline wiring (`pkg/state`, `pkg/proxy`).**
   - Goal: Serialize compiled `ext_proc` targets (with deduplicated client certs) in `DataplaneConfig`, execute `ExtensionRef` chains in the Section 3.4 pipeline order with `FailClosed`/`FailOpen` semantics, and evict unused gRPC connections on config reload.
   - Acceptance: Unit tests verify filter ordering, rules with and without `backendRefs`, mirroring suppression on `ImmediateResponse`, and reload eviction.
5. **Issue 5 — Aggregated RBAC and SPIFFE/cleartext flags (`k8s/controller.yaml`, `pkg/gari`).**
   - Goal: Support opt-in extension CRD RBAC aggregation while preserving narrowed default permissions, and wire SPIFFE trust-bundle verification and `--allow-insecure-ext-proc` mode selection from controller configuration.
   - Acceptance: RBAC and TLS tests verify narrowed default permissions, aggregated extension reads, and cleartext rejection unless explicitly enabled.
6. **Issue 6 — End-to-end validation with `k8s.io` redirector scenarios (`tests/e2e`).**
   - Goal: Exercise dynamic status discovery, cross-namespace `ReferenceGrant` denial and approval, ordered `k8s.io` redirects, `?go-get=1` coexistence with `HTTPRoute`, and fail-closed timeouts against a sample out-of-process `ext_proc` server.

### Deferred (Phase 2+)

- `ResponseHeaders` phase (`responseHeaders: Send`) and reverse-order response execution.
- `RequestBody` and `ResponseBody` streaming with bounded buffering.
- `ExtensionRef` on `backendRefs[].filters` and `GRPCRoute`.
- Bounded `clear_route_cache` re-routing.

## Open Questions

- **Protobuf dependency vs minimal stubs.** Import `go-control-plane`'s `ext_proc/v3` package directly, or generate wire-compatible stubs from a minimal `.proto` subset via `ap tool protoc` to keep `go.mod` small?
- **Status field naming.** Keep `status.externalProcessor`, or coordinate naming (for example, `status.extProc`) with Gateway API upstream discussions before stabilizing it?
- **`ReferenceGrant` `from` subject.** Authorizing `from: <extension-CRD>` prevents tenants from proxying direct HTTP traffic to the `ext_proc` Service, at the cost of one `from` entry per CRD kind. Confirm this separation over authorizing `HTTPRoute`.
- **Controller RBAC aggregation.** Converting `gari-controller`'s `ClusterRole` in `k8s/controller.yaml` to an aggregated `ClusterRole` requires moving base rules into a child `ClusterRole` so Kubernetes aggregation does not overwrite them. Confirm whether that manifest split is acceptable.
