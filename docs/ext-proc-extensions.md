# Design: Generic HTTPRoute ExtensionRef via Envoy ext_proc Status Discovery

## Context and Goals

Gateway API provides the `ExtensionRef` filter on `HTTPRoute` rules so operators can attach implementation-specific or experimental behaviors without encoding configuration in annotations. Today, `pkg/state/httproute.go` rejects `HTTPRouteFilterExtensionRef` as an unsupported filter type. Supporting each third-party extension CRD directly in GARI would couple GARI's controller and data plane to external schemas and release cycles.

This document defines a generic extension mechanism for GARI. An `HTTPRoute` references any Kubernetes object through `filters[].type: ExtensionRef`. The referenced object publishes a Kubernetes `Service` and port in its `status` that implements Envoy's `ext_proc` gRPC protocol (`envoy.service.ext_proc.v3.ExternalProcessor`). GARI discovers the endpoint from `status`, enforces cluster trust boundaries, compiles the target into `DataplaneConfig`, and invokes `ext_proc` from `pkg/proxy`.

This design complements #1637. Issue #1637 handles declarative path-template redirects in-process without an extra network hop. This design lets arbitrary out-of-process extensions implement custom redirects, `?go-get=1` HTML responses, header enrichment, or policy checks without teaching GARI their CRD schemas.

### Terms

- **Extension object:** The Kubernetes object named by an `HTTPRoute` rule filter's `extensionRef` (`LocalObjectReference`). It lives in the same namespace as the referencing `HTTPRoute`.
- **Extension controller:** The third-party controller that reconciles an extension object's `spec` and writes its `ext_proc` endpoint into `status`.
- **External processor (`ext_proc`):** A gRPC server implementing `envoy.service.ext_proc.v3.ExternalProcessor` that inspects and mutates HTTP requests or returns immediate HTTP responses.
- **Discovery hop:** The reference from an extension object's `status` to a Kubernetes `Service` and port.

### Non-Goals for Phase 1

- Request or response body streaming over `ext_proc`. Phase 1 covers request headers only.
- Re-evaluating route matching after `ext_proc` mutates headers (`clear_route_cache`).
- `ExtensionRef` filters on `backendRefs[].filters` or `GRPCRoute`. Both can adopt the same contract in later phases.
- Running arbitrary extension code in-process inside GARI.

## Design Invariants

- **Service-only addressing.** The controller accepts only a Kubernetes `Service` name, optional namespace, and numeric port from an extension object's `status`. It rejects raw IP addresses, arbitrary hostnames, URLs, and `ExternalName` Services so an extension cannot direct data planes to metadata servers, loopback addresses, or external hosts.
- **Two-hop namespace authorization.** An `HTTPRoute` can reference an extension object only in its own namespace because `LocalObjectReference` has no namespace field. If that extension object's `status` points to a `Service` in another namespace, the controller requires a `ReferenceGrant` in the `Service`'s namespace authorizing the extension object's `GroupKind` and namespace.
- **No wildcard CRD RBAC.** The controller watches an extension `GroupVersionKind` only when cluster RBAC grants `get`, `list`, and `watch` for that resource. When RBAC is missing, the controller reports `ResolvedRefs=False` on the referencing `HTTPRoute` rather than failing startup or crashing.
- **Fail-closed default.** When an `ExtensionRef` fails resolution during compilation, the matched rule returns HTTP `500`. When an `ext_proc` call fails at request time, `pkg/proxy` fails closed unless the extension object explicitly opts into `FailOpen`.
- **Bounded request-path work.** Every `ext_proc` call runs under a bounded per-call timeout clamped by the `HTTPRoute` rule's `timeouts.request` deadline. The proxy also caps `ImmediateResponse` body sizes and header mutation counts.
- **Status does not block the data plane.** The controller extracts discovery data from informer caches into `State` (`ModelInputs`) and pushes compiled targets through `DataplaneConfig`. Data planes do not query the Kubernetes API server or resolve `ExtensionRef` objects directly.

## 1. Discovery Contract

### 1.1 Extension Object Status Schema

An extension CRD opts into GARI discovery by publishing an `externalProcessor` object under `status`. GARI reads only `metadata`, `status.conditions`, and `status.externalProcessor`. GARI ignores the extension object's `spec`.

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
    timeout: 200ms               # optional Go duration; defaults to 200ms, capped at 5s
```

Field rules:

- **`serviceRef.name` (required):** Name of a Kubernetes `Service` in `serviceRef.namespace`.
- **`serviceRef.namespace` (optional):** Defaults to the extension object's namespace. Cross-namespace references require a `ReferenceGrant` (see Section 2.1).
- **`serviceRef.port` (required):** Numeric `Service` port (`1` to `65535`). The port must match a port declared on the target `Service`. GARI resolves the `Service` to its cluster DNS name (`<service>.<namespace>.svc.cluster.local`) and port, matching `resolveBackendTarget` in `pkg/state/httproute.go`.
- **`processingMode` (optional):** Defaults to `requestHeaders: Send` and `responseHeaders: Skip`. Phase 1 rejects `responseHeaders: Send` or any body/trailer mode fields as unsupported so extensions cannot silently assume body inspection is active.
- **`failureMode` (optional):** `FailClosed` (default) or `FailOpen`. Unknown values fail validation.
- **`timeout` (optional):** Positive Go duration string. If omitted, GARI applies a `200ms` default. Values above a controller ceiling (`5s` default) fail validation rather than being silently truncated.
- **Readiness via `status.conditions`:** If `status.conditions` includes a condition with `type: Ready`, GARI requires `status: "True"`. If `Ready` is `"False"` or `"Unknown"`, GARI treats the extension as not ready. If `status.conditions` has no `Ready` condition, GARI treats the extension as ready once `status.externalProcessor.serviceRef` is valid and the target `Service` exists.

**Trade-off on `observedGeneration`.** Checking `observedGeneration == metadata.generation` would invalidate a working route whenever an operator edits an extension `spec` and before the extension controller finishes reconciling. Ignoring `observedGeneration` during readiness avoids brief `500` blips on spec edits, at the cost of serving the prior processor configuration until the extension controller updates `status` (or sets `Ready=False` during a broken rollout). We choose to check `Ready=True` without failing on stale `observedGeneration`, while surfacing `Ready=False` promptly.

**Beyond the Gateway API specification:** Gateway API defines `HTTPRouteFilterExtensionRef` as implementation-specific and does not define a status discovery contract. The `status.externalProcessor` schema is a GARI convention designed to stay small enough to align with or migrate to an upstream standard later.

### 1.2 Passing Per-Object Context to Shared Processors

A single `ext_proc` Deployment often serves many extension CR instances across namespaces. To let the processor look up which CR triggered a request without creating one `Service` per CR, `pkg/proxy` populates `ProcessingRequest.attributes` under the key `"gateway.gke-labs.io/ext_proc"` with a protobuf `Struct`:

```json
{
  "extension.group": "redirect.k8s.io",
  "extension.kind": "VanityRedirect",
  "extension.namespace": "k8s-io",
  "extension.name": "git-k8s-io",
  "route.namespace": "k8s-io",
  "route.name": "git-k8s-io",
  "route.rule_name": "default-redirect"
}
```

Because the data plane constructs this `Struct` from compiled `DataplaneConfig`, untrusted HTTP clients cannot spoof these fields. An `ext_proc` server must rely on these attributes only when it authenticates the data plane over mTLS (see Section 2.2).

### 1.3 Watching Arbitrary Referenced Objects in the Controller

GARI's controller feeds all inputs into a central `State` (`pkg/state/state.go`) that compiles `ModelInputs` into route statuses and per-Gateway `DataplaneConfig` snapshots. Dynamic extension discovery fits into that model without introducing per-reconciler cross-object mapping logic.

```
HTTPRoute informer ──▶ State (collects referenced ExtensionRef GroupKinds)
                            │
                            ▼ desired GroupKind set
                ExtensionWatchManager (pkg/controller)
                  • resolves (group, kind) via RESTMapper
                  • starts/stops dynamic unstructured informer per GVK
                  • applies informer Transform: keeps metadata + status only
                  • handles 403 Forbidden and missing CRD gracefully
                            │
                            ▼ UpsertExtensionTarget / DeleteExtensionTarget
                State (ModelInputs.ExtensionTargets) ──▶ CompileModel()
                                                              │
                                                              ▼
                                                       DataplaneConfig
```

Two approaches exist for reading arbitrary extension CRDs:

1. **Direct API `Get` during reconcile.** The reconciler fetches each referenced object on demand. This avoids dynamic informers, but it does not receive push updates when an extension controller updates `status.externalProcessor` or toggles `Ready`. Detecting status changes would require periodic polling.
2. **Ref-counted dynamic unstructured informers (`client-go/dynamic`).** When `State` sees one or more `HTTPRoute` rules referencing `(group, kind)`, an `ExtensionWatchManager` resolves `(group, kind)` to a `GroupVersionResource` via the manager's `RESTMapper` and starts a dynamic informer for that GVR. When the reference count drops to zero, the manager stops the informer after a short grace period (for example, `30s`) to avoid thrashing during route updates.

**Decision:** Use ref-counted dynamic unstructured informers with a status-only transform.

Each dynamic informer attaches a `TransformFunc` that strips `spec` and unrelated fields before storing objects in the informer cache, retaining only `metadata` (`namespace`, `name`, `generation`, `resourceVersion`), `status.conditions`, and `status.externalProcessor`. This bounds controller memory even when third-party CRDs carry large specs.

The manager extracts a typed `ExtensionTarget` record from each informer event and writes it into `State` (`UpsertExtensionTarget` / `DeleteExtensionTarget`), triggering `State.Recompute()`. Because `ModelInputs` remains a plain map (`map[ExtensionObjectKey]*ExtensionTarget`), `CompileModel()` stays pure and deterministic, and aligns with the dependency-tracking model in `docs/incremental-state.md`.

Handling cluster lifecycle edge cases:

- **CRD not installed yet:** `RESTMapper.RESTMapping` returns `NoKindMatchError`. The manager records the `GroupKind` as unserved rather than erroring out. When `CRDView` (`pkg/controller/crdview.go`) observes CRD changes, it notifies `ExtensionWatchManager` to retry unserved `GroupKind`s.
- **RBAC `403 Forbidden`:** Before starting the informer (or on reflector auth error), the manager detects `Forbidden`, records a per-`GroupKind` watch error in `State`, and backs off instead of letting a failed reflector crash the controller manager.
- **CRD removed:** If a watched CRD is deleted, the manager stops its informer, clears cached targets for that `GroupKind`, marks it unserved, and triggers `State.Recompute()` so affected `HTTPRoute` statuses update immediately.

### 1.4 HTTPRoute Conditions (`Accepted` and `ResolvedRefs`)

GARI separates structural route validity (`Accepted`) from object resolution (`ResolvedRefs`), matching `pkg/state/httproute.go` and `pkg/state/conditions.go`. When a rule fails resolution, `Accepted` remains `True` (assuming parent attachment and route structure are valid), `ResolvedRefs` becomes `False`, and GARI records an `ErrorState` on the rule so `pkg/proxy` returns HTTP `500` for matching requests.

| Scenario | `Accepted` | `ResolvedRefs` | Reason | Proxy Behavior |
| --- | --- | --- | --- | --- |
| `type: ExtensionRef` with nil `extensionRef` or empty `kind`/`name` | `False` | unchanged | `UnsupportedValue` | Rule returns `500` |
| `ExtensionRef` combined with `RequestRedirect` in the same rule | `False` | unchanged | `IncompatibleFilters` | Rule returns `500` |
| Extension CRD not installed (`NoKindMatchError`) | `True` | `False` | `InvalidKind` | Rule returns `500` |
| Controller lacks RBAC (`403 Forbidden`) to watch extension GVK | `True` | `False` | `RefNotPermitted` | Rule returns `500` |
| Extension object not found in `HTTPRoute` namespace | `True` | `False` | `BackendNotFound` | Rule returns `500` |
| Extension object exists, `status.externalProcessor` missing or `Ready=False` | `True` | `False` | `ExtensionRefNotReady` | Rule returns `500` |
| `status.externalProcessor` malformed (bad port, timeout, mode, or `ExternalName` Service) | `True` | `False` | `InvalidExtensionRef` | Rule returns `500` |
| Cross-namespace `serviceRef` lacks matching `ReferenceGrant` | `True` | `False` | `RefNotPermitted` | Rule returns `500` |
| Target `Service` or declared port does not exist | `True` | `False` | `BackendNotFound` | Rule returns `500` |
| Target `Service` has an invalid `BackendTLSPolicy` | `True` | `False` | `ResolvedRefs` error from `BackendTLSPolicy` | Rule returns `500` |
| Valid and ready extension | `True` | `True` | `ResolvedRefs` | Invokes `ext_proc` |

**Beyond the Gateway API specification:** Gateway API v1 defines `InvalidKind`, `RefNotPermitted`, and `BackendNotFound` for `ResolvedRefs`, and `UnsupportedValue` and `IncompatibleFilters` for `Accepted`. It does not define dedicated `ResolvedRefs` reasons for an extension object that exists but has not published ready status or has invalid discovery status. GARI uses `ExtensionRefNotReady` and `InvalidExtensionRef` for those cases and surfaces actionable messages in the condition `Message` field. Reusing `BackendNotFound` for a missing extension object keeps conformance tooling compatibility while distinguishing readiness and schema errors cleanly.

An `HTTPRoute` rule with an `ExtensionRef` filter and no `backendRefs` is valid. Many extensions (such as redirectors or `?go-get=1` responders) answer every matching request with an `ImmediateResponse` and have no upstream backend.

## 2. Security and Trust Boundaries

### 2.1 Namespace Scoping, ReferenceGrant, and SSRF Prevention

Discovery introduces a two-hop reference chain:

```
HTTPRoute (ns: tenant-a)
   │  Hop 1: LocalObjectReference (same namespace enforced by Gateway API schema)
   ▼
Extension Object (ns: tenant-a)
   │  Hop 2: status.externalProcessor.serviceRef
   ▼
Kubernetes Service (ns: tenant-a or ns: ext-system)
```

Without controls on Hop 2, a tenant who can write `status` on a CRD (for example, a CRD missing `subresources.status: {}`, or a tenant-controlled extension) could point `serviceRef` at any cluster Service, metadata IP, or external host and turn GARI's data plane into an SSRF proxy.

GARI enforces four layered controls:

1. **Service-only resolution, no `ExternalName`.** The controller rejects raw IPs and arbitrary hostnames in `status`. It resolves `serviceRef` against its `Services` cache in `State` and rejects `corev1.ServiceTypeExternalName` Services so DNS CNAME indirection cannot escape the cluster.
2. **Cross-namespace `ReferenceGrant` on Hop 2.** When `serviceRef.namespace` equals the extension object's namespace, the controller permits the reference without a `ReferenceGrant`. When `serviceRef.namespace` differs, the controller checks `RefValidator.IsReferencePermitted(from, to)` (`pkg/state/referencegrant.go`) with:
   - `from`: `{ Group: <extension-group>, Kind: <extension-kind>, Namespace: <extension-namespace> }`
   - `to`: `{ Group: "", Kind: "Service", Name: <serviceRef.name>, Namespace: <serviceRef.namespace> }`

   Authorizing the extension CRD's `GroupKind` as `from`, rather than `HTTPRoute`, prevents privilege bleed. If the `ReferenceGrant` instead authorized `from: gateway.networking.k8s.io/HTTPRoute` to `to: Service/k8s-redirect-extproc`, any `HTTPRoute` in `tenant-a` could also list `k8s-redirect-extproc` directly in `backendRefs` and proxy untrusted client traffic straight to the internal gRPC server. Authorizing the extension `GroupKind` grants only the discovery hop. `pkg/state/referencegrant.go` already matches arbitrary `from.GroupKind` values without schema changes.
3. **Explicit RBAC opt-in for extension CRDs.** GARI's default `ClusterRole` in `k8s/controller.yaml` keeps narrowed permissions, verified by `TestController_NarrowedCRDPermissions` in `pkg/gari/rbac_test.go`. It does not grant wildcard `*/*` read access. To enable an extension CRD, a cluster administrator installs an aggregated `ClusterRole` labeled `rbac.authorization.k8s.io/aggregate-to-gari-controller: "true"` granting `get`, `list`, and `watch` on that specific API group and resource. This acts as a cluster-level allowlist of trusted extension CRDs.
4. **Status subresource expectation.** Extension CRD authors should enable `subresources.status: {}` and restrict `*/status` write RBAC to the extension controller's ServiceAccount so route authors cannot forge `status.externalProcessor` on same-namespace objects.

### 2.2 TLS, mTLS, and SPIFFE Alignment

GARI's internal workload identity direction uses SPIFFE X.509-SVIDs under the `cluster.local` trust domain (`spiffe/credentials.go`, `pkg/provisioning/singlepod/address_provider.go`, and #1503):

- Today, `singlepod` creates one `ServiceAccount` per Gateway (`ResourceNameForGateway(gw.Name)` in `gw.Namespace`) and mounts the cluster SPIFFE trust bundle ConfigMap (`gari-spiffe-bundle`, key `bundle.pem`) at `/etc/gari/bundle/bundle.pem`.
- Issue #1503 generalizes the `spiffe/` Job to issue X.509-SVIDs (`spiffe://cluster.local/ns/<ns>/sa/<sa>`) and DNS SANs (`<service>.<ns>.svc.cluster.local`) for workloads in any namespace, with a long-term path to `certserver` issuance.

Transport security between `pkg/proxy` and an `ext_proc` Service builds on two existing mechanisms rather than inventing a new TLS CRD:

1. **Server verification (`BackendTLSPolicy` + SPIFFE bundle).**
   - If a `BackendTLSPolicy` targets the `ext_proc` `Service` (with an optional `sectionName` matching the port name), GARI resolves it through the same `BackendTLSPolicy` compiler (`pkg/state/backendtlspolicy.go`) and `InternalTLSConfig` path used for HTTP backends. This supports custom CA ConfigMaps, system roots, hostname verification, and URI SAN validation (`spiffe://cluster.local/ns/<ns>/sa/<sa>`).
   - If no `BackendTLSPolicy` targets the `Service`, the `Service` port declares `appProtocol: kubernetes.io/h2c` (or `h2c`), and the controller allows cleartext `ext_proc`, the data plane dials plaintext HTTP/2 (`h2c`).
   - Otherwise, when the data plane has the mounted SPIFFE trust bundle (`/etc/gari/bundle/bundle.pem`), it dials TLS and verifies the server certificate against the SPIFFE trust bundle and the `Service`'s cluster DNS name (`spiffe.ServiceClusterDNSName`). If neither a `BackendTLSPolicy`, a SPIFFE bundle, nor an explicit `h2c` opt-in is present, the controller rejects the target rather than downgrading to plaintext.
2. **Client authentication (mTLS).**
   - `pkg/state/dataplane.go` already compiles `Gateway.spec.tls.backend.clientCertificateRef` into `DataplaneConfig.BackendClientCertID`. When configured on a Gateway, `pkg/proxy` presents that client certificate on TLS `ext_proc` connections as well.
   - Once #1503 issues per-Gateway data-plane SVIDs, `singlepod` mounts the Gateway's X.509-SVID (`spiffe://cluster.local/ns/<gw-ns>/sa/<gw-sa>`) into the data-plane pod. `pkg/proxy` presents it as the default client certificate for SPIFFE-verified `ext_proc` connections. The `ext_proc` server can then authorize callers by peer SPIFFE ID during the TLS handshake without calling `TokenReview` on the request path.

**Trade-off:** Requiring TLS by default adds setup steps for simple local extensions. Allowing explicit `h2c` opt-in via Service `appProtocol`, gated by a controller flag `--allow-insecure-ext-proc` (`false` in production manifests and enabled in local or test setups), balances security with local testability.

### 2.3 Timeouts, Failure Modes, and Resource Limits

- **Per-call timeout.** Each `ext_proc` invocation uses a context deadline equal to `min(extension.timeout, remaining rule timeouts.request)`. The default extension timeout is `200ms` and the controller caps configured timeouts at `5s`.
- **Fail-closed default (`FailClosed`).** When an `ext_proc` call fails:
  - Deadline exceeded (`codes.DeadlineExceeded` or `context.DeadlineExceeded`) returns HTTP `504 Gateway Timeout`.
  - Transport errors (`codes.Unavailable`), gRPC errors, unexpected EOF, or malformed `ProcessingResponse` messages return HTTP `502 Bad Gateway` (or `500 Internal Server Error` if the processor returns invalid mutations).
  - The proxy logs the failure details (including `ImmediateResponse.details` when present) and does not expose internal gRPC errors to clients unless `Proxy.DebugErrorResponses()` is enabled.
- **Fail-open (`FailOpen`).** The proxy fails open only when `status.externalProcessor.failureMode` is `FailOpen`. On timeout or transport/protocol error, the proxy logs the failure, discards partial mutations from that filter, and continues evaluating subsequent filters and backends. Extensions enforcing authentication or authorization should not configure `FailOpen`.
- **Response and header bounds.**
  - The proxy caps `ImmediateResponse.body` at `1 MiB` using both gRPC `MaxCallRecvMsgSize` and explicit length checks.
  - The proxy limits header mutation counts (for example, 100 mutations per response) and total mutated header bytes. It validates each header name and value with `httpguts.ValidHeaderFieldName` and `httpguts.ValidHeaderFieldValue` to prevent CRLF injection.
  - The proxy rejects hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Upgrade`, `Proxy-Connection`, `TE`) in `HeaderMutation`.

## 3. Data-Plane Execution (`pkg/proxy`)

### 3.1 Protocol Surface (`envoy.service.ext_proc.v3.ExternalProcessor`)

Envoy's `ext_proc` service exposes one bidirectional streaming RPC:

```protobuf
service ExternalProcessor {
  rpc Process(stream ProcessingRequest) returns (stream ProcessingResponse);
}
```

#### Dependency Trade-off: `go-control-plane` vs Minimal Generated Proto

Two options exist for Go protobuf types:

1. **Import `github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3`.** Gives exact upstream types immediately, but pulls a large transitive dependency graph (`cel-go`, `protoc-gen-validate`, Envoy xDS packages) into GARI's root `go.mod`.
2. **Generate wire-compatible Go stubs from the minimal `ext_proc` v3 `.proto` subset.** GARI already uses `google.golang.org/grpc`, `google.golang.org/protobuf`, and `ap tool protoc` (`pkg/dataplane/push/generate.go`). Keeping a small, wire-compatible subset of `external_processor.proto`, `processing_mode.proto`, `base.proto` (`HeaderValueOption`, `HeaderMap`), and `http_status.proto` keeps `go.mod` lean and readable while remaining wire-compatible with standard Envoy `ext_proc` servers written in Go, Rust, Python, or C++.

Open Questions tracks this choice. Both options produce the same wire protocol and runtime behavior.

### 3.2 Phase 1 Execution: Headers-Only vs Body Streaming

Phase 1 runs **request headers only** (`ProcessingRequest.request_headers`):

1. `pkg/proxy` opens a `Process` stream on the pooled `grpc.ClientConn` for the target `ext_proc` Service.
2. `pkg/proxy` sends a single `ProcessingRequest` containing:
   - `request_headers` (`HttpHeaders`):
     - Pseudo-headers: `:method`, `:scheme` (`http` or `https`), `:authority` (`r.Host`), and `:path` (`r.URL.RequestURI()`, preserving raw query parameters).
     - Incoming HTTP request headers (lowercased header names, one `HeaderValue` entry per header value, using `raw_value` bytes as required by Envoy v3 `HeaderValue`).
     - `end_of_stream`: `true` when `r.Body == nil || r.Body == http.NoBody` (or `r.ContentLength == 0`), `false` otherwise. Because Phase 1 does not negotiate body streaming, `pkg/proxy` closes the send side (`CloseSend`) immediately after sending `request_headers`.
   - `attributes`: the `"gateway.gke-labs.io/ext_proc"` `Struct` described in Section 1.2.
3. `pkg/proxy` reads one `ProcessingResponse` from the stream and closes the stream.

**Why headers-only first:** Redirects, `?go-get=1` HTML synthesis, authentication/authorization checks, and header/path rewrites need only request headers. Deferring `RequestBody` and `ResponseBody` streaming avoids buffering bodies in memory, preserves `pkg/proxy`'s streaming response behavior (`copyResponseBody`, Server-Sent Events, WebSockets, and `bodyDeadlineReader`), and avoids bidirectional stream flow-control complexity until a concrete use case requires body inspection.

### 3.3 Handling `ProcessingResponse`

`pkg/proxy` handles the two Phase 1 response variants:

- **`ImmediateResponse`:**
  - Validates the HTTP status code (`100` to `599`; rejects `0` or out-of-range values).
  - Starts a fresh response header map, applies `ImmediateResponse.headers` (`set_headers` and `remove_headers`), strips hop-by-hop headers, and then applies rule-level `CORS` and `ResponseHeaderModifier` (consistent with `bestRule.Redirect` and `bestRule.Error` in `pkg/proxy/proxy.go`).
  - Writes the status code and `ImmediateResponse.body` directly to `w`.
  - Short-circuits request processing so remaining `ExtensionRef` filters, `URLRewrite`, `Mirrors`, and `Backends` do not run.
  - Supports `301`/`302`/`307`/`308` redirects (setting `Location` in `headers`) and synthetic responses such as `?go-get=1` (`200 OK`, `Content-Type: text/html; charset=utf-8`, HTML body).

- **`RequestHeadersResponse` (`CommonResponse`):**
  - `status`: `CONTINUE` proceeds to the next filter or backend. `pkg/proxy` rejects `CONTINUE_AND_REPLACE` in Phase 1 (failing closed) because body streaming is disabled.
  - `header_mutation.remove_headers`: removes matching headers case-insensitively. `pkg/proxy` rejects attempts to remove pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`).
  - `header_mutation.set_headers`: applies each `HeaderValueOption` honoring `append_action`:
    - `APPEND_IF_EXISTS_OR_ADD` (and deprecated `append: true`) appends the value.
    - `OVERWRITE_IF_EXISTS_OR_ADD` (default) replaces existing values or adds the header.
    - `ADD_IF_ABSENT` adds only if the header is not present.
    - `OVERWRITE_IF_EXISTS` replaces only if the header is already present.
  - Pseudo-header mutations in `set_headers`:
    - `:path`: parses as a relative request-target starting with `/`. Updates `r.URL.Path`, `r.URL.RawPath`, and `r.URL.RawQuery`, then re-runs `normalizeRequestPath` so dot-segments and percent-encoding stay safe. Rejects invalid paths or paths containing CR/LF.
    - `:authority`: updates `r.Host` and marks `hostRewrittenContextKey` in `r.Context()` (matching `Proxy.rewrite` in `pkg/proxy/proxy.go` so backend forwarding preserves the rewritten Host header).
    - `:method` and `:scheme`: `pkg/proxy` rejects mutations to these headers in Phase 1 to prevent request smuggling or protocol mismatch on already-matched HTTP rules.
  - `clear_route_cache`: `pkg/proxy` ignores this flag in Phase 1 because route selection is final once `state.MatchRoute` selects `bestRule`.

### 3.4 Interaction with `HTTPRoute` Filters and Backends

`Proxy.ServeHTTP` (`pkg/proxy/proxy.go`) executes a matched `bestRule` in this order:

1. **CORS preflight (`OPTIONS` with `Origin`)** — `ServeHTTP` answers preflight requests first, matching existing behavior.
2. **Static `bestRule.Error`** — `ServeHTTP` returns HTTP `500` immediately when compilation failed (for example, an unresolved `ExtensionRef`).
3. **Static `bestRule.Redirect`** — `ServeHTTP` answers static redirects immediately. The compiler rejects `ExtensionRef` and `RequestRedirect` on the same rule as `IncompatibleFilters`.
4. **`stripClientConnectionHeaders(r.Header)`** — `ServeHTTP` strips client-named connection headers before filters run, preserving GARI's invariant that clients cannot strip gateway- or filter-added headers.
5. **`bestRule.ExternalProcessors` (in declaration order)** — `ServeHTTP` invokes each `ext_proc` filter sequentially:
   - If a processor returns `ImmediateResponse`, `ServeHTTP` applies rule-level `CORS` and `ResponseHeaderModifier`, writes the response, and returns immediately.
   - If a processor returns `RequestHeadersResponse`, `ServeHTTP` applies the mutations to `r` before invoking the next processor.
6. **Rule-level `URLRewrite` and `RequestHeaderModifier`** — `ServeHTTP` applies these filters to `r` after `ext_proc` mutations.
7. **Rule-level `Mirrors`** — `ServeHTTP` sends mirrored requests with the post-`ext_proc` headers and path, and skips mirroring if `ext_proc` returned an `ImmediateResponse`.
8. **Backend selection, backend-level filters, and `forward`** — When `len(bestRule.Backends) > 0`, `ServeHTTP` forwards the mutated request to the selected backend. When `len(bestRule.Backends) == 0` and all `ext_proc` filters return `CONTINUE` without an `ImmediateResponse`, `ServeHTTP` returns HTTP `500` (`No backend refs specified`), matching existing behavior.

**Trade-off on filter ordering:** Running `ExternalProcessors` before `URLRewrite` and `RequestHeaderModifier` ensures that redirectors and auth filters inspect the normalized incoming client path and host, and prevents an extension from stripping gateway-configured `RequestHeaderModifier` headers. The trade-off is that a route cannot place a `RequestHeaderModifier` ahead of an `ExtensionRef` to inject a custom header for `ext_proc` to read. Instead, `ext_proc` receives structured extension and route identity through `ProcessingRequest.attributes`. If interleaved declaration order across built-in and `ExtensionRef` filters is later needed, `InternalRule` can switch to an ordered filter list without changing the external API.

### 3.5 Connection Pooling and Config Reloads

`InternalRule` gains `ExternalProcessors []InternalExternalProcessor`, serialized inside `DataplaneConfig`:

```go
type InternalExternalProcessor struct {
	Host             string
	Port             int32
	TLSConfig        *InternalTLSConfig
	UseSPIFFEBundle  bool
	AllowCleartext   bool
	Timeout          time.Duration
	FailureMode      ExternalProcessorFailureMode
	ExtensionRef     ExternalProcessorRefMetadata // group, kind, namespace, name
	RouteRef         types.NamespacedName
	RuleName         string
}
```

In `pkg/proxy`, `Proxy` maintains a map of pooled `*grpc.ClientConn` instances keyed by `(host, port, tlsConfigHash)`, mirroring `backendTransportKey` and `evictUnusedTransports` in `pkg/proxy/proxy.go`.

- Each HTTP request opens a lightweight HTTP/2 stream over the existing `grpc.ClientConn`.
- On `Proxy.UpdateConfig`, `Proxy` closes and evicts gRPC connections no longer referenced by any active rule.
- `DataplaneConfig` certificate deduplication (`pkg/state/dataplane.go`) wires `BackendClientCertID` into `InternalExternalProcessor.TLSConfig.ClientCert` using the same content-addressed certificate map used for `InternalBackend`.

## 4. Validation Scenario: `k8s.io` Vanity Redirector (#1601)

Issue #1601 lists real-world `k8s.io` vanity redirector rules currently served by nginx that cannot be expressed with standard `HTTPRoute` `RequestRedirect`:

- `git.k8s.io/<repo>` -> `https://github.com/kubernetes/<repo>` (`^/([^/]*)/?$` before `^/([^/]*)/(.*)$`)
- `git.k8s.io/<repo>/<path>` -> `https://github.com/kubernetes/<repo>/blob/master/<path>`
- `sbom.k8s.io/<ver>/release.sig` -> `https://dl.k8s.io/release/<ver>/kubernetes-release.spdx.sig` (optional suffix captures)
- `go.k8s.io/owners/<user>` -> `https://cs.k8s.io/?q=<user>&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=` (escaping captured `<user>` without double-encoding `vendor%2F`)
- `rel.k8s.io/v1.32/retro` -> `https://github.com/kubernetes/sig-release/tree/master/releases/release-1.32/links.md#retro` (captures across path and `#fragment`)
- `ci-test.k8s.io/e2e/` vs `ci-test.k8s.io/e2e/file` (trailing-slash sensitive ordered rules)
- `?go-get=1` requests returning Go vanity import HTML (`<meta name="go-import" ...>`) alongside redirects on the same Gateway and hostname

### 4.1 Architecture of the Out-of-Process Extension

An external project runs a single `k8s-redirect-controller` Deployment in namespace `redirect-system`, exposed via Service `k8s-redirect-extproc:9001` (with a SPIFFE X.509-SVID). The controller watches a custom `VanityRedirect` CRD (`redirect.k8s.io/v1alpha1`), compiles each `VanityRedirect`'s ordered rules in memory, and writes `status.externalProcessor` on each `VanityRedirect` object.

GARI knows nothing about `VanityRedirect` or `GoGetResponder` specs. A cluster administrator grants GARI read RBAC on those CRDs via an aggregated `ClusterRole`, and `redirect-system` grants cross-namespace discovery via a `ReferenceGrant`.

### 4.2 Manifests

```yaml
# In namespace: redirect-system
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
---
# In namespace: k8s-io (spec owned by the third-party extension; status read by GARI)
apiVersion: redirect.k8s.io/v1alpha1
kind: VanityRedirect
metadata:
  name: git-k8s-io
  namespace: k8s-io
spec:
  rules:
    - match: "^/([^/]*)/?$"
      statusCode: 302
      location: "https://github.com/kubernetes/$1"
    - match: "^/([^/]*)/(.*)$"
      statusCode: 302
      location: "https://github.com/kubernetes/$1/blob/master/$2"
status:
  conditions:
    - type: Ready
      status: "True"
      observedGeneration: 1
  externalProcessor:
    serviceRef:
      name: k8s-redirect-extproc
      namespace: redirect-system
      port: 9001
    failureMode: FailClosed
    timeout: 200ms
```

### 4.3 Coexistence of Ordered Redirects and `?go-get=1` on `HTTPRoute`

Two clean coexistence patterns work without special-casing in GARI:

**Pattern A: `HTTPRoute` query-parameter precedence routes `?go-get=1` separately.**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: git-k8s-io
  namespace: k8s-io
spec:
  parentRefs:
    - name: k8s-io-gateway
  hostnames:
    - git.k8s.io
  rules:
    # Higher precedence: matches ?go-get=1 before the catch-all redirect rule.
    # Can target either a standard Service backend or a dedicated GoGetResponder ExtensionRef.
    - name: go-get
      matches:
        - path:
            type: PathPrefix
            value: /
          queryParams:
            - name: go-get
              value: "1"
      filters:
        - type: ExtensionRef
          extensionRef:
            group: redirect.k8s.io
            kind: GoGetResponder
            name: k8s-go-get
    # Lower precedence: all other requests go to the ordered vanity redirector.
    - name: vanity-redirects
      matches:
        - path:
            type: PathPrefix
            value: /
      filters:
        - type: ExtensionRef
          extensionRef:
            group: redirect.k8s.io
            kind: VanityRedirect
            name: git-k8s-io
```

Because `state.MatchRoute` ranks rules with query-parameter matches ahead of path-only rules, `GET https://git.k8s.io/kubernetes?go-get=1` matches rule `go-get`:

1. `pkg/proxy` calls `k8s-redirect-extproc:9001` with `extension.kind=GoGetResponder`, `extension.name=k8s-go-get`, `:authority=git.k8s.io`, and `:path=/kubernetes?go-get=1`.
2. The processor returns `ImmediateResponse` with status `200`, `content-type: text/html; charset=utf-8`, and body `<meta name="go-import" content="k8s.io/kubernetes git https://github.com/kubernetes/kubernetes">`.
3. `pkg/proxy` returns `200 OK` immediately.

Meanwhile, `GET https://git.k8s.io/kubernetes/README.md` matches rule `vanity-redirects`:

1. `pkg/proxy` calls `k8s-redirect-extproc:9001` with `extension.kind=VanityRedirect`, `extension.name=git-k8s-io`, `:authority=git.k8s.io`, and `:path=/kubernetes/README.md`.
2. The processor evaluates rules in order: `^/([^/]*)/?$` does not match; `^/([^/]*)/(.*)$` matches with `$1=kubernetes`, `$2=README.md`.
3. The processor returns `ImmediateResponse{status: 302, headers: {"location": "https://github.com/kubernetes/kubernetes/blob/master/README.md"}}`.
4. `pkg/proxy` writes `302 Found` with the `Location` header and returns immediately.

The same mechanism handles `go.k8s.io/owners/<user>`, `rel.k8s.io/v1.32/retro`, `sbom.k8s.io/<ver>/release.sig`, and trailing-slash sensitive `ci-test.k8s.io/e2e/` vs `ci-test.k8s.io/e2e/file`—each hostname attaches its `VanityRedirect` object to its `HTTPRoute`, and the processor owns the ordered matching and percent-encoding logic.

**Pattern B: Single `ext_proc` with fallback `backendRefs`.**

If a hostname serves both redirects and static files from a backend `Service`, the `HTTPRoute` rule includes both the `ExtensionRef` filter and a `backendRefs` entry. The processor returns `ImmediateResponse` for `?go-get=1` or matched redirects, and returns `RequestHeadersResponse{status: CONTINUE}` for unmatched paths so GARI forwards those requests to the fallback backend.

## 5. Implementation Breakdown

Each follow-up issue represents one idea with a budget of ~200 non-test lines, ordered so every PR compiles, passes tests, and is independently reviewable.

1. **Issue 1 — Extension status parser and `pkg/state` compilation (~180 non-test lines).**
   - Define `ExtensionObjectKey`, `ExtensionTarget`, `ParseExtensionTarget(*unstructured.Unstructured)`, and `InternalExternalProcessor` in `pkg/state`.
   - Add `ExtensionTargets` to `ModelInputs` and `ExternalProcessors` to `InternalRule`.
   - Compile `HTTPRouteFilterExtensionRef` in `pkg/state/httproute.go` with `Accepted` / `ResolvedRefs` conditions, `Service` lookup, `ExternalName` rejection, `ReferenceGrant` validation on the extension `GroupKind`, and `BackendTLSPolicy` reuse.
   - Unit tests in `pkg/state/httproute_test.go` covering every condition row in Section 1.4.

2. **Issue 2 — Dynamic unstructured watch manager in `pkg/controller` (~200 non-test lines).**
   - Add `ExtensionWatchManager` in `pkg/controller` using `client-go/dynamic` informers with a metadata-and-status-only `TransformFunc`.
   - Sync desired `GroupKind`s from `State`, ref-count watches with teardown grace period, integrate with `CRDView` for runtime CRD install/uninstall, and surface `403 Forbidden` / `NoKindMatchError` into `State`.
   - Integration tests with `testenv` verifying dynamic status updates, CRD install after startup, watch cleanup, and `403 Forbidden` handling.

3. **Issue 3 — Minimal `ext_proc` v3 gRPC client and connection pool (`pkg/proxy/extproc`) (~200 non-test lines).**
   - Add the minimal `envoy.service.ext_proc.v3.ExternalProcessor` protobuf definitions/client (per the Open Question decision) and a headers-only `Client` in `pkg/proxy/extproc`.
   - Implement pooled `*grpc.ClientConn` management with TLS config wiring (`InternalTLSConfig` + optional SPIFFE bundle), per-call deadlines, `ImmediateResponse` size/status validation, and `HeaderMutation` validation.
   - Unit tests against an in-process fake `ExternalProcessor` gRPC server covering `ImmediateResponse`, header/`:path`/`:authority` mutations, timeouts, and malformed responses.

4. **Issue 4 — `DataplaneConfig` serialization and `Proxy.ServeHTTP` integration (~180 non-test lines).**
   - Wire `InternalExternalProcessor` (including `ClientCertID` certificate resolution) into `pkg/state/dataplane.go`.
   - Invoke `ExternalProcessors` in `Proxy.ServeHTTP` (`pkg/proxy/proxy.go`) with `ImmediateResponse` short-circuiting, header/`:path`/`:authority` mutation application, `FailClosed`/`FailOpen` handling, and gRPC connection eviction on `Proxy.UpdateConfig`.
   - Unit tests in `pkg/state/dataplane_test.go` and `pkg/proxy/proxy_test.go` verifying filter ordering, rules with and without `backendRefs`, mirroring suppression on `ImmediateResponse`, and reload eviction.

5. **Issue 5 — Aggregated RBAC and SPIFFE mTLS wiring (~120 non-test lines).**
   - Add `aggregationRule` (`rbac.authorization.k8s.io/aggregate-to-gari-controller: "true"`) or documented RBAC pattern in `k8s/controller.yaml` while preserving `TestController_NarrowedCRDPermissions`.
   - Wire the mounted SPIFFE trust bundle path (`/etc/gari/bundle/bundle.pem`) and `--allow-insecure-ext-proc` flag into `pkg/gari` and `pkg/proxy`, and document client SVID hookup once #1503 lands.
   - RBAC and TLS verification tests in `pkg/gari`.

6. **Issue 6 — End-to-end validation with `k8s.io` redirector scenarios (~200 non-test lines).**
   - Add a test `ext_proc` server and CRD in `tests/e2e` exercising dynamic status discovery, cross-namespace `ReferenceGrant` denial and approval, ordered `k8s.io` redirects (`git.k8s.io`, `sbom.k8s.io`, `go.k8s.io/owners/<user>`, `rel.k8s.io/v1.32/retro`, `ci-test.k8s.io/e2e/`), `?go-get=1` coexistence with `HTTPRoute`, and fail-closed timeout behavior.

### Deferred (Phase 2+)

- `ResponseHeaders` phase (`responseHeaders: Send`) and reverse-order response filter execution.
- `RequestBody` and `ResponseBody` streaming modes with bounded buffering.
- `ExtensionRef` on `backendRefs[].filters` and `GRPCRoute`.
- Bounded `clear_route_cache` re-routing if a concrete use case emerges.

## Open Questions

- **Protobuf dependency vs minimal stubs.** Should Issue 3 import `github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3` directly or generate wire-compatible stubs from a minimal `.proto` subset via `ap tool protoc` to keep `go.mod` small?
- **Status field naming and upstream alignment.** Is `status.externalProcessor` the right field name, or should we coordinate naming (for example `status.extProc` or a shared status condition/endpoint convention) with Gateway API upstream discussions before stabilizing it?
- **`ReferenceGrant` `from` subject.** Authorizing `from: <extension-CRD>` prevents tenants from proxying direct HTTP traffic to the `ext_proc` Service, but requires one `ReferenceGrant` entry per extension CRD kind. Should we require `from: <extension-CRD>`, or also document how extension operators ship a single `ReferenceGrant` template?
- **Controller RBAC aggregation.** `k8s/controller.yaml` currently defines a plain `ClusterRole`. Switching `gari-controller` to an aggregated `ClusterRole` requires separating the base rules into a child `ClusterRole` so Kubernetes aggregation does not overwrite them. Confirm whether that split is acceptable in `k8s/controller.yaml` and `pkg/gari/rbac_test.go`.
