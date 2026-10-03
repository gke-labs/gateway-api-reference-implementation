# Conformance Test Journal: HTTPRouteRequestMirror, HTTPRouteRequestMultipleMirrors, and HTTPRouteRequestPercentageMirror

## 1. Test Overview
- **Name**: `HTTPRouteRequestMirror`, `HTTPRouteRequestMultipleMirrors`, and `HTTPRouteRequestPercentageMirror`
- **Description**:
  - `HTTPRouteRequestMirror`: Verifies that an HTTPRoute with a RequestMirror filter duplicates traffic asynchronously (fire-and-forget) to a mirror backend while forwarding the original request to the main backend, and applies rule-level request header modifiers to both.
  - `HTTPRouteRequestMultipleMirrors`: Verifies that multiple RequestMirror filters can be attached to the same HTTPRoute rule and each receives the duplicated request.
  - `HTTPRouteRequestPercentageMirror`: Verifies percentage and fraction-based request mirroring where only a configured percentage or fraction of requests are mirrored to the mirror backend.
- **Manifests**:
  - `tests/httproute-request-mirror.yaml`
  - `tests/httproute-request-multiple-mirrors.yaml`
  - `tests/httproute-request-percentage-mirror.yaml`

## 2. Issue / Failure Analysis
- **Observed Behavior**: The RequestMirror conformance tests were not enabled in `tests/e2e/conformance_test.go`, and the reference implementation did not support the `RequestMirror` filter type.
- **Root Cause**:
  - `pkg/state/httproute.go` did not handle `gatewayv1.HTTPRouteFilterRequestMirror` and treated it as an unsupported filter type.
  - `pkg/state/gateway.go` lacked `InternalMirror` definition and `Mirrors` field on `InternalRule`.
  - `pkg/proxy/proxy.go` did not support dispatching mirrored requests or handling percentage/fractional mirror distributions.

## 3. Implementation / Fix Strategy
- **Approach**:
  1. Defined `InternalMirror` struct in `pkg/state/gateway.go` containing `Backend InternalBackend`, `Numerator int32`, and `Denominator int32`, and added `Mirrors []InternalMirror` to `InternalRule`.
  2. Implemented `HTTPRouteFilterRequestMirror` support in `CompileHTTPRoute` in `pkg/state/httproute.go`:
     - Validated `Percent` and `Fraction` configurations (ensuring mutual exclusivity, valid bounds, and valid numerator/denominator ratios).
     - Resolved mirror backend references (Service lookup, cross-namespace ReferenceGrant checks, Port/AppProtocol resolution, and BackendTLSPolicy matching).
     - Appended valid mirrors to `iRule.Mirrors`, and updated `ResolvedRefs` and `Accepted` conditions on the route state accordingly.
  3. Implemented request mirroring in `pkg/proxy/proxy.go`:
     - Evaluated each mirror's probability using `rand.Int32N(denominator) < numerator`.
     - Buffered `r.Body` when mirrors are active so both the primary backend and mirror backends receive the complete body.
     - Dispatched mirrored requests asynchronously in a separate goroutine with fire-and-forget semantics, cloning request headers, stripping hop-by-hop headers, setting `X-Forwarded-For`, and using independent background contexts and transports so mirror latency/failures do not impact the client.
  4. Added comprehensive unit tests in `pkg/state/httproute_test.go` and `pkg/proxy/proxy_test.go`.
  5. Added `tests.HTTPRouteRequestMirror`, `tests.HTTPRouteRequestMultipleMirrors`, and `tests.HTTPRouteRequestPercentageMirror` in alphabetical order to `selectedTests` in `tests/e2e/conformance_test.go`.
- **Key Files Modified**:
  - `pkg/state/gateway.go`
  - `pkg/state/httproute.go`
  - `pkg/state/httproute_test.go`
  - `pkg/proxy/proxy.go`
  - `pkg/proxy/proxy_test.go`
  - `tests/e2e/conformance_test.go`
  - `.agents/skills/implement-conformance-test/journal/httproute-request-mirror.md`

## 4. Validation & Results
- **Unit Tests**:
  - Ran `go test ./pkg/...` - all unit tests pass.
- **Conformance Logs**:
  - Verified with `ap e2e` running conformance tests, including `HTTPRouteRequestMirror`, `HTTPRouteRequestMultipleMirrors`, and `HTTPRouteRequestPercentageMirror`.
