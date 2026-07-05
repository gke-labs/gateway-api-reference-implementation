# Conformance Test Journal: HTTPRouteExactPathMatching

## 1. Test Overview
- **Name**: `HTTPRouteExactPathMatching`
- **Description**: Verifies exact path matching for a single HTTPRoute with different backends.
- **Manifests**: `tests/httproute-exact-path-matching.yaml`

## 2. Issue / Failure Analysis
- **Observed Behavior**: The test failed in CI with a 30s timeout on requests like `/Two`, `/two/`, `/one/example`, and `/` which are expected to return `404 Not Found`.
- **Root Cause**: The conformance test suite is run sequentially, but by default `CleanupTestResources` is `false`. Because of this, resources (such as the catch-all wildcard rule from `HTTPRouteSimpleSameNamespace` or `HTTPRouteMatching`) remained deployed in the cluster and intercepted requests during the `HTTPRouteExactPathMatching` run, causing them to return `200 OK` instead of `404 Not Found`.

## 3. Implementation / Fix Strategy
- **Approach**: 
  - Set `CleanupTestResources: true` in the `suite.ConformanceOptions` struct in `tests/e2e/conformance_test.go` to properly isolate tests and tear down test-specific manifests (like HTTPRoutes) between conformance tests.
  - Keep `tests.HTTPRouteExactPathMatching` enabled/uncommented.
- **Key Files Modified**: `tests/e2e/conformance_test.go`

## 4. Validation & Results
- **Unit Tests**: Existing unit tests cover exact matching logic.
- **Conformance Logs**:
  The E2E test runs successfully with the following results:
  ```
  --- PASS: TestConformance (61.89s)
      ...
      --- PASS: TestConformance/HTTPRouteExactPathMatching (0.02s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/5_request_to_'/Two'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/3_request_to_'/one/example'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/2_request_to_'/'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/4_request_to_'/two/'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/0_request_to_'/one'_should_go_to_infra-backend-v1 (0.00s)
          --- PASS: TestConformance/HTTPRouteExactPathMatching/1_request_to_'/two'_should_go_to_infra-backend-v2 (0.00s)
  ```
