# Conformance Test Journal: HTTPRouteMethodMatching

## 1. Test Overview
- **Name**: `HTTPRouteMethodMatching`
- **Description**: Verifies that HTTPRoute routes requests correctly to different backends based on the HTTP request method matching rules.
- **Manifests**: `sigs.k8s.io/gateway-api/conformance/tests/httproute-method-matching.yaml` (v1.6.0)

## 2. Issue / Failure Analysis
- **Observed Behavior**: The test case `11_request_to_'/'_with_headers_should_go_to_infra-backend-v2` timed out and failed because the request matched `infra-backend-v3` instead of the expected `infra-backend-v2`.
- **Root Cause**: According to the Kubernetes Gateway API specification, if there is a tie on path specificity, Method match precedence takes priority over Header match precedence. In the reference implementation's `isBetterMatch` function under `pkg/state/gateway.go`, Header match counts were evaluated before Method matches. As a result, a rule specifying only a header match (routing to `infra-backend-v3`) mistakenly won over a rule specifying only a method match (routing to `infra-backend-v2`) when a request had both matching criteria.

## 3. Implementation / Fix Strategy
- **Approach**: 
  1. Reordered the priority checks within `isBetterMatch` in `pkg/state/gateway.go` to match the official spec priority hierarchy (Path Type > Path Length > Method specified > Headers match count).
  2. Enabled the `tests.HTTPRouteMethodMatching` conformance test in `tests/e2e/conformance_test.go`.
  3. Added a new unit test `TestMatchRoute_MethodVsHeaderPrecedence` to `pkg/state/match_test.go` to assert the correct field precedence between Method and Header matching.
- **Key Files Modified**:
  - `pkg/state/gateway.go`
  - `pkg/state/match_test.go`
  - `tests/e2e/conformance_test.go`

## 4. Validation & Results
- **Unit Tests**: Added `TestMatchRoute_MethodVsHeaderPrecedence` under `pkg/state/match_test.go` and verified successful execution via `ap test`.
- **Conformance Logs**: 
  ```
  --- PASS: TestConformance (119.72s)
      --- PASS: TestConformance/HTTPRouteMethodMatching (0.12s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/8_request_to_'/'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/2_request_to_'/'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/9_request_to_'/path4'_should_receive_one_of_[] (0.00s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/1_request_to_'/'_should_go_to_infra-backend-v2 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/4_request_to_'/'_with_headers_should_go_to_infra-backend-v2 (0.01s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/5_request_to_'/path2'_with_headers_should_go_to_infra-backend-v3 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/11_request_to_'/'_with_headers_should_go_to_infra-backend-v2 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/7_request_to_'/path4'_with_headers_should_go_to_infra-backend-v1 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/6_request_to_'/path3'_should_go_to_infra-backend-v1 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/3_request_to_'/path1'_should_go_to_infra-backend-v1 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/0_request_to_'/'_should_go_to_infra-backend-v1 (0.02s)
          --- PASS: TestConformance/HTTPRouteMethodMatching/10_request_to_'/path5'_should_go_to_infra-backend-v1 (0.02s)
  PASS
  ok      github.com/gke-labs/gateway-api-reference-implementation/tests/e2e     119.739s
  ```
