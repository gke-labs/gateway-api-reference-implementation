// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type udpRouteAdapter struct{}

func (udpRouteAdapter) Kind() string                     { return "UDPRoute" }
func (udpRouteAdapter) IsNil(r *gatewayv1.UDPRoute) bool { return r == nil }
func (udpRouteAdapter) ParentRefs(r *gatewayv1.UDPRoute) []gatewayv1.ParentReference {
	return r.Spec.ParentRefs
}
func (udpRouteAdapter) Parents(r *gatewayv1.UDPRoute) []gatewayv1.RouteParentStatus {
	return r.Status.Parents
}
func (udpRouteAdapter) Spec(r *gatewayv1.UDPRoute) any { return r.Spec }

func (udpRouteAdapter) Rules(r *gatewayv1.UDPRoute) []L4Rule {
	rules := make([]L4Rule, len(r.Spec.Rules))
	for i, rule := range r.Spec.Rules {
		rules[i] = L4Rule{Name: rule.Name, BackendRefs: rule.BackendRefs}
	}
	return rules
}

// InternalUDPRule represents a compiled UDPRoute rule with resolved backend targets.
type InternalUDPRule = InternalL4Rule

// InternalUDPRoute represents a compiled UDPRoute containing resolved references,
// rules, and conditions.
type InternalUDPRoute = InternalL4Route[*gatewayv1.UDPRoute]

// UDPRouteState wraps a UDPRoute with its compiled representation.
type UDPRouteState = L4RouteState[*gatewayv1.UDPRoute, udpRouteAdapter]

// CompileUDPRoute parses and compiles a UDPRoute object into an InternalUDPRoute.
func CompileUDPRoute(
	route *gatewayv1.UDPRoute,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalUDPRoute {
	return CompileL4Route[*gatewayv1.UDPRoute, udpRouteAdapter](route, services, refValidator)
}
