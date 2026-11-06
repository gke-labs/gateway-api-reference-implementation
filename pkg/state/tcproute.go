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

type tcpRouteAdapter struct{}

func (tcpRouteAdapter) Kind() string                     { return "TCPRoute" }
func (tcpRouteAdapter) IsNil(r *gatewayv1.TCPRoute) bool { return r == nil }
func (tcpRouteAdapter) ParentRefs(r *gatewayv1.TCPRoute) []gatewayv1.ParentReference {
	return r.Spec.ParentRefs
}
func (tcpRouteAdapter) Parents(r *gatewayv1.TCPRoute) []gatewayv1.RouteParentStatus {
	return r.Status.Parents
}
func (tcpRouteAdapter) Spec(r *gatewayv1.TCPRoute) any { return r.Spec }

func (tcpRouteAdapter) Rules(r *gatewayv1.TCPRoute) []L4Rule {
	rules := make([]L4Rule, len(r.Spec.Rules))
	for i, rule := range r.Spec.Rules {
		rules[i] = L4Rule{Name: rule.Name, BackendRefs: rule.BackendRefs}
	}
	return rules
}

// InternalTCPRule represents a compiled TCPRoute rule with resolved backend targets.
type InternalTCPRule = InternalL4Rule

// InternalTCPRoute represents a compiled TCPRoute containing resolved references,
// rules, and conditions.
type InternalTCPRoute = InternalL4Route[*gatewayv1.TCPRoute]

// TCPRouteState wraps a TCPRoute with its compiled representation.
type TCPRouteState = L4RouteState[*gatewayv1.TCPRoute, tcpRouteAdapter]

// CompileTCPRoute parses and compiles a TCPRoute object into an InternalTCPRoute.
func CompileTCPRoute(
	route *gatewayv1.TCPRoute,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalTCPRoute {
	return CompileL4Route[*gatewayv1.TCPRoute, tcpRouteAdapter](route, services, refValidator)
}
