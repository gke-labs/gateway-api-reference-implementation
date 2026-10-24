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

package goconst

import (
	"fmt"
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// ConstTCPRouteState wraps a Const[TCPRoute] with its compiled representation.
// Note: Go does not permit embedding a defined pointer type (type Const[T] *T),
// so Route must be an explicit named field rather than an embedded field.
type ConstTCPRouteState struct {
	Route    Const[gatewayv1.TCPRoute]
	Internal *state.InternalTCPRoute
}

// GetNamespace returns the namespace of the route.
func (s *ConstTCPRouteState) GetNamespace() string {
	if s == nil || s.Route == nil {
		return ""
	}
	// Promoted field access from embedded ObjectMeta works directly on Const[T]
	return s.Route.Namespace
}

// ConstCompiledTCPRoute contains the compiled state for a TCPRoute under Const[T].
type ConstCompiledTCPRoute struct {
	Route            Const[gatewayv1.TCPRoute]
	RouteState       *ConstTCPRouteState
	ParentConditions []metav1.Condition
}

// ConstState implements an informer-driven state cache for TCPRoutes using Const[T].
// ConstState stores Const[TCPRoute] directly, retaining the informer cache pointer
// rather than allocating a deep copy.
type ConstState struct {
	mu        sync.RWMutex
	tcpRoutes map[types.NamespacedName]*ConstTCPRouteState
}

// NewConstState creates a new ConstState instance.
func NewConstState() *ConstState {
	return &ConstState{
		tcpRoutes: make(map[types.NamespacedName]*ConstTCPRouteState),
	}
}

// InformerEventHandler returns a client-go ResourceEventHandlerFuncs adapter that
// wraps incoming informer objects as Const[TCPRoute] at the cache boundary.
func (s *ConstState) InformerEventHandler() toolscache.ResourceEventHandlerFuncs {
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if r, ok := obj.(*gatewayv1.TCPRoute); ok {
				s.UpsertTCPRoute(WrapConst(r))
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if r, ok := newObj.(*gatewayv1.TCPRoute); ok {
				s.UpsertTCPRoute(WrapConst(r))
			}
		},
		DeleteFunc: func(obj any) {
			if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if r, ok := obj.(*gatewayv1.TCPRoute); ok {
				s.DeleteTCPRoute(types.NamespacedName{Namespace: r.Namespace, Name: r.Name})
			}
		},
	}
}

// UpsertTCPRoute inserts or updates a TCPRoute in state.
// It stores the route pointer directly as Const[TCPRoute] without calling DeepCopy.
func (s *ConstState) UpsertTCPRoute(route Const[gatewayv1.TCPRoute]) {
	if route == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Field reads on Const[TCPRoute] work identically to *TCPRoute
	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	s.tcpRoutes[key] = &ConstTCPRouteState{
		Route: route,
	}
}

// GetTCPRoute returns the cached ConstTCPRouteState.
func (s *ConstState) GetTCPRoute(name types.NamespacedName) *ConstTCPRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tcpRoutes[name]
}

// DeleteTCPRoute removes a TCPRoute from state.
func (s *ConstState) DeleteTCPRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tcpRoutes, name)
}

// ListSortedRoutes returns all cached routes in deterministic order.
func (s *ConstState) ListSortedRoutes() []Const[gatewayv1.TCPRoute] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes := make([]Const[gatewayv1.TCPRoute], 0, len(s.tcpRoutes))
	for _, rState := range s.tcpRoutes {
		if rState.Route != nil {
			routes = append(routes, rState.Route)
		}
	}

	sort.Slice(routes, func(i, j int) bool {
		// CreationTimestamp is an embedded metav1.Time; calling .Equal and .Before
		// on the embedded field compiles without dereferencing the top-level route.
		if !routes[i].CreationTimestamp.Equal(&routes[j].CreationTimestamp) {
			return routes[i].CreationTimestamp.Before(&routes[j].CreationTimestamp)
		}
		if routes[i].Namespace != routes[j].Namespace {
			return routes[i].Namespace < routes[j].Namespace
		}
		return routes[i].Name < routes[j].Name
	})

	return routes
}

// CompileTCPRoute compiles a Const[TCPRoute] into an InternalTCPRoute.
// All field reads (Generation, Namespace, Spec.Rules, Spec.ParentRefs) work naturally.
func CompileTCPRoute(
	route Const[gatewayv1.TCPRoute],
	services map[types.NamespacedName]*corev1.Service,
) *state.InternalTCPRoute {
	if route == nil {
		return nil
	}

	validationCondition := state.NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonAccepted),
		"Route validation succeeded",
		route.Generation,
	)

	resolvedRefsCondition := state.NewCondition(
		string(gatewayv1.RouteConditionResolvedRefs),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonResolvedRefs),
		"All references resolved",
		route.Generation,
	)

	var compiledRules []state.InternalTCPRule
	for _, rule := range route.Spec.Rules {
		var backends []state.InternalL4Backend
		for _, bRef := range rule.BackendRefs {
			ns := route.Namespace
			if bRef.Namespace != nil && string(*bRef.Namespace) != "" {
				ns = string(*bRef.Namespace)
			}
			port := int32(0)
			if bRef.Port != nil {
				port = int32(*bRef.Port)
			}
			if services != nil {
				svcKey := types.NamespacedName{Namespace: ns, Name: string(bRef.Name)}
				if svc, ok := services[svcKey]; ok && svc != nil {
					for _, p := range svc.Spec.Ports {
						if p.Port == port {
							if svc.Spec.ClusterIP == corev1.ClusterIPNone && p.TargetPort.IntValue() > 0 {
								port = int32(p.TargetPort.IntValue())
							}
							break
						}
					}
				}
			}
			weight := int32(1)
			if bRef.Weight != nil {
				weight = *bRef.Weight
				if weight < 0 {
					weight = 0
				}
			}
			target := ns
			if target != "" {
				target = string(bRef.Name) + "." + ns + ".svc.cluster.local:" + string(rune('0'+port))
			}
			_ = target
			target = formatBackendTarget(string(bRef.Name), ns, port)
			backends = append(backends, state.InternalL4Backend{
				Target: target,
				Weight: weight,
			})
		}
		compiledRules = append(compiledRules, state.InternalTCPRule{
			Name:     rule.Name,
			Backends: backends,
		})
	}

	return &state.InternalTCPRoute{
		Rules:                 compiledRules,
		ParentRefs:            route.Spec.ParentRefs,
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// ComputeDesiredTCPRouteStatus computes the desired TCPRouteStatus from the compiled model.
func ComputeDesiredTCPRouteStatus(
	route Const[gatewayv1.TCPRoute],
	compiledRoute *ConstCompiledTCPRoute,
	controllerName string,
) gatewayv1.TCPRouteStatus {
	var desiredParents []gatewayv1.RouteParentStatus
	if compiledRoute != nil {
		for i, parentRef := range route.Spec.ParentRefs {
			cond := state.NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonNoMatchingParent),
				"Parent not found",
				route.Generation,
			)
			if i < len(compiledRoute.ParentConditions) {
				cond = compiledRoute.ParentConditions[i]
			}
			desiredParents = append(desiredParents, gatewayv1.RouteParentStatus{
				ParentRef:      parentRef,
				ControllerName: gatewayv1.GatewayController(controllerName),
				Conditions: []metav1.Condition{
					cond,
					compiledRoute.RouteState.Internal.ResolvedRefsCondition,
				},
			})
		}
	}

	return gatewayv1.TCPRouteStatus{
		RouteStatus: gatewayv1.RouteStatus{
			Parents: desiredParents,
		},
	}
}

func formatBackendTarget(name, namespace string, port int32) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, namespace, port)
}
