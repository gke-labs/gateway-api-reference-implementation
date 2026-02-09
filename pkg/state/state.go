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
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type State struct {
	mu sync.RWMutex

	gateways   map[types.NamespacedName]*GatewayState
	httpRoutes map[types.NamespacedName]*HTTPRouteState
}

func NewState() *State {
	return &State{
		gateways:   make(map[types.NamespacedName]*GatewayState),
		httpRoutes: make(map[types.NamespacedName]*HTTPRouteState),
	}
}

func (s *State) UpsertGateway(gw *gatewayv1.Gateway) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.gateways[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = &GatewayState{
		Gateway: gw,
	}
}

func (s *State) DeleteGateway(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.gateways, name)
}

func (s *State) UpsertHTTPRoute(route *gatewayv1.HTTPRoute) metav1.Condition {
	rs := &HTTPRouteState{
		HTTPRoute: route,
	}

	status := metav1.ConditionTrue
	reason := gatewayv1.RouteReasonAccepted
	message := "Route accepted by reference implementation"

	if err := rs.Validate(); err != nil {
		status = metav1.ConditionFalse
		reason = gatewayv1.RouteReasonUnsupportedValue
		message = fmt.Sprintf("Invalid route: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.httpRoutes[types.NamespacedName{Namespace: route.Namespace, Name: route.Name}] = rs

	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             status,
		ObservedGeneration: route.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}
}

func (s *State) DeleteHTTPRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.httpRoutes, name)
}

func (s *State) GetGateways() []*GatewayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var gateways []*GatewayState
	for _, gw := range s.gateways {
		gateways = append(gateways, gw)
	}
	return gateways
}

func (s *State) GetHTTPRoutes() []*HTTPRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var routes []*HTTPRouteState
	for _, route := range s.httpRoutes {
		routes = append(routes, route)
	}
	return routes
}
