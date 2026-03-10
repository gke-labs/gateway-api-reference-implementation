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
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type State struct {
	mu sync.RWMutex

	gateways           map[types.NamespacedName]*GatewayState
	httpRoutes         map[types.NamespacedName]*HTTPRouteState
	grpcRoutes         map[types.NamespacedName]*GRPCRouteState
	backendTLSPolicies map[types.NamespacedName]*gatewayv1.BackendTLSPolicy
	services           map[types.NamespacedName]*corev1.Service
	configMaps         map[types.NamespacedName]*corev1.ConfigMap
}

func NewState() *State {
	return &State{
		gateways:           make(map[types.NamespacedName]*GatewayState),
		httpRoutes:         make(map[types.NamespacedName]*HTTPRouteState),
		grpcRoutes:         make(map[types.NamespacedName]*GRPCRouteState),
		backendTLSPolicies: make(map[types.NamespacedName]*gatewayv1.BackendTLSPolicy),
		services:           make(map[types.NamespacedName]*corev1.Service),
		configMaps:         make(map[types.NamespacedName]*corev1.ConfigMap),
	}
}

func (s *State) UpsertConfigMap(cm *corev1.ConfigMap) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.configMaps[types.NamespacedName{Namespace: cm.Namespace, Name: cm.Name}] = cm
}

func (s *State) DeleteConfigMap(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.configMaps, name)
}

func (s *State) GetConfigMaps() map[types.NamespacedName]*corev1.ConfigMap {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cms := make(map[types.NamespacedName]*corev1.ConfigMap)
	for k, v := range s.configMaps {
		cms[k] = v
	}
	return cms
}

func (s *State) UpsertService(svc *corev1.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.services[types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}] = svc
}

func (s *State) DeleteService(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.services, name)
}

func (s *State) GetService(name types.NamespacedName) *corev1.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.services[name]
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

func (s *State) UpsertGRPCRoute(route *gatewayv1.GRPCRoute) metav1.Condition {
	rs := &GRPCRouteState{
		GRPCRoute: route,
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

	s.grpcRoutes[types.NamespacedName{Namespace: route.Namespace, Name: route.Name}] = rs

	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             status,
		ObservedGeneration: route.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}
}

func (s *State) DeleteGRPCRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.grpcRoutes, name)
}

func (s *State) UpsertBackendTLSPolicy(policy *gatewayv1.BackendTLSPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.backendTLSPolicies[types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}] = policy
}

func (s *State) DeleteBackendTLSPolicy(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.backendTLSPolicies, name)
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

	// Sort by creation timestamp, then by namespace/name to ensure deterministic order
	// and follow Gateway API precedence rules for ties.
	sort.Slice(routes, func(i, j int) bool {
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

func (s *State) GetGRPCRoutes() []*GRPCRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var routes []*GRPCRouteState
	for _, route := range s.grpcRoutes {
		routes = append(routes, route)
	}

	// Sort by creation timestamp, then by namespace/name to ensure deterministic order
	// and follow Gateway API precedence rules for ties.
	sort.Slice(routes, func(i, j int) bool {
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

func (s *State) GetBackendTLSPolicies() []*gatewayv1.BackendTLSPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var policies []*gatewayv1.BackendTLSPolicy
	for _, policy := range s.backendTLSPolicies {
		policies = append(policies, policy)
	}
	return policies
}

func (s *State) GetServices() map[types.NamespacedName]*corev1.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make(map[types.NamespacedName]*corev1.Service)
	for k, v := range s.services {
		services[k] = v
	}
	return services
}
