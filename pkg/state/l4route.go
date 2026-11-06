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
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalL4Backend represents a resolved backend target and weight for an L4 route (TCPRoute or UDPRoute).
type InternalL4Backend struct {
	Target string
	Weight int32
}

// InternalTCPBackend is an alias for InternalL4Backend.
type InternalTCPBackend = InternalL4Backend

// InternalUDPBackend is an alias for InternalL4Backend.
type InternalUDPBackend = InternalL4Backend

// L4Rule represents an uncompiled rule in an L4 route.
type L4Rule struct {
	Name        *gatewayv1.SectionName
	BackendRefs []gatewayv1.BackendRef
}

// L4RouteAdapter provides access to kind-specific fields of an L4 route.
type L4RouteAdapter[R any] interface {
	Kind() string
	IsNil(r R) bool
	Rules(r R) []L4Rule
	ParentRefs(r R) []gatewayv1.ParentReference
	Parents(r R) []gatewayv1.RouteParentStatus
	Spec(r R) any
}

// InternalL4Rule represents a compiled L4 route rule with resolved backend targets.
type InternalL4Rule struct {
	Name     *gatewayv1.SectionName
	Backends []InternalL4Backend
}

// InternalL4Route represents a compiled L4 route containing resolved references,
// rules, and conditions.
type InternalL4Route[R any] struct {
	Route                 R
	Rules                 []InternalL4Rule
	ParentRefs            []gatewayv1.ParentReference
	ValidationCondition   metav1.Condition
	ResolvedRefsCondition metav1.Condition
}

// L4RouteState wraps an L4 route with its compiled representation.
type L4RouteState[R client.Object, A L4RouteAdapter[R]] struct {
	Route    R
	Internal *InternalL4Route[R]
}

// GetNamespace returns the namespace of the route.
func (s *L4RouteState[R, A]) GetNamespace() string {
	var a A
	if s == nil || a.IsNil(s.Route) {
		return ""
	}
	return s.Route.GetNamespace()
}

// Validate checks that the route values are syntactically and structurally correct.
func (s *L4RouteState[R, A]) Validate() error {
	var a A
	if s == nil || a.IsNil(s.Route) {
		return nil
	}
	if s.Internal == nil {
		s.Compile(nil, nil)
	}
	if s.Internal.ValidationCondition.Status == metav1.ConditionFalse {
		return errors.New(s.Internal.ValidationCondition.Message)
	}
	return nil
}

// Compile compiles the route into an InternalL4Route, resolving references and recording conditions.
func (s *L4RouteState[R, A]) Compile(
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalL4Route[R] {
	var a A
	if s == nil || a.IsNil(s.Route) {
		return nil
	}
	s.Internal = CompileL4Route[R, A](s.Route, services, refValidator)
	return s.Internal
}

// CompileL4Route parses and compiles an L4 route object into an InternalL4Route.
func CompileL4Route[R client.Object, A L4RouteAdapter[R]](
	route R,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalL4Route[R] {
	var a A
	if a.IsNil(route) {
		return nil
	}

	validationCondition := NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonAccepted),
		"Route validation succeeded",
		route.GetGeneration(),
	)

	resolvedRefsCondition := NewCondition(
		string(gatewayv1.RouteConditionResolvedRefs),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonResolvedRefs),
		"All references resolved",
		route.GetGeneration(),
	)

	kind := a.Kind()
	rules := a.Rules(route)
	var compiledRules []InternalL4Rule
	for _, rule := range rules {
		compiledRules = append(compiledRules, InternalL4Rule{
			Name:     rule.Name,
			Backends: resolveL4BackendRefs(rule.BackendRefs, route.GetNamespace(), route.GetGeneration(), kind, services, refValidator, &resolvedRefsCondition),
		})
	}

	return &InternalL4Route[R]{
		Route:                 route,
		Rules:                 compiledRules,
		ParentRefs:            a.ParentRefs(route),
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// IsAccepted returns true if the route has an Accepted condition with Status True for the given controller.
func (s *L4RouteState[R, A]) IsAccepted(controllerName string) bool {
	var a A
	if s == nil || a.IsNil(s.Route) {
		return false
	}
	return isRouteAccepted(a.Parents(s.Route), controllerName)
}

// IsAcceptedForParentRef checks if the route is accepted for a specific parent reference.
func (s *L4RouteState[R, A]) IsAcceptedForParentRef(parentRef gatewayv1.ParentReference, controllerName string) bool {
	var a A
	if s == nil || a.IsNil(s.Route) {
		return false
	}
	return isRouteAcceptedForParentRef(a.Parents(s.Route), parentRef, s.Route.GetNamespace(), controllerName)
}

// resolveL4BackendRefs compiles a slice of gatewayv1.BackendRef into InternalL4Backend targets
// using resolveBackendTarget, recording the first resolution failure in resolvedRefsCondition.
func resolveL4BackendRefs(
	backendRefs []gatewayv1.BackendRef,
	routeNamespace string,
	routeGeneration int64,
	routeKind string,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
	resolvedRefsCondition *metav1.Condition,
) []InternalL4Backend {
	var backends []InternalL4Backend
	for _, backendRef := range backendRefs {
		backend, resolutionErr := resolveBackendTarget(
			backendRef.BackendObjectReference,
			routeKind,
			routeNamespace,
			routeGeneration,
			services,
			nil,
			nil,
			refValidator,
		)
		if resolutionErr != nil {
			if resolvedRefsCondition != nil && resolvedRefsCondition.Status == metav1.ConditionTrue {
				*resolvedRefsCondition = resolutionErr.Condition
			}
			continue
		}

		backends = append(backends, InternalL4Backend{
			Target: fmt.Sprintf("%s:%d", backend.Host, backend.Port),
			Weight: resolveBackendWeight(backendRef.Weight),
		})
	}
	return backends
}
