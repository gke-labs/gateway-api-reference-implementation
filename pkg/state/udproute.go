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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalUDPRule represents a compiled UDPRoute rule with resolved backend targets.
type InternalUDPRule struct {
	Name     *gatewayv1.SectionName
	Backends []InternalL4Backend
}

// InternalUDPRoute represents a compiled UDPRoute containing resolved references,
// rules, and conditions.
type InternalUDPRoute struct {
	Route                 *gatewayv1.UDPRoute
	Rules                 []InternalUDPRule
	ParentRefs            []gatewayv1.ParentReference
	ValidationCondition   metav1.Condition
	ResolvedRefsCondition metav1.Condition
}

// UDPRouteState wraps a UDPRoute with its compiled representation.
type UDPRouteState struct {
	*gatewayv1.UDPRoute
	Internal *InternalUDPRoute
}

// GetNamespace returns the namespace of the route.
func (s *UDPRouteState) GetNamespace() string {
	if s == nil || s.UDPRoute == nil {
		return ""
	}
	return s.Namespace
}

// Validate checks that the UDPRoute values are syntactically and structurally correct.
func (s *UDPRouteState) Validate() error {
	if s == nil || s.UDPRoute == nil {
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

// Compile compiles the UDPRoute into an InternalUDPRoute, resolving references and recording conditions.
func (s *UDPRouteState) Compile(
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalUDPRoute {
	if s == nil || s.UDPRoute == nil {
		return nil
	}
	s.Internal = CompileUDPRoute(s.UDPRoute, services, refValidator)
	return s.Internal
}

// CompileUDPRoute parses and compiles a UDPRoute object into an InternalUDPRoute.
func CompileUDPRoute(
	route *gatewayv1.UDPRoute,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) *InternalUDPRoute {
	if route == nil {
		return nil
	}

	validationCondition := NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonAccepted),
		"Route validation succeeded",
		route.Generation,
	)

	resolvedRefsCondition := NewCondition(
		string(gatewayv1.RouteConditionResolvedRefs),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonResolvedRefs),
		"All references resolved",
		route.Generation,
	)

	var compiledRules []InternalUDPRule
	for _, rule := range route.Spec.Rules {
		compiledRules = append(compiledRules, InternalUDPRule{
			Name:     rule.Name,
			Backends: resolveL4BackendRefs(rule.BackendRefs, route.Namespace, route.Generation, "UDPRoute", services, refValidator, &resolvedRefsCondition),
		})
	}

	return &InternalUDPRoute{
		Route:                 route,
		Rules:                 compiledRules,
		ParentRefs:            route.Spec.ParentRefs,
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// IsAccepted returns true if the route has an Accepted condition with Status True for the given controller.
func (s *UDPRouteState) IsAccepted(controllerName string) bool {
	if s == nil || s.UDPRoute == nil {
		return false
	}
	return isRouteAccepted(s.Status.Parents, controllerName)
}

// IsAcceptedForParentRef checks if the route is accepted for a specific parent reference.
func (s *UDPRouteState) IsAcceptedForParentRef(parentRef gatewayv1.ParentReference, controllerName string) bool {
	if s == nil || s.UDPRoute == nil {
		return false
	}
	return isRouteAcceptedForParentRef(s.Status.Parents, parentRef, s.Namespace, controllerName)
}
