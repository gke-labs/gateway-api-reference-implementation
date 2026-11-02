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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalTLSBackend represents a resolved backend target and weight for a TLSRoute.
type InternalTLSBackend struct {
	Target    string
	Weight    int32
	TLSConfig *InternalTLSConfig
	Error     *ErrorState
}

// InternalTLSRule represents a compiled TLSRoute rule with resolved backend targets.
type InternalTLSRule struct {
	Name     *gatewayv1.SectionName
	Backends []InternalTLSBackend
}

// InternalTLSRoute represents a compiled TLSRoute containing hostnames,
// resolved references, rules, and conditions.
type InternalTLSRoute struct {
	Route                 *gatewayv1.TLSRoute
	Rules                 []InternalTLSRule
	Hostnames             []string
	ParentRefs            []gatewayv1.ParentReference
	ValidationCondition   metav1.Condition
	ResolvedRefsCondition metav1.Condition
}

// TLSRouteState wraps a TLSRoute with its compiled representation.
type TLSRouteState struct {
	*gatewayv1.TLSRoute
	Internal *InternalTLSRoute
}

// GetHostnames returns the list of hostnames declared on the route as strings.
func (s *TLSRouteState) GetHostnames() []string {
	if s == nil || s.TLSRoute == nil {
		return nil
	}
	var res []string
	for _, h := range s.Spec.Hostnames {
		res = append(res, string(h))
	}
	return res
}

// GetNamespace returns the namespace of the route.
func (s *TLSRouteState) GetNamespace() string {
	if s == nil || s.TLSRoute == nil {
		return ""
	}
	return s.Namespace
}

// Validate checks that the TLSRoute values are syntactically and structurally correct.
func (s *TLSRouteState) Validate() error {
	if s == nil || s.TLSRoute == nil {
		return nil
	}
	if s.Internal == nil {
		s.Compile(nil, nil, nil, nil)
	}
	if s.Internal.ValidationCondition.Status == metav1.ConditionFalse {
		return errors.New(s.Internal.ValidationCondition.Message)
	}
	return nil
}

// Compile compiles the TLSRoute into an InternalTLSRoute, resolving references and recording conditions.
func (s *TLSRouteState) Compile(
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalTLSRoute {
	if s == nil || s.TLSRoute == nil {
		return nil
	}
	s.Internal = CompileTLSRoute(s.TLSRoute, services, backendTLSPolicies, configMaps, refValidator)
	return s.Internal
}

// CompileTLSRoute parses and compiles a TLSRoute object into an InternalTLSRoute.
func CompileTLSRoute(
	route *gatewayv1.TLSRoute,
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalTLSRoute {
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

	var hostnames []string
	for _, h := range route.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}

	sortedTLSPolicies := sortBackendTLSPolicies(backendTLSPolicies)

	var compiledRules []InternalTLSRule
	for _, rule := range route.Spec.Rules {
		iRule := InternalTLSRule{
			Name: rule.Name,
		}

		for _, backendRef := range rule.BackendRefs {
			backend, refErr := resolveBackendTarget(
				backendRef.BackendObjectReference,
				"TLSRoute",
				route.Namespace,
				route.Generation,
				services,
				sortedTLSPolicies,
				configMaps,
				refValidator,
			)
			if refErr != nil {
				if resolvedRefsCondition.Status == metav1.ConditionTrue {
					resolvedRefsCondition = refErr.Condition
				}
				continue
			}

			weight := int32(1)
			if backendRef.Weight != nil {
				weight = *backendRef.Weight
				if weight < 0 {
					weight = 0
				}
			}

			target := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
			iRule.Backends = append(iRule.Backends, InternalTLSBackend{
				Target:    target,
				Weight:    weight,
				TLSConfig: backend.TLSConfig,
				Error:     backend.Error,
			})
		}

		compiledRules = append(compiledRules, iRule)
	}

	return &InternalTLSRoute{
		Route:                 route,
		Rules:                 compiledRules,
		Hostnames:             hostnames,
		ParentRefs:            route.Spec.ParentRefs,
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// IsAccepted returns true if the route has an Accepted condition with Status True for the given controller.
func (s *TLSRouteState) IsAccepted(controllerName string) bool {
	if s == nil || s.TLSRoute == nil {
		return false
	}
	for _, ps := range s.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			for _, c := range ps.Conditions {
				if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
					return true
				}
			}
		}
	}
	return false
}

// IsAcceptedForParentRef checks if the route is accepted for a specific parent reference.
func (s *TLSRouteState) IsAcceptedForParentRef(parentRef gatewayv1.ParentReference, controllerName string) bool {
	if s == nil || s.TLSRoute == nil {
		return false
	}
	parentNamespace := s.Namespace
	if ns := ValueOf(parentRef.Namespace); ns != "" {
		parentNamespace = string(ns)
	}
	pKind := ValueOf(parentRef.Kind)
	if pKind == "" {
		pKind = "Gateway"
	}
	pGroup := ValueOf(parentRef.Group)
	if pGroup == "" {
		pGroup = gatewayv1.GroupName
	}
	for _, ps := range s.Status.Parents {
		if string(ps.ControllerName) != controllerName {
			continue
		}
		psNamespace := s.Namespace
		if ns := ValueOf(ps.ParentRef.Namespace); ns != "" {
			psNamespace = string(ns)
		}
		psKind := ValueOf(ps.ParentRef.Kind)
		if psKind == "" {
			psKind = "Gateway"
		}
		psGroup := ValueOf(ps.ParentRef.Group)
		if psGroup == "" {
			psGroup = gatewayv1.GroupName
		}
		if string(ps.ParentRef.Name) == string(parentRef.Name) &&
			psNamespace == parentNamespace &&
			psKind == pKind &&
			psGroup == pGroup &&
			ValueOf(ps.ParentRef.SectionName) == ValueOf(parentRef.SectionName) &&
			ValueOf(ps.ParentRef.Port) == ValueOf(parentRef.Port) {
			for _, c := range ps.Conditions {
				if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
					return true
				}
			}
		}
	}
	return false
}
