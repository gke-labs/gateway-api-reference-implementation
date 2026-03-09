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
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type HTTPRouteState struct {
	*gatewayv1.HTTPRoute
}

func (s *HTTPRouteState) Validate() error {
	if s.HTTPRoute == nil {
		return nil
	}
	for _, rule := range s.Spec.Rules {
		for _, match := range rule.Matches {
			for _, header := range match.Headers {
				if ValueOf(header.Type) == gatewayv1.HeaderMatchRegularExpression {
					if _, err := regexp.Compile(header.Value); err != nil {
						return fmt.Errorf("invalid regular expression in header match: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (s *HTTPRouteState) ComputeAcceptedCondition(parentRef gatewayv1.ParentReference, gateways []*GatewayState) metav1.Condition {
	acceptedStatus := metav1.ConditionTrue
	acceptedReason := gatewayv1.RouteReasonAccepted
	acceptedMessage := "Route accepted by reference implementation"

	if err := s.Validate(); err != nil {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = gatewayv1.RouteReasonUnsupportedValue
		acceptedMessage = fmt.Sprintf("Invalid route: %v", err)
	} else {
		// Check if Gateway exists and has matching listeners
		var gw *GatewayState
		for _, g := range gateways {
			gwNamespace := s.Namespace
			if parentRef.Namespace != nil {
				gwNamespace = string(*parentRef.Namespace)
			}
			if g.Name == string(parentRef.Name) && g.Namespace == gwNamespace {
				gw = g
				break
			}
		}

		if gw == nil {
			acceptedStatus = metav1.ConditionFalse
			acceptedReason = gatewayv1.RouteReasonNoMatchingParent
			acceptedMessage = fmt.Sprintf("Gateway %s/%s not found", ValueOf(parentRef.Namespace), parentRef.Name)
		} else {
			matched := false
			for _, listener := range gw.Spec.Listeners {
				if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
					continue
				}
				if sectionName := ValueOf(parentRef.SectionName); sectionName != "" && sectionName != listener.Name {
					continue
				}

				if !isRouteAllowed(gw.Namespace, listener.AllowedRoutes, s.Namespace) {
					continue
				}

				effectiveHostnames := IntersectHostnames(s.GetHostnames(), string(ValueOf(listener.Hostname)))
				if len(effectiveHostnames) > 0 || len(s.Spec.Hostnames) == 0 {
					matched = true
					break
				}
			}
			if !matched {
				acceptedStatus = metav1.ConditionFalse
				acceptedReason = gatewayv1.RouteReasonNoMatchingListenerHostname
				acceptedMessage = "No matching listener hostname or route not allowed by listener"
			}
		}
	}

	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             acceptedStatus,
		ObservedGeneration: s.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(acceptedReason),
		Message:            acceptedMessage,
	}
}

func isRouteAllowed(gwNamespace string, allowed *gatewayv1.AllowedRoutes, routeNamespace string) bool {
	if allowed == nil || allowed.Namespaces == nil || allowed.Namespaces.From == nil {
		return gwNamespace == routeNamespace
	}

	switch *allowed.Namespaces.From {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return gwNamespace == routeNamespace
	case gatewayv1.NamespacesFromSelector:
		// TODO: Implement selector matching. For now, we don't have namespace labels.
		// Conformance tests for cross-namespace often use 'All'.
		return false
	}
	return gwNamespace == routeNamespace
}

func (s *HTTPRouteState) ComputeResolvedRefsCondition(referenceGrants []*gatewayv1beta1.ReferenceGrant) metav1.Condition {
	resolvedRefsStatus := metav1.ConditionTrue
	resolvedRefsReason := gatewayv1.RouteReasonResolvedRefs
	resolvedRefsMessage := "All references resolved"

	for _, rule := range s.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			if backendRef.Kind != nil && *backendRef.Kind != "Service" {
				resolvedRefsStatus = metav1.ConditionFalse
				resolvedRefsReason = gatewayv1.RouteReasonInvalidKind
				resolvedRefsMessage = fmt.Sprintf("Unsupported backend kind: %s", *backendRef.Kind)
				goto done
			}

			backendSvcNamespace := s.Namespace
			if backendRef.Namespace != nil {
				backendSvcNamespace = string(*backendRef.Namespace)
			}

			if backendSvcNamespace != s.Namespace {
				if !isReferenceAllowed("HTTPRoute", s.Namespace, "Service", backendSvcNamespace, string(backendRef.Name), referenceGrants) {
					resolvedRefsStatus = metav1.ConditionFalse
					resolvedRefsReason = gatewayv1.RouteReasonRefNotPermitted
					resolvedRefsMessage = fmt.Sprintf("Reference to Service %s/%s not permitted by ReferenceGrant", backendSvcNamespace, backendRef.Name)
					goto done
				}
			}
		}
	}

done:
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		Status:             resolvedRefsStatus,
		ObservedGeneration: s.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(resolvedRefsReason),
		Message:            resolvedRefsMessage,
	}
}

func (s *HTTPRouteState) IsAccepted(controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}
	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			if s.IsAcceptedByParent(ps) {
				return true
			}
		}
	}
	return false
}

func (s *HTTPRouteState) IsAcceptedByParent(ps gatewayv1.RouteParentStatus) bool {
	for _, c := range ps.Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func (s *HTTPRouteState) MatchesGateway(gw *gatewayv1.Gateway, controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}

	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			ns := s.Namespace
			if ps.ParentRef.Namespace != nil {
				ns = string(*ps.ParentRef.Namespace)
			}
			if string(ps.ParentRef.Name) == gw.Name && ns == gw.Namespace {
				for _, c := range ps.Conditions {
					if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
						return true
					}
				}
			}
		}
	}

	return false
}
