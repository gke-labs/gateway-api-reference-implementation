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
			if g.Name == string(parentRef.Name) {
				// Note: for now we only check name, but should check namespace too if specified
				gw = g
				break
			}
		}

		if gw == nil {
			acceptedStatus = metav1.ConditionFalse
			acceptedReason = gatewayv1.RouteReasonNoMatchingParent
			acceptedMessage = "Gateway not found"
		} else {
			matched := false
			for _, listener := range gw.Spec.Listeners {
				if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
					continue
				}
				if sectionName := ValueOf(parentRef.SectionName); sectionName != "" && sectionName != listener.Name {
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
				acceptedMessage = "No matching listener hostname"
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

func (s *HTTPRouteState) IsAccepted(controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}
	for _, ps := range s.HTTPRoute.Status.Parents {
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

func (s *HTTPRouteState) MatchesGateway(gw *gatewayv1.Gateway, controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}

	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			if string(ps.ParentRef.Name) == gw.Name {
				// Note: for now we only check name, but should check namespace too if specified
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
