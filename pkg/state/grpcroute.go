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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type GRPCRouteState struct {
	*gatewayv1.GRPCRoute
}

func (s *GRPCRouteState) Validate() error {
	return nil
}

func (s *GRPCRouteState) ComputeAcceptedCondition(parentRef gatewayv1.ParentReference, gateways []*GatewayState) metav1.Condition {
	acceptedStatus := metav1.ConditionTrue
	acceptedReason := gatewayv1.RouteReasonAccepted
	acceptedMessage := "Route accepted by reference implementation"

	// Check if Gateway exists and has matching listeners
	var gw *GatewayState
	for _, g := range gateways {
		if g.Name == string(parentRef.Name) {
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
			if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType && listener.Protocol != "TLS" {
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

	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             acceptedStatus,
		ObservedGeneration: s.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             string(acceptedReason),
		Message:            acceptedMessage,
	}
}

func (s *GRPCRouteState) ComputeResolvedRefsCondition() metav1.Condition {
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

func (s *GRPCRouteState) GetHostnames() []string {
	var hostnames []string
	for _, h := range s.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}
	return hostnames
}

func (s *GRPCRouteState) MatchesGateway(gw *gatewayv1.Gateway, controllerName string) bool {
	if s.GRPCRoute == nil {
		return false
	}

	for _, ps := range s.GRPCRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			if string(ps.ParentRef.Name) == gw.Name {
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
