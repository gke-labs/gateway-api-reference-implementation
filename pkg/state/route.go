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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func isRouteAccepted(parents []gatewayv1.RouteParentStatus, controllerName string) bool {
	for _, ps := range parents {
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

func isRouteAcceptedForParentRef(parents []gatewayv1.RouteParentStatus, parentRef gatewayv1.ParentReference, routeNamespace string, controllerName string) bool {
	parentNamespace := routeNamespace
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
	for _, ps := range parents {
		if string(ps.ControllerName) != controllerName {
			continue
		}
		psNamespace := routeNamespace
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
