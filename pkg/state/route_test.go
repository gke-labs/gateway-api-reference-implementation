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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsRouteAcceptedForParentRef_Defaulting(t *testing.T) {
	const controller = "example.com/controller"
	parents := []gatewayv1.RouteParentStatus{
		{
			ParentRef: gatewayv1.ParentReference{
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			ControllerName: controller,
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue},
			},
		},
	}

	tests := []struct {
		name      string
		parentRef gatewayv1.ParentReference
		want      bool
	}{
		{
			name: "defaulted matches defaulted status",
			parentRef: gatewayv1.ParentReference{
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: true,
		},
		{
			name: "explicit standard group kind namespace matches",
			parentRef: gatewayv1.ParentReference{
				Group:       Ptr(gatewayv1.Group(gatewayv1.GroupName)),
				Kind:        Ptr(gatewayv1.Kind("Gateway")),
				Namespace:   Ptr(gatewayv1.Namespace("route-ns")),
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: true,
		},
		{
			name: "different namespace",
			parentRef: gatewayv1.ParentReference{
				Namespace:   Ptr(gatewayv1.Namespace("other-ns")),
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: false,
		},
		{
			name: "different kind",
			parentRef: gatewayv1.ParentReference{
				Kind:        Ptr(gatewayv1.Kind("Other")),
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: false,
		},
		{
			name: "different group",
			parentRef: gatewayv1.ParentReference{
				Group:       Ptr(gatewayv1.Group("other.group")),
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: false,
		},
		{
			name: "different section name",
			parentRef: gatewayv1.ParentReference{
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("http")),
				Port:        Ptr(gatewayv1.PortNumber(8443)),
			},
			want: false,
		},
		{
			name: "different port",
			parentRef: gatewayv1.ParentReference{
				Name:        "gw",
				SectionName: Ptr(gatewayv1.SectionName("https")),
				Port:        Ptr(gatewayv1.PortNumber(80)),
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isRouteAcceptedForParentRef(parents, tc.parentRef, "route-ns", controller)
			if got != tc.want {
				t.Errorf("isRouteAcceptedForParentRef() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHTTPRouteState_NilGuard(t *testing.T) {
	const controller = "example.com/controller"
	parentRef := gatewayv1.ParentReference{Name: "gw"}

	var nilRoute *HTTPRouteState
	if nilRoute.IsAccepted(controller) {
		t.Error("expected (*HTTPRouteState)(nil).IsAccepted() = false")
	}
	if nilRoute.IsAcceptedForParentRef(parentRef, controller) {
		t.Error("expected (*HTTPRouteState)(nil).IsAcceptedForParentRef() = false")
	}

	emptyRoute := &HTTPRouteState{}
	if emptyRoute.IsAccepted(controller) {
		t.Error("expected empty HTTPRouteState.IsAccepted() = false")
	}
	if emptyRoute.IsAcceptedForParentRef(parentRef, controller) {
		t.Error("expected empty HTTPRouteState.IsAcceptedForParentRef() = false")
	}
}
