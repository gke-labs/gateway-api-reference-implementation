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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestComputeResolvedRefsCondition(t *testing.T) {
	tests := []struct {
		name            string
		route           *HTTPRouteState
		services        map[types.NamespacedName]*corev1.Service
		referenceGrants []*gatewayv1beta1.ReferenceGrant
		expectedStatus  metav1.ConditionStatus
		expectedReason  string
	}{
		{
			name: "valid backend ref with default kind and group",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "valid-service",
												Port: Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "valid-service"}: {},
			},
			expectedStatus: metav1.ConditionTrue,
			expectedReason: string(gatewayv1.RouteReasonResolvedRefs),
		},
		{
			name: "valid backend ref with explicit Service kind and empty group",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Group: Ptr(gatewayv1.Group("")),
												Kind:  Ptr(gatewayv1.Kind("Service")),
												Name:  "valid-service",
												Port:  Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "valid-service"}: {},
			},
			expectedStatus: metav1.ConditionTrue,
			expectedReason: string(gatewayv1.RouteReasonResolvedRefs),
		},
		{
			name: "invalid backend ref with unknown kind",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Kind: Ptr(gatewayv1.Kind("NonExistent")),
												Name: "invalid-backend",
												Port: Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonInvalidKind),
		},
		{
			name: "invalid backend ref with custom group and kind",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Group: Ptr(gatewayv1.Group("unknownkind.example.com")),
												Kind:  Ptr(gatewayv1.Kind("NonExistent")),
												Name:  "invalid-backend",
												Port:  Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonInvalidKind),
		},
		{
			name: "invalid backend ref with nonexistent service",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "nonexistent-svc",
												Port: Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "other-svc"}: {},
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonBackendNotFound),
		},
		{
			name: "invalid cross-namespace backend ref without ReferenceGrant",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Namespace: Ptr(gatewayv1.Namespace("other-ns")),
												Name:      "web-backend",
												Port:      Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "other-ns", Name: "web-backend"}: {},
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonRefNotPermitted),
		},
		{
			name: "valid cross-namespace backend ref with ReferenceGrant",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Namespace: Ptr(gatewayv1.Namespace("other-ns")),
												Name:      "web-backend",
												Port:      Ptr(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "other-ns", Name: "web-backend"}: {},
			},
			referenceGrants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "other-ns",
						Name:      "grant-all-services",
					},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Group:     gatewayv1.GroupName,
								Kind:      "HTTPRoute",
								Namespace: "default",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
							},
						},
					},
				},
			},
			expectedStatus: metav1.ConditionTrue,
			expectedReason: string(gatewayv1.RouteReasonResolvedRefs),
		},
		{
			name: "partially invalid cross-namespace backend ref with selective ReferenceGrant",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Namespace: Ptr(gatewayv1.Namespace("app-ns")),
												Name:      "app-backend-v2",
											},
										},
									},
								},
							},
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Namespace: Ptr(gatewayv1.Namespace("app-ns")),
												Name:      "app-backend-v1",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "app-ns", Name: "app-backend-v1"}: {},
				{Namespace: "app-ns", Name: "app-backend-v2"}: {},
			},
			referenceGrants: []*gatewayv1beta1.ReferenceGrant{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "app-ns",
						Name:      "grant-v1-only",
					},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Group:     gatewayv1.GroupName,
								Kind:      "HTTPRoute",
								Namespace: "default",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "Service",
								Name:  Ptr(gatewayv1beta1.ObjectName("app-backend-v1")),
							},
						},
					},
				},
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonRefNotPermitted),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := NewState()
			for _, rg := range tt.referenceGrants {
				st.UpsertReferenceGrant(rg)
			}
			cond := tt.route.ComputeResolvedRefsCondition(tt.services, st)
			if cond.Status != tt.expectedStatus {
				t.Errorf("ComputeResolvedRefsCondition() Status = %v, want %v", cond.Status, tt.expectedStatus)
			}
			if cond.Reason != tt.expectedReason {
				t.Errorf("ComputeResolvedRefsCondition() Reason = %v, want %v", cond.Reason, tt.expectedReason)
			}
		})
	}
}

func TestComputeAcceptedCondition(t *testing.T) {
	gw := &GatewayState{
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: Ptr(gatewayv1.NamespacesFromSame),
							},
						},
					},
					{
						Name:     "https",
						Port:     443,
						Hostname: Ptr(gatewayv1.Hostname("example.com")),
						Protocol: gatewayv1.HTTPSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: Ptr(gatewayv1.NamespacesFromAll),
							},
						},
					},
					{
						Name:     "tcp",
						Port:     9000,
						Protocol: gatewayv1.TLSProtocolType,
					},
				},
			},
		},
	}

	tlsGw := &GatewayState{
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tlsroutes-only",
				Namespace: "gateway-conformance-infra",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "tls",
						Port:     443,
						Protocol: gatewayv1.TLSProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: Ptr(gatewayv1.NamespacesFromSame),
							},
							Kinds: []gatewayv1.RouteGroupKind{
								{
									Kind: "TLSRoute",
								},
							},
						},
					},
				},
			},
		},
	}

	gateways := []*GatewayState{gw, tlsGw}

	tests := []struct {
		name           string
		route          *HTTPRouteState
		parentRef      gatewayv1.ParentReference
		expectedStatus metav1.ConditionStatus
		expectedReason string
	}{
		{
			name: "valid route matching http listener in same namespace",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name: "same-namespace",
			},
			expectedStatus: metav1.ConditionTrue,
			expectedReason: string(gatewayv1.RouteReasonAccepted),
		},
		{
			name: "unsupported parent group",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Group: Ptr(gatewayv1.Group("custom.io")),
				Name:  "same-namespace",
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "unsupported parent kind",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Kind: Ptr(gatewayv1.Kind("Service")),
				Name: "same-namespace",
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "gateway not found",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name: "non-existent-gw",
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "invalid parentRef not matching listener port",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:      "same-namespace",
				Namespace: Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				Port:      Ptr(gatewayv1.PortNumber(81)),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "invalid parentRef not matching section name",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:        "same-namespace",
				Namespace:   Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				Port:        Ptr(gatewayv1.PortNumber(80)),
				SectionName: Ptr(gatewayv1.SectionName("http1")),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "invalid parentRef section name not matching port",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:        "same-namespace",
				Namespace:   Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				SectionName: Ptr(gatewayv1.SectionName("http")),
				Port:        Ptr(gatewayv1.PortNumber(81)),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingParent),
		},
		{
			name: "invalid cross namespace parent ref when listener allows only Same",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-web-backend",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:      "same-namespace",
				Namespace: Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				Port:      Ptr(gatewayv1.PortNumber(80)),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNotAllowedByListeners),
		},
		{
			name: "valid cross namespace parent ref when listener allows All",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-web-backend",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Hostnames: []gatewayv1.Hostname{"example.com"},
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:        "same-namespace",
				Namespace:   Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				SectionName: Ptr(gatewayv1.SectionName("https")),
			},
			expectedStatus: metav1.ConditionTrue,
			expectedReason: string(gatewayv1.RouteReasonAccepted),
		},
		{
			name: "no matching listener hostname",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-web-backend",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Hostnames: []gatewayv1.Hostname{"other.com"},
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:        "same-namespace",
				Namespace:   Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				SectionName: Ptr(gatewayv1.SectionName("https")),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNoMatchingListenerHostname),
		},
		{
			name: "listener protocol not compatible (TCP listener only)",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:        "same-namespace",
				Namespace:   Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
				SectionName: Ptr(gatewayv1.SectionName("tcp")),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNotAllowedByListeners),
		},
		{
			name: "disallowed kind on gateway with only TLSRoute listeners",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "disallowed-kind",
						Namespace: "gateway-conformance-infra",
					},
				},
			},
			parentRef: gatewayv1.ParentReference{
				Name:      "tlsroutes-only",
				Namespace: Ptr(gatewayv1.Namespace("gateway-conformance-infra")),
			},
			expectedStatus: metav1.ConditionFalse,
			expectedReason: string(gatewayv1.RouteReasonNotAllowedByListeners),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := tt.route.ComputeAcceptedCondition(tt.parentRef, gateways)
			if cond.Status != tt.expectedStatus {
				t.Errorf("ComputeAcceptedCondition() Status = %v, want %v", cond.Status, tt.expectedStatus)
			}
			if cond.Reason != tt.expectedReason {
				t.Errorf("ComputeAcceptedCondition() Reason = %v, want %v", cond.Reason, tt.expectedReason)
			}
		})
	}
}

func TestIsAcceptedForParentRef(t *testing.T) {
	route := &HTTPRouteState{
		HTTPRoute: &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Status: gatewayv1.HTTPRouteStatus{
				RouteStatus: gatewayv1.RouteStatus{
					Parents: []gatewayv1.RouteParentStatus{
						{
							ParentRef: gatewayv1.ParentReference{
								Name: "gw-1",
							},
							ControllerName: "example.com/controller",
							Conditions: []metav1.Condition{
								{
									Type:   string(gatewayv1.RouteConditionAccepted),
									Status: metav1.ConditionTrue,
								},
							},
						},
						{
							ParentRef: gatewayv1.ParentReference{
								Name: "gw-2",
								Port: Ptr(gatewayv1.PortNumber(81)),
							},
							ControllerName: "example.com/controller",
							Conditions: []metav1.Condition{
								{
									Type:   string(gatewayv1.RouteConditionAccepted),
									Status: metav1.ConditionFalse,
									Reason: string(gatewayv1.RouteReasonNoMatchingParent),
								},
							},
						},
					},
				},
			},
		},
	}

	if !route.IsAcceptedForParentRef(gatewayv1.ParentReference{Name: "gw-1"}, "example.com/controller") {
		t.Errorf("expected route to be accepted for gw-1")
	}

	if route.IsAcceptedForParentRef(gatewayv1.ParentReference{Name: "gw-2", Port: Ptr(gatewayv1.PortNumber(81))}, "example.com/controller") {
		t.Errorf("expected route NOT to be accepted for gw-2 with port 81")
	}

	if route.IsAcceptedForParentRef(gatewayv1.ParentReference{Name: "gw-nonexistent"}, "example.com/controller") {
		t.Errorf("expected route NOT to be accepted for gw-nonexistent")
	}
}

func TestHTTPRouteValidate_Filters(t *testing.T) {
	tests := []struct {
		name        string
		route       *HTTPRouteState
		expectError bool
	}{
		{
			name: "supported rule filters and backend filters",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Filters: []gatewayv1.HTTPRouteFilter{
									{Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier},
									{Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier},
									{Type: gatewayv1.HTTPRouteFilterRequestRedirect},
									{Type: gatewayv1.HTTPRouteFilterURLRewrite},
									{Type: gatewayv1.HTTPRouteFilterCORS},
									{Type: gatewayv1.HTTPRouteFilterRequestMirror},
								},
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										Filters: []gatewayv1.HTTPRouteFilter{
											{Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier},
											{Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier},
											{Type: gatewayv1.HTTPRouteFilterCORS},
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "unsupported rule filter type",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Filters: []gatewayv1.HTTPRouteFilter{
									{Type: gatewayv1.HTTPRouteFilterType("UnknownFilter")},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "unsupported backend filter type",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										Filters: []gatewayv1.HTTPRouteFilter{
											{Type: gatewayv1.HTTPRouteFilterRequestMirror},
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("Validate() err = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestComputeAcceptedCondition_UnknownFilter(t *testing.T) {
	gw := &GatewayState{
		Gateway: &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Protocol: gatewayv1.HTTPProtocolType,
						Port:     80,
					},
				},
			},
		},
	}

	route := &HTTPRouteState{
		HTTPRoute: &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-filter-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: "test-gateway"},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								Filters: []gatewayv1.HTTPRouteFilter{
									{Type: gatewayv1.HTTPRouteFilterType("CustomFilter")},
								},
							},
						},
					},
				},
			},
		},
	}

	cond := route.ComputeAcceptedCondition(gatewayv1.ParentReference{Name: "test-gateway"}, []*GatewayState{gw})
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected Accepted status False, got %v", cond.Status)
	}
	if cond.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
		t.Errorf("expected Accepted reason UnsupportedValue, got %v", cond.Reason)
	}
}

func TestCompileHTTPRoute(t *testing.T) {
	t.Run("compiles valid route with matches, filters, backends, and TLS", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: "my-gw"},
					},
				},
				Hostnames: []gatewayv1.Hostname{"example.com"},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  Ptr(gatewayv1.PathMatchPathPrefix),
									Value: Ptr("/api"),
								},
								Headers: []gatewayv1.HTTPHeaderMatch{
									{
										Type:  Ptr(gatewayv1.HeaderMatchRegularExpression),
										Name:  "X-Version",
										Value: "v[0-9]+",
									},
								},
								Method: Ptr(gatewayv1.HTTPMethodGet),
							},
						},
						Filters: []gatewayv1.HTTPRouteFilter{
							{
								Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
								RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
									Set: []gatewayv1.HTTPHeader{
										{Name: "X-Forwarded-Proto", Value: "https"},
									},
								},
							},
						},
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "api-svc",
										Port: Ptr(gatewayv1.PortNumber(8443)),
									},
									Weight: Ptr(int32(10)),
								},
								Filters: []gatewayv1.HTTPRouteFilter{
									{
										Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
										ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
											Add: []gatewayv1.HTTPHeader{
												{Name: "X-Server", Value: "api"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		services := map[types.NamespacedName]*corev1.Service{
			{Namespace: "default", Name: "api-svc"}: {
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Port: 8443, AppProtocol: Ptr("https")},
					},
				},
			},
		}

		policies := []*gatewayv1.BackendTLSPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "api-tls",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: "",
								Kind:  "Service",
								Name:  "api-svc",
							},
						},
					},
					Validation: gatewayv1.BackendTLSPolicyValidation{
						Hostname: "api.example.internal",
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, services, policies, nil, nil)
		if internal == nil {
			t.Fatalf("expected non-nil InternalHTTPRoute")
		}

		if internal.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ValidationCondition True, got %+v", internal.ValidationCondition)
		}
		if internal.ResolvedRefsCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ResolvedRefsCondition True, got %+v", internal.ResolvedRefsCondition)
		}

		if len(internal.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(internal.Rules))
		}

		rule := internal.Rules[0]
		if rule.Error != nil {
			t.Fatalf("expected nil rule.Error, got %+v", rule.Error)
		}
		if len(rule.Matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(rule.Matches))
		}
		if rule.Matches[0].Path == nil || rule.Matches[0].Path.Value != "/api" {
			t.Errorf("expected path /api, got %+v", rule.Matches[0].Path)
		}
		if len(rule.Matches[0].Headers) != 1 || rule.Matches[0].Headers[0].MatchRegularExpressionValue == nil {
			t.Errorf("expected compiled regex header match, got %+v", rule.Matches[0].Headers)
		}
		if rule.RequestHeaderModifier == nil {
			t.Errorf("expected rule RequestHeaderModifier, got nil")
		}
		if len(rule.Backends) != 1 {
			t.Fatalf("expected 1 backend, got %d", len(rule.Backends))
		}

		backend := rule.Backends[0]
		if backend.Host != "api-svc.default.svc.cluster.local" || backend.Port != 8443 || backend.Weight != 10 {
			t.Errorf("unexpected backend values: %+v", backend)
		}
		if backend.TLSConfig == nil || backend.TLSConfig.Hostname != "api.example.internal" {
			t.Errorf("expected backend TLS config, got %+v", backend.TLSConfig)
		}
		if backend.ResponseHeaderModifier == nil {
			t.Errorf("expected backend ResponseHeaderModifier, got nil")
		}
	})

	t.Run("compiles invalid regex with error condition", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-regex", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								Headers: []gatewayv1.HTTPHeaderMatch{
									{
										Type:  Ptr(gatewayv1.HeaderMatchRegularExpression),
										Name:  "X-Version",
										Value: "[invalid",
									},
								},
							},
						},
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, nil, nil, nil, nil)
		if internal.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", internal.ValidationCondition.Status)
		}
		if internal.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %s", internal.ValidationCondition.Reason)
		}
		if len(internal.Rules) != 1 || internal.Rules[0].Error == nil {
			t.Fatalf("expected rule with ErrorState, got %+v", internal.Rules)
		}
	})

	t.Run("compiles timeouts on rule", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "timeout-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Timeouts: &gatewayv1.HTTPRouteTimeouts{
							Request:        Ptr(gatewayv1.Duration("10s")),
							BackendRequest: Ptr(gatewayv1.Duration("5s")),
						},
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "app-svc",
										Port: Ptr(gatewayv1.PortNumber(80)),
									},
								},
							},
						},
					},
				},
			},
		}

		services := map[types.NamespacedName]*corev1.Service{
			{Namespace: "default", Name: "app-svc"}: {
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{Port: 80}},
				},
			},
		}

		internal := CompileHTTPRoute(route, services, nil, nil, nil)
		if internal == nil {
			t.Fatalf("expected non-nil InternalHTTPRoute")
		}
		if internal.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ValidationCondition True, got %v", internal.ValidationCondition.Status)
		}
		if len(internal.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(internal.Rules))
		}
		if internal.Rules[0].Timeouts == nil {
			t.Fatalf("expected non-nil Timeouts on rule")
		}
		if internal.Rules[0].Timeouts.Request == nil || *internal.Rules[0].Timeouts.Request != 10*time.Second {
			t.Errorf("expected Request timeout 10s, got %v", internal.Rules[0].Timeouts.Request)
		}
		if internal.Rules[0].Timeouts.BackendRequest == nil || *internal.Rules[0].Timeouts.BackendRequest != 5*time.Second {
			t.Errorf("expected BackendRequest timeout 5s, got %v", internal.Rules[0].Timeouts.BackendRequest)
		}
	})

	t.Run("invalid timeout sets ValidationCondition False and rule error", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-timeout-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Timeouts: &gatewayv1.HTTPRouteTimeouts{
							Request: Ptr(gatewayv1.Duration("invalid-duration")),
						},
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, nil, nil, nil, nil)
		if internal == nil {
			t.Fatalf("expected non-nil InternalHTTPRoute")
		}
		if internal.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", internal.ValidationCondition.Status)
		}
		if internal.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected ValidationCondition reason UnsupportedValue, got %v", internal.ValidationCondition.Reason)
		}
		if len(internal.Rules) != 1 || internal.Rules[0].Error == nil {
			t.Fatalf("expected rule with ErrorState, got %+v", internal.Rules)
		}
	})

	t.Run("compiles query params correctly and deduplicates names", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "query-params", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								QueryParams: []gatewayv1.HTTPQueryParamMatch{
									{
										Name:  "animal",
										Value: "whale",
									},
									{
										Name:  "animal",
										Value: "dolphin", // Duplicate query param name should be ignored
									},
									{
										Type:  Ptr(gatewayv1.QueryParamMatchRegularExpression),
										Name:  "species",
										Value: "^whale-.*$",
									},
								},
							},
						},
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, nil, nil, nil, nil)
		if internal.ValidationCondition.Status != metav1.ConditionTrue {
			t.Fatalf("expected ValidationCondition True, got %v: %s", internal.ValidationCondition.Status, internal.ValidationCondition.Message)
		}
		if len(internal.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(internal.Rules))
		}
		matches := internal.Rules[0].Matches
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		qps := matches[0].QueryParams
		if len(qps) != 2 {
			t.Fatalf("expected 2 query params (deduplicated), got %d", len(qps))
		}
		if qps[0].Name != "animal" || qps[0].MatchExactValue != "whale" || qps[0].Type != gatewayv1.QueryParamMatchExact {
			t.Errorf("unexpected qp[0]: %+v", qps[0])
		}
		if qps[1].Name != "species" || qps[1].MatchRegularExpressionValue == nil || qps[1].Type != gatewayv1.QueryParamMatchRegularExpression {
			t.Errorf("unexpected qp[1]: %+v", qps[1])
		}
	})

	t.Run("compiles invalid query param regex with error condition", func(t *testing.T) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-qp-regex", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								QueryParams: []gatewayv1.HTTPQueryParamMatch{
									{
										Type:  Ptr(gatewayv1.QueryParamMatchRegularExpression),
										Name:  "animal",
										Value: "[invalid",
									},
								},
							},
						},
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, nil, nil, nil, nil)
		if internal.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", internal.ValidationCondition.Status)
		}
		if internal.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %s", internal.ValidationCondition.Reason)
		}
		if len(internal.Rules) != 1 || internal.Rules[0].Error == nil {
			t.Fatalf("expected rule with ErrorState, got %+v", internal.Rules)
		}
	})

	t.Run("compiles unsupported query param type with error condition", func(t *testing.T) {
		unknownType := gatewayv1.QueryParamMatchType("UnknownType")
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "unknown-qp-type", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								QueryParams: []gatewayv1.HTTPQueryParamMatch{
									{
										Type:  &unknownType,
										Name:  "animal",
										Value: "whale",
									},
								},
							},
						},
					},
				},
			},
		}

		internal := CompileHTTPRoute(route, nil, nil, nil, nil)
		if internal.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", internal.ValidationCondition.Status)
		}
		if internal.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %s", internal.ValidationCondition.Reason)
		}
	})

	t.Run("compiles named rules and rejects duplicate rule names", func(t *testing.T) {
		ruleName1 := gatewayv1.SectionName("rule-1")
		ruleName2 := gatewayv1.SectionName("rule-2")

		validRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "valid-named-rules", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Name: &ruleName1,
						Matches: []gatewayv1.HTTPRouteMatch{
							{Path: &gatewayv1.HTTPPathMatch{Value: Ptr("/rule1")}},
						},
					},
					{
						Name: &ruleName2,
						Matches: []gatewayv1.HTTPRouteMatch{
							{Path: &gatewayv1.HTTPPathMatch{Value: Ptr("/rule2")}},
						},
					},
					{
						// Unnamed rule alongside named rules is valid
						Matches: []gatewayv1.HTTPRouteMatch{
							{Path: &gatewayv1.HTTPPathMatch{Value: Ptr("/unnamed")}},
						},
					},
				},
			},
		}

		internalValid := CompileHTTPRoute(validRoute, nil, nil, nil, nil)
		if internalValid.ValidationCondition.Status != metav1.ConditionTrue {
			t.Fatalf("expected valid named route ValidationCondition True, got %v", internalValid.ValidationCondition.Status)
		}
		if len(internalValid.Rules) != 3 {
			t.Fatalf("expected 3 rules, got %d", len(internalValid.Rules))
		}
		if internalValid.Rules[0].Name == nil || *internalValid.Rules[0].Name != ruleName1 {
			t.Errorf("expected rule 0 name rule-1, got %v", internalValid.Rules[0].Name)
		}
		if internalValid.Rules[1].Name == nil || *internalValid.Rules[1].Name != ruleName2 {
			t.Errorf("expected rule 1 name rule-2, got %v", internalValid.Rules[1].Name)
		}
		if internalValid.Rules[2].Name != nil {
			t.Errorf("expected rule 2 name nil, got %v", internalValid.Rules[2].Name)
		}

		// Duplicate rule names
		duplicateRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "duplicate-named-rules", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Name: &ruleName1,
						Matches: []gatewayv1.HTTPRouteMatch{
							{Path: &gatewayv1.HTTPPathMatch{Value: Ptr("/rule1")}},
						},
					},
					{
						Name: &ruleName1, // duplicate name
						Matches: []gatewayv1.HTTPRouteMatch{
							{Path: &gatewayv1.HTTPPathMatch{Value: Ptr("/rule2")}},
						},
					},
				},
			},
		}

		internalDup := CompileHTTPRoute(duplicateRoute, nil, nil, nil, nil)
		if internalDup.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected duplicate rule names ValidationCondition False, got %v", internalDup.ValidationCondition.Status)
		}
		if internalDup.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %s", internalDup.ValidationCondition.Reason)
		}
	})
}

func TestHTTPRouteValidate_Timeouts(t *testing.T) {
	tests := []struct {
		name        string
		route       *HTTPRouteState
		expectError bool
	}{
		{
			name: "valid request and backendRequest timeouts",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Timeouts: &gatewayv1.HTTPRouteTimeouts{
									Request:        Ptr(gatewayv1.Duration("10s")),
									BackendRequest: Ptr(gatewayv1.Duration("5s")),
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid 0s timeouts (disabled)",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Timeouts: &gatewayv1.HTTPRouteTimeouts{
									Request:        Ptr(gatewayv1.Duration("0s")),
									BackendRequest: Ptr(gatewayv1.Duration("0s")),
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid request timeout string",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Timeouts: &gatewayv1.HTTPRouteTimeouts{
									Request: Ptr(gatewayv1.Duration("invalid-duration")),
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid backendRequest timeout string",
			route: &HTTPRouteState{
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								Timeouts: &gatewayv1.HTTPRouteTimeouts{
									BackendRequest: Ptr(gatewayv1.Duration("not-a-duration")),
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("Validate() err = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestCompileHTTPRoute_RequestMirror(t *testing.T) {
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 8080},
				},
			},
		},
		{Namespace: "default", Name: "mirror-svc"}: {
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 8080},
				},
			},
		},
		{Namespace: "other-ns", Name: "mirror-svc-2"}: {
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 9090},
				},
			},
		},
	}

	tests := []struct {
		name                 string
		route                *gatewayv1.HTTPRoute
		refValidator         ReferenceGrantValidator
		expectedAccepted     metav1.ConditionStatus
		expectedAcceptedReas string
		expectedResolvedRefs metav1.ConditionStatus
		expectedResolvedReas string
		expectedMirrorCount  int
		expectedNumerator    int32
		expectedDenominator  int32
	}{
		{
			name: "valid request mirror with default 100%",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionTrue,
			expectedAcceptedReas: string(gatewayv1.RouteReasonAccepted),
			expectedResolvedRefs: metav1.ConditionTrue,
			expectedResolvedReas: string(gatewayv1.RouteReasonResolvedRefs),
			expectedMirrorCount:  1,
			expectedNumerator:    100,
			expectedDenominator:  100,
		},
		{
			name: "valid request mirror with percent",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
										Percent: Ptr(int32(20)),
									},
								},
							},
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionTrue,
			expectedAcceptedReas: string(gatewayv1.RouteReasonAccepted),
			expectedResolvedRefs: metav1.ConditionTrue,
			expectedResolvedReas: string(gatewayv1.RouteReasonResolvedRefs),
			expectedMirrorCount:  1,
			expectedNumerator:    20,
			expectedDenominator:  100,
		},
		{
			name: "valid request mirror with fraction",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
										Fraction: &gatewayv1.Fraction{
											Numerator:   25,
											Denominator: Ptr(int32(50)),
										},
									},
								},
							},
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionTrue,
			expectedAcceptedReas: string(gatewayv1.RouteReasonAccepted),
			expectedResolvedRefs: metav1.ConditionTrue,
			expectedResolvedReas: string(gatewayv1.RouteReasonResolvedRefs),
			expectedMirrorCount:  1,
			expectedNumerator:    25,
			expectedDenominator:  50,
		},
		{
			name: "invalid request mirror with both percent and fraction",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
										Percent: Ptr(int32(20)),
										Fraction: &gatewayv1.Fraction{
											Numerator: 25,
										},
									},
								},
							},
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionFalse,
			expectedAcceptedReas: string(gatewayv1.RouteReasonUnsupportedValue),
			expectedResolvedRefs: metav1.ConditionTrue,
			expectedResolvedReas: string(gatewayv1.RouteReasonResolvedRefs),
			expectedMirrorCount:  0,
		},
		{
			name: "invalid request mirror percent > 100",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
										Percent: Ptr(int32(101)),
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionFalse,
			expectedAcceptedReas: string(gatewayv1.RouteReasonUnsupportedValue),
			expectedResolvedRefs: metav1.ConditionTrue,
			expectedResolvedReas: string(gatewayv1.RouteReasonResolvedRefs),
			expectedMirrorCount:  0,
		},
		{
			name: "invalid request mirror backend not found",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "nonexistent-mirror-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
											Port: Ptr(gatewayv1.PortNumber(8080)),
										},
									},
								},
							},
						},
					},
				},
			},
			expectedAccepted:     metav1.ConditionTrue,
			expectedAcceptedReas: string(gatewayv1.RouteReasonAccepted),
			expectedResolvedRefs: metav1.ConditionFalse,
			expectedResolvedReas: string(gatewayv1.RouteReasonBackendNotFound),
			expectedMirrorCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled := CompileHTTPRoute(tt.route, services, nil, nil, tt.refValidator)
			if compiled.ValidationCondition.Status != tt.expectedAccepted {
				t.Errorf("ValidationCondition.Status = %v, want %v", compiled.ValidationCondition.Status, tt.expectedAccepted)
			}
			if compiled.ValidationCondition.Reason != tt.expectedAcceptedReas {
				t.Errorf("ValidationCondition.Reason = %v, want %v", compiled.ValidationCondition.Reason, tt.expectedAcceptedReas)
			}
			if compiled.ResolvedRefsCondition.Status != tt.expectedResolvedRefs {
				t.Errorf("ResolvedRefsCondition.Status = %v, want %v", compiled.ResolvedRefsCondition.Status, tt.expectedResolvedRefs)
			}
			if compiled.ResolvedRefsCondition.Reason != tt.expectedResolvedReas {
				t.Errorf("ResolvedRefsCondition.Reason = %v, want %v", compiled.ResolvedRefsCondition.Reason, tt.expectedResolvedReas)
			}
			if len(compiled.Rules) > 0 {
				if len(compiled.Rules[0].Mirrors) != tt.expectedMirrorCount {
					t.Errorf("Mirrors count = %v, want %v", len(compiled.Rules[0].Mirrors), tt.expectedMirrorCount)
				}
				if tt.expectedMirrorCount > 0 {
					m := compiled.Rules[0].Mirrors[0]
					if m.Numerator != tt.expectedNumerator || m.Denominator != tt.expectedDenominator {
						t.Errorf("Mirror fraction = %d/%d, want %d/%d", m.Numerator, m.Denominator, tt.expectedNumerator, tt.expectedDenominator)
					}
				}
			}
		})
	}
}
