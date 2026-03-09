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
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBuildInternalRoutes(t *testing.T) {
	controllerName := "test-controller"
	tests := []struct {
		name               string
		routes             []*HTTPRouteState
		gateway            *GatewayState
		services           map[types.NamespacedName]*corev1.Service
		backendTLSPolicies []*gatewayv1.BackendTLSPolicy
		configMaps         map[types.NamespacedName]*corev1.ConfigMap
		expected           []InternalRoute
	}{
		{
			name: "single route with single backend and appProtocol",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Hostnames: []gatewayv1.Hostname{"example.com"},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Kind: Ptr(gatewayv1.Kind("Service")),
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
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
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port:        80,
								AppProtocol: Ptr("kubernetes.io/h2c"),
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"example.com"},
					Rules: []InternalRule{
						{
							Backend: &InternalBackend{
								Host:        "backend-svc.default.svc.cluster.local",
								Port:        80,
								AppProtocol: Ptr("kubernetes.io/h2c"),
							},
						},
					},
				},
			},
		},
		{
			name: "single route with single backend",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Hostnames: []gatewayv1.Hostname{"example.com"},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Kind: Ptr(gatewayv1.Kind("Service")),
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"example.com"},
					Rules: []InternalRule{
						{
							Backend: &InternalBackend{Host: "backend-svc.default.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
		{
			name: "multiple hostnames with intersection",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "test-ns",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
								Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "test-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Hostnames: []gatewayv1.Hostname{"example.com", "foo.example.com", "bar.com"},
							Rules: []gatewayv1.HTTPRouteRule{
								{
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
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"foo.example.com"},
					Rules: []InternalRule{
						{
							Backend: &InternalBackend{Host: "backend-svc.test-ns.svc.cluster.local", Port: 8080},
						},
					},
				},
			},
		},
		{
			name: "exact path match",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									Matches: []gatewayv1.HTTPRouteMatch{
										{
											Path: &gatewayv1.HTTPPathMatch{
												Type:  Ptr(gatewayv1.PathMatchExact),
												Value: Ptr("/foo"),
											},
										},
									},
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"*"},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchExact,
										Value: "/foo",
									},
								},
							},
							Backend: &InternalBackend{Host: "backend-svc.default.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
		{
			name: "method matching",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									Matches: []gatewayv1.HTTPRouteMatch{
										{
											Method: Ptr(gatewayv1.HTTPMethod("POST")),
										},
									},
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"*"},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Method: Ptr(gatewayv1.HTTPMethod("POST")),
								},
							},
							Backend: &InternalBackend{Host: "backend-svc.default.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
		{
			name: "invalid backend kind",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Kind: Ptr(gatewayv1.Kind("Unknown")),
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"*"},
					Rules: []InternalRule{
						{
							Error: &ErrorState{
								Condition: metav1.Condition{
									Type:    string(gatewayv1.RouteConditionResolvedRefs),
									Status:  metav1.ConditionFalse,
									Reason:  string(gatewayv1.RouteReasonInvalidKind),
									Message: "Unsupported backend kind: Unknown",
								},
								HTTPStatusCode: 500,
								HTTPMessage:    "Unsupported backend kind: Unknown",
							},
						},
					},
				},
			},
		},
		{
			name: "BackendTLSPolicy conflict resolution - oldest wins",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "default",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name: "reference-gateway",
									},
								},
							},
							Hostnames: []gatewayv1.Hostname{"example.com"},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Kind: Ptr(gatewayv1.Kind("Service")),
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name: "reference-gateway",
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
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
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Port: 80,
							},
						},
					},
				},
			},
			backendTLSPolicies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-new",
						Namespace:         "default",
						CreationTimestamp: metav1.NewTime(metav1.Now().Add(10 * 1e9)),
					},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "backend-svc",
								},
							},
						},
						Validation: gatewayv1.BackendTLSPolicyValidation{
							Hostname: "new.example.com",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-old",
						Namespace:         "default",
						CreationTimestamp: metav1.NewTime(metav1.Now().Add(-10 * 1e9)),
					},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "backend-svc",
								},
							},
						},
						Validation: gatewayv1.BackendTLSPolicyValidation{
							Hostname: "old.example.com",
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"example.com"},
					Rules: []InternalRule{
						{
							Backend: &InternalBackend{
								Host:        "backend-svc.default.svc.cluster.local",
								Port:        80,
								AppProtocol: Ptr("https"),
								TLSConfig: &InternalTLSConfig{
									Hostname: "old.example.com",
									CACerts:  nil,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "cross-namespace route allowed by All",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "gateway-ns",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
								AllowedRoutes: &gatewayv1.AllowedRoutes{
									Namespaces: &gatewayv1.RouteNamespaces{
										From: Ptr(gatewayv1.NamespacesFromAll),
									},
								},
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "route-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name:      "reference-gateway",
										Namespace: Ptr(gatewayv1.Namespace("gateway-ns")),
									},
								},
							},
							Rules: []gatewayv1.HTTPRouteRule{
								{
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
										},
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name:      "reference-gateway",
											Namespace: Ptr(gatewayv1.Namespace("gateway-ns")),
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []string{"*"},
					Rules: []InternalRule{
						{
							Backend: &InternalBackend{Host: "backend-svc.route-ns.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
		{
			name: "cross-namespace route NOT allowed by default (Same namespace)",
			gateway: &GatewayState{
				Gateway: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reference-gateway",
						Namespace: "gateway-ns",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route1",
							Namespace: "route-ns",
						},
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: gatewayv1.CommonRouteSpec{
								ParentRefs: []gatewayv1.ParentReference{
									{
										Name:      "reference-gateway",
										Namespace: Ptr(gatewayv1.Namespace("gateway-ns")),
									},
								},
							},
						},
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
											Name:      "reference-gateway",
											Namespace: Ptr(gatewayv1.Namespace("gateway-ns")),
										},
										ControllerName: gatewayv1.GatewayController(controllerName),
										Conditions: []metav1.Condition{
											{
												Type:   string(gatewayv1.RouteConditionAccepted),
												Status: metav1.ConditionTrue,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.gateway.BuildInternalRoutes(tt.routes, tt.services, nil, tt.backendTLSPolicies, tt.configMaps, controllerName)
			diff := cmp.Diff(tt.expected, actual, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime", "ObservedGeneration"))
			if diff != "" {
				t.Errorf("BuildInternalRoutes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMatchRoute_Method(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: []string{"example.com"},
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Method: Ptr(gatewayv1.HTTPMethod("POST")),
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/submit",
							},
						},
					},
					Backend: &InternalBackend{Host: "post-backend", Port: 80},
				},
				{
					Matches: []InternalMatch{
						{
							Method: Ptr(gatewayv1.HTTPMethod("GET")),
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchExact,
								Value: "/submit",
							},
						},
					},
					Backend: &InternalBackend{Host: "get-backend", Port: 80},
				},
			},
		},
	}

	tests := []struct {
		name        string
		method      string
		path        string
		wantBackend string
	}{
		{
			name:        "match POST",
			method:      "POST",
			path:        "/submit",
			wantBackend: "post-backend",
		},
		{
			name:        "match GET",
			method:      "GET",
			path:        "/submit",
			wantBackend: "get-backend",
		},
		{
			name:        "no match for PUT",
			method:      "PUT",
			path:        "/submit",
			wantBackend: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			rule, _ := MatchRoute(routes, req)
			if tt.wantBackend == "" {
				if rule != nil {
					t.Errorf("MatchRoute() matched rule %v, want no match", rule.Backend.Host)
				}
			} else {
				if rule == nil {
					t.Errorf("MatchRoute() matched no rule, want %s", tt.wantBackend)
				} else if rule.Backend.Host != tt.wantBackend {
					t.Errorf("MatchRoute() matched backend %s, want %s", rule.Backend.Host, tt.wantBackend)
				}
			}
		})
	}
}
