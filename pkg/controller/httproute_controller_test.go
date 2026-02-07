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

package controller

import (
	"context"
	"reflect"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestExtractRoutes(t *testing.T) {
	tests := []struct {
		name     string
		routes   *gatewayv1.HTTPRouteList
		gateways *gatewayv1.GatewayList
		expected []proxy.HTTPRoute
	}{
		{
			name: "single route with single backend",
			gateways: &gatewayv1.GatewayList{
				Items: []gatewayv1.Gateway{
					{
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
			},
			routes: &gatewayv1.HTTPRouteList{
				Items: []gatewayv1.HTTPRoute{
					{
						ObjectMeta: metav1.ObjectMeta{
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
													Kind: ptr(gatewayv1.Kind("Service")),
													Name: "backend-svc",
													Port: ptr(gatewayv1.PortNumber(80)),
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
										ControllerName: ControllerName,
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
			expected: []proxy.HTTPRoute{
				{
					Hostnames: []string{"example.com"},
					Rules: []proxy.RouteRule{
						{
							Backend: proxy.Backend{Host: "backend-svc.default.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
		{
			name: "multiple hostnames with intersection",
			gateways: &gatewayv1.GatewayList{
				Items: []gatewayv1.Gateway{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "reference-gateway",
							Namespace: "test-ns",
						},
						Spec: gatewayv1.GatewaySpec{
							Listeners: []gatewayv1.Listener{
								{
									Name:     "http",
									Protocol: gatewayv1.HTTPProtocolType,
									Hostname: ptr(gatewayv1.Hostname("*.example.com")),
								},
							},
						},
					},
				},
			},
			routes: &gatewayv1.HTTPRouteList{
				Items: []gatewayv1.HTTPRoute{
					{
						ObjectMeta: metav1.ObjectMeta{
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
													Port: ptr(gatewayv1.PortNumber(8080)),
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
										ControllerName: ControllerName,
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
			expected: []proxy.HTTPRoute{
				{
					Hostnames: []string{"foo.example.com"},
					Rules: []proxy.RouteRule{
						{
							Backend: proxy.Backend{Host: "backend-svc.test-ns.svc.cluster.local", Port: 8080},
						},
					},
				},
			},
		},
		{
			name: "exact path match",
			gateways: &gatewayv1.GatewayList{
				Items: []gatewayv1.Gateway{
					{
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
			},
			routes: &gatewayv1.HTTPRouteList{
				Items: []gatewayv1.HTTPRoute{
					{
						ObjectMeta: metav1.ObjectMeta{
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
												Type:  ptr(gatewayv1.PathMatchExact),
												Value: ptr("/foo"),
											},
										},
									},
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-svc",
													Port: ptr(gatewayv1.PortNumber(80)),
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
										ControllerName: ControllerName,
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
			expected: []proxy.HTTPRoute{
				{
					Hostnames: []string{"*"},
					Rules: []proxy.RouteRule{
						{
							Matches: []proxy.RouteMatch{
								{
									Path: &proxy.PathMatch{
										Type:  proxy.PathMatchTypeExact,
										Value: "/foo",
									},
								},
							},
							Backend: proxy.Backend{Host: "backend-svc.default.svc.cluster.local", Port: 80},
						},
					},
				},
			},
		},
	}

	reconciler := &HTTPRouteReconciler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := reconciler.extractRoutes(context.Background(), tt.routes, tt.gateways)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}
