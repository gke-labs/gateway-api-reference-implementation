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
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func routeHostnamesFromStrings(hostnames ...string) []RouteHostname {
	out := make([]RouteHostname, len(hostnames))
	for i, h := range hostnames {
		out[i] = NewRouteHostname(h, h)
	}
	return out
}

func TestBuildInternalRoutes(t *testing.T) {
	controllerName := "test-controller"
	tests := []struct {
		name               string
		routes             []*HTTPRouteState
		gateway            *GatewayState
		services           map[types.NamespacedName]*corev1.Service
		backendTLSPolicies []*gatewayv1.BackendTLSPolicy
		configMaps         map[types.NamespacedName]*corev1.ConfigMap
		referenceGrants    []*gatewayv1beta1.ReferenceGrant
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
					Hostnames: []RouteHostname{
						NewRouteHostname("example.com", "example.com"),
					},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{
									Host:        "backend-svc.default.svc.cluster.local",
									Port:        80,
									AppProtocol: Ptr("kubernetes.io/h2c"),
									Weight:      1,
								},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{
						NewRouteHostname("example.com", "example.com"),
					},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "test-ns", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 8080}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{
						NewRouteHostname("foo.example.com", "foo.example.com"),
					},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{{Host: "backend-svc.test-ns.svc.cluster.local", Port: 8080, Weight: 1}},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
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
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Method: Ptr(gatewayv1.HTTPMethod("POST")),
								},
							},
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
						},
					},
				},
			},
		},
		{
			name: "route with request redirect 307",
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
							Name:      "307-redirect",
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
												Type:  Ptr(gatewayv1.PathMatchPathPrefix),
												Value: Ptr("/temporary"),
											},
										},
									},
									Filters: []gatewayv1.HTTPRouteFilter{
										{
											Type: gatewayv1.HTTPRouteFilterRequestRedirect,
											RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
												StatusCode: Ptr(307),
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/temporary",
									},
								},
							},
							Redirect: &InternalRedirect{
								StatusCode: Ptr(307),
							},
						},
					},
				},
			},
		},
		{
			name: "route with request redirect full options",
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
							Name:      "redirect-test",
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
												Type:  Ptr(gatewayv1.PathMatchPathPrefix),
												Value: Ptr("/see-other"),
											},
										},
									},
									Filters: []gatewayv1.HTTPRouteFilter{
										{
											Type: gatewayv1.HTTPRouteFilterRequestRedirect,
											RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
												Scheme:     Ptr("https"),
												Hostname:   Ptr(gatewayv1.PreciseHostname("example.org")),
												Port:       Ptr(gatewayv1.PortNumber(8443)),
												StatusCode: Ptr(303),
												Path: &gatewayv1.HTTPPathModifier{
													Type:               gatewayv1.PrefixMatchHTTPPathModifier,
													ReplacePrefixMatch: Ptr("/replacement-prefix"),
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/see-other",
									},
								},
							},
							Redirect: &InternalRedirect{
								Scheme:     Ptr("https"),
								Hostname:   Ptr(gatewayv1.PreciseHostname("example.org")),
								Port:       Ptr(gatewayv1.PortNumber(8443)),
								StatusCode: Ptr(303),
								Path: &InternalPathRedirect{
									Type:  gatewayv1.PrefixMatchHTTPPathModifier,
									Value: "/replacement-prefix",
								},
							},
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
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
			name: "invalid backend group and kind",
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
							Name:      "route-unknown-group",
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
													Group: Ptr(gatewayv1.Group("unknownkind.example.com")),
													Kind:  Ptr(gatewayv1.Kind("NonExistent")),
													Name:  "backend-svc",
													Port:  Ptr(gatewayv1.PortNumber(80)),
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Error: &ErrorState{
								Condition: metav1.Condition{
									Type:    string(gatewayv1.RouteConditionResolvedRefs),
									Status:  metav1.ConditionFalse,
									Reason:  string(gatewayv1.RouteReasonInvalidKind),
									Message: "Unsupported backend: unknownkind.example.com/NonExistent",
								},
								HTTPStatusCode: 500,
								HTTPMessage:    "Unsupported backend: unknownkind.example.com/NonExistent",
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
					Hostnames: []RouteHostname{
						NewRouteHostname("example.com", "example.com"),
					},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{
									Host:        "backend-svc.default.svc.cluster.local",
									Port:        80,
									AppProtocol: Ptr("https"),
									TLSConfig: &InternalTLSConfig{
										Hostname: "old.example.com",
										CACerts:  nil,
									},
									Weight: 1,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "single route with URL rewrite",
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
									Filters: []gatewayv1.HTTPRouteFilter{
										{
											Type: gatewayv1.HTTPRouteFilterURLRewrite,
											URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
												Hostname: Ptr(gatewayv1.PreciseHostname("new.example.com")),
												Path: &gatewayv1.HTTPPathModifier{
													Type:               gatewayv1.PrefixMatchHTTPPathModifier,
													ReplacePrefixMatch: Ptr("/new-prefix"),
												},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Rewrite: &InternalRewrite{
								Hostname: Ptr(gatewayv1.PreciseHostname("new.example.com")),
								Path: &InternalPathRewrite{
									Type:  gatewayv1.PrefixMatchHTTPPathModifier,
									Value: "/new-prefix",
								},
							},
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
						},
					},
				},
			},
		},
		{
			name: "route with URL rewrite and request header modifier",
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
									Filters: []gatewayv1.HTTPRouteFilter{
										{
											Type: gatewayv1.HTTPRouteFilterURLRewrite,
											URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
												Path: &gatewayv1.HTTPPathModifier{
													Type:            gatewayv1.FullPathHTTPPathModifier,
													ReplaceFullPath: Ptr("/test"),
												},
											},
										},
										{
											Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
											RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
												Set: []gatewayv1.HTTPHeader{
													{Name: "X-Header-Set", Value: "set-val"},
												},
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
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Rewrite: &InternalRewrite{
								Path: &InternalPathRewrite{
									Type:  gatewayv1.FullPathHTTPPathModifier,
									Value: "/test",
								},
							},
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Header-Set", Value: "set-val"},
								},
							},
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
						},
					},
				},
			},
		},
		{
			name: "route with response header modifier filter",
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
								Port:     80,
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					}},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 80},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route-with-resp-filter",
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
									Filters: []gatewayv1.HTTPRouteFilter{
										{
											Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
											ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
												Set: []gatewayv1.HTTPHeader{
													{Name: "X-Header-Set", Value: "set-val"},
												},
												Add: []gatewayv1.HTTPHeader{
													{Name: "X-Header-Add", Value: "add-val"},
												},
												Remove: []string{"X-Header-Remove"},
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Header-Set", Value: "set-val"},
								},
								Add: []gatewayv1.HTTPHeader{
									{Name: "X-Header-Add", Value: "add-val"},
								},
								Remove: []string{"X-Header-Remove"},
							},
							Backends: []InternalBackend{{Host: "backend-svc.default.svc.cluster.local", Port: 80, Weight: 1}},
						},
					},
				},
			},
		},
		{
			name: "route with multiple weighted backends and backend filters",
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
								Port:     80,
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					}},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-v1"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 8080},
						},
					},
				},
				{Namespace: "default", Name: "backend-v2"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 8080},
						},
					},
				},
				{Namespace: "default", Name: "backend-v3"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 8080},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "weighted-route",
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
													Name: "backend-v1",
													Port: Ptr(gatewayv1.PortNumber(8080)),
												},
												Weight: Ptr(int32(70)),
											},
											Filters: []gatewayv1.HTTPRouteFilter{
												{
													Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
													RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
														Set: []gatewayv1.HTTPHeader{
															{Name: "Backend", Value: "backend-v1"},
														},
													},
												},
											},
										},
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-v2",
													Port: Ptr(gatewayv1.PortNumber(8080)),
												},
												Weight: Ptr(int32(30)),
											},
											Filters: []gatewayv1.HTTPRouteFilter{
												{
													Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
													RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
														Set: []gatewayv1.HTTPHeader{
															{Name: "Backend", Value: "backend-v2"},
														},
													},
												},
											},
										},
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "backend-v3",
													Port: Ptr(gatewayv1.PortNumber(8080)),
												},
												Weight: Ptr(int32(0)),
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{
									Host:   "backend-v1.default.svc.cluster.local",
									Port:   8080,
									Weight: 70,
									RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "Backend", Value: "backend-v1"},
										},
									},
								},
								{
									Host:   "backend-v2.default.svc.cluster.local",
									Port:   8080,
									Weight: 30,
									RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "Backend", Value: "backend-v2"},
										},
									},
								},
								{
									Host:   "backend-v3.default.svc.cluster.local",
									Port:   8080,
									Weight: 0,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route-with-backend-filters",
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
								Port:     80,
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					}},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 80},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route-with-backend-filters",
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
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
											Filters: []gatewayv1.HTTPRouteFilter{
												{
													Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
													RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
														Set: []gatewayv1.HTTPHeader{
															{Name: "X-Backend-Req-Set", Value: "b-set"},
														},
													},
												},
												{
													Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
													ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
														Set: []gatewayv1.HTTPHeader{
															{Name: "X-Backend-Resp-Set", Value: "b-resp-set"},
														},
													},
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
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{
									Host:   "backend-svc.default.svc.cluster.local",
									Port:   80,
									Weight: 1,
									RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "X-Backend-Req-Set", Value: "b-set"},
										},
									},
									ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
										Set: []gatewayv1.HTTPHeader{
											{Name: "X-Backend-Resp-Set", Value: "b-resp-set"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "route-with-unsupported-backend-filter",
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
								Port:     80,
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					}},
			},
			services: map[types.NamespacedName]*corev1.Service{
				{Namespace: "default", Name: "backend-svc"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 80},
						},
					},
				},
			},
			routes: []*HTTPRouteState{
				{
					HTTPRoute: &gatewayv1.HTTPRoute{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "route-with-unsupported-backend-filter",
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
													Name: "backend-svc",
													Port: Ptr(gatewayv1.PortNumber(80)),
												},
											},
											Filters: []gatewayv1.HTTPRouteFilter{
												{
													Type: gatewayv1.HTTPRouteFilterRequestMirror,
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
												Status: metav1.ConditionFalse,
												Reason: string(gatewayv1.RouteReasonUnsupportedValue),
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
		{
			name: "invalid nonexistent backend ref",
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
													Name: "nonexistent-svc",
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
				{Namespace: "default", Name: "other-svc"}: {},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Error: &ErrorState{
								Condition: metav1.Condition{
									Type:    string(gatewayv1.RouteConditionResolvedRefs),
									Status:  metav1.ConditionFalse,
									Reason:  string(gatewayv1.RouteReasonBackendNotFound),
									Message: "Backend service default/nonexistent-svc not found",
								},
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    "Backend service default/nonexistent-svc not found",
							},
						},
					},
				},
			},
		},
		{
			name: "invalid cross-namespace backend ref without ReferenceGrant",
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
				{Namespace: "other-ns", Name: "web-backend"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Error: &ErrorState{
								Condition: metav1.Condition{
									Type:    string(gatewayv1.RouteConditionResolvedRefs),
									Status:  metav1.ConditionFalse,
									Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
									Message: "Cross-namespace reference to service other-ns/web-backend is not permitted by any ReferenceGrant",
								},
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    "Cross-namespace reference to service other-ns/web-backend is not permitted by any ReferenceGrant",
							},
						},
					},
				},
			},
		},
		{
			name: "valid cross-namespace backend ref with ReferenceGrant",
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
				{Namespace: "other-ns", Name: "web-backend"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
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
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{{Host: "web-backend.other-ns.svc.cluster.local", Port: 80, Weight: 1}},
						},
					},
				},
			},
		},
		{
			name: "partially invalid cross-namespace backend refs with selective ReferenceGrant",
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
							Name:      "route-partially-invalid",
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
												Type:  Ptr(gatewayv1.PathMatchPathPrefix),
												Value: Ptr("/v2"),
											},
										},
									},
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Namespace: Ptr(gatewayv1.Namespace("app-ns")),
													Name:      "app-backend-v2",
													Port:      Ptr(gatewayv1.PortNumber(8080)),
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
													Port:      Ptr(gatewayv1.PortNumber(8080)),
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
				{Namespace: "app-ns", Name: "app-backend-v1"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 8080}},
					},
				},
				{Namespace: "app-ns", Name: "app-backend-v2"}: {
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 8080}},
					},
				},
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
			expected: []InternalRoute{
				{
					Hostnames: []RouteHostname{NewRouteHostname("*", "")},
					Rules: []InternalRule{
						{
							Matches: []InternalMatch{
								{
									Path: &InternalPathMatch{
										Type:  gatewayv1.PathMatchPathPrefix,
										Value: "/v2",
									},
								},
							},
							Error: &ErrorState{
								Condition: metav1.Condition{
									Type:    string(gatewayv1.RouteConditionResolvedRefs),
									Status:  metav1.ConditionFalse,
									Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
									Message: "Cross-namespace reference to service app-ns/app-backend-v2 is not permitted by any ReferenceGrant",
								},
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    "Cross-namespace reference to service app-ns/app-backend-v2 is not permitted by any ReferenceGrant",
							},
						},
						{
							Backends: []InternalBackend{{Host: "app-backend-v1.app-ns.svc.cluster.local", Port: 8080, Weight: 1}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var routes []*gatewayv1.HTTPRoute
			for _, r := range tt.routes {
				if r != nil && r.HTTPRoute != nil {
					routes = append(routes, r.HTTPRoute)
				}
			}
			var gcs []*gatewayv1.GatewayClass
			if tt.gateway != nil && tt.gateway.Gateway != nil {
				gcs = append(gcs, &gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{Name: string(tt.gateway.Spec.GatewayClassName)},
					Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(controllerName)},
				})
			}
			rgMap := make(map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant)
			for _, rg := range tt.referenceGrants {
				if rg != nil {
					rgMap[types.NamespacedName{Namespace: rg.Namespace, Name: rg.Name}] = rg
				}
			}
			outputs := ComputeOutputs(ModelInputs{
				Gateways:           []*gatewayv1.Gateway{tt.gateway.Gateway},
				GatewayClasses:     gcs,
				HTTPRoutes:         routes,
				Services:           tt.services,
				BackendTLSPolicies: tt.backendTLSPolicies,
				ConfigMaps:         tt.configMaps,
				ReferenceGrants:    rgMap,
				ControllerName:     controllerName,
			})
			actual := outputs.ProxyRoutes
			diff := cmp.Diff(tt.expected, actual,
				cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime", "ObservedGeneration"),
				cmpopts.IgnoreUnexported(RouteHostname{}),
			)
			if diff != "" {
				t.Errorf("ComputeOutputs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMatchRoute_Method(t *testing.T) {
	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("example.com"),
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
					Backends: []InternalBackend{{Host: "post-backend", Port: 80, Weight: 1}},
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
					Backends: []InternalBackend{{Host: "get-backend", Port: 80, Weight: 1}},
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
					t.Errorf("MatchRoute() matched rule %v, want no match", rule.Backends[0].Host)
				}
			} else {
				if rule == nil {
					t.Errorf("MatchRoute() matched no rule, want %s", tt.wantBackend)
				} else if len(rule.Backends) == 0 || rule.Backends[0].Host != tt.wantBackend {
					t.Errorf("MatchRoute() matched backend %v, want %s", rule.Backends, tt.wantBackend)
				}
			}
		})
	}
}

func TestBuildInternalRoutesCORS(t *testing.T) {
	allowCreds := true
	corsFilter := &gatewayv1.HTTPCORSFilter{
		AllowOrigins:     []gatewayv1.CORSOrigin{"https://www.foo.com", "https://*.bar.com"},
		AllowMethods:     []gatewayv1.HTTPMethodWithWildcard{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []gatewayv1.HTTPHeaderName{"x-header-1", "x-header-2"},
		ExposeHeaders:    []gatewayv1.HTTPHeaderName{"x-header-3"},
		AllowCredentials: &allowCreds,
		MaxAge:           3600,
	}

	hr := &HTTPRouteState{
		HTTPRoute: &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cors-route",
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
						Filters: []gatewayv1.HTTPRouteFilter{
							{
								Type: gatewayv1.HTTPRouteFilterCORS,
								CORS: corsFilter,
							},
						},
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  Ptr(gatewayv1.PathMatchPathPrefix),
									Value: Ptr("/cors"),
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
								Filters: []gatewayv1.HTTPRouteFilter{
									{
										Type: gatewayv1.HTTPRouteFilterCORS,
										CORS: corsFilter,
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
		{Namespace: "default", Name: "backend-svc"}: {
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
				},
			},
		},
	}

	hr.Compile(services, nil, nil, nil)

	if len(hr.Internal.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(hr.Internal.Rules))
	}
	rule := hr.Internal.Rules[0]
	if rule.CORS == nil {
		t.Fatalf("expected rule CORS to be populated, got nil")
	}
	if len(rule.CORS.AllowOrigins) != 2 {
		t.Errorf("expected 2 allow origins, got %d", len(rule.CORS.AllowOrigins))
	}
	if len(rule.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(rule.Backends))
	}
	backend := rule.Backends[0]
	if backend.CORS == nil {
		t.Fatalf("expected backend CORS to be populated, got nil")
	}
}

func TestMatchRouteCORSPreflightMethod(t *testing.T) {
	routes := []InternalRoute{
		{
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
					CORS: &gatewayv1.HTTPCORSFilter{
						AllowOrigins: []gatewayv1.CORSOrigin{"https://example.com"},
					},
					Backends: []InternalBackend{{Host: "post-backend", Port: 80, Weight: 1}},
				},
			},
		},
	}

	// Normal OPTIONS without CORS headers should not match POST rule
	req1, _ := http.NewRequest("OPTIONS", "http://example.com/submit", nil)
	rule, _ := MatchRoute(routes, req1)
	if rule != nil {
		t.Errorf("expected no match for normal OPTIONS, got %v", rule.Backends)
	}

	// Preflight OPTIONS with Access-Control-Request-Method: POST and Origin should match
	req2, _ := http.NewRequest("OPTIONS", "http://example.com/submit", nil)
	req2.Header.Set("Origin", "https://example.com")
	req2.Header.Set("Access-Control-Request-Method", "POST")
	rule, _ = MatchRoute(routes, req2)
	if rule == nil {
		t.Fatalf("expected preflight OPTIONS to match POST rule with CORS, got nil")
	}
	if rule.Backends[0].Host != "post-backend" {
		t.Errorf("expected post-backend, got %s", rule.Backends[0].Host)
	}
}

func TestGateway_DisabledRouteKinds(t *testing.T) {
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	t.Run("default supported kinds omits disabled kinds", func(t *testing.T) {
		st := NewState()
		st.SetControllerName("example.net/gateway-controller")
		st.SetDisabledRouteKinds(map[gatewayv1.Kind]bool{
			gatewayv1.Kind("TCPRoute"): true,
			gatewayv1.Kind("UDPRoute"): true,
		})

		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-defaults"}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-defaults"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "my-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
					{Name: "udp", Port: 9001, Protocol: gatewayv1.UDPProtocolType},
				},
			},
		}

		st.UpsertGatewayClass(gc)
		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
		st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
		outputs := st.Recompute()

		cg := outputs.CompiledGateways[gwKey]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}

		status, ok := outputs.GatewayStatuses[gwKey]
		if !ok {
			t.Fatalf("expected gateway status")
		}

		if len(status.Listeners) != 3 {
			t.Fatalf("expected 3 listener statuses, got %d", len(status.Listeners))
		}

		// HTTP listener: default HTTPRoute is enabled
		lHTTP := status.Listeners[0]
		if len(lHTTP.SupportedKinds) != 1 || lHTTP.SupportedKinds[0].Kind != "HTTPRoute" {
			t.Errorf("expected HTTP listener SupportedKinds=[HTTPRoute], got %+v", lHTTP.SupportedKinds)
		}
		condHTTP := findCondition(lHTTP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condHTTP == nil || condHTTP.Status != metav1.ConditionTrue {
			t.Errorf("expected HTTP listener ResolvedRefs=True, got %+v", condHTTP)
		}

		// TCP listener: default TCPRoute is disabled -> supportedKinds empty, ResolvedRefs=False/InvalidRouteKinds
		lTCP := status.Listeners[1]
		if len(lTCP.SupportedKinds) != 0 {
			t.Errorf("expected TCP listener SupportedKinds to be empty, got %+v", lTCP.SupportedKinds)
		}
		condTCP := findCondition(lTCP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condTCP == nil || condTCP.Status != metav1.ConditionFalse || condTCP.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
			t.Errorf("expected TCP listener ResolvedRefs=False/InvalidRouteKinds, got %+v", condTCP)
		}
		progTCP := findCondition(lTCP.Conditions, string(gatewayv1.ListenerConditionProgrammed))
		if progTCP == nil || progTCP.Status != metav1.ConditionFalse || progTCP.Reason != string(gatewayv1.ListenerReasonInvalid) {
			t.Errorf("expected TCP listener Programmed=False/Invalid, got %+v", progTCP)
		}

		// UDP listener: default UDPRoute is disabled -> supportedKinds empty, ResolvedRefs=False/InvalidRouteKinds
		lUDP := status.Listeners[2]
		if len(lUDP.SupportedKinds) != 0 {
			t.Errorf("expected UDP listener SupportedKinds to be empty, got %+v", lUDP.SupportedKinds)
		}
		condUDP := findCondition(lUDP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condUDP == nil || condUDP.Status != metav1.ConditionFalse || condUDP.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
			t.Errorf("expected UDP listener ResolvedRefs=False/InvalidRouteKinds, got %+v", condUDP)
		}
	})

	t.Run("explicit allowed routes excludes disabled kinds and flags listeners restricted to only disabled kinds", func(t *testing.T) {
		st := NewState()
		st.SetControllerName("example.net/gateway-controller")
		st.SetDisabledRouteKinds(map[gatewayv1.Kind]bool{
			gatewayv1.Kind("GRPCRoute"): true,
			gatewayv1.Kind("TCPRoute"):  true,
		})

		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-explicit"}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-explicit"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "my-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "mixed",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Kinds: []gatewayv1.RouteGroupKind{
								{Kind: "HTTPRoute"},
								{Kind: "GRPCRoute"},
							},
						},
					},
					{
						Name:     "only-disabled-grpc",
						Port:     8080,
						Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Kinds: []gatewayv1.RouteGroupKind{
								{Kind: "GRPCRoute"},
							},
						},
					},
					{
						Name:     "only-disabled-tcp",
						Port:     9000,
						Protocol: gatewayv1.TCPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Kinds: []gatewayv1.RouteGroupKind{
								{Kind: "TCPRoute"},
							},
						},
					},
				},
			},
		}

		st.UpsertGatewayClass(gc)
		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
		st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
		outputs := st.Recompute()

		status, ok := outputs.GatewayStatuses[gwKey]
		if !ok {
			t.Fatalf("expected gateway status")
		}

		// Listener 0: mixed (HTTPRoute + GRPCRoute). SupportedKinds has only HTTPRoute. ResolvedRefs=True.
		lMixed := status.Listeners[0]
		if len(lMixed.SupportedKinds) != 1 || lMixed.SupportedKinds[0].Kind != "HTTPRoute" {
			t.Errorf("expected mixed listener SupportedKinds=[HTTPRoute], got %+v", lMixed.SupportedKinds)
		}
		condMixed := findCondition(lMixed.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condMixed == nil || condMixed.Status != metav1.ConditionTrue {
			t.Errorf("expected mixed listener ResolvedRefs=True, got %+v", condMixed)
		}

		// Listener 1: only disabled GRPCRoute. SupportedKinds empty. ResolvedRefs=False/InvalidRouteKinds.
		lOnlyGRPC := status.Listeners[1]
		if len(lOnlyGRPC.SupportedKinds) != 0 {
			t.Errorf("expected only-disabled-grpc SupportedKinds to be empty, got %+v", lOnlyGRPC.SupportedKinds)
		}
		condGRPC := findCondition(lOnlyGRPC.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condGRPC == nil || condGRPC.Status != metav1.ConditionFalse || condGRPC.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
			t.Errorf("expected only-disabled-grpc ResolvedRefs=False/InvalidRouteKinds, got %+v", condGRPC)
		}

		// Listener 2: only disabled TCPRoute. SupportedKinds empty. ResolvedRefs=False/InvalidRouteKinds.
		lOnlyTCP := status.Listeners[2]
		if len(lOnlyTCP.SupportedKinds) != 0 {
			t.Errorf("expected only-disabled-tcp SupportedKinds to be empty, got %+v", lOnlyTCP.SupportedKinds)
		}
		condTCP := findCondition(lOnlyTCP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if condTCP == nil || condTCP.Status != metav1.ConditionFalse || condTCP.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
			t.Errorf("expected only-disabled-tcp ResolvedRefs=False/InvalidRouteKinds, got %+v", condTCP)
		}
	})
}
