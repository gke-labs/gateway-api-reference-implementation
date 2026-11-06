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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestResolveL4BackendRefs(t *testing.T) {
	for _, routeKind := range []string{"TCPRoute", "UDPRoute"} {
		t.Run(routeKind, func(t *testing.T) {
			t.Run("first failing backend sets ResolvedRefs reason", func(t *testing.T) {
				cmKind := gatewayv1.Kind("ConfigMap")
				port := gatewayv1.PortNumber(8080)

				tests := []struct {
					name           string
					backendRefs    []gatewayv1.BackendRef
					expectedReason gatewayv1.RouteConditionReason
				}{
					{
						name: "invalid kind then not found",
						backendRefs: []gatewayv1.BackendRef{
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Kind: &cmKind,
									Name: "my-cm",
									Port: &port,
								},
							},
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "nonexistent",
									Port: &port,
								},
							},
						},
						expectedReason: gatewayv1.RouteReasonInvalidKind,
					},
					{
						name: "not found then invalid kind",
						backendRefs: []gatewayv1.BackendRef{
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "nonexistent",
									Port: &port,
								},
							},
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Kind: &cmKind,
									Name: "my-cm",
									Port: &port,
								},
							},
						},
						expectedReason: gatewayv1.RouteReasonBackendNotFound,
					},
				}

				for _, tc := range tests {
					t.Run(tc.name, func(t *testing.T) {
						cond := NewCondition(
							string(gatewayv1.RouteConditionResolvedRefs),
							metav1.ConditionTrue,
							string(gatewayv1.RouteReasonResolvedRefs),
							"All references resolved",
							1,
						)

						backends := resolveL4BackendRefs(
							tc.backendRefs,
							"default",
							1,
							routeKind,
							map[types.NamespacedName]*corev1.Service{},
							nil,
							&cond,
						)

						if len(backends) != 0 {
							t.Fatalf("expected 0 backends, got %d", len(backends))
						}
						if cond.Status != metav1.ConditionFalse {
							t.Errorf("expected ResolvedRefs Status False, got %s", cond.Status)
						}
						if cond.Reason != string(tc.expectedReason) {
							t.Errorf("expected ResolvedRefs Reason %s, got %s", tc.expectedReason, cond.Reason)
						}
					})
				}
			})

			t.Run("missing port defaults to 0", func(t *testing.T) {
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: "default"},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Port: 8080},
						},
					},
				}
				services := map[types.NamespacedName]*corev1.Service{
					{Namespace: "default", Name: "backend-svc"}: svc,
				}

				cond := NewCondition(
					string(gatewayv1.RouteConditionResolvedRefs),
					metav1.ConditionTrue,
					string(gatewayv1.RouteReasonResolvedRefs),
					"All references resolved",
					1,
				)

				backends := resolveL4BackendRefs(
					[]gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
							},
						},
					},
					"default",
					1,
					routeKind,
					services,
					nil,
					&cond,
				)

				if cond.Status != metav1.ConditionTrue {
					t.Errorf("expected ResolvedRefs Status True, got %s", cond.Status)
				}
				if len(backends) != 1 {
					t.Fatalf("expected 1 backend, got %d", len(backends))
				}
				expectedTarget := "backend-svc.default.svc.cluster.local:0"
				if backends[0].Target != expectedTarget {
					t.Errorf("expected target %q, got %q", expectedTarget, backends[0].Target)
				}
				if backends[0].Weight != 1 {
					t.Errorf("expected weight 1, got %d", backends[0].Weight)
				}
			})
		})
	}
}
