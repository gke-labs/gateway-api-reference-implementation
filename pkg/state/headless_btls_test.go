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

package state_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func TestHeadlessService_BackendTLSPolicy(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "headless-svc"},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports: []corev1.ServicePort{
				{
					Name:       "btls",
					Port:       443,
					TargetPort: intstr.FromInt(8443),
				},
			},
		},
	}
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-policy"},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "headless-svc",
					},
					SectionName: state.Ptr(gatewayv1.SectionName("btls")),
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:                "abc.example.com",
				WellKnownCACertificates: state.Ptr(gatewayv1.WellKnownCACertificatesSystem),
			},
		},
	}
	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-route"},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "headless-svc",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "headless-svc"}: svc,
	}
	compiled := state.CompileGRPCRoute(route, services, state.ResolveBackendTLSPolicyTargets([]*gatewayv1.BackendTLSPolicy{policy}, services), nil, nil)
	if len(compiled.Rules) == 0 || len(compiled.Rules[0].Backends) == 0 {
		t.Fatalf("expected compiled backends")
	}
	b := compiled.Rules[0].Backends[0]
	if b.TLSConfig == nil {
		t.Fatalf("expected TLSConfig to be set, but was nil (BackendTLSPolicy matching failed)")
	}
	if b.AppProtocol == nil || *b.AppProtocol != "https" {
		t.Errorf("expected AppProtocol https, got %v", b.AppProtocol)
	}
}
