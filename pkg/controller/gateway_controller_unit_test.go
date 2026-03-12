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
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGatewayReconciler_FrontendValidation(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = gatewayv1.AddToScheme(s)

	namespace := "default"
	gwName := "test-gateway"
	gcName := "test-gateway-class"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: gcName,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: ControllerName,
		},
	}

	proxySvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gari-proxy",
			Namespace: "default",
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}

	tests := []struct {
		name              string
		gateway           *gatewayv1.Gateway
		configMaps        []*corev1.ConfigMap
		expectedReason    string
		expectedStatus    metav1.ConditionStatus
		expectedAccepted  metav1.ConditionStatus
		expectedAccReason string
	}{
		{
			name: "valid FrontendValidation",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gwName,
					Namespace: namespace,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(gcName),
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https",
							Protocol: gatewayv1.HTTPSProtocolType,
							Port:     443,
						},
					},
					TLS: &gatewayv1.GatewayTLSConfig{
						Frontend: &gatewayv1.FrontendTLSConfig{
							Default: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{
										{
											Kind: "ConfigMap",
											Name: "ca-bundle",
										},
									},
								},
							},
						},
					},
				},
			},
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-bundle",
						Namespace: namespace,
					},
					Data: map[string]string{
						"ca.crt": "some-cert",
					},
				},
			},
			expectedStatus:    metav1.ConditionTrue,
			expectedReason:    string(gatewayv1.ListenerReasonResolvedRefs),
			expectedAccepted:  metav1.ConditionTrue,
			expectedAccReason: string(gatewayv1.ListenerReasonAccepted),
		},
		{
			name: "invalid FrontendValidation - ConfigMap not found",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gwName,
					Namespace: namespace,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(gcName),
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https",
							Protocol: gatewayv1.HTTPSProtocolType,
							Port:     443,
						},
					},
					TLS: &gatewayv1.GatewayTLSConfig{
						Frontend: &gatewayv1.FrontendTLSConfig{
							Default: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{
										{
											Kind: "ConfigMap",
											Name: "missing-ca",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedStatus:    metav1.ConditionFalse,
			expectedReason:    "InvalidCACertificateRef",
			expectedAccepted:  metav1.ConditionFalse,
			expectedAccReason: "NoValidCACertificate",
		},
		{
			name: "invalid FrontendValidation - unsupported Kind",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gwName,
					Namespace: namespace,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(gcName),
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https",
							Protocol: gatewayv1.HTTPSProtocolType,
							Port:     443,
						},
					},
					TLS: &gatewayv1.GatewayTLSConfig{
						Frontend: &gatewayv1.FrontendTLSConfig{
							Default: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{
										{
											Kind: "Secret",
											Name: "some-secret",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedStatus:    metav1.ConditionFalse,
			expectedReason:    "InvalidCACertificateKind",
			expectedAccepted:  metav1.ConditionFalse,
			expectedAccReason: "NoValidCACertificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{gc, proxySvc, tt.gateway}
			for _, cm := range tt.configMaps {
				objs = append(objs, cm)
			}

			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&gatewayv1.Gateway{}).Build()
			st := state.NewState()
			p := proxy.NewProxy()

			r := &GatewayReconciler{
				Client: cl,
				Scheme: s,
				State:  st,
				Proxy:  p,
			}

			_, err := r.Reconcile(context.Background(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: namespace,
					Name:      gwName,
				},
			})
			if err != nil {
				t.Fatalf("reconcile failed: %v", err)
			}

			updatedGw := &gatewayv1.Gateway{}
			err = cl.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: gwName}, updatedGw)
			if err != nil {
				t.Fatalf("failed to get updated gateway: %v", err)
			}

			if len(updatedGw.Status.Listeners) == 0 {
				t.Fatalf("no listener status found")
			}

			lStatus := updatedGw.Status.Listeners[0]
			var resolvedRefsCond *metav1.Condition
			var acceptedCond *metav1.Condition
			for i := range lStatus.Conditions {
				c := &lStatus.Conditions[i]
				if c.Type == string(gatewayv1.ListenerConditionResolvedRefs) {
					resolvedRefsCond = c
				}
				if c.Type == string(gatewayv1.ListenerConditionAccepted) {
					acceptedCond = c
				}
			}

			if resolvedRefsCond == nil {
				t.Errorf("ResolvedRefs condition not found")
			} else {
				if resolvedRefsCond.Status != tt.expectedStatus {
					t.Errorf("expected status %v, got %v", tt.expectedStatus, resolvedRefsCond.Status)
				}
				if resolvedRefsCond.Reason != tt.expectedReason {
					t.Errorf("expected reason %v, got %v", tt.expectedReason, resolvedRefsCond.Reason)
				}
			}

			if acceptedCond == nil {
				t.Errorf("Accepted condition not found")
			} else {
				if acceptedCond.Status != tt.expectedAccepted {
					t.Errorf("expected accepted status %v, got %v", tt.expectedAccepted, acceptedCond.Status)
				}
				if acceptedCond.Reason != tt.expectedAccReason {
					t.Errorf("expected accepted reason %v, got %v", tt.expectedAccReason, acceptedCond.Reason)
				}
			}
		})
	}
}
