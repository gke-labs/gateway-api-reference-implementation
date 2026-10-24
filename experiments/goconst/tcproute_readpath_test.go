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

package goconst

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func sampleRoute(name, ns string, port int32) *gatewayv1.TCPRoute {
	backendName := gatewayv1.ObjectName("backend-svc")
	ruleName := gatewayv1.SectionName("tcp-rule")
	return &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			Generation:        1,
			CreationTimestamp: metav1.NewTime(time.Unix(1000, 0)),
		},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName("my-gateway"),
						Port: (*gatewayv1.PortNumber)(&port),
					},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					Name: &ruleName,
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: backendName,
							},
						},
					},
				},
			},
		},
	}
}

func sampleService(name, ns, ip string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: ip,
		},
	}
}

func TestConstTCPRouteReadPath_EndToEnd(t *testing.T) {
	st := NewConstState()
	handler := st.InformerEventHandler()

	r1 := sampleRoute("route-1", "default", 8080)
	handler.AddFunc(r1)

	r2 := sampleRoute("route-2", "default", 8081)
	handler.AddFunc(r2)

	// Verify retrieval
	key1 := types.NamespacedName{Namespace: "default", Name: "route-1"}
	s1 := st.GetTCPRoute(key1)
	if s1 == nil || s1.Route == nil {
		t.Fatalf("expected route-1 in state, got nil")
	}

	// Verify pointer preservation
	if s1.Route != WrapConst(r1) {
		t.Fatalf("expected s1.Route to share the informer pointer %p, got %p", r1, s1.Route)
	}

	// Verify sorting
	routes := st.ListSortedRoutes()
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[0].Name != "route-1" || routes[1].Name != "route-2" {
		t.Errorf("unexpected sort order: %s, %s", routes[0].Name, routes[1].Name)
	}

	// Verify compilation
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: sampleService("backend-svc", "default", "10.0.0.42"),
	}

	internalRoute := CompileTCPRoute(s1.Route, services)
	if internalRoute == nil {
		t.Fatalf("expected non-nil internalRoute")
	}
	if len(internalRoute.Rules) != 1 || len(internalRoute.Rules[0].Backends) != 1 {
		t.Fatalf("expected 1 rule with 1 backend, got %+v", internalRoute.Rules)
	}
	if internalRoute.Rules[0].Backends[0].Target != "backend-svc.default.svc.cluster.local:0" {
		t.Errorf("expected backend target backend-svc.default.svc.cluster.local:0, got %s", internalRoute.Rules[0].Backends[0].Target)
	}

	// Verify status generation
	s1.Internal = internalRoute
	compiled := &ConstCompiledTCPRoute{
		Route:      s1.Route,
		RouteState: s1,
		ParentConditions: []metav1.Condition{
			state.NewCondition(string(gatewayv1.RouteConditionAccepted), metav1.ConditionTrue, string(gatewayv1.RouteReasonAccepted), "Accepted", 1),
		},
	}

	status := ComputeDesiredTCPRouteStatus(s1.Route, compiled, "example.com/gateway-controller")
	if len(status.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(status.Parents))
	}
	if len(status.Parents[0].Conditions) != 2 {
		t.Errorf("expected 2 conditions on parent status, got %d", len(status.Parents[0].Conditions))
	}

	// Verify delete
	handler.DeleteFunc(r1)
	if st.GetTCPRoute(key1) != nil {
		t.Errorf("expected route-1 to be deleted from state")
	}
}

func TestConstTCPRouteReadPath_Equivalence(t *testing.T) {
	r := sampleRoute("test-route", "gateway-system", 9000)
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "gateway-system", Name: "backend-svc"}: sampleService("backend-svc", "gateway-system", "10.1.2.3"),
	}

	// Standard GARI compilation from pkg/state
	stdInternal := state.CompileTCPRoute(r, services, nil)

	// Const GARI compilation from experiments/goconst
	constRoute := WrapConst(r)
	constInternal := CompileTCPRoute(constRoute, services)

	// Compare rules and conditions
	if len(stdInternal.Rules) != len(constInternal.Rules) {
		t.Fatalf("rule count mismatch: std=%d, const=%d", len(stdInternal.Rules), len(constInternal.Rules))
	}
	if !reflect.DeepEqual(stdInternal.Rules[0].Backends, constInternal.Rules[0].Backends) {
		t.Errorf("backend targets mismatch:\nstd: %+v\nconst: %+v", stdInternal.Rules[0].Backends, constInternal.Rules[0].Backends)
	}
	if stdInternal.ValidationCondition.Status != constInternal.ValidationCondition.Status {
		t.Errorf("validation condition status mismatch: std=%v, const=%v", stdInternal.ValidationCondition.Status, constInternal.ValidationCondition.Status)
	}
	if stdInternal.ResolvedRefsCondition.Status != constInternal.ResolvedRefsCondition.Status {
		t.Errorf("resolved refs condition status mismatch: std=%v, const=%v", stdInternal.ResolvedRefsCondition.Status, constInternal.ResolvedRefsCondition.Status)
	}
}

func TestConstTCPRouteReadPath_ExplicitClone(t *testing.T) {
	r := sampleRoute("clone-me", "default", 80)
	c := WrapConst(r)

	// Top-level method call requires explicit dereference: (*c).DeepCopy()
	cloned := (*c).DeepCopy()
	if cloned == nil {
		t.Fatalf("expected non-nil clone")
	}
	// Verify that clone is a distinct heap pointer
	if cloned == r {
		t.Errorf("expected clone to be a separate object, got same pointer %p", cloned)
	}

	// Modifying clone does not mutate original const object
	cloned.Spec.Rules = nil
	if len(c.Spec.Rules) != 1 {
		t.Errorf("original const object was mutated after clone modification!")
	}
}
