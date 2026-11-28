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
	"math/rand/v2"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestTCPRoute_AttachAll(t *testing.T) {
	port9001 := gatewayv1.PortNumber(9001)
	port9002 := gatewayv1.PortNumber(9002)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-attach-all", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp-1", Port: port9001, Protocol: gatewayv1.TCPProtocolType},
				{Name: "tcp-2", Port: port9002, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-attach-all", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				// No sectionName, no port -> attaches to all TCP listeners
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-attach-all"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port9001,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9001}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if len(gwStatus.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(gwStatus.Listeners))
	}
	for _, l := range gwStatus.Listeners {
		if l.AttachedRoutes != 1 {
			t.Errorf("listener %s: expected 1 attached route, got %d", l.Name, l.AttachedRoutes)
		}
	}

	routeStatus, ok := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	if !ok {
		t.Fatalf("expected status for route")
	}
	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
	}
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status != metav1.ConditionTrue {
			t.Errorf("expected Accepted=True, got %s", c.Status)
		}
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) && c.Status != metav1.ConditionTrue {
			t.Errorf("expected ResolvedRefs=True, got %s", c.Status)
		}
	}

	// Verify proxy listeners have backends
	if len(outputs.ProxyListeners) != 2 {
		t.Fatalf("expected 2 proxy listeners, got %d", len(outputs.ProxyListeners))
	}
	for _, pl := range outputs.ProxyListeners {
		if len(pl.TCPBackends) != 1 {
			t.Errorf("proxy listener %s: expected 1 TCPBackend, got %d", pl.Name, len(pl.TCPBackends))
		}
	}
}

func TestTCPRoute_SectionName(t *testing.T) {
	port9001 := gatewayv1.PortNumber(9001)
	port9002 := gatewayv1.PortNumber(9002)
	secName1 := gatewayv1.SectionName("tcp-1")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-section", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp-1", Port: port9001, Protocol: gatewayv1.TCPProtocolType},
				{Name: "tcp-2", Port: port9002, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-section", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-section", SectionName: &secName1},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port9001,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9001}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.Name == "tcp-1" && l.AttachedRoutes != 1 {
			t.Errorf("tcp-1: expected 1 attached route, got %d", l.AttachedRoutes)
		}
		if l.Name == "tcp-2" && l.AttachedRoutes != 0 {
			t.Errorf("tcp-2: expected 0 attached routes, got %d", l.AttachedRoutes)
		}
	}

	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
	}
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status != metav1.ConditionTrue {
			t.Errorf("expected Accepted=True, got %s", c.Status)
		}
	}
}

func TestTCPRoute_Port(t *testing.T) {
	port9001 := gatewayv1.PortNumber(9001)
	port9002 := gatewayv1.PortNumber(9002)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-port", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp-1", Port: port9001, Protocol: gatewayv1.TCPProtocolType},
				{Name: "tcp-2", Port: port9002, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-port", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-port", Port: &port9001},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port9001,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9001}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.Name == "tcp-1" && l.AttachedRoutes != 1 {
			t.Errorf("tcp-1: expected 1 attached route, got %d", l.AttachedRoutes)
		}
		if l.Name == "tcp-2" && l.AttachedRoutes != 0 {
			t.Errorf("tcp-2: expected 0 attached routes, got %d", l.AttachedRoutes)
		}
	}
}

func TestTCPRoute_PortAndSectionNameMismatch(t *testing.T) {
	port9001 := gatewayv1.PortNumber(9001)
	port9002 := gatewayv1.PortNumber(9002)
	secName1 := gatewayv1.SectionName("tcp-1") // tcp-1 is on port 9001

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-mismatch", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp-1", Port: port9001, Protocol: gatewayv1.TCPProtocolType},
				{Name: "tcp-2", Port: port9002, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	// sectionName is tcp-1, but port is 9002 -> mismatch
	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-mismatch", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-mismatch", SectionName: &secName1, Port: &port9002},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port9001,
							},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.AttachedRoutes != 0 {
			t.Errorf("listener %s: expected 0 attached routes, got %d", l.Name, l.AttachedRoutes)
		}
	}

	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
	}
	var acceptedCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil {
		t.Fatal("expected Accepted condition")
	}
	if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
		t.Errorf("expected Accepted=False with reason NoMatchingParent, got status=%s, reason=%s", acceptedCond.Status, acceptedCond.Reason)
	}
}

func TestTCPRoute_NonTCPListener(t *testing.T) {
	secNameHTTP := gatewayv1.SectionName("http")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-http", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	port8080 := gatewayv1.PortNumber(8080)
	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-nontcp", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-http", SectionName: &secNameHTTP},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port8080,
							},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var acceptedCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil {
		t.Fatal("expected Accepted condition")
	}
	if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected Accepted=False with reason NotAllowedByListeners, got status=%s, reason=%s", acceptedCond.Status, acceptedCond.Reason)
	}
}

func TestTCPRoute_AllowedRoutesKindExclusion(t *testing.T) {
	secNameTCP := gatewayv1.SectionName("tcp")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-kind-exclude", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tcp",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "HTTPRoute"},
						},
					},
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	port9000 := gatewayv1.PortNumber(9000)
	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-excluded", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-kind-exclude", SectionName: &secNameTCP},
				},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port9000,
							},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var acceptedCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil {
		t.Fatal("expected Accepted condition")
	}
	if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected Accepted=False with reason NotAllowedByListeners, got status=%s, reason=%s", acceptedCond.Status, acceptedCond.Reason)
	}
}

func TestTCPRoute_MissingBackend(t *testing.T) {
	port9000 := gatewayv1.PortNumber(9000)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-missing-backend", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Port: port9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-missing-backend", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-missing-backend"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "nonexistent-svc",
								Port: &port9000,
							},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{}, // empty map, service nonexistent
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}
	if len(outputs.ProxyListeners[0].TCPBackends) != 0 {
		t.Errorf("expected 0 TCPBackends, got %d", len(outputs.ProxyListeners[0].TCPBackends))
	}

	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var acceptedCond, resolvedRefsCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
		}
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsCond = &c
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True, got %+v", acceptedCond)
	}
	if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonBackendNotFound) {
		t.Errorf("expected ResolvedRefs=False with reason BackendNotFound, got %+v", resolvedRefsCond)
	}
}

func TestTCPRoute_CrossNamespace(t *testing.T) {
	port9000 := gatewayv1.PortNumber(9000)
	backendNs := gatewayv1.Namespace("backend-ns")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-xns", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Port: port9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-xns", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-xns"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name:      "remote-svc",
								Namespace: &backendNs,
								Port:      &port9000,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "backend-ns", Name: "remote-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "remote-svc", Namespace: "backend-ns"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9000}},
			},
		},
	}

	t.Run("without reference grant", func(t *testing.T) {
		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			TCPRoutes:      []*gatewayv1.TCPRoute{route},
			Services:       services,
			ControllerName: "example.net/gateway-controller",
		}

		outputs := ComputeOutputs(inputs)
		routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
		var resolvedRefsCond *metav1.Condition
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
				break
			}
		}
		if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonRefNotPermitted) {
			t.Errorf("expected ResolvedRefs=False with reason RefNotPermitted, got %+v", resolvedRefsCond)
		}
		if len(outputs.ProxyListeners[0].TCPBackends) != 0 {
			t.Errorf("expected 0 TCPBackends, got %d", len(outputs.ProxyListeners[0].TCPBackends))
		}
	})

	t.Run("with reference grant", func(t *testing.T) {
		refGrant := &gatewayv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tcp", Namespace: "backend-ns"},
			Spec: gatewayv1beta1.ReferenceGrantSpec{
				From: []gatewayv1beta1.ReferenceGrantFrom{
					{
						Group:     gatewayv1.GroupName,
						Kind:      "TCPRoute",
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
		}

		inputs := ModelInputs{
			Gateways:        []*gatewayv1.Gateway{gw},
			GatewayClasses:  []*gatewayv1.GatewayClass{gc},
			TCPRoutes:       []*gatewayv1.TCPRoute{route},
			Services:        services,
			ReferenceGrants: map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{{Namespace: "backend-ns", Name: "allow-tcp"}: refGrant},
			ControllerName:  "example.net/gateway-controller",
		}

		outputs := ComputeOutputs(inputs)
		routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
		var resolvedRefsCond *metav1.Condition
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
				break
			}
		}
		if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionTrue || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonResolvedRefs) {
			t.Errorf("expected ResolvedRefs=True with reason ResolvedRefs, got %+v", resolvedRefsCond)
		}
		if len(outputs.ProxyListeners[0].TCPBackends) != 1 {
			t.Fatalf("expected 1 TCPBackend, got %d", len(outputs.ProxyListeners[0].TCPBackends))
		}
		if outputs.ProxyListeners[0].TCPBackends[0].Target != "remote-svc.backend-ns.svc.cluster.local:9000" {
			t.Errorf("unexpected target: %s", outputs.ProxyListeners[0].TCPBackends[0].Target)
		}
	})
}

func TestTCPRoute_WeightZeroPreserved(t *testing.T) {
	port9000 := gatewayv1.PortNumber(9000)
	weight10 := int32(10)
	weight0 := int32(0)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-weight", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Port: port9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-weight", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-weight"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-active",
								Port: &port9000,
							},
							Weight: &weight10,
						},
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-canary",
								Port: &port9000,
							},
							Weight: &weight0,
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "svc-active"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-active", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9000}},
			},
		},
		{Namespace: "default", Name: "svc-canary"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-canary", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9000}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}
	backends := outputs.ProxyListeners[0].TCPBackends
	if len(backends) != 2 {
		t.Fatalf("expected 2 TCPBackends, got %d", len(backends))
	}
	if backends[0].Weight != 10 {
		t.Errorf("expected weight 10, got %d", backends[0].Weight)
	}
	if backends[1].Weight != 0 {
		t.Errorf("expected weight 0 preserved, got %d", backends[1].Weight)
	}

	// Verify that selection always picks weight 10, never weight 0
	for i := 0; i < 50; i++ {
		target, ok := outputs.ProxyListeners[0].SelectTCPBackend()
		if !ok || target != "svc-active.default.svc.cluster.local:9000" {
			t.Errorf("unexpected backend selection: target=%s, ok=%v", target, ok)
		}
	}
}

func TestTCPRoute_TwoRoutesOnOneListener(t *testing.T) {
	port9000 := gatewayv1.PortNumber(9000)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-two-routes", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Port: port9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route1 := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-1", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-two-routes"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-1",
								Port: &port9000,
							},
						},
					},
				},
			},
		},
	}

	route2 := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-2", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-two-routes"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-2",
								Port: &port9000,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "svc-1"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9000}},
			},
		},
		{Namespace: "default", Name: "svc-2"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-2", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 9000}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route1, route2},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 2 {
		t.Errorf("expected 2 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	for _, rName := range []string{"route-1", "route-2"} {
		routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: rName}]
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status != metav1.ConditionTrue {
				t.Errorf("%s: expected Accepted=True, got %s", rName, c.Status)
			}
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) && c.Status != metav1.ConditionTrue {
				t.Errorf("%s: expected ResolvedRefs=True, got %s", rName, c.Status)
			}
		}
	}

	// In Gateway API conformance (TCPRouteMultipleRoutesAttachment), both routes are
	// accepted and AttachedRoutes is 2, but only the oldest route is bound to the listener
	// for traffic routing.
	if len(outputs.ProxyListeners[0].TCPBackends) != 1 {
		t.Fatalf("expected 1 TCPBackend on listener (from oldest route), got %d", len(outputs.ProxyListeners[0].TCPBackends))
	}
	if outputs.ProxyListeners[0].TCPBackends[0].Target != "svc-1.default.svc.cluster.local:9000" {
		t.Errorf("expected target from route-1, got %s", outputs.ProxyListeners[0].TCPBackends[0].Target)
	}
}

func TestTCPRoute_InvalidKind(t *testing.T) {
	port9000 := gatewayv1.PortNumber(9000)
	cmKind := gatewayv1.Kind("ConfigMap")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-invalid-kind", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Port: port9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-invalid-kind", Namespace: "default"},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-invalid-kind"}},
			},
			Rules: []gatewayv1.TCPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Kind: &cmKind,
								Name: "my-cm",
								Port: &port9000,
							},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TCPRoutes:      []*gatewayv1.TCPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	routeStatus := outputs.TCPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var resolvedRefsCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsCond = &c
			break
		}
	}
	if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonInvalidKind) {
		t.Errorf("expected ResolvedRefs=False with reason InvalidKind, got %+v", resolvedRefsCond)
	}
}

func TestPickTCPBackend(t *testing.T) {
	// Empty slice
	if _, ok := PickTCPBackend(nil); ok {
		t.Errorf("expected ok=false for nil backends")
	}
	if _, ok := PickTCPBackend([]InternalTCPBackend{}); ok {
		t.Errorf("expected ok=false for empty backends")
	}

	// All zero weights
	zeroBackends := []InternalTCPBackend{
		{Target: "target1", Weight: 0},
		{Target: "target2", Weight: 0},
	}
	if _, ok := PickTCPBackend(zeroBackends); ok {
		t.Errorf("expected ok=false for all zero weights")
	}

	// Single backend
	singleBackend := []InternalTCPBackend{{Target: "target1", Weight: 1}}
	if target, ok := PickTCPBackend(singleBackend); !ok || target != "target1" {
		t.Errorf("expected target1, got target=%s, ok=%v", target, ok)
	}

	// InternalListener methods
	lis := &InternalListener{
		TCPBackends: singleBackend,
	}
	if target, ok := lis.SelectTCPBackend(); !ok || target != "target1" {
		t.Errorf("expected target1, got target=%s, ok=%v", target, ok)
	}

	r := rand.New(rand.NewPCG(42, 42))
	if target, ok := lis.SelectTCPBackendWithRand(r); !ok || target != "target1" {
		t.Errorf("expected target1 with rand, got target=%s, ok=%v", target, ok)
	}

	var nilLis *InternalListener
	if _, ok := nilLis.SelectTCPBackend(); ok {
		t.Errorf("expected ok=false on nil listener")
	}
}

func TestTCPListener_ConflictReservedPorts(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-reserved-conflict",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tcp-8080",
					Port:     8080,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-8443",
					Port:     8443,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-8999",
					Port:     8999,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-8000",
					Port:     8000,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-8081",
					Port:     8081,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-valid",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		GatewayAddresses: map[types.NamespacedName][]gatewayv1.GatewayStatusAddress{
			{Namespace: "default", Name: gw.Name}: {{Value: "192.0.2.1"}},
		},
		ControllerName: "test-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]

	listenerStatusMap := make(map[gatewayv1.SectionName]gatewayv1.ListenerStatus)
	for _, ls := range gwStatus.Listeners {
		listenerStatusMap[ls.Name] = ls
	}

	for _, name := range []gatewayv1.SectionName{"tcp-8080", "tcp-8443", "tcp-8999"} {
		ls, ok := listenerStatusMap[name]
		if !ok {
			t.Fatalf("listener %s status not found", name)
		}
		var confCond, acceptedCond, progCond *metav1.Condition
		for _, c := range ls.Conditions {
			switch c.Type {
			case string(gatewayv1.ListenerConditionConflicted):
				confCond = &c
			case string(gatewayv1.ListenerConditionAccepted):
				acceptedCond = &c
			case string(gatewayv1.ListenerConditionProgrammed):
				progCond = &c
			}
		}
		if confCond == nil || confCond.Status != metav1.ConditionTrue || confCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
			t.Errorf("listener %s expected Conflicted=True PortUnavailable, got %+v", name, confCond)
		}
		if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
			t.Errorf("listener %s expected Accepted=False PortUnavailable, got %+v", name, acceptedCond)
		}
		if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
			t.Errorf("listener %s expected Programmed=False PortUnavailable, got %+v", name, progCond)
		}
	}

	// Unreserved ports (8000, 8081, 9000) must be accepted and programmed
	for _, name := range []gatewayv1.SectionName{"tcp-8000", "tcp-8081", "tcp-valid"} {
		ls, ok := listenerStatusMap[name]
		if !ok {
			t.Fatalf("listener %s status not found", name)
		}
		var validAccepted, validProg *metav1.Condition
		for _, c := range ls.Conditions {
			switch c.Type {
			case string(gatewayv1.ListenerConditionAccepted):
				validAccepted = &c
			case string(gatewayv1.ListenerConditionProgrammed):
				validProg = &c
			}
		}
		if validAccepted == nil || validAccepted.Status != metav1.ConditionTrue {
			t.Errorf("listener %s expected Accepted=True, got %+v", name, validAccepted)
		}
		if validProg == nil || validProg.Status != metav1.ConditionTrue {
			t.Errorf("listener %s expected Programmed=True, got %+v", name, validProg)
		}
	}

	// In outputs.ProxyListeners, all 3 unreserved listeners should appear
	if len(outputs.ProxyListeners) != 3 {
		t.Errorf("expected 3 proxy listeners on unreserved ports, got %+v", outputs.ProxyListeners)
	}
}

func TestTCPListener_AllInOneModeConflict(t *testing.T) {
	now := metav1.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw1-older",
			Namespace:         "default",
			CreationTimestamp: olderTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tcp-shared",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
			},
		},
	}

	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw2-newer",
			Namespace:         "default",
			CreationTimestamp: newerTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tcp-shared",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	gatewayAddresses := map[types.NamespacedName][]gatewayv1.GatewayStatusAddress{
		{Namespace: "default", Name: gw1.Name}: {{Value: "192.0.2.1"}},
		{Namespace: "default", Name: gw2.Name}: {{Value: "192.0.2.2"}},
	}

	// 1. With AllInOneMode: true
	inputsAllInOne := ModelInputs{
		Gateways:         []*gatewayv1.Gateway{gw2, gw1}, // pass in arbitrary order
		GatewayClasses:   []*gatewayv1.GatewayClass{gc},
		GatewayAddresses: gatewayAddresses,
		ControllerName:   "test-controller",
		AllInOneMode:     true,
	}

	outputsAllInOne := ComputeOutputs(inputsAllInOne)

	// First gateway (older) wins: Programmed=True
	gw1Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw1.Name}]
	var gw1ProgCond *metav1.Condition
	for _, c := range gw1Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw1ProgCond = &c
			break
		}
	}
	if gw1ProgCond == nil || gw1ProgCond.Status != metav1.ConditionTrue {
		t.Errorf("gw1 (older) expected Programmed=True, got %+v", gw1ProgCond)
	}

	// Second gateway (newer) loses: Programmed=False, reason PortUnavailable
	gw2Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2ProgCond *metav1.Condition
	for _, c := range gw2Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2ProgCond = &c
			break
		}
	}
	if gw2ProgCond == nil || gw2ProgCond.Status != metav1.ConditionFalse || gw2ProgCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
		t.Errorf("gw2 (newer) expected Programmed=False PortUnavailable, got %+v", gw2ProgCond)
	}

	// Proxy listeners in all-in-one should only include the first (gw1) listener
	if len(outputsAllInOne.ProxyListeners) != 1 || outputsAllInOne.ProxyListeners[0].GatewayName.String() != "default/gw1-older" {
		t.Errorf("expected only gw1 proxy listener, got %+v", outputsAllInOne.ProxyListeners)
	}

	// 2. With AllInOneMode: false (singlepod mode)
	inputsSinglePod := ModelInputs{
		Gateways:         []*gatewayv1.Gateway{gw1, gw2},
		GatewayClasses:   []*gatewayv1.GatewayClass{gc},
		GatewayAddresses: gatewayAddresses,
		ControllerName:   "test-controller",
		AllInOneMode:     false,
	}

	outputsSinglePod := ComputeOutputs(inputsSinglePod)
	gw2SinglePodStatus := outputsSinglePod.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2SinglePodProg *metav1.Condition
	for _, c := range gw2SinglePodStatus.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2SinglePodProg = &c
			break
		}
	}
	if gw2SinglePodProg == nil || gw2SinglePodProg.Status != metav1.ConditionTrue {
		t.Errorf("in singlepod mode, gw2 expected Programmed=True, got %+v", gw2SinglePodProg)
	}
}
