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

func TestUDPRoute_AttachAll(t *testing.T) {
	port5301 := gatewayv1.PortNumber(5301)
	port5302 := gatewayv1.PortNumber(5302)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-attach-all", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp-1", Port: port5301, Protocol: gatewayv1.UDPProtocolType},
				{Name: "udp-2", Port: port5302, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-attach-all", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				// No sectionName, no port -> attaches to all UDP listeners
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-attach-all"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port5301,
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
				Ports: []corev1.ServicePort{{Port: 5301}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
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

	routeStatus, ok := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
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
		if len(pl.UDPBackends) != 1 {
			t.Errorf("proxy listener %s: expected 1 UDPBackend, got %d", pl.Name, len(pl.UDPBackends))
		}
	}
}

func TestUDPRoute_SectionName(t *testing.T) {
	port5301 := gatewayv1.PortNumber(5301)
	port5302 := gatewayv1.PortNumber(5302)
	secName1 := gatewayv1.SectionName("udp-1")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-section-name", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp-1", Port: port5301, Protocol: gatewayv1.UDPProtocolType},
				{Name: "udp-2", Port: port5302, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-section-name", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw-section-name",
						SectionName: &secName1,
					},
				},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port5301,
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
				Ports: []corev1.ServicePort{{Port: 5301}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.Name == "udp-1" && l.AttachedRoutes != 1 {
			t.Errorf("listener udp-1: expected 1 attached route, got %d", l.AttachedRoutes)
		}
		if l.Name == "udp-2" && l.AttachedRoutes != 0 {
			t.Errorf("listener udp-2: expected 0 attached routes, got %d", l.AttachedRoutes)
		}
	}

	for _, pl := range outputs.ProxyListeners {
		if pl.Name == "default/gw-section-name/udp-1" && len(pl.UDPBackends) != 1 {
			t.Errorf("expected 1 UDPBackend on udp-1, got %d", len(pl.UDPBackends))
		}
		if pl.Name == "default/gw-section-name/udp-2" && len(pl.UDPBackends) != 0 {
			t.Errorf("expected 0 UDPBackends on udp-2, got %d", len(pl.UDPBackends))
		}
	}
}

func TestUDPRoute_Port(t *testing.T) {
	port5301 := gatewayv1.PortNumber(5301)
	port5302 := gatewayv1.PortNumber(5302)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-port", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp-1", Port: port5301, Protocol: gatewayv1.UDPProtocolType},
				{Name: "udp-2", Port: port5302, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-port", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "gw-port",
						Port: &port5302,
					},
				},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port5302,
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
				Ports: []corev1.ServicePort{{Port: 5302}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.Name == "udp-1" && l.AttachedRoutes != 0 {
			t.Errorf("listener udp-1: expected 0 attached routes, got %d", l.AttachedRoutes)
		}
		if l.Name == "udp-2" && l.AttachedRoutes != 1 {
			t.Errorf("listener udp-2: expected 1 attached route, got %d", l.AttachedRoutes)
		}
	}
}

func TestUDPRoute_PortAndSectionNameMismatch(t *testing.T) {
	port5301 := gatewayv1.PortNumber(5301)
	port5302 := gatewayv1.PortNumber(5302)
	secName1 := gatewayv1.SectionName("udp-1")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-mismatch", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp-1", Port: port5301, Protocol: gatewayv1.UDPProtocolType},
				{Name: "udp-2", Port: port5302, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	// SectionName selects udp-1 (port 5301), but Port specifies 5302 -> mismatch -> no matching parent
	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-mismatch", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw-mismatch",
						SectionName: &secName1,
						Port:        &port5302,
					},
				},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
								Port: &port5301,
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
				Ports: []corev1.ServicePort{{Port: 5301}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	for _, l := range gwStatus.Listeners {
		if l.AttachedRoutes != 0 {
			t.Errorf("listener %s: expected 0 attached routes, got %d", l.Name, l.AttachedRoutes)
		}
	}

	routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
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
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
		t.Errorf("expected Accepted=False with reason NoMatchingParent, got %+v", acceptedCond)
	}
}

func TestUDPRoute_NonUDPListener(t *testing.T) {
	secNameHTTP := gatewayv1.SectionName("http")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-non-udp", Namespace: "default"},
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

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-non-udp", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw-non-udp",
						SectionName: &secNameHTTP,
					},
				},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
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
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes on HTTP listener, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var acceptedCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected Accepted=False with reason NotAllowedByListeners, got %+v", acceptedCond)
	}
}

func TestUDPRoute_AllowedRoutesKindExclusion(t *testing.T) {
	secNameUDP := gatewayv1.SectionName("udp")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-kind-exclusion", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "udp",
					Port:     5301,
					Protocol: gatewayv1.UDPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TCPRoute"}, // Only TCPRoute allowed, excluding UDPRoute
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

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-excluded", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw-kind-exclusion",
						SectionName: &secNameUDP,
					},
				},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-svc",
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
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	var acceptedCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected Accepted=False with reason NotAllowedByListeners, got %+v", acceptedCond)
	}
}

func TestUDPRoute_MissingBackend(t *testing.T) {
	port5300 := gatewayv1.PortNumber(5300)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-missing-backend", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp", Port: port5300, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-missing-backend", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-missing-backend"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "nonexistent-svc",
								Port: &port5300,
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
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       map[types.NamespacedName]*corev1.Service{},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]

	var resolvedRefsCond *metav1.Condition
	for _, c := range routeStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsCond = &c
			break
		}
	}
	if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonBackendNotFound) {
		t.Errorf("expected ResolvedRefs=False with reason BackendNotFound, got %+v", resolvedRefsCond)
	}
}

func TestUDPRoute_CrossNamespace(t *testing.T) {
	port5300 := gatewayv1.PortNumber(5300)
	backendNs := gatewayv1.Namespace("backend-ns")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-cross-ns", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp", Port: port5300, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-cross-ns", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-cross-ns"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name:      "remote-svc",
								Namespace: &backendNs,
								Port:      &port5300,
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
				Ports: []corev1.ServicePort{{Port: 5300}},
			},
		},
	}

	// 1. Without ReferenceGrant -> RefNotPermitted
	inputsNoGrant := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputsNoGrant := ComputeOutputs(inputsNoGrant)
	routeStatusNoGrant := outputsNoGrant.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]

	var resolvedRefsCond *metav1.Condition
	for _, c := range routeStatusNoGrant.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsCond = &c
			break
		}
	}
	if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.RouteReasonRefNotPermitted) {
		t.Errorf("expected ResolvedRefs=False with reason RefNotPermitted, got %+v", resolvedRefsCond)
	}

	// 2. With ReferenceGrant -> ResolvedRefs=True
	refGrant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "grant-udp", Namespace: "backend-ns"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "UDPRoute",
					Namespace: "default",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Kind: "Service",
				},
			},
		},
	}

	inputsWithGrant := ModelInputs{
		Gateways:        []*gatewayv1.Gateway{gw},
		GatewayClasses:  []*gatewayv1.GatewayClass{gc},
		UDPRoutes:       []*gatewayv1.UDPRoute{route},
		Services:        services,
		ReferenceGrants: map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{{Namespace: "backend-ns", Name: "grant-udp"}: refGrant},
		ControllerName:  "example.net/gateway-controller",
	}

	outputsWithGrant := ComputeOutputs(inputsWithGrant)
	routeStatusWithGrant := outputsWithGrant.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]

	var resolvedRefsWithGrant *metav1.Condition
	for _, c := range routeStatusWithGrant.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsWithGrant = &c
			break
		}
	}
	if resolvedRefsWithGrant == nil || resolvedRefsWithGrant.Status != metav1.ConditionTrue {
		t.Errorf("expected ResolvedRefs=True with ReferenceGrant, got %+v", resolvedRefsWithGrant)
	}
}

func TestUDPRoute_WeightZeroPreserved(t *testing.T) {
	port5300 := gatewayv1.PortNumber(5300)
	weight10 := int32(10)
	weight0 := int32(0)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-weight", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp", Port: port5300, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-weight", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-weight"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-active",
								Port: &port5300,
							},
							Weight: &weight10,
						},
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-standby",
								Port: &port5300,
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
				Ports: []corev1.ServicePort{{Port: 5300}},
			},
		},
		{Namespace: "default", Name: "svc-standby"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-standby", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 5300}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}
	backends := outputs.ProxyListeners[0].UDPBackends
	if len(backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(backends))
	}
	if backends[0].Weight != 10 {
		t.Errorf("expected weight 10, got %d", backends[0].Weight)
	}
	if backends[1].Weight != 0 {
		t.Errorf("expected weight 0 preserved, got %d", backends[1].Weight)
	}

	// Verify that selection always picks weight 10, never weight 0
	for i := 0; i < 50; i++ {
		target, ok := outputs.ProxyListeners[0].SelectUDPBackend()
		if !ok || target != "svc-active.default.svc.cluster.local:5300" {
			t.Errorf("unexpected backend selection: target=%s, ok=%v", target, ok)
		}
	}
}

func TestUDPRoute_TwoRoutesOnOneListener(t *testing.T) {
	port5300 := gatewayv1.PortNumber(5300)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-two-routes", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp", Port: port5300, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route1 := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-1", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-two-routes"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-1",
								Port: &port5300,
							},
						},
					},
				},
			},
		},
	}

	route2 := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-2", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-two-routes"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "svc-2",
								Port: &port5300,
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
				Ports: []corev1.ServicePort{{Port: 5300}},
			},
		},
		{Namespace: "default", Name: "svc-2"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "svc-2", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 5300}},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		UDPRoutes:      []*gatewayv1.UDPRoute{route1, route2},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if gwStatus.Listeners[0].AttachedRoutes != 2 {
		t.Errorf("expected 2 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	for _, rName := range []string{"route-1", "route-2"} {
		routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: rName}]
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status != metav1.ConditionTrue {
				t.Errorf("%s: expected Accepted=True, got %s", rName, c.Status)
			}
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) && c.Status != metav1.ConditionTrue {
				t.Errorf("%s: expected ResolvedRefs=True, got %s", rName, c.Status)
			}
		}
	}

	// Both routes are accepted and AttachedRoutes is 2, but only the oldest route is bound to the listener
	// for traffic routing.
	if len(outputs.ProxyListeners[0].UDPBackends) != 1 {
		t.Fatalf("expected 1 UDPBackend on listener (from oldest route), got %d", len(outputs.ProxyListeners[0].UDPBackends))
	}
	if outputs.ProxyListeners[0].UDPBackends[0].Target != "svc-1.default.svc.cluster.local:5300" {
		t.Errorf("expected backend from route-1 (oldest), got %s", outputs.ProxyListeners[0].UDPBackends[0].Target)
	}
}

func TestUDPRoute_InvalidKind(t *testing.T) {
	port5300 := gatewayv1.PortNumber(5300)
	cmKind := gatewayv1.Kind("ConfigMap")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-invalid-kind", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "udp", Port: port5300, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-invalid-kind", Namespace: "default"},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-invalid-kind"}},
			},
			Rules: []gatewayv1.UDPRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "my-cm",
								Kind: &cmKind,
								Port: &port5300,
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
		UDPRoutes:      []*gatewayv1.UDPRoute{route},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	routeStatus := outputs.UDPRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]

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

func TestSelectUDPBackend(t *testing.T) {
	singleBackend := []InternalUDPBackend{{Target: "dns1.default.svc.cluster.local:53", Weight: 1}}

	lis := &InternalListener{
		UDPBackends: singleBackend,
	}
	if target, ok := lis.SelectUDPBackend(); !ok || target != "dns1.default.svc.cluster.local:53" {
		t.Errorf("expected dns1, got target=%s, ok=%v", target, ok)
	}

	r := rand.New(rand.NewPCG(42, 42))
	if target, ok := lis.SelectUDPBackendWithRand(r); !ok || target != "dns1.default.svc.cluster.local:53" {
		t.Errorf("expected dns1 with rand, got target=%s, ok=%v", target, ok)
	}

	var nilLis *InternalListener
	if _, ok := nilLis.SelectUDPBackend(); ok {
		t.Errorf("expected ok=false on nil listener")
	}
}

func TestUDPPort8443Conflict(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-udp-reserved",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "udp-8080",
					Port:     8080,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-8443",
					Port:     8443,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-8999",
					Port:     8999,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-8000",
					Port:     8000,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-8081",
					Port:     8081,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-valid",
					Port:     9000,
					Protocol: gatewayv1.UDPProtocolType,
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

	for _, name := range []gatewayv1.SectionName{"udp-8080", "udp-8443", "udp-8999"} {
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
	for _, name := range []gatewayv1.SectionName{"udp-8000", "udp-8081", "udp-valid"} {
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
}

func TestUDPListener_AllInOneModeConflict(t *testing.T) {
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
					Name:     "udp-shared",
					Port:     5300,
					Protocol: gatewayv1.UDPProtocolType,
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
					Name:     "udp-shared",
					Port:     5300,
					Protocol: gatewayv1.UDPProtocolType,
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
		Gateways:         []*gatewayv1.Gateway{gw2, gw1},
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
