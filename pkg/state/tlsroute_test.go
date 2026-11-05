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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestTLSRoute_SupportedKinds_InvalidRouteKinds(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute-passthrough-supported-kind",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls-passthrough",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TCPRoute"},
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &passthroughMode,
					},
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus, ok := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if !ok {
		t.Fatalf("expected status for gateway %s", gw.Name)
	}

	if len(gwStatus.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(gwStatus.Listeners))
	}
	lStatus := gwStatus.Listeners[0]
	if string(lStatus.Name) != "tls-passthrough" {
		t.Errorf("expected listener name tls-passthrough, got %s", lStatus.Name)
	}

	// SupportedKinds must report only TLSRoute
	if len(lStatus.SupportedKinds) != 1 {
		t.Fatalf("expected 1 supported kind, got %d", len(lStatus.SupportedKinds))
	}
	if lStatus.SupportedKinds[0].Kind != "TLSRoute" || ValueOf(lStatus.SupportedKinds[0].Group) != gatewayv1.GroupName {
		t.Errorf("expected supported kind TLSRoute with group %s, got %+v", gatewayv1.GroupName, lStatus.SupportedKinds[0])
	}

	if lStatus.AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes, got %d", lStatus.AttachedRoutes)
	}

	// ResolvedRefs must be ConditionFalse with reason InvalidRouteKinds
	var resolvedRefsCond *metav1.Condition
	for _, c := range lStatus.Conditions {
		if c.Type == string(gatewayv1.ListenerConditionResolvedRefs) {
			resolvedRefsCond = &c
			break
		}
	}
	if resolvedRefsCond == nil {
		t.Fatal("expected ResolvedRefs condition on listener status")
	}
	if resolvedRefsCond.Status != metav1.ConditionFalse {
		t.Errorf("expected ResolvedRefs status False, got %s", resolvedRefsCond.Status)
	}
	if resolvedRefsCond.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
		t.Errorf("expected ResolvedRefs reason InvalidRouteKinds, got %s", resolvedRefsCond.Reason)
	}
}

func TestTLSRoute_AttachedRoutes(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	hostname := gatewayv1.Hostname("*.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostname,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &passthroughMode,
					},
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	port8443 := gatewayv1.PortNumber(8443)
	route1 := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route-1",
			Namespace: "default",
		},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"abc.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-1",
								Port: &port8443,
							},
						},
					},
				},
			},
		},
	}

	route2 := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route-2",
			Namespace: "default",
		},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"def.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend-2",
								Port: &port8443,
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
		TLSRoutes:      []*gatewayv1.TLSRoute{route1, route2},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
	if len(gwStatus.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(gwStatus.Listeners))
	}
	if gwStatus.Listeners[0].AttachedRoutes != 2 {
		t.Errorf("expected 2 attached routes, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}

	// Verify both TLSRoutes have Accepted=True and ResolvedRefs=True
	for _, r := range []*gatewayv1.TLSRoute{route1, route2} {
		rStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: r.Name}]
		if !ok {
			t.Fatalf("expected status for route %s", r.Name)
		}
		if len(rStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status for route %s, got %d", r.Name, len(rStatus.Parents))
		}
		pStatus := rStatus.Parents[0]
		var acceptedCond, resolvedRefsCond *metav1.Condition
		for _, c := range pStatus.Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) {
				acceptedCond = &c
			}
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
			}
		}
		if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
			t.Errorf("route %s: expected Accepted=True, got %+v", r.Name, acceptedCond)
		}
		if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionTrue {
			t.Errorf("route %s: expected ResolvedRefs=True, got %+v", r.Name, resolvedRefsCond)
		}
	}
}

func TestTLSRoute_NoMatchingListenerHostname(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	gwHostname := gatewayv1.Hostname("foo.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &gwHostname,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &passthroughMode,
					},
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	port8443 := gatewayv1.PortNumber(8443)
	route := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route-bar",
			Namespace: "default",
		},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"bar.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend",
								Port: &port8443,
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
		TLSRoutes:      []*gatewayv1.TLSRoute{route},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	rStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: route.Name}]
	if !ok {
		t.Fatalf("expected status for route %s", route.Name)
	}
	if len(rStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(rStatus.Parents))
	}
	pStatus := rStatus.Parents[0]

	var acceptedCond *metav1.Condition
	for _, c := range pStatus.Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil {
		t.Fatal("expected Accepted condition on route parent status")
	}
	if acceptedCond.Status != metav1.ConditionFalse {
		t.Errorf("expected Accepted status False, got %s", acceptedCond.Status)
	}
	if acceptedCond.Reason != string(gatewayv1.RouteReasonNoMatchingListenerHostname) {
		t.Errorf("expected Accepted reason NoMatchingListenerHostname, got %s", acceptedCond.Reason)
	}
}

func TestTLSRoute_HostnameIntersection_SelectedBackendMatrix(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	port443 := gatewayv1.PortNumber(443)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "infra", Name: "tls-backend"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "tls-backend", Namespace: "infra"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
		{Namespace: "infra", Name: "tls-backend-2"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "tls-backend-2", Namespace: "infra"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
	}

	// Matrix of tests corresponding to the four listener hostname shapes
	tests := []struct {
		name             string
		listenerHostname *gatewayv1.Hostname
		routes           []*gatewayv1.TLSRoute
		queries          map[string]string // sni -> expected selected backend (empty string = no backend)
	}{
		{
			name:             "Shape 1: Exact listener hostname (abc.example.com)",
			listenerHostname: Ptr(gatewayv1.Hostname("abc.example.com")),
			routes: []*gatewayv1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-wc", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"*.example.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
			},
			queries: map[string]string{
				"abc.example.com":   "tls-backend.infra.svc.cluster.local:443",
				"other.example.com": "", // listener doesn't match other.example.com
				"non.matching.com":  "",
			},
		},
		{
			name:             "Shape 2: Specific wildcard listener hostname (*.example.com)",
			listenerHostname: Ptr(gatewayv1.Hostname("*.example.com")),
			routes: []*gatewayv1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-exact", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"abc.example.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-broad-wc", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"*.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend-2",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
			},
			queries: map[string]string{
				"abc.example.com":   "tls-backend.infra.svc.cluster.local:443",   // exact match wins over wildcard
				"other.example.com": "tls-backend-2.infra.svc.cluster.local:443", // matches *.example.com intersection
				"non.matching.com":  "",                                          // listener doesn't match
			},
		},
		{
			name:             "Shape 3: Less specific wildcard listener hostname (*.com)",
			listenerHostname: Ptr(gatewayv1.Hostname("*.com")),
			routes: []*gatewayv1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-exact", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"abc.example.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-narrow-wc", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"*.example.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend-2",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
			},
			queries: map[string]string{
				"abc.example.com":   "tls-backend.infra.svc.cluster.local:443",   // exact match wins
				"other.example.com": "tls-backend-2.infra.svc.cluster.local:443", // matches *.example.com
				"non.matching.com":  "",                                          // no route covers non.matching.com
			},
		},
		{
			name:             "Shape 4: Empty listener hostname",
			listenerHostname: nil,
			routes: []*gatewayv1.TLSRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-exact", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"abc.example.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-wc-com", Namespace: "infra"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
						},
						Hostnames: []gatewayv1.Hostname{"*.com"},
						Rules: []gatewayv1.TLSRouteRule{
							{
								BackendRefs: []gatewayv1.BackendRef{
									{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "tls-backend-2",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
			},
			queries: map[string]string{
				"abc.example.com":   "tls-backend.infra.svc.cluster.local:443",   // exact match
				"other.example.com": "tls-backend-2.infra.svc.cluster.local:443", // matches *.com
				"non.matching.org":  "",                                          // no route covers .org
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gw",
					Namespace: "infra",
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "ref-class",
					Listeners: []gatewayv1.Listener{
						{
							Name:     "tls",
							Port:     443,
							Protocol: gatewayv1.TLSProtocolType,
							Hostname: tc.listenerHostname,
							TLS: &gatewayv1.ListenerTLSConfig{
								Mode: &passthroughMode,
							},
						},
					},
				},
			}

			inputs := ModelInputs{
				Gateways:       []*gatewayv1.Gateway{gw},
				GatewayClasses: []*gatewayv1.GatewayClass{gc},
				TLSRoutes:      tc.routes,
				Services:       services,
				ControllerName: "example.net/gateway-controller",
			}

			outputs := ComputeOutputs(inputs)
			if len(outputs.ProxyListeners) != 1 {
				t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
			}
			pListener := outputs.ProxyListeners[0]

			for sni, wantBackend := range tc.queries {
				gotBackend, ok := pListener.SelectTLSBackend(sni)
				if wantBackend == "" {
					if ok {
						t.Errorf("sni %q: expected no backend, got %q", sni, gotBackend)
					}
				} else {
					if !ok {
						t.Errorf("sni %q: expected backend %q, got none", sni, wantBackend)
					} else if gotBackend != wantBackend {
						t.Errorf("sni %q: expected backend %q, got %q", sni, wantBackend, gotBackend)
					}
				}
			}
		})
	}
}

func TestTLSRoute_UnresolvableBackendRef(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	port443 := gatewayv1.PortNumber(443)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					TLS:      &gatewayv1.ListenerTLSConfig{Mode: &passthroughMode},
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	t.Run("nonexistent backend service", func(t *testing.T) {
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-nonexistent", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
				},
				Hostnames: []gatewayv1.Hostname{"example.com"},
				Rules: []gatewayv1.TLSRouteRule{
					{
						BackendRefs: []gatewayv1.BackendRef{
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "nonexistent",
									Port: &port443,
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
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       map[types.NamespacedName]*corev1.Service{},
			ControllerName: "example.net/gateway-controller",
		}

		outputs := ComputeOutputs(inputs)
		if len(outputs.ProxyListeners) != 1 {
			t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
		}
		pLis := outputs.ProxyListeners[0]

		// Listener must have NO TLS backend for that hostname
		if backend, ok := pLis.SelectTLSBackend("example.com"); ok {
			t.Errorf("expected no TLS backend for example.com, got %q", backend)
		}
		if backends, ok := pLis.TLSBackends["example.com"]; ok && len(backends) > 0 {
			t.Errorf("expected empty or missing TLSBackends for example.com, got %v", backends)
		}

		// Route status must report ResolvedRefs=False with reason BackendNotFound
		routeStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-nonexistent"}]
		if !ok {
			t.Fatalf("expected status for route")
		}
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		var resolvedRefsCond *metav1.Condition
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
				break
			}
		}
		if resolvedRefsCond == nil {
			t.Fatal("expected ResolvedRefs condition on parent status")
		}
		if resolvedRefsCond.Status != metav1.ConditionFalse {
			t.Errorf("expected ResolvedRefs status False, got %s", resolvedRefsCond.Status)
		}
		if resolvedRefsCond.Reason != string(gatewayv1.RouteReasonBackendNotFound) {
			t.Errorf("expected ResolvedRefs reason BackendNotFound, got %s", resolvedRefsCond.Reason)
		}
	})

	t.Run("unknown backend kind", func(t *testing.T) {
		unknownGroup := gatewayv1.Group("unknownkind.example.com")
		unknownKind := gatewayv1.Kind("NonExistent")
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-unknown-kind", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
				},
				Hostnames: []gatewayv1.Hostname{"example.com"},
				Rules: []gatewayv1.TLSRouteRule{
					{
						BackendRefs: []gatewayv1.BackendRef{
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Group: &unknownGroup,
									Kind:  &unknownKind,
									Name:  "tls-backend",
									Port:  &port443,
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
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       map[types.NamespacedName]*corev1.Service{},
			ControllerName: "example.net/gateway-controller",
		}

		outputs := ComputeOutputs(inputs)
		if len(outputs.ProxyListeners) != 1 {
			t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
		}
		pLis := outputs.ProxyListeners[0]

		// Listener must have NO TLS backend for that hostname
		if backend, ok := pLis.SelectTLSBackend("example.com"); ok {
			t.Errorf("expected no TLS backend for example.com, got %q", backend)
		}
		if backends, ok := pLis.TLSBackends["example.com"]; ok && len(backends) > 0 {
			t.Errorf("expected empty or missing TLSBackends for example.com, got %v", backends)
		}

		// Route status must report ResolvedRefs=False with reason InvalidKind
		routeStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-unknown-kind"}]
		if !ok {
			t.Fatalf("expected status for route")
		}
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		var resolvedRefsCond *metav1.Condition
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
				break
			}
		}
		if resolvedRefsCond == nil {
			t.Fatal("expected ResolvedRefs condition on parent status")
		}
		if resolvedRefsCond.Status != metav1.ConditionFalse {
			t.Errorf("expected ResolvedRefs status False, got %s", resolvedRefsCond.Status)
		}
		if resolvedRefsCond.Reason != string(gatewayv1.RouteReasonInvalidKind) {
			t.Errorf("expected ResolvedRefs reason InvalidKind, got %s", resolvedRefsCond.Reason)
		}
	})

	t.Run("first failing backend sets ResolvedRefs reason", func(t *testing.T) {
		unknownGroup := gatewayv1.Group("unknownkind.example.com")
		unknownKind := gatewayv1.Kind("NonExistent")
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-multiple-failures", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
				},
				Hostnames: []gatewayv1.Hostname{"example.com"},
				Rules: []gatewayv1.TLSRouteRule{
					{
						BackendRefs: []gatewayv1.BackendRef{
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Group: &unknownGroup,
									Kind:  &unknownKind,
									Name:  "tls-backend",
									Port:  &port443,
								},
							},
							{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "nonexistent",
									Port: &port443,
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
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       map[types.NamespacedName]*corev1.Service{},
			ControllerName: "example.net/gateway-controller",
		}

		outputs := ComputeOutputs(inputs)
		routeStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-multiple-failures"}]
		if !ok {
			t.Fatalf("expected status for route")
		}
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		var resolvedRefsCond *metav1.Condition
		for _, c := range routeStatus.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				resolvedRefsCond = &c
				break
			}
		}
		if resolvedRefsCond == nil {
			t.Fatal("expected ResolvedRefs condition on parent status")
		}
		if resolvedRefsCond.Status != metav1.ConditionFalse {
			t.Errorf("expected ResolvedRefs status False, got %s", resolvedRefsCond.Status)
		}
		if resolvedRefsCond.Reason != string(gatewayv1.RouteReasonInvalidKind) {
			t.Errorf("expected ResolvedRefs reason InvalidKind, got %s", resolvedRefsCond.Reason)
		}
	})
}

func TestTLSRoute_InvalidNoMatchingListener(t *testing.T) {
	terminateMode := gatewayv1.TLSModeTerminate
	passthroughMode := gatewayv1.TLSModePassthrough
	port80 := gatewayv1.PortNumber(80)
	port443 := gatewayv1.PortNumber(443)

	gwHTTP := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-http", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gwHTTPS := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-https", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &terminateMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-secret"},
						},
					},
				},
			},
		},
	}
	gwTLS := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-tls", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls-passthrough",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					TLS:      &gatewayv1.ListenerTLSConfig{Mode: &passthroughMode},
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cert-secret", Namespace: "default"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("dummy-cert"),
			corev1.TLSPrivateKeyKey: []byte("dummy-key"),
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}},
		},
	}

	t.Run("parentRef to HTTP listener yields NotAllowedByListeners", func(t *testing.T) {
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-http", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: "gw-http"}},
				},
				Rules: []gatewayv1.TLSRouteRule{
					{BackendRefs: []gatewayv1.BackendRef{{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port80}}}},
				},
			},
		}
		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gwHTTP},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       services,
			ControllerName: "example.net/gateway-controller",
		}
		outputs := ComputeOutputs(inputs)
		routeStatus := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-http"}]
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		pStatus := routeStatus.Parents[0]
		var acceptedCond *metav1.Condition
		for _, c := range pStatus.Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) {
				acceptedCond = &c
				break
			}
		}
		if acceptedCond == nil {
			t.Fatal("expected Accepted condition")
		}
		if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
			t.Errorf("expected Accepted=False Reason=NotAllowedByListeners, got Status=%s Reason=%s", acceptedCond.Status, acceptedCond.Reason)
		}
	})

	t.Run("parentRef to HTTPS listener yields NotAllowedByListeners", func(t *testing.T) {
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-https", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: "gw-https"}},
				},
				Rules: []gatewayv1.TLSRouteRule{
					{BackendRefs: []gatewayv1.BackendRef{{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port443}}}},
				},
			},
		}
		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gwHTTPS},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       services,
			Secrets:        map[types.NamespacedName]*corev1.Secret{{Namespace: "default", Name: "cert-secret"}: secret},
			ControllerName: "example.net/gateway-controller",
		}
		outputs := ComputeOutputs(inputs)
		routeStatus := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-https"}]
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		pStatus := routeStatus.Parents[0]
		var acceptedCond *metav1.Condition
		for _, c := range pStatus.Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) {
				acceptedCond = &c
				break
			}
		}
		if acceptedCond == nil {
			t.Fatal("expected Accepted condition")
		}
		if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
			t.Errorf("expected Accepted=False Reason=NotAllowedByListeners, got Status=%s Reason=%s", acceptedCond.Status, acceptedCond.Reason)
		}
	})

	t.Run("parentRef missing sectionName yields NoMatchingParent", func(t *testing.T) {
		nonexistentSection := gatewayv1.SectionName("nonexistent-listener")
		route := &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route-missing-section", Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: "gw-tls", SectionName: &nonexistentSection},
					},
				},
				Rules: []gatewayv1.TLSRouteRule{
					{BackendRefs: []gatewayv1.BackendRef{{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: &port443}}}},
				},
			},
		}
		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gwTLS},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			TLSRoutes:      []*gatewayv1.TLSRoute{route},
			Services:       services,
			ControllerName: "example.net/gateway-controller",
		}
		outputs := ComputeOutputs(inputs)
		routeStatus := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route-missing-section"}]
		if len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
		}
		pStatus := routeStatus.Parents[0]
		var acceptedCond *metav1.Condition
		for _, c := range pStatus.Conditions {
			if c.Type == string(gatewayv1.RouteConditionAccepted) {
				acceptedCond = &c
				break
			}
		}
		if acceptedCond == nil {
			t.Fatal("expected Accepted condition")
		}
		if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
			t.Errorf("expected Accepted=False Reason=NoMatchingParent, got Status=%s Reason=%s", acceptedCond.Status, acceptedCond.Reason)
		}
	})
}

func TestTLSRoute_TerminateListener_SupportedKinds(t *testing.T) {
	terminateMode := gatewayv1.TLSModeTerminate
	port8443 := gatewayv1.PortNumber(8443)
	hostname := gatewayv1.Hostname("terminate.example.com")

	certPEM, keyPEM := generateTestCertPEM(t, "terminate.example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "cert-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-tlsroute-terminate-supported", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls-terminate",
					Port:     port8443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostname,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &terminateMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-secret"},
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

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		Secrets:        secrets,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwStatus, ok := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "gateway-tlsroute-terminate-supported"}]
	if !ok {
		t.Fatalf("expected status for gateway")
	}

	if len(gwStatus.Listeners) != 1 {
		t.Fatalf("expected 1 listener in status, got %d", len(gwStatus.Listeners))
	}

	lisStatus := gwStatus.Listeners[0]
	if lisStatus.Name != "tls-terminate" {
		t.Errorf("expected listener name tls-terminate, got %s", lisStatus.Name)
	}

	if len(lisStatus.SupportedKinds) != 1 {
		t.Fatalf("expected 1 supported kind, got %d", len(lisStatus.SupportedKinds))
	}
	if lisStatus.SupportedKinds[0].Kind != "TLSRoute" || ValueOf(lisStatus.SupportedKinds[0].Group) != gatewayv1.GroupName {
		t.Errorf("expected SupportedKinds [TLSRoute], got %+v", lisStatus.SupportedKinds)
	}

	var resolvedRefsCond, acceptedCond, programmedCond *metav1.Condition
	for i := range lisStatus.Conditions {
		c := &lisStatus.Conditions[i]
		switch c.Type {
		case string(gatewayv1.ListenerConditionResolvedRefs):
			resolvedRefsCond = c
		case string(gatewayv1.ListenerConditionAccepted):
			acceptedCond = c
		case string(gatewayv1.ListenerConditionProgrammed):
			programmedCond = c
		}
	}

	if resolvedRefsCond == nil || resolvedRefsCond.Status != metav1.ConditionTrue {
		t.Errorf("expected ResolvedRefs=True on listener, got %+v", resolvedRefsCond)
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True on listener, got %+v", acceptedCond)
	}
	if programmedCond == nil || programmedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Programmed=True on listener, got %+v", programmedCond)
	}
}

func TestTLSRoute_BindsToTerminateListener(t *testing.T) {
	terminateMode := gatewayv1.TLSModeTerminate
	port8443 := gatewayv1.PortNumber(8443)
	port3000 := gatewayv1.PortNumber(3000)
	hostname := gatewayv1.Hostname("tls.example.com")

	certPEM, keyPEM := generateTestCertPEM(t, "tls.example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "cert-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-tlsroute-terminate", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tlsterminate",
					Port:     port8443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostname,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &terminateMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-secret"},
						},
					},
				},
			},
		},
	}

	route := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "tlsroute-terminated-test", Namespace: "default"},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute-terminate"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"tls.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "tcp-backend",
								Port: &port3000,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "tcp-backend"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "tcp-backend", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3000}}},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TLSRoutes:      []*gatewayv1.TLSRoute{route},
		Services:       services,
		Secrets:        secrets,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)

	// Check Route status
	routeStatus, ok := outputs.TLSRouteStatuses[types.NamespacedName{Namespace: "default", Name: "tlsroute-terminated-test"}]
	if !ok {
		t.Fatalf("expected status for route")
	}
	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
	}
	var routeAcceptedCond, routeResolvedRefsCond *metav1.Condition
	for i := range routeStatus.Parents[0].Conditions {
		c := &routeStatus.Parents[0].Conditions[i]
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			routeAcceptedCond = c
		}
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			routeResolvedRefsCond = c
		}
	}
	if routeAcceptedCond == nil || routeAcceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Route Accepted=True, got %+v", routeAcceptedCond)
	}
	if routeResolvedRefsCond == nil || routeResolvedRefsCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Route ResolvedRefs=True, got %+v", routeResolvedRefsCond)
	}

	// Check Gateway status listener attached routes
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "gateway-tlsroute-terminate"}]
	if len(gwStatus.Listeners) != 1 || gwStatus.Listeners[0].AttachedRoutes != 1 {
		t.Errorf("expected AttachedRoutes == 1, got %v", gwStatus.Listeners)
	}

	// Check compiled Proxy listener
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}
	pLis := outputs.ProxyListeners[0]
	if pLis.Protocol != gatewayv1.TLSProtocolType {
		t.Errorf("expected protocol TLS, got %s", pLis.Protocol)
	}
	if pLis.TLSMode == nil || *pLis.TLSMode != gatewayv1.TLSModeTerminate {
		t.Errorf("expected TLSMode Terminate, got %v", pLis.TLSMode)
	}

	backend, ok := pLis.SelectTLSBackend("tls.example.com")
	if !ok || backend != "tcp-backend.default.svc.cluster.local:3000" {
		t.Errorf("expected backend tcp-backend.default.svc.cluster.local:3000, got %q (ok=%v)", backend, ok)
	}
	if len(pLis.TLSBackends["tls.example.com"]) != 1 {
		t.Fatalf("expected 1 backend in TLSBackends, got %d", len(pLis.TLSBackends["tls.example.com"]))
	}
	if pLis.TLSBackends["tls.example.com"][0].Weight != 1 {
		t.Errorf("expected default weight 1, got %d", pLis.TLSBackends["tls.example.com"][0].Weight)
	}
}

func TestTLSRoute_MixedTerminationGateway(t *testing.T) {
	terminateMode := gatewayv1.TLSModeTerminate
	passthroughMode := gatewayv1.TLSModePassthrough
	port8883 := gatewayv1.PortNumber(8883)
	port3000 := gatewayv1.PortNumber(3000)
	port8443 := gatewayv1.PortNumber(8443)
	hostTerminate := gatewayv1.Hostname("tls.example.com")
	hostPassthrough := gatewayv1.Hostname("abc.example.com")

	certPEM, keyPEM := generateTestCertPEM(t, "tls.example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "cert-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-tlsroute-mixed-termination", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls-terminate",
					Port:     port8883,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostTerminate,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &terminateMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-secret"},
						},
					},
				},
				{
					Name:     "tls-passthrough",
					Port:     port8883,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostPassthrough,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &passthroughMode,
					},
				},
			},
		},
	}

	routeTerminate := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-conformance-mixed-terminateroute", Namespace: "default"},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute-mixed-termination"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"tls.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "tcp-backend",
								Port: &port3000,
							},
						},
					},
				},
			},
		},
	}

	routePassthrough := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-conformance-mixed-passthroughroute", Namespace: "default"},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gateway-tlsroute-mixed-termination"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"abc.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "tcp-backend",
								Port: &port8443,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "tcp-backend"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "tcp-backend", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3000}, {Port: 8443}}},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TLSRoutes:      []*gatewayv1.TLSRoute{routeTerminate, routePassthrough},
		Services:       services,
		Secrets:        secrets,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)

	// Check Gateway Status: both listeners must be accepted with no conflicts
	gwStatus, ok := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "gateway-tlsroute-mixed-termination"}]
	if !ok {
		t.Fatalf("expected status for mixed gateway")
	}
	if len(gwStatus.Listeners) != 2 {
		t.Fatalf("expected 2 listeners in status, got %d", len(gwStatus.Listeners))
	}
	for _, l := range gwStatus.Listeners {
		for _, c := range l.Conditions {
			if c.Type == string(gatewayv1.ListenerConditionConflicted) && c.Status == metav1.ConditionTrue {
				t.Errorf("listener %s unexpectedly conflicted: %s", l.Name, c.Message)
			}
			if c.Reason == string(gatewayv1.ListenerReasonHostnameConflict) || c.Reason == string(gatewayv1.ListenerReasonProtocolConflict) {
				t.Errorf("listener %s has unexpected conflict reason: %s", l.Name, c.Reason)
			}
		}
		if l.AttachedRoutes != 1 {
			t.Errorf("listener %s expected 1 attached route, got %d", l.Name, l.AttachedRoutes)
		}
	}

	// Check compiled Proxy listeners: 2 listeners with distinct modes and backends
	if len(outputs.ProxyListeners) != 2 {
		t.Fatalf("expected 2 proxy listeners, got %d", len(outputs.ProxyListeners))
	}

	var termLis, passLis *InternalListener
	for i := range outputs.ProxyListeners {
		l := &outputs.ProxyListeners[i]
		if l.TLSMode != nil && *l.TLSMode == gatewayv1.TLSModeTerminate {
			termLis = l
		} else if l.TLSMode != nil && *l.TLSMode == gatewayv1.TLSModePassthrough {
			passLis = l
		}
	}

	if termLis == nil {
		t.Fatal("expected Terminate proxy listener")
	}
	if passLis == nil {
		t.Fatal("expected Passthrough proxy listener")
	}

	bTerm, ok := termLis.SelectTLSBackend("tls.example.com")
	if !ok || bTerm != "tcp-backend.default.svc.cluster.local:3000" {
		t.Errorf("terminate listener expected tcp-backend.default.svc.cluster.local:3000, got %q", bTerm)
	}

	bPass, ok := passLis.SelectTLSBackend("abc.example.com")
	if !ok || bPass != "tcp-backend.default.svc.cluster.local:8443" {
		t.Errorf("passthrough listener expected tcp-backend.default.svc.cluster.local:8443, got %q", bPass)
	}
}

func TestTLSRoute_WeightedBackendsSelection(t *testing.T) {
	terminateMode := gatewayv1.TLSModeTerminate
	port8443 := gatewayv1.PortNumber(8443)
	port3001 := gatewayv1.PortNumber(3001)
	port3002 := gatewayv1.PortNumber(3002)
	port3003 := gatewayv1.PortNumber(3003)
	hostname := gatewayv1.Hostname("weighted.example.com")

	certPEM, keyPEM := generateTestCertPEM(t, "weighted.example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "cert-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-weighted", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     port8443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: &hostname,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "TLSRoute"},
						},
					},
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &terminateMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-secret"},
						},
					},
				},
			},
		},
	}

	w3 := int32(3)
	w1 := int32(1)
	w0 := int32(0)

	route := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-weighted", Namespace: "default"},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-weighted"},
				},
			},
			Hostnames: []gatewayv1.Hostname{"weighted.example.com"},
			Rules: []gatewayv1.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "b1",
								Port: &port3001,
							},
							Weight: &w3,
						},
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "b2",
								Port: &port3002,
							},
							Weight: &w1,
						},
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "b3",
								Port: &port3003,
							},
							Weight: &w0,
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "b1"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "b1", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3001}}},
		},
		{Namespace: "default", Name: "b2"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "b2", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3002}}},
		},
		{Namespace: "default", Name: "b3"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "b3", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3003}}},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		TLSRoutes:      []*gatewayv1.TLSRoute{route},
		Services:       services,
		Secrets:        secrets,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}

	pLis := outputs.ProxyListeners[0]
	backends := pLis.TLSBackends["weighted.example.com"]
	if len(backends) != 3 {
		t.Fatalf("expected 3 backends in TLSBackends, got %d", len(backends))
	}

	// Verify weights are carried through
	if backends[0].Weight != 3 || backends[0].Target != "b1.default.svc.cluster.local:3001" {
		t.Errorf("backend 0 unexpected: %+v", backends[0])
	}
	if backends[1].Weight != 1 || backends[1].Target != "b2.default.svc.cluster.local:3002" {
		t.Errorf("backend 1 unexpected: %+v", backends[1])
	}
	if backends[2].Weight != 0 || backends[2].Target != "b3.default.svc.cluster.local:3003" {
		t.Errorf("backend 2 unexpected: %+v", backends[2])
	}

	// Draw many times with seeded RNG and verify 3:1 selection proportion
	rng := rand.New(rand.NewPCG(42, 1024))
	counts := make(map[string]int)
	totalDraws := 10000

	for i := 0; i < totalDraws; i++ {
		target, ok := pLis.SelectTLSBackendWithRand("weighted.example.com", rng)
		if !ok {
			t.Fatalf("draw %d failed to select backend", i)
		}
		counts[target]++
	}

	target1 := "b1.default.svc.cluster.local:3001"
	target2 := "b2.default.svc.cluster.local:3002"
	target3 := "b3.default.svc.cluster.local:3003"

	if counts[target3] != 0 {
		t.Errorf("expected 0 selections for weight-0 backend, got %d", counts[target3])
	}

	ratio1 := float64(counts[target1]) / float64(totalDraws)
	ratio2 := float64(counts[target2]) / float64(totalDraws)

	// Tolerance around 0.75 and 0.25
	if ratio1 < 0.70 || ratio1 > 0.80 {
		t.Errorf("expected target1 proportion ~0.75, got %f (%d/%d)", ratio1, counts[target1], totalDraws)
	}
	if ratio2 < 0.20 || ratio2 > 0.30 {
		t.Errorf("expected target2 proportion ~0.25, got %f (%d/%d)", ratio2, counts[target2], totalDraws)
	}
}
