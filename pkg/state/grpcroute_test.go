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
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestGRPCRoute_MethodCompilation(t *testing.T) {
	svc := "my.package.MyService"
	method := "MyMethod"

	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpcroute-methods",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
								Method:  &method,
							},
						},
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
							},
						},
					},
				},
			},
		},
	}

	compiled := CompileGRPCRoute(route, nil, nil, nil, nil)
	if compiled == nil {
		t.Fatalf("expected compiled GRPCRoute")
	}
	if len(compiled.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled.Rules))
	}
	if len(compiled.Rules[0].Matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(compiled.Rules[0].Matches))
	}

	// First match: method{service, method} -> Exact match on /<service>/<method>
	m1 := compiled.Rules[0].Matches[0]
	if m1.Path == nil {
		t.Fatalf("expected path match for m1")
	}
	if m1.Path.Type != gatewayv1.PathMatchExact {
		t.Errorf("expected PathMatchExact, got %s", m1.Path.Type)
	}
	if m1.Path.Value != "/my.package.MyService/MyMethod" {
		t.Errorf("expected path /my.package.MyService/MyMethod, got %s", m1.Path.Value)
	}

	// Second match: service alone -> PathPrefix match on /<service>/
	m2 := compiled.Rules[0].Matches[1]
	if m2.Path == nil {
		t.Fatalf("expected path match for m2")
	}
	if m2.Path.Type != gatewayv1.PathMatchPathPrefix {
		t.Errorf("expected PathMatchPathPrefix, got %s", m2.Path.Type)
	}
	if m2.Path.Value != "/my.package.MyService/" {
		t.Errorf("expected path /my.package.MyService/, got %s", m2.Path.Value)
	}
}

func TestGRPCRoute_HeaderCompilation(t *testing.T) {
	regexType := gatewayv1.GRPCHeaderMatchRegularExpression
	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpcroute-headers",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Headers: []gatewayv1.GRPCHeaderMatch{
								{
									Name:  "X-Exact-Header",
									Value: "exact-val",
								},
								{
									Type:  &regexType,
									Name:  "X-Regex-Header",
									Value: "val-[0-9]+",
								},
								// Duplicate header name (case-insensitive) should be ignored
								{
									Name:  "x-exact-header",
									Value: "duplicate-ignored",
								},
							},
						},
					},
				},
			},
		},
	}

	compiled := CompileGRPCRoute(route, nil, nil, nil, nil)
	if compiled == nil {
		t.Fatalf("expected compiled GRPCRoute")
	}
	if len(compiled.Rules) != 1 || len(compiled.Rules[0].Matches) != 1 {
		t.Fatalf("expected 1 rule with 1 match")
	}

	match := compiled.Rules[0].Matches[0]
	if len(match.Headers) != 2 {
		t.Fatalf("expected 2 headers after deduplication, got %d", len(match.Headers))
	}

	h1 := match.Headers[0]
	if h1.Name != "X-Exact-Header" || h1.Type != gatewayv1.HeaderMatchExact || h1.MatchExactValue != "exact-val" {
		t.Errorf("unexpected h1: %+v", h1)
	}

	h2 := match.Headers[1]
	if h2.Name != "X-Regex-Header" || h2.Type != gatewayv1.HeaderMatchRegularExpression || h2.MatchRegularExpressionValue == nil {
		t.Errorf("unexpected h2: %+v", h2)
	}
	if !h2.MatchRegularExpressionValue.MatchString("val-123") {
		t.Errorf("regex didn't match expected string")
	}
}

func TestGRPCRoute_ListenerBinding(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-listener-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https-listener",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
				{
					Name:     "tls-listener",
					Port:     8443,
					Protocol: gatewayv1.TLSProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	// GRPCRoute attempting to attach to all listeners of the Gateway
	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpcroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "multi-listener-gateway",
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		GRPCRoutes:     []*gatewayv1.GRPCRoute{grpcRoute},
		ControllerName: "example.net/gateway-controller",
	}

	cm := CompileModel(inputs)
	cg := cm.Gateways[types.NamespacedName{Namespace: "default", Name: "multi-listener-gateway"}]
	if cg == nil {
		t.Fatalf("expected compiled gateway")
	}

	var httpEl, httpsEl, tlsEl *EffectiveListener
	for _, el := range cg.EffectiveListeners {
		switch el.Name {
		case "http-listener":
			httpEl = el
		case "https-listener":
			httpsEl = el
		case "tls-listener":
			tlsEl = el
		}
	}

	if httpEl == nil || httpsEl == nil || tlsEl == nil {
		t.Fatalf("missing expected listeners")
	}

	// GRPCRoute binds to HTTP and HTTPS listeners, not to TLS
	if httpEl.AttachedRoutes != 1 {
		t.Errorf("expected 1 attached route on HTTP listener, got %d", httpEl.AttachedRoutes)
	}
	if len(httpEl.Routes) != 1 {
		t.Errorf("expected 1 compiled route on HTTP listener, got %d", len(httpEl.Routes))
	}

	if httpsEl.AttachedRoutes != 1 {
		t.Errorf("expected 1 attached route on HTTPS listener, got %d", httpsEl.AttachedRoutes)
	}
	if len(httpsEl.Routes) != 1 {
		t.Errorf("expected 1 compiled route on HTTPS listener, got %d", len(httpsEl.Routes))
	}

	if tlsEl.AttachedRoutes != 0 {
		t.Errorf("expected 0 attached routes on TLS listener, got %d", tlsEl.AttachedRoutes)
	}
	if len(tlsEl.Routes) != 0 {
		t.Errorf("expected 0 compiled routes on TLS listener, got %d", len(tlsEl.Routes))
	}
}

func TestGRPCRoute_AttachedRoutes_Coexistence(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-httproute",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gateway"},
				},
			},
		},
	}

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpcroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gateway"},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:     []*gatewayv1.HTTPRoute{httpRoute},
		GRPCRoutes:     []*gatewayv1.GRPCRoute{grpcRoute},
		ControllerName: "example.net/gateway-controller",
	}

	cm := CompileModel(inputs)
	cg := cm.Gateways[types.NamespacedName{Namespace: "default", Name: "shared-gateway"}]
	if cg == nil {
		t.Fatalf("expected compiled gateway")
	}

	if len(cg.EffectiveListeners) != 1 {
		t.Fatalf("expected 1 effective listener, got %d", len(cg.EffectiveListeners))
	}

	el := cg.EffectiveListeners[0]
	// Listener with one HTTPRoute and one GRPCRoute reports attachedRoutes: 2
	if el.AttachedRoutes != 2 {
		t.Errorf("expected attachedRoutes 2, got %d", el.AttachedRoutes)
	}

	// Both routes are present in the compiled listener
	if len(el.Routes) != 2 {
		t.Errorf("expected 2 compiled routes in listener, got %d", len(el.Routes))
	}

	outputs := ComputeOutputs(inputs)
	gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "shared-gateway"}]
	if len(gwStatus.Listeners) != 1 {
		t.Fatalf("expected 1 listener status")
	}
	if gwStatus.Listeners[0].AttachedRoutes != 2 {
		t.Errorf("expected listener status attachedRoutes 2, got %d", gwStatus.Listeners[0].AttachedRoutes)
	}
}

func TestGRPCRoute_Status_Conditions(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "status-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	port8080 := gatewayv1.PortNumber(8080)
	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "status-grpcroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "status-gateway"},
				},
			},
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "grpc-svc",
									Port: &port8080,
								},
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
		GRPCRoutes:     []*gatewayv1.GRPCRoute{grpcRoute},
		Services: map[types.NamespacedName]*corev1.Service{
			{Namespace: "default", Name: "grpc-svc"}: svc,
		},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	routeStatus, ok := outputs.GRPCRouteStatuses[types.NamespacedName{Namespace: "default", Name: "status-grpcroute"}]
	if !ok {
		t.Fatalf("expected status for status-grpcroute")
	}

	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(routeStatus.Parents))
	}

	parent := routeStatus.Parents[0]
	if string(parent.ControllerName) != "example.net/gateway-controller" {
		t.Errorf("expected controllerName example.net/gateway-controller, got %s", parent.ControllerName)
	}

	var acceptedCond, resolvedRefsCond *metav1.Condition
	for _, c := range parent.Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
		}
		if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefsCond = &c
		}
	}

	if acceptedCond == nil {
		t.Fatalf("expected Accepted condition")
	}
	if acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True, got %s", acceptedCond.Status)
	}

	if resolvedRefsCond == nil {
		t.Fatalf("expected ResolvedRefs condition")
	}
	if resolvedRefsCond.Status != metav1.ConditionTrue {
		t.Errorf("expected ResolvedRefs=True, got %s", resolvedRefsCond.Status)
	}
}

func TestGRPCRoute_NamedRules(t *testing.T) {
	ruleName1 := gatewayv1.SectionName("named-rule")
	ruleName2 := gatewayv1.SectionName("second-rule")
	svc := "my.package.MyService"
	method1 := "Echo"
	method2 := "EchoTwo"

	validRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-named-rules",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Name: &ruleName1,
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
								Method:  &method1,
							},
						},
					},
				},
				{
					Name: &ruleName2,
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
								Method:  &method2,
							},
						},
					},
				},
				{
					// Unnamed rule alongside named rules is valid
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
							},
						},
					},
				},
			},
		},
	}

	internalValid := CompileGRPCRoute(validRoute, nil, nil, nil, nil)
	if internalValid == nil {
		t.Fatalf("expected compiled GRPCRoute")
	}
	if internalValid.ValidationCondition.Status != metav1.ConditionTrue {
		t.Fatalf("expected valid named route ValidationCondition True, got %v", internalValid.ValidationCondition.Status)
	}
	if len(internalValid.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(internalValid.Rules))
	}
	if internalValid.Rules[0].Name == nil || *internalValid.Rules[0].Name != ruleName1 {
		t.Errorf("expected rule 0 name %q, got %v", ruleName1, internalValid.Rules[0].Name)
	}
	if internalValid.Rules[1].Name == nil || *internalValid.Rules[1].Name != ruleName2 {
		t.Errorf("expected rule 1 name %q, got %v", ruleName2, internalValid.Rules[1].Name)
	}
	if internalValid.Rules[2].Name != nil {
		t.Errorf("expected rule 2 name nil, got %v", internalValid.Rules[2].Name)
	}

	// Duplicate rule names
	duplicateRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "duplicate-named-rules",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Name: &ruleName1,
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
								Method:  &method1,
							},
						},
					},
				},
				{
					Name: &ruleName1, // duplicate name
					Matches: []gatewayv1.GRPCRouteMatch{
						{
							Method: &gatewayv1.GRPCMethodMatch{
								Service: &svc,
								Method:  &method2,
							},
						},
					},
				},
			},
		},
	}

	internalDup := CompileGRPCRoute(duplicateRoute, nil, nil, nil, nil)
	if internalDup.ValidationCondition.Status != metav1.ConditionFalse {
		t.Errorf("expected duplicate rule names ValidationCondition False, got %v", internalDup.ValidationCondition.Status)
	}
	if internalDup.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
		t.Errorf("expected Reason UnsupportedValue, got %s", internalDup.ValidationCondition.Reason)
	}

	// Verify duplicate rule name causes Accepted=False in ComputeOutputs
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	duplicateRoute.Spec.ParentRefs = []gatewayv1.ParentReference{{Name: "gw"}}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		GRPCRoutes:     []*gatewayv1.GRPCRoute{duplicateRoute},
		ControllerName: "example.net/gateway-controller",
	}
	outputs := ComputeOutputs(inputs)
	dupStatus := outputs.GRPCRouteStatuses[types.NamespacedName{Namespace: "default", Name: "duplicate-named-rules"}]
	if len(dupStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(dupStatus.Parents))
	}
	var acceptedCond *metav1.Condition
	for _, c := range dupStatus.Parents[0].Conditions {
		if c.Type == string(gatewayv1.RouteConditionAccepted) {
			acceptedCond = &c
			break
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
		t.Errorf("expected Accepted=False with UnsupportedValue, got %+v", acceptedCond)
	}
}

func TestGRPCRoute_WeightedBackends(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-weight", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	w70 := int32(70)
	w30 := int32(30)
	w0 := int32(0)
	port8080 := gatewayv1.PortNumber(8080)

	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "weighted-grpcroute", Namespace: "default"},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw-weight"}},
			},
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-v1",
									Port: &port8080,
								},
								Weight: &w70,
							},
						},
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-v2",
									Port: &port8080,
								},
								Weight: &w30,
							},
						},
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-v3",
									Port: &port8080,
								},
								Weight: &w0,
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-v1"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-v1", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		{Namespace: "default", Name: "backend-v2"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-v2", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		{Namespace: "default", Name: "backend-v3"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-v3", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		GRPCRoutes:     []*gatewayv1.GRPCRoute{route},
		Services:       services,
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)
	if len(outputs.ProxyListeners) != 1 {
		t.Fatalf("expected 1 proxy listener, got %d", len(outputs.ProxyListeners))
	}
	pLis := outputs.ProxyListeners[0]
	if len(pLis.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(pLis.Routes))
	}
	r := pLis.Routes[0]
	if len(r.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(r.Rules))
	}
	backends := r.Rules[0].Backends
	if len(backends) != 3 {
		t.Fatalf("expected 3 backends, got %d", len(backends))
	}

	// Verify weights are carried through
	if backends[0].Weight != 70 || backends[0].Host != "backend-v1.default.svc.cluster.local" {
		t.Errorf("backend 0 unexpected: %+v", backends[0])
	}
	if backends[1].Weight != 30 || backends[1].Host != "backend-v2.default.svc.cluster.local" {
		t.Errorf("backend 1 unexpected: %+v", backends[1])
	}
	if backends[2].Weight != 0 || backends[2].Host != "backend-v3.default.svc.cluster.local" {
		t.Errorf("backend 2 unexpected: %+v", backends[2])
	}

	// Draw many times with seeded RNG and verify 70/30 distribution and 0 draws for weight 0
	rng := rand.New(rand.NewPCG(42, 1024))
	counts := make(map[string]int)
	totalDraws := 10000

	for i := 0; i < totalDraws; i++ {
		b, err := PickBackendWithRand(backends, rng)
		if err != nil {
			t.Fatalf("draw %d failed to select backend: %v", i, err)
		}
		counts[b.Host]++
	}

	host1 := "backend-v1.default.svc.cluster.local"
	host2 := "backend-v2.default.svc.cluster.local"
	host3 := "backend-v3.default.svc.cluster.local"

	if counts[host3] != 0 {
		t.Errorf("expected 0 selections for weight-0 backend, got %d", counts[host3])
	}

	ratio1 := float64(counts[host1]) / float64(totalDraws)
	ratio2 := float64(counts[host2]) / float64(totalDraws)

	if ratio1 < 0.65 || ratio1 > 0.75 {
		t.Errorf("expected host1 proportion ~0.70, got %f (%d/%d)", ratio1, counts[host1], totalDraws)
	}
	if ratio2 < 0.25 || ratio2 > 0.35 {
		t.Errorf("expected host2 proportion ~0.30, got %f (%d/%d)", ratio2, counts[host2], totalDraws)
	}
}

func TestGRPCRoute_HeaderModifiers(t *testing.T) {
	ruleReqMod := &gatewayv1.HTTPHeaderFilter{
		Set:    []gatewayv1.HTTPHeader{{Name: "X-Rule-Req-Set", Value: "rule-set"}},
		Add:    []gatewayv1.HTTPHeader{{Name: "X-Rule-Req-Add", Value: "rule-add"}},
		Remove: []string{"X-Rule-Req-Remove"},
	}
	ruleRespMod := &gatewayv1.HTTPHeaderFilter{
		Set:    []gatewayv1.HTTPHeader{{Name: "X-Rule-Resp-Set", Value: "rule-resp-set"}},
		Add:    []gatewayv1.HTTPHeader{{Name: "X-Rule-Resp-Add", Value: "rule-resp-add"}},
		Remove: []string{"X-Rule-Resp-Remove"},
	}
	backendReqMod := &gatewayv1.HTTPHeaderFilter{
		Set:    []gatewayv1.HTTPHeader{{Name: "X-Backend-Req-Set", Value: "backend-set"}},
		Add:    []gatewayv1.HTTPHeader{{Name: "X-Backend-Req-Add", Value: "backend-add"}},
		Remove: []string{"X-Backend-Req-Remove"},
	}
	backendRespMod := &gatewayv1.HTTPHeaderFilter{
		Set:    []gatewayv1.HTTPHeader{{Name: "X-Backend-Resp-Set", Value: "backend-resp-set"}},
		Add:    []gatewayv1.HTTPHeader{{Name: "X-Backend-Resp-Add", Value: "backend-resp-add"}},
		Remove: []string{"X-Backend-Resp-Remove"},
	}
	port := gatewayv1.PortNumber(8080)
	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "header-modifiers-grpcroute", Namespace: "default"},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type:                  gatewayv1.GRPCRouteFilterRequestHeaderModifier,
							RequestHeaderModifier: ruleReqMod,
						},
						{
							Type:                   gatewayv1.GRPCRouteFilterResponseHeaderModifier,
							ResponseHeaderModifier: ruleRespMod,
						},
					},
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-svc",
									Port: &port,
								},
							},
							Filters: []gatewayv1.GRPCRouteFilter{
								{
									Type:                  gatewayv1.GRPCRouteFilterRequestHeaderModifier,
									RequestHeaderModifier: backendReqMod,
								},
								{
									Type:                   gatewayv1.GRPCRouteFilterResponseHeaderModifier,
									ResponseHeaderModifier: backendRespMod,
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
			ObjectMeta: metav1.ObjectMeta{Name: "backend-svc", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	compiled := CompileGRPCRoute(route, services, nil, nil, nil)
	if compiled.ValidationCondition.Status != metav1.ConditionTrue {
		t.Fatalf("ValidationCondition.Status = %v, want True", compiled.ValidationCondition.Status)
	}
	if compiled.ResolvedRefsCondition.Status != metav1.ConditionTrue {
		t.Fatalf("ResolvedRefsCondition.Status = %v, want True", compiled.ResolvedRefsCondition.Status)
	}
	if len(compiled.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled.Rules))
	}

	rule := compiled.Rules[0]
	if !reflect.DeepEqual(rule.RequestHeaderModifier, ruleReqMod) {
		t.Errorf("rule RequestHeaderModifier = %+v, want %+v", rule.RequestHeaderModifier, ruleReqMod)
	}
	if !reflect.DeepEqual(rule.ResponseHeaderModifier, ruleRespMod) {
		t.Errorf("rule ResponseHeaderModifier = %+v, want %+v", rule.ResponseHeaderModifier, ruleRespMod)
	}

	if len(rule.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(rule.Backends))
	}
	backend := rule.Backends[0]
	if !reflect.DeepEqual(backend.RequestHeaderModifier, backendReqMod) {
		t.Errorf("backend RequestHeaderModifier = %+v, want %+v", backend.RequestHeaderModifier, backendReqMod)
	}
	if !reflect.DeepEqual(backend.ResponseHeaderModifier, backendRespMod) {
		t.Errorf("backend ResponseHeaderModifier = %+v, want %+v", backend.ResponseHeaderModifier, backendRespMod)
	}
}

func TestGRPCRoute_RequestMirror(t *testing.T) {
	port8080 := gatewayv1.PortNumber(8080)
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		{Namespace: "other-ns", Name: "mirror-svc"}: {
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	crossGrantForGRPCRoute := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "grant-grpc"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "GRPCRoute",
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

	crossGrantForHTTPRouteOnly := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "grant-http"},
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
	}

	routeWithCrossNsMirror := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-route"},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Namespace: Ptr(gatewayv1.Namespace("other-ns")),
									Name:      "mirror-svc",
									Port:      &port8080,
								},
							},
						},
					},
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend-svc",
									Port: &port8080,
								},
							},
						},
					},
				},
			},
		},
	}

	t.Run("cross-namespace mirror without ReferenceGrant is rejected", func(t *testing.T) {
		compiled := CompileGRPCRoute(routeWithCrossNsMirror, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ValidationCondition True, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ResolvedRefsCondition False, got %v", compiled.ResolvedRefsCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Reason != string(gatewayv1.RouteReasonRefNotPermitted) {
			t.Errorf("expected Reason RefNotPermitted, got %v", compiled.ResolvedRefsCondition.Reason)
		}
		if len(compiled.Rules) > 0 && len(compiled.Rules[0].Mirrors) != 0 {
			t.Errorf("expected 0 mirrors, got %d", len(compiled.Rules[0].Mirrors))
		}
	})

	t.Run("cross-namespace mirror with ReferenceGrant for HTTPRoute only is rejected", func(t *testing.T) {
		refValidator := mapReferenceValidator{
			referenceGrants: map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{
				{Namespace: "other-ns", Name: "grant-http"}: crossGrantForHTTPRouteOnly,
			},
		}
		compiled := CompileGRPCRoute(routeWithCrossNsMirror, services, nil, nil, refValidator)
		if compiled.ResolvedRefsCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ResolvedRefsCondition False, got %v", compiled.ResolvedRefsCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Reason != string(gatewayv1.RouteReasonRefNotPermitted) {
			t.Errorf("expected Reason RefNotPermitted, got %v", compiled.ResolvedRefsCondition.Reason)
		}
	})

	t.Run("cross-namespace mirror with ReferenceGrant for GRPCRoute succeeds", func(t *testing.T) {
		refValidator := mapReferenceValidator{
			referenceGrants: map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{
				{Namespace: "other-ns", Name: "grant-grpc"}: crossGrantForGRPCRoute,
			},
		}
		compiled := CompileGRPCRoute(routeWithCrossNsMirror, services, nil, nil, refValidator)
		if compiled.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ValidationCondition True, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ResolvedRefsCondition True, got %v (%s)", compiled.ResolvedRefsCondition.Status, compiled.ResolvedRefsCondition.Message)
		}
		if compiled.ResolvedRefsCondition.Reason != string(gatewayv1.RouteReasonResolvedRefs) {
			t.Errorf("expected Reason ResolvedRefs, got %v", compiled.ResolvedRefsCondition.Reason)
		}
		if len(compiled.Rules) != 1 || len(compiled.Rules[0].Mirrors) != 1 {
			t.Fatalf("expected 1 mirror, got %d", len(compiled.Rules[0].Mirrors))
		}
		mirror := compiled.Rules[0].Mirrors[0]
		if mirror.Backend.Host != "mirror-svc.other-ns.svc.cluster.local" {
			t.Errorf("expected mirror host mirror-svc.other-ns.svc.cluster.local, got %s", mirror.Backend.Host)
		}
		if mirror.Numerator != 100 || mirror.Denominator != 100 {
			t.Errorf("expected fraction 100/100, got %d/%d", mirror.Numerator, mirror.Denominator)
		}
	})

	t.Run("mirror percent and fraction options", func(t *testing.T) {
		routePercent := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mirror-percent"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						Filters: []gatewayv1.GRPCRouteFilter{
							{
								Type: gatewayv1.GRPCRouteFilterRequestMirror,
								RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "backend-svc",
										Port: &port8080,
									},
									Percent: Ptr(int32(40)),
								},
							},
						},
						BackendRefs: []gatewayv1.GRPCBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "backend-svc",
										Port: &port8080,
									},
								},
							},
						},
					},
				},
			},
		}
		compiled := CompileGRPCRoute(routePercent, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected ValidationCondition True, got %v", compiled.ValidationCondition.Status)
		}
		if len(compiled.Rules[0].Mirrors) != 1 || compiled.Rules[0].Mirrors[0].Numerator != 40 || compiled.Rules[0].Mirrors[0].Denominator != 100 {
			t.Errorf("expected 40/100 mirror, got %+v", compiled.Rules[0].Mirrors)
		}
	})
}

func TestGRPCRoute_ExtensionRef_And_UnsupportedFilters(t *testing.T) {
	port8080 := gatewayv1.PortNumber(8080)
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-svc"}: {
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	t.Run("rule-level ExtensionRef rejected with UnsupportedValue", func(t *testing.T) {
		route := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "extref-rule", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						Filters: []gatewayv1.GRPCRouteFilter{
							{
								Type: gatewayv1.GRPCRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: "custom.example.com",
									Kind:  "CustomFilter",
									Name:  "my-filter",
								},
							},
						},
						BackendRefs: []gatewayv1.GRPCBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "backend-svc",
										Port: &port8080,
									},
								},
							},
						},
					},
				},
			},
		}

		compiled := CompileGRPCRoute(route, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %v", compiled.ValidationCondition.Reason)
		}
		if len(compiled.Rules[0].Backends) != 0 {
			t.Errorf("expected 0 backends on invalid rule, got %d", len(compiled.Rules[0].Backends))
		}

		routeState := &GRPCRouteState{GRPCRoute: route, Internal: compiled}
		if err := routeState.Validate(); err == nil {
			t.Errorf("expected Validate() error, got nil")
		}
	})

	t.Run("backend-level ExtensionRef rejected with UnsupportedValue", func(t *testing.T) {
		route := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "extref-backend", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						BackendRefs: []gatewayv1.GRPCBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "backend-svc",
										Port: &port8080,
									},
								},
								Filters: []gatewayv1.GRPCRouteFilter{
									{
										Type: gatewayv1.GRPCRouteFilterExtensionRef,
										ExtensionRef: &gatewayv1.LocalObjectReference{
											Group: "custom.example.com",
											Kind:  "CustomFilter",
											Name:  "my-filter",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		compiled := CompileGRPCRoute(route, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %v", compiled.ValidationCondition.Reason)
		}

		routeState := &GRPCRouteState{GRPCRoute: route, Internal: compiled}
		if err := routeState.Validate(); err == nil {
			t.Errorf("expected Validate() error, got nil")
		}
	})

	t.Run("backend-level RequestMirror rejected with UnsupportedValue", func(t *testing.T) {
		route := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "mirror-backend", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						BackendRefs: []gatewayv1.GRPCBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "backend-svc",
										Port: &port8080,
									},
								},
								Filters: []gatewayv1.GRPCRouteFilter{
									{
										Type: gatewayv1.GRPCRouteFilterRequestMirror,
										RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
											BackendRef: gatewayv1.BackendObjectReference{
												Name: "backend-svc",
												Port: &port8080,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		compiled := CompileGRPCRoute(route, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %v", compiled.ValidationCondition.Reason)
		}
	})

	t.Run("rule-level unknown filter rejected with UnsupportedValue", func(t *testing.T) {
		route := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "unknown-filter", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						Filters: []gatewayv1.GRPCRouteFilter{
							{
								Type: gatewayv1.GRPCRouteFilterType("CompletelyUnknown"),
							},
						},
					},
				},
			},
		}

		compiled := CompileGRPCRoute(route, services, nil, nil, nil)
		if compiled.ValidationCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected ValidationCondition False, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ValidationCondition.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
			t.Errorf("expected Reason UnsupportedValue, got %v", compiled.ValidationCondition.Reason)
		}
	})
}

func TestCompileGRPCRoute_BackendTLSWithoutPolicy_ResolvedRefsMessage(t *testing.T) {
	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "grpc-tls-backend-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "grpc-https-svc",
									Port: Ptr(gatewayv1.PortNumber(8443)),
								},
							},
						},
					},
				},
			},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "grpc-https-svc"}: {
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 8443, AppProtocol: Ptr("https")},
				},
			},
		},
	}

	t.Run("no policy surfaces verification mode and why on ResolvedRefs", func(t *testing.T) {
		compiled := CompileGRPCRoute(route, services, nil, nil, nil)
		if compiled == nil {
			t.Fatalf("expected non-nil InternalGRPCRoute")
		}
		if compiled.ValidationCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected Accepted=True, got %v", compiled.ValidationCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Status != metav1.ConditionTrue {
			t.Fatalf("expected ResolvedRefs=True, got %v", compiled.ResolvedRefsCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Reason != string(gatewayv1.RouteReasonResolvedRefs) {
			t.Errorf("expected reason %s, got %s", gatewayv1.RouteReasonResolvedRefs, compiled.ResolvedRefsCondition.Reason)
		}
		expectedMsg := "Backend TLS without BackendTLSPolicy: verifying against system trust roots with ServerName grpc-https-svc.default.svc.cluster.local (backend Service specifies appProtocol: https without a BackendTLSPolicy)"
		if compiled.ResolvedRefsCondition.Message != expectedMsg {
			t.Errorf("expected message %q, got %q", expectedMsg, compiled.ResolvedRefsCondition.Message)
		}
	})

	t.Run("with policy preserves standard All references resolved message", func(t *testing.T) {
		policies := []*gatewayv1.BackendTLSPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-https-svc-policy",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: "",
								Kind:  "Service",
								Name:  "grpc-https-svc",
							},
						},
					},
					Validation: gatewayv1.BackendTLSPolicyValidation{
						Hostname: "grpc-https-svc.default.svc.cluster.local",
					},
				},
			},
		}

		compiled := CompileGRPCRoute(route, services, policies, nil, nil)
		if compiled == nil {
			t.Fatalf("expected non-nil InternalGRPCRoute")
		}
		if compiled.ResolvedRefsCondition.Status != metav1.ConditionTrue {
			t.Fatalf("expected ResolvedRefs=True, got %v", compiled.ResolvedRefsCondition.Status)
		}
		if compiled.ResolvedRefsCondition.Message != "All references resolved" {
			t.Errorf("expected message 'All references resolved', got %q", compiled.ResolvedRefsCondition.Message)
		}
	})

	t.Run("mirror backend without policy is surfaced", func(t *testing.T) {
		mirrorRoute := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "grpc-mirror-route",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						Filters: []gatewayv1.GRPCRouteFilter{
							{
								Type: gatewayv1.GRPCRouteFilterRequestMirror,
								RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
									BackendRef: gatewayv1.BackendObjectReference{
										Name: "grpc-https-svc",
										Port: Ptr(gatewayv1.PortNumber(8443)),
									},
								},
							},
						},
					},
				},
			},
		}

		compiled := CompileGRPCRoute(mirrorRoute, services, nil, nil, nil)
		if compiled == nil {
			t.Fatalf("expected non-nil InternalGRPCRoute")
		}
		expectedMsg := "Backend TLS without BackendTLSPolicy: verifying against system trust roots with ServerName grpc-https-svc.default.svc.cluster.local (backend Service specifies appProtocol: https without a BackendTLSPolicy)"
		if compiled.ResolvedRefsCondition.Message != expectedMsg {
			t.Errorf("expected message %q, got %q", expectedMsg, compiled.ResolvedRefsCondition.Message)
		}
	})
}
