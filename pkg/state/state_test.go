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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

type testQueue struct {
	workqueue.TypedRateLimitingInterface[reconcile.Request]
}

func newTestQueue() *testQueue {
	return &testQueue{
		TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]()),
	}
}

func (q *testQueue) drain() []types.NamespacedName {
	var res []types.NamespacedName
	for q.Len() > 0 {
		item, _ := q.Get()
		res = append(res, item.NamespacedName)
		q.Done(item)
	}
	return res
}

func TestComputeOutputs_UnchangedInputsProduceNoEvents(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	qGC := newTestQueue()
	qGW := newTestQueue()
	qRoute := newTestQueue()

	ctx := t.Context()
	_ = st.GatewayClassSource().Start(ctx, qGC)
	_ = st.GatewaySource().Start(ctx, qGW)
	_ = st.HTTPRouteSource().Start(ctx, qRoute)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "my-gw"},
				},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertHTTPRoute(route)
	st.Recompute()

	// Initial drain
	qGC.drain()
	qGW.drain()
	qRoute.drain()

	// Recompute with unchanged inputs
	st.Recompute()

	gcEvents := qGC.drain()
	gwEvents := qGW.drain()
	routeEvents := qRoute.drain()

	if len(gcEvents) != 0 {
		t.Errorf("expected 0 GatewayClass events for unchanged inputs, got %d", len(gcEvents))
	}
	if len(gwEvents) != 0 {
		t.Errorf("expected 0 Gateway events for unchanged inputs, got %d", len(gwEvents))
	}
	if len(routeEvents) != 0 {
		t.Errorf("expected 0 HTTPRoute events for unchanged inputs, got %d", len(routeEvents))
	}

	// Calling Upsert with identical object should not bump revision
	revBefore := st.Revision()
	st.UpsertGateway(gw)
	st.UpsertHTTPRoute(route)
	if st.Revision() != revBefore {
		t.Errorf("expected revision unchanged on duplicate upsert: before=%d, after=%d", revBefore, st.Revision())
	}
}

func TestComputeOutputs_SingleChangeProducesEventsOnlyForAffectedObjects(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	qGC := newTestQueue()
	qGW := newTestQueue()

	ctx := t.Context()
	_ = st.GatewayClassSource().Start(ctx, qGC)
	_ = st.GatewaySource().Start(ctx, qGW)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "other-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertGateway(gw2)
	st.Recompute()

	qGW.drain()
	qGC.drain()

	// Change only gw2 addresses
	st.SetGatewayAddresses(types.NamespacedName{Namespace: "default", Name: "other-gw"}, []gatewayv1.GatewayStatusAddress{
		{Value: "10.0.0.2"},
	})
	st.Recompute()

	gwEvents := qGW.drain()
	if len(gwEvents) != 1 {
		t.Fatalf("expected exactly 1 Gateway event for other-gw, got %d (%v)", len(gwEvents), gwEvents)
	}
	if gwEvents[0].Name != "other-gw" {
		t.Errorf("expected event for other-gw, got %s", gwEvents[0].Name)
	}

	gcEvents := qGC.drain()
	if len(gcEvents) != 0 {
		t.Errorf("expected 0 GatewayClass events when Gateway addresses change, got %d", len(gcEvents))
	}
}

func TestEventSource_BuffersEventsBeforeStart(t *testing.T) {
	source := NewEventSource()

	req1 := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-1"}}
	req2 := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-2"}}

	// Enqueue before Start
	source.Enqueue(req1)
	source.Enqueue(req2)
	source.Enqueue(req1) // duplicate should dedupe in set

	q := newTestQueue()
	ctx := t.Context()
	if err := source.Start(ctx, q); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	items := q.drain()
	if len(items) != 2 {
		t.Fatalf("expected 2 buffered items flushed into workqueue, got %d (%v)", len(items), items)
	}

	// A second Start call should not re-flush old pending requests because pending was cleared
	q2 := newTestQueue()
	if err := source.Start(ctx, q2); err != nil {
		t.Fatalf("second Start failed: %v", err)
	}
	items2 := q2.drain()
	if len(items2) != 0 {
		t.Fatalf("expected 0 items flushed into second workqueue after pending cleared, got %d (%v)", len(items2), items2)
	}
}

func TestState_NotRunningMarksDirtyWithoutAsyncRecompute(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	if st.IsDirty() {
		t.Errorf("expected initial state not dirty")
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	// Mutating state when not running should mark state dirty
	st.UpsertGatewayClass(gc)
	if !st.IsDirty() {
		t.Errorf("expected state to be marked dirty after UpsertGatewayClass")
	}

	// Calling Recompute clears dirty flag and produces outputs
	outputs := st.Recompute()
	if outputs == nil {
		t.Fatalf("expected non-nil outputs from Recompute")
	}
	if st.IsDirty() {
		t.Errorf("expected state to not be dirty after explicit Recompute")
	}
}

func TestState_NamespaceLabelChangeDependencyWithoutMapping(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	qRoute := newTestQueue()
	ctx := t.Context()
	_ = st.HTTPRouteSource().Start(ctx, qRoute)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "infra-ns", Name: "prod-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: Ptr(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
						},
					},
				},
			},
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app-ns",
			Labels: map[string]string{"env": "dev"},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "app-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Namespace: Ptr(gatewayv1.Namespace("infra-ns")),
						Name:      "prod-gw",
					},
				},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertNamespace(ns)
	st.UpsertGateway(gw)
	st.UpsertHTTPRoute(route)
	st.Recompute()

	// Route should initially be not accepted because namespace label is env: dev
	routeStatus, ok := st.GetDesiredHTTPRouteStatus(types.NamespacedName{Namespace: "app-ns", Name: "app-route"})
	if !ok || len(routeStatus.Parents) != 1 {
		t.Fatalf("expected route status present, got %+v", routeStatus)
	}
	if routeStatus.Parents[0].Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("expected route initially Accepted=False, got %v", routeStatus.Parents[0].Conditions[0])
	}

	qRoute.drain()

	// Mutate namespace label to env: prod
	nsUpdated := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}
	st.UpsertNamespace(nsUpdated)
	st.Recompute()

	// Central recomputation should automatically detect route is now accepted and emit an event!
	routeEvents := qRoute.drain()
	if len(routeEvents) != 1 {
		t.Fatalf("expected 1 HTTPRoute event on namespace label change, got %d", len(routeEvents))
	}
	if routeEvents[0].Namespace != "app-ns" || routeEvents[0].Name != "app-route" {
		t.Errorf("expected event for app-ns/app-route, got %v", routeEvents[0])
	}

	routeStatusAfter, _ := st.GetDesiredHTTPRouteStatus(types.NamespacedName{Namespace: "app-ns", Name: "app-route"})
	if routeStatusAfter.Parents[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected route Accepted=True after namespace label change, got %v", routeStatusAfter.Parents[0].Conditions[0])
	}
}

func TestState_ReferenceGrantDeletionDependencyWithoutMapping(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	qRoute := newTestQueue()
	ctx := t.Context()
	_ = st.HTTPRouteSource().Start(ctx, qRoute)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "backend-ns", Name: "my-svc"},
	}

	rg := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Namespace: "backend-ns", Name: "allow-route"},
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
					Name:  Ptr(gatewayv1.ObjectName("my-svc")),
				},
			},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cross-ns-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "my-gw"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Namespace: Ptr(gatewayv1.Namespace("backend-ns")),
									Name:      "my-svc",
								},
							},
						},
					},
				},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertService(svc)
	st.UpsertReferenceGrant(rg)
	st.UpsertHTTPRoute(route)
	st.Recompute()

	// Initially ResolvedRefs should be True
	statusBefore, ok := st.GetDesiredHTTPRouteStatus(types.NamespacedName{Namespace: "default", Name: "cross-ns-route"})
	if !ok || len(statusBefore.Parents) != 1 {
		t.Fatalf("expected route status present")
	}
	if statusBefore.Parents[0].Conditions[1].Status != metav1.ConditionTrue {
		t.Fatalf("expected ResolvedRefs=True, got %v", statusBefore.Parents[0].Conditions[1])
	}

	qRoute.drain()

	// Delete ReferenceGrant
	st.DeleteReferenceGrant(types.NamespacedName{Namespace: "backend-ns", Name: "allow-route"})
	st.Recompute()

	// Central recomputation should detect ResolvedRefs became False and emit an event
	events := qRoute.drain()
	if len(events) != 1 {
		t.Fatalf("expected 1 HTTPRoute event on ReferenceGrant deletion, got %d", len(events))
	}
	if events[0].Name != "cross-ns-route" {
		t.Errorf("expected event for cross-ns-route, got %s", events[0].Name)
	}

	statusAfter, _ := st.GetDesiredHTTPRouteStatus(types.NamespacedName{Namespace: "default", Name: "cross-ns-route"})
	if statusAfter.Parents[0].Conditions[1].Status != metav1.ConditionFalse ||
		statusAfter.Parents[0].Conditions[1].Reason != string(gatewayv1.RouteReasonRefNotPermitted) {
		t.Errorf("expected ResolvedRefs=False/RefNotPermitted, got %v", statusAfter.Parents[0].Conditions[1])
	}
}

func TestState_ConfigMapChangeBackendTLSPolicyDependencyWithoutMapping(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	qPolicy := newTestQueue()
	ctx := t.Context()
	_ = st.BackendTLSPolicySource().Start(ctx, qPolicy)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "secure-svc"},
	}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{Name: "secure-svc"},
							},
						},
					},
				},
			},
		},
	}

	validCertPEM := "-----BEGIN CERTIFICATE-----\nMIIBkDCB+aADAgECAgEBMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCHNlcnZp\nY2UwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjATMREwDwYDVQQDDAhz\nZXJ2aWNlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3/1234567890ABCDEF\nMA0GCSqGSIb3DQEBCwUAA4GBACb1234567890ABCDEF\n-----END CERTIFICATE-----"
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ca-cert-cm"},
		Data: map[string]string{
			ConfigMapCACertKey: validCertPEM,
		},
	}

	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tls-policy"},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "secure-svc",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "ca-cert-cm",
					},
				},
				Hostname: "secure.example.com",
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertService(svc)
	st.UpsertHTTPRoute(route)
	st.UpsertConfigMap(cm)
	st.UpsertBackendTLSPolicy(policy)
	st.Recompute()

	// Policy should be Accepted=True
	policyStatus, ok := st.GetDesiredBackendTLSPolicyStatus(types.NamespacedName{Namespace: "default", Name: "tls-policy"})
	if !ok || len(policyStatus.Ancestors) != 1 {
		t.Fatalf("expected policy status with 1 ancestor, got %+v", policyStatus)
	}
	if policyStatus.Ancestors[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected policy Accepted=True, got %v", policyStatus.Ancestors[0].Conditions[0])
	}

	qPolicy.drain()

	// Update ConfigMap with invalid data
	cmInvalid := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ca-cert-cm"},
		Data: map[string]string{
			ConfigMapCACertKey: "invalid cert data",
		},
	}
	st.UpsertConfigMap(cmInvalid)
	st.Recompute()

	// Central recomputation should detect policy Accepted=False and emit an event
	events := qPolicy.drain()
	if len(events) != 1 {
		t.Fatalf("expected 1 BackendTLSPolicy event on ConfigMap change, got %d", len(events))
	}
	if events[0].Name != "tls-policy" {
		t.Errorf("expected event for tls-policy, got %s", events[0].Name)
	}

	policyStatusAfter, _ := st.GetDesiredBackendTLSPolicyStatus(types.NamespacedName{Namespace: "default", Name: "tls-policy"})
	if policyStatusAfter.Ancestors[0].Conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("expected policy Accepted=False after ConfigMap corruption, got %v", policyStatusAfter.Ancestors[0].Conditions[0])
	}
}

func TestMergeHTTPRouteStatus_DeterministicOrderAndOtherControllers(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("example.net/gateway-controller")
	otherCtrl := gatewayv1.GatewayController("other.org/other-controller")

	t0 := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	c := []metav1.Condition{
		{
			Type:               "Accepted",
			Status:             metav1.ConditionTrue,
			Reason:             "Accepted",
			Message:            "Accepted",
			ObservedGeneration: 1,
			LastTransitionTime: t0,
		},
	}

	current := &gatewayv1.HTTPRouteStatus{
		Parents: []gatewayv1.RouteParentStatus{
			{ParentRef: gatewayv1.ParentReference{Name: "gw-other"}, ControllerName: otherCtrl, Conditions: c},
			{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
			{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
		},
	}

	// Desired parents for our controller in unsorted order
	desired := gatewayv1.HTTPRouteStatus{
		Parents: []gatewayv1.RouteParentStatus{
			{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
			{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
		},
	}

	updated := MergeHTTPRouteStatus(current, desired, "default", myCtrl)
	if updated {
		t.Errorf("expected updated=false when only ordering of existing entries differs")
	}

	// Current parents should now be deterministically sorted: gw-a, gw-b, then gw-other
	if len(current.Parents) != 3 {
		t.Fatalf("expected 3 parents, got %d", len(current.Parents))
	}
	if current.Parents[0].ParentRef.Name != "gw-a" || current.Parents[0].ControllerName != myCtrl {
		t.Errorf("expected current.Parents[0] to be myCtrl/gw-a, got %+v", current.Parents[0])
	}
	if current.Parents[1].ParentRef.Name != "gw-b" || current.Parents[1].ControllerName != myCtrl {
		t.Errorf("expected current.Parents[1] to be myCtrl/gw-b, got %+v", current.Parents[1])
	}
	if current.Parents[2].ParentRef.Name != "gw-other" || current.Parents[2].ControllerName != otherCtrl {
		t.Errorf("expected current.Parents[2] to be otherCtrl/gw-other, got %+v", current.Parents[2])
	}
}

func TestState_GatewayReadinessGating(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})

	// 1. Initial recompute with ready=false -> Programmed=False, Reason=Pending
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: false})
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	var progCond *metav1.Condition
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil {
		t.Fatalf("expected Programmed condition")
	}
	if progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Errorf("expected Programmed=False Reason=Pending when ready=false, got Status=%s Reason=%s", progCond.Status, progCond.Reason)
	}

	// 2. Set ready=true -> Programmed=True, Reason=Programmed
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
	st.Recompute()

	status, ok = st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True Reason=Programmed when ready=true, got Status=%s Reason=%s", progCond.Status, progCond.Reason)
	}

	// 3. Custom readiness reason and message
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: false, Reason: "Pending", Message: "Waiting for tunnel connection to frontend"})
	st.Recompute()

	status, ok = st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	progCond = nil
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != "Pending" || progCond.Message != "Waiting for tunnel connection to frontend" {
		t.Errorf("expected Programmed=False Reason=Pending Message='Waiting for tunnel connection to frontend', got %+v", progCond)
	}
}

func TestState_GatewayProvisioningErrorStatus(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})

	// 1. With provisioning error -> Programmed=False, Message=error
	provErr := "conflict: existing Service default/my-gw-gari is not owned by Gateway my-gw"
	st.SetGatewayProvisioningError(gwKey, provErr)
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	var progCond *metav1.Condition
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil {
		t.Fatalf("expected Programmed condition")
	}
	if progCond.Status != metav1.ConditionFalse || progCond.Message != provErr {
		t.Errorf("expected Programmed=False Message=%q when provisioning error present, got Status=%s Message=%q", provErr, progCond.Status, progCond.Message)
	}

	// 2. Clear provisioning error -> Programmed=True restored (given address and readiness)
	st.SetGatewayProvisioningError(gwKey, "")
	st.Recompute()

	status, ok = st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	progCond = nil
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil {
		t.Fatalf("expected Programmed condition")
	}
	if progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True Reason=Programmed when provisioning error cleared, got Status=%s Reason=%s", progCond.Status, progCond.Reason)
	}
}

type mockDataplanePublisher struct {
	publishErr error
	published  map[types.NamespacedName]*DataplaneConfig
}

func (m *mockDataplanePublisher) Begin(ctx context.Context) error  { return nil }
func (m *mockDataplanePublisher) Commit(ctx context.Context) error { return nil }
func (m *mockDataplanePublisher) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *DataplaneConfig) error {
	if m.publishErr != nil {
		return m.publishErr
	}
	if m.published == nil {
		m.published = make(map[types.NamespacedName]*DataplaneConfig)
	}
	if gw != nil {
		m.published[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = config
	}
	return nil
}

func TestState_PublishDataplaneConfig_OwnershipConflict(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	mockPub := &mockDataplanePublisher{
		publishErr: &OwnershipConflictError{
			Message: "conflict: existing Secret default/my-gw-gari is not owned by Gateway my-gw",
		},
	}
	st.SetDataplanePublisher(mockPub)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})

	// 1. Initial recompute publishes config and encounters OwnershipConflictError,
	// which records the provisioning error and marks state dirty.
	st.Recompute()
	// Next recompute folds the recorded conflict into Gateway status.
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	var progCond *metav1.Condition
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil {
		t.Fatalf("expected Programmed condition")
	}
	if progCond.Status != metav1.ConditionFalse || progCond.Message != mockPub.publishErr.Error() {
		t.Errorf("expected Programmed=False Message=%q, got Status=%s Message=%q", mockPub.publishErr.Error(), progCond.Status, progCond.Message)
	}

	// 2. Conflict resolved: publisher succeeds, clearing the recorded error.
	mockPub.publishErr = nil
	st.Recompute()
	// Next recompute folds the cleared error into Gateway status, restoring Programmed=True.
	st.Recompute()

	status, ok = st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	progCond = nil
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			progCond = &status.Conditions[i]
			break
		}
	}
	if progCond == nil {
		t.Fatalf("expected Programmed condition")
	}
	if progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True when conflict resolved, got Status=%s Reason=%s", progCond.Status, progCond.Reason)
	}
}

type retryTestPublisher struct {
	mu           sync.Mutex
	failCount    int
	attemptTimes []time.Time
	published    map[types.NamespacedName]*DataplaneConfig
}

func (m *retryTestPublisher) Begin(ctx context.Context) error  { return nil }
func (m *retryTestPublisher) Commit(ctx context.Context) error { return nil }
func (m *retryTestPublisher) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *DataplaneConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attemptTimes = append(m.attemptTimes, time.Now())
	if m.failCount > 0 {
		m.failCount--
		return errors.New("simulated publish failure")
	}
	if m.published == nil {
		m.published = make(map[types.NamespacedName]*DataplaneConfig)
	}
	if gw != nil {
		m.published[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = config
	}
	return nil
}

func (m *retryTestPublisher) getPublished(key types.NamespacedName) *DataplaneConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.published[key]
}

func (m *retryTestPublisher) attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.attemptTimes)
}

func (m *retryTestPublisher) getAttemptTimes() []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]time.Time, len(m.attemptTimes))
	copy(res, m.attemptTimes)
	return res
}

func TestState_PublishDataplaneConfig_RetryOnFailure(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	mockPub := &retryTestPublisher{
		failCount: 1,
	}
	st.SetDataplanePublisher(mockPub)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- st.Start(ctx)
	}()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})

	// Wait for retry to publish without any other event.
	pollUntil(t, 2*time.Second, func() bool {
		return mockPub.getPublished(gwKey) != nil
	})

	published := mockPub.getPublished(gwKey)
	if published == nil {
		t.Fatalf("expected config to be published on retry with no other event")
	}
	if published.GatewayName != gwKey {
		t.Errorf("expected GatewayName %v, got %v", gwKey, published.GatewayName)
	}
	if mockPub.attempts() != 2 {
		t.Errorf("expected exactly 2 publish attempts (1 initial failure + 1 retry), got %d", mockPub.attempts())
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
}

func TestState_PublishDataplaneConfig_RepeatedFailuresBackoff(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	mockPub := &retryTestPublisher{
		failCount: 100, // always fail
	}
	st.SetDataplanePublisher(mockPub)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- st.Start(ctx)
	}()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})

	// Wait for at least 4 publish attempts without any other events.
	pollUntil(t, 2*time.Second, func() bool {
		return mockPub.attempts() >= 4
	})

	times := mockPub.getAttemptTimes()
	if len(times) < 4 {
		t.Fatalf("expected at least 4 attempts, got %d", len(times))
	}

	d1 := times[1].Sub(times[0])
	d2 := times[2].Sub(times[1])
	d3 := times[3].Sub(times[2])

	// Expected nominal backoffs are 50ms, 100ms, 200ms (+ 10ms coalesceDelay).
	// Verify intervals are non-spinning (greater than minimum threshold) and increasing.
	if d1 < 35*time.Millisecond {
		t.Errorf("expected d1 >= 35ms (not spinning), got %v", d1)
	}
	if d2 < 70*time.Millisecond {
		t.Errorf("expected d2 >= 70ms (not spinning), got %v", d2)
	}
	if d3 < 140*time.Millisecond {
		t.Errorf("expected d3 >= 140ms (not spinning), got %v", d3)
	}
	if d2 <= d1 {
		t.Errorf("expected backoff interval d2 (%v) > d1 (%v)", d2, d1)
	}
	if d3 <= d2 {
		t.Errorf("expected backoff interval d3 (%v) > d2 (%v)", d3, d2)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
}

func TestState_PublishDataplaneConfig_RetryCancelledOnGatewayDelete(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	mockPub := &retryTestPublisher{
		failCount: 100,
	}
	st.SetDataplanePublisher(mockPub)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- st.Start(ctx)
	}()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})

	// Wait for first failure
	pollUntil(t, 2*time.Second, func() bool {
		return mockPub.attempts() >= 1
	})

	// Delete Gateway
	st.DeleteGateway(gwKey)

	// Poll until recompute runs
	time.Sleep(100 * time.Millisecond)

	st.mu.Lock()
	retryCount := len(st.publishRetries)
	st.mu.Unlock()
	if retryCount != 0 {
		t.Errorf("expected 0 pending retries after Gateway deletion, got %d", retryCount)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
}

type countingProxyUpdater struct {
	mu          sync.Mutex
	updateCount int
}

func (c *countingProxyUpdater) UpdateConfig(listeners []InternalListener, routes []InternalRoute) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateCount++
}

func (c *countingProxyUpdater) UpdateCertificates(certs map[string]*tls.Certificate, defaultCert *tls.Certificate) {
}

func (c *countingProxyUpdater) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.updateCount
}

func recomputeCount(st *State) uint64 {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.recomputes
}

func pollUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !condition() {
		t.Fatalf("condition not met within %v", timeout)
	}
}

func TestState_SetSyncedDoesNotRecomputeDirectly(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetSynced(false)

	if recomputeCount(st) != 0 {
		t.Fatalf("expected 0 recomputes initially, got %d", recomputeCount(st))
	}

	st.SetSynced(true)
	if recomputeCount(st) != 0 {
		t.Fatalf("expected SetSynced(true) to not trigger recompute directly, got %d", recomputeCount(st))
	}

	st.Recompute()
	if recomputeCount(st) != 1 {
		t.Fatalf("expected Recompute() to perform exactly 1 recompute, got %d", recomputeCount(st))
	}
}

func TestState_StartInitialRecomputeOnce(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetSynced(false)

	updater := &countingProxyUpdater{}
	st.SetProxy(updater)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)

	if recomputeCount(st) != 0 {
		t.Fatalf("expected 0 recomputes before Start, got %d", recomputeCount(st))
	}
	if updater.Count() != 0 {
		t.Fatalf("expected 0 proxy updates before Start, got %d", updater.Count())
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- st.Start(ctx)
	}()

	// Poll until the initial recompute has completed.
	pollUntil(t, 2*time.Second, func() bool {
		return recomputeCount(st) >= 1
	})

	// Verify that the recompute count remains exactly 1 over a short window (no duplicate initial recompute).
	time.Sleep(30 * time.Millisecond)
	if got := recomputeCount(st); got != 1 {
		t.Fatalf("expected initial recompute to run exactly 1 time, got %d", got)
	}

	// Verify that only one proxy push reaches the data plane at startup.
	if got := updater.Count(); got != 1 {
		t.Fatalf("expected initial proxy update to run exactly 1 time, got %d", got)
	}

	// Mutate state while running; should trigger a coalesced recompute via notification channel.
	st.UpsertNamespace(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "new-ns"},
	})

	// Poll for the second recompute after mutation.
	pollUntil(t, 2*time.Second, func() bool {
		return recomputeCount(st) >= 2
	})

	time.Sleep(30 * time.Millisecond)
	if got := recomputeCount(st); got != 2 {
		t.Fatalf("expected 2 recomputes after mutation while running, got %d", got)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

func TestState_GatewayAddresses_UnsupportedType(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)

	// Case 1: Provider supports IPAddress, but Gateway requests test/fake-invalid-type
	st.SetSupportedAddressTypes([]gatewayv1.AddressType{gatewayv1.IPAddressType})

	invalidType := gatewayv1.AddressType("test/fake-invalid-type")
	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-invalid"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-invalid"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &invalidType, Value: "fake address"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw)
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress, got %+v", acceptedCond)
	}
	progCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonInvalid) {
		t.Errorf("expected Programmed=False Reason=Invalid when not accepted, got %+v", progCond)
	}
	if len(status.Addresses) != 0 {
		t.Errorf("expected no status addresses when address type is unsupported, got %+v", status.Addresses)
	}

	// Case 2: When provider declares NO supported types (default absent), any spec.addresses entry is UnsupportedAddress
	st2 := NewState()
	st2.SetControllerName("example.net/gateway-controller")
	st2.UpsertGatewayClass(gc)

	gwKey2 := types.NamespacedName{Namespace: "default", Name: "gw-default-none"}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-default-none"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: Ptr(gatewayv1.IPAddressType), Value: "192.0.2.1"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st2.UpsertGateway(gw2)
	st2.Recompute()

	status2, ok := st2.GetDesiredGatewayStatus(gwKey2)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond2 := findCondition(status2.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond2 == nil || acceptedCond2.Status != metav1.ConditionFalse || acceptedCond2.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress with default absent types, got %+v", acceptedCond2)
	}
}

func TestState_GatewayAddresses_AddressNotUsable(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetSupportedAddressTypes([]gatewayv1.AddressType{gatewayv1.IPAddressType})

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-unusable"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-unusable"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: Ptr(gatewayv1.IPAddressType), Value: "192.0.2.1"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw)

	// Provider reports AddressNotUsable readiness
	notUsableMsg := "Requested address 192.0.2.1 could not be bound to Service"
	st.SetGatewayAddresses(gwKey, nil)
	st.SetGatewayReadiness(gwKey, GatewayReadiness{
		Ready:   false,
		Reason:  string(gatewayv1.GatewayReasonAddressNotUsable),
		Message: notUsableMsg,
	})
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue || acceptedCond.Reason != string(gatewayv1.GatewayReasonAccepted) {
		t.Errorf("expected Accepted=True Reason=Accepted, got %+v", acceptedCond)
	}
	progCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) || progCond.Message != notUsableMsg {
		t.Errorf("expected Programmed=False Reason=AddressNotUsable Message=%q, got %+v", notUsableMsg, progCond)
	}
	if len(status.Addresses) != 0 {
		t.Errorf("expected no status addresses when address is not usable, got %+v", status.Addresses)
	}
}

func TestState_GatewayAddresses_BoundProgrammed(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetSupportedAddressTypes([]gatewayv1.AddressType{gatewayv1.IPAddressType})

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-bound"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-bound"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: Ptr(gatewayv1.IPAddressType), Value: "192.0.2.1"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw)

	// Provider reports bound address and Ready=true, also includes another unrelated address to test filtering
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{
		{Type: Ptr(gatewayv1.IPAddressType), Value: "192.0.2.1"},
		{Type: Ptr(gatewayv1.IPAddressType), Value: "10.0.0.99"},
	})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True, got %+v", acceptedCond)
	}
	progCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True Reason=Programmed, got %+v", progCond)
	}
	// Status addresses should contain exactly the requested bound address, nothing else
	if len(status.Addresses) != 1 {
		t.Fatalf("expected exactly 1 status address, got %d: %+v", len(status.Addresses), status.Addresses)
	}
	if status.Addresses[0].Value != "192.0.2.1" || *status.Addresses[0].Type != gatewayv1.IPAddressType {
		t.Errorf("expected status address 192.0.2.1 (IPAddress), got %+v", status.Addresses[0])
	}
}

func TestState_GatewayAddresses_EmptyValueNormalAllocation(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetSupportedAddressTypes([]gatewayv1.AddressType{gatewayv1.IPAddressType})

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-empty-val"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-empty-val"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: Ptr(gatewayv1.IPAddressType), Value: ""},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw)

	// Normal dynamic allocation assigns an IP
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{
		{Type: Ptr(gatewayv1.IPAddressType), Value: "10.0.0.5"},
	})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True, got %+v", acceptedCond)
	}
	progCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True Reason=Programmed, got %+v", progCond)
	}
	if len(status.Addresses) != 1 || status.Addresses[0].Value != "10.0.0.5" {
		t.Errorf("expected status address 10.0.0.5, got %+v", status.Addresses)
	}
}

func TestState_GatewayAddresses_NoSpecAddresses(t *testing.T) {
	st := NewState()
	st.SetControllerName("example.net/gateway-controller")

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-no-spec-addrs"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-no-spec-addrs"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw)

	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{
		{Type: Ptr(gatewayv1.IPAddressType), Value: "10.0.0.1"},
	})
	st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(gwKey)
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}
	acceptedCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True, got %+v", acceptedCond)
	}
	progCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True Reason=Programmed, got %+v", progCond)
	}
	if len(status.Addresses) != 1 || status.Addresses[0].Value != "10.0.0.1" {
		t.Errorf("expected status address 10.0.0.1, got %+v", status.Addresses)
	}
}

func TestState_GatewayCRDBundleVersionEnqueuesGatewayClass(t *testing.T) {
	st := NewState()
	st.SetControllerName("test-controller")

	qGC := newTestQueue()
	ctx := t.Context()
	_ = st.GatewayClassSource().Start(ctx, qGC)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc", Generation: 1},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gc)
	st.Recompute()

	// Initial reconcile without bundle version has Accepted=True, but no SupportedVersion condition
	qGC.drain()
	status, ok := st.GetDesiredGatewayClassStatus(types.NamespacedName{Name: "test-gc"})
	if !ok {
		t.Fatalf("expected desired GatewayClassStatus to be present")
	}
	if findCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion)) != nil {
		t.Fatalf("expected SupportedVersion condition to be absent before bundle version is set")
	}

	// Setting bundle version and recomputing adds SupportedVersion to outputs and enqueues GatewayClass
	bundleVersion := gatewayconsts.BundleVersion
	st.SetGatewayCRDBundleVersion(&bundleVersion)
	st.Recompute()

	enqueued := qGC.drain()
	if len(enqueued) != 1 || enqueued[0].Name != "test-gc" {
		t.Errorf("expected GatewayClass test-gc to be enqueued, got %v", enqueued)
	}

	status, ok = st.GetDesiredGatewayClassStatus(types.NamespacedName{Name: "test-gc"})
	if !ok {
		t.Fatalf("expected desired GatewayClassStatus to be present after recompute")
	}
	cond := findCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
	if cond == nil {
		t.Fatalf("expected SupportedVersion condition to be present after recompute, got nil")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayClassReasonSupportedVersion) {
		t.Errorf("expected SupportedVersion=True/SupportedVersion, got %+v", cond)
	}

	// Setting previous minor bundle version (N-1) keeps SupportedVersion=True
	compiledV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("failed to parse compiled bundle version %q: %v", gatewayconsts.BundleVersion, err)
	}
	prevMinor := fmt.Sprintf("v%d.%d.0", compiledV.Major(), compiledV.Minor()-1)
	st.SetGatewayCRDBundleVersion(&prevMinor)
	st.Recompute()

	status, ok = st.GetDesiredGatewayClassStatus(types.NamespacedName{Name: "test-gc"})
	if !ok {
		t.Fatalf("expected desired GatewayClassStatus to be present")
	}
	cond = findCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayClassReasonSupportedVersion) {
		t.Errorf("expected SupportedVersion=True/SupportedVersion for previous minor, got %+v", cond)
	}

	// Changing to mismatched bundle version (N-2) updates status and enqueues GatewayClass again
	mismatched := fmt.Sprintf("v%d.%d.0", compiledV.Major(), compiledV.Minor()-2)
	st.SetGatewayCRDBundleVersion(&mismatched)
	st.Recompute()

	enqueued = qGC.drain()
	if len(enqueued) != 1 || enqueued[0].Name != "test-gc" {
		t.Errorf("expected GatewayClass test-gc to be enqueued on version mismatch change, got %v", enqueued)
	}

	status, _ = st.GetDesiredGatewayClassStatus(types.NamespacedName{Name: "test-gc"})
	cond = findCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(gatewayv1.GatewayClassReasonUnsupportedVersion) {
		t.Errorf("expected SupportedVersion=False/UnsupportedVersion, got %+v", cond)
	}
}
