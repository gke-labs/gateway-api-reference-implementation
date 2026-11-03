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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSetCondition(t *testing.T) {
	var conditions []metav1.Condition

	t0 := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	c1 := NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted message", 1)
	c1.LastTransitionTime = t0

	// Add condition
	changed := SetCondition(&conditions, c1)
	if !changed {
		t.Errorf("expected changed=true for new condition")
	}
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}

	// Re-add identical condition -> no change
	c1Same := NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted message", 1)
	changed = SetCondition(&conditions, c1Same)
	if changed {
		t.Errorf("expected changed=false for identical condition")
	}
	if conditions[0].LastTransitionTime != t0 {
		t.Errorf("expected LastTransitionTime preserved, got %v", conditions[0].LastTransitionTime)
	}

	// Update condition message / reason only (same status) -> changed, but LastTransitionTime preserved
	c1Updated := NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "New message", 1)
	changed = SetCondition(&conditions, c1Updated)
	if !changed {
		t.Errorf("expected changed=true when message changes")
	}
	if conditions[0].Message != "New message" {
		t.Errorf("expected message 'New message', got %s", conditions[0].Message)
	}
	if conditions[0].LastTransitionTime != t0 {
		t.Errorf("expected LastTransitionTime preserved when status same, got %v", conditions[0].LastTransitionTime)
	}

	// Update condition status (True -> False) -> changed, LastTransitionTime updated
	c1StatusChanged := NewCondition("Accepted", metav1.ConditionFalse, "Rejected", "Rejected message", 1)
	changed = SetCondition(&conditions, c1StatusChanged)
	if !changed {
		t.Errorf("expected changed=true when status changes")
	}
	if conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("expected status False, got %v", conditions[0].Status)
	}
	if conditions[0].LastTransitionTime == t0 {
		t.Errorf("expected LastTransitionTime updated when status changes")
	}
}

func TestSetConditions(t *testing.T) {
	var conditions []metav1.Condition

	newConds := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
		NewCondition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs", "ResolvedRefs", 1),
	}

	changed := SetConditions(&conditions, newConds)
	if !changed || len(conditions) != 2 {
		t.Fatalf("expected 2 conditions added, changed=%v", changed)
	}

	// Idempotent
	changed = SetConditions(&conditions, newConds)
	if changed {
		t.Errorf("expected changed=false for same conditions")
	}

	// Remove one condition
	reducedConds := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
	}
	changed = SetConditions(&conditions, reducedConds)
	if !changed || len(conditions) != 1 {
		t.Errorf("expected 1 condition remaining, changed=%v", changed)
	}
}

func sameCondition(a, b *metav1.Condition) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type == b.Type &&
		a.Status == b.Status &&
		a.Reason == b.Reason &&
		a.Message == b.Message &&
		a.ObservedGeneration == b.ObservedGeneration &&
		a.LastTransitionTime.Equal(&b.LastTransitionTime)
}

func TestMergeConditions(t *testing.T) {
	ownedTypes := map[string]bool{
		"Accepted":                       true,
		"Programmed":                     true,
		"InsecureFrontendValidationMode": true,
	}

	t0 := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	foreignCond := metav1.Condition{
		Type:               "conformance.gateway.networking.k8s.io/StaleCondition",
		Status:             metav1.ConditionTrue,
		Reason:             "Seeded",
		Message:            "Foreign condition message",
		ObservedGeneration: 1,
		LastTransitionTime: t0,
	}

	// 1. Initial merge on existing slice containing foreign condition
	existing := []metav1.Condition{
		foreignCond,
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
	}

	desired := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
		NewCondition("Programmed", metav1.ConditionTrue, "Programmed", "Programmed", 1),
	}

	changed := MergeConditions(&existing, desired, ownedTypes)
	if !changed {
		t.Fatalf("expected changed=true when Programmed was added")
	}

	// Check foreign condition is still present and unchanged
	foundForeign := FindCondition(existing, "conformance.gateway.networking.k8s.io/StaleCondition")
	if foundForeign == nil {
		t.Fatalf("expected foreign condition to be preserved")
	}
	if !sameCondition(foundForeign, &foreignCond) {
		t.Errorf("foreign condition was modified: got %+v, want %+v", *foundForeign, foreignCond)
	}

	// 2. Idempotent merge with no changes to owned conditions must return false (no-op)
	changed = MergeConditions(&existing, desired, ownedTypes)
	if changed {
		t.Errorf("expected changed=false when desired conditions are unchanged")
	}

	// 3. Foreign condition survives status change of owned condition
	desiredUpdated := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionFalse, "ListenersNotValid", "Listeners invalid", 2),
		NewCondition("Programmed", metav1.ConditionTrue, "Programmed", "Programmed", 2),
	}
	changed = MergeConditions(&existing, desiredUpdated, ownedTypes)
	if !changed {
		t.Fatalf("expected changed=true when Accepted changed")
	}
	foundForeign = FindCondition(existing, "conformance.gateway.networking.k8s.io/StaleCondition")
	if foundForeign == nil || !sameCondition(foundForeign, &foreignCond) {
		t.Errorf("foreign condition was not preserved after update: %+v", foundForeign)
	}

	// 4. Stale owned condition is removed, foreign condition is kept
	existingWithStaleOwned := []metav1.Condition{
		foreignCond,
		NewCondition("InsecureFrontendValidationMode", metav1.ConditionTrue, "ConfigChanged", "Fallback", 1),
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
	}
	desiredWithoutStale := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
	}
	changed = MergeConditions(&existingWithStaleOwned, desiredWithoutStale, ownedTypes)
	if !changed {
		t.Fatalf("expected changed=true when InsecureFrontendValidationMode was removed")
	}
	if FindCondition(existingWithStaleOwned, "InsecureFrontendValidationMode") != nil {
		t.Errorf("expected InsecureFrontendValidationMode to be removed")
	}
	if FindCondition(existingWithStaleOwned, "conformance.gateway.networking.k8s.io/StaleCondition") == nil {
		t.Errorf("expected foreign condition to be preserved")
	}
}

func TestMergeGatewayStatus_PreservesForeignConditions(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	foreignGwCond := metav1.Condition{
		Type:               "conformance.gateway.networking.k8s.io/StaleCondition",
		Status:             metav1.ConditionTrue,
		Reason:             "Seeded",
		Message:            "Foreign GW",
		ObservedGeneration: 1,
		LastTransitionTime: t0,
	}
	foreignListenerCond := metav1.Condition{
		Type:               "conformance.gateway.networking.k8s.io/StaleCondition",
		Status:             metav1.ConditionTrue,
		Reason:             "SeededListener",
		Message:            "Foreign Listener",
		ObservedGeneration: 1,
		LastTransitionTime: t0,
	}

	current := gatewayv1.GatewayStatus{
		Conditions: []metav1.Condition{
			foreignGwCond,
			NewCondition(string(gatewayv1.GatewayConditionAccepted), metav1.ConditionTrue, "Accepted", "Accepted", 1),
		},
		Listeners: []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					foreignListenerCond,
					NewCondition(string(gatewayv1.ListenerConditionProgrammed), metav1.ConditionTrue, "Programmed", "Programmed", 1),
				},
				SupportedKinds: []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}},
			},
		},
	}

	desired := gatewayv1.GatewayStatus{
		Conditions: []metav1.Condition{
			NewCondition(string(gatewayv1.GatewayConditionAccepted), metav1.ConditionTrue, "Accepted", "Accepted", 1),
			NewCondition(string(gatewayv1.GatewayConditionProgrammed), metav1.ConditionTrue, "Programmed", "Programmed", 1),
		},
		Listeners: []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					NewCondition(string(gatewayv1.ListenerConditionProgrammed), metav1.ConditionTrue, "Programmed", "Programmed", 1),
					NewCondition(string(gatewayv1.ListenerConditionAccepted), metav1.ConditionTrue, "Accepted", "Accepted", 1),
				},
				SupportedKinds: []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}},
			},
		},
	}

	// Merge with additions: Programmed on GW, Accepted on listener
	changed := MergeGatewayStatus(&current, desired)
	if !changed {
		t.Fatalf("expected changed=true on initial merge")
	}

	// Verify foreign conditions survive
	storedGw := FindCondition(current.Conditions, "conformance.gateway.networking.k8s.io/StaleCondition")
	if storedGw == nil || !sameCondition(storedGw, &foreignGwCond) {
		t.Fatalf("foreign Gateway condition was lost or modified: got %+v, want %+v", storedGw, foreignGwCond)
	}

	storedListener := FindCondition(current.Listeners[0].Conditions, "conformance.gateway.networking.k8s.io/StaleCondition")
	if storedListener == nil || !sameCondition(storedListener, &foreignListenerCond) {
		t.Fatalf("foreign Listener condition was lost or modified: got %+v, want %+v", storedListener, foreignListenerCond)
	}

	// Merge again without changes -> must be a no-op (return false)
	changed = MergeGatewayStatus(&current, desired)
	if changed {
		t.Errorf("expected changed=false on second merge with identical desired status")
	}
}

// TestOwnedConditionTypes_CoversComputedConditions verifies that every condition type
// produced on a Gateway or its listeners during state compilation is registered in
// GatewayOwnedConditionTypes or ListenerOwnedConditionTypes.
func TestOwnedConditionTypes_CoversComputedConditions(t *testing.T) {
	st := NewState()
	st.SetControllerName("test-controller")

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gwClass)

	// Case 1: Standard HTTP Gateway.
	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-standard"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw1)

	// Case 2: Gateway with insecure fallback listener (produces InsecureFrontendValidationMode).
	caPEM, _ := generateTestCertPEM(t, "ca.example.com")
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ca-config"},
		Data:       map[string]string{ConfigMapCACertKey: string(caPEM)},
	}
	st.UpsertConfigMap(caConfigMap)
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-fallback"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: []gatewayv1.ObjectReference{
								{Kind: "ConfigMap", Group: "", Name: "ca-config"},
							},
							Mode: gatewayv1.AllowInsecureFallback,
						},
					},
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	st.UpsertGateway(gw2)

	// Case 3: Gateway with overlapping TLS listeners (produces OverlappingTLSConfig).
	certPEM1, keyPEM1 := generateTestCertPEM(t, "*.example.com", "foo.example.com")
	secret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-1"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM1,
			corev1.TLSPrivateKeyKey: keyPEM1,
		},
	}
	st.UpsertSecret(secret1)
	certPEM2, keyPEM2 := generateTestCertPEM(t, "foo.example.com")
	secret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-2"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM2,
			corev1.TLSPrivateKeyKey: keyPEM2,
		},
	}
	st.UpsertSecret(secret2)
	gw3 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-overlapping"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls-wildcard",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-1"},
						},
					},
				},
				{
					Name:     "tls-exact",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-2"},
						},
					},
				},
			},
		},
	}
	st.UpsertGateway(gw3)

	// Case 4: Gateway with port conflict (produces Conflicted).
	gw4 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-conflicted"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "tcp", Port: 8080, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}
	st.UpsertGateway(gw4)

	st.Recompute()

	gateways := []*gatewayv1.Gateway{gw1, gw2, gw3, gw4}
	for _, gw := range gateways {
		key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		status, ok := st.GetDesiredGatewayStatus(key)
		if !ok {
			t.Fatalf("expected desired status for gateway %s", key)
		}

		for _, cond := range status.Conditions {
			if !GatewayOwnedConditionTypes[cond.Type] {
				t.Errorf("Gateway %s has condition %q which is missing from GatewayOwnedConditionTypes", key, cond.Type)
			}
		}

		for _, lis := range status.Listeners {
			for _, cond := range lis.Conditions {
				if !ListenerOwnedConditionTypes[cond.Type] {
					t.Errorf("Gateway %s listener %s has condition %q which is missing from ListenerOwnedConditionTypes", key, lis.Name, cond.Type)
				}
			}
		}
	}
}

func TestConditionsEqual(t *testing.T) {
	c1 := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Msg", 1),
	}
	c2 := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Msg", 1),
	}
	c3 := []metav1.Condition{
		NewCondition("Accepted", metav1.ConditionFalse, "Accepted", "Msg", 1),
	}

	if !ConditionsEqual(c1, c2) {
		t.Errorf("expected c1 and c2 to be equal")
	}
	if ConditionsEqual(c1, c3) {
		t.Errorf("expected c1 and c3 NOT to be equal")
	}
}

func TestUpdateRouteParentStatuses(t *testing.T) {
	parentRef := gatewayv1.ParentReference{Name: "gw-1"}
	controller := gatewayv1.GatewayController("example.com/controller")

	t0 := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	existing := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      parentRef,
			ControllerName: controller,
			Conditions: []metav1.Condition{
				{
					Type:               "Accepted",
					Status:             metav1.ConditionTrue,
					Reason:             "Accepted",
					Message:            "Route accepted",
					ObservedGeneration: 1,
					LastTransitionTime: t0,
				},
			},
		},
	}

	desired := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      parentRef,
			ControllerName: controller,
			Conditions: []metav1.Condition{
				NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Route accepted", 1),
				NewCondition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs", "Resolved", 1),
			},
		},
	}

	result, updated := UpdateRouteParentStatuses(existing, desired, "", controller)
	if !updated {
		t.Errorf("expected updated=true when adding ResolvedRefs condition")
	}
	if len(result[0].Conditions) != 2 {
		t.Fatalf("expected 2 conditions in result, got %d", len(result[0].Conditions))
	}
	if result[0].Conditions[0].LastTransitionTime != t0 {
		t.Errorf("expected Accepted LastTransitionTime preserved, got %v", result[0].Conditions[0].LastTransitionTime)
	}

	// Test ObservedGeneration bump
	desiredBumped := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      parentRef,
			ControllerName: controller,
			Conditions: []metav1.Condition{
				NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Route accepted", 2),
				NewCondition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs", "Resolved", 2),
			},
		},
	}
	resultBumped, updatedBumped := UpdateRouteParentStatuses(result, desiredBumped, "", controller)
	if !updatedBumped {
		t.Errorf("expected updated=true when observedGeneration changes")
	}
	if resultBumped[0].Conditions[0].ObservedGeneration != 2 {
		t.Errorf("expected ObservedGeneration 2, got %d", resultBumped[0].Conditions[0].ObservedGeneration)
	}
	if resultBumped[0].Conditions[0].LastTransitionTime != t0 {
		t.Errorf("expected Accepted LastTransitionTime preserved on generation bump, got %v", resultBumped[0].Conditions[0].LastTransitionTime)
	}
}

func TestUpdateRouteParentStatuses_MultiController(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("my-org/gateway-controller")
	otherCtrl := gatewayv1.GatewayController("other-org/other-controller")

	p1 := gatewayv1.ParentReference{Name: "gw-1"}
	p2 := gatewayv1.ParentReference{Name: "gw-2"}
	pOther := gatewayv1.ParentReference{Name: "gw-other"}

	t0 := metav1.NewTime(time.Now().Add(-10 * time.Minute))

	c1 := NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1)
	c1.LastTransitionTime = t0
	cOther := NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1)
	cOther.LastTransitionTime = t0

	existing := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      p1,
			ControllerName: myCtrl,
			Conditions:     []metav1.Condition{c1},
		},
		{
			ParentRef:      pOther,
			ControllerName: otherCtrl,
			Conditions:     []metav1.Condition{cOther},
		},
	}

	// Case 1: myCtrl updates p1, pOther from otherCtrl must be preserved
	desired := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      p1,
			ControllerName: myCtrl,
			Conditions: []metav1.Condition{
				NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
			},
		},
	}

	res, updated := UpdateRouteParentStatuses(existing, desired, "", myCtrl)
	if updated {
		t.Errorf("expected updated=false when nothing changed for myCtrl")
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 parent statuses (including other controller), got %d", len(res))
	}

	// Case 2: myCtrl replaces p1 with p2. p1 is removed, p2 added, pOther preserved.
	desiredP2 := []gatewayv1.RouteParentStatus{
		{
			ParentRef:      p2,
			ControllerName: myCtrl,
			Conditions: []metav1.Condition{
				NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1),
			},
		},
	}
	res2, updated2 := UpdateRouteParentStatuses(existing, desiredP2, "", myCtrl)
	if !updated2 {
		t.Errorf("expected updated=true when parentRef changed for myCtrl")
	}
	if len(res2) != 2 {
		t.Fatalf("expected 2 parent statuses, got %d", len(res2))
	}
	var foundP2, foundOther, foundP1 bool
	for _, p := range res2 {
		if p.ControllerName == myCtrl && p.ParentRef.Name == "gw-2" {
			foundP2 = true
		}
		if p.ControllerName == otherCtrl && p.ParentRef.Name == "gw-other" {
			foundOther = true
		}
		if p.ControllerName == myCtrl && p.ParentRef.Name == "gw-1" {
			foundP1 = true
		}
	}
	if !foundP2 || !foundOther || foundP1 {
		t.Errorf("expected p2 and pOther present and p1 removed, got foundP2=%v, foundOther=%v, foundP1=%v", foundP2, foundOther, foundP1)
	}

	// Case 3: myCtrl removes all its parentRefs. pOther must still be preserved.
	res3, updated3 := UpdateRouteParentStatuses(existing, nil, "", myCtrl)
	if !updated3 {
		t.Errorf("expected updated=true when myCtrl parentRefs removed")
	}
	if len(res3) != 1 || res3[0].ControllerName != otherCtrl {
		t.Errorf("expected only otherCtrl parent preserved, got %+v", res3)
	}
}

func ptr[T any](v T) *T {
	return &v
}

func TestCompareParentReference(t *testing.T) {
	routeNS := "test-ns"

	tests := []struct {
		name     string
		a        gatewayv1.ParentReference
		b        gatewayv1.ParentReference
		expected int
	}{
		{
			name:     "identical references",
			a:        gatewayv1.ParentReference{Name: "gw-1"},
			b:        gatewayv1.ParentReference{Name: "gw-1"},
			expected: 0,
		},
		{
			name:     "group comparison normalized",
			a:        gatewayv1.ParentReference{Group: ptr(gatewayv1.Group("custom.io")), Name: "gw-1"},
			b:        gatewayv1.ParentReference{Group: ptr(gatewayv1.Group("gateway.networking.k8s.io")), Name: "gw-1"},
			expected: -1,
		},
		{
			name:     "nil group matches standard gateway group",
			a:        gatewayv1.ParentReference{Group: nil, Name: "gw-1"},
			b:        gatewayv1.ParentReference{Group: ptr(gatewayv1.Group("gateway.networking.k8s.io")), Name: "gw-1"},
			expected: 0,
		},
		{
			name:     "kind comparison normalized (Gateway vs ListenerSet)",
			a:        gatewayv1.ParentReference{Kind: ptr(gatewayv1.Kind("Gateway")), Name: "gw-1"},
			b:        gatewayv1.ParentReference{Kind: ptr(gatewayv1.Kind("ListenerSet")), Name: "gw-1"},
			expected: -1,
		},
		{
			name:     "nil kind matches Gateway",
			a:        gatewayv1.ParentReference{Kind: nil, Name: "gw-1"},
			b:        gatewayv1.ParentReference{Kind: ptr(gatewayv1.Kind("Gateway")), Name: "gw-1"},
			expected: 0,
		},
		{
			name:     "namespace comparison with default route namespace",
			a:        gatewayv1.ParentReference{Namespace: nil, Name: "gw-1"},
			b:        gatewayv1.ParentReference{Namespace: ptr(gatewayv1.Namespace("test-ns")), Name: "gw-1"},
			expected: 0,
		},
		{
			name:     "different namespaces",
			a:        gatewayv1.ParentReference{Namespace: ptr(gatewayv1.Namespace("alpha")), Name: "gw-1"},
			b:        gatewayv1.ParentReference{Namespace: ptr(gatewayv1.Namespace("beta")), Name: "gw-1"},
			expected: -1,
		},
		{
			name:     "different names",
			a:        gatewayv1.ParentReference{Name: "gw-a"},
			b:        gatewayv1.ParentReference{Name: "gw-b"},
			expected: -1,
		},
		{
			name:     "different sectionNames",
			a:        gatewayv1.ParentReference{Name: "gw-1", SectionName: ptr(gatewayv1.SectionName("http"))},
			b:        gatewayv1.ParentReference{Name: "gw-1", SectionName: ptr(gatewayv1.SectionName("https"))},
			expected: -1,
		},
		{
			name:     "nil sectionName before non-nil",
			a:        gatewayv1.ParentReference{Name: "gw-1", SectionName: nil},
			b:        gatewayv1.ParentReference{Name: "gw-1", SectionName: ptr(gatewayv1.SectionName("http"))},
			expected: -1,
		},
		{
			name:     "different ports",
			a:        gatewayv1.ParentReference{Name: "gw-1", Port: ptr(gatewayv1.PortNumber(80))},
			b:        gatewayv1.ParentReference{Name: "gw-1", Port: ptr(gatewayv1.PortNumber(443))},
			expected: -1,
		},
		{
			name:     "nil port before non-nil",
			a:        gatewayv1.ParentReference{Name: "gw-1", Port: nil},
			b:        gatewayv1.ParentReference{Name: "gw-1", Port: ptr(gatewayv1.PortNumber(80))},
			expected: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CompareParentReference(tc.a, tc.b, routeNS)
			if (tc.expected < 0 && got >= 0) || (tc.expected > 0 && got <= 0) || (tc.expected == 0 && got != 0) {
				t.Errorf("CompareParentReference(%+v, %+v) = %d, expected sign of %d", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}

func TestUpdateRouteParentStatuses_DeterministicOrder(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("my-org/gateway-controller")

	p1 := gatewayv1.ParentReference{Name: "gw-a", SectionName: ptr(gatewayv1.SectionName("http"))}
	p2 := gatewayv1.ParentReference{Name: "gw-a", SectionName: ptr(gatewayv1.SectionName("https"))}
	p3 := gatewayv1.ParentReference{Name: "gw-b"}
	p4 := gatewayv1.ParentReference{Group: ptr(gatewayv1.Group("gateway.networking.k8s.io")), Kind: ptr(gatewayv1.Kind("ListenerSet")), Name: "ls-1"}

	c := []metav1.Condition{NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1)}

	// Desired entries provided in order: p4, p3, p2, p1
	desired1 := []gatewayv1.RouteParentStatus{
		{ParentRef: p4, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p3, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p2, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p1, ControllerName: myCtrl, Conditions: c},
	}

	// Desired entries provided in reverse order: p1, p2, p3, p4
	desired2 := []gatewayv1.RouteParentStatus{
		{ParentRef: p1, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p2, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p3, ControllerName: myCtrl, Conditions: c},
		{ParentRef: p4, ControllerName: myCtrl, Conditions: c},
	}

	res1, _ := UpdateRouteParentStatuses(nil, desired1, "default", myCtrl)
	res2, _ := UpdateRouteParentStatuses(nil, desired2, "default", myCtrl)

	if len(res1) != 4 || len(res2) != 4 {
		t.Fatalf("expected 4 parent statuses, got res1=%d res2=%d", len(res1), len(res2))
	}

	for i := range res1 {
		if CompareParentReference(res1[i].ParentRef, res2[i].ParentRef, "default") != 0 {
			t.Errorf("at index %d: res1 parentRef %+v != res2 parentRef %+v", i, res1[i].ParentRef, res2[i].ParentRef)
		}
	}

	// Expected sorted order:
	// 1. Gateway default/gw-a section=http (p1)
	// 2. Gateway default/gw-a section=https (p2)
	// 3. Gateway default/gw-b (p3)
	// 4. ListenerSet default/ls-1 (p4)
	if res1[0].ParentRef.Name != "gw-a" || ValueOf(res1[0].ParentRef.SectionName) != "http" {
		t.Errorf("expected res1[0] to be gw-a/http, got %+v", res1[0].ParentRef)
	}
	if res1[1].ParentRef.Name != "gw-a" || ValueOf(res1[1].ParentRef.SectionName) != "https" {
		t.Errorf("expected res1[1] to be gw-a/https, got %+v", res1[1].ParentRef)
	}
	if res1[2].ParentRef.Name != "gw-b" {
		t.Errorf("expected res1[2] to be gw-b, got %+v", res1[2].ParentRef)
	}
	if res1[3].ParentRef.Name != "ls-1" || normalizeKind(res1[3].ParentRef.Kind) != "ListenerSet" {
		t.Errorf("expected res1[3] to be ListenerSet/ls-1, got %+v", res1[3].ParentRef)
	}
}

func TestUpdateRouteParentStatuses_OtherControllersPreservedOrderAndAfterOurs(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("my-org/my-ctrl")
	otherCtrl1 := gatewayv1.GatewayController("other-org/ctrl-1")
	otherCtrl2 := gatewayv1.GatewayController("other-org/ctrl-2")

	c := []metav1.Condition{NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1)}

	existing := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "z-parent"}, ControllerName: otherCtrl1, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "a-parent"}, ControllerName: otherCtrl2, Conditions: c},
	}

	desired := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
	}

	res, updated := UpdateRouteParentStatuses(existing, desired, "default", myCtrl)
	if !updated {
		t.Errorf("expected updated=true when adding gw-a")
	}

	// Result should have:
	// 1. myCtrl / gw-a
	// 2. myCtrl / gw-b
	// 3. otherCtrl1 / z-parent (preserved relative order)
	// 4. otherCtrl2 / a-parent (preserved relative order)
	if len(res) != 4 {
		t.Fatalf("expected 4 parent statuses, got %d", len(res))
	}

	if res[0].ControllerName != myCtrl || res[0].ParentRef.Name != "gw-a" {
		t.Errorf("expected res[0] to be myCtrl/gw-a, got %+v", res[0])
	}
	if res[1].ControllerName != myCtrl || res[1].ParentRef.Name != "gw-b" {
		t.Errorf("expected res[1] to be myCtrl/gw-b, got %+v", res[1])
	}
	if res[2].ControllerName != otherCtrl1 || res[2].ParentRef.Name != "z-parent" {
		t.Errorf("expected res[2] to be otherCtrl1/z-parent, got %+v", res[2])
	}
	if res[3].ControllerName != otherCtrl2 || res[3].ParentRef.Name != "a-parent" {
		t.Errorf("expected res[3] to be otherCtrl2/a-parent, got %+v", res[3])
	}
}

func TestUpdateRouteParentStatuses_OrderOnlyDifferenceNotAnUpdate(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("my-org/my-ctrl")
	otherCtrl := gatewayv1.GatewayController("other-org/other-ctrl")

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

	// Existing has other controller first, then our entries in unsorted order
	existing := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-other"}, ControllerName: otherCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
	}

	desired := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
	}

	res, updated := UpdateRouteParentStatuses(existing, desired, "default", myCtrl)
	if updated {
		t.Errorf("expected updated=false when only ordering differs")
	}

	// Verify that res is still returned in sorted order (our entries sorted, otherCtrl after)
	if len(res) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(res))
	}
	if res[0].ControllerName != myCtrl || res[0].ParentRef.Name != "gw-a" {
		t.Errorf("expected res[0] to be myCtrl/gw-a, got %+v", res[0])
	}
	if res[1].ControllerName != myCtrl || res[1].ParentRef.Name != "gw-b" {
		t.Errorf("expected res[1] to be myCtrl/gw-b, got %+v", res[1])
	}
	if res[2].ControllerName != otherCtrl || res[2].ParentRef.Name != "gw-other" {
		t.Errorf("expected res[2] to be otherCtrl/gw-other, got %+v", res[2])
	}
}

func TestUpdateRouteParentStatuses_AddRemoveEntriesStability(t *testing.T) {
	myCtrl := gatewayv1.GatewayController("my-org/my-ctrl")
	otherCtrl := gatewayv1.GatewayController("other-org/other-ctrl")

	c := []metav1.Condition{NewCondition("Accepted", metav1.ConditionTrue, "Accepted", "Accepted", 1)}

	existing := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-c"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-z"}, ControllerName: otherCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-y"}, ControllerName: otherCtrl, Conditions: c},
	}

	// 1. Adding gw-b
	desiredAdd := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-c"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-b"}, ControllerName: myCtrl, Conditions: c},
		{ParentRef: gatewayv1.ParentReference{Name: "gw-a"}, ControllerName: myCtrl, Conditions: c},
	}

	resAdd, updatedAdd := UpdateRouteParentStatuses(existing, desiredAdd, "default", myCtrl)
	if !updatedAdd {
		t.Errorf("expected updated=true when adding gw-b")
	}
	if len(resAdd) != 5 {
		t.Fatalf("expected 5 parent statuses, got %d", len(resAdd))
	}
	expectedNamesAdd := []string{"gw-a", "gw-b", "gw-c", "gw-z", "gw-y"}
	for i, exp := range expectedNamesAdd {
		if resAdd[i].ParentRef.Name != gatewayv1.ObjectName(exp) {
			t.Errorf("at index %d: expected name %q, got %q", i, exp, resAdd[i].ParentRef.Name)
		}
	}

	// 2. Removing gw-a
	desiredRemove := []gatewayv1.RouteParentStatus{
		{ParentRef: gatewayv1.ParentReference{Name: "gw-c"}, ControllerName: myCtrl, Conditions: c},
	}
	resRemove, updatedRemove := UpdateRouteParentStatuses(existing, desiredRemove, "default", myCtrl)
	if !updatedRemove {
		t.Errorf("expected updated=true when removing gw-a")
	}
	if len(resRemove) != 3 {
		t.Fatalf("expected 3 parent statuses, got %d", len(resRemove))
	}
	expectedNamesRemove := []string{"gw-c", "gw-z", "gw-y"}
	for i, exp := range expectedNamesRemove {
		if resRemove[i].ParentRef.Name != gatewayv1.ObjectName(exp) {
			t.Errorf("at index %d: expected name %q, got %q", i, exp, resRemove[i].ParentRef.Name)
		}
	}
}
