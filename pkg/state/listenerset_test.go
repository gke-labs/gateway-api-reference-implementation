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

func TestIsListenerSetParent(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
	}

	tests := []struct {
		name     string
		ls       *gatewayv1.ListenerSet
		expected bool
	}{
		{
			name: "exact match same namespace",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ls-1",
					Namespace: "default",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name: "test-gw",
					},
				},
			},
			expected: true,
		},
		{
			name: "explicit namespace match",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ls-2",
					Namespace: "other-ns",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name:      "test-gw",
						Namespace: Ptr(gatewayv1.Namespace("default")),
					},
				},
			},
			expected: true,
		},
		{
			name: "different gateway name",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ls-3",
					Namespace: "default",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name: "other-gw",
					},
				},
			},
			expected: false,
		},
		{
			name: "unsupported parent group",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ls-4",
					Namespace: "default",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Group: Ptr(gatewayv1.Group("example.com")),
						Name:  "test-gw",
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsListenerSetParent(tt.ls, gw)
			if got != tt.expected {
				t.Errorf("IsListenerSetParent() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsListenerSetAllowed(t *testing.T) {
	sameFrom := gatewayv1.NamespacesFromSame
	allFrom := gatewayv1.NamespacesFromAll
	noneFrom := gatewayv1.NamespacesFromNone
	selectorFrom := gatewayv1.NamespacesFromSelector

	namespaces := map[string]*corev1.Namespace{
		"default": {
			ObjectMeta: metav1.ObjectMeta{
				Name:   "default",
				Labels: map[string]string{"env": "prod"},
			},
		},
		"tenant-a": {
			ObjectMeta: metav1.ObjectMeta{
				Name:   "tenant-a",
				Labels: map[string]string{"env": "prod", "tenant": "a"},
			},
		},
		"tenant-b": {
			ObjectMeta: metav1.ObjectMeta{
				Name:   "tenant-b",
				Labels: map[string]string{"env": "dev"},
			},
		},
	}

	tests := []struct {
		name     string
		gw       *gatewayv1.Gateway
		ls       *gatewayv1.ListenerSet
		expected bool
	}{
		{
			name: "default not allowed (nil AllowedListeners)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
			},
			expected: false,
		},
		{
			name: "AllowedListeners From: None",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &noneFrom,
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
			},
			expected: false,
		},
		{
			name: "AllowedListeners From: Same (same namespace)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &sameFrom,
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
			},
			expected: true,
		},
		{
			name: "AllowedListeners From: Same (different namespace)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &sameFrom,
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "tenant-a"},
			},
			expected: false,
		},
		{
			name: "AllowedListeners From: All (different namespace)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &allFrom,
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "tenant-a"},
			},
			expected: true,
		},
		{
			name: "AllowedListeners From: Selector (matches labels)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &selectorFrom,
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "tenant-a"},
			},
			expected: true,
		},
		{
			name: "AllowedListeners From: Selector (does not match labels)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &selectorFrom,
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
						},
					},
				},
			},
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "tenant-b"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsListenerSetAllowed(tt.ls, tt.gw, namespaces)
			if got != tt.expected {
				t.Errorf("IsListenerSetAllowed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStateListenerSetOperations(t *testing.T) {
	st := NewState()
	now := time.Now()

	ls1 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ls-b",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(1 * time.Minute)),
		},
	}
	ls2 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ls-a",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now),
		},
	}

	st.UpsertListenerSet(ls1)
	st.UpsertListenerSet(ls2)

	got := st.GetListenerSets()
	if len(got) != 2 {
		t.Fatalf("expected 2 ListenerSets, got %d", len(got))
	}
	if got[0].Name != "ls-a" || got[1].Name != "ls-b" {
		t.Errorf("expected sorted [ls-a, ls-b], got [%s, %s]", got[0].Name, got[1].Name)
	}

	st.DeleteListenerSet(types.NamespacedName{Namespace: "default", Name: "ls-a"})
	got = st.GetListenerSets()
	if len(got) != 1 || got[0].Name != "ls-b" {
		t.Errorf("expected 1 ListenerSet [ls-b], got %v", got)
	}
}

func TestListenerSet_AllowedRoutesSupportedKinds_TLSInvalidKinds(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-allowed-ls",
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
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromAll),
				},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ls-tls-invalid-kind",
			Namespace: "default",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "gw-allowed-ls",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "tls-listener",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &passthroughMode,
					},
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "HTTPRoute"},
						},
					},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ListenerSets:   []*gatewayv1.ListenerSet{ls},
		ControllerName: "example.net/gateway-controller",
	}

	outputs := ComputeOutputs(inputs)

	// Parent Gateway must remain Accepted=True
	gwStatus, ok := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "gw-allowed-ls"}]
	if !ok {
		t.Fatalf("expected status for gateway")
	}
	var gwAcceptedCond *metav1.Condition
	for _, c := range gwStatus.Conditions {
		if c.Type == string(gatewayv1.GatewayConditionAccepted) {
			gwAcceptedCond = &c
			break
		}
	}
	if gwAcceptedCond == nil || gwAcceptedCond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Gateway Accepted=True, got %+v", gwAcceptedCond)
	}

	// ListenerSet listener status must have ResolvedRefs=False with reason InvalidRouteKinds, and supportedKinds empty
	lsStatus, ok := outputs.ListenerSetStatuses[types.NamespacedName{Namespace: "default", Name: "ls-tls-invalid-kind"}]
	if !ok {
		t.Fatalf("expected status for listener set")
	}
	if len(lsStatus.Listeners) != 1 {
		t.Fatalf("expected 1 listener in listener set status, got %d", len(lsStatus.Listeners))
	}
	lStatus := lsStatus.Listeners[0]
	if len(lStatus.SupportedKinds) != 0 {
		t.Errorf("expected empty supportedKinds, got %v", lStatus.SupportedKinds)
	}

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

func TestState_OnGatewaysUpdate_ListenerSetLifecycle(t *testing.T) {
	controllerState := NewState()
	controllerState.SetControllerName("example.net/gateway-controller")

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "shared-gw"}
	var listenerSnapshots [][]*EffectiveListener
	controllerState.SetOnGatewaysUpdate(func(gateways []*gatewayv1.Gateway) {
		var listeners []*EffectiveListener
		for _, gateway := range gateways {
			key := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
			listeners = append(listeners, controllerState.GetEffectiveListeners(key)...)
		}
		listenerSnapshots = append(listenerSnapshots, listeners)
	})

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "shared-gw",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromSame),
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "default", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	controllerState.UpsertGatewayClass(gatewayClass)
	controllerState.UpsertGateway(gateway)
	controllerState.Recompute()
	if len(listenerSnapshots) != 1 || len(listenerSnapshots[0]) != 1 {
		t.Fatalf("expected 1 callback with 1 listener after Gateway upsert, got %d callbacks", len(listenerSnapshots))
	}

	// Add ListenerSet without changing the Gateway: callback must fire.
	listenerSet := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "app-ls",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "shared-gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("v1.example.com")),
				},
			},
		},
	}
	controllerState.UpsertListenerSet(listenerSet)
	controllerState.Recompute()
	if len(listenerSnapshots) != 2 || len(listenerSnapshots[1]) != 2 {
		t.Fatalf("expected 2 callbacks with 2 effective listeners after ListenerSet add, got %d callbacks", len(listenerSnapshots))
	}

	// Update ListenerSet hostname without changing AttachedListenerSets: callback must fire.
	updatedListenerSet := listenerSet.DeepCopy()
	updatedListenerSet.Generation = 2
	updatedListenerSet.Spec.Listeners[0].Hostname = Ptr(gatewayv1.Hostname("v2.example.com"))
	controllerState.UpsertListenerSet(updatedListenerSet)
	controllerState.Recompute()
	if len(listenerSnapshots) != 3 {
		t.Fatalf("expected 3 callbacks after ListenerSet hostname edit, got %d", len(listenerSnapshots))
	}
	if got := ValueOf(controllerState.GetEffectiveListeners(gatewayKey)[1].Hostname); got != "v2.example.com" {
		t.Fatalf("expected updated effective listener hostname v2.example.com, got %q", got)
	}

	// Recompute with no changes must not fire the callback again.
	controllerState.Recompute()
	if len(listenerSnapshots) != 3 {
		t.Fatalf("expected no extra callback when nothing changed, got %d", len(listenerSnapshots))
	}

	// Delete ListenerSet: callback must fire with only the Gateway's own listener remaining.
	controllerState.DeleteListenerSet(types.NamespacedName{Namespace: "default", Name: "app-ls"})
	controllerState.Recompute()
	if len(listenerSnapshots) != 4 || len(listenerSnapshots[3]) != 1 {
		t.Fatalf("expected 4 callbacks with 1 effective listener after ListenerSet delete, got %d callbacks", len(listenerSnapshots))
	}
}
