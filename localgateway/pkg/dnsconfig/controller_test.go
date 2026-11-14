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

package dnsconfig

import (
	"net"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/address"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const testControllerName = "github.com/gke-labs/gateway-api-reference-implementation/localgateway"

func setupStateWithPublisher(t *testing.T, initialObjects ...runtime.Object) (*state.State, *Publisher) {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(initialObjects...).
		Build()

	publisher := NewPublisher(fakeClient, DefaultSecretNamespace, DefaultSecretName, "localgateway")

	st := state.NewState()
	p := proxy.NewProxy()

	st.SetControllerName(testControllerName)
	st.SetListenerValidator(validation.ValidateListener)
	st.SetProxy(p)

	return st, publisher
}

func resolveGatewaysFromState(st *state.State, outputs *state.Outputs) []*gatewayv1.Gateway {
	var resolved []*gatewayv1.Gateway
	for _, gw := range outputs.ResolvedGateways {
		gwCopy := gw.DeepCopy()
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		if status, ok := st.GetDesiredGatewayStatus(gwKey); ok {
			gwCopy.Status = status
		}
		resolved = append(resolved, gwCopy)
	}
	return resolved
}

func makeTestGatewayWithTime(name, hostname, ip string, createdAt time.Time) (*gatewayv1.Gateway, *address.AddressProvider) {
	hName := gatewayv1.Hostname(hostname)
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              name,
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hName,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	addrProvider := address.NewAddressProvider(address.Options{
		InterfaceName: "eth0",
		InterfaceAddrsFunc: func(string) ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)},
			}, nil
		},
	})

	return gw, addrProvider
}

// TestControllerThroughState_DeterministicConflictResolutionBothOrders verifies:
// 1. Through state.State, when two Gateways claim the same hostname, the oldest Gateway wins.
// 2. Both creation orders in state result in the older Gateway's IP being published.
func TestControllerThroughState_DeterministicConflictResolutionBothOrders(t *testing.T) {
	now := time.Now()
	olderTime := now.Add(-10 * time.Minute)
	newerTime := now.Add(-5 * time.Minute)

	olderIP := "192.168.1.100"
	newerIP := "192.168.1.200"

	testCases := []struct {
		name       string
		orderFirst string
	}{
		{
			name:       "older added first",
			orderFirst: "older",
		},
		{
			name:       "newer added first",
			orderFirst: "newer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			st, publisher := setupStateWithPublisher(t)

			gc := &gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
				Spec:       gatewayv1.GatewayClassSpec{ControllerName: testControllerName},
			}
			st.UpsertGatewayClass(gc)

			gwOlderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
			gwNewerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

			gwOlder, _ := makeTestGatewayWithTime("gw-older", "app.local", olderIP, olderTime)
			gwNewer, _ := makeTestGatewayWithTime("gw-newer", "app.local", newerIP, newerTime)

			if tc.orderFirst == "older" {
				st.UpsertGateway(gwOlder)
				st.UpsertGateway(gwNewer)
			} else {
				st.UpsertGateway(gwNewer)
				st.UpsertGateway(gwOlder)
			}

			st.SetGatewayAddresses(gwOlderKey, []gatewayv1.GatewayStatusAddress{{Value: olderIP}})
			st.SetGatewayReadiness(gwOlderKey, state.GatewayReadiness{Ready: true})
			st.SetGatewayAddresses(gwNewerKey, []gatewayv1.GatewayStatusAddress{{Value: newerIP}})
			st.SetGatewayReadiness(gwNewerKey, state.GatewayReadiness{Ready: true})

			st.SetSynced(true)
			outputs := st.Recompute()
			if outputs == nil {
				t.Fatalf("Recompute returned nil")
			}

			resolved := resolveGatewaysFromState(st, outputs)
			if err := publisher.Publish(ctx, resolved); err != nil {
				t.Fatalf("Publish failed: %v", err)
			}

			var sec corev1.Secret
			if err := publisher.client.Get(ctx, types.NamespacedName{Namespace: DefaultSecretNamespace, Name: DefaultSecretName}, &sec); err != nil {
				t.Fatalf("Get Secret failed: %v", err)
			}

			cfg, err := Unmarshal(sec.Data[DefaultSecretDataKey])
			if err != nil {
				t.Fatalf("Unmarshal config failed: %v", err)
			}

			if len(cfg.Records) != 1 {
				t.Fatalf("expected exactly 1 record, got %d", len(cfg.Records))
			}
			rec := cfg.Records[0]
			if rec.Name != "app.local" {
				t.Errorf("expected name app.local, got %s", rec.Name)
			}
			if !slices.Contains(rec.Addresses, olderIP) {
				t.Errorf("expected winner to be older Gateway IP %s, got %v", olderIP, rec.Addresses)
			}
		})
	}
}

// TestControllerThroughState_GatewayLosingProgrammed verifies that when a Gateway
// loses its Programmed condition, its records are withdrawn from the published Secret.
func TestControllerThroughState_GatewayLosingProgrammed(t *testing.T) {
	ctx := t.Context()
	st, publisher := setupStateWithPublisher(t)

	targetIP := "192.168.1.100"
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: testControllerName},
	}
	st.UpsertGatewayClass(gc)

	gw, _ := makeTestGatewayWithTime("my-gw", "app.local", targetIP, time.Now())
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: targetIP}})
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
	st.SetSynced(true)

	outputs := st.Recompute()
	resolved := resolveGatewaysFromState(st, outputs)
	if err := publisher.Publish(ctx, resolved); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// 1. Initially Gateway is Programmed -> app.local published
	var sec corev1.Secret
	if err := publisher.client.Get(ctx, types.NamespacedName{Namespace: DefaultSecretNamespace, Name: DefaultSecretName}, &sec); err != nil {
		t.Fatalf("Get Secret failed: %v", err)
	}
	cfg, err := Unmarshal(sec.Data[DefaultSecretDataKey])
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(cfg.Records) != 1 || !slices.Contains(cfg.Records[0].Addresses, targetIP) {
		t.Fatalf("expected Gateway to hold app.local, got %+v", cfg.Records)
	}

	// 2. Gateway loses Programmed (readiness becomes false) -> record withdrawn
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: false})
	outputs = st.Recompute()
	resolved = resolveGatewaysFromState(st, outputs)
	if err := publisher.Publish(ctx, resolved); err != nil {
		t.Fatalf("Publish after unprogrammed failed: %v", err)
	}

	if err := publisher.client.Get(ctx, types.NamespacedName{Namespace: DefaultSecretNamespace, Name: DefaultSecretName}, &sec); err != nil {
		t.Fatalf("Get Secret failed: %v", err)
	}
	cfg, err = Unmarshal(sec.Data[DefaultSecretDataKey])
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(cfg.Records) != 0 {
		t.Fatalf("expected records to be withdrawn when Gateway loses Programmed, got %+v", cfg.Records)
	}
}

// TestControllerThroughState_ContestedNameDeletedGatewayTransfer verifies that when
// the winning Gateway is deleted, the remaining Gateway's record is published.
func TestControllerThroughState_ContestedNameDeletedGatewayTransfer(t *testing.T) {
	ctx := t.Context()
	st, publisher := setupStateWithPublisher(t)

	now := time.Now()
	olderTime := now.Add(-10 * time.Minute)
	newerTime := now.Add(-5 * time.Minute)
	olderIP := "192.168.1.100"
	newerIP := "192.168.1.200"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: testControllerName},
	}
	st.UpsertGatewayClass(gc)

	gwOlderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
	gwNewerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

	gwOlder, _ := makeTestGatewayWithTime("gw-older", "app.local", olderIP, olderTime)
	gwNewer, _ := makeTestGatewayWithTime("gw-newer", "app.local", newerIP, newerTime)

	st.UpsertGateway(gwOlder)
	st.UpsertGateway(gwNewer)
	st.SetGatewayAddresses(gwOlderKey, []gatewayv1.GatewayStatusAddress{{Value: olderIP}})
	st.SetGatewayReadiness(gwOlderKey, state.GatewayReadiness{Ready: true})
	st.SetGatewayAddresses(gwNewerKey, []gatewayv1.GatewayStatusAddress{{Value: newerIP}})
	st.SetGatewayReadiness(gwNewerKey, state.GatewayReadiness{Ready: true})
	st.SetSynced(true)

	outputs := st.Recompute()
	resolved := resolveGatewaysFromState(st, outputs)
	if err := publisher.Publish(ctx, resolved); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// 1. Initially older Gateway holds app.local
	var sec corev1.Secret
	if err := publisher.client.Get(ctx, types.NamespacedName{Namespace: DefaultSecretNamespace, Name: DefaultSecretName}, &sec); err != nil {
		t.Fatalf("Get Secret failed: %v", err)
	}
	cfg, _ := Unmarshal(sec.Data[DefaultSecretDataKey])
	if len(cfg.Records) != 1 || !slices.Contains(cfg.Records[0].Addresses, olderIP) {
		t.Fatalf("expected older Gateway to hold app.local, got %+v", cfg.Records)
	}

	// 2. Older Gateway is deleted -> newer Gateway takes over app.local
	st.DeleteGateway(gwOlderKey)
	outputs = st.Recompute()
	resolved = resolveGatewaysFromState(st, outputs)
	if err := publisher.Publish(ctx, resolved); err != nil {
		t.Fatalf("Publish after older deleted failed: %v", err)
	}

	if err := publisher.client.Get(ctx, types.NamespacedName{Namespace: DefaultSecretNamespace, Name: DefaultSecretName}, &sec); err != nil {
		t.Fatalf("Get Secret failed: %v", err)
	}
	cfg, _ = Unmarshal(sec.Data[DefaultSecretDataKey])
	if len(cfg.Records) != 1 || !slices.Contains(cfg.Records[0].Addresses, newerIP) {
		t.Fatalf("expected newer Gateway to take over app.local, got %+v", cfg.Records)
	}
}
