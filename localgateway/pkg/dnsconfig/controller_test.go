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
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const testControllerName = "github.com/gke-labs/gateway-api-reference-implementation/localgateway"

func setupStateAndPublisher(t *testing.T, ctx context.Context) (*state.State, client.Client, *Publisher) {
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
		Build()

	st := state.NewState()
	p := proxy.NewProxy()

	st.SetControllerName(testControllerName)
	st.SetListenerValidator(validation.ValidateListener)
	st.SetProxy(p)

	dnsPublisher := NewPublisher(fakeClient, "default", "localgateway-dns", st)
	go func() {
		_ = dnsPublisher.Start(ctx)
	}()

	return st, fakeClient, dnsPublisher
}

func makeTestGateway(name, hostname string, createdAt time.Time) *gatewayv1.Gateway {
	hName := gatewayv1.Hostname(hostname)
	return &gatewayv1.Gateway{
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
}

func waitForConfig(t *testing.T, ctx context.Context, cl client.Client, condition func(cfg *Config) bool) *Config {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		var secret corev1.Secret
		err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "localgateway-dns"}, &secret)
		if err == nil {
			payload, ok := secret.Data[singlepod.DataplaneSecretDataKey]
			if ok && len(payload) > 0 {
				var config Config
				if err := json.Unmarshal(payload, &config); err == nil {
					if condition(&config) {
						return &config
					}
				}
			}
		} else if apierrors.IsNotFound(err) {
			if condition(nil) {
				return nil
			}
		}

		select {
		case <-deadline:
			t.Fatalf("timeout waiting for expected DNS config in Secret")
		case <-time.After(10 * time.Millisecond):
		}
	}
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
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			st, fakeClient, _ := setupStateAndPublisher(t, ctx)

			gc := &gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
				Spec:       gatewayv1.GatewayClassSpec{ControllerName: testControllerName},
			}
			st.UpsertGatewayClass(gc)

			gwOlderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
			gwNewerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

			gwOlder := makeTestGateway("gw-older", "app.local", olderTime)
			gwNewer := makeTestGateway("gw-newer", "app.local", newerTime)

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

			config := waitForConfig(t, ctx, fakeClient, func(c *Config) bool {
				return c != nil && len(c.Records) == 1
			})

			rec := config.Records[0]
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	st, fakeClient, _ := setupStateAndPublisher(t, ctx)

	targetIP := "192.168.1.100"
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: testControllerName},
	}
	st.UpsertGatewayClass(gc)

	gw := makeTestGateway("my-gw", "app.local", time.Now())
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: targetIP}})
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
	st.SetSynced(true)

	outputs := st.Recompute()
	if outputs == nil {
		t.Fatalf("Recompute returned nil")
	}

	// 1. Initially Gateway is Programmed -> app.local published
	config := waitForConfig(t, ctx, fakeClient, func(c *Config) bool {
		return c != nil && len(c.Records) == 1 && slices.Contains(c.Records[0].Addresses, targetIP)
	})
	if config == nil {
		t.Fatalf("expected Gateway to hold app.local")
	}

	// 2. Gateway loses Programmed (readiness becomes false) -> record withdrawn (Secret deleted or empty)
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: false})
	outputs = st.Recompute()
	if outputs == nil {
		t.Fatalf("Recompute after unprogrammed returned nil")
	}

	waitForConfig(t, ctx, fakeClient, func(c *Config) bool {
		return c == nil || len(c.Records) == 0
	})
}

// TestControllerThroughState_ContestedNameDeletedGatewayTransfer verifies that when
// the winning Gateway is deleted, the remaining Gateway's record is published.
func TestControllerThroughState_ContestedNameDeletedGatewayTransfer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	st, fakeClient, _ := setupStateAndPublisher(t, ctx)

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

	gwOlder := makeTestGateway("gw-older", "app.local", olderTime)
	gwNewer := makeTestGateway("gw-newer", "app.local", newerTime)

	st.UpsertGateway(gwOlder)
	st.UpsertGateway(gwNewer)
	st.SetGatewayAddresses(gwOlderKey, []gatewayv1.GatewayStatusAddress{{Value: olderIP}})
	st.SetGatewayReadiness(gwOlderKey, state.GatewayReadiness{Ready: true})
	st.SetGatewayAddresses(gwNewerKey, []gatewayv1.GatewayStatusAddress{{Value: newerIP}})
	st.SetGatewayReadiness(gwNewerKey, state.GatewayReadiness{Ready: true})
	st.SetSynced(true)

	outputs := st.Recompute()
	if outputs == nil {
		t.Fatalf("Recompute returned nil")
	}

	// 1. Initially older Gateway holds app.local
	waitForConfig(t, ctx, fakeClient, func(c *Config) bool {
		return c != nil && len(c.Records) == 1 && slices.Contains(c.Records[0].Addresses, olderIP)
	})

	// 2. Older Gateway is deleted -> newer Gateway takes over app.local
	st.DeleteGateway(gwOlderKey)
	outputs = st.Recompute()
	if outputs == nil {
		t.Fatalf("Recompute after delete returned nil")
	}

	waitForConfig(t, ctx, fakeClient, func(c *Config) bool {
		return c != nil && len(c.Records) == 1 && slices.Contains(c.Records[0].Addresses, newerIP)
	})
}
