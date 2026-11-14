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
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const testControllerName = "github.com/gke-labs/gateway-api-reference-implementation/localgateway"

func setupTestState(t *testing.T) *state.State {
	t.Helper()

	st := state.NewState()
	st.SetControllerName(testControllerName)
	st.SetListenerValidator(validation.ValidateListener)
	p := proxy.NewProxy()
	st.SetProxy(p)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(testControllerName),
		},
	}
	st.UpsertGatewayClass(gc)
	return st
}

func makeGateway(ns, name, hostname string, port int, createdAt time.Time) *gatewayv1.Gateway {
	h := gatewayv1.Hostname(hostname)
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     gatewayv1.PortNumber(port),
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: &h,
				},
			},
		},
	}
}

// TestBuildRecords_ProgrammedGatewayWithAddress verifies that a programmed Gateway
// with an address produces a DNS record.
func TestBuildRecords_ProgrammedGatewayWithAddress(t *testing.T) {
	st := setupTestState(t)

	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
	st.SetSynced(true)
	st.Recompute()

	records := BuildRecords(st)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Name != "app.local" {
		t.Errorf("expected name app.local, got %q", records[0].Name)
	}
	expectedAddresses := []string{"192.168.1.100"}
	if !slices.Equal(records[0].Addresses, expectedAddresses) {
		t.Errorf("expected addresses %v, got %v", expectedAddresses, records[0].Addresses)
	}
}

// TestBuildRecords_ContestedNameBothCreationOrders verifies that when two Gateways
// claim the same name, the oldest Gateway holds it regardless of the order they are added.
func TestBuildRecords_ContestedNameBothCreationOrders(t *testing.T) {
	now := time.Now()
	olderTime := now.Add(-10 * time.Minute)
	newerTime := now.Add(-5 * time.Minute)

	olderIP := "192.168.1.10"
	newerIP := "192.168.1.20"

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
			st := setupTestState(t)

			olderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
			newerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

			olderGw := makeGateway("default", "gw-older", "app.local", 80, olderTime)
			newerGw := makeGateway("default", "gw-newer", "app.local", 8080, newerTime)

			if tc.orderFirst == "older" {
				st.UpsertGateway(olderGw)
				st.UpsertGateway(newerGw)
			} else {
				st.UpsertGateway(newerGw)
				st.UpsertGateway(olderGw)
			}

			st.SetGatewayAddresses(olderKey, []gatewayv1.GatewayStatusAddress{{Value: olderIP}})
			st.SetGatewayReadiness(olderKey, state.GatewayReadiness{Ready: true})
			st.SetGatewayAddresses(newerKey, []gatewayv1.GatewayStatusAddress{{Value: newerIP}})
			st.SetGatewayReadiness(newerKey, state.GatewayReadiness{Ready: true})

			st.SetSynced(true)
			st.Recompute()

			records := BuildRecords(st)
			if len(records) != 1 {
				t.Fatalf("expected 1 record, got %d", len(records))
			}
			if records[0].Name != "app.local" {
				t.Errorf("expected name app.local, got %q", records[0].Name)
			}
			if !slices.Contains(records[0].Addresses, olderIP) {
				t.Errorf("expected winning record to contain older IP %s, got %v", olderIP, records[0].Addresses)
			}
		})
	}
}

// TestBuildRecords_EqualTimestamps verifies tie-breaking when two Gateways have equal
// creation timestamps: the oldest Gateway holds it, then namespace and name.
func TestBuildRecords_EqualTimestamps(t *testing.T) {
	sameTime := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	t.Run("tie-break by namespace", func(t *testing.T) {
		st := setupTestState(t)

		gwAlphaKey := types.NamespacedName{Namespace: "alpha", Name: "gw"}
		gwBetaKey := types.NamespacedName{Namespace: "beta", Name: "gw"}

		gwAlpha := makeGateway("alpha", "gw", "service.local", 80, sameTime)
		gwBeta := makeGateway("beta", "gw", "service.local", 8080, sameTime)

		// Insert beta first to verify insertion order does not decide winner
		st.UpsertGateway(gwBeta)
		st.UpsertGateway(gwAlpha)

		st.SetGatewayAddresses(gwAlphaKey, []gatewayv1.GatewayStatusAddress{{Value: "10.0.1.1"}})
		st.SetGatewayReadiness(gwAlphaKey, state.GatewayReadiness{Ready: true})
		st.SetGatewayAddresses(gwBetaKey, []gatewayv1.GatewayStatusAddress{{Value: "10.0.2.1"}})
		st.SetGatewayReadiness(gwBetaKey, state.GatewayReadiness{Ready: true})

		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if !slices.Contains(records[0].Addresses, "10.0.1.1") {
			t.Errorf("expected alpha namespace to win tie-break, got addresses %v", records[0].Addresses)
		}
	})

	t.Run("tie-break by name within same namespace", func(t *testing.T) {
		st := setupTestState(t)

		gwAKey := types.NamespacedName{Namespace: "default", Name: "gw-a"}
		gwBKey := types.NamespacedName{Namespace: "default", Name: "gw-b"}

		gwA := makeGateway("default", "gw-a", "service.local", 80, sameTime)
		gwB := makeGateway("default", "gw-b", "service.local", 8080, sameTime)

		// Insert B first to verify insertion order does not decide winner
		st.UpsertGateway(gwB)
		st.UpsertGateway(gwA)

		st.SetGatewayAddresses(gwAKey, []gatewayv1.GatewayStatusAddress{{Value: "10.0.1.1"}})
		st.SetGatewayReadiness(gwAKey, state.GatewayReadiness{Ready: true})
		st.SetGatewayAddresses(gwBKey, []gatewayv1.GatewayStatusAddress{{Value: "10.0.2.1"}})
		st.SetGatewayReadiness(gwBKey, state.GatewayReadiness{Ready: true})

		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if !slices.Contains(records[0].Addresses, "10.0.1.1") {
			t.Errorf("expected gw-a name to win tie-break, got addresses %v", records[0].Addresses)
		}
	})
}

// TestBuildRecords_OlderGatewayLosesProgrammed verifies that when an older winning Gateway
// loses Programmed status, the newer Gateway takes over the record, and when a Gateway
// loses Programmed status without contenders its records are withdrawn.
func TestBuildRecords_OlderGatewayLosesProgrammed(t *testing.T) {
	t.Run("single Gateway loses Programmed withdraws record", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record initially, got %d", len(records))
		}

		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: false})
		st.Recompute()

		records = BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected 0 records after gateway lost programmed, got %d", len(records))
		}
	})

	t.Run("contested name transfers when older Gateway loses Programmed", func(t *testing.T) {
		st := setupTestState(t)

		now := time.Now()
		olderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
		newerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

		olderGw := makeGateway("default", "gw-older", "app.local", 80, now.Add(-10*time.Minute))
		newerGw := makeGateway("default", "gw-newer", "app.local", 8080, now.Add(-5*time.Minute))

		st.UpsertGateway(olderGw)
		st.UpsertGateway(newerGw)

		st.SetGatewayAddresses(olderKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.10"}})
		st.SetGatewayReadiness(olderKey, state.GatewayReadiness{Ready: true})
		st.SetGatewayAddresses(newerKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.20"}})
		st.SetGatewayReadiness(newerKey, state.GatewayReadiness{Ready: true})

		st.SetSynced(true)
		st.Recompute()

		// Initially older Gateway wins
		records := BuildRecords(st)
		if len(records) != 1 || !slices.Contains(records[0].Addresses, "192.168.1.10") {
			t.Fatalf("expected older Gateway to hold record initially, got %v", records)
		}

		// Older Gateway loses Programmed (ready = false)
		st.SetGatewayReadiness(olderKey, state.GatewayReadiness{Ready: false})
		st.Recompute()

		records = BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record after older gateway lost programmed, got %d", len(records))
		}
		if !slices.Contains(records[0].Addresses, "192.168.1.20") {
			t.Errorf("expected newer Gateway to take over record, got %v", records[0].Addresses)
		}

		// Newer Gateway also loses Programmed -> no records
		st.SetGatewayReadiness(newerKey, state.GatewayReadiness{Ready: false})
		st.Recompute()

		records = BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records when all gateways lose programmed, got %v", records)
		}
	})
}

// TestBuildRecords_NamesDifferOnlyInCase verifies that hostnames differing only in case
// collide on the canonical lowercase name and are resolved by the oldest Gateway rule.
func TestBuildRecords_NamesDifferOnlyInCase(t *testing.T) {
	now := time.Now()

	t.Run("older has mixed case, newer has lowercase", func(t *testing.T) {
		st := setupTestState(t)

		olderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
		newerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

		olderGw := makeGateway("default", "gw-older", "App.Local", 80, now.Add(-10*time.Minute))
		newerGw := makeGateway("default", "gw-newer", "app.local", 8080, now.Add(-5*time.Minute))

		st.UpsertGateway(olderGw)
		st.UpsertGateway(newerGw)
		st.SetGatewayAddresses(olderKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.10"}})
		st.SetGatewayReadiness(olderKey, state.GatewayReadiness{Ready: true})
		st.SetGatewayAddresses(newerKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.20"}})
		st.SetGatewayReadiness(newerKey, state.GatewayReadiness{Ready: true})

		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Name != "app.local" {
			t.Errorf("expected canonical lowercase name app.local, got %q", records[0].Name)
		}
		if !slices.Contains(records[0].Addresses, "192.168.1.10") {
			t.Errorf("expected older Gateway to hold record, got %v", records[0].Addresses)
		}
	})

	t.Run("older has lowercase, newer has uppercase", func(t *testing.T) {
		st := setupTestState(t)

		olderKey := types.NamespacedName{Namespace: "default", Name: "gw-older"}
		newerKey := types.NamespacedName{Namespace: "default", Name: "gw-newer"}

		olderGw := makeGateway("default", "gw-older", "app.local", 80, now.Add(-10*time.Minute))
		newerGw := makeGateway("default", "gw-newer", "APP.LOCAL", 8080, now.Add(-5*time.Minute))

		st.UpsertGateway(olderGw)
		st.UpsertGateway(newerGw)
		st.SetGatewayAddresses(olderKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.10"}})
		st.SetGatewayReadiness(olderKey, state.GatewayReadiness{Ready: true})
		st.SetGatewayAddresses(newerKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.20"}})
		st.SetGatewayReadiness(newerKey, state.GatewayReadiness{Ready: true})

		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		if records[0].Name != "app.local" {
			t.Errorf("expected canonical lowercase name app.local, got %q", records[0].Name)
		}
		if !slices.Contains(records[0].Addresses, "192.168.1.10") {
			t.Errorf("expected older Gateway to hold record, got %v", records[0].Addresses)
		}
	})
}

// TestBuildRecords_LoopbackAndUnspecifiedAddresses verifies that loopback and unspecified
// addresses are filtered out and not published.
func TestBuildRecords_LoopbackAndUnspecifiedAddresses(t *testing.T) {
	t.Run("only loopback IPv4 address yields no records", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-loopback"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "127.0.0.1"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for loopback IPv4 address, got %v", records)
		}
	})

	t.Run("only loopback IPv6 address yields no records", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-loopback6"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "::1"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for loopback IPv6 address, got %v", records)
		}
	})

	t.Run("only unspecified IPv4 address yields no records", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-unspec4"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "0.0.0.0"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for unspecified IPv4 address, got %v", records)
		}
	})

	t.Run("only unspecified IPv6 address yields no records", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-unspec6"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "::"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for unspecified IPv6 address, got %v", records)
		}
	})

	t.Run("mixed loopback and routable addresses filters loopback", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-mixed"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{
			{Value: "127.0.0.1"},
			{Value: "192.168.1.50"},
			{Value: "::1"},
			{Value: "0.0.0.0"},
			{Value: "2001:db8::50"},
		})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(records))
		}
		expectedAddresses := []string{"192.168.1.50", "2001:db8::50"}
		if !slices.Equal(records[0].Addresses, expectedAddresses) {
			t.Errorf("expected addresses %v, got %v", expectedAddresses, records[0].Addresses)
		}
	})
}

// TestBuildRecords_EdgeCases verifies edge conditions like nil state, non-HTTP listeners,
// invalid hostnames, and deleted Gateways.
func TestBuildRecords_EdgeCases(t *testing.T) {
	t.Run("nil state returns nil", func(t *testing.T) {
		records := BuildRecords(nil)
		if records != nil {
			t.Errorf("expected nil records for nil state, got %v", records)
		}
	})

	t.Run("deleted Gateway is skipped", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-deleted"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "app.local", 80, time.Now())
		deletionTime := metav1.Now()
		gw.DeletionTimestamp = &deletionTime

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for deleted gateway, got %v", records)
		}
	})

	t.Run("non-HTTP listener is skipped", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-https"}
		h := gatewayv1.Hostname("app.local")
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gwKey.Namespace,
				Name:      gwKey.Name,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "localgateway",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: &h,
					},
				},
			},
		}

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for non-HTTP listener, got %v", records)
		}
	})

	t.Run("invalid hostname is skipped", func(t *testing.T) {
		st := setupTestState(t)
		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-invalid"}
		gw := makeGateway(gwKey.Namespace, gwKey.Name, "multi.label.local", 80, time.Now())

		st.UpsertGateway(gw)
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
		st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
		st.SetSynced(true)
		st.Recompute()

		records := BuildRecords(st)
		if len(records) != 0 {
			t.Errorf("expected no records for invalid multi-label hostname, got %v", records)
		}
	})
}
