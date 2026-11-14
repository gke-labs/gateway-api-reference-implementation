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

	testState := state.NewState()
	testState.SetControllerName(testControllerName)
	testState.SetListenerValidator(validation.ValidateListener)
	testProxy := proxy.NewProxy()
	testState.SetProxy(testProxy)
	testState.SetSynced(true)

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(testControllerName),
		},
	}
	testState.UpsertGatewayClass(gatewayClass)
	return testState
}

func makeGateway(namespace, name, hostname string, port int, createdAt time.Time) *gatewayv1.Gateway {
	host := gatewayv1.Hostname(hostname)
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
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
					Hostname: &host,
				},
			},
		},
	}
}

func upsertGateway(testState *state.State, gateway *gatewayv1.Gateway, addresses []string, ready bool) {
	testState.UpsertGateway(gateway)
	key := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
	var statusAddresses []gatewayv1.GatewayStatusAddress
	for _, address := range addresses {
		statusAddresses = append(statusAddresses, gatewayv1.GatewayStatusAddress{Value: address})
	}
	testState.SetGatewayAddresses(key, statusAddresses)
	testState.SetGatewayReadiness(key, state.GatewayReadiness{Ready: ready})
	testState.Recompute()
}

func assertRecords(t *testing.T, actual, expected []Record) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("record count mismatch: got %d (%+v), want %d (%+v)", len(actual), actual, len(expected), expected)
	}
	for i := range actual {
		if actual[i].Name != expected[i].Name || !slices.Equal(actual[i].Addresses, expected[i].Addresses) {
			t.Fatalf("record[%d] mismatch:\ngot:  %+v\nwant: %+v", i, actual[i], expected[i])
		}
	}
}

// TestBuildRecords_ProgrammedGatewayWithAddress verifies that a programmed Gateway
// with an address produces a DNS record.
func TestBuildRecords_ProgrammedGatewayWithAddress(t *testing.T) {
	testState := setupTestState(t)
	gateway := makeGateway("default", "my-gateway", "app.local", 80, time.Now())
	upsertGateway(testState, gateway, []string{"192.168.1.100"}, true)

	assertRecords(t, BuildRecords(testState), []Record{
		{Name: "app.local", Addresses: []string{"192.168.1.100"}},
	})
}

// TestBuildRecords_ContestedNameBothCreationOrders verifies that when two Gateways
// claim the same name, the oldest Gateway holds it regardless of the order they are added.
func TestBuildRecords_ContestedNameBothCreationOrders(t *testing.T) {
	now := time.Now()
	olderTime := now.Add(-10 * time.Minute)
	newerTime := now.Add(-5 * time.Minute)

	testCases := []struct {
		name       string
		orderFirst string
	}{
		{name: "older added first", orderFirst: "older"},
		{name: "newer added first", orderFirst: "newer"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testState := setupTestState(t)

			olderGateway := makeGateway("default", "gateway-older", "app.local", 80, olderTime)
			newerGateway := makeGateway("default", "gateway-newer", "app.local", 8080, newerTime)

			if testCase.orderFirst == "older" {
				upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, true)
				upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, true)
			} else {
				upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, true)
				upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, true)
			}

			assertRecords(t, BuildRecords(testState), []Record{
				{Name: "app.local", Addresses: []string{"192.168.1.10"}},
			})
		})
	}
}

// TestBuildRecords_EqualTimestamps verifies tie-breaking when two Gateways have equal
// creation timestamps: the oldest Gateway holds it, then namespace and name.
func TestBuildRecords_EqualTimestamps(t *testing.T) {
	sameTime := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	t.Run("tie-break by namespace", func(t *testing.T) {
		testState := setupTestState(t)
		alphaGateway := makeGateway("alpha", "gateway", "service.local", 80, sameTime)
		betaGateway := makeGateway("beta", "gateway", "service.local", 8080, sameTime)

		upsertGateway(testState, betaGateway, []string{"10.0.2.1"}, true)
		upsertGateway(testState, alphaGateway, []string{"10.0.1.1"}, true)

		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "service.local", Addresses: []string{"10.0.1.1"}},
		})
	})

	t.Run("tie-break by name within same namespace", func(t *testing.T) {
		testState := setupTestState(t)
		gatewayA := makeGateway("default", "gateway-a", "service.local", 80, sameTime)
		gatewayB := makeGateway("default", "gateway-b", "service.local", 8080, sameTime)

		upsertGateway(testState, gatewayB, []string{"10.0.2.1"}, true)
		upsertGateway(testState, gatewayA, []string{"10.0.1.1"}, true)

		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "service.local", Addresses: []string{"10.0.1.1"}},
		})
	})
}

// TestBuildRecords_OlderGatewayLosesProgrammed verifies that when an older winning Gateway
// loses Programmed status, the newer Gateway takes over the record, and when a Gateway
// loses Programmed status without contenders its records are withdrawn.
func TestBuildRecords_OlderGatewayLosesProgrammed(t *testing.T) {
	t.Run("single Gateway loses Programmed withdraws record", func(t *testing.T) {
		testState := setupTestState(t)
		gateway := makeGateway("default", "my-gateway", "app.local", 80, time.Now())
		upsertGateway(testState, gateway, []string{"192.168.1.100"}, true)
		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "app.local", Addresses: []string{"192.168.1.100"}},
		})

		upsertGateway(testState, gateway, []string{"192.168.1.100"}, false)
		assertRecords(t, BuildRecords(testState), nil)
	})

	t.Run("contested name transfers when older Gateway loses Programmed", func(t *testing.T) {
		testState := setupTestState(t)
		now := time.Now()
		olderGateway := makeGateway("default", "gateway-older", "app.local", 80, now.Add(-10*time.Minute))
		newerGateway := makeGateway("default", "gateway-newer", "app.local", 8080, now.Add(-5*time.Minute))

		upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, true)
		upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, true)
		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "app.local", Addresses: []string{"192.168.1.10"}},
		})

		upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, false)
		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "app.local", Addresses: []string{"192.168.1.20"}},
		})

		upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, false)
		assertRecords(t, BuildRecords(testState), nil)
	})
}

// TestBuildRecords_NamesDifferOnlyInCase verifies that hostnames differing only in case
// collide on the canonical lowercase name and are resolved by the oldest Gateway rule.
func TestBuildRecords_NamesDifferOnlyInCase(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		name          string
		olderHostname string
		newerHostname string
	}{
		{name: "older mixed case, newer lowercase", olderHostname: "App.Local", newerHostname: "app.local"},
		{name: "older lowercase, newer uppercase", olderHostname: "app.local", newerHostname: "APP.LOCAL"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testState := setupTestState(t)
			olderGateway := makeGateway("default", "gateway-older", testCase.olderHostname, 80, now.Add(-10*time.Minute))
			newerGateway := makeGateway("default", "gateway-newer", testCase.newerHostname, 8080, now.Add(-5*time.Minute))

			upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, true)
			upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, true)

			assertRecords(t, BuildRecords(testState), []Record{
				{Name: "app.local", Addresses: []string{"192.168.1.10"}},
			})
		})
	}
}

// TestBuildRecords_LoopbackAndUnspecifiedAddresses verifies that loopback and unspecified
// addresses are filtered out and not published.
func TestBuildRecords_LoopbackAndUnspecifiedAddresses(t *testing.T) {
	testCases := []struct {
		name    string
		address string
	}{
		{name: "loopback IPv4", address: "127.0.0.1"},
		{name: "loopback IPv6", address: "::1"},
		{name: "unspecified IPv4", address: "0.0.0.0"},
		{name: "unspecified IPv6", address: "::"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testState := setupTestState(t)
			gateway := makeGateway("default", "gateway", "app.local", 80, time.Now())
			upsertGateway(testState, gateway, []string{testCase.address}, true)
			assertRecords(t, BuildRecords(testState), nil)
		})
	}

	t.Run("mixed loopback and routable addresses filters loopback", func(t *testing.T) {
		testState := setupTestState(t)
		gateway := makeGateway("default", "gateway", "app.local", 80, time.Now())
		upsertGateway(testState, gateway, []string{
			"127.0.0.1",
			"192.168.1.50",
			"::1",
			"0.0.0.0",
			"2001:db8::50",
		}, true)

		assertRecords(t, BuildRecords(testState), []Record{
			{Name: "app.local", Addresses: []string{"192.168.1.50", "2001:db8::50"}},
		})
	})
}

// TestBuildRecords_AddressSortingAndDeduplication verifies that addresses are sorted
// and de-duplicated in records computed from Gateway status.
func TestBuildRecords_AddressSortingAndDeduplication(t *testing.T) {
	testState := setupTestState(t)
	gateway := makeGateway("default", "gateway", "app.local", 80, time.Now())

	upsertGateway(testState, gateway, []string{
		"192.168.1.50",
		"192.168.1.10",
		"192.168.1.50",
		"192.168.1.20",
	}, true)

	assertRecords(t, BuildRecords(testState), []Record{
		{Name: "app.local", Addresses: []string{"192.168.1.10", "192.168.1.20", "192.168.1.50"}},
	})
}

// TestBuildRecords_RecordsSortedByName verifies that BuildRecords returns records
// sorted alphabetically by name.
func TestBuildRecords_RecordsSortedByName(t *testing.T) {
	testState := setupTestState(t)
	now := time.Now()

	olderGateway := makeGateway("default", "gateway-older", "zulu.local", 80, now.Add(-10*time.Minute))
	newerGateway := makeGateway("default", "gateway-newer", "alpha.local", 8080, now.Add(-5*time.Minute))

	upsertGateway(testState, olderGateway, []string{"192.168.1.10"}, true)
	upsertGateway(testState, newerGateway, []string{"192.168.1.20"}, true)

	assertRecords(t, BuildRecords(testState), []Record{
		{Name: "alpha.local", Addresses: []string{"192.168.1.20"}},
		{Name: "zulu.local", Addresses: []string{"192.168.1.10"}},
	})
}

// TestBuildRecords_SkippedGatewaysAndListeners verifies that non-viable Gateways and listeners
// (deleted, non-HTTP, invalid hostname) are skipped.
func TestBuildRecords_SkippedGatewaysAndListeners(t *testing.T) {
	t.Run("deleted Gateway is skipped", func(t *testing.T) {
		testState := setupTestState(t)
		gateway := makeGateway("default", "gateway-deleted", "app.local", 80, time.Now())
		deletionTime := metav1.Now()
		gateway.DeletionTimestamp = &deletionTime

		upsertGateway(testState, gateway, []string{"192.168.1.100"}, true)
		assertRecords(t, BuildRecords(testState), nil)
	})

	t.Run("non-HTTP listener is skipped", func(t *testing.T) {
		testState := setupTestState(t)
		hostname := gatewayv1.Hostname("app.local")
		gateway := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "gateway-https",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "localgateway",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: &hostname,
					},
				},
			},
		}

		upsertGateway(testState, gateway, []string{"192.168.1.100"}, true)
		assertRecords(t, BuildRecords(testState), nil)
	})

	t.Run("invalid hostname is skipped", func(t *testing.T) {
		testState := setupTestState(t)
		gateway := makeGateway("default", "gateway-invalid", "multi.label.local", 80, time.Now())

		upsertGateway(testState, gateway, []string{"192.168.1.100"}, true)
		assertRecords(t, BuildRecords(testState), nil)
	})
}
