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

package tunnel

import (
	"errors"
	"flag"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type fakeTunnelState struct {
	mu                  sync.Mutex
	connected           bool
	registeredHostnames map[string]bool
	listeners           []func()
}

func (f *fakeTunnelState) IsConnected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected
}

func (f *fakeTunnelState) HasRegisteredHostnames(hostnames []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.connected {
		return false
	}
	for _, h := range hostnames {
		if !f.registeredHostnames[strings.ToLower(strings.TrimSpace(h))] {
			return false
		}
	}
	return true
}

func (f *fakeTunnelState) AddStateChangeListener(l func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listeners = append(f.listeners, l)
}

func (f *fakeTunnelState) setConnected(c bool) {
	f.mu.Lock()
	f.connected = c
	listeners := slices.Clone(f.listeners)
	f.mu.Unlock()
	for _, l := range listeners {
		l()
	}
}

func (f *fakeTunnelState) setRegistered(hostnames ...string) {
	f.mu.Lock()
	if f.registeredHostnames == nil {
		f.registeredHostnames = make(map[string]bool)
	}
	for _, h := range hostnames {
		f.registeredHostnames[strings.ToLower(strings.TrimSpace(h))] = true
	}
	listeners := slices.Clone(f.listeners)
	f.mu.Unlock()
	for _, l := range listeners {
		l()
	}
}

func TestAddressProvider_ReadinessLogic(t *testing.T) {
	fakeState := &fakeTunnelState{
		connected:           false,
		registeredHostnames: make(map[string]bool),
	}

	provider := NewAddressProvider(fakeState, "192.0.2.1", "frontend.example.com")

	gwHostname := gatewayv1.Hostname("echo.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "snigateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: &gwHostname,
				},
			},
		},
	}

	ctx := t.Context()

	// 1. Initially disconnected: returns addresses and a Pending ConditionError with tunnel-specific message
	addrs, err := provider.GatewayAddresses(ctx, gw, nil)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	var condErr *state.ConditionError
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError when tunnel is disconnected, got %v", err)
	}
	if condErr.Type != string(gatewayv1.GatewayConditionProgrammed) {
		t.Errorf("expected type=Programmed, got %s", condErr.Type)
	}
	if condErr.Reason != "Pending" || !strings.Contains(condErr.Message, "not connected") {
		t.Errorf("expected reason=Pending, msg containing 'not connected', got reason=%s, msg=%s", condErr.Reason, condErr.Message)
	}

	// 2. Tunnel connects, but hostnames not registered yet: Pending ConditionError
	fakeState.setConnected(true)
	addrs, err = provider.GatewayAddresses(ctx, gw, nil)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	condErr = nil
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError when hostnames not yet registered, got %v", err)
	}
	if condErr.Reason != "Pending" || !strings.Contains(condErr.Message, "registration") {
		t.Errorf("expected reason=Pending, msg containing 'registration', got reason=%s, msg=%s", condErr.Reason, condErr.Message)
	}

	// 3. Register a different hostname: still Pending ConditionError for this Gateway
	fakeState.setRegistered("other.example.com")
	_, err = provider.GatewayAddresses(ctx, gw, nil)
	condErr = nil
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError when this Gateway's hostname is not registered, got %v", err)
	}

	// 4. Register this Gateway's hostname: nil error (ready)
	fakeState.setRegistered("echo.example.com")
	_, err = provider.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("expected nil error when tunnel is connected and hostnames are registered, got: %v", err)
	}

	// 5. Kill session (disconnect): flips back to Pending ConditionError
	fakeState.setConnected(false)
	_, err = provider.GatewayAddresses(ctx, gw, nil)
	condErr = nil
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError after killing tunnel session, got %v", err)
	}
	if condErr.Reason != "Pending" || !strings.Contains(condErr.Message, "not connected") {
		t.Errorf("expected reason=Pending, msg containing 'not connected' after kill, got reason=%s, msg=%s", condErr.Reason, condErr.Message)
	}

	// 6. Restore session: flips back to nil error (ready)
	fakeState.setConnected(true)
	_, err = provider.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("expected nil error after restoring tunnel session, got: %v", err)
	}
}

func TestAddressProvider_MultipleListeners(t *testing.T) {
	fakeState := &fakeTunnelState{
		connected:           true,
		registeredHostnames: make(map[string]bool),
	}
	provider := NewAddressProvider(fakeState, "127.0.0.1")

	h1 := gatewayv1.Hostname("echo1.example.com")
	h2 := gatewayv1.Hostname("echo2.example.com")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "multi-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "snigateway",
			Listeners: []gatewayv1.Listener{
				{Name: "l1", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: &h1},
				{Name: "l2", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: &h2},
			},
		},
	}

	ctx := t.Context()

	// Only h1 registered
	fakeState.setRegistered("echo1.example.com")
	_, err := provider.GatewayAddresses(ctx, gw, nil)
	var condErr *state.ConditionError
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError when only 1 of 2 listener hostnames is registered, got %v", err)
	}

	// Register h2 as well
	fakeState.setRegistered("echo2.example.com")
	_, err = provider.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("expected nil error when all listener hostnames are registered, got %v", err)
	}
}

func TestAddressProvider_NoHostnamesGateway(t *testing.T) {
	fakeState := &fakeTunnelState{
		connected:           true,
		registeredHostnames: make(map[string]bool),
	}
	provider := NewAddressProvider(fakeState, "127.0.0.1")

	// Gateway with HTTP listener (no HTTPS/TLS hostnames)
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "http-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "snigateway",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	ctx := t.Context()
	_, err := provider.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("expected nil error for Gateway with no SNI hostnames when tunnel is connected, got %v", err)
	}
}

func TestAddressProvider_AddressInferenceAndParsing(t *testing.T) {
	tests := []struct {
		name      string
		inputs    []string
		wantTypes []gatewayv1.AddressType
		wantVals  []string
	}{
		{
			name:      "IPv4 address",
			inputs:    []string{"192.0.2.1"},
			wantTypes: []gatewayv1.AddressType{gatewayv1.IPAddressType},
			wantVals:  []string{"192.0.2.1"},
		},
		{
			name:      "IPv6 address",
			inputs:    []string{"::1"},
			wantTypes: []gatewayv1.AddressType{gatewayv1.IPAddressType},
			wantVals:  []string{"::1"},
		},
		{
			name:      "Hostname",
			inputs:    []string{"frontend.example.com"},
			wantTypes: []gatewayv1.AddressType{gatewayv1.HostnameAddressType},
			wantVals:  []string{"frontend.example.com"},
		},
		{
			name:   "Multiple mixed addresses",
			inputs: []string{"192.0.2.1", "frontend.example.com", "2001:db8::1"},
			wantTypes: []gatewayv1.AddressType{
				gatewayv1.IPAddressType,
				gatewayv1.HostnameAddressType,
				gatewayv1.IPAddressType,
			},
			wantVals: []string{"192.0.2.1", "frontend.example.com", "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs := ParseGatewayAddresses(tt.inputs)
			if len(addrs) != len(tt.wantVals) {
				t.Fatalf("got %d addresses, want %d", len(addrs), len(tt.wantVals))
			}
			for i, a := range addrs {
				if a.Value != tt.wantVals[i] {
					t.Errorf("address[%d].Value = %s, want %s", i, a.Value, tt.wantVals[i])
				}
				if a.Type == nil || *a.Type != tt.wantTypes[i] {
					t.Errorf("address[%d].Type = %v, want %v", i, a.Type, tt.wantTypes[i])
				}
			}
		})
	}
}

func TestParseFrontendHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"127.0.0.1:443", "127.0.0.1"},
		{"snigateway-frontend.default.svc.cluster.local:443", "snigateway-frontend.default.svc.cluster.local"},
		{"[::1]:443", "::1"},
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"frontend.example.com", "frontend.example.com"},
		{"10.0.0.1", "10.0.0.1"},
	}

	for _, tt := range tests {
		got := ParseFrontendHost(tt.input)
		if got != tt.want {
			t.Errorf("ParseFrontendHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGatewayAddressFlagParsing(t *testing.T) {
	// Case 1: --gateway-address omitted, defaults to host part of --frontend
	{
		var (
			frontendAddr     = "frontend.example.com:443"
			gatewayAddresses []string
		)
		if len(gatewayAddresses) == 0 {
			gatewayAddresses = []string{ParseFrontendHost(frontendAddr)}
		}
		if len(gatewayAddresses) != 1 || gatewayAddresses[0] != "frontend.example.com" {
			t.Fatalf("expected omitted flag to default to host part of --frontend, got %v", gatewayAddresses)
		}
	}

	// Case 2: --gateway-address given twice, reports both
	{
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var gwAddrs stringSliceFlag
		fs.Var(&gwAddrs, "gateway-address", "Address to report")

		err := fs.Parse([]string{"--gateway-address=192.0.2.1", "--gateway-address=frontend.example.com"})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		if len(gwAddrs) != 2 {
			t.Fatalf("expected 2 addresses from repeated flags, got %v", gwAddrs)
		}
		if gwAddrs[0] != "192.0.2.1" || gwAddrs[1] != "frontend.example.com" {
			t.Fatalf("unexpected flag values: %v", gwAddrs)
		}

		parsed := ParseGatewayAddresses(gwAddrs)
		if len(parsed) != 2 {
			t.Fatalf("expected 2 parsed addresses, got %d", len(parsed))
		}
		if *parsed[0].Type != gatewayv1.IPAddressType || parsed[0].Value != "192.0.2.1" {
			t.Errorf("expected first address to be IPAddress 192.0.2.1, got %+v", parsed[0])
		}
		if *parsed[1].Type != gatewayv1.HostnameAddressType || parsed[1].Value != "frontend.example.com" {
			t.Errorf("expected second address to be Hostname frontend.example.com, got %+v", parsed[1])
		}
	}
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func TestAddressProvider_WatcherReconcileEnqueuesGateways(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gatewayv1.AddToScheme(scheme)

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-1"},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "gw-2"},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw1, gw2).
		Build()

	fakeState := &fakeTunnelState{connected: true}
	provider := NewAddressProvider(fakeState, "127.0.0.1")
	provider.client = cl

	// Tunnel state change should enqueue events
	select {
	case <-provider.eventCh:
		t.Fatal("expected empty channel initially")
	default:
	}

	fakeState.setConnected(false)

	select {
	case <-provider.eventCh:
		// Succeeded in receiving event on tunnel state change
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected reconcile trigger on tunnel state change")
	}

	// mapFunc should list and map all Gateways
	reqs := provider.mapFunc(t.Context(), nil)
	if len(reqs) != 2 {
		t.Fatalf("expected 2 reconcile requests from mapFunc, got %d", len(reqs))
	}

	hasGW1 := false
	hasGW2 := false
	for _, req := range reqs {
		if req.NamespacedName == (types.NamespacedName{Namespace: "default", Name: "gw-1"}) {
			hasGW1 = true
		}
		if req.NamespacedName == (types.NamespacedName{Namespace: "prod", Name: "gw-2"}) {
			hasGW2 = true
		}
	}
	if !hasGW1 || !hasGW2 {
		t.Errorf("expected reconcile requests for both Gateways, got: %v", reqs)
	}
}
