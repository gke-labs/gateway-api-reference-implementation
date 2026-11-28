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

package address

import (
	"errors"
	"net"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestAddressProvider_ConfiguredInterface(t *testing.T) {
	ctx := t.Context()

	t.Run("reports configured interface addresses including IPv6", func(t *testing.T) {
		mockAddrs := []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			// Loopback and link-local should be filtered out
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		}

		provider := NewAddressProvider(Options{
			InterfaceName: "eth0",
			InterfaceAddrsFunc: func(name string) ([]net.Addr, error) {
				if name != "eth0" {
					return nil, errors.New("unexpected interface")
				}
				return mockAddrs, nil
			},
		})

		gw := &gatewayv1.Gateway{}
		addrs, err := provider.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(addrs) != 2 {
			t.Fatalf("expected 2 addresses (1 IPv4, 1 IPv6), got %d: %+v", len(addrs), addrs)
		}

		// IPv4 comes first
		if *addrs[0].Type != gatewayv1.IPAddressType || addrs[0].Value != "192.168.1.100" {
			t.Errorf("expected IPv4 address 192.168.1.100, got %+v", addrs[0])
		}

		// IPv6 comes second
		if *addrs[1].Type != gatewayv1.IPAddressType || addrs[1].Value != "fd00::1" {
			t.Errorf("expected IPv6 address fd00::1, got %+v", addrs[1])
		}
	})

	t.Run("interface returns error", func(t *testing.T) {
		provider := NewAddressProvider(Options{
			InterfaceName: "nonexistent",
			InterfaceAddrsFunc: func(name string) ([]net.Addr, error) {
				return nil, errors.New("interface not found")
			},
		})

		gw := &gatewayv1.Gateway{}
		addrs, err := provider.GatewayAddresses(ctx, gw, nil)
		var condErr *state.ConditionError
		if !errors.As(err, &condErr) {
			t.Fatalf("expected *state.ConditionError, got %v", err)
		}
		if condErr.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
			t.Errorf("expected reason=%s, got %s", gatewayv1.GatewayReasonAddressNotAssigned, condErr.Reason)
		}
		if len(addrs) != 0 {
			t.Errorf("expected 0 addresses, got %d", len(addrs))
		}
	})
}

func TestAddressProvider_NodeFallback(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-node-1",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.5"},
				{Type: corev1.NodeInternalIP, Address: "2001:db8::5"},
				{Type: corev1.NodeExternalIP, Address: "198.51.100.1"},
				{Type: corev1.NodeHostName, Address: "worker-node-1"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()

	provider := NewAddressProvider(Options{
		NodeName: "worker-node-1",
		Client:   cl,
	})

	gw := &gatewayv1.Gateway{}
	addrs, err := provider.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addrs) != 2 {
		t.Fatalf("expected 2 InternalIP addresses from node, got %d: %+v", len(addrs), addrs)
	}

	if addrs[0].Value != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", addrs[0].Value)
	}
	if addrs[1].Value != "2001:db8::5" {
		t.Errorf("expected 2001:db8::5, got %s", addrs[1].Value)
	}
}

func TestAddressProvider_Unconfigured(t *testing.T) {
	ctx := t.Context()
	provider := NewAddressProvider(Options{})
	gw := &gatewayv1.Gateway{}
	addrs, err := provider.GatewayAddresses(ctx, gw, nil)
	var condErr *state.ConditionError
	if !errors.As(err, &condErr) {
		t.Fatalf("expected *state.ConditionError when unconfigured, got %v", err)
	}
	if condErr.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected reason=%s, got %s", gatewayv1.GatewayReasonAddressNotAssigned, condErr.Reason)
	}
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses, got %d", len(addrs))
	}
}

func TestAddressProvider_SetupWatches(t *testing.T) {
	provider := NewAddressProvider(Options{NodeName: "node-1"})
	if err := provider.SetupWatches(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddressProvider_SupportedAddressTypes(t *testing.T) {
	provider := NewAddressProvider(Options{})
	supported := provider.SupportedAddressTypes()
	if len(supported) != 0 {
		t.Fatalf("expected nil/empty supported address types, got %+v", supported)
	}
}
