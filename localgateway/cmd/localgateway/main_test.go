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

package main

import (
	"net"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/address"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func TestBuildOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		opts, cfg, err := BuildOptions([]string{})
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}

		if opts.ControllerName != DefaultControllerName {
			t.Errorf("expected ControllerName %q, got %q", DefaultControllerName, opts.ControllerName)
		}
		if opts.ProxyAddr != ":80" {
			t.Errorf("expected ProxyAddr %q, got %q", ":80", opts.ProxyAddr)
		}
		if opts.ProxyHTTPSAddr != "" {
			t.Errorf("expected empty ProxyHTTPSAddr, got %q", opts.ProxyHTTPSAddr)
		}
		if opts.ProxyHTTP3Addr != "" {
			t.Errorf("expected empty ProxyHTTP3Addr, got %q", opts.ProxyHTTP3Addr)
		}
		if opts.LeaderElection {
			t.Errorf("expected LeaderElection false")
		}
		if opts.LeaderElectionID != "localgateway-controller" {
			t.Errorf("expected LeaderElectionID 'localgateway-controller', got %q", opts.LeaderElectionID)
		}
		if opts.MetricsAddr != ":8999" {
			t.Errorf("expected MetricsAddr :8999, got %q", opts.MetricsAddr)
		}
		if opts.HealthProbeBindAddress != ":8999" {
			t.Errorf("expected HealthProbeBindAddress :8999, got %q", opts.HealthProbeBindAddress)
		}
		if cfg.Interface != "" {
			t.Errorf("expected empty cfg.Interface, got %q", cfg.Interface)
		}
		if cfg.MDNSPort != 5353 {
			t.Errorf("expected MDNSPort 5353, got %d", cfg.MDNSPort)
		}

		// Ensure listener validator and address provider are set
		if opts.ListenerValidator == nil {
			t.Errorf("expected ListenerValidator to be set")
		}
		if opts.AddressProvider == nil {
			t.Errorf("expected AddressProvider to be set")
		}
	})

	t.Run("custom flags", func(t *testing.T) {
		args := []string{
			"--controller-name=example.org/custom-gw",
			"--proxy-bind-address=:8080",
			"--interface=eth0",
			"--node-name=worker-node",
			"--leader-elect=true",
			"--leader-election-id=custom-lead",
			"--mdns-port=5354",
		}

		opts, cfg, err := BuildOptions(args)
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}

		if opts.ControllerName != "example.org/custom-gw" {
			t.Errorf("expected custom controller name, got %q", opts.ControllerName)
		}
		if opts.ProxyAddr != ":8080" {
			t.Errorf("expected :8080, got %q", opts.ProxyAddr)
		}
		if cfg.Interface != "eth0" {
			t.Errorf("expected eth0, got %q", cfg.Interface)
		}
		if cfg.NodeName != "worker-node" {
			t.Errorf("expected worker-node, got %q", cfg.NodeName)
		}
		if cfg.MDNSPort != 5354 {
			t.Errorf("expected MDNSPort 5354, got %d", cfg.MDNSPort)
		}
		if !opts.LeaderElection {
			t.Errorf("expected LeaderElection true")
		}
		if opts.LeaderElectionID != "custom-lead" {
			t.Errorf("expected custom-lead, got %q", opts.LeaderElectionID)
		}
	})
}

// TestLocalGateway_E2E_AppLocalCompiledRoute verifies what GARI compiles from the Kubernetes objects:
// 1. The listener for `app.local` is Accepted and Programmed.
// 2. The HTTPRoute attaches to the Gateway listener.
// 3. The compiled route maps `app.local` to `app-service.default.svc.cluster.local:<port>`.
// 4. The address provider reports the node LAN IP.
func TestLocalGateway_E2E_AppLocalCompiledRoute(t *testing.T) {
	ctx := t.Context()

	nodeIP := "192.168.1.100"
	backendPort := int32(8080)
	proxyPort := 80

	// 1. Build localgateway options
	opts, _, err := BuildOptions([]string{})
	if err != nil {
		t.Fatalf("BuildOptions failed: %v", err)
	}

	// AddressProvider reporting configured interface LAN IP
	addrProvider := address.NewAddressProvider(address.Options{
		InterfaceName: "eth0",
		InterfaceAddrsFunc: func(name string) ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP(nodeIP), Mask: net.CIDRMask(24, 32)},
			}, nil
		},
	})
	opts.AddressProvider = addrProvider

	// 2. Initialize Kubernetes resources
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(DefaultControllerName),
		},
	}

	appLocalHostname := gatewayv1.Hostname("app.local")
	gwKey := types.NamespacedName{Namespace: "default", Name: "local-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwKey.Namespace,
			Name:      gwKey.Name,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     gatewayv1.PortNumber(proxyPort),
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: &appLocalHostname,
				},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "app-service",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port: backendPort,
				},
			},
		},
	}

	portNum := gatewayv1.PortNumber(backendPort)
	routeKey := types.NamespacedName{Namespace: "default", Name: "app-route"}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: routeKey.Namespace,
			Name:      routeKey.Name,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "local-gw",
					},
				},
			},
			Hostnames: []gatewayv1.Hostname{appLocalHostname},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "app-service",
									Port: &portNum,
								},
							},
						},
					},
				},
			},
		},
	}

	st := state.NewState()
	p := proxy.NewProxy()

	st.SetControllerName(DefaultControllerName)
	st.SetListenerValidator(opts.ListenerValidator)
	st.SetProxy(p)

	// Feed resources to state
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertService(svc)
	st.UpsertHTTPRoute(route)
	st.SetSynced(true)
	outputs := st.Recompute()
	if outputs == nil {
		t.Fatalf("st.Recompute returned nil outputs")
	}

	// 1. Assert the listener is Accepted and Programmed
	t.Run("listener is Accepted and Programmed", func(t *testing.T) {
		cg := outputs.CompiledGateways[gwKey]
		if cg == nil {
			t.Fatalf("expected compiled gateway for %v", gwKey)
		}
		if len(cg.EffectiveListeners) != 1 {
			t.Fatalf("expected 1 effective listener, got %d", len(cg.EffectiveListeners))
		}
		el := cg.EffectiveListeners[0]
		if !el.IsAccepted() {
			t.Errorf("expected listener IsAccepted() to be true")
		}
		if !el.IsProgrammed() {
			t.Errorf("expected listener IsProgrammed() to be true")
		}

		accCond := state.FindCondition(el.Conditions, string(gatewayv1.ListenerConditionAccepted))
		if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
			t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
		}

		progCond := state.FindCondition(el.Conditions, string(gatewayv1.ListenerConditionProgrammed))
		if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
			t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
		}
	})

	// 2. Assert the route attaches
	t.Run("route attaches", func(t *testing.T) {
		cg := outputs.CompiledGateways[gwKey]
		if cg.EffectiveListeners[0].AttachedRoutes != 1 {
			t.Errorf("expected 1 attached route, got %d", cg.EffectiveListeners[0].AttachedRoutes)
		}

		routeStatus, ok := outputs.HTTPRouteStatuses[routeKey]
		if !ok || len(routeStatus.Parents) != 1 {
			t.Fatalf("expected 1 parent in route status, got %+v", routeStatus)
		}
		parent := routeStatus.Parents[0]
		accCond := state.FindCondition(parent.Conditions, string(gatewayv1.RouteConditionAccepted))
		if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.RouteReasonAccepted) {
			t.Errorf("expected Route Accepted=True/Accepted, got %+v", accCond)
		}
	})

	// 3. Assert the compiled route maps app.local to app-service.default.svc.cluster.local:<port>
	t.Run("compiled route maps app.local to service DNS", func(t *testing.T) {
		if len(outputs.ProxyRoutes) != 1 {
			t.Fatalf("expected 1 proxy route, got %d", len(outputs.ProxyRoutes))
		}
		pr := outputs.ProxyRoutes[0]
		if len(pr.Hostnames) != 1 || pr.Hostnames[0].Hostname != "app.local" {
			t.Errorf("expected proxy route hostnames ['app.local'], got %+v", pr.Hostnames)
		}

		if len(pr.Rules) != 1 || len(pr.Rules[0].Backends) != 1 {
			t.Fatalf("expected 1 rule with 1 backend, got %+v", pr.Rules)
		}
		backend := pr.Rules[0].Backends[0]
		expectedHost := "app-service.default.svc.cluster.local"
		if backend.Host != expectedHost {
			t.Errorf("expected backend host %q, got %q", expectedHost, backend.Host)
		}
		if backend.Port != backendPort {
			t.Errorf("expected backend port %d, got %d", backendPort, backend.Port)
		}
	})

	// 4. Assert address provider reports node LAN IP
	t.Run("address provider reports node LAN IP", func(t *testing.T) {
		addrs, ready, err := addrProvider.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("GatewayAddresses failed: %v", err)
		}
		if !ready {
			t.Fatalf("expected address provider ready=true")
		}
		if len(addrs) == 0 || addrs[0].Value != nodeIP {
			t.Fatalf("expected address provider to report node IP %s, got %+v", nodeIP, addrs)
		}
	})
}

// TestLocalGateway_WirePublisher verifies that WirePublisher hooks the mDNS Publisher
// into GatewayStatusHook, OnGatewaysUpdate, and SetupWithManager.
func TestLocalGateway_WirePublisher(t *testing.T) {
	opts, _, err := BuildOptions([]string{})
	if err != nil {
		t.Fatalf("BuildOptions failed: %v", err)
	}

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind test socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := mdns.NewPublisher(mdns.PublisherOptions{
		Port:        ephemeralPort,
		IPv4Conn:    rawConn,
		Ephemeral:   true,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("NewPublisher failed: %v", err)
	}
	defer pub.Close()

	WirePublisher(&opts, pub)

	if opts.GatewayStatusHook == nil {
		t.Errorf("expected GatewayStatusHook to be set")
	}
	if opts.OnGatewaysUpdate == nil {
		t.Errorf("expected OnGatewaysUpdate to be set")
	}
	if opts.SetupWithManager == nil {
		t.Errorf("expected SetupWithManager to be set")
	}
}

// TestLocalGateway_MDNSPortOccupiedFailsStartup verifies that if the mDNS port is already taken,
// starting the publisher fails clearly without touching real port 5353.
func TestLocalGateway_MDNSPortOccupiedFailsStartup(t *testing.T) {
	// Occupy a random ephemeral port first
	blocker, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind test socket: %v", err)
	}
	occupiedPort := blocker.LocalAddr().(*net.UDPAddr).Port
	defer blocker.Close()

	_, err = mdns.NewPublisher(mdns.PublisherOptions{
		Port:        occupiedPort,
		DisableIPv6: true,
	})
	if err == nil {
		t.Fatalf("expected NewPublisher to fail on occupied port %d, but succeeded", occupiedPort)
	}

	expectedSub := "is already in use (host avahi-daemon must be stopped or bound elsewhere)"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Fatalf("expected error containing %q, got: %v", expectedSub, err)
	}
}
