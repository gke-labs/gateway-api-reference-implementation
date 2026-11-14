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
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	return scheme
}

func startTestPublisher(t *testing.T, ctx context.Context, options mdns.PublisherOptions) (*mdns.Publisher, <-chan error) {
	t.Helper()
	publisher, err := mdns.NewPublisher(options)
	if err != nil {
		t.Fatalf("NewPublisher failed: %v", err)
	}
	t.Cleanup(func() {
		_ = publisher.Close()
	})

	errChan := make(chan error, 1)
	go func() {
		errChan <- publisher.Start(ctx)
	}()
	return publisher, errChan
}

func TestBuildOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		configuration, err := buildOptions([]string{})
		if err != nil {
			t.Fatalf("buildOptions failed: %v", err)
		}
		if configuration.gatewayClass != defaultGatewayClassName {
			t.Errorf("expected gatewayClass %q, got %q", defaultGatewayClassName, configuration.gatewayClass)
		}
		if configuration.networkInterface != "" {
			t.Errorf("expected empty networkInterface, got %q", configuration.networkInterface)
		}
		if configuration.mdnsPort != mdns.DefaultPort {
			t.Errorf("expected mdnsPort %d, got %d", mdns.DefaultPort, configuration.mdnsPort)
		}
		if configuration.metricsAddr != "0" {
			t.Errorf("expected metricsAddr %q, got %q", "0", configuration.metricsAddr)
		}
	})

	t.Run("custom flags", func(t *testing.T) {
		args := []string{
			"--gateway-class=custom-class",
			"--interface=eth0",
			"--mdns-port=5354",
			"--metrics-bind-address=:9090",
		}
		configuration, err := buildOptions(args)
		if err != nil {
			t.Fatalf("buildOptions failed: %v", err)
		}
		if configuration.gatewayClass != "custom-class" {
			t.Errorf("expected gatewayClass custom-class, got %q", configuration.gatewayClass)
		}
		if configuration.networkInterface != "eth0" {
			t.Errorf("expected networkInterface eth0, got %q", configuration.networkInterface)
		}
		if configuration.mdnsPort != 5354 {
			t.Errorf("expected mdnsPort 5354, got %d", configuration.mdnsPort)
		}
		if configuration.metricsAddr != ":9090" {
			t.Errorf("expected metricsAddr :9090, got %q", configuration.metricsAddr)
		}
	})

	t.Run("empty gateway-class fails", func(t *testing.T) {
		_, err := buildOptions([]string{"--gateway-class="})
		if err == nil {
			t.Fatalf("expected error for empty --gateway-class, got nil")
		}
	})
}

// TestGatewayReconciler_AnnounceAndWithdraw verifies that with a fake API server:
// 1. A Gateway with a .local hostname and an address causes the responder to announce that name and address.
// 2. Removing the Gateway withdraws it (sends a goodbye packet and removes the record).
func TestGatewayReconciler_AnnounceAndWithdraw(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scheme := newTestScheme(t)

	announcedChannel := make(chan []byte, 10)
	goodbyeChannel := make(chan []byte, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	publisher, errChan := startTestPublisher(t, ctx, mdns.PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         10 * time.Millisecond,
		ProbeCount:            1,
		AnnounceInterval:      10 * time.Millisecond,
		ConflictRetryInterval: 100 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var parser dnsmessage.Parser
			if _, err := parser.Start(raw); err != nil {
				return
			}
			if err := parser.SkipAllQuestions(); err != nil {
				return
			}
			for {
				header, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(header.Name.String(), "app.local.") {
					if header.TTL == 0 {
						goodbyeChannel <- raw
					} else {
						announcedChannel <- raw
					}
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	hostname := gatewayv1.Hostname("app.local")
	ipAddrType := gatewayv1.IPAddressType
	targetIP := "192.168.1.100"

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  gatewayKey.Namespace,
			Name:       gatewayKey.Name,
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: defaultGatewayClassName,
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hostname,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionProgrammed),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.GatewayReasonProgrammed),
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: string(gatewayv1.ListenerReasonAccepted),
						},
						{
							Type:   string(gatewayv1.ListenerConditionProgrammed),
							Status: metav1.ConditionTrue,
							Reason: string(gatewayv1.ListenerReasonProgrammed),
						},
					},
				},
			},
			Addresses: []gatewayv1.GatewayStatusAddress{
				{
					Type:  &ipAddrType,
					Value: targetIP,
				},
			},
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:           testClient,
		gatewayClassName: defaultGatewayClassName,
		publisher:        publisher,
	}

	// 1. Reconcile with the Gateway present -> should probe and announce
	request := ctrl.Request{NamespacedName: gatewayKey}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	select {
	case raw := <-announcedChannel:
		var parser dnsmessage.Parser
		if _, err := parser.Start(raw); err != nil {
			t.Fatalf("parser.Start failed: %v", err)
		}
		if err := parser.SkipAllQuestions(); err != nil {
			t.Fatalf("parser.SkipAllQuestions failed: %v", err)
		}
		header, err := parser.AnswerHeader()
		if err != nil {
			t.Fatalf("parser.AnswerHeader failed: %v", err)
		}
		if header.TTL == 0 {
			t.Fatalf("expected non-zero TTL in announcement, got %+v", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for app.local announcement")
	}

	record, ok := publisher.Responder().GetRecord("app.local")
	if !ok {
		t.Fatalf("expected responder to have record for app.local")
	}
	if len(record.A) == 0 || record.A[0].String() != targetIP {
		t.Fatalf("expected responder record A to be %s, got %+v", targetIP, record.A)
	}

	// 2. Remove the Gateway -> should withdraw
	if err := testClient.Delete(ctx, gateway); err != nil {
		t.Fatalf("failed to delete gateway: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("Reconcile on delete failed: %v", err)
	}

	select {
	case raw := <-goodbyeChannel:
		var parser dnsmessage.Parser
		if _, err := parser.Start(raw); err != nil {
			t.Fatalf("parser.Start failed: %v", err)
		}
		if err := parser.SkipAllQuestions(); err != nil {
			t.Fatalf("parser.SkipAllQuestions failed: %v", err)
		}
		header, err := parser.AnswerHeader()
		if err != nil {
			t.Fatalf("parser.AnswerHeader failed: %v", err)
		}
		if header.TTL != 0 {
			t.Fatalf("expected TTL 0 in goodbye answer, got %+v", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for app.local goodbye packet")
	}

	if _, ok := publisher.Responder().GetRecord("app.local"); ok {
		t.Fatalf("expected record for app.local to be withdrawn from responder")
	}

	cancel()
	if err := <-errChan; err != nil {
		t.Errorf("publisher.Start returned unexpected error: %v", err)
	}
}

// TestGatewayReconciler_RequiresAcceptedAndProgrammed verifies that a listener is only published
// when the Gateway's Programmed condition and the listener's Accepted and Programmed conditions are true.
func TestGatewayReconciler_RequiresAcceptedAndProgrammed(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scheme := newTestScheme(t)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	announcedChannel := make(chan []byte, 10)
	publisher, errChan := startTestPublisher(t, ctx, mdns.PublisherOptions{
		Interface:        "lo",
		Port:             ephemeralPort,
		IPv4Conn:         rawConn,
		DisableIPv6:      true,
		ProbeInterval:    10 * time.Millisecond,
		ProbeCount:       1,
		AnnounceInterval: 10 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var parser dnsmessage.Parser
			if _, err := parser.Start(raw); err != nil {
				return
			}
			if err := parser.SkipAllQuestions(); err != nil {
				return
			}
			for {
				header, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(header.Name.String(), "test.local.") && header.TTL > 0 {
					announcedChannel <- raw
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "prog-gateway"}
	hostname := gatewayv1.Hostname("test.local")
	ipAddrType := gatewayv1.IPAddressType
	targetIP := "192.168.1.10"

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayKey.Namespace,
			Name:      gatewayKey.Name,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: defaultGatewayClassName,
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hostname,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{
				{
					Type:  &ipAddrType,
					Value: targetIP,
				},
			},
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionProgrammed),
					Status: metav1.ConditionFalse,
					Reason: "NotProgrammed",
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionAccepted),
							Status: metav1.ConditionFalse,
							Reason: "NotAccepted",
						},
						{
							Type:   string(gatewayv1.ListenerConditionProgrammed),
							Status: metav1.ConditionFalse,
							Reason: "NotProgrammed",
						},
					},
				},
			},
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:           testClient,
		gatewayClassName: defaultGatewayClassName,
		publisher:        publisher,
	}

	// 1. Both Gateway and listener are not programmed -> should not publish
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gatewayKey}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if _, ok := publisher.Responder().GetRecord("test.local"); ok {
		t.Fatalf("expected test.local not to be published when Programmed=False")
	}

	// 2. Gateway Programmed=True, but listener Accepted=False -> should not publish
	gateway.Status.Conditions[0].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, gateway); err != nil {
		t.Fatalf("Status update failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gatewayKey}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if _, ok := publisher.Responder().GetRecord("test.local"); ok {
		t.Fatalf("expected test.local not to be published when listener Accepted=False")
	}

	// 3. Gateway Programmed=True, listener Accepted=True, but listener Programmed=False -> should not publish
	gateway.Status.Listeners[0].Conditions[0].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, gateway); err != nil {
		t.Fatalf("Status update failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gatewayKey}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if _, ok := publisher.Responder().GetRecord("test.local"); ok {
		t.Fatalf("expected test.local not to be published when listener Programmed=False")
	}

	// 4. Gateway Programmed=True, listener Accepted=True AND Programmed=True -> should publish
	gateway.Status.Listeners[0].Conditions[1].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, gateway); err != nil {
		t.Fatalf("Status update failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gatewayKey}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	select {
	case <-announcedChannel:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for announcement when both Gateway and listener are Programmed")
	}

	if _, ok := publisher.Responder().GetRecord("test.local"); !ok {
		t.Fatalf("expected test.local to be published when Programmed=True")
	}

	cancel()
	if err := <-errChan; err != nil {
		t.Errorf("publisher.Start returned unexpected error: %v", err)
	}
}

// TestGatewayReconciler_DeterministicConflictResolutionBothOrders verifies that when two Gateways
// claim the same hostname, the oldest Gateway by creation time wins regardless of API list order.
func TestGatewayReconciler_DeterministicConflictResolutionBothOrders(t *testing.T) {
	scheme := newTestScheme(t)

	now := time.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	hostname := gatewayv1.Hostname("shared.local")
	ipAddrType := gatewayv1.IPAddressType
	olderIP := "192.168.1.100"
	newerIP := "192.168.1.200"

	makeGateway := func(name string, createdAt metav1.Time, ip string) *gatewayv1.Gateway {
		return &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "default",
				Name:              name,
				CreationTimestamp: createdAt,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: defaultGatewayClassName,
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Hostname: &hostname,
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
					},
				},
			},
			Status: gatewayv1.GatewayStatus{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.GatewayConditionProgrammed),
						Status: metav1.ConditionTrue,
						Reason: "Programmed",
					},
				},
				Listeners: []gatewayv1.ListenerStatus{
					{
						Name: "http",
						Conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: "Accepted",
							},
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: "Programmed",
							},
						},
					},
				},
				Addresses: []gatewayv1.GatewayStatusAddress{
					{
						Type:  &ipAddrType,
						Value: ip,
					},
				},
			},
		}
	}

	testCases := []struct {
		name     string
		gateways []*gatewayv1.Gateway
	}{
		{
			name:     "older first in list order",
			gateways: []*gatewayv1.Gateway{makeGateway("gw-older", olderTime, olderIP), makeGateway("gw-newer", newerTime, newerIP)},
		},
		{
			name:     "newer first in list order",
			gateways: []*gatewayv1.Gateway{makeGateway("gw-newer", newerTime, newerIP), makeGateway("gw-older", olderTime, olderIP)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			rawConn, err := net.ListenPacket("udp4", ":0")
			if err != nil {
				t.Fatalf("failed to bind ephemeral socket: %v", err)
			}
			defer rawConn.Close()
			ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

			announcedChannel := make(chan []byte, 10)
			publisher, errChan := startTestPublisher(t, ctx, mdns.PublisherOptions{
				Interface:        "lo",
				Port:             ephemeralPort,
				IPv4Conn:         rawConn,
				DisableIPv6:      true,
				ProbeInterval:    10 * time.Millisecond,
				ProbeCount:       1,
				AnnounceInterval: 10 * time.Millisecond,
				MulticastTap: func(raw []byte) {
					var parser dnsmessage.Parser
					if _, err := parser.Start(raw); err != nil {
						return
					}
					if err := parser.SkipAllQuestions(); err != nil {
						return
					}
					for {
						header, err := parser.AnswerHeader()
						if err != nil {
							break
						}
						if strings.EqualFold(header.Name.String(), "shared.local.") && header.TTL > 0 {
							announcedChannel <- raw
						}
						if err := parser.SkipAnswer(); err != nil {
							break
						}
					}
				},
			})

			testClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.gateways[0], tc.gateways[1]).
				WithStatusSubresource(&gatewayv1.Gateway{}).
				Build()

			reconciler := &gatewayReconciler{
				Client:           testClient,
				gatewayClassName: defaultGatewayClassName,
				publisher:        publisher,
			}

			if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
				t.Fatalf("Reconcile failed: %v", err)
			}

			select {
			case <-announcedChannel:
			case <-time.After(2 * time.Second):
				t.Fatalf("timeout waiting for announcement")
			}

			record, ok := publisher.Responder().GetRecord("shared.local")
			if !ok {
				t.Fatalf("expected responder to have record for shared.local")
			}
			if len(record.A) == 0 || record.A[0].String() != olderIP {
				t.Fatalf("expected deterministic winner to be older Gateway IP %s, got %+v", olderIP, record.A)
			}

			cancel()
			if err := <-errChan; err != nil {
				t.Errorf("publisher.Start returned unexpected error: %v", err)
			}
		})
	}
}

// TestGatewayReconciler_IgnoresOtherGatewayClasses verifies that Gateways with a different
// GatewayClassName are not published, using a tap wait rather than a fixed sleep.
func TestGatewayReconciler_IgnoresOtherGatewayClasses(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scheme := newTestScheme(t)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	matchingAnnounced := make(chan []byte, 10)
	otherAnnounced := make(chan []byte, 10)

	publisher, errChan := startTestPublisher(t, ctx, mdns.PublisherOptions{
		Interface:        "lo",
		Port:             ephemeralPort,
		IPv4Conn:         rawConn,
		DisableIPv6:      true,
		ProbeInterval:    10 * time.Millisecond,
		ProbeCount:       1,
		AnnounceInterval: 10 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var parser dnsmessage.Parser
			if _, err := parser.Start(raw); err != nil {
				return
			}
			if err := parser.SkipAllQuestions(); err != nil {
				return
			}
			for {
				header, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(header.Name.String(), "matching.local.") {
					matchingAnnounced <- raw
				}
				if strings.EqualFold(header.Name.String(), "other.local.") {
					otherAnnounced <- raw
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})

	ipAddrType := gatewayv1.IPAddressType
	otherHostname := gatewayv1.Hostname("other.local")
	matchingHostname := gatewayv1.Hostname("matching.local")

	otherGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "other-gateway"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "unrelated-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &otherHostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted"},
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
					},
				},
			},
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "192.168.1.50"}},
		},
	}

	matchingGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "matching-gateway"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: defaultGatewayClassName,
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &matchingHostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted"},
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
					},
				},
			},
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "192.168.1.100"}},
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(otherGateway, matchingGateway).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:           testClient,
		gatewayClassName: defaultGatewayClassName,
		publisher:        publisher,
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Wait on the tap for the matching Gateway to be announced, proving the batch has been processed
	select {
	case <-matchingAnnounced:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for matching.local on multicast tap")
	}

	select {
	case raw := <-otherAnnounced:
		t.Fatalf("unexpected packet observed on tap for other.local: %v", raw)
	default:
	}

	if _, ok := publisher.Responder().GetRecord("other.local"); ok {
		t.Fatalf("unrelated GatewayClass should not be published in responder")
	}

	cancel()
	if err := <-errChan; err != nil {
		t.Errorf("publisher.Start returned unexpected error: %v", err)
	}
}

// TestPublisher_ShutdownSendsGoodbye verifies that cancelling the publisher context
// sends a goodbye packet for all published hostnames.
func TestPublisher_ShutdownSendsGoodbye(t *testing.T) {
	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())

	scheme := newTestScheme(t)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	announcedChannel := make(chan []byte, 10)
	goodbyeChannel := make(chan []byte, 10)

	publisher, errChan := startTestPublisher(t, shutdownCtx, mdns.PublisherOptions{
		Interface:        "lo",
		Port:             ephemeralPort,
		IPv4Conn:         rawConn,
		DisableIPv6:      true,
		ProbeInterval:    10 * time.Millisecond,
		ProbeCount:       1,
		AnnounceInterval: 10 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var parser dnsmessage.Parser
			if _, err := parser.Start(raw); err != nil {
				return
			}
			if err := parser.SkipAllQuestions(); err != nil {
				return
			}
			for {
				header, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(header.Name.String(), "shutdown.local.") {
					if header.TTL == 0 {
						goodbyeChannel <- raw
					} else {
						announcedChannel <- raw
					}
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})

	hostname := gatewayv1.Hostname("shutdown.local")
	ipAddrType := gatewayv1.IPAddressType
	targetIP := "192.168.1.100"

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-shutdown"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: defaultGatewayClassName,
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hostname, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted"},
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue, Reason: "Programmed"},
					},
				},
			},
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: targetIP}},
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gateway).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:           testClient,
		gatewayClassName: defaultGatewayClassName,
		publisher:        publisher,
	}

	if _, err := reconciler.Reconcile(shutdownCtx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	select {
	case <-announcedChannel:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for announcement")
	}

	if _, ok := publisher.Responder().GetRecord("shutdown.local"); !ok {
		t.Fatalf("expected record to be published before shutdown")
	}

	// Cancel context to simulate manager stopping the publisher
	cancelShutdown()

	select {
	case raw := <-goodbyeChannel:
		var parser dnsmessage.Parser
		if _, err := parser.Start(raw); err != nil {
			t.Fatalf("parser.Start failed: %v", err)
		}
		if err := parser.SkipAllQuestions(); err != nil {
			t.Fatalf("parser.SkipAllQuestions failed: %v", err)
		}
		header, err := parser.AnswerHeader()
		if err != nil {
			t.Fatalf("parser.AnswerHeader failed: %v", err)
		}
		if header.TTL != 0 {
			t.Fatalf("expected TTL 0 in shutdown goodbye, got %+v", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for goodbye packet on shutdown")
	}

	if err := <-errChan; err != nil {
		t.Errorf("publisher.Start returned unexpected error: %v", err)
	}
}

// TestDNSManifest_RBACAndHostNetworking verifies acceptance criteria:
// 1. The RBAC contains no rule for Secrets.
// 2. The RBAC allows get, list, watch on Gateways, and nothing else (no nodes rule).
// 3. The manifest runs with host networking.
// 4. The container runs with unprivileged securityContext (non-root, no privilege escalation).
func TestDNSManifest_RBACAndHostNetworking(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "dns.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundClusterRole bool
	var foundDeploy bool

	for _, doc := range docs {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &role); err == nil && role.Kind == "ClusterRole" && role.Name == "localgateway-dns" {
			foundClusterRole = true

			for _, rule := range role.Rules {
				// Acceptance criterion: The new program's RBAC contains no rule for Secrets.
				for _, resource := range rule.Resources {
					if strings.Contains(strings.ToLower(resource), "secret") {
						t.Errorf("RBAC ClusterRole must NOT contain rule for secrets, but found %q", resource)
					}
				}

				// Must allow get, list, watch on gateways only
				for _, apiGroup := range rule.APIGroups {
					switch apiGroup {
					case "gateway.networking.k8s.io":
						if !slices.Equal(rule.Resources, []string{"gateways"}) {
							t.Errorf("unexpected resources in gateway.networking.k8s.io rule: %v", rule.Resources)
						}
					default:
						t.Errorf("unexpected apiGroup in DNS RBAC: %q", apiGroup)
					}
				}

				for _, verb := range rule.Verbs {
					if verb != "get" && verb != "list" && verb != "watch" {
						t.Errorf("unexpected verb in DNS RBAC rule: %q", verb)
					}
				}
			}
		}

		var deploy appsv1.Deployment
		if err := yaml.Unmarshal([]byte(doc), &deploy); err == nil && deploy.Kind == "Deployment" && deploy.Name == "localgateway-dns" {
			foundDeploy = true

			// Acceptance criterion: The manifest runs it with host networking
			if !deploy.Spec.Template.Spec.HostNetwork {
				t.Errorf("expected hostNetwork: true in DNS deployment spec")
			}

			// SecurityContext: non-root without privilege escalation
			if len(deploy.Spec.Template.Spec.Containers) == 0 {
				t.Fatalf("expected containers in Deployment template")
			}
			container := deploy.Spec.Template.Spec.Containers[0]
			if container.SecurityContext == nil {
				t.Fatalf("expected container SecurityContext to be set")
			}
			if container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot {
				t.Errorf("expected runAsNonRoot: true")
			}
			if container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				t.Errorf("expected allowPrivilegeEscalation: false")
			}
		}
	}

	if !foundClusterRole {
		t.Fatalf("ClusterRole localgateway-dns not found in %s", manifestPath)
	}
	if !foundDeploy {
		t.Fatalf("Deployment localgateway-dns not found in %s", manifestPath)
	}
}
