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

func TestBuildOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := BuildOptions([]string{})
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}
		if cfg.GatewayClass != DefaultGatewayClassName {
			t.Errorf("expected GatewayClass %q, got %q", DefaultGatewayClassName, cfg.GatewayClass)
		}
		if cfg.Interface != "" {
			t.Errorf("expected empty Interface, got %q", cfg.Interface)
		}
		if cfg.MDNSPort != mdns.DefaultPort {
			t.Errorf("expected MDNSPort %d, got %d", mdns.DefaultPort, cfg.MDNSPort)
		}
		if cfg.MetricsAddr != "0" {
			t.Errorf("expected MetricsAddr %q, got %q", "0", cfg.MetricsAddr)
		}
	})

	t.Run("custom flags", func(t *testing.T) {
		args := []string{
			"--gateway-class=custom-class",
			"--interface=eth0",
			"--mdns-port=5354",
			"--metrics-bind-address=:9090",
		}
		cfg, err := BuildOptions(args)
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}
		if cfg.GatewayClass != "custom-class" {
			t.Errorf("expected GatewayClass custom-class, got %q", cfg.GatewayClass)
		}
		if cfg.Interface != "eth0" {
			t.Errorf("expected Interface eth0, got %q", cfg.Interface)
		}
		if cfg.MDNSPort != 5354 {
			t.Errorf("expected MDNSPort 5354, got %d", cfg.MDNSPort)
		}
		if cfg.MetricsAddr != ":9090" {
			t.Errorf("expected MetricsAddr :9090, got %q", cfg.MetricsAddr)
		}
	})
}

// TestGatewayReconciler_AnnounceAndWithdraw verifies that with a fake API server:
// 1. A Gateway with a .local hostname and an address causes the responder to announce that name and address.
// 2. Removing the Gateway withdraws it (sends a goodbye packet and removes the record).
func TestGatewayReconciler_AnnounceAndWithdraw(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	announcedCh := make(chan []byte, 10)
	goodbyeCh := make(chan []byte, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := mdns.NewPublisher(mdns.PublisherOptions{
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
			var p dnsmessage.Parser
			if _, err := p.Start(raw); err != nil {
				return
			}
			if err := p.SkipAllQuestions(); err != nil {
				return
			}
			for {
				h, err := p.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(h.Name.String(), "app.local.") {
					if h.TTL == 0 {
						goodbyeCh <- raw
					} else {
						announcedCh <- raw
					}
				}
				if err := p.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	hName := gatewayv1.Hostname("app.local")
	ipAddrType := gatewayv1.IPAddressType
	targetIP := "192.168.1.100"

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  gwKey.Namespace,
			Name:       gwKey.Name,
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: DefaultGatewayClassName,
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hName,
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
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &GatewayReconciler{
		Client:           cl,
		GatewayClassName: DefaultGatewayClassName,
		Publisher:        pub,
	}

	// 1. Reconcile with the Gateway present -> should probe and announce
	req := ctrl.Request{NamespacedName: gwKey}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	select {
	case raw := <-announcedCh:
		var p dnsmessage.Parser
		_, _ = p.Start(raw)
		_ = p.SkipAllQuestions()
		h, err := p.AnswerHeader()
		if err != nil || h.TTL == 0 {
			t.Fatalf("expected non-zero TTL in announcement, got %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for app.local announcement")
	}

	rec, ok := pub.Responder().GetRecord("app.local")
	if !ok {
		t.Fatalf("expected responder to have record for app.local")
	}
	if len(rec.A) == 0 || rec.A[0].String() != targetIP {
		t.Fatalf("expected responder record A to be %s, got %+v", targetIP, rec.A)
	}

	// 2. Remove the Gateway -> should withdraw
	if err := cl.Delete(ctx, gw); err != nil {
		t.Fatalf("failed to delete gateway: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile on delete failed: %v", err)
	}

	select {
	case raw := <-goodbyeCh:
		var p dnsmessage.Parser
		_, _ = p.Start(raw)
		_ = p.SkipAllQuestions()
		h, err := p.AnswerHeader()
		if err != nil || h.TTL != 0 {
			t.Fatalf("expected TTL 0 in goodbye answer, got %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for app.local goodbye packet")
	}

	if _, ok := pub.Responder().GetRecord("app.local"); ok {
		t.Fatalf("expected record for app.local to be withdrawn from responder")
	}
}

// TestGatewayReconciler_IgnoresOtherGatewayClasses verifies that Gateways with a different
// GatewayClassName are not published.
func TestGatewayReconciler_IgnoresOtherGatewayClasses(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := mdns.NewPublisher(mdns.PublisherOptions{
		Interface:     "lo",
		Port:          ephemeralPort,
		IPv4Conn:      rawConn,
		DisableIPv6:   true,
		ProbeInterval: 10 * time.Millisecond,
		ProbeCount:    1,
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	gwKey := types.NamespacedName{Namespace: "default", Name: "other-gw"}
	hName := gatewayv1.Hostname("other.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "unrelated-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.50"}},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		Build()

	reconciler := &GatewayReconciler{
		Client:           cl,
		GatewayClassName: DefaultGatewayClassName,
		Publisher:        pub,
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if _, ok := pub.Responder().GetRecord("other.local"); ok {
		t.Fatalf("unrelated GatewayClass should not be published in responder")
	}
}

// TestDNSManifest_RBACAndHostNetworking verifies acceptance criteria:
// 1. The RBAC contains no rule for Secrets.
// 2. The RBAC allows get, list, watch on Gateways and nodes, and nothing else.
// 3. The manifest runs with host networking.
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
				for _, res := range rule.Resources {
					if strings.Contains(strings.ToLower(res), "secret") {
						t.Errorf("RBAC ClusterRole must NOT contain rule for secrets, but found %q", res)
					}
				}

				// Must allow get, list, watch on gateways and nodes, and nothing else
				for _, g := range rule.APIGroups {
					switch g {
					case "gateway.networking.k8s.io":
						if !slices.Equal(rule.Resources, []string{"gateways"}) {
							t.Errorf("unexpected resources in gateway.networking.k8s.io rule: %v", rule.Resources)
						}
					case "":
						if !slices.Equal(rule.Resources, []string{"nodes"}) {
							t.Errorf("unexpected resources in core rule: %v", rule.Resources)
						}
					default:
						t.Errorf("unexpected apiGroup in DNS RBAC: %q", g)
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
		}
	}

	if !foundClusterRole {
		t.Fatalf("ClusterRole localgateway-dns not found in %s", manifestPath)
	}
	if !foundDeploy {
		t.Fatalf("Deployment localgateway-dns not found in %s", manifestPath)
	}
}
