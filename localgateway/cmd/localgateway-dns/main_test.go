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
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	return scheme
}

func isNormalClose(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

func startTestPublisherWithTap(t *testing.T, ctx context.Context) (*mdns.Publisher, <-chan string, <-chan string) {
	t.Helper()

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	announcedChannel := make(chan string, 20)
	withdrawnChannel := make(chan string, 20)

	publisher, err := mdns.NewPublisher(mdns.PublisherOptions{
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
				name := strings.TrimSuffix(header.Name.String(), ".")
				if header.TTL == 0 {
					withdrawnChannel <- name
				} else {
					announcedChannel <- name
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})
	if err != nil {
		_ = rawConn.Close()
		t.Fatalf("NewPublisher failed: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- publisher.Start(ctx)
	}()

	t.Cleanup(func() {
		if err := publisher.Close(); err != nil && !isNormalClose(err) {
			t.Errorf("publisher.Close failed: %v", err)
		}
		if err := rawConn.Close(); err != nil && !isNormalClose(err) {
			t.Errorf("rawConn.Close failed: %v", err)
		}
		if err := <-errChan; err != nil {
			t.Errorf("publisher.Start returned unexpected error: %v", err)
		}
	})

	return publisher, announcedChannel, withdrawnChannel
}

func buildTestGateway(name, hostname, address string, creationTime time.Time, gatewayProgrammed, listenerAccepted, listenerProgrammed bool) *gatewayv1.Gateway {
	hName := gatewayv1.Hostname(hostname)
	ipAddrType := gatewayv1.IPAddressType

	gwCondStatus := metav1.ConditionFalse
	gwReason := "NotProgrammed"
	if gatewayProgrammed {
		gwCondStatus = metav1.ConditionTrue
		gwReason = string(gatewayv1.GatewayReasonProgrammed)
	}

	lisAcceptedStatus := metav1.ConditionFalse
	lisAcceptedReason := "NotAccepted"
	if listenerAccepted {
		lisAcceptedStatus = metav1.ConditionTrue
		lisAcceptedReason = string(gatewayv1.ListenerReasonAccepted)
	}

	lisProgStatus := metav1.ConditionFalse
	lisProgReason := "NotProgrammed"
	if listenerProgrammed {
		lisProgStatus = metav1.ConditionTrue
		lisProgReason = string(gatewayv1.ListenerReasonProgrammed)
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: defaultGatewayClassName,
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
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionProgrammed),
					Status: gwCondStatus,
					Reason: gwReason,
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionAccepted),
							Status: lisAcceptedStatus,
							Reason: lisAcceptedReason,
						},
						{
							Type:   string(gatewayv1.ListenerConditionProgrammed),
							Status: lisProgStatus,
							Reason: lisProgReason,
						},
					},
				},
			},
		},
	}

	if !creationTime.IsZero() {
		gw.CreationTimestamp = metav1.NewTime(creationTime)
	}
	if address != "" {
		gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{
			{
				Type:  &ipAddrType,
				Value: address,
			},
		}
	}
	return gw
}

func waitForName(t *testing.T, ch <-chan string, expectedName string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case name := <-ch:
			if strings.EqualFold(name, expectedName) {
				return
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %s", expectedName)
		}
	}
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
	ctx := t.Context()
	scheme := newTestScheme(t)
	publisher, announcedChan, withdrawnChan := startTestPublisherWithTap(t, ctx)

	gateway := buildTestGateway("my-gateway", "app.local", "192.168.1.100", time.Time{}, true, true, true)
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
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	waitForName(t, announcedChan, "app.local")

	record, ok := publisher.Responder().GetRecord("app.local")
	if !ok {
		t.Fatalf("expected responder to have record for app.local")
	}
	if len(record.A) == 0 || record.A[0].String() != "192.168.1.100" {
		t.Fatalf("expected responder record A to be 192.168.1.100, got %+v", record.A)
	}

	// 2. Remove the Gateway -> should withdraw
	if err := testClient.Delete(ctx, gateway); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile on delete failed: %v", err)
	}

	waitForName(t, withdrawnChan, "app.local")

	if _, ok := publisher.Responder().GetRecord("app.local"); ok {
		t.Fatalf("expected record for app.local to be withdrawn from responder")
	}
}

// TestGatewayReconciler_RequiresAcceptedAndProgrammed verifies that a listener is only published
// when the Gateway's Programmed condition and the listener's Accepted and Programmed conditions are true.
// A second fully-programmed sentinel Gateway is used in each negative step to ensure the reconcile batch
// completes before asserting the absence of the candidate's record. A final step verifies withdrawal
// when a published Gateway loses its Programmed condition.
func TestGatewayReconciler_RequiresAcceptedAndProgrammed(t *testing.T) {
	ctx := t.Context()
	scheme := newTestScheme(t)
	publisher, announcedChan, withdrawnChan := startTestPublisherWithTap(t, ctx)

	candidate := buildTestGateway("candidate", "candidate.local", "192.168.1.10", time.Time{}, false, false, false)
	witness := buildTestGateway("witness", "witness.local", "192.168.1.20", time.Time{}, true, true, true)

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(candidate, witness).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:           testClient,
		gatewayClassName: defaultGatewayClassName,
		publisher:        publisher,
	}

	// 1. Both Gateway and listener are not programmed -> should not publish candidate
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	waitForName(t, announcedChan, "witness.local")
	if _, ok := publisher.Responder().GetRecord("candidate.local"); ok {
		t.Fatalf("expected candidate.local not to be published when Programmed=False")
	}

	// 2. Gateway Programmed=True, but listener Accepted=False -> should not publish candidate
	candidate.Status.Conditions[0].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, candidate); err != nil {
		t.Fatalf("Status update candidate failed: %v", err)
	}
	witness2 := buildTestGateway("witness2", "witness2.local", "192.168.1.22", time.Time{}, true, true, true)
	if err := testClient.Create(ctx, witness2); err != nil {
		t.Fatalf("Create witness2 failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	waitForName(t, announcedChan, "witness2.local")
	if _, ok := publisher.Responder().GetRecord("candidate.local"); ok {
		t.Fatalf("expected candidate.local not to be published when listener Accepted=False")
	}

	// 3. Gateway Programmed=True, listener Accepted=True, but listener Programmed=False -> should not publish candidate
	candidate.Status.Listeners[0].Conditions[0].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, candidate); err != nil {
		t.Fatalf("Status update candidate failed: %v", err)
	}
	witness3 := buildTestGateway("witness3", "witness3.local", "192.168.1.23", time.Time{}, true, true, true)
	if err := testClient.Create(ctx, witness3); err != nil {
		t.Fatalf("Create witness3 failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	waitForName(t, announcedChan, "witness3.local")
	if _, ok := publisher.Responder().GetRecord("candidate.local"); ok {
		t.Fatalf("expected candidate.local not to be published when listener Programmed=False")
	}

	// 4. Gateway Programmed=True, listener Accepted=True AND Programmed=True -> should publish candidate
	candidate.Status.Listeners[0].Conditions[1].Status = metav1.ConditionTrue
	if err := testClient.Status().Update(ctx, candidate); err != nil {
		t.Fatalf("Status update candidate failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	waitForName(t, announcedChan, "candidate.local")
	if _, ok := publisher.Responder().GetRecord("candidate.local"); !ok {
		t.Fatalf("expected candidate.local to be published when all conditions are True")
	}

	// 5. Candidate loses Programmed condition -> should be withdrawn with a goodbye packet
	candidate.Status.Conditions[0].Status = metav1.ConditionFalse
	if err := testClient.Status().Update(ctx, candidate); err != nil {
		t.Fatalf("Status update candidate failed: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	waitForName(t, withdrawnChan, "candidate.local")
	if _, ok := publisher.Responder().GetRecord("candidate.local"); ok {
		t.Fatalf("expected candidate.local to be withdrawn when Programmed condition is lost")
	}
}

// TestGatewayReconciler_DeterministicConflictResolutionBothOrders verifies that when two Gateways
// claim the same hostname, the oldest Gateway by creation time wins regardless of API list order.
func TestGatewayReconciler_DeterministicConflictResolutionBothOrders(t *testing.T) {
	scheme := newTestScheme(t)

	now := time.Now()
	olderTime := now.Add(-10 * time.Minute)
	newerTime := now.Add(-5 * time.Minute)

	olderIP := "192.168.1.100"
	newerIP := "192.168.1.200"

	testCases := []struct {
		name     string
		gateways []*gatewayv1.Gateway
	}{
		{
			name: "older first in list order",
			gateways: []*gatewayv1.Gateway{
				buildTestGateway("gw-older", "shared.local", olderIP, olderTime, true, true, true),
				buildTestGateway("gw-newer", "shared.local", newerIP, newerTime, true, true, true),
			},
		},
		{
			name: "newer first in list order",
			gateways: []*gatewayv1.Gateway{
				buildTestGateway("gw-newer", "shared.local", newerIP, newerTime, true, true, true),
				buildTestGateway("gw-older", "shared.local", olderIP, olderTime, true, true, true),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			publisher, announcedChan, _ := startTestPublisherWithTap(t, ctx)

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

			waitForName(t, announcedChan, "shared.local")

			record, ok := publisher.Responder().GetRecord("shared.local")
			if !ok {
				t.Fatalf("expected responder to have record for shared.local")
			}
			if len(record.A) == 0 || record.A[0].String() != olderIP {
				t.Fatalf("expected deterministic winner to be older Gateway IP %s, got %+v", olderIP, record.A)
			}
		})
	}
}

// TestGatewayReconciler_IgnoresOtherGatewayClasses verifies that Gateways with a different
// GatewayClassName are not published, using a tap wait rather than a fixed sleep.
func TestGatewayReconciler_IgnoresOtherGatewayClasses(t *testing.T) {
	ctx := t.Context()
	scheme := newTestScheme(t)
	publisher, announcedChan, _ := startTestPublisherWithTap(t, ctx)

	otherGateway := buildTestGateway("other-gw", "other.local", "192.168.1.50", time.Time{}, true, true, true)
	otherGateway.Spec.GatewayClassName = "unrelated-class"

	matchingGateway := buildTestGateway("matching-gw", "matching.local", "192.168.1.100", time.Time{}, true, true, true)

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
	waitForName(t, announcedChan, "matching.local")

	if _, ok := publisher.Responder().GetRecord("other.local"); ok {
		t.Fatalf("unrelated GatewayClass should not be published in responder")
	}
}

// TestPublisher_ShutdownSendsGoodbye verifies that cancelling the publisher context
// sends a goodbye packet for all published hostnames.
func TestPublisher_ShutdownSendsGoodbye(t *testing.T) {
	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())
	scheme := newTestScheme(t)
	publisher, announcedChan, withdrawnChan := startTestPublisherWithTap(t, shutdownCtx)

	gateway := buildTestGateway("gw-shutdown", "shutdown.local", "192.168.1.100", time.Time{}, true, true, true)
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

	waitForName(t, announcedChan, "shutdown.local")

	if _, ok := publisher.Responder().GetRecord("shutdown.local"); !ok {
		t.Fatalf("expected record to be published before shutdown")
	}

	// Cancel context to simulate manager stopping the publisher
	cancelShutdown()

	waitForName(t, withdrawnChan, "shutdown.local")
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
