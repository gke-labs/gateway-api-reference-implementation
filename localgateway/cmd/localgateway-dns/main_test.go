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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	return scheme
}

func isNormalClose(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

func startTestResponderWithTap(t *testing.T) (*mdns.Responder, net.PacketConn, <-chan string, <-chan string) {
	t.Helper()

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	announcedChannel := make(chan string, 20)
	withdrawnChannel := make(chan string, 20)

	responder, err := mdns.NewResponder(mdns.ResponderOptions{
		InterfaceName: "lo",
		Port:          ephemeralPort,
		IPv4Conn:      rawConn,
		DisableIPv6:   true,
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
		t.Fatalf("NewResponder failed: %v", err)
	}

	t.Cleanup(func() {
		if err := responder.Close(); err != nil && !isNormalClose(err) {
			t.Errorf("responder.Close failed: %v", err)
		}
		if err := rawConn.Close(); err != nil && !isNormalClose(err) {
			t.Errorf("rawConn.Close failed: %v", err)
		}
	})

	return responder, rawConn, announcedChannel, withdrawnChannel
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

func makeConfigSecret(namespace, name string, records []dnsconfig.Record) *corev1.Secret {
	cfg := &dnsconfig.Config{
		Records: records,
	}
	rev, _ := cfg.ComputeRevision()
	cfg.Revision = rev
	data, _ := cfg.Marshal()

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string][]byte{
			dnsconfig.DefaultSecretDataKey: data,
		},
	}
}

func TestBuildOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		configuration, err := buildOptions([]string{})
		if err != nil {
			t.Fatalf("buildOptions failed: %v", err)
		}
		if configuration.secretName != dnsconfig.DefaultSecretName {
			t.Errorf("expected secretName %q, got %q", dnsconfig.DefaultSecretName, configuration.secretName)
		}
		if configuration.secretNamespace != dnsconfig.DefaultSecretNamespace {
			t.Errorf("expected secretNamespace %q, got %q", dnsconfig.DefaultSecretNamespace, configuration.secretNamespace)
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
			"--config-secret=custom-dns",
			"--config-namespace=custom-ns",
			"--interface=eth0",
			"--mdns-port=5354",
			"--metrics-bind-address=:9090",
		}
		configuration, err := buildOptions(args)
		if err != nil {
			t.Fatalf("buildOptions failed: %v", err)
		}
		if configuration.secretName != "custom-dns" {
			t.Errorf("expected secretName custom-dns, got %q", configuration.secretName)
		}
		if configuration.secretNamespace != "custom-ns" {
			t.Errorf("expected secretNamespace custom-ns, got %q", configuration.secretNamespace)
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

	t.Run("empty config-secret fails", func(t *testing.T) {
		_, err := buildOptions([]string{"--config-secret="})
		if err == nil {
			t.Fatalf("expected error for empty --config-secret, got nil")
		}
	})

	t.Run("empty config-namespace fails", func(t *testing.T) {
		_, err := buildOptions([]string{"--config-namespace="})
		if err == nil {
			t.Fatalf("expected error for empty --config-namespace, got nil")
		}
	})
}

// TestConfigReconciler_AnnounceAndWithdraw verifies acceptance criterion:
// With a fake config source, a record in the config is announced, and removing it sends a goodbye.
func TestConfigReconciler_AnnounceAndWithdraw(t *testing.T) {
	ctx := t.Context()
	scheme := newTestScheme(t)
	responder, _, announcedChan, withdrawnChan := startTestResponderWithTap(t)

	secretNamespace := "default"
	secretName := "localgateway-dns"

	secret := makeConfigSecret(secretNamespace, secretName, []dnsconfig.Record{
		{
			Name:      "app.local",
			Addresses: []string{"192.168.1.100"},
		},
	})

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	reconciler := newConfigReconciler(testClient, secretNamespace, secretName, responder)

	// 1. Reconcile with the record in the Secret -> announced
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: secretNamespace, Name: secretName}}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	waitForName(t, announcedChan, "app.local")

	record, ok := responder.GetRecord("app.local.")
	if !ok {
		t.Fatalf("expected responder to have record for app.local.")
	}
	if len(record.A) == 0 || record.A[0].String() != "192.168.1.100" {
		t.Fatalf("expected responder record A to be 192.168.1.100, got %+v", record.A)
	}

	// 2. Remove the record from the Secret -> withdrawn with a goodbye packet
	secretUpdated := makeConfigSecret(secretNamespace, secretName, []dnsconfig.Record{})
	if err := testClient.Update(ctx, secretUpdated); err != nil {
		t.Fatalf("Update Secret failed: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile after removal failed: %v", err)
	}

	waitForName(t, withdrawnChan, "app.local")

	if _, ok := responder.GetRecord("app.local."); ok {
		t.Fatalf("expected record for app.local. to be withdrawn from responder")
	}
}

// TestConfigReconciler_ShutdownSendsGoodbye verifies that when the reconciler runnable stops,
// goodbyes are sent for all active records.
func TestConfigReconciler_ShutdownSendsGoodbye(t *testing.T) {
	shutdownCtx, cancelShutdown := context.WithCancel(t.Context())
	scheme := newTestScheme(t)
	responder, _, announcedChan, withdrawnChan := startTestResponderWithTap(t)

	secretNamespace := "default"
	secretName := "localgateway-dns"

	secret := makeConfigSecret(secretNamespace, secretName, []dnsconfig.Record{
		{
			Name:      "shutdown.local",
			Addresses: []string{"192.168.1.50"},
		},
	})

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	reconciler := newConfigReconciler(testClient, secretNamespace, secretName, responder)

	errChan := make(chan error, 1)
	go func() {
		errChan <- reconciler.Start(shutdownCtx)
	}()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: secretNamespace, Name: secretName}}
	if _, err := reconciler.Reconcile(shutdownCtx, req); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	waitForName(t, announcedChan, "shutdown.local")

	// Trigger shutdown
	cancelShutdown()

	waitForName(t, withdrawnChan, "shutdown.local")

	if err := <-errChan; err != nil && !isNormalClose(err) {
		t.Errorf("Start returned error: %v", err)
	}
}

// TestDNSManifest_RBACAndHostNetworking verifies acceptance criteria:
// 1. The RBAC contains access ONLY to its own config Secret (localgateway-dns).
// 2. The RBAC has no access to Gateways, TLS Secrets, or other Gateway configs.
// 3. The manifest runs with host networking.
// 4. The container runs with unprivileged securityContext (non-root, no privilege escalation).
func TestDNSManifest_RBACAndHostNetworking(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "k8s", "dns.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", manifestPath, err)
	}

	docs := strings.Split(string(data), "\n---")
	var foundRole bool
	var foundDeploy bool

	for _, doc := range docs {
		var role rbacv1.Role
		if err := yaml.Unmarshal([]byte(doc), &role); err == nil && role.Kind == "Role" && role.Name == "localgateway-dns" {
			foundRole = true

			for _, rule := range role.Rules {
				// Must allow only secrets with resourceNames = ["localgateway-dns"]
				if !slices.Equal(rule.Resources, []string{"secrets"}) {
					t.Errorf("unexpected resources in rule: %v", rule.Resources)
				}
				if !slices.Equal(rule.ResourceNames, []string{"localgateway-dns"}) {
					t.Errorf("expected rule to be restricted to resourceNames [localgateway-dns], got %v", rule.ResourceNames)
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

	if !foundRole {
		t.Fatalf("Role localgateway-dns not found in %s", manifestPath)
	}
	if !foundDeploy {
		t.Fatalf("Deployment localgateway-dns not found in %s", manifestPath)
	}
}
