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
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func setupStateAndPublisher(t *testing.T, ctx context.Context, initialObjects ...client.Object) (*state.State, client.Client, *Publisher) {
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
		WithObjects(initialObjects...).
		Build()

	controllerState := state.NewState()
	internalProxy := proxy.NewProxy()

	controllerState.SetControllerName("github.com/gke-labs/gateway-api-reference-implementation/localgateway")
	controllerState.SetListenerValidator(validation.ValidateListener)
	controllerState.SetProxy(internalProxy)

	dnsPublisher := NewPublisher(fakeClient, DefaultConfigSecretNamespace, DefaultConfigSecretName, controllerState)
	startErrChan := make(chan error, 1)
	go func() {
		startErrChan <- dnsPublisher.Start(ctx)
	}()

	t.Cleanup(func() {
		if err := <-startErrChan; err != nil {
			t.Errorf("dnsPublisher.Start returned unexpected error: %v", err)
		}
	})

	return controllerState, fakeClient, dnsPublisher
}

func makePublisherTestGateway(name, hostname string, createdAt time.Time) *gatewayv1.Gateway {
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

func waitForConfig(t *testing.T, ctx context.Context, kubernetesClient client.Client, condition func(config *Config) bool) *Config {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		var secret corev1.Secret
		err := kubernetesClient.Get(ctx, types.NamespacedName{Namespace: DefaultConfigSecretNamespace, Name: DefaultConfigSecretName}, &secret)
		if err == nil {
			payload, ok := secret.Data[ConfigSecretDataKey]
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

// TestPublisher_StartReturnsAfterContextCancel verifies that Publisher.Start wakes up
// and terminates cleanly when its context is canceled straight away.
func TestPublisher_StartReturnsAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel straight away without arbitrary sleeps

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	controllerState := state.NewState()
	dnsPublisher := NewPublisher(fakeClient, DefaultConfigSecretNamespace, DefaultConfigSecretName, controllerState)

	startErr := make(chan error, 1)
	go func() {
		startErr <- dnsPublisher.Start(ctx)
	}()

	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("Publisher.Start returned unexpected error on cancel: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Publisher.Start did not return within 1s after context cancel")
	}
}

// TestPublisher_UnsyncedStateDoesNotDeleteExistingSecret verifies that an existing
// Secret survives Publisher startup while the State is unsynced, and once the State is
// marked synced with no Gateways, the publisher publishes and deletes the stale Secret.
func TestPublisher_UnsyncedStateDoesNotDeleteExistingSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	existingConfig := &Config{
		Revision: "initial-revision",
		Records: []Record{
			{Name: "app.local", Addresses: []string{"192.168.1.50"}},
		},
	}
	payload, err := json.Marshal(existingConfig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: DefaultConfigSecretNamespace,
			Name:      DefaultConfigSecretName,
		},
		Data: map[string][]byte{
			ConfigSecretDataKey: payload,
		},
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingSecret).
		Build()

	controllerState := state.NewState()
	controllerState.SetSynced(false) // State is unsynced on startup, with no Gateways

	dnsPublisher := NewPublisher(fakeClient, DefaultConfigSecretNamespace, DefaultConfigSecretName, controllerState)

	startErr := make(chan error, 1)
	go func() {
		startErr <- dnsPublisher.Start(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		if err := <-startErr; err != nil {
			t.Errorf("Publisher.Start returned unexpected error: %v", err)
		}
	})

	// 1. Verify existing Secret survives while state is unsynced.
	survivingConfig := waitForConfig(t, ctx, fakeClient, func(config *Config) bool {
		return config != nil && config.Revision == "initial-revision"
	})
	if survivingConfig == nil {
		t.Fatalf("expected existing Secret to survive startup while state is unsynced")
	}

	// 2. Mark state as synced with no Gateways; publisher polls, detects sync, and deletes the Secret.
	controllerState.SetSynced(true)

	// Wait with deadline for Secret to be deleted (nil config).
	waitForConfig(t, ctx, fakeClient, func(config *Config) bool {
		return config == nil
	})
}

// TestPublisher_PublishesUpdatesAndDeletesConfig verifies that Publisher writes the Secret
// when Gateways become programmed, updates it when Gateway configuration changes,
// and deletes the Secret when all Gateways are removed.
func TestPublisher_PublishesUpdatesAndDeletesConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	controllerState, fakeClient, _ := setupStateAndPublisher(t, ctx)

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "github.com/gke-labs/gateway-api-reference-implementation/localgateway",
		},
	}
	controllerState.UpsertGatewayClass(gatewayClass)

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gateway := makePublisherTestGateway("my-gw", "app.local", time.Now())
	controllerState.UpsertGateway(gateway)
	controllerState.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
	controllerState.SetSynced(true)
	controllerState.Recompute()

	// 1. Initial publish writes the Secret
	config := waitForConfig(t, ctx, fakeClient, func(config *Config) bool {
		return config != nil && len(config.Records) == 1 && slices.Contains(config.Records[0].Addresses, "192.168.1.100")
	})
	if config == nil {
		t.Fatalf("expected Gateway to hold app.local")
	}

	// 2. Gateway addresses update -> Secret is updated
	controllerState.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.200"}})
	controllerState.Recompute()

	updatedConfig := waitForConfig(t, ctx, fakeClient, func(config *Config) bool {
		return config != nil && len(config.Records) == 1 && slices.Contains(config.Records[0].Addresses, "192.168.1.200")
	})
	if updatedConfig == nil {
		t.Fatalf("expected Secret to be updated with 192.168.1.200")
	}

	// 3. Gateway loses Programmed -> Secret is deleted
	controllerState.SetGatewayProvisioningErrors(gatewayKey, nil, &state.ConditionError{Type: string(gatewayv1.GatewayConditionProgrammed)})
	controllerState.Recompute()

	waitForConfig(t, ctx, fakeClient, func(config *Config) bool {
		return config == nil || len(config.Records) == 0
	})
}

// TestPublisher_RefusesConflictingOwner verifies that Publisher refuses to overwrite
// or delete an existing Secret owned by another controller.
func TestPublisher_RefusesConflictingOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	isController := true
	ownedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: DefaultConfigSecretNamespace,
			Name:      DefaultConfigSecretName,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "gateway.networking.k8s.io/v1",
					Kind:       "Gateway",
					Name:       "other-gateway",
					UID:        "other-uid",
					Controller: &isController,
				},
			},
		},
		Data: map[string][]byte{
			ConfigSecretDataKey: []byte("foreign-content"),
		},
	}

	controllerState, fakeClient, _ := setupStateAndPublisher(t, ctx, ownedSecret)

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "github.com/gke-labs/gateway-api-reference-implementation/localgateway",
		},
	}
	controllerState.UpsertGatewayClass(gatewayClass)

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	gateway := makePublisherTestGateway("my-gw", "app.local", time.Now())
	controllerState.UpsertGateway(gateway)
	controllerState.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
	controllerState.SetSynced(true)
	controllerState.Recompute()

	// Wait briefly and verify the existing Secret was NOT overwritten
	time.Sleep(100 * time.Millisecond)
	var secret corev1.Secret
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: DefaultConfigSecretNamespace, Name: DefaultConfigSecretName}, &secret); err != nil {
		t.Fatalf("failed to get Secret: %v", err)
	}
	if string(secret.Data[ConfigSecretDataKey]) != "foreign-content" {
		t.Fatalf("expected existing owned Secret to be preserved, got %q", string(secret.Data[ConfigSecretDataKey]))
	}
}
