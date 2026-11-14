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
	"encoding/json"
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestAddressProvider_Readiness(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	podUnready := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snigateway-controller-1",
			Namespace: "default",
			Labels:    map[string]string{"app": "snigateway-controller"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(podUnready).Build()
	provider := newAddressProvider("snigateway-controller", "default", "test-gw", "default", "frontend.example.com")
	provider.client = client

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
	}

	addresses, readiness, err := provider.GatewayAddressesWithReadiness(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected readiness.Ready=false, got true")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Errorf("expected Reason=Pending, got %s", readiness.Reason)
	}
	if !strings.Contains(strings.ToLower(readiness.Message), "tunnel") {
		t.Errorf("expected message to mention tunnel, got %s", readiness.Message)
	}
	if len(addresses) != 1 || addresses[0].Value != "frontend.example.com" {
		t.Errorf("expected frontend.example.com address, got %+v", addresses)
	}

	// Gateway other than configured single Gateway reports unready with demo message
	otherGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-gw",
			Namespace: "default",
		},
	}
	_, otherReadiness, err := provider.GatewayAddressesWithReadiness(t.Context(), otherGateway, nil)
	if err != nil {
		t.Fatalf("unexpected error for other gateway: %v", err)
	}
	if otherReadiness.Ready {
		t.Errorf("expected otherGateway readiness.Ready=false, got true")
	}
	if !strings.Contains(otherReadiness.Message, "serves only Gateway default/test-gw") {
		t.Errorf("expected single-gateway message, got %s", otherReadiness.Message)
	}

	// Mark pod ready
	podReady := podUnready.DeepCopy()
	podReady.Status.Conditions[0].Status = corev1.ConditionTrue
	if err := client.Status().Update(t.Context(), podReady); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	_, readiness, err = provider.GatewayAddressesWithReadiness(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready {
		t.Errorf("expected readiness.Ready=true, got false")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Reason=Programmed, got %s", readiness.Reason)
	}
}

func TestAddressProvider_NoHostnamesGateway(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	podReady := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "snigateway-controller-1",
			Namespace: "default",
			Labels:    map[string]string{"app": "snigateway-controller"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(podReady).Build()
	provider := newAddressProvider("snigateway-controller", "default", "http-gw", "default", "127.0.0.1")
	provider.client = client

	httpGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "snigateway",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, readiness, err := provider.GatewayAddressesWithReadiness(t.Context(), httpGateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready {
		t.Errorf("expected ready=true for Gateway with no HTTPS/TLS hostnames when pod is ready, got false: %s", readiness.Message)
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Reason=Programmed, got %s", readiness.Reason)
	}
}

func TestAddressProvider_PublishDataplaneConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := newAddressProvider("snigateway-controller", "default", "my-gateway", "default", "10.0.0.1")
	provider.client = client

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gateway",
			Namespace: "default",
			UID:       types.UID("12345"),
		},
	}

	dataplaneConfig := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "default", Name: "my-gateway"},
		Listeners: []state.InternalListener{
			{Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Hostname: "app.example.com"},
		},
	}

	if err := provider.PublishDataplaneConfig(t.Context(), gateway, dataplaneConfig); err != nil {
		t.Fatalf("failed to publish config: %v", err)
	}

	secretName := singlepod.ResourceNameForGateway("my-gateway")
	var secret corev1.Secret
	if err := client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: secretName}, &secret); err != nil {
		t.Fatalf("failed to get Secret %s: %v", secretName, err)
	}

	data := secret.Data[singlepod.DataplaneSecretDataKey]
	var readConfig state.DataplaneConfig
	if err := json.Unmarshal(data, &readConfig); err != nil {
		t.Fatalf("failed to unmarshal Secret data: %v", err)
	}
	if len(readConfig.Listeners) != 1 || readConfig.Listeners[0].Hostname != "app.example.com" {
		t.Errorf("unexpected listeners in published config: %+v", readConfig.Listeners)
	}

	// Update config
	dataplaneConfig.Listeners = append(dataplaneConfig.Listeners, state.InternalListener{
		Name:     "https-2",
		Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: "app2.example.com",
	})
	if err := provider.PublishDataplaneConfig(t.Context(), gateway, dataplaneConfig); err != nil {
		t.Fatalf("failed to update published config: %v", err)
	}

	if err := client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: secretName}, &secret); err != nil {
		t.Fatalf("failed to get updated Secret: %v", err)
	}
	data = secret.Data[singlepod.DataplaneSecretDataKey]
	if err := json.Unmarshal(data, &readConfig); err != nil {
		t.Fatalf("failed to unmarshal updated Secret data: %v", err)
	}
	if len(readConfig.Listeners) != 2 {
		t.Errorf("expected 2 listeners after update, got %d", len(readConfig.Listeners))
	}

	// When config is nil, Secret is deleted
	if err := provider.PublishDataplaneConfig(t.Context(), gateway, nil); err != nil {
		t.Fatalf("failed to delete published config: %v", err)
	}
	if err := client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: secretName}, &secret); !apierrors.IsNotFound(err) {
		t.Errorf("expected Secret to be deleted when config is nil, got err: %v", err)
	}
}

func TestExtractHostnamesFromConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *state.DataplaneConfig
		wantHostnames []string
	}{
		{
			name: "Multiple distinct listeners",
			config: &state.DataplaneConfig{
				Listeners: []state.InternalListener{
					{Name: "h1", Protocol: gatewayv1.HTTPSProtocolType, Hostname: "B.example.com"},
					{Name: "h2", Protocol: gatewayv1.TLSProtocolType, Hostname: "a.example.com"},
					{Name: "h3", Protocol: gatewayv1.HTTPProtocolType, Hostname: "c.example.com"},
					{Name: "h4", Protocol: gatewayv1.HTTPSProtocolType, Hostname: ""},
				},
			},
			wantHostnames: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "Several listeners with the same hostname are deduplicated",
			config: &state.DataplaneConfig{
				Listeners: []state.InternalListener{
					{Name: "l1", Protocol: gatewayv1.HTTPSProtocolType, Hostname: "shared.example.com"},
					{Name: "l2", Protocol: gatewayv1.HTTPSProtocolType, Hostname: "SHARED.example.com"},
					{Name: "l3", Protocol: gatewayv1.TLSProtocolType, Hostname: " shared.example.com "},
				},
			},
			wantHostnames: []string{"shared.example.com"},
		},
		{
			name: "Config with no hostnames (HTTP only)",
			config: &state.DataplaneConfig{
				Listeners: []state.InternalListener{
					{Name: "http-1", Protocol: gatewayv1.HTTPProtocolType, Hostname: "http.example.com"},
					{Name: "http-2", Protocol: gatewayv1.HTTPProtocolType, Hostname: ""},
				},
			},
			wantHostnames: nil,
		},
		{
			name:          "Empty config",
			config:        &state.DataplaneConfig{},
			wantHostnames: nil,
		},
		{
			name:          "Nil config",
			config:        nil,
			wantHostnames: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnel.ExtractHostnamesFromConfig(tc.config)
			if len(got) != len(tc.wantHostnames) {
				t.Fatalf("got %v, want %v", got, tc.wantHostnames)
			}
			for i := range tc.wantHostnames {
				if got[i] != tc.wantHostnames[i] {
					t.Errorf("got[%d]=%q, want %q", i, got[i], tc.wantHostnames[i])
				}
			}
		})
	}
}
