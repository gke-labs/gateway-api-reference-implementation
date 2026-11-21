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

package hostport

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func setupTestClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	bundleCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-trust-bundle",
		},
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(bundleCM).
		WithReturnManagedFields().
		Build()
}

type hostPortSignature struct {
	containerPort int32
	hostPort      int32
	protocol      corev1.Protocol
}

func extractHostPortSignatures(ports []corev1.ContainerPort) []hostPortSignature {
	var signatures []hostPortSignature
	for _, port := range ports {
		if port.HostPort > 0 {
			signatures = append(signatures, hostPortSignature{
				containerPort: port.ContainerPort,
				hostPort:      port.HostPort,
				protocol:      port.Protocol,
			})
		}
	}
	return signatures
}

func TestHostPortAddressProvider_MatchesSinglePodWithHostPorts(t *testing.T) {
	ctx := t.Context()

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-hp",
			Namespace: "test-ns",
			UID:       types.UID("gw-hp-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
				{Name: "udp", Port: 5353, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		{Name: "udp", Port: 5353, Protocol: gatewayv1.UDPProtocolType},
	}

	resourceName := state.ResourceNameForGateway(gateway.Name)

	// 1. Expected: run existing singlepod provider with WithHostPorts()
	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, "default", singlepod.WithHostPorts())
	expectedAddresses, expectedReadiness, err := singlePodHP.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}

	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	// 2. Actual: run HostPortAddressProvider
	actualClient := setupTestClient(t)
	hostPortProvider, err := New(actualClient, actualClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	actualAddresses, actualReadiness, err := hostPortProvider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}

	var actualDeployment appsv1.Deployment
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &actualDeployment); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	// 3. Deployment rollout strategy verification: RollingUpdate with maxSurge: 0 and maxUnavailable: 1
	if actualDeployment.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("expected Deployment strategy RollingUpdate, got %s", actualDeployment.Spec.Strategy.Type)
	}
	if actualDeployment.Spec.Strategy.RollingUpdate == nil {
		t.Fatalf("expected RollingUpdate strategy configuration")
	}
	if actualDeployment.Spec.Strategy.RollingUpdate.MaxSurge == nil || actualDeployment.Spec.Strategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Errorf("expected maxSurge=0, got %v", actualDeployment.Spec.Strategy.RollingUpdate.MaxSurge)
	}
	if actualDeployment.Spec.Strategy.RollingUpdate.MaxUnavailable == nil || actualDeployment.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected maxUnavailable=1, got %v", actualDeployment.Spec.Strategy.RollingUpdate.MaxUnavailable)
	}

	// Verify strategy matches singlepod.WithHostPorts() exactly
	if !reflect.DeepEqual(actualDeployment.Spec.Strategy, expectedDeployment.Spec.Strategy) {
		t.Errorf("strategy mismatch:\ngot  %+v\nwant %+v", actualDeployment.Spec.Strategy, expectedDeployment.Spec.Strategy)
	}

	// 4. Container ports verification: compare hostPort, containerPort, and protocol with singlepod.WithHostPorts()
	actualPorts := actualDeployment.Spec.Template.Spec.Containers[0].Ports
	expectedPorts := expectedDeployment.Spec.Template.Spec.Containers[0].Ports

	actualSignatures := extractHostPortSignatures(actualPorts)
	expectedSignatures := extractHostPortSignatures(expectedPorts)

	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("host port signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}

	// 5. Verify no Service created
	var service corev1.Service
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &service); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Service to be created, got err: %v", err)
	}

	// 6. Verify address and readiness stub
	if actualReadiness.Ready {
		t.Errorf("expected ready=false in this step")
	}
	if len(actualAddresses) > 0 {
		t.Errorf("expected 0 addresses in this step, got %+v", actualAddresses)
	}
	if !reflect.DeepEqual(actualAddresses, expectedAddresses) {
		t.Errorf("addresses mismatch: got %+v, want %+v", actualAddresses, expectedAddresses)
	}
	if actualReadiness.Ready != expectedReadiness.Ready {
		t.Errorf("readiness.Ready mismatch: got %v, want %v", actualReadiness.Ready, expectedReadiness.Ready)
	}
}

func TestHostPortAddressProvider_ReservedPortsSkipped(t *testing.T) {
	ctx := t.Context()

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-reserved",
			Namespace: "test-ns",
			UID:       types.UID("gw-reserved-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "tcp-reserved", Port: 8080, Protocol: gatewayv1.TCPProtocolType},
				{Name: "udp-reserved", Port: 8443, Protocol: gatewayv1.UDPProtocolType},
				{Name: "health-reserved", Port: 8999, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "tcp-reserved", Port: 8080, Protocol: gatewayv1.TCPProtocolType},
		{Name: "udp-reserved", Port: 8443, Protocol: gatewayv1.UDPProtocolType},
		{Name: "health-reserved", Port: 8999, Protocol: gatewayv1.TCPProtocolType},
	}

	resourceName := state.ResourceNameForGateway(gateway.Name)

	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, "default", singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	actualClient := setupTestClient(t)
	hostPortProvider, err := New(actualClient, actualClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	_, _, err = hostPortProvider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var actualDeployment appsv1.Deployment
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &actualDeployment); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(actualDeployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := extractHostPortSignatures(expectedDeployment.Spec.Template.Spec.Containers[0].Ports)

	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("host port signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}

	// Only port 80 should have a hostPort; reserved ports 8080 TCP, 8443 UDP, and 8999 TCP should be skipped
	if len(actualSignatures) != 1 {
		t.Fatalf("expected exactly 1 host port signature, got %d: %+v", len(actualSignatures), actualSignatures)
	}
	expectedSingle := hostPortSignature{
		containerPort: singlepod.DataPlaneHTTPPort,
		hostPort:      80,
		protocol:      corev1.ProtocolTCP,
	}
	if actualSignatures[0] != expectedSingle {
		t.Errorf("expected port 80 host port mapping %+v, got %+v", expectedSingle, actualSignatures[0])
	}
}

func TestHostPortAddressProvider_NonDefaultPorts(t *testing.T) {
	ctx := t.Context()

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-custom-ports",
			Namespace: "test-ns",
			UID:       types.UID("gw-custom-ports-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "https", Port: 8444, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "https", Port: 8444, Protocol: gatewayv1.HTTPSProtocolType},
	}

	resourceName := state.ResourceNameForGateway(gateway.Name)

	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, "default", singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	actualClient := setupTestClient(t)
	hostPortProvider, err := New(actualClient, actualClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	_, _, err = hostPortProvider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var actualDeployment appsv1.Deployment
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &actualDeployment); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(actualDeployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := extractHostPortSignatures(expectedDeployment.Spec.Template.Spec.Containers[0].Ports)

	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("host port signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}
}

func TestHostPortAddressProvider_UnmatchedContainerPortGetsNoHostPort(t *testing.T) {
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-extra", Namespace: "default"},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
	}

	deployment := appsv1ac.Deployment("dataplane", "default").
		WithSpec(appsv1ac.DeploymentSpec().
			WithTemplate(corev1ac.PodTemplateSpec().
				WithSpec(corev1ac.PodSpec().
					WithContainers(corev1ac.Container().
						WithName(singlepod.DataplaneContainerName).
						WithPorts(
							corev1ac.ContainerPort().
								WithName(singlepod.HTTPPortName).
								WithContainerPort(singlepod.DataPlaneHTTPPort).
								WithProtocol(corev1.ProtocolTCP),
							corev1ac.ContainerPort().
								WithName("tcp-9000").
								WithContainerPort(9000).
								WithProtocol(corev1.ProtocolTCP),
							// Unmatched metrics port that no listener names
							corev1ac.ContainerPort().
								WithName("metrics").
								WithContainerPort(9090).
								WithProtocol(corev1.ProtocolTCP),
							// Unmatched UDP health port that no listener names
							corev1ac.ContainerPort().
								WithName("health-udp").
								WithContainerPort(8999).
								WithProtocol(corev1.ProtocolUDP),
						),
					),
				),
			),
		)

	if err := MutateDeployment(deployment, gateway, effectiveListeners); err != nil {
		t.Fatalf("MutateDeployment failed: %v", err)
	}

	containers := deployment.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	for _, port := range containers[0].Ports {
		portName := ""
		if port.Name != nil {
			portName = *port.Name
		}
		switch portName {
		case singlepod.HTTPPortName:
			if port.HostPort == nil || *port.HostPort != 80 {
				t.Errorf("expected http hostPort=80, got %v", port.HostPort)
			}
		case "tcp-9000":
			if port.HostPort == nil || *port.HostPort != 9000 {
				t.Errorf("expected tcp-9000 hostPort=9000, got %v", port.HostPort)
			}
		case "metrics":
			if port.HostPort != nil && *port.HostPort != 0 {
				t.Errorf("expected metrics to get no hostPort, got %v", *port.HostPort)
			}
		case "health-udp":
			if port.HostPort != nil && *port.HostPort != 0 {
				t.Errorf("expected health-udp to get no hostPort, got %v", *port.HostPort)
			}
		}
	}
}

func TestHostPortAddressProvider_ListenerSetListener(t *testing.T) {
	ctx := t.Context()

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-listenerset",
			Namespace: "test-ns",
			UID:       types.UID("gw-ls-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Owner: state.ListenerOwner{
				Kind:      "Gateway",
				Namespace: "test-ns",
				Name:      "gw-listenerset",
			},
			Name:     "http",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		},
		{
			Owner: state.ListenerOwner{
				Kind:      "ListenerSet",
				Namespace: "test-ns",
				Name:      "my-listenerset",
			},
			Name:     "tcp-ls",
			Port:     9090,
			Protocol: gatewayv1.TCPProtocolType,
		},
	}

	resourceName := state.ResourceNameForGateway(gateway.Name)

	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, "default", singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	actualClient := setupTestClient(t)
	hostPortProvider, err := New(actualClient, actualClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	_, _, err = hostPortProvider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var actualDeployment appsv1.Deployment
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &actualDeployment); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(actualDeployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := extractHostPortSignatures(expectedDeployment.Spec.Template.Spec.Containers[0].Ports)

	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("host port signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}

	// Verify the ListenerSet's TCP port 9090 got a hostPort
	foundListenerSetPort := false
	for _, signature := range actualSignatures {
		if signature.hostPort == 9090 && signature.containerPort == 9090 && signature.protocol == corev1.ProtocolTCP {
			foundListenerSetPort = true
			break
		}
	}
	if !foundListenerSetPort {
		t.Errorf("expected hostPort 9090 from ListenerSet in actual signatures: %+v", actualSignatures)
	}
}

func TestHostPortAddressProvider_ConflictedListenerSkipped(t *testing.T) {
	ctx := t.Context()

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-conflicted",
			Namespace: "test-ns",
			UID:       types.UID("gw-conflicted-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "tcp-conflict", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Name:     "http",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		},
		{
			Name:     "tcp-conflict",
			Port:     9000,
			Protocol: gatewayv1.TCPProtocolType,
			ListenerInfo: state.ListenerInfo{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionConflicted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.ListenerReasonHostnameConflict),
					},
				},
			},
		},
	}

	resourceName := state.ResourceNameForGateway(gateway.Name)

	actualClient := setupTestClient(t)
	hostPortProvider, err := New(actualClient, actualClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	_, _, err = hostPortProvider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var actualDeployment appsv1.Deployment
	if err := actualClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &actualDeployment); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(actualDeployment.Spec.Template.Spec.Containers[0].Ports)
	if len(actualSignatures) != 1 || actualSignatures[0].hostPort != 80 {
		t.Errorf("expected only port 80 host port, got %+v", actualSignatures)
	}
}

func TestHostPortAddressProvider_ContainerMissing(t *testing.T) {
	emptyDeployment := appsv1ac.Deployment("test", "default")
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-empty", Namespace: "default"},
	}

	err := MutateDeployment(emptyDeployment, gateway, nil)
	if err == nil {
		t.Fatalf("expected error when dataplane container is missing, got nil")
	}
}

func TestHostPortAddressProvider_AddressRequestRejected(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	ipAddressType := gatewayv1.IPAddressType
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-request-addr",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddressType, Value: "192.168.1.100"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "localgateway",
		},
	}

	bundleCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-trust-bundle",
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithObjects(gateway, gatewayClass, bundleCM).
		Build()

	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	// 1. SupportedAddressTypes returns nil
	supported := provider.SupportedAddressTypes()
	if supported != nil {
		t.Fatalf("expected SupportedAddressTypes() to be nil, got %+v", supported)
	}

	// 2. Gateway requesting an address is rejected via state.State
	gatewayState := state.NewState()
	gatewayState.SetSupportedAddressTypes(provider.SupportedAddressTypes())
	gatewayState.UpsertGatewayClass(gatewayClass)
	gatewayState.UpsertGateway(gateway)
	gatewayState.Recompute()

	status, ok := gatewayState.GetDesiredGatewayStatus(types.NamespacedName{Namespace: "default", Name: "gw-request-addr"})
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}

	var acceptedCondition *metav1.Condition
	for index := range status.Conditions {
		if status.Conditions[index].Type == string(gatewayv1.GatewayConditionAccepted) {
			acceptedCondition = &status.Conditions[index]
			break
		}
	}
	if acceptedCondition == nil || acceptedCondition.Status != metav1.ConditionFalse || acceptedCondition.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress from State, got %+v", acceptedCondition)
	}

	// 3. Gateway requesting an address is rejected via controller.GatewayReconciler
	reconciler := &controller.GatewayReconciler{
		Client:          testClient,
		Scheme:          scheme,
		State:           gatewayState,
		ControllerName:  "localgateway",
		AddressProvider: provider,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-request-addr"}}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	var reconciledGateway gatewayv1.Gateway
	if err := testClient.Get(ctx, req.NamespacedName, &reconciledGateway); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}

	var reconciledAcceptedCondition *metav1.Condition
	for index := range reconciledGateway.Status.Conditions {
		if reconciledGateway.Status.Conditions[index].Type == string(gatewayv1.GatewayConditionAccepted) {
			reconciledAcceptedCondition = &reconciledGateway.Status.Conditions[index]
			break
		}
	}
	if reconciledAcceptedCondition == nil || reconciledAcceptedCondition.Status != metav1.ConditionFalse || reconciledAcceptedCondition.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress from Reconciler, got %+v", reconciledAcceptedCondition)
	}
}

func TestHostPortAddressProvider_GatewayAddresses(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-simple",
			Namespace: "test-ns",
			UID:       types.UID("gw-simple-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	addresses, readiness, err := provider.GatewayAddresses(t.Context(), gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false")
	}
	if len(addresses) != 0 {
		t.Errorf("expected 0 addresses, got %+v", addresses)
	}
}

func TestHostPortAddressProvider_SetupWatches(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(nil, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	// SetupWatches without scheme/mapper delegates to singlepod and returns an error
	if err := provider.SetupWatches(nil, nil); err == nil {
		t.Fatalf("expected error from SetupWatches without scheme and mapper, got nil")
	}
}

func TestHostPortAddressProvider_NewRequiresReader(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(testClient, nil, "default")
	if err == nil {
		t.Fatalf("expected error when reader is nil, got nil")
	}
	if provider != nil {
		t.Fatalf("expected nil provider when reader is nil, got %+v", provider)
	}
}

func TestHostPortAddressProvider_NewRequiresControllerNamespace(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "")
	if err == nil {
		t.Fatalf("expected error when controllerNamespace is empty, got nil")
	}
	if provider != nil {
		t.Fatalf("expected nil provider when controllerNamespace is empty, got %+v", provider)
	}
}

func TestHostPortAddressProvider_SetState(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gatewayState := state.NewState()
	provider.SetState(gatewayState)
}

func TestHostPortAddressProvider_WrappedReadinessPropagated(t *testing.T) {
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gatewayState := state.NewState()
	provider.SetState(gatewayState)

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-pending-params",
			Namespace: "test-ns",
			UID:       types.UID("gw-params-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	// With state set on provider but no parameters computed in state,
	// singlepod returns GatewayReasonPending ("Waiting for state to compute gateway parameters").
	// HostPortAddressProvider must return that readiness without discovering pods.
	addresses, readiness, err := provider.GatewayAddresses(t.Context(), gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Errorf("expected Pending readiness from wrapped provider, got addresses=%+v readiness=%+v", addresses, readiness)
	}
}

type hostPortsFixture struct {
	client     client.Client
	gateway    *gatewayv1.Gateway
	deployment *appsv1.Deployment
	replicaSet *appsv1.ReplicaSet
	node1      *corev1.Node
	node2      *corev1.Node
	provider   *HostPortAddressProvider
}

func setupHostPortsFixture(t *testing.T) (*hostPortsFixture, context.Context) {
	t.Helper()
	testClient := setupTestClient(t)
	ctx := t.Context()

	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "198.51.100.1"},
				{Type: corev1.NodeHostName, Address: "node-1.local"},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.5"},
				{Type: corev1.NodeInternalIP, Address: "2001:db8::5"},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.5"}, // duplicate
			},
		},
	}
	if err := testClient.Create(ctx, node1); err != nil {
		t.Fatalf("failed to create node-1: %v", err)
	}

	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "192.168.1.20"},
			},
		},
	}
	if err := testClient.Create(ctx, node2); err != nil {
		t.Fatalf("failed to create node-2: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-hp",
			Namespace: "test-ns",
			UID:       types.UID("gw-hp-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	// Run provider to build the Deployment
	if _, _, err := provider.GatewayAddresses(ctx, gateway, nil); err != nil {
		t.Fatalf("initial reconciliation failed: %v", err)
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}
	if deployment.UID == "" {
		deployment.UID = types.UID("deploy-uid-hp")
		if err := testClient.Update(ctx, &deployment); err != nil {
			t.Fatalf("failed to set deployment UID: %v", err)
		}
	}

	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment.Name + "-6d487f589b",
			Namespace: deployment.Namespace,
			UID:       types.UID("rs-uid-hp"),
			Labels:    deployment.Labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               deployment.Name,
					UID:                deployment.UID,
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
	}
	if err := testClient.Create(ctx, replicaSet); err != nil {
		t.Fatalf("failed to create ReplicaSet: %v", err)
	}

	return &hostPortsFixture{
		client:     testClient,
		gateway:    gateway,
		deployment: &deployment,
		replicaSet: replicaSet,
		node1:      node1,
		node2:      node2,
		provider:   provider,
	}, ctx
}

func (fixture *hostPortsFixture) createPod(t *testing.T, ctx context.Context, podName, nodeName string, owned bool) *corev1.Pod {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: fixture.gateway.Namespace,
			UID:       types.UID("pod-uid-" + podName),
			Labels: map[string]string{
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway(fixture.gateway.Name),
				singlepod.LabelAppName:     singlepod.AppNameValue,
				singlepod.LabelManagedBy:   singlepod.ManagedByValue,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}
	if owned {
		pod.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         "apps/v1",
				Kind:               "ReplicaSet",
				Name:               fixture.replicaSet.Name,
				UID:                fixture.replicaSet.UID,
				Controller:         state.Ptr(true),
				BlockOwnerDeletion: state.Ptr(true),
			},
		}
	}
	if err := fixture.client.Create(ctx, pod); err != nil {
		t.Fatalf("failed to create pod %s: %v", podName, err)
	}
	return pod
}

func (fixture *hostPortsFixture) setDeploymentReady(t *testing.T, ctx context.Context, ready bool) {
	t.Helper()
	if err := fixture.client.Get(ctx, types.NamespacedName{Namespace: fixture.gateway.Namespace, Name: fixture.deployment.Name}, fixture.deployment); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if ready {
		fixture.deployment.Status.ReadyReplicas = 1
	} else {
		fixture.deployment.Status.ReadyReplicas = 0
	}
	if err := fixture.client.Status().Update(ctx, fixture.deployment); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}
}

func TestHostPortAddressProvider_AddressFollowsNode(t *testing.T) {
	fixture, ctx := setupHostPortsFixture(t)

	// 1. Initial reconcile: no pod exists yet -> no address and not programmed
	addresses, readiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected 0 addresses and AddressNotAssigned before pod exists, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 2. Pod exists but has no node assigned (Spec.NodeName = "") -> no address and not programmed
	pod := fixture.createPod(t, ctx, "gw-hp-pod", "", true)
	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected 0 addresses and AddressNotAssigned when pod has no node, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 3. Pod is scheduled onto node-1 and deployment is available:
	// Addresses are node-1's internal addresses (sorted, deduplicated), and Gateway is ready.
	pod.Spec.NodeName = "node-1"
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod nodeName: %v", err)
	}
	fixture.setDeploymentReady(t, ctx, true)

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected ready=true and Reason=Programmed, got readiness=%+v", readiness)
	}
	// Verify addresses: only InternalIPs, sorted (IPv4 before IPv6), duplicate removed
	if len(addresses) != 2 || addresses[0].Value != "10.0.0.5" || addresses[1].Value != "2001:db8::5" {
		t.Fatalf("expected [10.0.0.5, 2001:db8::5] from node-1, got %+v", addresses)
	}
	if *addresses[0].Type != gatewayv1.IPAddressType || *addresses[1].Type != gatewayv1.IPAddressType {
		t.Errorf("expected IPAddressType for all addresses, got %+v", addresses)
	}

	// Also verify through GatewayAddresses public API
	gwAddresses, gwReadiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil || !gwReadiness.Ready || len(gwAddresses) != 2 || gwAddresses[0].Value != "10.0.0.5" || gwAddresses[1].Value != "2001:db8::5" {
		t.Errorf("unexpected addresses from GatewayAddresses: ready=%v addrs=%+v err=%v", gwReadiness.Ready, gwAddresses, err)
	}

	// 4. Pod is rescheduled to node-2: addresses follow to node-2's internal address
	pod.Spec.NodeName = "node-2"
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to reschedule pod to node-2: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error after reschedule: %v", err)
	}
	if !readiness.Ready || len(addresses) != 1 || addresses[0].Value != "192.168.1.20" {
		t.Fatalf("expected ready=true with 192.168.1.20 after reschedule, got ready=%v addresses=%+v", readiness.Ready, addresses)
	}

	// 5. Pod moves back to unscheduled: address is cleared and not programmed
	pod.Spec.NodeName = ""
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error when unscheduled: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected 0 addresses and AddressNotAssigned when unscheduled, got addresses=%+v readiness=%+v", addresses, readiness)
	}
}

func TestHostPortAddressProvider_OwnerReferenceRequired(t *testing.T) {
	fixture, ctx := setupHostPortsFixture(t)
	fixture.setDeploymentReady(t, ctx, true)

	// 1. Unowned pod that matches labels but lacks owner references -> ignored
	unownedPod := fixture.createPod(t, ctx, "spoofed-pod", "node-1", false)

	addresses, readiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected unowned pod copying labels to be ignored, got addresses=%+v readiness=%+v", addresses, readiness)
	}
	if err := fixture.client.Delete(ctx, unownedPod); err != nil {
		t.Fatalf("failed to delete unowned pod: %v", err)
	}

	// 2. Pod naming a ReplicaSet that the Deployment doesn't own -> ignored
	foreignReplicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign-rs",
			Namespace: fixture.gateway.Namespace,
			UID:       types.UID("foreign-rs-uid"),
		},
	}
	if err := fixture.client.Create(ctx, foreignReplicaSet); err != nil {
		t.Fatalf("failed to create foreign ReplicaSet: %v", err)
	}

	foreignPod := fixture.createPod(t, ctx, "foreign-rs-pod", "node-1", false)
	foreignPod.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         "apps/v1",
			Kind:               "ReplicaSet",
			Name:               foreignReplicaSet.Name,
			UID:                foreignReplicaSet.UID,
			Controller:         state.Ptr(true),
			BlockOwnerDeletion: state.Ptr(true),
		},
	}
	if err := fixture.client.Update(ctx, foreignPod); err != nil {
		t.Fatalf("failed to update foreign pod owner reference: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected pod owned by foreign ReplicaSet to be ignored, got addresses=%+v readiness=%+v", addresses, readiness)
	}
	if err := fixture.client.Delete(ctx, foreignPod); err != nil {
		t.Fatalf("failed to delete foreign pod: %v", err)
	}

	// 3. Pod with ownerRef missing UID -> ignored
	noUIDPod := fixture.createPod(t, ctx, "no-uid-pod", "node-1", false)
	noUIDPod.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         "apps/v1",
			Kind:               "ReplicaSet",
			Name:               fixture.replicaSet.Name,
			UID:                "", // empty UID
			Controller:         state.Ptr(true),
			BlockOwnerDeletion: state.Ptr(true),
		},
	}
	if err := fixture.client.Update(ctx, noUIDPod); err != nil {
		t.Fatalf("failed to update no-uid pod: %v", err)
	}
	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected pod with empty ownerRef UID to be ignored, got addresses=%+v readiness=%+v", addresses, readiness)
	}
	if err := fixture.client.Delete(ctx, noUIDPod); err != nil {
		t.Fatalf("failed to delete no-uid pod: %v", err)
	}

	// 4. Pod referencing ReplicaSet whose ownerRef to Deployment has mismatched UID -> ignored
	mismatchedRS := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mismatched-rs",
			Namespace: fixture.gateway.Namespace,
			UID:       types.UID("mismatched-rs-uid"),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               fixture.deployment.Name,
					UID:                types.UID("wrong-deploy-uid"),
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
	}
	if err := fixture.client.Create(ctx, mismatchedRS); err != nil {
		t.Fatalf("failed to create mismatched RS: %v", err)
	}
	mismatchedPod := fixture.createPod(t, ctx, "mismatched-pod", "node-1", false)
	mismatchedPod.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         "apps/v1",
			Kind:               "ReplicaSet",
			Name:               mismatchedRS.Name,
			UID:                mismatchedRS.UID,
			Controller:         state.Ptr(true),
			BlockOwnerDeletion: state.Ptr(true),
		},
	}
	if err := fixture.client.Update(ctx, mismatchedPod); err != nil {
		t.Fatalf("failed to update mismatched pod: %v", err)
	}
	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected pod with mismatched Deployment UID to be ignored, got addresses=%+v readiness=%+v", addresses, readiness)
	}
	if err := fixture.client.Delete(ctx, mismatchedPod); err != nil {
		t.Fatalf("failed to delete mismatched pod: %v", err)
	}

	// 5. Pod owned by the Deployment's ReplicaSet with strictly matching UIDs -> accepted
	_ = fixture.createPod(t, ctx, "valid-rs-pod", "node-1", true)
	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready || len(addresses) != 2 {
		t.Errorf("expected owned pod to be accepted, got ready=%v addresses=%+v", readiness.Ready, addresses)
	}
}

func TestHostPortAddressProvider_MultiplePodsOnMultipleNodesAndShrink(t *testing.T) {
	fixture, ctx := setupHostPortsFixture(t)
	fixture.setDeploymentReady(t, ctx, true)

	now := metav1.Now()
	// Terminating old pod on node-1
	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-old",
			Namespace:         fixture.gateway.Namespace,
			UID:               types.UID("pod-old-uid"),
			CreationTimestamp: metav1.Time{Time: now.Add(-10 * time.Minute)},
			Finalizers:        []string{"test.finalizer"},
			Labels: map[string]string{
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway(fixture.gateway.Name),
				singlepod.LabelAppName:     singlepod.AppNameValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               fixture.replicaSet.Name,
					UID:                fixture.replicaSet.UID,
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
	}
	// Active new pod on node-2
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-new",
			Namespace:         fixture.gateway.Namespace,
			UID:               types.UID("pod-new-uid"),
			CreationTimestamp: now,
			Labels: map[string]string{
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway(fixture.gateway.Name),
				singlepod.LabelAppName:     singlepod.AppNameValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               fixture.replicaSet.Name,
					UID:                fixture.replicaSet.UID,
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
		Spec: corev1.PodSpec{NodeName: "node-2"},
	}

	if err := fixture.client.Create(ctx, oldPod); err != nil {
		t.Fatalf("failed to create oldPod: %v", err)
	}
	// A terminating pod holds its host port until it exits, so its node stays in the list
	if err := fixture.client.Delete(ctx, oldPod); err != nil {
		t.Fatalf("failed to delete oldPod: %v", err)
	}
	if err := fixture.client.Create(ctx, newPod); err != nil {
		t.Fatalf("failed to create newPod: %v", err)
	}

	// Two owned pods on two nodes give both nodes' addresses:
	// node-1 (10.0.0.5, 2001:db8::5) and node-2 (192.168.1.20)
	addresses, readiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error during rollout: %v", err)
	}
	if !readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected ready=true and Reason=Programmed, got %+v", readiness)
	}
	if len(addresses) != 3 || addresses[0].Value != "10.0.0.5" || addresses[1].Value != "192.168.1.20" || addresses[2].Value != "2001:db8::5" {
		t.Fatalf("expected both nodes' addresses [10.0.0.5, 192.168.1.20, 2001:db8::5], got %+v", addresses)
	}

	// The list shrinks when a pod is gone: remove finalizer so oldPod exits completely
	if err := fixture.client.Get(ctx, types.NamespacedName{Namespace: fixture.gateway.Namespace, Name: "pod-old"}, oldPod); err != nil {
		t.Fatalf("failed to get oldPod: %v", err)
	}
	oldPod.Finalizers = nil
	if err := fixture.client.Update(ctx, oldPod); err != nil {
		t.Fatalf("failed to remove finalizer: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 1 || addresses[0].Value != "192.168.1.20" {
		t.Fatalf("expected address list to shrink to [192.168.1.20] after old pod is gone, got %+v", addresses)
	}
}

func TestHostPortAddressProvider_MultiplePodsOnSameNode(t *testing.T) {
	fixture, ctx := setupHostPortsFixture(t)
	fixture.setDeploymentReady(t, ctx, true)

	// Two owned pods on one node (node-1)
	_ = fixture.createPod(t, ctx, "pod-a", "node-1", true)
	_ = fixture.createPod(t, ctx, "pod-b", "node-1", true)

	// Two pods on one node give that node once (node-1 read once, deduplicated addresses)
	addresses, readiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected ready=true and Reason=Programmed, got %+v", readiness)
	}
	if len(addresses) != 2 || addresses[0].Value != "10.0.0.5" || addresses[1].Value != "2001:db8::5" {
		t.Fatalf("expected node-1 addresses once [10.0.0.5, 2001:db8::5], got %+v", addresses)
	}
}

func TestHostPortAddressProvider_EdgeCases(t *testing.T) {
	fixture, ctx := setupHostPortsFixture(t)

	// 1. Pod on node that does not exist -> AddressNotAssigned
	pod := fixture.createPod(t, ctx, "edge-pod", "non-existent-node", true)
	addresses, readiness, err := fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected 0 addresses for missing node, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 2. Pod on node without NodeInternalIP -> AddressNotAssigned
	nodeNoIP := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-no-ip"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "198.51.100.2"},
			},
		},
	}
	if err := fixture.client.Create(ctx, nodeNoIP); err != nil {
		t.Fatalf("failed to create nodeNoIP: %v", err)
	}
	pod.Spec.NodeName = "node-no-ip"
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod: %v", err)
	}
	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected 0 addresses for node without internal IP, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 3. Pod on node with unparseable NodeInternalIP -> returns error naming the node
	nodeBadIP := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-bad-ip"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "not-an-ip-address"},
			},
		},
	}
	if err := fixture.client.Create(ctx, nodeBadIP); err != nil {
		t.Fatalf("failed to create nodeBadIP: %v", err)
	}
	pod.Spec.NodeName = "node-bad-ip"
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod: %v", err)
	}
	_, _, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err == nil {
		t.Fatalf("expected error for unparseable NodeInternalIP, got nil")
	}
	if !strings.Contains(err.Error(), "node-bad-ip") {
		t.Errorf("expected error to name the node node-bad-ip, got %v", err)
	}

	// 4. Pod on valid node, but deployment is NOT available -> returns addresses, but Ready=false / Pending
	pod.Spec.NodeName = "node-1"
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod: %v", err)
	}
	fixture.setDeploymentReady(t, ctx, false)

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 2 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Errorf("expected 2 addresses and Pending when deployment not ready, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 5. Pod in Failed phase (e.g. evicted) with a node assigned -> ignored
	fixture.setDeploymentReady(t, ctx, true)
	pod.Status.Phase = corev1.PodFailed
	if err := fixture.client.Status().Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected Failed pod to be skipped, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 6. Pod in Succeeded phase -> ignored
	pod.Status.Phase = corev1.PodSucceeded
	if err := fixture.client.Status().Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected Succeeded pod to be skipped, got addresses=%+v readiness=%+v", addresses, readiness)
	}

	// 7. Pod with empty NodeName -> ignored
	pod.Status.Phase = corev1.PodRunning
	pod.Spec.NodeName = ""
	if err := fixture.client.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod: %v", err)
	}

	addresses, readiness, err = fixture.provider.GatewayAddresses(ctx, fixture.gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addresses) != 0 || readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected pod with empty NodeName to be ignored, got addresses=%+v readiness=%+v", addresses, readiness)
	}
}

func TestHostPortAddressProvider_GatewayReconciler_EndToEnd(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add clientgoscheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add gatewayv1: %v", err)
	}

	stateStore := state.NewState()
	stateStore.SetControllerName("test-controller")

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gw",
			Namespace:  "test-ns",
			UID:        types.UID("gw-uid-hp-e2e"),
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.200.0.1"},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-2"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.200.0.2"},
			},
		},
	}

	stateStore.UpsertGatewayClass(gatewayClass)
	stateStore.UpsertGateway(gateway)
	stateStore.Recompute()

	bundleCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-trust-bundle",
		},
	}

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gatewayClass, gateway, node1, node2, bundleCM).
		WithStatusSubresource(gateway).
		WithReturnManagedFields().
		Build()

	ctx := t.Context()
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}
	stateStore.SetSupportedAddressTypes(provider.SupportedAddressTypes())

	reconciler := &controller.GatewayReconciler{
		Client:          testClient,
		Scheme:          scheme,
		State:           stateStore,
		ControllerName:  "test-controller",
		AddressProvider: provider,
	}

	request := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}}

	// 1. Initial reconcile: creates Deployment with host ports, but no Service and no pod yet
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deployment); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}
	if deployment.UID == "" {
		deployment.UID = types.UID("deploy-uid-hp-e2e")
		if err := testClient.Update(ctx, &deployment); err != nil {
			t.Fatalf("failed to update Deployment UID: %v", err)
		}
	}
	deployment.Status.ReadyReplicas = 1
	if err := testClient.Status().Update(ctx, &deployment); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}

	// Create ReplicaSet owned by Deployment
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment.Name + "-6d487f589b",
			Namespace: deployment.Namespace,
			UID:       types.UID("rs-uid-hp-e2e"),
			Labels:    deployment.Labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               deployment.Name,
					UID:                deployment.UID,
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
	}
	if err := testClient.Create(ctx, replicaSet); err != nil {
		t.Fatalf("failed to create ReplicaSet: %v", err)
	}

	stateStore.Recompute()
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling second time: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := testClient.Get(ctx, request.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 0 {
		t.Fatalf("expected 0 addresses in status before pod scheduled, got %+v", reconciledGW.Status.Addresses)
	}
	programCondition := state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programCondition == nil || programCondition.Status != metav1.ConditionFalse || programCondition.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Fatalf("expected Programmed=False/AddressNotAssigned, got %+v", programCondition)
	}

	// 2. Pod is scheduled on worker-1 and owned by ReplicaSet
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw-dataplane-pod",
			Namespace: "test-ns",
			UID:       types.UID("pod-uid-e2e"),
			Labels: map[string]string{
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway("test-gw"),
				singlepod.LabelAppName:     singlepod.AppNameValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               replicaSet.Name,
					UID:                replicaSet.UID,
					Controller:         state.Ptr(true),
					BlockOwnerDeletion: state.Ptr(true),
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
		},
	}
	if err := testClient.Create(ctx, pod); err != nil {
		t.Fatalf("failed to create pod: %v", err)
	}

	// Reconcile -> State picks up addresses and readiness
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling with pod: %v", err)
	}
	stateStore.Recompute()
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling after recompute: %v", err)
	}

	if err := testClient.Get(ctx, request.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 1 || reconciledGW.Status.Addresses[0].Value != "10.200.0.1" {
		t.Fatalf("expected Gateway.status.addresses = [10.200.0.1], got %+v", reconciledGW.Status.Addresses)
	}
	programCondition = state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programCondition == nil || programCondition.Status != metav1.ConditionTrue || programCondition.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Fatalf("expected Programmed=True/Programmed, got %+v", programCondition)
	}

	// 3. Pod moves to worker-2
	pod.Spec.NodeName = "worker-2"
	if err := testClient.Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod nodeName: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling rescheduled pod: %v", err)
	}
	stateStore.Recompute()
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatalf("unexpected error reconciling rescheduled pod after recompute: %v", err)
	}

	if err := testClient.Get(ctx, request.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 1 || reconciledGW.Status.Addresses[0].Value != "10.200.0.2" {
		t.Fatalf("expected Gateway.status.addresses = [10.200.0.2] after reschedule, got %+v", reconciledGW.Status.Addresses)
	}
}

func TestHostPortAddressProvider_MultipleHTTPListeners_AddressNotUsable(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-two-http",
			Namespace: "test-ns",
			UID:       types.UID("gw-two-http-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
	}

	addresses, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false for two HTTP listeners on different ports")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected reason=AddressNotUsable, got %s", readiness.Reason)
	}
	expectedMsg := "host ports allow one HTTP and one HTTPS port"
	if readiness.Message != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, readiness.Message)
	}
	if len(addresses) > 0 {
		t.Errorf("expected no addresses, got %+v", addresses)
	}

	// Verify no Deployment exists
	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Deployment to exist, got err: %v", err)
	}
}

func TestHostPortAddressProvider_MultipleHTTPSListeners_AddressNotUsable(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-two-https",
			Namespace: "test-ns",
			UID:       types.UID("gw-two-https-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "https-8443", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "https-8443", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
	}

	addresses, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false for two HTTPS listeners on different ports")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected reason=AddressNotUsable, got %s", readiness.Reason)
	}
	expectedMsg := "host ports allow one HTTP and one HTTPS port"
	if readiness.Message != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, readiness.Message)
	}
	if len(addresses) > 0 {
		t.Errorf("expected no addresses, got %+v", addresses)
	}

	// Verify no Deployment exists
	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Deployment to exist, got err: %v", err)
	}
}

func TestHostPortAddressProvider_HTTPSAndTLSListenersDifferentPorts_AddressNotUsable(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-https-tls-diff",
			Namespace: "test-ns",
			UID:       types.UID("gw-https-tls-diff-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "tls-8443", Port: 8443, Protocol: gatewayv1.TLSProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "tls-8443", Port: 8443, Protocol: gatewayv1.TLSProtocolType},
	}

	addresses, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false for one HTTPS port and one differing TLS port")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected reason=AddressNotUsable, got %s", readiness.Reason)
	}
	expectedMsg := "host ports allow one HTTP and one HTTPS port"
	if readiness.Message != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, readiness.Message)
	}
	if len(addresses) > 0 {
		t.Errorf("expected no addresses, got %+v", addresses)
	}

	// Verify no Deployment exists
	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Deployment to exist, got err: %v", err)
	}
}

func TestHostPortAddressProvider_HTTPSAndTLSListenersSamePort_Provisioned(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-https-tls-same",
			Namespace: "test-ns",
			UID:       types.UID("gw-https-tls-same-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "tls-443", Port: 443, Protocol: gatewayv1.TLSProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "tls-443", Port: 443, Protocol: gatewayv1.TLSProtocolType},
	}

	_, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Reason == string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected not rejected with AddressNotUsable for HTTPS and TLS on same port")
	}

	// Deployment should be provisioned
	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
}

func TestHostPortAddressProvider_OneHTTPOneHTTPSSeveralTCPUDP_Provisioned(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-mixed",
			Namespace: "test-ns",
			UID:       types.UID("gw-mixed-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				{Name: "tcp-9000", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
				{Name: "tcp-9001", Port: 9001, Protocol: gatewayv1.TCPProtocolType},
				{Name: "udp-5353", Port: 5353, Protocol: gatewayv1.UDPProtocolType},
				{Name: "udp-5354", Port: 5354, Protocol: gatewayv1.UDPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
		{Name: "tcp-9000", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		{Name: "tcp-9001", Port: 9001, Protocol: gatewayv1.TCPProtocolType},
		{Name: "udp-5353", Port: 5353, Protocol: gatewayv1.UDPProtocolType},
		{Name: "udp-5354", Port: 5354, Protocol: gatewayv1.UDPProtocolType},
	}

	_, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Reason == string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("mixed listener configuration with 1 HTTP and 1 HTTPS should be provisioned, got AddressNotUsable")
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(deployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := []hostPortSignature{
		{containerPort: singlepod.DataPlaneHTTPPort, hostPort: 80, protocol: corev1.ProtocolTCP},
		{containerPort: singlepod.DataPlaneHTTPSPort, hostPort: 443, protocol: corev1.ProtocolTCP},
		{containerPort: singlepod.DataPlaneHTTPSPort, hostPort: 443, protocol: corev1.ProtocolUDP},
		{containerPort: 9000, hostPort: 9000, protocol: corev1.ProtocolTCP},
		{containerPort: 9001, hostPort: 9001, protocol: corev1.ProtocolTCP},
		{containerPort: 5353, hostPort: 5353, protocol: corev1.ProtocolUDP},
		{containerPort: 5354, hostPort: 5354, protocol: corev1.ProtocolUDP},
	}

	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}
}

func TestHostPortAddressProvider_TwoHTTPListenersSamePortDifferentHostnames(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	h1 := gatewayv1.Hostname("foo.example.com")
	h2 := gatewayv1.Hostname("bar.example.com")
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-hostnames",
			Namespace: "test-ns",
			UID:       types.UID("gw-hostnames-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http-foo", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h1},
				{Name: "http-bar", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h2},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http-foo", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h1},
		{Name: "http-bar", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h2},
	}

	_, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Reason == string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("two HTTP listeners on same port with different hostnames must count as one port, got AddressNotUsable")
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(deployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := []hostPortSignature{
		{containerPort: singlepod.DataPlaneHTTPPort, hostPort: 80, protocol: corev1.ProtocolTCP},
	}
	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}
}

func TestHostPortAddressProvider_ConflictedListenerSkippedInPortCount(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-conflicted-http",
			Namespace: "test-ns",
			UID:       types.UID("gw-conflicted-http-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{
			Name:     "http-8080",
			Port:     8080,
			Protocol: gatewayv1.HTTPProtocolType,
			ListenerInfo: state.ListenerInfo{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionConflicted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.ListenerReasonHostnameConflict),
					},
				},
			},
		},
	}

	_, readiness, err := provider.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Reason == string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("conflicted listener should be excluded from port count, got AddressNotUsable")
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var deployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	actualSignatures := extractHostPortSignatures(deployment.Spec.Template.Spec.Containers[0].Ports)
	expectedSignatures := []hostPortSignature{
		{containerPort: singlepod.DataPlaneHTTPPort, hostPort: 80, protocol: corev1.ProtocolTCP},
	}
	if !reflect.DeepEqual(actualSignatures, expectedSignatures) {
		t.Errorf("signatures mismatch:\ngot  %+v\nwant %+v", actualSignatures, expectedSignatures)
	}
}

func TestHostPortAddressProvider_ExistingDeploymentUnchangedWhenPortLimitExceeded(t *testing.T) {
	ctx := t.Context()
	testClient := setupTestClient(t)
	provider, err := New(testClient, testClient, "default")
	if err != nil {
		t.Fatalf("failed to create HostPortAddressProvider: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-unchanged",
			Namespace: "test-ns",
			UID:       types.UID("gw-unchanged-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	validListeners := []*state.EffectiveListener{
		{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
	}

	// 1. Initial valid reconcile provisions Deployment
	_, _, err = provider.GatewayAddresses(ctx, gateway, validListeners)
	if err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)
	var initialDeployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &initialDeployment); err != nil {
		t.Fatalf("failed to get initial Deployment: %v", err)
	}

	// 2. Gateway updated with conflicting HTTP ports
	invalidListeners := []*state.EffectiveListener{
		{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
	}
	gateway.Spec.Listeners = append(gateway.Spec.Listeners, gatewayv1.Listener{
		Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType,
	})

	addresses, readiness, err := provider.GatewayAddresses(ctx, gateway, invalidListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready || readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected AddressNotUsable, got readiness: %+v", readiness)
	}
	if len(addresses) > 0 {
		t.Errorf("expected no addresses, got %+v", addresses)
	}

	// Verify existing Deployment is unchanged
	var currentDeployment appsv1.Deployment
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &currentDeployment); err != nil {
		t.Fatalf("failed to get current Deployment: %v", err)
	}
	if currentDeployment.ResourceVersion != initialDeployment.ResourceVersion {
		t.Errorf("expected Deployment to be unchanged (resourceVersion %s != %s)", currentDeployment.ResourceVersion, initialDeployment.ResourceVersion)
	}
}
