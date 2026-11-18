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
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

func setupTestClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	return fake.NewClientBuilder().
		WithScheme(scheme).
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

	resourceName := singlepod.ResourceNameForGateway(gateway.Name)

	// 1. Expected: run existing singlepod provider with WithHostPorts()
	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, singlepod.WithHostPorts())
	expectedAddresses, expectedReadiness, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gateway, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}

	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	// 2. Actual: run HostPortAddressProvider
	actualClient := setupTestClient(t)
	hostPortProvider := New(actualClient)
	actualAddresses, actualReadiness, err := hostPortProvider.GatewayAddressesWithReadiness(ctx, gateway, nil)
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

	resourceName := singlepod.ResourceNameForGateway(gateway.Name)

	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gateway, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	actualClient := setupTestClient(t)
	hostPortProvider := New(actualClient)
	_, _, err = hostPortProvider.GatewayAddressesWithReadiness(ctx, gateway, nil)
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

	resourceName := singlepod.ResourceNameForGateway(gateway.Name)

	expectedClient := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(expectedClient, singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gateway, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var expectedDeployment appsv1.Deployment
	if err := expectedClient.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: resourceName}, &expectedDeployment); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	actualClient := setupTestClient(t)
	hostPortProvider := New(actualClient)
	_, _, err = hostPortProvider.GatewayAddressesWithReadiness(ctx, gateway, nil)
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

	testClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithObjects(gateway, gatewayClass).
		Build()

	provider := New(testClient)

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
	provider := New(testClient)

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

	addresses, ready, err := provider.GatewayAddresses(t.Context(), gateway, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ready {
		t.Errorf("expected ready=false")
	}
	if len(addresses) != 0 {
		t.Errorf("expected 0 addresses, got %+v", addresses)
	}
}

func TestHostPortAddressProvider_SetupWatches(t *testing.T) {
	provider := New(nil)

	// SetupWatches without scheme/mapper delegates to singlepod and returns an error
	if err := provider.SetupWatches(nil, nil); err == nil {
		t.Fatalf("expected error from SetupWatches without scheme and mapper, got nil")
	}
}

func TestHostPortAddressProvider_SetState(t *testing.T) {
	testClient := setupTestClient(t)
	provider := New(testClient)

	gatewayState := state.NewState()
	provider.SetState(gatewayState)
}
