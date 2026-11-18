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
	"fmt"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

func TestHostPortAddressProvider_MatchesSinglePodWithHostPorts(t *testing.T) {
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
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

	resName := singlepod.ResourceNameForGateway(gw.Name)

	// 1. Expected: run existing singlepod provider with WithHostPorts()
	cExpected := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(cExpected, singlepod.WithHostPorts())
	expectedAddrs, expectedReadiness, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}

	var deployExpected appsv1.Deployment
	if err := cExpected.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployExpected); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	// 2. Actual: run HostPortAddressProvider
	cActual := setupTestClient(t)
	hpProvider := New(cActual)
	actualAddrs, actualReadiness, err := hpProvider.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}

	var deployActual appsv1.Deployment
	if err := cActual.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployActual); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	// 3. Deployment rollout strategy verification
	if deployActual.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("expected Deployment strategy RollingUpdate, got %s", deployActual.Spec.Strategy.Type)
	}
	if deployActual.Spec.Strategy.RollingUpdate == nil {
		t.Fatalf("expected RollingUpdate strategy configuration")
	}
	if deployActual.Spec.Strategy.RollingUpdate.MaxSurge == nil || deployActual.Spec.Strategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Errorf("expected maxSurge=0, got %v", deployActual.Spec.Strategy.RollingUpdate.MaxSurge)
	}
	if deployActual.Spec.Strategy.RollingUpdate.MaxUnavailable == nil || deployActual.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected maxUnavailable=1, got %v", deployActual.Spec.Strategy.RollingUpdate.MaxUnavailable)
	}

	// Verify strategy matches singlepod.WithHostPorts() exactly
	if !reflect.DeepEqual(deployActual.Spec.Strategy, deployExpected.Spec.Strategy) {
		t.Errorf("strategy mismatch:\ngot  %+v\nwant %+v", deployActual.Spec.Strategy, deployExpected.Spec.Strategy)
	}

	// 4. Container ports verification
	actualPorts := deployActual.Spec.Template.Spec.Containers[0].Ports
	expectedPorts := deployExpected.Spec.Template.Spec.Containers[0].Ports
	if !reflect.DeepEqual(actualPorts, expectedPorts) {
		t.Errorf("container ports mismatch:\ngot  %+v\nwant %+v", actualPorts, expectedPorts)
	}

	portMap := make(map[string]corev1.ContainerPort)
	for _, cp := range actualPorts {
		portMap[fmt.Sprintf("%s/%s", cp.Name, cp.Protocol)] = cp
	}

	// Verify HTTP mapping: containerPort 8080, hostPort 80
	if cp, ok := portMap["http/TCP"]; !ok {
		t.Errorf("missing http/TCP port in container")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPPort || cp.HostPort != 80 {
		t.Errorf("http/TCP: expected containerPort=%d hostPort=80, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPPort, cp.ContainerPort, cp.HostPort)
	}

	// Verify HTTPS TCP mapping: containerPort 8443, hostPort 443
	if cp, ok := portMap["https/TCP"]; !ok {
		t.Errorf("missing https/TCP port in container")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPSPort || cp.HostPort != 443 {
		t.Errorf("https/TCP: expected containerPort=%d hostPort=443, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPSPort, cp.ContainerPort, cp.HostPort)
	}

	// Verify HTTP/3 UDP mapping: containerPort 8443, hostPort 443
	if cp, ok := portMap["http3/UDP"]; !ok {
		t.Errorf("missing http3/UDP port in container")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPSPort || cp.HostPort != 443 {
		t.Errorf("http3/UDP: expected containerPort=%d hostPort=443, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPSPort, cp.ContainerPort, cp.HostPort)
	}

	// Verify TCP mapping: containerPort 9000, hostPort 9000
	if cp, ok := portMap["tcp-9000/TCP"]; !ok {
		t.Errorf("missing tcp-9000/TCP port in container")
	} else if cp.ContainerPort != 9000 || cp.HostPort != 9000 {
		t.Errorf("tcp-9000/TCP: expected containerPort=9000 hostPort=9000, got containerPort=%d hostPort=%d", cp.ContainerPort, cp.HostPort)
	}

	// Verify UDP mapping: containerPort 5353, hostPort 5353
	if cp, ok := portMap["udp-5353/UDP"]; !ok {
		t.Errorf("missing udp-5353/UDP port in container")
	} else if cp.ContainerPort != 5353 || cp.HostPort != 5353 {
		t.Errorf("udp-5353/UDP: expected containerPort=5353 hostPort=5353, got containerPort=%d hostPort=%d", cp.ContainerPort, cp.HostPort)
	}

	// 5. Verify no Service created
	var svc corev1.Service
	if err := cActual.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Service to be created, got err: %v", err)
	}

	// 6. Verify address and readiness stub
	if actualReadiness.Ready {
		t.Errorf("expected ready=false in this step")
	}
	if len(actualAddrs) > 0 {
		t.Errorf("expected 0 addresses in this step, got %+v", actualAddrs)
	}
	if !reflect.DeepEqual(actualAddrs, expectedAddrs) {
		t.Errorf("addresses mismatch: got %+v, want %+v", actualAddrs, expectedAddrs)
	}
	if actualReadiness.Ready != expectedReadiness.Ready {
		t.Errorf("readiness.Ready mismatch: got %v, want %v", actualReadiness.Ready, expectedReadiness.Ready)
	}
}

func TestHostPortAddressProvider_ReservedPortsSkipped(t *testing.T) {
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
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

	resName := singlepod.ResourceNameForGateway(gw.Name)

	cExpected := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(cExpected, singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var deployExpected appsv1.Deployment
	if err := cExpected.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployExpected); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	cActual := setupTestClient(t)
	hpProvider := NewHostPortAddressProvider(cActual)
	_, _, err = hpProvider.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var deployActual appsv1.Deployment
	if err := cActual.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployActual); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualPorts := deployActual.Spec.Template.Spec.Containers[0].Ports
	expectedPorts := deployExpected.Spec.Template.Spec.Containers[0].Ports
	if !reflect.DeepEqual(actualPorts, expectedPorts) {
		t.Errorf("container ports mismatch:\ngot  %+v\nwant %+v", actualPorts, expectedPorts)
	}

	// Only port 80 should be in container ports; 8080 TCP, 8443 UDP, and 8999 TCP should be skipped
	if len(actualPorts) != 1 {
		t.Fatalf("expected exactly 1 container port (port 80), got %d: %+v", len(actualPorts), actualPorts)
	}
	if actualPorts[0].HostPort != 80 || actualPorts[0].ContainerPort != singlepod.DataPlaneHTTPPort {
		t.Errorf("expected port 80 mapping, got %+v", actualPorts[0])
	}
}

func TestHostPortAddressProvider_NonDefaultPorts(t *testing.T) {
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
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

	resName := singlepod.ResourceNameForGateway(gw.Name)

	cExpected := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(cExpected, singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var deployExpected appsv1.Deployment
	if err := cExpected.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployExpected); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	cActual := setupTestClient(t)
	hpProvider := NewAddressProvider(cActual)
	_, _, err = hpProvider.GatewayAddressesWithReadiness(ctx, gw, nil)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var deployActual appsv1.Deployment
	if err := cActual.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployActual); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualPorts := deployActual.Spec.Template.Spec.Containers[0].Ports
	expectedPorts := deployExpected.Spec.Template.Spec.Containers[0].Ports
	if !reflect.DeepEqual(actualPorts, expectedPorts) {
		t.Errorf("container ports mismatch:\ngot  %+v\nwant %+v", actualPorts, expectedPorts)
	}

	portMap := make(map[string]corev1.ContainerPort)
	for _, cp := range actualPorts {
		portMap[fmt.Sprintf("%s/%s", cp.Name, cp.Protocol)] = cp
	}

	// http-8081 -> containerPort 8080, hostPort 8081
	if cp, ok := portMap["http-8081/TCP"]; !ok {
		t.Errorf("missing http-8081/TCP port")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPPort || cp.HostPort != 8081 {
		t.Errorf("http-8081/TCP: expected containerPort=%d hostPort=8081, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPPort, cp.ContainerPort, cp.HostPort)
	}

	// https-8444 -> containerPort 8443, hostPort 8444
	if cp, ok := portMap["https-8444/TCP"]; !ok {
		t.Errorf("missing https-8444/TCP port")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPSPort || cp.HostPort != 8444 {
		t.Errorf("https-8444/TCP: expected containerPort=%d hostPort=8444, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPSPort, cp.ContainerPort, cp.HostPort)
	}

	// http3-8444 -> containerPort 8443, hostPort 8444
	if cp, ok := portMap["http3-8444/UDP"]; !ok {
		t.Errorf("missing http3-8444/UDP port")
	} else if cp.ContainerPort != singlepod.DataPlaneHTTPSPort || cp.HostPort != 8444 {
		t.Errorf("http3-8444/UDP: expected containerPort=%d hostPort=8444, got containerPort=%d hostPort=%d", singlepod.DataPlaneHTTPSPort, cp.ContainerPort, cp.HostPort)
	}
}

func TestHostPortAddressProvider_EffectiveListeners(t *testing.T) {
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-effective",
			Namespace: "test-ns",
			UID:       types.UID("gw-effective-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "conflicted", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		},
		{
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

	resName := singlepod.ResourceNameForGateway(gw.Name)

	cExpected := setupTestClient(t)
	singlePodHP := singlepod.NewAddressProvider(cExpected, singlepod.WithHostPorts())
	_, _, err := singlePodHP.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("singlepod WithHostPorts reconcile failed: %v", err)
	}
	var deployExpected appsv1.Deployment
	if err := cExpected.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployExpected); err != nil {
		t.Fatalf("failed to get expected Deployment: %v", err)
	}

	cActual := setupTestClient(t)
	hpProvider := New(cActual)
	_, _, err = hpProvider.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("HostPortAddressProvider reconcile failed: %v", err)
	}
	var deployActual appsv1.Deployment
	if err := cActual.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deployActual); err != nil {
		t.Fatalf("failed to get actual Deployment: %v", err)
	}

	actualPorts := deployActual.Spec.Template.Spec.Containers[0].Ports
	expectedPorts := deployExpected.Spec.Template.Spec.Containers[0].Ports
	if !reflect.DeepEqual(actualPorts, expectedPorts) {
		t.Errorf("container ports mismatch:\ngot  %+v\nwant %+v", actualPorts, expectedPorts)
	}

	// Conflicted listener on port 8080 should have been skipped
	if len(actualPorts) != 1 || actualPorts[0].HostPort != 80 {
		t.Fatalf("expected only port 80, got %+v", actualPorts)
	}
}

func TestHostPortAddressProvider_AddressRequestRejected(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-request-addr",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "192.168.1.100"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "localgateway",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithObjects(gw, gc).
		Build()

	provider := New(c)

	// 1. SupportedAddressTypes returns nil
	supported := provider.SupportedAddressTypes()
	if supported != nil {
		t.Fatalf("expected SupportedAddressTypes() to be nil, got %+v", supported)
	}

	// 2. Gateway requesting an address is rejected via state.State
	st := state.NewState()
	st.SetSupportedAddressTypes(provider.SupportedAddressTypes())
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.Recompute()

	status, ok := st.GetDesiredGatewayStatus(types.NamespacedName{Namespace: "default", Name: "gw-request-addr"})
	if !ok {
		t.Fatalf("expected desired status for gateway")
	}

	var acceptedCond *metav1.Condition
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionAccepted) {
			acceptedCond = &status.Conditions[i]
			break
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress from State, got %+v", acceptedCond)
	}

	// 3. Gateway requesting an address is rejected via controller.GatewayReconciler
	r := &controller.GatewayReconciler{
		Client:          c,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "localgateway",
		AddressProvider: provider,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-request-addr"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := c.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}

	var rAcceptedCond *metav1.Condition
	for i := range reconciledGW.Status.Conditions {
		if reconciledGW.Status.Conditions[i].Type == string(gatewayv1.GatewayConditionAccepted) {
			rAcceptedCond = &reconciledGW.Status.Conditions[i]
			break
		}
	}
	if rAcceptedCond == nil || rAcceptedCond.Status != metav1.ConditionFalse || rAcceptedCond.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Errorf("expected Accepted=False Reason=UnsupportedAddress from Reconciler, got %+v", rAcceptedCond)
	}
}

func TestHostPortAddressProvider_GatewayAddresses(t *testing.T) {
	c := setupTestClient(t)
	provider := New(c)

	gw := &gatewayv1.Gateway{
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

	addrs, ready, err := provider.GatewayAddresses(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ready {
		t.Errorf("expected ready=false")
	}
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses, got %+v", addrs)
	}
}

func TestHostPortAddressProvider_SetupWatches(t *testing.T) {
	c := setupTestClient(t)
	provider := New(c)

	// SetupWatches with nil mgr/bldr should delegate safely without error
	if err := provider.SetupWatches(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHostPortAddressProvider_SetState(t *testing.T) {
	c := setupTestClient(t)
	provider := New(c)

	st := state.NewState()
	provider.SetState(st)
}
