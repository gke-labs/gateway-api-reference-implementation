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

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/metadata"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/registrar"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	compute "google.golang.org/api/compute/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func setupScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	if err := discoveryv1.AddToScheme(s); err != nil {
		panic(err)
	}
	_ = gatewayv1.Install(s)
	return s
}

func getConditionFromStatus(status *gatewayv1.GatewayStatus, condType string) *metav1.Condition {
	for _, c := range status.Conditions {
		if c.Type == condType {
			return &c
		}
	}
	return nil
}

func makeTestPod(t *testing.T, c client.Client, gw *gatewayv1.Gateway, name, nodeName, ip string, extraConditions []corev1.PodCondition) *corev1.Pod {
	drainVol := corev1ac.Volume().
		WithName("drain-volume").
		WithEmptyDir(corev1ac.EmptyDirVolumeSource().WithMedium(corev1.StorageMediumMemory))
	drainMount := corev1ac.VolumeMount().
		WithName("drain-volume").
		WithMountPath("/var/run/gcpgateway")
	preStopCmd := []string{"/gcpgateway", "hook", "pre-stop", "--drain-seconds=35"}

	p := singlepod.NewAddressProvider(
		c,
		singlepod.WithExtraReadinessGates(registrar.LoadBalancerReadyGate),
		singlepod.WithPreStopCommand(preStopCmd...),
		singlepod.WithExtraVolumes([]*corev1ac.VolumeApplyConfiguration{drainVol}, []*corev1ac.VolumeMountApplyConfiguration{drainMount}),
		singlepod.WithTerminationGracePeriodSeconds(60),
	)

	_, _, err := p.GatewayAddressesWithReadiness(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("failed to reconcile deployment for pod template: %v", err)
	}

	resName := singlepod.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName(name),
		testenv.WithNodeName(nodeName),
		testenv.WithPodIP(ip),
	)

	if err := c.Create(t.Context(), pod); err != nil {
		t.Fatalf("failed to create pod: %v", err)
	}

	pod.Status = corev1.PodStatus{
		PodIP:      ip,
		Conditions: extraConditions,
	}
	if err := c.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	return pod
}

// TestReadinessGate_SetOnlyAfterHealthy verifies that the pod readiness gate is set to True
// only after fake getHealth reports HEALTHY, and sets Gateway condition Programmed=True.
func TestReadinessGate_SetOnlyAfterHealthy(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.10",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}

	// 1. Initial reconcile: getHealth reports UNHEALTHY
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	res, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res.RequeueAfter != HealthPollInterval {
		t.Errorf("expected RequeueAfter=%v when UNHEALTHY, got %v", HealthPollInterval, res.RequeueAfter)
	}

	// Verify pod readiness gate is still False
	var updatedPod corev1.Pod
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "dp-pod-1"}, &updatedPod); err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	var gateCond *corev1.PodCondition
	for _, cond := range updatedPod.Status.Conditions {
		if cond.Type == corev1.PodConditionType(registrar.LoadBalancerReadyGate) {
			gateCond = &cond
			break
		}
	}
	if gateCond == nil || gateCond.Status != corev1.ConditionFalse {
		t.Errorf("expected readiness gate to be False when UNHEALTHY, got %+v", gateCond)
	}

	// Verify Gateway condition is WaitingForEndpoints in cache and via GatewayStatusHook
	cached := reconciler.GetCachedStatus(req.NamespacedName)
	if cached == nil || cached.Reason != ReasonWaitingForEndpoints {
		t.Errorf("expected Programmed=False with Reason WaitingForEndpoints, got %+v", cached)
	}
	var gwStatus gatewayv1.GatewayStatus
	var currentGW gatewayv1.Gateway
	_ = c.Get(t.Context(), req.NamespacedName, &currentGW)
	_ = reconciler.GatewayStatusHook(t.Context(), &currentGW, &gwStatus)
	prog := getConditionFromStatus(&gwStatus, string(gatewayv1.GatewayConditionProgrammed))
	if prog == nil || prog.Reason != ReasonWaitingForEndpoints {
		t.Errorf("expected hook to produce Reason WaitingForEndpoints, got %+v", prog)
	}

	// 2. Health check passes: getHealth reports HEALTHY
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	res, err = reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res.RequeueAfter != ResyncInterval {
		t.Errorf("expected RequeueAfter=%v when HEALTHY, got %v", ResyncInterval, res.RequeueAfter)
	}

	// Verify pod readiness gate was updated to True!
	_ = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "dp-pod-1"}, &updatedPod)
	for _, cond := range updatedPod.Status.Conditions {
		if cond.Type == corev1.PodConditionType(registrar.LoadBalancerReadyGate) {
			gateCond = &cond
			break
		}
	}
	if gateCond == nil || gateCond.Status != corev1.ConditionTrue {
		t.Errorf("expected readiness gate to be True when HEALTHY, got %+v", gateCond)
	}

	// Verify Gateway condition is Programmed=True in cache and via GatewayStatusHook!
	cached = reconciler.GetCachedStatus(req.NamespacedName)
	if cached == nil || cached.ProgrammedStatus != metav1.ConditionTrue || cached.Reason != ReasonProgrammed {
		t.Errorf("expected Programmed=True with Reason Programmed, got %+v", cached)
	}
	if len(cached.Addresses) != 1 || cached.Addresses[0].Value != "34.120.254.10" {
		t.Errorf("expected Gateway address 34.120.254.10, got %+v", cached.Addresses)
	}
	gwStatus = gatewayv1.GatewayStatus{}
	_ = reconciler.GatewayStatusHook(t.Context(), &currentGW, &gwStatus)
	prog = getConditionFromStatus(&gwStatus, string(gatewayv1.GatewayConditionProgrammed))
	if prog == nil || prog.Status != metav1.ConditionTrue || prog.Reason != ReasonProgrammed {
		t.Errorf("expected hook to produce Programmed=True, got %+v", prog)
	}
}

// TestRolloutStalled_ReportsConditionWhenUnhealthy verifies that the Gateway reports RolloutStalled
// when a pod remains held by the readiness gate and never becomes healthy.
func TestRolloutStalled_ReportsConditionWhenUnhealthy(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.10",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:     "cluster-1",
		NegPrefix:     "gcpgw",
		Project:       "my-project",
		Zones:         []string{"us-central1-a"},
		HealthTimeout: 1 * time.Millisecond,
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}

	// First reconcile starts the timer
	_, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("first Reconcile failed: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	// Second reconcile: timeout elapsed, pod still not healthy -> RolloutStalled
	_, err = reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}

	cached := reconciler.GetCachedStatus(req.NamespacedName)
	if cached == nil || cached.ProgrammedStatus != metav1.ConditionFalse || cached.Reason != ReasonRolloutStalled {
		t.Fatalf("expected Programmed=False with Reason RolloutStalled in cache, got %+v", cached)
	}
}

// TestGateway_MultipleGateways_WaitingSinceIsolation verifies that alternating reconciles
// between multiple Gateways with waiting pods do not reset each other's wait times,
// that RolloutStalled fires for each after the configured timeout, and that deleting
// a Gateway cleans up only its own waitingSince entries.
func TestGateway_MultipleGateways_WaitingSinceIsolation(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw",
			UID:       types.UID("gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.10",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw-2",
			UID:       types.UID("gw-2-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.11",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw1, gw2, node).
		Build()

	pod1 := makeTestPod(t, c, gw1, "gateway-gw-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})
	pod2 := makeTestPod(t, c, gw2, "gateway-gw-2-pod-1", "node-1", "10.0.1.6", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})

	fakeGCP := gcp.NewFakeComputeClient()

	for _, gw := range []*gatewayv1.Gateway{gw1, gw2} {
		negDesc, _ := (&metadata.NegMetadata{
			ClusterID:   "cluster-1",
			Namespace:   gw.Namespace,
			GatewayName: gw.Name,
			Port:        8443,
		}).Encode()
		negName := metadata.ResourceName("gcpgw", "cluster-1", gw.Namespace, gw.Name, "8443")
		fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
			Name:        negName,
			Zone:        "us-central1-a",
			Description: negDesc,
		})
	}

	bsName1 := metadata.ResourceName("gcpgw", "cluster-1", "default", "gw", "bs-443")
	negName1 := metadata.ResourceName("gcpgw", "cluster-1", "default", "gw", "8443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName1, negName1, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	bsName2 := metadata.ResourceName("gcpgw", "cluster-1", "default", "gw-2", "bs-443")
	negName2 := metadata.ResourceName("gcpgw", "cluster-1", "default", "gw-2", "8443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName2, negName2, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.6", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	healthTimeout := 20 * time.Millisecond
	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:     "cluster-1",
		NegPrefix:     "gcpgw",
		Project:       "my-project",
		Zones:         []string{"us-central1-a"},
		HealthTimeout: healthTimeout,
	})

	req1 := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw"}}
	req2 := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-2"}}

	// First reconcile of gw -> starts timer for gw
	if _, err := reconciler.Reconcile(t.Context(), req1); err != nil {
		t.Fatalf("first Reconcile gw failed: %v", err)
	}

	// First reconcile of gw-2 -> starts timer for gw-2, must not reset gw timer
	if _, err := reconciler.Reconcile(t.Context(), req2); err != nil {
		t.Fatalf("first Reconcile gw-2 failed: %v", err)
	}

	// Neither gateway should be RolloutStalled yet
	cached1 := reconciler.GetCachedStatus(req1.NamespacedName)
	if cached1 != nil && cached1.Reason == ReasonRolloutStalled {
		t.Fatalf("gw prematurely marked RolloutStalled")
	}
	cached2 := reconciler.GetCachedStatus(req2.NamespacedName)
	if cached2 != nil && cached2.Reason == ReasonRolloutStalled {
		t.Fatalf("gw-2 prematurely marked RolloutStalled")
	}

	// Alternate reconciles again before timeout
	if _, err := reconciler.Reconcile(t.Context(), req1); err != nil {
		t.Fatalf("second Reconcile gw failed: %v", err)
	}
	if _, err := reconciler.Reconcile(t.Context(), req2); err != nil {
		t.Fatalf("second Reconcile gw-2 failed: %v", err)
	}

	// Wait past healthTimeout
	time.Sleep(healthTimeout + 5*time.Millisecond)

	// Alternating reconciles after timeout: both should report RolloutStalled
	if _, err := reconciler.Reconcile(t.Context(), req1); err != nil {
		t.Fatalf("reconcile gw after timeout failed: %v", err)
	}
	cached1 = reconciler.GetCachedStatus(req1.NamespacedName)
	if cached1 == nil || cached1.ProgrammedStatus != metav1.ConditionFalse || cached1.Reason != ReasonRolloutStalled {
		t.Fatalf("expected gw Programmed=False with Reason RolloutStalled, got %+v", cached1)
	}

	if _, err := reconciler.Reconcile(t.Context(), req2); err != nil {
		t.Fatalf("reconcile gw-2 after timeout failed: %v", err)
	}
	cached2 = reconciler.GetCachedStatus(req2.NamespacedName)
	if cached2 == nil || cached2.ProgrammedStatus != metav1.ConditionFalse || cached2.Reason != ReasonRolloutStalled {
		t.Fatalf("expected gw-2 Programmed=False with Reason RolloutStalled, got %+v", cached2)
	}

	// Verify both Gateways have waitingSince entries
	pod1Key := fmt.Sprintf("%s/%s", pod1.Namespace, pod1.Name)
	pod2Key := fmt.Sprintf("%s/%s", pod2.Namespace, pod2.Name)

	if _, exists := reconciler.waitingSince[req1.NamespacedName][pod1Key]; !exists {
		t.Errorf("expected gw waitingSince entry for pod1")
	}
	if _, exists := reconciler.waitingSince[req2.NamespacedName][pod2Key]; !exists {
		t.Errorf("expected gw-2 waitingSince entry for pod2")
	}

	// Delete gw and reconcile its deletion
	var gw1ToDel gatewayv1.Gateway
	if err := c.Get(t.Context(), req1.NamespacedName, &gw1ToDel); err != nil {
		t.Fatalf("getting gw: %v", err)
	}
	if err := c.Delete(t.Context(), &gw1ToDel); err != nil {
		t.Fatalf("deleting gw: %v", err)
	}

	if _, err := reconciler.Reconcile(t.Context(), req1); err != nil {
		t.Fatalf("reconcile gw deletion failed: %v", err)
	}

	// Deleting gw must remove ONLY gw's entries, preserving gw-2's entries
	if _, exists := reconciler.waitingSince[req1.NamespacedName]; exists {
		t.Errorf("expected gw waitingSince to be deleted after gateway deletion")
	}
	if _, exists := reconciler.waitingSince[req2.NamespacedName][pod2Key]; !exists {
		t.Errorf("expected gw-2 waitingSince entry to be preserved after gw deletion")
	}

	// Reconciling a non-existent Gateway also does not affect gw-2
	if _, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "non-existent"}}); err != nil {
		t.Fatalf("reconcile non-existent gw failed: %v", err)
	}
	if _, exists := reconciler.waitingSince[req2.NamespacedName][pod2Key]; !exists {
		t.Errorf("expected gw-2 waitingSince entry to be preserved after reconciling non-existent gateway")
	}
}

// TestGateway_ErrorConditions verifies that Compute API errors produce expected condition reasons.
func TestGateway_ErrorConditions(t *testing.T) {
	tests := []struct {
		name           string
		injectError    error
		expectedReason string
	}{
		{"PERMISSION_DENIED", gcp.ErrPermissionDenied, ReasonPermissionDenied},
		{"QuotaExceeded", gcp.ErrQuotaExceeded, ReasonQuotaExceeded},
		{"NEGNotFound", gcp.ErrNEGNotFound, ReasonNEGNotFound},
		{"InvalidIP", gcp.ErrInvalidIP, ReasonUnsupportedCluster},
		{"OtherError", errors.New("backend error with random req-id-12345"), ReasonEndpointAttachmentFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := setupScheme()
			ipAddrType := gatewayv1.IPAddressType
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "my-gw",
					UID:       types.UID("my-gw-uid"),
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "gcpgateway",
					Addresses: []gatewayv1.GatewaySpecAddress{
						{Type: &ipAddrType, Value: "34.120.254.10"},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
					},
				},
			}

			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
				WithObjects(gw, node).
				Build()

			makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
			})

			fakeGCP := gcp.NewFakeComputeClient()
			negDesc, _ := (&metadata.NegMetadata{
				ClusterID:   "cluster-1",
				Namespace:   "default",
				GatewayName: "my-gw",
				Port:        8443,
			}).Encode()

			negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
			fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
				Name:        negName,
				Zone:        "us-central1-a",
				Description: negDesc,
			})
			fakeGCP.InjectAttachError = tc.injectError

			reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
				ClusterID: "cluster-1",
				NegPrefix: "gcpgw",
				Project:   "my-project",
				Zones:     []string{"us-central1-a"},
			})

			reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
				ClusterID: "cluster-1",
				NegPrefix: "gcpgw",
				Project:   "my-project",
				Zones:     []string{"us-central1-a"},
			})

			req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}
			_, err := reconciler.Reconcile(t.Context(), req)
			if err == nil {
				t.Fatalf("expected error returned from Reconcile on GCP error, got nil")
			}

			cached := reconciler.GetCachedStatus(req.NamespacedName)
			if cached == nil || cached.ProgrammedStatus != metav1.ConditionFalse || cached.Reason != tc.expectedReason {
				t.Errorf("expected condition Reason %q, got %+v", tc.expectedReason, cached)
			}
			if tc.expectedReason == ReasonPermissionDenied {
				if !strings.Contains(cached.Message, "compute.instances.use") {
					t.Errorf("expected message to mention compute.instances.use, got %q", cached.Message)
				}
			}
			if tc.expectedReason == ReasonEndpointAttachmentFailed {
				if cached.Message != "Failed to attach endpoints to zonal NEGs; see controller logs for details." {
					t.Errorf("expected stable message for unclassified error, got %q", cached.Message)
				}
			}
		})
	}
}

// TestGateway_AttachErrorRecoveryClearsCondition verifies that a failing attach returns an error
// and sets a stable condition reason in cache, and a later success clears it to Programmed=True.
func TestGateway_AttachErrorRecoveryClearsCondition(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
	})

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})
	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	fakeGCP.InjectAttachError = gcp.ErrPermissionDenied

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}
	// 1. Failing attach returns an error and sets cached PermissionDenied
	_, err := reconciler.Reconcile(t.Context(), req)
	if err == nil {
		t.Fatalf("expected error from Reconcile when attach fails, got nil")
	}

	cached := reconciler.GetCachedStatus(req.NamespacedName)
	if cached == nil || cached.ProgrammedStatus != metav1.ConditionFalse || cached.Reason != ReasonPermissionDenied {
		t.Fatalf("expected ReasonPermissionDenied in cache, got %+v", cached)
	}

	// 2. Clear attach error (permission granted)
	fakeGCP.InjectAttachError = nil

	// 3. Next reconcile succeeds and clears failure condition to Programmed=True
	_, err = reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("expected successful reconcile after attach error cleared, got: %v", err)
	}

	cachedAfter := reconciler.GetCachedStatus(req.NamespacedName)
	if cachedAfter == nil || cachedAfter.ProgrammedStatus != metav1.ConditionTrue || cachedAfter.Reason != ReasonProgrammed {
		t.Errorf("expected cached status to be cleared and set to Programmed=True, got %+v", cachedAfter)
	}
}

type countingStatusWriter struct {
	client.SubResourceWriter
	podStatusUpdates *atomic.Int32
}

func (w *countingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if _, isPod := obj.(*corev1.Pod); isPod {
		w.podStatusUpdates.Add(1)
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func (w *countingStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if _, isPod := obj.(*corev1.Pod); isPod {
		w.podStatusUpdates.Add(1)
	}
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

type countingClient struct {
	client.Client
	writer *countingStatusWriter
}

func (c *countingClient) Status() client.SubResourceWriter {
	return c.writer
}

// TestGateway_ReconcileUnchangedPod_PerformsNoWrite verifies that when data-plane pods
// already have the desired readiness gate condition, Reconcile performs no status writes
// on those pods, preventing self-triggered watch events from bypassing workqueue rate limiting.
func TestGateway_ReconcileUnchangedPod_PerformsNoWrite(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	baseClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	// Pod already has ContainersReady=True AND LoadBalancerReadyGate=True (unchanged steady state)
	makeTestPod(t, baseClient, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionTrue, Reason: "LoadBalancerHealthy"},
	})

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})
	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	var updateCount atomic.Int32
	trackedClient := &countingClient{
		Client: baseClient,
		writer: &countingStatusWriter{
			SubResourceWriter: baseClient.Status(),
			podStatusUpdates:  &updateCount,
		},
	}

	reg := registrar.NewRegistrar(trackedClient, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(trackedClient, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}
	_, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify that NO pod status writes were performed
	if writes := updateCount.Load(); writes != 0 {
		t.Errorf("expected 0 pod status writes for unchanged pod, got %d", writes)
	}
}

// TestGateway_ConflictingGateways verifies that two Gateways targeting identical NEGs resolve deterministically.
func TestGateway_ConflictingGateways(t *testing.T) {
	scheme := setupScheme()
	t0 := time.Now()
	t1 := t0.Add(10 * time.Minute)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "shared-params",
		},
		Data: map[string]string{
			"negHTTPS": "gcpgw-shared-8443",
		},
	}

	paramsRef := &gatewayv1.LocalParametersReference{
		Group: "",
		Kind:  "ConfigMap",
		Name:  "shared-params",
	}

	gwOld := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "gw-old",
			UID:               types.UID("gw-old-uid"),
			CreationTimestamp: metav1.NewTime(t0),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: paramsRef,
			},
		},
	}

	gwNew := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "gw-new",
			UID:               types.UID("gw-new-uid"),
			CreationTimestamp: metav1.NewTime(t1),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: paramsRef,
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm, gwOld, gwNew).
		WithStatusSubresource(gwOld, gwNew).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
	})

	// Reconcile gwNew
	reqNew := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-new"}}
	_, err := reconciler.Reconcile(t.Context(), reqNew)
	if err != nil {
		t.Fatalf("Reconcile gw-new failed: %v", err)
	}

	cached := reconciler.GetCachedStatus(reqNew.NamespacedName)
	if cached == nil || cached.ProgrammedStatus != metav1.ConditionFalse || cached.AcceptedStatus != metav1.ConditionFalse || cached.Reason != ReasonConflictingParameters {
		t.Errorf("expected gw-new to have Accepted=False and Programmed=False with ConflictingParameters in cache, got %+v", cached)
	}

	var gwStatus gatewayv1.GatewayStatus
	_ = reconciler.GatewayStatusHook(t.Context(), gwNew, &gwStatus)
	acc := getConditionFromStatus(&gwStatus, string(gatewayv1.GatewayConditionAccepted))
	if acc == nil || acc.Status != metav1.ConditionFalse || acc.Reason != ReasonConflictingParameters {
		t.Errorf("expected GatewayStatusHook to downgrade Accepted=False with ConflictingParameters, got %+v", acc)
	}
}

// TestController_ScopedPodStatusPatching verifies that the controller only ever patches
// its own gcpgateway.gke-labs.io/load-balancer-ready condition on this Gateway's data-plane pods,
// leaving other conditions and foreign pods untouched.
func TestController_ScopedPodStatusPatching(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	// 1. Data-plane pod for my-gw with existing conditions
	makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.PodScheduled, Status: corev1.ConditionTrue, Reason: "Scheduled"},
		{Type: corev1.PodInitialized, Status: corev1.ConditionTrue, Reason: "Initialized"},
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue, Reason: "ContainersReady"},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse, Reason: "Waiting"},
	})

	// 2. Foreign pod in same namespace belonging to another service/app
	foreignPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foreign-backend",
			Labels: map[string]string{
				"app": "unrelated-app",
			},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			PodIP: "10.0.1.99",
			Conditions: []corev1.PodCondition{
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	if err := c.Create(t.Context(), foreignPod); err != nil {
		t.Fatalf("failed to create foreign pod: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}
	_, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify my-gw data-plane pod: LoadBalancerReadyGate patched to True, other conditions preserved
	var updatedDPPod corev1.Pod
	_ = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "dp-pod-1"}, &updatedDPPod)

	condMap := make(map[corev1.PodConditionType]corev1.ConditionStatus)
	for _, cond := range updatedDPPod.Status.Conditions {
		condMap[cond.Type] = cond.Status
	}

	if condMap[corev1.PodScheduled] != corev1.ConditionTrue {
		t.Errorf("expected PodScheduled preserved as True")
	}
	if condMap[corev1.PodInitialized] != corev1.ConditionTrue {
		t.Errorf("expected PodInitialized preserved as True")
	}
	if condMap[corev1.ContainersReady] != corev1.ConditionTrue {
		t.Errorf("expected ContainersReady preserved as True")
	}
	if condMap[corev1.PodConditionType(registrar.LoadBalancerReadyGate)] != corev1.ConditionTrue {
		t.Errorf("expected LoadBalancerReadyGate patched to True, got %v", condMap[corev1.PodConditionType(registrar.LoadBalancerReadyGate)])
	}

	// Verify foreign pod was NEVER touched
	var updatedForeignPod corev1.Pod
	_ = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "foreign-backend"}, &updatedForeignPod)
	if len(updatedForeignPod.Status.Conditions) != 2 {
		t.Errorf("expected foreign pod to retain exactly 2 conditions, got %d", len(updatedForeignPod.Status.Conditions))
	}
	for _, cond := range updatedForeignPod.Status.Conditions {
		if cond.Type == corev1.PodConditionType(registrar.LoadBalancerReadyGate) {
			t.Errorf("foreign pod must NEVER have load-balancer-ready readiness gate patched onto it")
		}
	}
}

type failOnceClient struct {
	client.Client
	failOnce atomic.Bool
}

func (f *failOnceClient) Status() client.SubResourceWriter {
	return &failOnceStatusWriter{
		SubResourceWriter: f.Client.Status(),
		failOnce:          &f.failOnce,
	}
}

type failOnceStatusWriter struct {
	client.SubResourceWriter
	failOnce *atomic.Bool
}

func (w *failOnceStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if _, isPod := obj.(*corev1.Pod); isPod {
		if w.failOnce.CompareAndSwap(false, true) {
			return errors.New("injected transient pod status update error")
		}
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// TestReadinessGate_PatchRetryOnFailure verifies that if patching a pod's readiness gate fails,
// the error is returned (not dropped), and subsequent reconciliation retries successfully.
func TestReadinessGate_PatchRetryOnFailure(t *testing.T) {
	scheme := setupScheme()
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
			UID:       types.UID("my-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	baseClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, baseClient, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})

	c := &failOnceClient{Client: baseClient}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-gw"}}

	// First reconcile: injected client error on pod status update -> returns error (not dropped!)
	_, err := reconciler.Reconcile(t.Context(), req)
	if err == nil {
		t.Fatalf("expected Reconcile to return error on gate patch failure, got nil")
	}

	// Verify pod readiness gate was NOT updated to True
	var pod corev1.Pod
	if err := baseClient.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "dp-pod-1"}, &pod); err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	var gateCond *corev1.PodCondition
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodConditionType(registrar.LoadBalancerReadyGate) {
			gateCond = &cond
			break
		}
	}
	if gateCond == nil || gateCond.Status != corev1.ConditionFalse {
		t.Errorf("expected readiness gate to remain False after failed patch, got %+v", gateCond)
	}

	// Second reconcile: retry succeeds
	res, err := reconciler.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("retried Reconcile failed: %v", err)
	}
	if res.RequeueAfter != ResyncInterval {
		t.Errorf("expected RequeueAfter=%v after success, got %v", ResyncInterval, res.RequeueAfter)
	}

	// Verify readiness gate is now True
	if err := baseClient.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "dp-pod-1"}, &pod); err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodConditionType(registrar.LoadBalancerReadyGate) {
			gateCond = &cond
			break
		}
	}
	if gateCond == nil || gateCond.Status != corev1.ConditionTrue {
		t.Errorf("expected readiness gate to be True after successful retry, got %+v", gateCond)
	}

	// Verify Gateway condition Programmed=True in cache
	cached := reconciler.GetCachedStatus(req.NamespacedName)
	if cached == nil || cached.ProgrammedStatus != metav1.ConditionTrue || cached.Reason != ReasonProgrammed {
		t.Errorf("expected Programmed=True in cache after successful retry, got %+v", cached)
	}
}

// TestGateway_PeriodicResyncPrunesOrphanedEndpoints verifies that an orphaned endpoint,
// attached in the fake NEG with no matching pod, is pruned by the periodic resync without any Kubernetes event.
func TestGateway_PeriodicResyncPrunesOrphanedEndpoints(t *testing.T) {
	env := testenv.Start(t)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "gcpgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.com/gcpgateway"},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "resync-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				registrar.ZoneLabelStandard: "us-central1-a",
			},
		},
		Spec: corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}
	if err := env.Client.Create(t.Context(), node); err != nil {
		t.Fatalf("creating Node: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "resync-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "resync-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "resync-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	ap := singlepod.NewAddressProvider(
		env.Client,
		singlepod.WithExtraReadinessGates(registrar.LoadBalancerReadyGate),
		singlepod.WithTerminationGracePeriodSeconds(60),
	)
	_, _, err := ap.GatewayAddressesWithReadiness(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("GatewayAddressesWithReadiness failed: %v", err)
	}

	resName := singlepod.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName("dp-pod-1"),
		testenv.WithNodeName("node-1"),
		testenv.WithPodIP("10.0.1.5"),
		testenv.WithContainersReady(true),
	)
	if err := env.Client.Create(t.Context(), pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}
	pod.Status.PodIP = "10.0.1.5"
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionTrue},
	}
	if err := env.Client.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("updating pod status: %v", err)
	}

	skipNameValidation := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: ctrlcfg.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}

	reg := registrar.NewRegistrar(env.Client, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	rec := NewGatewayReconciler(mgr.GetClient(), mgr.GetScheme(), fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:          "cluster-1",
		NegPrefix:          "gcpgw",
		Project:            "my-project",
		ControllerName:     "example.com/gcpgateway",
		Zones:              []string{"us-central1-a"},
		ResyncInterval:     200 * time.Millisecond,
		HealthPollInterval: 200 * time.Millisecond,
	})

	if err := rec.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager failed: %v", err)
	}

	mgrErrCh := make(chan error, 1)
	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	go func() {
		mgrErrCh <- mgr.Start(mgrCtx)
	}()
	t.Cleanup(func() {
		cancelMgr()
		select {
		case err := <-mgrErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("manager stopped with unexpected error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timed out waiting for manager to exit")
		}
	})

	// 1. Wait for steady state: pod endpoint attached to NEG and Gateway Programmed=True in cache
	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(50 * time.Millisecond) {
		eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
		cached := rec.GetCachedStatus(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name})
		if len(eps) == 1 && cached != nil && cached.ProgrammedStatus == metav1.ConditionTrue {
			break
		}
	}

	// 2. Attach an orphaned endpoint directly to the fake NEG (e.g. leftover from node crash)
	orphanEP := &compute.NetworkEndpoint{
		Instance:  "gke-node-crashed",
		IpAddress: "10.0.99.88",
		Port:      8443,
	}
	if err := fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName, []*compute.NetworkEndpoint{orphanEP}); err != nil {
		t.Fatalf("failed to attach orphan endpoint: %v", err)
	}

	currentEps, err := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
	if err != nil || len(currentEps) != 2 {
		t.Fatalf("expected 2 endpoints in NEG after injecting orphan, got %d (err: %v)", len(currentEps), err)
	}

	// 3. Assert that periodic resync prunes the orphaned endpoint WITHOUT ANY Kubernetes event
	var finalEps []*compute.NetworkEndpoint
	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(50 * time.Millisecond) {
		finalEps, _ = fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
		if len(finalEps) == 1 {
			break
		}
	}

	if len(finalEps) != 1 || finalEps[0].IpAddress != "10.0.1.5" {
		t.Errorf("expected orphaned endpoint to be pruned by periodic resync, remaining: %+v", finalEps)
	}
}

// TestGateway_FinalizerManagement tests that the FinalizerCleanup is added to active Gateways
// of the managed controller class, but not to Gateways belonging to other classes.
func TestGateway_FinalizerManagement(t *testing.T) {
	scheme := setupScheme()

	gcManaged := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "managed-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "gke-labs.io/gcpgateway"},
	}
	gcForeign := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "other.io/controller"},
	}

	ipAddrType := gatewayv1.IPAddressType
	gwManaged := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "managed-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "managed-gc",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	gwForeign := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foreign-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "foreign-gc",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.20"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gcManaged, gcForeign, gwManaged, gwForeign).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:      "cluster-1",
		NegPrefix:      "gcpgw",
		Project:        "my-project",
		ControllerName: "gke-labs.io/gcpgateway",
		Zones:          []string{"us-central1-a"},
	})

	// 1. Reconcile foreign gateway -> no finalizer added
	_, err := rec.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "foreign-gw"},
	})
	if err != nil {
		t.Fatalf("Reconcile on foreign gateway failed: %v", err)
	}
	var checkForeign gatewayv1.Gateway
	_ = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "foreign-gw"}, &checkForeign)
	if controllerutil.ContainsFinalizer(&checkForeign, FinalizerCleanup) {
		t.Errorf("expected no finalizer on foreign gateway, got %v", checkForeign.Finalizers)
	}

	// 2. Reconcile managed gateway -> FinalizerCleanup is added
	_, err = rec.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "managed-gw"},
	})
	if err != nil {
		t.Fatalf("Reconcile on managed gateway failed: %v", err)
	}
	var checkManaged gatewayv1.Gateway
	_ = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "managed-gw"}, &checkManaged)
	if !controllerutil.ContainsFinalizer(&checkManaged, FinalizerCleanup) {
		t.Errorf("expected FinalizerCleanup on managed gateway, got %v", checkManaged.Finalizers)
	}
}

// TestGateway_DeleteDetachesEndpointsAndRemovesFinalizer verifies issue #871:
// When a Gateway is being deleted (DeletionTimestamp != nil), the reconciler calls DetachAll
// to cleanly detach all endpoints from all matched zonal NEGs, then removes the finalizer.
func TestGateway_DeleteDetachesEndpointsAndRemovesFinalizer(t *testing.T) {
	scheme := setupScheme()
	now := metav1.Now()

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "del-gw",
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()

	desc8080, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "del-gw",
		Port:        8080,
	}).Encode()
	desc8443, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "del-gw",
		Port:        8443,
	}).Encode()

	neg8080 := metadata.ResourceName("gcpgw", "cluster-1", "default", "del-gw", "8080")
	neg8443 := metadata.ResourceName("gcpgw", "cluster-1", "default", "del-gw", "8443")

	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8080,
		Zone:        "us-central1-a",
		Description: desc8080,
	})
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8443,
		Zone:        "us-central1-a",
		Description: desc8443,
	})

	// Pre-populate endpoints in both NEGs (as if the data plane had been running)
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8080, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.4.0.10", Port: 8080},
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.4.0.10", Port: 8443},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	// Populate status cache and waitingSince to verify they get cleaned up
	rec.statusMu.Lock()
	rec.statusCache[types.NamespacedName{Namespace: "default", Name: "del-gw"}] = &GatewayStatusResult{
		ProgrammedStatus: metav1.ConditionTrue,
		Reason:           ReasonProgrammed,
	}
	rec.statusMu.Unlock()

	delDeployName := singlepod.ResourceNameForGateway("del-gw")
	otherDeployName := singlepod.ResourceNameForGateway("other-gw")
	delPodKey := fmt.Sprintf("default/%s-pod-1", delDeployName)
	otherPodKey := fmt.Sprintf("default/%s-pod-1", otherDeployName)

	delGwKey := types.NamespacedName{Namespace: "default", Name: "del-gw"}
	otherGwKey := types.NamespacedName{Namespace: "default", Name: "other-gw"}

	rec.waitingSince[delGwKey] = map[string]time.Time{delPodKey: time.Now()}
	rec.waitingSince[otherGwKey] = map[string]time.Time{otherPodKey: time.Now()}

	req := reconcile.Request{NamespacedName: delGwKey}
	res, err := rec.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile on deleting gateway failed: %v", err)
	}
	if res.Requeue || res.RequeueAfter != 0 {
		t.Errorf("expected no requeue on successful deletion, got %+v", res)
	}

	// 1. Verify endpoints in both NEGs were detached
	eps8080, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8080)
	if len(eps8080) != 0 {
		t.Errorf("expected 0 endpoints in 8080 NEG, got %d", len(eps8080))
	}
	eps8443, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443)
	if len(eps8443) != 0 {
		t.Errorf("expected 0 endpoints in 8443 NEG, got %d", len(eps8443))
	}

	// 2. Verify FinalizerCleanup was removed from the Gateway
	var updatedGW gatewayv1.Gateway
	err = c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "del-gw"}, &updatedGW)
	if err == nil {
		if controllerutil.ContainsFinalizer(&updatedGW, FinalizerCleanup) {
			t.Errorf("expected FinalizerCleanup to be removed from gateway, got %v", updatedGW.Finalizers)
		}
	}

	// 3. Verify statusCache was cleared, del-gw waitingSince cleared, and other-gw waitingSince preserved
	if rec.GetCachedStatus(delGwKey) != nil {
		t.Errorf("expected statusCache to be cleared for deleted gateway")
	}
	if _, exists := rec.waitingSince[delGwKey]; exists {
		t.Errorf("expected waitingSince entry to be cleaned up for deleted gateway")
	}
	if _, exists := rec.waitingSince[otherGwKey]; !exists {
		t.Errorf("expected waitingSince entry for other gateway in same namespace to be preserved")
	} else if _, exists := rec.waitingSince[otherGwKey][otherPodKey]; !exists {
		t.Errorf("expected waitingSince pod entry for other gateway to be preserved")
	}
}

// TestGateway_DeletingGatewayDoesNotBlockConflictWinner verifies that a Gateway with
// DeletionTimestamp != nil is excluded from conflicting candidate sets and does not block
// a newer active Gateway from winning the NEG.
func TestGateway_DeletingGatewayDoesNotBlockConflictWinner(t *testing.T) {
	scheme := setupScheme()
	t0 := time.Now()
	t1 := t0.Add(5 * time.Minute)
	now := metav1.Now()

	ipAddrType := gatewayv1.IPAddressType
	// gwOld is older but has DeletionTimestamp set
	gwOld := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "gw-old",
			CreationTimestamp: metav1.NewTime(t0),
			DeletionTimestamp: &now,
			Finalizers:        []string{FinalizerCleanup},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses:        []gatewayv1.GatewaySpecAddress{{Type: &ipAddrType, Value: "34.120.254.10"}},
			Listeners:        []gatewayv1.Listener{{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType}},
		},
	}
	// gwNew is newer and active
	gwNew := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "gw-new",
			CreationTimestamp: metav1.NewTime(t1),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses:        []gatewayv1.GatewaySpecAddress{{Type: &ipAddrType, Value: "34.120.254.10"}},
			Listeners:        []gatewayv1.Listener{{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType}},
		},
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gwOld, gwNew, node).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	// Reconcile gwNew: it must NOT be marked as ReasonConflictingParameters because gwOld is deleting
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-new"}}
	_, err := rec.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile on gw-new failed: %v", err)
	}

	cached := rec.GetCachedStatus(req.NamespacedName)
	if cached != nil && cached.Reason == ReasonConflictingParameters {
		t.Errorf("expected active gw-new not to be blocked by deleting gw-old, but got ReasonConflictingParameters")
	}
}

// TestGateway_DeleteDetachesEndpoints_EnvTest runs an end-to-end test against a real kube-apiserver
// and manager: deploys a Gateway and pod, verifies endpoint attachment and finalizer addition,
// deletes the Gateway, and confirms that endpoints are cleanly detached from the NEG and the Gateway is removed.
func TestGateway_DeleteDetachesEndpoints_EnvTest(t *testing.T) {
	env := testenv.Start(t)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "gcpgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.com/gcpgateway"},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "delete-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				registrar.ZoneLabelStandard: "us-central1-a",
			},
		},
		Spec: corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}
	if err := env.Client.Create(t.Context(), node); err != nil {
		t.Fatalf("creating Node: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "delete-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "delete-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "delete-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	ap := singlepod.NewAddressProvider(
		env.Client,
		singlepod.WithExtraReadinessGates(registrar.LoadBalancerReadyGate),
		singlepod.WithTerminationGracePeriodSeconds(60),
	)
	_, _, err := ap.GatewayAddressesWithReadiness(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("GatewayAddressesWithReadiness failed: %v", err)
	}

	resName := singlepod.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName("dp-pod-del"),
		testenv.WithNodeName("node-1"),
		testenv.WithPodIP("10.0.1.5"),
		testenv.WithContainersReady(true),
	)
	if err := env.Client.Create(t.Context(), pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}
	pod.Status.PodIP = "10.0.1.5"
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionTrue},
	}
	if err := env.Client.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("updating pod status: %v", err)
	}

	skipNameValidation := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: ctrlcfg.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}

	reg := registrar.NewRegistrar(env.Client, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(mgr.GetClient(), mgr.GetScheme(), fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:          "cluster-1",
		NegPrefix:          "gcpgw",
		Project:            "my-project",
		ControllerName:     "example.com/gcpgateway",
		Zones:              []string{"us-central1-a"},
		ResyncInterval:     200 * time.Millisecond,
		HealthPollInterval: 200 * time.Millisecond,
	})

	if err := rec.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager failed: %v", err)
	}

	mgrErrCh := make(chan error, 1)
	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	go func() {
		mgrErrCh <- mgr.Start(mgrCtx)
	}()
	t.Cleanup(func() {
		cancelMgr()
		select {
		case err := <-mgrErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("manager stopped with unexpected error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timed out waiting for manager to exit")
		}
	})

	// 1. Wait for Gateway to be Programmed and endpoint attached
	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(50 * time.Millisecond) {
		eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
		cached := rec.GetCachedStatus(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name})
		if len(eps) == 1 && cached != nil && cached.ProgrammedStatus == metav1.ConditionTrue {
			break
		}
	}

	// Verify FinalizerCleanup was added to the Gateway
	var currentGW gatewayv1.Gateway
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &currentGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&currentGW, FinalizerCleanup) {
		t.Fatalf("expected Gateway to have FinalizerCleanup, got: %v", currentGW.Finalizers)
	}

	// 2. Delete the Gateway
	if err := env.Client.Delete(t.Context(), &currentGW); err != nil {
		t.Fatalf("failed to delete Gateway: %v", err)
	}

	// 3. Confirm that the Gateway is deleted from the API server and endpoints in the NEG are detached
	deletedFromKube := false
	negCleanedUp := false
	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(50 * time.Millisecond) {
		if !deletedFromKube {
			var checkGW gatewayv1.Gateway
			err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &checkGW)
			if err != nil {
				deletedFromKube = true
			}
		}
		if !negCleanedUp {
			eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
			if len(eps) == 0 {
				negCleanedUp = true
			}
		}
		if deletedFromKube && negCleanedUp {
			break
		}
	}

	if !negCleanedUp {
		remainingEps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
		t.Errorf("expected NEG to be cleared of endpoints after Gateway deletion, still has %d: %+v", len(remainingEps), remainingEps)
	}
	if !deletedFromKube {
		t.Errorf("expected Gateway to be finalized and removed from API server, but it still exists")
	}
}

// TestGateway_Delete_GCPErrorKeepsFinalizer verifies that a GCP error during endpoint
// detachment returns an error and keeps the FinalizerCleanup on the Gateway.
func TestGateway_Delete_GCPErrorKeepsFinalizer(t *testing.T) {
	scheme := setupScheme()
	now := metav1.Now()

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "err-gw",
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	desc8443, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "err-gw",
		Port:        8443,
	}).Encode()

	neg8443 := metadata.ResourceName("gcpgw", "cluster-1", "default", "err-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8443,
		Zone:        "us-central1-a",
		Description: desc8443,
	})

	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.4.0.10", Port: 8443},
	})

	// Inject error on detach
	fakeGCP.InjectDetachError = errors.New("simulated GCP detach failure")

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "err-gw"}}
	_, err := rec.Reconcile(t.Context(), req)
	if err == nil {
		t.Fatalf("expected error from Reconcile when GCP detach fails, got nil")
	}

	// Verify FinalizerCleanup is still present on the Gateway
	var updatedGW gatewayv1.Gateway
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "err-gw"}, &updatedGW); err != nil {
		t.Fatalf("getting gateway: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&updatedGW, FinalizerCleanup) {
		t.Errorf("expected FinalizerCleanup to be retained on detach error, got %v", updatedGW.Finalizers)
	}

	// Verify endpoint was not detached
	eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443)
	if len(eps) != 1 {
		t.Errorf("expected 1 endpoint remaining in NEG, got %d", len(eps))
	}
}

// TestGateway_Delete_ForeignNEGsUntouched verifies that deleting a Gateway only detaches
// endpoints from NEGs matching its cluster ID, namespace, and Gateway name, leaving NEGs
// belonging to other Gateways or other cluster IDs untouched.
func TestGateway_Delete_ForeignNEGsUntouched(t *testing.T) {
	scheme := setupScheme()
	now := metav1.Now()

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "target-gw",
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()

	// 1. Target NEG (same cluster-1, default, target-gw)
	descTarget, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "target-gw",
		Port:        8443,
	}).Encode()
	negTarget := metadata.ResourceName("gcpgw", "cluster-1", "default", "target-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negTarget,
		Zone:        "us-central1-a",
		Description: descTarget,
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negTarget, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.0.1.10", Port: 8443},
	})

	// 2. Foreign Gateway NEG (same cluster-1, default, other-gw)
	descOtherGW, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "other-gw",
		Port:        8443,
	}).Encode()
	negOtherGW := metadata.ResourceName("gcpgw", "cluster-1", "default", "other-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negOtherGW,
		Zone:        "us-central1-a",
		Description: descOtherGW,
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negOtherGW, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.0.1.20", Port: 8443},
	})

	// 3. Foreign Cluster NEG (other cluster-2, default, target-gw)
	descOtherCluster, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-2",
		Namespace:   "default",
		GatewayName: "target-gw",
		Port:        8443,
	}).Encode()
	negOtherCluster := metadata.ResourceName("gcpgw", "cluster-2", "default", "target-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negOtherCluster,
		Zone:        "us-central1-a",
		Description: descOtherCluster,
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negOtherCluster, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.0.1.30", Port: 8443},
	})

	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	rec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "target-gw"}}
	_, err := rec.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("Reconcile on target-gw failed: %v", err)
	}

	// 1. Target NEG must have 0 endpoints
	epsTarget, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negTarget)
	if len(epsTarget) != 0 {
		t.Errorf("expected 0 endpoints in target NEG, got %d", len(epsTarget))
	}

	// 2. Foreign Gateway NEG must still have its endpoint
	epsOtherGW, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negOtherGW)
	if len(epsOtherGW) != 1 || epsOtherGW[0].IpAddress != "10.0.1.20" {
		t.Errorf("expected other-gw NEG to be untouched, got: %+v", epsOtherGW)
	}

	// 3. Foreign Cluster NEG must still have its endpoint
	epsOtherCluster, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negOtherCluster)
	if len(epsOtherCluster) != 1 || epsOtherCluster[0].IpAddress != "10.0.1.30" {
		t.Errorf("expected other-cluster NEG to be untouched, got: %+v", epsOtherCluster)
	}
}

// TestGateway_ControllerRestartWithNoDeletionDetachesNothing verifies that when the controller
// restarts with a fresh in-memory state, reconciling an existing active Gateway does not detach
// any endpoints from the NEGs.
func TestGateway_ControllerRestartWithNoDeletionDetachesNothing(t *testing.T) {
	scheme := setupScheme()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "gcpgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "gke-labs.io/gcpgateway"},
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "restart-gw",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &ipAddrType, Value: "34.120.254.10"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "https", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}

	deployName := singlepod.ResourceNameForGateway("restart-gw")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      fmt.Sprintf("%s-pod-1", deployName),
			Labels: map[string]string{
				singlepod.LabelAppName:     singlepod.AppNameValue,
				singlepod.LabelGatewayName: "restart-gw",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.1.5",
			Conditions: []corev1.PodCondition{
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
				{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionTrue},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gc, gw, node, pod).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	desc8443, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "restart-gw",
		Port:        8443,
	}).Encode()

	neg8443 := metadata.ResourceName("gcpgw", "cluster-1", "default", "restart-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8443,
		Zone:        "us-central1-a",
		Description: desc8443,
	})

	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443},
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "restart-gw", "bs-443")
	negURL := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/networkEndpointGroups/%s", neg8443)
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negURL, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	// Pre-condition: detach calls is 0
	if len(fakeGCP.DetachCalls) != 0 {
		t.Fatalf("expected 0 detach calls initially, got %d", len(fakeGCP.DetachCalls))
	}

	// Create a new controller instance, simulating controller restart with fresh in-memory state
	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	restartedRec := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:      "cluster-1",
		NegPrefix:      "gcpgw",
		Project:        "my-project",
		ControllerName: "gke-labs.io/gcpgateway",
		Zones:          []string{"us-central1-a"},
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "restart-gw"}}
	_, err := restartedRec.Reconcile(t.Context(), req)
	if err != nil {
		t.Fatalf("reconcile after restart failed: %v", err)
	}

	// Verify no detach calls were made during controller restart
	if len(fakeGCP.DetachCalls) != 0 {
		t.Errorf("expected 0 detach calls on restart with active gateway, got %d: %+v", len(fakeGCP.DetachCalls), fakeGCP.DetachCalls)
	}

	// Verify endpoint is still in NEG
	eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443)
	if len(eps) != 1 || eps[0].IpAddress != "10.0.1.5" {
		t.Errorf("expected endpoint to remain attached, got: %+v", eps)
	}
}

func setupLongNameTest(t *testing.T, initObjs ...client.Object) (string, *gatewayv1.Gateway, client.Client, *GatewayReconciler, *gcp.FakeComputeClient) {
	t.Helper()
	scheme := setupScheme()
	prefix := "gateway-name-maximum-length-"
	longGwName := prefix + strings.Repeat("a", 253-len(prefix))
	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      longGwName,
			UID:       types.UID("long-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.10",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	objs := append([]client.Object{gw}, initObjs...)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithIndex(&gatewayv1.Gateway{}, GatewayLabelValueIndex, GatewayLabelValueIndexer).
		WithObjects(objs...).
		Build()

	fakeGCP := gcp.NewFakeComputeClient()
	reg := registrar.NewRegistrar(c, fakeGCP, registrar.Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})
	reconciler := NewGatewayReconciler(c, scheme, fakeGCP, reg, GatewayReconcilerConfig{
		ClusterID:      "cluster-1",
		NegPrefix:      "gcpgw",
		Project:        "my-project",
		ControllerName: "gke-labs.io/gcpgateway",
		Zones:          []string{"us-central1-a"},
	})

	return longGwName, gw, c, reconciler, fakeGCP
}

func TestGateway_LabelValueIndex_MapFunctions(t *testing.T) {
	scheme := setupScheme()
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "short-gw"},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&gatewayv1.Gateway{}, GatewayLabelValueIndex, GatewayLabelValueIndexer).
		WithObjects(gw).
		Build()

	rec := &GatewayReconciler{Client: c}
	labelVal := singlepod.LabelValueForGateway("short-gw")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Labels: map[string]string{
				singlepod.LabelAppName:     singlepod.AppNameValue,
				singlepod.LabelGatewayName: labelVal,
			},
		},
	}
	if reqs := rec.podToGateway(t.Context(), pod); len(reqs) != 1 || reqs[0].Name != "short-gw" {
		t.Errorf("podToGateway = %v, want default/short-gw", reqs)
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Labels:    map[string]string{singlepod.LabelGatewayName: labelVal},
		},
	}
	if reqs := rec.endpointSliceToGateway(t.Context(), slice); len(reqs) != 1 || reqs[0].Name != "short-gw" {
		t.Errorf("endpointSliceToGateway = %v, want default/short-gw", reqs)
	}
}

func TestGateway_LabelValueIndex_MultipleMatches(t *testing.T) {
	scheme := setupScheme()
	gw1 := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-one"}}
	gw2 := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-two"}}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&gatewayv1.Gateway{}, GatewayLabelValueIndex, func(client.Object) []string {
			return []string{"collision-label"}
		}).
		WithObjects(gw1, gw2).
		Build()

	rec := &GatewayReconciler{Client: c}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Labels: map[string]string{
				singlepod.LabelAppName:     singlepod.AppNameValue,
				singlepod.LabelGatewayName: "collision-label",
			},
		},
	}

	reqs := rec.podToGateway(t.Context(), pod)
	var names []string
	for _, req := range reqs {
		names = append(names, req.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"gw-one", "gw-two"}) {
		t.Errorf("podToGateway = %v, want [gw-one gw-two]", names)
	}
}

func TestGateway_LongName_PodToGateway(t *testing.T) {
	longGwName, _, _, reconciler, _ := setupLongNameTest(t)

	// Pod carries the hashed 63-character label value from singlepod.LabelValueForGateway
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-pod",
			Labels: map[string]string{
				singlepod.LabelAppName:     singlepod.AppNameValue,
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway(longGwName),
			},
		},
	}

	reqs := reconciler.podToGateway(t.Context(), pod)
	if len(reqs) != 1 || reqs[0].NamespacedName != (types.NamespacedName{Namespace: "default", Name: longGwName}) {
		t.Errorf("podToGateway mapped to %v, want default/%s", reqs, longGwName)
	}
}

func TestGateway_LongName_EndpointSliceToGateway(t *testing.T) {
	longGwName, _, _, reconciler, _ := setupLongNameTest(t)

	// EndpointSlice carries the hashed 63-character label value copied from Service
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-slice",
			Labels: map[string]string{
				singlepod.LabelGatewayName: singlepod.LabelValueForGateway(longGwName),
			},
		},
	}

	reqs := reconciler.endpointSliceToGateway(t.Context(), slice)
	if len(reqs) != 1 || reqs[0].NamespacedName != (types.NamespacedName{Namespace: "default", Name: longGwName}) {
		t.Errorf("endpointSliceToGateway mapped to %v, want default/%s", reqs, longGwName)
	}
}

func TestGateway_LongName_Reconcile(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/gke-node-1"},
	}
	longGwName, gw, c, reconciler, fakeGCP := setupLongNameTest(t, node)

	makeTestPod(t, c, gw, "dp-pod-1", "node-1", "10.0.1.5", []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(registrar.LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	})

	negDesc, err := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: longGwName,
		Port:        8443,
	}).Encode()
	if err != nil {
		t.Fatalf("failed to encode NEG metadata: %v", err)
	}

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", longGwName, "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: longGwName}}
	if _, err := reconciler.Reconcile(t.Context(), req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify that the data plane pod was matched and attached to the NEG
	eps, err := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
	if err != nil {
		t.Fatalf("listing network endpoints: %v", err)
	}
	if len(eps) != 1 || eps[0].IpAddress != "10.0.1.5" {
		t.Fatalf("expected pod attached to NEG, got %+v", eps)
	}
}
