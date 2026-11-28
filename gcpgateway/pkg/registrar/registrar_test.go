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

package registrar

import (
	"errors"
	"fmt"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/metadata"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
	compute "google.golang.org/api/compute/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func setupTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = gatewayv1.Install(s)
	return s
}

func makeTestGateway(ns, name string, createdAt time.Time) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID(fmt.Sprintf("%s-%s-uid", ns, name)),
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
}

func makeTestNode(name, zone, instance string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				ZoneLabelStandard: zone,
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: fmt.Sprintf("gce://my-project/%s/%s", zone, instance),
		},
	}
}

func makeTestPod(t *testing.T, c client.Client, gw *gatewayv1.Gateway, name, nodeName, ip string, containersReady, overallReady bool, isTerminating bool) *corev1.Pod {
	if err := spiffe.EnsureCredentials(t.Context(), c, "default"); err != nil {
		t.Fatalf("ensuring credentials: %v", err)
	}

	drainVol := corev1ac.Volume().
		WithName("drain-volume").
		WithEmptyDir(corev1ac.EmptyDirVolumeSource().WithMedium(corev1.StorageMediumMemory))
	drainMount := corev1ac.VolumeMount().
		WithName("drain-volume").
		WithMountPath("/var/run/gcpgateway")
	preStopCmd := []string{"/gcpgateway", "hook", "pre-stop", "--drain-seconds=35"}

	p := singlepod.NewAddressProvider(
		c,
		"default",
		singlepod.WithExtraReadinessGates(LoadBalancerReadyGate),
		singlepod.WithPreStopCommand(preStopCmd...),
		singlepod.WithExtraVolumes([]*corev1ac.VolumeApplyConfiguration{drainVol}, []*corev1ac.VolumeMountApplyConfiguration{drainMount}),
		singlepod.WithTerminationGracePeriodSeconds(60),
	)

	_, err := p.GatewayAddresses(t.Context(), gw, nil)
	var condErr *state.ConditionError
	if err != nil && !errors.As(err, &condErr) {
		t.Fatalf("failed to reconcile deployment for pod template: %v", err)
	}

	resName := state.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	conditions := []corev1.PodCondition{
		{
			Type:   corev1.ContainersReady,
			Status: corev1.ConditionFalse,
		},
		{
			Type:   corev1.PodReady,
			Status: corev1.ConditionFalse,
		},
	}
	if containersReady {
		conditions[0].Status = corev1.ConditionTrue
	}
	if overallReady {
		conditions[1].Status = corev1.ConditionTrue
	}

	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName(name),
		testenv.WithNodeName(nodeName),
		testenv.WithPodIP(ip),
		testenv.WithContainersReady(containersReady),
		testenv.WithReady(overallReady),
	)
	pod.Finalizers = []string{"kubernetes.io/gcpgateway-test"}

	if err := c.Create(t.Context(), pod); err != nil {
		t.Fatalf("failed to create pod: %v", err)
	}

	pod.Status = corev1.PodStatus{
		PodIP:      ip,
		Conditions: conditions,
	}
	if err := c.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	if isTerminating {
		if err := c.Delete(t.Context(), pod); err != nil {
			t.Fatalf("failed to delete pod: %v", err)
		}
		_ = c.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: name}, pod)
	}

	return pod
}

// TestRegistrar_ReadinessGateDeadlockPrevention tests that a pod whose ContainersReady is true,
// but which is held not-ready by the readiness gate (Ready=false), DOES get attached to the NEG.
func TestRegistrar_ReadinessGateDeadlockPrevention(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())
	node := makeTestNode("node-1", "us-central1-a", "gke-node-1")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	// Pod has ContainersReady=true, but Ready=false!
	makeTestPod(t, k8sClient, gw, "dp-pod-1", "node-1", "10.0.1.5", true, false, false)

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

	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	res, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("ReconcileEndpoints failed: %v", err)
	}

	if res.AttachedCount != 1 {
		t.Errorf("expected 1 pod attached, got %d", res.AttachedCount)
	}

	eps, err := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
	if err != nil {
		t.Fatalf("ListNetworkEndpoints failed: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint in NEG, got %d", len(eps))
	}
	if eps[0].IpAddress != "10.0.1.5" || eps[0].Instance != "gke-node-1" || eps[0].Port != 8443 {
		t.Errorf("unexpected endpoint in NEG: %+v", eps[0])
	}
}

// TestRegistrar_ImmediateDetachOfTerminatingPod verifies that a terminating pod detaches immediately.
func TestRegistrar_ImmediateDetachOfTerminatingPod(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())
	node := makeTestNode("node-1", "us-central1-a", "gke-node-1")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	// Pod is terminating: ContainersReady=true, but DeletionTimestamp != nil
	makeTestPod(t, k8sClient, gw, "dp-pod-1", "node-1", "10.0.1.5", true, true, true)

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

	// Pre-populate NEG with this endpoint
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName, []*compute.NetworkEndpoint{
		{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443},
	})

	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	res, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("ReconcileEndpoints failed: %v", err)
	}

	if res.DetachedCount != 1 {
		t.Errorf("expected 1 detached endpoint, got %d", res.DetachedCount)
	}

	eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints in NEG after immediate detach, got %d", len(eps))
	}
}

// TestRegistrar_FlappingHysteresis verifies that unready non-terminating pods observe hysteresis before detach.
func TestRegistrar_FlappingHysteresis(t *testing.T) {
	tracker := NewHysteresisTracker(15 * time.Second)
	baseTime := time.Now()
	podKey := "default/dp-pod-1"

	// 1. Pod loses ContainersReady at t=0
	if tracker.ShouldDetach(podKey, false, false, baseTime) {
		t.Errorf("t=0: expected ShouldDetach=false (hysteresis window just started)")
	}

	// 2. Pod is still unready at t=5s (<15s window)
	if tracker.ShouldDetach(podKey, false, false, baseTime.Add(5*time.Second)) {
		t.Errorf("t=5s: expected ShouldDetach=false (within hysteresis window)")
	}

	// 3. Pod recovers ContainersReady at t=10s (<15s window)
	if tracker.ShouldDetach(podKey, true, false, baseTime.Add(10*time.Second)) {
		t.Errorf("t=10s: expected ShouldDetach=false (pod recovered readiness)")
	}

	// 4. Pod loses ContainersReady again at t=12s: timer restarts from t=12s
	if tracker.ShouldDetach(podKey, false, false, baseTime.Add(12*time.Second)) {
		t.Errorf("t=12s: expected ShouldDetach=false (new window started)")
	}

	// 5. Pod remains unready at t=28s (16s > 15s window)
	if !tracker.ShouldDetach(podKey, false, false, baseTime.Add(28*time.Second)) {
		t.Errorf("t=28s: expected ShouldDetach=true (hysteresis window elapsed)")
	}
}

// TestRegistrar_OrphanPruning verifies that endpoints in a NEG with no corresponding pod are pruned.
func TestRegistrar_OrphanPruning(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())

	// No pods in k8s!
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		Build()

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

	// Seed NEG with an orphaned endpoint
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName, []*compute.NetworkEndpoint{
		{Instance: "gke-old-instance", IpAddress: "10.0.1.99", Port: 8443},
	})

	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	res, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("ReconcileEndpoints failed: %v", err)
	}

	if res.DetachedCount != 1 {
		t.Errorf("expected 1 orphaned endpoint pruned, got %d", res.DetachedCount)
	}

	eps, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
	if len(eps) != 0 {
		t.Errorf("expected 0 endpoints remaining in NEG after orphan pruning, got %d", len(eps))
	}
}

// TestRegistrar_OwnershipProtection verifies that NEGs with matching prefix but foreign or missing metadata
// are never attached, detached or pruned.
func TestRegistrar_OwnershipProtection(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())
	node := makeTestNode("node-1", "us-central1-a", "gke-node-1")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, k8sClient, gw, "dp-pod-1", "node-1", "10.0.1.5", true, true, false)

	fakeGCP := gcp.NewFakeComputeClient()

	// 1. NEG with missing metadata
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        "gcpgw-no-desc",
		Zone:        "us-central1-a",
		Description: "",
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", "gcpgw-no-desc", []*compute.NetworkEndpoint{
		{Instance: "other-inst", IpAddress: "10.0.9.1", Port: 8443},
	})

	// 2. NEG with unparseable metadata
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        "gcpgw-bad-json",
		Zone:        "us-central1-a",
		Description: "{invalid-json",
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", "gcpgw-bad-json", []*compute.NetworkEndpoint{
		{Instance: "other-inst", IpAddress: "10.0.9.2", Port: 8443},
	})

	// 3. NEG with foreign cluster ID
	foreignClusterDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "foreign-cluster",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        "gcpgw-foreign-cluster",
		Zone:        "us-central1-a",
		Description: foreignClusterDesc,
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", "gcpgw-foreign-cluster", []*compute.NetworkEndpoint{
		{Instance: "foreign-inst", IpAddress: "10.0.9.3", Port: 8443},
	})

	// 4. NEG with foreign namespace
	foreignNsDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "other-namespace",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        "gcpgw-foreign-ns",
		Zone:        "us-central1-a",
		Description: foreignNsDesc,
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", "gcpgw-foreign-ns", []*compute.NetworkEndpoint{
		{Instance: "foreign-inst-2", IpAddress: "10.0.9.4", Port: 8443},
	})

	// Reset recorded calls so we only inspect calls made during reconciliation
	fakeGCP.AttachCalls = nil
	fakeGCP.DetachCalls = nil

	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
	})

	res, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("ReconcileEndpoints failed: %v", err)
	}

	if res.MatchedNEGs != 0 {
		t.Errorf("expected 0 matched NEGs, got %d", res.MatchedNEGs)
	}
	if len(fakeGCP.AttachCalls) != 0 {
		t.Errorf("expected 0 attach calls to foreign/unowned NEGs, got %d", len(fakeGCP.AttachCalls))
	}
	if len(fakeGCP.DetachCalls) != 0 {
		t.Errorf("expected 0 detach calls to foreign/unowned NEGs, got %d", len(fakeGCP.DetachCalls))
	}
}

// TestRegistrar_DeterministicConflictResolution verifies deterministic resolution of NEG conflicts.
func TestRegistrar_DeterministicConflictResolution(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(5 * time.Minute)

	// gwOld is older than gwNew
	gwOld := makeTestGateway("default", "gw-old", t0)
	gwNew := makeTestGateway("default", "gw-new", t1)

	winner := ResolveNEGConflict([]*gatewayv1.Gateway{gwNew, gwOld})
	if winner.Name != "gw-old" {
		t.Errorf("expected older gateway to win, got %s", winner.Name)
	}

	// Identical creation timestamp: lexicographical tie-breaker
	gwA := makeTestGateway("ns-b", "gw-1", t0)
	gwB := makeTestGateway("ns-a", "gw-2", t0)

	winnerTie := ResolveNEGConflict([]*gatewayv1.Gateway{gwA, gwB})
	if winnerTie.Namespace != "ns-a" {
		t.Errorf("expected ns-a to win tie-breaker, got %s", winnerTie.Namespace)
	}

	// Repeated resolution after simulated restart yields identical deterministic winner
	for i := 0; i < 5; i++ {
		repeatWinner := ResolveNEGConflict([]*gatewayv1.Gateway{gwA, gwB})
		if repeatWinner.Namespace != "ns-a" {
			t.Errorf("iteration %d: expected deterministic winner ns-a, got %s", i, repeatWinner.Namespace)
		}
	}
}

// TestRegistrar_ErrorHandling verifies PERMISSION_DENIED, quota, NEGNotFound, and invalid-IP
// errors each produce appropriate errors without crashing the controller.
func TestRegistrar_ErrorHandling(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())
	node := makeTestNode("node-1", "us-central1-a", "gke-node-1")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, k8sClient, gw, "dp-pod-1", "node-1", "10.0.1.5", true, true, false)

	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")

	tests := []struct {
		name        string
		injectError error
		checkFunc   func(error) bool
	}{
		{
			name:        "PERMISSION_DENIED",
			injectError: gcp.ErrPermissionDenied,
			checkFunc:   gcp.IsPermissionDenied,
		},
		{
			name:        "QuotaExceeded",
			injectError: gcp.ErrQuotaExceeded,
			checkFunc:   gcp.IsQuotaExceeded,
		},
		{
			name:        "NEGNotFound",
			injectError: gcp.ErrNEGNotFound,
			checkFunc:   gcp.IsNEGNotFound,
		},
		{
			name:        "InvalidIP",
			injectError: gcp.ErrInvalidIP,
			checkFunc:   gcp.IsInvalidIP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeGCP := gcp.NewFakeComputeClient()
			fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
				Name:        negName,
				Zone:        "us-central1-a",
				Description: negDesc,
			})
			fakeGCP.InjectAttachError = tc.injectError

			reg := NewRegistrar(k8sClient, fakeGCP, Config{
				ClusterID: "cluster-1",
				NegPrefix: "gcpgw",
				Project:   "my-project",
				Zones:     []string{"us-central1-a"},
			})

			_, err := reg.ReconcileEndpoints(t.Context(), gw)
			if err == nil {
				t.Fatalf("expected error from ReconcileEndpoints, got nil")
			}
			if !tc.checkFunc(err) && !errors.Is(err, tc.injectError) {
				t.Errorf("expected error matching %s check, got: %v", tc.name, err)
			}
		})
	}
}

// TestRegistrar_DetachAll tests that DetachAll and ReconcileEndpoints on a deleting Gateway
// cleanly detach all endpoints from all matched zonal NEGs across all ports and zones.
func TestRegistrar_DetachAll(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "del-gw", time.Now())
	nodeA := makeTestNode("node-a", "us-central1-a", "gke-node-a")
	nodeB := makeTestNode("node-b", "us-central1-b", "gke-node-b")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &gatewayv1.Gateway{}, &appsv1.Deployment{}).
		WithObjects(gw, nodeA, nodeB).
		Build()

	makeTestPod(t, k8sClient, gw, "dp-pod-a", "node-a", "10.0.1.5", true, true, false)
	makeTestPod(t, k8sClient, gw, "dp-pod-b", "node-b", "10.0.2.6", true, true, false)

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

	neg8080A := metadata.ResourceName("gcpgw", "cluster-1", "default", "del-gw", "8080")
	neg8443A := metadata.ResourceName("gcpgw", "cluster-1", "default", "del-gw", "8443")
	neg8443B := metadata.ResourceName("gcpgw", "cluster-1", "default", "del-gw", "8443")

	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8080A,
		Zone:        "us-central1-a",
		Description: desc8080,
	})
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        neg8443A,
		Zone:        "us-central1-a",
		Description: desc8443,
	})
	fakeGCP.AddNEG("my-project", "us-central1-b", &compute.NetworkEndpointGroup{
		Name:        neg8443B,
		Zone:        "us-central1-b",
		Description: desc8443,
	})

	// Pre-populate endpoints in all NEGs
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8080A, []*compute.NetworkEndpoint{
		{Instance: "gke-node-a", IpAddress: "10.0.1.5", Port: 8080},
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443A, []*compute.NetworkEndpoint{
		{Instance: "gke-node-a", IpAddress: "10.0.1.5", Port: 8443},
	})
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-b", neg8443B, []*compute.NetworkEndpoint{
		{Instance: "gke-node-b", IpAddress: "10.0.2.6", Port: 8443},
	})

	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a", "us-central1-b"},
	})

	// 1. Explicit DetachAll call
	res, err := reg.DetachAll(t.Context(), gw)
	if err != nil {
		t.Fatalf("DetachAll failed: %v", err)
	}
	if res.DetachedCount != 3 {
		t.Errorf("expected 3 detached endpoints, got %d", res.DetachedCount)
	}

	for _, tc := range []struct {
		zone, neg string
	}{
		{"us-central1-a", neg8080A},
		{"us-central1-a", neg8443A},
		{"us-central1-b", neg8443B},
	} {
		eps, err := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", tc.zone, tc.neg)
		if err != nil {
			t.Fatalf("listing endpoints for %s/%s: %v", tc.zone, tc.neg, err)
		}
		if len(eps) != 0 {
			t.Errorf("expected 0 endpoints in %s/%s, got %d", tc.zone, tc.neg, len(eps))
		}
	}

	// 2. ReconcileEndpoints on deleting Gateway (gw.DeletionTimestamp != nil)
	_ = fakeGCP.AttachNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443A, []*compute.NetworkEndpoint{
		{Instance: "gke-node-a", IpAddress: "10.0.1.5", Port: 8443},
	})
	now := metav1.Now()
	gw.DeletionTimestamp = &now
	res2, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("ReconcileEndpoints on deleting gateway failed: %v", err)
	}
	if res2.DetachedCount != 1 {
		t.Errorf("expected 1 detached endpoint, got %d", res2.DetachedCount)
	}
	epsAfter, _ := fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", neg8443A)
	if len(epsAfter) != 0 {
		t.Errorf("expected 0 endpoints remaining, got %d", len(epsAfter))
	}
}

// TestRegistrar_AttachErrorAndEvents verifies that failing attachNetworkEndpoints calls
// return an error, emit Warning events on the Gateway and affected data-plane pods,
// and succeed when the underlying error is cleared.
func TestRegistrar_AttachErrorAndEvents(t *testing.T) {
	scheme := setupTestScheme()
	gw := makeTestGateway("default", "my-gw", time.Now())
	node := makeTestNode("node-1", "us-central1-a", "gke-node-1")

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, node).
		Build()

	makeTestPod(t, k8sClient, gw, "dp-pod-1", "node-1", "10.0.1.5", true, true, false)

	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")

	fakeGCP := gcp.NewFakeComputeClient()
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})
	fakeGCP.InjectAttachError = gcp.ErrPermissionDenied

	fakeRecorder := record.NewFakeRecorder(100)
	reg := NewRegistrar(k8sClient, fakeGCP, Config{
		ClusterID: "cluster-1",
		NegPrefix: "gcpgw",
		Project:   "my-project",
		Zones:     []string{"us-central1-a"},
		Recorder:  fakeRecorder,
	})

	// 1. Initial attempt fails and emits warning events on Gateway and Pod
	_, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err == nil || !gcp.IsPermissionDenied(err) {
		t.Fatalf("expected permission denied error, got: %v", err)
	}
	if len(fakeGCP.AttachCalls) != 1 {
		t.Fatalf("expected exactly 1 Attach call, got %d", len(fakeGCP.AttachCalls))
	}

	// Verify events were emitted: one on Gateway and one on the data-plane pod
	var events []string
	for len(fakeRecorder.Events) > 0 {
		events = append(events, <-fakeRecorder.Events)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 warning events (1 on GW, 1 on Pod), got %d: %v", len(events), events)
	}
	for _, ev := range events {
		if !strings.Contains(ev, "Warning") || !strings.Contains(ev, "PermissionDenied") {
			t.Errorf("expected warning event with Reason PermissionDenied, got %q", ev)
		}
	}

	// 2. Clear error (IAM permission granted)
	fakeGCP.InjectAttachError = nil

	// 3. Subsequent reconcile succeeds and attaches endpoints
	res, err := reg.ReconcileEndpoints(t.Context(), gw)
	if err != nil {
		t.Fatalf("expected successful reconcile after error cleared, got: %v", err)
	}
	if res.AttachedCount != 1 {
		t.Errorf("expected 1 attached endpoint, got %d", res.AttachedCount)
	}
	if len(fakeGCP.AttachCalls) != 2 {
		t.Errorf("expected 2 total Attach calls, got %d", len(fakeGCP.AttachCalls))
	}
}
