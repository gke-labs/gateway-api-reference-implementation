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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/metadata"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/registrar"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// GatewayLabelValueIndex is the field index name used to map singlepod label values to Gateways.
	GatewayLabelValueIndex = "gcpgateway.gke-labs.io/gateway-label-value"

	// FinalizerCleanup is added to Gateways managed by gcpgateway to ensure data-plane
	// endpoints and resources are cleanly detached and cleaned up before the Gateway is deleted.
	FinalizerCleanup = "gcpgateway.gke-labs.io/cleanup"

	// DefaultHealthTimeout is the duration after which an unconfirmed endpoint triggers RolloutStalled.
	DefaultHealthTimeout = 60 * time.Second

	// HealthPollInterval is the interval at which the reconciler requeues to poll load balancer
	// health when data-plane pods are attached to NEGs but their readiness gates are not yet True.
	// A 5-second interval balances fast rollout progression (health check convergence typically
	// takes 10–30s on Google Cloud) against Compute API rate limits and quota usage.
	HealthPollInterval = 5 * time.Second

	// ResyncInterval is the interval at which every Gateway is periodically requeued in the steady state.
	// This ensures periodic orphan endpoint pruning (such as endpoints left behind after node crashes
	// or ungraceful pod deletions without Kubernetes events) and drift correction. A 60-second
	// interval bounds the lifetime of orphaned endpoints while minimizing background Compute API load.
	ResyncInterval = 60 * time.Second

	// Condition reasons
	ReasonAccepted                 = "Accepted"
	ReasonInvalidParameters        = "InvalidParameters"
	ReasonConflictingParameters    = "ConflictingParameters"
	ReasonAddressNotAssigned       = "AddressNotAssigned"
	ReasonWaitingForDataPlane      = "WaitingForDataPlane"
	ReasonWaitingForEndpoints      = "WaitingForEndpoints"
	ReasonRolloutStalled           = "RolloutStalled"
	ReasonProgrammed               = "Programmed"
	ReasonPermissionDenied         = registrar.ReasonPermissionDenied
	ReasonQuotaExceeded            = registrar.ReasonQuotaExceeded
	ReasonNEGNotFound              = registrar.ReasonNEGNotFound
	ReasonUnsupportedCluster       = registrar.ReasonUnsupportedCluster
	ReasonEndpointAttachmentFailed = registrar.ReasonEndpointAttachmentFailed
)

// GatewayStatusResult represents the cached status result for a Gateway.
type GatewayStatusResult struct {
	AcceptedStatus   metav1.ConditionStatus
	ProgrammedStatus metav1.ConditionStatus
	Reason           string
	Message          string
	Addresses        []gatewayv1.GatewayStatusAddress
	CustomConditions []metav1.Condition
}

func (r *GatewayStatusResult) equal(other *GatewayStatusResult) bool {
	if r == nil || other == nil {
		return r == other
	}
	if r.AcceptedStatus != other.AcceptedStatus || r.ProgrammedStatus != other.ProgrammedStatus || r.Reason != other.Reason || r.Message != other.Message {
		return false
	}
	if len(r.Addresses) != len(other.Addresses) {
		return false
	}
	for i := range r.Addresses {
		a1 := r.Addresses[i]
		a2 := other.Addresses[i]
		if a1.Value != a2.Value {
			return false
		}
		if (a1.Type == nil) != (a2.Type == nil) {
			return false
		}
		if a1.Type != nil && *a1.Type != *a2.Type {
			return false
		}
	}
	if len(r.CustomConditions) != len(other.CustomConditions) {
		return false
	}
	for i := range r.CustomConditions {
		c1 := r.CustomConditions[i]
		c2 := other.CustomConditions[i]
		if c1.Type != c2.Type || c1.Status != c2.Status || c1.Reason != c2.Reason || c1.Message != c2.Message {
			return false
		}
	}
	return true
}

// GatewayReconciler reconciles Gateways using Google Cloud zonal NEGs and L4 load balancers.
type GatewayReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	GCPClient      gcp.ComputeClient
	ClusterID      string
	NegPrefix      string
	Project        string
	Zones          []string
	ControllerName string
	HealthTimeout  time.Duration
	Registrar      *registrar.Registrar

	HealthPollInterval time.Duration
	ResyncInterval     time.Duration

	// mu guards waitingSince.
	mu           sync.Mutex
	waitingSince map[types.NamespacedName]map[string]time.Time

	// EnqueueGateway is an optional callback to trigger a GARI Gateway reconcile when state changes.
	EnqueueGateway func(types.NamespacedName)

	// statusMu guards statusCache.
	statusMu    sync.RWMutex
	statusCache map[types.NamespacedName]*GatewayStatusResult
}

// GatewayReconcilerConfig contains configuration parameters for GatewayReconciler.
type GatewayReconcilerConfig struct {
	ClusterID          string
	NegPrefix          string
	Project            string
	Zones              []string
	ControllerName     string
	HealthTimeout      time.Duration
	HealthPollInterval time.Duration
	ResyncInterval     time.Duration
	EnqueueGateway     func(types.NamespacedName)
}

// NewGatewayReconciler creates a new GatewayReconciler.
func NewGatewayReconciler(c client.Client, scheme *runtime.Scheme, gcpClient gcp.ComputeClient, reg *registrar.Registrar, cfg GatewayReconcilerConfig) *GatewayReconciler {
	if cfg.NegPrefix == "" {
		cfg.NegPrefix = "gcpgw"
	}
	healthTimeout := cfg.HealthTimeout
	if healthTimeout <= 0 {
		healthTimeout = DefaultHealthTimeout
	}
	pollInterval := cfg.HealthPollInterval
	if pollInterval <= 0 {
		pollInterval = HealthPollInterval
	}
	resyncInterval := cfg.ResyncInterval
	if resyncInterval <= 0 {
		resyncInterval = ResyncInterval
	}
	return &GatewayReconciler{
		Client:             c,
		Scheme:             scheme,
		GCPClient:          gcpClient,
		ClusterID:          cfg.ClusterID,
		NegPrefix:          cfg.NegPrefix,
		Project:            cfg.Project,
		Zones:              cfg.Zones,
		ControllerName:     cfg.ControllerName,
		HealthTimeout:      healthTimeout,
		HealthPollInterval: pollInterval,
		ResyncInterval:     resyncInterval,
		EnqueueGateway:     cfg.EnqueueGateway,
		Registrar:          reg,
		waitingSince:       make(map[types.NamespacedName]map[string]time.Time),
		statusCache:        make(map[types.NamespacedName]*GatewayStatusResult),
	}
}

// GatewayLabelValueIndexer indexes a Gateway by singlepod.LabelValueForGateway.
func GatewayLabelValueIndexer(rawObj client.Object) []string {
	gw, ok := rawObj.(*gatewayv1.Gateway)
	if !ok || gw == nil || gw.Name == "" {
		return nil
	}
	return []string{singlepod.LabelValueForGateway(gw.Name)}
}

// SetupWithManager registers GatewayReconciler with the controller-runtime Manager,
// watching Gateways, data-plane Pods, and EndpointSlices.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, GatewayLabelValueIndex, GatewayLabelValueIndexer); err != nil {
		return fmt.Errorf("registering field index %s: %w", GatewayLabelValueIndex, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("gcpgateway").
		For(&gatewayv1.Gateway{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.podToGateway)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.endpointSliceToGateway)).
		Complete(r)
}

// gatewayRequestForLabel finds Gateways in the namespace matching the label value
// using the GatewayLabelValueIndex field index. If multiple Gateways match
// (which can only occur due to a hash collision between long Gateway names),
// a warning is logged and all matching Gateways are enqueued.
func (r *GatewayReconciler) gatewayRequestForLabel(ctx context.Context, namespace, labelValue string) []reconcile.Request {
	if labelValue == "" {
		return nil
	}
	var gwList gatewayv1.GatewayList
	if err := r.Client.List(ctx, &gwList, client.InNamespace(namespace), client.MatchingFields{GatewayLabelValueIndex: labelValue}); err != nil {
		klog.ErrorS(err, "listing gateways to map label to gateway", "namespace", namespace, "labelValue", labelValue)
		return nil
	}
	if len(gwList.Items) == 0 {
		return nil
	}
	if len(gwList.Items) > 1 {
		names := make([]string, len(gwList.Items))
		for i, gw := range gwList.Items {
			names[i] = gw.Name
		}
		klog.Warningf("Multiple Gateways matched label value %q in namespace %q: %v; enqueuing all matches (possible hash collision)", labelValue, namespace, names)
	}
	reqs := make([]reconcile.Request, len(gwList.Items))
	for i, gw := range gwList.Items {
		reqs[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: namespace,
				Name:      gw.Name,
			},
		}
	}
	return reqs
}

func (r *GatewayReconciler) podToGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod == nil {
		return nil
	}
	if pod.Labels[singlepod.LabelAppName] != singlepod.AppNameValue {
		return nil
	}
	return r.gatewayRequestForLabel(ctx, pod.Namespace, pod.Labels[singlepod.LabelGatewayName])
}

func (r *GatewayReconciler) endpointSliceToGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok || slice == nil {
		return nil
	}
	return r.gatewayRequestForLabel(ctx, slice.Namespace, slice.Labels[singlepod.LabelGatewayName])
}

// Reconcile performs the full reconciliation loop for a Gateway.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pollInterval := r.HealthPollInterval
	if pollInterval <= 0 {
		pollInterval = HealthPollInterval
	}
	resyncInterval := r.ResyncInterval
	if resyncInterval <= 0 {
		resyncInterval = ResyncInterval
	}

	var gw gatewayv1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		if apierrors.IsNotFound(err) {
			r.statusMu.Lock()
			delete(r.statusCache, req.NamespacedName)
			r.statusMu.Unlock()
			delete(r.waitingSince, req.NamespacedName)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// Handle deletion if DeletionTimestamp is set
	if gw.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(&gw, FinalizerCleanup) {
			if r.Registrar != nil {
				if _, err := r.Registrar.DetachAll(ctx, &gw); err != nil {
					return reconcile.Result{}, err
				}
			}
			patch := client.MergeFrom(gw.DeepCopy())
			controllerutil.RemoveFinalizer(&gw, FinalizerCleanup)
			if err := r.Patch(ctx, &gw, patch); err != nil {
				return reconcile.Result{}, err
			}
		}
		r.statusMu.Lock()
		delete(r.statusCache, req.NamespacedName)
		r.statusMu.Unlock()
		delete(r.waitingSince, req.NamespacedName)
		return reconcile.Result{}, nil
	}

	// 1. Check GatewayClass match
	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, &gc); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
	} else if r.ControllerName != "" && string(gc.Spec.ControllerName) != r.ControllerName {
		r.statusMu.Lock()
		delete(r.statusCache, req.NamespacedName)
		r.statusMu.Unlock()
		delete(r.waitingSince, req.NamespacedName)
		return reconcile.Result{}, nil
	}

	// Ensure finalizer is present on active Gateways of this class
	if !controllerutil.ContainsFinalizer(&gw, FinalizerCleanup) {
		patch := client.MergeFrom(gw.DeepCopy())
		controllerutil.AddFinalizer(&gw, FinalizerCleanup)
		if err := r.Patch(ctx, &gw, patch); err != nil {
			return reconcile.Result{}, err
		}
	}

	// 2. Resolve NEG conflicts deterministically across Gateways targeting identical NEGs
	targetNEG, err := r.targetNEGKey(ctx, &gw)
	if err != nil {
		return reconcile.Result{}, err
	}
	var allGateways gatewayv1.GatewayList
	if err := r.List(ctx, &allGateways); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing gateways: %w", err)
	}

	var conflicting []*gatewayv1.Gateway
	for i := range allGateways.Items {
		candidate := &allGateways.Items[i]
		if candidate.DeletionTimestamp != nil {
			continue
		}
		if candidate.Spec.GatewayClassName == gw.Spec.GatewayClassName {
			candKey, err := r.targetNEGKey(ctx, candidate)
			if err != nil {
				return reconcile.Result{}, err
			}
			if candKey == targetNEG {
				conflicting = append(conflicting, candidate)
			}
		}
	}

	if len(conflicting) > 1 {
		winner := registrar.ResolveNEGConflict(conflicting)
		if winner != nil && (winner.Namespace != gw.Namespace || winner.Name != gw.Name) {
			r.updateCachedStatus(req.NamespacedName, &GatewayStatusResult{
				AcceptedStatus:   metav1.ConditionFalse,
				ProgrammedStatus: metav1.ConditionFalse,
				Reason:           ReasonConflictingParameters,
				Message:          "Configured NEGs are already claimed by an older active Gateway in the cluster.",
			})
			return reconcile.Result{RequeueAfter: resyncInterval}, nil
		}
	}

	// 3. Resolve external static IP
	externalIP, err := r.resolveExternalIP(ctx, &gw)
	if err != nil {
		return reconcile.Result{}, err
	}

	// 4. Reconcile endpoints with zonal NEGs via the registrar
	reconcileRes, err := r.Registrar.ReconcileEndpoints(ctx, &gw)
	if err != nil {
		reason, msg := r.gcpErrorReasonAndMessage(err)
		r.updateCachedStatus(req.NamespacedName, &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionFalse,
			Reason:           reason,
			Message:          msg,
		})
		return reconcile.Result{}, err
	}

	if externalIP == "" {
		r.updateCachedStatus(req.NamespacedName, &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionFalse,
			Reason:           ReasonAddressNotAssigned,
			Message:          "Neither spec.addresses nor parameters ConfigMap provides external static IP.",
		})
		return reconcile.Result{RequeueAfter: resyncInterval}, nil
	}

	// 5. Poll health status from Google Cloud Load Balancer and update readiness gates
	var podList corev1.PodList
	if err := r.List(ctx, &podList, client.InNamespace(gw.Namespace), client.MatchingLabels{
		singlepod.LabelAppName:     singlepod.AppNameValue,
		singlepod.LabelGatewayName: singlepod.LabelValueForGateway(gw.Name),
	}); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing pods: %w", err)
	}

	hasHealthyReplica := false
	isRolloutStalled := false
	dataplanePodCount := 0
	waitingForHealth := false
	now := time.Now()
	activePodKeys := make(map[string]bool)
	gwWaiting := r.waitingSince[req.NamespacedName]

	for i := range podList.Items {
		pod := &podList.Items[i]
		dataplanePodCount++

		if pod.Status.PodIP == "" || pod.Spec.NodeName == "" || !registrar.IsContainersReady(pod) || pod.DeletionTimestamp != nil {
			continue
		}

		podKey := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		activePodKeys[podKey] = true

		var node corev1.Node
		if err := r.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, &node); err != nil {
			if !apierrors.IsNotFound(err) {
				return reconcile.Result{}, fmt.Errorf("getting node %s: %w", pod.Spec.NodeName, err)
			}
			continue
		}
		nodeInfo, err := registrar.ResolveNodeInstance(&node)
		if err != nil {
			klog.Warningf("Failed to resolve node instance for pod %s/%s: %v", pod.Namespace, pod.Name, err)
			continue
		}

		// Check health on backend service
		bsName := metadata.ResourceName(r.NegPrefix, r.ClusterID, gw.Namespace, gw.Name, "bs-443")
		negName := metadata.ResourceName(r.NegPrefix, r.ClusterID, gw.Namespace, gw.Name, "8443")
		// backendServices.getHealth takes a resourceGroup reference, which must be the full NEG URL;
		// a bare name is rejected with "Invalid value for field 'resourceGroup.group' ... malformed".
		negURL := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/networkEndpointGroups/%s", r.Project, nodeInfo.Zone, negName)

		health, err := r.GCPClient.GetBackendServiceHealth(ctx, r.Project, bsName, negURL)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("getting backend service health for %s: %w", bsName, err)
		}
		isHealthy := false
		if health != nil {
			for _, hs := range health.HealthStatus {
				if (hs.Instance == nodeInfo.Instance || strings.HasSuffix(hs.Instance, "/"+nodeInfo.Instance)) && hs.IpAddress == pod.Status.PodIP && hs.HealthState == "HEALTHY" {
					isHealthy = true
					break
				}
			}
		}

		if isHealthy {
			if gwWaiting != nil {
				delete(gwWaiting, podKey)
			}
			hasHealthyReplica = true
			if err := r.updatePodReadinessGate(ctx, pod, corev1.ConditionTrue, "LoadBalancerHealthy", "Endpoint is healthy on Google Cloud load balancer"); err != nil {
				return reconcile.Result{}, fmt.Errorf("updating readiness gate for pod %s: %w", podKey, err)
			}
		} else {
			if gwWaiting == nil {
				gwWaiting = make(map[string]time.Time)
				r.waitingSince[req.NamespacedName] = gwWaiting
			}
			since, exists := gwWaiting[podKey]
			if !exists {
				gwWaiting[podKey] = now
			} else if now.Sub(since) >= r.HealthTimeout {
				isRolloutStalled = true
			}
		}

		if !isPodReadinessGateTrue(pod) {
			waitingForHealth = true
		}
	}

	if gwWaiting != nil {
		for k := range gwWaiting {
			if !activePodKeys[k] {
				delete(gwWaiting, k)
			}
		}
		if len(gwWaiting) == 0 {
			delete(r.waitingSince, req.NamespacedName)
		}
	}

	// 6. Cache Gateway status conditions and addresses
	var res *GatewayStatusResult
	if dataplanePodCount == 0 {
		res = &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionFalse,
			Reason:           ReasonWaitingForDataPlane,
			Message:          "Data-plane Deployment has 0 available/ready replicas.",
		}
	} else if isRolloutStalled {
		res = &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionFalse,
			Reason:           ReasonRolloutStalled,
			Message:          "New data-plane pod failed to become healthy on load balancer; rollout halted to protect old pods.",
		}
	} else if !hasHealthyReplica {
		res = &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionFalse,
			Reason:           ReasonWaitingForEndpoints,
			Message:          "Ready pods exist, but attachment to zonal NEGs or health check convergence is in-flight.",
		}
	} else {
		addrType := gatewayv1.IPAddressType
		res = &GatewayStatusResult{
			ProgrammedStatus: metav1.ConditionTrue,
			Reason:           ReasonProgrammed,
			Message:          "Ready data-plane pods attached to zonal NEGs and passing health checks behind Google Cloud Load Balancer",
			Addresses: []gatewayv1.GatewayStatusAddress{
				{
					Type:  &addrType,
					Value: externalIP,
				},
			},
		}
	}

	_ = reconcileRes
	r.updateCachedStatus(req.NamespacedName, res)

	if waitingForHealth {
		return reconcile.Result{RequeueAfter: pollInterval}, nil
	}
	return reconcile.Result{RequeueAfter: resyncInterval}, nil
}

// GetCachedStatus returns the cached GatewayStatusResult for the given Gateway.
func (r *GatewayReconciler) GetCachedStatus(nn types.NamespacedName) *GatewayStatusResult {
	r.statusMu.RLock()
	defer r.statusMu.RUnlock()
	return r.statusCache[nn]
}

func (r *GatewayReconciler) updateCachedStatus(nn types.NamespacedName, newRes *GatewayStatusResult) {
	r.statusMu.Lock()
	oldRes := r.statusCache[nn]
	changed := !oldRes.equal(newRes)
	if changed {
		r.statusCache[nn] = newRes
	}
	r.statusMu.Unlock()

	if changed && r.EnqueueGateway != nil {
		r.EnqueueGateway(nn)
	}
}

// GatewayStatusHook is called by GARI's Gateway reconciler to adjust Gateway status before writing.
func (r *GatewayReconciler) GatewayStatusHook(ctx context.Context, gw *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	r.statusMu.RLock()
	cached, ok := r.statusCache[key]
	r.statusMu.RUnlock()

	// On a cache miss, leave status as GARI computed it to avoid flipping Programmed
	// to False during controller restart before gcpgateway has completed its first reconcile.
	if !ok || cached == nil {
		return nil
	}

	// The hook may downgrade Accepted to False (never upgrade it).
	if cached.AcceptedStatus == metav1.ConditionFalse {
		foundAccepted := false
		for i := range status.Conditions {
			if status.Conditions[i].Type == string(gatewayv1.GatewayConditionAccepted) {
				status.Conditions[i].Status = metav1.ConditionFalse
				status.Conditions[i].Reason = cached.Reason
				status.Conditions[i].Message = cached.Message
				status.Conditions[i].ObservedGeneration = gw.Generation
				foundAccepted = true
				break
			}
		}
		if !foundAccepted {
			status.Conditions = append(status.Conditions, metav1.Condition{
				Type:               string(gatewayv1.GatewayConditionAccepted),
				Status:             metav1.ConditionFalse,
				Reason:             cached.Reason,
				Message:            cached.Message,
				ObservedGeneration: gw.Generation,
			})
		}
	}

	found := false
	for i := range status.Conditions {
		if status.Conditions[i].Type == string(gatewayv1.GatewayConditionProgrammed) {
			status.Conditions[i].Status = cached.ProgrammedStatus
			status.Conditions[i].Reason = cached.Reason
			status.Conditions[i].Message = cached.Message
			status.Conditions[i].ObservedGeneration = gw.Generation
			found = true
			break
		}
	}
	if !found {
		status.Conditions = append(status.Conditions, metav1.Condition{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             cached.ProgrammedStatus,
			Reason:             cached.Reason,
			Message:            cached.Message,
			ObservedGeneration: gw.Generation,
		})
	}

	// Copy addresses so the cached slice is not mutated or shared directly
	if len(cached.Addresses) > 0 {
		status.Addresses = make([]gatewayv1.GatewayStatusAddress, len(cached.Addresses))
		copy(status.Addresses, cached.Addresses)
	}

	if len(cached.CustomConditions) > 0 {
		for _, cc := range cached.CustomConditions {
			foundCC := false
			for i := range status.Conditions {
				if status.Conditions[i].Type == cc.Type {
					status.Conditions[i] = cc
					foundCC = true
					break
				}
			}
			if !foundCC {
				status.Conditions = append(status.Conditions, cc)
			}
		}
	}

	return nil
}

func (r *GatewayReconciler) gcpErrorReasonAndMessage(err error) (string, string) {
	return registrar.GCPErrorReasonAndMessage(err)
}

func isPodReadinessGateTrue(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	gateType := corev1.PodConditionType(registrar.LoadBalancerReadyGate)
	for _, cond := range pod.Status.Conditions {
		if cond.Type == gateType {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (r *GatewayReconciler) targetNEGKey(ctx context.Context, gw *gatewayv1.Gateway) (string, error) {
	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		ref := gw.Spec.Infrastructure.ParametersRef
		if ref.Kind == "ConfigMap" && ref.Name != "" {
			var cm corev1.ConfigMap
			err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: string(ref.Name)}, &cm)
			if err != nil {
				if !apierrors.IsNotFound(err) {
					return "", fmt.Errorf("getting parameters ConfigMap %s: %w", ref.Name, err)
				}
			} else {
				if neg := cm.Data["negHTTPS"]; neg != "" {
					return neg, nil
				}
				if targetGW := cm.Data["gatewayName"]; targetGW != "" {
					ns := cm.Data["gatewayNamespace"]
					if ns == "" {
						ns = gw.Namespace
					}
					return metadata.ResourceName(r.NegPrefix, r.ClusterID, ns, targetGW, "8443"), nil
				}
			}
		}
	}
	return metadata.ResourceName(r.NegPrefix, r.ClusterID, gw.Namespace, gw.Name, "8443"), nil
}

func (r *GatewayReconciler) resolveExternalIP(ctx context.Context, gw *gatewayv1.Gateway) (string, error) {
	for _, addr := range gw.Spec.Addresses {
		if addr.Type == nil || *addr.Type == gatewayv1.IPAddressType {
			if strings.TrimSpace(addr.Value) != "" {
				return strings.TrimSpace(addr.Value), nil
			}
		}
	}

	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		ref := gw.Spec.Infrastructure.ParametersRef
		if ref.Kind == "ConfigMap" && ref.Name != "" {
			var cm corev1.ConfigMap
			err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: string(ref.Name)}, &cm)
			if err != nil {
				if !apierrors.IsNotFound(err) {
					return "", fmt.Errorf("getting parameters ConfigMap %s: %w", ref.Name, err)
				}
			} else {
				if ip, ok := cm.Data["externalIP"]; ok && strings.TrimSpace(ip) != "" {
					return strings.TrimSpace(ip), nil
				}
			}
		}
	}

	return "", nil
}

func (r *GatewayReconciler) updatePodReadinessGate(ctx context.Context, pod *corev1.Pod, status corev1.ConditionStatus, reason, message string) error {
	gateType := corev1.PodConditionType(registrar.LoadBalancerReadyGate)
	for i, cond := range pod.Status.Conditions {
		if cond.Type == gateType {
			if cond.Status == status {
				return nil
			}
			pod.Status.Conditions[i].Status = status
			pod.Status.Conditions[i].Reason = reason
			pod.Status.Conditions[i].Message = message
			pod.Status.Conditions[i].LastTransitionTime = metav1.Now()
			return r.Status().Update(ctx, pod)
		}
	}

	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               gateType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	return r.Status().Update(ctx, pod)
}
