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

package state

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"reflect"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// ProxyConfigUpdater defines the interface needed by State to update the proxy.
type ProxyConfigUpdater interface {
	UpdateConfig(listeners []InternalListener, routes []InternalRoute)
	UpdateCertificates(certs map[string]*tls.Certificate, defaultCert *tls.Certificate)
}

// EventSource implements source.TypedSource[reconcile.Request].
// It delivers reconcile requests directly to controller workqueues without dropping events.
// If requests arrive before a controller starts, they are buffered as pending and flushed upon Start.
type EventSource struct {
	mu      sync.Mutex
	queues  []workqueue.TypedRateLimitingInterface[reconcile.Request]
	pending map[reconcile.Request]struct{}
}

func NewEventSource() *EventSource {
	return &EventSource{
		pending: make(map[reconcile.Request]struct{}),
	}
}

// Start is called by controller-runtime when starting a controller.
func (s *EventSource) Start(ctx context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	s.mu.Lock()
	s.queues = append(s.queues, q)
	// Flush any pending requests that arrived before Start was called
	for req := range s.pending {
		q.Add(req)
	}
	s.pending = make(map[reconcile.Request]struct{})
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, existing := range s.queues {
			if existing == q {
				s.queues = append(s.queues[:i], s.queues[i+1:]...)
				break
			}
		}
	}()

	return nil
}

// Enqueue adds a reconcile.Request to all active controller workqueues,
// or buffers it if no workqueues are active yet.
func (s *EventSource) Enqueue(req reconcile.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queues) == 0 {
		s.pending[req] = struct{}{}
		return
	}
	for _, q := range s.queues {
		q.Add(req)
	}
}

var _ source.TypedSource[reconcile.Request] = (*EventSource)(nil)

type State struct {
	mu sync.RWMutex

	recomputeMu sync.Mutex

	revision   uint64
	recomputes uint64

	gatewayClasses     map[types.NamespacedName]*gatewayv1.GatewayClass
	gateways           map[types.NamespacedName]*GatewayState
	gatewayAddresses   map[types.NamespacedName][]gatewayv1.GatewayStatusAddress
	gatewayReadiness   map[types.NamespacedName]bool
	provisioningErrors map[types.NamespacedName]string
	listenerSets       map[types.NamespacedName]*ListenerSetState
	httpRoutes         map[types.NamespacedName]*HTTPRouteState
	tlsRoutes          map[types.NamespacedName]*TLSRouteState
	grpcRoutes         map[types.NamespacedName]*GRPCRouteState
	backendTLSPolicies map[types.NamespacedName]*gatewayv1.BackendTLSPolicy
	services           map[types.NamespacedName]*corev1.Service
	configMaps         map[types.NamespacedName]*corev1.ConfigMap
	secrets            map[types.NamespacedName]*corev1.Secret
	referenceGrants    map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant
	namespaces         map[string]*corev1.Namespace

	controllerName   string
	proxy            ProxyConfigUpdater
	onGatewaysUpdate func([]*gatewayv1.Gateway)
	gatewayFilter    func(gw *gatewayv1.Gateway) bool

	dataplanePublisher DataplanePublisher
	lastWrittenConfigs map[types.NamespacedName][]byte

	previousOutputs *Outputs

	gatewaySource          *EventSource
	httpRouteSource        *EventSource
	tlsRouteSource         *EventSource
	grpcRouteSource        *EventSource
	listenerSetSource      *EventSource
	backendTLSPolicySource *EventSource
	gatewayClassSource     *EventSource

	registrations []toolscache.ResourceEventHandlerRegistration
	notifyCh      chan struct{}
	synced        bool
	running       bool
	dirty         bool
}

func NewState() *State {
	return &State{
		gatewayClasses:         make(map[types.NamespacedName]*gatewayv1.GatewayClass),
		gateways:               make(map[types.NamespacedName]*GatewayState),
		gatewayAddresses:       make(map[types.NamespacedName][]gatewayv1.GatewayStatusAddress),
		gatewayReadiness:       make(map[types.NamespacedName]bool),
		provisioningErrors:     make(map[types.NamespacedName]string),
		listenerSets:           make(map[types.NamespacedName]*ListenerSetState),
		httpRoutes:             make(map[types.NamespacedName]*HTTPRouteState),
		tlsRoutes:              make(map[types.NamespacedName]*TLSRouteState),
		grpcRoutes:             make(map[types.NamespacedName]*GRPCRouteState),
		backendTLSPolicies:     make(map[types.NamespacedName]*gatewayv1.BackendTLSPolicy),
		services:               make(map[types.NamespacedName]*corev1.Service),
		configMaps:             make(map[types.NamespacedName]*corev1.ConfigMap),
		secrets:                make(map[types.NamespacedName]*corev1.Secret),
		referenceGrants:        make(map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant),
		namespaces:             make(map[string]*corev1.Namespace),
		gatewaySource:          NewEventSource(),
		httpRouteSource:        NewEventSource(),
		tlsRouteSource:         NewEventSource(),
		grpcRouteSource:        NewEventSource(),
		listenerSetSource:      NewEventSource(),
		backendTLSPolicySource: NewEventSource(),
		gatewayClassSource:     NewEventSource(),
		lastWrittenConfigs:     make(map[types.NamespacedName][]byte),
		notifyCh:               make(chan struct{}, 1),
		synced:                 true,
		running:                false,
	}
}

func (s *State) SetControllerName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controllerName = name
}

func (s *State) SetProxy(p ProxyConfigUpdater) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxy = p
}

func (s *State) SetOnGatewaysUpdate(fn func([]*gatewayv1.Gateway)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onGatewaysUpdate = fn
}

func (s *State) SetGatewayFilter(fn func(gw *gatewayv1.Gateway) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gatewayFilter = fn
}

func (s *State) SetDataplanePublisher(p DataplanePublisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataplanePublisher = p
}

func (s *State) GetDataplaneConfig(key types.NamespacedName) *DataplaneConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.previousOutputs != nil && s.previousOutputs.DataplaneConfigs != nil {
		return s.previousOutputs.DataplaneConfigs[key]
	}
	return nil
}

func (s *State) AddRegistration(reg toolscache.ResourceEventHandlerRegistration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrations = append(s.registrations, reg)
}

func (s *State) SetSynced(synced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synced = synced
}

func (s *State) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

func (s *State) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *State) GatewaySource() *EventSource {
	return s.gatewaySource
}

func (s *State) HTTPRouteSource() *EventSource {
	return s.httpRouteSource
}

func (s *State) TLSRouteSource() *EventSource {
	return s.tlsRouteSource
}

func (s *State) GRPCRouteSource() *EventSource {
	return s.grpcRouteSource
}

func (s *State) ListenerSetSource() *EventSource {
	return s.listenerSetSource
}

func (s *State) BackendTLSPolicySource() *EventSource {
	return s.backendTLSPolicySource
}

func (s *State) GatewayClassSource() *EventSource {
	return s.gatewayClassSource
}

func (s *State) markDirtyLocked() {
	s.dirty = true
	if !s.synced || !s.running {
		return
	}
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

// Start runs the background coalescing loop and recomputes outputs when inputs change.
func (s *State) Start(ctx context.Context) error {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	// Wait for all informer event handler registrations to be fully synced.
	for _, reg := range s.registrations {
		if !toolscache.WaitForCacheSync(ctx.Done(), reg.HasSynced) {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return nil
		}
	}

	// Mark state as synced and perform the initial full recomputation.
	s.SetSynced(true)
	s.Recompute()

	const coalesceDelay = 10 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return nil
		case <-s.notifyCh:
			timer := time.NewTimer(coalesceDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				s.mu.Lock()
				s.running = false
				s.mu.Unlock()
				return nil
			case <-timer.C:
			}

			// Drain any extra notification
			select {
			case <-s.notifyCh:
			default:
			}

			s.Recompute()
		}
	}
}

// Recompute synchronously computes all outputs from recorded inputs, diffs against previous outputs,
// sends events for changed objects, and updates the proxy.
func (s *State) Recompute() *Outputs {
	s.recomputeMu.Lock()
	defer s.recomputeMu.Unlock()

	s.mu.Lock()
	if !s.synced {
		s.mu.Unlock()
		return nil
	}

	s.recomputes++
	s.dirty = false
	start := time.Now()
	inputs := s.snapshotInputsLocked()
	outputs := ComputeOutputs(inputs)
	outputs.Revision = inputs.Revision

	duration := time.Since(start)
	klog.V(2).Infof("Recomputed state outputs in %v (revision: %d, gateways: %d, httpRoutes: %d)",
		duration, outputs.Revision, len(inputs.Gateways), len(inputs.HTTPRoutes))

	s.diffAndEmitLocked(outputs)

	prev := s.previousOutputs
	proxyChanged := prev == nil ||
		!reflect.DeepEqual(outputs.ProxyListeners, prev.ProxyListeners) ||
		!reflect.DeepEqual(outputs.ProxyRoutes, prev.ProxyRoutes) ||
		!certsMapEqual(outputs.CertificatesMap, prev.CertificatesMap) ||
		!defaultCertEqual(outputs.DefaultCert, prev.DefaultCert)

	gatewaysChanged := prev == nil || !reflectGatewaysEqual(outputs.ResolvedGateways, prev.ResolvedGateways)

	p := s.proxy
	onGatewaysUpdate := s.onGatewaysUpdate
	dpPublisher := s.dataplanePublisher

	s.previousOutputs = outputs
	s.mu.Unlock()

	// Run callbacks outside the lock to prevent deadlocks and avoid blocking state mutations.
	if proxyChanged && p != nil {
		p.UpdateConfig(outputs.ProxyListeners, outputs.ProxyRoutes)
		p.UpdateCertificates(outputs.CertificatesMap, outputs.DefaultCert)
	}

	if gatewaysChanged && onGatewaysUpdate != nil {
		onGatewaysUpdate(outputs.ResolvedGateways)
	}

	if dpPublisher != nil {
		s.publishDataplaneConfigs(outputs, dpPublisher)
	}

	return outputs
}

// publishDataplaneConfigs iterates through compiled data-plane configs and pushes updates to the publisher.
// TODO(#637): Publishing is currently synchronous inside Recompute; consider making it asynchronous
// or streaming (e.g. xDS-like) if cluster size or write latency becomes an issue.
func (s *State) publishDataplaneConfigs(outputs *Outputs, publisher DataplanePublisher) {
	if outputs == nil || publisher == nil {
		return
	}

	for gwKey, dpConfig := range outputs.DataplaneConfigs {
		cg := outputs.CompiledGateways[gwKey]
		if cg == nil || cg.Gateway == nil {
			continue
		}
		if s.gatewayFilter != nil && !s.gatewayFilter(cg.Gateway) {
			continue
		}

		data, err := json.Marshal(dpConfig)
		if err != nil {
			klog.Errorf("failed to marshal dataplane config for %s: %v", gwKey, err)
			continue
		}

		if len(data) > 1024*1024 {
			klog.Errorf("dataplane config size for %s (%d bytes) exceeds 1MiB secret limit", gwKey, len(data))
		}

		s.mu.Lock()
		lastData := s.lastWrittenConfigs[gwKey]
		s.mu.Unlock()

		if bytes.Equal(data, lastData) {
			continue
		}

		if err := publisher.PublishDataplaneConfig(context.Background(), cg.Gateway, dpConfig); err != nil {
			klog.Errorf("failed to publish dataplane config for %s: %v", gwKey, err)
			continue
		}

		s.mu.Lock()
		s.lastWrittenConfigs[gwKey] = data
		s.mu.Unlock()
	}

	s.mu.Lock()
	for gwKey := range s.lastWrittenConfigs {
		if _, ok := outputs.DataplaneConfigs[gwKey]; !ok {
			delete(s.lastWrittenConfigs, gwKey)
		}
	}
	s.mu.Unlock()
}

func (s *State) snapshotInputsLocked() ModelInputs {
	var gws []*gatewayv1.Gateway
	for _, gwState := range s.gateways {
		if gwState != nil && gwState.Gateway != nil {
			gws = append(gws, gwState.Gateway)
		}
	}
	sort.Slice(gws, func(i, j int) bool {
		if gws[i].Namespace != gws[j].Namespace {
			return gws[i].Namespace < gws[j].Namespace
		}
		return gws[i].Name < gws[j].Name
	})

	var gcs []*gatewayv1.GatewayClass
	for _, gc := range s.gatewayClasses {
		if gc != nil {
			gcs = append(gcs, gc)
		}
	}
	sort.Slice(gcs, func(i, j int) bool {
		return gcs[i].Name < gcs[j].Name
	})

	gwAddrs := make(map[types.NamespacedName][]gatewayv1.GatewayStatusAddress)
	for k, v := range s.gatewayAddresses {
		copied := make([]gatewayv1.GatewayStatusAddress, len(v))
		copy(copied, v)
		gwAddrs[k] = copied
	}

	gwReady := make(map[types.NamespacedName]bool)
	for k, v := range s.gatewayReadiness {
		gwReady[k] = v
	}

	gwProvErrs := make(map[types.NamespacedName]string)
	for k, v := range s.provisioningErrors {
		gwProvErrs[k] = v
	}

	var listenerSets []*gatewayv1.ListenerSet
	for _, lsState := range s.listenerSets {
		if lsState != nil && lsState.ListenerSet != nil {
			listenerSets = append(listenerSets, lsState.ListenerSet)
		}
	}
	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(listenerSets, func(i, j int) bool {
		if !listenerSets[i].CreationTimestamp.Equal(&listenerSets[j].CreationTimestamp) {
			return listenerSets[i].CreationTimestamp.Before(&listenerSets[j].CreationTimestamp)
		}
		if listenerSets[i].Namespace != listenerSets[j].Namespace {
			return listenerSets[i].Namespace < listenerSets[j].Namespace
		}
		return listenerSets[i].Name < listenerSets[j].Name
	})

	var routes []*gatewayv1.HTTPRoute
	for _, rState := range s.httpRoutes {
		if rState != nil && rState.HTTPRoute != nil {
			routes = append(routes, rState.HTTPRoute)
		}
	}
	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(routes, func(i, j int) bool {
		if !routes[i].CreationTimestamp.Equal(&routes[j].CreationTimestamp) {
			return routes[i].CreationTimestamp.Before(&routes[j].CreationTimestamp)
		}
		if routes[i].Namespace != routes[j].Namespace {
			return routes[i].Namespace < routes[j].Namespace
		}
		return routes[i].Name < routes[j].Name
	})

	var tlsRoutes []*gatewayv1.TLSRoute
	for _, rState := range s.tlsRoutes {
		if rState != nil && rState.TLSRoute != nil {
			tlsRoutes = append(tlsRoutes, rState.TLSRoute)
		}
	}
	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(tlsRoutes, func(i, j int) bool {
		if !tlsRoutes[i].CreationTimestamp.Equal(&tlsRoutes[j].CreationTimestamp) {
			return tlsRoutes[i].CreationTimestamp.Before(&tlsRoutes[j].CreationTimestamp)
		}
		if tlsRoutes[i].Namespace != tlsRoutes[j].Namespace {
			return tlsRoutes[i].Namespace < tlsRoutes[j].Namespace
		}
		return tlsRoutes[i].Name < tlsRoutes[j].Name
	})

	var grpcRoutes []*gatewayv1.GRPCRoute
	for _, rState := range s.grpcRoutes {
		if rState != nil && rState.GRPCRoute != nil {
			grpcRoutes = append(grpcRoutes, rState.GRPCRoute)
		}
	}
	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(grpcRoutes, func(i, j int) bool {
		if !grpcRoutes[i].CreationTimestamp.Equal(&grpcRoutes[j].CreationTimestamp) {
			return grpcRoutes[i].CreationTimestamp.Before(&grpcRoutes[j].CreationTimestamp)
		}
		if grpcRoutes[i].Namespace != grpcRoutes[j].Namespace {
			return grpcRoutes[i].Namespace < grpcRoutes[j].Namespace
		}
		return grpcRoutes[i].Name < grpcRoutes[j].Name
	})

	var backendTLSPolicies []*gatewayv1.BackendTLSPolicy
	for _, b := range s.backendTLSPolicies {
		if b != nil {
			backendTLSPolicies = append(backendTLSPolicies, b)
		}
	}
	sort.Slice(backendTLSPolicies, func(i, j int) bool {
		if !backendTLSPolicies[i].CreationTimestamp.Equal(&backendTLSPolicies[j].CreationTimestamp) {
			return backendTLSPolicies[i].CreationTimestamp.Before(&backendTLSPolicies[j].CreationTimestamp)
		}
		if backendTLSPolicies[i].Namespace != backendTLSPolicies[j].Namespace {
			return backendTLSPolicies[i].Namespace < backendTLSPolicies[j].Namespace
		}
		return backendTLSPolicies[i].Name < backendTLSPolicies[j].Name
	})

	services := make(map[types.NamespacedName]*corev1.Service)
	for k, v := range s.services {
		services[k] = v
	}

	configMaps := make(map[types.NamespacedName]*corev1.ConfigMap)
	for k, v := range s.configMaps {
		configMaps[k] = v
	}

	secrets := make(map[types.NamespacedName]*corev1.Secret)
	for k, v := range s.secrets {
		secrets[k] = v
	}

	namespaces := make(map[string]*corev1.Namespace)
	for k, v := range s.namespaces {
		namespaces[k] = v
	}

	referenceGrants := make(map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant)
	for k, v := range s.referenceGrants {
		referenceGrants[k] = v
	}

	return ModelInputs{
		Revision:           s.revision,
		Gateways:           gws,
		GatewayClasses:     gcs,
		GatewayAddresses:   gwAddrs,
		GatewayReadiness:   gwReady,
		ProvisioningErrors: gwProvErrs,
		ListenerSets:       listenerSets,
		HTTPRoutes:         routes,
		TLSRoutes:          tlsRoutes,
		GRPCRoutes:         grpcRoutes,
		Services:           services,
		BackendTLSPolicies: backendTLSPolicies,
		ConfigMaps:         configMaps,
		Secrets:            secrets,
		Namespaces:         namespaces,
		ReferenceGrants:    referenceGrants,
		RefValidator:       mapReferenceValidator{referenceGrants: referenceGrants},
		ControllerName:     s.controllerName,
	}
}

func (s *State) diffAndEmitLocked(outputs *Outputs) {
	prev := s.previousOutputs

	// 1. Gateway diff
	var prevGWStatuses map[types.NamespacedName]gatewayv1.GatewayStatus
	if prev != nil {
		prevGWStatuses = prev.GatewayStatuses
	}
	allGWKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.GatewayStatuses {
		allGWKeys[k] = true
	}
	if prevGWStatuses != nil {
		for k := range prevGWStatuses {
			allGWKeys[k] = true
		}
	}
	for k := range allGWKeys {
		cur, curOk := outputs.GatewayStatuses[k]
		old, oldOk := prevGWStatuses[k]
		if curOk != oldOk || (curOk && !GatewayStatusesEqual(cur, old)) {
			s.gatewaySource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 2. HTTPRoute diff
	var prevRouteStatuses map[types.NamespacedName]gatewayv1.HTTPRouteStatus
	if prev != nil {
		prevRouteStatuses = prev.HTTPRouteStatuses
	}
	allRouteKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.HTTPRouteStatuses {
		allRouteKeys[k] = true
	}
	if prevRouteStatuses != nil {
		for k := range prevRouteStatuses {
			allRouteKeys[k] = true
		}
	}
	for k := range allRouteKeys {
		cur, curOk := outputs.HTTPRouteStatuses[k]
		old, oldOk := prevRouteStatuses[k]
		if curOk != oldOk || (curOk && !HTTPRouteStatusesEqual(cur, old)) {
			s.httpRouteSource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 2b. TLSRoute diff
	var prevTLSRouteStatuses map[types.NamespacedName]gatewayv1.TLSRouteStatus
	if prev != nil {
		prevTLSRouteStatuses = prev.TLSRouteStatuses
	}
	allTLSRouteKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.TLSRouteStatuses {
		allTLSRouteKeys[k] = true
	}
	if prevTLSRouteStatuses != nil {
		for k := range prevTLSRouteStatuses {
			allTLSRouteKeys[k] = true
		}
	}
	for k := range allTLSRouteKeys {
		cur, curOk := outputs.TLSRouteStatuses[k]
		old, oldOk := prevTLSRouteStatuses[k]
		if curOk != oldOk || (curOk && !TLSRouteStatusesEqual(cur, old)) {
			s.tlsRouteSource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 2c. GRPCRoute diff
	var prevGRPCRouteStatuses map[types.NamespacedName]gatewayv1.GRPCRouteStatus
	if prev != nil {
		prevGRPCRouteStatuses = prev.GRPCRouteStatuses
	}
	allGRPCRouteKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.GRPCRouteStatuses {
		allGRPCRouteKeys[k] = true
	}
	if prevGRPCRouteStatuses != nil {
		for k := range prevGRPCRouteStatuses {
			allGRPCRouteKeys[k] = true
		}
	}
	for k := range allGRPCRouteKeys {
		cur, curOk := outputs.GRPCRouteStatuses[k]
		old, oldOk := prevGRPCRouteStatuses[k]
		if curOk != oldOk || (curOk && !GRPCRouteStatusesEqual(cur, old)) {
			s.grpcRouteSource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 3. ListenerSet diff
	var prevLSStatuses map[types.NamespacedName]gatewayv1.ListenerSetStatus
	if prev != nil {
		prevLSStatuses = prev.ListenerSetStatuses
	}
	allLSKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.ListenerSetStatuses {
		allLSKeys[k] = true
	}
	if prevLSStatuses != nil {
		for k := range prevLSStatuses {
			allLSKeys[k] = true
		}
	}
	for k := range allLSKeys {
		cur, curOk := outputs.ListenerSetStatuses[k]
		old, oldOk := prevLSStatuses[k]
		if curOk != oldOk || (curOk && !ListenerSetStatusesEqual(cur, old)) {
			s.listenerSetSource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 4. BackendTLSPolicy diff
	var prevPolicyStatuses map[types.NamespacedName]gatewayv1.PolicyStatus
	if prev != nil {
		prevPolicyStatuses = prev.BackendTLSPolicyStatuses
	}
	allPolicyKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.BackendTLSPolicyStatuses {
		allPolicyKeys[k] = true
	}
	if prevPolicyStatuses != nil {
		for k := range prevPolicyStatuses {
			allPolicyKeys[k] = true
		}
	}
	for k := range allPolicyKeys {
		cur, curOk := outputs.BackendTLSPolicyStatuses[k]
		old, oldOk := prevPolicyStatuses[k]
		if curOk != oldOk || (curOk && !PolicyStatusesEqual(cur, old)) {
			s.backendTLSPolicySource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}

	// 5. GatewayClass diff
	var prevGCStatuses map[types.NamespacedName]gatewayv1.GatewayClassStatus
	if prev != nil {
		prevGCStatuses = prev.GatewayClassStatuses
	}
	allGCKeys := make(map[types.NamespacedName]bool)
	for k := range outputs.GatewayClassStatuses {
		allGCKeys[k] = true
	}
	if prevGCStatuses != nil {
		for k := range prevGCStatuses {
			allGCKeys[k] = true
		}
	}
	for k := range allGCKeys {
		cur, curOk := outputs.GatewayClassStatuses[k]
		old, oldOk := prevGCStatuses[k]
		if curOk != oldOk || (curOk && !GatewayClassStatusesEqual(cur, old)) {
			s.gatewayClassSource.Enqueue(ctrl.Request{NamespacedName: k})
		}
	}
}

func certsMapEqual(a, b map[string]*tls.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for k, vA := range a {
		vB, ok := b[k]
		if !ok || !defaultCertEqual(vA, vB) {
			return false
		}
	}
	return true
}

func defaultCertEqual(a, b *tls.Certificate) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	if len(a.Certificate) != len(b.Certificate) {
		return false
	}
	for i := range a.Certificate {
		if !reflect.DeepEqual(a.Certificate[i], b.Certificate[i]) {
			return false
		}
	}
	return true
}

func reflectGatewaysEqual(a, b []*gatewayv1.Gateway) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Namespace != b[i].Namespace || a[i].Name != b[i].Name || a[i].Generation != b[i].Generation {
			return false
		}
	}
	return true
}

func (s *State) GetDesiredGatewayStatus(key types.NamespacedName) (gatewayv1.GatewayStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.GatewayStatus{}, false
	}
	st, ok := s.previousOutputs.GatewayStatuses[key]
	return st, ok
}

func (s *State) GetDesiredHTTPRouteStatus(key types.NamespacedName) (gatewayv1.HTTPRouteStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.HTTPRouteStatus{}, false
	}
	st, ok := s.previousOutputs.HTTPRouteStatuses[key]
	return st, ok
}

func (s *State) GetDesiredTLSRouteStatus(key types.NamespacedName) (gatewayv1.TLSRouteStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.TLSRouteStatus{}, false
	}
	st, ok := s.previousOutputs.TLSRouteStatuses[key]
	return st, ok
}

func (s *State) GetDesiredGRPCRouteStatus(key types.NamespacedName) (gatewayv1.GRPCRouteStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.GRPCRouteStatus{}, false
	}
	st, ok := s.previousOutputs.GRPCRouteStatuses[key]
	return st, ok
}

func (s *State) GetDesiredListenerSetStatus(key types.NamespacedName) (gatewayv1.ListenerSetStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.ListenerSetStatus{}, false
	}
	st, ok := s.previousOutputs.ListenerSetStatuses[key]
	return st, ok
}

func (s *State) GetDesiredBackendTLSPolicyStatus(key types.NamespacedName) (gatewayv1.PolicyStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.PolicyStatus{}, false
	}
	st, ok := s.previousOutputs.BackendTLSPolicyStatuses[key]
	return st, ok
}

func (s *State) GetDesiredGatewayClassStatus(key types.NamespacedName) (gatewayv1.GatewayClassStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.previousOutputs == nil {
		return gatewayv1.GatewayClassStatus{}, false
	}
	st, ok := s.previousOutputs.GatewayClassStatuses[key]
	return st, ok
}

// Input mutation methods

func (s *State) UpsertGatewayClass(gc *gatewayv1.GatewayClass) {
	if gc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Name: gc.Name}
	old := s.gatewayClasses[key]
	if old != nil && reflect.DeepEqual(old.Spec, gc.Spec) && reflect.DeepEqual(old.Labels, gc.Labels) && old.Generation == gc.Generation {
		return
	}

	s.gatewayClasses[key] = gc.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteGatewayClass(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Name: name.Name}
	if _, ok := s.gatewayClasses[key]; ok {
		delete(s.gatewayClasses, key)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetGatewayClass(name string) (*gatewayv1.GatewayClass, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gc, ok := s.gatewayClasses[types.NamespacedName{Name: name}]
	return gc, ok
}

func (s *State) GetGatewayClasses() map[types.NamespacedName]*gatewayv1.GatewayClass {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gcs := make(map[types.NamespacedName]*gatewayv1.GatewayClass)
	for k, v := range s.gatewayClasses {
		gcs[k] = v
	}
	return gcs
}

func (s *State) UpsertGateway(gw *gatewayv1.Gateway) {
	if gw == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}

	if s.gatewayFilter != nil && !s.gatewayFilter(gw) {
		if _, ok := s.gateways[key]; ok {
			delete(s.gateways, key)
			delete(s.gatewayAddresses, key)
			delete(s.gatewayReadiness, key)
			delete(s.provisioningErrors, key)
			s.revision++
			s.markDirtyLocked()
		}
		return
	}

	old := s.gateways[key]
	if old != nil && old.Gateway != nil && reflect.DeepEqual(old.Spec, gw.Spec) && reflect.DeepEqual(old.Labels, gw.Labels) && old.Generation == gw.Generation {
		return
	}

	s.gateways[key] = &GatewayState{
		Gateway: gw.DeepCopy(),
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteGateway(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.gateways[name]; ok {
		delete(s.gateways, name)
		delete(s.gatewayAddresses, name)
		delete(s.gatewayReadiness, name)
		delete(s.provisioningErrors, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) SetGatewayAddresses(key types.NamespacedName, addrs []gatewayv1.GatewayStatusAddress) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if reflectAddressesEqual(s.gatewayAddresses[key], addrs) {
		return
	}

	if len(addrs) == 0 {
		delete(s.gatewayAddresses, key)
	} else {
		copied := make([]gatewayv1.GatewayStatusAddress, len(addrs))
		copy(copied, addrs)
		s.gatewayAddresses[key] = copied
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteGatewayAddresses(key types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.gatewayAddresses[key]; ok {
		delete(s.gatewayAddresses, key)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetGatewayAddresses() map[types.NamespacedName][]gatewayv1.GatewayStatusAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	gwAddrs := make(map[types.NamespacedName][]gatewayv1.GatewayStatusAddress)
	for k, v := range s.gatewayAddresses {
		copied := make([]gatewayv1.GatewayStatusAddress, len(v))
		copy(copied, v)
		gwAddrs[k] = copied
	}
	return gwAddrs
}

func (s *State) SetGatewayReadiness(key types.NamespacedName, ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cur, ok := s.gatewayReadiness[key]; ok && cur == ready {
		return
	}

	s.gatewayReadiness[key] = ready
	s.revision++
	s.markDirtyLocked()
}

func (s *State) SetGatewayProvisioningError(key types.NamespacedName, provErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cur, ok := s.provisioningErrors[key]; ok && cur == provErr {
		return
	}

	if provErr == "" {
		delete(s.provisioningErrors, key)
	} else {
		s.provisioningErrors[key] = provErr
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) GetEffectiveListeners(key types.NamespacedName) []*EffectiveListener {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.previousOutputs == nil || s.previousOutputs.CompiledGateways == nil {
		return nil
	}
	cg := s.previousOutputs.CompiledGateways[key]
	if cg == nil {
		return nil
	}
	return cg.EffectiveListeners
}

func (s *State) UpsertNamespace(ns *corev1.Namespace) {
	if ns == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.namespaces[ns.Name]
	if old != nil && reflect.DeepEqual(old.Labels, ns.Labels) {
		return
	}

	s.namespaces[ns.Name] = ns.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteNamespace(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.namespaces[name]; ok {
		delete(s.namespaces, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetNamespaces() map[string]*corev1.Namespace {
	s.mu.RLock()
	defer s.mu.RUnlock()

	namespaces := make(map[string]*corev1.Namespace)
	for k, v := range s.namespaces {
		namespaces[k] = v
	}
	return namespaces
}

func (s *State) UpsertReferenceGrant(rg *gatewayv1beta1.ReferenceGrant) {
	if rg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: rg.Namespace, Name: rg.Name}
	old := s.referenceGrants[key]
	if old != nil && reflect.DeepEqual(old.Spec, rg.Spec) && reflect.DeepEqual(old.Labels, rg.Labels) && old.Generation == rg.Generation {
		return
	}

	s.referenceGrants[key] = rg.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteReferenceGrant(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.referenceGrants[name]; ok {
		delete(s.referenceGrants, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) UpsertSecret(secret *corev1.Secret) {
	if secret == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
	old := s.secrets[key]
	if old != nil && reflect.DeepEqual(old.Data, secret.Data) && reflect.DeepEqual(old.Labels, secret.Labels) {
		return
	}

	s.secrets[key] = secret.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteSecret(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.secrets[name]; ok {
		delete(s.secrets, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetSecrets() map[types.NamespacedName]*corev1.Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets := make(map[types.NamespacedName]*corev1.Secret)
	for k, v := range s.secrets {
		secrets[k] = v
	}
	return secrets
}

func (s *State) UpsertConfigMap(cm *corev1.ConfigMap) {
	if cm == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: cm.Namespace, Name: cm.Name}
	old := s.configMaps[key]
	if old != nil && reflect.DeepEqual(old.Data, cm.Data) && reflect.DeepEqual(old.BinaryData, cm.BinaryData) && reflect.DeepEqual(old.Labels, cm.Labels) {
		return
	}

	s.configMaps[key] = cm.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteConfigMap(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.configMaps[name]; ok {
		delete(s.configMaps, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetConfigMaps() map[types.NamespacedName]*corev1.ConfigMap {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cms := make(map[types.NamespacedName]*corev1.ConfigMap)
	for k, v := range s.configMaps {
		cms[k] = v
	}
	return cms
}

func (s *State) UpsertService(svc *corev1.Service) {
	if svc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
	old := s.services[key]
	if old != nil && reflect.DeepEqual(old.Spec.Ports, svc.Spec.Ports) && old.Spec.ClusterIP == svc.Spec.ClusterIP && reflect.DeepEqual(old.Labels, svc.Labels) && reflect.DeepEqual(old.Annotations, svc.Annotations) {
		return
	}

	s.services[key] = svc.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteService(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.services[name]; ok {
		delete(s.services, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetService(name types.NamespacedName) *corev1.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.services[name]
}

func (s *State) UpsertHTTPRoute(route *gatewayv1.HTTPRoute) {
	if route == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	old := s.httpRoutes[key]
	if old != nil && old.HTTPRoute != nil && reflect.DeepEqual(old.Spec, route.Spec) && reflect.DeepEqual(old.Labels, route.Labels) && old.Generation == route.Generation {
		return
	}

	s.httpRoutes[key] = &HTTPRouteState{
		HTTPRoute: route.DeepCopy(),
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) GetHTTPRoute(name types.NamespacedName) *HTTPRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.httpRoutes[name]
}

func (s *State) DeleteHTTPRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.httpRoutes[name]; ok {
		delete(s.httpRoutes, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) UpsertTLSRoute(route *gatewayv1.TLSRoute) {
	if route == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	old := s.tlsRoutes[key]
	if old != nil && old.TLSRoute != nil && reflect.DeepEqual(old.Spec, route.Spec) && reflect.DeepEqual(old.Labels, route.Labels) && old.Generation == route.Generation {
		return
	}

	s.tlsRoutes[key] = &TLSRouteState{
		TLSRoute: route.DeepCopy(),
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) GetTLSRoute(name types.NamespacedName) *TLSRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.tlsRoutes[name]
}

func (s *State) DeleteTLSRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tlsRoutes[name]; ok {
		delete(s.tlsRoutes, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) UpsertGRPCRoute(route *gatewayv1.GRPCRoute) {
	if route == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	old := s.grpcRoutes[key]
	if old != nil && old.GRPCRoute != nil && reflect.DeepEqual(old.Spec, route.Spec) && reflect.DeepEqual(old.Labels, route.Labels) && old.Generation == route.Generation {
		return
	}

	s.grpcRoutes[key] = &GRPCRouteState{
		GRPCRoute: route.DeepCopy(),
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) GetGRPCRoute(name types.NamespacedName) *GRPCRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.grpcRoutes[name]
}

func (s *State) DeleteGRPCRoute(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.grpcRoutes[name]; ok {
		delete(s.grpcRoutes, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) UpsertBackendTLSPolicy(policy *gatewayv1.BackendTLSPolicy) {
	if policy == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
	old := s.backendTLSPolicies[key]
	if old != nil && reflect.DeepEqual(old.Spec, policy.Spec) && reflect.DeepEqual(old.Labels, policy.Labels) && old.Generation == policy.Generation {
		return
	}

	s.backendTLSPolicies[key] = policy.DeepCopy()
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteBackendTLSPolicy(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.backendTLSPolicies[name]; ok {
		delete(s.backendTLSPolicies, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetGateways() []*GatewayState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var gateways []*GatewayState
	for _, gw := range s.gateways {
		gateways = append(gateways, gw)
	}
	return gateways
}

func (s *State) GetHTTPRoutes() []*HTTPRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var routes []*HTTPRouteState
	for _, route := range s.httpRoutes {
		routes = append(routes, route)
	}

	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(routes, func(i, j int) bool {
		if !routes[i].CreationTimestamp.Equal(&routes[j].CreationTimestamp) {
			return routes[i].CreationTimestamp.Before(&routes[j].CreationTimestamp)
		}
		if routes[i].Namespace != routes[j].Namespace {
			return routes[i].Namespace < routes[j].Namespace
		}
		return routes[i].Name < routes[j].Name
	})

	return routes
}

func (s *State) GetTLSRoutes() []*TLSRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var routes []*TLSRouteState
	for _, route := range s.tlsRoutes {
		routes = append(routes, route)
	}

	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(routes, func(i, j int) bool {
		if !routes[i].CreationTimestamp.Equal(&routes[j].CreationTimestamp) {
			return routes[i].CreationTimestamp.Before(&routes[j].CreationTimestamp)
		}
		if routes[i].Namespace != routes[j].Namespace {
			return routes[i].Namespace < routes[j].Namespace
		}
		return routes[i].Name < routes[j].Name
	})

	return routes
}

func (s *State) GetGRPCRoutes() []*GRPCRouteState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var routes []*GRPCRouteState
	for _, route := range s.grpcRoutes {
		routes = append(routes, route)
	}

	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(routes, func(i, j int) bool {
		if !routes[i].CreationTimestamp.Equal(&routes[j].CreationTimestamp) {
			return routes[i].CreationTimestamp.Before(&routes[j].CreationTimestamp)
		}
		if routes[i].Namespace != routes[j].Namespace {
			return routes[i].Namespace < routes[j].Namespace
		}
		return routes[i].Name < routes[j].Name
	})

	return routes
}

func (s *State) GetBackendTLSPolicies() []*gatewayv1.BackendTLSPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var policies []*gatewayv1.BackendTLSPolicy
	for _, policy := range s.backendTLSPolicies {
		policies = append(policies, policy)
	}
	return policies
}

func (s *State) UpsertListenerSet(ls *gatewayv1.ListenerSet) {
	if ls == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := types.NamespacedName{Namespace: ls.Namespace, Name: ls.Name}
	old := s.listenerSets[key]
	if old != nil && old.ListenerSet != nil && reflect.DeepEqual(old.Spec, ls.Spec) && reflect.DeepEqual(old.Labels, ls.Labels) && old.Generation == ls.Generation {
		return
	}

	s.listenerSets[key] = &ListenerSetState{
		ListenerSet: ls.DeepCopy(),
	}
	s.revision++
	s.markDirtyLocked()
}

func (s *State) DeleteListenerSet(name types.NamespacedName) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.listenerSets[name]; ok {
		delete(s.listenerSets, name)
		s.revision++
		s.markDirtyLocked()
	}
}

func (s *State) GetListenerSet(name types.NamespacedName) *ListenerSetState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.listenerSets[name]
}

func (s *State) GetListenerSets() []*ListenerSetState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sets []*ListenerSetState
	for _, ls := range s.listenerSets {
		sets = append(sets, ls)
	}

	// Precedence order:
	// 1. Creation time (oldest first)
	// 2. Alphabetically by "{namespace}/{name}"
	sort.Slice(sets, func(i, j int) bool {
		if !sets[i].CreationTimestamp.Equal(&sets[j].CreationTimestamp) {
			return sets[i].CreationTimestamp.Before(&sets[j].CreationTimestamp)
		}
		if sets[i].Namespace != sets[j].Namespace {
			return sets[i].Namespace < sets[j].Namespace
		}
		return sets[i].Name < sets[j].Name
	})

	return sets
}

func (s *State) GetServices() map[types.NamespacedName]*corev1.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make(map[types.NamespacedName]*corev1.Service)
	for k, v := range s.services {
		services[k] = v
	}
	return services
}
