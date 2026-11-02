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
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

// CRD names for Gateway API resources.
const (
	GatewayClassCRDName     = "gatewayclasses.gateway.networking.k8s.io"
	GatewayCRDName          = "gateways.gateway.networking.k8s.io"
	HTTPRouteCRDName        = "httproutes.gateway.networking.k8s.io"
	TLSRouteCRDName         = "tlsroutes.gateway.networking.k8s.io"
	GRPCRouteCRDName        = "grpcroutes.gateway.networking.k8s.io"
	TCPRouteCRDName         = "tcproutes.gateway.networking.k8s.io"
	UDPRouteCRDName         = "udproutes.gateway.networking.k8s.io"
	BackendTLSPolicyCRDName = "backendtlspolicies.gateway.networking.k8s.io"
	ListenerSetCRDName      = "listenersets.gateway.networking.k8s.io"
	ReferenceGrantCRDName   = "referencegrants.gateway.networking.k8s.io"
)

// GatewayAPICRDNames contains all CustomResourceDefinition names for Gateway API resources.
var GatewayAPICRDNames = []string{
	GatewayClassCRDName,
	GatewayCRDName,
	HTTPRouteCRDName,
	TLSRouteCRDName,
	GRPCRouteCRDName,
	TCPRouteCRDName,
	UDPRouteCRDName,
	BackendTLSPolicyCRDName,
	ListenerSetCRDName,
	ReferenceGrantCRDName,
}

// CustomResourceDefinitionGVK is the GroupVersionKind for CustomResourceDefinitions.
var CustomResourceDefinitionGVK = schema.GroupVersionKind{
	Group:   "apiextensions.k8s.io",
	Version: "v1",
	Kind:    "CustomResourceDefinition",
}

// ServedKinds represents the set of Gateway API kinds served at the version GARI uses.
// It is a comparable struct of booleans.
type ServedKinds struct {
	GatewayClass     bool
	Gateway          bool
	HTTPRoute        bool
	TLSRoute         bool
	GRPCRoute        bool
	TCPRoute         bool
	UDPRoute         bool
	BackendTLSPolicy bool
	ListenerSet      bool
	ReferenceGrant   bool
}

type kindDefinition struct {
	gk        schema.GroupKind
	crdName   string
	required  bool
	prototype client.Object
	get       func(s *ServedKinds) bool
	set       func(s *ServedKinds, v bool)
}

var knownKinds = []kindDefinition{
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "GatewayClass"},
		crdName:   GatewayClassCRDName,
		required:  true,
		prototype: &gatewayv1.GatewayClass{},
		get:       func(s *ServedKinds) bool { return s.GatewayClass },
		set:       func(s *ServedKinds, v bool) { s.GatewayClass = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "Gateway"},
		crdName:   GatewayCRDName,
		required:  true,
		prototype: &gatewayv1.Gateway{},
		get:       func(s *ServedKinds) bool { return s.Gateway },
		set:       func(s *ServedKinds, v bool) { s.Gateway = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "HTTPRoute"},
		crdName:   HTTPRouteCRDName,
		required:  true,
		prototype: &gatewayv1.HTTPRoute{},
		get:       func(s *ServedKinds) bool { return s.HTTPRoute },
		set:       func(s *ServedKinds, v bool) { s.HTTPRoute = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "TLSRoute"},
		crdName:   TLSRouteCRDName,
		required:  false,
		prototype: &gatewayv1.TLSRoute{},
		get:       func(s *ServedKinds) bool { return s.TLSRoute },
		set:       func(s *ServedKinds, v bool) { s.TLSRoute = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "GRPCRoute"},
		crdName:   GRPCRouteCRDName,
		required:  false,
		prototype: &gatewayv1.GRPCRoute{},
		get:       func(s *ServedKinds) bool { return s.GRPCRoute },
		set:       func(s *ServedKinds, v bool) { s.GRPCRoute = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "TCPRoute"},
		crdName:   TCPRouteCRDName,
		required:  false,
		prototype: &gatewayv1.TCPRoute{},
		get:       func(s *ServedKinds) bool { return s.TCPRoute },
		set:       func(s *ServedKinds, v bool) { s.TCPRoute = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "UDPRoute"},
		crdName:   UDPRouteCRDName,
		required:  false,
		prototype: &gatewayv1.UDPRoute{},
		get:       func(s *ServedKinds) bool { return s.UDPRoute },
		set:       func(s *ServedKinds, v bool) { s.UDPRoute = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "BackendTLSPolicy"},
		crdName:   BackendTLSPolicyCRDName,
		required:  false,
		prototype: &gatewayv1.BackendTLSPolicy{},
		get:       func(s *ServedKinds) bool { return s.BackendTLSPolicy },
		set:       func(s *ServedKinds, v bool) { s.BackendTLSPolicy = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1.GroupName, Kind: "ListenerSet"},
		crdName:   ListenerSetCRDName,
		required:  false,
		prototype: &gatewayv1.ListenerSet{},
		get:       func(s *ServedKinds) bool { return s.ListenerSet },
		set:       func(s *ServedKinds, v bool) { s.ListenerSet = v },
	},
	{
		gk:        schema.GroupKind{Group: gatewayv1beta1.GroupName, Kind: "ReferenceGrant"},
		crdName:   ReferenceGrantCRDName,
		required:  false,
		prototype: &gatewayv1beta1.ReferenceGrant{},
		get:       func(s *ServedKinds) bool { return s.ReferenceGrant },
		set:       func(s *ServedKinds, v bool) { s.ReferenceGrant = v },
	},
}

var crdNameToKind = func() map[string]kindDefinition {
	m := make(map[string]kindDefinition, len(knownKinds))
	for _, k := range knownKinds {
		m[k.crdName] = k
	}
	return m
}()

// CRDSnapshot represents an immutable snapshot of Gateway API CRD presence and bundle version.
// It is a comparable value so snapshots can be compared directly using ==.
type CRDSnapshot struct {
	ServedKinds   ServedKinds
	BundleVersion string // empty string if not present
}

// IsKindServed reports whether the given GroupKind is served.
func (s CRDSnapshot) IsKindServed(gk schema.GroupKind) bool {
	for i := range knownKinds {
		if knownKinds[i].gk == gk {
			return knownKinds[i].get(&s.ServedKinds)
		}
	}
	return false
}

// DisabledKinds returns the sorted names of optional Gateway API kinds that are not served.
func (s CRDSnapshot) DisabledKinds() []string {
	var disabled []string
	for i := range knownKinds {
		if !knownKinds[i].required && !knownKinds[i].get(&s.ServedKinds) {
			disabled = append(disabled, knownKinds[i].gk.Kind)
		}
	}
	sort.Strings(disabled)
	return disabled
}

// ServedGroupKinds returns a map of GroupKinds to whether they are served.
func (s CRDSnapshot) ServedGroupKinds() map[schema.GroupKind]bool {
	m := make(map[schema.GroupKind]bool, len(knownKinds))
	for i := range knownKinds {
		if knownKinds[i].get(&s.ServedKinds) {
			m[knownKinds[i].gk] = true
		}
	}
	return m
}

// ValidateRequired verifies that all required Gateway API CRDs (GatewayClass, Gateway, HTTPRoute) are served.
func (s CRDSnapshot) ValidateRequired() error {
	for i := range knownKinds {
		if knownKinds[i].required && !knownKinds[i].get(&s.ServedKinds) {
			return fmt.Errorf("required Gateway API CRD %s (%s) is not installed", knownKinds[i].gk.Kind, knownKinds[i].gk.String())
		}
	}
	return nil
}

// CRDViewReader provides access to the current CRDSnapshot.
type CRDViewReader interface {
	Snapshot() CRDSnapshot
}

type crdRecord struct {
	ResourceVersion string
	BundleVersion   string
}

// CRDView manages the Gateway API CRD view: tracking served kinds, bundle version,
// and reacting to CRD changes at runtime.
type CRDView struct {
	// mu guards crds, snapshot, onBundleVersionChanged, and informers.
	mu                     sync.RWMutex
	crds                   map[string]crdRecord
	snapshot               CRDSnapshot
	onBundleVersionChanged func(newVersion string)
	informers              []toolscache.SharedIndexInformer

	crdChanges atomic.Uint64
}

// NewCRDView initializes a new CRDView using the RESTMapper as the single source of truth
// for served kinds at the version GARI uses. If reader is provided, it reads the initial
// bundle version from the Gateway CRD metadata.
func NewCRDView(ctx context.Context, mapper meta.RESTMapper, scheme *runtime.Scheme, reader client.Reader) (*CRDView, error) {
	if mapper == nil {
		return nil, fmt.Errorf("RESTMapper is required")
	}
	if scheme == nil {
		return nil, fmt.Errorf("scheme is required")
	}

	servedKinds, err := SnapshotFromRESTMapper(mapper, scheme)
	if err != nil {
		return nil, err
	}

	v := &CRDView{
		crds: make(map[string]crdRecord),
		snapshot: CRDSnapshot{
			ServedKinds: servedKinds,
		},
	}

	if reader != nil {
		gatewayMeta := &metav1.PartialObjectMetadata{}
		gatewayMeta.SetGroupVersionKind(CustomResourceDefinitionGVK)
		if err := reader.Get(ctx, client.ObjectKey{Name: GatewayCRDName}, gatewayMeta); err != nil {
			if !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
				return nil, fmt.Errorf("failed to get Gateway CRD metadata: %w", err)
			}
			// NotFound or NoMatch: The Gateway CRD object is not present in the reader
			// (e.g. in minimal unit test environments). Safe to proceed with an empty
			// bundle version; the informer watch will deliver the CRD if it is created later.
		} else {
			bv := gatewayMeta.Annotations[gatewayconsts.BundleVersionAnnotation]
			v.crds[GatewayCRDName] = crdRecord{
				ResourceVersion: gatewayMeta.ResourceVersion,
				BundleVersion:   bv,
			}
			v.snapshot.BundleVersion = bv
		}
	}

	return v, nil
}

// NewCRDViewFromSnapshot creates a CRDView with a pre-configured snapshot (useful for unit testing).
func NewCRDViewFromSnapshot(snapshot CRDSnapshot) *CRDView {
	v := &CRDView{
		crds:     make(map[string]crdRecord),
		snapshot: snapshot,
	}
	if snapshot.BundleVersion != "" {
		v.crds[GatewayCRDName] = crdRecord{
			BundleVersion: snapshot.BundleVersion,
		}
	}
	return v
}

// SetOnBundleVersionChanged sets a callback function to be called when the bundle version changes.
func (v *CRDView) SetOnBundleVersionChanged(fn func(newVersion string)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onBundleVersionChanged = fn
}

// CRDChangeCount returns the number of meaningful CRD changes observed.
func (v *CRDView) CRDChangeCount() uint64 {
	return v.crdChanges.Load()
}

// Snapshot returns the current immutable CRDSnapshot.
func (v *CRDView) Snapshot() CRDSnapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.snapshot
}

// RegisterWithManager registers field-selected metadata informers for each named
// Gateway API CRD with mgr.
func (v *CRDView) RegisterWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("manager is required")
	}

	v.mu.Lock()
	alreadyRegistered := len(v.informers) > 0
	v.mu.Unlock()

	if alreadyRegistered {
		return nil
	}

	cfg := mgr.GetConfig()
	if cfg == nil {
		return fmt.Errorf("manager rest.Config is required for CRD informers")
	}

	metaClient, err := metadata.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create metadata client for CRD informers: %w", err)
	}

	crdGVR := schema.GroupVersionResource{
		Group:    CustomResourceDefinitionGVK.Group,
		Version:  CustomResourceDefinitionGVK.Version,
		Resource: "customresourcedefinitions",
	}

	var informers []toolscache.SharedIndexInformer
	for _, crdName := range GatewayAPICRDNames {
		name := crdName
		tweak := func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
		}
		genInformer := metadatainformer.NewFilteredMetadataInformer(
			metaClient,
			crdGVR,
			metav1.NamespaceAll,
			0,
			toolscache.Indexers{},
			tweak,
		)
		inf := genInformer.Informer()
		if err := inf.SetTransform(toolscache.TransformFunc(CRDMetadataTransform)); err != nil {
			return fmt.Errorf("failed to set transform for %s CRD informer: %w", name, err)
		}
		_, err := inf.AddEventHandler(toolscache.ResourceEventHandlerDetailedFuncs{
			AddFunc: func(obj any, isInInitialList bool) {
				v.HandleAdd(obj, isInInitialList)
			},
			UpdateFunc: v.HandleUpdate,
			DeleteFunc: v.HandleDelete,
		})
		if err != nil {
			return fmt.Errorf("failed to add event handler for %s CRD informer: %w", name, err)
		}
		informers = append(informers, inf)
	}

	v.mu.Lock()
	v.informers = informers
	v.mu.Unlock()

	if err := mgr.Add(v); err != nil {
		return fmt.Errorf("failed to add CRDView to manager: %w", err)
	}
	return nil
}

// Start runs all registered CRD informers until ctx is cancelled.
func (v *CRDView) Start(ctx context.Context) error {
	v.mu.RLock()
	informers := make([]toolscache.SharedIndexInformer, len(v.informers))
	copy(informers, v.informers)
	v.mu.RUnlock()

	if len(informers) == 0 {
		<-ctx.Done()
		return nil
	}

	var wg sync.WaitGroup
	for _, inf := range informers {
		wg.Add(1)
		go func(inf toolscache.SharedIndexInformer) {
			defer wg.Done()
			inf.RunWithContext(ctx)
		}(inf)
	}
	wg.Wait()
	return nil
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
// CRD informers do not require leader election and should run immediately.
func (v *CRDView) NeedLeaderElection() bool {
	return false
}

// HandleAdd processes CRD creation events.
func (v *CRDView) HandleAdd(obj any, isInInitialList bool) {
	metaObj, ok := toPartialObjectMetadata(obj)
	if !ok {
		return
	}
	kd, ok := crdNameToKind[metaObj.Name]
	if !ok {
		return
	}

	var bv string
	if metaObj.Name == GatewayCRDName && metaObj.Annotations != nil {
		bv = metaObj.Annotations[gatewayconsts.BundleVersionAnnotation]
	}

	v.mu.Lock()
	existing, found := v.crds[metaObj.Name]
	if found && existing.ResourceVersion == metaObj.ResourceVersion {
		v.mu.Unlock()
		return
	}
	v.crds[metaObj.Name] = crdRecord{
		ResourceVersion: metaObj.ResourceVersion,
		BundleVersion:   bv,
	}

	isUnservedAdd := !isInInitialList && !v.snapshot.IsKindServed(kd.gk)
	var bvChanged bool
	var newBV string
	var cb func(string)
	if metaObj.Name == GatewayCRDName && v.snapshot.BundleVersion != bv {
		oldBV := v.snapshot.BundleVersion
		v.snapshot.BundleVersion = bv
		bvChanged = true
		newBV = bv
		cb = v.onBundleVersionChanged
		setupLog.Info("Gateway API bundle-version changed; restart controller deployment to pick up newly served kinds or versions", "oldVersion", oldBV, "newVersion", newBV)
	}

	if isUnservedAdd || bvChanged {
		v.crdChanges.Add(1)
	}
	v.mu.Unlock()

	if isUnservedAdd {
		setupLog.Info("Gateway API CRD added for unserved kind; restart controller deployment to serve it", "kind", kd.gk.Kind, "crd", metaObj.Name)
	}

	if bvChanged && cb != nil {
		cb(newBV)
	}
}

// HandleUpdate processes CRD update events.
func (v *CRDView) HandleUpdate(oldObj, newObj any) {
	metaObj, ok := toPartialObjectMetadata(newObj)
	if !ok {
		return
	}
	if !isGatewayAPICRD(metaObj.Name) {
		return
	}

	var bv string
	if metaObj.Name == GatewayCRDName && metaObj.Annotations != nil {
		bv = metaObj.Annotations[gatewayconsts.BundleVersionAnnotation]
	}

	v.mu.Lock()
	existing, found := v.crds[metaObj.Name]
	if found && existing.ResourceVersion == metaObj.ResourceVersion {
		v.mu.Unlock()
		return
	}
	v.crds[metaObj.Name] = crdRecord{
		ResourceVersion: metaObj.ResourceVersion,
		BundleVersion:   bv,
	}

	var bvChanged bool
	var newBV string
	var cb func(string)
	if metaObj.Name == GatewayCRDName && v.snapshot.BundleVersion != bv {
		oldBV := v.snapshot.BundleVersion
		v.snapshot.BundleVersion = bv
		bvChanged = true
		newBV = bv
		cb = v.onBundleVersionChanged
		v.crdChanges.Add(1)
		setupLog.Info("Gateway API bundle-version changed; restart controller deployment to pick up newly served kinds or versions", "oldVersion", oldBV, "newVersion", newBV)
	}
	v.mu.Unlock()

	// Regular updates to other CRDs or non-bundle annotations do not change served kinds or bundle version and are silent.

	if bvChanged && cb != nil {
		cb(newBV)
	}
}

// HandleDelete processes CRD deletion events.
func (v *CRDView) HandleDelete(obj any) {
	if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	metaObj, ok := toPartialObjectMetadata(obj)
	if !ok {
		return
	}
	kd, ok := crdNameToKind[metaObj.Name]
	if !ok {
		return
	}

	v.mu.Lock()
	delete(v.crds, metaObj.Name)

	isServedDelete := v.snapshot.IsKindServed(kd.gk)
	var bvChanged bool
	var cb func(string)
	if metaObj.Name == GatewayCRDName && v.snapshot.BundleVersion != "" {
		oldBV := v.snapshot.BundleVersion
		v.snapshot.BundleVersion = ""
		bvChanged = true
		cb = v.onBundleVersionChanged
		setupLog.Info("Gateway API bundle-version changed; restart controller deployment to pick up newly served kinds or versions", "oldVersion", oldBV, "newVersion", "")
	}

	if isServedDelete || bvChanged {
		v.crdChanges.Add(1)
	}
	v.mu.Unlock()

	if isServedDelete {
		setupLog.Info("Gateway API CRD deleted for served kind; restart controller deployment to update served kinds", "kind", kd.gk.Kind, "crd", metaObj.Name)
	}

	if bvChanged && cb != nil {
		cb("")
	}
}

func isGatewayAPICRD(name string) bool {
	return strings.HasSuffix(name, ".gateway.networking.k8s.io")
}

func toPartialObjectMetadata(obj any) (*metav1.PartialObjectMetadata, bool) {
	if pom, ok := obj.(*metav1.PartialObjectMetadata); ok {
		return pom, true
	}
	if clientObj, ok := obj.(client.Object); ok {
		return &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Name:            clientObj.GetName(),
				Namespace:       clientObj.GetNamespace(),
				Annotations:     clientObj.GetAnnotations(),
				ResourceVersion: clientObj.GetResourceVersion(),
			},
		}, true
	}
	return nil, false
}

// CRDMetadataTransform drops managedFields and all annotations except the Gateway API
// bundle-version annotation before PartialObjectMetadata is committed to the informer cache.
func CRDMetadataTransform(obj any) (any, error) {
	if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	metaObj, ok := obj.(metav1.Object)
	if !ok {
		return obj, nil
	}
	metaObj.SetManagedFields(nil)
	annotations := metaObj.GetAnnotations()
	if val, ok := annotations[gatewayconsts.BundleVersionAnnotation]; ok && val != "" {
		metaObj.SetAnnotations(map[string]string{
			gatewayconsts.BundleVersionAnnotation: val,
		})
	} else {
		metaObj.SetAnnotations(nil)
	}
	return obj, nil
}

// SnapshotFromRESTMapper checks the cluster's served API resources using the RESTMapper.
// It verifies that all required and optional Gateway API kinds are served at the specific
// API versions GARI builds against, serving as the single source of truth for served kinds.
func SnapshotFromRESTMapper(mapper meta.RESTMapper, scheme *runtime.Scheme) (ServedKinds, error) {
	var served ServedKinds
	for _, kd := range knownKinds {
		gvk, err := apiutil.GVKForObject(kd.prototype, scheme)
		if err != nil {
			return ServedKinds{}, fmt.Errorf("error getting GVK for %T: %w", kd.prototype, err)
		}
		_, err = mapper.RESTMapping(kd.gk, gvk.Version)
		if err != nil {
			if kd.required {
				return ServedKinds{}, fmt.Errorf("required Gateway API CRD %s (%s) is not installed: %w", kd.gk.Kind, kd.gk.String(), err)
			}
			if meta.IsNoMatchError(err) {
				continue
			}
			return ServedKinds{}, fmt.Errorf("failed to check CRD for %s (%s): %w", kd.gk.Kind, kd.gk.String(), err)
		}
		kd.set(&served, true)
	}

	return served, nil
}
