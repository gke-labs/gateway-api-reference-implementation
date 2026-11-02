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
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/version"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

func makeTestCRD(name string, bundleVersion string) *metav1.PartialObjectMetadata {
	m := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CustomResourceDefinitionGVK.GroupVersion().String(),
			Kind:       CustomResourceDefinitionGVK.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: "1",
		},
	}
	if bundleVersion != "" {
		m.Annotations = map[string]string{
			gatewayconsts.BundleVersionAnnotation: bundleVersion,
		}
	}
	return m
}

func requiredGatewayAPICRDs(bundleVersion string) []*metav1.PartialObjectMetadata {
	return []*metav1.PartialObjectMetadata{
		makeTestCRD(GatewayClassCRDName, ""),
		makeTestCRD(GatewayCRDName, bundleVersion),
		makeTestCRD(HTTPRouteCRDName, ""),
	}
}

func newTestSchemeWithApiextensions() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = apiextensionsv1.AddToScheme(s)
	_ = gatewayv1.AddToScheme(s)
	_ = gatewayv1beta1.AddToScheme(s)
	return s
}

// TestSnapshotFromRESTMapper_CRDExistsWithDifferentVersion tests that when a CRD exists
// on the cluster but only serves a different version than GARI uses (e.g. TLSRoute at v1alpha2
// instead of v1), it is correctly identified as not served.
func TestSnapshotFromRESTMapper_CRDExistsWithDifferentVersion(t *testing.T) {
	scheme := newTestSchemeWithApiextensions()

	// Cluster serves required CRDs at v1, but TLSRoute only at v1alpha2
	mapper := newTestRESTMapper(
		gwV1.WithKind("GatewayClass"),
		gwV1.WithKind("Gateway"),
		gwV1.WithKind("HTTPRoute"),
		schema.GroupVersion{Group: gatewayv1.GroupName, Version: "v1alpha2"}.WithKind("TLSRoute"),
	)

	servedKinds, err := SnapshotFromRESTMapper(mapper, scheme)
	if err != nil {
		t.Fatalf("unexpected SnapshotFromRESTMapper error: %v", err)
	}

	snapshot := CRDSnapshot{ServedKinds: servedKinds}
	if snapshot.IsKindServed(schema.GroupKind{Group: gatewayv1.GroupName, Kind: "TLSRoute"}) {
		t.Errorf("expected TLSRoute NOT to be served because cluster only serves v1alpha2, but GARI requires v1")
	}

	disabled := snapshot.DisabledKinds()
	foundTLSRoute := false
	for _, k := range disabled {
		if k == "TLSRoute" {
			foundTLSRoute = true
			break
		}
	}
	if !foundTLSRoute {
		t.Errorf("expected TLSRoute to be in disabled kinds, got %v", disabled)
	}
}

// TestCRDSnapshot_Comparable tests that CRDSnapshot values can be compared directly using ==.
func TestCRDSnapshot_Comparable(t *testing.T) {
	s1 := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}

	s2 := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}

	s3 := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
			TLSRoute:     true,
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}

	s4 := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
		},
		BundleVersion: gatewayconsts.BundleVersion + "-different",
	}

	if s1 != s2 {
		t.Errorf("expected s1 == s2")
	}
	if s1 == s3 {
		t.Errorf("expected s1 != s3 (different served kinds)")
	}
	if s1 == s4 {
		t.Errorf("expected s1 != s4 (different bundle version)")
	}
}

// TestCRDView_UpgradingBundleVersionUpdatesSupportedVersion tests that upgrading the
// bundle-version annotation updates the snapshot and notifies State without restart.
func TestCRDView_UpgradingBundleVersionUpdatesSupportedVersion(t *testing.T) {
	ctx := t.Context()
	scheme := newTestSchemeWithApiextensions()

	parsedV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("failed to parse bundle version %q: %v", gatewayconsts.BundleVersion, err)
	}
	initialBV := fmt.Sprintf("v%d.%d.%d", parsedV.Major(), parsedV.Minor(), parsedV.Patch()+1)
	upgradedBV := fmt.Sprintf("v%d.%d.%d", parsedV.Major(), parsedV.Minor(), parsedV.Patch()+2)

	initCRDs := requiredGatewayAPICRDs(initialBV)
	var initObjs []runtime.Object
	for _, c := range initCRDs {
		initObjs = append(initObjs, c)
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gc",
			Generation: 1,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}
	initObjs = append(initObjs, gc)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(initObjs...).
		WithStatusSubresource(gc).
		Build()

	mapper := newTestRESTMapper(
		gwV1.WithKind("GatewayClass"),
		gwV1.WithKind("Gateway"),
		gwV1.WithKind("HTTPRoute"),
	)

	crdView, err := NewCRDView(ctx, mapper, scheme, cl)
	if err != nil {
		t.Fatalf("unexpected NewCRDView error: %v", err)
	}

	if crdView.Snapshot().BundleVersion != initialBV {
		t.Fatalf("expected initial bundle version %s, got %q", initialBV, crdView.Snapshot().BundleVersion)
	}

	st := state.NewState()
	st.SetControllerName("test-controller")
	initBVVal := crdView.Snapshot().BundleVersion
	st.SetGatewayCRDBundleVersion(&initBVVal)
	st.UpsertGatewayClass(gc)
	st.Recompute()

	// Hook crdView to state
	crdView.SetOnBundleVersionChanged(func(newVersion string) {
		st.SetGatewayCRDBundleVersion(&newVersion)
	})

	r := &GatewayClassReconciler{
		Client:         cl,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
		CRDView:        crdView,
	}

	// Reconcile initial GatewayClass
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	var resGC gatewayv1.GatewayClass
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-gc"}, &resGC); err != nil {
		t.Fatalf("failed to get GatewayClass: %v", err)
	}
	cond := findCondition(resGC.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
	if cond == nil {
		t.Fatalf("expected SupportedVersion condition, got nil")
	}
	expectedInitialMsg := fmt.Sprintf("%q is supported", initialBV)
	if !strings.Contains(cond.Message, expectedInitialMsg) {
		t.Errorf("expected initial message to contain %s, got: %s", expectedInitialMsg, cond.Message)
	}

	// Upgrade bundle version annotation
	oldGatewayCRD := makeTestCRD(GatewayCRDName, initialBV)
	newGatewayCRD := makeTestCRD(GatewayCRDName, upgradedBV)
	newGatewayCRD.ResourceVersion = "2"

	crdView.HandleUpdate(oldGatewayCRD, newGatewayCRD)

	if crdView.Snapshot().BundleVersion != upgradedBV {
		t.Errorf("expected snapshot bundle version to be %s, got %q", upgradedBV, crdView.Snapshot().BundleVersion)
	}

	// State was updated via callback; recompute outputs
	st.Recompute()

	// Reconcile GatewayClass again
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: "test-gc"}, &resGC); err != nil {
		t.Fatalf("failed to get GatewayClass: %v", err)
	}
	cond = findCondition(resGC.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
	if cond == nil {
		t.Fatalf("expected SupportedVersion condition, got nil")
	}
	expectedUpgradedMsg := fmt.Sprintf("%q is supported", upgradedBV)
	if !strings.Contains(cond.Message, expectedUpgradedMsg) {
		t.Errorf("expected updated message to contain %s, got: %s", expectedUpgradedMsg, cond.Message)
	}
}

// TestCRDView_InitialSyncReplayDoesNotLogOrIncrementCounter tests that replaying an
// initial list of already-served CRDs during startup is silent and does not increment crdChanges.
func TestCRDView_InitialSyncReplayDoesNotLogOrIncrementCounter(t *testing.T) {
	snapshot := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}
	crdView := NewCRDViewFromSnapshot(snapshot)

	if crdView.CRDChangeCount() != 0 {
		t.Fatalf("expected initial change count 0, got %d", crdView.CRDChangeCount())
	}

	// Replay initial-sync Add events for all already-served CRDs
	crdView.HandleAdd(makeTestCRD(GatewayClassCRDName, ""), true)
	crdView.HandleAdd(makeTestCRD(GatewayCRDName, gatewayconsts.BundleVersion), true)
	crdView.HandleAdd(makeTestCRD(HTTPRouteCRDName, ""), true)

	if crdView.CRDChangeCount() != 0 {
		t.Errorf("expected change count still 0 after initial sync of served CRDs, got %d", crdView.CRDChangeCount())
	}

	// Unrelated update to already-served CRD (e.g. metadata/status bump with same bundle version)
	updatedHTTPRoute := makeTestCRD(HTTPRouteCRDName, "")
	updatedHTTPRoute.ResourceVersion = "2"
	crdView.HandleUpdate(makeTestCRD(HTTPRouteCRDName, ""), updatedHTTPRoute)

	if crdView.CRDChangeCount() != 0 {
		t.Errorf("expected change count still 0 after non-meaningful update, got %d", crdView.CRDChangeCount())
	}
}

// TestCRDView_InitialListAddForUnservedKindDoesNotLogOrCount tests that when a CRD exists
// on the cluster but its version isn't served by GARI (e.g. older bundle with TLSRoute at v1alpha2),
// the informer's initial list delivers an Add event (isInInitialList=true) which must NOT log
// a restart or increment the counter, but must still record the resourceVersion.
func TestCRDView_InitialListAddForUnservedKindDoesNotLogOrCount(t *testing.T) {
	snapshot := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
			TLSRoute:     false, // Unserved kind (e.g. older cluster bundle only serves v1alpha2)
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}
	crdView := NewCRDViewFromSnapshot(snapshot)

	if crdView.CRDChangeCount() != 0 {
		t.Fatalf("expected initial change count 0, got %d", crdView.CRDChangeCount())
	}

	// CRD exists on cluster, but comes from initial list (isInInitialList = true)
	tlsCRD := makeTestCRD(TLSRouteCRDName, gatewayconsts.BundleVersion)
	tlsCRD.ResourceVersion = "42"
	crdView.HandleAdd(tlsCRD, true)

	// Should not be counted or log restart
	if crdView.CRDChangeCount() != 0 {
		t.Errorf("expected change count 0 for initial-list add of unserved kind, got %d", crdView.CRDChangeCount())
	}

	// Should still record the resourceVersion in private tracking
	crdView.mu.RLock()
	record, exists := crdView.crds[TLSRouteCRDName]
	crdView.mu.RUnlock()
	if !exists {
		t.Fatalf("expected TLSRoute to be recorded in crds map")
	}
	if record.ResourceVersion != "42" {
		t.Errorf("expected recorded ResourceVersion 42, got %q", record.ResourceVersion)
	}

	// Now deliver a runtime add (isInInitialList = false) for a different unserved kind -> should count!
	grpcCRD := makeTestCRD(GRPCRouteCRDName, gatewayconsts.BundleVersion)
	crdView.HandleAdd(grpcCRD, false)
	if crdView.CRDChangeCount() != 1 {
		t.Errorf("expected change count 1 after runtime add of unserved kind, got %d", crdView.CRDChangeCount())
	}
}

// TestNewCRDView_RequiresMapperAndScheme tests that NewCRDView returns an error when
// mapper or scheme is nil.
func TestNewCRDView_RequiresMapperAndScheme(t *testing.T) {
	ctx := t.Context()
	scheme := newTestSchemeWithApiextensions()
	mapper := newTestRESTMapper(gwV1.WithKind("GatewayClass"))

	if _, err := NewCRDView(ctx, nil, scheme, nil); err == nil {
		t.Errorf("expected error when mapper is nil, got nil")
	}
	if _, err := NewCRDView(ctx, mapper, nil, nil); err == nil {
		t.Errorf("expected error when scheme is nil, got nil")
	}
}

type errorReader struct {
	client.Reader
	err error
}

func (r *errorReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return r.err
}

// TestNewCRDView_ReaderGetError verifies that unexpected reader errors fail NewCRDView,
// while NotFound errors are safely tolerated with an empty bundle version.
func TestNewCRDView_ReaderGetError(t *testing.T) {
	ctx := t.Context()
	scheme := newTestSchemeWithApiextensions()
	mapper := newTestRESTMapper(allGatewayAPIGVKs()...)

	// Unexpected error (e.g. apiserver failure) must fail NewCRDView
	errReader := &errorReader{err: fmt.Errorf("connection refused")}
	if _, err := NewCRDView(ctx, mapper, scheme, errReader); err == nil {
		t.Errorf("expected error when reader.Get fails unexpectedly, got nil")
	} else if !strings.Contains(err.Error(), "failed to get Gateway CRD metadata") {
		t.Errorf("expected error message to mention Gateway CRD metadata, got: %v", err)
	}

	// NotFound error must succeed with an empty bundle version
	notFoundReader := &errorReader{
		err: apierrors.NewNotFound(schema.GroupResource{Resource: "customresourcedefinitions"}, GatewayCRDName),
	}
	v, err := NewCRDView(ctx, mapper, scheme, notFoundReader)
	if err != nil {
		t.Fatalf("unexpected error on NotFound reader: %v", err)
	}
	if v.Snapshot().BundleVersion != "" {
		t.Errorf("expected empty bundle version on NotFound, got %q", v.Snapshot().BundleVersion)
	}
}

// TestCRDView_RuntimeCRDChangesIncrementCounter tests that runtime CRD additions, updates,
// and deletions increment the change counter only for meaningful changes.
func TestCRDView_RuntimeCRDChangesIncrementCounter(t *testing.T) {
	snapshot := CRDSnapshot{
		ServedKinds: ServedKinds{
			GatewayClass: true,
			Gateway:      true,
			HTTPRoute:    true,
		},
		BundleVersion: gatewayconsts.BundleVersion,
	}
	crdView := NewCRDViewFromSnapshot(snapshot)

	if crdView.CRDChangeCount() != 0 {
		t.Fatalf("expected initial change count 0, got %d", crdView.CRDChangeCount())
	}

	// Add an unserved optional CRD at runtime -> meaningful change!
	tlsCRD := makeTestCRD(TLSRouteCRDName, gatewayconsts.BundleVersion)
	tlsCRD.ResourceVersion = "1"
	crdView.HandleAdd(tlsCRD, false)

	if crdView.CRDChangeCount() != 1 {
		t.Errorf("expected change count 1 after add of unserved kind, got %d", crdView.CRDChangeCount())
	}

	// Resync with same ResourceVersion should be ignored
	crdView.HandleAdd(tlsCRD, false)
	if crdView.CRDChangeCount() != 1 {
		t.Errorf("expected change count still 1 after resync, got %d", crdView.CRDChangeCount())
	}

	// Update unserved CRD without bundle version change -> not a change to served kinds
	tlsCRDUpdated := makeTestCRD(TLSRouteCRDName, gatewayconsts.BundleVersion)
	tlsCRDUpdated.ResourceVersion = "2"
	crdView.HandleUpdate(tlsCRD, tlsCRDUpdated)

	if crdView.CRDChangeCount() != 1 {
		t.Errorf("expected change count still 1 after update to non-bundle CRD, got %d", crdView.CRDChangeCount())
	}

	// Delete a served CRD -> meaningful change!
	httpRouteCRD := makeTestCRD(HTTPRouteCRDName, "")
	crdView.HandleDelete(httpRouteCRD)
	if crdView.CRDChangeCount() != 2 {
		t.Errorf("expected change count 2 after deleting served kind, got %d", crdView.CRDChangeCount())
	}

	// Bundle version change on Gateway CRD -> meaningful change!
	gatewayUpdated := makeTestCRD(GatewayCRDName, gatewayconsts.BundleVersion+"-different")
	gatewayUpdated.ResourceVersion = "2"
	crdView.HandleUpdate(makeTestCRD(GatewayCRDName, gatewayconsts.BundleVersion), gatewayUpdated)
	if crdView.CRDChangeCount() != 3 {
		t.Errorf("expected change count 3 after bundle version change, got %d", crdView.CRDChangeCount())
	}

	// Unrelated CRD should be ignored
	unrelatedCRD := makeTestCRD("certificates.cert-manager.io", "v1.0.0")
	crdView.HandleAdd(unrelatedCRD, false)
	if crdView.CRDChangeCount() != 3 {
		t.Errorf("expected change count still 3 after unrelated CRD, got %d", crdView.CRDChangeCount())
	}
}

// TestCRDMetadataTransform_DropsManagedFieldsAndAnnotations tests that CRDMetadataTransform
// clears managedFields and drops all annotations except the Gateway API bundle-version annotation.
func TestCRDMetadataTransform_DropsManagedFieldsAndAnnotations(t *testing.T) {
	crd := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CustomResourceDefinitionGVK.GroupVersion().String(),
			Kind:       CustomResourceDefinitionGVK.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            GatewayCRDName,
			ResourceVersion: "100",
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:    "kubectl",
					Operation:  metav1.ManagedFieldsOperationApply,
					APIVersion: "apiextensions.k8s.io/v1",
				},
			},
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition"}`,
				"kubectl.kubernetes.io/client-side-filter":         "true",
				gatewayconsts.BundleVersionAnnotation:              gatewayconsts.BundleVersion,
				"custom.company.org/team":                          "networking",
			},
		},
	}

	transformed, err := CRDMetadataTransform(crd)
	if err != nil {
		t.Fatalf("unexpected CRDMetadataTransform error: %v", err)
	}

	metaObj := transformed.(*metav1.PartialObjectMetadata)
	if metaObj.ManagedFields != nil {
		t.Errorf("expected ManagedFields to be nil, got: %v", metaObj.ManagedFields)
	}
	if _, hasLastApplied := metaObj.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; hasLastApplied {
		t.Errorf("expected kubectl.kubernetes.io/last-applied-configuration to be dropped")
	}
	if _, hasCustom := metaObj.Annotations["custom.company.org/team"]; hasCustom {
		t.Errorf("expected custom annotation to be dropped")
	}
	if bv, ok := metaObj.Annotations[gatewayconsts.BundleVersionAnnotation]; !ok || bv != gatewayconsts.BundleVersion {
		t.Errorf("expected bundle version annotation %s, got %q", gatewayconsts.BundleVersion, bv)
	}
}

// TestCRDInformer_CacheTransformInspectStore tests that an informer configured with
// CRDMetadataTransform stores only stripped metadata in its cache store.
func TestCRDInformer_CacheTransformInspectStore(t *testing.T) {
	crd := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: CustomResourceDefinitionGVK.GroupVersion().String(),
			Kind:       CustomResourceDefinitionGVK.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            GatewayCRDName,
			ResourceVersion: "1",
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:   "kubectl",
					Operation: metav1.ManagedFieldsOperationApply,
				},
			},
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"apiextensions.k8s.io/v1"}`,
				gatewayconsts.BundleVersionAnnotation:              gatewayconsts.BundleVersion,
			},
		},
	}

	indexer := toolscache.NewIndexer(toolscache.MetaNamespaceKeyFunc, toolscache.Indexers{})
	fifo := toolscache.NewDeltaFIFOWithOptions(toolscache.DeltaFIFOOptions{
		KnownObjects: indexer,
		Transformer:  toolscache.TransformFunc(CRDMetadataTransform),
	})

	if err := fifo.Add(crd); err != nil {
		t.Fatalf("failed to add to fifo: %v", err)
	}

	_, err := fifo.Pop(func(obj any, isInInitialList bool) error {
		deltas := obj.(toolscache.Deltas)
		for _, d := range deltas {
			if err := indexer.Add(d.Object); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to pop from fifo: %v", err)
	}

	items := indexer.List()
	if len(items) != 1 {
		t.Fatalf("expected 1 item in store, got %d", len(items))
	}

	storedObj, ok := items[0].(*metav1.PartialObjectMetadata)
	if !ok {
		t.Fatalf("expected *metav1.PartialObjectMetadata in store, got %T", items[0])
	}

	if storedObj.ManagedFields != nil {
		t.Errorf("expected informer cache to store nil ManagedFields, got: %v", storedObj.ManagedFields)
	}
	if _, exists := storedObj.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; exists {
		t.Errorf("expected informer cache to not contain last-applied-configuration")
	}
	if bv := storedObj.Annotations[gatewayconsts.BundleVersionAnnotation]; bv != gatewayconsts.BundleVersion {
		t.Errorf("expected informer cache to retain bundle version %s, got %q", gatewayconsts.BundleVersion, bv)
	}
}

// Acceptance criteria: The cache holds no CRD specs (metadata only), if the watch approach is chosen.
func TestCRDView_RegistersMetadataOnlyInformer(t *testing.T) {
	scheme := newTestSchemeWithApiextensions()

	var capturedObj any
	fakeCache := &informerCaptureCache{
		scheme: scheme,
		onGetInformer: func(obj any) {
			capturedObj = obj
		},
	}

	mgr := &mockManager{
		scheme: scheme,
		cache:  fakeCache,
	}

	crdView := NewCRDViewFromSnapshot(CRDSnapshot{})
	if err := crdView.RegisterWithManager(mgr); err != nil {
		t.Fatalf("unexpected RegisterWithManager error: %v", err)
	}

	if capturedObj == nil {
		t.Fatalf("expected GetInformer to be called with CRD object, got nil")
	}

	metaObj, ok := capturedObj.(*metav1.PartialObjectMetadata)
	if !ok {
		t.Fatalf("expected GetInformer to be called with *metav1.PartialObjectMetadata, got %T (CRD specs must not be cached)", capturedObj)
	}

	gvk := metaObj.GetObjectKind().GroupVersionKind()
	if gvk != CustomResourceDefinitionGVK {
		t.Errorf("expected GVK %v, got %v", CustomResourceDefinitionGVK, gvk)
	}
}

type informerCaptureCache struct {
	fakeCache
	scheme        *runtime.Scheme
	onGetInformer func(obj any)
}

func (c *informerCaptureCache) GetInformer(ctx context.Context, obj client.Object, opts ...ctrlcache.InformerGetOption) (ctrlcache.Informer, error) {
	if c.onGetInformer != nil {
		c.onGetInformer(obj)
	}
	return &fakeInformer{}, nil
}
