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
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestResolveNamespacedName(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "route-ns",
			Name:      "test-route",
		},
	}

	customNs := gatewayv1.Namespace("custom-ns")
	emptyNs := gatewayv1.Namespace("")

	tests := []struct {
		name      string
		namespace *gatewayv1.Namespace
		objName   gatewayv1.ObjectName
		src       client.Object
		expected  types.NamespacedName
	}{
		{
			name:      "nil namespace defaults to source object namespace",
			namespace: nil,
			objName:   "backend-svc",
			src:       route,
			expected: types.NamespacedName{
				Namespace: "route-ns",
				Name:      "backend-svc",
			},
		},
		{
			name:      "empty namespace defaults to source object namespace",
			namespace: &emptyNs,
			objName:   "backend-svc",
			src:       route,
			expected: types.NamespacedName{
				Namespace: "route-ns",
				Name:      "backend-svc",
			},
		},
		{
			name:      "explicit namespace overrides source object namespace",
			namespace: &customNs,
			objName:   "backend-svc",
			src:       route,
			expected: types.NamespacedName{
				Namespace: "custom-ns",
				Name:      "backend-svc",
			},
		},
		{
			name:      "nil src with explicit namespace",
			namespace: &customNs,
			objName:   "backend-svc",
			src:       nil,
			expected: types.NamespacedName{
				Namespace: "custom-ns",
				Name:      "backend-svc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ResolveNamespacedName(tt.namespace, tt.objName, tt.src)
			if actual != tt.expected {
				t.Errorf("ResolveNamespacedName() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

var (
	gwV1      = schema.GroupVersion{Group: gatewayv1.GroupName, Version: "v1"}
	gwV1Beta1 = schema.GroupVersion{Group: gatewayv1beta1.GroupName, Version: "v1beta1"}
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)
	_ = gatewayv1beta1.AddToScheme(scheme)
	return scheme
}

func newTestRESTMapper(servedGVKs ...schema.GroupVersionKind) *meta.DefaultRESTMapper {
	gvList := []schema.GroupVersion{
		gwV1,
		gwV1Beta1,
		corev1.SchemeGroupVersion,
	}
	mapper := meta.NewDefaultRESTMapper(gvList)
	for _, gvk := range servedGVKs {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}
	return mapper
}

func allGatewayAPIGVKs() []schema.GroupVersionKind {
	return []schema.GroupVersionKind{
		gwV1.WithKind("GatewayClass"),
		gwV1.WithKind("Gateway"),
		gwV1.WithKind("HTTPRoute"),
		gwV1.WithKind("TLSRoute"),
		gwV1.WithKind("GRPCRoute"),
		gwV1.WithKind("TCPRoute"),
		gwV1.WithKind("UDPRoute"),
		gwV1.WithKind("BackendTLSPolicy"),
		gwV1.WithKind("ListenerSet"),
		gwV1Beta1.WithKind("ReferenceGrant"),
	}
}

func gkeStandardGatewayAPIGVKs() []schema.GroupVersionKind {
	return []schema.GroupVersionKind{
		gwV1.WithKind("GatewayClass"),
		gwV1.WithKind("Gateway"),
		gwV1.WithKind("HTTPRoute"),
		gwV1.WithKind("TLSRoute"),
		gwV1.WithKind("BackendTLSPolicy"),
		gwV1Beta1.WithKind("ReferenceGrant"),
	}
}

func TestSnapshotFromRESTMapper(t *testing.T) {
	scheme := newTestScheme()

	t.Run("all CRDs served", func(t *testing.T) {
		mapper := newTestRESTMapper(allGatewayAPIGVKs()...)
		servedKinds, err := SnapshotFromRESTMapper(mapper, scheme)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		snapshot := CRDSnapshot{ServedKinds: servedKinds}
		disabled := snapshot.DisabledKinds()
		if len(disabled) != 0 {
			t.Errorf("expected 0 disabled kinds, got %v", disabled)
		}
		served := snapshot.ServedGroupKinds()
		if len(served) != 10 {
			t.Errorf("expected 10 served kinds, got %d", len(served))
		}
	})

	t.Run("partial installation with 4 optional CRDs missing", func(t *testing.T) {
		mapper := newTestRESTMapper(gkeStandardGatewayAPIGVKs()...)
		servedKinds, err := SnapshotFromRESTMapper(mapper, scheme)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		snapshot := CRDSnapshot{ServedKinds: servedKinds}
		disabled := snapshot.DisabledKinds()
		served := snapshot.ServedGroupKinds()
		if len(served) != 6 {
			t.Errorf("expected 6 served kinds, got %d", len(served))
		}
		expectedDisabled := map[string]bool{
			"GRPCRoute":   true,
			"ListenerSet": true,
			"TCPRoute":    true,
			"UDPRoute":    true,
		}
		if len(disabled) != len(expectedDisabled) {
			t.Fatalf("expected %d disabled kinds, got %d: %v", len(expectedDisabled), len(disabled), disabled)
		}
		for _, d := range disabled {
			if !expectedDisabled[d] {
				t.Errorf("unexpected disabled kind: %s", d)
			}
		}
	})

	t.Run("fails fast when GatewayClass is missing", func(t *testing.T) {
		// Only Gateway and HTTPRoute, missing GatewayClass
		mapper := newTestRESTMapper(
			gwV1.WithKind("Gateway"),
			gwV1.WithKind("HTTPRoute"),
		)
		_, err := SnapshotFromRESTMapper(mapper, scheme)
		if err == nil {
			t.Fatalf("expected error when GatewayClass is missing, got nil")
		}
		if !strings.Contains(err.Error(), "GatewayClass") {
			t.Errorf("expected error to name 'GatewayClass', got %v", err)
		}
	})

	t.Run("fails fast when Gateway is missing", func(t *testing.T) {
		// Only GatewayClass and HTTPRoute, missing Gateway
		mapper := newTestRESTMapper(
			gwV1.WithKind("GatewayClass"),
			gwV1.WithKind("HTTPRoute"),
		)
		_, err := SnapshotFromRESTMapper(mapper, scheme)
		if err == nil {
			t.Fatalf("expected error when Gateway is missing, got nil")
		}
		if !strings.Contains(err.Error(), "Gateway") {
			t.Errorf("expected error to name 'Gateway', got %v", err)
		}
	})

	t.Run("fails fast when HTTPRoute is missing", func(t *testing.T) {
		// Only GatewayClass and Gateway, missing HTTPRoute
		mapper := newTestRESTMapper(
			gwV1.WithKind("GatewayClass"),
			gwV1.WithKind("Gateway"),
		)
		_, err := SnapshotFromRESTMapper(mapper, scheme)
		if err == nil {
			t.Fatalf("expected error when HTTPRoute is missing, got nil")
		}
		if !strings.Contains(err.Error(), "HTTPRoute") {
			t.Errorf("expected error to name 'HTTPRoute', got %v", err)
		}
	})
}

type fakeInformer struct {
	toolscache.SharedIndexInformer
}

func (f *fakeInformer) AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	return &fakeRegistration{}, nil
}

type fakeRegistration struct{}

func (f *fakeRegistration) HasSynced() bool { return true }
func (f *fakeRegistration) HasSyncedChecker() toolscache.DoneChecker {
	return fakeDoneChecker{}
}

type fakeDoneChecker struct{}

func (f fakeDoneChecker) Name() string { return "fake" }
func (f fakeDoneChecker) Done() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

type fakeCache struct {
	cache.Cache
	scheme *runtime.Scheme
	served map[schema.GroupKind]bool
}

func (f *fakeCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	gvk, err := apiutil.GVKForObject(obj, f.scheme)
	if err != nil {
		return nil, err
	}
	if gvk.Group == gatewayv1.GroupName && !f.served[gvk.GroupKind()] {
		return nil, &meta.NoKindMatchError{GroupKind: gvk.GroupKind()}
	}
	return &fakeInformer{}, nil
}

type mockManager struct {
	ctrl.Manager
	client    client.Client
	reader    client.Reader
	scheme    *runtime.Scheme
	mapper    meta.RESTMapper
	cache     cache.Cache
	config    *rest.Config
	runnables []manager.Runnable
}

func (m *mockManager) Add(r manager.Runnable) error {
	m.runnables = append(m.runnables, r)
	return nil
}

func (m *mockManager) GetConfig() *rest.Config {
	if m.config != nil {
		return m.config
	}
	return &rest.Config{Host: "http://localhost:8080"}
}
func (m *mockManager) GetCache() cache.Cache          { return m.cache }
func (m *mockManager) GetScheme() *runtime.Scheme     { return m.scheme }
func (m *mockManager) GetClient() client.Client       { return m.client }
func (m *mockManager) GetRESTMapper() meta.RESTMapper { return m.mapper }
func (m *mockManager) GetAPIReader() client.Reader    { return m.reader }
func (m *mockManager) GetEventRecorderFor(name string) record.EventRecorder {
	return &record.FakeRecorder{}
}

func TestRegisterReconcilers_RequiredCRDMissing(t *testing.T) {
	scheme := newTestScheme()

	requiredCases := []struct {
		missingKind string
		gvks        []schema.GroupVersionKind
	}{
		{
			missingKind: "GatewayClass",
			gvks: []schema.GroupVersionKind{
				gwV1.WithKind("Gateway"),
				gwV1.WithKind("HTTPRoute"),
			},
		},
		{
			missingKind: "Gateway",
			gvks: []schema.GroupVersionKind{
				gwV1.WithKind("GatewayClass"),
				gwV1.WithKind("HTTPRoute"),
			},
		},
		{
			missingKind: "HTTPRoute",
			gvks: []schema.GroupVersionKind{
				gwV1.WithKind("GatewayClass"),
				gwV1.WithKind("Gateway"),
			},
		},
	}

	for _, tc := range requiredCases {
		t.Run("missing "+tc.missingKind, func(t *testing.T) {
			mapper := newTestRESTMapper(tc.gvks...)
			mgr := &mockManager{
				scheme: scheme,
				mapper: mapper,
			}
			err := RegisterReconcilers(mgr, nil, nil, ReconcilerOptions{})
			if err == nil {
				t.Fatalf("expected error when %s is missing, got nil", tc.missingKind)
			}
			if !strings.Contains(err.Error(), tc.missingKind) {
				t.Errorf("expected error to name %q, got %v", tc.missingKind, err)
			}
		})
	}
}

func TestRegisterReconcilers_PartialCRDs(t *testing.T) {
	scheme := newTestScheme()
	mapper := newTestRESTMapper(gkeStandardGatewayAPIGVKs()...)

	servedMap := make(map[schema.GroupKind]bool)
	for _, gvk := range gkeStandardGatewayAPIGVKs() {
		servedMap[gvk.GroupKind()] = true
	}

	mgr := &mockManager{
		scheme: scheme,
		mapper: mapper,
		cache: &fakeCache{
			scheme: scheme,
			served: servedMap,
		},
	}

	st := state.NewState()
	err := RegisterReconcilers(mgr, st, nil, ReconcilerOptions{
		DisableStatusUpdates: true,
	})
	if err != nil {
		t.Fatalf("unexpected error registering reconcilers with partial CRDs: %v", err)
	}

	disabledKinds := st.DisabledRouteKinds()
	if !disabledKinds[gatewayv1.Kind("GRPCRoute")] {
		t.Errorf("expected GRPCRoute to be disabled")
	}
	if !disabledKinds[gatewayv1.Kind("TCPRoute")] {
		t.Errorf("expected TCPRoute to be disabled")
	}
	if !disabledKinds[gatewayv1.Kind("UDPRoute")] {
		t.Errorf("expected UDPRoute to be disabled")
	}
	if disabledKinds[gatewayv1.Kind("HTTPRoute")] {
		t.Errorf("expected HTTPRoute NOT to be disabled")
	}
	if disabledKinds[gatewayv1.Kind("TLSRoute")] {
		t.Errorf("expected TLSRoute NOT to be disabled")
	}
}
