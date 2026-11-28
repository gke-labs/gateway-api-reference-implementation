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

package singlepod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/spiffe"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ssaNoOpInterceptor adjusts controller-runtime's fake client for Server-Side Apply:
// It models Kubernetes SSA no-op behavior: when an apply configuration produces no changes on an existing object, no write is issued and resourceVersion is not incremented.
func ssaNoOpInterceptor() interceptor.Funcs {
	return interceptor.Funcs{
		Apply: func(ctx context.Context, cl client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			data, err := json.Marshal(obj)
			if err != nil {
				return err
			}
			var tm struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Metadata   struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(data, &tm); err != nil {
				return err
			}

			u := &unstructured.Unstructured{}
			u.SetAPIVersion(tm.APIVersion)
			u.SetKind(tm.Kind)
			key := types.NamespacedName{Namespace: tm.Metadata.Namespace, Name: tm.Metadata.Name}
			if err := cl.Get(ctx, key, u); err != nil {
				return cl.Apply(ctx, obj, opts...)
			}

			probeClient := fake.NewClientBuilder().
				WithScheme(cl.Scheme()).
				WithReturnManagedFields().
				WithObjects(u.DeepCopy()).
				Build()

			probeObj := &unstructured.Unstructured{}
			if err := json.Unmarshal(data, probeObj); err != nil {
				return err
			}
			unstructured.RemoveNestedField(probeObj.Object, "metadata", "resourceVersion")
			probeAC := client.ApplyConfigurationFromUnstructured(probeObj)

			if err := probeClient.Apply(ctx, probeAC, opts...); err != nil {
				return err
			}

			probed := &unstructured.Unstructured{}
			probed.SetAPIVersion(tm.APIVersion)
			probed.SetKind(tm.Kind)
			if err := probeClient.Get(ctx, key, probed); err != nil {
				return cl.Apply(ctx, obj, opts...)
			}

			clean := func(item *unstructured.Unstructured) map[string]any {
				m := item.DeepCopy().Object
				unstructured.RemoveNestedField(m, "metadata", "resourceVersion")
				unstructured.RemoveNestedField(m, "metadata", "managedFields")
				return m
			}

			if reflect.DeepEqual(clean(u), clean(probed)) {
				// No fields changed; SSA is a no-op so avoid writing and bumping resourceVersion.
				return nil
			}

			return cl.Apply(ctx, obj, opts...)
		},
	}
}

func testBundleConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-trust-bundle-pem",
		},
	}
}

func TestSinglePodAddressProvider_GatewayAddresses(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testBundleConfigMap()).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	ctx := t.Context()
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gw",
			Namespace: "my-ns",
			UID:       types.UID("12345"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"custom-label": "custom-val",
					// User label with reserved prefix should be ignored
					gatewayv1.LabelKey(LabelGatewayName): "malicious-name",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"custom-anno": "custom-val",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Name:     "http",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Owner:    state.ListenerOwner{Kind: "Gateway", Namespace: "my-ns", Name: "my-gw"},
		},
		{
			Name:     "https",
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
			Owner:    state.ListenerOwner{Kind: "Gateway", Namespace: "my-ns", Name: "my-gw"},
		},
		// ListenerSet listener on port 8080
		{
			Name:     "ls-http",
			Port:     8080,
			Protocol: gatewayv1.HTTPProtocolType,
			Owner:    state.ListenerOwner{Kind: "ListenerSet", Namespace: "my-ns", Name: "my-ls"},
		},
	}

	p := NewAddressProvider(client, "default", WithEnableH2C(true))

	// 1. Initial reconcile creates SA, adds to CRB, creates Deployment and Service in my-ns, but no Ingress and replicas not ready yet
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses before LB ingress is assigned, got %d", len(addrs))
	}
	if readiness.Ready {
		t.Fatalf("expected ready=false before deployment replicas become available")
	}

	// Verify Service was created in my-ns with all effective listener ports (including ListenerSet port 8080)
	name := state.ResourceNameForGateway("my-gw")
	var svc corev1.Service
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &svc); err != nil {
		t.Fatalf("failed to get created Service: %v", err)
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("expected Service type LoadBalancer, got %s", svc.Spec.Type)
	}
	if svc.Labels["custom-label"] != "custom-val" {
		t.Errorf("expected custom-label on Service, got %s", svc.Labels["custom-label"])
	}
	if svc.Labels[LabelGatewayName] != "my-gw" {
		t.Errorf("expected LabelGatewayName to not be overridden by user label, got %s", svc.Labels[LabelGatewayName])
	}
	if svc.Annotations["custom-anno"] != "custom-val" {
		t.Errorf("expected custom-anno on Service, got %s", svc.Annotations["custom-anno"])
	}
	if len(svc.OwnerReferences) == 0 || svc.OwnerReferences[0].Name != "my-gw" {
		t.Errorf("expected ownerReference pointing to my-gw, got %+v", svc.OwnerReferences)
	}
	// Expected ports: 80 (HTTP), 443 (HTTPS TCP), 443 (HTTP3 UDP), 8080 (HTTP) -> 4 ports
	if len(svc.Spec.Ports) != 4 {
		t.Fatalf("expected 4 service ports, got %d: %+v", len(svc.Spec.Ports), svc.Spec.Ports)
	}

	// Verify ServiceAccount was created in my-ns
	var sa corev1.ServiceAccount
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &sa); err != nil {
		t.Fatalf("failed to get created ServiceAccount: %v", err)
	}
	if sa.Labels["custom-label"] != "custom-val" {
		t.Errorf("expected custom-label on ServiceAccount, got %s", sa.Labels["custom-label"])
	}

	// Verify destination ConfigMap was created in my-ns with bundle data
	var destCM corev1.ConfigMap
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &destCM); err != nil {
		t.Fatalf("failed to get created ConfigMap: %v", err)
	}
	if destCM.Data[spiffe.BundleDataKey] != "test-trust-bundle-pem" {
		t.Errorf("expected bundle data %q, got %q", "test-trust-bundle-pem", destCM.Data[spiffe.BundleDataKey])
	}

	// Verify no Role or RoleBinding was created in my-ns
	var role rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &role); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Role to not exist, got: %v", err)
	}
	var rb rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &rb); !apierrors.IsNotFound(err) {
		t.Fatalf("expected RoleBinding to not exist, got: %v", err)
	}

	// Verify no Secret was created in my-ns
	var sec corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &sec); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret to not exist, got: %v", err)
	}

	// Verify Deployment was created in my-ns
	var deploy appsv1.Deployment
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}
	if len(deploy.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("expected container in deployment")
	}
	if deploy.Spec.Template.Spec.Containers[0].ReadinessProbe == nil {
		t.Fatalf("expected readiness probe on container")
	}
	if deploy.Spec.Template.Spec.ServiceAccountName != name {
		t.Errorf("expected ServiceAccountName %s, got %s", name, deploy.Spec.Template.Spec.ServiceAccountName)
	}

	// 2. Simulate MetalLB assigning LB Ingress IP and Deployment replicas becoming available
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "172.18.255.201"},
	}
	if err := client.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update service status: %v", err)
	}

	deploy.Status.AvailableReplicas = 1
	if err := client.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update deploy status: %v", err)
	}

	// Reconcile again -> should return the assigned LB address and ready=true
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.Ready {
		t.Fatalf("expected ready=true after replicas available")
	}
	if len(addrs) != 1 || addrs[0].Value != "172.18.255.201" || state.ValueOf(addrs[0].Type) != gatewayv1.IPAddressType {
		t.Fatalf("expected IP 172.18.255.201, got %+v", addrs)
	}

	// 3. Update Gateway infrastructure labels -> should update template hash and pod template
	gw.Spec.Infrastructure.Labels["updated-label"] = "updated-val"
	_, _, err = p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("failed to update gateway with new infrastructure label: %v", err)
	}
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &deploy); err != nil {
		t.Fatalf("failed to get updated deployment: %v", err)
	}
	if deploy.Spec.Template.Labels["updated-label"] != "updated-val" {
		t.Errorf("expected updated pod template labels to include updated-label")
	}

	// 4. (Namespaced resources have controller ownerReferences verified in step 1 and are deleted by k8s garbage collector)
}

func TestSinglePodAddressProvider_NamespacedConfigMaps(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testBundleConfigMap()).
		Build()

	p := NewAddressProvider(client, "default")
	ctx := t.Context()

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: "ns-1", UID: types.UID("gw-1-uid")},
		Spec:       gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}}},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-2", Namespace: "ns-2", UID: types.UID("gw-2-uid")},
		Spec:       gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}}},
	}

	// Add two gateways concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, _ = p.GatewayAddresses(ctx, gw1, nil)
	}()
	go func() {
		defer wg.Done()
		_, _, _ = p.GatewayAddresses(ctx, gw2, nil)
	}()
	wg.Wait()

	resName1 := state.ResourceNameForGateway("gw-1")
	resName2 := state.ResourceNameForGateway("gw-2")

	// Verify ns-1 has ConfigMap with bundle, but no Role, RoleBinding, or Secret
	var cm1 corev1.ConfigMap
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: resName1}, &cm1); err != nil {
		t.Fatalf("failed to get ConfigMap for gw-1: %v", err)
	}
	if cm1.Data[spiffe.BundleDataKey] != "test-trust-bundle-pem" {
		t.Errorf("unexpected bundle data in ns-1: %q", cm1.Data[spiffe.BundleDataKey])
	}
	var role1 rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: resName1}, &role1); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Role for gw-1 to not exist, got: %v", err)
	}
	var rb1 rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: resName1}, &rb1); !apierrors.IsNotFound(err) {
		t.Fatalf("expected RoleBinding for gw-1 to not exist, got: %v", err)
	}
	var sec1 corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: resName1}, &sec1); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret for gw-1 to not exist, got: %v", err)
	}

	// Verify ns-2 has ConfigMap with bundle, but no Role, RoleBinding, or Secret
	var cm2 corev1.ConfigMap
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: resName2}, &cm2); err != nil {
		t.Fatalf("failed to get ConfigMap for gw-2: %v", err)
	}
	if cm2.Data[spiffe.BundleDataKey] != "test-trust-bundle-pem" {
		t.Errorf("unexpected bundle data in ns-2: %q", cm2.Data[spiffe.BundleDataKey])
	}
	var role2 rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: resName2}, &role2); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Role for gw-2 to not exist, got: %v", err)
	}
	var rb2 rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: resName2}, &rb2); !apierrors.IsNotFound(err) {
		t.Fatalf("expected RoleBinding for gw-2 to not exist, got: %v", err)
	}
	var sec2 corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: resName2}, &sec2); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret for gw-2 to not exist, got: %v", err)
	}
}

func TestSinglePodAddressProvider_OwnershipConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "conflict-gw",
			Namespace: "default",
			UID:       types.UID("99999"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	resName := state.ResourceNameForGateway("conflict-gw")

	trueVal := true
	diffOwnerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       "conflict-gw",
		UID:        types.UID("other-uid-11111"),
		Controller: &trueVal,
	}

	tests := []struct {
		name   string
		object client.Object
	}{
		{
			name: "foreign service with no labels and no ownerRef",
			object: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
				},
			},
		},
		{
			name: "service with managed labels but no ownerRef",
			object: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
				},
			},
		},
		{
			name: "service with managed labels and ownerRef with different UID",
			object: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
					OwnerReferences: []metav1.OwnerReference{diffOwnerRef},
				},
			},
		},
		{
			name: "deployment with managed labels but no ownerRef",
			object: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
				},
			},
		},
		{
			name: "deployment with managed labels and ownerRef with different UID",
			object: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
					OwnerReferences: []metav1.OwnerReference{diffOwnerRef},
				},
			},
		},
		{
			name: "serviceaccount with managed labels but no ownerRef",
			object: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
				},
			},
		},
		{
			name: "serviceaccount with managed labels and ownerRef with different UID",
			object: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
					OwnerReferences: []metav1.OwnerReference{diffOwnerRef},
				},
			},
		},
		{
			name: "configmap with managed labels but no ownerRef",
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
				},
			},
		},
		{
			name: "configmap with managed labels and ownerRef with different UID",
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resName,
					Namespace: "default",
					Labels: map[string]string{
						LabelGatewayName: "conflict-gw",
						LabelManagedBy:   ManagedByValue,
					},
					OwnerReferences: []metav1.OwnerReference{diffOwnerRef},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.object, testBundleConfigMap()).
				Build()

			p := NewAddressProvider(cl, "default")
			ctx := t.Context()

			_, _, err := p.GatewayAddresses(ctx, gw, nil)
			if err == nil {
				t.Fatalf("expected ownership conflict error, got nil")
			}
			var conflictErr *controller.OwnershipConflictError
			if !errors.As(err, &conflictErr) {
				t.Fatalf("expected OwnershipConflictError, got: %v", err)
			}
		})
	}
}

func TestSinglePodAddressProvider_Watches(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gwGV := schema.GroupVersion{Group: gatewayv1.GroupName, Version: "v1"}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{gwGV})
	mapper.Add(gwGV.WithKind("Gateway"), meta.RESTScopeNamespace)
	pred := managedByPredicate()
	ownerHandler := handler.EnqueueRequestForOwner(scheme, mapper, &gatewayv1.Gateway{}, handler.OnlyControllerOwner())

	trueVal := true
	falseVal := false
	ownerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       "gw-1",
		UID:        types.UID("gw-uid-1"),
		Controller: &trueVal,
	}
	nonControllerOwnerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       "gw-1",
		UID:        types.UID("gw-uid-1"),
		Controller: &falseVal,
	}

	ctx := t.Context()
	processCreate := func(obj client.Object) []reconcile.Request {
		evt := event.CreateEvent{Object: obj}
		if !pred.Create(evt) {
			return nil
		}
		q := workqueue.NewTypedRateLimitingQueue[reconcile.Request](workqueue.DefaultTypedItemBasedRateLimiter[reconcile.Request]())
		defer q.ShutDown()
		ownerHandler.Create(ctx, evt, q)
		var reqs []reconcile.Request
		for q.Len() > 0 {
			item, _ := q.Get()
			reqs = append(reqs, item)
			q.Done(item)
		}
		return reqs
	}

	processUpdate := func(oldObj, newObj client.Object) []reconcile.Request {
		evt := event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}
		if !pred.Update(evt) {
			return nil
		}
		q := workqueue.NewTypedRateLimitingQueue[reconcile.Request](workqueue.DefaultTypedItemBasedRateLimiter[reconcile.Request]())
		defer q.ShutDown()
		ownerHandler.Update(ctx, evt, q)
		var reqs []reconcile.Request
		for q.Len() > 0 {
			item, _ := q.Get()
			reqs = append(reqs, item)
			q.Done(item)
		}
		return reqs
	}

	// 1. Service with managed label and controller ownerReference -> enqueues owning Gateway
	ownedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            state.ResourceNameForGateway("gw-1"),
			Namespace:       "custom-ns",
			Labels:          map[string]string{LabelManagedBy: ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
	}
	reqs := processCreate(ownedSvc)
	if len(reqs) != 1 || reqs[0].NamespacedName != (types.NamespacedName{Namespace: "custom-ns", Name: "gw-1"}) {
		t.Errorf("expected 1 request for custom-ns/gw-1 from owned Service, got %+v", reqs)
	}

	// 2. Deployment with managed label and controller ownerReference -> enqueues owning Gateway
	ownedDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            state.ResourceNameForGateway("gw-1"),
			Namespace:       "custom-ns",
			Labels:          map[string]string{LabelManagedBy: ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
	}
	reqs = processCreate(ownedDeploy)
	if len(reqs) != 1 || reqs[0].NamespacedName != (types.NamespacedName{Namespace: "custom-ns", Name: "gw-1"}) {
		t.Errorf("expected 1 request for custom-ns/gw-1 from owned Deployment, got %+v", reqs)
	}

	// 3. Non-owned Service with managed labels (no ownerRef) -> does not enqueue
	nonOwnedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      state.ResourceNameForGateway("gw-1"),
			Namespace: "custom-ns",
			Labels:    map[string]string{LabelManagedBy: ManagedByValue, LabelGatewayName: "gw-1"},
		},
	}
	reqs = processCreate(nonOwnedSvc)
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests for non-owned Service with managed labels, got %+v", reqs)
	}

	// 4. Non-owned Deployment with managed labels (no ownerRef) -> does not enqueue
	nonOwnedDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      state.ResourceNameForGateway("gw-1"),
			Namespace: "custom-ns",
			Labels:    map[string]string{LabelManagedBy: ManagedByValue, LabelGatewayName: "gw-1"},
		},
	}
	reqs = processCreate(nonOwnedDeploy)
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests for non-owned Deployment with managed labels, got %+v", reqs)
	}

	// 5. Service with managed labels and non-controller ownerRef -> does not enqueue
	nonCtrlSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            state.ResourceNameForGateway("gw-1"),
			Namespace:       "custom-ns",
			Labels:          map[string]string{LabelManagedBy: ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{nonControllerOwnerRef},
		},
	}
	reqs = processCreate(nonCtrlSvc)
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests for Service with non-controller ownerRef, got %+v", reqs)
	}

	// 6. Unmanaged Service (without managed-by label) -> predicate filters out
	unmanagedSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "unmanaged",
			Namespace:       "custom-ns",
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
	}
	reqs = processCreate(unmanagedSvc)
	if len(reqs) != 0 {
		t.Errorf("expected 0 requests for unmanaged Service, got %+v", reqs)
	}

	// 7. Update event on owned Service -> enqueues owning Gateway
	updatedSvc := ownedSvc.DeepCopy()
	updatedSvc.Annotations = map[string]string{"foo": "bar"}
	reqs = processUpdate(ownedSvc, updatedSvc)
	if len(reqs) != 1 || reqs[0].NamespacedName != (types.NamespacedName{Namespace: "custom-ns", Name: "gw-1"}) {
		t.Errorf("expected 1 request for custom-ns/gw-1 from updated owned Service, got %+v", reqs)
	}
}

func setupTestClient(t *testing.T, extraObjs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	objs := append([]client.Object{testBundleConfigMap()}, extraObjs...)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()
}

func TestSinglePodAddressProvider_InfrastructureLabelsAndAnnotationsLandOnAllFour(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"example.com/tier": "frontend",
					"custom-label":     "value-1",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"example.com/cost-center": "12345",
					"custom-anno":             "anno-val-1",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")

	// 1. ServiceAccount
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if sa.Labels["example.com/tier"] != "frontend" || sa.Labels["custom-label"] != "value-1" {
		t.Errorf("ServiceAccount missing infrastructure labels: got %+v", sa.Labels)
	}
	if sa.Annotations["example.com/cost-center"] != "12345" || sa.Annotations["custom-anno"] != "anno-val-1" {
		t.Errorf("ServiceAccount missing infrastructure annotations: got %+v", sa.Annotations)
	}

	// 2. Deployment
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.Labels["example.com/tier"] != "frontend" || deploy.Labels["custom-label"] != "value-1" {
		t.Errorf("Deployment missing infrastructure labels: got %+v", deploy.Labels)
	}
	if deploy.Annotations["example.com/cost-center"] != "12345" || deploy.Annotations["custom-anno"] != "anno-val-1" {
		t.Errorf("Deployment missing infrastructure annotations: got %+v", deploy.Annotations)
	}

	// 3. Pod Template
	if deploy.Spec.Template.Labels["example.com/tier"] != "frontend" || deploy.Spec.Template.Labels["custom-label"] != "value-1" {
		t.Errorf("Pod template missing infrastructure labels: got %+v", deploy.Spec.Template.Labels)
	}
	if deploy.Spec.Template.Annotations["example.com/cost-center"] != "12345" || deploy.Spec.Template.Annotations["custom-anno"] != "anno-val-1" {
		t.Errorf("Pod template missing infrastructure annotations: got %+v", deploy.Spec.Template.Annotations)
	}

	// 4. Service
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Labels["example.com/tier"] != "frontend" || svc.Labels["custom-label"] != "value-1" {
		t.Errorf("Service missing infrastructure labels: got %+v", svc.Labels)
	}
	if svc.Annotations["example.com/cost-center"] != "12345" || svc.Annotations["custom-anno"] != "anno-val-1" {
		t.Errorf("Service missing infrastructure annotations: got %+v", svc.Annotations)
	}
}

func TestSinglePodAddressProvider_InfrastructureValueUpdate(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"tier": "frontend-v1",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"cost-center": "1000",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on initial reconcile: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")

	// Update label and annotation values in Gateway infrastructure
	gw.Spec.Infrastructure.Labels["tier"] = "frontend-v2"
	gw.Spec.Infrastructure.Annotations["cost-center"] = "2000"

	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on update reconcile: %v", err)
	}

	// 1. ServiceAccount
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if sa.Labels["tier"] != "frontend-v2" {
		t.Errorf("ServiceAccount label not updated: got %s, want frontend-v2", sa.Labels["tier"])
	}
	if sa.Annotations["cost-center"] != "2000" {
		t.Errorf("ServiceAccount annotation not updated: got %s, want 2000", sa.Annotations["cost-center"])
	}

	// 2. Deployment
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.Labels["tier"] != "frontend-v2" {
		t.Errorf("Deployment label not updated: got %s, want frontend-v2", deploy.Labels["tier"])
	}
	if deploy.Annotations["cost-center"] != "2000" {
		t.Errorf("Deployment annotation not updated: got %s, want 2000", deploy.Annotations["cost-center"])
	}

	// 3. Pod Template (ensures pods are rolled)
	if deploy.Spec.Template.Labels["tier"] != "frontend-v2" {
		t.Errorf("Pod template label not updated: got %s, want frontend-v2", deploy.Spec.Template.Labels["tier"])
	}
	if deploy.Spec.Template.Annotations["cost-center"] != "2000" {
		t.Errorf("Pod template annotation not updated: got %s, want 2000", deploy.Spec.Template.Annotations["cost-center"])
	}

	// 4. Service
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Labels["tier"] != "frontend-v2" {
		t.Errorf("Service label not updated: got %s, want frontend-v2", svc.Labels["tier"])
	}
	if svc.Annotations["cost-center"] != "2000" {
		t.Errorf("Service annotation not updated: got %s, want 2000", svc.Annotations["cost-center"])
	}
}

func TestSinglePodAddressProvider_InfrastructureKeyRemoval(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"tier":      "frontend",
					"remove-me": "label-val",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"cost-center": "1000",
					"remove-me":   "anno-val",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on initial reconcile: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")

	// Remove keys from Gateway infrastructure
	delete(gw.Spec.Infrastructure.Labels, "remove-me")
	delete(gw.Spec.Infrastructure.Annotations, "remove-me")

	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on removal reconcile: %v", err)
	}

	// 1. ServiceAccount
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if _, ok := sa.Labels["remove-me"]; ok {
		t.Errorf("ServiceAccount still has removed label: %+v", sa.Labels)
	}
	if sa.Labels["tier"] != "frontend" {
		t.Errorf("ServiceAccount lost retained label 'tier'")
	}
	if _, ok := sa.Annotations["remove-me"]; ok {
		t.Errorf("ServiceAccount still has removed annotation: %+v", sa.Annotations)
	}
	if sa.Annotations["cost-center"] != "1000" {
		t.Errorf("ServiceAccount lost retained annotation 'cost-center'")
	}

	// 2. Deployment
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if _, ok := deploy.Labels["remove-me"]; ok {
		t.Errorf("Deployment still has removed label: %+v", deploy.Labels)
	}
	if deploy.Labels["tier"] != "frontend" {
		t.Errorf("Deployment lost retained label 'tier'")
	}
	if _, ok := deploy.Annotations["remove-me"]; ok {
		t.Errorf("Deployment still has removed annotation: %+v", deploy.Annotations)
	}
	if deploy.Annotations["cost-center"] != "1000" {
		t.Errorf("Deployment lost retained annotation 'cost-center'")
	}

	// 3. Pod Template
	if _, ok := deploy.Spec.Template.Labels["remove-me"]; ok {
		t.Errorf("Pod template still has removed label: %+v", deploy.Spec.Template.Labels)
	}
	if deploy.Spec.Template.Labels["tier"] != "frontend" {
		t.Errorf("Pod template lost retained label 'tier'")
	}
	if _, ok := deploy.Spec.Template.Annotations["remove-me"]; ok {
		t.Errorf("Pod template still has removed annotation: %+v", deploy.Spec.Template.Annotations)
	}
	if deploy.Spec.Template.Annotations["cost-center"] != "1000" {
		t.Errorf("Pod template lost retained annotation 'cost-center'")
	}

	// 4. Service
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if _, ok := svc.Labels["remove-me"]; ok {
		t.Errorf("Service still has removed label: %+v", svc.Labels)
	}
	if svc.Labels["tier"] != "frontend" {
		t.Errorf("Service lost retained label 'tier'")
	}
	if _, ok := svc.Annotations["remove-me"]; ok {
		t.Errorf("Service still has removed annotation: %+v", svc.Annotations)
	}
	if svc.Annotations["cost-center"] != "1000" {
		t.Errorf("Service lost retained annotation 'cost-center'")
	}
}

func TestSinglePodAddressProvider_InfrastructureUserKeysCannotOverrideReservedLabelsOrSelectors(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					gatewayv1.LabelKey(LabelGatewayName):          "override-name",
					"gateway.networking.k8s.io/gateway-namespace": "override-ns",
					"gateway.networking.k8s.io/custom-reserved":   "malicious-val",
					gatewayv1.LabelKey(LabelManagedBy):            "override-managed-by",
					gatewayv1.LabelKey(LabelAppName):              "override-name",
					"custom-valid-label":                          "valid-val",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")

	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}

	type labelHolder struct {
		name   string
		labels map[string]string
	}
	holders := []labelHolder{
		{name: "ServiceAccount", labels: sa.Labels},
		{name: "Deployment", labels: deploy.Labels},
		{name: "PodTemplate", labels: deploy.Spec.Template.Labels},
		{name: "Service", labels: svc.Labels},
	}

	for _, h := range holders {
		if h.labels[LabelGatewayName] != "test-gw" {
			t.Errorf("%s: LabelGatewayName was overridden: got %q, want %q", h.name, h.labels[LabelGatewayName], "test-gw")
		}
		if _, ok := h.labels["gateway.networking.k8s.io/gateway-namespace"]; ok {
			t.Errorf("%s: contains dropped gateway.networking.k8s.io/gateway-namespace label: got %q", h.name, h.labels["gateway.networking.k8s.io/gateway-namespace"])
		}
		if h.labels[LabelManagedBy] != ManagedByValue {
			t.Errorf("%s: LabelManagedBy was overridden: got %q, want %q", h.name, h.labels[LabelManagedBy], ManagedByValue)
		}
		if h.labels[LabelAppName] != AppNameValue {
			t.Errorf("%s: LabelAppName was overridden: got %q, want %q", h.name, h.labels[LabelAppName], AppNameValue)
		}
		if _, ok := h.labels["gateway.networking.k8s.io/custom-reserved"]; ok {
			t.Errorf("%s: contains forbidden gateway.networking.k8s.io/* label", h.name)
		}
		if h.labels["custom-valid-label"] != "valid-val" {
			t.Errorf("%s: missing valid custom label: got %q", h.name, h.labels["custom-valid-label"])
		}
	}

	// Verify Deployment selector is not overridden
	expectedDeploySelector := map[string]string{
		LabelGatewayName: "test-gw",
		LabelAppName:     AppNameValue,
	}
	if !maps.Equal(deploy.Spec.Selector.MatchLabels, expectedDeploySelector) {
		t.Errorf("Deployment selector was modified: got %+v, want %+v", deploy.Spec.Selector.MatchLabels, expectedDeploySelector)
	}

	// Verify Service selector is not overridden
	if !maps.Equal(svc.Spec.Selector, expectedDeploySelector) {
		t.Errorf("Service selector was modified: got %+v, want %+v", svc.Spec.Selector, expectedDeploySelector)
	}
}

func TestSinglePodAddressProvider_PreservesForeignLabelsAndAnnotations(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"tier":       "frontend",
					"remove-lbl": "old-val",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"cost-center": "1000",
					"remove-anno": "old-val",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on initial reconcile: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")

	// Inject foreign annotation and foreign label onto existing ServiceAccount, Deployment, and Service
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	sa.Labels["custom.io/zone"] = "us-central1-a"
	sa.Annotations["cloud.google.com/neg-status"] = `{"network_endpoint_groups":{"80":"k8s1-neg"}}`
	if err := c.Update(ctx, &sa); err != nil {
		t.Fatalf("failed to update ServiceAccount with foreign metadata: %v", err)
	}

	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	deploy.Labels["custom.io/zone"] = "us-central1-a"
	deploy.Annotations["deployment.kubernetes.io/revision"] = "1"
	deploy.Annotations["cloud.google.com/neg-status"] = `{"network_endpoint_groups":{"80":"k8s1-neg"}}`
	if err := c.Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update Deployment with foreign metadata: %v", err)
	}

	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	svc.Labels["custom.io/zone"] = "us-central1-a"
	svc.Annotations["cloud.google.com/neg-status"] = `{"network_endpoint_groups":{"80":"k8s1-neg"}}`
	svc.Annotations["metallb.universe.tf/ip-allocated-from-pool"] = "example"
	if err := c.Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update Service with foreign metadata: %v", err)
	}

	// Update infrastructure metadata: change one value and remove one key
	gw.Spec.Infrastructure.Labels["tier"] = "frontend-v2"
	delete(gw.Spec.Infrastructure.Labels, "remove-lbl")
	gw.Spec.Infrastructure.Annotations["cost-center"] = "2000"
	delete(gw.Spec.Infrastructure.Annotations, "remove-anno")

	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}

	// Verify ServiceAccount preserves foreign labels/annotations and updates/removes infra keys
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if sa.Labels["custom.io/zone"] != "us-central1-a" {
		t.Errorf("ServiceAccount lost foreign label: got %+v", sa.Labels)
	}
	if sa.Annotations["cloud.google.com/neg-status"] != `{"network_endpoint_groups":{"80":"k8s1-neg"}}` {
		t.Errorf("ServiceAccount lost foreign annotation: got %+v", sa.Annotations)
	}
	if sa.Labels["tier"] != "frontend-v2" {
		t.Errorf("ServiceAccount did not update tier label: got %q", sa.Labels["tier"])
	}
	if _, ok := sa.Labels["remove-lbl"]; ok {
		t.Errorf("ServiceAccount still has removed label: got %+v", sa.Labels)
	}
	if sa.Annotations["cost-center"] != "2000" {
		t.Errorf("ServiceAccount did not update cost-center annotation: got %q", sa.Annotations["cost-center"])
	}
	if _, ok := sa.Annotations["remove-anno"]; ok {
		t.Errorf("ServiceAccount still has removed annotation: got %+v", sa.Annotations)
	}

	// Verify Deployment preserves foreign labels/annotations and updates/removes infra keys
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.Labels["custom.io/zone"] != "us-central1-a" {
		t.Errorf("Deployment lost foreign label: got %+v", deploy.Labels)
	}
	if deploy.Annotations["cloud.google.com/neg-status"] != `{"network_endpoint_groups":{"80":"k8s1-neg"}}` {
		t.Errorf("Deployment lost foreign annotation cloud.google.com/neg-status: got %+v", deploy.Annotations)
	}
	if deploy.Annotations["deployment.kubernetes.io/revision"] != "1" {
		t.Errorf("Deployment lost foreign annotation deployment.kubernetes.io/revision: got %+v", deploy.Annotations)
	}
	if deploy.Labels["tier"] != "frontend-v2" {
		t.Errorf("Deployment did not update tier label: got %q", deploy.Labels["tier"])
	}
	if _, ok := deploy.Labels["remove-lbl"]; ok {
		t.Errorf("Deployment still has removed label: got %+v", deploy.Labels)
	}
	if deploy.Annotations["cost-center"] != "2000" {
		t.Errorf("Deployment did not update cost-center annotation: got %q", deploy.Annotations["cost-center"])
	}
	if _, ok := deploy.Annotations["remove-anno"]; ok {
		t.Errorf("Deployment still has removed annotation: got %+v", deploy.Annotations)
	}

	// Verify Service preserves foreign labels/annotations and updates/removes infra keys
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Labels["custom.io/zone"] != "us-central1-a" {
		t.Errorf("Service lost foreign label: got %+v", svc.Labels)
	}
	if svc.Annotations["cloud.google.com/neg-status"] != `{"network_endpoint_groups":{"80":"k8s1-neg"}}` {
		t.Errorf("Service lost foreign annotation cloud.google.com/neg-status: got %+v", svc.Annotations)
	}
	if svc.Annotations["metallb.universe.tf/ip-allocated-from-pool"] != "example" {
		t.Errorf("Service lost foreign annotation metallb.universe.tf/ip-allocated-from-pool: got %+v", svc.Annotations)
	}
	if svc.Labels["tier"] != "frontend-v2" {
		t.Errorf("Service did not update tier label: got %q", svc.Labels["tier"])
	}
	if _, ok := svc.Labels["remove-lbl"]; ok {
		t.Errorf("Service still has removed label: got %+v", svc.Labels)
	}
	if svc.Annotations["cost-center"] != "2000" {
		t.Errorf("Service did not update cost-center annotation: got %q", svc.Annotations["cost-center"])
	}
	if _, ok := svc.Annotations["remove-anno"]; ok {
		t.Errorf("Service still has removed annotation: got %+v", svc.Annotations)
	}
}

func TestSinglePodAddressProvider_NoChangesIssuesNoWrite(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"tier": "frontend",
				},
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"cost-center": "1000",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	resName := state.ResourceNameForGateway("test-gw")

	// 1. Initial reconcile creates resources
	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on initial reconcile: %v", err)
	}

	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	saRV := sa.ResourceVersion

	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	deployRV := deploy.ResourceVersion

	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	svcRV := svc.ResourceVersion

	// 2. Second reconcile with identical configuration: no writes issued, resourceVersion unchanged
	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on no-op reconcile: %v", err)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if sa.ResourceVersion != saRV {
		t.Errorf("ServiceAccount resourceVersion changed on no-op reconcile: got %s, want %s", sa.ResourceVersion, saRV)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.ResourceVersion != deployRV {
		t.Errorf("Deployment resourceVersion changed on no-op reconcile: got %s, want %s", deploy.ResourceVersion, deployRV)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.ResourceVersion != svcRV {
		t.Errorf("Service resourceVersion changed on no-op reconcile: got %s, want %s", svc.ResourceVersion, svcRV)
	}

	// 3. Third reconcile with changed infrastructure metadata: resourceVersion must change
	gw.Spec.Infrastructure.Labels["tier"] = "frontend-v2"
	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on update reconcile: %v", err)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount: %v", err)
	}
	if sa.ResourceVersion == saRV {
		t.Errorf("ServiceAccount resourceVersion expected to change on update, but stayed %s", sa.ResourceVersion)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.ResourceVersion == deployRV {
		t.Errorf("Deployment resourceVersion expected to change on update, but stayed %s", deploy.ResourceVersion)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.ResourceVersion == svcRV {
		t.Errorf("Service resourceVersion expected to change on update, but stayed %s", svc.ResourceVersion)
	}
}

func TestSinglePodAddressProvider_RequestedAddresses_AddRemove(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  state.Ptr(gatewayv1.IPAddressType),
					Value: "192.0.2.1",
				},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	// 1. Initial reconcile with requested IP: Service pins loadBalancerIP, readiness is AddressNotUsable
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false when requested address not in ingress")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected reason=AddressNotUsable, got %s", readiness.Reason)
	}
	if !strings.Contains(readiness.Message, "192.0.2.1") {
		t.Errorf("expected message mentioning 192.0.2.1, got %s", readiness.Message)
	}

	resName := state.ResourceNameForGateway("test-gw")
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Spec.LoadBalancerIP != "192.0.2.1" {
		t.Errorf("expected Service LoadBalancerIP='192.0.2.1', got %q", svc.Spec.LoadBalancerIP)
	}

	// 2. Mark Deployment ready and Service ingress bound
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	deploy.Status.ReadyReplicas = 1
	if err := c.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}

	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "192.0.2.1"},
	}
	if err := c.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update Service status: %v", err)
	}

	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}
	if !readiness.Ready {
		t.Errorf("expected ready=true when requested address is bound in ingress")
	}
	if len(addrs) != 1 || addrs[0].Value != "192.0.2.1" {
		t.Errorf("expected 1 address 192.0.2.1, got %+v", addrs)
	}

	// 3. Removing requested address from spec.addresses releases it:
	// Service no longer pins it and status updates on next reconcile without restart.
	gw.Spec.Addresses = nil
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error on remove reconcile: %v", err)
	}
	if !readiness.Ready {
		t.Errorf("expected ready=true after releasing static address")
	}
	if len(addrs) != 1 || addrs[0].Value != "192.0.2.1" {
		t.Errorf("expected reported address to still report ingress address 192.0.2.1, got %+v", addrs)
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Spec.LoadBalancerIP != "" {
		t.Errorf("expected Service LoadBalancerIP to be released/empty, got %q", svc.Spec.LoadBalancerIP)
	}
}

func TestSinglePodAddressProvider_TwoGatewaysSameIP(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-1",
			Namespace: "test-ns",
			UID:       types.UID("gw-1-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Value: "192.0.2.50"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-2",
			Namespace: "test-ns",
			UID:       types.UID("gw-2-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Value: "192.0.2.50"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	// Reconcile gw1 and mark bound
	_, _, err := p.GatewayAddresses(ctx, gw1, nil)
	if err != nil {
		t.Fatalf("unexpected error on gw1: %v", err)
	}
	svc1Name := state.ResourceNameForGateway("gw-1")
	var svc1 corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: svc1Name}, &svc1); err != nil {
		t.Fatalf("failed to get svc1: %v", err)
	}
	svc1.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.50"}}
	_ = c.Status().Update(ctx, &svc1)
	var deploy1 appsv1.Deployment
	_ = c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: svc1Name}, &deploy1)
	deploy1.Status.ReadyReplicas = 1
	_ = c.Status().Update(ctx, &deploy1)

	_, readiness1, _ := p.GatewayAddresses(ctx, gw1, nil)
	if !readiness1.Ready {
		t.Fatalf("expected gw1 to be ready")
	}

	// Reconcile gw2 requesting the same IP: its service does NOT have the ingress IP bound
	_, readiness2, err := p.GatewayAddresses(ctx, gw2, nil)
	if err != nil {
		t.Fatalf("unexpected error on gw2: %v", err)
	}
	if readiness2.Ready {
		t.Errorf("expected gw2 ready=false when requesting already bound IP")
	}
	if readiness2.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected gw2 reason=AddressNotUsable, got %s", readiness2.Reason)
	}
	if !strings.Contains(readiness2.Message, "192.0.2.50") {
		t.Errorf("expected message mentioning 192.0.2.50, got %s", readiness2.Message)
	}
}

func TestSinglePodAddressProvider_MultipleRequestedIPs(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-multi",
			Namespace: "test-ns",
			UID:       types.UID("gw-multi-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Value: "192.0.2.10"},
				{Value: "192.0.2.20"},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mock the first IP bound in service ingress
	resName := state.ResourceNameForGateway("gw-multi")
	var svc corev1.Service
	_ = c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.10"}}
	_ = c.Status().Update(ctx, &svc)

	_, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false when second requested IP cannot be bound")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Errorf("expected reason=AddressNotUsable, got %s", readiness.Reason)
	}
	expectedMsgSub := "singlepod binds at most one requested IP"
	if !strings.Contains(readiness.Message, expectedMsgSub) {
		t.Errorf("expected message to contain %q, got %q", expectedMsgSub, readiness.Message)
	}
}

func TestSinglePodAddressProvider_TCPListenerServiceAndDeploymentPorts(t *testing.T) {
	c := setupTestClient(t)
	p := NewAddressProvider(c, "default")
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-tcp",
			Namespace: "test-ns",
			UID:       types.UID("gw-tcp-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "tcp-1",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-2",
					Port:     9001,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-conflicted",
					Port:     8080,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "tcp-8000",
					Port:     8000,
					Protocol: gatewayv1.TCPProtocolType,
				},
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
			Name:     "tcp-1",
			Port:     9000,
			Protocol: gatewayv1.TCPProtocolType,
		},
		{
			Name:     "tcp-2",
			Port:     9001,
			Protocol: gatewayv1.TCPProtocolType,
		},
		{
			Name:     "tcp-conflicted",
			Port:     8080,
			Protocol: gatewayv1.TCPProtocolType,
			ListenerInfo: state.ListenerInfo{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionConflicted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.ListenerReasonPortUnavailable),
					},
				},
			},
		},
		{
			Name:     "tcp-8000",
			Port:     8000,
			Protocol: gatewayv1.TCPProtocolType,
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("gw-tcp")

	// 1. Verify Service ports
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get created Service: %v", err)
	}

	svcPortMap := make(map[string]corev1.ServicePort)
	for _, sp := range svc.Spec.Ports {
		svcPortMap[sp.Name] = sp
	}

	// Verify HTTP port mapped to named targetPort "http"
	if sp, ok := svcPortMap["http-80"]; !ok {
		t.Errorf("expected Service port http-80")
	} else {
		if sp.Port != 80 || sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal != "http" || sp.Protocol != corev1.ProtocolTCP {
			t.Errorf("http-80: got port=%d targetPort=%v proto=%s", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	// Verify TCP ports mapped to matching target ports
	if sp, ok := svcPortMap["tcp-9000"]; !ok {
		t.Errorf("expected Service port tcp-9000")
	} else {
		if sp.Port != 9000 || sp.TargetPort.IntValue() != 9000 || sp.Protocol != corev1.ProtocolTCP {
			t.Errorf("tcp-9000: got port=%d targetPort=%v proto=%s, want matching targetPort 9000", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	if sp, ok := svcPortMap["tcp-9001"]; !ok {
		t.Errorf("expected Service port tcp-9001")
	} else {
		if sp.Port != 9001 || sp.TargetPort.IntValue() != 9001 || sp.Protocol != corev1.ProtocolTCP {
			t.Errorf("tcp-9001: got port=%d targetPort=%v proto=%s, want matching targetPort 9001", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	// Verify unreserved TCP listener port 8000 IS in Service
	if sp, ok := svcPortMap["tcp-8000"]; !ok {
		t.Errorf("unreserved port 8000 should be exposed on Service")
	} else if sp.Port != 8000 || sp.TargetPort.IntValue() != 8000 || sp.Protocol != corev1.ProtocolTCP {
		t.Errorf("tcp-8000: got port=%d targetPort=%v proto=%s", sp.Port, sp.TargetPort, sp.Protocol)
	}

	// Verify conflicted TCP listener port 8080 is NOT in Service
	if _, ok := svcPortMap["tcp-8080"]; ok {
		t.Errorf("conflicted port 8080 should NOT be exposed on Service")
	}

	// 2. Verify Deployment container ports
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	containerPorts := deploy.Spec.Template.Spec.Containers[0].Ports
	cpMap := make(map[string]corev1.ContainerPort)
	for _, cp := range containerPorts {
		cpMap[cp.Name] = cp
	}

	// Verify default container ports
	if cp, ok := cpMap["http"]; !ok || cp.ContainerPort != 8080 {
		t.Errorf("expected container port http:8080, got %+v", cpMap["http"])
	}
	if cp, ok := cpMap["https"]; !ok || cp.ContainerPort != 8443 {
		t.Errorf("expected container port https:8443")
	}

	// Verify readiness probe port 8999
	probe := deploy.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Port.IntValue() != 8999 {
		t.Errorf("expected readiness probe on port 8999, got %+v", probe)
	}

	// Verify TCP listener container ports
	if cp, ok := cpMap["tcp-9000"]; !ok {
		t.Errorf("expected container port tcp-9000")
	} else if cp.ContainerPort != 9000 || cp.Protocol != corev1.ProtocolTCP {
		t.Errorf("tcp-9000: got containerPort=%d proto=%s, want 9000/TCP", cp.ContainerPort, cp.Protocol)
	}

	if cp, ok := cpMap["tcp-9001"]; !ok {
		t.Errorf("expected container port tcp-9001")
	} else if cp.ContainerPort != 9001 || cp.Protocol != corev1.ProtocolTCP {
		t.Errorf("tcp-9001: got containerPort=%d proto=%s, want 9001/TCP", cp.ContainerPort, cp.Protocol)
	}

	// Verify unreserved TCP listener port 8000 IS in Deployment
	if cp, ok := cpMap["tcp-8000"]; !ok || cp.ContainerPort != 8000 {
		t.Errorf("unreserved port 8000 should be in Deployment container ports, got %+v", cpMap["tcp-8000"])
	}

	// Verify conflicted TCP listener port 8080 is NOT in Deployment
	if _, ok := cpMap["tcp-8080"]; ok {
		t.Errorf("conflicted port 8080 should NOT be declared on Deployment container ports")
	}
}

func TestSinglePodAddressProvider_UDPListenerServiceAndDeploymentPorts(t *testing.T) {
	c := setupTestClient(t)
	p := NewAddressProvider(c, "default")
	ctx := t.Context()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-udp",
			Namespace: "test-ns",
			UID:       types.UID("gw-udp-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "udp-dns",
					Port:     53,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-custom",
					Port:     5300,
					Protocol: gatewayv1.UDPProtocolType,
				},
				{
					Name:     "udp-conflicted",
					Port:     8443,
					Protocol: gatewayv1.UDPProtocolType,
				},
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
			Name:     "udp-dns",
			Port:     53,
			Protocol: gatewayv1.UDPProtocolType,
		},
		{
			Name:     "udp-custom",
			Port:     5300,
			Protocol: gatewayv1.UDPProtocolType,
		},
		{
			Name:     "udp-conflicted",
			Port:     8443,
			Protocol: gatewayv1.UDPProtocolType,
			ListenerInfo: state.ListenerInfo{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionConflicted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.ListenerReasonPortUnavailable),
					},
				},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("gw-udp")

	// 1. Verify Service ports
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get created Service: %v", err)
	}

	svcPortMap := make(map[string]corev1.ServicePort)
	for _, sp := range svc.Spec.Ports {
		svcPortMap[sp.Name] = sp
	}

	// Verify HTTP port mapped to named targetPort "http"
	if sp, ok := svcPortMap["http-80"]; !ok {
		t.Errorf("expected Service port http-80")
	} else {
		if sp.Port != 80 || sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal != "http" || sp.Protocol != corev1.ProtocolTCP {
			t.Errorf("http-80: got port=%d targetPort=%v proto=%s", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	// Verify UDP ports mapped to matching target ports
	if sp, ok := svcPortMap["udp-53"]; !ok {
		t.Errorf("expected Service port udp-53")
	} else {
		if sp.Port != 53 || sp.TargetPort.IntValue() != 53 || sp.Protocol != corev1.ProtocolUDP {
			t.Errorf("udp-53: got port=%d targetPort=%v proto=%s, want matching targetPort 53", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	if sp, ok := svcPortMap["udp-5300"]; !ok {
		t.Errorf("expected Service port udp-5300")
	} else {
		if sp.Port != 5300 || sp.TargetPort.IntValue() != 5300 || sp.Protocol != corev1.ProtocolUDP {
			t.Errorf("udp-5300: got port=%d targetPort=%v proto=%s, want matching targetPort 5300", sp.Port, sp.TargetPort, sp.Protocol)
		}
	}

	// Verify conflicted UDP listener port 8443 is NOT in Service as udp-8443
	if _, ok := svcPortMap["udp-8443"]; ok {
		t.Errorf("conflicted port 8443 should NOT be exposed on Service as udp-8443")
	}

	// 2. Verify Deployment container ports
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	containerPorts := deploy.Spec.Template.Spec.Containers[0].Ports
	cpMap := make(map[string]corev1.ContainerPort)
	for _, cp := range containerPorts {
		cpMap[cp.Name] = cp
	}

	// Verify default container ports
	if cp, ok := cpMap["http"]; !ok || cp.ContainerPort != 8080 {
		t.Errorf("expected container port http:8080, got %+v", cpMap["http"])
	}
	if cp, ok := cpMap["https"]; !ok || cp.ContainerPort != 8443 {
		t.Errorf("expected container port https:8443")
	}
	if cp, ok := cpMap["http3"]; !ok || cp.ContainerPort != 8443 || cp.Protocol != corev1.ProtocolUDP {
		t.Errorf("expected container port http3:8443/UDP")
	}

	// Verify readiness probe port 8999
	probe := deploy.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Port.IntValue() != 8999 {
		t.Errorf("expected readiness probe on port 8999, got %+v", probe)
	}

	// Verify UDP listener container ports
	if cp, ok := cpMap["udp-53"]; !ok {
		t.Errorf("expected container port udp-53")
	} else if cp.ContainerPort != 53 || cp.Protocol != corev1.ProtocolUDP {
		t.Errorf("udp-53: got containerPort=%d proto=%s, want 53/UDP", cp.ContainerPort, cp.Protocol)
	}

	if cp, ok := cpMap["udp-5300"]; !ok {
		t.Errorf("expected container port udp-5300")
	} else if cp.ContainerPort != 5300 || cp.Protocol != corev1.ProtocolUDP {
		t.Errorf("udp-5300: got containerPort=%d proto=%s, want 5300/UDP", cp.ContainerPort, cp.Protocol)
	}

	// Verify conflicted UDP listener port 8443 is NOT in Deployment as udp-8443
	if _, ok := cpMap["udp-8443"]; ok {
		t.Errorf("conflicted port 8443 should NOT be declared on Deployment container ports as udp-8443")
	}
}

func TestSinglePodAddressProvider_ForwardedForModeArg(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithForwardedForMode("replace"))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("test-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	name := state.ResourceNameForGateway("test-gw")
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: name}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	args := deploy.Spec.Template.Spec.Containers[0].Args
	hasArg := false
	for _, arg := range args {
		if arg == "--forwarded-for-mode=replace" {
			hasArg = true
			break
		}
	}
	if !hasArg {
		t.Errorf("expected container args to include '--forwarded-for-mode=replace', got %v", args)
	}
}

func TestSinglePodAddressProvider_WithholdAddressesUntilDataPlaneReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	st.SetControllerName("test-controller")

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gw",
			Namespace:  "test-ns",
			UID:        types.UID("gw-uid-123"),
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.Recompute()

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, testBundleConfigMap()).
		WithStatusSubresource(gw).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	ctx := t.Context()
	p := NewAddressProvider(c, "default")
	st.SetSupportedAddressTypes(p.SupportedAddressTypes())

	r := &controller.GatewayReconciler{
		Client:          c,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: p,
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "test-gw"}}

	// 1. Initial reconcile creates resources: Service has an LB IP, but Deployment has no ready replicas.
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	resName := state.ResourceNameForGateway("test-gw")
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	// Simulate MetalLB assigning an LB IP to the Service
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.100"}}
	if err := c.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update Service status: %v", err)
	}

	// Verify at the provider level: Service has an LB IP but Deployment has 0 ready replicas
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error from GatewayAddresses: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected no addresses when data plane is not ready, got %d", len(addrs))
	}
	if readiness.Ready {
		t.Fatalf("expected readiness.Ready=false when deployment has no ready replicas")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Fatalf("expected readiness.Reason=AddressNotAssigned, got %s", readiness.Reason)
	}
	if readiness.Message != "Waiting for data-plane deployment to become available" {
		t.Fatalf("expected readiness.Message='Waiting for data-plane deployment to become available', got %q", readiness.Message)
	}

	// Reconcile through GatewayReconciler and verify status:
	// Programmed=False with reason AddressNotAssigned and deployment-waiting message, status.addresses empty.
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway second time: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := c.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 0 {
		t.Fatalf("expected 0 addresses in status, got %+v", reconciledGW.Status.Addresses)
	}
	progCond := state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Fatalf("expected Programmed=False/AddressNotAssigned, got %+v", progCond)
	}
	if progCond.Message != "Waiting for data-plane deployment to become available" {
		t.Fatalf("expected Programmed message 'Waiting for data-plane deployment to become available', got %q", progCond.Message)
	}

	// 2. Deployment is ready, but Service has no LB IP yet:
	// Programmed=False with reason AddressNotAssigned and address-waiting message.
	svc.Status.LoadBalancer.Ingress = nil
	if err := c.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to clear Service LB Ingress: %v", err)
	}

	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	deploy.Status.ReadyReplicas = 1
	if err := c.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}

	// Provider level check
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error from GatewayAddresses: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses before LB ingress is assigned, got %d", len(addrs))
	}
	if readiness.Ready {
		t.Fatalf("expected readiness.Ready=false before LB ingress is assigned")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Fatalf("expected readiness.Reason=AddressNotAssigned, got %s", readiness.Reason)
	}
	if readiness.Message != "Waiting for address to be assigned to the Gateway" {
		t.Fatalf("expected readiness.Message='Waiting for address to be assigned to the Gateway', got %q", readiness.Message)
	}

	// Controller reconcile check
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	if err := c.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 0 {
		t.Fatalf("expected 0 addresses in status, got %+v", reconciledGW.Status.Addresses)
	}
	progCond = state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Fatalf("expected Programmed=False/AddressNotAssigned, got %+v", progCond)
	}
	if progCond.Message != "Waiting for address to be assigned to the Gateway" {
		t.Fatalf("expected Programmed message 'Waiting for address to be assigned to the Gateway', got %q", progCond.Message)
	}

	// 3. Service gets LB IP while Deployment is ready -> address present, Programmed=True
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.100"}}
	if err := c.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update Service status with LB IP: %v", err)
	}

	// Provider level check
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error from GatewayAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0].Value != "192.0.2.100" {
		t.Fatalf("expected 1 address 192.0.2.100, got %+v", addrs)
	}
	if !readiness.Ready {
		t.Fatalf("expected readiness.Ready=true when deployment is ready and LB IP is bound")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Fatalf("expected readiness.Reason=Programmed, got %s", readiness.Reason)
	}

	// Controller reconcile check
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	if err := c.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 1 || reconciledGW.Status.Addresses[0].Value != "192.0.2.100" {
		t.Fatalf("expected address 192.0.2.100 in status, got %+v", reconciledGW.Status.Addresses)
	}
	progCond = state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Fatalf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	// 4. Requested-IP-not-bound case unchanged: Programmed=False/AddressNotUsable
	reconciledGW.Spec.Addresses = []gatewayv1.GatewaySpecAddress{
		{
			Type:  state.Ptr(gatewayv1.IPAddressType),
			Value: "192.0.2.200", // different from Service's 192.0.2.100
		},
	}
	if err := c.Update(ctx, &reconciledGW); err != nil {
		t.Fatalf("failed to update gateway with requested address: %v", err)
	}
	st.UpsertGateway(&reconciledGW)
	st.Recompute()

	addrs, readiness, err = p.GatewayAddresses(ctx, &reconciledGW, nil)
	if err != nil {
		t.Fatalf("unexpected error from GatewayAddresses: %v", err)
	}
	if readiness.Ready {
		t.Fatalf("expected readiness.Ready=false when requested IP is not bound")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Fatalf("expected readiness.Reason=AddressNotUsable, got %s", readiness.Reason)
	}

	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	if err := c.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	progCond = state.FindCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotUsable) {
		t.Fatalf("expected Programmed=False/AddressNotUsable, got %+v", progCond)
	}
}

func TestSinglePodAddressProvider_ParametersRef_MergeOrder(t *testing.T) {
	ctx := t.Context()
	gcNS := gatewayv1.Namespace("default")
	gcCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gc-params"},
		Data: map[string]string{
			state.ParameterKeyServiceType:           "LoadBalancer",
			state.ParameterKeyExternalTrafficPolicy: "Local",
			state.ParameterKeyServiceAnnotations:    "class-anno: val1\ncommon: class-val\n",
		},
	}
	gwCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "gw-params"},
		Data: map[string]string{
			state.ParameterKeyServiceAnnotations: "gw-anno: val2\ncommon: gw-val\n",
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
			ParametersRef: &gatewayv1.ParametersReference{
				Group:     "",
				Kind:      "ConfigMap",
				Namespace: &gcNS,
				Name:      "gc-params",
			},
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gw",
			Namespace:  "test-ns",
			UID:        types.UID("gw-uid-1"),
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					"infra-anno": "infra-val",
				},
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: "",
					Kind:  "ConfigMap",
					Name:  "gw-params",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gcCM, gwCM, gc, gw, testBundleConfigMap()).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertConfigMap(gcCM)
	st.UpsertConfigMap(gwCM)
	st.Recompute()

	p := NewAddressProvider(c, "default", WithState(st))
	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var svc corev1.Service
	resName := state.ResourceNameForGateway("test-gw")
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}

	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("expected ServiceType LoadBalancer, got %s", svc.Spec.Type)
	}
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		t.Errorf("expected ExternalTrafficPolicy Local, got %s", svc.Spec.ExternalTrafficPolicy)
	}
	if svc.Annotations["class-anno"] != "val1" {
		t.Errorf("expected class-anno=val1, got %q", svc.Annotations["class-anno"])
	}
	if svc.Annotations["gw-anno"] != "val2" {
		t.Errorf("expected gw-anno=val2, got %q", svc.Annotations["gw-anno"])
	}
	if svc.Annotations["common"] != "gw-val" {
		t.Errorf("expected common=gw-val (Gateway overrides GatewayClass), got %q", svc.Annotations["common"])
	}
	if svc.Annotations["infra-anno"] != "infra-val" {
		t.Errorf("expected infra-anno=infra-val, got %q", svc.Annotations["infra-anno"])
	}

	// Verify serviceAnnotations are applied to Service only, not Deployment
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}
	if deploy.Annotations["class-anno"] != "" || deploy.Annotations["gw-anno"] != "" || deploy.Annotations["common"] != "" {
		t.Errorf("serviceAnnotations leaked to Deployment: %+v", deploy.Annotations)
	}
	if deploy.Annotations["infra-anno"] != "infra-val" {
		t.Errorf("expected infra-anno on Deployment, got %q", deploy.Annotations["infra-anno"])
	}
}

func TestSinglePodAddressProvider_ParametersRef_EachKey(t *testing.T) {
	ctx := t.Context()

	t.Run("serviceType ClusterIP", func(t *testing.T) {
		gwCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "clusterip-params"},
			Data: map[string]string{
				state.ParameterKeyServiceType: "ClusterIP",
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-clusterip",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-2"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "clusterip-params",
					},
				},
			},
		}

		scheme := runtime.NewScheme()
		_ = clientgoscheme.AddToScheme(scheme)
		_ = gatewayv1.AddToScheme(scheme)
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gwCM, gw, testBundleConfigMap()).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
		})
		st.UpsertGateway(gw)
		st.UpsertConfigMap(gwCM)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		_, _, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var svc corev1.Service
		resName := state.ResourceNameForGateway("gw-clusterip")
		if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
			t.Fatalf("failed to get Service: %v", err)
		}
		if svc.Spec.Type != corev1.ServiceTypeClusterIP {
			t.Errorf("expected ServiceType ClusterIP, got %s", svc.Spec.Type)
		}
		if svc.Spec.ExternalTrafficPolicy != "" {
			t.Errorf("expected ExternalTrafficPolicy empty for ClusterIP, got %s", svc.Spec.ExternalTrafficPolicy)
		}
	})

	t.Run("externalTrafficPolicy Local", func(t *testing.T) {
		gwCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "local-params"},
			Data: map[string]string{
				state.ParameterKeyServiceType:           "LoadBalancer",
				state.ParameterKeyExternalTrafficPolicy: "Local",
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-local",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-3"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "local-params",
					},
				},
			},
		}

		scheme := runtime.NewScheme()
		_ = clientgoscheme.AddToScheme(scheme)
		_ = gatewayv1.AddToScheme(scheme)
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gwCM, gw, testBundleConfigMap()).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
		})
		st.UpsertGateway(gw)
		st.UpsertConfigMap(gwCM)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		_, _, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var svc corev1.Service
		resName := state.ResourceNameForGateway("gw-local")
		if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
			t.Fatalf("failed to get Service: %v", err)
		}
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			t.Errorf("expected ServiceType LoadBalancer, got %s", svc.Spec.Type)
		}
		if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
			t.Errorf("expected ExternalTrafficPolicy Local, got %s", svc.Spec.ExternalTrafficPolicy)
		}
	})
}

func TestSinglePodAddressProvider_ParametersRef_InvalidValues(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	testCases := []struct {
		name string
		data map[string]string
	}{
		{
			name: "unknown key",
			data: map[string]string{"foo": "bar"},
		},
		{
			name: "invalid serviceType",
			data: map[string]string{state.ParameterKeyServiceType: "NodePort"},
		},
		{
			name: "invalid externalTrafficPolicy",
			data: map[string]string{state.ParameterKeyExternalTrafficPolicy: "Invalid"},
		},
		{
			name: "invalid serviceAnnotations YAML",
			data: map[string]string{state.ParameterKeyServiceAnnotations: "invalid: [unclosed"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "bad-params"},
				Data:       tc.data,
			}
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "bad-gw",
					Namespace:  "test-ns",
					UID:        types.UID("gw-uid-bad"),
					Generation: 1,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "test-class",
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
					Infrastructure: &gatewayv1.GatewayInfrastructure{
						ParametersRef: &gatewayv1.LocalParametersReference{
							Group: "",
							Kind:  "ConfigMap",
							Name:  "bad-params",
						},
					},
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cm, gw, testBundleConfigMap()).
				WithReturnManagedFields().
				WithInterceptorFuncs(ssaNoOpInterceptor()).
				Build()

			st := state.NewState()
			st.SetControllerName("test-controller")
			st.UpsertGatewayClass(&gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
				Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
			})
			st.UpsertGateway(gw)
			st.UpsertConfigMap(cm)
			st.Recompute()

			p := NewAddressProvider(c, "default", WithState(st))
			addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
			if err != nil {
				t.Fatalf("expected nil error (reported via readiness), got: %v", err)
			}
			if len(addrs) != 0 {
				t.Fatalf("expected 0 addresses, got %d", len(addrs))
			}
			if readiness.Ready {
				t.Errorf("expected readiness.Ready=false")
			}
			if readiness.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
				t.Errorf("expected readiness.Reason=InvalidParameters, got %s", readiness.Reason)
			}

			// Verify no Service was created
			var svc corev1.Service
			resName := state.ResourceNameForGateway("bad-gw")
			if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
				t.Errorf("expected NotFound for Service, got err: %v", err)
			}
		})
	}
}

func TestSinglePodAddressProvider_ParametersRef_MissingConfigMap(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	t.Run("Gateway missing ConfigMap", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-missing-cm",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-missing"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "nonexistent-cm",
					},
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gw).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
		})
		st.UpsertGateway(gw)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		_, readiness, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
			t.Errorf("expected readiness.Reason=InvalidParameters, got %s", readiness.Reason)
		}
	})

	t.Run("GatewayClass missing ConfigMap", func(t *testing.T) {
		gcNS := gatewayv1.Namespace("default")
		gc := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "test-controller",
				ParametersRef: &gatewayv1.ParametersReference{
					Group:     "",
					Kind:      "ConfigMap",
					Namespace: &gcNS,
					Name:      "nonexistent-gc-cm",
				},
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-class-missing-cm",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-class-missing"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc, gw).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(gc)
		st.UpsertGateway(gw)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		_, readiness, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
			t.Errorf("expected readiness.Reason=InvalidParameters, got %s", readiness.Reason)
		}

		// Verify Gateway status has Accepted=False/InvalidParameters
		status, ok := st.GetDesiredGatewayStatus(types.NamespacedName{Namespace: "test-ns", Name: "gw-class-missing-cm"})
		if !ok {
			t.Fatalf("expected Gateway status in State")
		}
		acceptedCond := state.FindCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
			t.Errorf("expected Gateway Accepted=False/InvalidParameters for missing class ConfigMap, got %+v", acceptedCond)
		}
	})

	t.Run("GatewayClass invalid ConfigMap keys or values", func(t *testing.T) {
		gcNS := gatewayv1.Namespace("default")
		badCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "bad-gc-cm"},
			Data: map[string]string{
				state.ParameterKeyServiceType: "NodePort",
			},
		}
		gc := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-class"},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "test-controller",
				ParametersRef: &gatewayv1.ParametersReference{
					Group:     "",
					Kind:      "ConfigMap",
					Namespace: &gcNS,
					Name:      "bad-gc-cm",
				},
			},
		}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-class-bad-cm",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-class-bad"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "bad-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc, badCM, gw).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(gc)
		st.UpsertConfigMap(badCM)
		st.UpsertGateway(gw)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		_, readiness, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
			t.Errorf("expected readiness.Reason=InvalidParameters, got %s", readiness.Reason)
		}

		// Verify Gateway status has Accepted=False/InvalidParameters
		status, ok := st.GetDesiredGatewayStatus(types.NamespacedName{Namespace: "test-ns", Name: "gw-class-bad-cm"})
		if !ok {
			t.Fatalf("expected Gateway status in State")
		}
		acceptedCond := state.FindCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
		if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
			t.Errorf("expected Gateway Accepted=False/InvalidParameters for invalid class ConfigMap, got %+v", acceptedCond)
		}

		// Verify no Service was created
		var svc corev1.Service
		resName := state.ResourceNameForGateway("gw-class-bad-cm")
		if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
			t.Errorf("expected NotFound for Service, got err: %v", err)
		}
	})
}

func TestSinglePodAddressProvider_ParametersRef_NotComputedYet(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-not-computed",
			Namespace:  "test-ns",
			UID:        types.UID("gw-uid-not-computed"),
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	st := state.NewState()
	st.SetControllerName("test-controller")
	// State has not computed outputs for gw yet

	p := NewAddressProvider(c, "default", WithState(st))
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses before state computes parameters, got %d", len(addrs))
	}
	if readiness.Ready {
		t.Errorf("expected readiness.Ready=false")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Errorf("expected readiness.Reason=Pending, got %s", readiness.Reason)
	}

	// Verify no Service was created
	var svc corev1.Service
	resName := state.ResourceNameForGateway("gw-not-computed")
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound for Service, got err: %v", err)
	}
}

func TestSinglePodAddressProvider_ClusterIP_AddressRule(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "clusterip-cfg"},
		Data: map[string]string{
			state.ParameterKeyServiceType: "ClusterIP",
		},
	}

	t.Run("no spec.addresses -> Programmed=False/AddressNotAssigned with static address message", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-no-addr",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-no-addr"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "clusterip-cfg",
					},
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm, gw, testBundleConfigMap()).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
		})
		st.UpsertGateway(gw)
		st.UpsertConfigMap(cm)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))
		addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(addrs) != 0 {
			t.Fatalf("expected 0 addresses, got %d", len(addrs))
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
			t.Errorf("expected AddressNotAssigned, got %s", readiness.Reason)
		}
		if !strings.Contains(readiness.Message, "static address") {
			t.Errorf("expected message explaining static address needed, got %q", readiness.Message)
		}
	})

	t.Run("with spec.addresses: IP and Hostname", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "gw-with-addr",
				Namespace:  "test-ns",
				UID:        types.UID("gw-uid-with-addr"),
				Generation: 1,
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "test-class",
				Addresses: []gatewayv1.GatewaySpecAddress{
					{
						Type:  state.Ptr(gatewayv1.IPAddressType),
						Value: "203.0.113.50",
					},
					{
						Type:  state.Ptr(gatewayv1.HostnameAddressType),
						Value: "lb.example.com",
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
				Infrastructure: &gatewayv1.GatewayInfrastructure{
					ParametersRef: &gatewayv1.LocalParametersReference{
						Group: "",
						Kind:  "ConfigMap",
						Name:  "clusterip-cfg",
					},
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cm, gw, testBundleConfigMap()).
			WithReturnManagedFields().
			WithInterceptorFuncs(ssaNoOpInterceptor()).
			Build()

		st := state.NewState()
		st.SetControllerName("test-controller")
		st.UpsertGatewayClass(&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
		})
		st.UpsertGateway(gw)
		st.UpsertConfigMap(cm)
		st.Recompute()

		p := NewAddressProvider(c, "default", WithState(st))

		// 1. Initial reconcile: Deployment has 0 available replicas -> addresses withheld
		addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(addrs) != 0 {
			t.Fatalf("expected 0 addresses while deployment not ready, got %d", len(addrs))
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
			t.Errorf("expected AddressNotAssigned, got %s", readiness.Reason)
		}

		// 2. Simulate Deployment becoming available
		resName := state.ResourceNameForGateway("gw-with-addr")
		var deploy appsv1.Deployment
		if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
			t.Fatalf("failed to get Deployment: %v", err)
		}
		deploy.Status.AvailableReplicas = 1
		deploy.Status.ReadyReplicas = 1
		if err := c.Status().Update(ctx, &deploy); err != nil {
			t.Fatalf("failed to update Deployment status: %v", err)
		}

		// 3. Reconcile again: data plane is ready -> addresses are reported
		addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !readiness.Ready {
			t.Errorf("expected readiness.Ready=true")
		}
		if readiness.Reason != string(gatewayv1.GatewayReasonProgrammed) {
			t.Errorf("expected Programmed, got %s", readiness.Reason)
		}
		if len(addrs) != 2 {
			t.Fatalf("expected 2 addresses (IP and Hostname), got %d: %+v", len(addrs), addrs)
		}
		if *addrs[0].Type != gatewayv1.IPAddressType || addrs[0].Value != "203.0.113.50" {
			t.Errorf("unexpected address 0: %+v", addrs[0])
		}
		if *addrs[1].Type != gatewayv1.HostnameAddressType || addrs[1].Value != "lb.example.com" {
			t.Errorf("unexpected address 1: %+v", addrs[1])
		}
	})
}

func TestSinglePodAddressProvider_LiveSwitch_LoadBalancer_To_ClusterIP(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "gw-params"},
		Data: map[string]string{
			state.ParameterKeyServiceType: "LoadBalancer",
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "live-gw",
			Namespace:  "test-ns",
			UID:        types.UID("live-gw-uid"),
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: "",
					Kind:  "ConfigMap",
					Name:  "gw-params",
				},
			},
		},
	}

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertConfigMap(cm)
	st.Recompute()

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, cm, gw, testBundleConfigMap()).
		WithStatusSubresource(gw).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	p := NewAddressProvider(c, "default", WithState(st))
	st.SetSupportedAddressTypes(p.SupportedAddressTypes())

	r := &controller.GatewayReconciler{
		Client:          c,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: p,
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "live-gw"}}

	// 1. Initial reconcile creates Service as type LoadBalancer
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("live-gw")
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Fatalf("expected Service type LoadBalancer, got %s", svc.Spec.Type)
	}

	// 2. Change parameters to ClusterIP on the live Gateway
	cm.Data[state.ParameterKeyServiceType] = "ClusterIP"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatalf("failed to update ConfigMap: %v", err)
	}
	if err := c.Get(ctx, req.NamespacedName, gw); err != nil {
		t.Fatalf("failed to get latest Gateway: %v", err)
	}
	gw.Spec.Addresses = []gatewayv1.GatewaySpecAddress{
		{
			Type:  state.Ptr(gatewayv1.IPAddressType),
			Value: "10.0.0.99",
		},
	}
	gw.Generation = 2
	if err := c.Update(ctx, gw); err != nil {
		t.Fatalf("failed to update Gateway: %v", err)
	}

	st.UpsertConfigMap(cm)
	st.UpsertGateway(gw)
	st.Recompute()

	// 3. Reconcile again: Service is updated in-place to ClusterIP
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling updated gateway: %v", err)
	}

	var updatedSvc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &updatedSvc); err != nil {
		t.Fatalf("failed to get Service: %v", err)
	}
	if updatedSvc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("expected Service type ClusterIP after update, got %s", updatedSvc.Spec.Type)
	}
	if updatedSvc.Spec.ExternalTrafficPolicy != "" {
		t.Errorf("expected ExternalTrafficPolicy empty for ClusterIP, got %s", updatedSvc.Spec.ExternalTrafficPolicy)
	}

	// Verify no second or leftover LoadBalancer service exists in namespace
	var svcList corev1.ServiceList
	if err := c.List(ctx, &svcList, client.InNamespace("test-ns")); err != nil {
		t.Fatalf("failed to list services: %v", err)
	}
	if len(svcList.Items) != 1 {
		t.Errorf("expected exactly 1 Service in namespace, got %d", len(svcList.Items))
	}
}

func TestSinglePodAddressProvider_UpgradeUpdatesServiceAndDeploymentInPlace(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "upgrading-gw",
			Namespace:  "test-ns",
			Generation: 1,
			UID:        types.UID("gw-uid-1234"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
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
			Name:     "https",
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
		},
	}

	resName := state.ResourceNameForGateway(gw.Name)
	controllerTrue := true
	ownerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: &controllerTrue,
	}

	// 1. Simulate pre-upgrade state: Service uses numeric target ports 8000 and 8443
	oldSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            resName,
			Namespace:       "test-ns",
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{
					Name:       "http-80",
					Port:       80,
					TargetPort: intstr.FromInt32(8000),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https-443",
					Port:       443,
					TargetPort: intstr.FromInt32(8443),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
	if err := c.Create(ctx, oldSvc); err != nil {
		t.Fatalf("failed to create old Service: %v", err)
	}

	// 2. Simulate pre-upgrade state: Deployment uses containerPort 8000 for http and probe on 8081
	oldDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            resName,
			Namespace:       "test-ns",
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "dataplane",
							Image: "gari-dataplane:v1",
							Ports: []corev1.ContainerPort{
								{Name: "http", ContainerPort: 8000, Protocol: corev1.ProtocolTCP},
								{Name: "https", ContainerPort: 8443, Protocol: corev1.ProtocolTCP},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstr.FromInt32(8081),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if err := c.Create(ctx, oldDeploy); err != nil {
		t.Fatalf("failed to create old Deployment: %v", err)
	}

	// 3. Reconcile with updated provider
	_, _, err := p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error during reconcile: %v", err)
	}

	// 4. Verify Service updated in place to named target ports
	var updatedSvc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &updatedSvc); err != nil {
		t.Fatalf("failed to get updated Service: %v", err)
	}
	svcPortMap := make(map[string]corev1.ServicePort)
	for _, sp := range updatedSvc.Spec.Ports {
		svcPortMap[sp.Name] = sp
	}

	if sp, ok := svcPortMap["http-80"]; !ok {
		t.Errorf("expected Service port http-80")
	} else if sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal != "http" {
		t.Errorf("expected http-80 targetPort 'http', got %+v", sp.TargetPort)
	}

	if sp, ok := svcPortMap["https-443"]; !ok {
		t.Errorf("expected Service port https-443")
	} else if sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal != "https" {
		t.Errorf("expected https-443 targetPort 'https', got %+v", sp.TargetPort)
	}

	// 5. Verify Deployment updated in place to container port 8080 and readiness probe on 8999
	var updatedDeploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &updatedDeploy); err != nil {
		t.Fatalf("failed to get updated Deployment: %v", err)
	}
	cpMap := make(map[string]corev1.ContainerPort)
	for _, cp := range updatedDeploy.Spec.Template.Spec.Containers[0].Ports {
		cpMap[cp.Name] = cp
	}

	if cp, ok := cpMap["http"]; !ok || cp.ContainerPort != 8080 {
		t.Errorf("expected container port http:8080, got %+v", cpMap["http"])
	}
	if cp, ok := cpMap["https"]; !ok || cp.ContainerPort != 8443 {
		t.Errorf("expected container port https:8443, got %+v", cpMap["https"])
	}

	probe := updatedDeploy.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Port.IntValue() != 8999 {
		t.Errorf("expected readiness probe on port 8999, got %+v", probe)
	}
}

func TestAddressProvider_GcpGatewayHooks(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.Install(scheme)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "my-gw",
			UID:       types.UID("test-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}

	volApply := corev1ac.Volume().WithName("drain-volume").WithEmptyDir(corev1ac.EmptyDirVolumeSource())
	mountApply := corev1ac.VolumeMount().WithName("drain-volume").WithMountPath("/var/run/gcpgateway")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, testBundleConfigMap()).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()

	p := NewAddressProvider(
		c,
		"default",
		WithExtraReadinessGates("gcpgateway.gke-labs.io/load-balancer-ready"),
		WithPreStopCommand("/gcpgateway", "hook", "pre-stop", "--drain-seconds=35"),
		WithExtraVolumes([]*corev1ac.VolumeApplyConfiguration{volApply}, []*corev1ac.VolumeMountApplyConfiguration{mountApply}),
		WithTerminationGracePeriodSeconds(60),
	)

	_, _, err := p.GatewayAddresses(t.Context(), gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resName := state.ResourceNameForGateway("my-gw")
	var deploy appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	podSpec := deploy.Spec.Template.Spec

	// Check terminationGracePeriodSeconds
	if podSpec.TerminationGracePeriodSeconds == nil || *podSpec.TerminationGracePeriodSeconds != 60 {
		t.Errorf("expected TerminationGracePeriodSeconds=60, got %v", podSpec.TerminationGracePeriodSeconds)
	}

	// Check readiness gate
	foundGate := false
	for _, gate := range podSpec.ReadinessGates {
		if string(gate.ConditionType) == "gcpgateway.gke-labs.io/load-balancer-ready" {
			foundGate = true
			break
		}
	}
	if !foundGate {
		t.Errorf("readiness gate gcpgateway.gke-labs.io/load-balancer-ready not found in podSpec: %+v", podSpec.ReadinessGates)
	}

	// Check preStop command
	container := podSpec.Containers[0]
	if container.Lifecycle == nil || container.Lifecycle.PreStop == nil || container.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("expected preStop exec hook on container")
	}
	expectedCmd := []string{"/gcpgateway", "hook", "pre-stop", "--drain-seconds=35"}
	if !slices.Equal(container.Lifecycle.PreStop.Exec.Command, expectedCmd) {
		t.Errorf("expected preStop command %v, got %v", expectedCmd, container.Lifecycle.PreStop.Exec.Command)
	}

	// Check volume mount
	foundMount := false
	for _, m := range container.VolumeMounts {
		if m.Name == "drain-volume" && m.MountPath == "/var/run/gcpgateway" {
			foundMount = true
			break
		}
	}
	if !foundMount {
		t.Errorf("expected volume mount drain-volume at /var/run/gcpgateway")
	}

	// Check args
	argsStr := strings.Join(container.Args, " ")
	if !strings.Contains(argsStr, "--dataplane-mode") {
		t.Errorf("expected --dataplane-mode in args: %s", argsStr)
	}
	if !strings.Contains(argsStr, "--gateway-name=my-gw") {
		t.Errorf("expected --gateway-name in args: %s", argsStr)
	}
}

func TestAddressProvider_DebugErrorResponses(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
			UID:       types.UID("gw-uid-1234"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "default",
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Name:     "http",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Owner:    state.ListenerOwner{Kind: "Gateway", Namespace: "default", Name: "test-gw"},
		},
	}

	// 1. WithDebugErrorResponses(true) adds --debug-error-responses to container args
	{
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, testBundleConfigMap()).Build()
		p := NewAddressProvider(client, "default", WithDebugErrorResponses(true))
		_, _, err := p.GatewayAddresses(t.Context(), gw, effectiveListeners)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		name := state.ResourceNameForGateway("test-gw")
		var deploy appsv1.Deployment
		if err := client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: name}, &deploy); err != nil {
			t.Fatalf("failed to get deployment: %v", err)
		}
		args := deploy.Spec.Template.Spec.Containers[0].Args
		if !slices.Contains(args, "--debug-error-responses") {
			t.Errorf("expected --debug-error-responses in args: %v", args)
		}
	}

	// 2. Default (WithDebugErrorResponses not set or false) does NOT add --debug-error-responses
	{
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, testBundleConfigMap()).Build()
		p := NewAddressProvider(client, "default")
		_, _, err := p.GatewayAddresses(t.Context(), gw, effectiveListeners)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		name := state.ResourceNameForGateway("test-gw")
		var deploy appsv1.Deployment
		if err := client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: name}, &deploy); err != nil {
			t.Fatalf("failed to get deployment: %v", err)
		}
		args := deploy.Spec.Template.Spec.Containers[0].Args
		if slices.Contains(args, "--debug-error-responses") {
			t.Errorf("did not expect --debug-error-responses in args: %v", args)
		}
	}
}

func TestSinglePodAddressProvider_MaximumLengthGatewayName(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme clientgoscheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme gatewayv1: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme rbacv1: %v", err)
	}

	// Create a 253-character Gateway name (max allowed by Kubernetes)
	prefix := "gateway-name-maximum-length-"
	gwName := prefix + strings.Repeat("a", 253-len(prefix))
	if len(gwName) != 253 {
		t.Fatalf("expected gwName length 253, got %d", len(gwName))
	}
	gwNamespace := "default"

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gwName,
			Namespace: gwNamespace,
			UID:       types.UID("test-uid-max-length"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, testBundleConfigMap()).
		Build()

	p := NewAddressProvider(c, "default")

	effectiveListeners := []*state.EffectiveListener{
		{
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		},
	}

	// 1. Reconcile Gateway resources
	_, readiness, err := p.GatewayAddresses(t.Context(), gw, effectiveListeners)
	if err != nil {
		t.Fatalf("GatewayAddresses failed for max length gateway: %v", err)
	}

	expectedName := state.ResourceNameForGateway(gwName)
	expectedLabelGwName := LabelValueForGateway(gwName)

	if len(expectedName) > 63 {
		t.Errorf("expected resource name <= 63, got %d (%q)", len(expectedName), expectedName)
	}
	if len(expectedLabelGwName) > 63 {
		t.Errorf("expected label value <= 63, got %d (%q)", len(expectedLabelGwName), expectedLabelGwName)
	}
	if errs := validation.IsDNS1035Label(expectedName); len(errs) > 0 {
		t.Errorf("expectedName is not a valid DNS-1035 label: %v", errs)
	}
	if errs := validation.IsValidLabelValue(expectedLabelGwName); len(errs) > 0 {
		t.Errorf("expectedLabelGwName is not a valid label value: %v", errs)
	}

	// 2. Verify ServiceAccount exists with valid name
	var sa corev1.ServiceAccount
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &sa); err != nil {
		t.Fatalf("failed to get ServiceAccount %s: %v", expectedName, err)
	}
	if sa.Labels[LabelGatewayName] != expectedLabelGwName {
		t.Errorf("ServiceAccount LabelGatewayName = %q, want %q", sa.Labels[LabelGatewayName], expectedLabelGwName)
	}

	// 3. Verify ConfigMap exists and no Role or RoleBinding exists
	var cm corev1.ConfigMap
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &cm); err != nil {
		t.Fatalf("failed to get ConfigMap %s: %v", expectedName, err)
	}
	if cm.Data[spiffe.BundleDataKey] != "test-trust-bundle-pem" {
		t.Errorf("expected bundle data in ConfigMap %s", expectedName)
	}
	var role rbacv1.Role
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &role); !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to not exist, got: %v", err)
	}
	var rb rbacv1.RoleBinding
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &rb); !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist, got: %v", err)
	}

	// 4. Verify Deployment exists
	var deploy appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment %s: %v", expectedName, err)
	}
	if deploy.Spec.Template.Spec.ServiceAccountName != expectedName {
		t.Errorf("Deployment ServiceAccountName = %q, want %q", deploy.Spec.Template.Spec.ServiceAccountName, expectedName)
	}
	if deploy.Spec.Selector.MatchLabels[LabelGatewayName] != expectedLabelGwName {
		t.Errorf("Deployment selector LabelGatewayName = %q, want %q", deploy.Spec.Selector.MatchLabels[LabelGatewayName], expectedLabelGwName)
	}
	if deploy.Spec.Template.Labels[LabelGatewayName] != expectedLabelGwName {
		t.Errorf("Deployment template LabelGatewayName = %q, want %q", deploy.Spec.Template.Labels[LabelGatewayName], expectedLabelGwName)
	}

	// 5. Verify Service exists
	var svc corev1.Service
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: gwNamespace, Name: expectedName}, &svc); err != nil {
		t.Fatalf("failed to get Service %s: %v", expectedName, err)
	}
	if svc.Spec.Selector[LabelGatewayName] != expectedLabelGwName {
		t.Errorf("Service selector LabelGatewayName = %q, want %q", svc.Spec.Selector[LabelGatewayName], expectedLabelGwName)
	}

	// 6. Verify readiness becomes Programmed once Deployment is ready and Service has LB ingress
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}}
	if err := c.Status().Update(t.Context(), &svc); err != nil {
		t.Fatalf("failed to update Service status: %v", err)
	}
	deploy.Status.AvailableReplicas = 1
	if err := c.Status().Update(t.Context(), &deploy); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}

	finalAddrs, readiness, err := p.GatewayAddresses(t.Context(), gw, effectiveListeners)
	if err != nil {
		t.Fatalf("GatewayAddresses failed: %v", err)
	}
	if !readiness.Ready {
		t.Errorf("expected readiness.Ready = true, got false (reason=%s message=%s)", readiness.Reason, readiness.Message)
	}
	if len(finalAddrs) == 0 || finalAddrs[0].Value != "1.2.3.4" {
		t.Errorf("expected address 1.2.3.4, got %v", finalAddrs)
	}
}

func TestLabelValueForGateway(t *testing.T) {
	// 1. Length 63: fits within label limit, returned unchanged
	name63 := strings.Repeat("a", 63)
	got63 := LabelValueForGateway(name63)
	if got63 != name63 {
		t.Errorf("LabelValueForGateway(63) = %q, want %q", got63, name63)
	}
	if errs := validation.IsValidLabelValue(got63); len(errs) > 0 {
		t.Errorf("invalid label value for 63: %v", errs)
	}

	// 2. Length 64: exceeds 63, returned as 63-character derived resource name
	name64 := strings.Repeat("a", 64)
	got64 := LabelValueForGateway(name64)
	want64 := state.ResourceNameForGateway(name64)
	if got64 != want64 {
		t.Errorf("LabelValueForGateway(64) = %q, want %q", got64, want64)
	}
	if len(got64) != 63 {
		t.Errorf("expected length 63 for 64-char name, got %d", len(got64))
	}
	if errs := validation.IsValidLabelValue(got64); len(errs) > 0 {
		t.Errorf("invalid label value for 64: %v", errs)
	}

	// 3. Length 253: maximum Kubernetes name length, returned as 63-character derived resource name
	name253 := strings.Repeat("a", 253)
	got253 := LabelValueForGateway(name253)
	want253 := state.ResourceNameForGateway(name253)
	if got253 != want253 {
		t.Errorf("LabelValueForGateway(253) = %q, want %q", got253, want253)
	}
	if len(got253) != 63 {
		t.Errorf("expected length 63 for 253-char name, got %d", len(got253))
	}
	if errs := validation.IsValidLabelValue(got253); len(errs) > 0 {
		t.Errorf("invalid label value for 253: %v", errs)
	}

	// 4. Two long names sharing a prefix produce different label values
	t.Run("two long names sharing a prefix produce different label values", func(t *testing.T) {
		sharedPrefix := strings.Repeat("c", 240)
		nameA := sharedPrefix + "1234567890abc"
		nameB := sharedPrefix + "abcdefghijklm"
		labelA := LabelValueForGateway(nameA)
		labelB := LabelValueForGateway(nameB)

		if labelA == labelB {
			t.Errorf("expected distinct label values, got %q == %q", labelA, labelB)
		}
		if len(labelA) > 63 || len(labelB) > 63 {
			t.Errorf("expected label length <= 63, got len(A)=%d, len(B)=%d", len(labelA), len(labelB))
		}
		if errs := validation.IsValidLabelValue(labelA); len(errs) > 0 {
			t.Errorf("invalid label value labelA: %v", errs)
		}
		if errs := validation.IsValidLabelValue(labelB); len(errs) > 0 {
			t.Errorf("invalid label value labelB: %v", errs)
		}
	})
}

func TestSinglePodAddressProvider_GatewayNameWithDots(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("clientgoscheme.AddToScheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1.AddToScheme: %v", err)
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my.gateway", Namespace: "default", UID: "uid-dots"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, testBundleConfigMap()).Build()
	p := NewAddressProvider(c, "default")
	listeners := []*state.EffectiveListener{{Port: 80, Protocol: gatewayv1.HTTPProtocolType}}
	if _, _, err := p.GatewayAddresses(t.Context(), gw, listeners); err != nil {
		t.Fatalf("GatewayAddresses failed: %v", err)
	}

	expectedName := state.ResourceNameForGateway("my.gateway")
	var svc corev1.Service
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: expectedName}, &svc); err != nil {
		t.Fatalf("failed to get Service %s: %v", expectedName, err)
	}
	if errs := validation.IsDNS1035Label(svc.Name); len(errs) > 0 {
		t.Errorf("Service name %q is not a valid DNS-1035 label: %v", svc.Name, errs)
	}
}

func TestSinglePodAddressProvider_HostPorts_DeploymentAndNoService(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithHostPorts())

	if supported := p.SupportedAddressTypes(); supported != nil {
		t.Fatalf("expected SupportedAddressTypes() to be nil with host ports, got %+v", supported)
	}

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

	// 1. Initial reconciliation creates Deployment with host ports, but no Service
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false before pod is running")
	}
	if len(addrs) > 0 {
		t.Errorf("expected no addresses set by this step, got %+v", addrs)
	}

	resName := state.ResourceNameForGateway("gw-hp")

	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	// Verify Deployment uses RollingUpdate strategy with maxSurge: 0 and maxUnavailable: 1
	if deploy.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("expected Deployment strategy RollingUpdate, got %s", deploy.Spec.Strategy.Type)
	}
	if deploy.Spec.Strategy.RollingUpdate == nil {
		t.Fatalf("expected RollingUpdate strategy configuration")
	}
	if deploy.Spec.Strategy.RollingUpdate.MaxSurge == nil || deploy.Spec.Strategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Errorf("expected maxSurge=0, got %v", deploy.Spec.Strategy.RollingUpdate.MaxSurge)
	}
	if deploy.Spec.Strategy.RollingUpdate.MaxUnavailable == nil || deploy.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected maxUnavailable=1, got %v", deploy.Spec.Strategy.RollingUpdate.MaxUnavailable)
	}

	ports := deploy.Spec.Template.Spec.Containers[0].Ports
	portMap := make(map[string]corev1.ContainerPort)
	for _, cp := range ports {
		portMap[fmt.Sprintf("%s/%s", cp.Name, cp.Protocol)] = cp
	}

	// Verify HTTP mapping: containerPort 8080, hostPort 80
	if cp, ok := portMap["http/TCP"]; !ok {
		t.Errorf("missing http/TCP port in container")
	} else if cp.ContainerPort != 8080 || cp.HostPort != 80 {
		t.Errorf("http/TCP: expected containerPort=8080 hostPort=80, got containerPort=%d hostPort=%d", cp.ContainerPort, cp.HostPort)
	}

	// Verify HTTPS TCP mapping: containerPort 8443, hostPort 443
	if cp, ok := portMap["https/TCP"]; !ok {
		t.Errorf("missing https/TCP port in container")
	} else if cp.ContainerPort != 8443 || cp.HostPort != 443 {
		t.Errorf("https/TCP: expected containerPort=8443 hostPort=443, got containerPort=%d hostPort=%d", cp.ContainerPort, cp.HostPort)
	}

	// Verify HTTP/3 UDP mapping: containerPort 8443, hostPort 443
	if cp, ok := portMap["http3/UDP"]; !ok {
		t.Errorf("missing http3/UDP port in container")
	} else if cp.ContainerPort != 8443 || cp.HostPort != 443 {
		t.Errorf("http3/UDP: expected containerPort=8443 hostPort=443, got containerPort=%d hostPort=%d", cp.ContainerPort, cp.HostPort)
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

	// Verify no traffic Service exists
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected Service to not exist, got err: %v", err)
	}

	// When deployment has ready replicas, still reports AddressNotAssigned until address follows the node
	deploy.Status.ReadyReplicas = 1
	if err := c.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update deployment status: %v", err)
	}
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error when deployment is ready: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false until address follows the node, got ready=true")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected reason=AddressNotAssigned, got %s", readiness.Reason)
	}
	if len(addrs) > 0 {
		t.Errorf("expected no addresses set by this step, got %+v", addrs)
	}

	// 2. Switching from Service mode to host-port mode deletes existing owned Service
	pDefault := NewAddressProvider(c, "default")
	_, _, err = pDefault.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error creating Service with default provider: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Fatalf("expected Service to exist after default provider reconcile: %v", err)
	}

	// Reconcile with host-port provider again
	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error with host-port provider: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected existing Service to be deleted when host ports are enabled, got err: %v", err)
	}

	// Verify the existing Deployment was updated to have maxSurge: 0 and maxUnavailable: 1
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment after host-port reconcile: %v", err)
	}
	if deploy.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("expected RollingUpdate strategy after switch, got %s", deploy.Spec.Strategy.Type)
	}
	if deploy.Spec.Strategy.RollingUpdate == nil || deploy.Spec.Strategy.RollingUpdate.MaxSurge == nil || deploy.Spec.Strategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Errorf("expected maxSurge=0 after switch, got %v", deploy.Spec.Strategy.RollingUpdate)
	}
	if deploy.Spec.Strategy.RollingUpdate == nil || deploy.Spec.Strategy.RollingUpdate.MaxUnavailable == nil || deploy.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected maxUnavailable=1 after switch, got %v", deploy.Spec.Strategy.RollingUpdate)
	}
}

func TestSinglePodAddressProvider_HostPorts_MultipleHTTPListenersConflict(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithHostPorts())

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-two-http",
			Namespace: "test-ns",
			UID:       types.UID("gw-two-http-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http-80", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "http-8081", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
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
	if len(addrs) > 0 {
		t.Errorf("expected no addresses, got %+v", addrs)
	}

	// Verify no Deployment was created for the invalid listener configuration
	var deploy appsv1.Deployment
	resName := state.ResourceNameForGateway("gw-two-http")
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); !apierrors.IsNotFound(err) {
		t.Errorf("expected Deployment to not exist for invalid configuration, got err: %v", err)
	}
}

func TestSinglePodAddressProvider_HostPorts_MultipleHTTPSListenersConflict(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithHostPorts())

	gw := &gatewayv1.Gateway{
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

	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
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
	if len(addrs) > 0 {
		t.Errorf("expected no addresses, got %+v", addrs)
	}
}

func TestSinglePodAddressProvider_HostPorts_ReservedPortsSkipped(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithHostPorts())

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

	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var deploy appsv1.Deployment
	resName := state.ResourceNameForGateway("gw-reserved")
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	// Only port 80 should be in container ports; 8080 TCP, 8443 UDP, and 8999 TCP should be skipped
	ports := deploy.Spec.Template.Spec.Containers[0].Ports
	if len(ports) != 1 {
		t.Fatalf("expected exactly 1 container port (port 80), got %d: %+v", len(ports), ports)
	}
	if ports[0].HostPort != 80 || ports[0].ContainerPort != 8080 {
		t.Errorf("expected port 80 mapping, got %+v", ports[0])
	}
}

func TestSinglePodAddressProvider_WithNoService(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c, "default", WithNoService())

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-no-svc",
			Namespace: "test-ns",
			UID:       types.UID("gw-no-svc-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
			},
		},
	}

	// 1. Initial reconcile creates Deployment and no Service.
	addrs, readiness, err := p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false when deployment has no ready replicas")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected reason=AddressNotAssigned, got %s", readiness.Reason)
	}
	if len(addrs) > 0 {
		t.Errorf("expected no addresses, got %+v", addrs)
	}

	resName := state.ResourceNameForGateway("gw-no-svc")

	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected Service to not exist with WithNoService(), got err: %v", err)
	}

	// 2. When deployment has ready replicas, still reports AddressNotAssigned with no Service addresses
	deploy.Status.ReadyReplicas = 1
	if err := c.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update deployment status: %v", err)
	}
	addrs, readiness, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error when deployment ready: %v", err)
	}
	if readiness.Ready {
		t.Errorf("expected ready=false because no Service exists to supply addresses")
	}
	if readiness.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected reason=AddressNotAssigned, got %s", readiness.Reason)
	}
	if readiness.Message != "Waiting for address to be assigned to the Gateway" {
		t.Errorf("expected message 'Waiting for address to be assigned to the Gateway', got %q", readiness.Message)
	}
	if len(addrs) > 0 {
		t.Errorf("expected no addresses, got %+v", addrs)
	}

	// 3. Pre-existing Service is not deleted when reconciling with WithNoService()
	existingSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resName,
			Namespace: "test-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1.GroupVersion.String(),
					Kind:       "Gateway",
					Name:       gw.Name,
					UID:        gw.UID,
					Controller: state.Ptr(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
			},
		},
	}
	if err := c.Create(ctx, existingSvc); err != nil {
		t.Fatalf("failed to create existing Service: %v", err)
	}

	// Reconcile with WithNoService() provider again
	_, _, err = p.GatewayAddresses(ctx, gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify existing Service is STILL present (not deleted)
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); err != nil {
		t.Errorf("expected existing Service to remain untouched (not deleted) with WithNoService(), got err: %v", err)
	}
}

func TestSinglePodAddressProvider_WithDeploymentMutator(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()

	var passedGw *gatewayv1.Gateway
	var passedListeners []*state.EffectiveListener
	mutatorCalled := false

	mutator := func(deployment *appsv1ac.DeploymentApplyConfiguration, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error {
		mutatorCalled = true
		passedGw = gw
		passedListeners = effectiveListeners

		// Change rollout strategy to RollingUpdate with maxSurge: 0, maxUnavailable: 1
		deployment.Spec.WithStrategy(appsv1ac.DeploymentStrategy().
			WithType(appsv1.RollingUpdateDeploymentStrategyType).
			WithRollingUpdate(appsv1ac.RollingUpdateDeployment().
				WithMaxSurge(intstr.FromInt32(0)).
				WithMaxUnavailable(intstr.FromInt32(1)),
			),
		)

		// Add custom container port
		deployment.Spec.Template.Spec.Containers[0].WithPorts(
			corev1ac.ContainerPort().
				WithName("custom-port").
				WithContainerPort(9090).
				WithProtocol(corev1.ProtocolTCP),
		)
		return nil
	}

	p := NewAddressProvider(c, "default", WithDeploymentMutator(mutator))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-mutated",
			Namespace: "test-ns",
			UID:       types.UID("gw-mutated-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	listeners := []*state.EffectiveListener{
		{
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
		},
	}

	_, _, err := p.GatewayAddresses(ctx, gw, listeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mutatorCalled {
		t.Fatalf("expected mutator to be called")
	}
	if passedGw != gw {
		t.Errorf("expected mutator to receive Gateway, got %+v", passedGw)
	}
	if len(passedListeners) != 1 || passedListeners[0].Port != 80 {
		t.Errorf("expected mutator to receive effective listeners, got %+v", passedListeners)
	}

	resName := state.ResourceNameForGateway("gw-mutated")
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); err != nil {
		t.Fatalf("failed to get Deployment: %v", err)
	}

	// Verify rollout strategy was updated by the mutator
	if deploy.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("expected RollingUpdate strategy, got %s", deploy.Spec.Strategy.Type)
	}
	if deploy.Spec.Strategy.RollingUpdate == nil {
		t.Fatalf("expected RollingUpdate configuration")
	}
	if deploy.Spec.Strategy.RollingUpdate.MaxSurge == nil || deploy.Spec.Strategy.RollingUpdate.MaxSurge.IntValue() != 0 {
		t.Errorf("expected maxSurge=0, got %v", deploy.Spec.Strategy.RollingUpdate.MaxSurge)
	}
	if deploy.Spec.Strategy.RollingUpdate.MaxUnavailable == nil || deploy.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Errorf("expected maxUnavailable=1, got %v", deploy.Spec.Strategy.RollingUpdate.MaxUnavailable)
	}

	// Verify container port was added by the mutator
	ports := deploy.Spec.Template.Spec.Containers[0].Ports
	foundCustom := false
	for _, port := range ports {
		if port.Name == "custom-port" {
			foundCustom = true
			if port.ContainerPort != 9090 {
				t.Errorf("expected containerPort=9090, got %d", port.ContainerPort)
			}
			if port.Protocol != corev1.ProtocolTCP {
				t.Errorf("expected protocol TCP, got %s", port.Protocol)
			}
		}
	}
	if !foundCustom {
		t.Errorf("expected custom-port container port to be present in applied Deployment, got ports: %+v", ports)
	}
}

func TestSinglePodAddressProvider_WithDeploymentMutator_Error(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()

	expectedErr := errors.New("boom: mutator failed")
	mutator := func(deployment *appsv1ac.DeploymentApplyConfiguration, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error {
		return expectedErr
	}

	p := NewAddressProvider(c, "default", WithDeploymentMutator(mutator))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-mut-err",
			Namespace: "test-ns",
			UID:       types.UID("gw-mut-err-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	// Reconcile via GatewayAddresses
	_, _, err := p.GatewayAddresses(ctx, gw, nil)
	if err == nil {
		t.Fatalf("expected error from mutator, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}

	// Deployment must not have been applied
	resName := state.ResourceNameForGateway("gw-mut-err")
	var deploy appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &deploy); !apierrors.IsNotFound(err) {
		t.Errorf("expected Deployment to not exist after mutator error, got err: %v", err)
	}

	// Service must not have been applied
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: resName}, &svc); !apierrors.IsNotFound(err) {
		t.Errorf("expected Service to not exist after mutator error, got err: %v", err)
	}
}

func TestSinglePodAddressProvider_DataplaneConfigFromInternalAPI(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("clientgoscheme.AddToScheme failed: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1.AddToScheme failed: %v", err)
	}

	tests := []struct {
		name                string
		controllerNamespace string
		sourceBundleData    map[string]string
		omitSourceBundle    bool
		wantErrSubstring    string
		verify              func(t *testing.T, c client.Client, p *AddressProvider, gw *gatewayv1.Gateway, resName string)
	}{
		{
			name:                "enabled_copies_bundle_and_provisions_internal_api_flags",
			controllerNamespace: "default",
			sourceBundleData:    map[string]string{spiffe.BundleDataKey: "test-trust-bundle-pem"},
			verify: func(t *testing.T, c client.Client, p *AddressProvider, gw *gatewayv1.Gateway, resName string) {
				ctx := t.Context()

				// 1. Destination ConfigMap copied to Gateway namespace with bundle data
				var destinationConfigMap corev1.ConfigMap
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &destinationConfigMap); err != nil {
					t.Fatalf("failed to get destination bundle ConfigMap: %v", err)
				}
				if destinationConfigMap.Data[spiffe.BundleDataKey] != "test-trust-bundle-pem" {
					t.Errorf("expected bundle data %q, got %q", "test-trust-bundle-pem", destinationConfigMap.Data[spiffe.BundleDataKey])
				}
				if len(destinationConfigMap.OwnerReferences) == 0 || destinationConfigMap.OwnerReferences[0].UID != gw.UID {
					t.Errorf("expected destination bundle ConfigMap to be owned by Gateway %v, got %v", gw.UID, destinationConfigMap.OwnerReferences)
				}

				// 2. Role and RoleBinding are skipped, and no Secret is created
				var role rbacv1.Role
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &role); !apierrors.IsNotFound(err) {
					t.Errorf("expected Role to not exist when internal API is enabled, got err: %v", err)
				}
				var roleBinding rbacv1.RoleBinding
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &roleBinding); !apierrors.IsNotFound(err) {
					t.Errorf("expected RoleBinding to not exist when internal API is enabled, got err: %v", err)
				}
				var sec corev1.Secret
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &sec); !apierrors.IsNotFound(err) {
					t.Errorf("expected Secret to not exist when internal API is enabled, got err: %v", err)
				}

				// 3. Deployment has internal API flags, bundle volume, and projected token volume
				var deploy appsv1.Deployment
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
					t.Fatalf("failed to get Deployment: %v", err)
				}
				container := deploy.Spec.Template.Spec.Containers[0]

				expectedAddrFlag := fmt.Sprintf("--internal-api-address=%s.default.svc.cluster.local:%d", spiffe.ControllerServiceName, push.InternalAPIPort)
				expectedCAFlag := "--internal-api-ca-file=/etc/gari/bundle/" + spiffe.BundleDataKey
				expectedTokenFlag := "--internal-api-token-file=/var/run/secrets/tokens/internal-api/token"

				if !slices.Contains(container.Args, expectedAddrFlag) {
					t.Errorf("expected args to contain %q, got: %v", expectedAddrFlag, container.Args)
				}
				if !slices.Contains(container.Args, expectedCAFlag) {
					t.Errorf("expected args to contain %q, got: %v", expectedCAFlag, container.Args)
				}
				if !slices.Contains(container.Args, expectedTokenFlag) {
					t.Errorf("expected args to contain %q, got: %v", expectedTokenFlag, container.Args)
				}

				// Check bundle volume mount
				var hasBundleMount, hasTokenMount bool
				for _, vm := range container.VolumeMounts {
					if vm.Name == "internal-api-bundle" && vm.MountPath == "/etc/gari/bundle" && vm.ReadOnly {
						hasBundleMount = true
					}
					if vm.Name == "internal-api-token" && vm.MountPath == "/var/run/secrets/tokens/internal-api" && vm.ReadOnly {
						hasTokenMount = true
					}
				}
				if !hasBundleMount {
					t.Errorf("expected read-only bundle volume mount at /etc/gari/bundle")
				}
				if !hasTokenMount {
					t.Errorf("expected read-only token volume mount at /var/run/secrets/tokens/internal-api")
				}

				// Check volumes
				var hasBundleVol, hasTokenVol bool
				for _, v := range deploy.Spec.Template.Spec.Volumes {
					if v.Name == "certserver-token" {
						t.Errorf("unexpected certserver-token volume on data-plane pod")
					}
					if v.Name == "internal-api-bundle" && v.ConfigMap != nil && v.ConfigMap.Name == resName {
						hasBundleVol = true
					}
					if v.Name == "internal-api-token" && v.Projected != nil {
						for _, src := range v.Projected.Sources {
							if src.ServiceAccountToken != nil && src.ServiceAccountToken.Audience == push.DefaultAudience &&
								src.ServiceAccountToken.ExpirationSeconds != nil && *src.ServiceAccountToken.ExpirationSeconds == 3600 &&
								src.ServiceAccountToken.Path == "token" {
								hasTokenVol = true
							}
						}
					}
				}
				if !hasBundleVol {
					t.Errorf("expected internal-api-bundle volume backed by ConfigMap %q", resName)
				}
				if !hasTokenVol {
					t.Errorf("expected internal-api-token projected volume with audience %q", push.DefaultAudience)
				}
			},
		},
		{
			name:                "missing_source_bundle_returns_error",
			controllerNamespace: "default",
			omitSourceBundle:    true,
			wantErrSubstring:    "reading bundle configmap",
		},
		{
			name:                "missing_bundle_key",
			controllerNamespace: "default",
			sourceBundleData:    map[string]string{"other-key": "some-val"},
			wantErrSubstring:    "missing key bundle.pem",
		},
		{
			name:                "enabled_custom_controller_namespace",
			controllerNamespace: "custom-ctrl-ns",
			sourceBundleData:    map[string]string{spiffe.BundleDataKey: "custom-bundle-pem"},
			verify: func(t *testing.T, c client.Client, p *AddressProvider, gw *gatewayv1.Gateway, resName string) {
				ctx := t.Context()
				var deploy appsv1.Deployment
				if err := c.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err != nil {
					t.Fatalf("failed to get Deployment: %v", err)
				}
				expectedAddrFlag := fmt.Sprintf("--internal-api-address=%s.custom-ctrl-ns.svc.cluster.local:%d", spiffe.ControllerServiceName, push.InternalAPIPort)
				if !slices.Contains(deploy.Spec.Template.Spec.Containers[0].Args, expectedAddrFlag) {
					t.Errorf("expected args to contain %q, got: %v", expectedAddrFlag, deploy.Spec.Template.Spec.Containers[0].Args)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "gw-ns",
					Name:      "test-gw",
					UID:       types.UID("gw-uid-1234"),
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "gari",
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			}

			var objs []client.Object
			objs = append(objs, gw)

			if !tc.omitSourceBundle && tc.controllerNamespace != "" {
				bundleData := tc.sourceBundleData
				if bundleData == nil {
					bundleData = map[string]string{spiffe.BundleDataKey: "test-bundle"}
				}
				sourceCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: tc.controllerNamespace,
						Name:      spiffe.BundleConfigMapName,
					},
					Data: bundleData,
				}
				objs = append(objs, sourceCM)
			}

			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

			p := NewAddressProvider(c, tc.controllerNamespace)

			_, _, err := p.GatewayAddresses(ctx, gw, nil)
			if tc.wantErrSubstring != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSubstring)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErrSubstring, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("GatewayAddresses failed unexpectedly: %v", err)
			}
			if tc.verify != nil {
				tc.verify(t, c, p, gw, state.ResourceNameForGateway(gw.Name))
			}
		})
	}
}
