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
	"maps"
	"reflect"
	"sync"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
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

func TestSinglePodAddressProvider_GatewayAddresses(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
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
					"gateway.networking.k8s.io/gateway-name": "malicious-name",
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

	p := NewAddressProvider(client, WithEnableH2C(true))

	// 1. Initial reconcile creates SA, adds to CRB, creates Deployment and Service in my-ns, but no Ingress and replicas not ready yet
	addrs, ready, err := p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses before LB ingress is assigned, got %d", len(addrs))
	}
	if ready {
		t.Fatalf("expected ready=false before deployment replicas become available")
	}

	// Verify Service was created in my-ns with all effective listener ports (including ListenerSet port 8080)
	name := ResourceNameForGateway("my-gw")
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

	// Verify Role was created in my-ns
	var role rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &role); err != nil {
		t.Fatalf("failed to get created Role: %v", err)
	}
	if role.Labels["custom-label"] != "custom-val" {
		t.Errorf("expected custom-label on Role, got %s", role.Labels["custom-label"])
	}
	if len(role.Rules) != 1 || role.Rules[0].Resources[0] != "secrets" || role.Rules[0].ResourceNames[0] != name {
		t.Errorf("expected Role rule to permit secrets/%s, got %+v", name, role.Rules)
	}

	// Verify RoleBinding was created in my-ns
	var rb rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &rb); err != nil {
		t.Fatalf("failed to get created RoleBinding: %v", err)
	}
	if rb.RoleRef.Name != name {
		t.Errorf("expected RoleBinding roleRef %s, got %s", name, rb.RoleRef.Name)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != name || rb.Subjects[0].Namespace != "my-ns" {
		t.Errorf("expected RoleBinding subject to be SA %s in my-ns, got %+v", name, rb.Subjects)
	}

	// Verify Secret is NOT created by GatewayAddresses (placeholder secrets are not created;
	// config secret is created only when real config is published).
	var sec corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &sec); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret to not exist before publish, got: %v", err)
	}

	// Publish DataplaneConfig -> Secret is created
	dpCfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "my-ns", Name: "my-gw"},
	}
	if err := p.PublishDataplaneConfig(ctx, gw, dpCfg); err != nil {
		t.Fatalf("failed to publish config: %v", err)
	}
	if err := client.Get(ctx, types.NamespacedName{Namespace: "my-ns", Name: name}, &sec); err != nil {
		t.Fatalf("failed to get created Secret: %v", err)
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
	addrs, ready, err = p.GatewayAddresses(ctx, gw, effectiveListeners)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ready {
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

	// 4. Delete Gateway -> cleans up resources
	// (Namespaced resources have controller ownerReferences verified in step 1 and are deleted by k8s garbage collector)
	gwKey := types.NamespacedName{Namespace: "my-ns", Name: "my-gw"}
	if err := p.OnGatewayDeleted(ctx, gwKey); err != nil {
		t.Fatalf("OnGatewayDeleted failed: %v", err)
	}
}

func TestSinglePodAddressProvider_NamespacedRolesAndSecrets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	p := NewAddressProvider(client)
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

	// Verify ns-1 has Role, RoleBinding
	var role1 rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: "gw-1-gari"}, &role1); err != nil {
		t.Fatalf("failed to get Role for gw-1: %v", err)
	}
	var rb1 rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: "gw-1-gari"}, &rb1); err != nil {
		t.Fatalf("failed to get RoleBinding for gw-1: %v", err)
	}
	var sec1 corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: "gw-1-gari"}, &sec1); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret for gw-1 to not exist before publish, got: %v", err)
	}

	// Verify ns-2 has Role, RoleBinding
	var role2 rbacv1.Role
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: "gw-2-gari"}, &role2); err != nil {
		t.Fatalf("failed to get Role for gw-2: %v", err)
	}
	var rb2 rbacv1.RoleBinding
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: "gw-2-gari"}, &rb2); err != nil {
		t.Fatalf("failed to get RoleBinding for gw-2: %v", err)
	}
	var sec2 corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-2", Name: "gw-2-gari"}, &sec2); !apierrors.IsNotFound(err) {
		t.Fatalf("expected Secret for gw-2 to not exist before publish, got: %v", err)
	}

	// Publish DataplaneConfig for gw1
	dpCfg := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "ns-1", Name: "gw-1"},
		Routes: []state.InternalRoute{
			{Hostnames: []string{"test.com"}},
		},
	}
	if err := p.PublishDataplaneConfig(ctx, gw1, dpCfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{Namespace: "ns-1", Name: "gw-1-gari"}, &sec1); err != nil {
		t.Fatalf("failed to get updated Secret for gw-1: %v", err)
	}
	unmarshaled, err := state.UnmarshalDataplaneConfig(sec1.Data[DataplaneSecretDataKey])
	if err != nil {
		t.Fatalf("failed to unmarshal published config: %v", err)
	}
	if len(unmarshaled.Routes) != 1 || unmarshaled.Routes[0].Hostnames[0] != "test.com" {
		t.Errorf("unexpected published config: %+v", unmarshaled)
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
	resName := ResourceNameForGateway("conflict-gw")

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
			name: "role with managed labels and ownerRef with different UID",
			object: &rbacv1.Role{
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
			name: "rolebinding with managed labels and ownerRef with different UID",
			object: &rbacv1.RoleBinding{
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
			name: "secret with managed labels and ownerRef with different UID",
			object: &corev1.Secret{
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
				WithObjects(tc.object).
				Build()

			p := NewAddressProvider(cl)
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
			Name:            ResourceNameForGateway("gw-1"),
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
			Name:            ResourceNameForGateway("gw-1"),
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
			Name:      ResourceNameForGateway("gw-1"),
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
			Name:      ResourceNameForGateway("gw-1"),
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
			Name:            ResourceNameForGateway("gw-1"),
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

func setupTestClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithReturnManagedFields().
		WithInterceptorFuncs(ssaNoOpInterceptor()).
		Build()
}

func TestSinglePodAddressProvider_InfrastructureLabelsAndAnnotationsLandOnAllFour(t *testing.T) {
	c := setupTestClient(t)
	ctx := t.Context()
	p := NewAddressProvider(c)

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

	resName := ResourceNameForGateway("test-gw")

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
	p := NewAddressProvider(c)

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

	resName := ResourceNameForGateway("test-gw")

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
	p := NewAddressProvider(c)

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

	resName := ResourceNameForGateway("test-gw")

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
	p := NewAddressProvider(c)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("gw-uid-1"),
		},
		Spec: gatewayv1.GatewaySpec{
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
					"gateway.networking.k8s.io/gateway-name":      "override-name",
					"gateway.networking.k8s.io/gateway-namespace": "override-ns",
					"gateway.networking.k8s.io/custom-reserved":   "malicious-val",
					"app.kubernetes.io/managed-by":                "override-managed-by",
					"app.kubernetes.io/name":                      "override-name",
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

	resName := ResourceNameForGateway("test-gw")

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
	p := NewAddressProvider(c)

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

	resName := ResourceNameForGateway("test-gw")

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
	p := NewAddressProvider(c)

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

	resName := ResourceNameForGateway("test-gw")

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
