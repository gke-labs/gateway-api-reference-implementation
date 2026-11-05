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
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSinglePodAddressProvider_CleanupOldNamedResources(t *testing.T) {
	env := testenv.Start(t)
	ctx := t.Context()

	const (
		nsName  = "test-cleanup"
		gwName  = "test-gw"
		oldName = "test-gw-dataplane"
	)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	if err := env.Client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: controller.DefaultControllerName},
	}
	if err := env.Client.Create(ctx, gc); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create GatewayClass: %v", err)
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: nsName},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cleanup-class",
			Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	}
	if err := env.Client.Create(ctx, gw); err != nil {
		t.Fatalf("failed to create Gateway: %v", err)
	}

	currentName := ResourceNameForGateway(gw.Name)
	provLabels := map[string]string{LabelAppName: AppNameValue, LabelManagedBy: ManagedByValue}
	trueVal := true
	ownerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: &trueVal,
	}

	oldObjects := []client.Object{
		&corev1.ServiceAccount{},
		&rbacv1.Role{Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}},
		&rbacv1.RoleBinding{
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: oldName},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: oldName, Namespace: nsName}},
		},
		&appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: provLabels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: provLabels},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img"}}},
				},
			},
		},
		&corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}}},
		&corev1.Secret{},
	}
	for _, obj := range oldObjects {
		obj.SetName(oldName)
		obj.SetNamespace(nsName)
		obj.SetLabels(provLabels)
		obj.SetOwnerReferences([]metav1.OwnerReference{ownerRef})
		if err := env.Client.Create(ctx, obj); err != nil {
			t.Fatalf("failed to create old %T: %v", obj, err)
		}
	}

	unrelated := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: nsName, Labels: provLabels},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}},
	}
	if err := env.Client.Create(ctx, unrelated); err != nil {
		t.Fatalf("failed to create unrelated Service: %v", err)
	}

	st := state.NewState()
	st.SetControllerName(controller.DefaultControllerName)
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.Recompute()

	p := NewAddressProvider(env.Client, WithState(st))
	r := &controller.GatewayReconciler{
		Client:          env.Client,
		Scheme:          env.Scheme,
		State:           st,
		ControllerName:  controller.DefaultControllerName,
		AddressProvider: p,
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: nsName, Name: gw.Name}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("initial Reconcile failed: %v", err)
	}

	for _, obj := range oldObjects {
		if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: oldName}, obj); err != nil {
			t.Errorf("expected old %T %q to still exist before new data plane is ready, got: %v", obj, oldName, err)
		}
	}

	var deploy appsv1.Deployment
	if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: currentName}, &deploy); err != nil {
		t.Fatalf("failed to get current Deployment: %v", err)
	}
	deploy.Status.Replicas = 1
	deploy.Status.ReadyReplicas = 1
	deploy.Status.AvailableReplicas = 1
	if err := env.Client.Status().Update(ctx, &deploy); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}

	var svc corev1.Service
	if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: currentName}, &svc); err != nil {
		t.Fatalf("failed to get current Service: %v", err)
	}
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}}
	if err := env.Client.Status().Update(ctx, &svc); err != nil {
		t.Fatalf("failed to update Service status: %v", err)
	}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}

	for _, obj := range []client.Object{&corev1.ServiceAccount{}, &rbacv1.Role{}, &rbacv1.RoleBinding{}, &appsv1.Deployment{}, &corev1.Service{}} {
		if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: currentName}, obj); err != nil {
			t.Errorf("expected current %T %q to exist: %v", obj, currentName, err)
		}
	}
	for _, obj := range oldObjects {
		if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: oldName}, obj); !apierrors.IsNotFound(err) {
			t.Errorf("expected old %T %q to be deleted, got: %v", obj, oldName, err)
		}
	}
	if err := env.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: "unrelated"}, &corev1.Service{}); err != nil {
		t.Errorf("expected unrelated Service to remain: %v", err)
	}
}
