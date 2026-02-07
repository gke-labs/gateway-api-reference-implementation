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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type GatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, req.NamespacedName, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if gc.Spec.ControllerName != ControllerName {
		return ctrl.Result{}, nil
	}

	// Update status to Accepted
	gc.Status.Conditions = []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gc.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            "GatewayClass accepted by reference implementation",
		},
	}

	if err := r.Status().Update(ctx, &gc); err != nil {
		l.Error(err, "unable to update GatewayClass status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Complete(r)
}

type GatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var gw gatewayv1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the GatewayClass is managed by us
	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, &gc); err != nil {
		l.Error(err, "unable to fetch GatewayClass", "gatewayclass", gw.Spec.GatewayClassName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if gc.Spec.ControllerName != ControllerName {
		return ctrl.Result{}, nil
	}

	// Find the LoadBalancer IP of the gari-proxy service
	var svc corev1.Service
	if err := r.Get(ctx, client.ObjectKey{Name: "gari-proxy", Namespace: "default"}, &svc); err != nil {
		l.Error(err, "unable to fetch gari-proxy service")
		return ctrl.Result{}, err
	}

	var ip string
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		ip = svc.Status.LoadBalancer.Ingress[0].IP
	}

	if ip == "" {
		l.Info("gari-proxy service has no LoadBalancer IP yet")
		return ctrl.Result{Requeue: true}, nil
	}

	// Update status to Programmed and add address
	gw.Status.Conditions = []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             string(gatewayv1.GatewayReasonProgrammed),
			Message:            "Gateway programmed by reference implementation",
		},
		{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             string(gatewayv1.GatewayReasonAccepted),
			Message:            "Gateway accepted by reference implementation",
		},
	}
	gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{
		{
			Type:  ptr(gatewayv1.IPAddressType),
			Value: ip,
		},
	}

	if err := r.Status().Update(ctx, &gw); err != nil {
		l.Error(err, "unable to update Gateway status")
		return ctrl.Result{}, err
	}

	l.Info("Updated Gateway status", "address", ip)

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Complete(r)
}
