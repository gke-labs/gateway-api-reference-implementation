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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type ConfigMapReconciler struct {
	GatewayControllerOptions
}

func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteConfigMap(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	r.State.UpsertConfigMap(cm)
	r.updateProxy()

	l.Info("Updated ConfigMap in state")

	return ctrl.Result{}, nil
}

func (r *ConfigMapReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy)
}

func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Watches(&gatewayv1.BackendTLSPolicy{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			// This is actually backwards, we want to reconcile BackendTLSPolicy when ConfigMap changes.
			// But since we are in ConfigMapReconciler, we want to trigger BackendTLSPolicy reconciles.
			// Actually, it's easier to just make BackendTLSPolicy watch ConfigMaps.
			return nil
		})).
		Complete(r)
}
