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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type HTTPRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Proxy  *proxy.Proxy
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var routes gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routes); err != nil {
		return ctrl.Result{}, err
	}

	newRoutes := r.extractRoutes(&routes)

	r.Proxy.UpdateRoutes(newRoutes)
	l.Info("Updated proxy routes", "count", len(newRoutes))

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) extractRoutes(routes *gatewayv1.HTTPRouteList) map[string]proxy.Backend {
	newRoutes := make(map[string]proxy.Backend)
	for _, route := range routes.Items {
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				if backendRef.Kind != nil && *backendRef.Kind != "Service" {
					continue
				}

				// For minimal implementation, we just take the first Service backendRef
				// and map all hostnames of this route to it.
				if backendRef.Port == nil {
					continue
				}

				backend := proxy.Backend{
					Host: string(backendRef.Name),
					Port: int32(*backendRef.Port),
				}

				for _, hostname := range route.Spec.Hostnames {
					newRoutes[string(hostname)] = backend
				}

				// Just take the first one for now as per "minimal"
				break
			}
			// Just take the first rule for now
			break
		}
	}
	return newRoutes
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Complete(r)
}
