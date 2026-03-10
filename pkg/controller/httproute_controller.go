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
	"reflect"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type HTTPRouteReconciler struct {
	GatewayControllerOptions
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	route := &gatewayv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteHTTPRoute(req.NamespacedName)
			r.UpdateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If the route is not accepted, we still update the state but it won't be used for proxying
	validationCondition := r.State.UpsertHTTPRoute(route)

	// In operator mode, we don't update HTTPRoute status.
	// The gari-gateway instances for each Gateway update their respective status entry.
	if r.Proxy == nil {
		r.UpdateProxy()
		return ctrl.Result{}, nil
	}

	// Gateway mode: Update status for our Gateway and update proxy config
	gateways := r.State.GetGateways()
	rs := state.HTTPRouteState{HTTPRoute: route}

	// We only manage ParentStatus entries that refer to our Gateway
	var ourParentStatus *gatewayv1.RouteParentStatus
	for _, parentRef := range route.Spec.ParentRefs {
		if string(parentRef.Name) == r.GatewayName && (parentRef.Namespace == nil || string(*parentRef.Namespace) == r.GatewayNamespace) {
			acceptedCondition := validationCondition
			if acceptedCondition.Status == metav1.ConditionTrue {
				acceptedCondition = rs.ComputeAcceptedCondition(parentRef, gateways)
			}

			ourParentStatus = &gatewayv1.RouteParentStatus{
				ParentRef:      parentRef,
				ControllerName: ControllerName,
				Conditions: []metav1.Condition{
					acceptedCondition,
					rs.ComputeResolvedRefsCondition(),
				},
			}
			break
		}
	}

	if ourParentStatus != nil {
		// Update the status by merging our entry with existing ones
		updated := false
		newParents := make([]gatewayv1.RouteParentStatus, 0, len(route.Status.Parents))
		found := false
		for _, p := range route.Status.Parents {
			if string(p.ParentRef.Name) == r.GatewayName && (p.ParentRef.Namespace == nil || string(*p.ParentRef.Namespace) == r.GatewayNamespace) {
				if !reflect.DeepEqual(p, *ourParentStatus) {
					newParents = append(newParents, *ourParentStatus)
					updated = true
				} else {
					newParents = append(newParents, p)
				}
				found = true
			} else {
				newParents = append(newParents, p)
			}
		}
		if !found {
			newParents = append(newParents, *ourParentStatus)
			updated = true
		}

		if updated {
			// Using Update for now as in the rest of the project, but merging manually to avoid clobbering
			route.Status.Parents = newParents
			if err := r.Status().Update(ctx, route); err != nil {
				l.Error(err, "unable to update HTTPRoute status")
				return ctrl.Result{}, err
			}
		}
	}

	r.State.UpsertHTTPRoute(route)
	r.UpdateProxy()

	l.Info("Updated HTTPRoute status and proxy")

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Complete(r)
}
