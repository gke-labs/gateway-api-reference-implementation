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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type HTTPRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	State  *state.State
	Proxy  *proxy.Proxy
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	route := &gatewayv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteHTTPRoute(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If the route is not accepted, we still update the state but it won't be used for proxying
	validationCondition := r.State.UpsertHTTPRoute(route)

	// Update status
	// For each parentRef, we should add a ParentStatus
	gateways := r.State.GetGateways()
	rs := state.HTTPRouteState{HTTPRoute: route}

	var newParents []gatewayv1.RouteParentStatus
	for _, parentRef := range route.Spec.ParentRefs {
		acceptedCondition := validationCondition
		if acceptedCondition.Status == metav1.ConditionTrue {
			acceptedCondition = rs.ComputeAcceptedCondition(parentRef, gateways)
		}

		newParents = append(newParents, gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: ControllerName,
			Conditions: []metav1.Condition{
				acceptedCondition,
				rs.ComputeResolvedRefsCondition(),
			},
		})
	}

	updated := false
	if len(route.Status.Parents) != len(newParents) {
		updated = true
	} else {
		for i := range newParents {
			if !reflect.DeepEqual(route.Status.Parents[i].ParentRef, newParents[i].ParentRef) ||
				string(route.Status.Parents[i].ControllerName) != string(newParents[i].ControllerName) ||
				len(route.Status.Parents[i].Conditions) != len(newParents[i].Conditions) {
				updated = true
				break
			}
			for j := range newParents[i].Conditions {
				matched := false
				for k := range route.Status.Parents[i].Conditions {
					if route.Status.Parents[i].Conditions[k].Type == newParents[i].Conditions[j].Type {
						if route.Status.Parents[i].Conditions[k].Status == newParents[i].Conditions[j].Status &&
							route.Status.Parents[i].Conditions[k].ObservedGeneration == newParents[i].Conditions[j].ObservedGeneration &&
							route.Status.Parents[i].Conditions[k].Reason == newParents[i].Conditions[j].Reason &&
							route.Status.Parents[i].Conditions[k].Message == newParents[i].Conditions[j].Message {
							matched = true
						}
						break
					}
				}
				if !matched {
					updated = true
					break
				}
			}
			if updated {
				break
			}
		}
	}

	if updated {
		route.Status.Parents = newParents
		if err := r.Status().Update(ctx, route); err != nil {
			l.Error(err, "unable to update HTTPRoute status")
			return ctrl.Result{}, err
		}
	}

	r.State.UpsertHTTPRoute(route)
	r.updateProxy()

	l.Info("Updated HTTPRoute status and proxy")

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy)
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Complete(r)
}
