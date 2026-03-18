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

type GRPCRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	State  *state.State
	Proxy  *proxy.Proxy
}

func (r *GRPCRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	route := &gatewayv1.GRPCRoute{}
	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteGRPCRoute(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If the route is not accepted, we still update the state but it won't be used for proxying
	validationCondition := r.State.UpsertGRPCRoute(route)

	// Update status
	// For each parentRef, we should add a ParentStatus
	gateways := r.State.GetGateways()
	rs := state.GRPCRouteState{GRPCRoute: route}

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
		for _, np := range newParents {
			found := false
			for _, op := range route.Status.Parents {
				if reflect.DeepEqual(np.ParentRef, op.ParentRef) && np.ControllerName == op.ControllerName {
					found = true
					if len(np.Conditions) != len(op.Conditions) {
						updated = true
						break
					}
					for _, nc := range np.Conditions {
						matched := false
						for _, oc := range op.Conditions {
							if oc.Type == nc.Type {
								if oc.Status == nc.Status && oc.ObservedGeneration == nc.ObservedGeneration && oc.Reason == nc.Reason && oc.Message == nc.Message {
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
					break
				}
			}
			if !found || updated {
				updated = true
				break
			}
		}
	}

	if updated {
		route.Status.Parents = newParents
		if err := r.Status().Update(ctx, route); err != nil {
			l.Error(err, "unable to update GRPCRoute status")
			return ctrl.Result{}, err
		}
	}

	r.State.UpsertGRPCRoute(route)
	r.updateProxy()

	l.Info("Updated GRPCRoute status and proxy")

	return ctrl.Result{}, nil
}

func (r *GRPCRouteReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy)
}

func (r *GRPCRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GRPCRoute{}).
		Complete(r)
}
