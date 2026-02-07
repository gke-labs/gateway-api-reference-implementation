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
	"fmt"
	"regexp"

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

	var route gatewayv1.HTTPRoute
	if err := r.Get(ctx, req.NamespacedName, &route); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteHTTPRoute(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var gateways gatewayv1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		return ctrl.Result{}, err
	}

	gwMap := make(map[string]*gatewayv1.Gateway)
	for i := range gateways.Items {
		gwMap[gateways.Items[i].Name] = &gateways.Items[i]
	}

	// Update status
	// For each parentRef, we should add a ParentStatus
	var parentStatuses []gatewayv1.RouteParentStatus

	validationErr := r.validateRoute(&route)

	for _, parentRef := range route.Spec.ParentRefs {
		acceptedStatus := metav1.ConditionTrue
		acceptedReason := gatewayv1.RouteReasonAccepted
		acceptedMessage := "Route accepted by reference implementation"

		if validationErr != nil {
			acceptedStatus = metav1.ConditionFalse
			acceptedReason = gatewayv1.RouteReasonUnsupportedValue
			acceptedMessage = fmt.Sprintf("Invalid route: %v", validationErr)
		} else {
			// Check if Gateway exists and has matching listeners
			gw, ok := gwMap[string(parentRef.Name)]
			if !ok {
				acceptedStatus = metav1.ConditionFalse
				acceptedReason = gatewayv1.RouteReasonNoMatchingParent
				acceptedMessage = "Gateway not found"
			} else {
				matched := false
				for _, listener := range gw.Spec.Listeners {
					if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
						continue
					}
					if sectionName := state.ValueOf(parentRef.SectionName); sectionName != "" && sectionName != listener.Name {
						continue
					}

					var routeHostnames []string
					for _, h := range route.Spec.Hostnames {
						routeHostnames = append(routeHostnames, string(h))
					}

					listenerHostname := state.ValueOf(listener.Hostname)

					effectiveHostnames := state.IntersectHostnames(routeHostnames, string(listenerHostname))
					if len(effectiveHostnames) > 0 || len(routeHostnames) == 0 {
						matched = true
						break
					}
				}
				if !matched {
					acceptedStatus = metav1.ConditionFalse
					acceptedReason = gatewayv1.RouteReasonNoMatchingListenerHostname
					acceptedMessage = "No matching listener hostname"
				}
			}
		}

		parentStatuses = append(parentStatuses, gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: ControllerName,
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.RouteConditionAccepted),
					Status:             acceptedStatus,
					ObservedGeneration: route.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             string(acceptedReason),
					Message:            acceptedMessage,
				},
				{
					Type:               string(gatewayv1.RouteConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: route.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             string(gatewayv1.RouteReasonResolvedRefs),
					Message:            "All references resolved",
				},
			},
		})
	}
	route.Status.Parents = parentStatuses
	if err := r.Status().Update(ctx, &route); err != nil {
		l.Error(err, "unable to update HTTPRoute status")
		return ctrl.Result{}, err
	}

	// If the route is not accepted, we still update the state but it won't be used for proxying
	r.State.UpsertHTTPRoute(&route)
	r.updateProxy()

	l.Info("Updated HTTPRoute status and proxy")

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) updateProxy() {
	gateways := r.State.GetGateways()
	routes := r.State.GetHTTPRoutes()

	var proxyRoutes []state.InternalRoute
	for _, gw := range gateways {
		proxyRoutes = append(proxyRoutes, gw.BuildInternalRoutes(routes, ControllerName)...)
	}
	r.Proxy.UpdateRoutes(proxyRoutes)
}

func (r *HTTPRouteReconciler) validateRoute(route *gatewayv1.HTTPRoute) error {
	for _, rule := range route.Spec.Rules {
		for _, match := range rule.Matches {
			for _, header := range match.Headers {
				if state.ValueOf(header.Type) == gatewayv1.HeaderMatchRegularExpression {
					if _, err := regexp.Compile(header.Value); err != nil {
						return fmt.Errorf("invalid regular expression in header match: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Complete(r)
}