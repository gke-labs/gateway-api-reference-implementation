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
	"os"
	"reflect"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type GatewayClassReconciler struct {
	GatewayControllerOptions
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

	if r.SkipStatusUpdate {
		return ctrl.Result{}, nil
	}

	// Update status to Accepted
	newConditions := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gc.Generation,
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            "GatewayClass accepted by reference implementation",
		},
	}

	updated := false
	if len(gc.Status.Conditions) != len(newConditions) {
		updated = true
	} else {
		for i := range newConditions {
			matched := false
			for j := range gc.Status.Conditions {
				if gc.Status.Conditions[j].Type == newConditions[i].Type {
					if gc.Status.Conditions[j].Status == newConditions[i].Status &&
						gc.Status.Conditions[j].ObservedGeneration == newConditions[i].ObservedGeneration &&
						gc.Status.Conditions[j].Reason == newConditions[i].Reason &&
						gc.Status.Conditions[j].Message == newConditions[i].Message {
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
	}

	if updated {
		for i := range newConditions {
			newConditions[i].LastTransitionTime = metav1.Now()
		}
		gc.Status.Conditions = newConditions
		if err := r.Status().Update(ctx, &gc); err != nil {
			l.Error(err, "unable to update GatewayClass status")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Complete(r)
}

type GatewayReconciler struct {
	GatewayControllerOptions
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// If we are scoped to a specific gateway, ignore others
	if r.GatewayName != "" && (req.Name != r.GatewayName || req.Namespace != r.GatewayNamespace) {
		return ctrl.Result{}, nil
	}

	gw := &gatewayv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteGateway(req.NamespacedName)
			r.UpdateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the GatewayClass is managed by us
	gc := &gatewayv1.GatewayClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gc); err != nil {
		l.Error(err, "unable to fetch GatewayClass", "gatewayclass", gw.Spec.GatewayClassName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if gc.Spec.ControllerName != ControllerName {
		return ctrl.Result{}, nil
	}

	if r.Proxy == nil {
		// Operator mode: Sync infrastructure and update basic status (Accepted, Address)
		svc, err := r.syncInfrastructure(ctx, gw)
		if err != nil {
			l.Error(err, "unable to sync infrastructure")
			return ctrl.Result{}, err
		}

		var ip string
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			ip = svc.Status.LoadBalancer.Ingress[0].IP
		}

		if ip == "" {
			l.Info("Gateway service has no LoadBalancer IP yet")
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}

		// Update status to Accepted and add address
		newConditions := []metav1.Condition{
			{
				Type:               string(gatewayv1.GatewayConditionAccepted),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: gw.Generation,
				Reason:             string(gatewayv1.GatewayReasonAccepted),
				Message:            "Gateway accepted by reference implementation",
			},
		}
		newAddresses := []gatewayv1.GatewayStatusAddress{
			{
				Type:  state.Ptr(gatewayv1.IPAddressType),
				Value: ip,
			},
		}

		updated := false
		if !hasCondition(gw.Status.Conditions, newConditions[0]) || !reflect.DeepEqual(gw.Status.Addresses, newAddresses) {
			updated = true
		}

		if updated {
			for i := range newConditions {
				newConditions[i].LastTransitionTime = metav1.Now()
			}
			gw.Status.Conditions = mergeConditions(gw.Status.Conditions, newConditions)
			gw.Status.Addresses = newAddresses
			if err := r.Status().Update(ctx, gw); err != nil {
				l.Error(err, "unable to update Gateway status")
				return ctrl.Result{}, err
			}
		}

		r.State.UpsertGateway(gw)
		l.Info("Updated Gateway status (Operator)", "address", ip)
		return ctrl.Result{}, nil
	}

	// Gateway mode: Update Programmed/Listener status and proxy config
	r.State.UpsertGateway(gw)

	// Compute listener status
	routes := r.State.GetHTTPRoutes()
	var newListenerStatuses []gatewayv1.ListenerStatus
	for _, listener := range gw.Spec.Listeners {
		attachedRoutes := 0
		for _, route := range routes {
			if route.MatchesGateway(gw, ControllerName) {
				// Count how many listeners on this gateway the route is attached to
				for _, parentRef := range route.Spec.ParentRefs {
					if string(parentRef.Name) == gw.Name {
						if sn := state.ValueOf(parentRef.SectionName); sn == "" || string(sn) == string(listener.Name) {
							if route.IsAccepted(ControllerName) {
								attachedRoutes++
								break
							}
						}
					}
				}
			}
		}

		newListenerStatuses = append(newListenerStatuses, gatewayv1.ListenerStatus{
			Name:           listener.Name,
			SupportedKinds: []gatewayv1.RouteGroupKind{{Group: state.Ptr(gatewayv1.Group("gateway.networking.k8s.io")), Kind: "HTTPRoute"}},
			AttachedRoutes: int32(attachedRoutes),
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					Message:            "Listener programmed",
				},
				{
					Type:               string(gatewayv1.ListenerConditionAccepted),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             string(gatewayv1.ListenerReasonAccepted),
					Message:            "Listener accepted",
				},
				{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "All references resolved",
				},
			},
		})
	}

	newConditions := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.Generation,
			Reason:             string(gatewayv1.GatewayReasonProgrammed),
			Message:            "Gateway programmed by reference implementation",
		},
	}

	updated := false
	if !hasCondition(gw.Status.Conditions, newConditions[0]) || !reflect.DeepEqual(gw.Status.Listeners, newListenerStatuses) {
		updated = true
	}

	if updated {
		for i := range newConditions {
			newConditions[i].LastTransitionTime = metav1.Now()
		}
		gw.Status.Conditions = mergeConditions(gw.Status.Conditions, newConditions)
		gw.Status.Listeners = newListenerStatuses
		if err := r.Status().Update(ctx, gw); err != nil {
			l.Error(err, "unable to update Gateway status")
			return ctrl.Result{}, err
		}
	}

	r.UpdateProxy()
	l.Info("Updated Gateway status (Gateway)")

	return ctrl.Result{}, nil
}

func hasCondition(conditions []metav1.Condition, target metav1.Condition) bool {
	for _, c := range conditions {
		if c.Type == target.Type && c.Status == target.Status && c.Reason == target.Reason && c.ObservedGeneration == target.ObservedGeneration {
			return true
		}
	}
	return false
}

func mergeConditions(existing []metav1.Condition, newConds []metav1.Condition) []metav1.Condition {
	res := make([]metav1.Condition, len(existing))
	copy(res, existing)

	for _, n := range newConds {
		found := false
		for i, e := range res {
			if e.Type == n.Type {
				res[i] = n
				found = true
				break
			}
		}
		if !found {
			res = append(res, n)
		}
	}
	return res
}

func (r *GatewayReconciler) syncInfrastructure(ctx context.Context, gw *gatewayv1.Gateway) (*corev1.Service, error) {
	image := os.Getenv("CONTROLLER_IMAGE")
	if image == "" {
		image = "gari-controller:e2e"
	}

	labels := map[string]string{
		"app":                                    "gari-proxy",
		"gateway.networking.k8s.io/gateway-name": gw.Name,
	}
	if gw.Spec.Infrastructure != nil {
		for k, v := range gw.Spec.Infrastructure.Labels {
			labels[string(k)] = string(v)
		}
	}

	annotations := map[string]string{}
	if gw.Spec.Infrastructure != nil {
		for k, v := range gw.Spec.Infrastructure.Annotations {
			annotations[string(k)] = string(v)
		}
	}

	// 1. Create/Update ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("gari-%s", gw.Name),
			Namespace:   gw.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	if err := controllerutil.SetControllerReference(gw, sa, r.Scheme); err != nil {
		return nil, err
	}
	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, sa, func() error {
		sa.Labels = labels
		sa.Annotations = annotations
		return nil
	}); err != nil {
		return nil, err
	}

	// 2. Create/Update Deployment
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("gari-%s", gw.Name),
			Namespace:   gw.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	if err := controllerutil.SetControllerReference(gw, deploy, r.Scheme); err != nil {
		return nil, err
	}

	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		deploy.Labels = labels
		deploy.Annotations = annotations
		deploy.Spec.Replicas = state.Ptr(int32(1))
		deploy.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"gateway.networking.k8s.io/gateway-name": gw.Name,
			},
		}
		deploy.Spec.Template.ObjectMeta.Labels = labels
		deploy.Spec.Template.ObjectMeta.Annotations = annotations
		deploy.Spec.Template.Spec.ServiceAccountName = sa.Name
		deploy.Spec.Template.Spec.Containers = []corev1.Container{
			{
				Name:            "proxy",
				Image:           image,
				ImagePullPolicy: corev1.PullNever,
				Command:         []string{"/gari-gateway"},
				Args: []string{
					"--enable-h2c",
					fmt.Sprintf("--gateway-name=%s", gw.Name),
					fmt.Sprintf("--gateway-namespace=%s", gw.Namespace),
				},
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8000},
					{Name: "https", ContainerPort: 8443},
				},
			},
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// 3. Create/Update Service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("gari-%s", gw.Name),
			Namespace:   gw.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	if err := controllerutil.SetControllerReference(gw, svc, r.Scheme); err != nil {
		return nil, err
	}

	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = labels
		svc.Annotations = annotations
		svc.Spec.Type = corev1.ServiceTypeLoadBalancer
		svc.Spec.Selector = map[string]string{
			"gateway.networking.k8s.io/gateway-name": gw.Name,
		}
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Port:       80,
				TargetPort: intstr.FromString("http"),
			},
			{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromString("https"),
			},
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return svc, nil
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			// When an HTTPRoute changes, reconcile all Gateways it references
			route := obj.(*gatewayv1.HTTPRoute)
			var requests []ctrl.Request
			for _, parentRef := range route.Spec.ParentRefs {
				if string(state.ValueOf(parentRef.Group)) == "" || string(state.ValueOf(parentRef.Group)) == "gateway.networking.k8s.io" {
					if string(state.ValueOf(parentRef.Kind)) == "" || string(state.ValueOf(parentRef.Kind)) == "Gateway" {
						requests = append(requests, ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: route.Namespace, // Assuming same namespace for now
								Name:      string(parentRef.Name),
							},
						})
					}
				}
			}
			return requests
		})).
		Complete(r)
}
