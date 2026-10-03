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
	"crypto/tls"
	"fmt"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type GatewayClassReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	ControllerName string
}

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, req.NamespacedName, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if string(gc.Spec.ControllerName) != r.ControllerName {
		return ctrl.Result{}, nil
	}

	acceptedStatus := metav1.ConditionTrue
	acceptedReason := gatewayv1.GatewayClassReasonAccepted
	acceptedMessage := "GatewayClass accepted by reference implementation"

	if gc.Spec.ParametersRef != nil {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = gatewayv1.GatewayClassReasonInvalidParameters
		acceptedMessage = "Invalid parametersRef: parametersRef is not supported"
	}

	// Update status to Accepted
	newConditions := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             acceptedStatus,
			ObservedGeneration: gc.Generation,
			Reason:             string(acceptedReason),
			Message:            acceptedMessage,
		},
	}

	// Preserve LastTransitionTime if status has not changed
	for i, newCond := range newConditions {
		newConditions[i].LastTransitionTime = metav1.Now()
		for _, oldCond := range gc.Status.Conditions {
			if oldCond.Type == newCond.Type && oldCond.Status == newCond.Status {
				newConditions[i].LastTransitionTime = oldCond.LastTransitionTime
				break
			}
		}
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
	if r.ControllerName == "" {
		return fmt.Errorf("ControllerName is required")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Complete(r)
}

type GatewayReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	State            *state.State
	Proxy            *proxy.Proxy
	ControllerName   string
	OnGatewaysUpdate func([]*gatewayv1.Gateway)
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	controllerName := r.ControllerName

	gw := &gatewayv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteGateway(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the GatewayClass is managed by us
	gc := &gatewayv1.GatewayClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gc); err != nil {
		l.Error(err, "unable to fetch GatewayClass", "gatewayclass", gw.Spec.GatewayClassName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if string(gc.Spec.ControllerName) != controllerName {
		return ctrl.Result{}, nil
	}

	// Find the LoadBalancer IP of the gari-proxy service
	var svc corev1.Service
	if err := r.Get(ctx, client.ObjectKey{Name: "gari-proxy", Namespace: "default"}, &svc); err != nil {
		if !apierrors.IsNotFound(err) {
			l.Error(err, "unable to fetch gari-proxy service")
			return ctrl.Result{}, err
		}
	}

	var ip string
	var hostname string
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		ip = svc.Status.LoadBalancer.Ingress[0].IP
		hostname = svc.Status.LoadBalancer.Ingress[0].Hostname
	}

	// Compute listener status
	routes := r.State.GetHTTPRoutes()
	secrets := r.State.GetSecrets()
	gs := state.GatewayState{Gateway: gw}
	var newListenerStatuses []gatewayv1.ListenerStatus
	acceptedListenersCount := 0

	for _, listener := range gw.Spec.Listeners {
		isSupported := isSupportedProtocol(listener.Protocol)

		listenerAcceptedStatus := metav1.ConditionTrue
		listenerAcceptedReason := gatewayv1.ListenerReasonAccepted
		listenerAcceptedMessage := "Listener accepted"

		listenerProgrammedStatus := metav1.ConditionTrue
		listenerProgrammedReason := gatewayv1.ListenerReasonProgrammed
		listenerProgrammedMessage := "Listener programmed"

		resolvedRefsStatus := metav1.ConditionTrue
		resolvedRefsReason := gatewayv1.ListenerReasonResolvedRefs
		resolvedRefsMessage := "All references resolved"

		var supportedKinds []gatewayv1.RouteGroupKind
		hasInvalidRouteKind := false

		if !isSupported {
			listenerAcceptedStatus = metav1.ConditionFalse
			listenerAcceptedReason = gatewayv1.ListenerReasonUnsupportedProtocol
			listenerAcceptedMessage = fmt.Sprintf("Protocol %q is not supported", listener.Protocol)

			listenerProgrammedStatus = metav1.ConditionFalse
			listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
			listenerProgrammedMessage = fmt.Sprintf("Protocol %q is not supported", listener.Protocol)

			supportedKinds = []gatewayv1.RouteGroupKind{}
			if listener.AllowedRoutes != nil && len(listener.AllowedRoutes.Kinds) > 0 {
				for _, k := range listener.AllowedRoutes.Kinds {
					if !isValidRouteKindForProtocol(listener.Protocol, k.Group, k.Kind) {
						hasInvalidRouteKind = true
					}
				}
			}
		} else {
			if listener.AllowedRoutes != nil && len(listener.AllowedRoutes.Kinds) > 0 {
				supportedKinds = []gatewayv1.RouteGroupKind{}
				for _, k := range listener.AllowedRoutes.Kinds {
					if isValidRouteKindForProtocol(listener.Protocol, k.Group, k.Kind) {
						alreadyPresent := false
						for _, sk := range supportedKinds {
							if sk.Kind == k.Kind && state.ValueOf(sk.Group) == gatewayv1.GroupName {
								alreadyPresent = true
								break
							}
						}
						if !alreadyPresent {
							supportedKinds = append(supportedKinds, gatewayv1.RouteGroupKind{
								Group: state.Ptr(gatewayv1.Group(gatewayv1.GroupName)),
								Kind:  k.Kind,
							})
						}
					} else {
						hasInvalidRouteKind = true
					}
				}
			} else {
				supportedKinds = defaultSupportedKindsForProtocol(listener.Protocol)
			}
		}

		if hasInvalidRouteKind {
			resolvedRefsStatus = metav1.ConditionFalse
			resolvedRefsReason = gatewayv1.ListenerReasonInvalidRouteKinds
			resolvedRefsMessage = "One or more route kinds are not supported"

			listenerProgrammedStatus = metav1.ConditionFalse
			listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
			listenerProgrammedMessage = "One or more route kinds are not supported"
		}

		needsTLSSecretValidation := isSupported && (listener.Protocol == gatewayv1.HTTPSProtocolType || (listener.Protocol == gatewayv1.TLSProtocolType && listener.TLS != nil && (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayv1.TLSModeTerminate))) && listener.TLS != nil
		if needsTLSSecretValidation {
			if len(listener.TLS.CertificateRefs) == 0 {
				resolvedRefsStatus = metav1.ConditionFalse
				resolvedRefsReason = gatewayv1.ListenerReasonInvalidCertificateRef
				resolvedRefsMessage = "No certificate refs specified"

				listenerProgrammedStatus = metav1.ConditionFalse
				listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
				listenerProgrammedMessage = "Invalid TLS configuration: no certificate refs specified"
			}
			for _, ref := range listener.TLS.CertificateRefs {
				group := state.ValueOf(ref.Group)
				kind := state.ValueOf(ref.Kind)
				if (group != "" && group != "core") || (kind != "" && kind != "Secret") {
					resolvedRefsStatus = metav1.ConditionFalse
					resolvedRefsReason = gatewayv1.ListenerReasonInvalidCertificateRef
					resolvedRefsMessage = fmt.Sprintf("Unsupported certificate ref group %q kind %q", group, kind)

					listenerProgrammedStatus = metav1.ConditionFalse
					listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
					listenerProgrammedMessage = fmt.Sprintf("Invalid certificate ref group %q kind %q", group, kind)
					break
				}

				if kind == "" {
					kind = "Secret"
				}

				secretKey := ResolveNamespacedName(ref.Namespace, ref.Name, gw)
				if secretKey.Namespace != gw.Namespace {
					from := state.Reference{
						GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: "Gateway"},
						Namespace: gw.Namespace,
					}
					to := state.Reference{
						GroupKind: schema.GroupKind{Group: string(group), Kind: string(kind)},
						Namespace: secretKey.Namespace,
						Name:      secretKey.Name,
					}
					if !r.State.IsReferencePermitted(from, to) {
						resolvedRefsStatus = metav1.ConditionFalse
						resolvedRefsReason = gatewayv1.ListenerReasonRefNotPermitted
						resolvedRefsMessage = fmt.Sprintf("Cross-namespace reference to %s/%s is not permitted by any ReferenceGrant", secretKey.Namespace, secretKey.Name)

						listenerProgrammedStatus = metav1.ConditionFalse
						listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
						listenerProgrammedMessage = fmt.Sprintf("Cross-namespace reference to %s/%s is not permitted by any ReferenceGrant", secretKey.Namespace, secretKey.Name)
						break
					}
				}

				secret, ok := secrets[secretKey]
				if !ok || secret == nil {
					resolvedRefsStatus = metav1.ConditionFalse
					resolvedRefsReason = gatewayv1.ListenerReasonInvalidCertificateRef
					resolvedRefsMessage = fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name)

					listenerProgrammedStatus = metav1.ConditionFalse
					listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
					listenerProgrammedMessage = fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name)
					break
				}

				certBytes := secret.Data[corev1.TLSCertKey]
				keyBytes := secret.Data[corev1.TLSPrivateKeyKey]
				if len(certBytes) == 0 || len(keyBytes) == 0 {
					resolvedRefsStatus = metav1.ConditionFalse
					resolvedRefsReason = gatewayv1.ListenerReasonInvalidCertificateRef
					resolvedRefsMessage = fmt.Sprintf("Secret %s/%s is missing tls.crt or tls.key", secretKey.Namespace, secretKey.Name)

					listenerProgrammedStatus = metav1.ConditionFalse
					listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
					listenerProgrammedMessage = fmt.Sprintf("Secret %s/%s is missing tls.crt or tls.key", secretKey.Namespace, secretKey.Name)
					break
				}

				if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
					resolvedRefsStatus = metav1.ConditionFalse
					resolvedRefsReason = gatewayv1.ListenerReasonInvalidCertificateRef
					resolvedRefsMessage = fmt.Sprintf("Secret %s/%s contains invalid certificate or key: %v", secretKey.Namespace, secretKey.Name, err)

					listenerProgrammedStatus = metav1.ConditionFalse
					listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
					listenerProgrammedMessage = fmt.Sprintf("Secret %s/%s contains invalid certificate or key: %v", secretKey.Namespace, secretKey.Name, err)
					break
				}
			}
		}

		attachedRoutes := 0
		if isSupported {
			httpRouteAllowed := false
			if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
				httpRouteAllowed = (listener.Protocol == gatewayv1.HTTPProtocolType || listener.Protocol == gatewayv1.HTTPSProtocolType)
			} else {
				for _, k := range listener.AllowedRoutes.Kinds {
					if state.IsHTTPRoute(k.Group, k.Kind) {
						httpRouteAllowed = true
						break
					}
				}
			}

			if httpRouteAllowed {
				for _, route := range routes {
					for _, parentRef := range route.Spec.ParentRefs {
						parentNamespace := route.Namespace
						if ns := state.ValueOf(parentRef.Namespace); ns != "" {
							parentNamespace = string(ns)
						}
						if string(parentRef.Name) == gw.Name && parentNamespace == gw.Namespace {
							if sn := state.ValueOf(parentRef.SectionName); sn == "" || string(sn) == string(listener.Name) {
								if port := state.ValueOf(parentRef.Port); port == 0 || port == listener.Port {
									if route.IsAcceptedForParentRef(parentRef, controllerName) {
										routeHostnames := route.GetHostnames()
										listenerHostname := state.ValueOf(listener.Hostname)
										effectiveHostnames := state.IntersectHostnames(routeHostnames, string(listenerHostname))
										if len(effectiveHostnames) > 0 || len(routeHostnames) == 0 {
											attachedRoutes++
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}

		conds := []metav1.Condition{
			{
				Type:               string(gatewayv1.ListenerConditionProgrammed),
				Status:             listenerProgrammedStatus,
				ObservedGeneration: gw.Generation,
				Reason:             string(listenerProgrammedReason),
				Message:            listenerProgrammedMessage,
			},
			{
				Type:               string(gatewayv1.ListenerConditionAccepted),
				Status:             listenerAcceptedStatus,
				ObservedGeneration: gw.Generation,
				Reason:             string(listenerAcceptedReason),
				Message:            listenerAcceptedMessage,
			},
			{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             resolvedRefsStatus,
				ObservedGeneration: gw.Generation,
				Reason:             string(resolvedRefsReason),
				Message:            resolvedRefsMessage,
			},
		}

		var oldListener *gatewayv1.ListenerStatus
		for _, ol := range gw.Status.Listeners {
			if ol.Name == listener.Name {
				oldListener = &ol
				break
			}
		}

		for i, newCond := range conds {
			conds[i].LastTransitionTime = metav1.Now()
			if oldListener != nil {
				for _, oldCond := range oldListener.Conditions {
					if oldCond.Type == newCond.Type && oldCond.Status == newCond.Status {
						conds[i].LastTransitionTime = oldCond.LastTransitionTime
						break
					}
				}
			}
		}

		if listenerAcceptedStatus == metav1.ConditionTrue {
			acceptedListenersCount++
		}

		newListenerStatuses = append(newListenerStatuses, gatewayv1.ListenerStatus{
			Name:           listener.Name,
			SupportedKinds: supportedKinds,
			AttachedRoutes: int32(attachedRoutes),
			Conditions:     conds,
		})
	}

	totalListeners := len(gw.Spec.Listeners)

	gwAcceptedStatus := metav1.ConditionTrue
	gwAcceptedReason := gatewayv1.GatewayReasonAccepted
	gwAcceptedMessage := "Gateway accepted by reference implementation"

	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		gwAcceptedStatus = metav1.ConditionFalse
		gwAcceptedReason = gatewayv1.GatewayReasonInvalidParameters
		gwAcceptedMessage = "Invalid infrastructure parametersRef: parametersRef is not supported"
	} else if totalListeners == 0 {
		gwAcceptedStatus = metav1.ConditionFalse
		gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
		gwAcceptedMessage = "No listeners configured on Gateway"
	} else if acceptedListenersCount == 0 {
		gwAcceptedStatus = metav1.ConditionFalse
		gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
		gwAcceptedMessage = "No listeners are accepted"
	} else if acceptedListenersCount < totalListeners {
		gwAcceptedStatus = metav1.ConditionTrue
		gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
		gwAcceptedMessage = "One or more listeners have invalid configuration"
	}

	gwProgrammedStatus := metav1.ConditionTrue
	gwProgrammedReason := gatewayv1.GatewayReasonProgrammed
	gwProgrammedMessage := "Gateway programmed by reference implementation"

	if gwAcceptedStatus == metav1.ConditionFalse {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonInvalid
		gwProgrammedMessage = "Gateway is not accepted"
	} else if ip == "" && hostname == "" {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonAddressNotAssigned
		gwProgrammedMessage = "Waiting for LoadBalancer IP address to be assigned to the Gateway"
	}

	newConditions := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             gwProgrammedStatus,
			ObservedGeneration: gw.Generation,
			Reason:             string(gwProgrammedReason),
			Message:            gwProgrammedMessage,
		},
		{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             gwAcceptedStatus,
			ObservedGeneration: gw.Generation,
			Reason:             string(gwAcceptedReason),
			Message:            gwAcceptedMessage,
		},
	}

	// Preserve LastTransitionTime for Gateway conditions if Status hasn't changed
	for i, newCond := range newConditions {
		newConditions[i].LastTransitionTime = metav1.Now()
		for _, oldCond := range gw.Status.Conditions {
			if oldCond.Type == newCond.Type && oldCond.Status == newCond.Status {
				newConditions[i].LastTransitionTime = oldCond.LastTransitionTime
				break
			}
		}
	}

	newAddresses := make([]gatewayv1.GatewayStatusAddress, 0)
	if gwAcceptedStatus == metav1.ConditionTrue {
		if ip != "" {
			newAddresses = append(newAddresses, gatewayv1.GatewayStatusAddress{
				Type:  state.Ptr(gatewayv1.IPAddressType),
				Value: ip,
			})
		}
		if hostname != "" {
			newAddresses = append(newAddresses, gatewayv1.GatewayStatusAddress{
				Type:  state.Ptr(gatewayv1.HostnameAddressType),
				Value: hostname,
			})
		}
	}

	updated := false
	if len(gw.Status.Conditions) != len(newConditions) || len(gw.Status.Addresses) != len(newAddresses) || len(gw.Status.Listeners) != len(newListenerStatuses) {
		updated = true
	} else {
		for i := range newConditions {
			matched := false
			for j := range gw.Status.Conditions {
				if gw.Status.Conditions[j].Type == newConditions[i].Type {
					if gw.Status.Conditions[j].Status == newConditions[i].Status &&
						gw.Status.Conditions[j].ObservedGeneration == newConditions[i].ObservedGeneration &&
						gw.Status.Conditions[j].Reason == newConditions[i].Reason &&
						gw.Status.Conditions[j].Message == newConditions[i].Message {
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
		if !updated {
			for i := range newAddresses {
				if state.ValueOf(gw.Status.Addresses[i].Type) != state.ValueOf(newAddresses[i].Type) ||
					gw.Status.Addresses[i].Value != newAddresses[i].Value {
					updated = true
					break
				}
			}
		}
		if !updated {
			for i := range newListenerStatuses {
				if gw.Status.Listeners[i].Name != newListenerStatuses[i].Name ||
					gw.Status.Listeners[i].AttachedRoutes != newListenerStatuses[i].AttachedRoutes ||
					len(gw.Status.Listeners[i].Conditions) != len(newListenerStatuses[i].Conditions) ||
					len(gw.Status.Listeners[i].SupportedKinds) != len(newListenerStatuses[i].SupportedKinds) {
					updated = true
					break
				}
				for k := range newListenerStatuses[i].SupportedKinds {
					if state.ValueOf(gw.Status.Listeners[i].SupportedKinds[k].Group) != state.ValueOf(newListenerStatuses[i].SupportedKinds[k].Group) ||
						gw.Status.Listeners[i].SupportedKinds[k].Kind != newListenerStatuses[i].SupportedKinds[k].Kind {
						updated = true
						break
					}
				}
				if updated {
					break
				}
				// Also check if conditions changed (optional but safer)
				for j := range newListenerStatuses[i].Conditions {
					matched := false
					for k := range gw.Status.Listeners[i].Conditions {
						if gw.Status.Listeners[i].Conditions[k].Type == newListenerStatuses[i].Conditions[j].Type {
							if gw.Status.Listeners[i].Conditions[k].Status == newListenerStatuses[i].Conditions[j].Status &&
								gw.Status.Listeners[i].Conditions[k].ObservedGeneration == newListenerStatuses[i].Conditions[j].ObservedGeneration &&
								gw.Status.Listeners[i].Conditions[k].Reason == newListenerStatuses[i].Conditions[j].Reason &&
								gw.Status.Listeners[i].Conditions[k].Message == newListenerStatuses[i].Conditions[j].Message {
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
	}

	r.State.UpsertGateway(gw)
	_ = gs // keep for now
	r.updateProxy()

	if updated {
		gw.Status.Conditions = newConditions
		gw.Status.Addresses = newAddresses
		gw.Status.Listeners = newListenerStatuses
		if err := r.Status().Update(ctx, gw); err != nil {
			l.Error(err, "unable to update Gateway status")
			return ctrl.Result{}, err
		}
	}

	if ip == "" && hostname == "" {
		l.V(1).Info("gari-proxy service has no LoadBalancer address yet")
	} else if ip != "" {
		l.Info("Updated Gateway status", "address", ip)
	} else {
		l.Info("Updated Gateway status", "hostname", hostname)
	}

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy, r.ControllerName, r.OnGatewaysUpdate)
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ControllerName == "" {
		return fmt.Errorf("ControllerName is required")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		// A GatewayClass update invalidates all Gateways that reference it
		Watches(&gatewayv1.GatewayClass{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			gc := obj.(*gatewayv1.GatewayClass)
			if string(gc.Spec.ControllerName) != r.ControllerName {
				return nil
			}
			var gwList gatewayv1.GatewayList
			if err := r.List(ctx, &gwList); err == nil {
				var requests []ctrl.Request
				for _, gw := range gwList.Items {
					if string(gw.Spec.GatewayClassName) == gc.Name {
						requests = append(requests, ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: gw.Namespace,
								Name:      gw.Name,
							},
						})
					}
				}
				return requests
			}
			return nil
		})).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			// When an HTTPRoute changes, reconcile all Gateways it references
			route := obj.(*gatewayv1.HTTPRoute)
			var requests []ctrl.Request
			for _, parentRef := range route.Spec.ParentRefs {
				if string(state.ValueOf(parentRef.Group)) == "" || string(state.ValueOf(parentRef.Group)) == "gateway.networking.k8s.io" {
					if string(state.ValueOf(parentRef.Kind)) == "" || string(state.ValueOf(parentRef.Kind)) == "Gateway" {
						gwKey := ResolveNamespacedName(parentRef.Namespace, parentRef.Name, route)
						requests = append(requests, ctrl.Request{
							NamespacedName: gwKey,
						})
					}
				}
			}
			return requests
		})).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			svc := obj.(*corev1.Service)
			if svc.Name == "gari-proxy" && svc.Namespace == "default" {
				var gwList gatewayv1.GatewayList
				if err := r.List(ctx, &gwList); err == nil {
					var requests []ctrl.Request
					for _, gw := range gwList.Items {
						requests = append(requests, ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: gw.Namespace,
								Name:      gw.Name,
							},
						})
					}
					return requests
				}
			}
			return nil
		})).
		// A ReferenceGrant update invalidates all gateways that might use it
		Watches(&gatewayv1beta1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			rg := obj.(*gatewayv1beta1.ReferenceGrant)
			var gwList gatewayv1.GatewayList
			if err := r.List(ctx, &gwList); err == nil {
				var requests []ctrl.Request
				for _, gw := range gwList.Items {
					match := false
					for _, from := range rg.Spec.From {
						if (string(from.Group) == gatewayv1.GroupName || string(from.Group) == "") && string(from.Kind) == "Gateway" && string(from.Namespace) == gw.Namespace {
							match = true
							break
						}
					}
					if !match {
						for _, listener := range gw.Spec.Listeners {
							if listener.TLS != nil {
								for _, ref := range listener.TLS.CertificateRefs {
									refNs := gw.Namespace
									if ref.Namespace != nil && string(*ref.Namespace) != "" {
										refNs = string(*ref.Namespace)
									}
									if refNs == rg.Namespace {
										match = true
										break
									}
								}
							}
							if match {
								break
							}
						}
					}
					if match {
						requests = append(requests, ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: gw.Namespace,
								Name:      gw.Name,
							},
						})
					}
				}
				return requests
			}
			return nil
		})).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			secret := obj.(*corev1.Secret)
			var gwList gatewayv1.GatewayList
			if err := r.List(ctx, &gwList); err == nil {
				var requests []ctrl.Request
				for _, gw := range gwList.Items {
					for _, listener := range gw.Spec.Listeners {
						if listener.TLS != nil {
							for _, ref := range listener.TLS.CertificateRefs {
								secretKey := ResolveNamespacedName(ref.Namespace, ref.Name, &gw)
								if secretKey.Namespace == secret.Namespace && secretKey.Name == secret.Name {
									requests = append(requests, ctrl.Request{
										NamespacedName: types.NamespacedName{
											Namespace: gw.Namespace,
											Name:      gw.Name,
										},
									})
									break
								}
							}
						}
					}
				}
				return requests
			}
			return nil
		})).
		Complete(r)
}

func isSupportedProtocol(protocol gatewayv1.ProtocolType) bool {
	switch protocol {
	case gatewayv1.HTTPProtocolType,
		gatewayv1.HTTPSProtocolType,
		gatewayv1.TLSProtocolType,
		gatewayv1.TCPProtocolType,
		gatewayv1.UDPProtocolType:
		return true
	default:
		return false
	}
}

func isValidRouteKindForProtocol(protocol gatewayv1.ProtocolType, group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	grp := state.ValueOf(group)
	if grp != "" && grp != gatewayv1.GroupName {
		return false
	}
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return kind == "HTTPRoute" || kind == "GRPCRoute"
	case gatewayv1.TLSProtocolType:
		return kind == "TLSRoute"
	case gatewayv1.TCPProtocolType:
		return kind == "TCPRoute"
	case gatewayv1.UDPProtocolType:
		return kind == "UDPRoute"
	default:
		return false
	}
}

func defaultSupportedKindsForProtocol(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: state.Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("HTTPRoute"),
		}}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: state.Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("TLSRoute"),
		}}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: state.Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("TCPRoute"),
		}}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: state.Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("UDPRoute"),
		}}
	default:
		return []gatewayv1.RouteGroupKind{}
	}
}
