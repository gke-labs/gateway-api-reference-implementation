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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
	client.Client
	Scheme *runtime.Scheme
	State  *state.State
	Proxy  *proxy.Proxy
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

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
	newConditions := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: gw.Generation,
			Reason:             string(gatewayv1.GatewayReasonProgrammed),
			Message:            "Gateway programmed by reference implementation",
		},
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

	// Compute listener status
	routes := r.State.GetHTTPRoutes()
	gs := state.GatewayState{Gateway: gw}
	var newListenerStatuses []gatewayv1.ListenerStatus
	var errs []error
	for _, listener := range gw.Spec.Listeners {
		attachedRoutes := 0
		for _, route := range routes {
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

		var oldConditions []metav1.Condition
		for _, oldL := range gw.Status.Listeners {
			if oldL.Name == listener.Name {
				oldConditions = oldL.Conditions
				break
			}
		}

		newConds, err := r.validateListener(ctx, gw, listener, oldConditions)
		if err != nil {
			errs = append(errs, err)
		}

		var supportedKinds []gatewayv1.RouteGroupKind
		if listener.Protocol == gatewayv1.TLSProtocolType {
			supportedKinds = []gatewayv1.RouteGroupKind{{Group: state.Ptr(gatewayv1.Group("gateway.networking.k8s.io")), Kind: "TLSRoute"}}
		} else {
			supportedKinds = []gatewayv1.RouteGroupKind{{Group: state.Ptr(gatewayv1.Group("gateway.networking.k8s.io")), Kind: "HTTPRoute"}}
		}

		newListenerStatuses = append(newListenerStatuses, gatewayv1.ListenerStatus{
			Name:           listener.Name,
			SupportedKinds: supportedKinds,
			AttachedRoutes: int32(attachedRoutes),
			Conditions:     newConds,
		})
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
					len(gw.Status.Listeners[i].Conditions) != len(newListenerStatuses[i].Conditions) {
					updated = true
					break
				}
				// Also check if conditions changed (optional but safer)
				for j := range newListenerStatuses[i].Conditions {
					matched := false
					for k := range gw.Status.Listeners[i].Conditions {
						if gw.Status.Listeners[i].Conditions[k].Type == newListenerStatuses[i].Conditions[j].Type {
							if gw.Status.Listeners[i].Conditions[k].Status == newListenerStatuses[i].Conditions[j].Status &&
								gw.Status.Listeners[i].Conditions[k].ObservedGeneration == newListenerStatuses[i].Conditions[j].ObservedGeneration &&
								gw.Status.Listeners[i].Conditions[k].Reason == newListenerStatuses[i].Conditions[j].Reason {
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

	if updated {
		for i := range newConditions {
			newConditions[i].LastTransitionTime = metav1.Now()
		}
		gw.Status.Conditions = newConditions
		gw.Status.Addresses = newAddresses
		gw.Status.Listeners = newListenerStatuses
		if err := r.Status().Update(ctx, gw); err != nil {
			l.Error(err, "unable to update Gateway status")
			return ctrl.Result{}, err
		}
	}

	r.State.UpsertGateway(gw)
	_ = gs // keep for now
	r.updateProxy()

	l.Info("Updated Gateway status", "address", ip)

	if len(errs) > 0 {
		return ctrl.Result{}, fmt.Errorf("transient errors during validation: %v", errs)
	}

	return ctrl.Result{}, nil
}

func resolveSecretNamespace(ns *gatewayv1.Namespace, defaultNamespace string) string {
	if ns != nil {
		return string(*ns)
	}
	return defaultNamespace
}

func (r *GatewayReconciler) validateListener(ctx context.Context, gw *gatewayv1.Gateway, listener gatewayv1.Listener, oldConditions []metav1.Condition) ([]metav1.Condition, error) {
	resolvedRefsCond := metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionResolvedRefs),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
		Message:            "All references resolved",
	}

	acceptedCond := metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gatewayv1.ListenerReasonAccepted),
		Message:            "Listener accepted",
	}

	programmedCond := metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionProgrammed),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gatewayv1.ListenerReasonProgrammed),
		Message:            "Listener programmed",
	}

	var transientErr error

	// Validate protocol
	if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType && listener.Protocol != gatewayv1.TLSProtocolType {
		acceptedCond.Status = metav1.ConditionFalse
		acceptedCond.Reason = string(gatewayv1.ListenerReasonUnsupportedProtocol)
		acceptedCond.Message = fmt.Sprintf("Unsupported protocol: %s", listener.Protocol)
	} else if listener.Protocol == gatewayv1.HTTPProtocolType && listener.TLS != nil {
		acceptedCond.Status = metav1.ConditionFalse
		acceptedCond.Reason = string(gatewayv1.ListenerReasonInvalid)
		acceptedCond.Message = "TLS configuration must be nil for HTTP protocol"
	} else if listener.Protocol == gatewayv1.HTTPSProtocolType || listener.Protocol == gatewayv1.TLSProtocolType {
		if listener.TLS == nil {
			resolvedRefsCond.Status = metav1.ConditionFalse
			resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			resolvedRefsCond.Message = "TLS block is required for HTTPS/TLS protocols"
		} else if listener.TLS.Mode != nil && *listener.TLS.Mode == gatewayv1.TLSModePassthrough && len(listener.TLS.CertificateRefs) > 0 {
			resolvedRefsCond.Status = metav1.ConditionFalse
			resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			resolvedRefsCond.Message = "CertificateRefs MUST NOT be provided for Passthrough TLS mode"
		} else if (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayv1.TLSModeTerminate) && len(listener.TLS.CertificateRefs) == 0 {
			resolvedRefsCond.Status = metav1.ConditionFalse
			resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			resolvedRefsCond.Message = "CertificateRefs must be provided for TLS termination"
		} else if len(listener.TLS.CertificateRefs) > 0 {
			for _, ref := range listener.TLS.CertificateRefs {
				if (ref.Group != nil && *ref.Group != "") || (ref.Kind != nil && *ref.Kind != "" && *ref.Kind != "Secret") {
					resolvedRefsCond.Status = metav1.ConditionFalse
					resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					resolvedRefsCond.Message = fmt.Sprintf("Unsupported certificate ref %s/%s", state.ValueOf(ref.Group), state.ValueOf(ref.Kind))
					break
				}

				secretNamespace := resolveSecretNamespace(ref.Namespace, gw.Namespace)

				if secretNamespace == "" {
					resolvedRefsCond.Status = metav1.ConditionFalse
					resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					resolvedRefsCond.Message = "Certificate ref namespace cannot be empty"
					break
				}

				if secretNamespace != gw.Namespace {
					resolvedRefsCond.Status = metav1.ConditionFalse
					resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonRefNotPermitted)
					resolvedRefsCond.Message = fmt.Sprintf("Certificate ref to Secret %s/%s not permitted: cross-namespace references require ReferenceGrant (not implemented)", secretNamespace, ref.Name)
					break
				}

				secret := &corev1.Secret{}
				err := r.Get(ctx, types.NamespacedName{Namespace: secretNamespace, Name: string(ref.Name)}, secret)
				if err != nil {
					if apierrors.IsNotFound(err) {
						resolvedRefsCond.Status = metav1.ConditionFalse
						resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
						resolvedRefsCond.Message = fmt.Sprintf("Secret %s/%s not found", secretNamespace, ref.Name)
					} else {
						// Transient error: Requeue
						resolvedRefsCond.Status = metav1.ConditionFalse
						resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
						resolvedRefsCond.Message = fmt.Sprintf("Error fetching Secret %s/%s", secretNamespace, ref.Name)
						transientErr = err
					}
					break
				}

				// Validate Secret content
				if secret.Type != corev1.SecretTypeTLS {
					resolvedRefsCond.Status = metav1.ConditionFalse
					resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					resolvedRefsCond.Message = fmt.Sprintf("Secret %s/%s is not of type kubernetes.io/tls", secretNamespace, ref.Name)
					break
				}
				if _, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"]); err != nil {
					resolvedRefsCond.Status = metav1.ConditionFalse
					resolvedRefsCond.Reason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					resolvedRefsCond.Message = fmt.Sprintf("Secret %s/%s contains malformed certificate data: %v", secretNamespace, ref.Name, err)
					break
				}
			}
		}
	}

	if acceptedCond.Status == metav1.ConditionFalse {
		programmedCond.Status = metav1.ConditionFalse
		programmedCond.Reason = string(gatewayv1.ListenerReasonInvalid)
		programmedCond.Message = acceptedCond.Message
	} else if resolvedRefsCond.Status == metav1.ConditionFalse {
		programmedCond.Status = metav1.ConditionFalse
		programmedCond.Reason = string(gatewayv1.ListenerReasonInvalid)
		programmedCond.Message = fmt.Sprintf("Listener has invalid references: %s", resolvedRefsCond.Message)
	}

	// Merge with old conditions
	newConds := append([]metav1.Condition{}, oldConditions...)
	meta.SetStatusCondition(&newConds, programmedCond)
	meta.SetStatusCondition(&newConds, acceptedCond)
	meta.SetStatusCondition(&newConds, resolvedRefsCond)

	return newConds, transientErr
}

func (r *GatewayReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy)
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
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
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			secretNamespace := obj.GetNamespace()
			secretName := obj.GetName()

			var gateways gatewayv1.GatewayList
			if err := r.List(ctx, &gateways, client.InNamespace(secretNamespace)); err != nil {
				log.FromContext(ctx).Error(err, "failed to list gateways")
				return nil
			}
			var requests []ctrl.Request
			for _, gw := range gateways.Items {
				matched := false
				for _, listener := range gw.Spec.Listeners {
					if listener.TLS != nil {
						for _, ref := range listener.TLS.CertificateRefs {
							ns := resolveSecretNamespace(ref.Namespace, gw.Namespace)
							if ns == secretNamespace && string(ref.Name) == secretName {
								requests = append(requests, ctrl.Request{
									NamespacedName: types.NamespacedName{
										Namespace: gw.Namespace,
										Name:      gw.Name,
									},
								})
								matched = true
								break
							}
						}
					}
					if matched {
						break
					}
				}
			}
			return requests
		})).
		Complete(r)
}
