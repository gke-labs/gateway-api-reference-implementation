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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// ResolveNamespacedName resolves an optional namespace pointer and a name against a source object.
// If namespace is nil or empty, src.GetNamespace() is used.
func ResolveNamespacedName[N ~string, M ~string](namespace *N, name M, src client.Object) types.NamespacedName {
	ns := ""
	if src != nil {
		ns = src.GetNamespace()
	}
	if namespace != nil && string(*namespace) != "" {
		ns = string(*namespace)
	}
	return types.NamespacedName{
		Namespace: ns,
		Name:      string(name),
	}
}

// ReconcilerOptions contains configuration for setting up GARI reconcilers.
type ReconcilerOptions struct {
	ControllerName       string
	OnGatewaysUpdate     func([]*gatewayv1.Gateway)
	AddressProvider      AddressProvider
	GatewayFilter        func(gw *gatewayv1.Gateway) bool
	DisableStatusUpdates bool
}

// RegisterReconcilers registers all GARI reconcilers and informer event handlers with the given Manager.
func RegisterReconcilers(mgr ctrl.Manager, st *state.State, p *proxy.Proxy, opts ReconcilerOptions) error {
	controllerName := opts.ControllerName
	if controllerName == "" {
		controllerName = DefaultControllerName
	}

	if st != nil {
		st.SetControllerName(controllerName)
		st.SetProxy(p)
		st.SetOnGatewaysUpdate(opts.OnGatewaysUpdate)
		st.SetGatewayFilter(opts.GatewayFilter)
		st.SetSynced(false)

		if publisher, ok := opts.AddressProvider.(state.DataplanePublisher); ok {
			st.SetDataplanePublisher(publisher)
		}

		if err := registerInformerHandlers(context.Background(), mgr, st); err != nil {
			return fmt.Errorf("error registering informer event handlers: %w", err)
		}

		if err := mgr.Add(st); err != nil {
			return fmt.Errorf("error adding state runner to manager: %w", err)
		}
	}

	if opts.DisableStatusUpdates {
		return nil
	}

	if err := (&HTTPRouteReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating HTTPRoute controller: %w", err)
	}

	if err := (&TLSRouteReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating TLSRoute controller: %w", err)
	}

	if err := (&GRPCRouteReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating GRPCRoute controller: %w", err)
	}

	if err := (&GatewayClassReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating GatewayClass controller: %w", err)
	}

	if err := (&GatewayReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		State:           st,
		ControllerName:  controllerName,
		AddressProvider: opts.AddressProvider,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating Gateway controller: %w", err)
	}

	if err := (&BackendTLSPolicyReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating BackendTLSPolicy controller: %w", err)
	}

	if err := (&ListenerSetReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		State:          st,
		ControllerName: controllerName,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ListenerSet controller: %w", err)
	}

	return nil
}

func registerInformerHandlers(ctx context.Context, mgr ctrl.Manager, st *state.State) error {
	type registrationEntry struct {
		obj    client.Object
		add    func(obj any)
		update func(oldObj, newObj any)
		delete func(obj any)
	}

	entries := []registrationEntry{
		{
			obj: &gatewayv1.GatewayClass{},
			add: func(obj any) {
				if gc, ok := obj.(*gatewayv1.GatewayClass); ok {
					st.UpsertGatewayClass(gc)
				}
			},
			update: func(oldObj, newObj any) {
				if gc, ok := newObj.(*gatewayv1.GatewayClass); ok {
					st.UpsertGatewayClass(gc)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if gc, ok := obj.(*gatewayv1.GatewayClass); ok {
					st.DeleteGatewayClass(types.NamespacedName{Name: gc.Name})
				}
			},
		},
		{
			obj: &gatewayv1.Gateway{},
			add: func(obj any) {
				if gw, ok := obj.(*gatewayv1.Gateway); ok {
					st.UpsertGateway(gw)
				}
			},
			update: func(oldObj, newObj any) {
				if gw, ok := newObj.(*gatewayv1.Gateway); ok {
					st.UpsertGateway(gw)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if gw, ok := obj.(*gatewayv1.Gateway); ok {
					st.DeleteGateway(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name})
				}
			},
		},
		{
			obj: &gatewayv1.ListenerSet{},
			add: func(obj any) {
				if ls, ok := obj.(*gatewayv1.ListenerSet); ok {
					st.UpsertListenerSet(ls)
				}
			},
			update: func(oldObj, newObj any) {
				if ls, ok := newObj.(*gatewayv1.ListenerSet); ok {
					st.UpsertListenerSet(ls)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if ls, ok := obj.(*gatewayv1.ListenerSet); ok {
					st.DeleteListenerSet(types.NamespacedName{Namespace: ls.Namespace, Name: ls.Name})
				}
			},
		},
		{
			obj: &gatewayv1.HTTPRoute{},
			add: func(obj any) {
				if r, ok := obj.(*gatewayv1.HTTPRoute); ok {
					st.UpsertHTTPRoute(r)
				}
			},
			update: func(oldObj, newObj any) {
				if r, ok := newObj.(*gatewayv1.HTTPRoute); ok {
					st.UpsertHTTPRoute(r)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if r, ok := obj.(*gatewayv1.HTTPRoute); ok {
					st.DeleteHTTPRoute(types.NamespacedName{Namespace: r.Namespace, Name: r.Name})
				}
			},
		},
		{
			obj: &gatewayv1.TLSRoute{},
			add: func(obj any) {
				if r, ok := obj.(*gatewayv1.TLSRoute); ok {
					st.UpsertTLSRoute(r)
				}
			},
			update: func(oldObj, newObj any) {
				if r, ok := newObj.(*gatewayv1.TLSRoute); ok {
					st.UpsertTLSRoute(r)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if r, ok := obj.(*gatewayv1.TLSRoute); ok {
					st.DeleteTLSRoute(types.NamespacedName{Namespace: r.Namespace, Name: r.Name})
				}
			},
		},
		{
			obj: &gatewayv1.GRPCRoute{},
			add: func(obj any) {
				if r, ok := obj.(*gatewayv1.GRPCRoute); ok {
					st.UpsertGRPCRoute(r)
				}
			},
			update: func(oldObj, newObj any) {
				if r, ok := newObj.(*gatewayv1.GRPCRoute); ok {
					st.UpsertGRPCRoute(r)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if r, ok := obj.(*gatewayv1.GRPCRoute); ok {
					st.DeleteGRPCRoute(types.NamespacedName{Namespace: r.Namespace, Name: r.Name})
				}
			},
		},
		{
			obj: &gatewayv1.BackendTLSPolicy{},
			add: func(obj any) {
				if p, ok := obj.(*gatewayv1.BackendTLSPolicy); ok {
					st.UpsertBackendTLSPolicy(p)
				}
			},
			update: func(oldObj, newObj any) {
				if p, ok := newObj.(*gatewayv1.BackendTLSPolicy); ok {
					st.UpsertBackendTLSPolicy(p)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if p, ok := obj.(*gatewayv1.BackendTLSPolicy); ok {
					st.DeleteBackendTLSPolicy(types.NamespacedName{Namespace: p.Namespace, Name: p.Name})
				}
			},
		},
		{
			obj: &corev1.Service{},
			add: func(obj any) {
				if svc, ok := obj.(*corev1.Service); ok {
					st.UpsertService(svc)
				}
			},
			update: func(oldObj, newObj any) {
				if svc, ok := newObj.(*corev1.Service); ok {
					st.UpsertService(svc)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if svc, ok := obj.(*corev1.Service); ok {
					st.DeleteService(types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name})
				}
			},
		},
		{
			obj: &corev1.Secret{},
			add: func(obj any) {
				if s, ok := obj.(*corev1.Secret); ok {
					if isDataplaneConfigSecret(s) {
						return
					}
					st.UpsertSecret(s)
				}
			},
			update: func(oldObj, newObj any) {
				if s, ok := newObj.(*corev1.Secret); ok {
					if isDataplaneConfigSecret(s) {
						return
					}
					st.UpsertSecret(s)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if s, ok := obj.(*corev1.Secret); ok {
					if isDataplaneConfigSecret(s) {
						return
					}
					st.DeleteSecret(types.NamespacedName{Namespace: s.Namespace, Name: s.Name})
				}
			},
		},
		{
			obj: &corev1.ConfigMap{},
			add: func(obj any) {
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					st.UpsertConfigMap(cm)
				}
			},
			update: func(oldObj, newObj any) {
				if cm, ok := newObj.(*corev1.ConfigMap); ok {
					st.UpsertConfigMap(cm)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					st.DeleteConfigMap(types.NamespacedName{Namespace: cm.Namespace, Name: cm.Name})
				}
			},
		},
		{
			obj: &corev1.Namespace{},
			add: func(obj any) {
				if ns, ok := obj.(*corev1.Namespace); ok {
					st.UpsertNamespace(ns)
				}
			},
			update: func(oldObj, newObj any) {
				if ns, ok := newObj.(*corev1.Namespace); ok {
					st.UpsertNamespace(ns)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if ns, ok := obj.(*corev1.Namespace); ok {
					st.DeleteNamespace(ns.Name)
				}
			},
		},
		{
			obj: &gatewayv1beta1.ReferenceGrant{},
			add: func(obj any) {
				if rg, ok := obj.(*gatewayv1beta1.ReferenceGrant); ok {
					st.UpsertReferenceGrant(rg)
				}
			},
			update: func(oldObj, newObj any) {
				if rg, ok := newObj.(*gatewayv1beta1.ReferenceGrant); ok {
					st.UpsertReferenceGrant(rg)
				}
			},
			delete: func(obj any) {
				if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
					obj = tombstone.Obj
				}
				if rg, ok := obj.(*gatewayv1beta1.ReferenceGrant); ok {
					st.DeleteReferenceGrant(types.NamespacedName{Namespace: rg.Namespace, Name: rg.Name})
				}
			},
		},
	}

	for _, entry := range entries {
		informer, err := mgr.GetCache().GetInformer(ctx, entry.obj)
		if err != nil {
			return fmt.Errorf("error getting informer for %T: %w", entry.obj, err)
		}
		reg, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc:    entry.add,
			UpdateFunc: entry.update,
			DeleteFunc: entry.delete,
		})
		if err != nil {
			return fmt.Errorf("error adding event handler for %T: %w", entry.obj, err)
		}
		st.AddRegistration(reg)
	}

	return nil
}

func isDataplaneConfigSecret(s *corev1.Secret) bool {
	if s == nil || s.Labels == nil {
		return false
	}
	return s.Labels[state.LabelManagedBy] == state.ManagedByValue &&
		s.Labels[state.LabelAppName] == state.AppNameValue
}
