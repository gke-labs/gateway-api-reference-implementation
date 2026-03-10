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
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type BackendTLSPolicyReconciler struct {
	GatewayControllerOptions
}

func (r *BackendTLSPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	policy := &gatewayv1.BackendTLSPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			r.State.DeleteBackendTLSPolicy(req.NamespacedName)
			r.updateProxy()
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	r.State.UpsertBackendTLSPolicy(policy)

	if r.SkipStatusUpdate {
		r.updateProxy()
		return ctrl.Result{}, nil
	}

	// Find all Gateways that use this policy (via Services referenced in HTTPRoutes)
	gateways := r.State.GetGateways()
	routes := r.State.GetHTTPRoutes()
	allPolicies := r.State.GetBackendTLSPolicies()

	// Conflict resolution
	isConflicted := false
	var conflictingPolicy string
	for _, targetRef := range policy.Spec.TargetRefs {
		if string(targetRef.Group) != "" && string(targetRef.Group) != "gateway.networking.k8s.io" {
			continue
		}
		if string(targetRef.Kind) != "Service" {
			continue
		}

		targetSvcNamespace := policy.Namespace
		targetSvcName := string(targetRef.Name)

		for _, p := range allPolicies {
			if p.Namespace == policy.Namespace && p.Name == policy.Name {
				continue
			}

			for _, t := range p.Spec.TargetRefs {
				if (string(t.Group) == "" || string(t.Group) == "gateway.networking.k8s.io") && string(t.Kind) == "Service" {
					if p.Namespace == targetSvcNamespace && string(t.Name) == targetSvcName {
						// Found another policy targeting the same service
						// Check if it's older
						if p.CreationTimestamp.Time.Before(policy.CreationTimestamp.Time) {
							isConflicted = true
							conflictingPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
							break
						}
						if p.CreationTimestamp.Time.Equal(policy.CreationTimestamp.Time) {
							if p.Namespace < policy.Namespace || (p.Namespace == policy.Namespace && p.Name < policy.Name) {
								isConflicted = true
								conflictingPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
								break
							}
						}
					}
				}
			}
			if isConflicted {
				break
			}
		}
		if isConflicted {
			break
		}
	}

	// Validate CA certificates
	var caCerts [][]byte
	var unresolvedRefs []string
	for _, caRef := range policy.Spec.Validation.CACertificateRefs {
		if string(caRef.Group) == "" && string(caRef.Kind) == "ConfigMap" {
			cm := &corev1.ConfigMap{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: policy.Namespace, Name: string(caRef.Name)}, cm); err != nil {
				unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
			} else {
				var data []byte
				if d, ok := cm.Data["ca.crt"]; ok {
					data = []byte(d)
				} else if d, ok := cm.BinaryData["ca.crt"]; ok {
					data = d
				}

				if len(data) == 0 {
					unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
				} else {
					// Verify it's a valid PEM block
					block, _ := pem.Decode(data)
					if block == nil || block.Type != "CERTIFICATE" {
						unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
					} else {
						caCerts = append(caCerts, data)
					}
				}
			}
		} else {
			unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
		}
	}

	acceptedStatus := metav1.ConditionTrue
	acceptedReason := gatewayv1.PolicyReasonAccepted
	acceptedMessage := "Policy accepted"

	resolvedRefsStatus := metav1.ConditionTrue
	resolvedRefsReason := gatewayv1.BackendTLSPolicyReasonResolvedRefs
	resolvedRefsMessage := "All references resolved"

	if len(unresolvedRefs) > 0 {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = "NoValidCACertificate"
		acceptedMessage = fmt.Sprintf("Unresolved or invalid CA certificate references: %v", unresolvedRefs)

		resolvedRefsStatus = metav1.ConditionFalse
		resolvedRefsReason = "InvalidCACertificateRef"
		resolvedRefsMessage = fmt.Sprintf("Unresolved or invalid CA certificate references: %v", unresolvedRefs)
	}

	if isConflicted {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = gatewayv1.PolicyReasonConflicted
		acceptedMessage = fmt.Sprintf("Conflicted with older policy: %s", conflictingPolicy)
	}

	var ancestors []gatewayv1.PolicyAncestorStatus

	for _, gw := range gateways {
		usesPolicy := false
		for _, route := range routes {
			if route.MatchesGateway(gw.Gateway, ControllerName) {
				for _, rule := range route.Spec.Rules {
					for _, backendRef := range rule.BackendRefs {
						if string(state.ValueOf(backendRef.Kind)) == "Service" || state.ValueOf(backendRef.Kind) == "" {
							ns := route.Namespace
							if backendRef.Namespace != nil {
								ns = string(*backendRef.Namespace)
							}

							for _, targetRef := range policy.Spec.TargetRefs {
								if ns == policy.Namespace && string(backendRef.Name) == string(targetRef.Name) {
									usesPolicy = true
									break
								}
							}
						}
						if usesPolicy {
							break
						}
					}
					if usesPolicy {
						break
					}
				}
			}
			if usesPolicy {
				break
			}
		}

		if usesPolicy {
			ancestors = append(ancestors, gatewayv1.PolicyAncestorStatus{
				AncestorRef: gatewayv1.ParentReference{
					Group:     state.Ptr(gatewayv1.Group("gateway.networking.k8s.io")),
					Kind:      state.Ptr(gatewayv1.Kind("Gateway")),
					Namespace: state.Ptr(gatewayv1.Namespace(gw.Namespace)),
					Name:      gatewayv1.ObjectName(gw.Name),
				},
				ControllerName: gatewayv1.GatewayController(ControllerName),
				Conditions: []metav1.Condition{
					{
						Type:               string(gatewayv1.PolicyConditionAccepted),
						Status:             acceptedStatus,
						ObservedGeneration: policy.Generation,
						LastTransitionTime: metav1.Now(),
						Reason:             string(acceptedReason),
						Message:            acceptedMessage,
					},
					{
						Type:               string(gatewayv1.BackendTLSPolicyConditionResolvedRefs),
						Status:             resolvedRefsStatus,
						ObservedGeneration: policy.Generation,
						LastTransitionTime: metav1.Now(),
						Reason:             string(resolvedRefsReason),
						Message:            resolvedRefsMessage,
					},
				},
			})
		}
	}

	updated := false
	if len(policy.Status.Ancestors) != len(ancestors) {
		updated = true
	} else {
		for i := range ancestors {
			if !reflect.DeepEqual(policy.Status.Ancestors[i].AncestorRef, ancestors[i].AncestorRef) ||
				string(policy.Status.Ancestors[i].ControllerName) != string(ancestors[i].ControllerName) ||
				len(policy.Status.Ancestors[i].Conditions) != len(ancestors[i].Conditions) {
				updated = true
				break
			}
			for j := range ancestors[i].Conditions {
				matched := false
				for k := range policy.Status.Ancestors[i].Conditions {
					if policy.Status.Ancestors[i].Conditions[k].Type == ancestors[i].Conditions[j].Type {
						if policy.Status.Ancestors[i].Conditions[k].Status == ancestors[i].Conditions[j].Status &&
							policy.Status.Ancestors[i].Conditions[k].ObservedGeneration == ancestors[i].Conditions[j].ObservedGeneration &&
							policy.Status.Ancestors[i].Conditions[k].Reason == ancestors[i].Conditions[j].Reason &&
							policy.Status.Ancestors[i].Conditions[k].Message == ancestors[i].Conditions[j].Message {
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
		policy.Status.Ancestors = ancestors
		if err := r.Status().Update(ctx, policy); err != nil {
			l.Error(err, "unable to update BackendTLSPolicy status")
			return ctrl.Result{}, err
		}
	}

	r.State.UpsertBackendTLSPolicy(policy)
	_ = caCerts // keep for now
	r.updateProxy()

	l.Info("Updated BackendTLSPolicy status and proxy")

	return ctrl.Result{}, nil
}

func (r *BackendTLSPolicyReconciler) updateProxy() {
	updateProxy(r.State, r.Proxy)
}

func (r *BackendTLSPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.BackendTLSPolicy{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			cm := obj.(*corev1.ConfigMap)
			// Find all BackendTLSPolicies that reference this ConfigMap
			var list gatewayv1.BackendTLSPolicyList
			if err := mgr.GetClient().List(ctx, &list, client.InNamespace(cm.Namespace)); err != nil {
				return nil
			}
			var requests []ctrl.Request
			for _, policy := range list.Items {
				for _, caRef := range policy.Spec.Validation.CACertificateRefs {
					if string(caRef.Group) == "" && string(caRef.Kind) == "ConfigMap" && string(caRef.Name) == cm.Name {
						requests = append(requests, ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: policy.Namespace,
								Name:      policy.Name,
							},
						})
						break
					}
				}
			}
			return requests
		})).
		Complete(r)
}
