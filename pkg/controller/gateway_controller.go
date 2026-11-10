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
	"errors"
	"fmt"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// CertificateSourceOptionKey is the tls.options key used to select a certificate source for a listener.
const CertificateSourceOptionKey = state.CertificateSourceOptionKey

// CertificateResult contains the resolved certificates and condition details for a listener.
type CertificateResult = state.CertificateResult

// CertificateSource supplies TLS certificates for a Gateway's listeners.
// Implementations must be non-blocking and must not modify gw or listener (they are shared State objects).
type CertificateSource = state.CertificateSource

// TriggerableCertificateSource is an optional interface that a CertificateSource can implement
// to receive a trigger callback when registered with GARI.
type TriggerableCertificateSource = state.TriggerableCertificateSource

// SecretsCertificateSource resolves certificates from Secret references specified in listener.TLS.CertificateRefs.
type SecretsCertificateSource = state.SecretsCertificateSource

type GatewayClassReconciler struct {
	client.Client
	APIReader      client.Reader
	Scheme         *runtime.Scheme
	State          *state.State
	ControllerName string
	CRDView        CRDViewReader
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

	var crdBundleVersion *string
	if r.CRDView != nil {
		snapshot := r.CRDView.Snapshot()
		if snapshot.BundleVersion != "" {
			crdBundleVersion = &snapshot.BundleVersion
		}
	}

	var desired gatewayv1.GatewayClassStatus
	if r.State != nil {
		d, ok := r.State.GetDesiredGatewayClassStatus(req.NamespacedName)
		if !ok {
			return ctrl.Result{}, nil
		}
		desired = d
	} else {
		desired = state.ComputeDesiredGatewayClassStatus(&gc, r.ControllerName, crdBundleVersion)
	}

	if state.MergeGatewayClassStatus(&gc.Status, desired) {
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
	bldr := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{})
	if r.State != nil {
		bldr.WatchesRawSource(r.State.GatewayClassSource())
	}
	return bldr.Complete(r)
}

// AddressProvider returns the addresses to report in Gateway.status.addresses and whether the Gateway infrastructure is ready.
// An empty result means the address is not assigned yet.
//
// The ready flag indicates whether the data path from the reported addresses to this Gateway's
// listeners is serving the Gateway's current configuration, as far as the provider can tell.
// Concrete providers approximate this readiness contract using available infrastructure signals,
// but fall short of confirming that the latest configuration revision is actively being served.
type AddressProvider interface {
	GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) (addresses []gatewayv1.GatewayStatusAddress, ready bool, err error)
}

// AddressWatcher is an optional interface that an AddressProvider can implement
// to register custom watches with the Gateway controller.
type AddressWatcher interface {
	SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error
}

// AddressReadinessProvider is an optional interface that an AddressProvider can implement
// to report addresses and detailed readiness state (including reason and message) in a single call.
// GatewayReadiness.Ready shares the same semantics as AddressProvider's ready return value:
// the data path from the reported addresses to this Gateway's listeners is serving the Gateway's
// current configuration, as far as the provider can tell. Like AddressProvider, providers
// implementing AddressReadinessProvider approximate this signal and fall short of an end-to-end
// confirmation that the current configuration is applied by all data-plane replicas.
type AddressReadinessProvider interface {
	GatewayAddressesWithReadiness(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error)
}

// AddressTypeProvider is an optional interface that an AddressProvider can implement
// to declare which address types it supports for requested addresses (spec.addresses).
// If not implemented, the provider supports no address types, and any Gateway with
// requested addresses will receive Accepted=False with reason UnsupportedAddress.
type AddressTypeProvider interface {
	SupportedAddressTypes() []gatewayv1.AddressType
}

// OwnershipConflictError indicates that an existing resource in the cluster is not owned by the Gateway being reconciled.
type OwnershipConflictError = state.OwnershipConflictError

// DefaultConflictRequeueDelay is the duration after which a Gateway with an ownership conflict is requeued.
const DefaultConflictRequeueDelay = time.Minute

// GatewayStatusHook is an optional hook invoked by GatewayReconciler after computing
// the desired Gateway status and before writing it to the API server.
// The hook receives a deep copy of the desired status and may adjust Programmed
// (status, reason, and message) and addresses, downgrade Accepted to False,
// and add its own condition types.
// The gw parameter must not be modified.
// GARI retains ownership of Accepted (other than downgrading), listener conditions,
// and other core status fields.
// The hook should read from local/cached state and avoid slow or blocking remote calls,
// as it executes on GARI's reconcile path.
type GatewayStatusHook func(ctx context.Context, gw *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error

type GatewayReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	State                *state.State
	ControllerName       string
	AddressProvider      AddressProvider
	ConflictRequeueDelay time.Duration
	GatewayStatusHook    GatewayStatusHook
}

// EnqueueGateway requests a reconcile of the given Gateway in the Gateway controller.
func (r *GatewayReconciler) EnqueueGateway(req types.NamespacedName) {
	if r.State != nil {
		r.State.EnqueueGateway(req)
	}
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	gw := &gatewayv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var requeueAfter time.Duration
	if r.State != nil {
		// Verify this Gateway is managed by us in State before requesting addresses
		gc, ok := r.State.GetGatewayClass(string(gw.Spec.GatewayClassName))
		if !ok || string(gc.Spec.ControllerName) != r.ControllerName {
			return ctrl.Result{}, nil
		}

		if r.AddressProvider != nil {
			var supportedTypes []gatewayv1.AddressType
			if atp, ok := r.AddressProvider.(AddressTypeProvider); ok {
				supportedTypes = atp.SupportedAddressTypes()
			} else if r.State != nil {
				supportedTypes = r.State.GetSupportedAddressTypes()
			}

			var paramsErr error
			if r.State != nil {
				var found bool
				_, found, paramsErr = r.State.GetGatewayParameters(req.NamespacedName)
				if !found {
					// State has not computed outputs for this Gateway yet.
					// Leave Gateway pending without provisioning default resources;
					// State diff will enqueue the Gateway once outputs are computed.
					return ctrl.Result{}, nil
				}
			}

			if paramsErr != nil {
				// Parameters resolution error (Gateway or GatewayClass): fail closed, leave existing resources as they are.
				r.State.SetGatewayProvisioningError(req.NamespacedName, "")
				r.State.SetGatewayAddresses(req.NamespacedName, nil)
				r.State.SetGatewayReadiness(req.NamespacedName, state.GatewayReadiness{
					Ready:   false,
					Reason:  string(gatewayv1.GatewayReasonInvalidParameters),
					Message: paramsErr.Error(),
				})
			} else if unsupp, _ := state.HasUnsupportedAddress(gw.Spec.Addresses, supportedTypes); unsupp {
				r.State.SetGatewayProvisioningError(req.NamespacedName, "")
				r.State.SetGatewayAddresses(req.NamespacedName, nil)
				r.State.SetGatewayReadiness(req.NamespacedName, state.GatewayReadiness{Ready: false})
			} else {
				effectiveListeners := r.State.GetEffectiveListeners(req.NamespacedName)
				var (
					providedAddresses []gatewayv1.GatewayStatusAddress
					readiness         state.GatewayReadiness
					err               error
				)
				if arp, ok := r.AddressProvider.(AddressReadinessProvider); ok {
					providedAddresses, readiness, err = arp.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
				} else {
					var ready bool
					providedAddresses, ready, err = r.AddressProvider.GatewayAddresses(ctx, gw, effectiveListeners)
					readiness = state.GatewayReadiness{Ready: ready}
				}
				if err != nil {
					var conflictErr *OwnershipConflictError
					if errors.As(err, &conflictErr) {
						l.Error(err, "ownership conflict provisioning gateway")
						r.State.SetGatewayProvisioningError(req.NamespacedName, conflictErr.Error())
						r.State.SetGatewayReadiness(req.NamespacedName, state.GatewayReadiness{Ready: false})
						delay := r.ConflictRequeueDelay
						if delay == 0 {
							delay = DefaultConflictRequeueDelay
						}
						if requeueAfter == 0 || delay < requeueAfter {
							requeueAfter = delay
						}
					} else {
						l.Error(err, "unable to provision or fetch gateway addresses from address provider")
						return ctrl.Result{}, err
					}
				} else {
					r.State.SetGatewayProvisioningError(req.NamespacedName, "")
					r.State.SetGatewayAddresses(req.NamespacedName, providedAddresses)
					r.State.SetGatewayReadiness(req.NamespacedName, readiness)
				}
			}
		}

		desired, ok := r.State.GetDesiredGatewayStatus(req.NamespacedName)
		if !ok {
			return ctrl.Result{RequeueAfter: requeueAfter}, nil
		}

		if r.GatewayStatusHook != nil {
			desiredCopy := desired.DeepCopy()
			if err := r.GatewayStatusHook(ctx, gw, desiredCopy); err != nil {
				l.Error(err, "GatewayStatusHook failed")
				return ctrl.Result{}, err
			}
			// Enforce hook contract: hook may downgrade Accepted to False, but cannot upgrade it to True.
			var origAccepted *metav1.Condition
			for _, c := range desired.Conditions {
				if c.Type == string(gatewayv1.GatewayConditionAccepted) {
					origAccepted = &c
					break
				}
			}
			if origAccepted != nil && origAccepted.Status == metav1.ConditionFalse {
				for i, c := range desiredCopy.Conditions {
					if c.Type == string(gatewayv1.GatewayConditionAccepted) && c.Status != metav1.ConditionFalse {
						desiredCopy.Conditions[i] = *origAccepted
						break
					}
				}
			}
			desired = *desiredCopy
		}

		if state.MergeGatewayStatus(&gw.Status, desired) {
			if err := r.Status().Update(ctx, gw); err != nil {
				l.Error(err, "unable to update Gateway status")
				return ctrl.Result{}, err
			}
			l.Info("Updated Gateway status", "addresses", gw.Status.Addresses)
		}
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.ControllerName == "" {
		return fmt.Errorf("ControllerName is required")
	}
	bldr := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{})

	if r.State != nil {
		if sp, ok := r.AddressProvider.(interface{ SetState(*state.State) }); ok {
			sp.SetState(r.State)
		}
		bldr.WatchesRawSource(r.State.GatewaySource())
	}

	if watcher, ok := r.AddressProvider.(AddressWatcher); ok {
		if err := watcher.SetupWatches(mgr, bldr); err != nil {
			return fmt.Errorf("error setting up address provider watches: %w", err)
		}
	}

	return bldr.Complete(r)
}
