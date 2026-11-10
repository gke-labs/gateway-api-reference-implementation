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

package tunnel

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TunnelState provides tunnel connectivity and registration status needed by AddressProvider.
type TunnelState interface {
	IsConnected() bool
	HasRegisteredHostnames(hostnames []string) bool
	AddStateChangeListener(listener func())
}

var (
	_ controller.AddressProvider          = (*AddressProvider)(nil)
	_ controller.AddressWatcher           = (*AddressProvider)(nil)
	_ controller.AddressReadinessProvider = (*AddressProvider)(nil)
)

// AddressProvider reports frontend public addresses in Gateway status
// and gates readiness on tunnel connectivity and hostname registration.
//
// Readiness approximation: reports ready when the reverse tunnel session to the frontend is
// connected and the frontend has acknowledged registration of this Gateway's hostnames.
//
// Gap: frontend acknowledgement confirms hostname routing at the tunnel edge, but does not
// confirm that the data plane behind the tunnel has applied this Gateway's current configuration
// (listeners, routes, and certificates) or that the current configuration is actively being served.
type AddressProvider struct {
	mu             sync.Mutex
	tunnelState    TunnelState
	addresses      []gatewayv1.GatewayStatusAddress
	controllerName string
	client         client.Client
	eventCh        chan event.GenericEvent
	knownGateways  map[types.NamespacedName]struct{}
}

// NewAddressProvider creates a new AddressProvider reporting the specified addresses.
func NewAddressProvider(tunnelState TunnelState, addrs ...string) *AddressProvider {
	p := &AddressProvider{
		tunnelState:   tunnelState,
		addresses:     ParseGatewayAddresses(addrs),
		eventCh:       make(chan event.GenericEvent, 10),
		knownGateways: make(map[types.NamespacedName]struct{}),
	}
	if tunnelState != nil {
		tunnelState.AddStateChangeListener(func() {
			p.triggerReconcile()
		})
	}
	return p
}

// SetControllerName sets the GatewayClass controller name to filter Gateways by.
func (p *AddressProvider) SetControllerName(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.controllerName = name
}

func (p *AddressProvider) triggerReconcile() {
	select {
	case p.eventCh <- event.GenericEvent{}:
	default:
	}
}

// Addresses returns the parsed GatewayStatusAddresses reported by this provider.
func (p *AddressProvider) Addresses() []gatewayv1.GatewayStatusAddress {
	return slices.Clone(p.addresses)
}

// ParseFrontendHost extracts the host portion from a frontend address (e.g. host:port, [ipv6]:port, or host).
func ParseFrontendHost(frontendAddr string) string {
	frontendAddr = strings.TrimSpace(frontendAddr)
	if host, _, err := net.SplitHostPort(frontendAddr); err == nil && host != "" {
		return host
	}
	return frontendAddr
}

// ParseGatewayAddresses converts address strings to GatewayStatusAddress objects,
// inferring IPAddress vs Hostname type.
func ParseGatewayAddresses(addrs []string) []gatewayv1.GatewayStatusAddress {
	var result []gatewayv1.GatewayStatusAddress
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		addrType := gatewayv1.HostnameAddressType
		if net.ParseIP(addr) != nil {
			addrType = gatewayv1.IPAddressType
		}
		result = append(result, gatewayv1.GatewayStatusAddress{
			Type:  &addrType,
			Value: addr,
		})
	}
	return result
}

// GatewayAddresses returns the configured addresses and whether the Gateway is ready.
func (p *AddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addrs, readiness, err := p.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
	return addrs, readiness.Ready, err
}

// GatewayAddressesWithReadiness returns addresses and detailed readiness atomically in a single call.
func (p *AddressProvider) GatewayAddressesWithReadiness(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	if gw != nil {
		p.mu.Lock()
		p.knownGateways[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = struct{}{}
		p.mu.Unlock()
	}

	readiness := p.readinessForGateway(gw)
	return slices.Clone(p.addresses), readiness, nil
}

func (p *AddressProvider) readinessForGateway(gw *gatewayv1.Gateway) state.GatewayReadiness {
	if p.tunnelState == nil {
		return state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: "Tunnel state is unavailable",
		}
	}
	if !p.tunnelState.IsConnected() {
		return state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: "Tunnel session to frontend is not connected",
		}
	}

	var hostnames []string
	if gw != nil {
		hostnames = ExtractHostnames([]*gatewayv1.Gateway{gw})
	}
	if !p.tunnelState.HasRegisteredHostnames(hostnames) {
		return state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: "Waiting for tunnel hostname registration to complete",
		}
	}

	return state.GatewayReadiness{
		Ready:   true,
		Reason:  string(gatewayv1.GatewayReasonProgrammed),
		Message: "Gateway programmed by reference implementation",
	}
}

// SetupWatches registers a watch on tunnel state changes with the Gateway controller.
func (p *AddressProvider) SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error {
	if mgr != nil {
		p.client = mgr.GetClient()
	}
	if bldr != nil {
		bldr.WatchesRawSource(source.Channel(p.eventCh, handler.EnqueueRequestsFromMapFunc(p.mapFunc)))
	}
	return nil
}

func (p *AddressProvider) mapFunc(ctx context.Context, _ client.Object) []reconcile.Request {
	if p.client != nil {
		matchingClasses := make(map[string]bool)
		p.mu.Lock()
		cName := p.controllerName
		p.mu.Unlock()

		if cName != "" {
			var gcList gatewayv1.GatewayClassList
			err := p.client.List(ctx, &gcList)
			if err != nil {
				klog.V(2).Infof("Failed to list GatewayClasses: %v", err)
			} else {
				for _, gc := range gcList.Items {
					if string(gc.Spec.ControllerName) == cName {
						matchingClasses[gc.Name] = true
					}
				}
			}
		}

		var gwList gatewayv1.GatewayList
		if err := p.client.List(ctx, &gwList); err == nil {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.knownGateways = make(map[types.NamespacedName]struct{})
			var reqs []reconcile.Request
			for _, gw := range gwList.Items {
				if len(matchingClasses) > 0 && !matchingClasses[string(gw.Spec.GatewayClassName)] {
					continue
				}
				key := types.NamespacedName{
					Namespace: gw.Namespace,
					Name:      gw.Name,
				}
				p.knownGateways[key] = struct{}{}
				reqs = append(reqs, reconcile.Request{NamespacedName: key})
			}
			return reqs
		} else {
			klog.V(2).Infof("Failed to list Gateways during tunnel change: %v", err)
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	var reqs []reconcile.Request
	for key := range p.knownGateways {
		reqs = append(reqs, reconcile.Request{NamespacedName: key})
	}
	return reqs
}
