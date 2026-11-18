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

package hostport

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

var (
	_ controller.AddressProvider          = (*HostPortAddressProvider)(nil)
	_ controller.AddressReadinessProvider = (*HostPortAddressProvider)(nil)
	_ controller.AddressTypeProvider      = (*HostPortAddressProvider)(nil)
	_ controller.AddressWatcher           = (*HostPortAddressProvider)(nil)
)

// HostPortAddressProvider manages host-port data planes for localgateway.
// It wraps singlepod.AddressProvider to configure host-port container mappings,
// zero-surge rolling updates, and no Service creation.
//
// Addresses: In this step, the provider reports what the wrapped singlepod.AddressProvider
// reports with no Service: no address and not ready. Node address resolution
// (the address rule) is the next step.
type HostPortAddressProvider struct {
	provider *singlepod.AddressProvider
}

// New creates a new HostPortAddressProvider wrapping a singlepod.AddressProvider
// configured with WithNoService() and the host-port Deployment mutator.
func New(c client.Client, opts ...singlepod.Option) *HostPortAddressProvider {
	wrappedOpts := make([]singlepod.Option, 0, len(opts)+2)
	wrappedOpts = append(wrappedOpts, opts...)
	wrappedOpts = append(wrappedOpts,
		singlepod.WithNoService(),
		singlepod.WithDeploymentMutator(MutateDeployment),
	)
	return &HostPortAddressProvider{
		provider: singlepod.NewAddressProvider(c, wrappedOpts...),
	}
}

// NewHostPortAddressProvider creates a new HostPortAddressProvider.
func NewHostPortAddressProvider(c client.Client, opts ...singlepod.Option) *HostPortAddressProvider {
	return New(c, opts...)
}

// NewAddressProvider creates a new HostPortAddressProvider.
func NewAddressProvider(c client.Client, opts ...singlepod.Option) *HostPortAddressProvider {
	return New(c, opts...)
}

// GatewayAddresses returns the Gateway's addresses and whether the Deployment is ready.
func (p *HostPortAddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addrs, readiness, err := p.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
	return addrs, readiness.Ready, err
}

// GatewayAddressesWithReadiness reconciles the Gateway's data-plane infrastructure and returns
// addresses and readiness status. In this step, address resolution is not yet implemented, so
// the provider reports what the wrapped singlepod.AddressProvider reports with no Service:
// no address and not ready. Node address resolution will be added in a subsequent step.
func (p *HostPortAddressProvider) GatewayAddressesWithReadiness(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	return p.provider.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
}

// SupportedAddressTypes returns nil because host-port data planes bind directly to node host
// ports and do not support requested spec.addresses. Returning nil causes Gateway API
// to reject requested spec.addresses with Accepted=False and reason UnsupportedAddress.
func (p *HostPortAddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return nil
}

// SetupWatches registers watches on managed resources with the Gateway controller.
func (p *HostPortAddressProvider) SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error {
	if bldr == nil {
		return nil
	}
	return p.provider.SetupWatches(mgr, bldr)
}

// SetState sets the State reference on the wrapped singlepod.AddressProvider.
func (p *HostPortAddressProvider) SetState(s *state.State) {
	p.provider.SetState(s)
}

// MutateDeployment configures the Deployment with host-port container port mappings
// and a rolling update strategy with maxSurge: 0 and maxUnavailable: 1.
func MutateDeployment(deploy *appsv1ac.DeploymentApplyConfiguration, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error {
	if deploy.Spec == nil {
		deploy.WithSpec(appsv1ac.DeploymentSpec())
	}
	// The rollout strategy is a rolling update with no surge and one unavailable,
	// because two pods cannot hold the same host port on one node.
	deploy.Spec.WithStrategy(appsv1ac.DeploymentStrategy().
		WithType(appsv1.RollingUpdateDeploymentStrategyType).
		WithRollingUpdate(appsv1ac.RollingUpdateDeployment().
			WithMaxSurge(intstr.FromInt32(0)).
			WithMaxUnavailable(intstr.FromInt32(1)),
		),
	)

	containerPorts := buildContainerPorts(gw, effectiveListeners)
	if deploy.Spec.Template != nil && deploy.Spec.Template.Spec != nil {
		for i := range deploy.Spec.Template.Spec.Containers {
			c := &deploy.Spec.Template.Spec.Containers[i]
			if c.Name != nil && *c.Name == "dataplane" {
				c.Ports = nil
				c.WithPorts(containerPorts...)
				return nil
			}
		}
		if len(deploy.Spec.Template.Spec.Containers) > 0 {
			c := &deploy.Spec.Template.Spec.Containers[0]
			c.Ports = nil
			c.WithPorts(containerPorts...)
		}
	}
	return nil
}

type listenerItem struct {
	port       gatewayv1.PortNumber
	protocol   gatewayv1.ProtocolType
	conflicted bool
}

func buildContainerPorts(gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) []*corev1ac.ContainerPortApplyConfiguration {
	var items []listenerItem
	if len(effectiveListeners) > 0 {
		items = make([]listenerItem, 0, len(effectiveListeners))
		for _, el := range effectiveListeners {
			items = append(items, listenerItem{
				port:       el.Port,
				protocol:   el.Protocol,
				conflicted: el.IsConflicted(),
			})
		}
	} else if gw != nil {
		items = make([]listenerItem, 0, len(gw.Spec.Listeners))
		for _, l := range gw.Spec.Listeners {
			items = append(items, listenerItem{
				port:     l.Port,
				protocol: l.Protocol,
			})
		}
	}

	uniquePorts := make(map[gatewayv1.PortNumber]gatewayv1.ProtocolType)
	var udpPorts []int
	seenUDPPort := make(map[gatewayv1.PortNumber]bool)

	for _, item := range items {
		if item.conflicted {
			continue
		}
		if item.protocol == gatewayv1.UDPProtocolType {
			if !state.IsReservedDataPlanePort(item.port) && !seenUDPPort[item.port] {
				seenUDPPort[item.port] = true
				udpPorts = append(udpPorts, int(item.port))
			}
			continue
		}
		if item.protocol == gatewayv1.TCPProtocolType && state.IsReservedDataPlanePort(item.port) {
			continue
		}
		if prev, ok := uniquePorts[item.port]; !ok {
			uniquePorts[item.port] = item.protocol
		} else if item.protocol == gatewayv1.HTTPSProtocolType {
			uniquePorts[item.port] = gatewayv1.HTTPSProtocolType
		} else if item.protocol == gatewayv1.TLSProtocolType && prev != gatewayv1.HTTPSProtocolType {
			uniquePorts[item.port] = gatewayv1.TLSProtocolType
		}
	}

	sort.Ints(udpPorts)

	sortedPorts := make([]int, 0, len(uniquePorts))
	for port := range uniquePorts {
		sortedPorts = append(sortedPorts, int(port))
	}
	sort.Ints(sortedPorts)

	var containerPorts []*corev1ac.ContainerPortApplyConfiguration
	for _, portInt := range sortedPorts {
		port := gatewayv1.PortNumber(portInt)
		protocol := uniquePorts[port]
		if protocol == gatewayv1.TCPProtocolType && state.IsReservedDataPlanePort(port) {
			continue
		}
		name := fmt.Sprintf("%s-%d", strings.ToLower(string(protocol)), port)
		containerPort := int32(port)
		if protocol == gatewayv1.HTTPProtocolType {
			containerPort = singlepod.DataPlaneHTTPPort
			if port == 80 {
				name = "http"
			}
		} else if protocol == gatewayv1.HTTPSProtocolType || protocol == gatewayv1.TLSProtocolType {
			containerPort = singlepod.DataPlaneHTTPSPort
			if port == 443 && protocol == gatewayv1.HTTPSProtocolType {
				name = "https"
			}
		}
		containerPorts = append(containerPorts,
			corev1ac.ContainerPort().
				WithName(name).
				WithContainerPort(containerPort).
				WithHostPort(int32(port)).
				WithProtocol(corev1.ProtocolTCP),
		)
		if protocol == gatewayv1.HTTPSProtocolType {
			http3Name := fmt.Sprintf("http3-%d", port)
			if port == 443 {
				http3Name = "http3"
			}
			containerPorts = append(containerPorts,
				corev1ac.ContainerPort().
					WithName(http3Name).
					WithContainerPort(singlepod.DataPlaneHTTPSPort).
					WithHostPort(int32(port)).
					WithProtocol(corev1.ProtocolUDP),
			)
		}
	}
	for _, portInt := range udpPorts {
		port := gatewayv1.PortNumber(portInt)
		if state.IsReservedDataPlanePort(port) {
			continue
		}
		containerPorts = append(containerPorts,
			corev1ac.ContainerPort().
				WithName(fmt.Sprintf("udp-%d", portInt)).
				WithContainerPort(int32(portInt)).
				WithHostPort(int32(portInt)).
				WithProtocol(corev1.ProtocolUDP),
		)
	}

	return containerPorts
}
