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

	appsv1 "k8s.io/api/apps/v1"
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
func New(client client.Client, options ...singlepod.Option) *HostPortAddressProvider {
	wrappedOptions := make([]singlepod.Option, 0, len(options)+2)
	wrappedOptions = append(wrappedOptions, options...)
	wrappedOptions = append(wrappedOptions,
		singlepod.WithNoService(),
		singlepod.WithDeploymentMutator(MutateDeployment),
	)
	return &HostPortAddressProvider{
		provider: singlepod.NewAddressProvider(client, wrappedOptions...),
	}
}

// GatewayAddresses returns the Gateway's addresses and whether the Deployment is ready.
func (provider *HostPortAddressProvider) GatewayAddresses(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addresses, readiness, err := provider.GatewayAddressesWithReadiness(ctx, gateway, effectiveListeners)
	return addresses, readiness.Ready, err
}

// GatewayAddressesWithReadiness reconciles the Gateway's data-plane infrastructure and returns
// addresses and readiness status. In this step, address resolution is not yet implemented, so
// the provider reports what the wrapped singlepod.AddressProvider reports with no Service:
// no address and not ready. Node address resolution will be added in a subsequent step.
func (provider *HostPortAddressProvider) GatewayAddressesWithReadiness(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	return provider.provider.GatewayAddressesWithReadiness(ctx, gateway, effectiveListeners)
}

// SupportedAddressTypes returns nil because host-port data planes bind directly to node host
// ports and do not support requested spec.addresses. Returning nil causes Gateway API
// to reject requested spec.addresses with Accepted=False and reason UnsupportedAddress.
func (provider *HostPortAddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return nil
}

// SetupWatches registers watches on managed resources with the Gateway controller.
func (provider *HostPortAddressProvider) SetupWatches(manager ctrl.Manager, builder *builder.Builder) error {
	return provider.provider.SetupWatches(manager, builder)
}

// SetState sets the State reference on the wrapped singlepod.AddressProvider.
func (provider *HostPortAddressProvider) SetState(s *state.State) {
	provider.provider.SetState(s)
}

// MutateDeployment configures the Deployment with host-port container port mappings
// and a rolling update strategy with maxSurge: 0 and maxUnavailable: 1.
func MutateDeployment(deployment *appsv1ac.DeploymentApplyConfiguration, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error {
	if deployment.Spec == nil {
		deployment.WithSpec(appsv1ac.DeploymentSpec())
	}
	// The rollout strategy is a rolling update with no surge and one unavailable,
	// because two pods cannot hold the same host port on one node.
	deployment.Spec.WithStrategy(appsv1ac.DeploymentStrategy().
		WithType(appsv1.RollingUpdateDeploymentStrategyType).
		WithRollingUpdate(appsv1ac.RollingUpdateDeployment().
			WithMaxSurge(intstr.FromInt32(0)).
			WithMaxUnavailable(intstr.FromInt32(1)),
		),
	)

	var dataplaneContainer *corev1ac.ContainerApplyConfiguration
	if deployment.Spec.Template != nil && deployment.Spec.Template.Spec != nil {
		for index := range deployment.Spec.Template.Spec.Containers {
			container := &deployment.Spec.Template.Spec.Containers[index]
			if container.Name != nil && *container.Name == singlepod.DataplaneContainerName {
				dataplaneContainer = container
				break
			}
		}
	}
	if dataplaneContainer == nil {
		return fmt.Errorf("container %q not found in deployment", singlepod.DataplaneContainerName)
	}

	var httpPort, httpsPort int32
	if gateway != nil {
		for _, listener := range gateway.Spec.Listeners {
			switch listener.Protocol {
			case gatewayv1.HTTPProtocolType:
				if httpPort == 0 {
					httpPort = int32(listener.Port)
				}
			case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
				if httpsPort == 0 {
					httpsPort = int32(listener.Port)
				}
			}
		}
	}

	for index := range dataplaneContainer.Ports {
		port := &dataplaneContainer.Ports[index]
		portName := ""
		if port.Name != nil {
			portName = *port.Name
		}
		switch portName {
		case "http":
			if httpPort > 0 {
				port.WithHostPort(httpPort)
			}
		case "https", "http3":
			if httpsPort > 0 {
				port.WithHostPort(httpsPort)
			}
		default:
			if port.ContainerPort != nil {
				port.WithHostPort(*port.ContainerPort)
			}
		}
	}

	return nil
}
