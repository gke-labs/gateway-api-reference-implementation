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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	_ controller.AddressProvider     = (*HostPortAddressProvider)(nil)
	_ controller.AddressTypeProvider = (*HostPortAddressProvider)(nil)
	_ controller.AddressWatcher      = (*HostPortAddressProvider)(nil)
)

// HostPortAddressProvider manages host-port data planes for localgateway.
// It wraps singlepod.AddressProvider to configure host-port container mappings,
// zero-surge rolling updates, and no Service creation.
//
// Addresses: The Gateway's addresses are the internal addresses of every node that runs
// a data-plane pod owned by the Gateway's Deployment, sorted and deduplicated.
type HostPortAddressProvider struct {
	// reader is used for uncached reads of Pods, ReplicaSets, and Nodes.
	// When nil at construction, SetupWatches populates it once during manager
	// registration before GatewayAddresses runs concurrently.
	reader  client.Reader
	wrapped *singlepod.AddressProvider
}

// New creates a new HostPortAddressProvider wrapping a singlepod.AddressProvider
// configured with WithNoService() and the host-port Deployment mutator.
// When reader is nil, SetupWatches populates it from the manager's uncached API reader.
func New(client client.Client, reader client.Reader, controllerNamespace string, options ...singlepod.Option) (*HostPortAddressProvider, error) {
	if controllerNamespace == "" {
		return nil, fmt.Errorf("controllerNamespace is required for HostPortAddressProvider")
	}
	wrappedOptions := make([]singlepod.Option, 0, len(options)+2)
	wrappedOptions = append(wrappedOptions, options...)
	wrappedOptions = append(wrappedOptions,
		singlepod.WithNoService(),
		singlepod.WithDeploymentMutator(MutateDeployment),
	)
	return &HostPortAddressProvider{
		reader:  reader,
		wrapped: singlepod.NewAddressProvider(client, controllerNamespace, wrappedOptions...),
	}, nil
}

// GatewayAddresses reconciles the Gateway's data-plane infrastructure and returns
// addresses and a *state.ConditionError when not ready to serve, based on the nodes
// running the Gateway's data-plane pods.
func (provider *HostPortAddressProvider) GatewayAddresses(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, error) {
	if provider.reader == nil {
		return nil, fmt.Errorf("reader is required for HostPortAddressProvider")
	}

	// 0. Validate that listeners do not exceed one HTTP port and one HTTPS/TLS port.
	httpPorts := make(map[gatewayv1.PortNumber]struct{})
	httpsPorts := make(map[gatewayv1.PortNumber]struct{})
	for _, effectiveListener := range effectiveListeners {
		if effectiveListener.IsConflicted() {
			continue
		}
		switch effectiveListener.Protocol {
		case gatewayv1.HTTPProtocolType:
			httpPorts[effectiveListener.Port] = struct{}{}
		case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
			httpsPorts[effectiveListener.Port] = struct{}{}
		}
	}
	if len(httpPorts) > 1 || len(httpsPorts) > 1 {
		return nil, &state.ConditionError{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Reason:  string(gatewayv1.GatewayReasonAddressNotUsable),
			Message: "host ports allow one HTTP and one HTTPS port",
		}
	}

	// 1. Reconcile the Deployment via the wrapped singlepod provisioner.
	// With WithNoService(), singlepod can return not-ready ConditionErrors such as
	// GatewayReasonPending (waiting for state to compute gateway parameters) or
	// GatewayReasonInvalidParameters (problem with the Gateway's parameters).
	// If singlepod reports any error or any ConditionError other than AddressNotAssigned
	// ("no address yet"), return it immediately without discovering pods.
	_, err := provider.wrapped.GatewayAddresses(ctx, gateway, effectiveListeners)
	if err != nil {
		var conditionErr *state.ConditionError
		if !errors.As(err, &conditionErr) || (conditionErr.Reason != "" && conditionErr.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned)) {
			return nil, err
		}
	}

	deploymentName := state.ResourceNameForGateway(gateway.Name)

	var deployment appsv1.Deployment
	if err := provider.reader.Get(ctx, types.NamespacedName{Namespace: gateway.Namespace, Name: deploymentName}, &deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &state.ConditionError{
				Type:    string(gatewayv1.GatewayConditionProgrammed),
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: "Waiting for data-plane deployment to become available",
			}
		}
		return nil, fmt.Errorf("getting Deployment %s/%s for Gateway %s: %w", gateway.Namespace, deploymentName, gateway.Name, err)
	}

	deploymentAvailable := deployment.Status.AvailableReplicas > 0 || deployment.Status.ReadyReplicas > 0

	// 2. Find all data-plane pods owned by the Deployment.
	pods, err := provider.dataplanePods(ctx, gateway, &deployment)
	if err != nil {
		return nil, err
	}

	// With no such pod, the Gateway has no address and reason AddressNotAssigned.
	if len(pods) == 0 {
		message := "Waiting for data-plane deployment to become available"
		if deploymentAvailable {
			message = "Waiting for node address to be assigned to host-port Gateway"
		}
		return nil, &state.ConditionError{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: message,
		}
	}

	// 3. Collect unique node names to read each node once.
	seenNodes := make(map[string]bool)
	var nodeNames []string
	for index := range pods {
		nodeName := pods[index].Spec.NodeName
		if !seenNodes[nodeName] {
			seenNodes[nodeName] = true
			nodeNames = append(nodeNames, nodeName)
		}
	}

	var parsedIPs []netip.Addr
	for _, nodeName := range nodeNames {
		var node corev1.Node
		if err := provider.reader.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("getting Node %s for Gateway %s/%s: %w", nodeName, gateway.Namespace, gateway.Name, err)
		}

		for index := range node.Status.Addresses {
			nodeAddress := node.Status.Addresses[index]
			if nodeAddress.Type == corev1.NodeInternalIP && nodeAddress.Address != "" {
				trimmed := strings.TrimSpace(nodeAddress.Address)
				ip, err := netip.ParseAddr(trimmed)
				if err != nil {
					return nil, fmt.Errorf("parsing NodeInternalIP %q on node %s: %w", trimmed, nodeName, err)
				}
				parsedIPs = append(parsedIPs, ip)
			}
		}
	}

	if len(parsedIPs) == 0 {
		message := "Waiting for data-plane deployment to become available"
		if deploymentAvailable {
			message = "Waiting for node address to be assigned to host-port Gateway"
		}
		return nil, &state.ConditionError{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: message,
		}
	}

	// Sort parsed IP addresses (IPv4 before IPv6, then numerically) and deduplicate.
	slices.SortFunc(parsedIPs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})
	parsedIPs = slices.Compact(parsedIPs)

	addresses := make([]gatewayv1.GatewayStatusAddress, 0, len(parsedIPs))
	for _, ip := range parsedIPs {
		addresses = append(addresses, gatewayv1.GatewayStatusAddress{
			Type:  state.Ptr(gatewayv1.IPAddressType),
			Value: ip.String(),
		})
	}

	// Readiness: ready when the Deployment is available.
	if !deploymentAvailable {
		return addresses, &state.ConditionError{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: "Waiting for data-plane deployment to become available",
		}
	}

	return addresses, nil
}

// dataplanePods finds all data-plane pods owned by the Gateway's Deployment that have an assigned node,
// leaving out pods that have failed or completed. Terminating pods are kept because a terminating pod
// continues to hold its host port until it exits.
func (provider *HostPortAddressProvider) dataplanePods(ctx context.Context, gateway *gatewayv1.Gateway, deployment *appsv1.Deployment) ([]corev1.Pod, error) {
	var podList corev1.PodList
	if err := provider.reader.List(ctx, &podList, client.InNamespace(gateway.Namespace), client.MatchingLabels{
		singlepod.LabelGatewayName: singlepod.LabelValueForGateway(gateway.Name),
		singlepod.LabelAppName:     singlepod.AppNameValue,
	}); err != nil {
		return nil, fmt.Errorf("listing data-plane pods for Gateway %s/%s: %w", gateway.Namespace, gateway.Name, err)
	}

	var validPods []corev1.Pod
	for index := range podList.Items {
		pod := &podList.Items[index]
		if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if pod.Spec.NodeName == "" {
			continue
		}
		belongs, err := podBelongsToDeployment(ctx, provider.reader, pod, deployment)
		if err != nil {
			return nil, err
		}
		if !belongs {
			continue
		}
		validPods = append(validPods, *pod)
	}

	return validPods, nil
}

// podBelongsToDeployment checks whether pod belongs to the given Deployment through owner references
// (specifically through its owning ReplicaSet).
func podBelongsToDeployment(ctx context.Context, reader client.Reader, pod *corev1.Pod, deployment *appsv1.Deployment) (bool, error) {
	if pod == nil || deployment == nil || deployment.UID == "" {
		return false, nil
	}
	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil || controllerRef.Kind != "ReplicaSet" || controllerRef.UID == "" {
		return false, nil
	}
	var replicaSet appsv1.ReplicaSet
	if err := reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: controllerRef.Name}, &replicaSet); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("getting ReplicaSet %s/%s for pod %s: %w", pod.Namespace, controllerRef.Name, pod.Name, err)
	}
	if replicaSet.UID != controllerRef.UID {
		return false, nil
	}
	rsControllerRef := metav1.GetControllerOf(&replicaSet)
	if rsControllerRef == nil || rsControllerRef.Kind != "Deployment" {
		return false, nil
	}
	return rsControllerRef.UID == deployment.UID, nil
}

// SupportedAddressTypes returns nil because host-port data planes bind directly to node host
// ports and do not support requested spec.addresses. Returning nil causes Gateway API
// to reject requested spec.addresses with Accepted=False and reason UnsupportedAddress.
func (provider *HostPortAddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return nil
}

// SetupWatches captures the manager's uncached API reader when no reader was supplied
// to New and registers watches on managed resources with the Gateway controller.
func (provider *HostPortAddressProvider) SetupWatches(manager ctrl.Manager, builder *builder.Builder) error {
	if manager != nil && provider.reader == nil {
		provider.reader = manager.GetAPIReader()
	}
	return provider.wrapped.SetupWatches(manager, builder)
}

// SetState sets the State reference on the wrapped singlepod.AddressProvider.
func (provider *HostPortAddressProvider) SetState(s *state.State) {
	provider.wrapped.SetState(s)
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
	tcpPorts := make(map[int32]bool)
	udpPorts := make(map[int32]bool)

	for _, effectiveListener := range effectiveListeners {
		if effectiveListener.IsConflicted() {
			continue
		}
		port := int32(effectiveListener.Port)
		switch effectiveListener.Protocol {
		case gatewayv1.HTTPProtocolType:
			httpPort = port
		case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
			httpsPort = port
		case gatewayv1.TCPProtocolType:
			tcpPorts[port] = true
		case gatewayv1.UDPProtocolType:
			udpPorts[port] = true
		}
	}

	for index := range dataplaneContainer.Ports {
		port := &dataplaneContainer.Ports[index]
		portName := ""
		if port.Name != nil {
			portName = *port.Name
		}
		switch portName {
		case singlepod.HTTPPortName:
			if httpPort > 0 {
				port.WithHostPort(httpPort)
			}
		case singlepod.HTTPSPortName, singlepod.HTTP3PortName:
			if httpsPort > 0 {
				port.WithHostPort(httpsPort)
			}
		default:
			portNumber := int32(0)
			if port.ContainerPort != nil {
				portNumber = *port.ContainerPort
			}
			protocol := corev1.ProtocolTCP
			if port.Protocol != nil {
				protocol = *port.Protocol
			}
			if protocol == corev1.ProtocolTCP && tcpPorts[portNumber] {
				port.WithHostPort(portNumber)
			} else if protocol == corev1.ProtocolUDP && udpPorts[portNumber] {
				port.WithHostPort(portNumber)
			}
		}
	}

	return nil
}
