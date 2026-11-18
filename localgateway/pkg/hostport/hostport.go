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
	_ controller.AddressProvider          = (*HostPortAddressProvider)(nil)
	_ controller.AddressReadinessProvider = (*HostPortAddressProvider)(nil)
	_ controller.AddressTypeProvider      = (*HostPortAddressProvider)(nil)
	_ controller.AddressWatcher           = (*HostPortAddressProvider)(nil)
)

// HostPortAddressProvider manages host-port data planes for localgateway.
// It wraps singlepod.AddressProvider to configure host-port container mappings,
// zero-surge rolling updates, and no Service creation.
//
// Addresses: The Gateway's addresses are the internal addresses of the node that runs
// its data-plane pod, sorted and deduplicated.
type HostPortAddressProvider struct {
	reader  client.Reader
	wrapped *singlepod.AddressProvider
}

// New creates a new HostPortAddressProvider wrapping a singlepod.AddressProvider
// configured with WithNoService() and the host-port Deployment mutator.
// The reader is used for uncached reads of Pods, ReplicaSets, and Nodes.
func New(client client.Client, reader client.Reader, options ...singlepod.Option) *HostPortAddressProvider {
	wrappedOptions := make([]singlepod.Option, 0, len(options)+3)
	wrappedOptions = append(wrappedOptions, options...)
	wrappedOptions = append(wrappedOptions,
		singlepod.WithAPIReader(reader),
		singlepod.WithNoService(),
		singlepod.WithDeploymentMutator(MutateDeployment),
	)
	return &HostPortAddressProvider{
		reader:  reader,
		wrapped: singlepod.NewAddressProvider(client, wrappedOptions...),
	}
}

// GatewayAddresses returns the Gateway's addresses and whether the Deployment is ready.
func (provider *HostPortAddressProvider) GatewayAddresses(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addresses, readiness, err := provider.GatewayAddressesWithReadiness(ctx, gateway, effectiveListeners)
	return addresses, readiness.Ready, err
}

// GatewayAddressesWithReadiness reconciles the Gateway's data-plane infrastructure and returns
// addresses and readiness status based on the node running the Gateway's data-plane pod.
func (provider *HostPortAddressProvider) GatewayAddressesWithReadiness(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	if provider.reader == nil {
		return nil, state.GatewayReadiness{}, fmt.Errorf("reader is required for HostPortAddressProvider")
	}

	// 1. Reconcile the Deployment via the wrapped singlepod provisioner.
	_, _, err := provider.wrapped.GatewayAddressesWithReadiness(ctx, gateway, effectiveListeners)
	if err != nil {
		return nil, state.GatewayReadiness{}, err
	}

	gatewayNamespace := gateway.Namespace
	if gatewayNamespace == "" {
		gatewayNamespace = "default"
	}
	deploymentName := singlepod.ResourceNameForGateway(gateway.Name)

	var deployment appsv1.Deployment
	if err := provider.reader.Get(ctx, types.NamespacedName{Namespace: gatewayNamespace, Name: deploymentName}, &deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: "Waiting for data-plane deployment to become available",
			}, nil
		}
		return nil, state.GatewayReadiness{}, fmt.Errorf("getting Deployment %s/%s for Gateway %s: %w", gatewayNamespace, deploymentName, gateway.Name, err)
	}

	// 2. Find the active data-plane pod.
	selectedPod, err := provider.selectDataplanePod(ctx, gateway, &deployment)
	if err != nil {
		return nil, state.GatewayReadiness{}, err
	}

	deploymentAvailable := deployment.Status.AvailableReplicas > 0 || deployment.Status.ReadyReplicas > 0

	// While no pod has a node, the Gateway has no address and is not ready with reason AddressNotAssigned.
	if selectedPod == nil || selectedPod.Spec.NodeName == "" {
		message := "Waiting for data-plane deployment to become available"
		if deploymentAvailable {
			message = "Waiting for node address to be assigned to host-port Gateway"
		}
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: message,
		}, nil
	}

	// 3. Read the assigned Node and collect NodeInternalIP addresses.
	var node corev1.Node
	if err := provider.reader.Get(ctx, types.NamespacedName{Name: selectedPod.Spec.NodeName}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: fmt.Sprintf("Node %s not found", selectedPod.Spec.NodeName),
			}, nil
		}
		return nil, state.GatewayReadiness{}, fmt.Errorf("getting Node %s for Gateway %s/%s: %w", selectedPod.Spec.NodeName, gatewayNamespace, gateway.Name, err)
	}

	var internalIPs []string
	for index := range node.Status.Addresses {
		nodeAddress := node.Status.Addresses[index]
		if nodeAddress.Type == corev1.NodeInternalIP && nodeAddress.Address != "" {
			internalIPs = append(internalIPs, strings.TrimSpace(nodeAddress.Address))
		}
	}

	if len(internalIPs) == 0 {
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: fmt.Sprintf("Node %s has no NodeInternalIP addresses", selectedPod.Spec.NodeName),
		}, nil
	}

	// Sort addresses (IPv4 before IPv6, then numerically) and deduplicate.
	slices.SortFunc(internalIPs, func(firstAddress, secondAddress string) int {
		firstIP, firstErr := netip.ParseAddr(firstAddress)
		secondIP, secondErr := netip.ParseAddr(secondAddress)
		if firstErr == nil && secondErr == nil {
			return firstIP.Compare(secondIP)
		}
		return strings.Compare(firstAddress, secondAddress)
	})
	internalIPs = slices.Compact(internalIPs)

	addresses := make([]gatewayv1.GatewayStatusAddress, 0, len(internalIPs))
	for index := range internalIPs {
		addresses = append(addresses, gatewayv1.GatewayStatusAddress{
			Type:  state.Ptr(gatewayv1.IPAddressType),
			Value: internalIPs[index],
		})
	}

	// With a node but a Deployment that is not available, report addresses and reason Pending.
	if !deploymentAvailable {
		return addresses, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: "Waiting for data-plane deployment to become available",
		}, nil
	}

	return addresses, state.GatewayReadiness{
		Ready:   true,
		Reason:  string(gatewayv1.GatewayReasonProgrammed),
		Message: "Gateway programmed by reference implementation",
	}, nil
}

// selectDataplanePod finds the active data-plane pod for the Gateway.
//
// Order of preference and why:
//  1. Phase filtering: Pods in PodFailed or PodSucceeded phase (e.g., evicted or completed pods)
//     are ignored because they are no longer running traffic.
//  2. Owner verification: The pod must belong to the Gateway's Deployment through owner references
//     (specifically via its managing ReplicaSet). Unowned pods or pods belonging to other controllers
//     are ignored to prevent label spoofing.
//  3. Non-terminating over terminating: A pod without a DeletionTimestamp takes precedence over a
//     terminating pod (DeletionTimestamp != nil). The terminating pod is draining connections and
//     shutting down, while the non-terminating pod is the target of the rollout.
//  4. Scheduled over unscheduled: A pod assigned to a node (Spec.NodeName != "") takes precedence
//     over an unscheduled pod (Spec.NodeName == "") because an unscheduled pod cannot bind host ports.
//  5. Newer over older: If two candidate pods share the same deletion and scheduling status,
//     the pod with the later CreationTimestamp is preferred to reflect the newest rollout generation.
func (provider *HostPortAddressProvider) selectDataplanePod(ctx context.Context, gateway *gatewayv1.Gateway, deployment *appsv1.Deployment) (*corev1.Pod, error) {
	gatewayNamespace := gateway.Namespace
	if gatewayNamespace == "" {
		gatewayNamespace = "default"
	}

	var podList corev1.PodList
	if err := provider.reader.List(ctx, &podList, client.InNamespace(gatewayNamespace), client.MatchingLabels{
		singlepod.LabelGatewayName: singlepod.LabelValueForGateway(gateway.Name),
		singlepod.LabelAppName:     singlepod.AppNameValue,
	}); err != nil {
		return nil, fmt.Errorf("listing data-plane pods for Gateway %s/%s: %w", gatewayNamespace, gateway.Name, err)
	}

	var selectedPod *corev1.Pod
	for index := range podList.Items {
		pod := &podList.Items[index]
		if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		belongs, err := podBelongsToDeployment(ctx, provider.reader, pod, deployment)
		if err != nil {
			return nil, err
		}
		if !belongs {
			continue
		}
		if selectedPod == nil {
			selectedPod = pod
			continue
		}
		// Non-terminating preferred over terminating
		if selectedPod.DeletionTimestamp != nil && pod.DeletionTimestamp == nil {
			selectedPod = pod
			continue
		}
		if selectedPod.DeletionTimestamp == nil && pod.DeletionTimestamp != nil {
			continue
		}
		// Scheduled (has a node) preferred over unscheduled
		if selectedPod.Spec.NodeName == "" && pod.Spec.NodeName != "" {
			selectedPod = pod
			continue
		}
		if selectedPod.Spec.NodeName != "" && pod.Spec.NodeName == "" {
			continue
		}
		// Newer preferred over older
		if pod.CreationTimestamp.After(selectedPod.CreationTimestamp.Time) {
			selectedPod = pod
		}
	}

	return selectedPod, nil
}

// podBelongsToDeployment checks whether pod belongs to the given Deployment through owner references
// (specifically through its owning ReplicaSet, or directly).
func podBelongsToDeployment(ctx context.Context, reader client.Reader, pod *corev1.Pod, deployment *appsv1.Deployment) (bool, error) {
	if pod == nil || deployment == nil {
		return false, nil
	}
	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil {
		return false, nil
	}
	if controllerRef.Kind == "ReplicaSet" {
		var replicaSet appsv1.ReplicaSet
		err := reader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: controllerRef.Name}, &replicaSet)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("getting ReplicaSet %s/%s for pod %s: %w", pod.Namespace, controllerRef.Name, pod.Name, err)
		}
		if replicaSet.UID != "" && controllerRef.UID != "" && controllerRef.UID != replicaSet.UID {
			return false, nil
		}
		rsControllerRef := metav1.GetControllerOf(&replicaSet)
		if rsControllerRef == nil {
			return false, nil
		}
		if rsControllerRef.Kind == "Deployment" && rsControllerRef.Name == deployment.Name {
			if deployment.UID != "" && rsControllerRef.UID != "" && rsControllerRef.UID != deployment.UID {
				return false, nil
			}
			return true, nil
		}
		return false, nil
	}
	if controllerRef.Kind == "Deployment" && controllerRef.Name == deployment.Name {
		if deployment.UID != "" && controllerRef.UID != "" && controllerRef.UID != deployment.UID {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

// SupportedAddressTypes returns nil because host-port data planes bind directly to node host
// ports and do not support requested spec.addresses. Returning nil causes Gateway API
// to reject requested spec.addresses with Accepted=False and reason UnsupportedAddress.
func (provider *HostPortAddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return nil
}

// SetupWatches registers watches on managed resources with the Gateway controller.
func (provider *HostPortAddressProvider) SetupWatches(manager ctrl.Manager, builder *builder.Builder) error {
	if provider.reader == nil && manager != nil {
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
			if httpPort == 0 {
				httpPort = port
			}
		case gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
			if httpsPort == 0 {
				httpsPort = port
			}
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
