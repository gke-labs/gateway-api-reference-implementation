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

package singlepod

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultDataplaneImage is the default container image for per-Gateway data-plane deployments.
	DefaultDataplaneImage = "gari-controller:latest"

	// FieldManager is the field manager name used for server-side apply of per-Gateway resources.
	FieldManager = "gari-provisioner"

	// LabelGatewayName is the label identifying the Gateway name on provisioned resources.
	LabelGatewayName = state.LabelGatewayName

	// LabelManagedBy is the label indicating the resource is managed by the singlepod provisioner.
	LabelManagedBy = state.LabelManagedBy

	// ManagedByValue is the value of LabelManagedBy.
	ManagedByValue = state.ManagedByValue

	// LabelAppName is the label identifying the data-plane component.
	LabelAppName = state.LabelAppName

	// AppNameValue is the value for LabelAppName on data-plane components.
	AppNameValue = state.AppNameValue

	// MaxLabelValueLength is the maximum length of a Kubernetes label value (63 characters).
	MaxLabelValueLength = 63

	// DataplaneContainerName is the name of the data-plane container in the per-Gateway Deployment.
	DataplaneContainerName = "dataplane"

	// HTTPPortName is the container port name for HTTP traffic.
	HTTPPortName = "http"

	// HTTPSPortName is the container port name for HTTPS/TLS traffic.
	HTTPSPortName = "https"

	// HTTP3PortName is the container port name for HTTP/3 UDP traffic.
	HTTP3PortName = "http3"

	// DataplaneSecretDataKey is the key in the per-Gateway Secret holding the serialized DataplaneConfig.
	DataplaneSecretDataKey = "config.json"

	// DataPlaneHTTPPort is the default container port for HTTP traffic.
	DataPlaneHTTPPort = state.DataPlaneHTTPPort

	// DataPlaneHTTPSPort is the default container port for HTTPS/TLS traffic.
	DataPlaneHTTPSPort = state.DataPlaneHTTPSPort

	// DataPlaneHealthProbePort is the container port for health probes and metrics.
	DataPlaneHealthProbePort = state.DataPlaneHealthProbePort

	// DefaultACMEChallengeAudience is the token audience expected by certserver for ACME HTTP-01 challenge forwarding.
	DefaultACMEChallengeAudience = "certserver"

	// DefaultACMEChallengeTokenExpirationSeconds is the duration requested for projected service-account tokens (10 minutes, the minimum valid Kubernetes token expiry).
	DefaultACMEChallengeTokenExpirationSeconds int64 = 600

	// DefaultACMEChallengeVolumeName is the name of the projected service-account token volume.
	DefaultACMEChallengeVolumeName = "certserver-token"

	// DefaultACMEChallengeTokenPath is the full file path to the projected service-account token.
	DefaultACMEChallengeTokenPath = "/var/run/secrets/tokens/certserver/token"

	// internalAPIBundleVolumeName is the name of the ConfigMap volume mounting the trust bundle.
	internalAPIBundleVolumeName = "internal-api-bundle"

	// internalAPIBundleMountPath is the mount directory for the internal API trust bundle.
	internalAPIBundleMountPath = "/etc/gari/bundle"

	// internalAPICAFilePath is the full file path to the internal API trust bundle CA certificate.
	internalAPICAFilePath = internalAPIBundleMountPath + "/" + spiffe.BundleDataKey

	// internalAPITokenVolumeName is the name of the projected ServiceAccount token volume for internal API.
	internalAPITokenVolumeName = "internal-api-token"

	// internalAPITokenPath is the full file path to the projected ServiceAccount token for internal API.
	internalAPITokenPath = "/var/run/secrets/tokens/internal-api/token"

	// internalAPITokenExpirationSeconds is the duration requested for projected internal API service-account tokens (1 hour).
	internalAPITokenExpirationSeconds int64 = 3600
)

// LabelValueForGateway returns a valid Kubernetes label value for the parent Gateway name.
// Generated resources carry the standard gateway.networking.k8s.io/gateway-name label,
// whose value must be the Gateway's name, as checked by Gateway API conformance.
// Only names that exceed MaxLabelValueLength (63 characters) fall back to the hashed
// resource name so that the label value remains valid.
func LabelValueForGateway(gwName string) string {
	if len(gwName) <= MaxLabelValueLength {
		return gwName
	}
	return state.ResourceNameForGateway(gwName)
}

// Option configures an AddressProvider.
type Option func(*AddressProvider)

// WithDataplaneImage configures the data-plane container image.
func WithDataplaneImage(image string) Option {
	return func(p *AddressProvider) {
		p.dataplaneImage = image
	}
}

// WithHostPorts enables host-port mapping on the data-plane Deployment without
// creating a LoadBalancer Service for traffic.
func WithHostPorts() Option {
	return func(p *AddressProvider) {
		p.useHostPorts = true
	}
}

// WithNoService configures the AddressProvider to create and reconcile no
// Service for the Gateway, leaving any existing Service in place without
// deleting it. It is intended for callers that expose data-plane pods through
// alternative network mechanisms and manage Gateway addresses independently.
func WithNoService() Option {
	return func(p *AddressProvider) {
		p.noService = true
	}
}

// DeploymentMutator is a function called immediately before a data-plane
// Deployment apply configuration is applied to the API server.
type DeploymentMutator func(deployment *appsv1ac.DeploymentApplyConfiguration, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) error

// WithDeploymentMutator configures a function called immediately before the
// data-plane Deployment apply configuration is applied to the API server.
// The mutator receives the Deployment apply configuration, the Gateway, and
// its effective listeners. If the mutator returns an error, reconciliation stops
// and the error is returned to the caller. It is intended for callers that need
// to customize data-plane pod specs, container configurations, or deployment
// strategies beyond singlepod defaults.
func WithDeploymentMutator(mutator DeploymentMutator) Option {
	return func(p *AddressProvider) {
		p.deploymentMutator = mutator
	}
}

// WithEnableH2C configures whether H2C is enabled on data-plane instances.
func WithEnableH2C(enable bool) Option {
	return func(p *AddressProvider) {
		p.enableH2C = enable
	}
}

// WithForwardedForMode configures the forwarded-for-mode on data-plane instances.
func WithForwardedForMode(mode string) Option {
	return func(p *AddressProvider) {
		p.forwardedForMode = mode
	}
}

// WithDebugErrorResponses configures whether detailed error messages are included in unmatched responses on data-plane instances.
func WithDebugErrorResponses(debug bool) Option {
	return func(p *AddressProvider) {
		p.debugErrorResponses = debug
	}
}

// WithAPIReader configures the direct API reader for the AddressProvider.
func WithAPIReader(reader client.Reader) Option {
	return func(p *AddressProvider) {
		p.apiReader = reader
	}
}

// AddressProvider manages per-Gateway ServiceAccounts, Deployments, LoadBalancer Services, and ClusterRoleBinding subjects.
//
// Readiness approximation: reports ready when the per-Gateway Deployment has at least one ready/available
// replica and addresses are assigned. Because data-plane pods only pass readiness probes after applying a
// configuration Secret, ready guarantees a replica has applied a config.
//
// Gap: ready means "a replica has applied a config", not necessarily "the current configuration applied". The Secret-based
// config distribution path has no acknowledgement channel carrying the applied configuration revision back from
// data-plane replicas to the controller, so the provider cannot verify that the latest config is actively being served.
type AddressProvider struct {
	client         client.Client
	apiReader      client.Reader
	dataplaneImage string
	enableH2C      bool
	// useHostPorts indicates whether the data-plane Deployment maps listener ports
	// to host ports directly instead of provisioning a LoadBalancer Service.
	useHostPorts bool
	// noService indicates whether the provider skips creating and reconciling a
	// Service for the Gateway.
	noService bool
	// deploymentMutator is an optional function called immediately before the
	// Deployment apply configuration is applied to the API server.
	deploymentMutator             DeploymentMutator
	forwardedForMode              string
	debugErrorResponses           bool
	state                         *state.State
	extraReadinessGates           []string
	preStopCommand                []string
	extraVolumes                  []*corev1ac.VolumeApplyConfiguration
	extraVolumeMounts             []*corev1ac.VolumeMountApplyConfiguration
	terminationGracePeriodSeconds *int64
	acmeChallengeUpstreamURL      string
	acmeChallengeCABundlePath     string
	acmeChallengeTokenPath        string
	acmeChallengeAudience         string
	acmeChallengeTokenExpiration  int64
	controllerNamespace           string
}

// WithDataplaneConfigFromInternalAPI configures the AddressProvider to provide data planes
// with the trust bundle, token, and flags to receive configuration directly from the
// controller's internal API instead of reading a Secret from the Kubernetes API.
func WithDataplaneConfigFromInternalAPI(controllerNamespace string) Option {
	return func(p *AddressProvider) {
		p.controllerNamespace = controllerNamespace
	}
}

// WithACMEChallengeUpstreamURL configures the upstream certificate server URL for forwarding ACME HTTP-01 challenges.
func WithACMEChallengeUpstreamURL(url string) Option {
	return func(p *AddressProvider) {
		p.acmeChallengeUpstreamURL = url
	}
}

// WithACMEChallengeCABundlePath configures the CA bundle PEM file path to verify the upstream certificate server.
func WithACMEChallengeCABundlePath(path string) Option {
	return func(p *AddressProvider) {
		p.acmeChallengeCABundlePath = path
	}
}

// WithACMEChallengeTokenPath configures a custom path for the projected service-account token.
func WithACMEChallengeTokenPath(path string) Option {
	return func(p *AddressProvider) {
		p.acmeChallengeTokenPath = path
	}
}

// WithACMEChallengeAudience configures the audience for the projected service-account token.
func WithACMEChallengeAudience(audience string) Option {
	return func(p *AddressProvider) {
		p.acmeChallengeAudience = audience
	}
}

// WithACMEChallengeTokenExpiration configures the validity duration in seconds for the projected service-account token.
func WithACMEChallengeTokenExpiration(seconds int64) Option {
	return func(p *AddressProvider) {
		p.acmeChallengeTokenExpiration = seconds
	}
}

// WithExtraReadinessGates configures additional readiness gate condition types for the data-plane pods.
func WithExtraReadinessGates(gates ...string) Option {
	return func(p *AddressProvider) {
		p.extraReadinessGates = append(p.extraReadinessGates, gates...)
	}
}

// WithPreStopCommand configures a lifecycle preStop exec command on the data-plane container.
func WithPreStopCommand(cmd ...string) Option {
	return func(p *AddressProvider) {
		p.preStopCommand = cmd
	}
}

// WithExtraVolumes configures additional volumes and volume mounts for the data-plane pod.
func WithExtraVolumes(volumes []*corev1ac.VolumeApplyConfiguration, mounts []*corev1ac.VolumeMountApplyConfiguration) Option {
	return func(p *AddressProvider) {
		p.extraVolumes = append(p.extraVolumes, volumes...)
		p.extraVolumeMounts = append(p.extraVolumeMounts, mounts...)
	}
}

// WithTerminationGracePeriodSeconds configures the terminationGracePeriodSeconds on the data-plane pod template.
func WithTerminationGracePeriodSeconds(seconds int64) Option {
	return func(p *AddressProvider) {
		p.terminationGracePeriodSeconds = &seconds
	}
}

// WithState sets the State reference for the AddressProvider.
func WithState(s *state.State) Option {
	return func(p *AddressProvider) {
		p.state = s
	}
}

// SetState sets the State reference for the AddressProvider.
func (p *AddressProvider) SetState(s *state.State) {
	p.state = s
}

// isACMEChallengeEnabled reports whether ACME HTTP-01 challenge forwarding is active for the given Gateway parameters.
// Forwarding is on when the controller has an upstream configured and the Gateway's parameters say "enabled".
func (p *AddressProvider) isACMEChallengeEnabled(params *state.Parameters) bool {
	if p.acmeChallengeUpstreamURL == "" {
		return false
	}
	return params != nil && strings.EqualFold(params.ACMEChallenge, "enabled")
}

func (p *AddressProvider) acmeTokenPath() string {
	if p.acmeChallengeTokenPath != "" {
		return p.acmeChallengeTokenPath
	}
	return DefaultACMEChallengeTokenPath
}

// NewAddressProvider creates a new singlepod AddressProvider.
func NewAddressProvider(c client.Client, opts ...Option) *AddressProvider {
	p := &AddressProvider{
		client:         c,
		dataplaneImage: DefaultDataplaneImage,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// isOwnedByGateway checks if the object has a controller OwnerReference to this Gateway with a matching UID.
func isOwnedByGateway(obj metav1.Object, gw *gatewayv1.Gateway) bool {
	ref := metav1.GetControllerOf(obj)
	if ref == nil {
		return false
	}
	return ref.Kind == "Gateway" && ref.Name == gw.Name && gw.UID != "" && ref.UID == gw.UID
}

func buildLabelsAndAnnotations(gw *gatewayv1.Gateway) (map[string]string, map[string]string) {
	labels := make(map[string]string)
	var annotations map[string]string

	if gw.Spec.Infrastructure != nil {
		if gw.Spec.Infrastructure.Labels != nil {
			for k, v := range gw.Spec.Infrastructure.Labels {
				keyStr := string(k)
				if strings.HasPrefix(keyStr, "gateway.networking.k8s.io/") ||
					keyStr == LabelManagedBy ||
					keyStr == LabelAppName {
					continue
				}
				labels[keyStr] = string(v)
			}
		}
		if gw.Spec.Infrastructure.Annotations != nil {
			annotations = make(map[string]string)
			for k, v := range gw.Spec.Infrastructure.Annotations {
				keyStr := string(k)
				annotations[keyStr] = string(v)
			}
		}
	}

	// GARI-owned labels override user labels
	labels[LabelGatewayName] = LabelValueForGateway(gw.Name)
	labels[LabelManagedBy] = ManagedByValue
	labels[LabelAppName] = AppNameValue

	return labels, annotations
}

func requestedIPAddresses(gw *gatewayv1.Gateway) []string {
	var ips []string
	if gw == nil {
		return nil
	}
	for _, addr := range gw.Spec.Addresses {
		addrType := gatewayv1.IPAddressType
		if addr.Type != nil && *addr.Type != "" {
			addrType = *addr.Type
		}
		if addrType == gatewayv1.IPAddressType && addr.Value != "" {
			ips = append(ips, addr.Value)
		}
	}
	return ips
}

func requestedHostnameAddresses(gw *gatewayv1.Gateway) []string {
	var hosts []string
	if gw == nil {
		return nil
	}
	for _, addr := range gw.Spec.Addresses {
		if addr.Type != nil && *addr.Type == gatewayv1.HostnameAddressType && addr.Value != "" {
			hosts = append(hosts, addr.Value)
		}
	}
	return hosts
}

// GatewayAddresses reconciles the per-Gateway ServiceAccount, Deployment, and Service,
// and returns the Service's ingress addresses and detailed readiness state.
func (p *AddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	if p.client == nil {
		return nil, state.GatewayReadiness{}, nil
	}

	var params *state.Parameters
	if p.state != nil && gw != nil {
		prms, found, err := p.state.GetGatewayParameters(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name})
		if !found {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonPending),
				Message: "Waiting for state to compute gateway parameters",
			}, nil
		}
		if err != nil {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonInvalidParameters),
				Message: err.Error(),
			}, nil
		}
		params = prms
	} else if p.state == nil {
		params = state.DefaultParameters()
	}

	name := state.ResourceNameForGateway(gw.Name)
	labelGwName := LabelValueForGateway(gw.Name)
	gwNamespace := gw.Namespace

	labels, annotations := buildLabelsAndAnnotations(gw)

	ownerRef := metav1ac.OwnerReference().
		WithAPIVersion(gatewayv1.GroupVersion.String()).
		WithKind("Gateway").
		WithName(gw.Name).
		WithUID(gw.UID).
		WithController(true).
		WithBlockOwnerDeletion(true)

	// 1. Reconcile per-Gateway ServiceAccount in Gateway namespace
	var existingSA corev1.ServiceAccount
	err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSA)
	if err == nil {
		if !isOwnedByGateway(&existingSA, gw) {
			return nil, state.GatewayReadiness{}, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing ServiceAccount %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, state.GatewayReadiness{}, err
	}

	saApply := corev1ac.ServiceAccount(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels)
	if len(annotations) > 0 {
		saApply.WithAnnotations(annotations)
	}
	if err := p.client.Apply(ctx, saApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return nil, state.GatewayReadiness{}, fmt.Errorf("failed to apply ServiceAccount for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// Reconcile per-Gateway trust bundle ConfigMap in Gateway namespace when internal API is enabled
	if p.controllerNamespace != "" {
		var sourceConfigMap corev1.ConfigMap
		if err := p.client.Get(ctx, types.NamespacedName{Namespace: p.controllerNamespace, Name: spiffe.BundleConfigMapName}, &sourceConfigMap); err != nil {
			return nil, state.GatewayReadiness{}, fmt.Errorf("reading bundle configmap %s/%s: %w", p.controllerNamespace, spiffe.BundleConfigMapName, err)
		}
		bundleData, ok := sourceConfigMap.Data[spiffe.BundleDataKey]
		if !ok || bundleData == "" {
			return nil, state.GatewayReadiness{}, fmt.Errorf("bundle configmap %s/%s missing key %s", p.controllerNamespace, spiffe.BundleConfigMapName, spiffe.BundleDataKey)
		}

		var existingConfigMap corev1.ConfigMap
		err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingConfigMap)
		if err == nil {
			if !isOwnedByGateway(&existingConfigMap, gw) {
				return nil, state.GatewayReadiness{}, &controller.OwnershipConflictError{
					Message: fmt.Sprintf("conflict: existing ConfigMap %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
				}
			}
		} else if !apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{}, err
		}

		configMapApply := corev1ac.ConfigMap(name, gwNamespace).
			WithOwnerReferences(ownerRef).
			WithLabels(labels).
			WithData(map[string]string{
				spiffe.BundleDataKey: bundleData,
			})
		if len(annotations) > 0 {
			configMapApply.WithAnnotations(annotations)
		}
		if err := p.client.Apply(ctx, configMapApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
			return nil, state.GatewayReadiness{}, fmt.Errorf("failed to apply ConfigMap for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
		}
	} else {
		// 2. Reconcile per-Gateway Role and RoleBinding in Gateway namespace
		if err := p.reconcileRoleAndRoleBinding(ctx, gw, name, ownerRef, labels, annotations); err != nil {
			return nil, state.GatewayReadiness{}, err
		}
	}

	// 2c. Verify ownership of existing Secret in Gateway namespace
	var existingSecret corev1.Secret
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSecret)
	if err == nil {
		if !isOwnedByGateway(&existingSecret, gw) {
			return nil, state.GatewayReadiness{}, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Secret %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, state.GatewayReadiness{}, err
	}

	// 3. Reconcile per-Gateway Deployment in Gateway namespace
	var existingDeploy appsv1.Deployment
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingDeploy)
	if err == nil {
		if !isOwnedByGateway(&existingDeploy, gw) {
			return nil, state.GatewayReadiness{}, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Deployment %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, state.GatewayReadiness{}, err
	}

	args := []string{
		"--dataplane-mode",
		fmt.Sprintf("--gateway-namespace=%s", gw.Namespace),
		fmt.Sprintf("--gateway-name=%s", gw.Name),
	}
	// TODO(#620): support per-listener advertised HTTP/3 port when a Gateway has multiple HTTPS listeners on different ports.
	for _, el := range effectiveListeners {
		if el.Protocol == gatewayv1.HTTPSProtocolType {
			args = append(args, fmt.Sprintf("--proxy-http3-advertised-port=%d", el.Port))
			break
		}
	}
	if p.enableH2C {
		args = append(args, "--enable-h2c")
	}
	if p.forwardedForMode != "" {
		args = append(args, fmt.Sprintf("--forwarded-for-mode=%s", p.forwardedForMode))
	}
	if p.debugErrorResponses {
		args = append(args, "--debug-error-responses")
	}
	challengeEnabled := p.isACMEChallengeEnabled(params)
	if challengeEnabled {
		tokenPath := p.acmeTokenPath()
		args = append(args, fmt.Sprintf("--acme-challenge-upstream-url=%s", p.acmeChallengeUpstreamURL))
		args = append(args, fmt.Sprintf("--acme-challenge-token-path=%s", tokenPath))
		if p.acmeChallengeCABundlePath != "" {
			args = append(args, fmt.Sprintf("--acme-challenge-ca-bundle-path=%s", p.acmeChallengeCABundlePath))
		}
	}
	if p.controllerNamespace != "" {
		host, err := spiffe.ServiceClusterDNSName(spiffe.ControllerServiceName, p.controllerNamespace)
		if err != nil {
			return nil, state.GatewayReadiness{}, fmt.Errorf("building internal API address: %w", err)
		}
		internalAPIAddress := net.JoinHostPort(host, strconv.Itoa(push.InternalAPIPort))
		args = append(args,
			fmt.Sprintf("--internal-api-address=%s", internalAPIAddress),
			fmt.Sprintf("--internal-api-ca-file=%s", internalAPICAFilePath),
			fmt.Sprintf("--internal-api-token-file=%s", internalAPITokenPath),
		)
	}

	image := p.dataplaneImage
	if image == "" {
		image = DefaultDataplaneImage
	}

	// Compute unique listener ports and TCP/UDP ports across effective listeners
	uniquePorts := make(map[gatewayv1.PortNumber]gatewayv1.ProtocolType)
	var tcpPorts []int
	seenTCPPort := make(map[gatewayv1.PortNumber]bool)
	var udpPorts []int
	seenUDPPort := make(map[gatewayv1.PortNumber]bool)
	if len(effectiveListeners) > 0 {
		for _, el := range effectiveListeners {
			if el.IsConflicted() {
				continue
			}
			if el.Protocol == gatewayv1.TCPProtocolType {
				if !state.IsReservedDataPlanePort(el.Port) && !seenTCPPort[el.Port] {
					seenTCPPort[el.Port] = true
					tcpPorts = append(tcpPorts, int(el.Port))
				}
			}
			if el.Protocol == gatewayv1.UDPProtocolType {
				if !state.IsReservedDataPlanePort(el.Port) && !seenUDPPort[el.Port] {
					seenUDPPort[el.Port] = true
					udpPorts = append(udpPorts, int(el.Port))
				}
			}
			if el.Protocol != gatewayv1.UDPProtocolType {
				if el.Protocol == gatewayv1.TCPProtocolType && state.IsReservedDataPlanePort(el.Port) {
					continue
				}
				if prev, ok := uniquePorts[el.Port]; !ok {
					uniquePorts[el.Port] = el.Protocol
				} else if el.Protocol == gatewayv1.HTTPSProtocolType {
					uniquePorts[el.Port] = gatewayv1.HTTPSProtocolType
				} else if el.Protocol == gatewayv1.TLSProtocolType && prev != gatewayv1.HTTPSProtocolType {
					uniquePorts[el.Port] = gatewayv1.TLSProtocolType
				}
			}
		}
	} else {
		for _, l := range gw.Spec.Listeners {
			if l.Protocol == gatewayv1.TCPProtocolType {
				if !state.IsReservedDataPlanePort(l.Port) && !seenTCPPort[l.Port] {
					seenTCPPort[l.Port] = true
					tcpPorts = append(tcpPorts, int(l.Port))
				}
			}
			if l.Protocol == gatewayv1.UDPProtocolType {
				if !state.IsReservedDataPlanePort(l.Port) && !seenUDPPort[l.Port] {
					seenUDPPort[l.Port] = true
					udpPorts = append(udpPorts, int(l.Port))
				}
			}
			if l.Protocol != gatewayv1.UDPProtocolType {
				if l.Protocol == gatewayv1.TCPProtocolType && state.IsReservedDataPlanePort(l.Port) {
					continue
				}
				if prev, ok := uniquePorts[l.Port]; !ok {
					uniquePorts[l.Port] = l.Protocol
				} else if el := l; prev != gatewayv1.HTTPSProtocolType && el.Protocol == gatewayv1.HTTPSProtocolType {
					uniquePorts[l.Port] = gatewayv1.HTTPSProtocolType
				} else if prev, ok := uniquePorts[l.Port]; !ok || (l.Protocol == gatewayv1.TLSProtocolType && prev != gatewayv1.HTTPSProtocolType) {
					uniquePorts[l.Port] = gatewayv1.TLSProtocolType
				}
			}
		}
	}
	sort.Ints(tcpPorts)
	sort.Ints(udpPorts)

	var sortedPorts []int
	for port := range uniquePorts {
		sortedPorts = append(sortedPorts, int(port))
	}
	sort.Ints(sortedPorts)

	if p.useHostPorts {
		var httpPorts, httpsPorts int
		for _, protocol := range uniquePorts {
			if protocol == gatewayv1.HTTPProtocolType {
				httpPorts++
			} else if protocol == gatewayv1.HTTPSProtocolType || protocol == gatewayv1.TLSProtocolType {
				httpsPorts++
			}
		}
		if httpPorts > 1 || httpsPorts > 1 {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotUsable),
				Message: "host ports allow one HTTP and one HTTPS port",
			}, nil
		}
	}

	var containerPorts []*corev1ac.ContainerPortApplyConfiguration
	if p.useHostPorts {
		for _, portInt := range sortedPorts {
			port := gatewayv1.PortNumber(portInt)
			protocol := uniquePorts[port]
			if protocol == gatewayv1.TCPProtocolType && state.IsReservedDataPlanePort(port) {
				continue
			}
			name := fmt.Sprintf("%s-%d", strings.ToLower(string(protocol)), port)
			containerPort := int32(port)
			if protocol == gatewayv1.HTTPProtocolType {
				containerPort = DataPlaneHTTPPort
				if port == 80 {
					name = HTTPPortName
				}
			} else if protocol == gatewayv1.HTTPSProtocolType || protocol == gatewayv1.TLSProtocolType {
				containerPort = DataPlaneHTTPSPort
				if port == 443 && protocol == gatewayv1.HTTPSProtocolType {
					name = HTTPSPortName
				}
			}
			containerPorts = append(containerPorts,
				corev1ac.ContainerPort().WithName(name).WithContainerPort(containerPort).WithHostPort(int32(port)).WithProtocol(corev1.ProtocolTCP),
			)
			if protocol == gatewayv1.HTTPSProtocolType {
				http3Name := fmt.Sprintf("http3-%d", port)
				if port == 443 {
					http3Name = HTTP3PortName
				}
				containerPorts = append(containerPorts,
					corev1ac.ContainerPort().WithName(http3Name).WithContainerPort(DataPlaneHTTPSPort).WithHostPort(int32(port)).WithProtocol(corev1.ProtocolUDP),
				)
			}
		}
		for _, portInt := range udpPorts {
			port := gatewayv1.PortNumber(portInt)
			if state.IsReservedDataPlanePort(port) {
				continue
			}
			containerPorts = append(containerPorts,
				corev1ac.ContainerPort().WithName(fmt.Sprintf("udp-%d", portInt)).WithContainerPort(int32(portInt)).WithHostPort(int32(portInt)).WithProtocol(corev1.ProtocolUDP),
			)
		}
	} else {
		containerPorts = []*corev1ac.ContainerPortApplyConfiguration{
			corev1ac.ContainerPort().
				WithName(HTTPPortName).
				WithContainerPort(DataPlaneHTTPPort).
				WithProtocol(corev1.ProtocolTCP),
			corev1ac.ContainerPort().
				WithName(HTTPSPortName).
				WithContainerPort(DataPlaneHTTPSPort).
				WithProtocol(corev1.ProtocolTCP),
			corev1ac.ContainerPort().
				WithName(HTTP3PortName).
				WithContainerPort(DataPlaneHTTPSPort).
				WithProtocol(corev1.ProtocolUDP),
		}
		for _, portInt := range tcpPorts {
			if state.IsReservedDataPlanePort(gatewayv1.PortNumber(portInt)) {
				continue
			}
			containerPorts = append(containerPorts,
				corev1ac.ContainerPort().
					WithName(fmt.Sprintf("tcp-%d", portInt)).
					WithContainerPort(int32(portInt)).
					WithProtocol(corev1.ProtocolTCP),
			)
		}
		for _, portInt := range udpPorts {
			if state.IsReservedDataPlanePort(gatewayv1.PortNumber(portInt)) {
				continue
			}
			containerPorts = append(containerPorts,
				corev1ac.ContainerPort().
					WithName(fmt.Sprintf("udp-%d", portInt)).
					WithContainerPort(int32(portInt)).
					WithProtocol(corev1.ProtocolUDP),
			)
		}
	}

	containerApply := corev1ac.Container().
		WithName(DataplaneContainerName).
		WithImage(image).
		WithImagePullPolicy(corev1.PullIfNotPresent).
		WithArgs(args...).
		WithPorts(containerPorts...).
		WithReadinessProbe(corev1ac.Probe().
			WithHTTPGet(corev1ac.HTTPGetAction().
				WithPath("/readyz").
				WithPort(intstr.FromInt32(DataPlaneHealthProbePort)),
			).
			WithInitialDelaySeconds(1).
			WithPeriodSeconds(2),
		)

	var volumeMounts []*corev1ac.VolumeMountApplyConfiguration
	if len(p.extraVolumeMounts) > 0 {
		volumeMounts = append(volumeMounts, p.extraVolumeMounts...)
	}

	var volumes []*corev1ac.VolumeApplyConfiguration
	if len(p.extraVolumes) > 0 {
		volumes = append(volumes, p.extraVolumes...)
	}

	if challengeEnabled {
		tokenPath := p.acmeTokenPath()
		mountDir := filepath.Dir(tokenPath)
		subPath := filepath.Base(tokenPath)

		aud := p.acmeChallengeAudience
		if aud == "" {
			aud = DefaultACMEChallengeAudience
		}
		exp := p.acmeChallengeTokenExpiration
		if exp <= 0 {
			exp = DefaultACMEChallengeTokenExpirationSeconds
		}

		volumeMounts = append(volumeMounts, corev1ac.VolumeMount().
			WithName(DefaultACMEChallengeVolumeName).
			WithMountPath(mountDir).
			WithReadOnly(true),
		)

		volumes = append(volumes, corev1ac.Volume().
			WithName(DefaultACMEChallengeVolumeName).
			WithProjected(corev1ac.ProjectedVolumeSource().
				WithSources(corev1ac.VolumeProjection().
					WithServiceAccountToken(corev1ac.ServiceAccountTokenProjection().
						WithAudience(aud).
						WithExpirationSeconds(exp).
						WithPath(subPath),
					),
				),
			),
		)
	}

	if p.controllerNamespace != "" {
		volumeMounts = append(volumeMounts,
			corev1ac.VolumeMount().
				WithName(internalAPIBundleVolumeName).
				WithMountPath(internalAPIBundleMountPath).
				WithReadOnly(true),
			corev1ac.VolumeMount().
				WithName(internalAPITokenVolumeName).
				WithMountPath(filepath.Dir(internalAPITokenPath)).
				WithReadOnly(true),
		)

		volumes = append(volumes,
			corev1ac.Volume().
				WithName(internalAPIBundleVolumeName).
				WithConfigMap(corev1ac.ConfigMapVolumeSource().
					WithName(name),
				),
			corev1ac.Volume().
				WithName(internalAPITokenVolumeName).
				WithProjected(corev1ac.ProjectedVolumeSource().
					WithSources(corev1ac.VolumeProjection().
						WithServiceAccountToken(corev1ac.ServiceAccountTokenProjection().
							WithAudience(push.DefaultAudience).
							WithExpirationSeconds(internalAPITokenExpirationSeconds).
							WithPath(filepath.Base(internalAPITokenPath)),
						),
					),
				),
		)
	}

	containerApply.WithVolumeMounts(volumeMounts...)
	if len(p.preStopCommand) > 0 {
		containerApply.WithLifecycle(corev1ac.Lifecycle().
			WithPreStop(corev1ac.LifecycleHandler().
				WithExec(corev1ac.ExecAction().WithCommand(p.preStopCommand...)),
			),
		)
	}

	podSpec := corev1ac.PodSpec().
		WithServiceAccountName(name).
		WithContainers(containerApply)
	if p.terminationGracePeriodSeconds != nil {
		podSpec.WithTerminationGracePeriodSeconds(*p.terminationGracePeriodSeconds)
	}
	podSpec.WithVolumes(volumes...)
	for _, gate := range p.extraReadinessGates {
		podSpec.WithReadinessGates(corev1ac.PodReadinessGate().WithConditionType(corev1.PodConditionType(gate)))
	}

	podTemplate := corev1ac.PodTemplateSpec().
		WithLabels(labels).
		WithSpec(podSpec)
	if len(annotations) > 0 {
		podTemplate.WithAnnotations(annotations)
	}

	deploySpec := appsv1ac.DeploymentSpec().
		WithReplicas(1).
		WithSelector(metav1ac.LabelSelector().
			WithMatchLabels(map[string]string{
				LabelGatewayName: labelGwName,
				LabelAppName:     AppNameValue,
			}),
		).
		WithTemplate(podTemplate)
	if p.useHostPorts {
		// Use RollingUpdate with maxSurge: 0 and maxUnavailable: 1 when host ports are on.
		// On a one-node cluster, a new pod cannot bind the host port while the old pod
		// holds it, so zero surge ensures the old pod terminates before the new pod is
		// scheduled. Keeping the RollingUpdate strategy type avoids API server validation
		// errors when switching an existing Deployment whose defaulted rollingUpdate
		// parameters cannot coexist with strategy type Recreate.
		deploySpec.WithStrategy(appsv1ac.DeploymentStrategy().
			WithType(appsv1.RollingUpdateDeploymentStrategyType).
			WithRollingUpdate(appsv1ac.RollingUpdateDeployment().
				WithMaxSurge(intstr.FromInt32(0)).
				WithMaxUnavailable(intstr.FromInt32(1)),
			),
		)
	}

	deployApply := appsv1ac.Deployment(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels).
		WithSpec(deploySpec)
	if len(annotations) > 0 {
		deployApply.WithAnnotations(annotations)
	}
	if p.deploymentMutator != nil {
		if err := p.deploymentMutator(deployApply, gw, effectiveListeners); err != nil {
			return nil, state.GatewayReadiness{}, err
		}
	}
	if err := p.client.Apply(ctx, deployApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return nil, state.GatewayReadiness{}, fmt.Errorf("failed to apply Deployment for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	requestedIPs := requestedIPAddresses(gw)
	requestedHostnames := requestedHostnameAddresses(gw)

	var existingSvc corev1.Service
	// 4. Reconcile per-Gateway LoadBalancer Service in Gateway namespace
	if !p.noService {
		err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSvc)
		if err == nil {
			if !isOwnedByGateway(&existingSvc, gw) {
				return nil, state.GatewayReadiness{}, &controller.OwnershipConflictError{
					Message: fmt.Sprintf("conflict: existing Service %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
				}
			}
			if p.useHostPorts {
				if deleteErr := p.client.Delete(ctx, &existingSvc); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
					return nil, state.GatewayReadiness{}, fmt.Errorf("failed to delete Service for Gateway %s/%s: %w", gwNamespace, gw.Name, deleteErr)
				}
			}
		} else if !apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{}, err
		}

		var svcPorts []*corev1ac.ServicePortApplyConfiguration
		for _, portInt := range sortedPorts {
			port := gatewayv1.PortNumber(portInt)
			proto := uniquePorts[port]
			if proto == gatewayv1.HTTPSProtocolType {
				svcPorts = append(svcPorts,
					corev1ac.ServicePort().
						WithName(fmt.Sprintf("https-%d", port)).
						WithPort(int32(port)).
						WithTargetPort(intstr.FromString(HTTPSPortName)).
						WithProtocol(corev1.ProtocolTCP),
					corev1ac.ServicePort().
						WithName(fmt.Sprintf("http3-%d", port)).
						WithPort(int32(port)).
						WithTargetPort(intstr.FromString(HTTP3PortName)).
						WithProtocol(corev1.ProtocolUDP),
				)
			} else if proto == gatewayv1.TLSProtocolType {
				svcPorts = append(svcPorts,
					corev1ac.ServicePort().
						WithName(fmt.Sprintf("tls-%d", port)).
						WithPort(int32(port)).
						WithTargetPort(intstr.FromString(HTTPSPortName)).
						WithProtocol(corev1.ProtocolTCP),
				)
			} else if proto == gatewayv1.TCPProtocolType {
				svcPorts = append(svcPorts,
					corev1ac.ServicePort().
						WithName(fmt.Sprintf("tcp-%d", port)).
						WithPort(int32(port)).
						WithTargetPort(intstr.FromInt32(int32(port))).
						WithProtocol(corev1.ProtocolTCP),
				)
			} else {
				svcPorts = append(svcPorts,
					corev1ac.ServicePort().
						WithName(fmt.Sprintf("http-%d", port)).
						WithPort(int32(port)).
						WithTargetPort(intstr.FromString(HTTPPortName)).
						WithProtocol(corev1.ProtocolTCP),
				)
			}
		}
		for _, portInt := range udpPorts {
			port := gatewayv1.PortNumber(portInt)
			svcPorts = append(svcPorts,
				corev1ac.ServicePort().
					WithName(fmt.Sprintf("udp-%d", port)).
					WithPort(int32(port)).
					WithTargetPort(intstr.FromInt32(int32(port))).
					WithProtocol(corev1.ProtocolUDP),
			)
		}

		if !p.useHostPorts && len(svcPorts) > 0 {
			svcSpec := corev1ac.ServiceSpec().
				WithType(params.ServiceType).
				WithSelector(map[string]string{
					LabelGatewayName: labelGwName,
					LabelAppName:     AppNameValue,
				}).
				WithPorts(svcPorts...)
			if params.ServiceType == corev1.ServiceTypeLoadBalancer {
				if params.ExternalTrafficPolicy != "" {
					svcSpec.WithExternalTrafficPolicy(params.ExternalTrafficPolicy)
				}
				if len(requestedIPs) > 0 {
					svcSpec.WithLoadBalancerIP(requestedIPs[0])
				}
			}
			svcApply := corev1ac.Service(name, gwNamespace).
				WithOwnerReferences(ownerRef).
				WithLabels(labels).
				WithSpec(svcSpec)

			svcAnnos := make(map[string]string)
			for k, v := range annotations {
				svcAnnos[k] = v
			}
			for k, v := range params.ServiceAnnotations {
				svcAnnos[k] = v
			}
			if len(svcAnnos) > 0 {
				svcApply.WithAnnotations(svcAnnos)
			}
			if err := p.client.Apply(ctx, svcApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
				return nil, state.GatewayReadiness{}, fmt.Errorf("failed to apply Service for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
			}
		}
	}

	// 5. Check Readiness and LB Addresses
	deployReady := false
	if err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingDeploy); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{}, fmt.Errorf("getting Deployment %s/%s for readiness check: %w", gwNamespace, name, err)
		}
	} else {
		if existingDeploy.Status.AvailableReplicas > 0 || existingDeploy.Status.ReadyReplicas > 0 {
			deployReady = true
		}
	}

	if p.useHostPorts {
		message := "Waiting for data-plane deployment to become available"
		if deployReady {
			message = "Waiting for node address to be assigned to host-port Gateway"
		}
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: message,
		}, nil
	}

	if p.noService {
		message := "Waiting for data-plane deployment to become available"
		if deployReady {
			message = "Waiting for address to be assigned to the Gateway"
		}
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: message,
		}, nil
	}

	if params.ServiceType == corev1.ServiceTypeClusterIP {
		var addresses []gatewayv1.GatewayStatusAddress
		for _, addr := range gw.Spec.Addresses {
			if addr.Value != "" {
				addrType := gatewayv1.IPAddressType
				if addr.Type != nil && *addr.Type != "" {
					addrType = *addr.Type
				}
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  state.Ptr(addrType),
					Value: addr.Value,
				})
			}
		}

		if len(addresses) == 0 {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: "ClusterIP Gateway requires a static address in spec.addresses",
			}, nil
		}

		if !deployReady {
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: "Waiting for data-plane deployment to become available",
			}, nil
		}

		return addresses, state.GatewayReadiness{
			Ready:   true,
			Reason:  string(gatewayv1.GatewayReasonProgrammed),
			Message: "Gateway programmed by reference implementation",
		}, nil
	}

	var addresses []gatewayv1.GatewayStatusAddress
	var ingressIPs []string
	var ingressHostnames []string
	if err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSvc); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, state.GatewayReadiness{}, fmt.Errorf("getting Service %s/%s for address check: %w", gwNamespace, name, err)
		}
	} else {
		for _, ingress := range existingSvc.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				ingressIPs = append(ingressIPs, ingress.IP)
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  state.Ptr(gatewayv1.IPAddressType),
					Value: ingress.IP,
				})
			}
			if ingress.Hostname != "" {
				ingressHostnames = append(ingressHostnames, ingress.Hostname)
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  state.Ptr(gatewayv1.HostnameAddressType),
					Value: ingress.Hostname,
				})
			}
		}
	}

	for i, reqIP := range requestedIPs {
		bound := false
		for _, ingressIP := range ingressIPs {
			if ingressIP == reqIP {
				bound = true
				break
			}
		}
		if !bound {
			msg := fmt.Sprintf("Requested address %s could not be bound to Service", reqIP)
			if i > 0 {
				msg = fmt.Sprintf("Requested address %s could not be bound to Service: singlepod binds at most one requested IP", reqIP)
			}
			return addresses, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotUsable),
				Message: msg,
			}, nil
		}
	}

	for _, reqHost := range requestedHostnames {
		bound := false
		for _, ingressHost := range ingressHostnames {
			if ingressHost == reqHost {
				bound = true
				break
			}
		}
		if !bound {
			return addresses, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotUsable),
				Message: fmt.Sprintf("Requested address %s could not be bound to Service", reqHost),
			}, nil
		}
	}

	if !deployReady {
		// Withhold addresses until the data-plane Deployment has at least one ready replica.
		// If an address is published before the data plane is ready, traffic may reach an IP
		// that does not yet route to this Gateway's data plane (e.g. after IP reuse, kube-proxy
		// can still route to another Gateway's data plane until kube-proxy converges).
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: "Waiting for data-plane deployment to become available",
		}, nil
	}

	if len(addresses) == 0 {
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: "Waiting for address to be assigned to the Gateway",
		}, nil
	}

	return addresses, state.GatewayReadiness{
		Ready:   true,
		Reason:  string(gatewayv1.GatewayReasonProgrammed),
		Message: "Gateway programmed by reference implementation",
	}, nil
}

// SupportedAddressTypes returns the address types supported by singlepod.
func (p *AddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	if p.useHostPorts {
		return nil
	}
	return []gatewayv1.AddressType{gatewayv1.IPAddressType, gatewayv1.HostnameAddressType}
}

// reconcileRoleAndRoleBinding creates or updates the per-Gateway Role and RoleBinding
// granting the data plane permissions to read its configuration Secret.
func (p *AddressProvider) reconcileRoleAndRoleBinding(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	name string,
	ownerRef *metav1ac.OwnerReferenceApplyConfiguration,
	labels map[string]string,
	annotations map[string]string,
) error {
	gwNamespace := gw.Namespace

	// Reconcile per-Gateway Role in Gateway namespace
	var existingRole rbacv1.Role
	err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingRole)
	if err == nil {
		if !isOwnedByGateway(&existingRole, gw) {
			return &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Role %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	roleApply := rbacv1ac.Role(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels).
		WithRules(rbacv1ac.PolicyRule().
			WithAPIGroups("").
			WithResources("secrets").
			WithResourceNames(name).
			WithVerbs("get", "list", "watch"),
		)
	if len(annotations) > 0 {
		roleApply.WithAnnotations(annotations)
	}
	if err := p.client.Apply(ctx, roleApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply Role for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// Reconcile per-Gateway RoleBinding in Gateway namespace
	var existingRB rbacv1.RoleBinding
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingRB)
	if err == nil {
		if !isOwnedByGateway(&existingRB, gw) {
			return &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing RoleBinding %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	rbApply := rbacv1ac.RoleBinding(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels).
		WithRoleRef(rbacv1ac.RoleRef().
			WithAPIGroup(rbacv1.GroupName).
			WithKind("Role").
			WithName(name),
		).
		WithSubjects(rbacv1ac.Subject().
			WithKind("ServiceAccount").
			WithName(name).
			WithNamespace(gwNamespace),
		)
	if len(annotations) > 0 {
		rbApply.WithAnnotations(annotations)
	}
	if err := p.client.Apply(ctx, rbApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply RoleBinding for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	return nil
}

func managedByPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		labels := obj.GetLabels()
		return labels != nil && labels[LabelManagedBy] == ManagedByValue
	})
}

// SetupWatches registers watches on managed Services and Deployments.
func (p *AddressProvider) SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error {
	var scheme *runtime.Scheme
	var mapper meta.RESTMapper
	if mgr != nil {
		if p.client == nil {
			p.client = mgr.GetClient()
		}
		p.apiReader = mgr.GetAPIReader()
		scheme = mgr.GetScheme()
		mapper = mgr.GetRESTMapper()
	} else if p.client != nil {
		scheme = p.client.Scheme()
		mapper = p.client.RESTMapper()
	}

	if scheme == nil || mapper == nil {
		return fmt.Errorf("scheme and RESTMapper are required to setup watches")
	}

	pred := managedByPredicate()
	ownerHandler := handler.EnqueueRequestForOwner(scheme, mapper, &gatewayv1.Gateway{}, handler.OnlyControllerOwner())

	if !p.noService {
		bldr.Watches(&corev1.Service{}, ownerHandler, builder.WithPredicates(pred))
	}
	bldr.Watches(&appsv1.Deployment{}, ownerHandler, builder.WithPredicates(pred))

	if p.controllerNamespace != "" {
		bldr.Watches(&corev1.ConfigMap{}, ownerHandler, builder.WithPredicates(pred))
		// This watch uses the manager's ConfigMap informer and the predicate limits it to the bundle.
		bldr.Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			var gatewayList gatewayv1.GatewayList
			if err := p.client.List(ctx, &gatewayList); err != nil {
				// A failed List is logged and the change is then lost until the next resync,
				// because EnqueueRequestsFromMapFunc cannot return an error.
				ctrl.LoggerFrom(ctx).Error(err, "failed to list Gateways on bundle ConfigMap change",
					"namespace", p.controllerNamespace, "name", spiffe.BundleConfigMapName)
				return nil
			}
			requests := make([]reconcile.Request, len(gatewayList.Items))
			for i := range gatewayList.Items {
				requests[i] = reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: gatewayList.Items[i].Namespace,
						Name:      gatewayList.Items[i].Name,
					},
				}
			}
			return requests
		}), builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			return obj.GetNamespace() == p.controllerNamespace && obj.GetName() == spiffe.BundleConfigMapName
		})))
	}

	return nil
}

// PublishDataplaneConfig writes the Gateway's compiled data-plane config to its per-Gateway Secret.
func (p *AddressProvider) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	if p.client == nil || gw == nil {
		return nil
	}
	name := state.ResourceNameForGateway(gw.Name)
	return PublishDataplaneConfig(ctx, p.client, gw.Namespace, name, gw, config)
}

// PublishDataplaneConfig writes or deletes a data plane's config Secret.
// It guarantees that it applies with the provider's field owner, it refuses an
// object that another owner holds, and it deletes the object when the payload is nil.
func PublishDataplaneConfig(ctx context.Context, cl client.Client, namespace, name string, owner client.Object, payload any) error {
	if cl == nil {
		return nil
	}
	if owner != nil && reflect.ValueOf(owner).Kind() == reflect.Pointer && reflect.ValueOf(owner).IsNil() {
		owner = nil
	}

	var existingSecret corev1.Secret
	err := cl.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &existingSecret)
	if err == nil {
		ref := metav1.GetControllerOf(&existingSecret)
		if owner == nil {
			if ref != nil {
				return &controller.OwnershipConflictError{
					Message: fmt.Sprintf("conflict: existing Secret %s/%s is owned by %s %s", namespace, name, ref.Kind, ref.Name),
				}
			}
		} else {
			if ref == nil || (owner.GetUID() != "" && ref.UID != "" && ref.UID != owner.GetUID()) || ref.Name != owner.GetName() {
				ownerDesc := owner.GetName()
				if _, ok := owner.(*gatewayv1.Gateway); ok {
					ownerDesc = "Gateway " + ownerDesc
				}
				return &controller.OwnershipConflictError{
					Message: fmt.Sprintf("conflict: existing Secret %s/%s is not owned by %s", namespace, name, ownerDesc),
				}
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get config Secret %s/%s: %w", namespace, name, err)
	}

	isNil := payload == nil
	if !isNil {
		val := reflect.ValueOf(payload)
		switch val.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
			isNil = val.IsNil()
		}
	}
	if isNil {
		if err == nil {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			if err := cl.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete config Secret %s/%s: %w", namespace, name, err)
			}
		}
		return nil
	}

	var configJSON []byte
	if b, ok := payload.([]byte); ok {
		configJSON = b
	} else {
		var marshalErr error
		configJSON, marshalErr = json.Marshal(payload)
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal dataplane config: %w", marshalErr)
		}
	}

	secretApply := corev1ac.Secret(name, namespace).
		WithData(map[string][]byte{
			DataplaneSecretDataKey: configJSON,
		})

	if owner != nil {
		apiVersion := gatewayv1.GroupVersion.String()
		kind := "Gateway"
		if cl.Scheme() != nil {
			if gvk, err := apiutil.GVKForObject(owner, cl.Scheme()); err == nil && gvk.Kind != "" {
				apiVersion = gvk.GroupVersion().String()
				kind = gvk.Kind
			}
		}
		ref := metav1ac.OwnerReference().
			WithAPIVersion(apiVersion).
			WithKind(kind).
			WithName(owner.GetName()).
			WithController(true).
			WithBlockOwnerDeletion(true)
		if owner.GetUID() != "" {
			ref.WithUID(owner.GetUID())
		}
		secretApply.WithOwnerReferences(ref)

		if gw, ok := owner.(*gatewayv1.Gateway); ok && gw != nil {
			labels, annotations := buildLabelsAndAnnotations(gw)
			if len(labels) > 0 {
				secretApply.WithLabels(labels)
			}
			if len(annotations) > 0 {
				secretApply.WithAnnotations(annotations)
			}
		}
	}

	if err := cl.Apply(ctx, secretApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply config Secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// WaitApplied implements state.DataplanePublisher. A Secret carries no reply,
// so WaitApplied returns a result that says no data plane reports through this
// publisher. The planned removal of the Secret path removes this case.
func (p *AddressProvider) WaitApplied(ctx context.Context, gateway *gatewayv1.Gateway, revision string) (state.PublishResult, error) {
	return state.PublishResult{}, nil
}

var (
	_ controller.AddressProvider     = (*AddressProvider)(nil)
	_ controller.AddressWatcher      = (*AddressProvider)(nil)
	_ controller.AddressTypeProvider = (*AddressProvider)(nil)
	_ state.DataplanePublisher       = (*AddressProvider)(nil)
)
