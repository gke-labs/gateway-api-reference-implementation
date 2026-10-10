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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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

	// DataplaneSecretDataKey is the key in the per-Gateway Secret holding the serialized DataplaneConfig.
	DataplaneSecretDataKey = "config.json"
)

// ResourceNameForGateway computes the resource name for a Gateway within its namespace.
func ResourceNameForGateway(gwName string) string {
	base := fmt.Sprintf("%s-gari", gwName)
	if len(base) <= 63 {
		return base
	}
	h := sha256.Sum256([]byte(gwName))
	suffix := "-" + hex.EncodeToString(h[:4])
	return base[:63-len(suffix)] + suffix
}

// Option configures an AddressProvider.
type Option func(*AddressProvider)

// WithDataplaneImage configures the data-plane container image.
func WithDataplaneImage(image string) Option {
	return func(p *AddressProvider) {
		p.dataplaneImage = image
	}
}

// WithEnableH2C configures whether H2C is enabled on data-plane instances.
func WithEnableH2C(enable bool) Option {
	return func(p *AddressProvider) {
		p.enableH2C = enable
	}
}

// WithAPIReader configures the direct API reader for the AddressProvider.
func WithAPIReader(reader client.Reader) Option {
	return func(p *AddressProvider) {
		p.apiReader = reader
	}
}

// AddressProvider manages per-Gateway ServiceAccounts, Deployments, LoadBalancer Services, and ClusterRoleBinding subjects.
type AddressProvider struct {
	client         client.Client
	apiReader      client.Reader
	dataplaneImage string
	enableH2C      bool
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
	labels[LabelGatewayName] = gw.Name
	labels[LabelManagedBy] = ManagedByValue
	labels[LabelAppName] = AppNameValue

	return labels, annotations
}

// GatewayAddresses reconciles the per-Gateway ServiceAccount, Deployment, and LoadBalancer Service,
// and returns the Service's LoadBalancer ingress addresses and whether the Deployment is ready.
func (p *AddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	if p.client == nil {
		return nil, false, nil
	}

	name := ResourceNameForGateway(gw.Name)
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
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing ServiceAccount %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	saApply := corev1ac.ServiceAccount(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels)
	if len(annotations) > 0 {
		saApply.WithAnnotations(annotations)
	}
	if err := p.client.Apply(ctx, saApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return nil, false, fmt.Errorf("failed to apply ServiceAccount for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// 2. Reconcile per-Gateway Role in Gateway namespace
	var existingRole rbacv1.Role
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingRole)
	if err == nil {
		if !isOwnedByGateway(&existingRole, gw) {
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Role %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
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
		return nil, false, fmt.Errorf("failed to apply Role for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// 2b. Reconcile per-Gateway RoleBinding in Gateway namespace
	var existingRB rbacv1.RoleBinding
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingRB)
	if err == nil {
		if !isOwnedByGateway(&existingRB, gw) {
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing RoleBinding %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
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
		return nil, false, fmt.Errorf("failed to apply RoleBinding for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// 2c. Verify ownership of existing Secret in Gateway namespace
	var existingSecret corev1.Secret
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSecret)
	if err == nil {
		if !isOwnedByGateway(&existingSecret, gw) {
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Secret %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	// 3. Reconcile per-Gateway Deployment in Gateway namespace
	var existingDeploy appsv1.Deployment
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingDeploy)
	if err == nil {
		if !isOwnedByGateway(&existingDeploy, gw) {
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Deployment %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
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

	image := p.dataplaneImage
	if image == "" {
		image = DefaultDataplaneImage
	}

	podTemplate := corev1ac.PodTemplateSpec().
		WithLabels(labels).
		WithSpec(corev1ac.PodSpec().
			WithServiceAccountName(name).
			WithContainers(corev1ac.Container().
				WithName("dataplane").
				WithImage(image).
				WithImagePullPolicy(corev1.PullIfNotPresent).
				WithArgs(args...).
				WithPorts(
					corev1ac.ContainerPort().
						WithName("http").
						WithContainerPort(8000).
						WithProtocol(corev1.ProtocolTCP),
					corev1ac.ContainerPort().
						WithName("https").
						WithContainerPort(8443).
						WithProtocol(corev1.ProtocolTCP),
					corev1ac.ContainerPort().
						WithName("http3").
						WithContainerPort(8443).
						WithProtocol(corev1.ProtocolUDP),
				).
				WithReadinessProbe(corev1ac.Probe().
					WithHTTPGet(corev1ac.HTTPGetAction().
						WithPath("/readyz").
						WithPort(intstr.FromInt32(8081)),
					).
					WithInitialDelaySeconds(1).
					WithPeriodSeconds(2),
				),
			),
		)
	if len(annotations) > 0 {
		podTemplate.WithAnnotations(annotations)
	}

	deployApply := appsv1ac.Deployment(name, gwNamespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels).
		WithSpec(appsv1ac.DeploymentSpec().
			WithReplicas(1).
			WithSelector(metav1ac.LabelSelector().
				WithMatchLabels(map[string]string{
					LabelGatewayName: gw.Name,
					LabelAppName:     AppNameValue,
				}),
			).
			WithTemplate(podTemplate),
		)
	if len(annotations) > 0 {
		deployApply.WithAnnotations(annotations)
	}
	if err := p.client.Apply(ctx, deployApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return nil, false, fmt.Errorf("failed to apply Deployment for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}

	// 4. Reconcile per-Gateway LoadBalancer Service in Gateway namespace
	var existingSvc corev1.Service
	err = p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSvc)
	if err == nil {
		if !isOwnedByGateway(&existingSvc, gw) {
			return nil, false, &controller.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Service %s/%s is not owned by Gateway %s", gwNamespace, name, gw.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	uniquePorts := make(map[gatewayv1.PortNumber]gatewayv1.ProtocolType)
	if len(effectiveListeners) > 0 {
		for _, el := range effectiveListeners {
			if prev, ok := uniquePorts[el.Port]; !ok {
				uniquePorts[el.Port] = el.Protocol
			} else if el.Protocol == gatewayv1.HTTPSProtocolType {
				uniquePorts[el.Port] = gatewayv1.HTTPSProtocolType
			} else if el.Protocol == gatewayv1.TLSProtocolType && prev != gatewayv1.HTTPSProtocolType {
				uniquePorts[el.Port] = gatewayv1.TLSProtocolType
			}
		}
	} else {
		for _, l := range gw.Spec.Listeners {
			if prev, ok := uniquePorts[l.Port]; !ok {
				uniquePorts[l.Port] = l.Protocol
			} else if l.Protocol == gatewayv1.HTTPSProtocolType {
				uniquePorts[l.Port] = gatewayv1.HTTPSProtocolType
			} else if l.Protocol == gatewayv1.TLSProtocolType && prev != gatewayv1.HTTPSProtocolType {
				uniquePorts[l.Port] = gatewayv1.TLSProtocolType
			}
		}
	}

	var sortedPorts []int
	for port := range uniquePorts {
		sortedPorts = append(sortedPorts, int(port))
	}
	sort.Ints(sortedPorts)

	var svcPorts []*corev1ac.ServicePortApplyConfiguration
	for _, portInt := range sortedPorts {
		port := gatewayv1.PortNumber(portInt)
		proto := uniquePorts[port]
		if proto == gatewayv1.HTTPSProtocolType {
			svcPorts = append(svcPorts,
				corev1ac.ServicePort().
					WithName(fmt.Sprintf("https-%d", port)).
					WithPort(int32(port)).
					WithTargetPort(intstr.FromInt32(8443)).
					WithProtocol(corev1.ProtocolTCP),
				corev1ac.ServicePort().
					WithName(fmt.Sprintf("http3-%d", port)).
					WithPort(int32(port)).
					WithTargetPort(intstr.FromInt32(8443)).
					WithProtocol(corev1.ProtocolUDP),
			)
		} else if proto == gatewayv1.TLSProtocolType {
			svcPorts = append(svcPorts,
				corev1ac.ServicePort().
					WithName(fmt.Sprintf("tls-%d", port)).
					WithPort(int32(port)).
					WithTargetPort(intstr.FromInt32(8443)).
					WithProtocol(corev1.ProtocolTCP),
			)
		} else {
			svcPorts = append(svcPorts,
				corev1ac.ServicePort().
					WithName(fmt.Sprintf("http-%d", port)).
					WithPort(int32(port)).
					WithTargetPort(intstr.FromInt32(8000)).
					WithProtocol(corev1.ProtocolTCP),
			)
		}
	}

	if len(svcPorts) > 0 {
		svcApply := corev1ac.Service(name, gwNamespace).
			WithOwnerReferences(ownerRef).
			WithLabels(labels).
			WithSpec(corev1ac.ServiceSpec().
				WithType(corev1.ServiceTypeLoadBalancer).
				WithSelector(map[string]string{
					LabelGatewayName: gw.Name,
					LabelAppName:     AppNameValue,
				}).
				WithPorts(svcPorts...),
			)
		if len(annotations) > 0 {
			svcApply.WithAnnotations(annotations)
		}
		if err := p.client.Apply(ctx, svcApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
			return nil, false, fmt.Errorf("failed to apply Service for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
		}
	}

	// 5. Check Readiness and LB Addresses
	deployReady := false
	if err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingDeploy); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("getting Deployment %s/%s for readiness check: %w", gwNamespace, name, err)
		}
	} else {
		if existingDeploy.Status.AvailableReplicas > 0 || existingDeploy.Status.ReadyReplicas > 0 {
			deployReady = true
		}
	}

	var addresses []gatewayv1.GatewayStatusAddress
	if err := p.client.Get(ctx, types.NamespacedName{Namespace: gwNamespace, Name: name}, &existingSvc); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("getting Service %s/%s for address check: %w", gwNamespace, name, err)
		}
	} else {
		for _, ingress := range existingSvc.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  state.Ptr(gatewayv1.IPAddressType),
					Value: ingress.IP,
				})
			}
			if ingress.Hostname != "" {
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  state.Ptr(gatewayv1.HostnameAddressType),
					Value: ingress.Hostname,
				})
			}
		}
	}

	return addresses, deployReady, nil
}

// OnGatewayDeleted cleans up any resources for the deleted Gateway.
func (p *AddressProvider) OnGatewayDeleted(ctx context.Context, gwKey types.NamespacedName) error {
	return nil
}

// SweepOrphans garbage-collects stale resources across all namespaces whose corresponding Gateway no longer exists.
func (p *AddressProvider) SweepOrphans(ctx context.Context) error {
	return nil
}

func managedByPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		labels := obj.GetLabels()
		return labels != nil && labels[LabelManagedBy] == ManagedByValue
	})
}

// SetupWatches registers watches on managed Services and Deployments, and starts the orphan sweep runnable.
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

	if mgr != nil {
		err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			if !mgr.GetCache().WaitForCacheSync(ctx) {
				return fmt.Errorf("failed to wait for cache sync in address provider")
			}
			return p.SweepOrphans(ctx)
		}))
		if err != nil {
			return fmt.Errorf("failed to register orphan sweep runnable: %w", err)
		}
	}

	if scheme == nil || mapper == nil {
		return fmt.Errorf("scheme and RESTMapper are required to setup watches")
	}

	pred := managedByPredicate()
	ownerHandler := handler.EnqueueRequestForOwner(scheme, mapper, &gatewayv1.Gateway{}, handler.OnlyControllerOwner())

	bldr.Watches(&corev1.Service{}, ownerHandler, builder.WithPredicates(pred))
	bldr.Watches(&appsv1.Deployment{}, ownerHandler, builder.WithPredicates(pred))

	return nil
}

// PublishDataplaneConfig writes the Gateway's compiled data-plane config to its per-Gateway Secret.
func (p *AddressProvider) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	if p.client == nil || gw == nil || config == nil {
		return nil
	}

	name := ResourceNameForGateway(gw.Name)
	labels, annotations := buildLabelsAndAnnotations(gw)
	ownerRef := metav1ac.OwnerReference().
		WithAPIVersion(gatewayv1.GroupVersion.String()).
		WithKind("Gateway").
		WithName(gw.Name).
		WithUID(gw.UID).
		WithController(true).
		WithBlockOwnerDeletion(true)

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal dataplane config: %w", err)
	}

	secretApply := corev1ac.Secret(name, gw.Namespace).
		WithOwnerReferences(ownerRef).
		WithLabels(labels).
		WithData(map[string][]byte{
			DataplaneSecretDataKey: configJSON,
		})
	if len(annotations) > 0 {
		secretApply.WithAnnotations(annotations)
	}

	if err := p.client.Apply(ctx, secretApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply config Secret for Gateway %s/%s: %w", gw.Namespace, gw.Name, err)
	}
	return nil
}

var (
	_ controller.AddressProvider      = (*AddressProvider)(nil)
	_ controller.GatewayDeleteHandler = (*AddressProvider)(nil)
	_ controller.AddressWatcher       = (*AddressProvider)(nil)
	_ state.DataplanePublisher        = (*AddressProvider)(nil)
)
