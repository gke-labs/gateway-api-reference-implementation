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

package main

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/hostport"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
)

func requiredInternalAPIArgs() []string {
	return []string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/gari/svid/svid.pem",
		"--internal-api-tls-key-file=/etc/gari/svid/svid_key.pem",
	}
}

func TestBuildOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "default")

		options, err := BuildOptions(requiredInternalAPIArgs())
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}

		if options.ControllerName != DefaultControllerName {
			t.Errorf("ControllerName = %q, want %q", options.ControllerName, DefaultControllerName)
		}
		if options.ProxyAddr != "" {
			t.Errorf("ProxyAddr = %q, want empty", options.ProxyAddr)
		}
		if options.ProxyHTTPSAddr != "" {
			t.Errorf("ProxyHTTPSAddr = %q, want empty", options.ProxyHTTPSAddr)
		}
		if options.ProxyHTTP3Addr != "" {
			t.Errorf("ProxyHTTP3Addr = %q, want empty", options.ProxyHTTP3Addr)
		}
		if options.LeaderElection {
			t.Errorf("LeaderElection = true, want false")
		}
		if options.LeaderElectionID != "localgateway-controller" {
			t.Errorf("LeaderElectionID = %q, want %q", options.LeaderElectionID, "localgateway-controller")
		}
		if options.MetricsAddr != ":8999" {
			t.Errorf("MetricsAddr = %q, want %q", options.MetricsAddr, ":8999")
		}
		if options.HealthProbeBindAddress != ":8999" {
			t.Errorf("HealthProbeBindAddress = %q, want %q", options.HealthProbeBindAddress, ":8999")
		}
		if options.InternalAPIBindAddress != ":8443" {
			t.Errorf("InternalAPIBindAddress = %q, want %q", options.InternalAPIBindAddress, ":8443")
		}
		if options.ListenerValidator == nil {
			t.Errorf("expected ListenerValidator to be set")
		}
		if _, ok := options.AddressProvider.(*hostport.HostPortAddressProvider); !ok {
			t.Errorf("AddressProvider = %T, want *hostport.HostPortAddressProvider", options.AddressProvider)
		}
		if options.GatewayStatusHook != nil {
			t.Errorf("expected GatewayStatusHook to be nil")
		}
		if options.OnGatewaysUpdate != nil {
			t.Errorf("expected OnGatewaysUpdate to be nil")
		}
		if options.SetupWithManager == nil {
			t.Errorf("expected SetupWithManager to be set")
		}
	})

	t.Run("custom flags", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "gateway-system")

		args := append(requiredInternalAPIArgs(),
			"--controller-name=example.org/custom-gw",
			"--dataplane-image=example.org/gari-dataplane:v2",
			"--leader-elect=true",
			"--leader-election-id=custom-lead",
			"--metrics-bind-address=:9090",
			"--health-probe-bind-address=:9091",
		)

		options, err := BuildOptions(args)
		if err != nil {
			t.Fatalf("BuildOptions failed: %v", err)
		}

		if options.ControllerName != "example.org/custom-gw" {
			t.Errorf("ControllerName = %q, want %q", options.ControllerName, "example.org/custom-gw")
		}
		if !options.LeaderElection {
			t.Errorf("LeaderElection = false, want true")
		}
		if options.LeaderElectionID != "custom-lead" {
			t.Errorf("LeaderElectionID = %q, want %q", options.LeaderElectionID, "custom-lead")
		}
		if options.MetricsAddr != ":9090" {
			t.Errorf("MetricsAddr = %q, want %q", options.MetricsAddr, ":9090")
		}
		if options.HealthProbeBindAddress != ":9091" {
			t.Errorf("HealthProbeBindAddress = %q, want %q", options.HealthProbeBindAddress, ":9091")
		}
	})

	t.Run("missing POD_NAMESPACE fails", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "")

		_, err := BuildOptions(requiredInternalAPIArgs())
		if err == nil {
			t.Fatalf("expected error when POD_NAMESPACE is empty, got nil")
		}
		if !strings.Contains(err.Error(), "POD_NAMESPACE") {
			t.Errorf("error = %q, want mention of POD_NAMESPACE", err.Error())
		}
	})

	t.Run("missing internal API flags fails", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "default")

		_, err := BuildOptions([]string{})
		if err == nil {
			t.Fatalf("expected error when internal API flags are missing, got nil")
		}
		if !strings.Contains(err.Error(), "--internal-api-bind-address") {
			t.Errorf("error = %q, want mention of --internal-api-bind-address", err.Error())
		}
	})

	t.Run("removed proxy and mdns flags rejected", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "default")

		for _, removedFlag := range []string{
			"--proxy-bind-address=:80",
			"--interface=eth0",
			"--node-name=worker-node",
			"--mdns-port=5353",
		} {
			args := append(requiredInternalAPIArgs(), removedFlag)
			if _, err := BuildOptions(args); err == nil {
				t.Errorf("expected BuildOptions to reject removed flag %q", removedFlag)
			}
		}
	})
}

type wireTestManager struct {
	ctrl.Manager
	client    client.Client
	runnables []manager.Runnable
}

func (m *wireTestManager) GetClient() client.Client    { return m.client }
func (m *wireTestManager) GetAPIReader() client.Reader { return m.client }
func (m *wireTestManager) Add(runnable manager.Runnable) error {
	m.runnables = append(m.runnables, runnable)
	if m.Manager != nil {
		return m.Manager.Add(runnable)
	}
	return nil
}

type wiredControllerFixture struct {
	controllerNamespace string
	dataplaneImage      string
	options             gari.Options
	server              *gari.Server
	fakeClient          client.Client
}

func setupWiredController(t *testing.T, controllerNamespace, dataplaneImage string) *wiredControllerFixture {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Setenv("POD_NAMESPACE", controllerNamespace)

	args := append(requiredInternalAPIArgs(), "--dataplane-image="+dataplaneImage)
	options, err := BuildOptions(args)
	if err != nil {
		cancel()
		t.Fatalf("BuildOptions failed: %v", err)
	}

	env := testenv.Start(t)

	bundleConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: controllerNamespace,
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-trust-bundle",
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(env.Scheme).
		WithObjects(bundleConfigMap).
		Build()

	skipNameValidation := true
	realManager, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:  env.Scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		cancel()
		t.Fatalf("failed to create manager: %v", err)
	}

	mockManager := &wireTestManager{
		Manager: realManager,
		client:  fakeClient,
	}

	options.LeaderElection = false
	options.Manager = mockManager
	options.Scheme = env.Scheme
	server, err := gari.NewWithManager(mockManager, options)
	if err != nil {
		cancel()
		t.Fatalf("NewWithManager failed: %v", err)
	}

	var dnsPublisher *dnsconfig.Publisher
	for _, runnable := range mockManager.runnables {
		if candidate, ok := runnable.(*dnsconfig.Publisher); ok {
			dnsPublisher = candidate
			break
		}
	}
	if dnsPublisher == nil {
		cancel()
		t.Fatalf("expected dnsconfig.Publisher to be registered with manager")
	}

	publisherErrors := make(chan error, 1)
	go func() {
		publisherErrors <- dnsPublisher.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-publisherErrors; err != nil {
			t.Errorf("dnsPublisher.Start returned unexpected error: %v", err)
		}
	})

	return &wiredControllerFixture{
		controllerNamespace: controllerNamespace,
		dataplaneImage:      dataplaneImage,
		options:             options,
		server:              server,
		fakeClient:          fakeClient,
	}
}

func seedAppLocalGateway(t *testing.T, controllerState *state.State) (*gatewayv1.Gateway, *state.Outputs) {
	t.Helper()

	appLocalHostname := gatewayv1.Hostname("app.local")
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "local-gw"}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayKey.Namespace,
			Name:      gatewayKey.Name,
			UID:       types.UID("local-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: &appLocalHostname,
				},
			},
		},
	}

	backendPort := int32(8080)
	routePort := gatewayv1.PortNumber(backendPort)

	controllerState.UpsertGatewayClass(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(DefaultControllerName),
		},
	})
	controllerState.UpsertGateway(gateway)
	controllerState.UpsertService(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app-service"},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: backendPort}}},
	})
	controllerState.UpsertHTTPRoute(&gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "local-gw"}},
			},
			Hostnames: []gatewayv1.Hostname{appLocalHostname},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "app-service",
									Port: &routePort,
								},
							},
						},
					},
				},
			},
		},
	})
	controllerState.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: "192.168.1.100"}})
	controllerState.SetSynced(true)

	outputs := controllerState.Recompute()
	if outputs == nil {
		t.Fatalf("State.Recompute returned nil outputs")
	}
	return gateway, outputs
}

func TestLocalGateway_WiredControllerSetup(t *testing.T) {
	fixture := setupWiredController(t, "gateway-system", "example.org/gari-dataplane:v1")
	gateway, outputs := seedAppLocalGateway(t, fixture.server.State())

	gatewayKey := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
	compiledGateway := outputs.CompiledGateways[gatewayKey]
	if compiledGateway == nil {
		t.Fatalf("expected compiled gateway for %v", gatewayKey)
	}

	t.Run("listener and route compilation without Published condition", func(t *testing.T) {
		if len(compiledGateway.EffectiveListeners) != 1 {
			t.Fatalf("expected 1 effective listener, got %d", len(compiledGateway.EffectiveListeners))
		}
		effectiveListener := compiledGateway.EffectiveListeners[0]
		if !effectiveListener.IsAccepted() || !effectiveListener.IsProgrammed() {
			t.Errorf("expected listener Accepted and Programmed, got conditions %+v", effectiveListener.ListenerInfo.Conditions)
		}
		if publishedCondition := state.FindCondition(effectiveListener.ListenerInfo.Conditions, "Published"); publishedCondition != nil {
			t.Errorf("expected no Published listener condition, got %+v", publishedCondition)
		}
		if effectiveListener.AttachedRoutes != 1 {
			t.Errorf("AttachedRoutes = %d, want 1", effectiveListener.AttachedRoutes)
		}
		if len(outputs.ProxyRoutes) != 1 {
			t.Fatalf("expected 1 compiled proxy route, got %d", len(outputs.ProxyRoutes))
		}
		if backend := outputs.ProxyRoutes[0].Rules[0].Backends[0]; backend.Host != "app-service.default.svc.cluster.local" || backend.Port != 8080 {
			t.Errorf("compiled backend = %s:%d, want app-service.default.svc.cluster.local:8080", backend.Host, backend.Port)
		}
	})

	t.Run("host-port Deployment provisioned with internal API and no Service", func(t *testing.T) {
		ctx := t.Context()
		_, readiness, err := fixture.options.AddressProvider.GatewayAddresses(ctx, gateway, compiledGateway.EffectiveListeners)
		if err != nil {
			t.Fatalf("GatewayAddresses failed: %v", err)
		}
		if readiness.Ready {
			t.Errorf("expected readiness.Ready=false before data-plane pod is scheduled")
		}

		resourceKey := types.NamespacedName{
			Namespace: gateway.Namespace,
			Name:      state.ResourceNameForGateway(gateway.Name),
		}
		var deployment appsv1.Deployment
		if err := fixture.fakeClient.Get(ctx, resourceKey, &deployment); err != nil {
			t.Fatalf("expected host-port Deployment %v to be created: %v", resourceKey, err)
		}
		var provisionedService corev1.Service
		if err := fixture.fakeClient.Get(ctx, resourceKey, &provisionedService); !apierrors.IsNotFound(err) {
			t.Errorf("expected no Service for host-port Gateway, got err=%v", err)
		}
		if len(deployment.Spec.Template.Spec.Containers) == 0 {
			t.Fatalf("expected dataplane container in Deployment")
		}

		dataplaneContainer := deployment.Spec.Template.Spec.Containers[0]
		if dataplaneContainer.Image != fixture.dataplaneImage {
			t.Errorf("dataplane container image = %q, want %q", dataplaneContainer.Image, fixture.dataplaneImage)
		}

		expectedHost, err := spiffe.ServiceClusterDNSName(spiffe.ControllerServiceName, fixture.controllerNamespace)
		if err != nil {
			t.Fatalf("ServiceClusterDNSName failed: %v", err)
		}
		expectedInternalAPIArg := "--internal-api-address=" + net.JoinHostPort(expectedHost, strconv.Itoa(push.InternalAPIPort))
		if !slices.Contains(dataplaneContainer.Args, expectedInternalAPIArg) {
			t.Errorf("expected %q in dataplane args, got %v", expectedInternalAPIArg, dataplaneContainer.Args)
		}

		var foundHTTPPort bool
		for _, port := range dataplaneContainer.Ports {
			if port.HostPort == 80 && port.ContainerPort == singlepod.DataPlaneHTTPPort {
				foundHTTPPort = true
				break
			}
		}
		if !foundHTTPPort {
			t.Errorf("expected hostPort 80 -> containerPort %d in %+v", singlepod.DataPlaneHTTPPort, dataplaneContainer.Ports)
		}
	})

	t.Run("dnsconfig publisher writes localgateway-dns Secret", func(t *testing.T) {
		ctx := t.Context()
		secretKey := types.NamespacedName{
			Namespace: fixture.controllerNamespace,
			Name:      dnsconfig.DefaultConfigSecretName,
		}
		deadline := time.After(2 * time.Second)
		for {
			var secret corev1.Secret
			if err := fixture.fakeClient.Get(ctx, secretKey, &secret); err == nil {
				if len(secret.Data[dnsconfig.ConfigSecretDataKey]) > 0 {
					var dnsConfig dnsconfig.Config
					if err := json.Unmarshal(secret.Data[dnsconfig.ConfigSecretDataKey], &dnsConfig); err == nil {
						if len(dnsConfig.Records) == 1 && dnsConfig.Records[0].Name == "app.local" {
							return
						}
					}
				}
			}
			select {
			case <-deadline:
				t.Fatalf("timeout waiting for %v Secret", secretKey)
			case <-time.After(10 * time.Millisecond):
			}
		}
	})
}
