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
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	sniclient "github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// DefaultControllerName is the default GatewayClass controller name for snigateway.
const DefaultControllerName = "github.com/gke-labs/gateway-api-reference-implementation/snigateway"

var setupLog = ctrl.Log.WithName("setup")

// Config holds binary-specific configuration for snigateway.
type Config struct {
	FrontendAddr        string
	GatewayAddresses    []string
	CACertPath          string
	ClientCertPath      string
	ClientKeyPath       string
	TokenFilePath       string
	InternalHostname    string
	TunnelPoolSize      int
	DeploymentName      string
	DeploymentNamespace string
	GatewayName         string
	GatewayNamespace    string
}

// DefaultConfig returns standard default configuration for snigateway.
func DefaultConfig() Config {
	return Config{
		FrontendAddr:        "127.0.0.1:443",
		InternalHostname:    "snigateway.internal",
		TunnelPoolSize:      tunnel.DefaultPoolSize,
		DeploymentName:      "snigateway-controller",
		DeploymentNamespace: "default",
		GatewayName:         "example-gateway",
		GatewayNamespace:    "default",
	}
}

// DefaultGARIOptions returns the default gari.Options customized for snigateway.
func DefaultGARIOptions() gari.Options {
	opts := gari.DefaultOptions()
	opts.ControllerName = DefaultControllerName
	opts.MetricsAddr = ":8080"
	opts.HealthProbeBindAddress = ":8081"
	opts.LeaderElectionID = "snigateway-controller"
	opts.DataplaneGatewayNamespace = "default"
	opts.DataplaneGatewayName = "example-gateway"
	return opts
}

// BindFlags registers all command-line flags on the given FlagSet.
func BindFlags(fs *flag.FlagSet, opts *gari.Options, cfg *Config) {
	fs.StringVar(&cfg.FrontendAddr, "frontend", cfg.FrontendAddr, "Address of the snigateway-frontend server (<ip-or-host>:<port>).")
	fs.Var(gari.StringSlice(&cfg.GatewayAddresses), "gateway-address", "Address to report in Gateway status (repeatable, IP or hostname). Defaults to host part of --frontend.")
	fs.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "Path to the CA certificate PEM file used to verify snigateway-frontend.")
	fs.StringVar(&cfg.ClientCertPath, "client-cert", cfg.ClientCertPath, "Path to the client certificate PEM file for mTLS authentication.")
	fs.StringVar(&cfg.ClientKeyPath, "client-key", cfg.ClientKeyPath, "Path to the client private key PEM file for mTLS authentication.")
	fs.StringVar(&cfg.TokenFilePath, "token-file", cfg.TokenFilePath, "Path to ServiceAccount token file for authentication.")
	fs.StringVar(&cfg.InternalHostname, "internal-hostname", cfg.InternalHostname, "TLS ServerName for the snigateway-frontend mTLS management API.")
	fs.StringVar(&opts.ControllerName, "controller-name", opts.ControllerName, "The GatewayClass controller name managed by this instance.")
	fs.IntVar(&cfg.TunnelPoolSize, "tunnel-pool-size", cfg.TunnelPoolSize, "Number of idle pre-dialed reverse tunnel connections to maintain with the frontend.")
	fs.StringVar(&opts.MetricsAddr, "metrics-bind-address", opts.MetricsAddr, "The address the metric endpoint binds to.")
	fs.StringVar(&opts.HealthProbeBindAddress, "health-probe-bind-address", opts.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	fs.BoolVar(&opts.LeaderElection, "leader-elect", opts.LeaderElection, "Enable leader election for controller manager.")
	fs.StringVar(&opts.LeaderElectionID, "leader-election-id", opts.LeaderElectionID, "The ID used for leader election.")
	fs.BoolVar(&opts.DebugErrorResponses, "debug-error-responses", opts.DebugErrorResponses, "Include detailed error messages in unmatched responses.")
	fs.StringVar(&opts.ACMEChallengeUpstreamURL, "acme-challenge-upstream-url", opts.ACMEChallengeUpstreamURL, "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to.")
	fs.StringVar(&opts.ACMEChallengeCABundlePath, "acme-challenge-ca-bundle-path", opts.ACMEChallengeCABundlePath, "Path to the CA bundle PEM file to verify the upstream certificate server.")
	fs.StringVar(&opts.ACMEChallengeTokenPath, "acme-challenge-token-path", opts.ACMEChallengeTokenPath, "Path to the projected service-account token file for data-plane identity.")
	fs.BoolVar(&opts.DataplaneMode, "dataplane-mode", opts.DataplaneMode, "Run in data-plane mode serving a single Gateway.")
	fs.StringVar(&opts.DataplaneGatewayNamespace, "gateway-namespace", opts.DataplaneGatewayNamespace, "The namespace of the Gateway to serve in data-plane mode.")
	fs.StringVar(&opts.DataplaneGatewayName, "gateway-name", opts.DataplaneGatewayName, "The name of the Gateway to serve in data-plane mode.")
	fs.StringVar(&cfg.DeploymentName, "deployment-name", cfg.DeploymentName, "Name of the data-plane deployment to watch for readiness.")
	fs.StringVar(&cfg.DeploymentNamespace, "deployment-namespace", cfg.DeploymentNamespace, "Namespace of the data-plane deployment to watch for readiness.")
}

// addressProvider reports static frontend addresses in Gateway status,
// watches data-plane pod readiness, and publishes compiled data-plane config Secrets.
type addressProvider struct {
	// client is the Kubernetes client used for reading pod readiness and publishing secrets.
	client client.Client
	// addresses is the list of frontend addresses to report in Gateway status.
	addresses []gatewayv1.GatewayStatusAddress
	// appLabel is the label value to match data-plane pods for readiness checks.
	appLabel string
	// deploymentNamespace is the namespace where data-plane pods run.
	deploymentNamespace string
	// gatewayName is the name of the single Gateway served by this deployment.
	gatewayName string
	// gatewayNamespace is the namespace of the single Gateway served by this deployment.
	gatewayNamespace string
}

// newAddressProvider creates an addressProvider for the specified Gateway and deployment.
func newAddressProvider(appLabel, deploymentNamespace, gatewayName, gatewayNamespace string, addresses ...string) *addressProvider {
	var parsedAddresses []gatewayv1.GatewayStatusAddress
	for _, address := range addresses {
		if address = strings.TrimSpace(address); address != "" {
			addressType := gatewayv1.HostnameAddressType
			if net.ParseIP(address) != nil {
				addressType = gatewayv1.IPAddressType
			}
			parsedAddresses = append(parsedAddresses, gatewayv1.GatewayStatusAddress{Type: &addressType, Value: address})
		}
	}
	return &addressProvider{
		appLabel:            appLabel,
		deploymentNamespace: deploymentNamespace,
		gatewayName:         gatewayName,
		gatewayNamespace:    gatewayNamespace,
		addresses:           parsedAddresses,
	}
}

func (p *addressProvider) GatewayAddresses(ctx context.Context, gateway *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addresses, readiness, err := p.GatewayAddressesWithReadiness(ctx, gateway, effectiveListeners)
	return addresses, readiness.Ready, err
}

func (p *addressProvider) GatewayAddressesWithReadiness(ctx context.Context, gateway *gatewayv1.Gateway, _ []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	if gateway == nil || gateway.Name != p.gatewayName || gateway.Namespace != p.gatewayNamespace {
		return p.addresses, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonPending),
			Message: fmt.Sprintf("Static SNIGateway deployment serves only Gateway %s/%s", p.gatewayNamespace, p.gatewayName),
		}, nil
	}
	ready := false
	if p.client != nil {
		var pods corev1.PodList
		if err := p.client.List(ctx, &pods, client.InNamespace(p.deploymentNamespace), client.MatchingLabels{"app": p.appLabel}); err != nil {
			return p.addresses, state.GatewayReadiness{Ready: false, Reason: string(gatewayv1.GatewayReasonPending), Message: fmt.Sprintf("Listing data-plane pods: %v", err)}, err
		}
		for _, pod := range pods.Items {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if ready {
				break
			}
		}
	}
	if ready {
		return p.addresses, state.GatewayReadiness{Ready: true, Reason: string(gatewayv1.GatewayReasonProgrammed), Message: "Gateway programmed by reference implementation"}, nil
	}
	return p.addresses, state.GatewayReadiness{Ready: false, Reason: string(gatewayv1.GatewayReasonPending), Message: "Waiting for data-plane tunnel to become ready"}, nil
}

func (p *addressProvider) SetupWatches(mgr ctrl.Manager, controllerBuilder *builder.Builder) error {
	p.client = mgr.GetClient()
	mapFunc := func(ctx context.Context, _ client.Object) []reconcile.Request {
		var gateways gatewayv1.GatewayList
		if err := p.client.List(ctx, &gateways); err != nil {
			setupLog.Error(err, "failed to list gateways on pod change")
			return nil
		}
		reconcileRequests := make([]reconcile.Request, len(gateways.Items))
		for index, gateway := range gateways.Items {
			reconcileRequests[index] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}}
		}
		return reconcileRequests
	}
	predicate := predicate.NewPredicateFuncs(func(obj client.Object) bool { return obj.GetLabels()["app"] == p.appLabel })
	controllerBuilder.Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(mapFunc), builder.WithPredicates(predicate))
	return nil
}

func (p *addressProvider) Begin(context.Context) error  { return nil }
func (p *addressProvider) Commit(context.Context) error { return nil }

func (p *addressProvider) PublishDataplaneConfig(ctx context.Context, gateway *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	return singlepod.PublishDataplaneSecret(ctx, p.client, gateway, config)
}

var (
	_ controller.AddressProvider          = (*addressProvider)(nil)
	_ controller.AddressWatcher           = (*addressProvider)(nil)
	_ controller.AddressReadinessProvider = (*addressProvider)(nil)
	_ state.DataplanePublisher            = (*addressProvider)(nil)
)

func parseFrontendHost(frontendAddr string) string {
	frontendAddr = strings.TrimSpace(frontendAddr)
	if host, _, err := net.SplitHostPort(frontendAddr); err == nil && host != "" {
		return host
	}
	return frontendAddr
}

// runController runs the snigateway controller process, reconciling Gateway resources
// and publishing compiled data-plane config without starting a proxy or dialing the frontend.
func runController(ctx context.Context, config Config, gariOptions gari.Options) error {
	addresses := config.GatewayAddresses
	if len(addresses) == 0 {
		addresses = []string{parseFrontendHost(config.FrontendAddr)}
	}
	gariOptions.ProxyAddr, gariOptions.ProxyHTTPSAddr, gariOptions.ProxyHTTP3Addr, gariOptions.HTTPSListener = "", "", "", nil
	gariOptions.AddressProvider = newAddressProvider(
		config.DeploymentName,
		config.DeploymentNamespace,
		gariOptions.DataplaneGatewayName,
		gariOptions.DataplaneGatewayNamespace,
		addresses...,
	)
	return gari.Run(ctx, gariOptions)
}

// runDataplane runs the snigateway data-plane process, running the reference implementation
// proxy alongside the tunnel client, reading its configuration from the per-Gateway Secret,
// and serving an HTTP readiness probe.
func runDataplane(ctx context.Context, config Config, gariOptions gari.Options) error {
	if config.CACertPath == "" {
		return errors.New("--ca-cert is required")
	}
	if config.TokenFilePath == "" && (config.ClientCertPath == "" || config.ClientKeyPath == "") {
		return errors.New("--client-cert and --client-key are required when --token-file is not specified")
	}
	caCertPEM, err := os.ReadFile(config.CACertPath)
	if err != nil {
		return fmt.Errorf("reading CA certificate %q: %w", config.CACertPath, err)
	}
	var clientCertPEM, clientKeyPEM []byte
	if config.ClientCertPath != "" {
		if clientCertPEM, err = os.ReadFile(config.ClientCertPath); err != nil {
			return fmt.Errorf("reading client certificate %q: %w", config.ClientCertPath, err)
		}
	}
	if config.ClientKeyPath != "" {
		if clientKeyPEM, err = os.ReadFile(config.ClientKeyPath); err != nil {
			return fmt.Errorf("reading client private key %q: %w", config.ClientKeyPath, err)
		}
	}
	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, config.InternalHostname)
	if err != nil {
		return fmt.Errorf("creating client TLS config: %w", err)
	}
	clientOptions := []sniclient.ClientOption{sniclient.WithInternalHostname(config.InternalHostname)}
	if config.TokenFilePath != "" {
		clientOptions = append(clientOptions, sniclient.WithTokenFile(config.TokenFilePath))
	}

	snigatewayClient := sniclient.NewClient(config.FrontendAddr, clientTLS, clientOptions...)
	tunnelManager := tunnel.NewManager(snigatewayClient, tunnel.WithPoolSize(config.TunnelPoolSize))

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kubeconfig: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	var hasSecretInCluster atomic.Bool
	var hasAppliedConfig atomic.Bool
	secretName := singlepod.ResourceNameForGateway(gariOptions.DataplaneGatewayName)
	internalGariHealthAddr := "127.0.0.1:8083"

	waitProxySynced := func(checkCtx context.Context) bool {
		for {
			select {
			case <-checkCtx.Done():
				return false
			default:
			}
			req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, "http://"+internalGariHealthAddr+"/_gari/readyz", nil)
			if err != nil {
				setupLog.V(5).Info("creating readyz check request", "error", err)
			} else {
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					setupLog.V(5).Info("checking proxy readyz", "error", err)
				} else {
					if err := resp.Body.Close(); err != nil {
						setupLog.V(5).Info("closing readyz response body", "error", err)
					}
					if resp.StatusCode == http.StatusOK {
						return true
					}
				}
			}
			select {
			case <-checkCtx.Done():
				return false
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	applySecret := func(applyCtx context.Context, secret *corev1.Secret) {
		if secret == nil {
			return
		}
		data := secret.Data[singlepod.DataplaneSecretDataKey]
		if len(data) == 0 {
			return
		}
		dataplaneConfig, err := state.UnmarshalDataplaneConfig(data)
		if err != nil {
			setupLog.Error(err, "failed to unmarshal dataplane config from secret", "secret", secretName)
			return
		}
		if !waitProxySynced(applyCtx) {
			return
		}
		hostnames := tunnel.ExtractHostnamesFromConfig(dataplaneConfig)
		tunnelManager.UpdateHostnames(hostnames)
		hasAppliedConfig.Store(true)
	}

	group, ctx := errgroup.WithContext(ctx)

	// Background worker watching the config Secret
	group.Go(func() error {
		existingSecret, err := kubeClient.CoreV1().Secrets(gariOptions.DataplaneGatewayNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if err == nil {
			hasSecretInCluster.Store(true)
			applySecret(ctx, existingSecret)
		} else if !apierrors.IsNotFound(err) {
			setupLog.Error(err, "reading existing dataplane secret", "secret", secretName)
		}

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			watcher, err := kubeClient.CoreV1().Secrets(gariOptions.DataplaneGatewayNamespace).Watch(ctx, metav1.ListOptions{
				FieldSelector: "metadata.name=" + secretName,
			})
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
					continue
				}
			}

			stopped := false
			for !stopped {
				select {
				case <-ctx.Done():
					watcher.Stop()
					return nil
				case event, ok := <-watcher.ResultChan():
					if !ok {
						stopped = true
						break
					}
					if secret, ok := event.Object.(*corev1.Secret); ok {
						hasSecretInCluster.Store(true)
						applySecret(ctx, secret)
					}
				}
			}
		}
	})

	healthProbeBindAddress := gariOptions.HealthProbeBindAddress
	if healthProbeBindAddress == "" {
		healthProbeBindAddress = ":8081"
	}

	// HTTP health probe server
	group.Go(func() error {
		mux := http.NewServeMux()
		mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
			if hasSecretInCluster.Load() && !hasAppliedConfig.Load() {
				http.Error(writer, "proxy configuration not yet applied", http.StatusServiceUnavailable)
				return
			}
			if !tunnelManager.IsConnected() {
				http.Error(writer, "tunnel session to frontend is not connected", http.StatusServiceUnavailable)
				return
			}
			if !tunnelManager.HasRegisteredAllHostnames() {
				http.Error(writer, "waiting for tunnel hostname registration to complete", http.StatusServiceUnavailable)
				return
			}
			writer.WriteHeader(http.StatusOK)
			if _, err := writer.Write([]byte("ok")); err != nil {
				setupLog.V(4).Info("writing readyz response", "error", err)
			}
		})
		server := &http.Server{
			Addr:    healthProbeBindAddress,
			Handler: mux,
		}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				setupLog.V(4).Info("shutting down health probe server", "error", err)
			}
		}()
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serving health probe: %w", err)
		}
		return nil
	})

	gariOptions.DataplaneMode = true
	gariOptions.HTTPSListener = tunnelManager.Listener()
	gariOptions.HealthProbeBindAddress = internalGariHealthAddr
	gariOptions.MetricsAddr = "0"

	group.Go(func() error {
		return tunnelManager.Run(ctx)
	})
	group.Go(func() error {
		return gari.Run(ctx, gariOptions)
	})
	return group.Wait()
}

func main() {
	config := DefaultConfig()
	gariOptions := DefaultGARIOptions()
	BindFlags(flag.CommandLine, &gariOptions, &config)
	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(textlogger.NewLogger(logConfig))
	ctx := ctrl.SetupSignalHandler()

	if gariOptions.DataplaneMode {
		if err := runDataplane(ctx, config, gariOptions); err != nil {
			setupLog.Error(err, "fatal error running snigateway data plane")
			os.Exit(1)
		}
		return
	}
	if err := runController(ctx, config, gariOptions); err != nil {
		setupLog.Error(err, "fatal error running snigateway controller")
		os.Exit(1)
	}
}
