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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/registrar"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/certserversource"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	compute "google.golang.org/api/compute/v1"
	corev1 "k8s.io/api/core/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultDrainSeconds is the default sleep duration for connection draining.
	DefaultDrainSeconds = 35

	// DefaultSentinelPath is the default path to write the drain sentinel.
	DefaultSentinelPath = "/var/run/gcpgateway/draining"

	// DefaultNegPrefix is the default resource prefix.
	DefaultNegPrefix = "gcpgw"

	// DefaultControllerName is the default GatewayClass controller name for gcpgateway.
	DefaultControllerName = "gke-labs.io/gcpgateway"

	// LoadBalancerReadyGate is the readiness gate added to data plane pods.
	LoadBalancerReadyGate = "gcpgateway.gke-labs.io/load-balancer-ready"
)

// RunPreStopHook executes the pre-stop lifecycle hook: writes sentinel file and sleeps.
func RunPreStopHook(args []string) error {
	fs := flag.NewFlagSet("pre-stop", flag.ContinueOnError)
	drainSeconds := fs.Int("drain-seconds", DefaultDrainSeconds, "Seconds to wait while draining connections")
	sentinelFile := fs.String("sentinel-file", DefaultSentinelPath, "Path to the draining sentinel file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := filepath.Dir(*sentinelFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating sentinel directory %q: %w", dir, err)
	}

	if err := os.WriteFile(*sentinelFile, []byte("draining\n"), 0644); err != nil {
		return fmt.Errorf("writing drain sentinel %q: %w", *sentinelFile, err)
	}

	klog.Infof("Pre-stop hook: wrote sentinel to %q, sleeping for %d seconds...", *sentinelFile, *drainSeconds)
	time.Sleep(time.Duration(*drainSeconds) * time.Second)
	klog.Info("Pre-stop hook: drain period finished, exiting cleanly.")
	return nil
}

// Run parses arguments and executes the requested subcommand or mode.
func Run(ctx context.Context, args []string) error {
	if len(args) >= 2 && args[0] == "hook" && args[1] == "pre-stop" {
		return RunPreStopHook(args[2:])
	}

	for _, arg := range args {
		if arg == "-dataplane-mode" || arg == "--dataplane-mode" || strings.HasPrefix(arg, "-dataplane-mode=") || strings.HasPrefix(arg, "--dataplane-mode=") {
			return runDataplane(ctx, args)
		}
	}

	return runController(ctx, args)
}

func runDataplane(ctx context.Context, args []string) error {
	opts, err := SetupDataplane(args)
	if err != nil {
		return err
	}
	return gari.Run(ctx, opts)
}

// BindDataplaneFlags registers data-plane command-line flags on the given FlagSet.
func BindDataplaneFlags(fs *flag.FlagSet, opts *gari.Options) {
	fs.BoolVar(&opts.DataplaneMode, "dataplane-mode", opts.DataplaneMode, "Run in data-plane mode")
	fs.StringVar(&opts.DataplaneGatewayNamespace, "gateway-namespace", opts.DataplaneGatewayNamespace, "Gateway namespace")
	fs.StringVar(&opts.DataplaneGatewayName, "gateway-name", opts.DataplaneGatewayName, "Gateway name")
	fs.Var(gari.CommaSeparatedSlice(&opts.AllowedSourceCIDRs), "allowed-source-cidrs", "Allowed source CIDRs")
	fs.StringVar(&opts.ProxyProtocol, "proxy-protocol", opts.ProxyProtocol, "Enable PROXY protocol")
	fs.Var(gari.CommaSeparatedSlice(&opts.ProxyProtocolTrustedCIDRs), "proxy-protocol-trusted-cidrs", "Trusted PROXY protocol CIDRs")
	fs.StringVar(&opts.DrainSentinelPath, "drain-sentinel-path", opts.DrainSentinelPath, "Path to drain sentinel file")
	fs.StringVar(&opts.MetricsAddr, "metrics-bind-address", opts.MetricsAddr, "Metrics bind address")
	fs.StringVar(&opts.HealthProbeBindAddress, "health-probe-bind-address", opts.HealthProbeBindAddress, "Health probe bind address")
	fs.StringVar(&opts.ProxyAddr, "proxy-bind-address", opts.ProxyAddr, "HTTP proxy bind address")
	fs.StringVar(&opts.ProxyHTTPSAddr, "proxy-https-bind-address", opts.ProxyHTTPSAddr, "HTTPS proxy bind address")
	fs.BoolVar(&opts.DebugErrorResponses, "debug-error-responses", opts.DebugErrorResponses, "Include detailed error messages in unmatched responses")
	fs.BoolVar(&opts.EnableH2C, "enable-h2c", opts.EnableH2C, "Enable H2C support on the proxy server")
	fs.StringVar((*string)(&opts.ForwardedForMode), "forwarded-for-mode", string(opts.ForwardedForMode), "How to handle X-Forwarded-For: append (default) or replace")
	// The singlepod provisioner passes the HTTP/3 flags to every data plane with an HTTPS listener, so the
	// data-plane flag set must accept them (matching cmd/gateway-api-reference-implementation).
	fs.StringVar(&opts.ProxyHTTP3Addr, "proxy-http3-bind-address", opts.ProxyHTTP3Addr, "The UDP address the proxy binds to for HTTP/3 (defaults to the HTTPS bind address)")
	fs.IntVar(&opts.ProxyHTTP3AdvertisedPort, "proxy-http3-advertised-port", opts.ProxyHTTP3AdvertisedPort, "The port advertised in the Alt-Svc header for HTTP/3 (if 0, inferred from bind address)")
	fs.StringVar(&opts.ACMEChallengeUpstreamURL, "acme-challenge-upstream-url", opts.ACMEChallengeUpstreamURL, "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to")
	fs.StringVar(&opts.ACMEChallengeCABundlePath, "acme-challenge-ca-bundle-path", opts.ACMEChallengeCABundlePath, "Path to the CA bundle PEM file to verify the upstream certificate server")
	fs.StringVar(&opts.ACMEChallengeTokenPath, "acme-challenge-token-path", opts.ACMEChallengeTokenPath, "Path to the projected service-account token file for data-plane identity")
	gari.BindInternalAPIFlags(fs, opts)
}

// SetupDataplane parses args and builds the gari.Options for data-plane mode.
func SetupDataplane(args []string) (gari.Options, error) {
	opts := gari.DefaultOptions()
	opts.DataplaneMode = true
	opts.DrainSentinelPath = DefaultSentinelPath

	fs := flag.NewFlagSet("dataplane", flag.ContinueOnError)
	BindDataplaneFlags(fs, &opts)

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	if opts.DataplaneGatewayNamespace == "" || opts.DataplaneGatewayName == "" {
		return opts, fmt.Errorf("--gateway-namespace and --gateway-name are required in --dataplane-mode")
	}

	// Data-plane pods serve traffic for a single Gateway and do not perform
	// status updates, run leader election, or manage an address provider.
	opts.DisableStatusUpdates = true
	opts.LeaderElection = false
	// Default HTTP/3 bind address to HTTPS bind address for dataplane.
	if opts.ProxyHTTP3Addr == "" {
		opts.ProxyHTTP3Addr = opts.ProxyHTTPSAddr
	}
	opts.AddressProvider = nil

	return opts, nil
}

// ControllerConfig holds binary-specific configuration for the gcpgateway controller.
type ControllerConfig struct {
	ClusterID          string
	NegPrefix          string
	Project            string
	Region             string
	Zones              []string
	DataplaneImage     string
	DrainSeconds       int
	HealthPollInterval time.Duration
	ResyncInterval     time.Duration
	FakeCompute        bool
	Certserver         certserversource.Config
}

// DefaultControllerConfig returns the default ControllerConfig populated from environment variables.
func DefaultControllerConfig() ControllerConfig {
	defaultClusterID := os.Getenv("CLUSTER_ID")
	if defaultClusterID == "" {
		defaultClusterID = "cluster-1"
	}
	defaultNegPrefix := os.Getenv("NEG_PREFIX")
	if defaultNegPrefix == "" {
		defaultNegPrefix = DefaultNegPrefix
	}
	defaultProject := os.Getenv("PROJECT_ID")
	defaultRegion := os.Getenv("REGION")
	defaultImg := os.Getenv("GARI_IMAGE")
	if defaultImg == "" {
		defaultImg = singlepod.DefaultDataplaneImage
	}

	return ControllerConfig{
		ClusterID:          defaultClusterID,
		NegPrefix:          defaultNegPrefix,
		Project:            defaultProject,
		Region:             defaultRegion,
		DataplaneImage:     defaultImg,
		DrainSeconds:       DefaultDrainSeconds,
		HealthPollInterval: controller.HealthPollInterval,
		ResyncInterval:     controller.ResyncInterval,
		Certserver:         certserversource.DefaultConfig(),
	}
}

// BindControllerFlags registers controller command-line flags on the given FlagSet.
func BindControllerFlags(fs *flag.FlagSet, opts *gari.Options, cfg *ControllerConfig) {
	fs.StringVar(&cfg.ClusterID, "cluster-id", cfg.ClusterID, "Unique Kubernetes cluster identifier")
	fs.StringVar(&cfg.NegPrefix, "neg-prefix", cfg.NegPrefix, "Prefix for zonal NEG names")
	fs.StringVar(&cfg.Project, "project", cfg.Project, "GCP Project ID")
	fs.StringVar(&cfg.Region, "region", cfg.Region, "GCP Region")
	fs.Var(gari.CommaSeparatedSlice(&cfg.Zones), "zones", "Comma-separated list of GCP zones")
	fs.StringVar(&opts.ControllerName, "controller-name", opts.ControllerName, "GatewayClass controller name")
	fs.StringVar(&cfg.DataplaneImage, "dataplane-image", cfg.DataplaneImage, "Data-plane container image")
	fs.IntVar(&cfg.DrainSeconds, "drain-seconds", cfg.DrainSeconds, "Seconds to drain connections during rolling updates")
	fs.DurationVar(&cfg.HealthPollInterval, "health-poll-interval", cfg.HealthPollInterval, "Interval between load balancer health check polls")
	fs.DurationVar(&cfg.ResyncInterval, "resync-interval", cfg.ResyncInterval, "Interval between full periodic resyncs")
	fs.BoolVar(&opts.LeaderElection, "leader-elect", opts.LeaderElection, "Enable leader election")
	fs.BoolVar(&cfg.FakeCompute, "fake-compute", cfg.FakeCompute, "Use in-memory fake Compute client for testing/offline mode")
	fs.BoolVar(&opts.DebugErrorResponses, "debug-error-responses", opts.DebugErrorResponses, "Include detailed error messages in unmatched responses")
	fs.StringVar(&opts.ACMEChallengeUpstreamURL, "acme-challenge-upstream-url", opts.ACMEChallengeUpstreamURL, "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to")
	fs.StringVar(&opts.ACMEChallengeCABundlePath, "acme-challenge-ca-bundle-path", opts.ACMEChallengeCABundlePath, "Path to the CA bundle PEM file to verify the upstream certificate server")
	fs.StringVar(&opts.ACMEChallengeTokenPath, "acme-challenge-token-path", opts.ACMEChallengeTokenPath, "Path to the projected service-account token file for data-plane identity")
	certserversource.BindFlags(fs, &cfg.Certserver)
	gari.BindInternalAPIFlags(fs, opts)
}

// SetupController parses args and builds the gari.Options for controller mode.
// If computeClient is nil:
//   - if --fake-compute is set, gcp.NewFakeComputeClient() is used.
//   - otherwise compute.NewService(ctx) is called, returning an error on failure.
func SetupController(ctx context.Context, args []string, computeClient gcp.ComputeClient) (gari.Options, error) {
	cfg := DefaultControllerConfig()

	opts := gari.DefaultOptions()
	opts.ControllerName = DefaultControllerName
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.ProxyHTTP3Addr = ""
	opts.DrainSentinelPath = DefaultSentinelPath
	opts.LeaderElection = false
	opts.DebugErrorResponses = false

	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	BindControllerFlags(fs, &opts, &cfg)

	if err := fs.Parse(args); err != nil {
		return gari.Options{}, err
	}

	if err := certserversource.Register(&opts, cfg.Certserver); err != nil {
		return gari.Options{}, err
	}

	controllerNamespace := os.Getenv("POD_NAMESPACE")
	if controllerNamespace == "" {
		controllerNamespace = "default"
	}

	gcpClient := computeClient
	if gcpClient == nil {
		if cfg.FakeCompute {
			gcpClient = gcp.NewFakeComputeClient()
		} else {
			computeSvc, err := compute.NewService(ctx)
			if err != nil {
				return gari.Options{}, fmt.Errorf("initializing Google Cloud Compute API client: %w", err)
			}
			gcpClient = gcp.NewGCEComputeClient(computeSvc)
		}
	}

	drainVol := corev1ac.Volume().
		WithName("drain-volume").
		WithEmptyDir(corev1ac.EmptyDirVolumeSource().WithMedium(corev1.StorageMediumMemory))
	drainMount := corev1ac.VolumeMount().
		WithName("drain-volume").
		WithMountPath("/var/run/gcpgateway")

	preStopCmd := []string{
		"/gcpgateway",
		"hook",
		"pre-stop",
		fmt.Sprintf("--drain-seconds=%d", cfg.DrainSeconds),
	}

	gracePeriodSeconds := int64(cfg.DrainSeconds + 25)
	if gracePeriodSeconds < 60 {
		gracePeriodSeconds = 60
	}

	opts.AddressProvider = singlepod.NewAddressProvider(
		nil,
		singlepod.WithDataplaneImage(cfg.DataplaneImage),
		singlepod.WithExtraReadinessGates(LoadBalancerReadyGate),
		singlepod.WithPreStopCommand(preStopCmd...),
		singlepod.WithExtraVolumes([]*corev1ac.VolumeApplyConfiguration{drainVol}, []*corev1ac.VolumeMountApplyConfiguration{drainMount}),
		singlepod.WithTerminationGracePeriodSeconds(gracePeriodSeconds),
		singlepod.WithDebugErrorResponses(opts.DebugErrorResponses),
		singlepod.WithACMEChallengeUpstreamURL(opts.ACMEChallengeUpstreamURL),
		singlepod.WithACMEChallengeCABundlePath(opts.ACMEChallengeCABundlePath),
		singlepod.WithACMEChallengeTokenPath(opts.ACMEChallengeTokenPath),
		singlepod.WithDataplaneConfigFromInternalAPI(controllerNamespace),
	)

	reconcilerCfg := controller.GatewayReconcilerConfig{
		ClusterID:          cfg.ClusterID,
		NegPrefix:          cfg.NegPrefix,
		Project:            cfg.Project,
		Zones:              cfg.Zones,
		ControllerName:     opts.ControllerName,
		HealthPollInterval: cfg.HealthPollInterval,
		ResyncInterval:     cfg.ResyncInterval,
	}

	var rec *controller.GatewayReconciler
	opts.GatewayStatusHook = func(ctx context.Context, gw *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
		if rec != nil {
			return rec.GatewayStatusHook(ctx, gw, status)
		}
		return nil
	}

	prevSetup := opts.SetupWithManager
	opts.SetupWithManager = func(mgr ctrl.Manager, s *gari.Server) error {
		if prevSetup != nil {
			if err := prevSetup(mgr, s); err != nil {
				return err
			}
		}
		recorder := mgr.GetEventRecorderFor("gcpgateway")
		reg := registrar.NewRegistrar(mgr.GetClient(), gcpClient, registrar.Config{
			ClusterID: reconcilerCfg.ClusterID,
			NegPrefix: reconcilerCfg.NegPrefix,
			Project:   reconcilerCfg.Project,
			Zones:     reconcilerCfg.Zones,
			Recorder:  recorder,
		})

		rCfg := reconcilerCfg
		if s != nil {
			rCfg.EnqueueGateway = s.EnqueueGateway
		}

		rec = controller.NewGatewayReconciler(
			mgr.GetClient(),
			mgr.GetScheme(),
			gcpClient,
			reg,
			rCfg,
		)

		return rec.SetupWithManager(mgr)
	}

	return opts, nil
}

func runController(ctx context.Context, args []string) error {
	opts, err := SetupController(ctx, args, nil)
	if err != nil {
		return err
	}
	return gari.Run(ctx, opts)
}

func main() {
	// controller-runtime drops all log output until a logger is set.
	ctrl.SetLogger(klog.NewKlogr())
	ctx := ctrl.SetupSignalHandler()
	if err := Run(ctx, os.Args[1:]); err != nil {
		klog.Errorf("gcpgateway: %v", err)
		os.Exit(1)
	}
}
