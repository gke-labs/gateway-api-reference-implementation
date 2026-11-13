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
	"flag"
	"fmt"
	"os"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultControllerName is the default GatewayClass controller name for snigateway.
	DefaultControllerName = "github.com/gke-labs/gateway-api-reference-implementation/snigateway"
)

var setupLog = ctrl.Log.WithName("setup")

// Config holds binary-specific configuration for snigateway.
type Config struct {
	FrontendAddr     string
	GatewayAddresses []string
	CACertPath       string
	ClientCertPath   string
	ClientKeyPath    string
	TokenFilePath    string
	InternalHostname string
	TunnelTransport  string
	TunnelPoolSize   int
}

// DefaultConfig returns standard default configuration for snigateway.
func DefaultConfig() Config {
	return Config{
		FrontendAddr:     "127.0.0.1:443",
		InternalHostname: "snigateway.internal",
		TunnelTransport:  tunnel.TransportModeTCP,
		TunnelPoolSize:   tunnel.DefaultPoolSize,
	}
}

// DefaultGARIOptions returns the default gari.Options customized for snigateway.
func DefaultGARIOptions() gari.Options {
	opts := gari.DefaultOptions()
	opts.ControllerName = DefaultControllerName
	opts.MetricsAddr = ":8080"
	opts.HealthProbeBindAddress = ":8081"
	opts.ProxyAddr = ""
	opts.LeaderElection = false
	opts.LeaderElectionID = "snigateway-controller"
	opts.DebugErrorResponses = false
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
	fs.StringVar(&cfg.TunnelTransport, "tunnel-transport", cfg.TunnelTransport, "Tunnel transport to use (tcp, h2).")
	fs.IntVar(&cfg.TunnelPoolSize, "tunnel-pool-size", cfg.TunnelPoolSize, "Number of idle pre-dialed reverse tunnel connections to maintain with the frontend when using TCP pool or H2 transport.")
	fs.StringVar(&opts.MetricsAddr, "metrics-bind-address", opts.MetricsAddr, "The address the metric endpoint binds to.")
	fs.StringVar(&opts.HealthProbeBindAddress, "health-probe-bind-address", opts.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	fs.StringVar(&opts.ProxyAddr, "proxy-bind-address", opts.ProxyAddr, "Optional HTTP proxy bind address. Disabled by default.")
	fs.BoolVar(&opts.LeaderElection, "leader-elect", opts.LeaderElection, "Enable leader election for controller manager.")
	fs.StringVar(&opts.LeaderElectionID, "leader-election-id", opts.LeaderElectionID, "The ID used for leader election.")
	fs.BoolVar(&opts.DebugErrorResponses, "debug-error-responses", opts.DebugErrorResponses, "Include detailed error messages in unmatched responses.")
	fs.StringVar(&opts.ACMEChallengeUpstreamURL, "acme-challenge-upstream-url", opts.ACMEChallengeUpstreamURL, "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to.")
	fs.StringVar(&opts.ACMEChallengeCABundlePath, "acme-challenge-ca-bundle-path", opts.ACMEChallengeCABundlePath, "Path to the CA bundle PEM file to verify the upstream certificate server.")
	fs.StringVar(&opts.ACMEChallengeTokenPath, "acme-challenge-token-path", opts.ACMEChallengeTokenPath, "Path to the projected service-account token file for data-plane identity.")
}

func main() {
	cfg := DefaultConfig()
	gariOpts := DefaultGARIOptions()

	BindFlags(flag.CommandLine, &gariOpts, &cfg)

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	if cfg.CACertPath == "" {
		setupLog.Error(fmt.Errorf("--ca-cert is required"), "missing required flag")
		os.Exit(1)
	}
	if cfg.TokenFilePath == "" {
		if cfg.ClientCertPath == "" {
			setupLog.Error(fmt.Errorf("--client-cert is required when --token-file is not specified"), "missing required flag")
			os.Exit(1)
		}
		if cfg.ClientKeyPath == "" {
			setupLog.Error(fmt.Errorf("--client-key is required when --token-file is not specified"), "missing required flag")
			os.Exit(1)
		}
	}

	caCertPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		setupLog.Error(err, "failed to read CA certificate", "path", cfg.CACertPath)
		os.Exit(1)
	}

	var clientCertPEM, clientKeyPEM []byte
	if cfg.ClientCertPath != "" {
		clientCertPEM, err = os.ReadFile(cfg.ClientCertPath)
		if err != nil {
			setupLog.Error(err, "failed to read client certificate", "path", cfg.ClientCertPath)
			os.Exit(1)
		}
	}

	if cfg.ClientKeyPath != "" {
		clientKeyPEM, err = os.ReadFile(cfg.ClientKeyPath)
		if err != nil {
			setupLog.Error(err, "failed to read client private key", "path", cfg.ClientKeyPath)
			os.Exit(1)
		}
	}

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, cfg.InternalHostname)
	if err != nil {
		setupLog.Error(err, "failed to create client TLS config")
		os.Exit(1)
	}

	clientOpts := []client.ClientOption{
		client.WithInternalHostname(cfg.InternalHostname),
	}
	if cfg.TokenFilePath != "" {
		clientOpts = append(clientOpts, client.WithTokenFile(cfg.TokenFilePath))
	}

	snigatewayClient := client.NewClient(cfg.FrontendAddr, clientTLS, clientOpts...)
	tunnelMgr := tunnel.NewManager(snigatewayClient,
		tunnel.WithTransport(cfg.TunnelTransport),
		tunnel.WithPoolSize(cfg.TunnelPoolSize),
	)

	addrs := cfg.GatewayAddresses
	if len(addrs) == 0 {
		addrs = []string{tunnel.ParseFrontendHost(cfg.FrontendAddr)}
	}

	addrProvider := tunnel.NewAddressProvider(tunnelMgr, addrs...)
	addrProvider.SetControllerName(gariOpts.ControllerName)

	gariOpts.ProxyHTTPSAddr = ""
	gariOpts.HTTPSListener = tunnelMgr.Listener()
	gariOpts.AddressProvider = addrProvider
	gariOpts.OnGatewaysUpdate = func(gateways []*gatewayv1.Gateway) {
		tunnelMgr.UpdateGateways(gateways)
	}

	ctx := ctrl.SetupSignalHandler()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return tunnelMgr.Run(ctx)
	})

	g.Go(func() error {
		return gari.Run(ctx, gariOpts)
	})

	if err := g.Wait(); err != nil {
		setupLog.Error(err, "fatal error running snigateway controller")
		os.Exit(1)
	}
}
