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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/certserversource"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
)

var setupLog = ctrl.Log.WithName("setup")

// Config holds non-Options command-line flag variables.
type Config struct {
	DataplaneImage string
	Certserver     certserversource.Config
}

// DefaultConfig returns the default Config populated from environment variables.
func DefaultConfig() Config {
	defaultImg := os.Getenv("GARI_IMAGE")
	if defaultImg == "" {
		defaultImg = singlepod.DefaultDataplaneImage
	}
	return Config{
		DataplaneImage: defaultImg,
		Certserver:     certserversource.DefaultConfig(),
	}
}

// BindFlags registers all command-line flags on the given FlagSet.
func BindFlags(fs *flag.FlagSet, opts *gari.Options, cfg *Config) {
	if cfg.DataplaneImage == "" {
		cfg.DataplaneImage = DefaultConfig().DataplaneImage
	}

	fs.BoolVar(&opts.DataplaneMode, "dataplane-mode", opts.DataplaneMode, "Run in data-plane mode serving a single Gateway.")
	fs.StringVar(&opts.DataplaneGatewayNamespace, "gateway-namespace", opts.DataplaneGatewayNamespace, "The namespace of the Gateway to serve in data-plane mode.")
	fs.StringVar(&opts.DataplaneGatewayName, "gateway-name", opts.DataplaneGatewayName, "The name of the Gateway to serve in data-plane mode.")
	fs.StringVar(&cfg.DataplaneImage, "dataplane-image", cfg.DataplaneImage, "The container image to use for provisioned per-Gateway data-plane Deployments.")
	fs.Var(gari.CommaSeparatedSlice(&opts.AllowedSourceCIDRs), "allowed-source-cidrs", "Comma-separated list of CIDRs permitted to connect to HTTP/HTTPS listeners.")
	fs.StringVar(&opts.ProxyProtocol, "proxy-protocol", opts.ProxyProtocol, "Enable PROXY protocol ('enabled').")
	fs.Var(gari.CommaSeparatedSlice(&opts.ProxyProtocolTrustedCIDRs), "proxy-protocol-trusted-cidrs", "Comma-separated list of trusted CIDRs for PROXY protocol.")
	fs.StringVar(&opts.DrainSentinelPath, "drain-sentinel-path", opts.DrainSentinelPath, "Path to the sentinel file that marks the pod as draining.")
	fs.StringVar(&opts.MetricsAddr, "metrics-bind-address", opts.MetricsAddr, "The address the metric endpoint binds to.")
	fs.StringVar(&opts.HealthProbeBindAddress, "health-probe-bind-address", opts.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	fs.StringVar(&opts.ProxyAddr, "proxy-bind-address", opts.ProxyAddr, "The address the proxy binds to for HTTP.")
	fs.StringVar(&opts.ProxyHTTPSAddr, "proxy-https-bind-address", opts.ProxyHTTPSAddr, "The address the proxy binds to for HTTPS.")
	fs.StringVar(&opts.ProxyHTTP3Addr, "proxy-http3-bind-address", opts.ProxyHTTP3Addr, "The UDP address the proxy binds to for HTTP/3 (disabled by default).")
	fs.IntVar(&opts.ProxyHTTP3AdvertisedPort, "proxy-http3-advertised-port", opts.ProxyHTTP3AdvertisedPort, "The port advertised in the Alt-Svc header for HTTP/3 (if 0, inferred from bind address).")
	fs.BoolVar(&opts.EnableH2C, "enable-h2c", opts.EnableH2C, "Enable H2C support on the proxy server.")
	fs.DurationVar(&opts.UDPIdleTimeout, "udp-idle-timeout", opts.UDPIdleTimeout, "The idle timeout for UDP sessions.")
	fs.IntVar(&opts.UDPMaxSessions, "udp-max-sessions", opts.UDPMaxSessions, "The maximum number of concurrent UDP sessions per listener.")
	fs.DurationVar(&opts.ReadHeaderTimeout, "read-header-timeout", opts.ReadHeaderTimeout, "The amount of time allowed to read request headers on HTTP and HTTPS servers.")
	fs.DurationVar(&opts.IdleTimeout, "idle-timeout", opts.IdleTimeout, "The maximum amount of time to wait for the next request when keep-alives are enabled.")
	fs.DurationVar(&opts.ReadTimeout, "read-timeout", opts.ReadTimeout, "The maximum duration for reading the entire request, including the body (disabled by default).")
	fs.DurationVar(&opts.BodyReadTimeout, "body-read-timeout", opts.BodyReadTimeout, "The maximum duration allowed between read progress while reading a request body.")
	fs.DurationVar(&opts.WriteTimeout, "write-timeout", opts.WriteTimeout, "The maximum duration before timing out writes of the response (disabled by default).")
	fs.DurationVar(&opts.TCPIdleTimeout, "tcp-idle-timeout", opts.TCPIdleTimeout, "The idle timeout for TCP connections on spliced listeners (disabled by default).")
	fs.IntVar(&opts.TCPMaxConnections, "tcp-max-connections", opts.TCPMaxConnections, "The maximum number of concurrent TCP connections per listener.")
	fs.StringVar((*string)(&opts.ForwardedForMode), "forwarded-for-mode", string(opts.ForwardedForMode), "How to handle X-Forwarded-For: append (default) or replace.")
	fs.BoolVar(&opts.DebugErrorResponses, "debug-error-responses", opts.DebugErrorResponses, "Include detailed error messages in unmatched responses.")
	fs.StringVar(&opts.ACMEChallengeUpstreamURL, "acme-challenge-upstream-url", opts.ACMEChallengeUpstreamURL, "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to.")
	fs.StringVar(&opts.ACMEChallengeCABundlePath, "acme-challenge-ca-bundle-path", opts.ACMEChallengeCABundlePath, "Path to the CA bundle PEM file to verify the upstream certificate server.")
	fs.StringVar(&opts.ACMEChallengeTokenPath, "acme-challenge-token-path", opts.ACMEChallengeTokenPath, "Path to the projected service-account token file for data-plane identity.")
	fs.BoolVar(&opts.LeaderElection, "leader-elect", opts.LeaderElection,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	fs.StringVar(&opts.ControllerName, "controller-name", opts.ControllerName, "The GatewayClass controller name.")
	certserversource.BindFlags(fs, &cfg.Certserver)
}

func main() {
	opts, err := Setup(os.Args[1:])
	if err != nil {
		setupLog.Error(err, "invalid configuration")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := gari.Run(ctx, opts); err != nil {
		setupLog.Error(err, "fatal error")
		os.Exit(1)
	}
}

// Setup parses args once using flag.FlagSet and builds gari.Options for either
// data-plane mode (when --dataplane-mode is set) or controller mode.
func Setup(args []string) (gari.Options, error) {
	opts := gari.DefaultOptions()
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("gari", flag.ContinueOnError)
	BindFlags(fs, &opts, &cfg)

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(fs)

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	if opts.DataplaneMode {
		if opts.DataplaneGatewayNamespace == "" || opts.DataplaneGatewayName == "" {
			return opts, fmt.Errorf("--gateway-namespace and --gateway-name are required in --dataplane-mode")
		}
		// Data-plane pods serve traffic for a single Gateway and do not perform
		// status updates or run leader election.
		opts.DisableStatusUpdates = true
		opts.LeaderElection = false
		// Default HTTP/3 bind address to HTTPS bind address for dataplane.
		if opts.ProxyHTTP3Addr == "" && opts.ProxyHTTPSAddr != "" {
			opts.ProxyHTTP3Addr = opts.ProxyHTTPSAddr
		}
		return opts, nil
	}

	if err := certserversource.Register(&opts, cfg.Certserver); err != nil {
		return opts, err
	}

	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.ProxyHTTP3Addr = ""
	opts.AddressProvider = singlepod.NewAddressProvider(
		nil,
		singlepod.WithDataplaneImage(cfg.DataplaneImage),
		singlepod.WithEnableH2C(opts.EnableH2C),
		singlepod.WithForwardedForMode(string(opts.ForwardedForMode)),
		singlepod.WithDebugErrorResponses(opts.DebugErrorResponses),
		singlepod.WithACMEChallengeUpstreamURL(opts.ACMEChallengeUpstreamURL),
		singlepod.WithACMEChallengeCABundlePath(opts.ACMEChallengeCABundlePath),
		singlepod.WithACMEChallengeTokenPath(opts.ACMEChallengeTokenPath),
	)

	return opts, nil
}

// SetupController parses args and builds the gari.Options for controller mode.
func SetupController(args []string) (gari.Options, error) {
	opts, err := Setup(args)
	if err != nil {
		return opts, err
	}
	if opts.DataplaneMode {
		return opts, fmt.Errorf("unexpected --dataplane-mode in controller setup")
	}
	return opts, nil
}

// SetupDataplane parses args and builds the gari.Options for data-plane mode.
func SetupDataplane(args []string) (gari.Options, error) {
	hasDataplaneMode := false
	for _, a := range args {
		if a == "--dataplane-mode" || a == "-dataplane-mode" || a == "--dataplane-mode=true" || a == "-dataplane-mode=true" {
			hasDataplaneMode = true
			break
		}
	}
	if !hasDataplaneMode {
		args = append([]string{"--dataplane-mode"}, args...)
	}
	return Setup(args)
}
