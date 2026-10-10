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
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
)

var setupLog = ctrl.Log.WithName("setup")

func main() {
	opts := gari.DefaultOptions()

	var (
		dataplaneMode    bool
		gatewayNamespace string
		gatewayName      string
		dataplaneImage   string
	)

	defaultImg := os.Getenv("GARI_IMAGE")
	if defaultImg == "" {
		defaultImg = singlepod.DefaultDataplaneImage
	}

	flag.BoolVar(&dataplaneMode, "dataplane-mode", false, "Run in data-plane mode serving a single Gateway.")
	flag.StringVar(&gatewayNamespace, "gateway-namespace", "", "The namespace of the Gateway to serve in data-plane mode.")
	flag.StringVar(&gatewayName, "gateway-name", "", "The name of the Gateway to serve in data-plane mode.")
	flag.StringVar(&dataplaneImage, "dataplane-image", defaultImg, "The container image to use for provisioned per-Gateway data-plane Deployments.")
	flag.StringVar(&opts.MetricsAddr, "metrics-bind-address", opts.MetricsAddr, "The address the metric endpoint binds to.")
	flag.StringVar(&opts.HealthProbeBindAddress, "health-probe-bind-address", opts.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	flag.StringVar(&opts.ProxyAddr, "proxy-bind-address", opts.ProxyAddr, "The address the proxy binds to.")
	flag.StringVar(&opts.ProxyHTTPSAddr, "proxy-https-bind-address", opts.ProxyHTTPSAddr, "The address the proxy binds to for HTTPS.")
	flag.StringVar(&opts.ProxyHTTP3Addr, "proxy-http3-bind-address", opts.ProxyHTTP3Addr, "The UDP address the proxy binds to for HTTP/3 (disabled by default).")
	flag.IntVar(&opts.ProxyHTTP3AdvertisedPort, "proxy-http3-advertised-port", opts.ProxyHTTP3AdvertisedPort, "The port advertised in the Alt-Svc header for HTTP/3 (if 0, inferred from bind address).")
	flag.BoolVar(&opts.EnableH2C, "enable-h2c", opts.EnableH2C, "Enable H2C support on the proxy server.")
	flag.BoolVar(&opts.LeaderElection, "leader-elect", opts.LeaderElection,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&opts.ControllerName, "controller-name", opts.ControllerName, "The GatewayClass controller name.")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	if dataplaneMode {
		if gatewayNamespace == "" || gatewayName == "" {
			setupLog.Error(fmt.Errorf("--gateway-namespace and --gateway-name are required in --dataplane-mode"), "invalid configuration")
			os.Exit(1)
		}
		opts.DataplaneMode = true
		opts.DataplaneGatewayNamespace = gatewayNamespace
		opts.DataplaneGatewayName = gatewayName
		opts.DisableStatusUpdates = true
		opts.LeaderElection = false
		opts.ProxyHTTP3Addr = opts.ProxyHTTPSAddr // enable HTTP/3 on the HTTPS port for dataplane
		opts.AddressProvider = nil
	} else {
		opts.ProxyAddr = ""
		opts.ProxyHTTPSAddr = ""
		opts.ProxyHTTP3Addr = ""
		opts.AddressProvider = singlepod.NewAddressProvider(
			nil,
			singlepod.WithDataplaneImage(dataplaneImage),
			singlepod.WithEnableH2C(opts.EnableH2C),
		)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := gari.Run(ctx, opts); err != nil {
		setupLog.Error(err, "fatal error")
		os.Exit(1)
	}
}
