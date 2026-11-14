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

	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/address"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
)

const (
	// DefaultControllerName is the default GatewayClass controller name for localgateway.
	DefaultControllerName = "github.com/gke-labs/gateway-api-reference-implementation/localgateway"
)

// Config contains localgateway-specific configuration flags.
type Config struct {
	// Interface is the network interface to query for LAN IP addresses.
	Interface string

	// NodeName is the Kubernetes node name for fallback address resolution.
	NodeName string

	// MDNSPort is the UDP port for mDNS publishing (defaults to 5353).
	MDNSPort int
}

// BuildOptions parses args and constructs gari.Options and localgateway Config.
func BuildOptions(args []string) (gari.Options, Config, error) {
	fs := flag.NewFlagSet("localgateway", flag.ContinueOnError)

	gariOpts := gari.DefaultOptions()
	cfg := Config{
		NodeName: os.Getenv("NODE_NAME"),
		MDNSPort: mdns.DefaultPort,
	}

	// Defaults tailored for localgateway all-in-one hostNetwork mode
	gariOpts.ControllerName = DefaultControllerName
	gariOpts.ProxyAddr = ":80"
	gariOpts.ProxyHTTPSAddr = ""
	gariOpts.ProxyHTTP3Addr = ""
	gariOpts.LeaderElection = false
	gariOpts.LeaderElectionID = "localgateway-controller"

	// Flags binding directly to gari.Options using the field's own value as default
	fs.StringVar(&gariOpts.MetricsAddr, "metrics-bind-address", gariOpts.MetricsAddr, "The address the metric endpoint binds to.")
	fs.StringVar(&gariOpts.HealthProbeBindAddress, "health-probe-bind-address", gariOpts.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	fs.StringVar(&gariOpts.ProxyAddr, "proxy-bind-address", gariOpts.ProxyAddr, "The host network address the HTTP proxy listens on.")
	fs.StringVar(&gariOpts.ControllerName, "controller-name", gariOpts.ControllerName, "The GatewayClass controller name managed by this instance.")
	fs.BoolVar(&gariOpts.LeaderElection, "leader-elect", gariOpts.LeaderElection, "Enable leader election for controller manager.")
	fs.StringVar(&gariOpts.LeaderElectionID, "leader-election-id", gariOpts.LeaderElectionID, "The ID used for leader election.")

	// Flags binding directly to localgateway Config struct using the field's own value as default
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "Network interface to read LAN IP addresses from (e.g. eth0). If unset, node addresses are used.")
	fs.StringVar(&cfg.NodeName, "node-name", cfg.NodeName, "Kubernetes node name for looking up LAN IP addresses when --interface is unset.")
	fs.IntVar(&cfg.MDNSPort, "mdns-port", cfg.MDNSPort, "UDP port for mDNS publishing.")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(fs)

	if err := fs.Parse(args); err != nil {
		return gari.Options{}, Config{}, err
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	// Hostname and protocol validation hook
	gariOpts.ListenerValidator = validation.ValidateListener

	// Address provider: AddressProvider implements controller.AddressWatcher to capture
	// the manager's client during controller registration.
	addrProvider := address.NewAddressProvider(address.Options{
		InterfaceName: cfg.Interface,
		NodeName:      cfg.NodeName,
	})
	gariOpts.AddressProvider = addrProvider

	return gariOpts, cfg, nil
}

// WirePublisher connects an mDNS Publisher to GARI options and registers it as a manager Runnable.
func WirePublisher(opts *gari.Options, pub *mdns.Publisher) {
	opts.GatewayStatusHook = pub.StatusHook
	var dnsPub *dnsconfig.Publisher
	opts.OnGatewaysUpdate = func(gateways []*gatewayv1.Gateway) {
		pub.OnGatewaysUpdate(gateways)
		if dnsPub != nil {
			if err := dnsPub.Publish(context.Background(), gateways); err != nil {
				ctrl.Log.WithName("dns-publisher").Error(err, "failed to publish DNS data plane config")
			}
		}
	}
	opts.SetupWithManager = func(mgr ctrl.Manager, s *gari.Server) error {
		pub.SetEnqueueGateway(s.EnqueueGateway)
		if err := mgr.Add(pub); err != nil {
			return fmt.Errorf("failed to register mDNS publisher with manager: %w", err)
		}
		dnsPub = dnsconfig.NewPublisher(mgr.GetClient(), dnsconfig.DefaultSecretNamespace, dnsconfig.DefaultSecretName, "localgateway")
		return nil
	}
}

func main() {
	opts, cfg, err := BuildOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting localgateway controller (all-in-one hostNetwork)", "controllerName", opts.ControllerName, "proxyAddr", opts.ProxyAddr)

	// Build mDNS publisher upfront before starting GARI
	addrProvider, _ := opts.AddressProvider.(*address.AddressProvider)
	pub, err := mdns.NewPublisher(mdns.PublisherOptions{
		Interface:       cfg.Interface,
		Port:            cfg.MDNSPort,
		AddressProvider: addrProvider,
	})
	if err != nil {
		setupLog.Error(err, "failed to start mDNS publisher")
		os.Exit(1)
	}

	WirePublisher(&opts, pub)

	if err := gari.Run(ctx, opts); err != nil {
		setupLog.Error(err, "fatal error running localgateway")
		os.Exit(1)
	}
}
