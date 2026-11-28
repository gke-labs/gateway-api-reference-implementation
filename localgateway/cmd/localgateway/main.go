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
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/hostport"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

const (
	// DefaultControllerName is the default GatewayClass controller name for localgateway.
	DefaultControllerName = "github.com/gke-labs/gateway-api-reference-implementation/localgateway"
)

// Config holds localgateway-specific controller flags.
type Config struct {
	// DataplaneImage is the container image used for provisioned per-Gateway data-plane Deployments.
	DataplaneImage string
}

// DefaultConfig returns the default Config populated from environment variables.
func DefaultConfig() Config {
	defaultImage := os.Getenv("GARI_IMAGE")
	if defaultImage == "" {
		defaultImage = singlepod.DefaultDataplaneImage
	}
	return Config{
		DataplaneImage: defaultImage,
	}
}

// BindFlags registers localgateway and GARI controller flags on flagSet.
func BindFlags(flagSet *flag.FlagSet, options *gari.Options, config *Config) {
	if config.DataplaneImage == "" {
		config.DataplaneImage = DefaultConfig().DataplaneImage
	}

	flagSet.StringVar(&options.MetricsAddr, "metrics-bind-address", options.MetricsAddr, "The address the metric endpoint binds to.")
	flagSet.StringVar(&options.HealthProbeBindAddress, "health-probe-bind-address", options.HealthProbeBindAddress, "The address the probe endpoint binds to.")
	flagSet.StringVar(&options.ControllerName, "controller-name", options.ControllerName, "The GatewayClass controller name managed by this instance.")
	flagSet.StringVar(&config.DataplaneImage, "dataplane-image", config.DataplaneImage, "The container image to use for provisioned per-Gateway data-plane Deployments.")
	flagSet.BoolVar(&options.LeaderElection, "leader-elect", options.LeaderElection, "Enable leader election for controller manager.")
	flagSet.StringVar(&options.LeaderElectionID, "leader-election-id", options.LeaderElectionID, "The ID used for leader election.")
	gari.BindInternalAPIFlags(flagSet, options)
}

// BuildOptions parses command-line arguments and returns gari.Options configured
// for the localgateway host-port controller.
func BuildOptions(args []string) (gari.Options, error) {
	flagSet := flag.NewFlagSet("localgateway", flag.ContinueOnError)

	options := gari.DefaultOptions()
	options.ControllerName = DefaultControllerName
	options.ProxyAddr = ""
	options.ProxyHTTPSAddr = ""
	options.ProxyHTTP3Addr = ""
	options.LeaderElection = false
	options.LeaderElectionID = "localgateway-controller"

	config := DefaultConfig()
	BindFlags(flagSet, &options, &config)

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flagSet)

	if err := flagSet.Parse(args); err != nil {
		return gari.Options{}, err
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	controllerNamespace, err := gari.ProvisioningControllerNamespace(options)
	if err != nil {
		return gari.Options{}, err
	}

	options.ListenerValidator = validation.ValidateListener

	addressProvider, err := hostport.New(
		nil,
		nil,
		controllerNamespace,
		singlepod.WithDataplaneImage(config.DataplaneImage),
	)
	if err != nil {
		return gari.Options{}, fmt.Errorf("creating host-port address provider: %w", err)
	}
	options.AddressProvider = addressProvider

	options.SetupWithManager = func(manager ctrl.Manager, server *gari.Server) error {
		uncachedClient := &uncachedReaderClient{
			Client: manager.GetClient(),
			reader: manager.GetAPIReader(),
		}
		dnsPublisher := dnsconfig.NewPublisher(uncachedClient, controllerNamespace, dnsconfig.DefaultConfigSecretName, server.State())
		if err := manager.Add(dnsPublisher); err != nil {
			return fmt.Errorf("failed to register dns config publisher with manager: %w", err)
		}
		return nil
	}

	return options, nil
}

// uncachedReaderClient wraps a client.Client and sends Get calls through an uncached
// API reader so the DNS config publisher reads its Secret directly from the API server.
type uncachedReaderClient struct {
	client.Client
	reader client.Reader
}

// Get reads the object directly from the API server without using the controller cache.
func (c *uncachedReaderClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

func main() {
	options, err := BuildOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	setupLogger := ctrl.Log.WithName("setup")
	setupLogger.Info("Starting localgateway controller", "controllerName", options.ControllerName)

	if err := gari.Run(ctx, options); err != nil {
		setupLogger.Error(err, "fatal error running localgateway")
		os.Exit(1)
	}
}
