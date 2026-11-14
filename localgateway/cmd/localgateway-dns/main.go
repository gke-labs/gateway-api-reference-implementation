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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
)

// DefaultGatewayClassName is the default GatewayClass name managed by localgateway.
const DefaultGatewayClassName = "localgateway"

// Config contains localgateway-dns configuration flags.
type Config struct {
	GatewayClass string
	Interface    string
	MDNSPort     int
	MetricsAddr  string
}

// BuildOptions parses args and constructs the localgateway-dns Config.
func BuildOptions(args []string) (Config, error) {
	fs := flag.NewFlagSet("localgateway-dns", flag.ContinueOnError)
	cfg := Config{
		GatewayClass: DefaultGatewayClassName,
		MDNSPort:     mdns.DefaultPort,
		MetricsAddr:  "0",
	}

	fs.StringVar(&cfg.GatewayClass, "gateway-class", cfg.GatewayClass, "The GatewayClass name to watch Gateways for.")
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "Network interface to publish mDNS on (defaults to all).")
	fs.IntVar(&cfg.MDNSPort, "mdns-port", cfg.MDNSPort, "UDP port for mDNS publishing.")
	fs.StringVar(&cfg.MetricsAddr, "metrics-bind-address", cfg.MetricsAddr, "The address the metric endpoint binds to (0 to disable).")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(fs)

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))
	return cfg, nil
}

// GatewayReconciler watches Gateways for the configured GatewayClass and publishes
// their listener hostnames and status.addresses via mDNS.
type GatewayReconciler struct {
	client.Client
	GatewayClassName string
	Publisher        *mdns.Publisher
}

// Reconcile synchronizes active Gateways for the class with the mDNS publisher.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var gwList gatewayv1.GatewayList
	if err := r.List(ctx, &gwList); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var matching []*gatewayv1.Gateway
	for i := range gwList.Items {
		gw := &gwList.Items[i]
		if gw.DeletionTimestamp != nil {
			continue
		}
		if r.GatewayClassName == "" || string(gw.Spec.GatewayClassName) == r.GatewayClassName {
			matching = append(matching, gw)
		}
	}

	r.Publisher.OnGatewaysUpdate(matching)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the Gateway reconciler with the controller manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Complete(r)
}

func main() {
	cfg, err := BuildOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting localgateway-dns", "gatewayClass", cfg.GatewayClass, "mdnsPort", cfg.MDNSPort)

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "failed to add corev1 to scheme")
		os.Exit(1)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		setupLog.Error(err, "failed to install gatewayv1 to scheme")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		LeaderElection: false,
	})
	if err != nil {
		setupLog.Error(err, "failed to create manager")
		os.Exit(1)
	}

	pub, err := mdns.NewPublisher(mdns.PublisherOptions{
		Interface: cfg.Interface,
		Port:      cfg.MDNSPort,
	})
	if err != nil {
		setupLog.Error(err, "failed to create mDNS publisher")
		os.Exit(1)
	}

	if err := mgr.Add(pub); err != nil {
		setupLog.Error(err, "failed to register mDNS publisher with manager")
		os.Exit(1)
	}

	reconciler := &GatewayReconciler{
		Client:           mgr.GetClient(),
		GatewayClassName: cfg.GatewayClass,
		Publisher:        pub,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "failed to setup Gateway controller")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "fatal error running manager")
		os.Exit(1)
	}
}
