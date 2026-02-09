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
	"net/http"
	"os"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))
}

func main() {
	ctx := ctrl.SetupSignalHandler()
	if err := run(ctx); err != nil {
		setupLog.Error(err, "fatal error")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var proxyAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&proxyAddr, "proxy-bind-address", ":8000", "The address the proxy binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("unable to get kubeconfig: %w", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "gateway-api-reference-implementation",
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	st := state.NewState()
	p := proxy.NewProxy()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		setupLog.Info("starting proxy server", "addr", proxyAddr)
		srv := &http.Server{Addr: proxyAddr, Handler: p}
		go func() {
			<-ctx.Done()
			setupLog.Info("shutting down proxy server")
			_ = srv.Shutdown(context.Background())
		}()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("proxy server failed: %w", err)
		}
		return nil
	})

	if err = (&controller.HTTPRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		State:  st,
		Proxy:  p,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating HTTPRoute controller: %w", err)
	}

	if err = (&controller.GatewayClassReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating GatewayClass controller: %w", err)
	}

	if err = (&controller.GatewayReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		State:  st,
		Proxy:  p,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating Gateway controller: %w", err)
	}

	g.Go(func() error {
		setupLog.Info("starting manager")
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager: %w", err)
		}
		return nil
	})

	return g.Wait()
}
