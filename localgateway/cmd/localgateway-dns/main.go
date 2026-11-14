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
	"net"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
)

// defaultGatewayClassName is the default GatewayClass name managed by localgateway.
const defaultGatewayClassName = "localgateway"

// config contains localgateway-dns configuration flags.
type config struct {
	gatewayClass     string
	networkInterface string
	mdnsPort         int
	metricsAddr      string
}

// buildOptions parses args and constructs the localgateway-dns config.
func buildOptions(args []string) (config, error) {
	flagSet := flag.NewFlagSet("localgateway-dns", flag.ContinueOnError)
	configuration := config{
		gatewayClass: defaultGatewayClassName,
		mdnsPort:     mdns.DefaultPort,
		metricsAddr:  "0",
	}

	flagSet.StringVar(&configuration.gatewayClass, "gateway-class", configuration.gatewayClass, "The GatewayClass name to watch Gateways for.")
	flagSet.StringVar(&configuration.networkInterface, "interface", configuration.networkInterface, "Network interface to publish mDNS on (defaults to all).")
	flagSet.IntVar(&configuration.mdnsPort, "mdns-port", configuration.mdnsPort, "UDP port for mDNS publishing.")
	flagSet.StringVar(&configuration.metricsAddr, "metrics-bind-address", configuration.metricsAddr, "The address the metric endpoint binds to (0 to disable).")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flagSet)

	if err := flagSet.Parse(args); err != nil {
		return config{}, err
	}

	if strings.TrimSpace(configuration.gatewayClass) == "" {
		return config{}, fmt.Errorf("--gateway-class is required and cannot be empty")
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))
	return configuration, nil
}

// gatewayReconciler watches Gateways for the configured GatewayClass and publishes
// their listener hostnames and status.addresses via mDNS.
type gatewayReconciler struct {
	client.Client
	gatewayClassName string
	publisher        *mdns.Publisher
}

// Reconcile synchronizes active Gateways for the class with the mDNS publisher.
func (r *gatewayReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	var gatewayList gatewayv1.GatewayList
	if err := r.List(ctx, &gatewayList); err != nil {
		return ctrl.Result{}, err
	}

	var matchingGateways []*gatewayv1.Gateway
	for i := range gatewayList.Items {
		gateway := &gatewayList.Items[i]
		if gateway.DeletionTimestamp != nil {
			continue
		}
		if string(gateway.Spec.GatewayClassName) != r.gatewayClassName {
			continue
		}
		matchingGateways = append(matchingGateways, gateway)
	}

	// Beyond the Gateway API specification:
	// When multiple Gateways claim the same hostname, the conflict resolution is deterministic:
	// the oldest Gateway by creation time holds the name, breaking ties by namespace and name.
	sort.Slice(matchingGateways, func(i, j int) bool {
		timeI := matchingGateways[i].CreationTimestamp
		timeJ := matchingGateways[j].CreationTimestamp
		if !timeI.Equal(&timeJ) {
			return timeI.Before(&timeJ)
		}
		if matchingGateways[i].Namespace != matchingGateways[j].Namespace {
			return matchingGateways[i].Namespace < matchingGateways[j].Namespace
		}
		return matchingGateways[i].Name < matchingGateways[j].Name
	})

	claimedHostnames := make(map[string]bool)
	var gatewaysToPublish []*gatewayv1.Gateway

	for _, gateway := range matchingGateways {
		gatewayCopy := gateway.DeepCopy()

		// A Gateway must be Programmed and have addresses to publish listeners.
		if !isGatewayProgrammed(gateway) || !hasIPAddress(gateway) {
			gatewayCopy.Spec.Listeners = nil
			gatewaysToPublish = append(gatewaysToPublish, gatewayCopy)
			continue
		}

		var eligibleListeners []gatewayv1.Listener
		for _, listener := range gatewayCopy.Spec.Listeners {
			if listener.Protocol != gatewayv1.HTTPProtocolType || listener.Hostname == nil {
				continue
			}
			rawHostname := string(*listener.Hostname)
			if err := validation.ValidateSingleLabelLocalHostname(rawHostname); err != nil {
				continue
			}
			if !isListenerAcceptedAndProgrammed(gateway, listener.Name) {
				continue
			}

			canonicalHostname := strings.ToLower(rawHostname)
			if !strings.HasSuffix(canonicalHostname, ".") {
				canonicalHostname += "."
			}
			if claimedHostnames[canonicalHostname] {
				// Already claimed by an older Gateway (or earlier listener).
				continue
			}
			claimedHostnames[canonicalHostname] = true
			eligibleListeners = append(eligibleListeners, listener)
		}

		gatewayCopy.Spec.Listeners = eligibleListeners
		gatewaysToPublish = append(gatewaysToPublish, gatewayCopy)
	}

	r.publisher.OnGatewaysUpdate(gatewaysToPublish)
	return ctrl.Result{}, nil
}

func isGatewayProgrammed(gateway *gatewayv1.Gateway) bool {
	for _, condition := range gateway.Status.Conditions {
		if condition.Type == string(gatewayv1.GatewayConditionProgrammed) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func hasIPAddress(gateway *gatewayv1.Gateway) bool {
	for _, address := range gateway.Status.Addresses {
		if net.ParseIP(address.Value) != nil {
			return true
		}
	}
	return false
}

func isListenerAcceptedAndProgrammed(gateway *gatewayv1.Gateway, listenerName gatewayv1.SectionName) bool {
	for _, listenerStatus := range gateway.Status.Listeners {
		if listenerStatus.Name != listenerName {
			continue
		}
		var accepted, programmed bool
		for _, condition := range listenerStatus.Conditions {
			if condition.Type == string(gatewayv1.ListenerConditionAccepted) && condition.Status == metav1.ConditionTrue {
				accepted = true
			}
			if condition.Type == string(gatewayv1.ListenerConditionProgrammed) && condition.Status == metav1.ConditionTrue {
				programmed = true
			}
		}
		return accepted && programmed
	}
	return false
}

// setupWithManager registers the Gateway reconciler with the controller manager.
func (r *gatewayReconciler) setupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Complete(r)
}

func main() {
	configuration, err := buildOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting localgateway-dns", "gatewayClass", configuration.gatewayClass, "mdnsPort", configuration.mdnsPort)

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
			BindAddress: configuration.metricsAddr,
		},
		LeaderElection: false,
	})
	if err != nil {
		setupLog.Error(err, "failed to create manager")
		os.Exit(1)
	}

	publisher, err := mdns.NewPublisher(mdns.PublisherOptions{
		Interface: configuration.networkInterface,
		Port:      configuration.mdnsPort,
	})
	if err != nil {
		setupLog.Error(err, "failed to create mDNS publisher")
		os.Exit(1)
	}

	if err := mgr.Add(publisher); err != nil {
		setupLog.Error(err, "failed to register mDNS publisher with manager")
		os.Exit(1)
	}

	reconciler := &gatewayReconciler{
		Client:           mgr.GetClient(),
		gatewayClassName: configuration.gatewayClass,
		publisher:        publisher,
	}
	if err := reconciler.setupWithManager(mgr); err != nil {
		setupLog.Error(err, "failed to setup Gateway controller")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "fatal error running manager")
		os.Exit(1)
	}
}
