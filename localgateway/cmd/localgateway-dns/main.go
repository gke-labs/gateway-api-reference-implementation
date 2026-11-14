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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

// Reconciler watches the DNS config Secret and publishes records with mDNS.
type Reconciler struct {
	// Client is the Kubernetes client used to fetch the DNS configuration Secret.
	client.Client

	// Namespace is the namespace containing the DNS configuration Secret.
	Namespace string

	// SecretName is the name of the DNS configuration Secret.
	SecretName string

	// Prober manages mDNS probing, announcing, conflict handling, and withdrawing resource records.
	Prober *mdns.Prober

	// Responder is the mDNS responder that handles UDP packet transport.
	Responder *mdns.Responder
}

// NewReconciler constructs a new DNS data-plane Reconciler.
func NewReconciler(kubernetesClient client.Client, namespace, secretName string, prober *mdns.Prober, responder *mdns.Responder) *Reconciler {
	return &Reconciler{
		Client:     kubernetesClient,
		Namespace:  namespace,
		SecretName: secretName,
		Prober:     prober,
		Responder:  responder,
	}
}

// Reconcile processes updates to the DNS configuration Secret.
func (r *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	if request.Namespace != r.Namespace || request.Name != r.SecretName {
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	if err := r.Get(ctx, request.NamespacedName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			r.Prober.SetNames(nil)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	data := secret.Data[singlepod.DataplaneSecretDataKey]
	if len(data) == 0 {
		r.Prober.SetNames(nil)
		return ctrl.Result{}, nil
	}

	// If unmarshaling fails, keep the last good records in memory and return
	// the error so the controller-runtime manager retries reconciliation with backoff.
	var config dnsconfig.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("unmarshaling dns config: %w", err)
	}

	r.applyConfig(ctx, &config)
	return ctrl.Result{}, nil
}

func (r *Reconciler) applyConfig(ctx context.Context, config *dnsconfig.Config) {
	logger := log.FromContext(ctx)

	desired := make(map[string][]net.IP, len(config.Records))
	for _, record := range config.Records {
		if err := validation.ValidateSingleLabelLocalHostname(record.Name); err != nil {
			logger.Error(err, "invalid hostname in DNS config record", "name", record.Name)
			continue
		}

		var ipAddresses []net.IP
		for _, address := range record.Addresses {
			ip := net.ParseIP(address)
			if ip == nil {
				logger.Error(fmt.Errorf("invalid IP address %q", address), "failed to parse address in DNS config record", "name", record.Name, "address", address)
				continue
			}
			ipAddresses = append(ipAddresses, ip)
		}

		if len(ipAddresses) == 0 {
			logger.Error(fmt.Errorf("no valid IP addresses for %q", record.Name), "skipping record without valid addresses", "name", record.Name)
			continue
		}

		fqdn := strings.ToLower(mdns.ToFQDN(record.Name))
		desired[fqdn] = ipAddresses
	}

	r.Prober.SetNames(desired)
}

// Start implements manager.Runnable to withdraw records and close the responder on shutdown.
func (r *Reconciler) Start(ctx context.Context) error {
	<-ctx.Done()
	errShutdown := r.Prober.Shutdown()
	errClose := r.Responder.Close()
	return errors.Join(errShutdown, errClose)
}

// SetupWithManager registers the reconciler and its lifecycle runnable with the manager.
func (r *Reconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.Add(r); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&corev1.Secret{}).
		Complete(r)
}

// Options contains configuration for the localgateway-dns program.
type Options struct {
	// Namespace is the namespace containing the DNS configuration Secret.
	Namespace string

	// SecretName is the name of the DNS configuration Secret.
	SecretName string

	// Interface is the network interface on which to publish mDNS records.
	Interface string

	// MDNSPort is the UDP port used for multicast DNS.
	MDNSPort int
}

// ParseOptions parses command-line arguments into Options.
func ParseOptions(args []string) (Options, error) {
	options := Options{
		Namespace:  dnsconfig.DefaultConfigSecretNamespace,
		SecretName: dnsconfig.DefaultConfigSecretName,
		MDNSPort:   mdns.DefaultPort,
	}

	flagSet := flag.NewFlagSet("localgateway-dns", flag.ContinueOnError)
	flagSet.StringVar(&options.Namespace, "secret-namespace", options.Namespace, "Namespace of the DNS config Secret.")
	flagSet.StringVar(&options.SecretName, "secret-name", options.SecretName, "Name of the DNS config Secret.")
	flagSet.StringVar(&options.Interface, "interface", options.Interface, "Network interface to publish mDNS records on.")
	flagSet.IntVar(&options.MDNSPort, "mdns-port", options.MDNSPort, "UDP port for mDNS publishing.")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flagSet)

	if err := flagSet.Parse(args); err != nil {
		return Options{}, err
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))
	return options, nil
}

// logOnStateChange logs mDNS state transitions, logging LAN conflicts at error level.
// When another host on the LAN conflicts with a name, mdns.Prober marks the name
// as StateConflict and withdraws it. Because this standalone DNS program is decoupled
// from Gateway API types and only consumes the compiled Secret, it does not write
// back to Gateway status directly; a log message at error level informs operators
// of the LAN conflict.
func logOnStateChange(fqdn string, state mdns.HostnameState) {
	if state == mdns.StateConflict {
		klog.Errorf("mDNS conflict detected on LAN for hostname %s", fqdn)
	}
}

func main() {
	options, err := ParseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	responder, err := mdns.NewResponder(mdns.ResponderOptions{
		InterfaceName: options.Interface,
		Port:          options.MDNSPort,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create mDNS responder: %v\n", err)
		os.Exit(1)
	}

	prober, err := mdns.NewProber(mdns.ProberOptions{
		Responder:     responder,
		OnStateChange: logOnStateChange,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create mDNS prober: %v\n", err)
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add corev1 to scheme: %v\n", err)
		os.Exit(1)
	}

	cacheConfig := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Namespaces: map[string]cache.Config{
					options.Namespace: {
						FieldSelector: fields.OneTermEqualSelector("metadata.name", options.SecretName),
					},
				},
			},
		},
	}

	// Disable metrics server by setting bind address to "0".
	// This program runs with host networking, so it opens no listening TCP port.
	metricsOptions := metricsserver.Options{
		BindAddress: "0",
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  scheme,
		Cache:   cacheConfig,
		Metrics: metricsOptions,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create manager: %v\n", err)
		os.Exit(1)
	}

	reconciler := NewReconciler(manager.GetClient(), options.Namespace, options.SecretName, prober, responder)
	if err := reconciler.SetupWithManager(manager); err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup reconciler: %v\n", err)
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := manager.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "manager exited: %v\n", err)
		os.Exit(1)
	}
}
