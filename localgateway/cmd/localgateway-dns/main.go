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
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
)

type config struct {
	secretName       string
	secretNamespace  string
	networkInterface string
	mdnsPort         int
	metricsAddr      string
}

func buildOptions(args []string) (config, error) {
	flagSet := flag.NewFlagSet("localgateway-dns", flag.ContinueOnError)
	configuration := config{
		secretName:      dnsconfig.DefaultSecretName,
		secretNamespace: dnsconfig.DefaultSecretNamespace,
		mdnsPort:        mdns.DefaultPort,
		metricsAddr:     "0",
	}

	flagSet.StringVar(&configuration.secretName, "config-secret", configuration.secretName, "Name of the config Secret holding DNS records.")
	flagSet.StringVar(&configuration.secretNamespace, "config-namespace", configuration.secretNamespace, "Namespace of the config Secret.")
	flagSet.StringVar(&configuration.networkInterface, "interface", configuration.networkInterface, "Network interface to publish mDNS on (defaults to all).")
	flagSet.IntVar(&configuration.mdnsPort, "mdns-port", configuration.mdnsPort, "UDP port for mDNS publishing.")
	flagSet.StringVar(&configuration.metricsAddr, "metrics-bind-address", configuration.metricsAddr, "The address the metric endpoint binds to (0 to disable).")

	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flagSet)

	if err := flagSet.Parse(args); err != nil {
		return config{}, err
	}

	if strings.TrimSpace(configuration.secretName) == "" {
		return config{}, fmt.Errorf("--config-secret is required and cannot be empty")
	}
	if strings.TrimSpace(configuration.secretNamespace) == "" {
		return config{}, fmt.Errorf("--config-namespace is required and cannot be empty")
	}

	ctrl.SetLogger(textlogger.NewLogger(logConfig))
	return configuration, nil
}

type configReconciler struct {
	client.Client
	secretNamespace string
	secretName      string
	responder       *mdns.Responder

	mu            sync.Mutex
	activeRecords map[string][]dnsmessage.Resource
}

func newConfigReconciler(cl client.Client, namespace, name string, responder *mdns.Responder) *configReconciler {
	return &configReconciler{
		Client:          cl,
		secretNamespace: namespace,
		secretName:      name,
		responder:       responder,
		activeRecords:   make(map[string][]dnsmessage.Resource),
	}
}

func (r *configReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != r.secretNamespace || req.Name != r.secretName {
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			r.withdrawAll()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	data, ok := secret.Data[dnsconfig.DefaultSecretDataKey]
	if !ok || len(data) == 0 {
		r.withdrawAll()
		return ctrl.Result{}, nil
	}

	cfg, err := dnsconfig.Unmarshal(data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unmarshaling dns config: %w", err)
	}

	r.applyRecords(cfg.Records)
	return ctrl.Result{}, nil
}

func (r *configReconciler) applyRecords(records []dnsconfig.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNames := make(map[string]struct{})
	for _, rec := range records {
		fqdn := toFQDN(rec.Name)
		currentNames[fqdn] = struct{}{}

		resources, recordSet, err := buildResources(fqdn, rec.Addresses, mdns.DefaultTTL)
		if err != nil || len(resources) == 0 {
			continue
		}

		r.responder.SetRecord(recordSet)
		if err := r.responder.SendAnnouncement(resources); err != nil {
			ctrl.Log.WithName("dns-dataplane").Error(err, "failed to send announcement", "fqdn", fqdn)
		}
		r.activeRecords[fqdn] = resources
	}

	for fqdn, resources := range r.activeRecords {
		if _, stillPresent := currentNames[fqdn]; !stillPresent {
			if err := r.responder.SendGoodbye(resources); err != nil {
				ctrl.Log.WithName("dns-dataplane").Error(err, "failed to send goodbye", "fqdn", fqdn)
			}
			r.responder.RemoveRecord(fqdn)
			delete(r.activeRecords, fqdn)
		}
	}
}

func (r *configReconciler) withdrawAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for fqdn, resources := range r.activeRecords {
		if err := r.responder.SendGoodbye(resources); err != nil {
			ctrl.Log.WithName("dns-dataplane").Error(err, "failed to send goodbye", "fqdn", fqdn)
		}
		r.responder.RemoveRecord(fqdn)
		delete(r.activeRecords, fqdn)
	}
}

// Start implements manager.Runnable to withdraw records and close the responder on shutdown.
func (r *configReconciler) Start(ctx context.Context) error {
	<-ctx.Done()
	r.withdrawAll()
	return r.responder.Close()
}

func toFQDN(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func buildResources(fqdn string, addresses []string, ttl uint32) ([]dnsmessage.Resource, *mdns.RecordSet, error) {
	parsedName, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, nil, err
	}

	var aIPs []net.IP
	var aaaaIPs []net.IP
	var resources []dnsmessage.Resource

	for _, addrStr := range addresses {
		ip := net.ParseIP(addrStr)
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			aIPs = append(aIPs, ip4)
			var a [4]byte
			copy(a[:], ip4)
			resources = append(resources, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  parsedName,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET | mdns.CacheFlushBit,
					TTL:   ttl,
				},
				Body: &dnsmessage.AResource{A: a},
			})
		} else if ip6 := ip.To16(); ip6 != nil {
			aaaaIPs = append(aaaaIPs, ip6)
			var aaaa [16]byte
			copy(aaaa[:], ip6)
			resources = append(resources, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  parsedName,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET | mdns.CacheFlushBit,
					TTL:   ttl,
				},
				Body: &dnsmessage.AAAAResource{AAAA: aaaa},
			})
		}
	}

	rs := &mdns.RecordSet{
		FQDN: fqdn,
		A:    aIPs,
		AAAA: aaaaIPs,
		TTL:  ttl,
	}
	return resources, rs, nil
}

func (r *configReconciler) setupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

func main() {
	configuration, err := buildOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse options: %v\n", err)
		os.Exit(1)
	}

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting localgateway-dns data plane", "secret", configuration.secretName, "namespace", configuration.secretNamespace, "mdnsPort", configuration.mdnsPort)

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "failed to add corev1 to scheme")
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

	responder, err := mdns.NewResponder(mdns.ResponderOptions{
		InterfaceName: configuration.networkInterface,
		Port:          configuration.mdnsPort,
	})
	if err != nil {
		setupLog.Error(err, "failed to create mDNS responder")
		os.Exit(1)
	}

	reconciler := newConfigReconciler(mgr.GetClient(), configuration.secretNamespace, configuration.secretName, responder)
	if err := mgr.Add(reconciler); err != nil {
		setupLog.Error(err, "failed to register reconciler runnable with manager")
		os.Exit(1)
	}
	if err := reconciler.setupWithManager(mgr); err != nil {
		setupLog.Error(err, "failed to setup secret reconciler")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "fatal error running manager")
		os.Exit(1)
	}
}
