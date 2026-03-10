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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	var proxyHTTPSAddr string
	var enableH2C bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&proxyAddr, "proxy-bind-address", ":8000", "The address the proxy binds to.")
	flag.StringVar(&proxyHTTPSAddr, "proxy-https-bind-address", ":8443", "The address the proxy binds to for HTTPS.")
	flag.BoolVar(&enableH2C, "enable-h2c", false, "Enable H2C support on the proxy server.")
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
		var handler http.Handler = p
		if enableH2C {
			// h2c.NewHandler enables HTTP/2 Cleartext (H2C) support.
			// This is required to pass the HTTPRouteBackendProtocolH2C conformance test
			// when the test client uses HTTP/2 Prior Knowledge.
			h2s := &http2.Server{}
			handler = h2c.NewHandler(p, h2s)
		}
		srv := &http.Server{
			Addr:    proxyAddr,
			Handler: handler,
		}
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

	g.Go(func() error {
		setupLog.Info("starting proxy HTTPS server", "addr", proxyHTTPSAddr)

		// Generate a self-signed cert for the reference implementation
		cert, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed cert: %w", err)
		}

		p.SetDefaultCertificates([]tls.Certificate{cert})

		srv := &http.Server{
			Addr:    proxyHTTPSAddr,
			Handler: p,
			TLSConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				GetConfigForClient: p.GetConfigForClient,
			},
		}

		go func() {
			<-ctx.Done()
			setupLog.Info("shutting down proxy HTTPS server")
			_ = srv.Shutdown(context.Background())
		}()
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("proxy HTTPS server failed: %w", err)
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

	if err = (&controller.ServiceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		State:  st,
		Proxy:  p,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating Service controller: %w", err)
	}

	if err = (&controller.BackendTLSPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		State:  st,
		Proxy:  p,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating BackendTLSPolicy controller: %w", err)
	}

	if err = (&controller.ConfigMapReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		State:  st,
		Proxy:  p,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ConfigMap controller: %w", err)
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

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gateway API Reference Implementation"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "https-listener.org", "abc.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
