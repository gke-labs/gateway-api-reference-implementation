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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSetupDataplane_ProvisionerArgs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1 AddToScheme failed: %v", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-params",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			state.ParameterKeyServiceType:   "LoadBalancer",
			state.ParameterKeyACMEChallenge: "enabled",
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
			UID:       types.UID("test-gw-uid"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gari",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: "",
					Kind:  "ConfigMap",
					Name:  "gw-params",
				},
			},
		},
	}

	effectiveListeners := []*state.EffectiveListener{
		{
			Name:     gatewayv1.SectionName("https"),
			Port:     gatewayv1.PortNumber(8443),
			Protocol: gatewayv1.HTTPSProtocolType,
		},
	}

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "gari"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	})
	st.UpsertGateway(gw)
	st.UpsertConfigMap(cm)
	st.Recompute()

	bundleCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      spiffe.BundleConfigMapName,
		},
		Data: map[string]string{
			spiffe.BundleDataKey: "test-bundle-pem",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, cm, bundleCM).Build()
	p := singlepod.NewAddressProvider(
		c,
		"default",
		singlepod.WithState(st),
		singlepod.WithEnableH2C(true),
		singlepod.WithForwardedForMode("append"),
		singlepod.WithDebugErrorResponses(true),
		singlepod.WithACMEChallengeUpstreamURL("https://certserver.example.internal:8443"),
		singlepod.WithACMEChallengeCABundlePath("/etc/ssl/certs/certserver-ca.crt"),
		singlepod.WithACMEChallengeTokenPath("/var/run/secrets/tokens/certserver/token"),
	)

	_, _, err := p.GatewayAddresses(t.Context(), gw, effectiveListeners)
	if err != nil {
		t.Fatalf("GatewayAddresses failed: %v", err)
	}

	var deploy appsv1.Deployment
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: state.ResourceNameForGateway("test-gw")}, &deploy); err != nil {
		t.Fatalf("failed to get created Deployment: %v", err)
	}

	if len(deploy.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("expected at least 1 container in Deployment template, got 0")
	}
	args := deploy.Spec.Template.Spec.Containers[0].Args

	opts, err := Setup(args)
	if err != nil {
		t.Fatalf("Setup failed on provisioner-generated args %v: %v", args, err)
	}

	if !opts.DataplaneMode {
		t.Errorf("expected DataplaneMode=true")
	}
	if opts.DataplaneGatewayNamespace != "test-ns" {
		t.Errorf("expected DataplaneGatewayNamespace='test-ns', got %q", opts.DataplaneGatewayNamespace)
	}
	if opts.DataplaneGatewayName != "test-gw" {
		t.Errorf("expected DataplaneGatewayName='test-gw', got %q", opts.DataplaneGatewayName)
	}
	if opts.ProxyHTTP3AdvertisedPort != 8443 {
		t.Errorf("expected ProxyHTTP3AdvertisedPort=8443, got %d", opts.ProxyHTTP3AdvertisedPort)
	}
	if !opts.EnableH2C {
		t.Errorf("expected EnableH2C=true")
	}
	if string(opts.ForwardedForMode) != "append" {
		t.Errorf("expected ForwardedForMode='append', got %q", opts.ForwardedForMode)
	}
	if !opts.DebugErrorResponses {
		t.Errorf("expected DebugErrorResponses=true")
	}
	if opts.ACMEChallengeUpstreamURL != "https://certserver.example.internal:8443" {
		t.Errorf("expected ACMEChallengeUpstreamURL='https://certserver.example.internal:8443', got %q", opts.ACMEChallengeUpstreamURL)
	}
	if opts.ACMEChallengeCABundlePath != "/etc/ssl/certs/certserver-ca.crt" {
		t.Errorf("expected ACMEChallengeCABundlePath='/etc/ssl/certs/certserver-ca.crt', got %q", opts.ACMEChallengeCABundlePath)
	}
	if opts.ACMEChallengeTokenPath != "/var/run/secrets/tokens/certserver/token" {
		t.Errorf("expected ACMEChallengeTokenPath='/var/run/secrets/tokens/certserver/token', got %q", opts.ACMEChallengeTokenPath)
	}
	expectedAddr := fmt.Sprintf("%s.default.svc.cluster.local:%d", spiffe.ControllerServiceName, push.InternalAPIPort)
	if opts.InternalAPIAddress != expectedAddr {
		t.Errorf("expected InternalAPIAddress=%q, got %q", expectedAddr, opts.InternalAPIAddress)
	}
	expectedCAFile := "/etc/gari/bundle/" + spiffe.BundleDataKey
	if opts.InternalAPICAFile != expectedCAFile {
		t.Errorf("expected InternalAPICAFile=%q, got %q", expectedCAFile, opts.InternalAPICAFile)
	}
	expectedTokenFile := "/var/run/secrets/tokens/internal-api/token"
	if opts.InternalAPITokenFile != expectedTokenFile {
		t.Errorf("expected InternalAPITokenFile=%q, got %q", expectedTokenFile, opts.InternalAPITokenFile)
	}
}

func TestSetupController_RequiresPodNamespace(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	_, err := Setup(nil)
	if err == nil {
		t.Fatalf("expected error when POD_NAMESPACE is empty, got nil")
	}
	if !strings.Contains(err.Error(), "POD_NAMESPACE environment variable is required") {
		t.Errorf("expected error mentioning POD_NAMESPACE, got %v", err)
	}
}

func TestSetupController_RequiresInternalAPIFlags(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing all",
			args: []string{},
		},
		{
			name: "missing tls files",
			args: []string{"--internal-api-bind-address=:8443"},
		},
		{
			name: "missing key file",
			args: []string{"--internal-api-bind-address=:8443", "--internal-api-tls-cert-file=/etc/cert.pem"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Setup(tc.args)
			if err == nil {
				t.Fatalf("expected error when internal API flags are missing, got nil")
			}
			for _, flag := range []string{"--internal-api-bind-address", "--internal-api-tls-cert-file", "--internal-api-tls-key-file"} {
				if !strings.Contains(err.Error(), flag) {
					t.Errorf("expected error to name %s, got %v", flag, err)
				}
			}
		})
	}
}

func TestFlagsGolden(t *testing.T) {
	t.Setenv("GARI_IMAGE", "")
	t.Setenv("CERTSERVER_ADDRESS", "")
	t.Setenv("CERTSERVER_CA_BUNDLE_PATH", "")
	t.Setenv("CERTSERVER_TOKEN_PATH", "")

	type flagInfo struct {
		Name     string
		DefValue string
		Usage    string
	}
	golden := []flagInfo{
		{Name: "acme-challenge-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify the upstream certificate server."},
		{Name: "acme-challenge-token-path", DefValue: "", Usage: "Path to the projected service-account token file for data-plane identity."},
		{Name: "acme-challenge-upstream-url", DefValue: "", Usage: "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to."},
		{Name: "allowed-source-cidrs", DefValue: "", Usage: "Comma-separated list of CIDRs permitted to connect to HTTP/HTTPS listeners."},
		{Name: "body-read-timeout", DefValue: "5m0s", Usage: "The maximum duration allowed between read progress while reading a request body; the proxy responds 408 Request Timeout and closes the connection (0 disables)."},
		{Name: "certserver-address", DefValue: "", Usage: "Address of the certserver gRPC service"},
		{Name: "certserver-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify certserver TLS"},
		{Name: "certserver-token-path", DefValue: "", Usage: "Path to the projected service-account token file for controller identity"},
		{Name: "controller-name", DefValue: "github.com/gke-labs/gateway-api-reference-implementation", Usage: "The GatewayClass controller name."},
		{Name: "dataplane-image", DefValue: "gari-controller:latest", Usage: "The container image to use for provisioned per-Gateway data-plane Deployments."},
		{Name: "dataplane-mode", DefValue: "false", Usage: "Run in data-plane mode serving a single Gateway."},
		{Name: "debug-error-responses", DefValue: "false", Usage: "Include detailed error messages in unmatched responses."},
		{Name: "drain-sentinel-path", DefValue: "", Usage: "Path to the sentinel file that marks the pod as draining."},
		{Name: "enable-h2c", DefValue: "false", Usage: "Enable H2C support on the proxy server."},
		{Name: "forwarded-for-mode", DefValue: "append", Usage: "How to handle X-Forwarded-For: append (default) or replace."},
		{Name: "gateway-name", DefValue: "", Usage: "The name of the Gateway to serve in data-plane mode."},
		{Name: "gateway-namespace", DefValue: "", Usage: "The namespace of the Gateway to serve in data-plane mode."},
		{Name: "health-probe-bind-address", DefValue: ":8999", Usage: "The address the probe endpoint binds to."},
		{Name: "idle-timeout", DefValue: "1m0s", Usage: "The maximum amount of time to wait for the next request when keep-alives are enabled."},
		{Name: "internal-api-address", DefValue: "", Usage: "Host and port of the controller's Service."},
		{Name: "internal-api-bind-address", DefValue: "", Usage: "The address the internal API server binds to (disabled by default)."},
		{Name: "internal-api-ca-file", DefValue: "", Usage: "The trust bundle that verifies the controller's certificate."},
		{Name: "internal-api-tls-cert-file", DefValue: "", Usage: "Path to TLS server certificate file for internal API endpoint. The listener stays off until a certificate that data planes can verify is provided, and how it is provided is not settled."},
		{Name: "internal-api-tls-key-file", DefValue: "", Usage: "Path to TLS server private key file for internal API endpoint."},
		{Name: "internal-api-token-file", DefValue: "", Usage: "A projected ServiceAccount token with the audience the server expects."},
		{Name: "leader-elect", DefValue: "false", Usage: "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager."},
		{Name: "metrics-bind-address", DefValue: ":8999", Usage: "The address the metric endpoint binds to."},
		{Name: "proxy-bind-address", DefValue: ":8080", Usage: "The address the proxy binds to for HTTP."},
		{Name: "proxy-http3-advertised-port", DefValue: "0", Usage: "The port advertised in the Alt-Svc header for HTTP/3 (if 0, inferred from bind address)."},
		{Name: "proxy-http3-bind-address", DefValue: "", Usage: "The UDP address the proxy binds to for HTTP/3 (disabled by default)."},
		{Name: "proxy-https-bind-address", DefValue: ":8443", Usage: "The address the proxy binds to for HTTPS."},
		{Name: "proxy-protocol", DefValue: "", Usage: "Enable PROXY protocol ('enabled')."},
		{Name: "proxy-protocol-trusted-cidrs", DefValue: "", Usage: "Comma-separated list of trusted CIDRs for PROXY protocol."},
		{Name: "read-header-timeout", DefValue: "10s", Usage: "The amount of time allowed to read request headers on HTTP and HTTPS servers."},
		{Name: "read-timeout", DefValue: "0s", Usage: "The maximum duration for reading the entire request, including the body (disabled by default)."},
		{Name: "tcp-idle-timeout", DefValue: "0s", Usage: "The idle timeout for TCP connections on spliced listeners (disabled by default)."},
		{Name: "tcp-max-connections", DefValue: "10000", Usage: "The maximum number of concurrent TCP connections per listener."},
		{Name: "udp-idle-timeout", DefValue: "1m0s", Usage: "The idle timeout for UDP sessions."},
		{Name: "udp-max-sessions", DefValue: "10000", Usage: "The maximum number of concurrent UDP sessions per listener."},
		{Name: "write-timeout", DefValue: "0s", Usage: "The maximum duration before timing out writes of the response (disabled by default)."},
	}

	opts := gari.DefaultOptions()
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	BindFlags(fs, &opts, &cfg)

	var got []flagInfo
	fs.VisitAll(func(f *flag.Flag) {
		got = append(got, flagInfo{Name: f.Name, DefValue: f.DefValue, Usage: f.Usage})
	})

	if len(got) != len(golden) {
		t.Fatalf("got %d flags, want %d", len(got), len(golden))
	}
	for i := range golden {
		if got[i] != golden[i] {
			t.Errorf("flag %d mismatch:\ngot:  %+v\nwant: %+v", i, got[i], golden[i])
		}
	}
}

func TestSetupController_CertserverRegistered(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("CERTSERVER_ADDRESS", "")
	t.Setenv("CERTSERVER_CA_BUNDLE_PATH", "")
	t.Setenv("CERTSERVER_TOKEN_PATH", "")

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok"), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	opts, err := Setup([]string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
		"--certserver-address=127.0.0.1:8443",
		"--certserver-token-path=" + tokenFile,
	})
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if opts.CertificateSources == nil {
		t.Fatalf("expected CertificateSources to be initialized")
	}
	if opts.CertificateSources["certserver"] == nil {
		t.Errorf("expected 'certserver' source to be registered")
	}
}

func TestSetupController_CertserverUnregistered(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("CERTSERVER_ADDRESS", "")
	t.Setenv("CERTSERVER_CA_BUNDLE_PATH", "")
	t.Setenv("CERTSERVER_TOKEN_PATH", "")

	opts, err := Setup([]string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	})
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if opts.CertificateSources != nil && opts.CertificateSources["certserver"] != nil {
		t.Errorf("expected certserver source NOT to be registered when flags are omitted")
	}
}

func TestSetupController_CertserverValidationErrors(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("CERTSERVER_ADDRESS", "")
	t.Setenv("CERTSERVER_CA_BUNDLE_PATH", "")
	t.Setenv("CERTSERVER_TOKEN_PATH", "")

	// 1. Missing token
	_, err := Setup([]string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
		"--certserver-address=127.0.0.1:8443",
	})
	if err == nil {
		t.Fatalf("expected error when token is missing")
	}
	if !strings.Contains(err.Error(), "--certserver-token-path is required") {
		t.Errorf("expected error to mention --certserver-token-path, got %v", err)
	}

	// 2. Missing address
	_, err = Setup([]string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
		"--certserver-token-path=/path/to/token",
	})
	if err == nil {
		t.Fatalf("expected error when address is missing")
	}
	if !strings.Contains(err.Error(), "--certserver-address is required") {
		t.Errorf("expected error to mention --certserver-address, got %v", err)
	}
}

func TestSetup_ModeSelection(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	ctrlArgs := []string{
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	}
	// 1. Controller mode by default
	optsCtrl, err := Setup(ctrlArgs)
	if err != nil {
		t.Fatalf("Setup failed for controller mode: %v", err)
	}
	if optsCtrl.DataplaneMode {
		t.Errorf("expected DataplaneMode=false by default")
	}

	// 2. Explicit --dataplane-mode=false stays in controller mode
	optsCtrlExplicit, err := Setup(append([]string{"--dataplane-mode=false"}, ctrlArgs...))
	if err != nil {
		t.Fatalf("Setup failed for --dataplane-mode=false: %v", err)
	}
	if optsCtrlExplicit.DataplaneMode {
		t.Errorf("expected DataplaneMode=false for --dataplane-mode=false")
	}

	// 3. Dataplane mode selected via --dataplane-mode
	optsDP, err := Setup([]string{"--dataplane-mode", "--gateway-namespace=ns", "--gateway-name=gw"})
	if err != nil {
		t.Fatalf("Setup failed for dataplane mode: %v", err)
	}
	if !optsDP.DataplaneMode {
		t.Errorf("expected DataplaneMode=true")
	}
	if optsDP.DataplaneGatewayNamespace != "ns" || optsDP.DataplaneGatewayName != "gw" {
		t.Errorf("expected gateway ns/gw, got %s/%s", optsDP.DataplaneGatewayNamespace, optsDP.DataplaneGatewayName)
	}
}

type staticTokenReviewer struct {
	expectedToken, namespace, sa string
}

func (r *staticTokenReviewer) ReviewToken(_ context.Context, token string) (string, string, error) {
	if token == r.expectedToken {
		return r.namespace, r.sa, nil
	}
	return "", "", fmt.Errorf("invalid token")
}

func generateTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

func TestController_InternalAPIPush_DataPlaneReceivesConfig(t *testing.T) {
	env := testenv.Start(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		gwNamespace = "default"
		gwName      = "push-gw"
		tokenVal    = "valid-test-token"
	)
	saName := state.ResourceNameForGateway(gwName)

	certPEM, keyPEM := generateTestCertificate(t)
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	caFile := writeFile("ca.crt", certPEM)
	certFile := writeFile("tls.crt", certPEM)
	keyFile := writeFile("tls.key", keyPEM)
	tokenFile := writeFile("token", []byte(tokenVal))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	internalAPIAddr := lis.Addr().String()

	t.Setenv("POD_NAMESPACE", gwNamespace)
	ctrlOpts, err := Setup([]string{
		"--internal-api-bind-address=" + internalAPIAddr,
		"--internal-api-tls-cert-file=" + certFile,
		"--internal-api-tls-key-file=" + keyFile,
	})
	if err != nil {
		t.Fatalf("Setup controller failed: %v", err)
	}
	ctrlOpts.RestConfig, ctrlOpts.Scheme = env.Config, env.Scheme
	ctrlOpts.MetricsAddr, ctrlOpts.HealthProbeBindAddress = "0", "0"
	ctrlOpts.ProxyAddr, ctrlOpts.ProxyHTTPSAddr = "", ""
	ctrlOpts.InternalAPIListener = lis
	ctrlOpts.PushTokenReviewer = &staticTokenReviewer{expectedToken: tokenVal, namespace: gwNamespace, sa: saName}

	ctrlServer, err := gari.New(ctrlOpts)
	if err != nil {
		t.Fatalf("gari.New controller failed: %v", err)
	}
	ctrlErrCh := make(chan error, 1)
	go func() {
		if err := ctrlServer.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			ctrlErrCh <- err
		}
	}()

	if err := env.Client.Create(ctx, &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: controller.DefaultControllerName},
	}); err != nil {
		t.Fatalf("create GatewayClass: %v", err)
	}
	if err := env.Client.Create(ctx, &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: gwNamespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	}); err != nil {
		t.Fatalf("create Gateway: %v", err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate probe listener: %v", err)
	}
	probeAddr := probeLn.Addr().String()
	if err := probeLn.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	dpOpts, err := Setup([]string{
		"--dataplane-mode",
		"--gateway-namespace=" + gwNamespace,
		"--gateway-name=" + gwName,
		"--proxy-bind-address=127.0.0.1:0",
		"--proxy-https-bind-address=127.0.0.1:0",
		"--health-probe-bind-address=" + probeAddr,
		"--internal-api-address=" + internalAPIAddr,
		"--internal-api-ca-file=" + caFile,
		"--internal-api-token-file=" + tokenFile,
	})
	if err != nil {
		t.Fatalf("Setup data plane failed: %v", err)
	}
	dpOpts.MetricsAddr = "0"

	dpServer, err := gari.New(dpOpts)
	if err != nil {
		t.Fatalf("gari.New data plane failed: %v", err)
	}
	dpErrCh := make(chan error, 1)
	go func() {
		if err := dpServer.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			dpErrCh <- err
		}
	}()

	gwKey := types.NamespacedName{Namespace: gwNamespace, Name: gwName}.String()
	deadline := time.Now().Add(10 * time.Second)
	for dpServer.AppliedRevision(gwKey) == "" {
		select {
		case err := <-ctrlErrCh:
			t.Fatalf("controller exited with error: %v", err)
		case err := <-dpErrCh:
			t.Fatalf("data plane exited with error: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("data plane never received config for %s from controller internal API", gwKey)
		}
		time.Sleep(50 * time.Millisecond)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+probeAddr+"/readyz", nil)
	if err != nil {
		t.Fatalf("create readyz request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("readyz request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected readyz 200 OK after receiving config, got %d", resp.StatusCode)
	}
}
