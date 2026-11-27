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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/gcp"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/metadata"
	"github.com/gke-labs/gateway-api-reference-implementation/gcpgateway/pkg/registrar"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	compute "google.golang.org/api/compute/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestPreStopHook(t *testing.T) {
	tmpDir := t.TempDir()
	sentinelPath := filepath.Join(tmpDir, "sub", "draining")

	args := []string{
		"--drain-seconds=0",
		"--sentinel-file=" + sentinelPath,
	}

	if err := RunPreStopHook(args); err != nil {
		t.Fatalf("RunPreStopHook failed: %v", err)
	}

	data, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("failed to read sentinel file: %v", err)
	}
	if string(data) != "draining\n" {
		t.Errorf("expected 'draining\\n', got %q", string(data))
	}
}

func TestRun_HookPreStop(t *testing.T) {
	tmpDir := t.TempDir()
	sentinelPath := filepath.Join(tmpDir, "draining")

	args := []string{
		"hook",
		"pre-stop",
		"--drain-seconds=0",
		"--sentinel-file=" + sentinelPath,
	}

	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if _, err := os.Stat(sentinelPath); err != nil {
		t.Fatalf("sentinel file not created: %v", err)
	}
}

func TestDataplaneMissingFlags(t *testing.T) {
	err := Run(t.Context(), []string{"--dataplane-mode"})
	if err == nil {
		t.Fatalf("expected error when namespace/name missing in dataplane mode, got nil")
	}
}

func TestDataplaneMissingInternalAPIFlags(t *testing.T) {
	err := Run(t.Context(), []string{"--dataplane-mode", "--gateway-namespace=test-ns", "--gateway-name=test-gw"})
	if err == nil {
		t.Fatalf("expected error when internal API flags missing in dataplane mode, got nil")
	}
	if !strings.Contains(err.Error(), "--internal-api-address") {
		t.Errorf("expected error to name --internal-api-address, got: %v", err)
	}
}

func TestSetupDataplane_Flags(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		wantHTTPSAddr      string
		wantHTTP3Addr      string
		wantAdvertisedPort int
		wantErr            bool
	}{
		{
			name: "default HTTP/3 bind address inherits HTTPS bind address",
			args: []string{
				"--dataplane-mode",
				"--gateway-namespace=test-ns",
				"--gateway-name=test-gw",
				"--proxy-https-bind-address=:8443",
				"--proxy-http3-advertised-port=8443",
			},
			wantHTTPSAddr:      ":8443",
			wantHTTP3Addr:      ":8443",
			wantAdvertisedPort: 8443,
		},
		{
			name: "explicit HTTP/3 bind address",
			args: []string{
				"--dataplane-mode",
				"--gateway-namespace=test-ns",
				"--gateway-name=test-gw",
				"--proxy-https-bind-address=:8443",
				"--proxy-http3-bind-address=:9443",
				"--proxy-http3-advertised-port=443",
			},
			wantHTTPSAddr:      ":8443",
			wantHTTP3Addr:      ":9443",
			wantAdvertisedPort: 443,
		},
		{
			name: "missing gateway-namespace or gateway-name",
			args: []string{
				"--dataplane-mode",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := SetupDataplane(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetupDataplane failed: %v", err)
			}
			if opts.ProxyHTTPSAddr != tc.wantHTTPSAddr {
				t.Errorf("ProxyHTTPSAddr = %q, want %q", opts.ProxyHTTPSAddr, tc.wantHTTPSAddr)
			}
			if opts.ProxyHTTP3Addr != tc.wantHTTP3Addr {
				t.Errorf("ProxyHTTP3Addr = %q, want %q", opts.ProxyHTTP3Addr, tc.wantHTTP3Addr)
			}
			if opts.ProxyHTTP3AdvertisedPort != tc.wantAdvertisedPort {
				t.Errorf("ProxyHTTP3AdvertisedPort = %d, want %d", opts.ProxyHTTP3AdvertisedPort, tc.wantAdvertisedPort)
			}
		})
	}
}

func TestSetupDataplane_ProvisionerArgs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1 AddToScheme failed: %v", err)
	}

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	createBundleConfigMap(t, c)
	p := singlepod.NewAddressProvider(c, "default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "test-ns",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
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

	opts, err := SetupDataplane(args)
	if err != nil {
		t.Fatalf("SetupDataplane failed on provisioner-generated args %v: %v", args, err)
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
	if opts.ProxyHTTP3Addr != opts.ProxyHTTPSAddr {
		t.Errorf("expected ProxyHTTP3Addr=%q to default to ProxyHTTPSAddr=%q", opts.ProxyHTTP3Addr, opts.ProxyHTTPSAddr)
	}
}

func TestSetupDataplane_ProvisionerArgs_ACMEChallenge(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1 AddToScheme failed: %v", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gcp-params",
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
			GatewayClassName: "gcpgateway",
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
					Name:  "gcp-params",
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
		ObjectMeta: metav1.ObjectMeta{Name: "gcpgateway"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	})
	st.UpsertGateway(gw)
	st.UpsertConfigMap(cm)
	st.Recompute()

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, cm).Build()
	createBundleConfigMap(t, c)
	p := singlepod.NewAddressProvider(
		c,
		"default",
		singlepod.WithState(st),
		singlepod.WithACMEChallengeUpstreamURL("https://certserver.gcp.internal:8443"),
		singlepod.WithACMEChallengeCABundlePath("/etc/ssl/certs/certserver-ca.crt"),
		singlepod.WithACMEChallengeTokenPath("/var/run/secrets/tokens/certserver/token"),
	)

	// 1. Turned on via acmeChallenge: enabled in ConfigMap
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

	opts, err := SetupDataplane(args)
	if err != nil {
		t.Fatalf("SetupDataplane failed on provisioner-generated args %v: %v", args, err)
	}

	if opts.ACMEChallengeUpstreamURL != "https://certserver.gcp.internal:8443" {
		t.Errorf("expected ACMEChallengeUpstreamURL='https://certserver.gcp.internal:8443', got %q", opts.ACMEChallengeUpstreamURL)
	}
	if opts.ACMEChallengeCABundlePath != "/etc/ssl/certs/certserver-ca.crt" {
		t.Errorf("expected ACMEChallengeCABundlePath='/etc/ssl/certs/certserver-ca.crt', got %q", opts.ACMEChallengeCABundlePath)
	}
	if opts.ACMEChallengeTokenPath != "/var/run/secrets/tokens/certserver/token" {
		t.Errorf("expected ACMEChallengeTokenPath='/var/run/secrets/tokens/certserver/token', got %q", opts.ACMEChallengeTokenPath)
	}

	// 2. Turned off via acmeChallenge: disabled
	cm.Data[state.ParameterKeyACMEChallenge] = "disabled"
	st.UpsertConfigMap(cm)
	st.Recompute()

	_, _, err = p.GatewayAddresses(t.Context(), gw, effectiveListeners)
	if err != nil {
		t.Fatalf("GatewayAddresses failed: %v", err)
	}
	if err := c.Get(t.Context(), types.NamespacedName{Namespace: "test-ns", Name: state.ResourceNameForGateway("test-gw")}, &deploy); err != nil {
		t.Fatalf("failed to get updated Deployment: %v", err)
	}
	offArgs := deploy.Spec.Template.Spec.Containers[0].Args
	offOpts, err := SetupDataplane(offArgs)
	if err != nil {
		t.Fatalf("SetupDataplane failed on turned-off args %v: %v", offArgs, err)
	}
	if offOpts.ACMEChallengeUpstreamURL != "" {
		t.Errorf("expected empty ACMEChallengeUpstreamURL when turned off, got %q", offOpts.ACMEChallengeUpstreamURL)
	}
}

func TestSetupController_RequiresPodNamespace(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	_, err := SetupController(t.Context(), []string{
		"--cluster-id=c1",
		"--fake-compute",
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	}, nil)
	if err == nil {
		t.Fatalf("expected error when POD_NAMESPACE is empty, got nil")
	}
	if !strings.Contains(err.Error(), "POD_NAMESPACE") {
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
			args: []string{"--cluster-id=c1", "--fake-compute"},
		},
		{
			name: "missing tls files",
			args: []string{"--cluster-id=c1", "--fake-compute", "--internal-api-bind-address=:8443"},
		},
		{
			name: "missing key file",
			args: []string{"--cluster-id=c1", "--fake-compute", "--internal-api-bind-address=:8443", "--internal-api-tls-cert-file=/etc/cert.pem"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SetupController(t.Context(), tc.args, nil)
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

func TestSetupController_NoSilentFallback(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	// Without --fake-compute, SetupController initializes the real Compute client.
	// It must never silently substitute a FakeComputeClient.
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=c1",
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	}, nil)
	if err != nil {
		// Error returned instead of silent fallback is valid
		return
	}
	if opts.SetupWithManager == nil {
		t.Errorf("expected SetupWithManager to be set")
	}
}

func TestSetupController_FakeComputeFlag(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=c1",
		"--fake-compute",
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	}, nil)
	if err != nil {
		t.Fatalf("SetupController failed with --fake-compute: %v", err)
	}
	if opts.DrainSentinelPath != DefaultSentinelPath {
		t.Errorf("expected DrainSentinelPath=%q, got %q", DefaultSentinelPath, opts.DrainSentinelPath)
	}
	if opts.SetupWithManager == nil {
		t.Errorf("expected SetupWithManager to be set")
	}
}

func TestSetupController_DebugErrorResponsesFlag(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "default")
	baseArgs := []string{
		"--cluster-id=c1",
		"--fake-compute",
		"--internal-api-bind-address=:8443",
		"--internal-api-tls-cert-file=/etc/cert.pem",
		"--internal-api-tls-key-file=/etc/key.pem",
	}
	opts, err := SetupController(t.Context(), append(baseArgs, "--debug-error-responses"), nil)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}
	if !opts.DebugErrorResponses {
		t.Errorf("expected DebugErrorResponses=true, got %v", opts.DebugErrorResponses)
	}

	optsDefault, err := SetupController(t.Context(), baseArgs, nil)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}
	if optsDefault.DebugErrorResponses {
		t.Errorf("expected default DebugErrorResponses=false, got %v", optsDefault.DebugErrorResponses)
	}
}

func assertProductionDeployment(t *testing.T, deploy *appsv1.Deployment, expectedDrainSeconds int, expectedGracePeriod int64) {
	t.Helper()

	// 1. TerminationGracePeriodSeconds derived from --drain-seconds
	if deploy.Spec.Template.Spec.TerminationGracePeriodSeconds == nil {
		t.Errorf("expected TerminationGracePeriodSeconds to be set, got nil")
	} else if *deploy.Spec.Template.Spec.TerminationGracePeriodSeconds != expectedGracePeriod {
		t.Errorf("expected TerminationGracePeriodSeconds=%d, got %d", expectedGracePeriod, *deploy.Spec.Template.Spec.TerminationGracePeriodSeconds)
	}

	// 2. Pre-stop command
	if len(deploy.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("expected at least 1 container in Deployment template, got 0")
	}
	c := deploy.Spec.Template.Spec.Containers[0]
	if c.Lifecycle == nil || c.Lifecycle.PreStop == nil || c.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("expected Lifecycle.PreStop.Exec to be configured on container")
	}
	expectedPreStop := []string{
		"/gcpgateway",
		"hook",
		"pre-stop",
		fmt.Sprintf("--drain-seconds=%d", expectedDrainSeconds),
	}
	if !slices.Equal(c.Lifecycle.PreStop.Exec.Command, expectedPreStop) {
		t.Errorf("expected pre-stop command %v, got %v", expectedPreStop, c.Lifecycle.PreStop.Exec.Command)
	}

	// 3. Drain volume (memory-backed EmptyDir)
	var foundVol bool
	for _, v := range deploy.Spec.Template.Spec.Volumes {
		if v.Name == "drain-volume" {
			foundVol = true
			if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
				t.Errorf("expected drain-volume to have memory-backed EmptyDir, got %+v", v.EmptyDir)
			}
			break
		}
	}
	if !foundVol {
		t.Errorf("expected 'drain-volume' in Deployment template volumes")
	}

	// 4. Drain volume mount (/var/run/gcpgateway)
	var foundMount bool
	for _, m := range c.VolumeMounts {
		if m.Name == "drain-volume" {
			foundMount = true
			if m.MountPath != "/var/run/gcpgateway" {
				t.Errorf("expected drain-volume mount path '/var/run/gcpgateway', got %q", m.MountPath)
			}
			break
		}
	}
	if !foundMount {
		t.Errorf("expected 'drain-volume' mount in container volumeMounts")
	}

	// 5. Readiness gate
	var foundGate bool
	for _, g := range deploy.Spec.Template.Spec.ReadinessGates {
		if g.ConditionType == corev1.PodConditionType(LoadBalancerReadyGate) {
			foundGate = true
			break
		}
	}
	if !foundGate {
		t.Errorf("expected readiness gate %s in Deployment template, got %+v", LoadBalancerReadyGate, deploy.Spec.Template.Spec.ReadinessGates)
	}

	// 6. Data-plane container args parse cleanly in SetupDataplane
	dpOpts, err := SetupDataplane(c.Args)
	if err != nil {
		t.Errorf("expected container args %v to parse in SetupDataplane, got: %v", c.Args, err)
	} else if !dpOpts.DataplaneMode {
		t.Errorf("expected DataplaneMode=true, got false")
	}

	// 7. Data plane takes config from internal API
	var foundInternalAPIAddr bool
	for _, arg := range c.Args {
		if strings.HasPrefix(arg, "--internal-api-address=") {
			foundInternalAPIAddr = true
		}
		if strings.HasPrefix(arg, "--config-secret=") {
			t.Errorf("expected no --config-secret arg, got: %s", arg)
		}
	}
	if !foundInternalAPIAddr {
		t.Errorf("expected container args to contain --internal-api-address, got: %v", c.Args)
	}
}

func createBundleConfigMap(t *testing.T, c client.Client) {
	t.Helper()
	if err := spiffe.EnsureCredentials(t.Context(), c, "default"); err != nil {
		t.Fatalf("creating bundle ConfigMap: %v", err)
	}
}

func setupTestInternalAPIFiles(t *testing.T, env *testenv.Environment) (string, string) {
	t.Helper()
	var svidSec corev1.Secret
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: spiffe.ControllerSVIDSecretName}, &svidSec); err != nil {
		t.Fatalf("reading controller SVID secret: %v", err)
	}
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "svid.pem")
	keyFile := filepath.Join(tmpDir, "svid_key.pem")
	if err := os.WriteFile(certFile, svidSec.Data[corev1.TLSCertKey], 0600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, svidSec.Data[corev1.TLSPrivateKeyKey], 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return certFile, keyFile
}

// TestSetupController_EndToEndRealSetup verifies that the full controller setup wiring
// (SetupController -> AddressProvider -> Deployment -> Pod template -> SetupWithManager -> Reconciler)
// runs against an envtest control plane, attaches data-plane pods to zonal NEGs,
// sets the readiness gate, and marks the Gateway Programmed.
func TestSetupController_EndToEndRealSetup(t *testing.T) {
	env := testenv.Start(t)

	createBundleConfigMap(t, env.Client)

	// Create GatewayClass
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.10",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				registrar.ZoneLabelStandard: "us-central1-a",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "gce://my-project/us-central1-a/gke-node-1",
		},
	}
	if err := env.Client.Create(t.Context(), node); err != nil {
		t.Fatalf("creating Node: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "my-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "my-gw", "bs-443")
	// Initially, load balancer health check reports UNHEALTHY.
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	// 1. Run SetupController with real arguments
	t.Setenv("POD_NAMESPACE", "default")
	certFile, keyFile := setupTestInternalAPIFiles(t, env)
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=cluster-1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--drain-seconds=35",
		"--fake-compute",
		"--internal-api-bind-address=127.0.0.1:0",
		"--internal-api-tls-cert-file=" + certFile,
		"--internal-api-tls-key-file=" + keyFile,
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	// 2. Start GARI manager in background; GARI supplies the client,
	// executes opts.SetupWithManager, and provisions the Deployment.
	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	mgrErrCh := make(chan error, 1)
	go func() {
		if err := server.Manager().Start(mgrCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager exited with error: %v", err)
			mgrErrCh <- err
		}
	}()
	t.Cleanup(func() {
		cancelMgr()
		select {
		case err := <-mgrErrCh:
			t.Errorf("manager error reported during cleanup: %v", err)
		default:
		}
	})

	resName := state.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err == nil {
			break
		}
	}
	if deploy.Name == "" {
		t.Fatalf("timed out waiting for Deployment %s to be created by GARI", resName)
	}

	// Assert production-derived properties on real Deployment template (drain-seconds=35 -> grace period 60)
	assertProductionDeployment(t, &deploy, 35, 60)

	// Verify no Role or RoleBinding is created for the data plane
	var role rbacv1.Role
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &role); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Role for data plane, got: %v (role=%+v)", err, role)
	}
	var roleBinding rbacv1.RoleBinding
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &roleBinding); !apierrors.IsNotFound(err) {
		t.Errorf("expected no RoleBinding for data plane, got: %v (roleBinding=%+v)", err, roleBinding)
	}
	var sec corev1.Secret
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &sec); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Secret for data plane, got: %v", err)
	}

	// 3. Create real data-plane Pod matching the Deployment template via testenv.BuildPodFromDeployment
	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName("dp-pod-1"),
		testenv.WithNodeName("node-1"),
		testenv.WithPodIP("10.0.1.5"),
		testenv.WithContainersReady(true),
	)
	// Readiness gate starts false
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:   corev1.PodConditionType(LoadBalancerReadyGate),
		Status: corev1.ConditionFalse,
	})

	if err := env.Client.Create(t.Context(), pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}
	pod.Status.PodIP = "10.0.1.5"
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	}
	if err := env.Client.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("updating pod status: %v", err)
	}

	// 4. Assertions:
	// a. Verify endpoint is attached to zonal NEG while UNHEALTHY
	var (
		attachedEps []*compute.NetworkEndpoint
		updatedPod  corev1.Pod
		updatedGW   gatewayv1.Gateway
		foundGate   bool
		foundProg   bool
	)

	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(50 * time.Millisecond) {
		attachedEps, _ = fakeGCP.ListNetworkEndpoints(t.Context(), "my-project", "us-central1-a", negName)
		if len(attachedEps) == 1 {
			break
		}
	}
	if len(attachedEps) != 1 || attachedEps[0].IpAddress != "10.0.1.5" || attachedEps[0].Instance != "gke-node-1" {
		t.Fatalf("expected pod endpoint attached to NEG while UNHEALTHY, got %+v", attachedEps)
	}

	// Verify readiness gate remains False while UNHEALTHY
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: "dp-pod-1"}, &updatedPod); err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	for _, c := range updatedPod.Status.Conditions {
		if c.Type == corev1.PodConditionType(LoadBalancerReadyGate) && c.Status == corev1.ConditionTrue {
			t.Fatalf("readiness gate must NOT be True while fake reports UNHEALTHY: %+v", c)
		}
	}

	// b. Fake load balancer switches to HEALTHY with NO Kubernetes event
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	// Assert readiness gate becomes True within bounded time via health polling (no k8s events triggered)
	for start := time.Now(); time.Since(start) < 60*time.Second; time.Sleep(100 * time.Millisecond) {
		_ = env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: "dp-pod-1"}, &updatedPod)
		_ = env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &updatedGW)

		foundGate = false
		for _, c := range updatedPod.Status.Conditions {
			if c.Type == corev1.PodConditionType(LoadBalancerReadyGate) && c.Status == corev1.ConditionTrue {
				foundGate = true
				break
			}
		}

		foundProg = false
		for _, c := range updatedGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionTrue {
				foundProg = true
				break
			}
		}

		if foundGate && foundProg {
			break
		}
	}

	if !foundGate {
		t.Errorf("expected pod readiness gate %s=True after polling, conditions are: %+v", LoadBalancerReadyGate, updatedPod.Status.Conditions)
	}

	if !foundProg {
		t.Errorf("expected Gateway Programmed=True after polling, conditions are: %+v", updatedGW.Status.Conditions)
	} else {
		var progCond *metav1.Condition
		for _, c := range updatedGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				progCond = &c
				break
			}
		}
		if progCond == nil || progCond.Reason != controller.ReasonProgrammed {
			t.Errorf("expected Programmed condition reason %s, got %+v", controller.ReasonProgrammed, progCond)
		}
		if progCond != nil && progCond.Message != "Ready data-plane pods attached to zonal NEGs and passing health checks behind Google Cloud Load Balancer" {
			t.Errorf("expected gcpgateway Programmed message, got %q", progCond.Message)
		}
	}
}

// TestSetupController_EndToEndRealSetup_NonDefaultDrainSeconds verifies that GARI
// provisions a data-plane Deployment deriving the non-default grace period (45 + 25 = 70)
// and pre-stop command (--drain-seconds=45) from SetupController.
func TestSetupController_EndToEndRealSetup_NonDefaultDrainSeconds(t *testing.T) {
	env := testenv.Start(t)

	createBundleConfigMap(t, env.Client)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw-drain45",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.20",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()

	t.Setenv("POD_NAMESPACE", "default")
	certFile, keyFile := setupTestInternalAPIFiles(t, env)
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=cluster-1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--drain-seconds=45",
		"--fake-compute",
		"--internal-api-bind-address=127.0.0.1:0",
		"--internal-api-tls-cert-file=" + certFile,
		"--internal-api-tls-key-file=" + keyFile,
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	mgrErrCh := make(chan error, 1)
	go func() {
		if err := server.Manager().Start(mgrCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager exited with error: %v", err)
			mgrErrCh <- err
		}
	}()
	t.Cleanup(func() {
		cancelMgr()
		select {
		case err := <-mgrErrCh:
			t.Errorf("manager error reported during cleanup: %v", err)
		default:
		}
	})

	resName := state.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err == nil {
			break
		}
	}
	if deploy.Name == "" {
		t.Fatalf("timed out waiting for Deployment %s to be created by GARI", resName)
	}

	// drain-seconds=45 -> 45 + 25 = 70 (strictly greater than the 60s minimum clamp)
	assertProductionDeployment(t, &deploy, 45, 70)
}

// TestSetupController_SteadyStateZeroWritesAndNoFlapping validates issue #870:
// 1. With one gcpgateway Gateway in steady state, there are zero Gateway status writes.
// 2. The Gateway's Programmed condition shows gcpgateway's reason and message, and stays stable without flapping.
// 3. A change in NEG health is reflected in Gateway status without waiting for GARI's resync interval.
func TestSetupController_SteadyStateZeroWritesAndNoFlapping(t *testing.T) {
	env := testenv.Start(t)

	createBundleConfigMap(t, env.Client)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "steady-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.30",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
		},
		Spec: corev1.NodeSpec{
			ProviderID: "gce://my-project/us-central1-a/gke-node-1",
		},
	}
	if err := env.Client.Create(t.Context(), node); err != nil {
		t.Fatalf("creating Node: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	negDesc, _ := (&metadata.NegMetadata{
		ClusterID:   "cluster-1",
		Namespace:   "default",
		GatewayName: "steady-gw",
		Port:        8443,
	}).Encode()

	negName := metadata.ResourceName("gcpgw", "cluster-1", "default", "steady-gw", "8443")
	fakeGCP.AddNEG("my-project", "us-central1-a", &compute.NetworkEndpointGroup{
		Name:        negName,
		Zone:        "us-central1-a",
		Description: negDesc,
	})

	bsName := metadata.ResourceName("gcpgw", "cluster-1", "default", "steady-gw", "bs-443")
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "UNHEALTHY"},
		},
	})

	t.Setenv("POD_NAMESPACE", "default")
	certFile, keyFile := setupTestInternalAPIFiles(t, env)
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=cluster-1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--health-poll-interval=100ms",
		"--resync-interval=250ms",
		"--fake-compute",
		"--internal-api-bind-address=127.0.0.1:0",
		"--internal-api-tls-cert-file=" + certFile,
		"--internal-api-tls-key-file=" + keyFile,
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	mgrErrCh := make(chan error, 1)
	go func() {
		if err := server.Manager().Start(mgrCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager exited with error: %v", err)
			mgrErrCh <- err
		}
	}()
	t.Cleanup(func() {
		cancelMgr()
		select {
		case err := <-mgrErrCh:
			t.Errorf("manager error reported during cleanup: %v", err)
		default:
		}
	})

	resName := state.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err == nil {
			break
		}
	}
	if deploy.Name == "" {
		t.Fatalf("timed out waiting for Deployment %s to be created by GARI", resName)
	}

	pod := testenv.BuildPodFromDeployment(
		&deploy,
		testenv.WithPodName("dp-pod-steady"),
		testenv.WithNodeName("node-1"),
		testenv.WithPodIP("10.0.1.5"),
		testenv.WithContainersReady(true),
	)
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:   corev1.PodConditionType(LoadBalancerReadyGate),
		Status: corev1.ConditionFalse,
	})
	if err := env.Client.Create(t.Context(), pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}
	pod.Status.PodIP = "10.0.1.5"
	pod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
		{Type: corev1.PodConditionType(LoadBalancerReadyGate), Status: corev1.ConditionFalse},
	}
	if err := env.Client.Status().Update(t.Context(), pod); err != nil {
		t.Fatalf("updating pod status: %v", err)
	}

	// 1. Initial state: UNHEALTHY on load balancer -> Programmed condition shows WaitingForEndpoints
	var updatedGW gatewayv1.Gateway
	for start := time.Now(); time.Since(start) < 30*time.Second; time.Sleep(100 * time.Millisecond) {
		_ = env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &updatedGW)
		for _, c := range updatedGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionFalse && c.Reason == controller.ReasonWaitingForEndpoints {
				goto unhealthVerified
			}
		}
	}
	t.Fatalf("expected initial Programmed=False with Reason WaitingForEndpoints, conditions are: %+v", updatedGW.Status.Conditions)
unhealthVerified:

	// 2. Transition fake GCP load balancer to HEALTHY
	fakeGCP.SetBackendServiceHealth("my-project", bsName, negName, &compute.BackendServiceGroupHealth{
		HealthStatus: []*compute.HealthStatus{
			{Instance: "gke-node-1", IpAddress: "10.0.1.5", Port: 8443, HealthState: "HEALTHY"},
		},
	})

	// Wait for steady state: Programmed=True with gcpgateway's reason and message
	for start := time.Now(); time.Since(start) < 30*time.Second; time.Sleep(100 * time.Millisecond) {
		_ = env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &updatedGW)
		for _, c := range updatedGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionTrue && c.Reason == controller.ReasonProgrammed {
				goto steadyStateReached
			}
		}
	}
	t.Fatalf("expected Programmed=True with Reason Programmed, conditions are: %+v", updatedGW.Status.Conditions)
steadyStateReached:

	// Verify reason and message in steady state
	for _, c := range updatedGW.Status.Conditions {
		if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
			if c.Reason != controller.ReasonProgrammed {
				t.Errorf("expected reason %s, got %s", controller.ReasonProgrammed, c.Reason)
			}
			if c.Message != "Ready data-plane pods attached to zonal NEGs and passing health checks behind Google Cloud Load Balancer" {
				t.Errorf("expected gcpgateway Programmed message, got %q", c.Message)
			}
		}
	}
	if len(updatedGW.Status.Addresses) != 1 || updatedGW.Status.Addresses[0].Value != "34.120.254.30" {
		t.Errorf("expected Gateway address 34.120.254.30, got %+v", updatedGW.Status.Addresses)
	}

	// 3. Acceptance Criterion: In steady state, verify ZERO Gateway status writes and NO flapping over time.
	// With HealthPollInterval=100ms and ResyncInterval=250ms, a 5-second window observes 50 health poll cycles
	// and 20 full resync cycles, verifying that steady-state resync and polling produce zero writes.
	steadyRV := updatedGW.ResourceVersion
	steadyStart := time.Now()
	testDuration := 5 * time.Second
	for time.Since(steadyStart) < testDuration {
		time.Sleep(100 * time.Millisecond)
		var checkGW gatewayv1.Gateway
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &checkGW); err != nil {
			t.Fatalf("failed to get gateway during steady state: %v", err)
		}
		if checkGW.ResourceVersion != steadyRV {
			t.Fatalf("flapping detected: Gateway ResourceVersion changed in steady state from %s to %s", steadyRV, checkGW.ResourceVersion)
		}
		for _, c := range checkGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				if c.Status != metav1.ConditionTrue || c.Reason != controller.ReasonProgrammed {
					t.Fatalf("flapping detected: Programmed condition changed in steady state: %+v", c)
				}
			}
		}
	}

	// 4. Acceptance Criterion: Data-plane changes are promptly reflected in Gateway status without waiting for GARI's resync interval.
	if err := env.Client.Delete(t.Context(), pod); err != nil {
		t.Fatalf("deleting pod: %v", err)
	}

	// Must reflect Programmed=False promptly via EnqueueGateway
	dataPlaneReflected := false
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		_ = env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}, &updatedGW)
		for _, c := range updatedGW.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionFalse && (c.Reason == controller.ReasonWaitingForDataPlane || c.Reason == controller.ReasonWaitingForEndpoints) {
				dataPlaneReflected = true
				break
			}
		}
		if dataPlaneReflected {
			break
		}
	}
	if !dataPlaneReflected {
		t.Fatalf("expected pod deletion to be promptly reflected in Gateway status as Programmed=False, conditions are: %+v", updatedGW.Status.Conditions)
	}
}

func TestMain_SetsLogger(t *testing.T) {
	if os.Getenv("TEST_MAIN_SUBPROCESS") == "1" {
		sentinelPath := filepath.Join(t.TempDir(), "sentinel")
		os.Args = []string{"gcpgateway", "hook", "pre-stop", "--drain-seconds=0", "--sentinel-file=" + sentinelPath}
		main()
		ctrl.Log.WithName("test").Info("controller-runtime log message verified")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMain_SetsLogger$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_MAIN_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\nOutput: %s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "controller-runtime log message verified") {
		t.Errorf("expected output to contain 'controller-runtime log message verified', got:\n%s", output)
	}
	if strings.Contains(output, "[controller-runtime] log.SetLogger(...) was never called") {
		t.Errorf("expected no warning about SetLogger not being called, got:\n%s", output)
	}
}

func TestFlagsGolden(t *testing.T) {
	t.Setenv("CLUSTER_ID", "")
	t.Setenv("NEG_PREFIX", "")
	t.Setenv("PROJECT_ID", "")
	t.Setenv("REGION", "")
	t.Setenv("GARI_IMAGE", "")
	t.Setenv("CERTSERVER_ADDRESS", "")
	t.Setenv("CERTSERVER_CA_BUNDLE_PATH", "")
	t.Setenv("CERTSERVER_TOKEN_PATH", "")

	type flagInfo struct {
		Name     string
		DefValue string
		Usage    string
	}

	t.Run("dataplane", func(t *testing.T) {
		golden := []flagInfo{
			{Name: "acme-challenge-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify the upstream certificate server"},
			{Name: "acme-challenge-token-path", DefValue: "", Usage: "Path to the projected service-account token file for data-plane identity"},
			{Name: "acme-challenge-upstream-url", DefValue: "", Usage: "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to"},
			{Name: "allowed-source-cidrs", DefValue: "", Usage: "Allowed source CIDRs"},
			{Name: "dataplane-mode", DefValue: "true", Usage: "Run in data-plane mode"},
			{Name: "debug-error-responses", DefValue: "false", Usage: "Include detailed error messages in unmatched responses"},
			{Name: "drain-sentinel-path", DefValue: "/var/run/gcpgateway/draining", Usage: "Path to drain sentinel file"},
			{Name: "enable-h2c", DefValue: "false", Usage: "Enable H2C support on the proxy server"},
			{Name: "forwarded-for-mode", DefValue: "append", Usage: "How to handle X-Forwarded-For: append (default) or replace"},
			{Name: "gateway-name", DefValue: "", Usage: "Gateway name"},
			{Name: "gateway-namespace", DefValue: "", Usage: "Gateway namespace"},
			{Name: "health-probe-bind-address", DefValue: ":8999", Usage: "Health probe bind address"},
			{Name: "internal-api-address", DefValue: "", Usage: "Host and port of the controller's Service."},
			{Name: "internal-api-bind-address", DefValue: "", Usage: "The address the internal API server binds to (disabled by default)."},
			{Name: "internal-api-ca-file", DefValue: "", Usage: "The trust bundle that verifies the controller's certificate."},
			{Name: "internal-api-tls-cert-file", DefValue: "", Usage: "Path to TLS server certificate file for internal API endpoint. The listener stays off until a certificate that data planes can verify is provided, and how it is provided is not settled."},
			{Name: "internal-api-tls-key-file", DefValue: "", Usage: "Path to TLS server private key file for internal API endpoint."},
			{Name: "internal-api-token-file", DefValue: "", Usage: "A projected ServiceAccount token with the audience the server expects."},
			{Name: "metrics-bind-address", DefValue: ":8999", Usage: "Metrics bind address"},
			{Name: "proxy-bind-address", DefValue: ":8080", Usage: "HTTP proxy bind address"},
			{Name: "proxy-http3-advertised-port", DefValue: "0", Usage: "The port advertised in the Alt-Svc header for HTTP/3 (if 0, inferred from bind address)"},
			{Name: "proxy-http3-bind-address", DefValue: "", Usage: "The UDP address the proxy binds to for HTTP/3 (defaults to the HTTPS bind address)"},
			{Name: "proxy-https-bind-address", DefValue: ":8443", Usage: "HTTPS proxy bind address"},
			{Name: "proxy-protocol", DefValue: "", Usage: "Enable PROXY protocol"},
			{Name: "proxy-protocol-trusted-cidrs", DefValue: "", Usage: "Trusted PROXY protocol CIDRs"},
		}

		opts := gari.DefaultOptions()
		opts.DataplaneMode = true
		opts.DrainSentinelPath = DefaultSentinelPath

		fs := flag.NewFlagSet("dataplane", flag.ContinueOnError)
		BindDataplaneFlags(fs, &opts)

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
	})

	t.Run("controller", func(t *testing.T) {
		golden := []flagInfo{
			{Name: "acme-challenge-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify the upstream certificate server"},
			{Name: "acme-challenge-token-path", DefValue: "", Usage: "Path to the projected service-account token file for data-plane identity"},
			{Name: "acme-challenge-upstream-url", DefValue: "", Usage: "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to"},
			{Name: "certserver-address", DefValue: "", Usage: "Address of the certserver gRPC service"},
			{Name: "certserver-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify certserver TLS"},
			{Name: "certserver-token-path", DefValue: "", Usage: "Path to the projected service-account token file for controller identity"},
			{Name: "cluster-id", DefValue: "cluster-1", Usage: "Unique Kubernetes cluster identifier"},
			{Name: "controller-name", DefValue: "gke-labs.io/gcpgateway", Usage: "GatewayClass controller name"},
			{Name: "dataplane-image", DefValue: "gari-controller:latest", Usage: "Data-plane container image"},
			{Name: "debug-error-responses", DefValue: "false", Usage: "Include detailed error messages in unmatched responses"},
			{Name: "drain-seconds", DefValue: "35", Usage: "Seconds to drain connections during rolling updates"},
			{Name: "fake-compute", DefValue: "false", Usage: "Use in-memory fake Compute client for testing/offline mode"},
			{Name: "health-poll-interval", DefValue: "5s", Usage: "Interval between load balancer health check polls"},
			{Name: "internal-api-address", DefValue: "", Usage: "Host and port of the controller's Service."},
			{Name: "internal-api-bind-address", DefValue: "", Usage: "The address the internal API server binds to (disabled by default)."},
			{Name: "internal-api-ca-file", DefValue: "", Usage: "The trust bundle that verifies the controller's certificate."},
			{Name: "internal-api-tls-cert-file", DefValue: "", Usage: "Path to TLS server certificate file for internal API endpoint. The listener stays off until a certificate that data planes can verify is provided, and how it is provided is not settled."},
			{Name: "internal-api-tls-key-file", DefValue: "", Usage: "Path to TLS server private key file for internal API endpoint."},
			{Name: "internal-api-token-file", DefValue: "", Usage: "A projected ServiceAccount token with the audience the server expects."},
			{Name: "leader-elect", DefValue: "false", Usage: "Enable leader election"},
			{Name: "neg-prefix", DefValue: "gcpgw", Usage: "Prefix for zonal NEG names"},
			{Name: "project", DefValue: "", Usage: "GCP Project ID"},
			{Name: "region", DefValue: "", Usage: "GCP Region"},
			{Name: "resync-interval", DefValue: "1m0s", Usage: "Interval between full periodic resyncs"},
			{Name: "zones", DefValue: "", Usage: "Comma-separated list of GCP zones"},
		}

		cfg := DefaultControllerConfig()
		opts := gari.DefaultOptions()
		opts.ControllerName = DefaultControllerName
		opts.ProxyAddr = ""
		opts.ProxyHTTPSAddr = ""
		opts.ProxyHTTP3Addr = ""
		opts.DrainSentinelPath = DefaultSentinelPath
		opts.LeaderElection = false
		opts.DebugErrorResponses = false

		fs := flag.NewFlagSet("controller", flag.ContinueOnError)
		BindControllerFlags(fs, &opts, &cfg)

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
	})
}

func TestSetupController_DataplaneConfigFromInternalAPI(t *testing.T) {
	// 1. Verify gcpgateway has no flag to turn this off
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	BindControllerFlags(fs, &gari.Options{}, &ControllerConfig{})
	if fs.Lookup("dataplane-config-from-internal-api") != nil {
		t.Fatalf("expected no dataplane-config-from-internal-api flag")
	}

	// 2. Start-up path test: verify Deployment provisioned for a Gateway has --internal-api-address
	// and creates no Role or RoleBinding for the data plane.
	env := testenv.Start(t)

	createBundleConfigMap(t, env.Client)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gcpgateway",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}
	if err := env.Client.Create(t.Context(), gc); err != nil {
		t.Fatalf("creating GatewayClass: %v", err)
	}

	ipAddrType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-internalapi-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "gcpgateway",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddrType,
					Value: "34.120.254.20",
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(t.Context(), gw); err != nil {
		t.Fatalf("creating Gateway: %v", err)
	}

	fakeGCP := gcp.NewFakeComputeClient()
	t.Setenv("POD_NAMESPACE", "default")
	certFile, keyFile := setupTestInternalAPIFiles(t, env)
	opts, err := SetupController(t.Context(), []string{
		"--cluster-id=c1",
		"--neg-prefix=gcpgw",
		"--project=my-project",
		"--zones=us-central1-a",
		"--drain-seconds=35",
		"--fake-compute",
		"--internal-api-bind-address=127.0.0.1:0",
		"--internal-api-tls-cert-file=" + certFile,
		"--internal-api-tls-key-file=" + keyFile,
	}, fakeGCP)
	if err != nil {
		t.Fatalf("SetupController failed: %v", err)
	}

	trueVal := true
	mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Controller: config.Controller{
			SkipNameValidation: &trueVal,
		},
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	opts.Manager = mgr

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()
	go func() {
		_ = server.Manager().Start(mgrCtx)
	}()

	resName := state.ResourceNameForGateway(gw.Name)
	var deploy appsv1.Deployment
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &deploy); err == nil {
			break
		}
	}
	if deploy.Name == "" {
		t.Fatalf("timed out waiting for Deployment %s to be created by GARI", resName)
	}

	// Assert production-derived properties (readiness gate, pre-stop command, drain volume, grace period, --internal-api-address)
	assertProductionDeployment(t, &deploy, 35, 60)

	// Assert NO Role or RoleBinding created for the data plane
	var role rbacv1.Role
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &role); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Role for data plane, got: %v", err)
	}
	var roleBinding rbacv1.RoleBinding
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &roleBinding); !apierrors.IsNotFound(err) {
		t.Errorf("expected no RoleBinding for data plane, got: %v", err)
	}
	var sec corev1.Secret
	if err := env.Client.Get(t.Context(), types.NamespacedName{Namespace: gw.Namespace, Name: resName}, &sec); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Secret for data plane, got: %v", err)
	}
}
