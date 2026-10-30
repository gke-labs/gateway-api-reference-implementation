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

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/yaml"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/testserver"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
)

type syncBuffer struct {
	// mu guards buf to allow concurrent writes and reads between subprocess output and test assertions.
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type Harness struct {
	t           *testing.T
	clusterName string

	hostKindIP       string
	pebble           *testserver.Server
	certserverCmd    *exec.Cmd
	certserverCancel context.CancelFunc
	grpcAddr         string
	chalPort         int
	chalURL          string
	chalCAFile       string
	auditBuf         *syncBuffer
	ctrlCancel       context.CancelFunc
	ctrlDone         chan error
	ctrlLogBuf       *syncBuffer
	ctrlTokenPath    string
}

func NewHarness(t *testing.T, clusterName string) *Harness {
	return &Harness{
		t:           t,
		clusterName: clusterName,
		auditBuf:    &syncBuffer{},
		ctrlLogBuf:  &syncBuffer{},
		ctrlDone:    make(chan error, 1),
	}
}

func (h *Harness) Setup() {
	h.t.Logf("Setting up harness for cluster %s", h.clusterName)

	gitRoot := h.GetGitRoot()
	buildBin := filepath.Join(gitRoot, ".build/bin")
	if _, err := os.Stat(buildBin); err != nil {
		if !os.IsNotExist(err) {
			h.t.Logf("checking .build/bin: %v", err)
		}
	} else {
		h.t.Setenv("PATH", buildBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	if _, err := exec.LookPath("kind"); err != nil {
		h.t.Fatalf("kind not found: %v", err)
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		h.t.Fatalf("kubectl not found: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		h.t.Fatalf("docker not found: %v", err)
	}

	clusters := h.runCmd("kind", "get", "clusters")
	exists := false
	for _, cluster := range strings.Split(clusters, "\n") {
		if strings.TrimSpace(cluster) == h.clusterName {
			exists = true
			break
		}
	}

	if !exists {
		h.t.Logf("Creating kind cluster %s", h.clusterName)
		h.runCmd("kind", "create", "cluster", "--name", h.clusterName)
		h.t.Cleanup(func() {
			if os.Getenv("SKIP_CLEANUP") == "" {
				h.t.Logf("Deleting kind cluster %s", h.clusterName)
				h.runCmd("kind", "delete", "cluster", "--name", h.clusterName)
			}
		})
	}

	// Export kind cluster kubeconfig to ensure ctrl.GetConfig() connects to kind
	// even when running inside a container with in-cluster ServiceAccount credentials.
	kubeconfigData := h.runCmd("kind", "get", "kubeconfig", "--name", h.clusterName)
	kubeconfigFile := filepath.Join(h.t.TempDir(), "kind-kubeconfig")
	if err := os.WriteFile(kubeconfigFile, []byte(kubeconfigData), 0600); err != nil {
		h.t.Fatalf("failed to write kind kubeconfig: %v", err)
	}
	h.t.Setenv("KUBECONFIG", kubeconfigFile)

	contextName := "kind-" + h.clusterName
	h.runCmd("kubectl", "config", "use-context", contextName)
	h.runCmd("kubectl", "config", "set-context", "--current", "--namespace=default")

	h.InstallMetallb()
	h.InstallGatewayAPI()

	// Build and load required docker images
	h.DockerBuild("gari-controller:e2e", filepath.Join(gitRoot, "images/gari-controller/Dockerfile"), gitRoot)
	h.KindLoad("gari-controller:e2e")
	h.DockerBuild("toolbox:e2e", filepath.Join(gitRoot, "tests/toolbox/Dockerfile"), gitRoot)
	h.KindLoad("toolbox:e2e")

	h.DeployBackend()

	// Determine host IP on the kind docker network
	h.hostKindIP = h.getKindNetworkHostIP()
	h.t.Logf("Host IP on kind network: %s", h.hostKindIP)

	// Setup certserver binary and in-process controller
	h.setupCertServerAndController()

	h.t.Cleanup(func() {
		h.cleanup()
	})
}

func (h *Harness) cleanup() {
	if h.t.Failed() {
		h.dumpLogs()
	}

	if h.ctrlCancel != nil {
		h.ctrlCancel()
		select {
		case <-h.ctrlDone:
		case <-time.After(5 * time.Second):
			h.t.Log("timed out waiting for controller to stop")
		}
	}

	if h.certserverCancel != nil {
		h.certserverCancel()
	}
	if h.certserverCmd != nil && h.certserverCmd.Process != nil {
		if err := h.certserverCmd.Wait(); err != nil {
			h.t.Logf("certserver process exit: %v", err)
		}
	}

	if h.pebble != nil {
		h.pebble.Close()
	}
}

func (h *Harness) dumpLogs() {
	h.t.Log("================ CERT SERVER LOGS & AUDIT LOG ================")
	h.t.Log(h.auditBuf.String())
	h.t.Log("================ CONTROLLER LOGS ================")
	h.t.Log(h.ctrlLogBuf.String())
	h.t.Log("================ DATA PLANE LOGS (default) ================")
	h.t.Log(h.runCmdAllowError("kubectl", "logs", "-n", "default", "-l", "app.kubernetes.io/managed-by=gari-singlepod", "--tail=100"))
	h.t.Log("================ DATA PLANE LOGS (unauthorized-ns) ================")
	h.t.Log(h.runCmdAllowError("kubectl", "logs", "-n", "unauthorized-ns", "-l", "app.kubernetes.io/managed-by=gari-singlepod", "--tail=100"))

	// Verify no key material in logs
	allLogs := h.auditBuf.String() + "\n" + h.ctrlLogBuf.String()
	for _, pattern := range []string{"PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(allLogs, pattern) {
			h.t.Errorf("SECURITY RISK: private key material leaked in logs: %q", pattern)
		}
	}
}

func (h *Harness) getKindNetworkHostIP() string {
	out := h.runCmd("docker", "network", "inspect", "kind", "-f", "{{range .IPAM.Config}}{{if .Gateway}}{{println .Gateway}}{{end}}{{end}}")
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		ip := net.ParseIP(trimmed)
		if ip != nil && ip.To4() != nil {
			return trimmed
		}
	}
	return "172.18.0.1"
}

func (h *Harness) setupCertServerAndController() {
	tempDir := h.t.TempDir()
	gitRoot := h.GetGitRoot()

	// 1. Fetch kind cluster JWKS and issuer
	jwksJSON := h.runCmd("kubectl", "get", "--raw", "/openid/v1/jwks")
	jwksFile := filepath.Join(tempDir, "jwks.json")
	if err := os.WriteFile(jwksFile, []byte(jwksJSON), 0600); err != nil {
		h.t.Fatalf("failed to write jwks file: %v", err)
	}

	oidcConfigJSON := h.runCmd("kubectl", "get", "--raw", "/.well-known/openid-configuration")
	var oidcCfg struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal([]byte(oidcConfigJSON), &oidcCfg); err != nil {
		h.t.Fatalf("failed to parse openid configuration: %v", err)
	}
	issuerURL := oidcCfg.Issuer
	if issuerURL == "" {
		issuerURL = "https://kubernetes.default.svc.cluster.local"
	}

	// 2. Setup controller RBAC and ServiceAccount in kind
	h.KubectlApplyContent(h.controllerRBACManifest())

	// 3. Obtain projected service account token for controller identity
	ctrlToken := strings.TrimSpace(h.runCmd("kubectl", "create", "token", "gari-controller", "--namespace=default", "--audience=certserver", "--duration=1h"))
	ctrlTokenFile := filepath.Join(tempDir, "ctrl-token")
	if err := os.WriteFile(ctrlTokenFile, []byte(ctrlToken), 0600); err != nil {
		h.t.Fatalf("failed to write controller token file: %v", err)
	}
	h.ctrlTokenPath = ctrlTokenFile

	// 4. Setup Pebble test server
	pebble := testserver.StartPebble(h.t, testserver.ServerConfig{
		ChallengePort: 80, // Pebble VA will validate against port 80 (Gateway HTTP listener)
		ResolvedIP:    "127.0.0.1",
	})
	h.pebble = pebble

	pebbleCAFile := filepath.Join(tempDir, "pebble-ca.crt")
	var pebbleCAs []byte
	pebbleCAs = append(pebbleCAs, pebble.ServerCertPEM...)
	pebbleCAs = append(pebbleCAs, pebble.RootCertPEM...)
	if err := os.WriteFile(pebbleCAFile, pebbleCAs, 0644); err != nil {
		h.t.Fatalf("failed to write pebble CA file: %v", err)
	}

	// 5. Build certserver binary
	certserverBin := filepath.Join(tempDir, "certserver")
	buildCmd := exec.Command("go", "build", "-o", certserverBin, "./cmd/certserver")
	buildCmd.Dir = filepath.Join(gitRoot, "certserver")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		h.t.Fatalf("failed to build certserver binary: %v\nOutput: %s", err, string(out))
	}

	// 6. Generate self-signed TLS cert for certserver gRPC and challenge endpoints
	hostIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(h.hostKindIP)}
	chalCertPEM, chalKeyPEM, err := generateSelfSignedCert(hostIPs, []string{"localhost"})
	if err != nil {
		h.t.Fatalf("failed to generate certserver TLS cert: %v", err)
	}
	chalCertFile := filepath.Join(tempDir, "certserver.crt")
	if err := os.WriteFile(chalCertFile, chalCertPEM, 0644); err != nil {
		h.t.Fatalf("failed to write certserver cert file: %v", err)
	}
	chalKeyFile := filepath.Join(tempDir, "certserver.key")
	if err := os.WriteFile(chalKeyFile, chalKeyPEM, 0600); err != nil {
		h.t.Fatalf("failed to write certserver key file: %v", err)
	}
	h.chalCAFile = chalCertFile

	// Copy certserver CA cert onto kind node for hostPath mount
	nodeName := fmt.Sprintf("%s-control-plane", h.clusterName)
	h.runCmd("docker", "cp", chalCertFile, fmt.Sprintf("%s:/etc/certserver-ca.crt", nodeName))

	// 7. Generate cluster config file
	clusterConfig := registry.ServerConfig{
		Clusters: []registry.ClusterConfig{
			{
				ClusterID:                h.clusterName,
				IssuerURL:                issuerURL,
				JWKSFile:                 jwksFile,
				ControllerServiceAccount: "system:serviceaccount:default:gari-controller",
				AllowedHostnames:         []string{"app.test", "*.test"},
			},
		},
	}
	clusterConfigData, err := yaml.Marshal(clusterConfig)
	if err != nil {
		h.t.Fatalf("failed to marshal cluster config: %v", err)
	}
	clusterConfigFile := filepath.Join(tempDir, "cluster-config.yaml")
	if err := os.WriteFile(clusterConfigFile, clusterConfigData, 0644); err != nil {
		h.t.Fatalf("failed to write cluster config file: %v", err)
	}

	// 8. Allocate ports and run certserver binary
	grpcPort := getFreePort(h.t)
	chalPort := getFreePort(h.t)

	h.grpcAddr = fmt.Sprintf("127.0.0.1:%d", grpcPort)
	h.chalPort = chalPort
	h.chalURL = fmt.Sprintf("https://%s:%d", h.hostKindIP, h.chalPort)

	certserverCtx, certserverCancel := context.WithCancel(context.Background())
	h.certserverCancel = certserverCancel

	cacheDir := filepath.Join(tempDir, "cache")
	certserverCmd := exec.CommandContext(certserverCtx, certserverBin,
		"--directory-url", pebble.DirectoryURL,
		"--cache-dir", cacheDir,
		"--cluster-config-file", clusterConfigFile,
		"--grpc-listen-addr", fmt.Sprintf("0.0.0.0:%d", grpcPort),
		"--challenge-listen-addr", fmt.Sprintf("0.0.0.0:%d", chalPort),
		"--metrics-listen-addr", "127.0.0.1:0",
		"--tls-cert-file", chalCertFile,
		"--tls-key-file", chalKeyFile,
	)
	certserverCmd.Env = append(os.Environ(), "SSL_CERT_FILE="+pebbleCAFile)
	certserverCmd.Stdout = h.auditBuf
	certserverCmd.Stderr = h.auditBuf

	if err := certserverCmd.Start(); err != nil {
		h.t.Fatalf("failed to start certserver binary: %v", err)
	}
	h.certserverCmd = certserverCmd

	// Wait for certserver gRPC endpoint to be ready over TLS
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(chalCertPEM)

	probeTLS := &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "localhost",
	}

	waitForTLS(h.t, fmt.Sprintf("127.0.0.1:%d", grpcPort), probeTLS, 10*time.Second)

	// 9. Initialize shipped certserver client as CertificateSource (constructed as in gcpgateway)
	certCli, err := client.New(client.Config{
		ServerAddress: h.grpcAddr,
		CABundlePath:  chalCertFile,
		TokenPath:     ctrlTokenFile,
		MinBackoff:    100 * time.Millisecond,
		MaxBackoff:    1 * time.Second,
		RPCTimeout:    5 * time.Second,
		CheckInterval: 500 * time.Millisecond,
	})
	if err != nil {
		h.t.Fatalf("failed to create certserver client: %v", err)
	}

	// 10. Start GARI controller in-process
	ctrlCtx, ctrlCancel := context.WithCancel(context.Background())
	h.ctrlCancel = ctrlCancel

	ctrlLogWriter := textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(h.ctrlLogBuf)))
	ctrl.SetLogger(ctrlLogWriter)

	opts := gari.DefaultOptions()
	opts.LeaderElection = false
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.ProxyHTTP3Addr = ""
	opts.CertificateSources = map[string]gari.CertificateSource{
		"certserver": certCli,
	}
	opts.AddressProvider = singlepod.NewAddressProvider(
		nil,
		singlepod.WithDataplaneImage("gari-controller:e2e"),
		singlepod.WithACMEChallengeUpstreamURL(h.chalURL),
		singlepod.WithACMEChallengeCABundlePath("/etc/ssl/certs/certserver-ca.crt"),
		singlepod.WithExtraVolumes(
			[]*corev1ac.VolumeApplyConfiguration{
				corev1ac.Volume().WithName("certserver-ca").WithHostPath(
					corev1ac.HostPathVolumeSource().WithPath("/etc/certserver-ca.crt").WithType(corev1.HostPathFile),
				),
			},
			[]*corev1ac.VolumeMountApplyConfiguration{
				corev1ac.VolumeMount().WithName("certserver-ca").WithMountPath("/etc/ssl/certs/certserver-ca.crt").WithReadOnly(true),
			},
		),
	)

	go func() {
		err := gari.Run(ctrlCtx, opts)
		if err != nil {
			h.t.Logf("gari.Run exited with error: %v", err)
		}
		h.ctrlDone <- err
	}()

	select {
	case err := <-h.ctrlDone:
		h.t.Fatalf("gari.Run failed immediately: %v\nLogs:\n%s", err, h.ctrlLogBuf.String())
	case <-time.After(1 * time.Second):
	}

	h.t.Log("certserver binary and in-process GARI controller setup complete")
}

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Logf("error closing free port listener: %v", err)
	}
	return port
}

func waitForTLS(t *testing.T, addr string, tlsConfig *tls.Config, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 300 * time.Millisecond}, "tcp", addr, tlsConfig)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := conn.Close(); err != nil {
			t.Logf("error closing probe connection: %v", err)
		}
		return
	}
	t.Fatalf("timed out waiting for TLS endpoint %s", addr)
}

func generateSelfSignedCert(hostIPs []net.IP, dnsNames []string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "certserver-internal",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           hostIPs,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

func (h *Harness) controllerRBACManifest() string {
	return `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gari-controller
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gari-controller
rules:
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["httproutes", "gateways", "gatewayclasses", "backendtlspolicies", "referencegrants", "listenersets"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["tlsroutes", "grpcroutes", "tcproutes", "udproutes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["services", "serviceaccounts", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["configmaps", "namespaces", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gateways/status", "gatewayclasses/status", "httproutes/status", "backendtlspolicies/status", "listenersets/status", "tlsroutes/status", "grpcroutes/status", "tcproutes/status", "udproutes/status"]
  verbs: ["update", "patch"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gari-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gari-controller
subjects:
- kind: ServiceAccount
  name: gari-controller
  namespace: default
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: reference-class
spec:
  controllerName: github.com/gke-labs/gateway-api-reference-implementation
`
}

func (h *Harness) InstallMetallb() {
	h.t.Log("Installing Metallb")
	h.runCmd("kubectl", "apply", "-f", "https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml")
	h.runCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=available", "deployment/controller", "--timeout=90s")
	h.runCmd("kubectl", "wait", "--namespace", "metallb-system", "--for=condition=ready", "pod", "--selector=app=metallb", "--timeout=90s")

	h.KubectlApplyContentWithRetry(h.MetallbConfigManifest(), 90*time.Second)
}

func (h *Harness) MetallbConfigManifest() string {
	return `
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - 172.18.255.200-172.18.255.239
  - 172.18.255.241-172.18.255.250
---
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: static-address-pool
  namespace: metallb-system
spec:
  addresses:
  - 172.18.255.240-172.18.255.240
  autoAssign: false
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
`
}

func (h *Harness) InstallGatewayAPI() {
	h.t.Log("Installing Gateway API CRDs")
	h.runCmd("kubectl", "apply", "--server-side", "--force-conflicts", "-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/experimental-install.yaml")
}

func (h *Harness) GetGitRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("Failed to get git root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func (h *Harness) DockerBuild(tag, dockerfile, context string) {
	h.t.Logf("Building docker image %s", tag)
	h.runCmd("docker", "buildx", "build", "-t", tag, "-f", dockerfile, context)
}

func (h *Harness) KindLoad(tag string) {
	h.t.Logf("Loading image %s into kind cluster %s", tag, h.clusterName)
	h.runCmd("kind", "load", "docker-image", tag, "--name", h.clusterName)
}

func (h *Harness) KubectlApplyContent(content string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("Failed to apply kubectl content: %v, stderr: %s", err, stderr.String())
	}
}

func (h *Harness) KubectlApplyContentWithRetry(content string, timeout time.Duration) {
	start := time.Now()
	var lastErr error
	var lastStderr string
	for time.Since(start) < timeout {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(content)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			return
		} else {
			lastErr = err
			lastStderr = stderr.String()
			time.Sleep(2 * time.Second)
		}
	}
	h.t.Fatalf("Timed out applying content with retry: %v, stderr: %s", lastErr, lastStderr)
}

func (h *Harness) KubectlApplyFile(file string) {
	h.runCmd("kubectl", "apply", "-f", file)
}

func (h *Harness) DeployBackend() {
	h.t.Log("Deploying Backend")
	h.KubectlApplyContent(h.BackendManifest())
	h.WaitForDeployment("backend", "default", 2*time.Minute)
}

func (h *Harness) BackendManifest() string {
	return `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: toolbox
        image: toolbox:e2e
        imagePullPolicy: Never
        args: ["server"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: default
spec:
  selector:
    app: backend
  ports:
  - port: 8080
    targetPort: 8080
`
}

func (h *Harness) WaitForDeployment(depName, namespace string, timeout time.Duration) {
	h.t.Logf("Waiting for deployment %s/%s to be ready", namespace, depName)
	h.runCmd("kubectl", "wait", "--namespace", namespace, "--for=condition=available", fmt.Sprintf("deployment/%s", depName), fmt.Sprintf("--timeout=%s", timeout))
}

func (h *Harness) WaitForGatewayAddress(gwName, namespace string, timeout time.Duration) string {
	h.t.Logf("Waiting for Gateway %s/%s to have an address assigned", namespace, gwName)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := h.runCmdAllowError("kubectl", "get", "gateway", gwName, "--namespace", namespace, "-o", "jsonpath={.status.addresses[0].value}")
		trimmed := strings.TrimSpace(out)
		if trimmed != "" && !strings.Contains(trimmed, "error") {
			h.t.Logf("Gateway %s/%s assigned address: %s", namespace, gwName, trimmed)
			return trimmed
		}
		time.Sleep(1 * time.Second)
	}
	h.t.Fatalf("Timed out waiting for Gateway %s/%s to get address", namespace, gwName)
	return ""
}

func (h *Harness) CheckListenerCondition(gwName, namespace, listenerName, condType, expectedStatus string) bool {
	out := h.runCmdAllowError("kubectl", "get", "gateway", gwName, "--namespace", namespace, "-o", "json")
	if strings.TrimSpace(out) == "" {
		return false
	}
	var gw struct {
		Status struct {
			Listeners []struct {
				Name       string `json:"name"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"conditions"`
			} `json:"listeners"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &gw); err != nil {
		return false
	}
	for _, l := range gw.Status.Listeners {
		if l.Name == listenerName {
			for _, c := range l.Conditions {
				if c.Type == condType && c.Status == expectedStatus {
					return true
				}
			}
		}
	}
	return false
}

func (h *Harness) WaitForListenerCondition(gwName, namespace, listenerName, condType, expectedStatus string, timeout time.Duration) bool {
	h.t.Logf("Waiting for listener %s on Gateway %s/%s condition %s=%s", listenerName, namespace, gwName, condType, expectedStatus)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.CheckListenerCondition(gwName, namespace, listenerName, condType, expectedStatus) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (h *Harness) runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("Command %s %v failed: %v\nStdout: %s\nStderr: %s", name, args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func (h *Harness) runCmdAllowError(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Allowed error
	}
	if stdout.Len() > 0 {
		return stdout.String()
	}
	return stderr.String()
}
