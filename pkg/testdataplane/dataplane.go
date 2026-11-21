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

package testdataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
)

var (
	binaryOnce sync.Once
	binaryPath string
	binaryErr  error
)

func getOrBuildBinary() (string, error) {
	binaryOnce.Do(func() {
		root, err := findModuleRoot()
		if err != nil {
			binaryErr = err
			return
		}
		cacheDir := os.Getenv("GOCACHE")
		if cacheDir == "" {
			cacheDir = filepath.Join(os.TempDir(), "gari-build-cache")
		}
		targetDir := filepath.Join(cacheDir, "gari-dataplane")
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			binaryErr = fmt.Errorf("creating dataplane cache dir: %w", err)
			return
		}
		target := filepath.Join(targetDir, "gari")
		if isBinaryCurrent(target, root) {
			binaryPath = target
			return
		}
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", target, "./cmd/gateway-api-reference-implementation")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			binaryErr = fmt.Errorf("building dataplane binary: %w\n%s", err, string(out))
			return
		}
		binaryPath = target
	})
	return binaryPath, binaryErr
}

func isBinaryCurrent(targetPath, rootDir string) bool {
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		return false
	}
	targetModTime := targetInfo.ModTime()

	for _, file := range []string{"go.mod", "go.sum"} {
		info, err := os.Stat(filepath.Join(rootDir, file))
		if err != nil {
			return false
		}
		if info.ModTime().After(targetModTime) {
			return false
		}
	}

	for _, dir := range []string{"cmd", "pkg"} {
		err := filepath.WalkDir(filepath.Join(rootDir, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if strings.HasSuffix(path, ".go") {
				info, err := d.Info()
				if err != nil {
					return err
				}
				if info.ModTime().After(targetModTime) {
					return fmt.Errorf("outdated")
				}
			}
			return nil
		})
		if err != nil {
			return false
		}
	}
	return true
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		target := filepath.Join(d, "cmd", "gateway-api-reference-implementation")
		if _, err := os.Stat(target); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		return d, nil
	}
	return "", fmt.Errorf("could not find module root containing cmd/gateway-api-reference-implementation from %s", dir)
}

type safeBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.Buffer.Write(p)
}

func (s *safeBuffer) String() string {
	s.Lock()
	defer s.Unlock()
	return s.Buffer.String()
}

type staticTokenReviewer struct {
	expectedToken string
	namespace     string
	sa            string
}

func (r *staticTokenReviewer) ReviewToken(_ context.Context, token string) (string, string, error) {
	if token == r.expectedToken {
		return r.namespace, r.sa, nil
	}
	return "", "", errors.New("unauthorized token")
}

func generateTestCAAndServerCert() ([]byte, tls.Certificate, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("generating CA key: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test Dataplane CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("creating CA certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("generating server key: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Test Internal API Server"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("creating server cert: %w", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("creating X509KeyPair: %w", err)
	}
	return caPEM, serverTLSCert, nil
}

// Option configures Dataplane startup.
type Option func(*dataplaneOptions)

type dataplaneOptions struct {
	initialConfig *state.DataplaneConfig
}

// WithInitialConfig supplies an initial DataplaneConfig to be published
// before the data plane starts up.
func WithInitialConfig(cfg *state.DataplaneConfig) Option {
	return func(o *dataplaneOptions) {
		o.initialConfig = cfg
	}
}

// Dataplane manages a running GARI data-plane subprocess.
type Dataplane struct {
	HTTPAddress  string
	HTTPSAddress string
	PID          int

	PushServer       *push.Server
	gatewayNamespace string
	gatewayName      string
	healthAddress    string
	currentRevision  string
	output           *safeBuffer
}

// StartDataplane builds the main binary once per test run and starts it in data-plane mode
// as a subprocess against an in-memory internal API push server on free local ports.
// It waits until the initial revision is reported as applied (if provided), returns the running Dataplane,
// and automatically stops the subprocess and push server when the test ends.
func StartDataplane(t testing.TB, env *testenv.Environment, gatewayNamespace, gatewayName string, opts ...Option) *Dataplane {
	t.Helper()

	var dopts dataplaneOptions
	for _, opt := range opts {
		opt(&dopts)
	}

	binary, err := getOrBuildBinary()
	if err != nil {
		t.Fatalf("StartDataplane: %v", err)
	}

	allocatePort := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate free port: %v", err)
		}
		addr := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatalf("closing allocated port listener: %v", err)
		}
		return addr
	}
	httpAddress := allocatePort()
	httpsAddress := allocatePort()
	healthAddress := allocatePort()

	// 1. Setup internal API server credentials
	caPEM, serverTLSCert, err := generateTestCAAndServerCert()
	if err != nil {
		t.Fatalf("StartDataplane: generating TLS credentials: %v", err)
	}

	tempDir := t.TempDir()
	caFile := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("StartDataplane: writing CA file: %v", err)
	}

	testToken := "test-dataplane-token"
	tokenFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenFile, []byte(testToken), 0o600); err != nil {
		t.Fatalf("StartDataplane: writing token file: %v", err)
	}

	// 2. Start internal API push server
	saName := state.ResourceNameForGateway(gatewayName)
	reviewer := &staticTokenReviewer{
		expectedToken: testToken,
		namespace:     gatewayNamespace,
		sa:            saName,
	}

	pushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("StartDataplane: creating push server: %v", err)
	}

	internalAPILis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartDataplane: listening for internal API: %v", err)
	}
	internalAPIAddr := internalAPILis.Addr().String()

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&serverTLSCert)),
		grpc.MaxRecvMsgSize(push.MaxMessageBytes),
		grpc.MaxSendMsgSize(push.MaxMessageBytes),
	)
	push.RegisterPushServiceServer(grpcServer, pushServer)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- grpcServer.Serve(internalAPILis)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
	})

	var initialRevision string
	if dopts.initialConfig != nil {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: gatewayNamespace,
				Name:      gatewayName,
			},
		}
		if err := pushServer.PublishDataplaneConfig(t.Context(), gw, dopts.initialConfig); err != nil {
			t.Fatalf("StartDataplane: publishing initial config: %v", err)
		}
		initialRevision = dopts.initialConfig.Revision
	}

	cmd := exec.Command(binary,
		"--dataplane-mode",
		"--gateway-namespace="+gatewayNamespace,
		"--gateway-name="+gatewayName,
		"--proxy-bind-address="+httpAddress,
		"--proxy-https-bind-address="+httpsAddress,
		"--health-probe-bind-address="+healthAddress,
		"--metrics-bind-address=0",
		"--internal-api-address="+internalAPIAddr,
		"--internal-api-ca-file="+caFile,
		"--internal-api-token-file="+tokenFile,
	)
	output := &safeBuffer{}
	cmd.Stdout, cmd.Stderr = output, output

	if err := cmd.Start(); err != nil {
		t.Fatalf("StartDataplane: failed to start process: %v", err)
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Logf("dataplane signal SIGTERM: %v", err)
			}
			done := make(chan struct{})
			go func() {
				if err := cmd.Wait(); err != nil {
					t.Logf("dataplane wait: %v", err)
				}
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				if err := cmd.Process.Kill(); err != nil {
					t.Logf("dataplane kill: %v", err)
				}
				<-done
			}
		}
		if t.Failed() {
			t.Logf("dataplane subprocess (%s/%s) output:\n%s", gatewayNamespace, gatewayName, output.String())
		}
	})

	dp := &Dataplane{
		HTTPAddress:      httpAddress,
		HTTPSAddress:     httpsAddress,
		PID:              cmd.Process.Pid,
		PushServer:       pushServer,
		gatewayNamespace: gatewayNamespace,
		gatewayName:      gatewayName,
		healthAddress:    healthAddress,
		currentRevision:  initialRevision,
		output:           output,
	}

	if dopts.initialConfig != nil {
		if err := dp.WaitApplied(t.Context()); err != nil {
			t.Fatalf("StartDataplane: %v", err)
		}
	}

	waitPortReady := func(addr string) error {
		if addr == "" {
			return nil
		}
		return wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err != nil {
				return false, nil
			}
			if closeErr := conn.Close(); closeErr != nil {
				return false, closeErr
			}
			return true, nil
		})
	}
	if err := waitPortReady(httpAddress); err != nil {
		t.Fatalf("StartDataplane: waiting for HTTP proxy ready: %v", err)
	}
	if err := waitPortReady(httpsAddress); err != nil {
		t.Fatalf("StartDataplane: waiting for HTTPS proxy ready: %v", err)
	}
	return dp
}

// Publish publishes a configuration revision to the data plane via the internal API push server.
func (d *Dataplane) Publish(ctx context.Context, cfg *state.DataplaneConfig) error {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.gatewayNamespace,
			Name:      d.gatewayName,
		},
	}
	d.currentRevision = cfg.Revision
	return d.PushServer.PublishDataplaneConfig(ctx, gw, cfg)
}

// WaitApplied waits until the data plane reports that it has applied the configuration revision
// via the internal API push server Ack and health endpoint.
func (d *Dataplane) WaitApplied(ctx context.Context) error {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.gatewayNamespace,
			Name:      d.gatewayName,
		},
	}
	res, err := d.PushServer.WaitApplied(ctx, gw, d.currentRevision)
	if err != nil {
		return fmt.Errorf("waiting for internal API push ack (revision %q): %w\nSubprocess log:\n%s", d.currentRevision, err, d.output.String())
	}
	if len(res.Rejections) > 0 {
		return fmt.Errorf("dataplane rejected revision %q: %s", d.currentRevision, res.Rejections[0].Reason)
	}

	healthURL := fmt.Sprintf("http://%s/_gari/applied", d.healthAddress)
	client := &http.Client{Timeout: 2 * time.Second}
	err = wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, nil
		}
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			return false, closeErr
		}
		if readErr != nil || resp.StatusCode != http.StatusOK {
			return false, nil
		}
		var revisions []string
		if err := json.Unmarshal(bodyBytes, &revisions); err != nil {
			return false, nil
		}
		return slices.Contains(revisions, d.currentRevision), nil
	})
	if err != nil {
		return fmt.Errorf("waiting for dataplane to report revision %q: %w\nSubprocess log:\n%s", d.currentRevision, err, d.output.String())
	}

	return nil
}
