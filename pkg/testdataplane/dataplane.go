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
	"encoding/json"
	"fmt"
	"io"
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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
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

// Dataplane manages a running GARI data-plane subprocess.
type Dataplane struct {
	HTTPAddress  string
	HTTPSAddress string
	PID          int

	env              *testenv.Environment
	gatewayNamespace string
	gatewayName      string
	healthAddress    string
	currentRevision  string
	output           *safeBuffer
}

// StartDataplane builds the main binary once per test run and starts it in data-plane mode
// as a subprocess against the test environment's API server on free local ports.
// It waits until the published revision is reported as applied, returns the running Dataplane,
// and automatically stops the subprocess when the test ends.
func StartDataplane(t testing.TB, env *testenv.Environment, gatewayNamespace, gatewayName string) *Dataplane {
	t.Helper()

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

	kubeconfigFile := filepath.Join(t.TempDir(), "kubeconfig")
	if err := writeKubeconfig(env.Config, kubeconfigFile); err != nil {
		t.Fatalf("StartDataplane: writing kubeconfig: %v", err)
	}

	cmd := exec.Command(binary,
		"--dataplane-mode",
		"--gateway-namespace="+gatewayNamespace,
		"--gateway-name="+gatewayName,
		"--proxy-bind-address="+httpAddress,
		"--proxy-https-bind-address="+httpsAddress,
		"--health-probe-bind-address="+healthAddress,
		"--metrics-bind-address=0",
	)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfigFile)
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
		env:              env,
		gatewayNamespace: gatewayNamespace,
		gatewayName:      gatewayName,
		healthAddress:    healthAddress,
		output:           output,
	}

	if err := dp.WaitApplied(t.Context()); err != nil {
		t.Fatalf("StartDataplane: %v", err)
	}
	return dp
}

// WaitApplied waits until the controller publishes a configuration revision for the Gateway
// (differing from the last applied revision) and the data plane reports it as applied.
func (d *Dataplane) WaitApplied(ctx context.Context) error {
	secretName := singlepod.ResourceNameForGateway(d.gatewayName)
	secretKey := types.NamespacedName{Namespace: d.gatewayNamespace, Name: secretName}

	var targetRevision string
	err := wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		var secret corev1.Secret
		if err := d.env.Client.Get(ctx, secretKey, &secret); err != nil {
			return false, nil
		}
		data := secret.Data[singlepod.DataplaneSecretDataKey]
		if len(data) == 0 {
			return false, nil
		}
		dataplaneConfig, err := state.UnmarshalDataplaneConfig(data)
		if err != nil {
			return false, nil
		}
		if dataplaneConfig.Revision != "" && dataplaneConfig.Revision != d.currentRevision {
			targetRevision = dataplaneConfig.Revision
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for published secret revision (previous=%q): %w\nSubprocess log:\n%s", d.currentRevision, err, d.output.String())
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
		return slices.Contains(revisions, targetRevision), nil
	})
	if err != nil {
		return fmt.Errorf("waiting for dataplane to report revision %q: %w\nSubprocess log:\n%s", targetRevision, err, d.output.String())
	}

	d.currentRevision = targetRevision
	return nil
}

func writeKubeconfig(cfg *rest.Config, destPath string) error {
	clientConfig := clientcmdapi.NewConfig()
	clientConfig.Clusters["default"] = &clientcmdapi.Cluster{
		Server:                   cfg.Host,
		CertificateAuthorityData: cfg.CAData,
		CertificateAuthority:     cfg.CAFile,
		InsecureSkipTLSVerify:    cfg.Insecure,
	}
	clientConfig.AuthInfos["default"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: cfg.CertData,
		ClientCertificate:     cfg.CertFile,
		ClientKeyData:         cfg.KeyData,
		ClientKey:             cfg.KeyFile,
		Token:                 cfg.BearerToken,
	}
	clientConfig.Contexts["default"] = &clientcmdapi.Context{Cluster: "default", AuthInfo: "default"}
	clientConfig.CurrentContext = "default"
	return clientcmd.WriteToFile(*clientConfig, destPath)
}
