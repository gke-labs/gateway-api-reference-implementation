//go:build benchmark

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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

type StepTimings struct {
	DeployAndSvcExist time.Duration
	PodScheduled      time.Duration
	ContainerStarted  time.Duration
	ConfigApplied     time.Duration
	AddressAssigned   time.Duration
	Programmed        time.Duration
	FirstRequest      time.Duration
}

type staticAddressProvider struct{ addr string }

func (p *staticAddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	t := gatewayv1.IPAddressType
	return []gatewayv1.GatewayStatusAddress{{Type: &t, Value: p.addr}}, true, nil
}

func measureGateway(t *testing.T, h *Harness, cs *kubernetes.Clientset, gwName, class, host string, port int, reqURL, probeURL string) StepTimings {
	manifest := fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: %s
  namespace: default
spec:
  gatewayClassName: %s
  listeners:
  - name: http
    protocol: HTTP
    port: %d
    hostname: %q
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: %s-route
  namespace: default
spec:
  parentRefs:
  - name: %s
  hostnames: [%q]
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`, gwName, class, port, host, gwName, gwName, host)

	t0 := time.Now()
	h.KubectlApplyContent(manifest)

	var s StepTimings
	var podName, gwAddr string
	resName := singlepod.ResourceNameForGateway(gwName)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	for time.Since(t0) < 2*time.Minute {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		if class == "reference-class" {
			if s.DeployAndSvcExist == 0 {
				if _, errD := cs.AppsV1().Deployments("default").Get(ctx, resName, metav1.GetOptions{}); errD == nil {
					if _, errS := cs.CoreV1().Services("default").Get(ctx, resName, metav1.GetOptions{}); errS == nil {
						s.DeployAndSvcExist = time.Since(t0)
					}
				}
			}
			if s.PodScheduled == 0 {
				pods, err := cs.CoreV1().Pods("default").List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", singlepod.LabelGatewayName, gwName)})
				if err == nil && len(pods.Items) > 0 && pods.Items[0].Spec.NodeName != "" {
					s.PodScheduled = time.Since(t0)
					podName = pods.Items[0].Name
				}
			}
			if s.ContainerStarted == 0 && podName != "" {
				if p, err := cs.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{}); err == nil && len(p.Status.ContainerStatuses) > 0 && p.Status.ContainerStatuses[0].State.Running != nil {
					s.ContainerStarted = time.Since(t0)
				}
			}
			if s.ConfigApplied == 0 && podName != "" {
				if raw, err := cs.CoreV1().Pods("default").ProxyGet("http", podName, "8999", "/_gari/applied", nil).DoRaw(ctx); err == nil {
					var revs []string
					if json.Unmarshal(raw, &revs) == nil && len(revs) > 0 && revs[0] != "" {
						s.ConfigApplied = time.Since(t0)
						if s.ContainerStarted == 0 {
							s.ContainerStarted = s.ConfigApplied
						}
					}
				}
			}
		} else if s.ConfigApplied == 0 && probeURL != "" {
			if resp, err := client.Get(probeURL); err == nil {
				var revs []string
				if json.NewDecoder(resp.Body).Decode(&revs) == nil && len(revs) > 0 && revs[0] != "" {
					s.ConfigApplied = time.Since(t0)
				}
				resp.Body.Close()
			}
		}

		if s.AddressAssigned == 0 {
			out, err := exec.Command("kubectl", "get", "gateway", gwName, "-n", "default", "-o", "jsonpath={.status.addresses[0].value}").Output()
			if err == nil && strings.TrimSpace(string(out)) != "" {
				gwAddr = strings.TrimSpace(string(out))
				s.AddressAssigned = time.Since(t0)
			}
		}

		if s.Programmed == 0 {
			out, err := exec.Command("kubectl", "get", "gateway", gwName, "-n", "default", "-o", `jsonpath={.status.conditions[?(@.type=="Programmed")].status}`).Output()
			if err == nil && strings.TrimSpace(string(out)) == "True" {
				s.Programmed = time.Since(t0)
			}
		}

		target := reqURL
		if target == "" && gwAddr != "" {
			target = fmt.Sprintf("http://%s/", gwAddr)
		}
		if s.FirstRequest == 0 && target != "" {
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err == nil {
				req.Host = host
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						s.FirstRequest = time.Since(t0)
					}
				}
			}
		}

		cancel()
		if (class != "reference-class" || (s.DeployAndSvcExist > 0 && s.PodScheduled > 0 && s.ContainerStarted > 0)) &&
			s.ConfigApplied > 0 && s.AddressAssigned > 0 && s.Programmed > 0 && s.FirstRequest > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	return s
}

func TestBenchmarkGatewayStartup(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping benchmark")
	}

	ctrl.SetLogger(textlogger.NewLogger(textlogger.NewConfig()))

	h := NewHarness(t, "kind-bench")
	h.Setup()
	h.InstallGatewayAPI(gatewayconsts.BundleVersion)
	h.DeployBackend()
	h.DeployController()

	cs, err := kubernetes.NewForConfig(h.RESTConfig())
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	// Case 1: First Gateway in fresh cluster (cold)
	t.Log("Measuring Case 1 (First Gateway / Cold)...")
	cold := measureGateway(t, h, cs, "bench-gw-cold", "reference-class", "cold.example.com", 80, "", "")
	t.Logf("Case 1 Timings: %v", cold)

	// Case 2: Later Gateways (warm, image already on node)
	t.Log("Measuring Case 2 (Later Gateways / Warm)...")
	warm := make([]StepTimings, 3)
	for i := range warm {
		name := fmt.Sprintf("bench-gw-warm-%d", i+1)
		host := fmt.Sprintf("warm%d.example.com", i+1)
		warm[i] = measureGateway(t, h, cs, name, "reference-class", host, 80, "", "")
		t.Logf("Case 2 run %d Timings: %v", i+1, warm[i])
	}

	// Case 3: All-in-one mode comparison
	t.Log("Measuring Case 3 (All-in-One Mode)...")
	aioCtx, aioCancel := context.WithCancel(t.Context())
	defer aioCancel()

	pfCmd := exec.CommandContext(aioCtx, "kubectl", "port-forward", "svc/backend", "8080:8080")
	if err := pfCmd.Start(); err != nil {
		t.Fatalf("failed to port-forward backend: %v", err)
	}
	defer func() {
		if pfCmd.Process != nil {
			_ = pfCmd.Process.Kill()
		}
	}()

	_ = exec.Command("python3", "-c", "open('/etc/hosts', 'a').write('\\n127.0.0.1 backend.default.svc.cluster.local\\n')").Run()
	defer func() {
		_ = exec.Command("python3", "-c", "lines = [l for l in open('/etc/hosts').readlines() if 'backend.default.svc.cluster.local' not in l]; open('/etc/hosts', 'w').writelines(lines)").Run()
	}()

	for attempt := 0; attempt < 50; attempt++ {
		if resp, err := http.Get("http://127.0.0.1:8080/"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	h.KubectlApplyContent(`
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: aio-class
spec:
  controllerName: reference.gateway.networking.k8s.io/aio-controller
`)

	opts := gari.DefaultOptions()
	opts.RestConfig = h.RESTConfig()
	opts.MetricsAddr = "127.0.0.1:8998"
	opts.HealthProbeBindAddress = "127.0.0.1:8998"
	opts.ProxyAddr = "127.0.0.1:8088"
	opts.LeaderElection = false
	opts.ControllerName = "reference.gateway.networking.k8s.io/aio-controller"
	opts.AddressProvider = &staticAddressProvider{addr: "127.0.0.1"}

	aioServer, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}
	go func() {
		if err := aioServer.Start(aioCtx); err != nil && aioCtx.Err() == nil {
			t.Logf("aio server exited: %v", err)
		}
	}()

	if !aioServer.Manager().GetCache().WaitForCacheSync(aioCtx) {
		t.Fatalf("cache sync timeout")
	}

	for attempt := 0; attempt < 50; attempt++ {
		if resp, err := http.Get("http://127.0.0.1:8088/"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	aio := make([]StepTimings, 3)
	for i := range aio {
		name := fmt.Sprintf("bench-gw-aio-%d", i+1)
		host := fmt.Sprintf("aio%d.example.com", i+1)
		aio[i] = measureGateway(t, h, cs, name, "aio-class", host, 8088, "http://127.0.0.1:8088/", "http://127.0.0.1:8998/_gari/applied")
		t.Logf("Case 3 run %d Timings: %v", i+1, aio[i])
		h.RunCmd("kubectl", "delete", "gateway", name, "-n", "default", "--ignore-not-found")
		h.RunCmd("kubectl", "delete", "httproute", name+"-route", "-n", "default", "--ignore-not-found")
	}

	t.Log("\n=== BENCHMARK RESULTS SUMMARY ===")
	t.Logf("Case 1 (Cold / First GW): %+v", cold)
	for i, w := range warm {
		t.Logf("Case 2 (Warm / Later GW run %d): %+v", i+1, w)
	}
	for i, a := range aio {
		t.Logf("Case 3 (All-in-One run %d): %+v", i+1, a)
	}
}
