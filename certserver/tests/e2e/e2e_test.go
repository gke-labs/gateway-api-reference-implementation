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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

func TestCertserverE2E(t *testing.T) {
	if os.Getenv("RUN_E2E") == "" {
		t.Skip("RUN_E2E env var not set, skipping")
	}

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "kind"
	}

	h := NewHarness(t, clusterName)
	h.Setup()

	// =========================================================================
	// Scenario 1: Happy Path
	// A Gateway with an HTTP listener and an HTTPS listener
	// (tls.options selects certserver) for app.test. The listener goes pending,
	// then gets the certificate. An HTTPS request with SNI app.test is served
	// with a certificate chaining to Pebble's root.
	// =========================================================================
	t.Run("Scenario1_HappyPath", func(t *testing.T) {
		t.Log("Applying Gateway parameters ConfigMap (acmeChallenge: enabled)")
		h.KubectlApplyContent(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: happy-gw-params
  namespace: default
data:
  acmeChallenge: enabled
`)

		t.Log("Applying Gateway happy-gw with HTTP and HTTPS listeners (certificate-source: certserver)")
		h.KubectlApplyContent(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: happy-gw
  namespace: default
spec:
  gatewayClassName: reference-class
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: happy-gw-params
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  - name: https
    protocol: HTTPS
    port: 443
    hostname: "app.test"
    tls:
      mode: Terminate
      options:
        gateway.gke-labs.io/certificate-source: certserver
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: happy-route
  namespace: default
spec:
  parentRefs:
  - name: happy-gw
  hostnames: ["app.test"]
  rules:
  - backendRefs:
    - name: backend
      port: 8080
`)

		gwAddr := h.WaitForGatewayAddress("happy-gw", "default", 2*time.Minute)
		t.Logf("Gateway happy-gw got address %s", gwAddr)

		// Point Pebble's mock DNS to the Gateway's address so HTTP-01 validation connects to the Gateway
		h.pebble.SetResolvedIP(gwAddr)

		// Verify listener condition becomes Programmed=True and ResolvedRefs=True
		t.Log("Waiting for listener https on happy-gw to become Programmed=True and ResolvedRefs=True")
		if !h.WaitForListenerCondition("happy-gw", "default", "https", "Programmed", "True", 2*time.Minute) {
			t.Fatal("timed out waiting for happy-gw https listener Programmed=True")
		}
		if !h.WaitForListenerCondition("happy-gw", "default", "https", "ResolvedRefs", "True", 2*time.Minute) {
			t.Fatal("timed out waiting for happy-gw https listener ResolvedRefs=True")
		}

		// Send HTTPS request with SNI app.test and verify certificate chains to Pebble's root
		t.Log("Verifying HTTPS request with SNI app.test chains to Pebble root")
		var resp *http.Response
		var body string
		var lastErr error

		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			resp, body, lastErr = sendHTTPSRequest(gwAddr, "app.test", "/", h.pebble.RootCert)
			if lastErr == nil && resp.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		if lastErr != nil {
			t.Fatalf("HTTPS request to app.test failed: %v", lastErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200, got %d, body: %s", resp.StatusCode, body)
		}

		// Cryptographically verify peer certificate chains to Pebble root
		if len(resp.TLS.VerifiedChains) == 0 {
			t.Fatal("expected non-empty TLS verified chains")
		}
		leafCert := resp.TLS.PeerCertificates[0]
		t.Logf("Successfully served HTTPS! Peer cert subject: %s, issuer: %s, DNS: %v",
			leafCert.Subject.CommonName, leafCert.Issuer.CommonName, leafCert.DNSNames)

		if leafCert.Subject.CommonName != "app.test" && !containsString(leafCert.DNSNames, "app.test") {
			t.Fatalf("expected certificate for app.test, got CN=%s, DNSNames=%v", leafCert.Subject.CommonName, leafCert.DNSNames)
		}
	})

	// =========================================================================
	// Scenario 2: Binding
	// A second Gateway, in another namespace with its own data plane and
	// service account, that hostnames don't resolve to, requests the same hostname.
	// It must not get the certificate. Its listener stays pending or failed with a
	// stable reason, and certserver's audit log shows the refused challenge answer.
	// =========================================================================
	t.Run("Scenario2_Binding", func(t *testing.T) {
		t.Log("Creating unauthorized-ns namespace")
		h.runCmd("kubectl", "create", "namespace", "unauthorized-ns")
		t.Cleanup(func() {
			_ = h.runCmdAllowError("kubectl", "delete", "namespace", "unauthorized-ns", "--wait=false")
		})

		t.Log("Applying Gateway parameters ConfigMap in unauthorized-ns")
		h.KubectlApplyContent(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: binding-gw-params
  namespace: unauthorized-ns
data:
  acmeChallenge: enabled
`)

		t.Log("Applying Gateway binding-gw in unauthorized-ns requesting app.test")
		h.KubectlApplyContent(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: binding-gw
  namespace: unauthorized-ns
spec:
  gatewayClassName: reference-class
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: binding-gw-params
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  - name: https
    protocol: HTTPS
    port: 443
    hostname: "app.test"
    tls:
      mode: Terminate
      options:
        gateway.gke-labs.io/certificate-source: certserver
`)

		_ = h.WaitForGatewayAddress("binding-gw", "unauthorized-ns", 2*time.Minute)

		// Pebble still resolves app.test to happy-gw's address. When Pebble validates the challenge,
		// happy-gw data plane forwards with its SA (system:serviceaccount:default:happy-gw-gari),
		// which certserver refuses because it was ordered for unauthorized-ns/binding-gw.
		t.Log("Waiting for certserver audit log to record refused challenge binding")
		refusedFound := false
		auditDeadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(auditDeadline) {
			auditOutput := h.auditBuf.String()
			for _, line := range strings.Split(auditOutput, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
					continue
				}
				var entry registry.AuditEntry
				if err := json.Unmarshal([]byte(trimmed), &entry); err == nil {
					if entry.Decision == registry.DecisionRefused &&
						entry.Gateway == "unauthorized-ns/binding-gw" &&
						strings.Contains(entry.Reason, "is not authorized for requesting gateway unauthorized-ns/binding-gw in cluster") {
						refusedFound = true
						t.Logf("Found expected refused audit log entry: Gateway=%s, Reason=%s", entry.Gateway, entry.Reason)
						break
					}
				}
			}
			if refusedFound {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		if !refusedFound {
			t.Fatalf("did not find expected refused audit log in certserver audit log:\n%s", h.auditBuf.String())
		}

		// The second Gateway must NOT get the certificate (Programmed remains False).
		// Poll over a 3-second window ensuring Programmed never becomes True.
		t.Log("Verifying binding-gw listener does not become Programmed=True")
		pollDeadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(pollDeadline) {
			if h.CheckListenerCondition("binding-gw", "unauthorized-ns", "https", "Programmed", "True") {
				t.Fatal("expected binding-gw https listener to NOT be Programmed=True, but it was")
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Verify first Gateway is unaffected and continues to serve HTTPS with valid cert
		gwAddr := h.WaitForGatewayAddress("happy-gw", "default", 10*time.Second)
		resp, _, err := sendHTTPSRequest(gwAddr, "app.test", "/", h.pebble.RootCert)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("happy-gw HTTPS request failed after binding test: %v", err)
		}
	})

	// =========================================================================
	// Scenario 3: Fall-through
	// With forwarding turned on, an HTTPRoute that serves
	// /.well-known/acme-challenge/<unknown-token> still answers, because
	// certserver returns 404 and the data plane falls through.
	// =========================================================================
	t.Run("Scenario3_Fallthrough", func(t *testing.T) {
		t.Log("Applying HTTPRoute with fallthrough rule for /.well-known/acme-challenge/fallback-")
		h.KubectlApplyContent(`
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: fallthrough-route
  namespace: default
spec:
  parentRefs:
  - name: happy-gw
  hostnames: ["app.test"]
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /.well-known/acme-challenge/fallback-unknown-
    backendRefs:
    - name: backend
      port: 8080
`)

		gwAddr := h.WaitForGatewayAddress("happy-gw", "default", 30*time.Second)

		// Send request to /.well-known/acme-challenge/fallback-unknown-token-12345
		// Data plane intercepts, forwards to certserver, certserver returns 404,
		// data plane falls through to normal HTTP routing, and backend responds with 200 OK.
		t.Log("Sending request to /.well-known/acme-challenge/fallback-unknown-token-12345")
		var resp *http.Response
		var body string
		var lastErr error

		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			resp, body, lastErr = sendHTTPRequest(gwAddr, "app.test", "/.well-known/acme-challenge/fallback-unknown-token-12345")
			if lastErr == nil && resp.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		if lastErr != nil {
			t.Fatalf("request to fallthrough challenge path failed: %v", lastErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 from backend fallthrough, got %d, body: %s", resp.StatusCode, body)
		}

		t.Logf("Fall-through succeeded! Response from backend: %s", body)
	})
}

func sendHTTPSRequest(gwAddr, hostname, path string, rootCert *x509.Certificate) (*http.Response, string, error) {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: hostname,
			RootCAs:    rootPool,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, fmt.Sprintf("%s:443", gwAddr))
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("https://%s%s", hostname, path))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
}

func sendHTTPRequest(gwAddr, hostname, path string) (*http.Response, string, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, fmt.Sprintf("%s:80", gwAddr))
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", hostname, path), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
