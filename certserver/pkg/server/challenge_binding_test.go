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

package server

import (
	"context"
	"testing"
	"time"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
)

// waitForCertificate waits for certificate issuance by polling GetCertificate until a certificate
// is returned or the deadline passes. Under race detection and parallel CI load across packages,
// Pebble ACME order processing (order creation, challenge validation, and order finalization)
// takes multiple 1-second ACME client polling intervals (WaitAuthorization, WaitOrder), so allow
// 25 seconds for certificate issuance to complete.
func waitForCertificate(t *testing.T, client certserverv1.CertificateServiceClient, ctx context.Context, req *certserverv1.GetCertificateRequest) *certserverv1.GetCertificateResponse {
	t.Helper()

	deadline := time.Now().Add(25 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		resp, err := client.GetCertificate(ctx, req)
		if err == nil && resp != nil && len(resp.CertificateChain) > 0 {
			return resp
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("expected certificate issuance to succeed for %s, last error: %v", req.Gateway, lastErr)
	return nil
}

// TestPebble_TwoNamespacesSameHostname_SecondRequiresOwnValidation verifies that when two Gateways
// in two namespaces ask for the same hostname, the second Gateway gets no certificate until its own
// request has been validated.
func TestPebble_TwoNamespacesSameHostname_SecondRequiresOwnValidation(t *testing.T) {
	const host = "two-ns.example.com"
	h := setupSelfCheckTest(t, selfCheckHarnessConfig{allowedHostnames: []string{host}})

	newReq := func(ns, name string) *certserverv1.GetCertificateRequest {
		return &certserverv1.GetCertificateRequest{
			Hostnames:               []string{host},
			Gateway:                 ns + "/" + name,
			DataPlaneServiceAccount: ns + "/dp-" + name,
			ClusterId:               h.clusterID,
			Addresses:               []string{h.testServerIP},
		}
	}
	reqA, reqB := newReq("namespace-a", "gw-a"), newReq("namespace-b", "gw-b")

	h.obtainCertificate(t, reqA)

	respB, err := h.client.GetCertificate(h.callCtx, reqB)
	if err != nil {
		t.Fatalf("Gateway B GetCertificate failed: %v", err)
	}
	if len(respB.CertificateChain) > 0 || h.bindingStore.HasValidatedBinding(h.clusterID, reqB.Gateway, host, time.Now()) {
		t.Fatal("Gateway B received certificate or validated binding before validation")
	}
	if resp := h.obtainCertificate(t, reqB); len(resp.CertificateChain) == 0 {
		t.Fatal("expected Gateway B to receive certificate after validation")
	}
}
