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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
)

func TestFrontendCLI_ClientCAFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "frontend-cli-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certsA, err := certs.GenerateAll("snigateway.internal", "team-a-client")
	if err != nil {
		t.Fatalf("GenerateAll certsA: %v", err)
	}

	caPathA := filepath.Join(tempDir, "ca-a.crt")
	if err := os.WriteFile(caPathA, certsA.CA.CertPEM, 0644); err != nil {
		t.Fatalf("writing ca-a.crt: %v", err)
	}
	serverCertPath := filepath.Join(tempDir, "server.crt")
	if err := os.WriteFile(serverCertPath, certsA.Server.CertPEM, 0644); err != nil {
		t.Fatalf("writing server.crt: %v", err)
	}
	serverKeyPath := filepath.Join(tempDir, "server.key")
	if err := os.WriteFile(serverKeyPath, certsA.Server.KeyPEM, 0600); err != nil {
		t.Fatalf("writing server.key: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	listenAddr := "127.0.0.1:0"

	args := []string{
		"--listen=" + listenAddr,
		fmt.Sprintf("--client-ca=%s=*.a.example.com,a.example.org", caPathA),
		"--server-cert=" + serverCertPath,
		"--server-key=" + serverKeyPath,
	}

	// Run frontend in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, args)
	}()

	time.Sleep(100 * time.Millisecond)

	// Verify client A can create TLS config with caA and connect
	clientTLSA, err := certs.NewClientTLSConfig(certsA.CA.CertPEM, certsA.Client.CertPEM, certsA.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	_ = client.NewClient("127.0.0.1:443", clientTLSA)

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server shutdown")
	}
}
