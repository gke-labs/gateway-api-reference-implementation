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
	"strings"
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
		"--max-hostnames-per-session=500",
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

func TestFrontendCLI_JWTFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "frontend-jwt-cli-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certsA, err := certs.GenerateAll("snigateway.internal", "unused-client")
	if err != nil {
		t.Fatalf("GenerateAll certsA: %v", err)
	}

	serverCertPath := filepath.Join(tempDir, "server.crt")
	if err := os.WriteFile(serverCertPath, certsA.Server.CertPEM, 0644); err != nil {
		t.Fatalf("writing server.crt: %v", err)
	}
	serverKeyPath := filepath.Join(tempDir, "server.key")
	if err := os.WriteFile(serverKeyPath, certsA.Server.KeyPEM, 0600); err != nil {
		t.Fatalf("writing server.key: %v", err)
	}

	jwksPath := filepath.Join(tempDir, "jwks.json")
	if err := os.WriteFile(jwksPath, []byte(`{"keys":[]}`), 0644); err != nil {
		t.Fatalf("writing jwks.json: %v", err)
	}

	listenAddr := "127.0.0.1:0"

	t.Run("Startup succeeds with one issuer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		args := []string{
			"--listen=" + listenAddr,
			"--server-cert=" + serverCertPath,
			"--server-key=" + serverKeyPath,
			"--jwt-issuer=https://kubernetes.default.svc",
			"--jwt-jwks-file=" + jwksPath,
			"--jwt-audience=snigateway",
			"--client-subject=system:serviceaccount:default:*=*.example.com",
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- run(ctx, args)
		}()

		time.Sleep(100 * time.Millisecond)

		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				t.Fatalf("run returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for server shutdown")
		}
	})

	t.Run("Startup fails with two issuers", func(t *testing.T) {
		badArgs := []string{
			"--listen=" + listenAddr,
			"--server-cert=" + serverCertPath,
			"--server-key=" + serverKeyPath,
			"--jwt-issuer=https://issuer1.example.com",
			"--jwt-issuer=https://issuer2.example.com",
		}
		err := run(t.Context(), badArgs)
		if err == nil || !strings.Contains(err.Error(), "supports only one issuer") {
			t.Fatalf("expected startup with two issuers to fail, got: %v", err)
		}
	})

	t.Run("Startup fails with two jwks-file issuers", func(t *testing.T) {
		badArgs := []string{
			"--listen=" + listenAddr,
			"--server-cert=" + serverCertPath,
			"--server-key=" + serverKeyPath,
			"--jwt-jwks-file=https://issuer1.example.com=" + jwksPath,
			"--jwt-jwks-file=https://issuer2.example.com=" + jwksPath,
		}
		err := run(t.Context(), badArgs)
		if err == nil || !strings.Contains(err.Error(), "supports only one issuer") {
			t.Fatalf("expected startup with two jwks-file issuers to fail, got: %v", err)
		}
	})

	t.Run("Startup fails with jwt-issuer and different jwks-file issuer", func(t *testing.T) {
		badArgs := []string{
			"--listen=" + listenAddr,
			"--server-cert=" + serverCertPath,
			"--server-key=" + serverKeyPath,
			"--jwt-issuer=https://issuer1.example.com",
			"--jwt-jwks-file=https://issuer2.example.com=" + jwksPath,
		}
		err := run(t.Context(), badArgs)
		if err == nil || !strings.Contains(err.Error(), "supports only one issuer") {
			t.Fatalf("expected startup with jwt-issuer and different jwks-file issuer to fail, got: %v", err)
		}
	})

	t.Run("Bare jwks file without issuer fails", func(t *testing.T) {
		badArgs := []string{
			"--listen=" + listenAddr,
			"--server-cert=" + serverCertPath,
			"--server-key=" + serverKeyPath,
			"--jwt-jwks-file=" + jwksPath,
		}
		err := run(t.Context(), badArgs)
		if err == nil || !strings.Contains(err.Error(), "only valid when exactly one --jwt-issuer is configured") {
			t.Fatalf("expected bare jwks file without issuer to fail, got: %v", err)
		}
	})
}
