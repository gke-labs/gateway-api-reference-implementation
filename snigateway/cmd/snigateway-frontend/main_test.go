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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
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

func TestFrontendCLI_ListenHTTPFlag(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "frontend-http-cli-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certsA, err := certs.GenerateAll("snigateway.internal", "test-client")
	if err != nil {
		t.Fatalf("GenerateAll certs: %v", err)
	}

	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, certsA.CA.CertPEM, 0644); err != nil {
		t.Fatalf("writing ca.crt: %v", err)
	}
	serverCertPath := filepath.Join(tempDir, "server.crt")
	if err := os.WriteFile(serverCertPath, certsA.Server.CertPEM, 0644); err != nil {
		t.Fatalf("writing server.crt: %v", err)
	}
	serverKeyPath := filepath.Join(tempDir, "server.key")
	if err := os.WriteFile(serverKeyPath, certsA.Server.KeyPEM, 0600); err != nil {
		t.Fatalf("writing server.key: %v", err)
	}

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("picking free port for HTTP listener: %v", err)
	}
	httpAddr := httpListener.Addr().String()
	if err := httpListener.Close(); err != nil {
		t.Fatalf("closing port: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	args := []string{
		"--listen=127.0.0.1:0",
		"--listen-http=" + httpAddr,
		"--ca-cert=" + caPath,
		"--server-cert=" + serverCertPath,
		"--server-key=" + serverKeyPath,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, args)
	}()

	// Wait until HTTP listener is accepting connections
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", httpAddr, 50*time.Millisecond)
		if dialErr == nil {
			if err := conn.Close(); err != nil {
				t.Fatalf("closing probe connection: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for HTTP listener to start: %v", dialErr)
		}
		time.Sleep(5 * time.Millisecond)
	}

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

func TestFrontendCLI_WireGuardFlags(t *testing.T) {
	tempDir := t.TempDir()

	certsA, err := certs.GenerateAll("snigateway.internal", "test-client")
	if err != nil {
		t.Fatalf("GenerateAll certs: %v", err)
	}

	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, certsA.CA.CertPEM, 0644); err != nil {
		t.Fatalf("writing ca.crt: %v", err)
	}
	serverCertPath := filepath.Join(tempDir, "server.crt")
	if err := os.WriteFile(serverCertPath, certsA.Server.CertPEM, 0644); err != nil {
		t.Fatalf("writing server.crt: %v", err)
	}
	serverKeyPath := filepath.Join(tempDir, "server.key")
	if err := os.WriteFile(serverKeyPath, certsA.Server.KeyPEM, 0600); err != nil {
		t.Fatalf("writing server.key: %v", err)
	}

	baseArgs := []string{
		"--listen=127.0.0.1:0",
		"--ca-cert=" + caPath,
		"--server-cert=" + serverCertPath,
		"--server-key=" + serverKeyPath,
	}

	t.Run("port set without prefix fails", func(t *testing.T) {
		args := append([]string{}, baseArgs...)
		args = append(args, "--wireguard-listen-port=51820")
		err := run(t.Context(), args)
		if err == nil || !strings.Contains(err.Error(), "--wireguard-prefix is required") {
			t.Fatalf("expected error about required prefix, got: %v", err)
		}
	})

	t.Run("IPv4 prefix fails", func(t *testing.T) {
		args := append([]string{}, baseArgs...)
		args = append(args, "--wireguard-listen-port=51820", "--wireguard-prefix=192.168.1.0/24")
		err := run(t.Context(), args)
		if err == nil || !strings.Contains(err.Error(), "must be an IPv6 prefix") {
			t.Fatalf("expected error about IPv6 prefix, got: %v", err)
		}
	})

	t.Run("non-64 IPv6 prefix fails", func(t *testing.T) {
		args := append([]string{}, baseArgs...)
		args = append(args, "--wireguard-listen-port=51820", "--wireguard-prefix=fd00::/48")
		err := run(t.Context(), args)
		if err == nil || !strings.Contains(err.Error(), "must be a /64 prefix") {
			t.Fatalf("expected error about /64 prefix, got: %v", err)
		}
	})

	t.Run("valid flags attempt device open and exit with package error without privileges", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("skipping test that expects WireGuard device creation to fail because process is privileged (running as root); a test should not create links on the host")
		}
		args := append([]string{}, baseArgs...)
		args = append(args, "--wireguard-listen-port=51820", "--wireguard-prefix=fd00::/64")
		err := run(t.Context(), args)
		if err == nil {
			t.Fatal("expected run to fail in unprivileged environment, got nil")
		}
		if !errors.Is(err, wireguard.ErrPermission) && !errors.Is(err, wireguard.ErrNotSupported) {
			t.Fatalf("expected wireguard.ErrPermission or wireguard.ErrNotSupported, got: %v", err)
		}
	})
}
