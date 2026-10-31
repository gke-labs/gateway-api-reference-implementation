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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/testserver"
	"github.com/prometheus/client_golang/prometheus"
)

func TestParseFlags_DefaultsAndCustom(t *testing.T) {
	// 1. Defaults
	cfg, err := parseFlags([]string{})
	if err != nil {
		t.Fatalf("parseFlags default failed: %v", err)
	}

	if cfg.DirectoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("unexpected directory URL: %s", cfg.DirectoryURL)
	}
	if cfg.ClusterDir != "" {
		t.Errorf("unexpected default cluster dir: %s", cfg.ClusterDir)
	}
	if cfg.ClusterDirPollInterval != 2*time.Second {
		t.Errorf("unexpected default cluster dir poll interval: %v", cfg.ClusterDirPollInterval)
	}
	if cfg.MaxHostnames != 100 {
		t.Errorf("unexpected max hostnames: %d", cfg.MaxHostnames)
	}
	if cfg.MaxPendingOrders != 50 {
		t.Errorf("unexpected max pending orders: %d", cfg.MaxPendingOrders)
	}
	if cfg.ChallengeListenAddr != ":8080" {
		t.Errorf("unexpected challenge listen addr: %s", cfg.ChallengeListenAddr)
	}
	if cfg.MetricsListenAddr != ":9090" {
		t.Errorf("unexpected metrics listen addr: %s", cfg.MetricsListenAddr)
	}
	if cfg.GRPCListenAddr != ":8443" {
		t.Errorf("unexpected grpc listen addr: %s", cfg.GRPCListenAddr)
	}
	if !cfg.ReleaseMode {
		t.Errorf("unexpected release mode: %v", cfg.ReleaseMode)
	}

	// 2. Custom
	customArgs := []string{
		"--directory-url=https://custom-acme.local/dir",
		"--eab-kid=custom-kid",
		"--eab-hmac-key-file=/tmp/custom-key-file",
		"--cache-dir=/tmp/custom-cache",
		"--challenge-listen-addr=:18080",
		"--metrics-listen-addr=:19090",
		"--grpc-listen-addr=:18443",
		"--tls-cert-file=/tmp/tls.crt",
		"--tls-key-file=/tmp/tls.key",
		"--cluster-config-file=/tmp/clusters.yaml",
		"--cluster-dir=/tmp/clusters",
		"--cluster-dir-poll-interval=500ms",
		"--release-mode=false",
		"--rate-limit-qps=5.5",
		"--rate-limit-burst=15",
		"--max-hostnames=20",
		"--max-pending-orders=10",
	}

	cfg, err = parseFlags(customArgs)
	if err != nil {
		t.Fatalf("parseFlags custom failed: %v", err)
	}

	if cfg.DirectoryURL != "https://custom-acme.local/dir" {
		t.Errorf("unexpected custom directory URL: %s", cfg.DirectoryURL)
	}
	if cfg.ClusterDir != "/tmp/clusters" {
		t.Errorf("unexpected custom cluster dir: %s", cfg.ClusterDir)
	}
	if cfg.ClusterDirPollInterval != 500*time.Millisecond {
		t.Errorf("unexpected custom cluster dir poll interval: %v", cfg.ClusterDirPollInterval)
	}
	if cfg.EABKID != "custom-kid" {
		t.Errorf("unexpected custom EAB KID: %s", cfg.EABKID)
	}
	if cfg.EABHMACKeyFile != "/tmp/custom-key-file" {
		t.Errorf("unexpected custom EAB HMAC key file: %s", cfg.EABHMACKeyFile)
	}
	if cfg.CacheDir != "/tmp/custom-cache" {
		t.Errorf("unexpected custom cache dir: %s", cfg.CacheDir)
	}
	if cfg.ChallengeListenAddr != ":18080" {
		t.Errorf("unexpected custom challenge addr: %s", cfg.ChallengeListenAddr)
	}
	if cfg.MetricsListenAddr != ":19090" {
		t.Errorf("unexpected custom metrics addr: %s", cfg.MetricsListenAddr)
	}
	if cfg.GRPCListenAddr != ":18443" {
		t.Errorf("unexpected custom grpc addr: %s", cfg.GRPCListenAddr)
	}
	if cfg.TLSCertFile != "/tmp/tls.crt" {
		t.Errorf("unexpected custom tls cert file: %s", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/tmp/tls.key" {
		t.Errorf("unexpected custom tls key file: %s", cfg.TLSKeyFile)
	}
	if cfg.ClusterConfigFile != "/tmp/clusters.yaml" {
		t.Errorf("unexpected custom cluster config file: %s", cfg.ClusterConfigFile)
	}
	if cfg.ReleaseMode != false {
		t.Errorf("unexpected custom release mode: %v", cfg.ReleaseMode)
	}
	if cfg.RateLimitQPS != 5.5 {
		t.Errorf("unexpected custom rate limit qps: %f", cfg.RateLimitQPS)
	}
	if cfg.RateLimitBurst != 15 {
		t.Errorf("unexpected custom rate limit burst: %d", cfg.RateLimitBurst)
	}
	if cfg.MaxHostnames != 20 {
		t.Errorf("unexpected custom max hostnames: %d", cfg.MaxHostnames)
	}
	if cfg.MaxPendingOrders != 10 {
		t.Errorf("unexpected custom max pending orders: %d", cfg.MaxPendingOrders)
	}
}

func waitForReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("error closing probe connection to %s: %v", addr, closeErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for server to be ready on %s", addr)
}

func TestRun_LifecycleWithPebble(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")

	chalLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for challenge addr failed: %v", err)
	}
	chalAddr := chalLn.Addr().String()
	if err := chalLn.Close(); err != nil {
		t.Fatalf("Close chalLn failed: %v", err)
	}

	metricsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for metrics addr failed: %v", err)
	}
	metricsAddr := metricsLn.Addr().String()
	if err := metricsLn.Close(); err != nil {
		t.Fatalf("Close metricsLn failed: %v", err)
	}

	cfg := &Config{
		DirectoryURL:        pebble.DirectoryURL,
		HTTPClient:          pebble.HTTPClient,
		CacheDir:            cacheDir,
		ChallengeListenAddr: chalAddr,
		MetricsListenAddr:   metricsAddr,
		MaxHostnames:        100,
		MaxPendingOrders:    50,
		PrometheusRegistry:  prometheus.NewRegistry(),
	}

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg)
	}()

	// Wait for readiness instead of sleep
	waitForReady(t, chalAddr)
	waitForReady(t, metricsAddr)

	// Trigger graceful shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for certserver run to shut down")
	}

	// Verify account key was saved to cache directory
	if _, err := os.Stat(filepath.Join(cacheDir, "account.key")); err != nil {
		t.Fatalf("expected account.key to be created in cache dir: %v", err)
	}
}

func buildTestJWKS(keys map[string]*rsa.PublicKey) []byte {
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwksDoc struct {
		Keys []jwk `json:"keys"`
	}

	var doc jwksDoc
	for kid, pub := range keys {
		eBytes := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		doc.Keys = append(doc.Keys, jwk{
			Kty: "RSA",
			Kid: kid,
			Alg: "RS256",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}
	data, _ := json.Marshal(doc)
	return data
}

func TestRunRegisterCluster_Subcommand(t *testing.T) {
	tempDir := t.TempDir()
	regDir := filepath.Join(tempDir, "clusters")

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks1 := buildTestJWKS(map[string]*rsa.PublicKey{"key-1": &key1.PublicKey})

	// 1. Successful registration via stdin
	var stdout, stderr bytes.Buffer
	args := []string{
		"--dir", regDir,
		"--cluster-id", "prod-1",
		"--issuer", "https://container.googleapis.com/v1/projects/my-proj/clusters/prod-1",
		"--allow", "*.example.com",
		"--allow", "app.example.com",
		"--controller-sa", "gcpgateway-system/gcpgateway-controller",
		"--jwks", "-",
	}

	if err := runRegisterCluster(args, bytes.NewReader(jwks1), &stdout, &stderr); err != nil {
		t.Fatalf("runRegisterCluster failed: %v", err)
	}

	clusterDir := filepath.Join(regDir, "prod-1")
	dirInfo, err := os.Stat(clusterDir)
	if err != nil {
		t.Fatalf("cluster directory not created: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("expected cluster directory mode 0700, got %o", dirInfo.Mode().Perm())
	}

	jwksFile := filepath.Join(clusterDir, "jwks.json")
	jwksInfo, err := os.Stat(jwksFile)
	if err != nil {
		t.Fatalf("jwks.json not created: %v", err)
	}
	if jwksInfo.Mode().Perm() != 0600 {
		t.Errorf("expected jwks.json mode 0600, got %o", jwksInfo.Mode().Perm())
	}

	clusterFile := filepath.Join(clusterDir, "cluster.json")
	clusterInfo, err := os.Stat(clusterFile)
	if err != nil {
		t.Fatalf("cluster.json not created: %v", err)
	}
	if clusterInfo.Mode().Perm() != 0600 {
		t.Errorf("expected cluster.json mode 0600, got %o", clusterInfo.Mode().Perm())
	}

	clusterBytes, err := os.ReadFile(clusterFile)
	if err != nil {
		t.Fatal(err)
	}
	var clusterCfg registry.ClusterConfig
	if err := json.Unmarshal(clusterBytes, &clusterCfg); err != nil {
		t.Fatalf("parsing cluster.json: %v", err)
	}
	if clusterCfg.ClusterID != "prod-1" {
		t.Errorf("expected ClusterID prod-1, got %s", clusterCfg.ClusterID)
	}
	if len(clusterCfg.AllowedHostnames) != 2 || clusterCfg.AllowedHostnames[0] != "*.example.com" {
		t.Errorf("unexpected AllowedHostnames: %v", clusterCfg.AllowedHostnames)
	}

	// 2. Key rotation: run again with updated JWKS from file
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks2 := buildTestJWKS(map[string]*rsa.PublicKey{
		"key-1": &key1.PublicKey,
		"key-2": &key2.PublicKey,
	})
	jwksFilePath := filepath.Join(tempDir, "new-jwks.json")
	if err := os.WriteFile(jwksFilePath, jwks2, 0600); err != nil {
		t.Fatal(err)
	}

	argsRotate := []string{
		"--dir", regDir,
		"--cluster-id", "prod-1",
		"--issuer", "https://container.googleapis.com/v1/projects/my-proj/clusters/prod-1",
		"--allow", "*.example.com,app.example.com",
		"--jwks", jwksFilePath,
	}
	if err := runRegisterCluster(argsRotate, nil, &stdout, &stderr); err != nil {
		t.Fatalf("runRegisterCluster key rotation failed: %v", err)
	}

	rotatedJWKSBytes, err := os.ReadFile(jwksFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rotatedJWKSBytes), "key-2") {
		t.Errorf("expected rotated JWKS to contain key-2, got:\n%s", string(rotatedJWKSBytes))
	}

	// 3. Validation failure modes
	testCases := []struct {
		name    string
		args    []string
		stdin   []byte
		wantErr string
	}{
		{
			name:    "missing dir",
			args:    []string{"--cluster-id", "p", "--issuer", "https://i", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "--dir is required",
		},
		{
			name:    "missing cluster-id",
			args:    []string{"--dir", regDir, "--issuer", "https://i", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "--cluster-id is required",
		},
		{
			name:    "missing issuer",
			args:    []string{"--dir", regDir, "--cluster-id", "p", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "--issuer is required",
		},
		{
			name:    "non-https issuer",
			args:    []string{"--dir", regDir, "--cluster-id", "p", "--issuer", "http://insecure", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "--issuer must use HTTPS",
		},
		{
			name:    "invalid JWKS JSON",
			args:    []string{"--dir", regDir, "--cluster-id", "p", "--issuer", "https://i", "--jwks", "-"},
			stdin:   []byte("not json"),
			wantErr: "invalid JWKS",
		},
		{
			name:    "JWKS with no usable keys",
			args:    []string{"--dir", regDir, "--cluster-id", "p", "--issuer", "https://i", "--jwks", "-"},
			stdin:   []byte(`{"keys":[]}`),
			wantErr: "no usable keys",
		},
		{
			name:    "path traversal in cluster-id",
			args:    []string{"--dir", regDir, "--cluster-id", "../../traversal", "--issuer", "https://i", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "invalid --cluster-id",
		},
		{
			name:    "invalid allow hostname",
			args:    []string{"--dir", regDir, "--cluster-id", "p", "--issuer", "https://i", "--allow", "*", "--jwks", "-"},
			stdin:   jwks1,
			wantErr: "invalid hostname pattern",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRegisterCluster(tc.args, bytes.NewReader(tc.stdin), nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestRun_RegisterClusterLiveReloadIntegration(t *testing.T) {
	pebble := testserver.StartPebble(t, testserver.ServerConfig{})
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	regDir := filepath.Join(tempDir, "clusters")

	chalLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for challenge addr failed: %v", err)
	}
	chalAddr := chalLn.Addr().String()
	_ = chalLn.Close()

	metricsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for metrics addr failed: %v", err)
	}
	metricsAddr := metricsLn.Addr().String()
	_ = metricsLn.Close()

	cfg := &Config{
		DirectoryURL:           pebble.DirectoryURL,
		HTTPClient:             pebble.HTTPClient,
		CacheDir:               cacheDir,
		ChallengeListenAddr:    chalAddr,
		MetricsListenAddr:      metricsAddr,
		ClusterDir:             regDir,
		ClusterDirPollInterval: 50 * time.Millisecond,
		MaxHostnames:           100,
		MaxPendingOrders:       50,
		PrometheusRegistry:     prometheus.NewRegistry(),
	}

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg)
	}()

	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("run failed immediately: %v", err)
	default:
	}

	waitForReady(t, chalAddr)
	waitForReady(t, metricsAddr)

	// Register cluster dynamically while certserver is running
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksData := buildTestJWKS(map[string]*rsa.PublicKey{"key-1": &key1.PublicKey})

	args := []string{
		"--dir", regDir,
		"--cluster-id", "live-cluster",
		"--issuer", "https://container.googleapis.com/v1/projects/live/clusters/live-cluster",
		"--allow", "*.live.example.com",
		"--jwks", "-",
	}
	if err := runRegisterCluster(args, bytes.NewReader(jwksData), nil, nil); err != nil {
		t.Fatalf("runRegisterCluster failed: %v", err)
	}

	// Wait for background reload to scan and process the directory
	time.Sleep(200 * time.Millisecond)

	// Verify cluster files were created
	if _, err := os.Stat(filepath.Join(regDir, "live-cluster", "cluster.json")); err != nil {
		t.Fatalf("expected cluster.json to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(regDir, "live-cluster", "jwks.json")); err != nil {
		t.Fatalf("expected jwks.json to exist: %v", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for certserver shutdown")
	}
}
