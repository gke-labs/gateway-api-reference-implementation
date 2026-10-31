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
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	acmeclient "github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/acme"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/audit"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/manager"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/server"
)

type Config struct {
	DirectoryURL           string
	EABKID                 string
	EABHMACKeyFile         string
	CacheDir               string
	ChallengeListenAddr    string
	MetricsListenAddr      string
	GRPCListenAddr         string
	TLSCertFile            string
	TLSKeyFile             string
	TLSConfig              *tls.Config
	ClusterConfigFile      string
	ClusterDir             string
	ClusterDirPollInterval time.Duration
	ReleaseMode            bool
	RateLimitQPS           float64
	RateLimitBurst         int
	MaxHostnames           int
	MaxPendingOrders       int64
	HTTPClient             *http.Client
	PrometheusRegistry     *prometheus.Registry
}

func parseFlags(args []string) (*Config, error) {
	fs := flag.NewFlagSet("certserver", flag.ContinueOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.DirectoryURL, "directory-url", "https://acme-v02.api.letsencrypt.org/directory", "ACME directory URL")
	fs.StringVar(&cfg.EABKID, "eab-kid", "", "External Account Binding Key Identifier (KID)")
	fs.StringVar(&cfg.EABHMACKeyFile, "eab-hmac-key-file", "", "Path to file containing External Account Binding HMAC key")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "/var/cache/certserver", "Directory path for certificate and key disk cache")
	fs.StringVar(&cfg.ChallengeListenAddr, "challenge-listen-addr", ":8080", "HTTP listen address for /.well-known/acme-challenge/")
	fs.StringVar(&cfg.MetricsListenAddr, "metrics-listen-addr", ":9090", "HTTP listen address for Prometheus metrics")
	fs.StringVar(&cfg.GRPCListenAddr, "grpc-listen-addr", ":8443", "gRPC listen address for GetCertificate API (TLS)")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert-file", "", "Path to TLS server certificate for gRPC endpoint")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key-file", "", "Path to TLS private key for gRPC endpoint")
	fs.StringVar(&cfg.ClusterConfigFile, "cluster-config-file", "", "Path to cluster registry server configuration file (YAML/JSON)")
	fs.StringVar(&cfg.ClusterDir, "cluster-dir", "", "Path to cluster registration directory containing per-cluster subdirectories")
	fs.DurationVar(&cfg.ClusterDirPollInterval, "cluster-dir-poll-interval", 2*time.Second, "Polling interval for rescanning cluster registration directory")
	fs.BoolVar(&cfg.ReleaseMode, "release-mode", true, "Whether to release private keys to controllers (phase 1)")
	fs.Float64Var(&cfg.RateLimitQPS, "rate-limit-qps", 10.0, "Per-identity rate limit (requests per second)")
	fs.IntVar(&cfg.RateLimitBurst, "rate-limit-burst", 20, "Per-identity rate limit burst size")
	fs.IntVar(&cfg.MaxHostnames, "max-hostnames", 100, "Maximum number of hostnames permitted per certificate set")
	fs.Int64Var(&cfg.MaxPendingOrders, "max-pending-orders", 50, "Maximum number of concurrent pending ACME orders")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return cfg, nil
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			*s = append(*s, trimmed)
		}
	}
	return nil
}

type registerClusterConfig struct {
	Dir                 string
	ClusterID           string
	Issuer              string
	JWKSPath            string
	AllowPatterns       stringSliceFlag
	DenyPatterns        stringSliceFlag
	ControllerSA        string
	ControllerNamespace string
	SharedFrontendGroup string
}

func runRegisterCluster(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("register-cluster", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg registerClusterConfig

	fs.StringVar(&cfg.Dir, "dir", "", "Path to cluster registration directory (required)")
	fs.StringVar(&cfg.ClusterID, "cluster-id", "", "Cluster identifier (required)")
	fs.StringVar(&cfg.Issuer, "issuer", "", "Cluster OIDC issuer URL (required, must start with https://)")
	fs.StringVar(&cfg.JWKSPath, "jwks", "", "Path to JWKS JSON file, or '-' to read from stdin (required)")
	fs.Var(&cfg.AllowPatterns, "allow", "Allowed hostname pattern (can be repeated or comma-separated)")
	fs.Var(&cfg.DenyPatterns, "deny", "Denied hostname pattern (can be repeated or comma-separated)")
	fs.StringVar(&cfg.ControllerSA, "controller-sa", "", "Allowed controller service account identity")
	fs.StringVar(&cfg.ControllerNamespace, "controller-namespace", "", "Allowed controller namespace")
	fs.StringVar(&cfg.SharedFrontendGroup, "shared-frontend-group", "", "Shared front-end group name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg.Dir = strings.TrimSpace(cfg.Dir)
	if cfg.Dir == "" {
		return errors.New("--dir is required")
	}

	cfg.ClusterID = strings.TrimSpace(cfg.ClusterID)
	if cfg.ClusterID == "" {
		return errors.New("--cluster-id is required")
	}
	if err := registry.ValidateClusterID(cfg.ClusterID); err != nil {
		return fmt.Errorf("invalid --cluster-id: %w", err)
	}

	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	if cfg.Issuer == "" {
		return errors.New("--issuer is required")
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") {
		return fmt.Errorf("--issuer must use HTTPS: %q", cfg.Issuer)
	}

	cfg.JWKSPath = strings.TrimSpace(cfg.JWKSPath)
	if cfg.JWKSPath == "" {
		return errors.New("--jwks is required (path to file or '-')")
	}

	// 1. Read JWKS data
	var jwksBytes []byte
	const maxJWKSBytes = 1024 * 1024 // 1 MiB limit
	if cfg.JWKSPath == "-" {
		if stdin == nil {
			return errors.New("cannot read JWKS from nil stdin")
		}
		data, err := io.ReadAll(io.LimitReader(stdin, maxJWKSBytes+1))
		if err != nil {
			return fmt.Errorf("reading JWKS from stdin: %w", err)
		}
		if len(data) > maxJWKSBytes {
			return errors.New("JWKS from stdin exceeds 1 MiB limit")
		}
		jwksBytes = data
	} else {
		f, err := os.Open(cfg.JWKSPath)
		if err != nil {
			return fmt.Errorf("opening JWKS file %s: %w", cfg.JWKSPath, err)
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				log.Printf("warning: closing %s: %v", cfg.JWKSPath, closeErr)
			}
		}()
		data, err := io.ReadAll(io.LimitReader(f, maxJWKSBytes+1))
		if err != nil {
			return fmt.Errorf("reading JWKS file %s: %w", cfg.JWKSPath, err)
		}
		if len(data) > maxJWKSBytes {
			return fmt.Errorf("JWKS file %s exceeds 1 MiB limit", cfg.JWKSPath)
		}
		jwksBytes = data
	}

	if len(bytes.TrimSpace(jwksBytes)) == 0 {
		return errors.New("JWKS payload is empty")
	}

	// 2. Validate JWKS has at least one usable key
	parsedKeys, err := jwt.ParseJWKS(jwksBytes)
	if err != nil {
		return fmt.Errorf("invalid JWKS: %w", err)
	}
	if len(parsedKeys) == 0 {
		return errors.New("JWKS contains no usable keys")
	}

	// 3. Build and validate cluster config
	clusterCfg := registry.ClusterConfig{
		ClusterID:                cfg.ClusterID,
		IssuerURL:                cfg.Issuer,
		ControllerServiceAccount: strings.TrimSpace(cfg.ControllerSA),
		ControllerNamespace:      strings.TrimSpace(cfg.ControllerNamespace),
		AllowedHostnames:         cfg.AllowPatterns,
		DeniedHostnames:          cfg.DenyPatterns,
		SharedFrontEndGroup:      strings.TrimSpace(cfg.SharedFrontendGroup),
	}
	if err := clusterCfg.Validate(); err != nil {
		return fmt.Errorf("invalid cluster configuration: %w", err)
	}

	// 4. Ensure target directory exists (mode 0700)
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return fmt.Errorf("creating directory %s: %w", cfg.Dir, err)
	}
	if err := os.Chmod(cfg.Dir, 0700); err != nil {
		log.Printf("warning: setting permissions on %s: %v", cfg.Dir, err)
	}

	clusterDir := filepath.Join(cfg.Dir, cfg.ClusterID)
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return fmt.Errorf("creating cluster directory %s: %w", clusterDir, err)
	}
	if err := os.Chmod(clusterDir, 0700); err != nil {
		log.Printf("warning: setting permissions on %s: %v", clusterDir, err)
	}

	// 5. Atomically write jwks.json
	tmpJWKS, err := os.CreateTemp(clusterDir, ".jwks.json.*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file for JWKS: %w", err)
	}
	tmpJWKSName := tmpJWKS.Name()
	defer func() {
		if tmpJWKSName != "" {
			if rmErr := os.Remove(tmpJWKSName); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("warning: removing %s: %v", tmpJWKSName, rmErr)
			}
		}
	}()

	if _, err := tmpJWKS.Write(jwksBytes); err != nil {
		return errors.Join(fmt.Errorf("writing temp JWKS: %w", err), tmpJWKS.Close())
	}
	if err := tmpJWKS.Sync(); err != nil {
		return errors.Join(fmt.Errorf("syncing temp JWKS: %w", err), tmpJWKS.Close())
	}
	if err := tmpJWKS.Close(); err != nil {
		return fmt.Errorf("closing temp JWKS: %w", err)
	}
	if err := os.Chmod(tmpJWKSName, 0600); err != nil {
		return fmt.Errorf("setting permissions on temp JWKS: %w", err)
	}

	targetJWKS := filepath.Join(clusterDir, "jwks.json")
	if err := os.Rename(tmpJWKSName, targetJWKS); err != nil {
		return fmt.Errorf("renaming temp JWKS to %s: %w", targetJWKS, err)
	}
	tmpJWKSName = ""

	// 6. Atomically write cluster.json after jwks.json.
	// The directory scanner tolerates the in-between state:
	// - For a new cluster registration, if jwks.json lands first without cluster.json,
	//   the scanner considers the registration incomplete and waits for cluster.json.
	// - When rotating keys on an existing cluster, the new keys activate as soon as
	//   jwks.json lands (using the existing cluster.json), providing immediate, zero-downtime
	//   key availability; cluster.json settings are then refreshed once renamed.
	clusterBytes, err := json.MarshalIndent(clusterCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cluster config: %w", err)
	}
	clusterBytes = append(clusterBytes, '\n')

	tmpCluster, err := os.CreateTemp(clusterDir, ".cluster.json.*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file for cluster config: %w", err)
	}
	tmpClusterName := tmpCluster.Name()
	defer func() {
		if tmpClusterName != "" {
			if rmErr := os.Remove(tmpClusterName); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("warning: removing %s: %v", tmpClusterName, rmErr)
			}
		}
	}()

	if _, err := tmpCluster.Write(clusterBytes); err != nil {
		return errors.Join(fmt.Errorf("writing temp cluster config: %w", err), tmpCluster.Close())
	}
	if err := tmpCluster.Sync(); err != nil {
		return errors.Join(fmt.Errorf("syncing temp cluster config: %w", err), tmpCluster.Close())
	}
	if err := tmpCluster.Close(); err != nil {
		return fmt.Errorf("closing temp cluster config: %w", err)
	}
	if err := os.Chmod(tmpClusterName, 0600); err != nil {
		return fmt.Errorf("setting permissions on temp cluster config: %w", err)
	}

	targetCluster := filepath.Join(clusterDir, "cluster.json")
	if err := os.Rename(tmpClusterName, targetCluster); err != nil {
		return fmt.Errorf("renaming temp cluster config to %s: %w", targetCluster, err)
	}
	tmpClusterName = ""

	// 7. Durability: fsync the cluster directory to persist directory entry renames.
	dirFile, err := os.Open(clusterDir)
	if err != nil {
		log.Printf("warning: opening directory %s for sync: %v", clusterDir, err)
	} else {
		if syncErr := dirFile.Sync(); syncErr != nil {
			log.Printf("warning: syncing directory %s: %v", clusterDir, syncErr)
		}
		if closeErr := dirFile.Close(); closeErr != nil {
			log.Printf("warning: closing directory %s: %v", clusterDir, closeErr)
		}
	}

	if stdout != nil {
		if _, err := fmt.Fprintf(stdout, "Cluster %q registered successfully in %s\n", cfg.ClusterID, clusterDir); err != nil {
			log.Printf("warning: writing to stdout: %v", err)
		}
	}
	return nil
}

func run(ctx context.Context, cfg *Config) error {
	logger := log.New(os.Stdout, "certserver: ", log.LstdFlags)
	logger.Printf("Starting certserver with directory %s and cache %s", cfg.DirectoryURL, cfg.CacheDir)

	// Resolve EAB HMAC key from file or environment variable
	var eabHMACKey string
	if cfg.EABHMACKeyFile != "" {
		keyBytes, err := os.ReadFile(cfg.EABHMACKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read EAB HMAC key file: %w", err)
		}
		eabHMACKey = strings.TrimSpace(string(keyBytes))
	} else if envKey := os.Getenv("EAB_HMAC_KEY"); envKey != "" {
		eabHMACKey = strings.TrimSpace(envKey)
	}

	// Initialize Disk Cache
	diskCache, err := cache.NewDiskCache(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize disk cache: %w", err)
	}

	// Load or generate ACME account key from cache directory
	accountKey, err := diskCache.LoadOrGenerateAccountKey()
	if err != nil {
		return fmt.Errorf("failed to load or generate account key: %w", err)
	}

	// Initialize Prometheus Metrics
	var promReg prometheus.Registerer = prometheus.DefaultRegisterer
	var promGatherer prometheus.Gatherer = prometheus.DefaultGatherer
	if cfg.PrometheusRegistry != nil {
		promReg = cfg.PrometheusRegistry
		promGatherer = cfg.PrometheusRegistry
	}
	m := metrics.New(promReg)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(promGatherer, promhttp.HandlerOpts{}))
	metricsServer := &http.Server{
		Addr:    cfg.MetricsListenAddr,
		Handler: metricsMux,
	}

	// Initialize BindingStore and AuditLogger
	bindingStore := registry.NewMemoryBindingStore()
	auditLogger := registry.NewAuditLogger(os.Stdout)

	// Load cluster registry if configured
	var clusterReg *registry.Registry
	if cfg.ClusterConfigFile != "" || cfg.ClusterDir != "" {
		var initialClusters []registry.ClusterConfig
		if cfg.ClusterConfigFile != "" {
			serverCfg, err := registry.LoadServerConfigFile(cfg.ClusterConfigFile)
			if err != nil {
				return fmt.Errorf("failed to load cluster config file %s: %w", cfg.ClusterConfigFile, err)
			}
			initialClusters = serverCfg.Clusters
		}

		var regOpts []registry.Option
		regOpts = append(regOpts,
			registry.WithHTTPClient(cfg.HTTPClient),
			registry.WithAuditLogger(auditLogger),
		)
		if cfg.ClusterDir != "" {
			regOpts = append(regOpts,
				registry.WithRegistrationDir(cfg.ClusterDir),
				registry.WithPollInterval(cfg.ClusterDirPollInterval),
			)
		}

		clusterReg, err = registry.NewRegistry(initialClusters, regOpts...)
		if err != nil {
			return fmt.Errorf("failed to initialize cluster registry: %w", err)
		}
		defer func() {
			if err := clusterReg.Close(); err != nil {
				logger.Printf("error closing cluster registry: %v", err)
			}
		}()
	}

	// Initialize Challenge Store and HTTP Handler
	challengeStore := challenge.NewMemoryStore()
	var chalOpts []challenge.HandlerOption
	if clusterReg != nil {
		chalOpts = append(chalOpts,
			challenge.WithRegistry(clusterReg),
			challenge.WithBindingStore(bindingStore),
			challenge.WithAuditLogger(auditLogger),
			challenge.WithMetrics(m),
		)
	}
	challengeHandler := challenge.NewHandler(challengeStore, chalOpts...)

	var challengeHTTPHandler http.Handler = challengeHandler
	if auditLogger != nil {
		challengeHTTPHandler = audit.WrapHTTP(auditLogger, challengeHandler)
	}

	challengeServer := &http.Server{
		Addr:    cfg.ChallengeListenAddr,
		Handler: challengeHTTPHandler,
	}

	// Initialize ACME Client
	acmeCli, err := acmeclient.NewClient(ctx, acmeclient.Config{
		DirectoryURL: cfg.DirectoryURL,
		EABKID:       cfg.EABKID,
		EABHMACKey:   eabHMACKey,
		AccountKey:   accountKey,
		HTTPClient:   cfg.HTTPClient,
		UserAgent:    "gari-certserver/1.0",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize ACME client: %w", err)
	}

	// Initialize Certificate Manager
	mgr := manager.NewManager(acmeCli, diskCache, challengeStore, m, func(o *manager.Options) {
		o.MaxHostnamesPerSet = cfg.MaxHostnames
		o.MaxPendingOrders = cfg.MaxPendingOrders
		o.BindingStore = bindingStore
	})

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start certificate manager: %w", err)
	}
	defer mgr.Stop()

	// Initialize and start gRPC server if cluster config is provided
	var grpcSrv *server.Server
	if clusterReg != nil {
		if (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") && cfg.TLSConfig == nil {
			logger.Println("Warning: gRPC endpoint disabled (tls-cert-file and tls-key-file required)")
		} else {
			srvOpts := server.Options{
				ListenAddr:        cfg.GRPCListenAddr,
				TLSCertFile:       cfg.TLSCertFile,
				TLSKeyFile:        cfg.TLSKeyFile,
				TLSConfig:         cfg.TLSConfig,
				ReleaseMode:       cfg.ReleaseMode,
				MaxHostnames:      cfg.MaxHostnames,
				MaxHostnameLength: 253,
				RateLimitQPS:      rate.Limit(cfg.RateLimitQPS),
				RateLimitBurst:    cfg.RateLimitBurst,
			}

			grpcSrv, err = server.NewServer(srvOpts, clusterReg, mgr, bindingStore, auditLogger)
			if err != nil {
				return fmt.Errorf("failed to create gRPC server: %w", err)
			}

			if err := grpcSrv.Start(ctx); err != nil {
				return fmt.Errorf("failed to start gRPC server: %w", err)
			}
			defer grpcSrv.Stop()
			logger.Printf("Serving gRPC GetCertificate API on %s", grpcSrv.Addr())
		}
	}

	// Start HTTP servers in background
	go func() {
		logger.Printf("Serving ACME HTTP-01 challenges on %s", cfg.ChallengeListenAddr)
		if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("Challenge server error: %v", err)
		}
	}()

	go func() {
		logger.Printf("Serving Prometheus metrics on %s/metrics", cfg.MetricsListenAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("Metrics server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Println("Shutting down certserver...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := challengeServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("Challenge server shutdown error: %v", err)
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("Metrics server shutdown error: %v", err)
	}

	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "register-cluster" {
		if err := runRegisterCluster(os.Args[2:], os.Stdin, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "error registering cluster: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatalf("certserver error: %v", err)
	}
}
