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
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/audit"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/manager"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

// Options configures the CertificateService gRPC server.
type Options struct {
	ListenAddr        string
	TLSCertFile       string
	TLSKeyFile        string
	TLSConfig         *tls.Config
	ReleaseMode       bool       // If true, returns private keys in GetCertificate responses (phase 1)
	MaxHostnames      int        // Maximum hostnames allowed per request (e.g. 100)
	MaxHostnameLength int        // Maximum length of a single hostname (e.g. 253)
	RateLimitQPS      rate.Limit // Per-identity rate limit (queries per second)
	RateLimitBurst    int        // Per-identity burst size
	LookupIP          func(ctx context.Context, host string) ([]net.IP, error)
}

// Server implements certserverv1.CertificateServiceServer.
type Server struct {
	certserverv1.UnimplementedCertificateServiceServer

	opts         Options
	registry     *registry.Registry
	mgr          *manager.Manager
	bindingStore registry.BindingStore
	auditLogger  *registry.AuditLogger
	rateLimiter  *registry.IdentityRateLimiter

	// mu guards listener, grpcServer, and closed.
	mu         sync.Mutex
	listener   net.Listener
	grpcServer *grpc.Server
	closed     bool
}

// NewServer creates a new gRPC Server instance.
func NewServer(
	opts Options,
	reg *registry.Registry,
	mgr *manager.Manager,
	bindingStore registry.BindingStore,
	auditLogger *registry.AuditLogger,
) (*Server, error) {
	if reg == nil {
		return nil, errors.New("registry cannot be nil")
	}
	if mgr == nil {
		return nil, errors.New("manager cannot be nil")
	}
	if bindingStore == nil {
		bindingStore = registry.NewMemoryBindingStore()
	}
	if auditLogger == nil {
		auditLogger = registry.NewAuditLogger(nil)
	}

	if opts.MaxHostnames <= 0 {
		opts.MaxHostnames = 100
	}
	if opts.MaxHostnameLength <= 0 {
		opts.MaxHostnameLength = 253
	}
	if opts.LookupIP == nil {
		opts.LookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}

	limiter := registry.NewIdentityRateLimiter(opts.RateLimitQPS, opts.RateLimitBurst)

	return &Server{
		opts:         opts,
		registry:     reg,
		mgr:          mgr,
		bindingStore: bindingStore,
		auditLogger:  auditLogger,
		rateLimiter:  limiter,
	}, nil
}

// Start binds to the configured listen address, configures TLS, and starts serving gRPC requests.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("server already closed")
	}

	// 1. Configure TLS
	tlsCfg := s.opts.TLSConfig
	if tlsCfg == nil {
		if s.opts.TLSCertFile == "" || s.opts.TLSKeyFile == "" {
			return errors.New("either TLSConfig or both TLSCertFile and TLSKeyFile must be provided")
		}
		cert, err := tls.LoadX509KeyPair(s.opts.TLSCertFile, s.opts.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS server key pair: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	creds := credentials.NewTLS(tlsCfg)

	// 2. Listen on address
	lis, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.opts.ListenAddr, err)
	}
	s.listener = lis

	// 3. Create gRPC server with interceptors and register service
	grpcOpts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			AuditUnaryInterceptor(s.auditLogger),
			AuthUnaryInterceptor(s.registry),
		),
		grpc.ChainStreamInterceptor(
			AuditStreamInterceptor(s.auditLogger),
			AuthStreamInterceptor(s.registry),
		),
	}
	s.grpcServer = grpc.NewServer(grpcOpts...)
	certserverv1.RegisterCertificateServiceServer(s.grpcServer, s)

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			log.Printf("certserver gRPC serve error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("certserver: error closing listener: %v", err)
		}
	}
}

// Addr returns the listener's network address, or empty string if not running.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// BindingStore returns the active Gateway binding store.
func (s *Server) BindingStore() registry.BindingStore {
	return s.bindingStore
}

// GetCertificate implements certserverv1.CertificateServiceServer.
func (s *Server) GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest) (*certserverv1.GetCertificateResponse, error) {
	gateway := strings.TrimSpace(req.GetGateway())
	dataPlaneSA := strings.TrimSpace(req.GetDataPlaneServiceAccount())
	rawHostnames := req.GetHostnames()

	// 1. Retrieve verified caller identity from context (placed by Auth interceptor)
	identity, ok := CallerIdentityFromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "unauthenticated")
	}

	cluster, ok := ClusterConfigFromContext(ctx)
	if !ok || cluster == nil {
		var found bool
		cluster, found = s.registry.GetCluster(identity.ClusterID)
		if !found || cluster == nil {
			audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, fmt.Sprintf("cluster %q not found", identity.ClusterID))
			return nil, status.Errorf(codes.PermissionDenied, "cluster %q not found", identity.ClusterID)
		}
	}

	// 2. Enforce per-identity rate limits
	if !s.rateLimiter.Allow(identity) {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, "per-identity rate limit exceeded")
		return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for identity %s", identity)
	}

	// 3. Authorize caller as the cluster's designated GARI controller
	if !registry.IsAuthorizedController(cluster, identity) {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, fmt.Sprintf("caller %s is not an authorized controller for cluster %s", identity, cluster.ClusterID))
		return nil, status.Errorf(codes.PermissionDenied, "caller %s is not an authorized controller for cluster %s", identity, cluster.ClusterID)
	}

	// 4. Validate Gateway, DataPlane SA, and hostnames arguments
	if gateway == "" {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, "gateway parameter is required")
		return nil, status.Errorf(codes.InvalidArgument, "gateway parameter is required")
	}
	if dataPlaneSA == "" {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, "data_plane_service_account parameter is required")
		return nil, status.Errorf(codes.InvalidArgument, "data_plane_service_account parameter is required")
	}
	if len(rawHostnames) == 0 {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, "no hostnames provided")
		return nil, status.Errorf(codes.InvalidArgument, "no hostnames provided")
	}

	// 5. Normalize hostnames using the shared manager normaliser
	normalized, hostnamesKey, err := manager.NormalizeHostnames(rawHostnames, s.opts.MaxHostnames, s.opts.MaxHostnameLength)
	if err != nil {
		audit.FromContext(ctx).Set(gateway, rawHostnames, audit.DecisionRefused, fmt.Sprintf("hostname normalization failed: %v", err))
		return nil, status.Errorf(codes.InvalidArgument, "invalid hostnames: %v", err)
	}

	// 6. Check per-cluster hostname policy (allow / deny lists)
	if err := registry.CheckHostnamesPolicy(cluster, normalized); err != nil {
		audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionRefused, fmt.Sprintf("policy refused: %v", err))
		return nil, status.Errorf(codes.PermissionDenied, "hostname policy refused: %v", err)
	}

	requester := challenge.Requester{
		ClusterID:               cluster.ClusterID,
		Gateway:                 gateway,
		DataPlaneServiceAccount: dataPlaneSA,
		HostnamesKey:            hostnamesKey,
	}

	// 7. Check certificate cache via manager interface
	now := time.Now()
	certData, err := s.mgr.GetCertificate(hostnamesKey, s.opts.ReleaseMode)
	if err == nil && certData != nil {
		// Cache hit! Check if this Gateway has passed its own binding check for these hostnames
		if s.bindingStore.HasValidatedBinding(cluster.ClusterID, gateway, hostnamesKey, now) {
			s.bindingStore.RecordBinding(registry.Binding{
				ClusterID:               cluster.ClusterID,
				Gateway:                 gateway,
				DataPlaneServiceAccount: dataPlaneSA,
				Hostnames:               normalized,
				RecordedAt:              now,
			})

			audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionAllowed, "certificate returned from cache")

			return &certserverv1.GetCertificateResponse{
				CertificateChain: certData.CertificateChain,
				PrivateKey:       certData.PrivateKey,
				Challenges:       s.mgr.GetPendingChallenges(ctx, requester),
			}, nil
		}

		// Second requester / unvalidated gateway attempting to access cached certificate
		// Run address check before RecordBinding so that requests failing the check leave no binding behind.
		if err := s.checkAttestedAddresses(ctx, normalized, req.GetAddresses()); err != nil {
			audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionRefused, fmt.Sprintf("address check failed: %v", err))
			return nil, status.Errorf(codes.FailedPrecondition, "address check failed: %v", err)
		}

		s.bindingStore.RecordBinding(registry.Binding{
			ClusterID:               cluster.ClusterID,
			Gateway:                 gateway,
			DataPlaneServiceAccount: dataPlaneSA,
			Hostnames:               normalized,
			RecordedAt:              now,
		})

		audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionRefused, "cached certificate requires binding validation for this gateway")

		// Trigger revalidation for this requester to validate its domain control
		if _, revalErr := s.mgr.EnsureRevalidation(ctx, normalized, requester); revalErr != nil {
			log.Printf("certserver: failed to initiate revalidation for %s: %v", hostnamesKey, revalErr)
		}

		return &certserverv1.GetCertificateResponse{
			Challenges: s.mgr.GetPendingChallenges(ctx, requester),
		}, nil
	}

	if !errors.Is(err, cache.ErrNotFound) {
		log.Printf("certserver: error reading certificate from cache for %s: %v", hostnamesKey, err)
		audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionRefused, fmt.Sprintf("failed to read certificate from cache: %v", err))
		return nil, status.Errorf(codes.Internal, "internal error retrieving certificate")
	}

	// 8. Cache miss: record Gateway binding and start issuance only if none in flight, passing requester binding info
	s.bindingStore.RecordBinding(registry.Binding{
		ClusterID:               cluster.ClusterID,
		Gateway:                 gateway,
		DataPlaneServiceAccount: dataPlaneSA,
		Hostnames:               normalized,
		RecordedAt:              now,
	})
	if _, err := s.mgr.EnsureIssuance(ctx, normalized, requester); err != nil {
		log.Printf("certserver: failed to initiate issuance for %s: %v", hostnamesKey, err)
	}

	audit.FromContext(ctx).Set(gateway, normalized, audit.DecisionAllowed, "certificate issuance in progress; returning pending challenges")

	return &certserverv1.GetCertificateResponse{
		Challenges: s.mgr.GetPendingChallenges(ctx, requester),
	}, nil
}

// maxAttestedAddresses is the maximum number of attested addresses accepted in a request.
// Bounding the addresses prevents excessive DNS lookups and comparisons.
const maxAttestedAddresses = 16

// checkAttestedAddresses resolves each requested hostname through public DNS and verifies that at
// least one resolved IP is among the Gateway's attested addresses from the request.
// Because the addresses come from the requester, this check filters requests early and the probe is the proof.
func (s *Server) checkAttestedAddresses(ctx context.Context, hostnames []string, attestedAddresses []string) error {
	if len(attestedAddresses) == 0 {
		return errors.New("no attested addresses provided in request")
	}
	if len(attestedAddresses) > maxAttestedAddresses {
		return fmt.Errorf("attested addresses count %d exceeds maximum allowed (%d)", len(attestedAddresses), maxAttestedAddresses)
	}

	attestedIPs := make([]net.IP, 0, len(attestedAddresses))
	for _, address := range attestedAddresses {
		if ip := net.ParseIP(strings.TrimSpace(address)); ip != nil {
			attestedIPs = append(attestedIPs, ip)
		}
	}
	if len(attestedIPs) == 0 {
		return errors.New("no valid IP addresses in attested addresses")
	}

	for _, hostname := range hostnames {
		resolvedIPs, err := s.opts.LookupIP(ctx, hostname)
		if err != nil {
			return fmt.Errorf("resolving hostname %q: %w", hostname, err)
		}
		if len(resolvedIPs) == 0 {
			return fmt.Errorf("hostname %q did not resolve to any addresses", hostname)
		}

		var matched bool
		for _, resolved := range resolvedIPs {
			for _, attested := range attestedIPs {
				if resolved.Equal(attested) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Errorf("hostname %q does not resolve to any attested Gateway address", hostname)
		}
	}
	return nil
}
