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

package push

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/klog/v2"
)

const (
	// DefaultAudience is the expected audience for projected ServiceAccount tokens.
	DefaultAudience = "gari-controller"

	// DefaultMaxStreamsPerGateway is the default maximum concurrent streams allowed per Gateway.
	DefaultMaxStreamsPerGateway = 32

	// MaxMessageBytes is the maximum message size covering MaxConfigMessageBytes plus framing overhead.
	MaxMessageBytes = MaxConfigMessageBytes + 1024*1024
)

// TokenReviewer verifies a projected ServiceAccount token and returns the caller's namespace and ServiceAccount name.
type TokenReviewer interface {
	ReviewToken(ctx context.Context, token string) (callerNamespace, callerServiceAccount string, err error)
}

// KubeTokenReviewer validates projected ServiceAccount tokens against the Kubernetes TokenReview API.
type KubeTokenReviewer struct {
	// client is the Kubernetes TokenReviews API client.
	client authenticationv1client.TokenReviewInterface
	// audience is the expected audience for projected tokens.
	audience string
}

// NewKubeTokenReviewer creates a new KubeTokenReviewer for the specified client and audience.
// If audience is empty, DefaultAudience is used.
func NewKubeTokenReviewer(client authenticationv1client.TokenReviewInterface, audience string) *KubeTokenReviewer {
	if audience == "" {
		audience = DefaultAudience
	}
	return &KubeTokenReviewer{
		client:   client,
		audience: audience,
	}
}

// ReviewToken submits a TokenReview to the Kubernetes API and extracts the caller's namespace and ServiceAccount.
func (reviewer *KubeTokenReviewer) ReviewToken(ctx context.Context, token string) (string, string, error) {
	if reviewer.client == nil {
		return "", "", errors.New("kubernetes TokenReview client is not configured")
	}

	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{reviewer.audience},
		},
	}

	result, err := reviewer.client.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return "", "", fmt.Errorf("creating token review: %w", err)
	}
	if result.Status.Error != "" {
		return "", "", fmt.Errorf("token review status error: %s", result.Status.Error)
	}
	if !result.Status.Authenticated {
		return "", "", errors.New("token is not authenticated")
	}

	username := result.Status.User.Username
	const serviceAccountPrefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, serviceAccountPrefix) {
		return "", "", fmt.Errorf("user %q is not a service account", username)
	}
	rest := strings.TrimPrefix(username, serviceAccountPrefix)
	callerNamespace, callerServiceAccount, ok := strings.Cut(rest, ":")
	if !ok || callerNamespace == "" || callerServiceAccount == "" {
		return "", "", fmt.Errorf("malformed service account username %q", username)
	}

	return callerNamespace, callerServiceAccount, nil
}

// ServerOptions configures the push Server.
type ServerOptions struct {
	// TokenReviewer is the required token reviewer used to authenticate data planes.
	TokenReviewer TokenReviewer

	// MaxStreamsPerGateway is the maximum number of concurrent streams allowed for a single Gateway.
	// If <= 0, DefaultMaxStreamsPerGateway is used.
	MaxStreamsPerGateway int
}

// activeStream represents a connected data plane stream.
type activeStream struct {
	// done signals when the active stream is terminating.
	done chan struct{}
}

// Server implements PushServiceServer for configuration push.
type Server struct {
	UnimplementedPushServiceServer

	// tokenReviewer verifies incoming ServiceAccount tokens against the TokenReview API.
	tokenReviewer TokenReviewer

	// maxStreamsPerGateway bounds the number of concurrent streams permitted for one Gateway.
	maxStreamsPerGateway int

	// mu guards streams.
	mu sync.Mutex

	// streams tracks active streams grouped by Gateway namespace and name.
	streams map[types.NamespacedName]map[*activeStream]struct{}
}

var _ PushServiceServer = (*Server)(nil)

// NewServer creates a new push configuration Server.
// tokenReviewer is required; if nil, an error is returned.
func NewServer(options ServerOptions) (*Server, error) {
	if options.TokenReviewer == nil {
		return nil, errors.New("TokenReviewer is required")
	}
	maxStreams := options.MaxStreamsPerGateway
	if maxStreams <= 0 {
		maxStreams = DefaultMaxStreamsPerGateway
	}
	return &Server{
		tokenReviewer:        options.TokenReviewer,
		maxStreamsPerGateway: maxStreams,
		streams:              make(map[types.NamespacedName]map[*activeStream]struct{}),
	}, nil
}

// DefaultServerOptions returns gRPC server options with keepalive settings and raised message limits.
// The total number of streams across all Gateways is not bounded by this server and is left to the listener,
// while per-Gateway streams are bounded by MaxStreamsPerGateway.
func DefaultServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 15 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}
}

// GRPCServer creates and returns a *grpc.Server with DefaultServerOptions and this service registered.
func (server *Server) GRPCServer(options ...grpc.ServerOption) *grpc.Server {
	mergedOptions := append(DefaultServerOptions(), options...)
	grpcServer := grpc.NewServer(mergedOptions...)
	RegisterPushServiceServer(grpcServer, server)
	return grpcServer
}

// Serve runs the gRPC server on the given listener until the context is canceled.
// When ctx is canceled, a bounded graceful shutdown is performed: streams are given
// 5 seconds to drain before forceful termination via Stop.
func (server *Server) Serve(ctx context.Context, listener net.Listener, options ...grpc.ServerOption) error {
	grpcServer := server.GRPCServer(options...)
	serverStopped := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			const shutdownTimeout = 5 * time.Second
			timer := time.AfterFunc(shutdownTimeout, func() {
				grpcServer.Stop()
			})
			grpcServer.GracefulStop()
			timer.Stop()
		case <-serverStopped:
		}
	}()

	err := grpcServer.Serve(listener)
	close(serverStopped)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

// ActiveStreams returns the number of active streams currently connected for the given Gateway.
func (server *Server) ActiveStreams(gatewayKey types.NamespacedName) int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.streams[gatewayKey])
}

// StreamConfig establishes a bidirectional stream with a data plane.
// A data plane stream is authenticated once when the stream opens using its projected
// ServiceAccount token. If the projected token expires while the stream is open, the
// existing stream remains active; token expiration is enforced when the stream reconnects.
func (server *Server) StreamConfig(stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage]) error {
	ctx := stream.Context()
	logger := klog.FromContext(ctx)

	// 1. Authentication
	token := extractToken(ctx)
	if token == "" {
		logger.Error(errors.New("missing or invalid authorization header"), "authentication failed")
		return status.Errorf(codes.Unauthenticated, "authentication failed")
	}

	callerNamespace, callerServiceAccount, err := server.tokenReviewer.ReviewToken(ctx, token)
	if err != nil {
		logger.Error(err, "authentication failed")
		return status.Errorf(codes.Unauthenticated, "authentication failed")
	}

	// 2. Initial Hello
	firstMessage, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := firstMessage.GetHello()
	if hello == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be Hello")
	}
	if hello.GatewayNamespace == "" || hello.GatewayName == "" {
		return status.Errorf(codes.InvalidArgument, "Hello message must specify gateway namespace and name")
	}

	// 3. Scoping check
	expectedServiceAccount := singlepod.ResourceNameForGateway(hello.GatewayName)
	if callerNamespace != hello.GatewayNamespace || callerServiceAccount != expectedServiceAccount {
		logger.Error(fmt.Errorf("caller %s/%s does not match expected %s/%s", callerNamespace, callerServiceAccount, hello.GatewayNamespace, expectedServiceAccount), "permission denied")
		return status.Errorf(codes.PermissionDenied, "permission denied")
	}

	// 4. Stream limits and registration
	gatewayKey := types.NamespacedName{Namespace: hello.GatewayNamespace, Name: hello.GatewayName}
	server.mu.Lock()
	if len(server.streams[gatewayKey]) >= server.maxStreamsPerGateway {
		server.mu.Unlock()
		return status.Errorf(codes.ResourceExhausted, "stream limit exceeded for gateway %s", gatewayKey)
	}

	streamHandle := &activeStream{
		done: make(chan struct{}),
	}
	if server.streams[gatewayKey] == nil {
		server.streams[gatewayKey] = make(map[*activeStream]struct{})
	}
	server.streams[gatewayKey][streamHandle] = struct{}{}
	server.mu.Unlock()

	defer func() {
		close(streamHandle.done)
		server.mu.Lock()
		delete(server.streams[gatewayKey], streamHandle)
		if len(server.streams[gatewayKey]) == 0 {
			delete(server.streams, gatewayKey)
		}
		server.mu.Unlock()
	}()

	// 5. Message loop: read and enforce protocol rules until connection terminates.
	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if message.GetHello() != nil {
			return status.Errorf(codes.InvalidArgument, "unexpected second Hello message")
		}
	}
}

func extractToken(ctx context.Context) string {
	incomingMetadata, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	authHeaders := incomingMetadata.Get("authorization")
	if len(authHeaders) == 0 {
		return ""
	}
	raw := strings.TrimSpace(authHeaders[0])
	const prefix = "bearer "
	if strings.HasPrefix(strings.ToLower(raw), prefix) {
		return strings.TrimSpace(raw[len(prefix):])
	}
	return ""
}
