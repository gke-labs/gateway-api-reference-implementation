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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultAudience is the expected audience for projected ServiceAccount tokens.
	DefaultAudience = "gari-controller"

	// DefaultMaxStreamsPerGateway is the default maximum concurrent streams allowed per Gateway.
	DefaultMaxStreamsPerGateway = 32

	// DefaultSendTimeout is the maximum duration the server waits for a data plane to accept
	// a pushed configuration before closing the stream.
	DefaultSendTimeout = 10 * time.Second

	// MaxMessageBytes is the maximum message size covering MaxConfigMessageBytes plus framing overhead.
	MaxMessageBytes = MaxConfigMessageBytes + 1024*1024

	// serverKeepaliveIdle is the maximum duration an idle connection may remain open
	// before the server sends a GOAWAY to reclaim unused connection resources.
	serverKeepaliveIdle = 15 * time.Minute

	// serverKeepalivePingTime is the duration of client inactivity after which the server
	// pings the client to verify connection liveness and detect dead peers.
	serverKeepalivePingTime = 2 * time.Minute

	// serverKeepalivePingTimeout is the time the server waits for a keepalive ping acknowledgment
	// before considering the connection dead and terminating it.
	serverKeepalivePingTimeout = 20 * time.Second

	// clientKeepaliveMinPingInterval is the minimum interval between client keepalive pings
	// that the server permits, protecting against aggressive client ping flooding.
	clientKeepaliveMinPingInterval = 30 * time.Second

	// serverShutdownTimeout is the maximum duration GracefulStop waits for active streams
	// to drain before Stop forcefully closes them. Because configuration push streams are
	// long-lived, 5 seconds allows in-flight RPCs to finish while completing controller
	// termination well within standard Kubernetes pod shutdown grace periods (typically 30s).
	serverShutdownTimeout = 5 * time.Second
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
	if !slices.Contains(result.Status.Audiences, reviewer.audience) {
		return "", "", fmt.Errorf("token audiences %v do not contain audience %q", result.Status.Audiences, reviewer.audience)
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

	// SendTimeout is the maximum duration allowed to push a configuration to a stream before the
	// stream is closed. If <= 0, DefaultSendTimeout is used.
	SendTimeout time.Duration
}

// StreamReply records the latest acknowledgment or negative acknowledgment received from a data plane stream.
// This record is read by the controller step that derives the Programmed condition.
type StreamReply struct {
	Revision string
	Accepted bool
	Reason   string
}

type gatewayConfig struct {
	revision string
	data     []byte
}

type streamSubscriber struct {
	id       uint64
	notifyCh chan struct{}
}

// Server implements PushServiceServer for configuration push.
type Server struct {
	UnimplementedPushServiceServer

	// tokenReviewer verifies incoming ServiceAccount tokens against the TokenReview API.
	tokenReviewer TokenReviewer

	// maxStreamsPerGateway bounds the number of concurrent streams permitted for one Gateway.
	maxStreamsPerGateway int

	// sendTimeout is the maximum duration allowed to push a configuration to a stream.
	sendTimeout time.Duration

	// mu guards streams, subscribers, configs, and replies.
	mu sync.Mutex

	// streams tracks the number of active streams grouped by Gateway namespace and name.
	streams map[types.NamespacedName]int

	// subscribers tracks active stream subscribers grouped by Gateway.
	subscribers map[types.NamespacedName]map[uint64]*streamSubscriber

	// configs holds the latest configuration for each Gateway.
	configs map[types.NamespacedName]*gatewayConfig

	// replies holds the last reply for each stream grouped by Gateway.
	replies map[types.NamespacedName]map[uint64]StreamReply

	// nextStreamID generates unique IDs for streams.
	nextStreamID uint64
}

var (
	_ PushServiceServer        = (*Server)(nil)
	_ state.DataplanePublisher = (*Server)(nil)
)

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
	sendTimeout := options.SendTimeout
	if sendTimeout <= 0 {
		sendTimeout = DefaultSendTimeout
	}
	return &Server{
		tokenReviewer:        options.TokenReviewer,
		maxStreamsPerGateway: maxStreams,
		sendTimeout:          sendTimeout,
		streams:              make(map[types.NamespacedName]int),
		subscribers:          make(map[types.NamespacedName]map[uint64]*streamSubscriber),
		configs:              make(map[types.NamespacedName]*gatewayConfig),
		replies:              make(map[types.NamespacedName]map[uint64]StreamReply),
	}, nil
}

// Begin implements state.DataplanePublisher.
func (server *Server) Begin(ctx context.Context) error {
	return nil
}

// Commit implements state.DataplanePublisher.
func (server *Server) Commit(ctx context.Context) error {
	return nil
}

// PublishDataplaneConfig implements state.DataplanePublisher.
func (server *Server) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	if gw == nil {
		return nil
	}
	gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}

	if config == nil {
		server.mu.Lock()
		delete(server.configs, gwKey)
		delete(server.replies, gwKey)
		server.mu.Unlock()
		return nil
	}

	rev := config.Revision
	if rev == "" {
		var err error
		rev, err = config.ComputeRevision()
		if err != nil {
			return fmt.Errorf("computing revision for gateway %s: %w", gwKey, err)
		}
		config.Revision = rev
	}

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling dataplane config for gateway %s: %w", gwKey, err)
	}

	server.mu.Lock()
	if server.configs == nil {
		server.configs = make(map[types.NamespacedName]*gatewayConfig)
	}
	server.configs[gwKey] = &gatewayConfig{
		revision: rev,
		data:     data,
	}

	for _, sub := range server.subscribers[gwKey] {
		select {
		case sub.notifyCh <- struct{}{}:
		default:
		}
	}
	server.mu.Unlock()

	return nil
}

// StreamReplies returns the latest reply recorded for each stream serving the given Gateway.
// This is read by the controller step that derives the Programmed condition.
func (server *Server) StreamReplies(gw types.NamespacedName) []StreamReply {
	server.mu.Lock()
	defer server.mu.Unlock()

	gwReplies, ok := server.replies[gw]
	if !ok || len(gwReplies) == 0 {
		return nil
	}
	result := make([]StreamReply, 0, len(gwReplies))
	for _, r := range gwReplies {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Revision != result[j].Revision {
			return result[i].Revision < result[j].Revision
		}
		return result[i].Reason < result[j].Reason
	})
	return result
}

// defaultServerOptions returns gRPC server options with keepalive settings and raised message limits.
// The total number of streams across all Gateways is not bounded by this server and is left to the listener,
// while per-Gateway streams are bounded by MaxStreamsPerGateway.
func defaultServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: serverKeepaliveIdle,
			Time:              serverKeepalivePingTime,
			Timeout:           serverKeepalivePingTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             clientKeepaliveMinPingInterval,
			PermitWithoutStream: true,
		}),
	}
}

// grpcServer creates and returns a *grpc.Server with defaultServerOptions and this service registered.
func (server *Server) grpcServer(options ...grpc.ServerOption) *grpc.Server {
	mergedOptions := append(defaultServerOptions(), options...)
	grpcServer := grpc.NewServer(mergedOptions...)
	RegisterPushServiceServer(grpcServer, server)
	return grpcServer
}

// Serve runs the gRPC server on the given listener until the context is canceled.
// When ctx is canceled, a bounded graceful shutdown is performed: streams are given
// serverShutdownTimeout to drain before forceful termination via Stop.
func (server *Server) Serve(ctx context.Context, listener net.Listener, options ...grpc.ServerOption) error {
	grpcServer := server.grpcServer(options...)
	serverStopped := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			timer := time.AfterFunc(serverShutdownTimeout, func() {
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

func truncateReason(reason string) string {
	if len(reason) <= MaxNACKReasonBytes {
		return reason
	}
	reason = reason[:MaxNACKReasonBytes]
	for !utf8.ValidString(reason) && len(reason) > 0 {
		reason = reason[:len(reason)-1]
	}
	return reason
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
		logger.Error(nil, "authentication failed", "reason", "missing or invalid authorization header")
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
		logger.Error(nil, "permission denied",
			"callerNamespace", callerNamespace,
			"callerServiceAccount", callerServiceAccount,
			"gatewayNamespace", hello.GatewayNamespace,
			"expectedServiceAccount", expectedServiceAccount,
		)
		return status.Errorf(codes.PermissionDenied, "permission denied")
	}

	// 4. Stream limits and registration
	gatewayKey := types.NamespacedName{Namespace: hello.GatewayNamespace, Name: hello.GatewayName}
	server.mu.Lock()
	if server.streams[gatewayKey] >= server.maxStreamsPerGateway {
		server.mu.Unlock()
		return status.Errorf(codes.ResourceExhausted, "stream limit exceeded for gateway %s", gatewayKey)
	}
	server.streams[gatewayKey]++
	streamID := server.nextStreamID
	server.nextStreamID++

	sub := &streamSubscriber{
		id:       streamID,
		notifyCh: make(chan struct{}, 1),
	}
	if server.subscribers[gatewayKey] == nil {
		server.subscribers[gatewayKey] = make(map[uint64]*streamSubscriber)
	}
	server.subscribers[gatewayKey][streamID] = sub
	server.mu.Unlock()

	defer func() {
		server.mu.Lock()
		server.streams[gatewayKey]--
		if server.streams[gatewayKey] <= 0 {
			delete(server.streams, gatewayKey)
		}
		if subs, ok := server.subscribers[gatewayKey]; ok {
			delete(subs, streamID)
			if len(subs) == 0 {
				delete(server.subscribers, gatewayKey)
			}
		}
		if reps, ok := server.replies[gatewayKey]; ok {
			delete(reps, streamID)
			if len(reps) == 0 {
				delete(server.replies, gatewayKey)
			}
		}
		server.mu.Unlock()
	}()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	senderErrCh := make(chan error, 1)
	receiverErrCh := make(chan error, 1)

	go func() {
		senderErrCh <- server.runSender(streamCtx, stream, gatewayKey, sub, hello.AppliedRevision, logger)
	}()

	go func() {
		receiverErrCh <- server.runReceiver(streamCtx, stream, gatewayKey, streamID)
	}()

	select {
	case err := <-senderErrCh:
		cancel()
		return err
	case err := <-receiverErrCh:
		cancel()
		return err
	}
}

func (server *Server) runSender(
	ctx context.Context,
	stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage],
	gatewayKey types.NamespacedName,
	sub *streamSubscriber,
	appliedRevision string,
	logger klog.Logger,
) error {
	lastSentRevision := appliedRevision

	sendLatest := func() error {
		server.mu.Lock()
		latest := server.configs[gatewayKey]
		server.mu.Unlock()

		if latest == nil || latest.revision == lastSentRevision {
			return nil
		}

		if len(latest.data) > MaxConfigMessageBytes {
			logger.Error(nil, fmt.Sprintf("dataplane config for gateway %s (%d bytes) exceeds MaxConfigMessageBytes (%d bytes)", gatewayKey, len(latest.data), MaxConfigMessageBytes),
				"gateway", gatewayKey.String(),
				"size", len(latest.data),
				"maxSize", MaxConfigMessageBytes,
			)
			lastSentRevision = latest.revision
			return nil
		}

		msg := &ControllerMessage{
			Body: &ControllerMessage_Config{
				Config: &Config{
					Revision:        latest.revision,
					DataplaneConfig: latest.data,
				},
			},
		}

		sendDone := make(chan error, 1)
		go func() {
			sendDone <- stream.Send(msg)
		}()

		timer := time.NewTimer(server.sendTimeout)
		defer timer.Stop()

		select {
		case err := <-sendDone:
			if err != nil {
				return err
			}
			lastSentRevision = latest.revision
			return nil
		case <-timer.C:
			logger.Error(nil, "closing slow data plane stream that did not take config within timeout",
				"gateway", gatewayKey.String(),
				"timeout", server.sendTimeout,
			)
			return status.Errorf(codes.DeadlineExceeded, "stream send timed out after %v", server.sendTimeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := sendLatest(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.notifyCh:
			if err := sendLatest(); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		}
	}
}

func (server *Server) runReceiver(
	ctx context.Context,
	stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage],
	gatewayKey types.NamespacedName,
	streamID uint64,
) error {
	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		if message.GetHello() != nil {
			return status.Errorf(codes.InvalidArgument, "unexpected second Hello message")
		}

		if ack := message.GetAck(); ack != nil {
			server.mu.Lock()
			if server.replies[gatewayKey] == nil {
				server.replies[gatewayKey] = make(map[uint64]StreamReply)
			}
			server.replies[gatewayKey][streamID] = StreamReply{
				Revision: ack.AppliedRevision,
				Accepted: true,
				Reason:   "",
			}
			server.mu.Unlock()
		} else if nack := message.GetNack(); nack != nil {
			reason := truncateReason(nack.Reason)
			server.mu.Lock()
			if server.replies[gatewayKey] == nil {
				server.replies[gatewayKey] = make(map[uint64]StreamReply)
			}
			server.replies[gatewayKey][streamID] = StreamReply{
				Revision: nack.Revision,
				Accepted: false,
				Reason:   reason,
			}
			server.mu.Unlock()
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
