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
	"google.golang.org/grpc/peer"
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
}

type gatewayConfig struct {
	// revision is the content-derived version identifier of the configuration.
	revision string

	// data is the JSON-encoded DataplaneConfig payload pushed to data planes.
	data []byte
}

type streamReply struct {
	// revision is the configuration revision this reply applies to.
	revision string

	// accepted indicates whether the configuration was applied successfully.
	accepted bool

	// reason explains why the configuration was rejected or could not be applied.
	reason string
}

type streamSubscriber struct {
	// id uniquely identifies this stream subscriber.
	id uint64

	// dataPlane identifies the data plane for error and rejection reporting.
	dataPlane string

	// notifyChannel signals when a new configuration revision is available.
	notifyChannel chan struct{}

	// reply is the latest reply recorded for this stream.
	reply streamReply
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

	// mu guards subscribers, configs, rejections, and replyChannel.
	mu sync.Mutex

	// subscribers tracks active stream subscribers grouped by Gateway namespace and name.
	subscribers map[types.NamespacedName]map[uint64]*streamSubscriber

	// configs holds the latest configuration for each Gateway namespace and name.
	configs map[types.NamespacedName]*gatewayConfig

	// rejections holds unhandled failures (such as a failed send or timeout) for each Gateway
	// that outlive the stream until the next publish.
	rejections map[types.NamespacedName][]state.DataPlaneRejection

	// replyChannel signals when a stream reply arrives, a stream closes, or an error is recorded.
	replyChannel chan struct{}

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
	return &Server{
		tokenReviewer:        options.TokenReviewer,
		maxStreamsPerGateway: maxStreams,
		sendTimeout:          DefaultSendTimeout,
		subscribers:          make(map[types.NamespacedName]map[uint64]*streamSubscriber),
		configs:              make(map[types.NamespacedName]*gatewayConfig),
		rejections:           make(map[types.NamespacedName][]state.DataPlaneRejection),
		replyChannel:         make(chan struct{}),
	}, nil
}

func (server *Server) notifyReplyLocked() {
	close(server.replyChannel)
	server.replyChannel = make(chan struct{})
}

func (server *Server) recordReplyLocked(gatewayKey types.NamespacedName, subscriber *streamSubscriber, revision string, accepted bool, reason string) {
	if server.subscribers[gatewayKey][subscriber.id] != subscriber {
		return
	}
	subscriber.reply = streamReply{
		revision: revision,
		accepted: accepted,
		reason:   reason,
	}
	server.notifyReplyLocked()
}

func (server *Server) recordFailureLocked(gatewayKey types.NamespacedName, dataPlane, reason string) {
	server.rejections[gatewayKey] = append(server.rejections[gatewayKey], state.DataPlaneRejection{
		DataPlane: dataPlane,
		Reason:    reason,
	})
	server.notifyReplyLocked()
}

// PublishDataplaneConfig implements state.DataplanePublisher.
func (server *Server) PublishDataplaneConfig(ctx context.Context, gateway *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	if gateway == nil {
		return nil
	}
	gatewayKey := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}

	server.mu.Lock()
	delete(server.rejections, gatewayKey)
	if config == nil {
		delete(server.configs, gatewayKey)
		server.notifyReplyLocked()
		server.mu.Unlock()
		return nil
	}
	server.mu.Unlock()

	if config.Revision == "" {
		return fmt.Errorf("dataplane config for gateway %s has empty revision", gatewayKey)
	}

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling dataplane config for gateway %s: %w", gatewayKey, err)
	}

	server.mu.Lock()
	server.configs[gatewayKey] = &gatewayConfig{
		revision: config.Revision,
		data:     data,
	}

	// Notify all active stream subscribers for this Gateway. notifyChannel has a buffer
	// capacity of 1. A non-blocking send drops the token only when a notification is
	// already pending in the channel. Because runSender always reads the latest configuration
	// directly from server.configs under mutex when processing a notification, intermediate
	// revisions that arrive while a send is in flight are coalesced into the latest revision,
	// and no updates are lost.
	for _, subscriber := range server.subscribers[gatewayKey] {
		select {
		case subscriber.notifyChannel <- struct{}{}:
		default:
		}
	}
	server.mu.Unlock()

	return nil
}

func (server *Server) buildResultLocked(gatewayKey types.NamespacedName, revision string) (state.PublishResult, bool) {
	subscribers := server.subscribers[gatewayKey]
	rejections := slices.Clone(server.rejections[gatewayKey])

	if len(subscribers) == 0 {
		if len(rejections) == 0 {
			return state.PublishResult{}, true
		}
		return state.PublishResult{Rejections: rejections}, true
	}

	var applied int
	var notAnswered int
	allAnswered := true

	for _, subscriber := range subscribers {
		if subscriber.reply.revision != revision {
			allAnswered = false
			notAnswered++
			continue
		}
		if subscriber.reply.accepted {
			applied++
		} else {
			rejections = append(rejections, state.DataPlaneRejection{
				DataPlane: subscriber.dataPlane,
				Reason:    subscriber.reply.reason,
			})
		}
	}

	if allAnswered {
		return state.PublishResult{
			Applied:    applied,
			Rejections: rejections,
		}, true
	}

	return state.PublishResult{
		Applied:     applied,
		Rejections:  rejections,
		NotAnswered: notAnswered,
	}, false
}

// WaitApplied implements state.DataplanePublisher. It returns when every open stream
// for the Gateway has answered for the revision, or when ctx ends.
// If a newer revision is published while a wait for an older revision is in progress,
// the wait for the older revision cannot be answered and will return only when its context ends.
func (server *Server) WaitApplied(ctx context.Context, gateway *gatewayv1.Gateway, revision string) (state.PublishResult, error) {
	if gateway == nil {
		return state.PublishResult{}, nil
	}
	gatewayKey := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}

	for {
		server.mu.Lock()
		result, allAnswered := server.buildResultLocked(gatewayKey, revision)
		if allAnswered {
			server.mu.Unlock()
			return result, nil
		}
		replyChannel := server.replyChannel
		server.mu.Unlock()

		select {
		case <-ctx.Done():
			server.mu.Lock()
			result, _ := server.buildResultLocked(gatewayKey, revision)
			server.mu.Unlock()
			return result, nil
		case <-replyChannel:
		}
	}
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
	for len(reason) > 0 && !utf8.ValidString(reason) {
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
	if len(server.subscribers[gatewayKey]) >= server.maxStreamsPerGateway {
		server.mu.Unlock()
		return status.Errorf(codes.ResourceExhausted, "stream limit exceeded for gateway %s", gatewayKey)
	}

	streamID := server.nextStreamID
	server.nextStreamID++

	dataPlane := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		dataPlane = p.Addr.String()
		if dataPlane == "bufconn" || dataPlane == "bufnet" {
			dataPlane = fmt.Sprintf("%s:%d", dataPlane, streamID)
		}
	}
	if dataPlane == "" {
		dataPlane = fmt.Sprintf("%s/%s#%d", callerNamespace, callerServiceAccount, streamID)
	}

	subscriber := &streamSubscriber{
		id:            streamID,
		dataPlane:     dataPlane,
		notifyChannel: make(chan struct{}, 1),
	}
	if server.subscribers[gatewayKey] == nil {
		server.subscribers[gatewayKey] = make(map[uint64]*streamSubscriber)
	}
	server.subscribers[gatewayKey][streamID] = subscriber

	if hello.AppliedRevision != "" {
		server.recordReplyLocked(gatewayKey, subscriber, hello.AppliedRevision, true, "")
	}
	server.notifyReplyLocked()
	server.mu.Unlock()

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var senderWaitGroup sync.WaitGroup
	senderWaitGroup.Add(1)
	senderErrChannel := make(chan error, 1)

	go func() {
		defer senderWaitGroup.Done()
		senderErrChannel <- server.runSender(streamCtx, stream, gatewayKey, subscriber, hello.AppliedRevision, logger)
	}()

	receiverErrChannel := make(chan error, 1)
	go func() {
		receiverErrChannel <- server.runReceiver(stream, gatewayKey, subscriber)
	}()

	var returnErr error
	select {
	case returnErr = <-senderErrChannel:
		cancel()
	case returnErr = <-receiverErrChannel:
		cancel()
	}

	// Wait for the sender goroutine to exit so it cannot call stream.Send
	// or access server maps after StreamConfig returns.
	senderWaitGroup.Wait()

	server.mu.Lock()
	if subscribers, ok := server.subscribers[gatewayKey]; ok {
		delete(subscribers, subscriber.id)
		if len(subscribers) == 0 {
			delete(server.subscribers, gatewayKey)
		}
	}
	server.notifyReplyLocked()
	server.mu.Unlock()

	return returnErr
}

func (server *Server) runSender(
	ctx context.Context,
	stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage],
	gatewayKey types.NamespacedName,
	subscriber *streamSubscriber,
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
			logger.Error(nil, "dataplane config exceeds MaxConfigMessageBytes; not sending to stream",
				"gateway", gatewayKey.String(),
				"revision", latest.revision,
				"size", len(latest.data),
				"maxSize", MaxConfigMessageBytes,
			)
			server.mu.Lock()
			server.recordReplyLocked(gatewayKey, subscriber, latest.revision, false,
				fmt.Sprintf("config size %d exceeds MaxConfigMessageBytes %d", len(latest.data), MaxConfigMessageBytes))
			server.mu.Unlock()
			lastSentRevision = latest.revision
			return nil
		}

		message := &ControllerMessage{
			Body: &ControllerMessage_Config{
				Config: &Config{
					Revision:        latest.revision,
					DataplaneConfig: latest.data,
				},
			},
		}

		sendDone := make(chan error, 1)
		go func() {
			sendDone <- stream.Send(message)
		}()

		timer := time.NewTimer(server.sendTimeout)
		defer timer.Stop()

		select {
		case err := <-sendDone:
			if err != nil {
				logger.Error(err, "failed to send dataplane config",
					"gateway", gatewayKey.String(),
					"revision", latest.revision,
				)
				server.mu.Lock()
				server.recordFailureLocked(gatewayKey, subscriber.dataPlane, "failed to send dataplane config: "+err.Error())
				server.mu.Unlock()
				return err
			}
			lastSentRevision = latest.revision
			return nil
		case <-timer.C:
			logger.Error(nil, "closing slow data plane stream that did not take config within timeout",
				"gateway", gatewayKey.String(),
				"revision", latest.revision,
				"timeout", server.sendTimeout,
			)
			server.mu.Lock()
			server.recordFailureLocked(gatewayKey, subscriber.dataPlane, fmt.Sprintf("stream send timed out after %v", server.sendTimeout))
			server.mu.Unlock()
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
		case <-subscriber.notifyChannel:
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
	stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage],
	gatewayKey types.NamespacedName,
	subscriber *streamSubscriber,
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
			server.recordReplyLocked(gatewayKey, subscriber, ack.AppliedRevision, true, "")
			server.mu.Unlock()
		} else if nack := message.GetNack(); nack != nil {
			reason := truncateReason(nack.Reason)
			server.mu.Lock()
			server.recordReplyLocked(gatewayKey, subscriber, nack.Revision, false, reason)
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
