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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// DefaultAudience is the expected audience for projected ServiceAccount tokens.
	DefaultAudience = "gari-controller"

	// DefaultMaxStreamsPerGateway is the default maximum concurrent streams allowed per Gateway.
	DefaultMaxStreamsPerGateway = 32

	// MaxMessageBytes is the maximum message size covering MaxConfigMessageBytes plus framing overhead.
	MaxMessageBytes = MaxConfigMessageBytes + 1024*1024
)

// TokenReviewer verifies a projected ServiceAccount token and returns the caller's namespace and ServiceAccount.
type TokenReviewer interface {
	ReviewToken(ctx context.Context, token string) (namespace, serviceAccount string, err error)
}

// TokenReviewFunc adapts an ordinary function to the TokenReviewer interface.
type TokenReviewFunc func(ctx context.Context, token string) (string, string, error)

func (f TokenReviewFunc) ReviewToken(ctx context.Context, token string) (string, string, error) {
	return f(ctx, token)
}

// ParseServiceAccount parses a Kubernetes service account username ("system:serviceaccount:<ns>:<sa>" or "<ns>/<sa>").
func ParseServiceAccount(username string) (string, string, error) {
	const prefix = "system:serviceaccount:"
	if strings.HasPrefix(username, prefix) {
		rest := strings.TrimPrefix(username, prefix)
		ns, sa, ok := strings.Cut(rest, ":")
		if !ok || ns == "" || sa == "" {
			return "", "", fmt.Errorf("malformed service account username %q", username)
		}
		return ns, sa, nil
	}
	if ns, sa, ok := strings.Cut(username, "/"); ok && ns != "" && sa != "" {
		return ns, sa, nil
	}
	return "", "", fmt.Errorf("invalid service account username %q", username)
}

// ReplyType indicates whether a reply is an ACK or NACK.
type ReplyType string

const (
	ReplyTypeAck  ReplyType = "ACK"
	ReplyTypeNack ReplyType = "NACK"
)

// Reply records the last ACK or NACK received from a data plane.
type Reply struct {
	Type            ReplyType
	AppliedRevision string
	Revision        string
	Reason          string
}

// ServerOptions configures the push Server.
type ServerOptions struct {
	TokenReviewer          TokenReviewer
	State                  *state.State
	Downstream             state.DataplanePublisher
	MaxStreamsPerGateway   int
	ResourceNameForGateway func(gwName string) string
}

type activeStream struct {
	ch   chan *ControllerMessage
	done chan struct{}
}

// Server implements PushServiceServer and state.DataplanePublisher.
type Server struct {
	UnimplementedPushServiceServer

	tokenReviewer          TokenReviewer
	state                  *state.State
	downstream             state.DataplanePublisher
	maxStreamsPerGateway   int
	resourceNameForGateway func(string) string

	mu          sync.Mutex
	nextConnID  uint64
	configs     map[types.NamespacedName]*state.DataplaneConfig
	streams     map[types.NamespacedName]map[*activeStream]struct{}
	connReplies map[uint64]Reply
	gwReplies   map[types.NamespacedName]Reply
	allReplies  []Reply
}

var _ PushServiceServer = (*Server)(nil)
var _ state.DataplanePublisher = (*Server)(nil)

// NewServer creates a new push configuration Server.
func NewServer(opts ServerOptions) *Server {
	maxStreams := opts.MaxStreamsPerGateway
	if maxStreams <= 0 {
		maxStreams = DefaultMaxStreamsPerGateway
	}
	resNameFn := opts.ResourceNameForGateway
	if resNameFn == nil {
		resNameFn = singlepod.ResourceNameForGateway
	}
	return &Server{
		tokenReviewer:          opts.TokenReviewer,
		state:                  opts.State,
		downstream:             opts.Downstream,
		maxStreamsPerGateway:   maxStreams,
		resourceNameForGateway: resNameFn,
		configs:                make(map[types.NamespacedName]*state.DataplaneConfig),
		streams:                make(map[types.NamespacedName]map[*activeStream]struct{}),
		connReplies:            make(map[uint64]Reply),
		gwReplies:              make(map[types.NamespacedName]Reply),
	}
}

// DefaultServerOptions returns gRPC server options with receive/send limits raised to cover config payloads.
func DefaultServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageBytes),
		grpc.MaxSendMsgSize(MaxMessageBytes),
	}
}

// GRPCServer creates and returns a *grpc.Server with DefaultServerOptions and this service registered.
func (s *Server) GRPCServer(opt ...grpc.ServerOption) *grpc.Server {
	opts := append(DefaultServerOptions(), opt...)
	srv := grpc.NewServer(opts...)
	RegisterPushServiceServer(srv, s)
	return srv
}

// Serve runs the gRPC server on lis until ctx is canceled.
func (s *Server) Serve(ctx context.Context, lis net.Listener, opt ...grpc.ServerOption) error {
	srv := s.GRPCServer(opt...)
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		srv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// ListenAndServe listens on addr with TLS and serves until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, addr string, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return errors.New("tlsConfig must not be nil")
	}
	creds := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, lis, grpc.Creds(creds))
}

// StreamConfig handles bidirectional streaming configuration push.
func (s *Server) StreamConfig(stream grpc.BidiStreamingServer[DataplaneMessage, ControllerMessage]) error {
	ctx := stream.Context()

	// 1. Authentication
	token := extractToken(ctx)
	if token == "" {
		return status.Errorf(codes.Unauthenticated, "missing service account token")
	}
	if s.tokenReviewer == nil {
		return status.Errorf(codes.Internal, "token reviewer not configured")
	}
	callerNS, callerSA, err := s.tokenReviewer.ReviewToken(ctx, token)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// 2. Initial Hello
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := firstMsg.GetHello()
	if hello == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be Hello")
	}
	if hello.GatewayNamespace == "" || hello.GatewayName == "" {
		return status.Errorf(codes.InvalidArgument, "Hello message must specify gateway namespace and name")
	}

	// 3. Scoping check
	expectedSA := s.resourceNameForGateway(hello.GatewayName)
	if callerNS != hello.GatewayNamespace || callerSA != expectedSA {
		return status.Errorf(codes.PermissionDenied, "caller %s/%s is not authorized for gateway %s/%s", callerNS, callerSA, hello.GatewayNamespace, hello.GatewayName)
	}

	// 4. Stream limits and registration
	gwKey := types.NamespacedName{Namespace: hello.GatewayNamespace, Name: hello.GatewayName}
	s.mu.Lock()
	if len(s.streams[gwKey]) >= s.maxStreamsPerGateway {
		s.mu.Unlock()
		return status.Errorf(codes.ResourceExhausted, "stream limit exceeded for gateway %s", gwKey)
	}
	connID := s.nextConnID
	s.nextConnID++
	active := &activeStream{
		ch:   make(chan *ControllerMessage, 16),
		done: make(chan struct{}),
	}
	if s.streams[gwKey] == nil {
		s.streams[gwKey] = make(map[*activeStream]struct{})
	}
	s.streams[gwKey][active] = struct{}{}

	// Check current config
	cfg := s.configs[gwKey]
	if cfg == nil && s.state != nil {
		cfg = s.state.GetDataplaneConfig(gwKey)
	}
	var initialMsg *ControllerMessage
	if cfg != nil && cfg.Revision != "" && cfg.Revision != hello.AppliedRevision {
		initialMsg, err = buildConfigMessage(cfg)
		if err != nil {
			delete(s.streams[gwKey], active)
			if len(s.streams[gwKey]) == 0 {
				delete(s.streams, gwKey)
			}
			s.mu.Unlock()
			return fmt.Errorf("building initial config message: %w", err)
		}
	}
	s.mu.Unlock()

	var closeOnce sync.Once
	closeActive := func() {
		closeOnce.Do(func() {
			close(active.done)
		})
	}

	defer func() {
		closeActive()
		s.mu.Lock()
		delete(s.streams[gwKey], active)
		if len(s.streams[gwKey]) == 0 {
			delete(s.streams, gwKey)
		}
		s.mu.Unlock()
	}()

	if initialMsg != nil {
		active.ch <- initialMsg
	}

	// Sender goroutine
	sendErrCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-active.done:
				sendErrCh <- nil
				return
			case <-ctx.Done():
				sendErrCh <- ctx.Err()
				return
			case msg := <-active.ch:
				if err := stream.Send(msg); err != nil {
					sendErrCh <- err
					return
				}
			}
		}
	}()

	// Receiver loop
	var recvErr error
	for {
		msg, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				recvErr = err
			}
			break
		}
		if msg.GetHello() != nil {
			recvErr = status.Errorf(codes.InvalidArgument, "unexpected second Hello message")
			break
		}
		if ack := msg.GetAck(); ack != nil {
			s.recordReply(connID, gwKey, Reply{
				Type:            ReplyTypeAck,
				AppliedRevision: ack.AppliedRevision,
			})
		} else if nack := msg.GetNack(); nack != nil {
			reason := nack.Reason
			if len(reason) > MaxNACKReasonBytes {
				reason = reason[:MaxNACKReasonBytes]
			}
			s.recordReply(connID, gwKey, Reply{
				Type:     ReplyTypeNack,
				Revision: nack.Revision,
				Reason:   reason,
			})
		}
	}

	closeActive()
	sendErr := <-sendErrCh
	if recvErr != nil {
		return recvErr
	}
	if sendErr != nil && !errors.Is(sendErr, context.Canceled) && !errors.Is(sendErr, io.EOF) {
		return sendErr
	}
	return nil
}

// Begin implements state.DataplanePublisher.
func (s *Server) Begin(ctx context.Context) error {
	if s.downstream != nil {
		return s.downstream.Begin(ctx)
	}
	return nil
}

// Commit implements state.DataplanePublisher.
func (s *Server) Commit(ctx context.Context) error {
	if s.downstream != nil {
		return s.downstream.Commit(ctx)
	}
	return nil
}

// PublishDataplaneConfig implements state.DataplanePublisher.
func (s *Server) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	if gw == nil {
		return nil
	}
	gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}

	var msg *ControllerMessage
	var targets []*activeStream

	s.mu.Lock()
	if config == nil {
		delete(s.configs, gwKey)
	} else {
		s.configs[gwKey] = config
		var err error
		msg, err = buildConfigMessage(config)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		for st := range s.streams[gwKey] {
			targets = append(targets, st)
		}
	}
	s.mu.Unlock()

	if msg != nil {
		for _, st := range targets {
			select {
			case st.ch <- msg:
			case <-st.done:
			default:
				select {
				case <-st.ch:
				default:
				}
				select {
				case st.ch <- msg:
				default:
				}
			}
		}
	}

	if s.downstream != nil {
		return s.downstream.PublishDataplaneConfig(ctx, gw, config)
	}
	return nil
}

func (s *Server) recordReply(connID uint64, gwKey types.NamespacedName, r Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connReplies[connID] = r
	s.gwReplies[gwKey] = r
	s.allReplies = append(s.allReplies, r)
}

// LastReplyForConnection returns the last reply recorded for the given connection ID.
func (s *Server) LastReplyForConnection(connID uint64) (Reply, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.connReplies[connID]
	return r, ok
}

// LastReplyForGateway returns the last reply recorded for the given Gateway.
func (s *Server) LastReplyForGateway(gwKey types.NamespacedName) (Reply, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.gwReplies[gwKey]
	return r, ok
}

// RecordedReplies returns a copy of all replies received across connections.
func (s *Server) RecordedReplies() []Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.allReplies)
}

func buildConfigMessage(cfg *state.DataplaneConfig) (*ControllerMessage, error) {
	data, err := cfg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling dataplane config: %w", err)
	}
	return &ControllerMessage{
		Body: &ControllerMessage_Config{
			Config: &Config{
				Revision:        cfg.Revision,
				DataplaneConfig: data,
			},
		},
	}, nil
}

func extractToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	authHeaders := md.Get("authorization")
	if len(authHeaders) > 0 {
		raw := strings.TrimSpace(authHeaders[0])
		const prefix = "bearer "
		if strings.HasPrefix(strings.ToLower(raw), prefix) {
			return strings.TrimSpace(raw[len(prefix):])
		}
		return raw
	}
	tokens := md.Get("token")
	if len(tokens) > 0 {
		return strings.TrimSpace(tokens[0])
	}
	return ""
}
