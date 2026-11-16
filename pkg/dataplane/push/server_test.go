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

package push_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func testDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
}

func startInProcessServer(t *testing.T, srv *push.Server) push.PushServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	grpcServer := srv.GRPCServer()

	go func() {
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("grpcServer.Serve error: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(testDialer(lis)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial in-process server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return push.NewPushServiceClient(conn)
}

func pollUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !condition() {
		t.Fatalf("condition not met within %v", timeout)
	}
}

type mockPublisher struct {
	mu        sync.Mutex
	begins    int
	commits   int
	published []*state.DataplaneConfig
	gateways  []*gatewayv1.Gateway
}

func (m *mockPublisher) Begin(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.begins++
	return nil
}

func (m *mockPublisher) Commit(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commits++
	return nil
}

func (m *mockPublisher) PublishDataplaneConfig(ctx context.Context, gw *gatewayv1.Gateway, config *state.DataplaneConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gateways = append(m.gateways, gw)
	m.published = append(m.published, config)
	return nil
}

func (m *mockPublisher) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.published)
}

// TestStreamConfig_Success_RealState verifies that a data plane with the right token
// receives its Gateway's initial config and a second config when real state changes,
// and that Ack and Nack replies are recorded.
func TestStreamConfig_Success_RealState(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	st := state.NewState()
	st.SetControllerName("example.net/gateway-controller")

	gw1Key := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	expectedSA := singlepod.ResourceNameForGateway(gw1Key.Name)

	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		if token == "valid-token-gw-1" {
			return "default", expectedSA, nil
		}
		return "", "", errors.New("unrecognized token")
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
		State:         st,
	})
	st.SetDataplanePublisher(srv)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw1Key.Namespace, Name: gw1Key.Name},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "my-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw1)
	st.SetGatewayAddresses(gw1Key, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gw1Key, state.GatewayReadiness{Ready: true})

	go func() {
		_ = st.Start(ctx)
	}()

	client := startInProcessServer(t, srv)

	// Connect with valid token
	streamCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer valid-token-gw-1"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// Send initial Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gw1Key.Namespace,
				GatewayName:      gw1Key.Name,
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	// 1. Receive first config
	msg1, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive first config: %v", err)
	}
	cfg1 := msg1.GetConfig()
	if cfg1 == nil {
		t.Fatalf("expected Config message, got: %v", msg1)
	}
	if cfg1.Revision == "" {
		t.Fatalf("expected non-empty revision in first config")
	}

	// Send ACK for first revision
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{
				AppliedRevision: cfg1.Revision,
			},
		},
	}); err != nil {
		t.Fatalf("Send Ack failed: %v", err)
	}

	// Verify ACK recorded
	pollUntil(t, 2*time.Second, func() bool {
		r, ok := srv.LastReplyForGateway(gw1Key)
		return ok && r.Type == push.ReplyTypeAck && r.AppliedRevision == cfg1.Revision
	})

	// 2. Change state by adding an HTTPRoute
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "http-route-1"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw-1"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  ptrTo(gatewayv1.PathMatchPathPrefix),
								Value: ptrTo("/api"),
							},
						},
					},
				},
			},
		},
	}
	st.UpsertHTTPRoute(route)

	// 3. Receive second config on the active stream
	msg2, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive second config: %v", err)
	}
	cfg2 := msg2.GetConfig()
	if cfg2 == nil {
		t.Fatalf("expected Config message for update, got: %v", msg2)
	}
	if cfg2.Revision == cfg1.Revision {
		t.Fatalf("expected second revision to differ from first revision %q, got same", cfg1.Revision)
	}

	// Send NACK for second revision
	const nackReason = "failed to bind socket on port 8080"
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: cfg2.Revision,
				Reason:   nackReason,
			},
		},
	}); err != nil {
		t.Fatalf("Send Nack failed: %v", err)
	}

	// Verify NACK recorded
	pollUntil(t, 2*time.Second, func() bool {
		r, ok := srv.LastReplyForGateway(gw1Key)
		return ok && r.Type == push.ReplyTypeNack && r.Revision == cfg2.Revision && r.Reason == nackReason
	})

	// Verify RecordedReplies contains both replies
	replies := srv.RecordedReplies()
	if len(replies) != 2 {
		t.Fatalf("expected 2 recorded replies, got %d", len(replies))
	}
	if replies[0].Type != push.ReplyTypeAck || replies[0].AppliedRevision != cfg1.Revision {
		t.Errorf("unexpected first reply: %+v", replies[0])
	}
	if replies[1].Type != push.ReplyTypeNack || replies[1].Revision != cfg2.Revision || replies[1].Reason != nackReason {
		t.Errorf("unexpected second reply: %+v", replies[1])
	}
}

// TestStreamConfig_Scoping_Refused verifies that a token for another Gateway's
// ServiceAccount is refused with PermissionDenied and receives nothing.
func TestStreamConfig_Scoping_Refused(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		// Returns SA for gw-2, while client claims gw-1
		return "default", singlepod.ResourceNameForGateway("gw-2"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	client := startInProcessServer(t, srv)

	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer valid-token-gw-2"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// Client claims to serve gw-1
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "gw-1",
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	// Stream should be closed with PermissionDenied and receive no configs
	msg, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected permission error, but received message: %v", msg)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got %v (status: %v)", err, st)
	}
}

// TestStreamConfig_Authentication_MissingOrInvalidToken verifies that missing or invalid
// tokens are rejected with Unauthenticated.
func TestStreamConfig_Authentication_MissingOrInvalidToken(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		if token == "good-token" {
			return "default", singlepod.ResourceNameForGateway("gw-1"), nil
		}
		return "", "", errors.New("token expired or signature invalid")
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	client := startInProcessServer(t, srv)

	// 1. Missing token
	t.Run("MissingToken", func(t *testing.T) {
		stream, err := client.StreamConfig(t.Context())
		if err != nil {
			t.Fatalf("StreamConfig failed: %v", err)
		}
		msg, err := stream.Recv()
		if err == nil {
			t.Fatalf("expected Unauthenticated error, got message: %v", msg)
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated, got: %v", err)
		}
	})

	// 2. Invalid token
	t.Run("InvalidToken", func(t *testing.T) {
		streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer bad-token"))
		stream, err := client.StreamConfig(streamCtx)
		if err != nil {
			t.Fatalf("StreamConfig failed: %v", err)
		}
		msg, err := stream.Recv()
		if err == nil {
			t.Fatalf("expected Unauthenticated error, got message: %v", msg)
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated, got: %v", err)
		}
	})
}

// TestStreamConfig_Ordering_MessageBeforeHello verifies that sending anything before
// Hello closes the stream with InvalidArgument.
func TestStreamConfig_Ordering_MessageBeforeHello(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	client := startInProcessServer(t, srv)

	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// Send Ack first instead of Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: "rev-1"},
		},
	}); err != nil {
		t.Fatalf("Send Ack failed: %v", err)
	}

	msg, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected error for non-Hello first message, got: %v", msg)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
}

// TestStreamConfig_Ordering_SecondHello verifies that sending a second Hello message
// closes the stream with InvalidArgument.
func TestStreamConfig_Ordering_SecondHello(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	client := startInProcessServer(t, srv)

	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// First Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "gw-1",
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send first Hello failed: %v", err)
	}

	// Second Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "gw-1",
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send second Hello failed: %v", err)
	}

	msg, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected error for second Hello, got: %v", msg)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
}

// TestStreamConfig_Limits_MaxStreams verifies that the number of concurrent streams
// for one Gateway is bounded.
func TestStreamConfig_Limits_MaxStreams(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer:        reviewer,
		MaxStreamsPerGateway: 1,
	})
	client := startInProcessServer(t, srv)

	// Stream 1: successful
	streamCtx1 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream1, err := client.StreamConfig(streamCtx1)
	if err != nil {
		t.Fatalf("StreamConfig 1 failed: %v", err)
	}
	if err := stream1.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "gw-1",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello 1 failed: %v", err)
	}

	// Wait briefly so stream 1 registers
	time.Sleep(20 * time.Millisecond)

	// Stream 2: exceeds limit of 1
	streamCtx2 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream2, err := client.StreamConfig(streamCtx2)
	if err != nil {
		t.Fatalf("StreamConfig 2 failed: %v", err)
	}
	if err := stream2.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "gw-1",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello 2 failed: %v", err)
	}

	msg, err := stream2.Recv()
	if err == nil {
		t.Fatalf("expected ResourceExhausted error for stream 2, got: %v", msg)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted, got: %v", err)
	}
}

// TestStreamConfig_Limits_NACKReasonBounded verifies that oversized NACK reasons
// are bounded by MaxNACKReasonBytes.
func TestStreamConfig_Limits_NACKReasonBounded(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	client := startInProcessServer(t, srv)

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gwKey.Namespace,
				GatewayName:      gwKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	oversizedReason := strings.Repeat("x", push.MaxNACKReasonBytes+500)
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: "rev-fail",
				Reason:   oversizedReason,
			},
		},
	}); err != nil {
		t.Fatalf("Send Nack failed: %v", err)
	}

	pollUntil(t, 2*time.Second, func() bool {
		r, ok := srv.LastReplyForGateway(gwKey)
		return ok && r.Type == push.ReplyTypeNack
	})

	r, ok := srv.LastReplyForGateway(gwKey)
	if !ok {
		t.Fatalf("expected recorded reply")
	}
	if len(r.Reason) != push.MaxNACKReasonBytes {
		t.Fatalf("expected reason bounded to %d bytes, got %d", push.MaxNACKReasonBytes, len(r.Reason))
	}
}

// TestStreamConfig_NoSendWhenRevisionMatches verifies that no config is sent
// if Hello reports the same revision as current.
func TestStreamConfig_NoSendWhenRevisionMatches(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}
	cfg := &state.DataplaneConfig{Revision: "rev-current"}
	if err := srv.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, srv)
	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// Hello reports applied_revision matching current config revision
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gwKey.Namespace,
				GatewayName:      gwKey.Name,
				AppliedRevision:  "rev-current",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	recvCh := make(chan *push.ControllerMessage, 1)
	go func() {
		msg, _ := stream.Recv()
		if msg != nil {
			recvCh <- msg
		}
	}()

	select {
	case msg := <-recvCh:
		t.Fatalf("expected no initial config send when revision matches, got: %v", msg)
	case <-time.After(100 * time.Millisecond):
		// Success: nothing was sent
	}
}

// TestStreamConfig_SecretPathUnchanged verifies that publishing through push.Server
// forwards exactly to the downstream DataplanePublisher, leaving Secret publishing unchanged.
func TestStreamConfig_SecretPathUnchanged(t *testing.T) {
	mock := &mockPublisher{}
	srv := push.NewServer(push.ServerOptions{
		Downstream: mock,
	})

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}
	cfg := &state.DataplaneConfig{Revision: "rev-secret"}

	if err := srv.Begin(t.Context()); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if err := srv.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}
	if err := srv.Commit(t.Context()); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if mock.begins != 1 {
		t.Errorf("expected 1 Begin call to downstream, got %d", mock.begins)
	}
	if mock.commits != 1 {
		t.Errorf("expected 1 Commit call to downstream, got %d", mock.commits)
	}
	if mock.count() != 1 {
		t.Fatalf("expected 1 published config to downstream, got %d", mock.count())
	}
	if mock.published[0].Revision != "rev-secret" {
		t.Errorf("expected revision 'rev-secret', got %q", mock.published[0].Revision)
	}
}

// TestStreamConfig_Limits_ConfigPayloadExceeds4MiB verifies that configs up to
// MaxConfigMessageBytes (larger than gRPC's default 4 MiB receive limit) are supported.
func TestStreamConfig_Limits_ConfigPayloadExceeds4MiB(t *testing.T) {
	reviewer := push.TokenReviewFunc(func(ctx context.Context, token string) (string, string, error) {
		return "default", singlepod.ResourceNameForGateway("gw-1"), nil
	})

	srv := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})

	const bufSize = 8 * 1024 * 1024
	lis := bufconn.Listen(bufSize)
	grpcServer := srv.GRPCServer()

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = lis.Close()
	})

	// Client also uses raised receive message size
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(testDialer(lis)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(push.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(push.MaxMessageBytes),
		),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	client := push.NewPushServiceClient(conn)

	// Publish config with ~4.1 MiB payload
	gwKey := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}
	// A mock raw config with 4.1 MiB dummy field
	largePayload := bytes.Repeat([]byte("a"), 4100*1024)
	cfg := &state.DataplaneConfig{
		Revision: "rev-large",
		Listeners: []state.InternalListener{
			{Name: string(largePayload)},
		},
	}
	if err := srv.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	streamCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gwKey.Namespace,
				GatewayName:      gwKey.Name,
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive large config: %v", err)
	}
	c := msg.GetConfig()
	if c == nil || c.Revision != "rev-large" {
		t.Fatalf("unexpected message: %v", msg)
	}
	if len(c.DataplaneConfig) < 4*1024*1024 {
		t.Fatalf("expected payload > 4 MiB, got %d bytes", len(c.DataplaneConfig))
	}
}

// TestServer_Serve_ContextCancel verifies that Serve terminates gracefully when context is canceled.
func TestServer_Serve_ContextCancel(t *testing.T) {
	srv := push.NewServer(push.ServerOptions{})
	lis := bufconn.Listen(1024)
	defer lis.Close()

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, lis)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned unexpected error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit within timeout after context cancel")
	}
}

// TestServer_ListenAndServe_NilTLS verifies that ListenAndServe rejects nil tlsConfig.
func TestServer_ListenAndServe_NilTLS(t *testing.T) {
	srv := push.NewServer(push.ServerOptions{})
	err := srv.ListenAndServe(t.Context(), "127.0.0.1:0", nil)
	if err == nil {
		t.Fatal("expected error for nil tlsConfig, got nil")
	}
}

// TestParseServiceAccount verifies parsing service account usernames in various formats.
func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		input   string
		wantNS  string
		wantSA  string
		wantErr bool
	}{
		{"system:serviceaccount:default:my-sa", "default", "my-sa", false},
		{"system:serviceaccount:kube-system:coredns", "kube-system", "coredns", false},
		{"prod/gateway-sa", "prod", "gateway-sa", false},
		{"invalid", "", "", true},
		{"system:serviceaccount::sa", "", "", true},
		{"system:serviceaccount:ns:", "", "", true},
	}
	for _, tc := range tests {
		ns, sa, err := push.ParseServiceAccount(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseServiceAccount(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && (ns != tc.wantNS || sa != tc.wantSA) {
			t.Errorf("ParseServiceAccount(%q) = (%q, %q), want (%q, %q)", tc.input, ns, sa, tc.wantNS, tc.wantSA)
		}
	}
}

func ptrTo[T any](v T) *T {
	return &v
}
