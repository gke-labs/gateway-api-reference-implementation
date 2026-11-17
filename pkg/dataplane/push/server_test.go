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
	"context"
	"errors"
	"io"
	"net"
	"strings"
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
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type fakeTokenReviewClient struct {
	authenticationv1client.TokenReviewInterface
	createFunc func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error)
}

func (client *fakeTokenReviewClient) Create(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	return client.createFunc(ctx, tokenReview, options)
}

type staticTokenReviewer struct {
	reviewFunc func(ctx context.Context, token string) (string, string, error)
}

func (reviewer *staticTokenReviewer) ReviewToken(ctx context.Context, token string) (string, string, error) {
	return reviewer.reviewFunc(ctx, token)
}

func testDialer(listener *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}

func startInProcessServer(t *testing.T, server *push.Server) push.PushServiceClient {
	t.Helper()
	const bufferSize = 1024 * 1024
	listener := bufconn.Listen(bufferSize)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		if err := server.Serve(ctx, listener); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("server.Serve error: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener.Close error: %v", err)
		}
	})

	clientConn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(testDialer(listener)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial in-process server: %v", err)
	}
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil {
			t.Errorf("clientConn.Close error: %v", err)
		}
	})

	return push.NewPushServiceClient(clientConn)
}

func TestKubeTokenReviewer(t *testing.T) {
	t.Run("ValidToken", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				if tokenReview.Spec.Token != "valid-token" {
					t.Fatalf("unexpected token: %s", tokenReview.Spec.Token)
				}
				if len(tokenReview.Spec.Audiences) != 1 || tokenReview.Spec.Audiences[0] != push.DefaultAudience {
					t.Fatalf("unexpected audiences: %v", tokenReview.Spec.Audiences)
				}
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: true,
						Audiences:     []string{push.DefaultAudience},
						User: authenticationv1.UserInfo{
							Username: "system:serviceaccount:gateway-ns:my-gateway-sa",
						},
					},
				}, nil
			},
		}

		reviewer := push.NewKubeTokenReviewer(client, "")
		namespace, serviceAccount, err := reviewer.ReviewToken(t.Context(), "valid-token")
		if err != nil {
			t.Fatalf("ReviewToken failed: %v", err)
		}
		if namespace != "gateway-ns" || serviceAccount != "my-gateway-sa" {
			t.Fatalf("expected gateway-ns/my-gateway-sa, got %s/%s", namespace, serviceAccount)
		}
	})

	t.Run("OtherAudience", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: true,
						Audiences:     []string{"other-audience"},
						User: authenticationv1.UserInfo{
							Username: "system:serviceaccount:gateway-ns:my-gateway-sa",
						},
					},
				}, nil
			},
		}
		reviewer := push.NewKubeTokenReviewer(client, push.DefaultAudience)
		_, _, err := reviewer.ReviewToken(t.Context(), "other-audience-token")
		if err == nil {
			t.Fatal("expected audience mismatch error, got nil")
		}
	})

	t.Run("StatusError", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Error: "token expired",
					},
				}, nil
			},
		}
		reviewer := push.NewKubeTokenReviewer(client, push.DefaultAudience)
		_, _, err := reviewer.ReviewToken(t.Context(), "expired-token")
		if err == nil || !errors.Is(err, err) {
			t.Fatalf("expected error, got: %v", err)
		}
	})

	t.Run("NotAuthenticated", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: false,
					},
				}, nil
			},
		}
		reviewer := push.NewKubeTokenReviewer(client, push.DefaultAudience)
		_, _, err := reviewer.ReviewToken(t.Context(), "bad-token")
		if err == nil {
			t.Fatal("expected unauthenticated error, got nil")
		}
	})

	t.Run("NonServiceAccountUser", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: true,
						Audiences:     []string{push.DefaultAudience},
						User: authenticationv1.UserInfo{
							Username: "system:admin",
						},
					},
				}, nil
			},
		}
		reviewer := push.NewKubeTokenReviewer(client, push.DefaultAudience)
		_, _, err := reviewer.ReviewToken(t.Context(), "admin-token")
		if err == nil {
			t.Fatal("expected non-service-account error, got nil")
		}
	})

	t.Run("ClientCreateError", func(t *testing.T) {
		client := &fakeTokenReviewClient{
			createFunc: func(ctx context.Context, tokenReview *authenticationv1.TokenReview, options metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				return nil, errors.New("apiserver unreachable")
			},
		}
		reviewer := push.NewKubeTokenReviewer(client, push.DefaultAudience)
		_, _, err := reviewer.ReviewToken(t.Context(), "any-token")
		if err == nil {
			t.Fatal("expected API client error, got nil")
		}
	})
}

func TestNewServer_RequiresTokenReviewer(t *testing.T) {
	_, err := push.NewServer(push.ServerOptions{
		TokenReviewer: nil,
	})
	if err == nil {
		t.Fatal("expected error when TokenReviewer is nil, got nil")
	}
}

func TestStreamConfig_Success_AuthenticationAndScoping(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "secret-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
			}
			return "", "", errors.New("invalid token")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	client := startInProcessServer(t, server)

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer secret-token"))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
				AppliedRevision:  "",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	if err := stream.CloseSend(); err != nil {
		t.Errorf("CloseSend error: %v", err)
	}

	message, err := stream.Recv()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on clean stream termination, got message=%v err=%v", message, err)
	}
}

func TestStreamConfig_Scoping_Refused(t *testing.T) {
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return "default", singlepod.ResourceNameForGateway("other-gateway"), nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client := startInProcessServer(t, server)

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer valid-token"))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: "default",
				GatewayName:      "my-gateway",
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}

	message, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected PermissionDenied error, received message: %v", message)
	}
	rpcStatus, ok := status.FromError(err)
	if !ok || rpcStatus.Code() != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got: %v", err)
	}
}

func TestStreamConfig_Authentication_MissingOrInvalidToken(t *testing.T) {
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "good-token" {
				return "default", singlepod.ResourceNameForGateway("my-gateway"), nil
			}
			return "", "", errors.New("signature verification failed")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client := startInProcessServer(t, server)

	t.Run("MissingToken", func(t *testing.T) {
		stream, err := client.StreamConfig(t.Context())
		if err != nil {
			t.Fatalf("StreamConfig failed: %v", err)
		}
		message, err := stream.Recv()
		if err == nil {
			t.Fatalf("expected Unauthenticated error, got: %v", message)
		}
		rpcStatus, ok := status.FromError(err)
		if !ok || rpcStatus.Code() != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated, got: %v", err)
		}
	})

	t.Run("BareTokenWithoutBearer", func(t *testing.T) {
		outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "good-token"))
		stream, err := client.StreamConfig(outgoingContext)
		if err != nil {
			t.Fatalf("StreamConfig failed: %v", err)
		}
		message, err := stream.Recv()
		if err == nil {
			t.Fatalf("expected Unauthenticated error for bare token, got: %v", message)
		}
		rpcStatus, ok := status.FromError(err)
		if !ok || rpcStatus.Code() != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated, got: %v", err)
		}
	})

	t.Run("ReviewerError", func(t *testing.T) {
		outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer bad-token"))
		stream, err := client.StreamConfig(outgoingContext)
		if err != nil {
			t.Fatalf("StreamConfig failed: %v", err)
		}
		message, err := stream.Recv()
		if err == nil {
			t.Fatalf("expected Unauthenticated error, got: %v", message)
		}
		rpcStatus, ok := status.FromError(err)
		if !ok || rpcStatus.Code() != codes.Unauthenticated {
			t.Fatalf("expected codes.Unauthenticated, got: %v", err)
		}
		if rpcStatus.Message() != "authentication failed" {
			t.Fatalf("expected fixed message 'authentication failed', got %q", rpcStatus.Message())
		}
	})
}

func TestStreamConfig_Ordering_MessageBeforeHello(t *testing.T) {
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return "default", singlepod.ResourceNameForGateway("my-gateway"), nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client := startInProcessServer(t, server)

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: "rev-1"},
		},
	}); err != nil {
		t.Fatalf("Send Ack failed: %v", err)
	}

	message, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected error for non-Hello first message, got: %v", message)
	}
	rpcStatus, ok := status.FromError(err)
	if !ok || rpcStatus.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
}

func TestStreamConfig_Ordering_SecondHello(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, singlepod.ResourceNameForGateway(gatewayKey.Name), nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client := startInProcessServer(t, server)

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token"))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// First Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send first Hello failed: %v", err)
	}

	// Second Hello
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send second Hello failed: %v", err)
	}

	message, err := stream.Recv()
	if err == nil {
		t.Fatalf("expected error for second Hello, got: %v", message)
	}
	rpcStatus, ok := status.FromError(err)
	if !ok || rpcStatus.Code() != codes.InvalidArgument {
		t.Fatalf("expected codes.InvalidArgument, got: %v", err)
	}
}

func TestStreamConfig_Limits_MaxStreams(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}

	stream1Reviewed := make(chan struct{})
	stream2CanProceed := make(chan struct{})
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "token1" {
				close(stream1Reviewed)
				return gatewayKey.Namespace, singlepod.ResourceNameForGateway(gatewayKey.Name), nil
			}
			<-stream2CanProceed
			return gatewayKey.Namespace, singlepod.ResourceNameForGateway(gatewayKey.Name), nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer:        reviewer,
		MaxStreamsPerGateway: 1,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	client := startInProcessServer(t, server)

	outgoingContext1 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token1"))
	stream1, err := client.StreamConfig(outgoingContext1)
	if err != nil {
		t.Fatalf("StreamConfig 1 failed: %v", err)
	}
	if err := stream1.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello 1 failed: %v", err)
	}

	// Wait for stream 1 to be authenticated and in flight before letting stream 2 proceed.
	<-stream1Reviewed
	// Allow stream 2 to proceed; stream 1 has sent Hello and will register before stream 2 finishes auth.
	time.Sleep(10 * time.Millisecond)
	close(stream2CanProceed)

	// Stream 2 should exceed limit and receive ResourceExhausted.
	outgoingContext2 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token2"))
	stream2, err := client.StreamConfig(outgoingContext2)
	if err != nil {
		t.Fatalf("StreamConfig 2 failed: %v", err)
	}
	if err := stream2.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello 2 failed: %v", err)
	}

	message, err := stream2.Recv()
	if err == nil {
		t.Fatalf("expected ResourceExhausted error for stream 2, got: %v", message)
	}
	rpcStatus, ok := status.FromError(err)
	if !ok || rpcStatus.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted, got: %v", err)
	}

	// Closing stream 1 unregisters it, allowing subsequent streams to succeed.
	if err := stream1.CloseSend(); err != nil {
		t.Fatalf("stream1.CloseSend error: %v", err)
	}
	_, _ = stream1.Recv()

	outgoingContext3 := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer token3"))
	stream3, err := client.StreamConfig(outgoingContext3)
	if err != nil {
		t.Fatalf("StreamConfig 3 failed: %v", err)
	}
	if err := stream3.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello 3 failed: %v", err)
	}
	if err := stream3.CloseSend(); err != nil {
		t.Fatalf("stream3.CloseSend error: %v", err)
	}
	_, err = stream3.Recv()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on stream 3, got: %v", err)
	}
}

func TestServer_Serve_ContextCancel(t *testing.T) {
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return "default", "service-account", nil
		},
	}
	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	listener := bufconn.Listen(1024)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener.Close error: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx, listener)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned error on cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit within timeout")
	}
}

func pollUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

func setupTestState(t *testing.T, pub state.DataplanePublisher) *state.State {
	t.Helper()
	st := state.NewState()
	st.SetControllerName("example.net/gateway-controller")
	st.SetDataplanePublisher(pub)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go func() {
		_ = st.Start(ctx)
	}()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)
	return st
}

func addTestGateway(st *state.State, gwKey types.NamespacedName, port int) *gatewayv1.Gateway {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwKey.Namespace,
			Name:      gwKey.Name,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     gatewayv1.SectionName("http"),
					Port:     gatewayv1.PortNumber(port),
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	st.UpsertGateway(gw)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
	return gw
}

func openTestStream(t *testing.T, client push.PushServiceClient, gwKey types.NamespacedName, token string, appliedRev string) (grpc.BidiStreamingClient[push.DataplaneMessage, push.ControllerMessage], *testStreamReader) {
	t.Helper()
	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+token))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gwKey.Namespace,
				GatewayName:      gwKey.Name,
				AppliedRevision:  appliedRev,
			},
		},
	}); err != nil {
		t.Fatalf("Send Hello failed: %v", err)
	}
	reader := newTestStreamReader(stream)
	return stream, reader
}

type testStreamReader struct {
	msgCh chan *push.ControllerMessage
	errCh chan error
}

func newTestStreamReader(stream grpc.BidiStreamingClient[push.DataplaneMessage, push.ControllerMessage]) *testStreamReader {
	r := &testStreamReader{
		msgCh: make(chan *push.ControllerMessage, 10),
		errCh: make(chan error, 10),
	}
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				r.errCh <- err
				return
			}
			r.msgCh <- msg
		}
	}()
	return r
}

func (r *testStreamReader) recv(timeout time.Duration) (*push.Config, error) {
	select {
	case msg := <-r.msgCh:
		cfg := msg.GetConfig()
		if cfg == nil {
			return nil, errors.New("expected Config message, got nil")
		}
		return cfg, nil
	case err := <-r.errCh:
		return nil, err
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

func TestStreamConfig_ReceivesConfigAfterHelloAndOnStateChange(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gwKey.Namespace, expectedSA, nil
			}
			return "", "", errors.New("unauthorized")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	st := setupTestState(t, server)
	addTestGateway(st, gwKey, 80)

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gwKey, "valid-token", "")

	// 1. Receives initial config
	cfg1, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive initial config: %v", err)
	}
	if cfg1.Revision == "" {
		t.Fatal("expected non-empty revision in initial config")
	}
	dpCfg1, err := state.UnmarshalDataplaneConfig(cfg1.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}
	if dpCfg1.GatewayName != gwKey {
		t.Fatalf("expected GatewayName %v, got %v", gwKey, dpCfg1.GatewayName)
	}

	// 2. Change state by updating gateway listener port
	addTestGateway(st, gwKey, 8080)

	// 3. Receives second config with updated revision
	cfg2, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive second config: %v", err)
	}
	if cfg2.Revision == cfg1.Revision {
		t.Fatalf("expected revision to change, but stayed %s", cfg1.Revision)
	}
	dpCfg2, err := state.UnmarshalDataplaneConfig(cfg2.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}
	if dpCfg2.GatewayName != gwKey {
		t.Fatalf("expected GatewayName %v, got %v", gwKey, dpCfg2.GatewayName)
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_HelloWithLatestRevisionReceivesNothingUntilStateChanges(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gwKey.Namespace, expectedSA, nil
			}
			return "", "", errors.New("unauthorized")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	st := setupTestState(t, server)
	addTestGateway(st, gwKey, 80)

	// Wait until real state has published the first config to server
	pollUntil(t, 2*time.Second, func() bool {
		dpCfg := st.GetDataplaneConfig(gwKey)
		return dpCfg != nil && dpCfg.Revision != ""
	})
	currentRev := st.GetDataplaneConfig(gwKey).Revision

	client := startInProcessServer(t, server)

	// Connect with Hello reporting current revision
	stream, reader := openTestStream(t, client, gwKey, "valid-token", currentRev)

	// Must receive nothing initially
	cfg, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no config when Hello reports latest revision, got cfg=%v err=%v", cfg, err)
	}

	// Now trigger state change
	addTestGateway(st, gwKey, 8080)

	// Receives new config after state change
	cfgNew, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("expected new config after state change, got error: %v", err)
	}
	if cfgNew.Revision == currentRev {
		t.Fatalf("expected new revision, got old %s", currentRev)
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_TwoGatewaysTwoStreamsIsolation(t *testing.T) {
	gwKey1 := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	gwKey2 := types.NamespacedName{Namespace: "default", Name: "gw-2"}
	sa1 := singlepod.ResourceNameForGateway(gwKey1.Name)
	sa2 := singlepod.ResourceNameForGateway(gwKey2.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			switch token {
			case "token-gw-1":
				return gwKey1.Namespace, sa1, nil
			case "token-gw-2":
				return gwKey2.Namespace, sa2, nil
			default:
				return "", "", errors.New("unauthorized")
			}
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	st := setupTestState(t, server)
	addTestGateway(st, gwKey1, 80)
	addTestGateway(st, gwKey2, 8080)

	client := startInProcessServer(t, server)

	stream1, reader1 := openTestStream(t, client, gwKey1, "token-gw-1", "")
	stream2, reader2 := openTestStream(t, client, gwKey2, "token-gw-2", "")

	cfg1, err := reader1.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream1 failed to receive config: %v", err)
	}
	dpCfg1, err := state.UnmarshalDataplaneConfig(cfg1.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig 1 failed: %v", err)
	}
	if dpCfg1.GatewayName != gwKey1 {
		t.Fatalf("stream1 expected config for %v, got %v", gwKey1, dpCfg1.GatewayName)
	}

	cfg2, err := reader2.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream2 failed to receive config: %v", err)
	}
	dpCfg2, err := state.UnmarshalDataplaneConfig(cfg2.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig 2 failed: %v", err)
	}
	if dpCfg2.GatewayName != gwKey2 {
		t.Fatalf("stream2 expected config for %v, got %v", gwKey2, dpCfg2.GatewayName)
	}

	// Update only gw-1 in state
	addTestGateway(st, gwKey1, 9090)

	// Stream 1 receives updated config
	cfg1Updated, err := reader1.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream1 failed to receive updated config: %v", err)
	}
	if cfg1Updated.Revision == cfg1.Revision {
		t.Fatalf("stream1 expected new revision")
	}

	// Stream 2 receives nothing
	cfg2Unexpected, err := reader2.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stream2 expected nothing when gw-1 updated, got %v, err=%v", cfg2Unexpected, err)
	}

	_ = stream1.CloseSend()
	_ = stream2.CloseSend()
}

func TestStreamConfig_AckAndNackRecordedAndTruncated(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gwKey.Namespace, expectedSA, nil
			}
			return "", "", errors.New("unauthorized")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	st := setupTestState(t, server)
	addTestGateway(st, gwKey, 80)

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gwKey, "valid-token", "")

	cfg, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive config: %v", err)
	}

	// 1. Send Ack
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: cfg.Revision},
		},
	}); err != nil {
		t.Fatalf("failed to send Ack: %v", err)
	}

	pollUntil(t, 2*time.Second, func() bool {
		replies := server.StreamReplies(gwKey)
		return len(replies) == 1 && replies[0].Accepted && replies[0].Revision == cfg.Revision
	})
	ackReplies := server.StreamReplies(gwKey)
	if ackReplies[0].Reason != "" {
		t.Fatalf("expected empty reason for Ack, got %q", ackReplies[0].Reason)
	}

	// 2. Send Nack with reason longer than MaxNACKReasonBytes (1024 bytes)
	longReason := strings.Repeat("A", 2000)
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: "failed-rev",
				Reason:   longReason,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send Nack: %v", err)
	}

	pollUntil(t, 2*time.Second, func() bool {
		replies := server.StreamReplies(gwKey)
		return len(replies) == 1 && !replies[0].Accepted && replies[0].Revision == "failed-rev"
	})

	nackReplies := server.StreamReplies(gwKey)
	if len(nackReplies[0].Reason) != push.MaxNACKReasonBytes {
		t.Fatalf("expected reason length %d, got %d", push.MaxNACKReasonBytes, len(nackReplies[0].Reason))
	}
	expectedReason := strings.Repeat("A", push.MaxNACKReasonBytes)
	if nackReplies[0].Reason != expectedReason {
		t.Fatalf("truncated reason mismatch")
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_SecretPathUnchanged(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)
	secretName := singlepod.ResourceNameForGateway(gwKey.Name)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	addrProvider := singlepod.NewAddressProvider(fakeClient)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gwKey.Namespace, expectedSA, nil
			}
			return "", "", errors.New("unauthorized")
		},
	}

	pushServer, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	multiPub := state.NewMultiDataplanePublisher(addrProvider, pushServer)
	st := setupTestState(t, multiPub)
	addTestGateway(st, gwKey, 80)

	client := startInProcessServer(t, pushServer)
	stream, reader := openTestStream(t, client, gwKey, "valid-token", "")

	// 1. Verify push stream receives the config
	pushedCfg, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive config on push stream: %v", err)
	}

	// 2. Verify Secret is published in the fake client
	var sec corev1.Secret
	pollUntil(t, 2*time.Second, func() bool {
		err := fakeClient.Get(t.Context(), types.NamespacedName{Namespace: gwKey.Namespace, Name: secretName}, &sec)
		return err == nil && len(sec.Data[singlepod.DataplaneSecretDataKey]) > 0
	})

	secData := sec.Data[singlepod.DataplaneSecretDataKey]
	secretCfg, err := state.UnmarshalDataplaneConfig(secData)
	if err != nil {
		t.Fatalf("failed to unmarshal secret config: %v", err)
	}

	// 3. Secret config and push stream config must carry identical revision and gateway name
	if secretCfg.Revision != pushedCfg.Revision {
		t.Fatalf("revision mismatch: Secret has %s, push stream has %s", secretCfg.Revision, pushedCfg.Revision)
	}
	if secretCfg.GatewayName != gwKey {
		t.Fatalf("expected gateway name %v in Secret, got %v", gwKey, secretCfg.GatewayName)
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_OversizedConfigNotSentStreamStaysOpen(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gwKey.Namespace, expectedSA, nil
			}
			return "", "", errors.New("unauthorized")
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create an oversized config (> 4 MiB)
	hugePayload := strings.Repeat("A", push.MaxConfigMessageBytes+1024)
	oversizedConfig := &state.DataplaneConfig{
		GatewayName: gwKey,
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
		DefaultCertID: hugePayload,
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gw, oversizedConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gwKey, "valid-token", "")

	// Oversized config should NOT be received
	cfg, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no config when oversized, got cfg=%v, err=%v", cfg, err)
	}

	// Stream is still open; publish normal config and verify it is received
	normalConfig := &state.DataplaneConfig{
		GatewayName: gwKey,
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gw, normalConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig normal failed: %v", err)
	}

	receivedNormal, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive normal config on open stream: %v", err)
	}
	if receivedNormal.Revision == "" {
		t.Fatal("expected non-empty revision for normal config")
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_CoalesceIntermediateRevisions(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gwKey.Namespace, expectedSA, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}

	// 1. Publish rev-1
	cfg1 := &state.DataplaneConfig{Revision: "rev-1", GatewayName: gwKey}
	if err := server.PublishDataplaneConfig(t.Context(), gw, cfg1); err != nil {
		t.Fatalf("PublishDataplaneConfig 1 failed: %v", err)
	}

	client := startInProcessServer(t, server)
	// Connect reporting rev-1 as already applied
	stream, reader := openTestStream(t, client, gwKey, "token", "rev-1")

	// Verify nothing sent initially
	recInit, err := reader.recv(50 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no initial config, got %v", recInit)
	}

	// Publish rev-2, rev-3, rev-4
	for _, rev := range []string{"rev-2", "rev-3", "rev-4"} {
		cfg := &state.DataplaneConfig{Revision: rev, GatewayName: gwKey}
		if err := server.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
			t.Fatalf("PublishDataplaneConfig %s failed: %v", rev, err)
		}
	}

	// Stream reads: should receive rev-4!
	recNext, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive next config: %v", err)
	}
	if recNext.Revision != "rev-4" {
		t.Fatalf("expected coalesced latest revision rev-4, got %s", recNext.Revision)
	}

	// Verify no more configs arrive
	recExtra, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no extra configs after rev-4, got %v, err=%v", recExtra, err)
	}

	_ = stream.CloseSend()
}

func TestStreamConfig_GatewayRemovedDropsConfig(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gwKey.Namespace, expectedSA, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name},
	}
	cfg := &state.DataplaneConfig{Revision: "rev-1", GatewayName: gwKey}
	if err := server.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	// Remove gateway by publishing nil config
	if err := server.PublishDataplaneConfig(t.Context(), gw, nil); err != nil {
		t.Fatalf("PublishDataplaneConfig deletion failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gwKey, "token", "")

	// Since config was dropped, stream receives nothing
	rec, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected nothing after gateway removed, got %v, err=%v", rec, err)
	}

	_ = stream.CloseSend()
}

type slowStreamWrapper struct {
	grpc.ServerStream
	delay time.Duration
}

func (w *slowStreamWrapper) SendMsg(m any) error {
	if _, ok := m.(*push.ControllerMessage); ok {
		time.Sleep(w.delay)
	}
	return w.ServerStream.SendMsg(m)
}

func slowSendInterceptor(delay time.Duration) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &slowStreamWrapper{ServerStream: ss, delay: delay})
	}
}

func TestStreamConfig_SlowReaderClosedAfterTimeout(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedSA := singlepod.ResourceNameForGateway(gwKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gwKey.Namespace, expectedSA, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
		SendTimeout:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name}}
	cfg := &state.DataplaneConfig{GatewayName: gwKey, Revision: "rev-1"}
	if err := server.PublishDataplaneConfig(t.Context(), gw, cfg); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	listener := bufconn.Listen(1024)
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() {
		_ = server.Serve(ctx, listener, grpc.StreamInterceptor(slowSendInterceptor(200*time.Millisecond)))
	}()

	clientConn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(testDialer(listener)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	client := push.NewPushServiceClient(clientConn)

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer valid-token"))
	stream, err := client.StreamConfig(outgoingContext)
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

	// Server attempts to push config, but slowSendInterceptor delays SendMsg by 200ms,
	// exceeding SendTimeout of 50ms, causing the stream to close with DeadlineExceeded.
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Fatal("expected error due to slow reader closure, got nil")
	}
	rpcStatus, ok := status.FromError(recvErr)
	if !ok || rpcStatus.Code() != codes.DeadlineExceeded {
		t.Fatalf("expected codes.DeadlineExceeded, got: %v", recvErr)
	}
}
