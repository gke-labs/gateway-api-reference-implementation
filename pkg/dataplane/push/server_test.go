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
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func startInProcessServer(t *testing.T, server *push.Server, options ...grpc.ServerOption) push.PushServiceClient {
	t.Helper()
	const bufferSize = 1024 * 1024
	listener := bufconn.Listen(bufferSize)

	ctx, cancel := context.WithCancel(t.Context())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(ctx, listener, options...)
	}()

	clientConn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(testDialer(listener)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		if serveErr := <-serverDone; serveErr != nil {
			t.Errorf("server.Serve error: %v", serveErr)
		}
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("listener.Close error: %v", closeErr)
		}
		t.Fatalf("failed to dial in-process server: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			t.Errorf("clientConn.Close error: %v", closeErr)
		}
		cancel()
		if serveErr := <-serverDone; serveErr != nil {
			t.Errorf("server.Serve error: %v", serveErr)
		}
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("listener.Close error: %v", closeErr)
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
	if _, err := stream1.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on stream 1, got: %v", err)
	}

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
		if err := st.Start(ctx); err != nil {
			t.Errorf("st.Start error: %v", err)
		}
	}()

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}
	st.UpsertGatewayClass(gc)
	return st
}

func addTestGateway(stateEngine *state.State, gatewayKey types.NamespacedName, port int) *gatewayv1.Gateway {
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayKey.Namespace,
			Name:      gatewayKey.Name,
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
	stateEngine.UpsertGateway(gateway)
	stateEngine.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	stateEngine.SetGatewayReadiness(gatewayKey, state.GatewayReadiness{Ready: true})
	return gateway
}

func openTestStream(t *testing.T, client push.PushServiceClient, gatewayKey types.NamespacedName, token string, appliedRevision string) (grpc.BidiStreamingClient[push.DataplaneMessage, push.ControllerMessage], *testStreamReader) {
	t.Helper()
	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+token))
	stream, err := client.StreamConfig(outgoingContext)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: gatewayKey.Namespace,
				GatewayName:      gatewayKey.Name,
				AppliedRevision:  appliedRevision,
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
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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

	stateEngine := setupTestState(t, server)
	addTestGateway(stateEngine, gatewayKey, 80)

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", "")

	// 1. Receives initial config
	config1, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive initial config: %v", err)
	}
	if config1.Revision == "" {
		t.Fatal("expected non-empty revision in initial config")
	}
	dataplaneConfig1, err := state.UnmarshalDataplaneConfig(config1.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}
	if dataplaneConfig1.GatewayName != gatewayKey {
		t.Fatalf("expected GatewayName %v, got %v", gatewayKey, dataplaneConfig1.GatewayName)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}

	// Send Ack for initial config and verify WaitApplied returns applied
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: config1.Revision},
		},
	}); err != nil {
		t.Fatalf("failed to send Ack: %v", err)
	}

	res1, err := server.WaitApplied(t.Context(), gateway, config1.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed: %v", err)
	}
	if res1.Applied != 1 || res1.NotAnswered != 0 || len(res1.Rejections) != 0 {
		t.Fatalf("expected Applied=1, got %+v", res1)
	}

	// 2. Change state by updating gateway listener port
	addTestGateway(stateEngine, gatewayKey, 8080)

	// 3. Receives second config with updated revision
	config2, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive second config: %v", err)
	}
	if config2.Revision == config1.Revision {
		t.Fatalf("expected revision to change, but stayed %s", config1.Revision)
	}
	dataplaneConfig2, err := state.UnmarshalDataplaneConfig(config2.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}
	if dataplaneConfig2.GatewayName != gatewayKey {
		t.Fatalf("expected GatewayName %v, got %v", gatewayKey, dataplaneConfig2.GatewayName)
	}

	// Send Ack for second config and verify WaitApplied returns applied
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: config2.Revision},
		},
	}); err != nil {
		t.Fatalf("failed to send Ack for second config: %v", err)
	}

	res2, err := server.WaitApplied(t.Context(), gateway, config2.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed for second config: %v", err)
	}
	if res2.Applied != 1 || res2.NotAnswered != 0 || len(res2.Rejections) != 0 {
		t.Fatalf("expected Applied=1 for second config, got %+v", res2)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_HelloWithLatestRevisionReceivesNothingUntilStateChanges(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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

	stateEngine := setupTestState(t, server)
	addTestGateway(stateEngine, gatewayKey, 80)

	// Wait until real state has published the first config to server
	pollUntil(t, 2*time.Second, func() bool {
		dataplaneConfig := stateEngine.GetDataplaneConfig(gatewayKey)
		return dataplaneConfig != nil && dataplaneConfig.Revision != ""
	})
	currentRevision := stateEngine.GetDataplaneConfig(gatewayKey).Revision

	client := startInProcessServer(t, server)

	// Connect with Hello reporting current revision
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", currentRevision)

	// Must receive nothing initially
	config, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no config when Hello reports latest revision, got config=%v err=%v", config, err)
	}

	// Now trigger state change
	addTestGateway(stateEngine, gatewayKey, 8080)

	// Receives new config after state change
	newConfig, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("expected new config after state change, got error: %v", err)
	}
	if newConfig.Revision == currentRevision {
		t.Fatalf("expected new revision, got old %s", currentRevision)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_TwoGatewaysTwoStreamsIsolation(t *testing.T) {
	gatewayKey1 := types.NamespacedName{Namespace: "default", Name: "gw-1"}
	gatewayKey2 := types.NamespacedName{Namespace: "default", Name: "gw-2"}
	serviceAccount1 := singlepod.ResourceNameForGateway(gatewayKey1.Name)
	serviceAccount2 := singlepod.ResourceNameForGateway(gatewayKey2.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			switch token {
			case "token-gw-1":
				return gatewayKey1.Namespace, serviceAccount1, nil
			case "token-gw-2":
				return gatewayKey2.Namespace, serviceAccount2, nil
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

	stateEngine := setupTestState(t, server)
	addTestGateway(stateEngine, gatewayKey1, 80)
	addTestGateway(stateEngine, gatewayKey2, 8080)

	client := startInProcessServer(t, server)

	stream1, reader1 := openTestStream(t, client, gatewayKey1, "token-gw-1", "")
	stream2, reader2 := openTestStream(t, client, gatewayKey2, "token-gw-2", "")

	config1, err := reader1.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream1 failed to receive config: %v", err)
	}
	dataplaneConfig1, err := state.UnmarshalDataplaneConfig(config1.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig 1 failed: %v", err)
	}
	if dataplaneConfig1.GatewayName != gatewayKey1 {
		t.Fatalf("stream1 expected config for %v, got %v", gatewayKey1, dataplaneConfig1.GatewayName)
	}

	config2, err := reader2.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream2 failed to receive config: %v", err)
	}
	dataplaneConfig2, err := state.UnmarshalDataplaneConfig(config2.DataplaneConfig)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig 2 failed: %v", err)
	}
	if dataplaneConfig2.GatewayName != gatewayKey2 {
		t.Fatalf("stream2 expected config for %v, got %v", gatewayKey2, dataplaneConfig2.GatewayName)
	}

	// Update only gw-1 in state
	addTestGateway(stateEngine, gatewayKey1, 9090)

	// Stream 1 receives updated config
	config1Updated, err := reader1.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("stream1 failed to receive updated config: %v", err)
	}
	if config1Updated.Revision == config1.Revision {
		t.Fatalf("stream1 expected new revision")
	}

	// Stream 2 receives nothing
	config2Unexpected, err := reader2.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stream2 expected nothing when gw-1 updated, got %v, err=%v", config2Unexpected, err)
	}

	gateway1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey1.Namespace, Name: gatewayKey1.Name},
	}
	gateway2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey2.Namespace, Name: gatewayKey2.Name},
	}

	// Stream 1 acknowledges updated config for gw-1
	if err := stream1.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Ack{
			Ack: &push.Ack{AppliedRevision: config1Updated.Revision},
		},
	}); err != nil {
		t.Fatalf("stream1 failed to send Ack: %v", err)
	}

	// WaitApplied for gw-1 reports Applied=1
	res1, err := server.WaitApplied(t.Context(), gateway1, config1Updated.Revision)
	if err != nil {
		t.Fatalf("WaitApplied gw-1 failed: %v", err)
	}
	if res1.Applied != 1 || res1.NotAnswered != 0 || len(res1.Rejections) != 0 {
		t.Fatalf("expected gw-1 Applied=1, got: %+v", res1)
	}

	// WaitApplied for gw-2 querying gw-1's revision reports NotAnswered=1 (only gw-2's stream is checked, and it has not answered for that revision)
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer shortCancel()
	res2ForGw1Rev, err := server.WaitApplied(shortCtx, gateway2, config1Updated.Revision)
	if err != nil {
		t.Fatalf("WaitApplied gw-2 unexpected error: %v", err)
	}
	if res2ForGw1Rev.NotAnswered != 1 || res2ForGw1Rev.Applied != 0 {
		t.Fatalf("expected gw-2 NotAnswered=1 for gw-1 revision, got: %+v", res2ForGw1Rev)
	}

	if err := stream1.CloseSend(); err != nil {
		t.Fatalf("stream1.CloseSend error: %v", err)
	}
	if err := stream2.CloseSend(); err != nil {
		t.Fatalf("stream2.CloseSend error: %v", err)
	}
}

func TestStreamConfig_NackRejectionWithReasonTruncatedUTF8(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}
	config := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "rev-nack-test",
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", "")

	if _, err := reader.recv(2 * time.Second); err != nil {
		t.Fatalf("failed to receive config: %v", err)
	}

	// Reason longer than MaxNACKReasonBytes (1024) where byte 1024 cuts across
	// a multi-byte UTF-8 character (1023 'A's + "世界" which is multi-byte UTF-8).
	// Truncation must drop the partial rune and yield valid UTF-8 of length <= 1024.
	longReason := strings.Repeat("A", 1023) + "世界" + strings.Repeat("B", 1000)
	if err := stream.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: config.Revision,
				Reason:   longReason,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send Nack: %v", err)
	}

	result, err := server.WaitApplied(t.Context(), gateway, config.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed: %v", err)
	}
	if result.Applied != 0 {
		t.Errorf("expected Applied=0, got %d", result.Applied)
	}
	if len(result.Rejections) != 1 {
		t.Fatalf("expected 1 rejection, got %d", len(result.Rejections))
	}
	if result.Rejections[0].DataPlane == "" {
		t.Errorf("expected non-empty DataPlane")
	}
	if len(result.Rejections[0].Reason) > push.MaxNACKReasonBytes {
		t.Errorf("expected reason length <= %d, got %d", push.MaxNACKReasonBytes, len(result.Rejections[0].Reason))
	}
	if !utf8.ValidString(result.Rejections[0].Reason) {
		t.Errorf("expected valid UTF-8 string in rejection reason")
	}
	if result.Rejections[0].Reason != strings.Repeat("A", 1023) {
		t.Errorf("expected reason to be truncated to 1023 'A's at UTF-8 boundary, got length %d", len(result.Rejections[0].Reason))
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_NeverReplies_WaitAppliedReturnsNotAnswered(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}
	config := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "rev-never-reply",
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", "")

	if _, err := reader.recv(2 * time.Second); err != nil {
		t.Fatalf("failed to receive config: %v", err)
	}

	// Data plane never sends Ack or Nack; verify WaitApplied returns when context ends
	waitCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	result, err := server.WaitApplied(waitCtx, gateway, config.Revision)
	if err != nil {
		t.Fatalf("expected nil error when context deadline ends, got: %v", err)
	}
	if result.NotAnswered != 1 {
		t.Errorf("expected NotAnswered=1, got %d", result.NotAnswered)
	}
	if result.Applied != 0 {
		t.Errorf("expected Applied=0, got %d", result.Applied)
	}
	if len(result.Rejections) != 0 {
		t.Errorf("expected 0 rejections, got %d", len(result.Rejections))
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestPublishDataplaneConfig_RequiresRevision(t *testing.T) {
	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return "default", "gari-my-gateway-6632e849", nil
		},
	}
	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gateway"},
	}
	configWithoutRevision := &state.DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "default", Name: "my-gateway"},
	}

	err = server.PublishDataplaneConfig(t.Context(), gateway, configWithoutRevision)
	if err == nil {
		t.Fatal("expected error when publishing config with empty revision, got nil")
	}
}

func TestStreamConfig_ClosedStreamWhileMessagesArriveCleansUp(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer:        reviewer,
		MaxStreamsPerGateway: 1,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}
	initialConfig := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "rev-0",
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, initialConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream1, reader1 := openTestStream(t, client, gatewayKey, "valid-token", "")

	// Read initial config so stream 1 is actively flowing
	if _, err := reader1.recv(1 * time.Second); err != nil {
		t.Fatalf("stream1 failed to receive initial config: %v", err)
	}

	// Concurrently publish configurations while closing stream 1
	stopPublishing := make(chan struct{})
	publishDone := make(chan struct{})
	go func() {
		defer close(publishDone)
		var revisionCounter int
		for {
			select {
			case <-stopPublishing:
				return
			default:
				revisionCounter++
				config := &state.DataplaneConfig{
					GatewayName: gatewayKey,
					Revision:    fmt.Sprintf("rev-%d", revisionCounter),
				}
				if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
					t.Errorf("PublishDataplaneConfig error: %v", err)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	// Close stream 1 from the client while messages are arriving
	if err := stream1.CloseSend(); err != nil {
		t.Fatalf("stream1.CloseSend error: %v", err)
	}

	// Drain receiver until stream 1 closes
	drainDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(drainDeadline) {
		_, err := reader1.recv(50 * time.Millisecond)
		if err != nil {
			break
		}
	}

	close(stopPublishing)
	<-publishDone

	// Publish the latest config that the second stream should receive
	finalConfig := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "final-rev",
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, finalConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig final failed: %v", err)
	}

	// Because MaxStreamsPerGateway is 1, a second stream is accepted only if
	// the first stream was completely cleaned up once its handler returned.
	stream2, reader2 := openTestStream(t, client, gatewayKey, "valid-token", "")
	config, err := reader2.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("second stream failed to be accepted and receive config: %v", err)
	}
	if config.Revision != "final-rev" {
		t.Fatalf("expected second stream to receive latest revision final-rev, got %s", config.Revision)
	}
	if err := stream2.CloseSend(); err != nil {
		t.Fatalf("stream2.CloseSend error: %v", err)
	}
}

func TestStreamConfig_SecretPathUnchanged(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)
	secretName := singlepod.ResourceNameForGateway(gatewayKey.Name)

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme failed: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("gatewayv1.AddToScheme failed: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	addrProvider := singlepod.NewAddressProvider(fakeClient)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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
	stateEngine := setupTestState(t, multiPub)
	addTestGateway(stateEngine, gatewayKey, 80)

	client := startInProcessServer(t, pushServer)
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", "")

	// 1. Verify push stream receives the config
	pushedConfig, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive config on push stream: %v", err)
	}

	// 2. Verify Secret is published in the fake client
	var secret corev1.Secret
	pollUntil(t, 2*time.Second, func() bool {
		err := fakeClient.Get(t.Context(), types.NamespacedName{Namespace: gatewayKey.Namespace, Name: secretName}, &secret)
		return err == nil && len(secret.Data[singlepod.DataplaneSecretDataKey]) > 0
	})

	secretData := secret.Data[singlepod.DataplaneSecretDataKey]
	secretConfig, err := state.UnmarshalDataplaneConfig(secretData)
	if err != nil {
		t.Fatalf("failed to unmarshal secret config: %v", err)
	}

	// 3. Secret config and push stream config must carry identical revision and gateway name
	if secretConfig.Revision != pushedConfig.Revision {
		t.Fatalf("revision mismatch: Secret has %s, push stream has %s", secretConfig.Revision, pushedConfig.Revision)
	}
	if secretConfig.GatewayName != gatewayKey {
		t.Fatalf("expected gateway name %v in Secret, got %v", gatewayKey, secretConfig.GatewayName)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_OversizedConfigNotSentStreamStaysOpen(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			if token == "valid-token" {
				return gatewayKey.Namespace, expectedServiceAccount, nil
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
		GatewayName: gatewayKey,
		Revision:    "oversized-rev",
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
		DefaultCertID: hugePayload,
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, oversizedConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gatewayKey, "valid-token", "")

	// Oversized config should NOT be received
	cfg, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no config when oversized, got cfg=%v, err=%v", cfg, err)
	}

	// WaitApplied reports rejection for oversized config
	res, err := server.WaitApplied(t.Context(), gateway, oversizedConfig.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed for oversized config: %v", err)
	}
	if res.Applied != 0 {
		t.Errorf("expected Applied=0 for oversized config, got %d", res.Applied)
	}
	if len(res.Rejections) != 1 {
		t.Fatalf("expected 1 rejection for oversized config, got %d", len(res.Rejections))
	}
	if !strings.Contains(res.Rejections[0].Reason, "MaxConfigMessageBytes") {
		t.Errorf("expected rejection reason to mention MaxConfigMessageBytes, got %q", res.Rejections[0].Reason)
	}
	if res.Rejections[0].DataPlane == "" {
		t.Errorf("expected non-empty DataPlane")
	}

	// Stream is still open; publish normal config and verify it is received
	normalConfig := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "normal-rev",
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, normalConfig); err != nil {
		t.Fatalf("PublishDataplaneConfig normal failed: %v", err)
	}

	receivedNormal, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive normal config on open stream: %v", err)
	}
	if receivedNormal.Revision != "normal-rev" {
		t.Fatalf("expected revision normal-rev, got %q", receivedNormal.Revision)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

type slowStreamWrapper struct {
	grpc.ServerStream
	delay time.Duration
}

func (wrapper *slowStreamWrapper) SendMsg(message any) error {
	if _, ok := message.(*push.ControllerMessage); ok {
		time.Sleep(wrapper.delay)
	}
	return wrapper.ServerStream.SendMsg(message)
}

func slowSendInterceptor(delay time.Duration) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &slowStreamWrapper{ServerStream: ss, delay: delay})
	}
}

func TestStreamConfig_CoalesceIntermediateRevisions(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Each Send takes 50ms, ensuring send is in progress when subsequent revisions arrive
	client := startInProcessServer(t, server, grpc.StreamInterceptor(slowSendInterceptor(50*time.Millisecond)))

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}

	// 1. Publish rev-1
	config1 := &state.DataplaneConfig{Revision: "rev-1", GatewayName: gatewayKey}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config1); err != nil {
		t.Fatalf("PublishDataplaneConfig 1 failed: %v", err)
	}

	// Connect reporting rev-1 as already applied
	stream, reader := openTestStream(t, client, gatewayKey, "token", "rev-1")

	// Verify nothing sent initially
	receivedInitial, err := reader.recv(50 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no initial config, got %v", receivedInitial)
	}

	// Publish rev-2 (which begins sending and takes 50ms)
	config2 := &state.DataplaneConfig{Revision: "rev-2", GatewayName: gatewayKey}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config2); err != nil {
		t.Fatalf("PublishDataplaneConfig 2 failed: %v", err)
	}

	// While rev-2 is in flight, publish rev-3 and rev-4
	time.Sleep(10 * time.Millisecond)
	config3 := &state.DataplaneConfig{Revision: "rev-3", GatewayName: gatewayKey}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config3); err != nil {
		t.Fatalf("PublishDataplaneConfig 3 failed: %v", err)
	}
	config4 := &state.DataplaneConfig{Revision: "rev-4", GatewayName: gatewayKey}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config4); err != nil {
		t.Fatalf("PublishDataplaneConfig 4 failed: %v", err)
	}

	// Stream reads rev-2
	received2, err := reader.recv(2 * time.Second)
	if err != nil || received2.Revision != "rev-2" {
		t.Fatalf("expected rev-2, got %v, err=%v", received2, err)
	}

	// Stream reads next: rev-3 was skipped while rev-2 was in flight, so rev-4 is received!
	received4, err := reader.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("failed to receive next config: %v", err)
	}
	if received4.Revision != "rev-4" {
		t.Fatalf("expected coalesced latest revision rev-4, got %s", received4.Revision)
	}

	// Verify no more configs arrive (rev-3 was never sent)
	receivedExtra, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected no extra configs after rev-4, got %v, err=%v", receivedExtra, err)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_GatewayRemovedDropsConfig(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name},
	}
	config := &state.DataplaneConfig{Revision: "rev-1", GatewayName: gatewayKey}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	// Remove gateway by publishing nil config
	if err := server.PublishDataplaneConfig(t.Context(), gateway, nil); err != nil {
		t.Fatalf("PublishDataplaneConfig deletion failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream, reader := openTestStream(t, client, gatewayKey, "token", "")

	// Since config was dropped, stream receives nothing
	received, err := reader.recv(100 * time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected nothing after gateway removed, got %v, err=%v", received, err)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("stream.CloseSend error: %v", err)
	}
}

func TestStreamConfig_SlowReaderClosedAfterTimeout(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	server.SetSendTimeoutForTest(50 * time.Millisecond)

	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name}}
	config := &state.DataplaneConfig{GatewayName: gatewayKey, Revision: "rev-1"}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server, grpc.StreamInterceptor(slowSendInterceptor(200*time.Millisecond)))

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer valid-token"))
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

	// Server attempts to push config, but slowSendInterceptor delays SendMsg by 200ms,
	// exceeding sendTimeout of 50ms, causing the stream to close with DeadlineExceeded.
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Fatal("expected error due to slow reader closure, got nil")
	}
	rpcStatus, ok := status.FromError(recvErr)
	if !ok || rpcStatus.Code() != codes.DeadlineExceeded {
		t.Fatalf("expected codes.DeadlineExceeded, got: %v", recvErr)
	}

	// WaitApplied reports the timeout failure as a rejection that outlives the closed stream
	result, err := server.WaitApplied(t.Context(), gateway, config.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed: %v", err)
	}
	if len(result.Rejections) != 1 {
		t.Fatalf("expected 1 rejection for timed out stream, got: %+v", result)
	}
	if !strings.Contains(result.Rejections[0].Reason, "timed out") {
		t.Errorf("expected rejection reason to mention timeout, got %q", result.Rejections[0].Reason)
	}
	if result.Rejections[0].DataPlane == "" {
		t.Errorf("expected non-empty DataPlane")
	}
}

type failSendStreamWrapper struct {
	grpc.ServerStream
}

func (wrapper *failSendStreamWrapper) SendMsg(message any) error {
	if _, ok := message.(*push.ControllerMessage); ok {
		return errors.New("simulated network send error")
	}
	return wrapper.ServerStream.SendMsg(message)
}

func failSendInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &failSendStreamWrapper{ServerStream: ss})
	}
}

func TestStreamConfig_FailedSendPersistsAsRejectionUntilNextPublish(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer: reviewer,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name}}
	config1 := &state.DataplaneConfig{GatewayName: gatewayKey, Revision: "rev-1"}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config1); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server, grpc.StreamInterceptor(failSendInterceptor()))

	outgoingContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer valid-token"))
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

	// Server tries to send config1, but failSendInterceptor fails it.
	// The stream receives an error and terminates.
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Fatal("expected receive error from failed send, got nil")
	}

	// WaitApplied reports the failed send as a rejection for rev-1 that outlives the stream
	res1, err := server.WaitApplied(t.Context(), gateway, config1.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed: %v", err)
	}
	if len(res1.Rejections) != 1 {
		t.Fatalf("expected 1 rejection for failed send, got: %+v", res1)
	}
	if !strings.Contains(res1.Rejections[0].Reason, "failed to send dataplane config") {
		t.Errorf("expected reason to mention failed to send, got %q", res1.Rejections[0].Reason)
	}
	if res1.Rejections[0].DataPlane == "" {
		t.Errorf("expected non-empty DataPlane")
	}

	// Next publish for this Gateway clears the persistent failure
	config2 := &state.DataplaneConfig{GatewayName: gatewayKey, Revision: "rev-2"}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config2); err != nil {
		t.Fatalf("PublishDataplaneConfig config2 failed: %v", err)
	}

	// Since the stream closed and the failure was cleared, WaitApplied for rev-2 reports no data plane
	res2, err := server.WaitApplied(t.Context(), gateway, config2.Revision)
	if err != nil {
		t.Fatalf("WaitApplied config2 failed: %v", err)
	}
	if res2.Applied != 0 || len(res2.Rejections) != 0 || res2.NotAnswered != 0 {
		t.Fatalf("expected all zeros after failure cleared, got: %+v", res2)
	}
}

func TestStreamConfig_TwoStreamsRejectionsHaveDistinctDataPlanes(t *testing.T) {
	gatewayKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	expectedServiceAccount := singlepod.ResourceNameForGateway(gatewayKey.Name)

	reviewer := &staticTokenReviewer{
		reviewFunc: func(ctx context.Context, token string) (string, string, error) {
			return gatewayKey.Namespace, expectedServiceAccount, nil
		},
	}

	server, err := push.NewServer(push.ServerOptions{
		TokenReviewer:        reviewer,
		MaxStreamsPerGateway: 2,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: gatewayKey.Namespace, Name: gatewayKey.Name}}
	config := &state.DataplaneConfig{
		GatewayName: gatewayKey,
		Revision:    "rev-two-streams",
		Listeners: []state.InternalListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}
	if err := server.PublishDataplaneConfig(t.Context(), gateway, config); err != nil {
		t.Fatalf("PublishDataplaneConfig failed: %v", err)
	}

	client := startInProcessServer(t, server)
	stream1, reader1 := openTestStream(t, client, gatewayKey, "valid-token", "")
	stream2, reader2 := openTestStream(t, client, gatewayKey, "valid-token", "")

	if _, err := reader1.recv(2 * time.Second); err != nil {
		t.Fatalf("stream1 failed to receive config: %v", err)
	}
	if _, err := reader2.recv(2 * time.Second); err != nil {
		t.Fatalf("stream2 failed to receive config: %v", err)
	}

	if err := stream1.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: config.Revision,
				Reason:   "failure from stream 1",
			},
		},
	}); err != nil {
		t.Fatalf("stream1 failed to send Nack: %v", err)
	}

	if err := stream2.Send(&push.DataplaneMessage{
		Body: &push.DataplaneMessage_Nack{
			Nack: &push.Nack{
				Revision: config.Revision,
				Reason:   "failure from stream 2",
			},
		},
	}); err != nil {
		t.Fatalf("stream2 failed to send Nack: %v", err)
	}

	result, err := server.WaitApplied(t.Context(), gateway, config.Revision)
	if err != nil {
		t.Fatalf("WaitApplied failed: %v", err)
	}
	if len(result.Rejections) != 2 {
		t.Fatalf("expected 2 rejections, got: %+v", result.Rejections)
	}
	if result.Rejections[0].DataPlane == result.Rejections[1].DataPlane {
		t.Errorf("expected distinct DataPlane identifiers for different streams, got both %q", result.Rejections[0].DataPlane)
	}

	if err := stream1.CloseSend(); err != nil {
		t.Fatalf("stream1.CloseSend error: %v", err)
	}
	if err := stream2.CloseSend(); err != nil {
		t.Fatalf("stream2.CloseSend error: %v", err)
	}
}
