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
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
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
