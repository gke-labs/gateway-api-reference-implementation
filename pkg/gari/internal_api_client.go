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

package gari

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

const (
	// defaultInternalAPIClientMinBackoff is the minimum backoff delay between reconnect attempts.
	defaultInternalAPIClientMinBackoff = 100 * time.Millisecond

	// defaultInternalAPIClientMaxBackoff is the maximum backoff delay between reconnect attempts.
	defaultInternalAPIClientMaxBackoff = 30 * time.Second
)

// internalAPIClient connects to the controller's internal API Service over TLS
// to receive configuration streams and acknowledge them.
type internalAPIClient struct {
	// server is the parent GARI server whose proxy configuration is updated.
	server *Server

	// options holds the data plane configuration options.
	options Options

	// minBackoff is the initial backoff delay before reconnect attempts.
	minBackoff time.Duration

	// maxBackoff is the maximum backoff delay before reconnect attempts.
	maxBackoff time.Duration
}

func newInternalAPIClient(server *Server, options Options) *internalAPIClient {
	return &internalAPIClient{
		server:     server,
		options:    options,
		minBackoff: defaultInternalAPIClientMinBackoff,
		maxBackoff: defaultInternalAPIClientMaxBackoff,
	}
}

func loadTLSConfig(caFile string, address string) (*tls.Config, error) {
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle file %q: %w", caFile, err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("no valid certificates in CA bundle file %q", caFile)
	}

	serverName, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing internal API address %q: %w", address, err)
	}

	return &tls.Config{
		RootCAs:    certPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func (client *internalAPIClient) run(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	backoff := client.minBackoff

	for {
		receivedMessage, err := client.runStream(ctx)
		if ctx.Err() != nil {
			return nil
		}

		logger.Error(err, "dataplane internal API stream disconnected, retrying",
			"gatewayNamespace", client.options.DataplaneGatewayNamespace,
			"gatewayName", client.options.DataplaneGatewayName,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		if receivedMessage {
			backoff = client.minBackoff
		} else {
			backoff = min(backoff*2, client.maxBackoff)
		}
	}
}

func (client *internalAPIClient) runStream(ctx context.Context) (bool, error) {
	logger := klog.FromContext(ctx)
	receivedMessage := false

	tokenBytes, err := os.ReadFile(client.options.InternalAPITokenFile)
	if err != nil {
		return receivedMessage, fmt.Errorf("reading token file %q: %w", client.options.InternalAPITokenFile, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return receivedMessage, fmt.Errorf("token file %q is empty", client.options.InternalAPITokenFile)
	}

	tlsConfig, err := loadTLSConfig(client.options.InternalAPICAFile, client.options.InternalAPIAddress)
	if err != nil {
		return receivedMessage, err
	}

	conn, err := grpc.NewClient(
		client.options.InternalAPIAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(push.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(push.MaxMessageBytes),
		),
	)
	if err != nil {
		return receivedMessage, fmt.Errorf("creating gRPC client for %s: %w", client.options.InternalAPIAddress, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Error(closeErr, "failed to close gRPC client connection")
		}
	}()

	pushClient := push.NewPushServiceClient(conn)
	streamCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	stream, err := pushClient.StreamConfig(streamCtx)
	if err != nil {
		return receivedMessage, fmt.Errorf("opening push stream: %w", err)
	}

	gatewayKey := types.NamespacedName{
		Namespace: client.options.DataplaneGatewayNamespace,
		Name:      client.options.DataplaneGatewayName,
	}.String()
	appliedRevision := client.server.AppliedRevision(gatewayKey)

	hello := &push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: client.options.DataplaneGatewayNamespace,
				GatewayName:      client.options.DataplaneGatewayName,
				AppliedRevision:  appliedRevision,
			},
		},
	}
	if err := stream.Send(hello); err != nil {
		return receivedMessage, fmt.Errorf("sending Hello: %w", err)
	}

	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				return receivedMessage, err
			}
			return receivedMessage, fmt.Errorf("push stream recv: %w", err)
		}
		receivedMessage = true

		config := message.GetConfig()
		if config == nil {
			continue
		}

		revision := config.Revision
		var reply *push.DataplaneMessage
		if applyErr := client.server.applyDataplaneConfig(config.DataplaneConfig); applyErr != nil {
			logger.Error(applyErr, "failed to apply dataplane config",
				"gatewayNamespace", client.options.DataplaneGatewayNamespace,
				"gatewayName", client.options.DataplaneGatewayName,
				"revision", revision,
			)
			reply = &push.DataplaneMessage{
				Body: &push.DataplaneMessage_Nack{
					Nack: &push.Nack{
						Revision: revision,
						Reason:   push.TruncateNACKReason(applyErr.Error()),
					},
				},
			}
		} else {
			reply = &push.DataplaneMessage{
				Body: &push.DataplaneMessage_Ack{
					Ack: &push.Ack{
						AppliedRevision: revision,
					},
				},
			}
		}
		if err := stream.Send(reply); err != nil {
			return receivedMessage, fmt.Errorf("sending reply: %w", err)
		}
	}
}
