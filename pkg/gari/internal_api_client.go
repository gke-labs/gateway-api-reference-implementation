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
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

const (
	// defaultInternalAPIClientMinBackoff is the minimum backoff delay between reconnect attempts.
	defaultInternalAPIClientMinBackoff = 100 * time.Millisecond

	// defaultInternalAPIClientMaxBackoff is the maximum backoff delay between reconnect attempts.
	defaultInternalAPIClientMaxBackoff = 30 * time.Second

	// stableConnectionThreshold is the duration a connection must remain healthy
	// before reconnect backoff is reset to the minimum backoff. This prevents
	// flapping connections from repeatedly connecting without backoff.
	stableConnectionThreshold = 2 * time.Second
)

// internalAPIClient connects to the controller's internal API Service over TLS
// to receive configuration streams and acknowledge them.
type internalAPIClient struct {
	// server is the parent GARI server whose proxy configuration is updated.
	server *Server

	// address is the host and port of the controller's internal API Service.
	address string

	// caFile is the path to the trust bundle that verifies the controller's certificate.
	caFile string

	// tokenFile is the path to the projected ServiceAccount token for data-plane identity.
	tokenFile string

	// gatewayNamespace is the namespace of the Gateway this data plane serves.
	gatewayNamespace string

	// gatewayName is the name of the Gateway this data plane serves.
	gatewayName string

	// minBackoff is the initial backoff delay before reconnect attempts.
	minBackoff time.Duration

	// maxBackoff is the maximum backoff delay before reconnect attempts.
	maxBackoff time.Duration

	// mu guards appliedRevision.
	mu sync.Mutex

	// appliedRevision is the configuration revision currently applied by the proxy.
	appliedRevision string
}

func newInternalAPIClient(server *Server, options Options) *internalAPIClient {
	return &internalAPIClient{
		server:           server,
		address:          options.InternalAPIAddress,
		caFile:           options.InternalAPICAFile,
		tokenFile:        options.InternalAPITokenFile,
		gatewayNamespace: options.DataplaneGatewayNamespace,
		gatewayName:      options.DataplaneGatewayName,
		minBackoff:       defaultInternalAPIClientMinBackoff,
		maxBackoff:       defaultInternalAPIClientMaxBackoff,
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
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		connected := false
		startTime := time.Now()
		err := client.runStream(ctx, func() {
			connected = true
		})

		if ctx.Err() != nil {
			return nil
		}

		logger.Error(err, "dataplane internal API stream disconnected, retrying",
			"gatewayNamespace", client.gatewayNamespace,
			"gatewayName", client.gatewayName,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		if connected || time.Since(startTime) > stableConnectionThreshold {
			backoff = client.minBackoff
		} else {
			backoff = min(backoff*2, client.maxBackoff)
		}
	}
}

func (client *internalAPIClient) runStream(ctx context.Context, onConnected func()) error {
	logger := klog.FromContext(ctx)

	tokenBytes, err := os.ReadFile(client.tokenFile)
	if err != nil {
		return fmt.Errorf("reading token file %q: %w", client.tokenFile, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("token file %q is empty", client.tokenFile)
	}

	tlsConfig, err := loadTLSConfig(client.caFile, client.address)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(
		client.address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(push.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(push.MaxMessageBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("creating gRPC client for %s: %w", client.address, err)
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
		return fmt.Errorf("opening push stream: %w", err)
	}

	client.mu.Lock()
	appliedRevision := client.appliedRevision
	client.mu.Unlock()

	hello := &push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: client.gatewayNamespace,
				GatewayName:      client.gatewayName,
				AppliedRevision:  appliedRevision,
			},
		},
	}
	if err := stream.Send(hello); err != nil {
		return fmt.Errorf("sending Hello: %w", err)
	}

	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
				return err
			}
			return fmt.Errorf("push stream recv: %w", err)
		}

		if onConnected != nil {
			onConnected()
			onConnected = nil
		}

		config := message.GetConfig()
		if config == nil {
			continue
		}

		revision := config.Revision
		applyErr := client.server.applyDataplaneConfig(config.DataplaneConfig)
		if applyErr != nil {
			logger.Error(applyErr, "failed to apply dataplane config",
				"gatewayNamespace", client.gatewayNamespace,
				"gatewayName", client.gatewayName,
				"revision", revision,
			)
			nack := &push.DataplaneMessage{
				Body: &push.DataplaneMessage_Nack{
					Nack: &push.Nack{
						Revision: revision,
						Reason:   push.TruncateNACKReason(applyErr.Error()),
					},
				},
			}
			if sendErr := stream.Send(nack); sendErr != nil {
				return fmt.Errorf("sending Nack: %w", sendErr)
			}
		} else {
			client.mu.Lock()
			client.appliedRevision = revision
			client.mu.Unlock()

			ack := &push.DataplaneMessage{
				Body: &push.DataplaneMessage_Ack{
					Ack: &push.Ack{
						AppliedRevision: revision,
					},
				},
			}
			if sendErr := stream.Send(ack); sendErr != nil {
				return fmt.Errorf("sending Ack: %w", sendErr)
			}
		}
	}
}
