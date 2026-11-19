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
	// DefaultPushClientMinBackoff is the minimum backoff delay between push client reconnect attempts.
	DefaultPushClientMinBackoff = 100 * time.Millisecond

	// DefaultPushClientMaxBackoff is the maximum backoff delay between push client reconnect attempts.
	DefaultPushClientMaxBackoff = 30 * time.Second
)

// pushClient maintains a configuration push stream connection to the controller.
type pushClient struct {
	server *Server

	address   string
	caFile    string
	tokenFile string

	gatewayNamespace string
	gatewayName      string

	minBackoff time.Duration
	maxBackoff time.Duration

	// mu guards appliedRevision.
	mu sync.Mutex
	// appliedRevision is the currently applied configuration revision, reported in Hello.
	appliedRevision string
}

func newPushClient(server *Server, opts Options) *pushClient {
	minBackoff := opts.PushClientMinBackoff
	if minBackoff <= 0 {
		minBackoff = DefaultPushClientMinBackoff
	}
	maxBackoff := opts.PushClientMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultPushClientMaxBackoff
	}
	return &pushClient{
		server:           server,
		address:          opts.InternalAPIAddress,
		caFile:           opts.InternalAPICAFile,
		tokenFile:        opts.InternalAPITokenFile,
		gatewayNamespace: opts.DataplaneGatewayNamespace,
		gatewayName:      opts.DataplaneGatewayName,
		minBackoff:       minBackoff,
		maxBackoff:       maxBackoff,
	}
}

// AppliedRevision returns the configuration revision currently applied by the data plane.
func (c *pushClient) AppliedRevision() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appliedRevision
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

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}

	return &tls.Config{
		RootCAs:    certPool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func (c *pushClient) run(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	backoff := c.minBackoff

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		connected := false
		startTime := time.Now()
		err := c.runStream(ctx, func() {
			connected = true
		})

		if ctx.Err() != nil {
			return nil
		}

		logger.Error(err, "dataplane push stream disconnected, retrying",
			"gatewayNamespace", c.gatewayNamespace,
			"gatewayName", c.gatewayName,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		if connected || time.Since(startTime) > 2*time.Second {
			backoff = c.minBackoff
		} else {
			backoff = min(backoff*2, c.maxBackoff)
		}
	}
}

func (c *pushClient) runStream(ctx context.Context, onConnected func()) error {
	logger := klog.FromContext(ctx)

	tokenBytes, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return fmt.Errorf("reading token file %q: %w", c.tokenFile, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("token file %q is empty", c.tokenFile)
	}

	tlsConfig, err := loadTLSConfig(c.caFile, c.address)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(
		c.address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(push.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(push.MaxMessageBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("creating gRPC client for %s: %w", c.address, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.V(4).Info("failed to close gRPC client connection", "err", closeErr)
		}
	}()

	client := push.NewPushServiceClient(conn)
	streamCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	stream, err := client.StreamConfig(streamCtx)
	if err != nil {
		return fmt.Errorf("opening push stream: %w", err)
	}

	c.mu.Lock()
	appliedRev := c.appliedRevision
	c.mu.Unlock()

	hello := &push.DataplaneMessage{
		Body: &push.DataplaneMessage_Hello{
			Hello: &push.Hello{
				GatewayNamespace: c.gatewayNamespace,
				GatewayName:      c.gatewayName,
				AppliedRevision:  appliedRev,
			},
		},
	}
	if err := stream.Send(hello); err != nil {
		return fmt.Errorf("sending Hello: %w", err)
	}

	for {
		msg, err := stream.Recv()
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

		cfg := msg.GetConfig()
		if cfg == nil {
			continue
		}

		revision := cfg.Revision
		applyErr := c.server.applyDataplaneConfig(cfg.DataplaneConfig)
		if applyErr != nil {
			logger.Error(applyErr, "failed to apply dataplane config",
				"gatewayNamespace", c.gatewayNamespace,
				"gatewayName", c.gatewayName,
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
			c.mu.Lock()
			c.appliedRevision = revision
			c.mu.Unlock()

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
