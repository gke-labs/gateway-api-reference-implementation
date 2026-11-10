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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
)

// Config configures the pure certserver gRPC client.
type Config struct {
	// ServerAddress is the host:port of the certserver gRPC service.
	ServerAddress string

	// CABundlePath is the path to a PEM file containing the CA bundle to verify certserver TLS.
	// If empty and TLSConfig is nil, system roots are used.
	CABundlePath string

	// TokenPath is the path to the projected service-account token file.
	// The token is read from this path on every RPC so rotations are picked up automatically.
	TokenPath string

	// TLSConfig is an optional tls.Config override (e.g. for testing with InsecureSkipVerify).
	TLSConfig *tls.Config

	// DialTimeout is the timeout for dialing certserver. Defaults to 10s.
	DialTimeout time.Duration

	// RPCTimeout is the timeout for individual GetCertificate RPCs. Defaults to 10s.
	RPCTimeout time.Duration

	// GRPCClient can be set in tests to mock the gRPC transport.
	GRPCClient certserverv1.CertificateServiceClient
}

// Client is a pure gRPC client for the certserver CertificateService.
type Client struct {
	cfg        Config
	conn       *grpc.ClientConn
	grpcClient certserverv1.CertificateServiceClient
	dialErr    error
	dialOnce   sync.Once
}

// New creates a new pure certserver Client.
func New(cfg Config) (*Client, error) {
	if cfg.ServerAddress == "" && cfg.GRPCClient == nil {
		return nil, errors.New("certserver ServerAddress is required")
	}
	if cfg.TokenPath == "" {
		return nil, errors.New("certserver TokenPath is required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.RPCTimeout <= 0 {
		cfg.RPCTimeout = 10 * time.Second
	}

	c := &Client{
		cfg:        cfg,
		grpcClient: cfg.GRPCClient,
	}

	// Validate token file existence early
	if _, err := c.readToken(); err != nil {
		return nil, fmt.Errorf("reading initial certserver token: %w", err)
	}

	// Validate CA bundle if specified
	if cfg.CABundlePath != "" && cfg.TLSConfig == nil {
		if _, err := os.ReadFile(cfg.CABundlePath); err != nil {
			return nil, fmt.Errorf("reading certserver CA bundle: %w", err)
		}
	}

	return c, nil
}

func (c *Client) readToken() (string, error) {
	data, err := os.ReadFile(c.cfg.TokenPath)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("certserver token file is empty")
	}
	return token, nil
}

func (c *Client) ensureConn(ctx context.Context) (certserverv1.CertificateServiceClient, error) {
	if c.grpcClient != nil {
		return c.grpcClient, nil
	}

	c.dialOnce.Do(func() {
		tlsConfig := c.cfg.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			if c.cfg.CABundlePath != "" {
				caData, err := os.ReadFile(c.cfg.CABundlePath)
				if err != nil {
					c.dialErr = fmt.Errorf("reading CA bundle: %w", err)
					return
				}
				rootCAs := x509.NewCertPool()
				if !rootCAs.AppendCertsFromPEM(caData) {
					c.dialErr = errors.New("failed to parse CA bundle PEM")
					return
				}
				tlsConfig.RootCAs = rootCAs
			}
		}

		dialCtx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
		defer cancel()

		conn, err := grpc.DialContext(dialCtx, c.cfg.ServerAddress,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
			grpc.WithBlock(),
		)
		if err != nil {
			c.dialErr = fmt.Errorf("dialing certserver at %s: %w", c.cfg.ServerAddress, err)
			return
		}
		c.conn = conn
		c.grpcClient = certserverv1.NewCertificateServiceClient(conn)
	})

	return c.grpcClient, c.dialErr
}

// GetCertificate performs the GetCertificate RPC to certserver, reading the current
// token from TokenPath and returning the parsed certificate and leaf, or pending challenges.
func (c *Client) GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest) (*tls.Certificate, *x509.Certificate, []*certserverv1.HTTP01Challenge, error) {
	grpcCli, err := c.ensureConn(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	token, err := c.readToken()
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Unauthenticated, "reading token file: %v", err)
	}

	rpcCtx, cancel := context.WithTimeout(ctx, c.cfg.RPCTimeout)
	defer cancel()

	md := metadata.Pairs("authorization", "Bearer "+token)
	rpcCtx = metadata.NewOutgoingContext(rpcCtx, md)

	resp, err := grpcCli.GetCertificate(rpcCtx, req)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(resp.GetCertificateChain()) == 0 {
		return nil, nil, resp.GetChallenges(), nil
	}

	tlsCert, leaf, err := ParseCertificateChain(resp.GetCertificateChain(), resp.GetPrivateKey())
	if err != nil {
		return nil, nil, nil, err
	}

	return tlsCert, leaf, resp.GetChallenges(), nil
}

// ParseCertificateChain parses PEM-encoded certificate chain and private key into tls.Certificate and leaf.
func ParseCertificateChain(certChainPEM, keyPEM []byte) (*tls.Certificate, *x509.Certificate, error) {
	if len(certChainPEM) == 0 {
		return nil, nil, status.Errorf(codes.Internal, "certserver returned empty certificate chain")
	}

	var tlsCert tls.Certificate
	var err error

	if len(keyPEM) > 0 {
		tlsCert, err = tls.X509KeyPair(certChainPEM, keyPEM)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "parsing certificate and key: %v", err)
		}
	} else {
		// Public cert chain only
		rest := certChainPEM
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				tlsCert.Certificate = append(tlsCert.Certificate, block.Bytes)
			}
		}
		if len(tlsCert.Certificate) == 0 {
			return nil, nil, status.Errorf(codes.Internal, "no certificate blocks found in chain")
		}
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "parsing leaf certificate: %v", err)
	}
	tlsCert.Leaf = leaf

	return &tlsCert, leaf, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
