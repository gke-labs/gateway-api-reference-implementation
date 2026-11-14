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
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultMaxInFlight is the default maximum number of concurrent in-flight Sign calls.
const DefaultMaxInFlight = 64

// DefaultDeadline is the default per-call timeout for Sign and other RPCs.
const DefaultDeadline = 5 * time.Second

type options struct {
	maxInFlight int
	deadline    time.Duration
	dialer      func(context.Context, string) (net.Conn, error)
}

// Option configures Client and Signer settings.
type Option func(*options)

// WithMaxInFlight sets the maximum number of concurrent in-flight Sign calls.
func WithMaxInFlight(max int) Option {
	return func(o *options) {
		if max > 0 {
			o.maxInFlight = max
		}
	}
}

// WithDeadline sets the per-call deadline for Sign and other RPCs.
func WithDeadline(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.deadline = d
		}
	}
}

// WithDialer configures a custom context dialer for gRPC transport.
func WithDialer(dialer func(context.Context, string) (net.Conn, error)) Option {
	return func(o *options) { o.dialer = dialer }
}

// Client communicates with KeyCustodianService over a Unix domain socket.
type Client struct {
	conn *grpc.ClientConn
	rpc  keycustodianv1alpha1.KeyCustodianServiceClient
	opts options
	sem  chan struct{}
}

// New creates a new Client connected to socketPath.
func New(socketPath string, opts ...Option) (*Client, error) {
	cfg := options{maxInFlight: DefaultMaxInFlight, deadline: DefaultDeadline}
	for _, opt := range opts {
		opt(&cfg)
	}

	dialer := cfg.dialer
	if dialer == nil {
		dialer = func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}
	}

	conn, err := grpc.NewClient("passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, fmt.Errorf("keycustodian: connecting to %s: %w", socketPath, err)
	}

	return &Client{
		conn: conn,
		rpc:  keycustodianv1alpha1.NewKeyCustodianServiceClient(conn),
		opts: cfg,
		sem:  make(chan struct{}, cfg.maxInFlight),
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, c.opts.deadline)
}

// ListKeys returns the names of all keys held by the custodian.
func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	callCtx, cancel := c.withDeadline(ctx)
	defer cancel()
	resp, err := c.rpc.ListKeys(callCtx, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// GetCertificateChain returns the PEM-encoded certificate chain for keyName.
func (c *Client) GetCertificateChain(ctx context.Context, keyName string) ([]byte, error) {
	callCtx, cancel := c.withDeadline(ctx)
	defer cancel()
	resp, err := c.rpc.GetCertificateChain(callCtx, &keycustodianv1alpha1.GetCertificateChainRequest{Key: keyName})
	if err != nil {
		return nil, err
	}
	return resp.CertificateChain, nil
}

// ListKeys connects to socketPath, retrieves key names, and closes the connection.
func ListKeys(ctx context.Context, socketPath string, opts ...Option) ([]string, error) {
	c, err := New(socketPath, opts...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	return c.ListKeys(ctx)
}

// GetCertificateChain connects to socketPath, retrieves the certificate chain, and closes the connection.
func GetCertificateChain(ctx context.Context, socketPath, keyName string, opts ...Option) ([]byte, error) {
	c, err := New(socketPath, opts...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	return c.GetCertificateChain(ctx, keyName)
}

// Signer implements crypto.Signer backed by KeyCustodianService.
type Signer struct {
	client     *Client
	keyName    string
	pubKey     crypto.PublicKey
	cert       *x509.Certificate
	certChain  []byte
	ownsClient bool
}

var _ crypto.Signer = (*Signer)(nil)
var _ io.Closer = (*Signer)(nil)

// Signer returns a *Signer for keyName using this client.
func (c *Client) Signer(keyName string) (*Signer, error) {
	chain, err := c.GetCertificateChain(context.Background(), keyName)
	if err != nil {
		return nil, fmt.Errorf("getting certificate chain for %q: %w", keyName, err)
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate PEM block found in chain for %q", keyName)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate for %q: %w", keyName, err)
	}
	return &Signer{
		client:    c,
		keyName:   keyName,
		pubKey:    cert.PublicKey,
		cert:      cert,
		certChain: chain,
	}, nil
}

// NewSigner creates a crypto.Signer for keyName using this client.
func (c *Client) NewSigner(keyName string) (crypto.Signer, error) {
	return c.Signer(keyName)
}

// NewSigner connects to socketPath and returns a crypto.Signer for keyName.
func NewSigner(socketPath, keyName string, opts ...Option) (crypto.Signer, error) {
	c, err := New(socketPath, opts...)
	if err != nil {
		return nil, err
	}
	s, err := c.Signer(keyName)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	s.ownsClient = true
	return s, nil
}

// Public returns the public key extracted from the key's certificate chain.
func (s *Signer) Public() crypto.PublicKey { return s.pubKey }

// Certificate returns the leaf certificate for the signer.
func (s *Signer) Certificate() *x509.Certificate { return s.cert }

// CertificateChain returns the PEM-encoded certificate chain for the signer.
func (s *Signer) CertificateChain() []byte { return s.certChain }

// TLSCertificate constructs a tls.Certificate using this Signer as its PrivateKey.
func (s *Signer) TLSCertificate() (tls.Certificate, error) {
	var certDERs [][]byte
	rest := s.certChain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certDERs = append(certDERs, block.Bytes)
		}
	}
	if len(certDERs) == 0 {
		return tls.Certificate{}, errors.New("keycustodian: no certificates found in chain")
	}
	return tls.Certificate{Certificate: certDERs, PrivateKey: s}, nil
}

// Close closes the underlying connection if created by NewSigner.
func (s *Signer) Close() error {
	if s.ownsClient && s.client != nil {
		return s.client.Close()
	}
	return nil
}

// Sign signs digest using the remote custodian.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignWithContext(context.Background(), digest, opts)
}

// SignWithContext signs digest using the remote custodian, bounded by ctx and the configured deadline.
func (s *Signer) SignWithContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := &keycustodianv1alpha1.SignRequest{Key: s.keyName, Digest: digest}

	var hash crypto.Hash
	if opts != nil {
		hash = opts.HashFunc()
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			saltLen := int32(pssOpts.SaltLength)
			req.RsaPssSaltLength = &saltLen
			if pssOpts.Hash != 0 {
				hash = pssOpts.Hash
			}
		}
	}

	algo, err := hashAlgo(hash, len(digest))
	if err != nil {
		return nil, err
	}
	req.HashAlgorithm = algo

	callCtx, cancel := s.client.withDeadline(ctx)
	defer cancel()

	select {
	case s.client.sem <- struct{}{}:
		defer func() { <-s.client.sem }()
	case <-callCtx.Done():
		return nil, fmt.Errorf("keycustodian: acquiring sign slot: %w", callCtx.Err())
	}

	resp, err := s.client.rpc.Sign(callCtx, req)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func hashAlgo(h crypto.Hash, digestLen int) (keycustodianv1alpha1.HashAlgorithm, error) {
	switch h {
	case crypto.SHA256:
		if digestLen != 32 {
			return 0, fmt.Errorf("keycustodian: digest length %d does not match SHA-256 (expected 32)", digestLen)
		}
		return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256, nil
	case crypto.SHA384:
		if digestLen != 48 {
			return 0, fmt.Errorf("keycustodian: digest length %d does not match SHA-384 (expected 48)", digestLen)
		}
		return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA384, nil
	case crypto.SHA512:
		if digestLen != 64 {
			return 0, fmt.Errorf("keycustodian: digest length %d does not match SHA-512 (expected 64)", digestLen)
		}
		return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA512, nil
	case 0:
		switch digestLen {
		case 32:
			return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256, nil
		case 48:
			return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA384, nil
		case 64:
			return keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA512, nil
		}
	}
	return 0, fmt.Errorf("keycustodian: unsupported hash algorithm %v", h)
}
