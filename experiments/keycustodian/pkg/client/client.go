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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
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

// DefaultMaxInFlight is the default maximum number of concurrent in-flight Sign calls (64).
// This bounds memory usage and concurrent RPCs to prevent overwhelming the local custodian
// daemon process while providing ample headroom for parallel TLS handshake bursts.
const DefaultMaxInFlight = 64

// DefaultDeadline is the default per-call timeout for Sign and other RPCs (5 seconds).
// This provides generous headroom for local Unix domain socket IPC and signature computation
// without false timeouts under scheduling jitter, while ensuring callers fail fast rather
// than hanging indefinitely if the daemon stalls.
const DefaultDeadline = 5 * time.Second

type options struct {
	// maxInFlight limits the maximum number of concurrent in-flight Sign calls.
	maxInFlight int
	// deadline is the per-call timeout for RPCs.
	deadline time.Duration
}

// Option configures Client and Signer settings.
type Option func(*options)

// WithMaxInFlight sets the maximum number of concurrent in-flight Sign calls.
func WithMaxInFlight(maxInFlight int) Option {
	return func(options *options) {
		if maxInFlight > 0 {
			options.maxInFlight = maxInFlight
		}
	}
}

// WithDeadline sets the per-call deadline for Sign and other RPCs.
func WithDeadline(deadline time.Duration) Option {
	return func(options *options) {
		if deadline > 0 {
			options.deadline = deadline
		}
	}
}

// Client communicates with the KeyCustodianService over a Unix domain socket.
type Client struct {
	// connection is the underlying gRPC client connection to the custodian daemon.
	connection *grpc.ClientConn
	// serviceClient is the gRPC client stub for the KeyCustodianService.
	serviceClient keycustodianv1alpha1.KeyCustodianServiceClient
	// options holds the configured client settings.
	options options
	// semaphore bounds the number of concurrent in-flight Sign calls.
	semaphore chan struct{}
}

// New creates a new Client connected to socketPath.
func New(socketPath string, clientOptions ...Option) (*Client, error) {
	configuration := options{
		maxInFlight: DefaultMaxInFlight,
		deadline:    DefaultDeadline,
	}
	for _, option := range clientOptions {
		option(&configuration)
	}

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		var socketDialer net.Dialer
		return socketDialer.DialContext(ctx, "unix", socketPath)
	}

	connection, err := grpc.NewClient("passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, fmt.Errorf("keycustodian: connecting to %s: %w", socketPath, err)
	}

	return &Client{
		connection:    connection,
		serviceClient: keycustodianv1alpha1.NewKeyCustodianServiceClient(connection),
		options:       configuration,
		semaphore:     make(chan struct{}, configuration.maxInFlight),
	}, nil
}

// Close closes the underlying gRPC connection.
func (client *Client) Close() error {
	return client.connection.Close()
}

func (client *Client) withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, client.options.deadline)
}

// ListKeys returns the names of all keys held by the custodian.
func (client *Client) ListKeys(ctx context.Context) ([]string, error) {
	callContext, cancel := client.withDeadline(ctx)
	defer cancel()
	response, err := client.serviceClient.ListKeys(callContext, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil {
		return nil, err
	}
	return response.Keys, nil
}

// GetCertificateChain returns the PEM-encoded certificate chain for keyName.
func (client *Client) GetCertificateChain(ctx context.Context, keyName string) ([]byte, error) {
	callContext, cancel := client.withDeadline(ctx)
	defer cancel()
	response, err := client.serviceClient.GetCertificateChain(callContext, &keycustodianv1alpha1.GetCertificateChainRequest{Key: keyName})
	if err != nil {
		return nil, err
	}
	return response.CertificateChain, nil
}

// NewSigner creates a Signer for keyName using this client.
//
// It asks the daemon for one signature over a fixed digest to check that the
// key matches the certificate, which adds one line to the daemon's audit log
// for each signer.
func (client *Client) NewSigner(keyName string) (*Signer, error) {
	chainPEM, err := client.GetCertificateChain(context.Background(), keyName)
	if err != nil {
		return nil, fmt.Errorf("getting certificate chain for %q: %w", keyName, err)
	}
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate PEM block found in chain for %q", keyName)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate for %q: %w", keyName, err)
	}

	signer := &Signer{
		client:    client,
		keyName:   keyName,
		publicKey: certificate.PublicKey,
	}

	probeDigest := sha256.Sum256([]byte("keycustodian probe " + keyName))
	signature, err := signer.Sign(nil, probeDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verifying key %q: %w", keyName, err)
	}
	if err := verifySignature(certificate.PublicKey, probeDigest[:], signature); err != nil {
		return nil, fmt.Errorf("key %q does not match certificate: %w", keyName, err)
	}

	return signer, nil
}

func verifySignature(publicKey crypto.PublicKey, digest []byte, signature []byte) error {
	switch typedPublicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(typedPublicKey, digest, signature) {
			return errors.New("signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(typedPublicKey, crypto.SHA256, digest, signature)
	default:
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

// NewSigner connects to socketPath and returns a crypto.Signer for keyName.
func NewSigner(socketPath string, keyName string, clientOptions ...Option) (crypto.Signer, error) {
	client, err := New(socketPath, clientOptions...)
	if err != nil {
		return nil, err
	}
	signer, err := client.NewSigner(keyName)
	if err != nil {
		if closeErr := client.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}
	signer.ownsClient = true
	return signer, nil
}

// Signer implements crypto.Signer backed by KeyCustodianService.
type Signer struct {
	// client is the custodian client used to perform signing RPCs.
	client *Client
	// keyName is the name of the key held by the custodian.
	keyName string
	// publicKey is the public key extracted from the key's certificate chain.
	publicKey crypto.PublicKey
	// ownsClient indicates whether this Signer created and owns its Client.
	ownsClient bool
}

var _ crypto.Signer = (*Signer)(nil)
var _ io.Closer = (*Signer)(nil)

// Public returns the public key extracted from the key's certificate chain.
func (signer *Signer) Public() crypto.PublicKey {
	return signer.publicKey
}

// Close closes the underlying gRPC connection if the Signer was created with NewSigner.
func (signer *Signer) Close() error {
	if signer.ownsClient && signer.client != nil {
		return signer.client.Close()
	}
	return nil
}

// Sign signs digest using the remote key custodian daemon.
//
// The signer supports ECDSA (P-256, P-384, P-521) and RSA keys with
// SHA-256, SHA-384, and SHA-512 hashes. RSA keys support PKCS #1 v1.5
// signatures (passing crypto.SHA256, crypto.SHA384, or crypto.SHA512 as options)
// or RSA-PSS signatures (passing *rsa.PSSOptions as options).
//
// Ed25519 keys are not supported. Unhashed messages (hash 0) are not supported.
// The options parameter must not be nil and must specify a supported hash function.
func (signer *Signer) Sign(_ io.Reader, digest []byte, signerOptions crypto.SignerOpts) ([]byte, error) {
	if signerOptions == nil || signerOptions.HashFunc() == 0 {
		return nil, errors.New("keycustodian: unhashed messages (hash 0) are not supported; options must specify a supported hash")
	}

	hashAlgorithm, pssSaltLength, err := convertHashAlgorithm(signerOptions, len(digest))
	if err != nil {
		return nil, err
	}

	request := &keycustodianv1alpha1.SignRequest{
		Key:              signer.keyName,
		HashAlgorithm:    hashAlgorithm,
		Digest:           digest,
		RsaPssSaltLength: pssSaltLength,
	}

	callContext, cancel := signer.client.withDeadline(context.Background())
	defer cancel()

	select {
	case signer.client.semaphore <- struct{}{}:
		defer func() { <-signer.client.semaphore }()
	case <-callContext.Done():
		return nil, fmt.Errorf("keycustodian: acquiring sign slot: %w", callContext.Err())
	}

	response, err := signer.client.serviceClient.Sign(callContext, request)
	if err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func convertHashAlgorithm(signerOptions crypto.SignerOpts, digestLength int) (keycustodianv1alpha1.HashAlgorithm, *int32, error) {
	hash := signerOptions.HashFunc()
	var pssSaltLength *int32
	if pssOptions, ok := signerOptions.(*rsa.PSSOptions); ok {
		salt := int32(pssOptions.SaltLength)
		pssSaltLength = &salt
		if pssOptions.Hash != 0 {
			hash = pssOptions.Hash
		}
	}

	var hashAlgorithm keycustodianv1alpha1.HashAlgorithm
	var expectedLength int
	switch hash {
	case crypto.SHA256:
		hashAlgorithm = keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256
		expectedLength = 32
	case crypto.SHA384:
		hashAlgorithm = keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA384
		expectedLength = 48
	case crypto.SHA512:
		hashAlgorithm = keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA512
		expectedLength = 64
	default:
		return 0, nil, fmt.Errorf("keycustodian: unsupported hash algorithm %v", hash)
	}

	if digestLength != expectedLength {
		return 0, nil, fmt.Errorf("keycustodian: digest length %d does not match hash algorithm (expected %d)", digestLength, expectedLength)
	}
	return hashAlgorithm, pssSaltLength, nil
}
