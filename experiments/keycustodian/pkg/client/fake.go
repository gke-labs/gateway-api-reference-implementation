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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/custodian"
	"google.golang.org/grpc"
)

// FakeCustodian is an in-process key custodian server for testing, backed by the real gRPC service.
type FakeCustodian struct {
	grpcServer  *grpc.Server
	listener    net.Listener
	socketPath  string
	keyName     string
	cert        *x509.Certificate
	certPEM     []byte
	signer      crypto.Signer
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	signDelay   time.Duration
	cleanup     func()
}

type fakeConfig struct {
	keys    []custodian.ServerOption
	primary struct {
		name    string
		cert    *x509.Certificate
		certPEM []byte
		signer  crypto.Signer
	}
	signDelay time.Duration
}

// FakeOption configures FakeCustodian.
type FakeOption func(*fakeConfig)

// WithFakeSignDelay adds a duration delay inside the custodian's Sign handler.
func WithFakeSignDelay(d time.Duration) FakeOption {
	return func(c *fakeConfig) { c.signDelay = d }
}

// WithFakeKey adds an in-memory key and certificate chain to the fake custodian.
func WithFakeKey(name string, signer crypto.Signer, certPEM []byte) FakeOption {
	return func(c *fakeConfig) {
		block, _ := pem.Decode(certPEM)
		var cert *x509.Certificate
		if block != nil && block.Type == "CERTIFICATE" {
			cert, _ = x509.ParseCertificate(block.Bytes)
		}
		if c.primary.name == "" {
			c.primary.name, c.primary.signer, c.primary.cert, c.primary.certPEM = name, signer, cert, certPEM
		}
		c.keys = append(c.keys, custodian.WithKey(name, signer, certPEM))
	}
}

// WithFakeRSAKey generates and adds a 2048-bit RSA key and self-signed certificate.
func WithFakeRSAKey(name string) FakeOption {
	return func(c *fakeConfig) {
		priv, certPEM, cert, err := generateRSAKey(name)
		if err != nil {
			panic(fmt.Sprintf("failed to generate RSA test key: %v", err))
		}
		if c.primary.name == "" {
			c.primary.name, c.primary.signer, c.primary.cert, c.primary.certPEM = name, priv, cert, certPEM
		}
		c.keys = append(c.keys, custodian.WithKey(name, priv, certPEM))
	}
}

func generateCert(name string, priv crypto.Signer, pub crypto.PublicKey) ([]byte, *x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost", name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, err
}

func generateECDSAKey(name string) (crypto.Signer, []byte, *x509.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, cert, err := generateCert(name, k, &k.PublicKey)
	return k, certPEM, cert, err
}

func generateRSAKey(name string) (crypto.Signer, []byte, *x509.Certificate, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, cert, err := generateCert(name, k, &k.PublicKey)
	return k, certPEM, cert, err
}

// StartFakeCustodian starts an in-process custodian server listening on a Unix domain socket.
func StartFakeCustodian(opts ...FakeOption) (*FakeCustodian, error) {
	var cfg fakeConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if len(cfg.keys) == 0 {
		priv, certPEM, cert, err := generateECDSAKey("default")
		if err != nil {
			return nil, fmt.Errorf("generating default key: %w", err)
		}
		cfg.primary.name, cfg.primary.signer, cfg.primary.cert, cfg.primary.certPEM = "default", priv, cert, certPEM
		cfg.keys = append(cfg.keys, custodian.WithKey("default", priv, certPEM))
	}

	tmpDir, err := os.MkdirTemp("", "kc")
	if err != nil {
		return nil, fmt.Errorf("creating socket temp dir: %w", err)
	}
	sockPath := filepath.Join(tmpDir, "kc.sock")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("listening on unix socket %s: %w", sockPath, err)
	}

	custodianServer, err := custodian.NewServer("", cfg.keys...)
	if err != nil {
		_ = lis.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("creating custodian server: %w", err)
	}

	fake := &FakeCustodian{
		listener:   lis,
		socketPath: sockPath,
		keyName:    cfg.primary.name,
		cert:       cfg.primary.cert,
		certPEM:    cfg.primary.certPEM,
		signer:     cfg.primary.signer,
		signDelay:  cfg.signDelay,
		cleanup:    func() { _ = os.RemoveAll(tmpDir) },
	}

	fake.grpcServer = grpc.NewServer(grpc.UnaryInterceptor(fake.interceptor))
	keycustodianv1alpha1.RegisterKeyCustodianServiceServer(fake.grpcServer, custodianServer)

	go func() { _ = fake.grpcServer.Serve(lis) }()

	return fake, nil
}

// NewFakeCustodian starts a FakeCustodian and registers its cleanup with t.
func NewFakeCustodian(t testing.TB, opts ...FakeOption) *FakeCustodian {
	t.Helper()
	fake, err := StartFakeCustodian(opts...)
	if err != nil {
		t.Fatalf("failed to start fake custodian: %v", err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	return fake
}

func (f *FakeCustodian) interceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if strings.HasSuffix(info.FullMethod, "/Sign") {
		curr := f.inFlight.Add(1)
		for {
			m := f.maxInFlight.Load()
			if curr <= m || f.maxInFlight.CompareAndSwap(m, curr) {
				break
			}
		}
		defer f.inFlight.Add(-1)

		if f.signDelay > 0 {
			time.Sleep(f.signDelay)
		}
	}
	return handler(ctx, req)
}

// SocketPath returns the Unix socket path the fake custodian is listening on.
func (f *FakeCustodian) SocketPath() string { return f.socketPath }

// KeyName returns the primary key name held by the fake custodian.
func (f *FakeCustodian) KeyName() string { return f.keyName }

// Certificate returns the leaf certificate for the primary key.
func (f *FakeCustodian) Certificate() *x509.Certificate { return f.cert }

// CertificatePEM returns the PEM-encoded certificate chain for the primary key.
func (f *FakeCustodian) CertificatePEM() []byte { return f.certPEM }

// PrivateKey returns the crypto.Signer for the primary key.
func (f *FakeCustodian) PrivateKey() crypto.Signer { return f.signer }

// MaxInFlight returns the maximum concurrent in-flight Sign requests observed by the custodian.
func (f *FakeCustodian) MaxInFlight() int { return int(f.maxInFlight.Load()) }

// Close stops the fake custodian server and removes the socket and its parent directory.
func (f *FakeCustodian) Close() error {
	f.grpcServer.Stop()
	_ = f.listener.Close()
	if f.cleanup != nil {
		f.cleanup()
	}
	return nil
}
