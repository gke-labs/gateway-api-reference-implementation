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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
)

func generateTestCert(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"certserver test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

type mockGRPCClient struct {
	certserverv1.CertificateServiceClient
	getCertFunc func(ctx context.Context, req *certserverv1.GetCertificateRequest, opts ...grpc.CallOption) (*certserverv1.GetCertificateResponse, error)
}

func (m *mockGRPCClient) GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest, opts ...grpc.CallOption) (*certserverv1.GetCertificateResponse, error) {
	return m.getCertFunc(ctx, req, opts...)
}

func TestPureClient_Validation(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	_ = os.WriteFile(tokenFile, []byte("tok"), 0600)

	// Missing server address and mock client
	_, err := New(Config{
		TokenPath: tokenFile,
	})
	if err == nil {
		t.Fatalf("expected error when ServerAddress is empty")
	}

	// Missing token path
	_, err = New(Config{
		ServerAddress: "localhost:1234",
	})
	if err == nil {
		t.Fatalf("expected error when TokenPath is empty")
	}

	// Token file does not exist
	_, err = New(Config{
		ServerAddress: "localhost:1234",
		TokenPath:     filepath.Join(tempDir, "nonexistent"),
	})
	if err == nil {
		t.Fatalf("expected error when token file does not exist")
	}
}

func TestPureClient_TokenRotation(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenFile, []byte("token-1"), 0600); err != nil {
		t.Fatalf("failed to write token: %v", err)
	}

	certPEM, keyPEM := generateTestCert(t)
	var capturedToken atomic.Value

	mock := &mockGRPCClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest, opts ...grpc.CallOption) (*certserverv1.GetCertificateResponse, error) {
			md, ok := metadata.FromOutgoingContext(ctx)
			if ok && len(md.Get("authorization")) > 0 {
				capturedToken.Store(md.Get("authorization")[0])
			}
			return &certserverv1.GetCertificateResponse{
				CertificateChain: certPEM,
				PrivateKey:       keyPEM,
			}, nil
		},
	}

	cli, err := New(Config{
		TokenPath:  tokenFile,
		GRPCClient: mock,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer cli.Close()

	// First call uses token-1
	req := &certserverv1.GetCertificateRequest{
		Hostnames: []string{"example.com"},
		Gateway:   "default/gw",
	}
	info, err := cli.GetCertificate(t.Context(), req)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if info == nil || info.Certificate == nil || info.Leaf == nil {
		t.Fatalf("expected parsed tlsCert and leaf, got %+v", info)
	}
	if len(info.Challenges) != 0 {
		t.Errorf("expected 0 challenges for issued certificate, got %d", len(info.Challenges))
	}
	if got := capturedToken.Load().(string); got != "Bearer token-1" {
		t.Errorf("expected Bearer token-1, got %q", got)
	}

	// Rotate token on disk
	if err := os.WriteFile(tokenFile, []byte("token-rotated"), 0600); err != nil {
		t.Fatalf("failed to write rotated token: %v", err)
	}

	// Second call uses token-rotated
	_, err = cli.GetCertificate(t.Context(), req)
	if err != nil {
		t.Fatalf("GetCertificate after rotation failed: %v", err)
	}
	if got := capturedToken.Load().(string); got != "Bearer token-rotated" {
		t.Errorf("expected Bearer token-rotated, got %q", got)
	}
}

func TestPureClient_PendingChallengesReturned(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	_ = os.WriteFile(tokenFile, []byte("token"), 0600)

	expectedChallenges := []*certserverv1.HTTP01Challenge{
		{
			Hostname:         "example.com",
			Token:            "chal-tok-123",
			KeyAuthorization: "chal-tok-123.auth-key-456",
		},
	}

	mock := &mockGRPCClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest, opts ...grpc.CallOption) (*certserverv1.GetCertificateResponse, error) {
			return &certserverv1.GetCertificateResponse{
				Challenges: expectedChallenges,
			}, nil
		},
	}

	cli, err := New(Config{
		TokenPath:  tokenFile,
		GRPCClient: mock,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer cli.Close()

	info, err := cli.GetCertificate(t.Context(), &certserverv1.GetCertificateRequest{
		Hostnames: []string{"example.com"},
		Gateway:   "default/gw",
	})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if info == nil {
		t.Fatalf("expected non-nil CertificateInfo")
	}
	if info.Certificate != nil || info.Leaf != nil {
		t.Errorf("expected nil Certificate and Leaf for pending cert, got cert=%v, leaf=%v", info.Certificate, info.Leaf)
	}
	if len(info.Challenges) != 1 {
		t.Fatalf("expected 1 pending challenge, got %d", len(info.Challenges))
	}
	if info.Challenges[0].Hostname != "example.com" || info.Challenges[0].Token != "chal-tok-123" || info.Challenges[0].KeyAuthorization != "chal-tok-123.auth-key-456" {
		t.Errorf("unexpected challenge: %+v", info.Challenges[0])
	}
}

func TestPureClient_StatusErrorPreserved(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "token")
	_ = os.WriteFile(tokenFile, []byte("token"), 0600)

	mock := &mockGRPCClient{
		getCertFunc: func(ctx context.Context, req *certserverv1.GetCertificateRequest, opts ...grpc.CallOption) (*certserverv1.GetCertificateResponse, error) {
			return nil, status.Errorf(codes.PermissionDenied, "hostname not allowed")
		},
	}

	cli, err := New(Config{
		TokenPath:  tokenFile,
		GRPCClient: mock,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer cli.Close()

	_, err = cli.GetCertificate(t.Context(), &certserverv1.GetCertificateRequest{
		Hostnames: []string{"denied.example.com"},
	})
	if err == nil {
		t.Fatalf("expected error from GetCertificate")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Errorf("expected codes.PermissionDenied, got %v", err)
	}
}
