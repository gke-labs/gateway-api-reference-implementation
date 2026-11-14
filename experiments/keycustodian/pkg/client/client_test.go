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

package client_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/custodian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testDaemon struct {
	socketPath  string
	maxInFlight atomic.Int32
	inFlight    atomic.Int32
	grpcServer  *grpc.Server
	listener    net.Listener
}

func (daemon *testDaemon) MaxInFlight() int {
	return int(daemon.maxInFlight.Load())
}

func (daemon *testDaemon) Close() error {
	daemon.grpcServer.Stop()
	err := daemon.listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func writeECDSAKeyAndCertificate(t *testing.T, directory, name string) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost", name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

	if err := os.WriteFile(filepath.Join(directory, name+".key"), keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".crt"), certificatePEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
	return privateKey
}

func writeRSAKeyAndCertificate(t *testing.T, directory, name string) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost", name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

	if err := os.WriteFile(filepath.Join(directory, name+".key"), keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".crt"), certificatePEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
	return privateKey
}

func writeMismatchedKeyAndCertificate(t *testing.T, directory, name string) {
	t.Helper()
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key A: %v", err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key B: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost", name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &keyB.PublicKey, keyB)
	if err != nil {
		t.Fatalf("failed to create certificate with key B: %v", err)
	}

	keyADER, err := x509.MarshalECPrivateKey(keyA)
	if err != nil {
		t.Fatalf("failed to marshal key A: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyADER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

	if err := os.WriteFile(filepath.Join(directory, name+".key"), keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".crt"), certificatePEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
}

func startTestDaemon(t *testing.T, keysDirectory string, signDelay time.Duration) *testDaemon {
	t.Helper()

	socketDirectory := t.TempDir()
	socketPath := filepath.Join(socketDirectory, "custodian.sock")

	custodianServer, err := custodian.NewServer(keysDirectory)
	if err != nil {
		t.Fatalf("failed to create custodian server: %v", err)
	}

	listener, err := custodian.ListenUnix(socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket %s: %v", socketPath, err)
	}

	daemon := &testDaemon{
		socketPath: socketPath,
		listener:   listener,
	}

	trackingInterceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.HasSuffix(info.FullMethod, "/Sign") {
			current := daemon.inFlight.Add(1)
			for {
				max := daemon.maxInFlight.Load()
				if current <= max || daemon.maxInFlight.CompareAndSwap(max, current) {
					break
				}
			}
			defer daemon.inFlight.Add(-1)
			if signDelay > 0 {
				time.Sleep(signDelay)
			}
		}
		return handler(ctx, req)
	}

	allowedUIDs := []uint32{uint32(os.Getuid())}
	daemon.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			custodian.UnaryAuthInterceptor(allowedUIDs, nil, nil),
			trackingInterceptor,
		),
		grpc.StreamInterceptor(custodian.StreamAuthInterceptor(allowedUIDs, nil, nil)),
	)
	keycustodianv1alpha1.RegisterKeyCustodianServiceServer(daemon.grpcServer, custodianServer)

	go func() {
		_ = daemon.grpcServer.Serve(listener)
	}()

	t.Cleanup(func() {
		daemon.grpcServer.Stop()
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("closing test daemon listener: %v", closeErr)
		}
	})

	return daemon
}

// Acceptance criterion: A tls.Server whose certificate uses the client's crypto.Signer
// completes a TLS 1.3 handshake with a tls.Client, through a real Unix socket (ECDSA).
func TestTLS13Handshake_ECDSA(t *testing.T) {
	keysDirectory := t.TempDir()
	writeECDSAKeyAndCertificate(t, keysDirectory, "p256")
	daemon := startTestDaemon(t, keysDirectory, 0)

	custodianClient, err := client.New(daemon.socketPath)
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	defer func() {
		if closeErr := custodianClient.Close(); closeErr != nil {
			t.Logf("closing client: %v", closeErr)
		}
	}()

	signer, err := custodianClient.NewSigner("p256")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	chainPEM, err := custodianClient.GetCertificateChain(t.Context(), "p256")
	if err != nil {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certificate.Raw},
		PrivateKey:  signer,
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	tlsListener := tls.NewListener(tcpListener, serverTLSConfig)
	defer func() {
		if closeErr := tlsListener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("closing tlsListener: %v", closeErr)
		}
	}()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Logf("closing server conn: %v", closeErr)
			}
		}()

		tlsConn := conn.(*tls.Conn)
		if handshakeErr := tlsConn.HandshakeContext(t.Context()); handshakeErr != nil {
			serverErrCh <- fmt.Errorf("server handshake: %w", handshakeErr)
			return
		}

		state := tlsConn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			serverErrCh <- fmt.Errorf("expected TLS 1.3, got %x", state.Version)
			return
		}

		buf := make([]byte, 5)
		if _, readErr := io.ReadFull(tlsConn, buf); readErr != nil {
			serverErrCh <- fmt.Errorf("server read: %w", readErr)
			return
		}
		if _, writeErr := tlsConn.Write([]byte("world")); writeErr != nil {
			serverErrCh <- fmt.Errorf("server write: %w", writeErr)
			return
		}
		serverErrCh <- nil
	}()

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}

	clientConn, err := tls.Dial("tcp", tlsListener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("closing clientConn: %v", closeErr)
		}
	}()

	if _, err := clientConn.Write([]byte("hello")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	resp := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(resp) != "world" {
		t.Fatalf("unexpected response: %q", string(resp))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// Acceptance criterion: A tls.Server whose certificate uses the client's crypto.Signer
// completes a TLS 1.3 handshake with a tls.Client, through a real Unix socket (RSA-PSS).
func TestTLS13Handshake_RSAPSS(t *testing.T) {
	keysDirectory := t.TempDir()
	writeRSAKeyAndCertificate(t, keysDirectory, "rsa")
	daemon := startTestDaemon(t, keysDirectory, 0)

	signer, err := client.NewSigner(daemon.socketPath, "rsa")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				t.Logf("closing signer: %v", closeErr)
			}
		}
	}()

	custodianClient, err := client.New(daemon.socketPath)
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	defer func() {
		if closeErr := custodianClient.Close(); closeErr != nil {
			t.Logf("closing client: %v", closeErr)
		}
	}()

	chainPEM, err := custodianClient.GetCertificateChain(t.Context(), "rsa")
	if err != nil {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
	block, _ := pem.Decode(chainPEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certificate.Raw},
		PrivateKey:  signer,
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	tlsListener := tls.NewListener(tcpListener, serverTLSConfig)
	defer func() {
		if closeErr := tlsListener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("closing tlsListener: %v", closeErr)
		}
	}()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Logf("closing server conn: %v", closeErr)
			}
		}()

		tlsConn := conn.(*tls.Conn)
		if handshakeErr := tlsConn.HandshakeContext(t.Context()); handshakeErr != nil {
			serverErrCh <- fmt.Errorf("server handshake: %w", handshakeErr)
			return
		}

		state := tlsConn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			serverErrCh <- fmt.Errorf("expected TLS 1.3, got %x", state.Version)
			return
		}

		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(tlsConn, buf); readErr != nil {
			serverErrCh <- fmt.Errorf("server read: %w", readErr)
			return
		}
		if _, writeErr := tlsConn.Write([]byte("pong")); writeErr != nil {
			serverErrCh <- fmt.Errorf("server write: %w", writeErr)
			return
		}
		serverErrCh <- nil
	}()

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}

	clientConn, err := tls.Dial("tcp", tlsListener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Logf("closing clientConn: %v", closeErr)
		}
	}()

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(resp) != "pong" {
		t.Fatalf("unexpected response: %q", string(resp))
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// Acceptance criterion: Under -race, 200 parallel Sign calls with the bound set to 8
// finish, and the custodian never sees more than 8 in flight.
func TestParallelSign_BoundedConcurrency(t *testing.T) {
	keysDirectory := t.TempDir()
	writeECDSAKeyAndCertificate(t, keysDirectory, "p256")
	daemon := startTestDaemon(t, keysDirectory, 2*time.Millisecond)

	signer, err := client.NewSigner(daemon.socketPath, "p256",
		client.WithMaxInFlight(8),
	)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				t.Logf("closing signer: %v", closeErr)
			}
		}
	}()

	const totalCalls = 200
	var waitGroup sync.WaitGroup
	errCh := make(chan error, totalCalls)

	for i := 0; i < totalCalls; i++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			digest := sha256.Sum256([]byte(fmt.Sprintf("message-%d", index)))
			sig, signErr := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if signErr != nil {
				errCh <- fmt.Errorf("call %d failed: %w", index, signErr)
				return
			}
			publicKey, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				errCh <- fmt.Errorf("unexpected public key type: %T", signer.Public())
				return
			}
			if !ecdsa.VerifyASN1(publicKey, digest[:], sig) {
				errCh <- fmt.Errorf("signature verification failed for call %d", index)
				return
			}
		}(i)
	}

	waitGroup.Wait()
	close(errCh)

	for callErr := range errCh {
		t.Fatal(callErr)
	}

	maxSeen := daemon.MaxInFlight()
	if maxSeen > 8 {
		t.Fatalf("custodian saw %d in flight, expected <= 8", maxSeen)
	}
	if maxSeen == 0 {
		t.Fatalf("expected custodian to see parallel calls in flight, got 0")
	}
}

// Acceptance criterion: When the socket is gone, Sign returns an error within the deadline.
// It never hangs.
func TestSign_SocketGoneReturnsWithinDeadline(t *testing.T) {
	keysDirectory := t.TempDir()
	writeECDSAKeyAndCertificate(t, keysDirectory, "p256")
	daemon := startTestDaemon(t, keysDirectory, 0)

	shortDeadline := 100 * time.Millisecond
	signer, err := client.NewSigner(daemon.socketPath, "p256",
		client.WithDeadline(shortDeadline),
	)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				t.Logf("closing signer: %v", closeErr)
			}
		}
	}()

	digest := sha256.Sum256([]byte("before closing socket"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("initial Sign failed: %v", err)
	}

	socketPath := daemon.socketPath
	if err := daemon.Close(); err != nil {
		t.Fatalf("daemon.Close failed: %v", err)
	}
	_ = os.Remove(socketPath)

	start := time.Now()
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Sign to fail when socket is gone, but succeeded")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("Sign took %v, exceeded deadline expectation of %v", elapsed, shortDeadline)
	}
}

func TestListKeysAndGetCertificateChain(t *testing.T) {
	keysDirectory := t.TempDir()
	writeECDSAKeyAndCertificate(t, keysDirectory, "p256")
	daemon := startTestDaemon(t, keysDirectory, 0)

	custodianClient, err := client.New(daemon.socketPath)
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	defer func() {
		if closeErr := custodianClient.Close(); closeErr != nil {
			t.Logf("closing client: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	keys, err := custodianClient.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != "p256" {
		t.Fatalf("expected keys [\"p256\"], got %v", keys)
	}

	chain, err := custodianClient.GetCertificateChain(ctx, "p256")
	if err != nil {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
	expectedCertPEM, err := os.ReadFile(filepath.Join(keysDirectory, "p256.crt"))
	if err != nil {
		t.Fatalf("reading expected cert file: %v", err)
	}
	if !bytes.Equal(chain, expectedCertPEM) {
		t.Fatalf("certificate chain mismatch")
	}

	_, err = custodianClient.GetCertificateChain(ctx, "non-existent")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for non-existent key, got: %v", err)
	}
}

func TestSign_HashAlgorithmsAndOptions(t *testing.T) {
	keysDirectory := t.TempDir()
	writeECDSAKeyAndCertificate(t, keysDirectory, "p256")
	daemon := startTestDaemon(t, keysDirectory, 0)

	signer, err := client.NewSigner(daemon.socketPath, "p256")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				t.Logf("closing signer: %v", closeErr)
			}
		}
	}()

	publicKey := signer.Public().(*ecdsa.PublicKey)

	// SHA-256
	d256 := sha256.Sum256([]byte("sha256 message"))
	sig256, err := signer.Sign(rand.Reader, d256[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign SHA256 failed: %v", err)
	}
	if !ecdsa.VerifyASN1(publicKey, d256[:], sig256) {
		t.Fatal("SHA256 verification failed")
	}

	// SHA-384
	d384 := sha512.Sum384([]byte("sha384 message"))
	sig384, err := signer.Sign(rand.Reader, d384[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign SHA384 failed: %v", err)
	}
	if !ecdsa.VerifyASN1(publicKey, d384[:], sig384) {
		t.Fatal("SHA384 verification failed")
	}

	// SHA-512
	d512 := sha512.Sum512([]byte("sha512 message"))
	sig512, err := signer.Sign(rand.Reader, d512[:], crypto.SHA512)
	if err != nil {
		t.Fatalf("Sign SHA512 failed: %v", err)
	}
	if !ecdsa.VerifyASN1(publicKey, d512[:], sig512) {
		t.Fatal("SHA512 verification failed")
	}

	// Nil options (hash 0) must be rejected
	if _, err := signer.Sign(rand.Reader, d256[:], nil); err == nil {
		t.Fatal("expected error for nil options, got nil")
	}

	// crypto.Hash(0) unhashed message must be rejected
	if _, err := signer.Sign(rand.Reader, d256[:], crypto.Hash(0)); err == nil {
		t.Fatal("expected error for hash 0, got nil")
	}

	// Digest length mismatch
	if _, err := signer.Sign(rand.Reader, d256[:10], crypto.SHA256); err == nil {
		t.Fatal("expected error for mismatched digest length, got nil")
	}

	// Unsupported hash (MD5)
	if _, err := signer.Sign(rand.Reader, make([]byte, 16), crypto.MD5); err == nil {
		t.Fatal("expected error for unsupported hash MD5, got nil")
	}
}

func TestSign_RSAPSSOptions(t *testing.T) {
	keysDirectory := t.TempDir()
	writeRSAKeyAndCertificate(t, keysDirectory, "rsa")
	daemon := startTestDaemon(t, keysDirectory, 0)

	signer, err := client.NewSigner(daemon.socketPath, "rsa")
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				t.Logf("closing signer: %v", closeErr)
			}
		}
	}()

	d256 := sha256.Sum256([]byte("rsa pss test message"))
	publicKey := signer.Public().(*rsa.PublicKey)

	pssOptions := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	sig, err := signer.Sign(rand.Reader, d256[:], pssOptions)
	if err != nil {
		t.Fatalf("Sign RSA-PSS failed: %v", err)
	}
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, d256[:], sig, pssOptions); err != nil {
		t.Fatalf("VerifyPSS failed: %v", err)
	}
}

func TestNewSigner_MismatchedKeyAndCertificateRejected(t *testing.T) {
	keysDirectory := t.TempDir()
	writeMismatchedKeyAndCertificate(t, keysDirectory, "mismatch")
	daemon := startTestDaemon(t, keysDirectory, 0)

	_, err := client.NewSigner(daemon.socketPath, "mismatch")
	if err == nil {
		t.Fatal("expected NewSigner to fail for mismatched key and certificate, but succeeded")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected error to name key %q, got: %v", "mismatch", err)
	}
}

func TestNewSigner_NonExistentSocketFailsWithinDeadline(t *testing.T) {
	start := time.Now()
	_, err := client.NewSigner("/tmp/non-existent-socket-never-created.sock", "key",
		client.WithDeadline(100*time.Millisecond),
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected NewSigner to fail with non-existent socket, got nil")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("NewSigner took %v, exceeded deadline expectation", elapsed)
	}
}
