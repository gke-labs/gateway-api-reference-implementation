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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Acceptance criterion: A tls.Server whose certificate uses the client's crypto.Signer
// completes a TLS 1.3 handshake with a tls.Client, through a real Unix socket (ECDSA).
func TestTLS13Handshake_ECDSA(t *testing.T) {
	fake := client.NewFakeCustodian(t)

	rawSigner, err := client.NewSigner(fake.SocketPath(), fake.KeyName())
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := rawSigner.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	tlsCert := tls.Certificate{
		Certificate: [][]byte{fake.Certificate().Raw},
		PrivateKey:  rawSigner,
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
	defer tlsListener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			serverErrCh <- fmt.Errorf("server handshake: %w", err)
			return
		}

		state := tlsConn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			serverErrCh <- fmt.Errorf("expected TLS 1.3, got %x", state.Version)
			return
		}

		buf := make([]byte, 5)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			serverErrCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := tlsConn.Write([]byte("world")); err != nil {
			serverErrCh <- fmt.Errorf("server write: %w", err)
			return
		}
		serverErrCh <- nil
	}()

	certPool := x509.NewCertPool()
	certPool.AddCert(fake.Certificate())

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}

	clientConn, err := tls.Dial("tcp", tlsListener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer clientConn.Close()

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
	fake := client.NewFakeCustodian(t, client.WithFakeRSAKey("rsa-test"))

	c, err := client.New(fake.SocketPath())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	defer c.Close()

	signer, err := c.Signer(fake.KeyName())
	if err != nil {
		t.Fatalf("c.Signer failed: %v", err)
	}

	tlsCert, err := signer.TLSCertificate()
	if err != nil {
		t.Fatalf("signer.TLSCertificate failed: %v", err)
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
	defer tlsListener.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			serverErrCh <- fmt.Errorf("server handshake: %w", err)
			return
		}

		state := tlsConn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			serverErrCh <- fmt.Errorf("expected TLS 1.3, got %x", state.Version)
			return
		}

		buf := make([]byte, 4)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			serverErrCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if _, err := tlsConn.Write([]byte("pong")); err != nil {
			serverErrCh <- fmt.Errorf("server write: %w", err)
			return
		}
		serverErrCh <- nil
	}()

	certPool := x509.NewCertPool()
	certPool.AddCert(fake.Certificate())

	clientTLSConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}

	clientConn, err := tls.Dial("tcp", tlsListener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	defer clientConn.Close()

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
	fake := client.NewFakeCustodian(t, client.WithFakeSignDelay(2*time.Millisecond))

	signer, err := client.NewSigner(fake.SocketPath(), fake.KeyName(),
		client.WithMaxInFlight(8),
	)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	const totalCalls = 200
	var wg sync.WaitGroup
	errCh := make(chan error, totalCalls)

	for i := 0; i < totalCalls; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			digest := sha256.Sum256([]byte(fmt.Sprintf("message-%d", idx)))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				errCh <- fmt.Errorf("call %d failed: %w", idx, err)
				return
			}
			pubKey, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				errCh <- fmt.Errorf("unexpected public key type: %T", signer.Public())
				return
			}
			if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
				errCh <- fmt.Errorf("signature verification failed for call %d", idx)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	maxSeen := fake.MaxInFlight()
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
	fake := client.NewFakeCustodian(t)

	// Configure a short deadline of 100ms
	shortDeadline := 100 * time.Millisecond
	signer, err := client.NewSigner(fake.SocketPath(), fake.KeyName(),
		client.WithDeadline(shortDeadline),
	)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	// Verify signing succeeds while the socket is alive.
	digest := sha256.Sum256([]byte("before closing socket"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("initial Sign failed: %v", err)
	}

	// Close the custodian server and ensure the socket file is removed.
	sockPath := fake.SocketPath()
	if err := fake.Close(); err != nil {
		t.Fatalf("fake.Close failed: %v", err)
	}
	_ = os.Remove(sockPath)

	// Sign must fail within the deadline and not hang.
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
	fake := client.NewFakeCustodian(t)

	c, err := client.New(fake.SocketPath())
	if err != nil {
		t.Fatalf("client.New failed: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keys, err := c.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 || keys[0] != fake.KeyName() {
		t.Fatalf("expected keys [%q], got %v", fake.KeyName(), keys)
	}

	chain, err := c.GetCertificateChain(ctx, fake.KeyName())
	if err != nil {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
	if !bytes.Equal(chain, fake.CertificatePEM()) {
		t.Fatalf("certificate chain mismatch")
	}

	// Top-level helpers
	topKeys, err := client.ListKeys(ctx, fake.SocketPath())
	if err != nil {
		t.Fatalf("client.ListKeys helper failed: %v", err)
	}
	if len(topKeys) != 1 || topKeys[0] != fake.KeyName() {
		t.Fatalf("top-level ListKeys mismatch: %v", topKeys)
	}

	topChain, err := client.GetCertificateChain(ctx, fake.SocketPath(), fake.KeyName())
	if err != nil {
		t.Fatalf("client.GetCertificateChain helper failed: %v", err)
	}
	if !bytes.Equal(topChain, fake.CertificatePEM()) {
		t.Fatalf("top-level GetCertificateChain mismatch")
	}

	// Unknown key
	_, err = c.GetCertificateChain(ctx, "non-existent")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for non-existent key, got: %v", err)
	}
}

func TestSign_HashAlgorithmsAndOptions(t *testing.T) {
	fake := client.NewFakeCustodian(t)

	signer, err := client.NewSigner(fake.SocketPath(), fake.KeyName())
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	// SHA-256
	d256 := sha256.Sum256([]byte("sha256 message"))
	sig256, err := signer.Sign(rand.Reader, d256[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign SHA256 failed: %v", err)
	}
	pubKey := signer.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pubKey, d256[:], sig256) {
		t.Fatal("SHA256 verification failed")
	}

	// SHA-384
	d384 := sha512.Sum384([]byte("sha384 message"))
	sig384, err := signer.Sign(rand.Reader, d384[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign SHA384 failed: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey, d384[:], sig384) {
		t.Fatal("SHA384 verification failed")
	}

	// SHA-512
	d512 := sha512.Sum512([]byte("sha512 message"))
	sig512, err := signer.Sign(rand.Reader, d512[:], crypto.SHA512)
	if err != nil {
		t.Fatalf("Sign SHA512 failed: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey, d512[:], sig512) {
		t.Fatal("SHA512 verification failed")
	}

	// Nil opts (infers SHA-256 from 32-byte digest)
	sigNil, err := signer.Sign(rand.Reader, d256[:], nil)
	if err != nil {
		t.Fatalf("Sign nil opts failed: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey, d256[:], sigNil) {
		t.Fatal("nil opts verification failed")
	}

	// Digest length mismatch
	_, err = signer.Sign(rand.Reader, d256[:10], crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for mismatched digest length, got nil")
	}

	// Unsupported hash (MD5)
	_, err = signer.Sign(rand.Reader, make([]byte, 16), crypto.MD5)
	if err == nil {
		t.Fatal("expected error for unsupported hash MD5, got nil")
	}
}

func TestSign_RSAPSSOptions(t *testing.T) {
	fake := client.NewFakeCustodian(t, client.WithFakeRSAKey("rsa-opts"))

	signer, err := client.NewSigner(fake.SocketPath(), fake.KeyName())
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer func() {
		if closer, ok := signer.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	d256 := sha256.Sum256([]byte("rsa pss test message"))
	pubKey := signer.Public().(*rsa.PublicKey)

	// RSA-PSS SaltLengthEqualsHash
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	sig, err := signer.Sign(rand.Reader, d256[:], pssOpts)
	if err != nil {
		t.Fatalf("Sign RSA-PSS failed: %v", err)
	}
	if err := rsa.VerifyPSS(pubKey, crypto.SHA256, d256[:], sig, pssOpts); err != nil {
		t.Fatalf("VerifyPSS failed: %v", err)
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
