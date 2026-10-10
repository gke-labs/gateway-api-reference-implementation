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

package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
)

func generateBackendCert(hosts ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames:              hosts,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestE2ESmoke(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "snigateway-e2e-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generate certificates to disk
	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "e2e-client"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	if err != nil {
		t.Fatalf("reading server.crt: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "server.key"))
	if err != nil {
		t.Fatalf("reading server.key: %v", err)
	}
	clientCertPEM, err := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	if err != nil {
		t.Fatalf("reading client.crt: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "client.key"))
	if err != nil {
		t.Fatalf("reading client.key: %v", err)
	}

	// 2. Start frontend server
	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		t.Fatalf("net.ListenPacket failed: %v", err)
	}

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
		ConnectTimeout:   5 * time.Second,
		ReadSNITimeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	// 3. Initialize client and tunnel Manager
	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	mgr := tunnel.NewManager(c)

	backendCert, err := generateBackendCert("app.example.com", "*.wildcard.org")
	if err != nil {
		t.Fatalf("generateBackendCert failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = mgr.Run(ctx)
	}()

	mgr.UpdateHostnames([]string{"app.example.com", "*.wildcard.org"})

	// Accept connections on tunnel listener
	go func() {
		lis := mgr.Listener()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsServer := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{backendCert},
				})
				defer tlsServer.Close()

				buf := make([]byte, 1024)
				n, err := tlsServer.Read(buf)
				if err != nil {
					return
				}
				reqStr := string(buf[:n])
				respStr := fmt.Sprintf("ECHO:%s", reqStr)
				_, _ = tlsServer.Write([]byte(respStr))
			}(conn)
		}
	}()

	// Wait for client to connect and register
	time.Sleep(100 * time.Millisecond)

	// 4. Dial frontend as external TLS client with SNI app.example.com
	t.Run("Exact SNI routing over reverse tunnel", func(t *testing.T) {
		tlsConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("tls.Dial failed: %v", err)
		}
		defer tlsConn.Close()

		payload := "ping-exact"
		if _, err := tlsConn.Write([]byte(payload)); err != nil {
			t.Fatalf("writing to tlsConn: %v", err)
		}

		reply := make([]byte, 1024)
		n, err := tlsConn.Read(reply)
		if err != nil {
			t.Fatalf("reading from tlsConn: %v", err)
		}

		got := string(reply[:n])
		want := "ECHO:ping-exact"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	// 5. Dial frontend as external TLS client with wildcard SNI
	t.Run("Wildcard SNI routing over reverse tunnel", func(t *testing.T) {
		tlsConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "sub.wildcard.org",
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("tls.Dial failed: %v", err)
		}
		defer tlsConn.Close()

		payload := "ping-wildcard"
		if _, err := tlsConn.Write([]byte(payload)); err != nil {
			t.Fatalf("writing to tlsConn: %v", err)
		}

		reply := make([]byte, 1024)
		n, err := tlsConn.Read(reply)
		if err != nil {
			t.Fatalf("reading from tlsConn: %v", err)
		}

		got := string(reply[:n])
		want := "ECHO:ping-wildcard"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	// 6. Unknown SNI is closed
	t.Run("Unregistered SNI is closed", func(t *testing.T) {
		conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			ServerName:         "unknown.example.org",
			InsecureSkipVerify: true,
		})
		if err == nil {
			buf := make([]byte, 10)
			_, readErr := conn.Read(buf)
			_ = conn.Close()
			if readErr == nil {
				t.Fatalf("expected unregistered SNI connection to be closed, but read succeeded")
			}
		}
	})
}
