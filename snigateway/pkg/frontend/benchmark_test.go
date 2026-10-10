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

package frontend

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"github.com/quic-go/quic-go"
)

func BenchmarkLatency_QUIC(b *testing.B) {
	srv, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(&testing.T{})
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		b.Fatalf("NewClientTLSConfig: %v", err)
	}

	backendCert, err := generateTestBackendCert("bench.example.com")
	if err != nil {
		b.Fatalf("generateTestBackendCert: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	qConn, err := c.DialQUIC(ctx)
	if err != nil {
		b.Fatalf("DialQUIC: %v", err)
	}
	defer qConn.CloseWithError(0, "bench done")

	ctrlStream, _ := qConn.OpenStreamSync(ctx)
	_, _ = ctrlStream.Write([]byte("{\"type\":\"session\"}\n"))
	reader := bufio.NewReader(ctrlStream)
	_, _ = reader.ReadBytes('\n')

	regReq := api.RegistrationRequest{Hostnames: []string{"bench.example.com"}}
	reqBytes, _ := jsonMarshal(regReq)
	_, _ = ctrlStream.Write(append(reqBytes, '\n'))
	_, _ = reader.ReadBytes('\n')

	go func() {
		for {
			s, err := qConn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func(stream *quic.Stream) {
				streamConn := api.NewQUICStreamConn(stream, qConn)
				bufReader := bufio.NewReader(streamConn)
				hdr, err := proxyproto.Decode(bufReader)
				if err != nil {
					_ = streamConn.Close()
					return
				}
				var remaining []byte
				if bufReader.Buffered() > 0 {
					remaining = make([]byte, bufReader.Buffered())
					_, _ = io.ReadFull(bufReader, remaining)
				}
				proxyConn := proxyproto.NewConn(streamConn, hdr.SrcAddr, hdr.DstAddr, remaining)
				tlsConn := tls.Server(proxyConn, &tls.Config{Certificates: []tls.Certificate{backendCert}})
				defer tlsConn.Close()

				buf := make([]byte, 1024)
				_, _ = tlsConn.Read(buf)
				_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(s)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "bench.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "bench.example.com",
					InsecureSkipVerify: true,
				})
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	_ = srv
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := httpClient.Get("https://bench.example.com/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkLatency_TCPPool(b *testing.B) {
	srv, serverAddr, generated, cleanup := setupTestServerAndClient(&testing.T{})
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		b.Fatalf("NewClientTLSConfig: %v", err)
	}

	backendCert, err := generateTestBackendCert("bench-tcp.example.com")
	if err != nil {
		b.Fatalf("generateTestBackendCert: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	mgr := tunnel.NewManager(c, tunnel.WithTransport("tcp"), tunnel.WithPoolSize(16))
	go func() {
		_ = mgr.Run(ctx)
	}()
	mgr.UpdateHostnames([]string{"bench-tcp.example.com"})

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{Certificates: []tls.Certificate{backendCert}})
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		}),
	}
	defer httpSrv.Close()
	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	time.Sleep(100 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "bench-tcp.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "bench-tcp.example.com",
					InsecureSkipVerify: true,
				})
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	_ = srv
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := httpClient.Get("https://bench-tcp.example.com/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkThroughput_QUIC(b *testing.B) {
	srv, serverAddr, generated, cleanup := setupTestServerWithUDPAndClient(&testing.T{})
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		b.Fatalf("NewClientTLSConfig: %v", err)
	}

	backendCert, err := generateTestBackendCert("tput-quic.example.com")
	if err != nil {
		b.Fatalf("generateTestBackendCert: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	mgr := tunnel.NewManager(c, tunnel.WithTransport("quic"))
	go func() {
		_ = mgr.Run(ctx)
	}()
	mgr.UpdateHostnames([]string{"tput-quic.example.com"})

	payload := make([]byte, 10*1024*1024) // 10MB
	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{Certificates: []tls.Certificate{backendCert}})
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "10485760")
			_, _ = w.Write(payload)
		}),
	}
	defer httpSrv.Close()
	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	time.Sleep(100 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "tput-quic.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "tput-quic.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 30 * time.Second,
	}

	_ = srv
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := httpClient.Get("https://tput-quic.example.com/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != int64(len(payload)) {
			b.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
	}
}

func BenchmarkThroughput_TCPPool(b *testing.B) {
	srv, serverAddr, generated, cleanup := setupTestServerAndClient(&testing.T{})
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		b.Fatalf("NewClientTLSConfig: %v", err)
	}

	backendCert, err := generateTestBackendCert("tput-tcp.example.com")
	if err != nil {
		b.Fatalf("generateTestBackendCert: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	mgr := tunnel.NewManager(c, tunnel.WithTransport("tcp"))
	go func() {
		_ = mgr.Run(ctx)
	}()
	mgr.UpdateHostnames([]string{"tput-tcp.example.com"})

	payload := make([]byte, 10*1024*1024) // 10MB
	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{Certificates: []tls.Certificate{backendCert}})
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "10485760")
			_, _ = w.Write(payload)
		}),
	}
	defer httpSrv.Close()
	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	time.Sleep(100 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "tput-tcp.example.com",
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         "tput-tcp.example.com",
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 30 * time.Second,
	}

	_ = srv
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := httpClient.Get("https://tput-tcp.example.com/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != int64(len(payload)) {
			b.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
	}
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
