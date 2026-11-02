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

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSNIListener_PassthroughAndHTTPSAndFailClosed(t *testing.T) {
	// 1. Backend TLS server for passthrough route
	backendCAPEM, backendTLSCert := generateTestCAAndCert(t, []string{"passthrough.example.com"}, nil)
	backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-passthrough-response"))
	}))
	backendServer.TLS = &tls.Config{Certificates: []tls.Certificate{backendTLSCert}}
	backendServer.StartTLS()
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server URL: %v", err)
	}
	backendHost, backendPortStr, err := net.SplitHostPort(backendURL.Host)
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}

	// 2. HTTPS terminating backend for proxy HTTPRoute
	httpsTermBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https-terminated-response"))
	}))
	defer httpsTermBackend.Close()

	termURL, err := url.Parse(httpsTermBackend.URL)
	if err != nil {
		t.Fatalf("failed to parse term backend URL: %v", err)
	}
	termHost, termPortStr, _ := net.SplitHostPort(termURL.Host)
	termPort, _ := strconv.Atoi(termPortStr)

	// 3. Proxy certificates
	proxyCAPEM, proxyTLSCert := generateTestCAAndCert(t, []string{"https.example.com"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com": &proxyTLSCert,
	}, &proxyTLSCert)

	// 4. Configure listeners on proxy:
	// - One TLS Passthrough listener for passthrough.example.com
	// - One HTTPS listener for https.example.com
	passthroughMode := gatewayv1.TLSModePassthrough
	httpsRoutes := []state.InternalRoute{
		{
			Hostnames: testRouteHostnames("https.example.com"),
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{
							Path: &state.InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/",
							},
						},
					},
					Backends: []state.InternalBackend{
						{
							Host:   termHost,
							Port:   int32(termPort),
							Weight: 1,
						},
					},
				},
			},
		},
	}

	p.UpdateConfig(
		[]state.InternalListener{
			{
				Name:        "tls-passthrough",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        443,
				Hostname:    "passthrough.example.com",
				TLSMode:     &passthroughMode,
				TLSBackends: map[string][]state.InternalTLSBackend{"passthrough.example.com": {{Target: net.JoinHostPort(backendHost, backendPortStr), Weight: 1}}},
			},
			{
				Name:     "https-terminating",
				Protocol: gatewayv1.HTTPSProtocolType,
				Port:     443,
				Hostname: "https.example.com",
				Routes:   httpsRoutes,
			},
		},
		httpsRoutes,
	)

	// 5. Start raw TCP listener with SNI front
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := &tls.Config{
		GetCertificate: p.GetCertificate,
	}
	httpsSrv := &http.Server{
		Handler:   p,
		TLSConfig: tlsConfig,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	go func() {
		_ = httpsSrv.Serve(tlsLis)
	}()
	defer httpsSrv.Close()

	addr := rawLis.Addr().String()

	// 6. Test Passthrough Route
	t.Run("Passthrough route presents backend cert unterminated", func(t *testing.T) {
		backendCertPool := x509.NewCertPool()
		backendCertPool.AppendCertsFromPEM(backendCAPEM)

		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: "passthrough.example.com",
			RootCAs:    backendCertPool,
		})
		if err != nil {
			t.Fatalf("failed to connect to passthrough SNI: %v", err)
		}
		defer conn.Close()

		// Verify backend's certificate was presented
		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Fatal("expected peer certificates from backend")
		}
		leaf := state.PeerCertificates[0]
		foundDNS := false
		for _, dns := range leaf.DNSNames {
			if dns == "passthrough.example.com" {
				foundDNS = true
				break
			}
		}
		if !foundDNS {
			t.Errorf("expected peer cert to have DNS passthrough.example.com, got %v", leaf.DNSNames)
		}

		// Make HTTP request over the connection
		req := "GET / HTTP/1.1\r\nHost: passthrough.example.com\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("failed to write HTTP request: %v", err)
		}
		respBytes, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("failed to read HTTP response: %v", err)
		}
		if !strings.Contains(string(respBytes), "backend-passthrough-response") {
			t.Errorf("expected response from passthrough backend, got %q", string(respBytes))
		}
	})

	// 7. Test HTTPS Terminating Route
	t.Run("HTTPS route terminates and serves with proxy cert", func(t *testing.T) {
		proxyCertPool := x509.NewCertPool()
		proxyCertPool.AppendCertsFromPEM(proxyCAPEM)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName: "https.example.com",
					RootCAs:    proxyCertPool,
				},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", addr)
				},
			},
			Timeout: 2 * time.Second,
		}

		resp, err := client.Get("https://https.example.com/")
		if err != nil {
			t.Fatalf("failed to GET from HTTPS listener: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if string(body) != "https-terminated-response" {
			t.Errorf("expected response %q, got %q", "https-terminated-response", string(body))
		}
	})

	// 8. Test Non-matching SNI is closed without response (Fail closed)
	t.Run("Non-matching SNI is closed without response", func(t *testing.T) {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         "unknown.example.com",
			InsecureSkipVerify: true,
		})
		if err == nil {
			conn.Close()
			t.Fatal("expected connection rejection for unknown SNI, but connection succeeded")
		}
	})
}

func TestSNIListener_ShutdownMidHandshakeRace(t *testing.T) {
	_, proxyTLSCert := generateTestCAAndCert(t, []string{"https.example.com"}, nil)
	_, termTLSCert := generateTestCAAndCert(t, []string{"terminate.example.com"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com":     &proxyTLSCert,
		"terminate.example.com": &termTLSCert,
	}, &proxyTLSCert)

	echoLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo backend: %v", err)
	}
	defer echoLis.Close()
	go func() {
		for {
			conn, err := echoLis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	terminateMode := gatewayv1.TLSModeTerminate
	p.UpdateConfig(
		[]state.InternalListener{
			{
				Name:     "https",
				Protocol: gatewayv1.HTTPSProtocolType,
				Port:     443,
				Hostname: "https.example.com",
			},
			{
				Name:        "tls-terminate",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        443,
				Hostname:    "terminate.example.com",
				TLSMode:     &terminateMode,
				TLSBackends: map[string][]state.InternalTLSBackend{"terminate.example.com": {{Target: echoLis.Addr().String(), Weight: 1}}},
			},
		},
		nil,
	)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	sniLis := p.NewSNIListener(rawLis)
	addr := rawLis.Addr().String()

	var wg sync.WaitGroup

	// Background worker accepting connections from sniLis
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := sniLis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// Spawn multiple clients that initiate TLS handshakes concurrently across both HTTPS and Terminate paths
	for i := 0; i < 40; i++ {
		wg.Add(1)
		serverName := "https.example.com"
		if i%2 == 0 {
			serverName = "terminate.example.com"
		}
		go func(sn string) {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: 1 * time.Second}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         sn,
				InsecureSkipVerify: true,
			})
			if err == nil {
				_ = conn.Close()
			}
		}(serverName)
	}

	// Close the listener while handshakes are mid-flight
	time.Sleep(2 * time.Millisecond)
	_ = sniLis.Close()

	wg.Wait()
	<-acceptDone
}

func TestSNIListener_PassthroughNoResolvableBackendClosed(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough

	p := NewProxy()
	p.UpdateConfig(
		[]state.InternalListener{
			{
				Name:        "tls-passthrough",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        443,
				Hostname:    "passthrough.example.com",
				TLSMode:     &passthroughMode,
				TLSBackends: nil, // Passthrough listener with no resolvable backend
			},
		},
		nil,
	)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	addr := rawLis.Addr().String()

	// Dial TLS with SNI matching the Passthrough listener
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         "passthrough.example.com",
		InsecureSkipVerify: true,
	})
	if err == nil {
		conn.Close()
		t.Fatal("expected connection rejection when passthrough listener has no resolvable backend, but connection succeeded")
	}
}

func TestSNIListener_BypassToggle(t *testing.T) {
	_, proxyTLSCert := generateTestCAAndCert(t, []string{"https.example.com"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com": &proxyTLSCert,
	}, &proxyTLSCert)

	httpsListener := state.InternalListener{
		Name:     "https-listener",
		Protocol: gatewayv1.HTTPSProtocolType,
		Port:     443,
		Hostname: "https.example.com",
	}

	backendCAPEM, backendTLSCert := generateTestCAAndCert(t, []string{"passthrough.example.com"}, nil)
	backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("passthrough-ok"))
	}))
	backendServer.TLS = &tls.Config{Certificates: []tls.Certificate{backendTLSCert}}
	backendServer.StartTLS()
	defer backendServer.Close()

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server URL: %v", err)
	}
	backendHost, backendPortStr, err := net.SplitHostPort(backendURL.Host)
	if err != nil {
		t.Fatalf("failed to split backend host port: %v", err)
	}

	passthroughMode := gatewayv1.TLSModePassthrough
	passthroughListener := state.InternalListener{
		Name:        "tls-passthrough",
		Protocol:    gatewayv1.TLSProtocolType,
		Port:        443,
		Hostname:    "passthrough.example.com",
		TLSMode:     &passthroughMode,
		TLSBackends: map[string][]state.InternalTLSBackend{"passthrough.example.com": {{Target: net.JoinHostPort(backendHost, backendPortStr), Weight: 1}}},
	}

	// 1. Initial config: no Passthrough listeners (HTTPS only)
	p.UpdateConfig([]state.InternalListener{httpsListener}, nil)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	addr := rawLis.Addr().String()

	// Step 1: With no Passthrough listeners, Accept returns raw connection (not *sni.PeekedConn)
	t.Run("Initially no Passthrough: returns raw connection", func(t *testing.T) {
		clientConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer clientConn.Close()

		acceptedConn, err := sniLis.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		defer acceptedConn.Close()

		if _, ok := acceptedConn.(*sni.PeekedConn); ok {
			t.Fatalf("expected raw connection, got *sni.PeekedConn")
		}
	})

	// Step 2: Add Passthrough listener via UpdateConfig: switches path ON without restarting listener
	t.Run("Add Passthrough: switches path ON", func(t *testing.T) {
		p.UpdateConfig([]state.InternalListener{httpsListener, passthroughListener}, nil)

		// First, verify passthrough traffic is spliced to backend
		backendCertPool := x509.NewCertPool()
		backendCertPool.AppendCertsFromPEM(backendCAPEM)
		ptConn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: "passthrough.example.com",
			RootCAs:    backendCertPool,
		})
		if err != nil {
			t.Fatalf("failed to dial passthrough SNI: %v", err)
		}
		defer ptConn.Close()

		req := "GET / HTTP/1.1\r\nHost: passthrough.example.com\r\nConnection: close\r\n\r\n"
		if _, err := ptConn.Write([]byte(req)); err != nil {
			t.Fatalf("failed to write request: %v", err)
		}
		resp, err := io.ReadAll(ptConn)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		if !strings.Contains(string(resp), "passthrough-ok") {
			t.Errorf("expected passthrough-ok response, got %q", string(resp))
		}

		// Second, verify HTTPS traffic is intercepted, sniffed, and returned as *sni.PeekedConn
		go func() {
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			c, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         "https.example.com",
				InsecureSkipVerify: true,
			})
			if err == nil {
				_ = c.Close()
			}
		}()

		acceptedConn, err := sniLis.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		defer acceptedConn.Close()

		if _, ok := acceptedConn.(*sni.PeekedConn); !ok {
			t.Fatalf("expected *sni.PeekedConn when passthrough is active, got %T", acceptedConn)
		}
	})

	// Step 3: Remove Passthrough listener via UpdateConfig: switches path OFF again
	t.Run("Remove Passthrough: switches path OFF", func(t *testing.T) {
		p.UpdateConfig([]state.InternalListener{httpsListener}, nil)

		clientConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer clientConn.Close()

		acceptedConn, err := sniLis.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		defer acceptedConn.Close()

		if _, ok := acceptedConn.(*sni.PeekedConn); ok {
			t.Fatalf("expected raw connection after removing passthrough, got *sni.PeekedConn")
		}

		// Subsequent connection should also be raw
		clientConn2, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial 2nd connection: %v", err)
		}
		defer clientConn2.Close()

		acceptedConn2, err := sniLis.Accept()
		if err != nil {
			t.Fatalf("Accept 2nd failed: %v", err)
		}
		defer acceptedConn2.Close()

		if _, ok := acceptedConn2.(*sni.PeekedConn); ok {
			t.Fatalf("expected raw connection on subsequent accept, got *sni.PeekedConn")
		}
	})
}

func TestSNIListener_SwitchOffHandOffStress(t *testing.T) {
	passthroughMode := gatewayv1.TLSModePassthrough
	httpsListener := state.InternalListener{
		Name:     "https-listener",
		Protocol: gatewayv1.HTTPSProtocolType,
		Port:     443,
		Hostname: "https.example.com",
	}
	passthroughListener := state.InternalListener{
		Name:     "tls-passthrough",
		Protocol: gatewayv1.TLSProtocolType,
		Port:     443,
		Hostname: "passthrough.example.com",
		TLSMode:  &passthroughMode,
	}

	p := NewProxy()
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	addr := rawLis.Addr().String()

	const iterations = 50
	for i := 0; i < iterations; i++ {
		// Turn passthrough ON so acceptLoop is active.
		p.UpdateConfig([]state.InternalListener{httpsListener, passthroughListener}, nil)

		// Switch passthrough OFF.
		p.UpdateConfig([]state.InternalListener{httpsListener}, nil)

		type acceptResult struct {
			conn net.Conn
			err  error
		}
		acceptCh := make(chan acceptResult, 1)

		var clientConn net.Conn
		if i%2 == 0 {
			// Dial first, then Accept
			clientConn, err = net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("iteration %d: failed to dial: %v", i, err)
			}
			go func() {
				c, aErr := sniLis.Accept()
				acceptCh <- acceptResult{conn: c, err: aErr}
			}()
		} else {
			// Accept first, then Dial
			go func() {
				c, aErr := sniLis.Accept()
				acceptCh <- acceptResult{conn: c, err: aErr}
			}()
			clientConn, err = net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("iteration %d: failed to dial: %v", i, err)
			}
		}

		select {
		case res := <-acceptCh:
			if res.err != nil {
				clientConn.Close()
				t.Fatalf("iteration %d: Accept failed: %v", i, res.err)
			}
			// Verify bidirectional data transfer over the accepted connection.
			msg := []byte("ping")
			if _, err := clientConn.Write(msg); err != nil {
				res.conn.Close()
				clientConn.Close()
				t.Fatalf("iteration %d: failed to write ping: %v", i, err)
			}
			buf := make([]byte, 4)
			_ = res.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			if _, err := io.ReadFull(res.conn, buf); err != nil {
				res.conn.Close()
				clientConn.Close()
				t.Fatalf("iteration %d: failed to read ping: %v", i, err)
			}
			res.conn.Close()
			clientConn.Close()
		case <-time.After(2 * time.Second):
			clientConn.Close()
			t.Fatalf("iteration %d: Accept timed out during switch-off hand-off (hung)", i)
		}
	}
}

func BenchmarkSNIListener_HTTPSOnly(b *testing.B) {
	_, proxyTLSCert := generateTestCAAndCert(b, []string{"https.example.com"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com": &proxyTLSCert,
	}, &proxyTLSCert)

	httpsRoutes := []state.InternalRoute{
		{
			Hostnames: testRouteHostnames("https.example.com"),
			Rules: []state.InternalRule{
				{
					Backends: []state.InternalBackend{
						{Host: "127.0.0.1", Port: 8080, Weight: 1},
					},
				},
			},
		},
	}
	p.UpdateConfig(
		[]state.InternalListener{
			{
				Name:     "https",
				Protocol: gatewayv1.HTTPSProtocolType,
				Port:     443,
				Hostname: "https.example.com",
				Routes:   httpsRoutes,
			},
		},
		httpsRoutes,
	)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsConfig := &tls.Config{
		GetCertificate: p.GetCertificate,
	}
	tlsLis := tls.NewListener(sniLis, tlsConfig)
	defer tlsLis.Close()

	go func() {
		for {
			conn, err := tlsLis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var buf [1]byte
				_, _ = c.Read(buf[:])
			}(conn)
		}
	}()

	addr := rawLis.Addr().String()
	clientTLSConfig := &tls.Config{
		ServerName:         "https.example.com",
		InsecureSkipVerify: true,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := tls.Dial("tcp", addr, clientTLSConfig)
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		_, _ = conn.Write([]byte("x"))
		_ = conn.Close()
	}
}

func TestSNIListener_TerminateAndMixedAndMissingCert(t *testing.T) {
	// 1. Plain-text TCP echo backend (records bytes received)
	var plainReceived sync.Map
	echoLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo backend: %v", err)
	}
	defer echoLis.Close()

	go func() {
		for {
			conn, err := echoLis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err == nil && n > 0 {
					plainReceived.Store("data", string(buf[:n]))
					_, _ = c.Write(append([]byte("plain-echo:"), buf[:n]...))
				}
			}(conn)
		}
	}()

	// 2. Passthrough TLS backend
	backendCAPEM, backendTLSCert := generateTestCAAndCert(t, []string{"passthrough.example.com"}, nil)
	tlsBackendLis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{backendTLSCert},
	})
	if err != nil {
		t.Fatalf("failed to listen for TLS backend: %v", err)
	}
	defer tlsBackendLis.Close()

	go func() {
		for {
			conn, err := tlsBackendLis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err == nil && n > 0 {
					_, _ = c.Write(append([]byte("tls-echo:"), buf[:n]...))
				}
			}(conn)
		}
	}()

	// 3. Certificates for proxy: certificate for terminate.example.com only
	termCAPEM, termTLSCert := generateTestCAAndCert(t, []string{"terminate.example.com"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"terminate.example.com": &termTLSCert,
	}, nil)

	// 4. Configure listeners on proxy on the same port (8443):
	// - Terminate listener for terminate.example.com
	// - Passthrough listener for passthrough.example.com
	// - Terminate listener with missing cert for missing-cert.example.com
	terminateMode := gatewayv1.TLSModeTerminate
	passthroughMode := gatewayv1.TLSModePassthrough

	p.UpdateConfig(
		[]state.InternalListener{
			{
				Name:        "tls-terminate",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        8443,
				Hostname:    "terminate.example.com",
				TLSMode:     &terminateMode,
				TLSBackends: map[string][]state.InternalTLSBackend{"terminate.example.com": {{Target: echoLis.Addr().String(), Weight: 1}}},
			},
			{
				Name:        "tls-passthrough",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        8443,
				Hostname:    "passthrough.example.com",
				TLSMode:     &passthroughMode,
				TLSBackends: map[string][]state.InternalTLSBackend{"passthrough.example.com": {{Target: tlsBackendLis.Addr().String(), Weight: 1}}},
			},
			{
				Name:        "tls-missing-cert",
				Protocol:    gatewayv1.TLSProtocolType,
				Port:        8443,
				Hostname:    "missing-cert.example.com",
				TLSMode:     &terminateMode,
				TLSBackends: map[string][]state.InternalTLSBackend{"missing-cert.example.com": {{Target: echoLis.Addr().String(), Weight: 1}}},
			},
		},
		nil,
	)

	// 5. Start raw TCP listener with SNI front
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	addr := rawLis.Addr().String()

	t.Run("Terminate listener terminates with listener cert and reaches backend in plain text", func(t *testing.T) {
		termCertPool := x509.NewCertPool()
		termCertPool.AppendCertsFromPEM(termCAPEM)

		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: "terminate.example.com",
			RootCAs:    termCertPool,
		})
		if err != nil {
			t.Fatalf("failed to dial terminate listener: %v", err)
		}
		defer conn.Close()

		// Verify client verified listener's cert
		connState := conn.ConnectionState()
		if len(connState.PeerCertificates) == 0 {
			t.Fatal("expected peer certificates")
		}
		if connState.PeerCertificates[0].DNSNames[0] != "terminate.example.com" {
			t.Errorf("expected peer cert for terminate.example.com, got %v", connState.PeerCertificates[0].DNSNames)
		}

		// Send message over TLS
		msg := "secret payload"
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("failed to write payload: %v", err)
		}

		reply := make([]byte, 1024)
		n, err := conn.Read(reply)
		if err != nil {
			t.Fatalf("failed to read reply: %v", err)
		}
		if string(reply[:n]) != "plain-echo:"+msg {
			t.Errorf("expected reply plain-echo:%s, got %s", msg, string(reply[:n]))
		}

		// Verify bytes arrived at backend in plain text
		received, ok := plainReceived.Load("data")
		if !ok || received.(string) != msg {
			t.Errorf("expected plain text %q at echo backend, got %v", msg, received)
		}
	})

	t.Run("Mixed mode on one port: passthrough SNI sees backend cert", func(t *testing.T) {
		backendCertPool := x509.NewCertPool()
		backendCertPool.AppendCertsFromPEM(backendCAPEM)

		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: "passthrough.example.com",
			RootCAs:    backendCertPool,
		})
		if err != nil {
			t.Fatalf("failed to dial passthrough listener: %v", err)
		}
		defer conn.Close()

		// Verify backend's cert was presented
		connState := conn.ConnectionState()
		if len(connState.PeerCertificates) == 0 {
			t.Fatal("expected peer certificates from backend")
		}
		if connState.PeerCertificates[0].DNSNames[0] != "passthrough.example.com" {
			t.Errorf("expected backend cert for passthrough.example.com, got %v", connState.PeerCertificates[0].DNSNames)
		}

		msg := "passthrough payload"
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("failed to write payload: %v", err)
		}
		reply := make([]byte, 1024)
		n, err := conn.Read(reply)
		if err != nil {
			t.Fatalf("failed to read reply: %v", err)
		}
		if string(reply[:n]) != "tls-echo:"+msg {
			t.Errorf("expected reply tls-echo:%s, got %s", msg, string(reply[:n]))
		}
	})

	t.Run("Terminate listener with missing cert closes connection (fail closed)", func(t *testing.T) {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         "missing-cert.example.com",
			InsecureSkipVerify: true,
		})
		if err == nil {
			conn.Close()
			t.Fatal("expected connection to fail closed when cert is missing, but connection succeeded")
		}
	})
}

func TestSNIListener_ConsistentConfigSnapshotDuringSwap(t *testing.T) {
	// Subtest 1: Structural atomicity: flag and candidates can never disagree
	t.Run("Snapshot flag and candidates never disagree", func(t *testing.T) {
		p := NewProxy()
		httpsListener := state.InternalListener{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "https.example.com",
		}
		ptMode := gatewayv1.TLSModePassthrough
		passthroughListener := state.InternalListener{
			Name:     "passthrough",
			Protocol: gatewayv1.TLSProtocolType,
			Port:     443,
			Hostname: "passthrough.example.com",
			TLSMode:  &ptMode,
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup

		// Writer swapping back and forth between HTTPS-only and Passthrough+HTTPS
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					if i%2 == 0 {
						p.UpdateConfig([]state.InternalListener{httpsListener}, nil)
					} else {
						p.UpdateConfig([]state.InternalListener{httpsListener, passthroughListener}, nil)
					}
				}
			}
		}()

		// Multiple concurrent readers inspecting loaded snapshots
		const readers = 8
		var readersWg sync.WaitGroup
		for r := 0; r < readers; r++ {
			readersWg.Add(1)
			go func() {
				defer readersWg.Done()
				for i := 0; i < 5000; i++ {
					cfg := p.sniConfig.Load()
					if cfg == nil {
						t.Errorf("cfg was nil")
						return
					}
					hasPTInCandidates := false
					for _, c := range cfg.candidates {
						if c.Protocol == gatewayv1.TLSProtocolType {
							hasPTInCandidates = true
							break
						}
					}
					if cfg.hasPassthrough != hasPTInCandidates {
						t.Errorf("inconsistent snapshot observed: hasPassthrough=%v but candidates has PT=%v",
							cfg.hasPassthrough, hasPTInCandidates)
						return
					}
				}
			}()
		}

		readersWg.Wait()
		close(stop)
		wg.Wait()
	})

	// Subtest 2: Connection uses single consistent snapshot grabbed on accept
	t.Run("Connection uses single consistent snapshot grabbed on accept", func(t *testing.T) {
		backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("backend-passthrough-response"))
		}))
		backendCAPEM, backendTLSCert := generateTestCAAndCert(t, []string{"passthrough.example.com"}, nil)
		backendServer.TLS = &tls.Config{Certificates: []tls.Certificate{backendTLSCert}}
		backendServer.StartTLS()
		defer backendServer.Close()

		backendURL, err := url.Parse(backendServer.URL)
		if err != nil {
			t.Fatalf("failed to parse backend URL: %v", err)
		}
		backendHost, backendPortStr, err := net.SplitHostPort(backendURL.Host)
		if err != nil {
			t.Fatalf("failed to split backend host port: %v", err)
		}

		ptMode := gatewayv1.TLSModePassthrough
		passthroughListener := state.InternalListener{
			Name:        "passthrough",
			Protocol:    gatewayv1.TLSProtocolType,
			Port:        443,
			Hostname:    "passthrough.example.com",
			TLSMode:     &ptMode,
			TLSBackends: map[string][]state.InternalTLSBackend{"passthrough.example.com": {{Target: net.JoinHostPort(backendHost, backendPortStr), Weight: 1}}},
		}
		httpsListener := state.InternalListener{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "https.example.com",
		}

		p := NewProxy()
		// Start with Passthrough configured
		p.UpdateConfig([]state.InternalListener{passthroughListener, httpsListener}, nil)

		rawLis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer rawLis.Close()

		sniLis := p.NewSNIListener(rawLis)
		defer sniLis.Close()

		addr := rawLis.Addr().String()

		// 1. Client connects via TCP (acceptLoop accepts and loads Passthrough snapshot cfg)
		rawConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial raw TCP: %v", err)
		}
		defer rawConn.Close()

		// 2. Allow acceptLoop to accept the connection before TLS handshake begins
		time.Sleep(20 * time.Millisecond)

		// 3. Swap config to HTTPS-only (removing passthroughListener from proxy)
		p.UpdateConfig([]state.InternalListener{httpsListener}, nil)

		// 4. Now perform the TLS ClientHello on the already-accepted connection.
		// If handleConn reloaded config or saw inconsistent config, it would fail closed.
		// Since it uses the captured snapshot from accept time, it routes to passthrough backend.
		backendCertPool := x509.NewCertPool()
		backendCertPool.AppendCertsFromPEM(backendCAPEM)
		tlsClient := tls.Client(rawConn, &tls.Config{
			ServerName: "passthrough.example.com",
			RootCAs:    backendCertPool,
		})
		defer tlsClient.Close()

		req := "GET / HTTP/1.1\r\nHost: passthrough.example.com\r\nConnection: close\r\n\r\n"
		if _, err := tlsClient.Write([]byte(req)); err != nil {
			t.Fatalf("failed to write request: %v", err)
		}
		respBytes, err := io.ReadAll(tlsClient)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		if !strings.Contains(string(respBytes), "backend-passthrough-response") {
			t.Errorf("expected backend-passthrough-response, got %q", string(respBytes))
		}
	})

	// Subtest 3: Concurrent connections during rapid config swap never see inconsistent snapshot
	t.Run("Concurrent connections during rapid config swap never see inconsistent snapshot", func(t *testing.T) {
		backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("backend-passthrough-response"))
		}))
		backendCAPEM, backendTLSCert := generateTestCAAndCert(t, []string{"passthrough.example.com"}, nil)
		backendServer.TLS = &tls.Config{Certificates: []tls.Certificate{backendTLSCert}}
		backendServer.StartTLS()
		defer backendServer.Close()

		backendURL, err := url.Parse(backendServer.URL)
		if err != nil {
			t.Fatalf("failed to parse backend URL: %v", err)
		}
		backendHost, backendPortStr, err := net.SplitHostPort(backendURL.Host)
		if err != nil {
			t.Fatalf("failed to split backend host port: %v", err)
		}

		ptMode := gatewayv1.TLSModePassthrough
		passthroughListener := state.InternalListener{
			Name:        "passthrough",
			Protocol:    gatewayv1.TLSProtocolType,
			Port:        443,
			Hostname:    "passthrough.example.com",
			TLSMode:     &ptMode,
			TLSBackends: map[string][]state.InternalTLSBackend{"passthrough.example.com": {{Target: net.JoinHostPort(backendHost, backendPortStr), Weight: 1}}},
		}
		httpsListener := state.InternalListener{
			Name:     "https",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     443,
			Hostname: "https.example.com",
		}

		p := NewProxy()
		p.UpdateConfig([]state.InternalListener{httpsListener}, nil)

		rawLis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer rawLis.Close()

		sniLis := p.NewSNIListener(rawLis)
		defer sniLis.Close()

		// Drain httpsConnCh so raw connections don't block
		go func() {
			for {
				conn, err := sniLis.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()

		addr := rawLis.Addr().String()

		stop := make(chan struct{})
		var wg sync.WaitGroup

		// Writer toggling config
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					if i%2 == 0 {
						p.UpdateConfig([]state.InternalListener{httpsListener}, nil)
					} else {
						p.UpdateConfig([]state.InternalListener{httpsListener, passthroughListener}, nil)
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()

		backendCertPool := x509.NewCertPool()
		backendCertPool.AppendCertsFromPEM(backendCAPEM)

		// Workers dialing with passthrough SNI
		const workers = 4
		var clientWg sync.WaitGroup
		for w := 0; w < workers; w++ {
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()
				for i := 0; i < 25; i++ {
					dialer := &net.Dialer{Timeout: 1 * time.Second}
					conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
						ServerName: "passthrough.example.com",
						RootCAs:    backendCertPool,
					})
					if err == nil {
						_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
						req := "GET / HTTP/1.1\r\nHost: passthrough.example.com\r\nConnection: close\r\n\r\n"
						_, _ = conn.Write([]byte(req))
						resp, _ := io.ReadAll(conn)
						_ = conn.Close()
						if len(resp) > 0 && !strings.Contains(string(resp), "backend-passthrough-response") {
							t.Errorf("unexpected response: %q", string(resp))
						}
					}
				}
			}()
		}

		clientWg.Wait()
		close(stop)
		wg.Wait()
	})
}

func TestTLSSessionResumption_HTTPSListener(t *testing.T) {
	caPEM, cert := generateTestCAAndCert(t, []string{"https.example.com"}, nil)
	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com": &cert,
	}, &cert)

	routes := []state.InternalRoute{
		{
			Hostnames: testRouteHostnames("https.example.com"),
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
					},
				},
			},
		},
	}
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "https-listener",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "https.example.com",
			Routes:   routes,
		},
	}, routes)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsLis := tls.NewListener(sniLis, p.TLSConfig())
	defer tlsLis.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	go func() {
		_ = srv.Serve(tlsLis)
	}()
	defer srv.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		ServerName:         "https.example.com",
		RootCAs:            caPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
	}

	addr := rawLis.Addr().String()

	// Connection 1: full TLS handshake, receives session ticket
	conn1, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 1 failed: %v", err)
	}
	req := "GET / HTTP/1.1\r\nHost: https.example.com\r\nConnection: close\r\n\r\n"
	if _, err := conn1.Write([]byte(req)); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	_, _ = io.ReadAll(conn1)
	if conn1.ConnectionState().DidResume {
		t.Errorf("connection 1 expected DidResume=false, got true")
	}
	conn1.Close()

	// Connection 2: resumed TLS handshake
	conn2, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 2 failed: %v", err)
	}
	if _, err := conn2.Write([]byte(req)); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	_, _ = io.ReadAll(conn2)
	if !conn2.ConnectionState().DidResume {
		t.Errorf("connection 2 expected DidResume=true, got false")
	}
	conn2.Close()
}

func TestTLSSessionResumption_HTTPSListener_ConcurrentWithReadLock(t *testing.T) {
	caPEM, cert := generateTestCAAndCert(t, []string{"https.example.com"}, nil)
	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"https.example.com": &cert,
	}, &cert)

	routes := []state.InternalRoute{
		{
			Hostnames: testRouteHostnames("https.example.com"),
			Rules: []state.InternalRule{
				{
					Matches: []state.InternalMatch{
						{Path: &state.InternalPathMatch{Type: gatewayv1.PathMatchPathPrefix, Value: "/"}},
					},
				},
			},
		},
	}
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "https-listener",
			Protocol: gatewayv1.HTTPSProtocolType,
			Port:     8443,
			Hostname: "https.example.com",
			Routes:   routes,
		},
	}, routes)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	tlsLis := tls.NewListener(sniLis, p.TLSConfig())
	defer tlsLis.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	go func() {
		_ = srv.Serve(tlsLis)
	}()
	defer srv.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		ServerName:         "https.example.com",
		RootCAs:            caPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
	}

	addr := rawLis.Addr().String()

	// Acquire proxy read lock. Both full handshake (wrapSession) and resumed handshake
	// (unwrapSession) must succeed concurrently without deadlocking on write locks.
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Connection 1: full TLS handshake, receives session ticket
	conn1, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 1 failed: %v", err)
	}
	req := "GET / HTTP/1.1\r\nHost: https.example.com\r\nConnection: close\r\n\r\n"
	if _, err := conn1.Write([]byte(req)); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	_, _ = io.ReadAll(conn1)
	if conn1.ConnectionState().DidResume {
		t.Errorf("connection 1 expected DidResume=false, got true")
	}
	conn1.Close()

	// Connection 2: resumed TLS handshake
	conn2, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 2 failed: %v", err)
	}
	if _, err := conn2.Write([]byte(req)); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	_, _ = io.ReadAll(conn2)
	if !conn2.ConnectionState().DidResume {
		t.Errorf("connection 2 expected DidResume=true, got false")
	}
	conn2.Close()
}

func TestTLSSessionResumption_TLSRouteTerminate(t *testing.T) {
	caPEM, cert := generateTestCAAndCert(t, []string{"tls.example.com"}, nil)
	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"tls.example.com": &cert,
	}, &cert)

	// Plain TCP backend that echoes back
	backendLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on backend: %v", err)
	}
	defer backendLis.Close()

	go func() {
		for {
			c, err := backendLis.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write([]byte("backend-echo: " + string(buf[:n])))
				}
			}(c)
		}
	}()

	terminateMode := gatewayv1.TLSModeTerminate
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "tls-terminate-listener",
			Protocol: gatewayv1.TLSProtocolType,
			Port:     8443,
			Hostname: "tls.example.com",
			TLSMode:  &terminateMode,
			TLSBackends: map[string][]state.InternalTLSBackend{
				"tls.example.com": {
					{
						Target: backendLis.Addr().String(),
						Weight: 1,
					},
				},
			},
		},
	}, nil)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	go func() {
		for {
			c, err := sniLis.Accept()
			if err != nil {
				return
			}
			// sniLis internally handles terminateTLSToBackend
			_ = c
		}
	}()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	clientTLS := &tls.Config{
		ServerName:         "tls.example.com",
		RootCAs:            caPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
	}

	addr := rawLis.Addr().String()

	// Connection 1: full TLS handshake
	conn1, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 1 failed: %v", err)
	}
	if _, err := conn1.Write([]byte("ping1\n")); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn1.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "backend-echo: ping1") {
		t.Fatalf("read 1 failed: %v, resp: %s", err, string(buf[:n]))
	}
	if conn1.ConnectionState().DidResume {
		t.Errorf("connection 1 expected DidResume=false, got true")
	}
	conn1.Close()

	// Connection 2: resumed TLS handshake
	conn2, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial 2 failed: %v", err)
	}
	if _, err := conn2.Write([]byte("ping2\n")); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	n, err = conn2.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "backend-echo: ping2") {
		t.Fatalf("read 2 failed: %v, resp: %s", err, string(buf[:n]))
	}
	if !conn2.ConnectionState().DidResume {
		t.Errorf("connection 2 expected DidResume=true, got false")
	}
	conn2.Close()
}

func TestTLSRouteTerminate_BackendTLSPolicy_Reencrypt(t *testing.T) {
	frontendCAPEM, frontendCert := generateTestCAAndCert(t, []string{"tls.example.com"}, nil)
	backendCAPEM, backendCert := generateTestCAAndCert(t, []string{"backend.local"}, nil)

	p := NewProxy()
	p.UpdateCertificates(map[string]*tls.Certificate{
		"tls.example.com": &frontendCert,
	}, &frontendCert)

	backendTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{backendCert},
	}
	backendLis, err := tls.Listen("tcp", "127.0.0.1:0", backendTLSConfig)
	if err != nil {
		t.Fatalf("failed to listen on backend: %v", err)
	}
	defer backendLis.Close()

	go func() {
		for {
			c, err := backendLis.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write([]byte("reencrypt-echo: " + string(buf[:n])))
				}
			}(c)
		}
	}()

	terminateMode := gatewayv1.TLSModeTerminate
	p.UpdateConfig([]state.InternalListener{
		{
			Name:     "tls-terminate-listener",
			Protocol: gatewayv1.TLSProtocolType,
			Port:     8443,
			Hostname: "tls.example.com",
			TLSMode:  &terminateMode,
			TLSBackends: map[string][]state.InternalTLSBackend{
				"tls.example.com": {
					{
						Target: backendLis.Addr().String(),
						Weight: 1,
						TLSConfig: &state.InternalTLSConfig{
							Hostname: "backend.local",
							CACerts:  [][]byte{backendCAPEM},
						},
					},
				},
			},
		},
	}, nil)

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawLis.Close()

	sniLis := p.NewSNIListener(rawLis)
	defer sniLis.Close()

	go func() {
		for {
			c, err := sniLis.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(frontendCAPEM)

	clientTLS := &tls.Config{
		ServerName: "tls.example.com",
		RootCAs:    caPool,
	}

	addr := rawLis.Addr().String()

	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello reencrypt\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "reencrypt-echo: hello reencrypt") {
		t.Fatalf("read failed: %v, resp: %s", err, string(buf[:n]))
	}
}
