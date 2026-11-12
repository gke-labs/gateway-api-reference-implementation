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
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
)

type leakTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newLeakTestClock() *leakTestClock {
	return &leakTestClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *leakTestClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *leakTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func setupTestServerForLeakTests(t *testing.T, clk *leakTestClock) (*Server, string, *certs.GeneratedCerts, func()) {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "test-cluster-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	pc, err := net.ListenPacket("udp", serverAddr)
	if err != nil {
		ln.Close()
		t.Fatalf("ListenPacket failed: %v", err)
	}

	cfg := ServerConfig{
		ServerTLSConfig:     serverTLS,
		InternalHostname:    "snigateway.internal",
		ConnectTimeout:      5 * time.Second,
		PerAttemptTimeout:   500 * time.Millisecond,
		ReadSNITimeout:      2 * time.Second,
		LeaseReaperInterval: 25 * time.Millisecond,
	}
	if clk != nil {
		cfg.TimeNow = clk.Now
	}

	srv, err := NewServer(cfg)
	if err != nil {
		ln.Close()
		pc.Close()
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		_ = srv.ServeAll([]net.Listener{ln}, []net.PacketConn{pc})
	}()

	cleanup := func() {
		_ = srv.Close()
	}

	return srv, serverAddr, generated, cleanup
}

// sessionCount returns the number of active session records in Server.sessions.
// Intended for tests to verify that no per-session entries leak.
func sessionCount(s *Server) int {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return len(s.sessions)
}

func waitForEmptySessionMaps(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sessionCount(srv) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	count := sessionCount(srv)
	t.Fatalf("session map not empty after deadline: count=%d", count)
}

func TestSessionTeardown_MapCleanup_NormalEnd(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerForLeakTests(t, nil)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	c := client.NewClient(serverAddr, clientTLS)

	const nSessions = 5

	t.Run("HTTP session", func(t *testing.T) {
		for i := 0; i < nSessions; i++ {
			sessCtx, cancel := context.WithCancel(t.Context())
			sessID, errCh, err := c.StartSession(sessCtx)
			if err != nil {
				cancel()
				t.Fatalf("session %d: StartSession failed: %v", i, err)
			}
			if sessID == "" {
				cancel()
				t.Fatalf("session %d: empty sessionID", i)
			}
			cancel()
			select {
			case <-errCh:
			case <-time.After(3 * time.Second):
				t.Fatalf("session %d: timed out waiting for session to end", i)
			}
		}
		waitForEmptySessionMaps(t, srv)
	})

	t.Run("QUIC session", func(t *testing.T) {
		for i := 0; i < nSessions; i++ {
			sessCtx, cancel := context.WithCancel(t.Context())
			qConn, err := c.DialQUIC(sessCtx)
			if err != nil {
				cancel()
				t.Fatalf("session %d: DialQUIC failed: %v", i, err)
			}
			ctrlStream, err := qConn.OpenStreamSync(sessCtx)
			if err != nil {
				_ = qConn.CloseWithError(0, "error")
				cancel()
				t.Fatalf("session %d: OpenStreamSync failed: %v", i, err)
			}
			if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
				_ = qConn.CloseWithError(0, "error")
				cancel()
				t.Fatalf("session %d: writing handshake failed: %v", i, err)
			}
			reader := bufio.NewReader(ctrlStream)
			line, err := reader.ReadBytes('\n')
			if err != nil {
				_ = qConn.CloseWithError(0, "error")
				cancel()
				t.Fatalf("session %d: reading SessionResponse failed: %v", i, err)
			}
			var sessResp api.SessionResponse
			if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
				_ = qConn.CloseWithError(0, "error")
				cancel()
				t.Fatalf("session %d: unmarshal SessionResponse failed: %v", i, err)
			}
			_ = ctrlStream.Close()
			_ = qConn.CloseWithError(0, "test done")
			cancel()
		}
		waitForEmptySessionMaps(t, srv)
	})
}

func TestSessionTeardown_LeaseReaperAndHandler(t *testing.T) {
	clk := newLeakTestClock()
	srv, serverAddr, generated, cleanup := setupTestServerForLeakTests(t, clk)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	c := client.NewClient(serverAddr, clientTLS)

	t.Run("HTTP session closed by lease reaper then handler teardown", func(t *testing.T) {
		sessCtx, cancel := context.WithCancel(t.Context())
		defer cancel()

		sessID, errCh, err := c.StartSession(sessCtx)
		if err != nil {
			t.Fatalf("StartSession failed: %v", err)
		}

		// Register a hostname with a lease expiring in 50ms from current mock clock
		leaseExp := clk.Now().Add(50 * time.Millisecond)
		srv.RegistrationTable().RegisterWithLease(sessID, []string{"reaper-http.example.com"}, leaseExp)

		// Verify registration exists initially
		if _, ok := srv.RegistrationTable().Match("reaper-http.example.com"); !ok {
			t.Fatal("expected hostname to be registered initially")
		}

		// Advance mock clock past lease expiration to trigger reaper
		clk.Advance(1 * time.Second)

		// The lease reaper will call CloseSession, which cancels the session context.
		// The handler will then unblock and run its deferred CloseSession.
		// We verify it finishes without panic or double-release.
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for session to close after lease expiration")
		}

		// Maps must be clean
		waitForEmptySessionMaps(t, srv)

		// Registration must be removed
		if _, ok := srv.RegistrationTable().Match("reaper-http.example.com"); ok {
			t.Fatal("expected hostname to be dropped from registration table")
		}
	})

	t.Run("QUIC session closed by lease reaper then handler teardown", func(t *testing.T) {
		sessCtx, cancel := context.WithCancel(t.Context())
		defer cancel()

		qConn, err := c.DialQUIC(sessCtx)
		if err != nil {
			t.Fatalf("DialQUIC failed: %v", err)
		}
		defer qConn.CloseWithError(0, "test done")

		ctrlStream, err := qConn.OpenStreamSync(sessCtx)
		if err != nil {
			t.Fatalf("OpenStreamSync failed: %v", err)
		}
		defer ctrlStream.Close()

		if _, err := ctrlStream.Write([]byte("{\"type\":\"session\"}\n")); err != nil {
			t.Fatalf("writing handshake failed: %v", err)
		}

		reader := bufio.NewReader(ctrlStream)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("reading SessionResponse failed: %v", err)
		}

		var sessResp api.SessionResponse
		if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
			t.Fatalf("unmarshal SessionResponse failed: %v", err)
		}
		sessID := sessResp.SessionID
		if sessID == "" {
			t.Fatal("empty sessionID")
		}

		// Register a hostname with a lease expiring in 50ms from mock clock
		leaseExp := clk.Now().Add(50 * time.Millisecond)
		srv.RegistrationTable().RegisterWithLease(sessID, []string{"reaper-quic.example.com"}, leaseExp)

		// Advance mock clock past lease expiration to trigger reaper
		clk.Advance(1 * time.Second)

		// The lease reaper calls CloseSession, which closes the QUIC connection.
		// The QUIC connection will be closed.
		select {
		case <-qConn.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for QUIC connection to close after lease expiration")
		}

		// Maps must be clean
		waitForEmptySessionMaps(t, srv)

		// Registration must be removed
		if _, ok := srv.RegistrationTable().Match("reaper-quic.example.com"); ok {
			t.Fatal("expected hostname to be dropped from registration table")
		}
	})
}

func TestSessionTeardown_IdempotentCloseSession(t *testing.T) {
	srv, serverAddr, generated, cleanup := setupTestServerForLeakTests(t, nil)
	defer cleanup()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}
	c := client.NewClient(serverAddr, clientTLS)

	sessCtx, cancel := context.WithCancel(t.Context())
	defer cancel()

	sessID, errCh, err := c.StartSession(sessCtx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	// Repeated sequential calls to CloseSession
	for i := 0; i < 5; i++ {
		srv.CloseSession(sessID)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}

	// Repeated concurrent calls to CloseSession
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.CloseSession(sessID)
		}()
	}
	wg.Wait()

	waitForEmptySessionMaps(t, srv)
}
