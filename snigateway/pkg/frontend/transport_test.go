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
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/quic-go/quic-go"
)

func TestPoolTransport_ConcurrentWaitersBurstNoLostWakeups(t *testing.T) {
	pool := NewPoolTransport()
	defer pool.Close()

	sessA := "session-A"
	sessB := "session-B"
	pool.RegisterSession(sessA)
	pool.RegisterSession(sessB)

	const waitersPerSession = 5
	const totalWaiters = waitersPerSession * 2

	var wg sync.WaitGroup
	wg.Add(totalWaiters)

	results := make([]net.Conn, totalWaiters)
	errs := make([]error, totalWaiters)
	durations := make([]time.Duration, totalWaiters)

	startWait := make(chan struct{})

	// Start waiters for session A
	for i := 0; i < waitersPerSession; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startWait
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()

			start := time.Now()
			conn, _, err := pool.GetConnForSessions(ctx, []string{sessA})
			durations[idx] = time.Since(start)
			results[idx] = conn
			errs[idx] = err
		}()
	}

	// Start waiters for session B
	for i := 0; i < waitersPerSession; i++ {
		idx := waitersPerSession + i
		go func() {
			defer wg.Done()
			<-startWait
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()

			start := time.Now()
			conn, _, err := pool.GetConnForSessions(ctx, []string{sessB})
			durations[idx] = time.Since(start)
			results[idx] = conn
			errs[idx] = err
		}()
	}

	// Unblock all waiters to begin waiting on empty pools
	close(startWait)
	time.Sleep(20 * time.Millisecond)

	// Add mock connections in rapid burst
	var mockConns []net.Conn
	defer func() {
		for _, c := range mockConns {
			_ = c.Close()
		}
	}()

	for i := 0; i < waitersPerSession; i++ {
		c1, c2 := net.Pipe()
		mockConns = append(mockConns, c1, c2)
		if err := pool.AddConn(sessA, c1); err != nil {
			t.Fatalf("AddConn sessA failed: %v", err)
		}
	}
	for i := 0; i < waitersPerSession; i++ {
		c1, c2 := net.Pipe()
		mockConns = append(mockConns, c1, c2)
		if err := pool.AddConn(sessB, c1); err != nil {
			t.Fatalf("AddConn sessB failed: %v", err)
		}
	}

	wg.Wait()

	// Verify all waiters received their connections without waiting for per-attempt timeout
	seenConns := make(map[net.Conn]bool)
	for i := 0; i < totalWaiters; i++ {
		if errs[i] != nil {
			t.Fatalf("waiter %d failed with error: %v (took %v)", i, errs[i], durations[i])
		}
		if results[i] == nil {
			t.Fatalf("waiter %d got nil conn", i)
		}
		if seenConns[results[i]] {
			t.Fatalf("waiter %d received duplicate conn %v", i, results[i])
		}
		seenConns[results[i]] = true

		if durations[i] >= 1500*time.Millisecond {
			t.Errorf("waiter %d took %v, indicating a lost wakeup and wait for per-attempt timeout", i, durations[i])
		}
	}
}

func TestCompositeTransport_ConcurrentBurstMixedSessionsNoLostWakeups(t *testing.T) {
	pool := NewPoolTransport()
	quicTr := NewQUICTransport()
	comp := NewCompositeTransport(pool, quicTr)
	defer comp.Close()

	// Setup fake QUIC server/client
	generated, err := certs.GenerateAll("snigateway.internal", "test-client")
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}

	serverTLS, _ := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	serverTLS.NextProtos = []string{api.TunnelALPN}
	clientTLS, _ := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	clientTLS.NextProtos = []string{api.TunnelALPN}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	ql, err := quic.Listen(pc, serverTLS, api.DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic.Listen: %v", err)
	}
	defer ql.Close()

	go func() {
		for {
			conn, err := ql.Accept(t.Context())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					s, err := c.AcceptStream(t.Context())
					if err != nil {
						return
					}
					// Accept streams from frontend
					_ = s
				}
			}(conn)
		}
	}()

	qClientConn, err := quic.DialAddr(t.Context(), pc.LocalAddr().String(), clientTLS, api.DefaultQUICConfig())
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer qClientConn.CloseWithError(0, "done")

	sessPool := "sess-pool"
	sessQUIC := "sess-quic"

	pool.RegisterSession(sessPool)
	quicTr.RegisterSession(sessQUIC, qClientConn)

	const waitersCount = 10
	var wg sync.WaitGroup
	wg.Add(waitersCount)

	results := make([]net.Conn, waitersCount)
	errs := make([]error, waitersCount)
	durations := make([]time.Duration, waitersCount)
	assignedSessions := make([]string, waitersCount)

	startWait := make(chan struct{})

	for i := 0; i < waitersCount; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startWait
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()

			start := time.Now()
			conn, sid, err := comp.GetConnForSessions(ctx, []string{sessPool, sessQUIC})
			durations[idx] = time.Since(start)
			results[idx] = conn
			assignedSessions[idx] = sid
			errs[idx] = err
		}()
	}

	close(startWait)
	time.Sleep(20 * time.Millisecond)

	// Add 5 pooled TCP connections for sessPool
	var mockConns []net.Conn
	defer func() {
		for _, c := range mockConns {
			_ = c.Close()
		}
	}()

	for i := 0; i < 5; i++ {
		c1, c2 := net.Pipe()
		mockConns = append(mockConns, c1, c2)
		if err := pool.AddConn(sessPool, c1); err != nil {
			t.Fatalf("AddConn failed: %v", err)
		}
	}

	wg.Wait()

	for i := 0; i < waitersCount; i++ {
		if errs[i] != nil {
			t.Fatalf("waiter %d failed: %v", i, errs[i])
		}
		if results[i] == nil {
			t.Fatalf("waiter %d got nil conn", i)
		}
		if durations[i] >= 1500*time.Millisecond {
			t.Errorf("waiter %d took %v, indicating lost wakeup", i, durations[i])
		}
	}
}
