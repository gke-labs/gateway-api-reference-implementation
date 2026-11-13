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
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// simulatedConn wraps net.Conn to simulate round-trip latency and loss on a byte stream.
type simulatedConn struct {
	net.Conn
	delay     time.Duration
	lossRate  float64
	lastWrite time.Time
	mu        sync.Mutex
}

func newSimulatedConn(c net.Conn, delay time.Duration, lossRate float64) *simulatedConn {
	return &simulatedConn{
		Conn:     c,
		delay:    delay,
		lossRate: lossRate,
	}
}

func (c *simulatedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.lastWrite = time.Now()
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *simulatedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	lastW := c.lastWrite
	c.lastWrite = time.Time{}
	c.mu.Unlock()

	if !lastW.IsZero() && c.delay > 0 {
		// Delay the arrival of the response after a write by 2 * delay (full RTT)
		elapsed := time.Since(lastW)
		rtt := 2 * c.delay
		if elapsed < rtt {
			time.Sleep(rtt - elapsed)
		}
		// Simulate TCP packet loss retransmission penalty (RTO of ~1 RTT)
		if c.lossRate > 0 && rand.Float64() < c.lossRate {
			time.Sleep(rtt)
		}
	}

	return c.Conn.Read(b)
}

func TestSimulatedConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	// 10ms one-way delay (20ms RTT)
	sim := newSimulatedConn(raw, 10*time.Millisecond, 0)

	t0 := time.Now()
	_, err = sim.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := sim.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	elapsed := time.Since(t0)

	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}
	if elapsed < 18*time.Millisecond {
		t.Fatalf("expected RTT delay at least ~18ms, got %v", elapsed)
	}
}
