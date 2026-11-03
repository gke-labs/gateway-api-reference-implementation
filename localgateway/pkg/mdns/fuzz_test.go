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

package mdns

import (
	"math/rand"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func newFuzzResponder(t testing.TB) *Responder {
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind test socket: %v", err)
	}

	r, err := NewResponder(ResponderOptions{
		Port:        c.LocalAddr().(*net.UDPAddr).Port,
		IPv4Conn:    c,
		DisableIPv6: true,
	})
	if err != nil {
		_ = c.Close()
		t.Fatalf("failed to create fuzz responder: %v", err)
	}

	r.SetRecord(&RecordSet{
		FQDN: "fuzz.local.",
		A:    []net.IP{net.ParseIP("192.168.1.1").To4()},
		AAAA: []net.IP{net.ParseIP("fd00::1")},
		TTL:  120,
	})

	name, _ := dnsmessage.NewName("probe.local.")
	r.RegisterProbe("probe.local.", []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
				TTL:   120,
			},
			Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 10}},
		},
	})

	return r
}

func FuzzPacketHandler(f *testing.F) {
	// Seed corpus 1: Empty
	f.Add([]byte{})

	// Seed corpus 2: Short/truncated
	f.Add([]byte{0x00, 0x01})

	// Seed corpus 3: Valid query
	bQ := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	bQ.EnableCompression()
	_ = bQ.StartQuestions()
	_ = bQ.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("fuzz.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	qBytes, _ := bQ.Finish()
	f.Add(qBytes)

	// Seed corpus 4: Query with QU bit
	bQU := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1234})
	bQU.EnableCompression()
	_ = bQU.StartQuestions()
	_ = bQU.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("fuzz.local."),
		Type:  dnsmessage.TypeALL,
		Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
	})
	quBytes, _ := bQU.Finish()
	f.Add(quBytes)

	// Seed corpus 5: Valid response
	bR := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	bR.EnableCompression()
	_ = bR.StartAnswers()
	_ = bR.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("fuzz.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
	)
	rBytes, _ := bR.Finish()
	f.Add(rBytes)

	// Seed corpus 6: Probe query with authority
	bP := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	bP.EnableCompression()
	_ = bP.StartQuestions()
	_ = bP.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("probe.local."),
		Type:  dnsmessage.TypeALL,
		Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
	})
	_ = bP.StartAuthorities()
	_ = bP.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("probe.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{192, 168, 1, 99}},
	)
	pBytes, _ := bP.Finish()
	f.Add(pBytes)

	// Seed corpus 7: Goodbye response
	bG := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	bG.EnableCompression()
	_ = bG.StartAnswers()
	_ = bG.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("fuzz.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   0,
		},
		dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
	)
	gBytes, _ := bG.Finish()
	f.Add(gBytes)

	// Seed corpus 8: Query with corrupted additional section
	bA := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	bA.EnableCompression()
	_ = bA.StartQuestions()
	_ = bA.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("fuzz.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	corruptBytes, _ := bA.Finish()
	// Set ARCOUNT = 1 in DNS header (bytes 10-11) and append incomplete additional record bytes
	corruptBytes[10] = 0
	corruptBytes[11] = 1
	corruptBytes = append(corruptBytes, 0x03, 'b', 'a', 'd')
	f.Add(corruptBytes)

	resp := newFuzzResponder(f)
	defer resp.Close()

	fromLocal := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: resp.Port()}
	fromLegacy := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	f.Fuzz(func(t *testing.T, data []byte) {
		resp.handlePacket(data, fromLocal, false)
		resp.handlePacket(data, fromLegacy, false)
		resp.handlePacket(data, fromLocal, true)
	})
}

// TestPacketHandler_RandomBytes runs 10,000 arbitrary pseudo-random byte slices through
// handlePacket as part of regular testing (without needing `go test -fuzz`) to ensure
// resilience against crashes or panics.
func TestPacketHandler_RandomBytes(t *testing.T) {
	resp := newFuzzResponder(t)
	defer resp.Close()

	fromLocal := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: resp.Port()}
	fromLegacy := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 10000; i++ {
		length := rng.Intn(1024)
		buf := make([]byte, length)
		rng.Read(buf)

		resp.handlePacket(buf, fromLocal, false)
		resp.handlePacket(buf, fromLegacy, false)
	}
}

// TestPacketHandler_MalformedAdditionalsDropped verifies that packets containing malformed
// additional records are dropped rather than partially processed.
func TestPacketHandler_MalformedAdditionalsDropped(t *testing.T) {
	resp := newFuzzResponder(t)
	defer resp.Close()

	var tapCalled bool
	resp.multicastTap = func(raw []byte) {
		tapCalled = true
	}

	var conflictCalled bool
	resp.SetConflictHandler(func(fqdn string, conflictingRR dnsmessage.Resource) {
		conflictCalled = true
	})

	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: resp.Port()}

	// 1. Query with corrupt additional section should be dropped without replying
	bQ := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	bQ.EnableCompression()
	_ = bQ.StartQuestions()
	_ = bQ.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("fuzz.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	qBytes, _ := bQ.Finish()
	qBytes[10] = 0
	qBytes[11] = 1
	qBytes = append(qBytes, 0x03, 'b', 'a', 'd')

	resp.handlePacket(qBytes, from, false)
	if tapCalled {
		t.Fatalf("expected query with corrupt additionals to be dropped, but response was sent")
	}

	// 2. Response with corrupt additional section should be dropped without raising conflict
	bR := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	bR.EnableCompression()
	_ = bR.StartAnswers()
	_ = bR.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("fuzz.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{10, 0, 0, 99}},
	)
	rBytes, _ := bR.Finish()
	rBytes[10] = 0
	rBytes[11] = 1
	rBytes = append(rBytes, 0x03, 'b', 'a', 'd')

	resp.handlePacket(rBytes, from, false)
	if conflictCalled {
		t.Fatalf("expected response with corrupt additionals to be dropped, but conflict was raised")
	}
}
