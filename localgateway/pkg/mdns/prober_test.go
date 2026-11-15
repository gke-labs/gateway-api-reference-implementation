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
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestProber_ProbeAndAnnounce(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	resp, err := NewResponder(ResponderOptions{
		Port:        port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer resp.Close()

	stateCh := make(chan HostnameState, 10)
	prober, err := NewProber(ProberOptions{
		Responder:             resp,
		TTL:                   60,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		OnStateChange: func(fqdn string, state HostnameState) {
			if strings.EqualFold(fqdn, "service.local.") {
				stateCh <- state
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create prober: %v", err)
	}
	defer func() {
		if err := prober.Shutdown(); err != nil && !isNormalClose(err) {
			t.Errorf("prober.Shutdown: %v", err)
		}
	}()

	ip := net.ParseIP("127.0.0.1")
	prober.SetNames(map[string][]net.IP{
		"service.local": {ip},
	})

	// Check immediate state
	snap, found := prober.GetHostnameState("service.local")
	if !found || snap.State != StateProbing {
		t.Fatalf("expected StateProbing immediately after SetNames, got: found=%v, state=%v", found, snap.State)
	}

	// Wait for published state
	select {
	case st := <-stateCh:
		if st != StatePublished {
			t.Fatalf("expected StatePublished, got: %v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for StatePublished")
	}

	snap, found = prober.GetHostnameState("service.local.")
	if !found || snap.State != StatePublished {
		t.Fatalf("expected StatePublished in snapshot, got: %+v", snap)
	}

	// Verify query answers
	querier := newInProcessQuerier(t, port)
	defer querier.Close()

	answers, err := querier.Query("service.local", dnsmessage.TypeA, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	aRes, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok || !net.IP(aRes.A[:]).Equal(ip) {
		t.Fatalf("unexpected answer: %+v", answers[0])
	}
}

func TestProber_AddressUpdate(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	resp, err := NewResponder(ResponderOptions{
		Port:        port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer resp.Close()

	publishedCh := make(chan struct{}, 1)
	prober, err := NewProber(ProberOptions{
		Responder:             resp,
		TTL:                   60,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		OnStateChange: func(fqdn string, state HostnameState) {
			if state == StatePublished {
				select {
				case publishedCh <- struct{}{}:
				default:
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create prober: %v", err)
	}
	defer func() {
		if err := prober.Shutdown(); err != nil && !isNormalClose(err) {
			t.Errorf("prober.Shutdown: %v", err)
		}
	}()

	prober.SetNames(map[string][]net.IP{
		"update.local": {net.ParseIP("127.0.0.1")},
	})

	select {
	case <-publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for initial publish")
	}

	// Update address to 127.0.0.2
	newIP := net.ParseIP("127.0.0.2")
	prober.SetNames(map[string][]net.IP{
		"update.local": {newIP},
	})

	querier := newInProcessQuerier(t, port)
	defer querier.Close()

	answers, err := querier.Query("update.local", dnsmessage.TypeA, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
	aRes, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok || !net.IP(aRes.A[:]).Equal(newIP) {
		t.Fatalf("expected updated IP %v, got %+v", newIP, answers[0])
	}
}

func TestProber_WithdrawSendsGoodbye(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	goodbyeCh := make(chan []byte, 10)
	resp, err := NewResponder(ResponderOptions{
		Port:        port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
		MulticastTap: func(raw []byte) {
			var parser dnsmessage.Parser
			if _, err := parser.Start(raw); err != nil {
				return
			}
			if err := parser.SkipAllQuestions(); err != nil {
				return
			}
			for {
				header, err := parser.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(header.Name.String(), "remove.local.") && header.TTL == 0 {
					goodbyeCh <- raw
				}
				if err := parser.SkipAnswer(); err != nil {
					break
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer resp.Close()

	publishedCh := make(chan struct{}, 1)
	prober, err := NewProber(ProberOptions{
		Responder:             resp,
		TTL:                   60,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		OnStateChange: func(fqdn string, state HostnameState) {
			if state == StatePublished {
				publishedCh <- struct{}{}
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create prober: %v", err)
	}
	defer func() {
		if err := prober.Shutdown(); err != nil && !isNormalClose(err) {
			t.Errorf("prober.Shutdown: %v", err)
		}
	}()

	prober.SetNames(map[string][]net.IP{
		"remove.local": {net.ParseIP("127.0.0.1")},
	})

	select {
	case <-publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for publish")
	}

	// Withdraw by setting empty map
	prober.SetNames(nil)

	select {
	case raw := <-goodbyeCh:
		var parser dnsmessage.Parser
		if _, err := parser.Start(raw); err != nil {
			t.Fatalf("parser.Start: %v", err)
		}
		if err := parser.SkipAllQuestions(); err != nil {
			t.Fatalf("parser.SkipAllQuestions: %v", err)
		}
		header, err := parser.AnswerHeader()
		if err != nil {
			t.Fatalf("parser.AnswerHeader: %v", err)
		}
		if header.TTL != 0 {
			t.Fatalf("expected TTL 0 in goodbye, got %+v", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for goodbye packet")
	}

	if _, ok := prober.GetHostnameState("remove.local"); ok {
		t.Fatalf("withdrawn name should not exist in prober")
	}
}
