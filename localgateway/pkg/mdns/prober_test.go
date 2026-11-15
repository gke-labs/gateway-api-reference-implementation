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

func TestResponder_PreviousAddressAnnouncementNotConflict(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	responder, err := NewResponder(ResponderOptions{
		Port:        port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer responder.Close()

	conflictCh := make(chan dnsmessage.Resource, 2)
	responder.SetConflictHandler(func(fqdn string, conflictingRR dnsmessage.Resource) {
		conflictCh <- conflictingRR
	})

	// 1. Initial publish: 192.168.1.100
	responder.SetRecord(&RecordSet{
		FQDN: "example.local.",
		A:    []net.IP{net.ParseIP("192.168.1.100")},
		TTL:  60,
	})

	// 2. Update address: 192.168.1.200
	responder.SetRecord(&RecordSet{
		FQDN: "example.local.",
		A:    []net.IP{net.ParseIP("192.168.1.200")},
		TTL:  60,
	})

	sender, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to create sender socket: %v", err)
	}
	defer sender.Close()
	destination := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

	buildResponsePacket := func(ip [4]byte) []byte {
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		})
		builder.EnableCompression()
		if err := builder.StartAnswers(); err != nil {
			t.Fatalf("builder.StartAnswers: %v", err)
		}
		if err := builder.AResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("example.local."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
				TTL:   60,
			},
			dnsmessage.AResource{A: ip},
		); err != nil {
			t.Fatalf("builder.AResource: %v", err)
		}
		data, err := builder.Finish()
		if err != nil {
			t.Fatalf("builder.Finish: %v", err)
		}
		return data
	}

	// 3. Send the old-address packet (192.168.1.100), then a foreign conflicting address (192.168.1.50).
	// Under RFC 6762 section 9, the old address announcement must not be treated as a conflict.
	oldData := buildResponsePacket([4]byte{192, 168, 1, 100})
	if _, err := sender.WriteTo(oldData, destination); err != nil {
		t.Fatalf("failed to send old announcement packet: %v", err)
	}

	foreignData := buildResponsePacket([4]byte{192, 168, 1, 50})
	if _, err := sender.WriteTo(foreignData, destination); err != nil {
		t.Fatalf("failed to send foreign conflict packet: %v", err)
	}

	// 4. Assert that the one conflict reported carries the foreign address without waiting on silence.
	select {
	case conflictingRR := <-conflictCh:
		aResource, ok := conflictingRR.Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("expected AResource in conflict, got %+v", conflictingRR.Body)
		}
		expectedForeignIP := [4]byte{192, 168, 1, 50}
		if aResource.A != expectedForeignIP {
			t.Fatalf("expected conflict for foreign IP %v, got %v", expectedForeignIP, aResource.A)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("expected conflict to be detected for foreign address, but none reported")
	}

	select {
	case extra := <-conflictCh:
		t.Fatalf("unexpected additional conflict reported: %+v", extra)
	default:
	}
}

func TestResponder_MultipleAddressUpdatesWithinGracePeriodNotConflict(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	responder, err := NewResponder(ResponderOptions{
		Port:        port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer responder.Close()

	conflictCh := make(chan dnsmessage.Resource, 2)
	responder.SetConflictHandler(func(fqdn string, conflictingRR dnsmessage.Resource) {
		conflictCh <- conflictingRR
	})

	// 1. Initial publish: 192.168.1.100 (address A)
	responder.SetRecord(&RecordSet{
		FQDN: "example.local.",
		A:    []net.IP{net.ParseIP("192.168.1.100")},
		TTL:  60,
	})

	// 2. First update: 192.168.1.200 (address B)
	responder.SetRecord(&RecordSet{
		FQDN: "example.local.",
		A:    []net.IP{net.ParseIP("192.168.1.200")},
		TTL:  60,
	})

	// 3. Second update: 192.168.1.201 (address C)
	responder.SetRecord(&RecordSet{
		FQDN: "example.local.",
		A:    []net.IP{net.ParseIP("192.168.1.201")},
		TTL:  60,
	})

	sender, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to create sender socket: %v", err)
	}
	defer sender.Close()
	destination := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

	buildResponsePacket := func(address [4]byte) []byte {
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		})
		builder.EnableCompression()
		if err := builder.StartAnswers(); err != nil {
			t.Fatalf("builder.StartAnswers: %v", err)
		}
		if err := builder.AResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("example.local."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
				TTL:   60,
			},
			dnsmessage.AResource{A: address},
		); err != nil {
			t.Fatalf("builder.AResource: %v", err)
		}
		data, err := builder.Finish()
		if err != nil {
			t.Fatalf("builder.Finish: %v", err)
		}
		return data
	}

	// 4. Send late announcement of the first address (192.168.1.100), then a foreign address (192.168.1.50).
	// Under RFC 6762 section 9, recent own announcements from prior updates within the grace period
	// must not be treated as conflicts, while an address never announced still must be.
	firstAddressData := buildResponsePacket([4]byte{192, 168, 1, 100})
	if _, err := sender.WriteTo(firstAddressData, destination); err != nil {
		t.Fatalf("failed to send first address announcement packet: %v", err)
	}

	foreignData := buildResponsePacket([4]byte{192, 168, 1, 50})
	if _, err := sender.WriteTo(foreignData, destination); err != nil {
		t.Fatalf("failed to send foreign conflict packet: %v", err)
	}

	// 5. Assert that the one conflict reported carries the foreign address without waiting on silence.
	select {
	case conflictingRR := <-conflictCh:
		resource, ok := conflictingRR.Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("expected AResource in conflict, got %+v", conflictingRR.Body)
		}
		expectedForeignAddress := [4]byte{192, 168, 1, 50}
		if resource.A != expectedForeignAddress {
			t.Fatalf("expected conflict for foreign address %v, got %v", expectedForeignAddress, resource.A)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("expected conflict to be detected for foreign address, but none reported")
	}

	select {
	case extra := <-conflictCh:
		t.Fatalf("unexpected additional conflict reported: %+v", extra)
	default:
	}
}

func TestResponder_RecentAnnouncementsPruningAndBounding(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()

	responder, err := NewResponder(ResponderOptions{
		Port:        rawConn.LocalAddr().(*net.UDPAddr).Port,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer responder.Close()

	// Initial publish
	responder.SetRecord(&RecordSet{
		FQDN: "bound.local.",
		A:    []net.IP{net.IPv4(10, 0, 0, 1)},
		TTL:  60,
	})

	// Perform 10 address updates
	for index := 2; index <= 11; index++ {
		responder.SetRecord(&RecordSet{
			FQDN: "bound.local.",
			A:    []net.IP{net.IPv4(10, 0, 0, byte(index))},
			TTL:  60,
		})
	}

	responder.mu.RLock()
	rec := responder.records["bound.local."]
	recentCount := len(rec.recentAnnouncements)
	responder.mu.RUnlock()

	if recentCount > maxRecentAnnouncements {
		t.Fatalf("expected at most %d recent announcements, got %d", maxRecentAnnouncements, recentCount)
	}

	// Test expiry directly on the published record set: an entry younger than the
	// grace period matches, and the same entry one grace period later does not.
	recentResource := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("bound.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 10}},
	}
	now := time.Now()
	if !rec.announcedRecently(recentResource, now) {
		t.Fatalf("expected recent announcement to match within grace period")
	}
	if rec.announcedRecently(recentResource, now.Add(PreviousAddressGracePeriod+time.Second)) {
		t.Fatalf("expected recent announcement to expire after grace period")
	}
}

func TestProber_RepeatAnnouncementUsesUpdatedRecords(t *testing.T) {
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	port := rawConn.LocalAddr().(*net.UDPAddr).Port

	announcementsCh := make(chan net.IP, 10)
	responder, err := NewResponder(ResponderOptions{
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
				ans, err := parser.Answer()
				if err != nil {
					break
				}
				if strings.EqualFold(ans.Header.Name.String(), "repeat.local.") && ans.Header.TTL > 0 {
					if a, ok := ans.Body.(*dnsmessage.AResource); ok {
						announcementsCh <- net.IP(a.A[:])
					}
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}
	defer responder.Close()

	publishedCh := make(chan struct{}, 1)
	prober, err := NewProber(ProberOptions{
		Responder:        responder,
		TTL:              60,
		ProbeInterval:    20 * time.Millisecond,
		ProbeCount:       2,
		AnnounceInterval: 80 * time.Millisecond,
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

	initialIP := net.ParseIP("127.0.0.1")
	prober.SetNames(map[string][]net.IP{
		"repeat.local": {initialIP},
	})

	select {
	case <-publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for initial publish")
	}

	// Drain initial announcement
	select {
	case ip := <-announcementsCh:
		if !ip.Equal(initialIP) {
			t.Fatalf("expected initial announcement %v, got %v", initialIP, ip)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for initial announcement")
	}

	// Update address before repeat announcement fires
	newIP := net.ParseIP("127.0.0.2")
	prober.SetNames(map[string][]net.IP{
		"repeat.local": {newIP},
	})

	// Address update triggers an announcement for newIP
	select {
	case ip := <-announcementsCh:
		if !ip.Equal(newIP) {
			t.Fatalf("expected re-announcement %v, got %v", newIP, ip)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for update announcement")
	}

	// Wait for the repeat announcement timer to fire (AnnounceInterval = 80ms)
	select {
	case ip := <-announcementsCh:
		if !ip.Equal(newIP) {
			t.Fatalf("expected repeat announcement to use updated IP %v, got stale IP %v", newIP, ip)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for repeat announcement")
	}
}
