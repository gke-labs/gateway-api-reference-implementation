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
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

var ipAddrType = gatewayv1.IPAddressType

func getOccupiedPort(t *testing.T) (int, net.PacketConn) {
	t.Helper()
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind test socket: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	return port, c
}

// inProcessQuerier is an mDNS client for testing on loopback.
type inProcessQuerier struct {
	port int
	conn net.PacketConn
}

func newInProcessQuerier(t *testing.T, port int) *inProcessQuerier {
	t.Helper()
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to create in-process querier: %v", err)
	}
	return &inProcessQuerier{port: port, conn: c}
}

func (q *inProcessQuerier) Close() {
	_ = q.conn.Close()
}

func (q *inProcessQuerier) Query(name string, qtype dnsmessage.Type, timeout time.Duration) ([]dnsmessage.Resource, error) {
	return q.QueryWithAnswers(name, qtype, nil, timeout)
}

func (q *inProcessQuerier) QueryWithAnswers(name string, qtype dnsmessage.Type, knownAnswers []dnsmessage.Resource, timeout time.Duration) ([]dnsmessage.Resource, error) {
	qname, err := dnsmessage.NewName(toFQDN(name))
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  qname,
		Type:  qtype,
		Class: dnsmessage.ClassINET, // legacy query from ephemeral port
	}); err != nil {
		return nil, err
	}

	if len(knownAnswers) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		for _, ans := range knownAnswers {
			if err := appendResource(&b, ans); err != nil {
				return nil, err
			}
		}
	}

	data, err := b.Finish()
	if err != nil {
		return nil, err
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: q.port}
	if _, err := q.conn.WriteTo(data, dst); err != nil {
		return nil, err
	}

	_ = q.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, _, err := q.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var answers []dnsmessage.Resource
	for {
		ans, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		answers = append(answers, ans)
	}
	return answers, nil
}

// TestPortAlreadyTakenFailsStartup occupies a random ephemeral port first and verifies that
// starting a responder on that port fails clearly without ever binding port 5353.
func TestPortAlreadyTakenFailsStartup(t *testing.T) {
	port, blocker := getOccupiedPort(t)
	defer blocker.Close()

	_, err := NewResponder(ResponderOptions{Port: port})
	if err == nil {
		t.Fatalf("expected NewResponder to fail on occupied port %d, but succeeded", port)
	}

	expectedSub := "is already in use (host avahi-daemon must be stopped or bound elsewhere)"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Fatalf("expected error containing %q, got: %v", expectedSub, err)
	}
}

// TestMDNSPublishAndResolveLoopback tests publishing driven by OnGatewaysUpdate on an ephemeral port
// and querying with in-process querier, asserting legacy unicast formatting (TTL<=10, no cache-flush bit).
func TestMDNSPublishAndResolveLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	reconcileCh := make(chan types.NamespacedName, 10)

	// Injected PacketConn on an ephemeral port (:0) - never touches real port 5353
	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		EnqueueGateway: func(req types.NamespacedName) {
			reconcileCh <- req
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	querier := newInProcessQuerier(t, ephemeralPort)
	defer querier.Close()

	hName := gatewayv1.Hostname("grafana.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  gwKey.Namespace,
			Name:       gwKey.Name,
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hName,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{
				{Type: &ipAddrType, Value: "127.0.0.1"},
				{Type: &ipAddrType, Value: "::1"},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionProgrammed),
							Status: metav1.ConditionTrue,
							Reason: string(gatewayv1.ListenerReasonProgrammed),
						},
					},
				},
			},
		},
	}

	// 1. Data plane push (OnGatewaysUpdate) drives publishing
	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

	// 2. StatusHook reads current publisher state (initially Probing)
	statusCopy := gw.Status.DeepCopy()
	if err := pub.StatusHook(ctx, gw, statusCopy); err != nil {
		t.Fatalf("StatusHook failed: %v", err)
	}
	cond := state.FindCondition(statusCopy.Listeners[0].Conditions, string(ConditionTypePublished))
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(ConditionReasonProbing) {
		t.Fatalf("expected Probing condition, got %+v", cond)
	}

	// 3. Wait for probing to complete and EnqueueGateway to be called
	select {
	case req := <-reconcileCh:
		if req != gwKey {
			t.Fatalf("unexpected reconcile key: %v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for probe completion")
	}

	// 4. Re-evaluating status after probe completion reports Published=True
	if err := pub.StatusHook(ctx, gw, statusCopy); err != nil {
		t.Fatalf("StatusHook failed: %v", err)
	}
	cond = state.FindCondition(statusCopy.Listeners[0].Conditions, string(ConditionTypePublished))
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(ConditionReasonPublished) {
		t.Fatalf("expected Published=True, got %+v", cond)
	}

	// 5. In-process querier sends legacy unicast query (source port != responder.port):
	// Assert RFC 6762 §6.7: TTL must be <= 10s and cache-flush bit must NOT be set!
	answersA, err := querier.Query("grafana.local", dnsmessage.TypeA, 1*time.Second)
	if err != nil {
		t.Fatalf("query A failed: %v", err)
	}
	if len(answersA) == 0 {
		t.Fatalf("expected A record, got none")
	}
	recA, ok := answersA[0].Body.(*dnsmessage.AResource)
	if !ok || net.IP(recA.A[:]).String() != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %v", answersA[0])
	}
	if uint16(answersA[0].Header.Class)&CacheFlushBit != 0 {
		t.Fatalf("RFC 6762 §6.7 violation: legacy unicast response must NOT set cache-flush bit, got class %d", answersA[0].Header.Class)
	}
	if answersA[0].Header.TTL > LegacyUnicastMaxTTL {
		t.Fatalf("RFC 6762 §6.7 violation: legacy unicast TTL must be <= %d, got %d", LegacyUnicastMaxTTL, answersA[0].Header.TTL)
	}

	answersAAAA, err := querier.Query("grafana.local", dnsmessage.TypeAAAA, 1*time.Second)
	if err != nil {
		t.Fatalf("query AAAA failed: %v", err)
	}
	if len(answersAAAA) == 0 {
		t.Fatalf("expected AAAA record, got none")
	}
	recAAAA, ok := answersAAAA[0].Body.(*dnsmessage.AAAAResource)
	if !ok || !net.IP(recAAAA.AAAA[:]).Equal(net.ParseIP("::1")) {
		t.Fatalf("expected ::1, got %v", answersAAAA[0])
	}
	if uint16(answersAAAA[0].Header.Class)&CacheFlushBit != 0 {
		t.Fatalf("RFC 6762 §6.7 violation: legacy unicast response must NOT set cache-flush bit, got class %d", answersAAAA[0].Header.Class)
	}
}

// TestMDNSRateLimitAndKnownAnswerSuppression tests multicast response rate limiting (RFC 6762 §6.2)
// and known-answer suppression (§7.1).
func TestMDNSRateLimitAndKnownAnswerSuppression(t *testing.T) {
	resp, err := NewResponder(ResponderOptions{
		Ephemeral:   true,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}
	defer resp.Close()

	resp.SetRecord(&RecordSet{
		FQDN: "grafana.local.",
		A:    []net.IP{net.ParseIP("192.168.1.100").To4()},
		TTL:  120,
	})

	var tapMu sync.Mutex
	var tappedMsgs [][]byte
	resp.multicastTap = func(raw []byte) {
		tapMu.Lock()
		defer tapMu.Unlock()
		tappedMsgs = append(tappedMsgs, raw)
	}

	// 1. Simulate standard multicast query (QU bit not set, port=responder.port)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("grafana.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	qData, err := b.Finish()
	if err != nil {
		t.Fatalf("building query: %v", err)
	}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: resp.Port()}

	resp.handlePacket(qData, from, false)

	tapMu.Lock()
	count1 := len(tappedMsgs)
	tapMu.Unlock()
	if count1 != 1 {
		t.Fatalf("expected 1 multicast response, got %d", count1)
	}

	// 2. Immediate second query within 1s MUST be suppressed per RFC 6762 §6.2
	resp.handlePacket(qData, from, false)

	tapMu.Lock()
	count2 := len(tappedMsgs)
	tapMu.Unlock()
	if count2 != 1 {
		t.Fatalf("RFC 6762 §6.2 violation: second response within 1s was not rate-limited (got %d)", count2)
	}

	// 3. Known-answer suppression (RFC 6762 §7.1): query containing answer with fresh TTL (100s >= 60s)
	bKnown := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	bKnown.EnableCompression()
	_ = bKnown.StartQuestions()
	_ = bKnown.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("grafana.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	_ = bKnown.StartAnswers()
	_ = bKnown.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("grafana.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   100, // >= 120/2
		},
		dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
	)
	qKnownData, err := bKnown.Finish()
	if err != nil {
		t.Fatalf("building query with known answer: %v", err)
	}

	// Reset rate-limit timer by advancing
	resp.mu.Lock()
	delete(resp.lastMulticast, "grafana.local./1")
	resp.mu.Unlock()

	resp.handlePacket(qKnownData, from, false)

	tapMu.Lock()
	count3 := len(tappedMsgs)
	tapMu.Unlock()
	if count3 != 1 {
		t.Fatalf("RFC 6762 §7.1 violation: known answer with fresh TTL was not suppressed (got %d responses)", count3)
	}
}

// TestMDNSMulticastAndLegacyUnicastResponse verifies that multicast responses set ID 0
// and omit questions, while legacy unicast responses echo the query ID and question.
func TestMDNSMulticastAndLegacyUnicastResponse(t *testing.T) {
	resp, err := NewResponder(ResponderOptions{
		Ephemeral:   true,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}
	t.Cleanup(func() {
		if err := resp.Close(); err != nil {
			t.Errorf("resp.Close failed: %v", err)
		}
	})

	resp.SetRecord(&RecordSet{
		FQDN: "grafana.local.",
		A:    []net.IP{net.ParseIP("192.168.1.100").To4()},
		TTL:  120,
	})

	const queryID = 0x4321
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: queryID})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("starting questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("grafana.local."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("adding question: %v", err)
	}
	qData, err := b.Finish()
	if err != nil {
		t.Fatalf("building query: %v", err)
	}

	t.Run("Multicast", func(t *testing.T) {
		var multicastData []byte
		resp.multicastTap = func(raw []byte) { multicastData = raw }
		resp.handlePacket(qData, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: resp.Port()}, false)

		if len(multicastData) == 0 {
			t.Fatalf("expected multicast response, got none")
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(multicastData)
		if err != nil {
			t.Fatalf("parsing response: %v", err)
		}
		if hdr.ID != 0 {
			t.Errorf("multicast response ID must be 0, got %d", hdr.ID)
		}
		if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
			t.Errorf("multicast response must omit questions, got err %v", err)
		}
	})

	t.Run("LegacyUnicast", func(t *testing.T) {
		legacyConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create legacy listener: %v", err)
		}
		t.Cleanup(func() {
			if err := legacyConn.Close(); err != nil {
				t.Errorf("legacyConn.Close failed: %v", err)
			}
		})

		resp.handlePacket(qData, legacyConn.LocalAddr(), false)

		buf := make([]byte, 1024)
		if err := legacyConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("setting read deadline: %v", err)
		}
		n, _, err := legacyConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("reading legacy unicast response: %v", err)
		}

		var p dnsmessage.Parser
		hdr, err := p.Start(buf[:n])
		if err != nil {
			t.Fatalf("parsing response: %v", err)
		}
		if hdr.ID != queryID {
			t.Errorf("legacy unicast response ID must match query ID %d, got %d", queryID, hdr.ID)
		}
		q, err := p.Question()
		if err != nil {
			t.Fatalf("reading question: %v", err)
		}
		if q.Name.String() != "grafana.local." || q.Type != dnsmessage.TypeA {
			t.Errorf("expected echoed question grafana.local. TypeA, got %v", q)
		}
	})
}

// TestMDNSRemoveSendsGoodbye verifies that removing a published name sends a goodbye record (TTL=0).
func TestMDNSRemoveSendsGoodbye(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	reconcileCh := make(chan types.NamespacedName, 10)
	goodbyeCh := make(chan []byte, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var p dnsmessage.Parser
			if _, err := p.Start(raw); err != nil {
				return
			}
			if err := p.SkipAllQuestions(); err != nil {
				return
			}
			for {
				h, err := p.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(h.Name.String(), "app.local.") && h.TTL == 0 {
					goodbyeCh <- raw
				}
				if err := p.SkipAnswer(); err != nil {
					break
				}
			}
		},
		EnqueueGateway: func(req types.NamespacedName) {
			reconcileCh <- req
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	hName := gatewayv1.Hostname("app.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name, Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "127.0.0.1"}},
		},
	}

	// Add via data plane
	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

	select {
	case <-reconcileCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for probe completion")
	}

	// Remove listener via data plane
	gwRemoved := gw.DeepCopy()
	gwRemoved.Spec.Listeners = nil
	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gwRemoved})

	select {
	case raw := <-goodbyeCh:
		var p dnsmessage.Parser
		_, _ = p.Start(raw)
		_ = p.SkipAllQuestions()
		h, err := p.AnswerHeader()
		if err != nil || h.TTL != 0 {
			t.Fatalf("expected TTL 0 in goodbye answer, got %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected goodbye packet with TTL=0 for app.local, but none was observed")
	}
}

// TestMDNSConflictStopsClaim verifies that a conflicting responder during probing stops the claim and sets conflict conditions.
func TestMDNSConflictStopsClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	gwKey := types.NamespacedName{Namespace: "default", Name: "conflict-gw"}
	reconcileCh := make(chan types.NamespacedName, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         50 * time.Millisecond,
		ProbeCount:            3,
		ConflictRetryInterval: 1 * time.Second,
		AnnounceInterval:      50 * time.Millisecond,
		EnqueueGateway: func(req types.NamespacedName) {
			reconcileCh <- req
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	hName := gatewayv1.Hostname("conflict.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name, Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "127.0.0.1"}},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue},
					},
				},
			},
		},
	}

	// Start data plane push
	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

	// Inject a conflicting response packet for conflict.local directly into the publisher
	bConflict := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true,
		Authoritative: true,
	})
	bConflict.EnableCompression()
	_ = bConflict.StartAnswers()
	_ = bConflict.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("conflict.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{10, 0, 0, 99}},
	)
	respData, err := bConflict.Finish()
	if err != nil {
		t.Fatalf("building conflicting response: %v", err)
	}

	sender, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer sender.Close()

	// Send conflicting response to publisher's port
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ephemeralPort}
	if _, err := sender.WriteTo(respData, dst); err != nil {
		t.Fatalf("failed to send conflicting response: %v", err)
	}

	// Wait for conflict detection to enqueue reconcile
	select {
	case req := <-reconcileCh:
		if req != gwKey {
			t.Fatalf("unexpected reconcile key: %v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for conflict detection")
	}

	// Check conditions via StatusHook
	statusCopy := gw.Status.DeepCopy()
	if err := pub.StatusHook(ctx, gw, statusCopy); err != nil {
		t.Fatalf("StatusHook failed: %v", err)
	}

	pubCond := state.FindCondition(statusCopy.Listeners[0].Conditions, string(ConditionTypePublished))
	if pubCond == nil || pubCond.Status != metav1.ConditionFalse || pubCond.Reason != string(ConditionReasonHostnameConflict) {
		t.Fatalf("expected Published=False HostnameConflict, got: %+v", pubCond)
	}

	confCond := state.FindCondition(statusCopy.Listeners[0].Conditions, string(gatewayv1.ListenerConditionConflicted))
	if confCond == nil || confCond.Status != metav1.ConditionTrue || confCond.Reason != string(gatewayv1.ListenerReasonHostnameConflict) {
		t.Fatalf("expected Conflicted=True HostnameConflict, got: %+v", confCond)
	}

	if _, ok := pub.Responder().GetRecord("conflict.local."); ok {
		t.Fatalf("conflict.local should NOT be published in responder")
	}
}

// TestMDNSConflictAfterPublishing verifies that conflicts occurring AFTER publishing (RFC 6762 §9)
// immediately cease answering, transition to StateConflict, and report the condition.
func TestMDNSConflictAfterPublishing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	gwKey := types.NamespacedName{Namespace: "default", Name: "post-conflict-gw"}
	reconcileCh := make(chan types.NamespacedName, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 1 * time.Second,
		AnnounceInterval:      20 * time.Millisecond,
		EnqueueGateway: func(req types.NamespacedName) {
			reconcileCh <- req
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	hName := gatewayv1.Hostname("active.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name, Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "127.0.0.1"}},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue},
					},
				},
			},
		},
	}

	// 1. Initial publish
	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

	select {
	case <-reconcileCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for claim")
	}

	// Verify currently published
	if _, ok := pub.Responder().GetRecord("active.local."); !ok {
		t.Fatalf("active.local. should be published")
	}

	// 2. Another host on the LAN announces active.local with a different IP address (RFC 6762 §9)
	bConflict := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true,
		Authoritative: true,
	})
	bConflict.EnableCompression()
	_ = bConflict.StartAnswers()
	_ = bConflict.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("active.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{10, 0, 0, 55}},
	)
	respData, err := bConflict.Finish()
	if err != nil {
		t.Fatalf("building conflicting response: %v", err)
	}

	sender, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer sender.Close()

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ephemeralPort}
	if _, err := sender.WriteTo(respData, dst); err != nil {
		t.Fatalf("failed to send conflicting response: %v", err)
	}

	// 3. RFC 6762 §9: Must trigger reconcile and cease answering
	select {
	case <-reconcileCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for post-publish conflict notification")
	}

	// Verify record was removed from responder
	if _, ok := pub.Responder().GetRecord("active.local."); ok {
		t.Fatalf("RFC 6762 §9 violation: active.local should have ceased answering immediately after conflict")
	}

	// Verify status condition updated
	statusCopy := gw.Status.DeepCopy()
	if err := pub.StatusHook(ctx, gw, statusCopy); err != nil {
		t.Fatalf("StatusHook failed: %v", err)
	}
	pubCond := state.FindCondition(statusCopy.Listeners[0].Conditions, string(ConditionTypePublished))
	if pubCond == nil || pubCond.Status != metav1.ConditionFalse || pubCond.Reason != string(ConditionReasonHostnameConflict) {
		t.Fatalf("expected Published=False HostnameConflict after post-publish conflict, got: %+v", pubCond)
	}
}

// TestMDNSPublishingOnlyCoversValidLocalHostnames verifies only valid single-label .local names are published.
func TestMDNSPublishingOnlyCoversValidLocalHostnames(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Port:        ephemeralPort,
		IPv4Conn:    rawConn,
		Ephemeral:   true,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	invalidHostnames := []string{
		"example.com",
		"a.b.local",
		"*.local",
		"",
		"-bad-.local",
	}

	for _, invalid := range invalidHostnames {
		hName := gatewayv1.Hostname(invalid)
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
			Status: gatewayv1.GatewayStatus{
				Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "127.0.0.1"}},
				Listeners: []gatewayv1.ListenerStatus{
					{
						Name: "http",
						Conditions: []metav1.Condition{
							{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue},
						},
					},
				},
			},
		}

		pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

		statusCopy := gw.Status.DeepCopy()
		if err := pub.StatusHook(ctx, gw, statusCopy); err != nil {
			t.Fatalf("StatusHook failed for %q: %v", invalid, err)
		}

		cond := state.FindCondition(statusCopy.Listeners[0].Conditions, string(ConditionTypePublished))
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(ConditionReasonUnsupportedHostname) {
			t.Fatalf("for hostname %q expected UnsupportedHostname, got: %+v", invalid, cond)
		}

		if _, ok := pub.Responder().GetRecord(invalid); ok {
			t.Fatalf("hostname %q was unexpectedly published in responder", invalid)
		}
	}
}

// TestMDNSGracefulShutdownSendsGoodbye verifies that canceling context on graceful shutdown sends goodbye packets.
func TestMDNSGracefulShutdownSendsGoodbye(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	gwKey := types.NamespacedName{Namespace: "default", Name: "shutdown-gw"}
	reconcileCh := make(chan types.NamespacedName, 10)
	goodbyeCh := make(chan []byte, 10)

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	pub, err := NewPublisher(PublisherOptions{
		Interface:             "lo",
		Port:                  ephemeralPort,
		IPv4Conn:              rawConn,
		DisableIPv6:           true,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		MulticastTap: func(raw []byte) {
			var p dnsmessage.Parser
			if _, err := p.Start(raw); err != nil {
				return
			}
			if err := p.SkipAllQuestions(); err != nil {
				return
			}
			for {
				h, err := p.AnswerHeader()
				if err != nil {
					break
				}
				if strings.EqualFold(h.Name.String(), "shutdown.local.") && h.TTL == 0 {
					goodbyeCh <- raw
				}
				if err := p.SkipAnswer(); err != nil {
					break
				}
			}
		},
		EnqueueGateway: func(req types.NamespacedName) {
			reconcileCh <- req
		},
	})
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}
	defer pub.Close()
	go func() { _ = pub.Start(ctx) }()

	hName := gatewayv1.Hostname("shutdown.local")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: gwKey.Namespace, Name: gwKey.Name, Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: &hName, Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &ipAddrType, Value: "127.0.0.1"}},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{Type: string(gatewayv1.ListenerConditionProgrammed), Status: metav1.ConditionTrue},
					},
				},
			},
		},
	}

	pub.OnGatewaysUpdate([]*gatewayv1.Gateway{gw})

	select {
	case <-reconcileCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for probe completion")
	}

	// Trigger graceful shutdown by canceling context
	cancel()

	select {
	case raw := <-goodbyeCh:
		var p dnsmessage.Parser
		_, _ = p.Start(raw)
		_ = p.SkipAllQuestions()
		h, err := p.AnswerHeader()
		if err != nil || h.TTL != 0 {
			t.Fatalf("expected TTL 0 in shutdown goodbye, got %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected goodbye packet with TTL=0 on graceful shutdown, but none was observed")
	}
}
