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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	// DefaultPort is the standard mDNS port per RFC 6762.
	DefaultPort = 5353

	// IPv4MulticastGroup is the mDNS IPv4 multicast group address (224.0.0.251).
	IPv4MulticastGroup = "224.0.0.251"

	// IPv6MulticastGroup is the mDNS IPv6 multicast group address (ff02::fb).
	IPv6MulticastGroup = "ff02::fb"

	// DefaultTTL is the default TTL in seconds for published records (RFC 6762).
	DefaultTTL = 120

	// LegacyUnicastMaxTTL is the maximum TTL for legacy unicast responses per RFC 6762 §6.7.
	LegacyUnicastMaxTTL = 10

	// CacheFlushBit is the most significant bit of the RRClass field (RFC 6762 §10.2).
	CacheFlushBit = 0x8000

	// QUBit is the unicast-response bit in question classes (RFC 6762 §5.4).
	QUBit = CacheFlushBit
)

// RecordSet represents the set of addresses published for an mDNS hostname.
type RecordSet struct {
	// FQDN is the fully-qualified domain name (lowercase, ending in dot, e.g. "grafana.local.").
	FQDN string

	// A contains IPv4 addresses to answer A queries.
	A []net.IP

	// AAAA contains IPv6 addresses to answer AAAA queries.
	AAAA []net.IP

	// TTL is the record TTL in seconds (defaults to DefaultTTL if zero).
	TTL uint32
}

// ConflictHandler is a callback invoked when a conflicting mDNS response or higher-priority probe is detected.
type ConflictHandler func(fqdn string, conflictingRR dnsmessage.Resource)

// ResponderOptions configures an mDNS Responder.
type ResponderOptions struct {
	// Port is the UDP port to bind (defaults to DefaultPort = 5353 if unset).
	Port int

	// Ephemeral indicates that an ephemeral port (:0) should be bound rather than DefaultPort.
	Ephemeral bool

	// InterfaceName is the specific network interface name to bind and join multicast.
	// If empty, all active multicast-capable interfaces are joined (or loopback in fallback).
	InterfaceName string

	// DisableIPv6 disables IPv6 multicast even if available.
	DisableIPv6 bool

	// IPv4Conn is an optional pre-bound PacketConn (useful for testing).
	IPv4Conn net.PacketConn

	// IPv6Conn is an optional pre-bound PacketConn (useful for testing).
	IPv6Conn net.PacketConn

	// MulticastTap is an optional callback receiving every multicast DNS packet sent.
	// Useful for testing without opening secondary multicast listener sockets.
	MulticastTap func(raw []byte)
}

// Responder is a pure-Go mDNS responder built on golang.org/x/net/dns/dnsmessage.
// It listens on UDP port 5353, answers A/AAAA queries for published single-label .local names,
// sends probes, detects conflicts, rate-limits multicast responses, and sends goodbye packets.
type Responder struct {
	port          int
	interfaceName string
	multicastTap  func(raw []byte)

	mu              sync.RWMutex
	records         map[string]*RecordSet // keyed by lowercase FQDN
	conflictHandler ConflictHandler
	activeProbes    map[string][]dnsmessage.Resource // keyed by lowercase FQDN -> proposed records
	lastMulticast   map[string]time.Time             // key: "name/type" -> last multicast send time (RFC 6762 §6.2)
	lastReadErrLog  time.Time

	raw4 net.PacketConn
	p4   *ipv4.PacketConn

	raw6 net.PacketConn
	p6   *ipv6.PacketConn

	closed sync.WaitGroup
	stopCh chan struct{}
	done   sync.Once
}

// NewResponder creates and starts a new mDNS responder.
func NewResponder(opts ResponderOptions) (*Responder, error) {
	var port int
	if opts.Ephemeral {
		port = 0
	} else if opts.Port != 0 {
		port = opts.Port
	} else if opts.IPv4Conn == nil {
		port = DefaultPort
	}

	r := &Responder{
		port:          port,
		interfaceName: opts.InterfaceName,
		multicastTap:  opts.MulticastTap,
		records:       make(map[string]*RecordSet),
		activeProbes:  make(map[string][]dnsmessage.Resource),
		lastMulticast: make(map[string]time.Time),
		stopCh:        make(chan struct{}),
	}

	// 1. Setup IPv4 connection exclusively without SO_REUSEPORT
	if opts.IPv4Conn != nil {
		r.raw4 = opts.IPv4Conn
		if udp, ok := opts.IPv4Conn.LocalAddr().(*net.UDPAddr); ok {
			r.port = udp.Port
		}
		r.p4 = ipv4.NewPacketConn(opts.IPv4Conn)
	} else {
		c4, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
		if err != nil {
			if isAddrInUse(err) {
				return nil, fmt.Errorf("UDP port %d is already in use (host avahi-daemon must be stopped or bound elsewhere): %w", port, err)
			}
			return nil, fmt.Errorf("failed to bind UDP IPv4 port %d: %w", port, err)
		}
		r.raw4 = c4
		r.p4 = ipv4.NewPacketConn(c4)
		if udp, ok := c4.LocalAddr().(*net.UDPAddr); ok {
			r.port = udp.Port
		}

		if err := r.joinMulticastIPv4(); err != nil {
			if closeErr := c4.Close(); closeErr != nil {
				klog.Warningf("failed to close IPv4 connection after join failure: %v", closeErr)
			}
			return nil, fmt.Errorf("failed to join IPv4 multicast group: %w", err)
		}
	}

	// 2. Setup IPv6 connection (optional) exclusively with IPV6_V6ONLY
	if !opts.DisableIPv6 {
		if opts.IPv6Conn != nil {
			r.raw6 = opts.IPv6Conn
			r.p6 = ipv6.NewPacketConn(opts.IPv6Conn)
		} else {
			lc := net.ListenConfig{
				Control: func(network, address string, c syscall.RawConn) error {
					var opErr error
					err := c.Control(func(fd uintptr) {
						opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
					})
					if err != nil {
						return err
					}
					return opErr
				},
			}
			c6, err := lc.ListenPacket(context.Background(), "udp6", fmt.Sprintf(":%d", r.port))
			if err != nil {
				klog.Warningf("IPv6 not available for mDNS on port %d: %v", r.port, err)
			} else {
				r.raw6 = c6
				r.p6 = ipv6.NewPacketConn(c6)
				if err := r.joinMulticastIPv6(); err != nil {
					klog.Warningf("failed to join IPv6 multicast group: %v", err)
				}
			}
		}
	}

	// 3. Start read loops
	if r.raw4 != nil {
		r.closed.Add(1)
		go r.readLoop(r.raw4, false)
	}
	if r.raw6 != nil {
		r.closed.Add(1)
		go r.readLoop(r.raw6, true)
	}

	return r, nil
}

func isAddrInUse(err error) bool {
	if errors.Is(err, unix.EADDRINUSE) {
		return true
	}
	return strings.Contains(err.Error(), "address already in use")
}

// Port returns the UDP port the responder is bound to.
func (r *Responder) Port() int {
	return r.port
}

// joinMulticastIPv4 joins 224.0.0.251 on specified or active multicast interfaces.
func (r *Responder) joinMulticastIPv4() error {
	group := &net.UDPAddr{IP: net.ParseIP(IPv4MulticastGroup)}
	ifaces := r.targetInterfaces()
	if len(ifaces) == 0 {
		return errors.New("no network interfaces available for multicast")
	}

	joined := 0
	for _, ifi := range ifaces {
		if err := r.p4.JoinGroup(&ifi, group); err != nil {
			continue
		}
		if err := r.p4.SetMulticastInterface(&ifi); err != nil {
			klog.Warningf("failed to set IPv4 multicast interface %s: %v", ifi.Name, err)
		}
		joined++
	}
	if err := r.p4.SetMulticastLoopback(true); err != nil {
		klog.Warningf("failed to set IPv4 multicast loopback: %v", err)
	}
	if err := r.p4.SetMulticastTTL(255); err != nil {
		klog.Warningf("failed to set IPv4 multicast TTL: %v", err)
	}

	if joined == 0 {
		return fmt.Errorf("failed to join IPv4 multicast group %s on any interface", IPv4MulticastGroup)
	}
	return nil
}

// joinMulticastIPv6 joins ff02::fb on specified or active multicast interfaces.
func (r *Responder) joinMulticastIPv6() error {
	group := &net.UDPAddr{IP: net.ParseIP(IPv6MulticastGroup)}
	ifaces := r.targetInterfaces()
	joined := 0
	for _, ifi := range ifaces {
		if err := r.p6.JoinGroup(&ifi, group); err != nil {
			continue
		}
		if err := r.p6.SetMulticastInterface(&ifi); err != nil {
			klog.Warningf("failed to set IPv6 multicast interface %s: %v", ifi.Name, err)
		}
		joined++
	}
	if err := r.p6.SetMulticastLoopback(true); err != nil {
		klog.Warningf("failed to set IPv6 multicast loopback: %v", err)
	}
	if err := r.p6.SetMulticastHopLimit(255); err != nil {
		klog.Warningf("failed to set IPv6 multicast hop limit: %v", err)
	}
	if joined == 0 {
		return fmt.Errorf("failed to join IPv6 multicast group %s on any interface", IPv6MulticastGroup)
	}
	return nil
}

func (r *Responder) targetInterfaces() []net.Interface {
	if r.interfaceName != "" {
		ifi, err := net.InterfaceByName(r.interfaceName)
		if err != nil {
			klog.Warningf("failed to find interface %q: %v", r.interfaceName, err)
		} else {
			return []net.Interface{*ifi}
		}
	}

	all, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var res []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagMulticast != 0 && ifi.Flags&net.FlagLoopback == 0 {
			res = append(res, ifi)
		}
	}
	if len(res) == 0 {
		for _, ifi := range all {
			if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagLoopback != 0 {
				res = append(res, ifi)
			}
		}
	}
	return res
}

// SetRecord updates or adds a published RecordSet.
func (r *Responder) SetRecord(rs *RecordSet) {
	if rs == nil || rs.FQDN == "" {
		return
	}
	fqdn := strings.ToLower(toFQDN(rs.FQDN))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[fqdn] = &RecordSet{
		FQDN: fqdn,
		A:    append([]net.IP(nil), rs.A...),
		AAAA: append([]net.IP(nil), rs.AAAA...),
		TTL:  rs.TTL,
	}
}

// RemoveRecord removes a published RecordSet by hostname.
func (r *Responder) RemoveRecord(hostname string) *RecordSet {
	fqdn := strings.ToLower(toFQDN(hostname))
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.records[fqdn]
	delete(r.records, fqdn)
	return old
}

// GetRecord returns a published RecordSet by hostname.
func (r *Responder) GetRecord(hostname string) (*RecordSet, bool) {
	fqdn := strings.ToLower(toFQDN(hostname))
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[fqdn]
	if !ok {
		return nil, false
	}
	return &RecordSet{
		FQDN: rec.FQDN,
		A:    append([]net.IP(nil), rec.A...),
		AAAA: append([]net.IP(nil), rec.AAAA...),
		TTL:  rec.TTL,
	}, true
}

// SetConflictHandler sets the callback for detected conflicts during probing or after publishing.
func (r *Responder) SetConflictHandler(h ConflictHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conflictHandler = h
}

// RegisterProbe registers an active probe for simultaneous conflict detection.
func (r *Responder) RegisterProbe(fqdn string, proposedRecords []dnsmessage.Resource) {
	name := strings.ToLower(toFQDN(fqdn))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activeProbes[name] = proposedRecords
}

// UnregisterProbe unregisters an active probe.
func (r *Responder) UnregisterProbe(fqdn string) {
	name := strings.ToLower(toFQDN(fqdn))
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.activeProbes, name)
}

// readLoop reads incoming datagrams from a packet connection and processes queries/responses.
func (r *Responder) readLoop(p net.PacketConn, isIPv6 bool) {
	defer r.closed.Done()
	buf := make([]byte, 4096)

	for {
		n, from, err := p.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-r.stopCh:
				return
			default:
			}
			r.logReadError(err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		r.handlePacket(buf[:n], from, isIPv6)
	}
}

func (r *Responder) logReadError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastReadErrLog) > time.Second {
		r.lastReadErrLog = time.Now()
		klog.Warningf("mDNS read error on port %d: %v", r.port, err)
	}
}

// handlePacket parses and dispatches an incoming DNS message.
func (r *Responder) handlePacket(data []byte, from net.Addr, isIPv6 bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(data)
	if err != nil {
		return
	}

	if hdr.Response {
		r.handleResponse(&p, hdr)
	} else {
		r.handleQuery(&p, hdr, from, isIPv6)
	}
}

// handleResponse inspects answers and authority records for conflicts with active probes
// and already published records per RFC 6762 §9.
func (r *Responder) handleResponse(p *dnsmessage.Parser, _ dnsmessage.Header) {
	if err := p.SkipAllQuestions(); err != nil {
		return
	}

	var answers []dnsmessage.Resource
	for {
		ans, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		answers = append(answers, ans)
	}

	var authorities []dnsmessage.Resource
	for {
		auth, err := p.Authority()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		authorities = append(authorities, auth)
	}

	if err := p.SkipAllAdditionals(); err != nil {
		return
	}

	r.mu.Lock()
	handler := r.conflictHandler
	probes := make(map[string][]dnsmessage.Resource, len(r.activeProbes))
	for k, v := range r.activeProbes {
		probes[k] = v
	}

	published := make(map[string]*RecordSet, len(r.records))
	for k, v := range r.records {
		published[k] = v
	}

	// Record multicast response time for multicast rate limiting (RFC 6762 §6.2)
	now := time.Now()
	for _, rr := range answers {
		key := fmt.Sprintf("%s/%d", strings.ToLower(rr.Header.Name.String()), rr.Header.Type)
		r.lastMulticast[key] = now
	}
	r.mu.Unlock()

	if handler == nil {
		return
	}

	for _, rr := range append(answers, authorities...) {
		name := strings.ToLower(rr.Header.Name.String())

		// 1. Conflict with an active probe
		if proposed, probing := probes[name]; probing {
			if isConflictingRecord(rr, proposed) {
				handler(name, rr)
				continue
			}
		}

		// 2. Conflict with an already published record (RFC 6762 §9)
		if pubRec, isPub := published[name]; isPub {
			proposed, err := buildRecords(pubRec.FQDN, append(append([]net.IP(nil), pubRec.A...), pubRec.AAAA...), pubRec.TTL)
			if err != nil {
				klog.Warningf("failed to build records for %s: %v", pubRec.FQDN, err)
				continue
			}
			if isConflictingRecord(rr, proposed) {
				handler(name, rr)
			}
		}
	}
}

// handleQuery handles mDNS queries:
//  1. Answers queries matching published records, respecting multicast rate limiting (RFC 6762 §6.2),
//     known-answer suppression (§7.1), and legacy unicast formatting (§6.7).
//  2. Checks simultaneous probe queries against active probes (RFC 6762 §8.2).
func (r *Responder) handleQuery(p *dnsmessage.Parser, queryHeader dnsmessage.Header, from net.Addr, isIPv6 bool) {
	var questions []dnsmessage.Question
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		questions = append(questions, q)
	}

	var knownAnswers []dnsmessage.Resource
	for {
		ans, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		knownAnswers = append(knownAnswers, ans)
	}

	var authorities []dnsmessage.Resource
	for {
		auth, err := p.Authority()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}
		authorities = append(authorities, auth)
	}

	if err := p.SkipAllAdditionals(); err != nil {
		return
	}

	r.mu.RLock()
	handler := r.conflictHandler
	probes := make(map[string][]dnsmessage.Resource, len(r.activeProbes))
	for k, v := range r.activeProbes {
		probes[k] = v
	}
	r.mu.RUnlock()

	// 1. Simultaneous probe conflict check (RFC 6762 §8.2)
	if handler != nil && len(probes) > 0 && len(authorities) > 0 {
		for _, q := range questions {
			qname := strings.ToLower(q.Name.String())
			proposed, probing := probes[qname]
			if !probing {
				continue
			}
			for _, nsRR := range authorities {
				if strings.ToLower(nsRR.Header.Name.String()) == qname {
					if isLexicographicallyGreater(nsRR, proposed) {
						handler(qname, nsRR)
					}
				}
			}
		}
	}

	// Determine if request expects unicast or is from a legacy unicast UDP port
	udpFrom, isUDP := from.(*net.UDPAddr)
	isLegacyUnicast := isUDP && udpFrom.Port != r.port

	unicastRequested := isLegacyUnicast
	for _, q := range questions {
		if uint16(q.Class)&QUBit != 0 {
			unicastRequested = true
		}
	}

	// 2. Construct answer for published records
	var answers []dnsmessage.Resource
	now := time.Now()

	r.mu.Lock()
	for _, q := range questions {
		// RFC 6762 §5.5: clear the QU bit, then ignore questions for classes we don't hold records in.
		class := q.Class &^ dnsmessage.Class(QUBit)
		if class != dnsmessage.ClassINET && class != dnsmessage.ClassANY {
			continue
		}

		qname := strings.ToLower(q.Name.String())
		rec, found := r.records[qname]
		if !found {
			continue
		}

		// RFC 6762 §6.7: Legacy unicast answers must use TTL <= 10s and standard ClassINET (no cache-flush bit).
		// RFC 6762 §10.2: Standard mDNS answers set CacheFlushBit and normal TTL.
		var rrClass uint16 = uint16(dnsmessage.ClassINET)
		ttl := rec.TTL
		if ttl == 0 {
			ttl = DefaultTTL
		}
		if isLegacyUnicast {
			if ttl > LegacyUnicastMaxTTL {
				ttl = LegacyUnicastMaxTTL
			}
		} else {
			rrClass |= CacheFlushBit
		}

		recName, err := dnsmessage.NewName(toFQDN(rec.FQDN))
		if err != nil {
			klog.Warningf("failed to construct DNS name for %q: %v", rec.FQDN, err)
			continue
		}

		// A records
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
			key := fmt.Sprintf("%s/%d", qname, dnsmessage.TypeA)
			// Multicast rate limiting: at most once per second per record (RFC 6762 §6.2)
			allowed := unicastRequested || now.Sub(r.lastMulticast[key]) >= time.Second

			if allowed {
				for _, ip4 := range rec.A {
					if ip4.To4() != nil {
						var a [4]byte
						copy(a[:], ip4.To4())
						rr := dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{
								Name:  recName,
								Type:  dnsmessage.TypeA,
								Class: dnsmessage.Class(rrClass),
								TTL:   ttl,
							},
							Body: &dnsmessage.AResource{A: a},
						}
						// Known-answer suppression (RFC 6762 §7.1): suppress if querier already has it with >= half TTL
						if !isKnownAnswer(rr, knownAnswers) {
							answers = append(answers, rr)
							if !unicastRequested {
								r.lastMulticast[key] = now
							}
						}
					}
				}
			}
		}

		// AAAA records
		if q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.TypeALL {
			key := fmt.Sprintf("%s/%d", qname, dnsmessage.TypeAAAA)
			allowed := unicastRequested || now.Sub(r.lastMulticast[key]) >= time.Second

			if allowed {
				for _, ip6 := range rec.AAAA {
					if ip6.To4() == nil && ip6.To16() != nil {
						var aaaa [16]byte
						copy(aaaa[:], ip6.To16())
						rr := dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{
								Name:  recName,
								Type:  dnsmessage.TypeAAAA,
								Class: dnsmessage.Class(rrClass),
								TTL:   ttl,
							},
							Body: &dnsmessage.AAAAResource{AAAA: aaaa},
						}
						if !isKnownAnswer(rr, knownAnswers) {
							answers = append(answers, rr)
							if !unicastRequested {
								r.lastMulticast[key] = now
							}
						}
					}
				}
			}
		}
	}
	r.mu.Unlock()

	if len(answers) == 0 {
		return
	}

	// Per RFC 6762 §18.1 and §6.7, multicast responses set the message ID to 0,
	// while legacy unicast responses copy the query ID.
	var respID uint16
	if isLegacyUnicast {
		respID = queryHeader.ID
	}

	respHdr := dnsmessage.Header{
		ID:               respID,
		Response:         true,
		OpCode:           queryHeader.OpCode,
		Authoritative:    true,
		RecursionDesired: queryHeader.RecursionDesired,
		CheckingDisabled: queryHeader.CheckingDisabled,
	}
	b := dnsmessage.NewBuilder(nil, respHdr)
	b.EnableCompression()

	// Per RFC 6762 §6 and §6.7, multicast responses omit the question section,
	// while legacy unicast responses echo the question.
	if isLegacyUnicast && len(questions) > 0 {
		if err := b.StartQuestions(); err != nil {
			klog.Warningf("failed to start questions in response: %v", err)
			return
		}
		if err := b.Question(questions[0]); err != nil {
			klog.Warningf("failed to add question to response: %v", err)
			return
		}
	}

	if err := b.StartAnswers(); err != nil {
		klog.Warningf("failed to start answers in response: %v", err)
		return
	}
	for _, ans := range answers {
		if err := appendResource(&b, ans); err != nil {
			klog.Warningf("failed to add answer to response: %v", err)
			return
		}
	}

	data, err := b.Finish()
	if err != nil {
		klog.Warningf("failed to finish building response: %v", err)
		return
	}

	if unicastRequested {
		r.sendUnicast(data, from, isIPv6)
	} else {
		r.sendMulticast(data, isIPv6)
	}
}

// isKnownAnswer determines whether the querier's Answer section contains an identical answer with >= half TTL (RFC 6762 §7.1).
func isKnownAnswer(ourRR dnsmessage.Resource, knownAnswers []dnsmessage.Resource) bool {
	for _, ka := range knownAnswers {
		if recordsEqual(ourRR, ka) {
			if ka.Header.TTL >= ourRR.Header.TTL/2 {
				return true
			}
		}
	}
	return false
}

// isConflictingRecord determines whether a received record conflicts with our proposed records.
func isConflictingRecord(received dnsmessage.Resource, proposed []dnsmessage.Resource) bool {
	// A TTL of 0 is a goodbye, not an active conflict.
	if received.Header.TTL == 0 {
		return false
	}

	// If the received record matches our own proposed address, it's our own announcement/response looped back.
	for _, prop := range proposed {
		if recordsEqual(received, prop) {
			return false
		}
	}

	switch received.Body.(type) {
	case *dnsmessage.AResource, *dnsmessage.AAAAResource:
		return true // different address published for same name
	}
	return false
}

// isLexicographicallyGreater determines whether opponent's authority record is greater than ours (RFC 6762 §8.2).
func isLexicographicallyGreater(oppRR dnsmessage.Resource, ourRRs []dnsmessage.Resource) bool {
	// If opponent record is identical to any of our proposed records, it is not a conflict (RFC 6762 §8.2).
	for _, ourRR := range ourRRs {
		if recordsEqual(oppRR, ourRR) {
			return false
		}
	}

	oppData, err := packResource(oppRR)
	if err != nil {
		return false
	}

	// Compare against our proposed record of the same RR type
	for _, ourRR := range ourRRs {
		if ourRR.Header.Type == oppRR.Header.Type {
			ourData, err := packResource(ourRR)
			if err != nil {
				continue
			}
			return bytes.Compare(oppData, ourData) > 0
		}
	}

	// If no same-type record found, compare against all
	for _, ourRR := range ourRRs {
		ourData, err := packResource(ourRR)
		if err != nil {
			continue
		}
		if bytes.Compare(oppData, ourData) > 0 {
			return true
		}
	}
	return false
}

func recordsEqual(a, b dnsmessage.Resource) bool {
	if a.Header.Type != b.Header.Type {
		return false
	}
	switch bodyA := a.Body.(type) {
	case *dnsmessage.AResource:
		if bodyB, ok := b.Body.(*dnsmessage.AResource); ok {
			return bodyA.A == bodyB.A
		}
	case *dnsmessage.AAAAResource:
		if bodyB, ok := b.Body.(*dnsmessage.AAAAResource); ok {
			return bodyA.AAAA == bodyB.AAAA
		}
	}
	return false
}

func packResource(r dnsmessage.Resource) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := appendResource(&b, r); err != nil {
		return nil, err
	}
	return b.Finish()
}

func appendResource(b *dnsmessage.Builder, r dnsmessage.Resource) error {
	switch body := r.Body.(type) {
	case *dnsmessage.AResource:
		return b.AResource(r.Header, *body)
	case *dnsmessage.AAAAResource:
		return b.AAAAResource(r.Header, *body)
	case *dnsmessage.CNAMEResource:
		return b.CNAMEResource(r.Header, *body)
	case *dnsmessage.PTRResource:
		return b.PTRResource(r.Header, *body)
	case *dnsmessage.TXTResource:
		return b.TXTResource(r.Header, *body)
	case *dnsmessage.SRVResource:
		return b.SRVResource(r.Header, *body)
	case *dnsmessage.UnknownResource:
		return b.UnknownResource(r.Header, *body)
	default:
		return fmt.Errorf("unsupported resource body: %T", r.Body)
	}
}

// SendProbe broadcasts an mDNS probe query for the given FQDN with proposed authority records (RFC 6762 §8.1).
func (r *Responder) SendProbe(fqdn string, proposedRecords []dnsmessage.Resource) error {
	name, err := dnsmessage.NewName(toFQDN(fqdn))
	if err != nil {
		return fmt.Errorf("invalid fqdn %q: %w", fqdn, err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response: false,
		OpCode:   0,
	})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return fmt.Errorf("starting questions: %w", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeALL,
		Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | QUBit), // QU bit requests unicast response
	}); err != nil {
		return fmt.Errorf("adding probe question: %w", err)
	}

	if err := b.StartAuthorities(); err != nil {
		return fmt.Errorf("starting authorities: %w", err)
	}
	for _, rec := range proposedRecords {
		if err := appendResource(&b, rec); err != nil {
			return fmt.Errorf("adding probe authority record: %w", err)
		}
	}

	data, err := b.Finish()
	if err != nil {
		return fmt.Errorf("finishing probe message: %w", err)
	}

	return r.BroadcastMulticast(data)
}

// SendAnnouncement broadcasts an mDNS announcement response for the given records (RFC 6762 §8.3).
func (r *Responder) SendAnnouncement(records []dnsmessage.Resource) error {
	if len(records) == 0 {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true,
		Authoritative: true,
	})
	b.EnableCompression()

	if err := b.StartAnswers(); err != nil {
		return fmt.Errorf("starting answers: %w", err)
	}
	for _, rec := range records {
		if err := appendResource(&b, rec); err != nil {
			return fmt.Errorf("adding announcement record: %w", err)
		}
	}

	data, err := b.Finish()
	if err != nil {
		return fmt.Errorf("finishing announcement message: %w", err)
	}

	return r.BroadcastMulticast(data)
}

// SendGoodbye broadcasts a goodbye packet (TTL=0) for the given records (RFC 6762 §10.1).
func (r *Responder) SendGoodbye(records []dnsmessage.Resource) error {
	if len(records) == 0 {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true,
		Authoritative: true,
	})
	b.EnableCompression()

	if err := b.StartAnswers(); err != nil {
		return fmt.Errorf("starting answers: %w", err)
	}
	for _, rec := range records {
		goodbyeRec := rec
		goodbyeRec.Header.TTL = 0
		if err := appendResource(&b, goodbyeRec); err != nil {
			return fmt.Errorf("adding goodbye record: %w", err)
		}
	}

	data, err := b.Finish()
	if err != nil {
		return fmt.Errorf("finishing goodbye message: %w", err)
	}

	return r.BroadcastMulticast(data)
}

// BroadcastMulticast sends a DNS message to both IPv4 and IPv6 multicast groups.
func (r *Responder) BroadcastMulticast(data []byte) error {
	if r.multicastTap != nil {
		r.multicastTap(data)
	}

	var errs []error
	if r.raw4 != nil {
		dst4 := &net.UDPAddr{IP: net.ParseIP(IPv4MulticastGroup), Port: r.port}
		if _, err := r.raw4.WriteTo(data, dst4); err != nil {
			errs = append(errs, err)
		}
	}
	if r.raw6 != nil {
		dst6 := &net.UDPAddr{IP: net.ParseIP(IPv6MulticastGroup), Port: r.port}
		if _, err := r.raw6.WriteTo(data, dst6); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Responder) sendMulticast(data []byte, isIPv6 bool) {
	if r.multicastTap != nil {
		r.multicastTap(data)
	}

	if isIPv6 && r.raw6 != nil {
		dst6 := &net.UDPAddr{IP: net.ParseIP(IPv6MulticastGroup), Port: r.port}
		if _, err := r.raw6.WriteTo(data, dst6); err != nil {
			klog.Warningf("failed to send IPv6 multicast response: %v", err)
		}
	} else if r.raw4 != nil {
		dst4 := &net.UDPAddr{IP: net.ParseIP(IPv4MulticastGroup), Port: r.port}
		if _, err := r.raw4.WriteTo(data, dst4); err != nil {
			klog.Warningf("failed to send IPv4 multicast response: %v", err)
		}
	}
}

func (r *Responder) sendUnicast(data []byte, to net.Addr, isIPv6 bool) {
	if isIPv6 && r.raw6 != nil {
		if _, err := r.raw6.WriteTo(data, to); err != nil {
			klog.Warningf("failed to send IPv6 unicast response to %v: %v", to, err)
		}
	} else if r.raw4 != nil {
		if _, err := r.raw4.WriteTo(data, to); err != nil {
			klog.Warningf("failed to send IPv4 unicast response to %v: %v", to, err)
		}
	}
}

// Close gracefully closes the responder sockets.
func (r *Responder) Close() error {
	var err error
	r.done.Do(func() {
		close(r.stopCh)
		var errs []error
		if r.raw4 != nil {
			if e := r.raw4.Close(); e != nil {
				errs = append(errs, e)
			}
		}
		if r.raw6 != nil {
			if e := r.raw6.Close(); e != nil {
				errs = append(errs, e)
			}
		}
		r.closed.Wait()
		err = errors.Join(errs...)
	})
	return err
}

func toFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
