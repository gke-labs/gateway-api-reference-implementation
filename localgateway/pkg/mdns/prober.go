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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"k8s.io/klog/v2"
)

// HostnameState represents the publication state of an mDNS hostname.
type HostnameState string

const (
	// StateProbing indicates the hostname is actively sending probes to verify uniqueness.
	StateProbing HostnameState = "Probing"

	// StatePublished indicates the hostname has been claimed and is answering queries.
	StatePublished HostnameState = "Published"

	// StateConflict indicates another host on the LAN responded to a probe or conflicting announcement.
	StateConflict HostnameState = "Conflict"
)

// HostnamePublicationSnapshot provides a read-only snapshot of publication status for a hostname.
type HostnamePublicationSnapshot struct {
	FQDN            string
	Hostname        string
	State           HostnameState
	ConflictMessage string
}

// ProberOptions configures the mDNS Prober.
type ProberOptions struct {
	// Responder is the mDNS Responder used to send packets and answer queries.
	Responder *Responder

	// TTL is the mDNS record TTL in seconds (defaults to 120s).
	TTL uint32

	// ProbeInterval is the time between probes (defaults to 250ms per RFC 6762 §8.1).
	ProbeInterval time.Duration

	// ProbeCount is the number of probe packets to send (defaults to 3 per RFC 6762 §8.1).
	ProbeCount int

	// ConflictRetryInterval is the interval before retrying a conflicting name (defaults to 30s).
	ConflictRetryInterval time.Duration

	// AnnounceInterval is the time between initial announcements (defaults to 1s per RFC 6762 §8.3).
	AnnounceInterval time.Duration

	// OnStateChange is an optional callback invoked when a hostname changes publication state.
	OnStateChange func(fqdn string, state HostnameState)
}

type proberEntry struct {
	fqdn            string // canonical lower-case with trailing dot
	hostname        string // name without trailing dot
	state           HostnameState
	addresses       []net.IP
	records         []dnsmessage.Resource
	conflictMessage string
	lastConflict    time.Time
	cancelProbe     context.CancelFunc
}

// Prober manages mDNS probing, claiming, announcing, conflict resolution, and withdrawal
// for a set of hostnames without any dependency on Kubernetes or Gateway API types.
type Prober struct {
	opts      ProberOptions
	responder *Responder

	mu    sync.RWMutex
	names map[string]*proberEntry // keyed by canonical lower-case FQDN

	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once
}

// NewProber creates a new mDNS prober.
func NewProber(opts ProberOptions) (*Prober, error) {
	if opts.Responder == nil {
		return nil, errors.New("responder is required")
	}
	if opts.TTL == 0 {
		opts.TTL = DefaultTTL
	}
	if opts.ProbeInterval <= 0 {
		opts.ProbeInterval = 250 * time.Millisecond
	}
	if opts.ProbeCount <= 0 {
		opts.ProbeCount = 3
	}
	if opts.ConflictRetryInterval <= 0 {
		opts.ConflictRetryInterval = 30 * time.Second
	}
	if opts.AnnounceInterval <= 0 {
		opts.AnnounceInterval = 1 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &Prober{
		opts:      opts,
		responder: opts.Responder,
		names:     make(map[string]*proberEntry),
		ctx:       ctx,
		cancel:    cancel,
	}

	p.responder.SetConflictHandler(p.onConflict)

	return p, nil
}

// Responder returns the underlying mDNS Responder.
func (p *Prober) Responder() *Responder {
	return p.responder
}

// SetNames updates the active set of hostnames and their addresses.
// New names are probed and announced. Names with changed addresses are re-announced.
// Names no longer in the set are withdrawn with goodbye packets.
func (p *Prober) SetNames(names map[string][]net.IP) {
	desired := make(map[string][]net.IP, len(names))
	rawNames := make(map[string]string, len(names))
	for name, ips := range names {
		fqdn := strings.ToLower(ToFQDN(name))
		desired[fqdn] = ips
		rawNames[fqdn] = strings.TrimSuffix(name, ".")
	}

	p.mu.Lock()
	// 1. Withdraw names that are no longer in the set
	var goodbyes []dnsmessage.Resource
	for fqdn, st := range p.names {
		if _, ok := desired[fqdn]; !ok {
			if st.cancelProbe != nil {
				st.cancelProbe()
				st.cancelProbe = nil
			}
			if st.state == StatePublished {
				p.responder.RemoveRecord(fqdn)
				if len(st.records) > 0 {
					goodbyes = append(goodbyes, st.records...)
				}
			}
			delete(p.names, fqdn)
		}
	}

	// 2. Add new names or update existing names
	type probeToStart struct {
		ctx     context.Context
		fqdn    string
		records []dnsmessage.Resource
	}
	var probes []probeToStart
	var announcements [][]dnsmessage.Resource

	for fqdn, ips := range desired {
		records, err := BuildRecords(fqdn, ips, p.opts.TTL)
		if err != nil {
			klog.Warningf("failed to build records for %s: %v", fqdn, err)
			continue
		}

		st, exists := p.names[fqdn]
		if !exists {
			probeCtx, cancel := context.WithCancel(p.ctx)
			st = &proberEntry{
				fqdn:        fqdn,
				hostname:    rawNames[fqdn],
				state:       StateProbing,
				addresses:   append([]net.IP(nil), ips...),
				records:     records,
				cancelProbe: cancel,
			}
			p.names[fqdn] = st
			probes = append(probes, probeToStart{
				ctx:     probeCtx,
				fqdn:    fqdn,
				records: records,
			})
			continue
		}

		// Existing entry: check if addresses changed
		if !ipsEqual(st.addresses, ips) {
			st.addresses = append([]net.IP(nil), ips...)
			st.records = records

			if st.state == StatePublished {
				var a []net.IP
				var aaaa []net.IP
				for _, ip := range ips {
					if ip.To4() != nil {
						a = append(a, ip.To4())
					} else if ip.To16() != nil {
						aaaa = append(aaaa, ip.To16())
					}
				}
				p.responder.SetRecord(&RecordSet{
					FQDN: fqdn,
					A:    a,
					AAAA: aaaa,
					TTL:  p.opts.TTL,
				})
				announcements = append(announcements, records)
			}
		}
	}
	p.mu.Unlock()

	// Execute network I/O outside the lock
	if len(goodbyes) > 0 {
		if err := p.responder.SendGoodbye(goodbyes); err != nil && !isNormalClose(err) {
			klog.Warningf("failed to send goodbye packets: %v", err)
		}
	}
	for _, recs := range announcements {
		if err := p.responder.SendAnnouncement(recs); err != nil {
			klog.Warningf("failed to send announcement: %v", err)
		}
	}
	for _, pr := range probes {
		go p.runProbe(pr.ctx, pr.fqdn, pr.records)
	}
}

// GetHostnameState returns a snapshot of the current publication state for a hostname.
func (p *Prober) GetHostnameState(fqdn string) (HostnamePublicationSnapshot, bool) {
	name := strings.ToLower(ToFQDN(fqdn))
	p.mu.RLock()
	defer p.mu.RUnlock()
	st, ok := p.names[name]
	if !ok {
		return HostnamePublicationSnapshot{}, false
	}
	return HostnamePublicationSnapshot{
		FQDN:            st.fqdn,
		Hostname:        st.hostname,
		State:           st.state,
		ConflictMessage: st.conflictMessage,
	}, true
}

// State returns a snapshot of the current publication state for a hostname.
func (p *Prober) State(fqdn string) (HostnamePublicationSnapshot, bool) {
	return p.GetHostnameState(fqdn)
}

// Shutdown cancels active probes and sends goodbye packets for all published names.
func (p *Prober) Shutdown() error {
	var err error
	p.shutdownOnce.Do(func() {
		p.cancel()
		p.responder.SetConflictHandler(nil)

		p.mu.Lock()
		var allRecords []dnsmessage.Resource
		for fqdn, st := range p.names {
			if st.state == StatePublished && len(st.records) > 0 {
				allRecords = append(allRecords, st.records...)
				p.responder.RemoveRecord(fqdn)
			}
		}
		p.names = make(map[string]*proberEntry)
		p.mu.Unlock()

		if len(allRecords) > 0 {
			if gErr := p.responder.SendGoodbye(allRecords); gErr != nil && !isNormalClose(gErr) {
				klog.Warningf("failed to send goodbye packets on shutdown: %v", gErr)
				err = gErr
			}
		}
	})
	return err
}

// Close stops all active probing and sends goodbyes on shutdown.
func (p *Prober) Close() error {
	return p.Shutdown()
}

// onConflict is invoked by the Responder when a conflict is detected on the LAN.
func (p *Prober) onConflict(fqdn string, conflictingRR dnsmessage.Resource) {
	name := strings.ToLower(ToFQDN(fqdn))

	p.mu.Lock()
	st, ok := p.names[name]
	if !ok {
		p.mu.Unlock()
		return
	}

	if st.state == StateConflict {
		p.mu.Unlock()
		return
	}

	if st.cancelProbe != nil {
		st.cancelProbe()
		st.cancelProbe = nil
	}

	if st.state == StatePublished {
		p.responder.RemoveRecord(name)
	}

	st.state = StateConflict
	st.lastConflict = time.Now()
	st.conflictMessage = fmt.Sprintf("Hostname %q conflicts with another host on the LAN: %v", st.hostname, conflictingRR)
	onStateChange := p.opts.OnStateChange
	p.mu.Unlock()

	if onStateChange != nil {
		onStateChange(name, StateConflict)
	}

	go func() {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.opts.ConflictRetryInterval):
			p.retryConflict(name)
		}
	}()
}

func (p *Prober) retryConflict(fqdn string) {
	p.mu.Lock()
	st, ok := p.names[fqdn]
	if !ok || st.state != StateConflict {
		p.mu.Unlock()
		return
	}

	st.state = StateProbing
	st.conflictMessage = ""

	probeCtx, cancel := context.WithCancel(p.ctx)
	st.cancelProbe = cancel
	records := append([]dnsmessage.Resource(nil), st.records...)
	p.mu.Unlock()

	go p.runProbe(probeCtx, fqdn, records)
}

func (p *Prober) runProbe(ctx context.Context, fqdn string, proposedRecords []dnsmessage.Resource) {
	p.responder.RegisterProbe(fqdn, proposedRecords)
	defer p.responder.UnregisterProbe(fqdn)

	for i := 0; i < p.opts.ProbeCount; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := p.responder.SendProbe(fqdn, proposedRecords); err != nil {
			klog.Warningf("failed to send probe for %s: %v", fqdn, err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(p.opts.ProbeInterval):
		}
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	p.mu.Lock()
	st, ok := p.names[fqdn]
	if !ok || st.state != StateProbing {
		p.mu.Unlock()
		return
	}

	st.state = StatePublished
	st.cancelProbe = nil

	var a []net.IP
	var aaaa []net.IP
	for _, ip := range st.addresses {
		if ip.To4() != nil {
			a = append(a, ip.To4())
		} else if ip.To16() != nil {
			aaaa = append(aaaa, ip.To16())
		}
	}

	p.responder.SetRecord(&RecordSet{
		FQDN: fqdn,
		A:    a,
		AAAA: aaaa,
		TTL:  p.opts.TTL,
	})
	records := append([]dnsmessage.Resource(nil), st.records...)
	onStateChange := p.opts.OnStateChange
	p.mu.Unlock()

	if err := p.responder.SendAnnouncement(records); err != nil {
		klog.Warningf("failed to send initial announcement for %s: %v", fqdn, err)
	}
	go func() {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.opts.AnnounceInterval):
			p.mu.RLock()
			entry, exists := p.names[fqdn]
			stillPublished := exists && entry.state == StatePublished
			p.mu.RUnlock()
			if stillPublished {
				if err := p.responder.SendAnnouncement(records); err != nil {
					klog.Warningf("failed to send repeat announcement for %s: %v", fqdn, err)
				}
			}
		}
	}()

	if onStateChange != nil {
		onStateChange(fqdn, StatePublished)
	}
}

// BuildRecords creates A and AAAA dnsmessage.Resource records for the given FQDN and IP addresses.
func BuildRecords(fqdn string, addrs []net.IP, ttl uint32) ([]dnsmessage.Resource, error) {
	name, err := dnsmessage.NewName(ToFQDN(fqdn))
	if err != nil {
		return nil, fmt.Errorf("invalid fqdn %q: %w", fqdn, err)
	}
	var records []dnsmessage.Resource
	for _, ip := range addrs {
		if ip4 := ip.To4(); ip4 != nil {
			var a [4]byte
			copy(a[:], ip4)
			records = append(records, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
					TTL:   ttl,
				},
				Body: &dnsmessage.AResource{A: a},
			})
		} else if ip6 := ip.To16(); ip6 != nil {
			var aaaa [16]byte
			copy(aaaa[:], ip6)
			records = append(records, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | CacheFlushBit),
					TTL:   ttl,
				},
				Body: &dnsmessage.AAAAResource{AAAA: aaaa},
			})
		}
	}
	return records, nil
}

func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
