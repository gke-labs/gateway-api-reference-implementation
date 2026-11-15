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
	// FQDN is the canonical lower-case hostname ending with a trailing dot.
	FQDN string

	// Hostname is the raw hostname without a trailing dot.
	Hostname string

	// State is the current publication state of the hostname.
	State HostnameState

	// ConflictMessage describes the LAN conflict when State is StateConflict.
	ConflictMessage string
}

// ProberOptions configures the mDNS Prober.
type ProberOptions struct {
	// Context is an optional parent context for background probe routines.
	Context context.Context

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
	// The prober calls OnStateChange without holding its lock, and reports StatePublished and StateConflict only.
	OnStateChange func(fqdn string, state HostnameState)
}

type proberEntry struct {
	// fqdn is the canonical lower-case hostname ending with a trailing dot.
	fqdn string

	// hostname is the raw hostname without a trailing dot.
	hostname string

	// state is the current publication state of this hostname.
	state HostnameState

	// addresses contains the IP addresses published for this hostname.
	addresses []net.IP

	// records contains the compiled DNS resource records for this hostname.
	records []dnsmessage.Resource

	// conflictMessage describes the LAN conflict when state is StateConflict.
	conflictMessage string

	// lastConflict is the timestamp of the most recent conflict event.
	lastConflict time.Time

	// cancelProbe cancels the active probe context for this entry, if probing.
	cancelProbe context.CancelFunc
}

// Prober manages mDNS probing, claiming, announcing, conflict resolution, and withdrawal
// for a set of hostnames without any dependency on Kubernetes or Gateway API types.
type Prober struct {
	// opts holds configuration options for the prober.
	opts ProberOptions

	// responder is the mDNS responder used to send packets and answer queries.
	responder *Responder

	// mu guards names and serializes state transitions.
	mu sync.RWMutex

	// names maps canonical lower-case FQDNs to their publication state entries.
	names map[string]*proberEntry

	// ctx is the root context cancelled on shutdown.
	ctx context.Context

	// cancel cancels ctx to terminate background probe routines.
	cancel context.CancelFunc

	// shutdownOnce ensures Shutdown executes only once.
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

	parentContext := opts.Context
	if parentContext == nil {
		parentContext = context.Background()
	}
	ctx, cancel := context.WithCancel(parentContext)
	prober := &Prober{
		opts:      opts,
		responder: opts.Responder,
		names:     make(map[string]*proberEntry),
		ctx:       ctx,
		cancel:    cancel,
	}

	prober.responder.SetConflictHandler(prober.onConflict)

	return prober, nil
}

// SetNames updates the active set of hostnames and their addresses.
// New names are probed and announced. Names with changed addresses are re-announced.
// Names no longer in the set are withdrawn with goodbye packets.
func (p *Prober) SetNames(names map[string][]net.IP) {
	desired := make(map[string][]net.IP, len(names))
	rawHostnames := make(map[string]string, len(names))
	for name, addresses := range names {
		fqdn := strings.ToLower(ToFQDN(name))
		desired[fqdn] = addresses
		rawHostnames[fqdn] = strings.TrimSuffix(name, ".")
	}

	p.mu.Lock()
	// 1. Withdraw names that are no longer in the set
	var goodbyes []dnsmessage.Resource
	for fqdn, entry := range p.names {
		if _, ok := desired[fqdn]; !ok {
			if entry.cancelProbe != nil {
				entry.cancelProbe()
				entry.cancelProbe = nil
			}
			if entry.state == StatePublished {
				p.responder.RemoveRecord(fqdn)
				if len(entry.records) > 0 {
					goodbyes = append(goodbyes, entry.records...)
				}
			}
			delete(p.names, fqdn)
		}
	}

	// 2. Add new names or update existing names
	type pendingProbe struct {
		ctx     context.Context
		fqdn    string
		records []dnsmessage.Resource
	}
	var probesToStart []pendingProbe
	var announcementsToStart [][]dnsmessage.Resource

	for fqdn, addresses := range desired {
		records, err := BuildRecords(fqdn, addresses, p.opts.TTL)
		if err != nil {
			klog.Warningf("failed to build records for %s: %v", fqdn, err)
			continue
		}

		entry, exists := p.names[fqdn]
		if !exists {
			probeCtx, cancel := context.WithCancel(p.ctx)
			entry = &proberEntry{
				fqdn:        fqdn,
				hostname:    rawHostnames[fqdn],
				state:       StateProbing,
				addresses:   append([]net.IP(nil), addresses...),
				records:     records,
				cancelProbe: cancel,
			}
			p.names[fqdn] = entry
			probesToStart = append(probesToStart, pendingProbe{
				ctx:     probeCtx,
				fqdn:    fqdn,
				records: records,
			})
			continue
		}

		// Existing entry: check if addresses changed
		if !ipsEqual(entry.addresses, addresses) {
			entry.addresses = append([]net.IP(nil), addresses...)
			entry.records = records

			if entry.state == StatePublished {
				var a []net.IP
				var aaaa []net.IP
				for _, ip := range addresses {
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
				announcementsToStart = append(announcementsToStart, records)
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
	for _, records := range announcementsToStart {
		if err := p.responder.SendAnnouncement(records); err != nil {
			klog.Warningf("failed to send announcement: %v", err)
		}
	}
	for _, probe := range probesToStart {
		go p.runProbe(probe.ctx, probe.fqdn, probe.records)
	}
}

// GetHostnameState returns a snapshot of the current publication state for a hostname.
func (p *Prober) GetHostnameState(fqdn string) (HostnamePublicationSnapshot, bool) {
	name := strings.ToLower(ToFQDN(fqdn))
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.names[name]
	if !ok {
		return HostnamePublicationSnapshot{}, false
	}
	return HostnamePublicationSnapshot{
		FQDN:            entry.fqdn,
		Hostname:        entry.hostname,
		State:           entry.state,
		ConflictMessage: entry.conflictMessage,
	}, true
}

// Shutdown cancels active probes and sends goodbye packets for all published names.
// It leaves records and names in place so that callers can continue to inspect the last state.
func (p *Prober) Shutdown() error {
	var err error
	p.shutdownOnce.Do(func() {
		p.cancel()
		p.responder.SetConflictHandler(nil)

		p.mu.Lock()
		var allRecords []dnsmessage.Resource
		for _, entry := range p.names {
			if entry.state == StatePublished && len(entry.records) > 0 {
				allRecords = append(allRecords, entry.records...)
			}
		}
		p.mu.Unlock()

		if len(allRecords) > 0 {
			if goodbyeErr := p.responder.SendGoodbye(allRecords); goodbyeErr != nil && !isNormalClose(goodbyeErr) {
				klog.Warningf("failed to send goodbye packets on shutdown: %v", goodbyeErr)
				err = goodbyeErr
			}
		}
	})
	return err
}

// onConflict is invoked by the Responder when a conflict is detected on the LAN.
func (p *Prober) onConflict(fqdn string, conflictingRR dnsmessage.Resource) {
	name := strings.ToLower(ToFQDN(fqdn))

	p.mu.Lock()
	entry, ok := p.names[name]
	if !ok {
		p.mu.Unlock()
		return
	}

	if entry.state == StateConflict {
		p.mu.Unlock()
		return
	}

	if entry.cancelProbe != nil {
		entry.cancelProbe()
		entry.cancelProbe = nil
	}

	if entry.state == StatePublished {
		p.responder.RemoveRecord(name)
	}

	entry.state = StateConflict
	entry.lastConflict = time.Now()
	entry.conflictMessage = fmt.Sprintf("Hostname %q conflicts with another host on the LAN: %v", entry.hostname, conflictingRR)
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
	entry, ok := p.names[fqdn]
	if !ok || entry.state != StateConflict {
		p.mu.Unlock()
		return
	}

	entry.state = StateProbing
	entry.conflictMessage = ""

	probeCtx, cancel := context.WithCancel(p.ctx)
	entry.cancelProbe = cancel
	records := append([]dnsmessage.Resource(nil), entry.records...)
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
	entry, ok := p.names[fqdn]
	if !ok || entry.state != StateProbing {
		p.mu.Unlock()
		return
	}

	entry.state = StatePublished
	entry.cancelProbe = nil

	var a []net.IP
	var aaaa []net.IP
	for _, ip := range entry.addresses {
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
	records := append([]dnsmessage.Resource(nil), entry.records...)
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
			currentEntry, exists := p.names[fqdn]
			var repeatRecords []dnsmessage.Resource
			if exists && currentEntry.state == StatePublished {
				repeatRecords = append([]dnsmessage.Resource(nil), currentEntry.records...)
			}
			p.mu.RUnlock()
			if len(repeatRecords) > 0 {
				if err := p.responder.SendAnnouncement(repeatRecords); err != nil {
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
