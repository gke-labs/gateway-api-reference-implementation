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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// Documented listener conditions for mDNS publishing.
const (
	// ConditionTypePublished is the condition type indicating whether the listener's hostname is published via mDNS.
	ConditionTypePublished gatewayv1.ListenerConditionType = "Published"

	// ConditionReasonPublished indicates the hostname was successfully claimed and is actively published.
	ConditionReasonPublished gatewayv1.ListenerConditionReason = "Published"

	// ConditionReasonHostnameConflict indicates probing or active conflict detection observed another host on the LAN answering for this name.
	ConditionReasonHostnameConflict gatewayv1.ListenerConditionReason = "HostnameConflict"

	// ConditionReasonProbing indicates the hostname is actively probing for conflicts before publishing.
	ConditionReasonProbing gatewayv1.ListenerConditionReason = "Probing"

	// ConditionReasonNotProgrammed indicates the listener is not Programmed.
	ConditionReasonNotProgrammed gatewayv1.ListenerConditionReason = "NotProgrammed"

	// ConditionReasonUnsupportedHostname indicates the hostname does not conform to localgateway's single-label .local rules.
	ConditionReasonUnsupportedHostname gatewayv1.ListenerConditionReason = "UnsupportedHostname"
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

// AddressProvider queries LAN addresses for a Gateway.
type AddressProvider interface {
	GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error)
}

// PublisherOptions configures the mDNS Publisher.
type PublisherOptions struct {
	// Interface is the network interface to bind and publish on (e.g. "eth0" or "lo").
	Interface string

	// Port is the UDP port (defaults to 5353).
	Port int

	// Ephemeral indicates that an ephemeral port (:0) should be bound rather than DefaultPort.
	Ephemeral bool

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

	// DisableIPv6 disables IPv6 multicast even if available.
	DisableIPv6 bool

	// IPv4Conn is an optional pre-bound PacketConn (useful for testing).
	IPv4Conn net.PacketConn

	// IPv6Conn is an optional pre-bound PacketConn (useful for testing).
	IPv6Conn net.PacketConn

	// AddressProvider optionally resolves node LAN IP addresses for Gateways during data-plane updates.
	AddressProvider AddressProvider

	// EnqueueGateway is called when publication state changes to request a Gateway reconciliation.
	EnqueueGateway func(req types.NamespacedName)

	// Responder is an optional custom Responder instance (useful for testing).
	Responder *Responder

	// MulticastTap is an optional callback receiving every multicast DNS packet sent.
	MulticastTap func(raw []byte)
}

type listenerKey struct {
	gw       types.NamespacedName
	listener gatewayv1.SectionName
}

type hostnamePublicationState struct {
	fqdn            string // canonical lower-case with trailing dot
	hostname        string // raw hostname
	state           HostnameState
	addresses       []net.IP
	records         []dnsmessage.Resource
	conflictReason  string
	conflictMessage string
	lastConflict    time.Time
	cancelProbe     context.CancelFunc
	listeners       map[listenerKey]struct{}
}

// HostnamePublicationSnapshot provides a read-only snapshot of publication status for a hostname.
type HostnamePublicationSnapshot struct {
	FQDN            string
	Hostname        string
	State           HostnameState
	ConflictMessage string
}

// Publisher coordinates mDNS probing, claiming, announcing, and withdrawal of single-label .local names.
// Publishing is driven from the data-plane push (OnGatewaysUpdate); Gateway status reconciliation
// (StatusHook) reads the publisher state to populate Gateway listener conditions.
type Publisher struct {
	opts      PublisherOptions
	responder *Responder
	ownResp   bool

	mu        sync.RWMutex
	names     map[string]*hostnamePublicationState // keyed by canonical lower-case FQDN
	listeners map[listenerKey]string               // (gw, listenerName) -> FQDN
	gateways  map[types.NamespacedName]map[string]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// NewPublisher creates a new mDNS publisher.
func NewPublisher(opts PublisherOptions) (*Publisher, error) {
	if opts.Ephemeral {
		opts.Port = 0
	} else if opts.Port <= 0 && opts.Responder == nil {
		opts.Port = DefaultPort
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

	resp := opts.Responder
	ownResp := false
	if resp == nil {
		r, err := NewResponder(ResponderOptions{
			Port:          opts.Port,
			Ephemeral:     opts.Ephemeral,
			InterfaceName: opts.Interface,
			DisableIPv6:   opts.DisableIPv6,
			IPv4Conn:      opts.IPv4Conn,
			IPv6Conn:      opts.IPv6Conn,
			MulticastTap:  opts.MulticastTap,
		})
		if err != nil {
			return nil, err
		}
		resp = r
		ownResp = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{
		opts:      opts,
		responder: resp,
		ownResp:   ownResp,
		names:     make(map[string]*hostnamePublicationState),
		listeners: make(map[listenerKey]string),
		gateways:  make(map[types.NamespacedName]map[string]struct{}),
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	p.responder.SetConflictHandler(p.onConflict)

	return p, nil
}

// Responder returns the underlying mDNS Responder.
func (p *Publisher) Responder() *Responder {
	return p.responder
}

// SetEnqueueGateway sets the callback to enqueue a Gateway for reconciliation.
func (p *Publisher) SetEnqueueGateway(fn func(types.NamespacedName)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts.EnqueueGateway = fn
}

func (p *Publisher) enqueueGateways(gws []types.NamespacedName) {
	p.mu.RLock()
	fn := p.opts.EnqueueGateway
	p.mu.RUnlock()

	if fn == nil || len(gws) == 0 {
		return
	}

	seen := make(map[types.NamespacedName]bool)
	for _, gw := range gws {
		if !seen[gw] {
			seen[gw] = true
			fn(gw)
		}
	}
}

// Close stops all active probing and closes the underlying responder.
func (p *Publisher) Close() error {
	p.cancel()
	if p.ownResp {
		return p.responder.Close()
	}
	return nil
}

// Start implements manager.Runnable for controller-runtime.
func (p *Publisher) Start(ctx context.Context) error {
	defer close(p.done)

	<-ctx.Done()

	// Graceful shutdown: send goodbyes for all active published hostnames
	p.mu.Lock()
	p.cancel() // cancel all probe routines
	var allRecords []dnsmessage.Resource
	for _, st := range p.names {
		if st.state == StatePublished && len(st.records) > 0 {
			allRecords = append(allRecords, st.records...)
		}
	}
	p.mu.Unlock()

	if len(allRecords) > 0 {
		if err := p.responder.SendGoodbye(allRecords); err != nil && !isNormalClose(err) {
			klog.Warningf("failed to send goodbye packets on shutdown: %v", err)
		}
	}

	if p.ownResp {
		if err := p.responder.Close(); err != nil && !isNormalClose(err) {
			klog.Warningf("failed to close responder on shutdown: %v", err)
		}
	}

	return nil
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}

// onConflict is invoked by the Responder when a conflict is detected on the LAN
// during active probing or after publishing (RFC 6762 §9).
func (p *Publisher) onConflict(fqdn string, conflictingRR dnsmessage.Resource) {
	name := strings.ToLower(toFQDN(fqdn))

	p.mu.Lock()
	st, ok := p.names[name]
	if !ok {
		p.mu.Unlock()
		return
	}

	// If already in conflict, nothing new to do
	if st.state == StateConflict {
		p.mu.Unlock()
		return
	}

	if st.cancelProbe != nil {
		st.cancelProbe()
		st.cancelProbe = nil
	}

	// RFC 6762 §9: If already published, immediately cease answering queries
	if st.state == StatePublished {
		p.responder.RemoveRecord(name)
	}

	st.state = StateConflict
	st.lastConflict = time.Now()
	st.conflictReason = string(ConditionReasonHostnameConflict)
	st.conflictMessage = fmt.Sprintf("Hostname %q conflicts with another host on the LAN: %v", st.hostname, conflictingRR)

	var affectedGWs []types.NamespacedName
	for lk := range st.listeners {
		affectedGWs = append(affectedGWs, lk.gw)
	}
	p.mu.Unlock()

	// Enqueue reconciles for affected gateways to update conditions
	p.enqueueGateways(affectedGWs)

	// Schedule retry after conflict retry interval
	go func() {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.opts.ConflictRetryInterval):
			p.retryConflict(name)
		}
	}()
}

func (p *Publisher) retryConflict(fqdn string) {
	p.mu.Lock()
	st, ok := p.names[fqdn]
	if !ok || st.state != StateConflict {
		p.mu.Unlock()
		return
	}

	if len(st.listeners) == 0 {
		delete(p.names, fqdn)
		p.mu.Unlock()
		return
	}

	st.state = StateProbing
	st.conflictReason = ""
	st.conflictMessage = ""

	probeCtx, cancel := context.WithCancel(p.ctx)
	st.cancelProbe = cancel
	records := append([]dnsmessage.Resource(nil), st.records...)
	var gws []types.NamespacedName
	for lk := range st.listeners {
		gws = append(gws, lk.gw)
	}
	p.mu.Unlock()

	go p.runProbe(probeCtx, fqdn, records, gws)
}

// OnGatewaysUpdate drives mDNS publishing from the data-plane push.
// Whenever GARI pushes updated configuration to the proxy, this hook synchronizes
// the published records, launches probes, re-announces address updates, and sends goodbyes for removed names.
func (p *Publisher) OnGatewaysUpdate(gateways []*gatewayv1.Gateway) {
	activeGWs := make(map[types.NamespacedName]bool)

	for _, gw := range gateways {
		if gw == nil {
			continue
		}
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		activeGWs[gwKey] = true

		// 1. Resolve LAN IP addresses from AddressProvider or Gateway status
		var ips []net.IP
		if p.opts.AddressProvider != nil {
			addrs, ready, err := p.opts.AddressProvider.GatewayAddresses(p.ctx, gw, nil)
			if err == nil && ready {
				for _, a := range addrs {
					if ip := net.ParseIP(a.Value); ip != nil {
						ips = append(ips, ip)
					}
				}
			}
		}
		if len(ips) == 0 {
			for _, a := range gw.Status.Addresses {
				if ip := net.ParseIP(a.Value); ip != nil {
					ips = append(ips, ip)
				}
			}
		}

		currentGWFQDNs := make(map[string]struct{})
		currentGWListeners := make(map[gatewayv1.SectionName]struct{})

		// 2. Evaluate listeners for single-label .local HTTP names
		for _, l := range gw.Spec.Listeners {
			if l.Protocol != gatewayv1.HTTPProtocolType {
				continue
			}
			if l.Hostname == nil {
				continue
			}
			rawHostname := string(*l.Hostname)
			if err := validation.ValidateSingleLabelLocalHostname(rawHostname); err != nil {
				continue
			}

			currentGWListeners[l.Name] = struct{}{}
			fqdn := strings.ToLower(toFQDN(rawHostname))
			currentGWFQDNs[fqdn] = struct{}{}
			lk := listenerKey{gw: gwKey, listener: l.Name}

			p.syncListener(lk, rawHostname, fqdn, ips)
		}

		// 3. Clean up any listeners that were removed from this Gateway
		p.mu.Lock()
		p.gateways[gwKey] = currentGWFQDNs
		var removedLKs []listenerKey
		for lk := range p.listeners {
			if lk.gw == gwKey {
				if _, stillPresent := currentGWListeners[lk.listener]; !stillPresent {
					removedLKs = append(removedLKs, lk)
				}
			}
		}
		for _, lk := range removedLKs {
			p.untrackListenerLocked(lk)
		}
		p.mu.Unlock()
	}

	// 4. Handle deleted Gateways
	p.mu.Lock()
	var deletedGWs []types.NamespacedName
	for gwKey := range p.gateways {
		if !activeGWs[gwKey] {
			deletedGWs = append(deletedGWs, gwKey)
		}
	}
	for _, gwKey := range deletedGWs {
		delete(p.gateways, gwKey)
		for lk := range p.listeners {
			if lk.gw == gwKey {
				p.untrackListenerLocked(lk)
			}
		}
	}
	p.mu.Unlock()
}

// StatusHook is localgateway's implementation of gari.Options.GatewayStatusHook.
// It is strictly read-only on the publisher, projecting the current mDNS publication state
// into Gateway listener status conditions.
func (p *Publisher) StatusHook(ctx context.Context, gw *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
	if gw == nil || status == nil {
		return nil
	}

	specListeners := make(map[gatewayv1.SectionName]gatewayv1.Listener)
	for _, l := range gw.Spec.Listeners {
		specListeners[l.Name] = l
	}

	for i := range status.Listeners {
		lisStatus := &status.Listeners[i]
		spec, ok := specListeners[lisStatus.Name]
		if !ok {
			continue
		}

		rawHostname := ""
		if spec.Hostname != nil {
			rawHostname = string(*spec.Hostname)
		}

		// Validation check
		if err := validation.ValidateSingleLabelLocalHostname(rawHostname); err != nil {
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionFalse,
				string(ConditionReasonUnsupportedHostname),
				fmt.Sprintf("Hostname %q does not conform to single-label .local rules: %v", rawHostname, err),
				gw.Generation,
			))
			continue
		}

		// Programmed check
		isProgrammed := false
		progCond := state.FindCondition(lisStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
		if progCond != nil && progCond.Status == metav1.ConditionTrue {
			isProgrammed = true
		}

		if !isProgrammed {
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionFalse,
				string(ConditionReasonNotProgrammed),
				"Listener is not programmed; hostname will not be published via mDNS",
				gw.Generation,
			))
			continue
		}

		// Read publisher state for this hostname
		fqdn := strings.ToLower(toFQDN(rawHostname))
		pubState, found := p.GetHostnameState(fqdn)
		if !found {
			// If not yet picked up by OnGatewaysUpdate, report Probing
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionFalse,
				string(ConditionReasonProbing),
				fmt.Sprintf("Probing hostname %s via mDNS", rawHostname),
				gw.Generation,
			))
			continue
		}

		switch pubState.State {
		case StatePublished:
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionTrue,
				string(ConditionReasonPublished),
				fmt.Sprintf("Hostname %s published via mDNS on interface %q", rawHostname, p.opts.Interface),
				gw.Generation,
			))
		case StateConflict:
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionFalse,
				string(ConditionReasonHostnameConflict),
				pubState.ConflictMessage,
				gw.Generation,
			))
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(gatewayv1.ListenerConditionConflicted),
				metav1.ConditionTrue,
				string(gatewayv1.ListenerReasonHostnameConflict),
				pubState.ConflictMessage,
				gw.Generation,
			))
		case StateProbing:
			state.SetCondition(&lisStatus.Conditions, state.NewCondition(
				string(ConditionTypePublished),
				metav1.ConditionFalse,
				string(ConditionReasonProbing),
				fmt.Sprintf("Probing hostname %s via mDNS", rawHostname),
				gw.Generation,
			))
		}
	}

	return nil
}

// GetHostnameState returns a snapshot of the current publication state for a hostname.
func (p *Publisher) GetHostnameState(fqdn string) (HostnamePublicationSnapshot, bool) {
	name := strings.ToLower(toFQDN(fqdn))
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

// syncListener tracks a listener for a hostname, initiating probing or updating addresses as needed.
func (p *Publisher) syncListener(lk listenerKey, rawHostname, fqdn string, addrs []net.IP) *hostnamePublicationState {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if this listener previously pointed to a different hostname
	if oldFQDN, exists := p.listeners[lk]; exists && oldFQDN != fqdn {
		p.untrackListenerLocked(lk)
	}
	p.listeners[lk] = fqdn

	records, err := buildRecords(fqdn, addrs, p.opts.TTL)
	if err != nil {
		klog.Warningf("failed to build records for %s: %v", fqdn, err)
		return nil
	}

	st, exists := p.names[fqdn]
	if !exists {
		// Brand new hostname: start probing
		probeCtx, cancel := context.WithCancel(p.ctx)
		st = &hostnamePublicationState{
			fqdn:        fqdn,
			hostname:    rawHostname,
			state:       StateProbing,
			addresses:   append([]net.IP(nil), addrs...),
			records:     records,
			cancelProbe: cancel,
			listeners:   map[listenerKey]struct{}{lk: {}},
		}
		p.names[fqdn] = st
		go p.runProbe(probeCtx, fqdn, records, []types.NamespacedName{lk.gw})
		return st
	}

	st.listeners[lk] = struct{}{}

	// If already published and addresses changed, re-announce
	if st.state == StatePublished && !ipsEqual(st.addresses, addrs) {
		st.addresses = append([]net.IP(nil), addrs...)
		st.records = records

		var a []net.IP
		var aaaa []net.IP
		for _, ip := range addrs {
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

		if err := p.responder.SendAnnouncement(records); err != nil {
			klog.Warningf("failed to send announcement for %s: %v", fqdn, err)
		}
	}

	return st
}

func (p *Publisher) untrackListenerLocked(lk listenerKey) {
	fqdn, exists := p.listeners[lk]
	if !exists {
		return
	}
	delete(p.listeners, lk)

	st, ok := p.names[fqdn]
	if !ok {
		return
	}

	delete(st.listeners, lk)
	if len(st.listeners) == 0 {
		// No remaining listeners for this hostname: cancel probe or send goodbye
		if st.cancelProbe != nil {
			st.cancelProbe()
			st.cancelProbe = nil
		}
		if st.state == StatePublished {
			p.responder.RemoveRecord(fqdn)
			if len(st.records) > 0 {
				if err := p.responder.SendGoodbye(st.records); err != nil {
					klog.Warningf("failed to send goodbye for %s: %v", fqdn, err)
				}
			}
		}
		delete(p.names, fqdn)
	}
}

// runProbe executes RFC 6762 §8.1 probing before claiming an mDNS hostname.
func (p *Publisher) runProbe(ctx context.Context, fqdn string, proposedRecords []dnsmessage.Resource, gws []types.NamespacedName) {
	p.responder.RegisterProbe(fqdn, proposedRecords)
	defer p.responder.UnregisterProbe(fqdn)

	// Send probe packets spaced by ProbeInterval
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

	// Final wait interval after last probe before concluding claim
	select {
	case <-ctx.Done():
		return
	default:
	}

	// If no conflict was detected, claim the name!
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
	p.mu.Unlock()

	// Send initial announcements (RFC 6762 §8.3: at least two announcements)
	if err := p.responder.SendAnnouncement(records); err != nil {
		klog.Warningf("failed to send initial announcement for %s: %v", fqdn, err)
	}
	go func() {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.opts.AnnounceInterval):
			if err := p.responder.SendAnnouncement(records); err != nil {
				klog.Warningf("failed to send repeat announcement for %s: %v", fqdn, err)
			}
		}
	}()

	// Enqueue Gateway reconciliation to update conditions
	p.enqueueGateways(gws)
}

// buildRecords creates A and AAAA dnsmessage.Resource records for the given FQDN and IP addresses.
func buildRecords(fqdn string, addrs []net.IP, ttl uint32) ([]dnsmessage.Resource, error) {
	name, err := dnsmessage.NewName(toFQDN(fqdn))
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
