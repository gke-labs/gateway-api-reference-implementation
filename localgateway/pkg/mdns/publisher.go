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
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

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

// AddressProvider queries LAN addresses for a Gateway.
type AddressProvider interface {
	GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error)
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

type listenerEndpoint struct {
	fqdn      string
	addresses []net.IP
}

// Publisher coordinates mDNS publishing for Kubernetes Gateways.
// It maps Gateways and listeners to hostnames and addresses, and turns reported publication state into Gateway conditions.
// Probing and conflict handling are delegated to Prober.
type Publisher struct {
	opts      PublisherOptions
	responder *Responder
	ownResp   bool
	prober    *Prober

	mu        sync.RWMutex
	listeners map[listenerKey]listenerEndpoint // (gw, listenerName) -> endpoint
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
		listeners: make(map[listenerKey]listenerEndpoint),
		gateways:  make(map[types.NamespacedName]map[string]struct{}),
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	prober, err := NewProber(ProberOptions{
		Context:               p.ctx,
		Responder:             resp,
		TTL:                   opts.TTL,
		ProbeInterval:         opts.ProbeInterval,
		ProbeCount:            opts.ProbeCount,
		ConflictRetryInterval: opts.ConflictRetryInterval,
		AnnounceInterval:      opts.AnnounceInterval,
		OnStateChange:         p.onHostnameStateChange,
	})
	if err != nil {
		cancel()
		if ownResp {
			if closeErr := resp.Close(); closeErr != nil && !isNormalClose(closeErr) {
				klog.Warningf("failed to close responder on prober creation failure: %v", closeErr)
			}
		}
		return nil, err
	}
	p.prober = prober

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

func (p *Publisher) onHostnameStateChange(fqdn string, state HostnameState) {
	if state != StatePublished && state != StateConflict {
		return
	}

	p.mu.RLock()
	var affectedGWs []types.NamespacedName
	for lk, endpoint := range p.listeners {
		if endpoint.fqdn == fqdn {
			affectedGWs = append(affectedGWs, lk.gw)
		}
	}
	p.mu.RUnlock()

	p.enqueueGateways(affectedGWs)
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
	if err := p.prober.Shutdown(); err != nil && !isNormalClose(err) {
		klog.Warningf("failed to send goodbye packets on shutdown: %v", err)
	}

	if p.ownResp {
		if err := p.responder.Close(); err != nil && !isNormalClose(err) {
			klog.Warningf("failed to close responder on shutdown: %v", err)
		}
	}

	return nil
}

// OnGatewaysUpdate drives mDNS publishing from the data-plane push.
// Whenever GARI pushes updated configuration to the proxy, this hook synchronizes
// the published records, launches probes, re-announces address updates, and sends goodbyes for removed names.
func (p *Publisher) OnGatewaysUpdate(gateways []*gatewayv1.Gateway) {
	activeGWs := make(map[types.NamespacedName]bool)

	p.mu.Lock()
	for _, gw := range gateways {
		if gw == nil {
			continue
		}
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		activeGWs[gwKey] = true

		// 1. Resolve LAN IP addresses from AddressProvider or Gateway status
		var addresses []net.IP
		if p.opts.AddressProvider != nil {
			addrs, readiness, err := p.opts.AddressProvider.GatewayAddresses(p.ctx, gw, nil)
			if err == nil && readiness.Ready {
				for _, a := range addrs {
					if ip := net.ParseIP(a.Value); ip != nil {
						addresses = append(addresses, ip)
					}
				}
			}
		}
		if len(addresses) == 0 {
			for _, a := range gw.Status.Addresses {
				if ip := net.ParseIP(a.Value); ip != nil {
					addresses = append(addresses, ip)
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
			fqdn := strings.ToLower(ToFQDN(rawHostname))
			currentGWFQDNs[fqdn] = struct{}{}
			lk := listenerKey{gw: gwKey, listener: l.Name}

			p.listeners[lk] = listenerEndpoint{
				fqdn:      fqdn,
				addresses: addresses,
			}
		}

		// 3. Clean up any listeners that were removed from this Gateway
		p.gateways[gwKey] = currentGWFQDNs
		for lk := range p.listeners {
			if lk.gw == gwKey {
				if _, stillPresent := currentGWListeners[lk.listener]; !stillPresent {
					delete(p.listeners, lk)
				}
			}
		}
	}

	// 4. Handle deleted Gateways
	for gwKey := range p.gateways {
		if !activeGWs[gwKey] {
			delete(p.gateways, gwKey)
			for lk := range p.listeners {
				if lk.gw == gwKey {
					delete(p.listeners, lk)
				}
			}
		}
	}

	// 5. Compute desired set of names with addresses deterministically by sorting listener keys
	keys := make([]listenerKey, 0, len(p.listeners))
	for lk := range p.listeners {
		keys = append(keys, lk)
	}
	slices.SortFunc(keys, func(a, b listenerKey) int {
		if c := strings.Compare(a.gw.Namespace, b.gw.Namespace); c != 0 {
			return c
		}
		if c := strings.Compare(a.gw.Name, b.gw.Name); c != 0 {
			return c
		}
		return strings.Compare(string(a.listener), string(b.listener))
	})
	desired := make(map[string][]net.IP)
	for _, lk := range keys {
		endpoint := p.listeners[lk]
		desired[endpoint.fqdn] = endpoint.addresses
	}
	p.mu.Unlock()

	p.prober.SetNames(desired)
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
		fqdn := strings.ToLower(ToFQDN(rawHostname))
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
	return p.prober.GetHostnameState(fqdn)
}
