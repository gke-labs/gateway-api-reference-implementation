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

package address

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

var (
	_ controller.AddressProvider          = (*AddressProvider)(nil)
	_ controller.AddressReadinessProvider = (*AddressProvider)(nil)
	_ controller.AddressTypeProvider      = (*AddressProvider)(nil)
	_ controller.AddressWatcher           = (*AddressProvider)(nil)
)

// Options configures an AddressProvider.
type Options struct {
	// InterfaceName is an optional network interface name to read LAN IPs from (e.g. "eth0").
	InterfaceName string

	// NodeName is an optional Kubernetes node name used to lookup node addresses when InterfaceName is unset.
	NodeName string

	// Client is the Kubernetes client used to look up Node resources when NodeName is set.
	Client client.Client

	// InterfaceAddrsFunc is an optional hook to resolve addresses for an interface by name (for testing).
	InterfaceAddrsFunc func(name string) ([]net.Addr, error)
}

// AddressProvider determines and reports the node's LAN IP addresses in Gateway status
// for localgateway's in-process data plane.
//
// Readiness approximation: reports ready as soon as the node's LAN IP addresses are resolved
// from the network interface or Node resource, assuming the co-located in-process proxy will serve traffic.
//
// Gap: reports ready based purely on address discovery, without verifying that the in-process proxy
// has bound listener ports or that the Gateway's current configuration is applied and being served.
type AddressProvider struct {
	// mu guards client, interfaceName, and nodeName from concurrent read/write access.
	mu                 sync.RWMutex
	interfaceName      string
	nodeName           string
	client             client.Client
	interfaceAddrsFunc func(name string) ([]net.Addr, error)
}

// NewAddressProvider creates a new AddressProvider.
func NewAddressProvider(opts Options) *AddressProvider {
	ap := &AddressProvider{
		interfaceName:      opts.InterfaceName,
		nodeName:           opts.NodeName,
		client:             opts.Client,
		interfaceAddrsFunc: opts.InterfaceAddrsFunc,
	}

	if ap.interfaceAddrsFunc == nil {
		ap.interfaceAddrsFunc = func(name string) ([]net.Addr, error) {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, err
			}
			return iface.Addrs()
		}
	}

	return ap
}

// SetupWatches implements controller.AddressWatcher to capture the manager's client
// for Node InternalIP resolution when --node-name is used.
func (p *AddressProvider) SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error {
	if mgr != nil {
		p.mu.Lock()
		p.client = mgr.GetClient()
		p.mu.Unlock()
	}
	return nil
}

// SupportedAddressTypes returns no supported address types because localgateway
// assigns node LAN addresses dynamically and does not support requested spec.addresses.
// Returning nil causes GARI to reject requested spec.addresses with Accepted=False and
// reason UnsupportedAddress.
func (p *AddressProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return nil
}

// GatewayAddresses returns the node's LAN IP addresses and ready status for the Gateway.
func (p *AddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	addrs, readiness, err := p.GatewayAddressesWithReadiness(ctx, gw, effectiveListeners)
	return addrs, readiness.Ready, err
}

// GatewayAddressesWithReadiness returns the node's LAN IP addresses and detailed readiness for the Gateway.
func (p *AddressProvider) GatewayAddressesWithReadiness(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	p.mu.RLock()
	ifaceName := p.interfaceName
	nodeName := p.nodeName
	cl := p.client
	ifaceAddrsFn := p.interfaceAddrsFunc
	p.mu.RUnlock()

	var ips []net.IP

	if ifaceName != "" {
		// 1. Configured interface flag
		addrs, err := ifaceAddrsFn(ifaceName)
		if err != nil {
			klog.Errorf("localgateway: failed to get addresses for interface %q: %v", ifaceName, err)
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: fmt.Sprintf("failed to get addresses for interface %q: %v", ifaceName, err),
			}, nil
		}
		ips = extractLANIPs(addrs)
		if len(ips) == 0 {
			klog.Errorf("localgateway: interface %q has no valid LAN IP addresses", ifaceName)
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: fmt.Sprintf("interface %q has no valid LAN IP addresses", ifaceName),
			}, nil
		}
	} else if nodeName != "" && cl != nil {
		// 2. Node lookup from Kubernetes API: require node's InternalIP
		node := &corev1.Node{}
		if err := cl.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
			klog.Errorf("localgateway: failed to get node %q: %v", nodeName, err)
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: fmt.Sprintf("failed to get node %q: %v", nodeName, err),
			}, nil
		}
		ips = extractNodeInternalIPs(node)
		if len(ips) == 0 {
			klog.Errorf("localgateway: node %q has no NodeInternalIP addresses in status.addresses", nodeName)
			return nil, state.GatewayReadiness{
				Ready:   false,
				Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
				Message: fmt.Sprintf("no NodeInternalIP addresses found on node %q", nodeName),
			}, nil
		}
	} else {
		// Neither interface nor node is available
		return nil, state.GatewayReadiness{
			Ready:   false,
			Reason:  string(gatewayv1.GatewayReasonAddressNotAssigned),
			Message: "either --interface or --node-name must be specified for localgateway address provider",
		}, nil
	}

	// Deduplicate and sort deterministically: IPv4 first, then IPv6
	sortedIPs := sortAndDeduplicateIPs(ips)
	var statusAddrs []gatewayv1.GatewayStatusAddress
	for _, ip := range sortedIPs {
		addrType := gatewayv1.IPAddressType
		statusAddrs = append(statusAddrs, gatewayv1.GatewayStatusAddress{
			Type:  &addrType,
			Value: ip.String(),
		})
	}

	return statusAddrs, state.GatewayReadiness{
		Ready:   true,
		Reason:  string(gatewayv1.GatewayReasonProgrammed),
		Message: "Node LAN addresses assigned",
	}, nil
}

// extractLANIPs extracts valid IPv4 and IPv6 LAN IPs from a slice of net.Addr.
func extractLANIPs(addrs []net.Addr) []net.IP {
	var ips []net.IP
	var loopbackIPs []net.IP
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			parsed := net.ParseIP(strings.TrimSpace(a.String()))
			if parsed != nil {
				ip = parsed
			}
		}

		if ip == nil {
			continue
		}

		// Skip link-local unicast (169.254.x.x / fe80::), multicast, and unspecified
		if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}

		if ip.IsLoopback() {
			loopbackIPs = append(loopbackIPs, ip)
			continue
		}

		ips = append(ips, ip)
	}

	if len(ips) == 0 && len(loopbackIPs) > 0 {
		return loopbackIPs
	}
	return ips
}

// extractNodeInternalIPs extracts InternalIP addresses from a Node.
func extractNodeInternalIPs(node *corev1.Node) []net.IP {
	var ips []net.IP
	var loopbackIPs []net.IP

	for _, addr := range node.Status.Addresses {
		if addr.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(addr.Address))
		if ip == nil || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}

		if ip.IsLoopback() {
			loopbackIPs = append(loopbackIPs, ip)
			continue
		}

		ips = append(ips, ip)
	}

	if len(ips) == 0 && len(loopbackIPs) > 0 {
		return loopbackIPs
	}
	return ips
}

// sortAndDeduplicateIPs deduplicates IPs and sorts IPv4 before IPv6, each sorted numerically.
func sortAndDeduplicateIPs(ips []net.IP) []net.IP {
	seen := make(map[string]bool)
	var v4 []net.IP
	var v6 []net.IP

	for _, ip := range ips {
		str := ip.String()
		if seen[str] {
			continue
		}
		seen[str] = true

		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	slices.SortFunc(v4, func(a, b net.IP) int {
		return bytes.Compare(a.To4(), b.To4())
	})

	slices.SortFunc(v6, func(a, b net.IP) int {
		return bytes.Compare(a.To16(), b.To16())
	})

	return append(v4, v6...)
}
