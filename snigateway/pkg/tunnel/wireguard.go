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

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
	"k8s.io/klog/v2"
)

const (
	// defaultWireGuardInterfaceName is the network interface name used for the WireGuard device.
	defaultWireGuardInterfaceName = "wg0"

	// wireguardPersistentKeepalive is the keepalive interval configured on the frontend WireGuard peer.
	wireguardPersistentKeepalive = 25 * time.Second
)

// WireGuardDevice manages peers and device lifecycle on a WireGuard network interface.
type WireGuardDevice interface {
	AddPeer(peer wireguard.Peer) error
	Close() error
}

// wireguardManager manages the WireGuard device and tunnel listener for the controller.
type wireguardManager struct {
	// deviceOpener creates a WireGuardDevice for a session (injected in tests).
	deviceOpener func(ctx context.Context, config wireguard.Config) (WireGuardDevice, error)
	// listenFunc creates a net.Listener inside the WireGuard tunnel (injected in tests).
	listenFunc func(network, address string) (net.Listener, error)
	// lastWireGuardErrMu guards lastWireGuardErr.
	lastWireGuardErrMu sync.Mutex
	// lastWireGuardErr tracks the last failure message to log each distinct error once.
	lastWireGuardErr string
}

func newWireGuardManager() *wireguardManager {
	return &wireguardManager{
		deviceOpener: func(ctx context.Context, config wireguard.Config) (WireGuardDevice, error) {
			return wireguard.OpenDevice(ctx, config)
		},
		listenFunc: net.Listen,
	}
}

// WithWireGuardDeviceOpener sets a custom opener for the WireGuard device.
func WithWireGuardDeviceOpener(opener func(ctx context.Context, config wireguard.Config) (WireGuardDevice, error)) ManagerOption {
	return func(m *Manager) {
		if m.wireguard != nil {
			m.wireguard.deviceOpener = opener
		}
	}
}

// WithListenFunc sets a custom network listener function.
func WithListenFunc(fn func(network, address string) (net.Listener, error)) ManagerOption {
	return func(m *Manager) {
		if m.wireguard != nil {
			m.wireguard.listenFunc = fn
		}
	}
}

// logWireGuardError logs a WireGuard setup error at error level on its first occurrence,
// remaining quiet for repeated occurrences until a session connects successfully.
func (m *wireguardManager) logWireGuardError(sessionID, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	m.lastWireGuardErrMu.Lock()
	defer m.lastWireGuardErrMu.Unlock()
	if message == m.lastWireGuardErr {
		return
	}
	m.lastWireGuardErr = message
	klog.Errorf("%s for session %s", message, sessionID)
}

// remoteIPFromAddr extracts the remote IP address from a net.Addr.
func remoteIPFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch addrType := addr.(type) {
	case *net.TCPAddr:
		return addrType.IP
	case *net.UDPAddr:
		return addrType.IP
	case *net.IPAddr:
		return addrType.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return net.ParseIP(addr.String())
		}
		return net.ParseIP(host)
	}
}

// validateWireGuardResponse checks that the frontend's WireGuard response contains valid parameters:
// the port is in range (1-65535), the prefix is an IPv6 /64 with zero host bits, the peer address
// is a valid IPv6 address inside the prefix, and the peer address does not conflict with the frontend's tunnel address.
func validateWireGuardResponse(response *api.WireGuardResponse) (net.IP, *net.IPNet, net.IP, error) {
	if response.Port <= 0 || response.Port > 65535 {
		return nil, nil, nil, fmt.Errorf("port %d is out of range (must be 1-65535)", response.Port)
	}

	prefixIP, prefixNet, err := net.ParseCIDR(response.Prefix)
	if err != nil || prefixIP == nil || prefixNet == nil {
		return nil, nil, nil, fmt.Errorf("invalid prefix %q: %w", response.Prefix, err)
	}
	if prefixIP.To4() != nil || prefixIP.To16() == nil {
		return nil, nil, nil, fmt.Errorf("prefix %q must be an IPv6 prefix", response.Prefix)
	}
	ones, bits := prefixNet.Mask.Size()
	if ones != 64 || bits != 128 {
		return nil, nil, nil, fmt.Errorf("prefix %q must be a /64 prefix (got /%d)", response.Prefix, ones)
	}
	if !prefixIP.Equal(prefixNet.IP) {
		return nil, nil, nil, fmt.Errorf("prefix %q must have zero host bits", response.Prefix)
	}

	peerIP := net.ParseIP(response.PeerAddress)
	if peerIP == nil {
		return nil, nil, nil, fmt.Errorf("invalid peer address %q", response.PeerAddress)
	}
	if peerIP.To4() != nil || peerIP.To16() == nil {
		return nil, nil, nil, fmt.Errorf("peer address %q must be an IPv6 address", response.PeerAddress)
	}
	if !prefixNet.Contains(peerIP) {
		return nil, nil, nil, fmt.Errorf("peer address %s is not within prefix %s", response.PeerAddress, response.Prefix)
	}

	frontendTunnelIP := make(net.IP, 16)
	copy(frontendTunnelIP, prefixNet.IP.To16())
	frontendTunnelIP[15] = 1

	if peerIP.Equal(frontendTunnelIP) {
		return nil, nil, nil, fmt.Errorf("peer address %s conflicts with frontend tunnel address", response.PeerAddress)
	}

	return peerIP, prefixNet, frontendTunnelIP, nil
}

// setupWireGuard establishes the WireGuard device and tunnel listener for the session.
// It returns a cleanup function that closes the listener and device when the session ends.
// If WireGuard setup fails, it returns an error.
func (m *wireguardManager) setupWireGuard(ctx context.Context, sessionID string, snigatewayClient *client.Client, handleConn func(net.Conn) error) (func(), error) {
	privateKey, publicKey, err := wireguard.GenerateKey()
	if err != nil {
		m.logWireGuardError(sessionID, "Failed to generate WireGuard key: %v", err)
		return nil, fmt.Errorf("generating WireGuard key: %w", err)
	}

	wireguardResponse, err := snigatewayClient.ExchangeWireGuard(ctx, sessionID, publicKey.String())
	if err != nil {
		if errors.Is(err, client.ErrWireGuardDisabled) {
			m.logWireGuardError(sessionID, "Frontend has WireGuard disabled: %v", err)
		} else {
			m.logWireGuardError(sessionID, "Failed to exchange WireGuard key with frontend: %v", err)
		}
		return nil, fmt.Errorf("exchanging WireGuard key with frontend: %w", err)
	}

	peerIP, prefixNet, frontendTunnelIP, err := validateWireGuardResponse(wireguardResponse)
	if err != nil {
		m.logWireGuardError(sessionID, "Invalid WireGuard configuration from frontend: %v", err)
		return nil, fmt.Errorf("validating WireGuard response: %w", err)
	}

	device, err := m.deviceOpener(ctx, wireguard.Config{
		InterfaceName: defaultWireGuardInterfaceName,
		PrivateKey:    privateKey,
		ListenPort:    0,
		DeviceAddress: peerIP,
		TunnelPrefix:  prefixNet,
	})
	if err != nil {
		m.logWireGuardError(sessionID, "Failed to open WireGuard device: %v", err)
		return nil, fmt.Errorf("opening WireGuard device: %w", err)
	}

	setupSucceeded := false
	defer func() {
		if !setupSucceeded {
			if closeErr := device.Close(); closeErr != nil {
				klog.Errorf("Failed to close WireGuard device for session %s: %v (a device that is not deleted will make the next session's OpenDevice fail)", sessionID, closeErr)
			}
		}
	}()

	frontendPublicKey, err := wireguard.ParseKey(wireguardResponse.PublicKey)
	if err != nil {
		m.logWireGuardError(sessionID, "Failed to parse frontend WireGuard public key %q: %v", wireguardResponse.PublicKey, err)
		return nil, fmt.Errorf("parsing frontend WireGuard public key: %w", err)
	}

	frontendHost := ParseFrontendHost(snigatewayClient.ServerAddr())
	frontendEndpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(frontendHost, strconv.Itoa(wireguardResponse.Port)))
	if err != nil {
		m.logWireGuardError(sessionID, "Failed to resolve frontend UDP endpoint %s:%d: %v", frontendHost, wireguardResponse.Port, err)
		return nil, fmt.Errorf("resolving frontend UDP endpoint: %w", err)
	}

	keepalive := wireguardPersistentKeepalive
	peer := wireguard.Peer{
		PublicKey:           frontendPublicKey,
		Endpoint:            frontendEndpoint,
		AllowedIPs:          []net.IPNet{{IP: frontendTunnelIP, Mask: net.CIDRMask(128, 128)}},
		PersistentKeepalive: &keepalive,
	}
	if err := device.AddPeer(peer); err != nil {
		m.logWireGuardError(sessionID, "Failed to add frontend WireGuard peer: %v", err)
		return nil, fmt.Errorf("adding frontend WireGuard peer: %w", err)
	}

	tunnelAddr := net.JoinHostPort(wireguardResponse.PeerAddress, strconv.Itoa(api.WireGuardTunnelPort))
	listener, err := m.listenFunc("tcp", tunnelAddr)
	if err != nil {
		m.logWireGuardError(sessionID, "Failed to listen on WireGuard address %s: %v", tunnelAddr, err)
		return nil, fmt.Errorf("listening on WireGuard address: %w", err)
	}

	// Session setup succeeded; disarm deferred device close and clear last error so future failures will be logged.
	setupSucceeded = true
	m.lastWireGuardErrMu.Lock()
	m.lastWireGuardErr = ""
	m.lastWireGuardErrMu.Unlock()

	klog.Infof("Listening on WireGuard tunnel address %s for session %s", tunnelAddr, sessionID)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			remoteIP := remoteIPFromAddr(conn.RemoteAddr())
			if remoteIP == nil || !remoteIP.Equal(frontendTunnelIP) {
				klog.Errorf("Tunnel listener rejected connection from unauthorized remote address %s (expected frontend tunnel address %s)", conn.RemoteAddr(), frontendTunnelIP)
				closeConn(conn)
				continue
			}

			go func(conn net.Conn) {
				// handleTunnelConn closes conn on error.
				if err := handleConn(conn); err != nil {
					return
				}
			}(conn)
		}
	}()

	return func() {
		closeConn(listener)
		if closeErr := device.Close(); closeErr != nil {
			klog.Errorf("Failed to close WireGuard device for session %s: %v (a device that is not deleted will make the next session's OpenDevice fail)", sessionID, closeErr)
		}
	}, nil
}
