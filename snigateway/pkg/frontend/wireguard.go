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

package frontend

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
	"k8s.io/klog/v2"
)

// WireGuardDevice manages peers on a WireGuard network interface.
type WireGuardDevice interface {
	AddPeer(peer wireguard.Peer) error
	RemovePeer(publicKey wireguard.Key) error
}

// wireguardPeer holds the WireGuard key and allocated IPv6 address for a session.
type wireguardPeer struct {
	// publicKey is the WireGuard public key of the client peer.
	publicKey wireguard.Key
	// address is the IPv6 tunnel address allocated to the client peer.
	address net.IP
}

// WireGuardManager manages the WireGuard device, peer allocations, and per-session keys.
type WireGuardManager struct {
	// mu guards peersBySession and sessionsByKey. It is not held on the data path.
	mu sync.Mutex

	// device is the underlying WireGuard device on which peers are added and removed.
	device WireGuardDevice
	// publicKey is the frontend WireGuard interface's public key.
	publicKey wireguard.Key
	// port is the UDP port the frontend WireGuard interface listens on.
	port int
	// prefix is the IPv6 /64 prefix for addresses inside the WireGuard tunnel.
	prefix *net.IPNet
	// table is the registration table tracking active sessions and identities.
	table *RegistrationTable

	// peersBySession maps each active session ID to its allocated WireGuard peer.
	peersBySession map[string]wireguardPeer
	// sessionsByKey indexes each registered WireGuard public key to its owning session ID.
	sessionsByKey map[wireguard.Key]string
}

// NewWireGuardManager creates a new WireGuardManager.
func NewWireGuardManager(device WireGuardDevice, publicKey wireguard.Key, port int, prefix *net.IPNet, table *RegistrationTable) *WireGuardManager {
	if device == nil || prefix == nil {
		return nil
	}
	return &WireGuardManager{
		device:         device,
		publicKey:      publicKey,
		port:           port,
		prefix:         prefix,
		table:          table,
		peersBySession: make(map[string]wireguardPeer),
		sessionsByKey:  make(map[wireguard.Key]string),
	}
}

// RemoveSession removes any WireGuard peer and frees the address for the given session.
func (m *WireGuardManager) RemoveSession(sessionID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, ok := m.peersBySession[sessionID]
	if !ok {
		return
	}
	delete(m.sessionsByKey, peer.publicKey)
	delete(m.peersBySession, sessionID)

	if err := m.device.RemovePeer(peer.publicKey); err != nil {
		klog.Errorf("Frontend: failed to remove WireGuard peer %s for session %s: %v", peer.publicKey, sessionID, err)
	}
}

func (m *WireGuardManager) isAddressUsedLocked(address net.IP) bool {
	for _, peer := range m.peersBySession {
		if peer.address.Equal(address) {
			return true
		}
	}
	return false
}

func (m *WireGuardManager) allocateAddressLocked() (net.IP, error) {
	base := m.prefix.IP.To16()
	if base == nil {
		return nil, errors.New("invalid wireguard prefix")
	}
	for host := uint64(2); host < math.MaxUint64; host++ {
		address := make(net.IP, 16)
		copy(address, base)
		binary.BigEndian.PutUint64(address[8:], host)
		if !m.isAddressUsedLocked(address) {
			return address, nil
		}
	}
	return nil, errors.New("no free wireguard addresses in prefix")
}

var (
	errSessionNotFound  = errors.New("session not found or expired")
	errIdentityMismatch = errors.New("session identity mismatch")
	errKeyInUse         = errors.New("public key already in use by another session")
)

// ConfigureSessionPeer allocates or preserves a peer address and installs the peer key.
// The session existence and identity check happens under mu because CloseSession removes
// the session from the table before it calls RemoveSession, so a session that ends during
// the exchange is either not found or has its peer removed afterwards.
func (m *WireGuardManager) ConfigureSessionPeer(sessionID string, clientIdentity ClientIdentity, clientPublicKey wireguard.Key) (api.WireGuardResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Verify session still exists and identity matches while holding the lock.
	sessIdentity, ok := m.table.GetSessionIdentity(sessionID)
	if !ok {
		return api.WireGuardResponse{}, errSessionNotFound
	}
	if sessIdentity.ID != clientIdentity.ID {
		return api.WireGuardResponse{}, errIdentityMismatch
	}

	// Check if this public key is already in use by a different session.
	if existingSession, inUse := m.sessionsByKey[clientPublicKey]; inUse && existingSession != sessionID {
		return api.WireGuardResponse{}, errKeyInUse
	}

	existingPeer, hasExisting := m.peersBySession[sessionID]
	peerAddress := existingPeer.address
	if !hasExisting {
		allocatedAddress, err := m.allocateAddressLocked()
		if err != nil {
			return api.WireGuardResponse{}, err
		}
		peerAddress = allocatedAddress
	}

	// Add the new peer to the device first before removing any old peer.
	newPeer := wireguard.Peer{
		PublicKey: clientPublicKey,
		AllowedIPs: []net.IPNet{
			{
				IP:   peerAddress,
				Mask: net.CIDRMask(128, 128),
			},
		},
	}
	if err := m.device.AddPeer(newPeer); err != nil {
		return api.WireGuardResponse{}, fmt.Errorf("adding wireguard peer: %w", err)
	}

	// If replacing an existing key for the same session, remove the old peer after AddPeer succeeds.
	if hasExisting && existingPeer.publicKey != clientPublicKey {
		if err := m.device.RemovePeer(existingPeer.publicKey); err != nil {
			klog.Errorf("Frontend: failed to remove old wireguard peer %s for session %s: %v", existingPeer.publicKey, sessionID, err)
		}
		delete(m.sessionsByKey, existingPeer.publicKey)
	}

	m.peersBySession[sessionID] = wireguardPeer{
		publicKey: clientPublicKey,
		address:   peerAddress,
	}
	m.sessionsByKey[clientPublicKey] = sessionID

	return api.WireGuardResponse{
		PublicKey:   m.publicKey.String(),
		Port:        m.port,
		PeerAddress: peerAddress.String(),
		Prefix:      m.prefix.String(),
	}, nil
}
