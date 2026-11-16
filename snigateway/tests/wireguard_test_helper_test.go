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

package tests

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

type fakeWireGuardDevice struct {
	mu    sync.Mutex
	peers map[wireguard.Key]wireguard.Peer
}

func newFakeWireGuardDevice() *fakeWireGuardDevice {
	return &fakeWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
}

func (f *fakeWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeWireGuardDevice) RemovePeer(key wireguard.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}

func (f *fakeWireGuardDevice) Close() error {
	return nil
}

type fakeTunnelConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *fakeTunnelConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

type fakeTunnelListener struct {
	net.Listener
	defaultRemoteIP net.IP
}

func (l *fakeTunnelListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fakeTunnelConn{
		Conn:       conn,
		remoteAddr: &net.TCPAddr{IP: l.defaultRemoteIP, Port: 51820},
	}, nil
}

func setupTestWireGuardPair(t *testing.T) (func(*frontend.ServerConfig), []tunnel.ManagerOption) {
	t.Helper()
	_, prefixNet, err := net.ParseCIDR("fd00:1234::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	_, frontendKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	frontendTunnelIP := make(net.IP, 16)
	copy(frontendTunnelIP, prefixNet.IP.To16())
	frontendTunnelIP[15] = 1

	var (
		mu                   sync.Mutex
		activeTunnelListener net.Listener
	)

	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		listener := activeTunnelListener
		mu.Unlock()
		if listener == nil {
			return nil, errors.New("no active tunnel listener")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}

	listenFunc := func(network, address string) (net.Listener, error) {
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listener := &fakeTunnelListener{Listener: rawListener, defaultRemoteIP: frontendTunnelIP}
		mu.Lock()
		activeTunnelListener = listener
		mu.Unlock()
		return listener, nil
	}

	opener := func(ctx context.Context, config wireguard.Config) (tunnel.WireGuardDevice, error) {
		return newFakeWireGuardDevice(), nil
	}

	applyFrontend := func(config *frontend.ServerConfig) {
		config.WireGuardDevice = newFakeWireGuardDevice()
		config.WireGuardPublicKey = frontendKey
		config.WireGuardPort = 51820
		config.WireGuardPrefix = prefixNet
		config.DialContext = dialFunc
	}

	mgrOpts := []tunnel.ManagerOption{
		tunnel.WithWireGuardDeviceOpener(opener),
		tunnel.WithListenFunc(listenFunc),
	}

	return applyFrontend, mgrOpts
}
