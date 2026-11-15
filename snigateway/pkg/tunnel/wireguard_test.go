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
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func TestValidateWireGuardResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    api.WireGuardResponse
		wantErr     bool
		errContains string
	}{
		{
			name: "valid response",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:4444::2",
			},
			wantErr: false,
		},
		{
			name: "port zero",
			response: api.WireGuardResponse{
				Port:        0,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "out of range",
		},
		{
			name: "port negative",
			response: api.WireGuardResponse{
				Port:        -1,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "out of range",
		},
		{
			name: "port above 65535",
			response: api.WireGuardResponse{
				Port:        65536,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "out of range",
		},
		{
			name: "wrong family prefix IPv4",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "192.168.1.0/24",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "must be an IPv6 prefix",
		},
		{
			name: "wrong family peer address IPv4",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "192.168.1.2",
			},
			wantErr:     true,
			errContains: "must be an IPv6 address",
		},
		{
			name: "prefix not /64",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::/48",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "must be a /64 prefix",
		},
		{
			name: "prefix host bits set",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::1/64",
				PeerAddress: "fd00:4444::2",
			},
			wantErr:     true,
			errContains: "must have zero host bits",
		},
		{
			name: "address outside prefix",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:5555::2",
			},
			wantErr:     true,
			errContains: "not within prefix",
		},
		{
			name: "address equal to frontend tunnel address",
			response: api.WireGuardResponse{
				Port:        51820,
				Prefix:      "fd00:4444::/64",
				PeerAddress: "fd00:4444::1",
			},
			wantErr:     true,
			errContains: "conflicts with frontend tunnel address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerIP, prefixNet, frontendTunnelIP, err := validateWireGuardResponse(&tt.response)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateWireGuardResponse() expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateWireGuardResponse() error = %v, want substring %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateWireGuardResponse() unexpected error: %v", err)
			}
			if !peerIP.Equal(net.ParseIP("fd00:4444::2")) {
				t.Errorf("peerIP = %v, want fd00:4444::2", peerIP)
			}
			if prefixNet.String() != "fd00:4444::/64" {
				t.Errorf("prefixNet = %s, want fd00:4444::/64", prefixNet)
			}
			if !frontendTunnelIP.Equal(net.ParseIP("fd00:4444::1")) {
				t.Errorf("frontendTunnelIP = %v, want fd00:4444::1", frontendTunnelIP)
			}
		})
	}
}

type fakeFrontendWireGuardDevice struct {
	mu    sync.Mutex
	peers map[wireguard.Key]wireguard.Peer
}

func (f *fakeFrontendWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeFrontendWireGuardDevice) RemovePeer(key wireguard.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}

type fakeMgrTestWireGuardDevice struct {
	mu      sync.Mutex
	peer    wireguard.Peer
	hasPeer bool
	closed  bool
}

func (f *fakeMgrTestWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peer = peer
	f.hasPeer = true
	return nil
}

func (f *fakeMgrTestWireGuardDevice) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeMgrTestWireGuardDevice) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeMgrTestWireGuardDevice) getPeer() (wireguard.Peer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peer, f.hasPeer
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
	defaultRemoteIP    net.IP
	mu                 sync.Mutex
	overrideRemoteAddr net.Addr
}

func (l *fakeTunnelListener) setOverrideRemoteAddr(addr net.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.overrideRemoteAddr = addr
}

func (l *fakeTunnelListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	override := l.overrideRemoteAddr
	l.mu.Unlock()

	remoteAddr := override
	if remoteAddr == nil {
		remoteAddr = &net.TCPAddr{IP: l.defaultRemoteIP, Port: 51820}
	}
	return &fakeTunnelConn{Conn: conn, remoteAddr: remoteAddr}, nil
}

type fixtureOptions struct {
	frontendWireGuard bool
	managerWireGuard  bool
}

type wireguardFixture struct {
	server           *frontend.Server
	serverListener   net.Listener
	clientConnsMu    sync.Mutex
	clientConns      []net.Conn
	frontendKey      wireguard.Key
	prefixNet        *net.IPNet
	frontendTunnelIP net.IP
	manager          *Manager

	devMu      sync.Mutex
	devices    []*fakeMgrTestWireGuardDevice
	devConfigs []wireguard.Config

	listenMu        sync.Mutex
	listenAddrs     []string
	tunnelListeners []*fakeTunnelListener

	srvErrCh  chan error
	mgrErrCh  chan error
	mgrCancel context.CancelFunc
}

func newWireGuardFixture(t *testing.T, options fixtureOptions) *wireguardFixture {
	t.Helper()

	generated, err := certs.GenerateAll("snigateway.internal", "mgr-client")
	if err != nil {
		t.Fatalf("GenerateAll failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	_, frontendKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefixNet, err := net.ParseCIDR("fd00:4444::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	frontendTunnelIP := make(net.IP, 16)
	copy(frontendTunnelIP, prefixNet.IP.To16())
	frontendTunnelIP[15] = 1

	serverConfig := frontend.ServerConfig{
		ServerTLSConfig:  serverTLS,
		InternalHostname: "snigateway.internal",
	}
	if options.frontendWireGuard {
		serverConfig.WireGuardDevice = &fakeFrontendWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		serverConfig.WireGuardPublicKey = frontendKey
		serverConfig.WireGuardPort = 51820
		serverConfig.WireGuardPrefix = prefixNet
	}

	server, err := frontend.NewServer(serverConfig)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	fixture := &wireguardFixture{
		server:           server,
		serverListener:   serverListener,
		frontendKey:      frontendKey,
		prefixNet:        prefixNet,
		frontendTunnelIP: frontendTunnelIP,
		srvErrCh:         make(chan error, 1),
		mgrErrCh:         make(chan error, 1),
	}

	go func() {
		fixture.srvErrCh <- server.Serve(serverListener)
	}()

	opener := func(ctx context.Context, config wireguard.Config) (WireGuardDevice, error) {
		fixture.devMu.Lock()
		defer fixture.devMu.Unlock()
		device := &fakeMgrTestWireGuardDevice{}
		fixture.devices = append(fixture.devices, device)
		fixture.devConfigs = append(fixture.devConfigs, config)
		return device, nil
	}

	listenFunc := func(network, address string) (net.Listener, error) {
		fixture.listenMu.Lock()
		defer fixture.listenMu.Unlock()
		fixture.listenAddrs = append(fixture.listenAddrs, address)
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		tunnelListener := &fakeTunnelListener{Listener: rawListener, defaultRemoteIP: frontendTunnelIP}
		fixture.tunnelListeners = append(fixture.tunnelListeners, tunnelListener)
		return tunnelListener, nil
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		fixture.clientConnsMu.Lock()
		fixture.clientConns = append(fixture.clientConns, conn)
		fixture.clientConnsMu.Unlock()
		return conn, nil
	}

	managerClient := client.NewClient(serverListener.Addr().String(), clientTLS, client.WithDialFunc(dialFunc))
	fixture.manager = NewManager(managerClient,
		WithWireGuard(options.managerWireGuard),
		WithWireGuardDeviceOpener(opener),
		WithListenFunc(listenFunc),
		WithBackoff(10*time.Millisecond, 50*time.Millisecond),
	)

	mgrCtx, mgrCancel := context.WithCancel(t.Context())
	fixture.mgrCancel = mgrCancel
	go func() {
		fixture.mgrErrCh <- fixture.manager.Run(mgrCtx)
	}()

	return fixture
}

func (f *wireguardFixture) cleanup(t *testing.T) {
	t.Helper()
	if f.mgrCancel != nil {
		f.mgrCancel()
		if err := <-f.mgrErrCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager error: %v", err)
		}
	}
	f.clientConnsMu.Lock()
	for _, c := range f.clientConns {
		_ = c.Close()
	}
	f.clientConnsMu.Unlock()
	if err := f.server.Close(); err != nil {
		t.Errorf("server.Close error: %v", err)
	}
	if err := f.serverListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("serverListener.Close error: %v", err)
	}
	if err := <-f.srvErrCh; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("server error: %v", err)
	}
}

func TestManager_WireGuard_Acceptance(t *testing.T) {
	t.Run("WireGuard session lifecycle and connection dispatching", func(t *testing.T) {
		fixture := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer fixture.cleanup(t)

		waitFor(t, 5*time.Second, fixture.manager.IsConnected)

		fixture.devMu.Lock()
		if len(fixture.devices) != 1 {
			fixture.devMu.Unlock()
			t.Fatalf("expected 1 WireGuard device opened, got %d", len(fixture.devices))
		}
		device := fixture.devices[0]
		deviceConfig := fixture.devConfigs[0]
		fixture.devMu.Unlock()

		if deviceConfig.InterfaceName != defaultWireGuardInterfaceName {
			t.Errorf("expected interface name %s, got %s", defaultWireGuardInterfaceName, deviceConfig.InterfaceName)
		}
		if !fixture.prefixNet.Contains(deviceConfig.DeviceAddress) {
			t.Errorf("expected DeviceAddress in %s, got %v", fixture.prefixNet, deviceConfig.DeviceAddress)
		}

		peer, ok := device.getPeer()
		if !ok || peer.PublicKey != fixture.frontendKey {
			t.Fatalf("expected frontend peer %s on device", fixture.frontendKey)
		}

		expectedEndpoint, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ParseFrontendHost(fixture.serverListener.Addr().String()), "51820"))
		if err != nil {
			t.Fatalf("ResolveUDPAddr failed: %v", err)
		}
		if peer.Endpoint.String() != expectedEndpoint.String() {
			t.Errorf("expected peer endpoint %s, got %s", expectedEndpoint, peer.Endpoint)
		}

		if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0].String() != "fd00:4444::1/128" {
			t.Errorf("expected AllowedIP fd00:4444::1/128, got %v", peer.AllowedIPs)
		}
		if peer.PersistentKeepalive == nil || *peer.PersistentKeepalive != wireguardPersistentKeepalive {
			t.Errorf("expected keepalive %v, got %v", wireguardPersistentKeepalive, peer.PersistentKeepalive)
		}

		fixture.listenMu.Lock()
		tunnelListener := fixture.tunnelListeners[0]
		listenAddr := fixture.listenAddrs[0]
		fixture.listenMu.Unlock()

		expectedListenAddr := net.JoinHostPort(deviceConfig.DeviceAddress.String(), strconv.Itoa(api.WireGuardTunnelPort))
		if listenAddr != expectedListenAddr {
			t.Errorf("expected listen addr %s, got %s", expectedListenAddr, listenAddr)
		}

		// TLS dispatch to HTTPSListener
		tlsConn, err := net.Dial("tcp", tunnelListener.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener: %v", err)
		}

		hdrTLS := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
		}
		encodedTLS, err := hdrTLS.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		tlsPayload := []byte("\x16\x03\x01\x00\x05hello")
		if _, err := tlsConn.Write(append(encodedTLS, tlsPayload...)); err != nil {
			t.Fatalf("write TLS to tunnel: %v", err)
		}

		acceptedTLS, err := fixture.manager.HTTPSListener().Accept()
		if err != nil {
			t.Fatalf("HTTPSListener.Accept failed: %v", err)
		}
		acceptedTLS.Close()
		tlsConn.Close()

		// HTTP dispatch to HTTPListener
		httpConn, err := net.Dial("tcp", tunnelListener.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener for HTTP: %v", err)
		}

		hdrHTTP := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 54321},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 80},
		}
		encodedHTTP, err := hdrHTTP.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if _, err := httpConn.Write(append(encodedHTTP, httpPayload...)); err != nil {
			t.Fatalf("write HTTP to tunnel: %v", err)
		}

		acceptedHTTP, err := fixture.manager.HTTPListener().Accept()
		if err != nil {
			t.Fatalf("HTTPListener.Accept failed: %v", err)
		}
		acceptedHTTP.Close()
		httpConn.Close()

		fixture.mgrCancel()
		if err := <-fixture.mgrErrCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager error: %v", err)
		}
		fixture.mgrCancel = nil
	})

	t.Run("Unauthorized connection from another address is closed", func(t *testing.T) {
		fixture := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer fixture.cleanup(t)

		waitFor(t, 5*time.Second, fixture.manager.IsConnected)

		fixture.listenMu.Lock()
		tunnelListener := fixture.tunnelListeners[0]
		fixture.listenMu.Unlock()

		tunnelListener.setOverrideRemoteAddr(&net.TCPAddr{IP: net.ParseIP("fd00:4444::99"), Port: 12345})

		unauthConn, err := net.Dial("tcp", tunnelListener.Addr().String())
		if err != nil {
			t.Fatalf("dialing tunnel listener: %v", err)
		}
		defer unauthConn.Close()

		hdr := &proxyproto.Header{
			Command: proxyproto.CommandProxy,
			SrcAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
			DstAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443},
		}
		encoded, err := hdr.Format()
		if err != nil {
			t.Fatalf("format PROXY header: %v", err)
		}
		if _, err := unauthConn.Write(append(encoded, []byte("\x16\x03\x01\x00\x05hello")...)); err != nil {
			t.Fatalf("write to unauthorized connection failed: %v", err)
		}

		buf := make([]byte, 1)
		if err := unauthConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		_, err = unauthConn.Read(buf)
		if err == nil {
			t.Errorf("expected read on rejected connection to fail or return EOF, got nil")
		}

		select {
		case c := <-fixture.manager.HTTPSListener().connCh:
			c.Close()
			t.Errorf("HTTPSListener unexpectedly received connection from unauthorized address")
		case c := <-fixture.manager.HTTPListener().connCh:
			c.Close()
			t.Errorf("HTTPListener unexpectedly received connection from unauthorized address")
		case <-time.After(50 * time.Millisecond):
		}
	})

	t.Run("Reconnecting session makes a new key and device", func(t *testing.T) {
		fixture := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: true})
		defer fixture.cleanup(t)

		waitFor(t, 5*time.Second, fixture.manager.IsConnected)

		fixture.devMu.Lock()
		if len(fixture.devices) != 1 {
			fixture.devMu.Unlock()
			t.Fatalf("expected 1 device, got %d", len(fixture.devices))
		}
		device1 := fixture.devices[0]
		key1 := fixture.devConfigs[0].PrivateKey
		fixture.devMu.Unlock()

		sessID1 := fixture.manager.SessionID()
		fixture.server.CloseSession(sessID1)

		waitFor(t, 5*time.Second, func() bool {
			return fixture.manager.IsConnected() && fixture.manager.SessionID() != sessID1
		})

		if !device1.isClosed() {
			t.Errorf("expected device 1 to be closed when session ended")
		}

		fixture.devMu.Lock()
		if len(fixture.devices) < 2 {
			fixture.devMu.Unlock()
			t.Fatalf("expected at least 2 devices opened after reconnect, got %d", len(fixture.devices))
		}
		key2 := fixture.devConfigs[1].PrivateKey
		fixture.devMu.Unlock()

		if key1 == key2 {
			t.Errorf("expected new key on reconnect, got same key %s", key1)
		}
	})

	t.Run("WireGuard-off frontend leaves TCP pool working", func(t *testing.T) {
		fixture := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: false, managerWireGuard: true})
		defer fixture.cleanup(t)

		waitFor(t, 5*time.Second, fixture.manager.IsConnected)

		fixture.devMu.Lock()
		numDevices := len(fixture.devices)
		fixture.devMu.Unlock()
		if numDevices != 0 {
			t.Errorf("expected no devices opened when frontend WireGuard is off, got %d", numDevices)
		}

		fixture.manager.UpdateHostnames([]string{"pool-test.example.com"})
		waitFor(t, 5*time.Second, func() bool {
			return fixture.manager.HasRegisteredHostnames([]string{"pool-test.example.com"})
		})
	})

	t.Run("Flag off leaves behaviour unchanged", func(t *testing.T) {
		fixture := newWireGuardFixture(t, fixtureOptions{frontendWireGuard: true, managerWireGuard: false})
		defer fixture.cleanup(t)

		waitFor(t, 5*time.Second, fixture.manager.IsConnected)

		fixture.devMu.Lock()
		numDevices := len(fixture.devices)
		fixture.devMu.Unlock()
		if numDevices != 0 {
			t.Errorf("expected no devices opened when flag is off, got %d", numDevices)
		}

		fixture.manager.UpdateHostnames([]string{"flagoff.example.com"})
		waitFor(t, 5*time.Second, func() bool {
			return fixture.manager.HasRegisteredHostnames([]string{"flagoff.example.com"})
		})
	})
}
