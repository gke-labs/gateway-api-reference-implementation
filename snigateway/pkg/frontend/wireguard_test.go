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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

type fakeWireGuardDevice struct {
	mu         sync.Mutex
	peers      map[wireguard.Key]wireguard.Peer
	addPeerErr error
}

func newFakeWireGuardDevice() *fakeWireGuardDevice {
	return &fakeWireGuardDevice{
		peers: make(map[wireguard.Key]wireguard.Peer),
	}
}

func (f *fakeWireGuardDevice) SetAddPeerError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addPeerErr = err
}

func (f *fakeWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addPeerErr != nil {
		return f.addPeerErr
	}
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeWireGuardDevice) RemovePeer(key wireguard.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}

func (f *fakeWireGuardDevice) HasPeer(key wireguard.Key) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.peers[key]
	return ok
}

func (f *fakeWireGuardDevice) Peer(key wireguard.Key) (wireguard.Peer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.peers[key]
	return p, ok
}

func (f *fakeWireGuardDevice) PeerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.peers)
}

type testWireGuardServer struct {
	server     *Server
	device     *fakeWireGuardDevice
	publicKey  wireguard.Key
	port       int
	serverAddr string
	generated  *certs.GeneratedCerts
}

func setupTestWireGuardServer(t *testing.T, prefixStr string, clientCerts ...*certs.GeneratedCerts) (*testWireGuardServer, func()) {
	t.Helper()

	var defaultGenerated *certs.GeneratedCerts
	var serverTLS *tls.Config

	if len(clientCerts) == 0 {
		var err error
		defaultGenerated, err = certs.GenerateAll("snigateway.internal", "test-client")
		if err != nil {
			t.Fatalf("GenerateAll certs failed: %v", err)
		}
		serverTLS, err = certs.NewServerTLSConfig(defaultGenerated.CA.CertPEM, defaultGenerated.Server.CertPEM, defaultGenerated.Server.KeyPEM)
		if err != nil {
			t.Fatalf("NewServerTLSConfig failed: %v", err)
		}
	} else {
		defaultGenerated = clientCerts[0]
		caPool := x509.NewCertPool()
		for _, certPair := range clientCerts {
			caPool.AppendCertsFromPEM(certPair.CA.CertPEM)
		}
		var err error
		serverTLS, err = certs.NewServerTLSConfigWithCertPool(caPool, clientCerts[0].Server.CertPEM, clientCerts[0].Server.KeyPEM)
		if err != nil {
			t.Fatalf("NewServerTLSConfigWithCertPool failed: %v", err)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	var dev WireGuardDevice
	var fakeDev *fakeWireGuardDevice
	var feKey wireguard.Key
	var prefixNet *net.IPNet
	fePort := 51820
	if prefixStr != "" {
		fakeDev = newFakeWireGuardDevice()
		dev = fakeDev
		_, feKey, err = wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		var cidrNet *net.IPNet
		_, cidrNet, err = net.ParseCIDR(prefixStr)
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}
		prefixNet = cidrNet
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    dev,
		WireGuardPublicKey: feKey,
		WireGuardPort:      fePort,
		WireGuardPrefix:    prefixNet,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			t.Logf("Serve exited: %v", serveErr)
		}
	}()

	cleanup := func() {
		if closeErr := srv.Close(); closeErr != nil {
			t.Logf("Close returned error: %v", closeErr)
		}
	}

	return &testWireGuardServer{
		server:     srv,
		device:     fakeDev,
		publicKey:  feKey,
		port:       fePort,
		serverAddr: ln.Addr().String(),
		generated:  defaultGenerated,
	}, cleanup
}

func putWireGuard(t *testing.T, clientTLS *tls.Config, serverAddr, sessionID string, req api.WireGuardRequest) (*http.Response, *api.WireGuardResponse) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal request failed: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
		},
	}

	url := fmt.Sprintf("https://%s/v1/sessions/%s/wireguard", serverAddr, sessionID)
	httpReq, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	httpReq.Host = "snigateway.internal"
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		t.Fatalf("Do request failed: %v", err)
	}

	var wgResp api.WireGuardResponse
	if resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		if decodeErr := json.NewDecoder(resp.Body).Decode(&wgResp); decodeErr != nil {
			t.Fatalf("Decode response failed: %v", decodeErr)
		}
	}
	return resp, &wgResp
}

func startClientSessionWithCA(ctx context.Context, t *testing.T, caCertPEM []byte, clientCert *certs.GeneratedCerts, serverAddr string) (*client.Client, string) {
	t.Helper()
	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCert.Client.CertPEM, clientCert.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := client.NewClient(serverAddr, clientTLS)
	sessID, _, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	return c, sessID
}

func TestWireGuard_Off_Returns404(t *testing.T) {
	env, cleanup := setupTestWireGuardServer(t, "")
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp, _ := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
		PublicKey: peerKey.String(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("ReadAll failed: %v", readErr)
		}
		t.Fatalf("expected 404 Not Found when WireGuard is off, got: %d, body: %q", resp.StatusCode, string(bodyBytes))
	}
}

func TestWireGuard_AddressInsidePrefix(t *testing.T) {
	prefixStr := "2001:db8:1234:5678::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp, wgResp := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
		PublicKey: peerKey.String(),
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}

	if wgResp.PublicKey != env.publicKey.String() {
		t.Errorf("expected frontend public key %s, got %s", env.publicKey.String(), wgResp.PublicKey)
	}
	if wgResp.Port != env.port {
		t.Errorf("expected port %d, got %d", env.port, wgResp.Port)
	}
	if wgResp.Prefix != prefixStr {
		t.Errorf("expected prefix %s, got %s", prefixStr, wgResp.Prefix)
	}

	peerIP := net.ParseIP(wgResp.PeerAddress)
	if peerIP == nil {
		t.Fatalf("failed to parse returned peer address: %q", wgResp.PeerAddress)
	}

	_, prefixNet, err := net.ParseCIDR(prefixStr)
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if !prefixNet.Contains(peerIP) {
		t.Fatalf("returned address %s is not inside prefix %s", peerIP, prefixStr)
	}

	peer, ok := env.device.Peer(peerKey)
	if !ok {
		t.Fatalf("peer %s not found on fake device", peerKey)
	}
	if len(peer.AllowedIPs) != 1 {
		t.Fatalf("expected 1 AllowedIP, got %d", len(peer.AllowedIPs))
	}
	if !peer.AllowedIPs[0].IP.Equal(peerIP) {
		t.Errorf("expected AllowedIP %s, got %s", peerIP, peer.AllowedIPs[0].IP)
	}
	ones, bits := peer.AllowedIPs[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("expected AllowedIP mask /128, got /%d", ones)
	}
}

func TestWireGuard_TwoSessionsDifferentAddresses(t *testing.T) {
	prefixStr := "fd00:abcd::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sess1 := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)
	_, sess2 := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, key1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key1 failed: %v", err)
	}
	_, key2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key2 failed: %v", err)
	}

	resp1, wgResp1 := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("session 1 wireguard put failed: %d", resp1.StatusCode)
	}

	resp2, wgResp2 := putWireGuard(t, clientTLS, env.serverAddr, sess2, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("session 2 wireguard put failed: %d", resp2.StatusCode)
	}

	if wgResp1.PeerAddress == wgResp2.PeerAddress {
		t.Fatalf("expected different addresses for two sessions, got %s for both", wgResp1.PeerAddress)
	}

	if !env.device.HasPeer(key1) || !env.device.HasPeer(key2) {
		t.Fatal("expected fake device to have both peers")
	}
	if env.device.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on fake device, got %d", env.device.PeerCount())
	}
}

func TestWireGuard_RepeatedCallKeepsAddressReplacesKey(t *testing.T) {
	prefixStr := "fd00:1234::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, key1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key1 failed: %v", err)
	}
	_, key2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key2 failed: %v", err)
	}

	resp1, wgResp1 := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("initial wireguard call failed: %d", resp1.StatusCode)
	}

	if !env.device.HasPeer(key1) {
		t.Fatal("expected device to have key1")
	}

	resp2, wgResp2 := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("repeated wireguard call failed: %d", resp2.StatusCode)
	}

	if wgResp1.PeerAddress != wgResp2.PeerAddress {
		t.Fatalf("expected address to be preserved across repeated calls, got %s then %s", wgResp1.PeerAddress, wgResp2.PeerAddress)
	}

	if env.device.HasPeer(key1) {
		t.Fatal("expected old key1 to be removed from fake device")
	}
	if !env.device.HasPeer(key2) {
		t.Fatal("expected new key2 to be present on fake device")
	}
	if env.device.PeerCount() != 1 {
		t.Fatalf("expected exactly 1 peer on device, got %d", env.device.PeerCount())
	}
}

func TestWireGuard_EndingSessionRemovesPeerAndFreesAddress(t *testing.T) {
	prefixStr := "fd00:9999::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sess1 := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, key1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key1 failed: %v", err)
	}

	resp1, wgResp1 := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("session 1 wireguard put failed: %d", resp1.StatusCode)
	}

	if !env.device.HasPeer(key1) {
		t.Fatal("expected fake device to have key1")
	}

	env.server.CloseSession(sess1)

	if env.device.HasPeer(key1) {
		t.Fatal("expected peer to be removed from fake device when session ends")
	}
	if env.device.PeerCount() != 0 {
		t.Fatalf("expected 0 peers on fake device, got %d", env.device.PeerCount())
	}

	_, sess2 := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)
	_, key2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key2 failed: %v", err)
	}

	resp2, wgResp2 := putWireGuard(t, clientTLS, env.serverAddr, sess2, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("session 2 wireguard put failed: %d", resp2.StatusCode)
	}

	if wgResp2.PeerAddress != wgResp1.PeerAddress {
		t.Fatalf("expected session 2 to allocate freed address %s, got %s", wgResp1.PeerAddress, wgResp2.PeerAddress)
	}
}

func TestWireGuard_SessionClosedDuringExchange_DoesNotLeakPeer(t *testing.T) {
	prefixStr := "fd00:8888::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Close session right before the exchange runs.
	env.server.CloseSession(sessID)

	resp, _ := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
		PublicKey: peerKey.String(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for session closed during/before exchange, got: %d", resp.StatusCode)
	}

	// Verify no peer was added to the device.
	if env.device.HasPeer(peerKey) {
		t.Fatal("expected no peer to be added to fake device when session is closed")
	}
	if env.device.PeerCount() != 0 {
		t.Fatalf("expected 0 peers on device, got: %d", env.device.PeerCount())
	}
}

func TestWireGuard_SessionCannotSetAnotherSessionKey(t *testing.T) {
	prefixStr := "fd00:7777::/64"
	generatedA, err := certs.GenerateAll("snigateway.internal", "client-a")
	if err != nil {
		t.Fatalf("GenerateAll client-a failed: %v", err)
	}
	generatedB, err := certs.GenerateAll("snigateway.internal", "client-b")
	if err != nil {
		t.Fatalf("GenerateAll client-b failed: %v", err)
	}

	env, cleanup := setupTestWireGuardServer(t, prefixStr, generatedA, generatedB)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessA := startClientSessionWithCA(ctx, t, generatedA.CA.CertPEM, generatedA, env.serverAddr)
	_, sessB := startClientSessionWithCA(ctx, t, generatedA.CA.CertPEM, generatedB, env.serverAddr)

	clientTLSA, err := certs.NewClientTLSConfig(generatedA.CA.CertPEM, generatedA.Client.CertPEM, generatedA.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig A failed: %v", err)
	}
	clientTLSB, err := certs.NewClientTLSConfig(generatedA.CA.CertPEM, generatedB.Client.CertPEM, generatedB.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig B failed: %v", err)
	}

	_, keyA, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey keyA failed: %v", err)
	}
	_, keyB, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey keyB failed: %v", err)
	}

	// Session A registers keyA
	respA, _ := putWireGuard(t, clientTLSA, env.serverAddr, sessA, api.WireGuardRequest{
		PublicKey: keyA.String(),
	})
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("session A wireguard put failed: %d", respA.StatusCode)
	}

	// 1. Client B tries to call PUT /v1/sessions/<sessA>/wireguard (identity mismatch) -> 403 Forbidden
	respMismatched, _ := putWireGuard(t, clientTLSB, env.serverAddr, sessA, api.WireGuardRequest{
		PublicKey: keyB.String(),
	})
	defer respMismatched.Body.Close()
	if respMismatched.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for session identity mismatch, got: %d", respMismatched.StatusCode)
	}

	// 2. Client B tries to register keyA (which belongs to session A) for session B -> 409 Conflict
	respConflict, _ := putWireGuard(t, clientTLSB, env.serverAddr, sessB, api.WireGuardRequest{
		PublicKey: keyA.String(),
	})
	defer respConflict.Body.Close()
	if respConflict.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when setting key of another session, got: %d", respConflict.StatusCode)
	}

	// 3. Client A tries to configure non-existent session -> 404 Not Found
	respNotFound, _ := putWireGuard(t, clientTLSA, env.serverAddr, "non-existent-session", api.WireGuardRequest{
		PublicKey: keyB.String(),
	})
	defer respNotFound.Body.Close()
	if respNotFound.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for non-existent session, got: %d", respNotFound.StatusCode)
	}
}

func TestWireGuard_InvalidPublicKey(t *testing.T) {
	prefixStr := "fd00:5555::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	testCases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"invalid base64", "not-base-64!!!"},
		{"too short", "c2hvcnQ="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := putWireGuard(t, clientTLS, env.serverAddr, sessID, api.WireGuardRequest{
				PublicKey: tc.key,
			})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400 Bad Request for %s, got: %d", tc.name, resp.StatusCode)
			}
		})
	}
}

func TestWireGuard_FailedAddPeer(t *testing.T) {
	prefixStr := "fd00:4444::/64"
	env, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	clientTLS, err := certs.NewClientTLSConfig(env.generated.CA.CertPEM, env.generated.Client.CertPEM, env.generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	simulatedErr := errors.New("simulated add peer failure")

	// 1. A first exchange that fails leaves no entry behind
	env.device.SetAddPeerError(simulatedErr)

	_, sess1 := startClientSessionWithCA(ctx, t, env.generated.CA.CertPEM, env.generated, env.serverAddr)

	_, key1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp1, _ := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error when AddPeer fails, got: %d", resp1.StatusCode)
	}
	bodyBytes, readErr := io.ReadAll(resp1.Body)
	if readErr != nil {
		t.Fatalf("ReadAll failed: %v", readErr)
	}
	if !strings.Contains(string(bodyBytes), "internal server error") {
		t.Errorf("expected fixed internal server error message, got: %q", string(bodyBytes))
	}

	// Verify no entry was left in device or manager table
	if env.device.HasPeer(key1) || env.device.PeerCount() != 0 {
		t.Fatalf("expected no peer left in device after initial AddPeer failure, got %d peers", env.device.PeerCount())
	}

	// Now clear the error: initial call should succeed and claim the first address
	env.device.SetAddPeerError(nil)

	respSuccess, wgRespSuccess := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if respSuccess.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after clearing AddPeer error, got: %d", respSuccess.StatusCode)
	}
	if !env.device.HasPeer(key1) {
		t.Fatal("expected device to have key1 after successful exchange")
	}
	initialAddr := wgRespSuccess.PeerAddress

	// 2. Replace a session's key with the error set:
	// check that the session keeps its old key and address in both the table and the device
	env.device.SetAddPeerError(simulatedErr)

	_, key2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	respReplaceFail, _ := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	defer respReplaceFail.Body.Close()

	if respReplaceFail.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on replacement failure, got: %d", respReplaceFail.StatusCode)
	}

	// Verify the session keeps its old key and address on the device
	if !env.device.HasPeer(key1) {
		t.Fatal("expected device to retain old key1 after failed key replacement")
	}
	if env.device.HasPeer(key2) {
		t.Fatal("expected device not to have key2 after failed key replacement")
	}
	peer1, ok := env.device.Peer(key1)
	if !ok || !peer1.AllowedIPs[0].IP.Equal(net.ParseIP(initialAddr)) {
		t.Fatalf("expected device to retain old address %s, got: %v", initialAddr, peer1.AllowedIPs)
	}

	// Verify the manager table still retains key1 and address by attempting key replacement without error:
	// it should know key1 was the old key and keep initialAddr!
	env.device.SetAddPeerError(nil)
	respReplaceOk, wgRespReplaceOk := putWireGuard(t, clientTLS, env.serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if respReplaceOk.StatusCode != http.StatusOK {
		t.Fatalf("expected replacement to succeed after clearing error, got: %d", respReplaceOk.StatusCode)
	}
	if wgRespReplaceOk.PeerAddress != initialAddr {
		t.Fatalf("expected kept address %s, got %s", initialAddr, wgRespReplaceOk.PeerAddress)
	}
	if env.device.HasPeer(key1) {
		t.Fatal("expected old key1 to be removed from device after successful replacement")
	}
	if !env.device.HasPeer(key2) {
		t.Fatal("expected new key2 to be on device after successful replacement")
	}
}

func TestWireGuard_AllocateAddressLocked(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8:cafe::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	mgr := NewWireGuardManager(newFakeWireGuardDevice(), wireguard.Key{}, 51820, prefix, nil)
	if mgr == nil {
		t.Fatal("NewWireGuardManager returned nil")
	}

	// 1. First allocation returns host 2
	addr1, err := mgr.allocateAddressLocked()
	if err != nil {
		t.Fatalf("allocateAddressLocked failed: %v", err)
	}
	expectedAddr1 := net.ParseIP("2001:db8:cafe::2")
	if !addr1.Equal(expectedAddr1) {
		t.Fatalf("expected first allocated address to be %s, got %s", expectedAddr1, addr1)
	}

	// Record addr1 in peersBySession
	key1, _, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	mgr.peersBySession["sess-1"] = wireguardPeer{publicKey: key1, address: addr1}

	// 2. Second allocation returns host 3
	addr2, err := mgr.allocateAddressLocked()
	if err != nil {
		t.Fatalf("allocateAddressLocked failed: %v", err)
	}
	expectedAddr2 := net.ParseIP("2001:db8:cafe::3")
	if !addr2.Equal(expectedAddr2) {
		t.Fatalf("expected second allocated address to be %s, got %s", expectedAddr2, addr2)
	}

	// Record addr2 in peersBySession
	key2, _, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	mgr.peersBySession["sess-2"] = wireguardPeer{publicKey: key2, address: addr2}

	// 3. Third allocation returns host 4
	addr3, err := mgr.allocateAddressLocked()
	if err != nil {
		t.Fatalf("allocateAddressLocked failed: %v", err)
	}
	expectedAddr3 := net.ParseIP("2001:db8:cafe::4")
	if !addr3.Equal(expectedAddr3) {
		t.Fatalf("expected third allocated address to be %s, got %s", expectedAddr3, addr3)
	}

	// Record addr3 in peersBySession
	key3, _, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	mgr.peersBySession["sess-3"] = wireguardPeer{publicKey: key3, address: addr3}

	// 4. Free sess-2 (host 3); next allocation should reuse host 3
	delete(mgr.peersBySession, "sess-2")
	addrReused, err := mgr.allocateAddressLocked()
	if err != nil {
		t.Fatalf("allocateAddressLocked failed: %v", err)
	}
	if !addrReused.Equal(expectedAddr2) {
		t.Fatalf("expected reused address to be %s, got %s", expectedAddr2, addrReused)
	}

	// 5. Add a peer with an address from a different prefix; it should not affect host allocation
	keyOther, _, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	mgr.peersBySession["sess-other"] = wireguardPeer{
		publicKey: keyOther,
		address:   net.ParseIP("2001:db8:other::2"),
	}
	// If sess-1 (host 2) is freed, host 2 in cafe prefix should still be allocated
	delete(mgr.peersBySession, "sess-1")
	addrHost2, err := mgr.allocateAddressLocked()
	if err != nil {
		t.Fatalf("allocateAddressLocked failed: %v", err)
	}
	if !addrHost2.Equal(expectedAddr1) {
		t.Fatalf("expected allocated address to be %s, got %s", expectedAddr1, addrHost2)
	}
}
