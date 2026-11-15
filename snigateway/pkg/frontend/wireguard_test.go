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
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

type fakeWireGuardDevice struct {
	mu    sync.Mutex
	peers map[wireguard.Key]wireguard.Peer
}

func newFakeWireGuardDevice() *fakeWireGuardDevice {
	return &fakeWireGuardDevice{
		peers: make(map[wireguard.Key]wireguard.Peer),
	}
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

func setupTestWireGuardServer(t *testing.T, prefixStr string) (*Server, *fakeWireGuardDevice, wireguard.Key, int, string, *certs.GeneratedCerts, func()) {
	t.Helper()
	generated, err := certs.GenerateAll("snigateway.internal", "test-client")
	if err != nil {
		t.Fatalf("GenerateAll certs failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

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
		_, prefixNet, err = net.ParseCIDR(prefixStr)
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}
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
		_ = srv.Serve(ln)
	}()

	cleanup := func() {
		_ = srv.Close()
	}

	return srv, fakeDev, feKey, fePort, serverAddr, generated, cleanup
}

func putWireGuard(t *testing.T, clientTLS *tls.Config, serverAddr, sessionID string, req api.WireGuardRequest) (*http.Response, *api.WireGuardResponse) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal request failed: %v", err)
	}

	httpTransport := &http.Transport{
		TLSClientConfig: clientTLS,
	}
	httpClient := &http.Client{Transport: httpTransport}

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
		if err := json.NewDecoder(resp.Body).Decode(&wgResp); err != nil {
			t.Fatalf("Decode response failed: %v", err)
		}
	}
	return resp, &wgResp
}

func startClientSession(ctx context.Context, t *testing.T, generated *certs.GeneratedCerts, serverAddr string) (*client.Client, string) {
	return startClientSessionWithCA(ctx, t, generated.CA.CertPEM, generated, serverAddr)
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
	_, _, _, _, serverAddr, generated, cleanup := setupTestWireGuardServer(t, "")
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp, _ := putWireGuard(t, clientTLS, serverAddr, sessID, api.WireGuardRequest{
		PublicKey: peerKey.String(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 404 Not Found when WireGuard is off, got: %d, body: %q", resp.StatusCode, string(bodyBytes))
	}
}

func TestWireGuard_AddressInsidePrefix(t *testing.T) {
	prefixStr := "2001:db8:1234:5678::/64"
	_, dev, feKey, fePort, serverAddr, generated, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	resp, wgResp := putWireGuard(t, clientTLS, serverAddr, sessID, api.WireGuardRequest{
		PublicKey: peerKey.String(),
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}

	if wgResp.PublicKey != feKey.String() {
		t.Errorf("expected frontend public key %s, got %s", feKey.String(), wgResp.PublicKey)
	}
	if wgResp.Port != fePort {
		t.Errorf("expected port %d, got %d", fePort, wgResp.Port)
	}
	if wgResp.Prefix != prefixStr {
		t.Errorf("expected prefix %s, got %s", prefixStr, wgResp.Prefix)
	}

	peerIP := net.ParseIP(wgResp.Address)
	if peerIP == nil {
		t.Fatalf("failed to parse returned peer address: %q", wgResp.Address)
	}

	_, prefixNet, _ := net.ParseCIDR(prefixStr)
	if !prefixNet.Contains(peerIP) {
		t.Fatalf("returned address %s is not inside prefix %s", peerIP, prefixStr)
	}

	// Verify fake device received the peer configuration
	peer, ok := dev.Peer(peerKey)
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
	_, dev, _, _, serverAddr, generated, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sess1 := startClientSession(ctx, t, generated, serverAddr)
	_, sess2 := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
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

	resp1, wgResp1 := putWireGuard(t, clientTLS, serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("session 1 wireguard put failed: %d", resp1.StatusCode)
	}

	resp2, wgResp2 := putWireGuard(t, clientTLS, serverAddr, sess2, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("session 2 wireguard put failed: %d", resp2.StatusCode)
	}

	if wgResp1.Address == wgResp2.Address {
		t.Fatalf("expected different addresses for two sessions, got %s for both", wgResp1.Address)
	}

	if !dev.HasPeer(key1) || !dev.HasPeer(key2) {
		t.Fatal("expected fake device to have both peers")
	}
	if dev.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on fake device, got %d", dev.PeerCount())
	}
}

func TestWireGuard_RepeatedCallKeepsAddressReplacesKey(t *testing.T) {
	prefixStr := "fd00:1234::/64"
	_, dev, _, _, serverAddr, generated, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
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

	// First call with key1
	resp1, wgResp1 := putWireGuard(t, clientTLS, serverAddr, sessID, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("initial wireguard call failed: %d", resp1.StatusCode)
	}

	if !dev.HasPeer(key1) {
		t.Fatal("expected device to have key1")
	}

	// Repeated call for the same session with key2
	resp2, wgResp2 := putWireGuard(t, clientTLS, serverAddr, sessID, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("repeated wireguard call failed: %d", resp2.StatusCode)
	}

	// Must keep the same address
	if wgResp1.Address != wgResp2.Address {
		t.Fatalf("expected address to be preserved across repeated calls, got %s then %s", wgResp1.Address, wgResp2.Address)
	}

	// Old key must be removed, new key must be present on device
	if dev.HasPeer(key1) {
		t.Fatal("expected old key1 to be removed from fake device")
	}
	if !dev.HasPeer(key2) {
		t.Fatal("expected new key2 to be present on fake device")
	}
	if dev.PeerCount() != 1 {
		t.Fatalf("expected exactly 1 peer on device, got %d", dev.PeerCount())
	}
}

func TestWireGuard_EndingSessionRemovesPeerAndFreesAddress(t *testing.T) {
	prefixStr := "fd00:9999::/64"
	srv, dev, _, _, serverAddr, generated, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sess1 := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	_, key1, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key1 failed: %v", err)
	}

	resp1, wgResp1 := putWireGuard(t, clientTLS, serverAddr, sess1, api.WireGuardRequest{
		PublicKey: key1.String(),
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("session 1 wireguard put failed: %d", resp1.StatusCode)
	}

	if !dev.HasPeer(key1) {
		t.Fatal("expected fake device to have key1")
	}

	// Close session 1
	srv.CloseSession(sess1)

	// Peer must be removed from device
	if dev.HasPeer(key1) {
		t.Fatal("expected peer to be removed from fake device when session ends")
	}
	if dev.PeerCount() != 0 {
		t.Fatalf("expected 0 peers on fake device, got %d", dev.PeerCount())
	}

	// Start session 2 and verify it reuses the freed address
	_, sess2 := startClientSession(ctx, t, generated, serverAddr)
	_, key2, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey key2 failed: %v", err)
	}

	resp2, wgResp2 := putWireGuard(t, clientTLS, serverAddr, sess2, api.WireGuardRequest{
		PublicKey: key2.String(),
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("session 2 wireguard put failed: %d", resp2.StatusCode)
	}

	if wgResp2.Address != wgResp1.Address {
		t.Fatalf("expected session 2 to allocate freed address %s, got %s", wgResp1.Address, wgResp2.Address)
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

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(generatedA.CA.CertPEM)
	caPool.AppendCertsFromPEM(generatedB.CA.CertPEM)

	serverTLS, err := certs.NewServerTLSConfigWithCertPool(caPool, generatedA.Server.CertPEM, generatedA.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfigWithCertPool failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serverAddr := ln.Addr().String()

	fakeDev := newFakeWireGuardDevice()
	_, feKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefixNet, err := net.ParseCIDR(prefixStr)
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    fakeDev,
		WireGuardPublicKey: feKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    prefixNet,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessA := startClientSessionWithCA(ctx, t, generatedA.CA.CertPEM, generatedA, serverAddr)
	_, sessB := startClientSessionWithCA(ctx, t, generatedA.CA.CertPEM, generatedB, serverAddr)

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
	respA, _ := putWireGuard(t, clientTLSA, serverAddr, sessA, api.WireGuardRequest{
		PublicKey: keyA.String(),
	})
	if respA.StatusCode != http.StatusOK {
		t.Fatalf("session A wireguard put failed: %d", respA.StatusCode)
	}

	// 1. Client B tries to call PUT /v1/sessions/<sessA>/wireguard (identity mismatch) -> 403 Forbidden
	respMismatched, _ := putWireGuard(t, clientTLSB, serverAddr, sessA, api.WireGuardRequest{
		PublicKey: keyB.String(),
	})
	defer respMismatched.Body.Close()
	if respMismatched.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for session identity mismatch, got: %d", respMismatched.StatusCode)
	}

	// 2. Client B tries to register keyA (which belongs to session A) for session B -> 409 Conflict
	respConflict, _ := putWireGuard(t, clientTLSB, serverAddr, sessB, api.WireGuardRequest{
		PublicKey: keyA.String(),
	})
	defer respConflict.Body.Close()
	if respConflict.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when setting key of another session, got: %d", respConflict.StatusCode)
	}

	// 3. Client A tries to configure non-existent session -> 404 Not Found
	respNotFound, _ := putWireGuard(t, clientTLSA, serverAddr, "non-existent-session", api.WireGuardRequest{
		PublicKey: keyB.String(),
	})
	defer respNotFound.Body.Close()
	if respNotFound.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for non-existent session, got: %d", respNotFound.StatusCode)
	}
}

func TestWireGuard_InvalidPublicKey(t *testing.T) {
	prefixStr := "fd00:5555::/64"
	_, _, _, _, serverAddr, generated, cleanup := setupTestWireGuardServer(t, prefixStr)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, sessID := startClientSession(ctx, t, generated, serverAddr)

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
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
			resp, _ := putWireGuard(t, clientTLS, serverAddr, sessID, api.WireGuardRequest{
				PublicKey: tc.key,
			})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400 Bad Request for %s, got: %d", tc.name, resp.StatusCode)
			}
		})
	}
}
