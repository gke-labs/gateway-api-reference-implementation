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

package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
)

func TestClient_Registration(t *testing.T) {
	generated, err := certs.GenerateAll("snigateway.internal", "client-test")
	if err != nil {
		t.Fatalf("GenerateAll failed: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(generated.CA.CertPEM, generated.Server.CertPEM, generated.Server.KeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	c := NewClient(ln.Addr().String(), clientTLS)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	sessID, _, err := c.StartSession(ctx)
	if err != nil {
		t.Fatalf("c.StartSession failed: %v", err)
	}

	resp, err := c.Register(ctx, sessID, []string{"foo.example.com", "*.bar.com"})
	if err != nil {
		t.Fatalf("c.Register failed: %v", err)
	}

	if resp.Status != "registered" {
		t.Fatalf("expected status registered, got %s", resp.Status)
	}

	if len(resp.Hostnames) != 2 {
		t.Fatalf("expected 2 hostnames, got %d (%v)", len(resp.Hostnames), resp.Hostnames)
	}
}

type fakeClientTestWireGuardDevice struct {
	peers map[wireguard.Key]wireguard.Peer
}

func (f *fakeClientTestWireGuardDevice) AddPeer(peer wireguard.Peer) error {
	f.peers[peer.PublicKey] = peer
	return nil
}

func (f *fakeClientTestWireGuardDevice) RemovePeer(key wireguard.Key) error {
	delete(f.peers, key)
	return nil
}

func TestClient_ExchangeWireGuard(t *testing.T) {
	generated, err := certs.GenerateAll("snigateway.internal", "client-test")
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

	t.Run("WireGuard enabled on frontend", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer listener.Close()

		_, feKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		_, prefixNet, err := net.ParseCIDR("fd00::/64")
		if err != nil {
			t.Fatalf("ParseCIDR failed: %v", err)
		}

		fakeDev := &fakeClientTestWireGuardDevice{peers: make(map[wireguard.Key]wireguard.Peer)}
		server, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig:    serverTLS,
			WireGuardDevice:    fakeDev,
			WireGuardPublicKey: feKey,
			WireGuardPort:      51820,
			WireGuardPrefix:    prefixNet,
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- server.Serve(listener)
		}()
		defer func() {
			if err := server.Close(); err != nil {
				t.Errorf("server.Close failed: %v", err)
			}
			if err := <-serverErrCh; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("server.Serve failed: %v", err)
			}
		}()

		c := NewClient(listener.Addr().String(), clientTLS)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		sessID, _, err := c.StartSession(ctx)
		if err != nil {
			t.Fatalf("StartSession failed: %v", err)
		}

		_, clientKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		resp, err := c.ExchangeWireGuard(ctx, sessID, clientKey.String())
		if err != nil {
			t.Fatalf("ExchangeWireGuard failed: %v", err)
		}

		if resp.PublicKey != feKey.String() {
			t.Errorf("expected PublicKey %s, got %s", feKey.String(), resp.PublicKey)
		}
		if resp.Port != 51820 {
			t.Errorf("expected Port 51820, got %d", resp.Port)
		}
		if resp.Prefix != "fd00::/64" {
			t.Errorf("expected Prefix fd00::/64, got %s", resp.Prefix)
		}
		if resp.PeerAddress == "" {
			t.Errorf("expected non-empty PeerAddress")
		}
	})

	t.Run("WireGuard disabled on frontend returns ErrWireGuardDisabled", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer listener.Close()

		server, err := frontend.NewServer(frontend.ServerConfig{
			ServerTLSConfig: serverTLS,
		})
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- server.Serve(listener)
		}()
		defer func() {
			if err := server.Close(); err != nil {
				t.Errorf("server.Close failed: %v", err)
			}
			if err := <-serverErrCh; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("server.Serve failed: %v", err)
			}
		}()

		c := NewClient(listener.Addr().String(), clientTLS)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		sessID, _, err := c.StartSession(ctx)
		if err != nil {
			t.Fatalf("StartSession failed: %v", err)
		}

		_, clientKey, err := wireguard.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		_, err = c.ExchangeWireGuard(ctx, sessID, clientKey.String())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrWireGuardDisabled) {
			t.Errorf("expected errors.Is(err, ErrWireGuardDisabled), got: %v", err)
		}
	})
}
