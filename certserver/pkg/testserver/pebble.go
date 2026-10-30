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

package testserver

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
)

// ServerConfig configures the in-process Pebble test server.
type ServerConfig struct {
	EABKeyID         string
	EABMACKey        string
	ValidityPeriod   uint64
	ChallengeStore   challenge.Store
	ChallengeHandler http.Handler
	ChallengePort    int
	ResolvedIP       string
}

// Server encapsulates an in-process Pebble ACME test environment.
type Server struct {
	DirectoryURL    string
	HTTPClient      *http.Client
	ChallengeStore  challenge.Store
	ChallengeServer *httptest.Server
	ServerCert      *x509.Certificate
	ServerCertPEM   []byte
	RootCert        *x509.Certificate
	RootCertPEM     []byte
	dnsServer       *dns.Server
	dnsListener     net.Listener
	pebbleServer    *httptest.Server
	dnsHandler      *mockDNSHandler

	// mu guards closed state to prevent concurrent or duplicate server shutdown.
	mu     sync.Mutex
	closed bool
}

// SetResolvedIP dynamically updates the IP address returned by mock DNS for TypeA queries.
func (s *Server) SetResolvedIP(ip string) {
	if s.dnsHandler != nil {
		s.dnsHandler.setIP(ip)
	}
}

// StartPebble creates and starts an in-process Pebble server without external network dependencies.
func StartPebble(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()

	// Disable VA validation sleeps for instant testing
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")

	// 1. Start Challenge HTTP server
	challengeStore := cfg.ChallengeStore
	if challengeStore == nil {
		challengeStore = challenge.NewMemoryStore()
	}
	challengeHandler := cfg.ChallengeHandler
	if challengeHandler == nil {
		challengeHandler = challenge.NewHandler(challengeStore)
	}
	challengeSrv := httptest.NewServer(challengeHandler)

	_, chalPortStr, err := net.SplitHostPort(challengeSrv.Listener.Addr().String())
	if err != nil {
		challengeSrv.Close()
		t.Fatalf("failed to parse challenge server port: %v", err)
	}
	challengePort, err := strconv.Atoi(chalPortStr)
	if err != nil {
		challengeSrv.Close()
		t.Fatalf("failed to convert challenge port: %v", err)
	}

	chalPort := challengePort
	if cfg.ChallengePort > 0 {
		chalPort = cfg.ChallengePort
	}

	// 2. Start mock DNS server that resolves all names to configured IP (default 127.0.0.1) via TCP (which Pebble VA uses)
	dnsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		challengeSrv.Close()
		t.Fatalf("failed to start TCP listener for mock DNS: %v", err)
	}

	dnsHandler := &mockDNSHandler{ip: cfg.ResolvedIP}
	dnsSrv := &dns.Server{
		Listener: dnsListener,
		Handler:  dnsHandler,
	}
	go func() {
		if serveErr := dnsSrv.ActivateAndServe(); serveErr != nil {
			// DNS server closed or failed
		}
	}()

	dnsAddr := dnsListener.Addr().String()

	// 3. Configure Pebble CA, VA, and WFE
	logger := log.New(io.Discard, "pebble: ", 0)
	memDB := db.NewMemoryStore()

	profiles := map[string]ca.Profile{
		"default": {
			Description:    "Default profile",
			ValidityPeriod: cfg.ValidityPeriod,
		},
	}

	eabRequired := false
	if cfg.EABKeyID != "" && cfg.EABMACKey != "" {
		eabRequired = true
		if err := memDB.AddExternalAccountKeyByID(cfg.EABKeyID, cfg.EABMACKey); err != nil {
			if closeErr := dnsListener.Close(); closeErr != nil {
				// ignore
			}
			challengeSrv.Close()
			t.Fatalf("failed to add EAB key to Pebble DB: %v", err)
		}
	}

	pebbleCA := ca.New(logger, memDB, "", "ecdsa", 0, 1, profiles)
	pebbleVA := va.New(logger, chalPort, 0, false, dnsAddr, memDB)
	pebbleWFE := wfe.New(logger, memDB, pebbleVA, pebbleCA, []string{"pebble.letsencrypt.org"}, false, eabRequired, 0, 0)

	pebbleSrv := httptest.NewTLSServer(pebbleWFE.Handler())
	dirURL := fmt.Sprintf("%s%s", pebbleSrv.URL, wfe.DirectoryPath)

	serverCert := pebbleSrv.Certificate()
	var serverPEM []byte
	if serverCert != nil {
		serverPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	}

	rootCert := pebbleCA.GetRootCert(0)
	var rootX509 *x509.Certificate
	var rootPEM []byte
	if rootCert != nil {
		rootX509 = rootCert.Cert
		rootPEM = rootCert.PEM()
	}

	srv := &Server{
		DirectoryURL:    dirURL,
		HTTPClient:      pebbleSrv.Client(),
		ChallengeStore:  challengeStore,
		ChallengeServer: challengeSrv,
		ServerCert:      serverCert,
		ServerCertPEM:   serverPEM,
		RootCert:        rootX509,
		RootCertPEM:     rootPEM,
		dnsServer:       dnsSrv,
		dnsListener:     dnsListener,
		pebbleServer:    pebbleSrv,
		dnsHandler:      dnsHandler,
	}

	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}

// Close shuts down the in-process test servers.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true

	if s.pebbleServer != nil {
		s.pebbleServer.Close()
	}
	if s.ChallengeServer != nil {
		s.ChallengeServer.Close()
	}
	if s.dnsServer != nil {
		if err := s.dnsServer.Shutdown(); err != nil {
			// ignore shutdown error
		}
	}
	if s.dnsListener != nil {
		if err := s.dnsListener.Close(); err != nil {
			// ignore close error
		}
	}
}

type mockDNSHandler struct {
	// mu guards ip to allow concurrent updates and reads during testing.
	mu sync.RWMutex
	ip string
}

func (h *mockDNSHandler) setIP(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ip = ip
}

func (h *mockDNSHandler) getIP() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.ip != "" {
		return h.ip
	}
	return "127.0.0.1"
}

func (h *mockDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	targetIP := h.getIP()

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, targetIP))
			if err != nil {
				continue
			}
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			// Do not return IPv6 addresses; environments in CI/containers often lack IPv6 loopback
		case dns.TypeCAA:
			// Pebble checks CAA, returning empty success indicates no blocking CAA records
		}
	}

	if err := w.WriteMsg(m); err != nil {
		return
	}
}
