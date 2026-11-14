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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
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
}

type orderRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *orderRecorder) WriteHeader(status int) {
	r.statusCode = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *orderRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Server encapsulates an in-process Pebble ACME test environment.
type Server struct {
	DirectoryURL    string
	HTTPClient      *http.Client
	ChallengeStore  challenge.Store
	ChallengeServer *httptest.Server
	dnsServer       *dns.Server
	dnsListener     net.Listener
	pebbleServer    *httptest.Server
	orderCount      *atomic.Int64

	// mu guards closed state to prevent concurrent or duplicate server shutdown.
	mu     sync.Mutex
	closed bool
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

	// 2. Start mock DNS server that resolves all names to 127.0.0.1 via TCP (which Pebble VA uses)
	dnsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		challengeSrv.Close()
		t.Fatalf("failed to start TCP listener for mock DNS: %v", err)
	}

	dnsHandler := &mockDNSHandler{}
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
	pebbleVA := va.New(logger, challengePort, 0, false, dnsAddr, memDB)
	pebbleWFE := wfe.New(logger, memDB, pebbleVA, pebbleCA, []string{"pebble.letsencrypt.org"}, false, eabRequired, 0, 0)

	orderCount := &atomic.Int64{}
	pebbleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/order-plz" && r.Method == http.MethodPost {
			rec := &orderRecorder{ResponseWriter: w}
			pebbleWFE.Handler().ServeHTTP(rec, r)
			if rec.statusCode == http.StatusCreated {
				orderCount.Add(1)
			}
			return
		}
		pebbleWFE.Handler().ServeHTTP(w, r)
	})

	pebbleSrv := httptest.NewTLSServer(pebbleHandler)
	dirURL := fmt.Sprintf("%s%s", pebbleSrv.URL, wfe.DirectoryPath)

	srv := &Server{
		DirectoryURL:    dirURL,
		HTTPClient:      pebbleSrv.Client(),
		ChallengeStore:  challengeStore,
		ChallengeServer: challengeSrv,
		dnsServer:       dnsSrv,
		dnsListener:     dnsListener,
		pebbleServer:    pebbleSrv,
		orderCount:      orderCount,
	}

	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}

// OrderCount returns the number of ACME orders received by Pebble.
func (s *Server) OrderCount() int {
	if s.orderCount == nil {
		return 0
	}
	return int(s.orderCount.Load())
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

type mockDNSHandler struct{}

func (h *mockDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 127.0.0.1", q.Name))
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
