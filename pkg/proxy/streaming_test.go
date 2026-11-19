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

package proxy

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// TestProxyStreamsServerSentEvents checks that an event reaches the client
// while the backend's response is still open. The backend sends one event
// and then waits; a proxy that only forwards full buffers would deliver
// nothing until the response ended.
func TestProxyStreamsServerSentEvents(t *testing.T) {
	release := make(chan struct{})
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("data: first\n\n")); err != nil {
			t.Errorf("failed to write backend event: %v", err)
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}))
	// Cleanups run last-registered first: the backend must be released
	// before the servers can finish closing.
	t.Cleanup(backendServer.Close)

	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("failed to parse backend server url: %v", err)
	}
	port, err := strconv.Atoi(backendURL.Port())
	if err != nil {
		t.Fatalf("failed to parse backend server port: %v", err)
	}

	proxyHandler := NewProxy()
	proxyHandler.UpdateRoutes([]state.InternalRoute{{
		Rules: []state.InternalRule{{
			Backends: []state.InternalBackend{{Host: backendURL.Hostname(), Port: int32(port), Weight: 1}},
		}},
	}})
	proxyServer := httptest.NewServer(proxyHandler)
	t.Cleanup(proxyServer.Close)
	t.Cleanup(func() { close(release) })

	type readResult struct {
		line string
		err  error
	}
	got := make(chan readResult, 1)
	go func() {
		resp, err := http.Get(proxyServer.URL + "/events")
		if err != nil {
			got <- readResult{err: err}
			return
		}
		defer resp.Body.Close()
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		got <- readResult{line: line, err: err}
	}()

	select {
	case result := <-got:
		if result.err != nil {
			t.Fatalf("reading the first event: %v", result.err)
		}
		if result.line != "data: first\n" {
			t.Errorf("first line = %q, want %q", result.line, "data: first\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event did not reach the client while the response was open")
	}
}
