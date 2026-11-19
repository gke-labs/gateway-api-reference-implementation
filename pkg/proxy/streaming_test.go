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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"sigs.k8s.io/controller-runtime/pkg/log"
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

// nonFlushingResponseWriter wraps an http.ResponseWriter without exposing
// http.Flusher or Unwrap, so http.NewResponseController(w).Flush() returns
// http.ErrNotSupported.
type nonFlushingResponseWriter struct {
	http.ResponseWriter
}

type recordLogSink struct {
	mu      sync.Mutex
	entries []recordedLogEntry
}

type recordedLogEntry struct {
	err           error
	msg           string
	keysAndValues map[string]any
}

func (s *recordLogSink) Init(info logr.RuntimeInfo) {}
func (s *recordLogSink) Enabled(level int) bool     { return true }

func (s *recordLogSink) Info(level int, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, recordedLogEntry{
		msg:           msg,
		keysAndValues: keysAndValuesToMap(keysAndValues),
	})
}

func (s *recordLogSink) Error(err error, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, recordedLogEntry{
		err:           err,
		msg:           msg,
		keysAndValues: keysAndValuesToMap(keysAndValues),
	})
}

func (s *recordLogSink) WithValues(keysAndValues ...any) logr.LogSink { return s }
func (s *recordLogSink) WithName(name string) logr.LogSink            { return s }

func keysAndValuesToMap(kvs []any) map[string]any {
	m := make(map[string]any)
	for i := 0; i < len(kvs)-1; i += 2 {
		if k, ok := kvs[i].(string); ok {
			m[k] = kvs[i+1]
		}
	}
	return m
}

// TestProxyStreamWhenFlushingNotSupported verifies that when the response writer
// does not support flushing (http.ErrNotSupported), the streamed response body
// is still copied in full to the client, and an error is logged once for that
// response (not once per write) with the request method and path, and the response
// content type.
func TestProxyStreamWhenFlushingNotSupported(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("data: first\n\n")); err != nil {
			t.Errorf("failed to write first chunk: %v", err)
			return
		}
		if _, err := w.Write([]byte("data: second\n\n")); err != nil {
			t.Errorf("failed to write second chunk: %v", err)
			return
		}
	}))
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

	sink := &recordLogSink{}
	logger := logr.New(sink)

	rec := httptest.NewRecorder()
	w := &nonFlushingResponseWriter{ResponseWriter: rec}

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req = req.WithContext(log.IntoContext(req.Context(), logger))

	proxyHandler.ServeHTTP(w, req)

	// Verify that the body was fully copied despite flushing returning ErrNotSupported.
	if got, want := rec.Body.String(), "data: first\n\ndata: second\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	sink.mu.Lock()
	entries := make([]recordedLogEntry, len(sink.entries))
	copy(entries, sink.entries)
	sink.mu.Unlock()

	// Verify that exactly one log entry was emitted for this response (not one per write).
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	entry := entries[0]
	if !errors.Is(entry.err, http.ErrNotSupported) {
		t.Errorf("logged err = %v, want ErrNotSupported", entry.err)
	}
	if got := entry.keysAndValues["method"]; got != http.MethodGet {
		t.Errorf("logged method = %v, want %q", got, http.MethodGet)
	}
	if got := entry.keysAndValues["path"]; got != "/events" {
		t.Errorf("logged path = %v, want %q", got, "/events")
	}
	if got := entry.keysAndValues["contentType"]; got != "text/event-stream" {
		t.Errorf("logged contentType = %v, want %q", got, "text/event-stream")
	}

	// Verify that a second streamed response also gets logged once for that response.
	rec2 := httptest.NewRecorder()
	w2 := &nonFlushingResponseWriter{ResponseWriter: rec2}

	req2 := httptest.NewRequest(http.MethodPost, "/events-second", nil)
	req2 = req2.WithContext(log.IntoContext(req2.Context(), logger))

	proxyHandler.ServeHTTP(w2, req2)

	if got, want := rec2.Body.String(), "data: first\n\ndata: second\n\n"; got != want {
		t.Errorf("second response body = %q, want %q", got, want)
	}

	sink.mu.Lock()
	entries = make([]recordedLogEntry, len(sink.entries))
	copy(entries, sink.entries)
	sink.mu.Unlock()

	if len(entries) != 2 {
		t.Fatalf("got %d total log entries after two responses, want 2", len(entries))
	}
	entry2 := entries[1]
	if got := entry2.keysAndValues["method"]; got != http.MethodPost {
		t.Errorf("second response logged method = %v, want %q", got, http.MethodPost)
	}
	if got := entry2.keysAndValues["path"]; got != "/events-second" {
		t.Errorf("second response logged path = %v, want %q", got, "/events-second")
	}
	if got := entry2.keysAndValues["contentType"]; got != "text/event-stream" {
		t.Errorf("second response logged contentType = %v, want %q", got, "text/event-stream")
	}
}

