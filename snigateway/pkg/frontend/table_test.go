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
	"testing"
	"time"
)

func TestRegistrationTable(t *testing.T) {
	tbl := NewRegistrationTable()

	// Register client A
	tbl.RegisterWithLease("client-a", []string{"foo.example.com", "*.wildcard.org"}, time.Time{})
	// Register client B
	tbl.RegisterWithLease("client-b", []string{"bar.example.com", "*.example.com", "*.sub.wildcard.org"}, time.Time{})

	tests := []struct {
		name       string
		hostname   string
		wantClient string
		wantFound  bool
	}{
		{
			name:       "exact match client A",
			hostname:   "foo.example.com",
			wantClient: "client-a",
			wantFound:  true,
		},
		{
			name:       "exact match client A with port and uppercase",
			hostname:   "FOO.EXAMPLE.COM:443",
			wantClient: "client-a",
			wantFound:  true,
		},
		{
			name:       "exact match client A with trailing dot",
			hostname:   "foo.example.com.",
			wantClient: "client-a",
			wantFound:  true,
		},
		{
			name:       "exact match client A with port, uppercase, and trailing dot",
			hostname:   "FOO.EXAMPLE.COM.:443",
			wantClient: "client-a",
			wantFound:  true,
		},
		{
			name:       "exact match client B",
			hostname:   "bar.example.com",
			wantClient: "client-b",
			wantFound:  true,
		},
		{
			name:       "wildcard match client B",
			hostname:   "other.example.com",
			wantClient: "client-b",
			wantFound:  true,
		},
		{
			name:       "longer wildcard match (*.sub.wildcard.org vs *.wildcard.org)",
			hostname:   "app.sub.wildcard.org",
			wantClient: "client-b",
			wantFound:  true,
		},
		{
			name:       "shorter wildcard match (*.wildcard.org)",
			hostname:   "other.wildcard.org",
			wantClient: "client-a",
			wantFound:  true,
		},
		{
			name:       "unknown domain",
			hostname:   "unregistered.net",
			wantClient: "",
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := tbl.MatchSessions(tt.hostname)
			gotFound := len(sessions) > 0
			var gotClient string
			if gotFound {
				gotClient = sessions[0]
			}
			if gotFound != tt.wantFound {
				t.Fatalf("MatchSessions(%q) gotFound = %v, want %v", tt.hostname, gotFound, tt.wantFound)
			}
			if gotClient != tt.wantClient {
				t.Fatalf("MatchSessions(%q) gotClient = %q, want %q", tt.hostname, gotClient, tt.wantClient)
			}
		})
	}

	// Test exact match wins over wildcard when both are registered
	tbl.RegisterWithLease("client-c", []string{"exact.example.com"}, time.Time{})
	sessions := tbl.MatchSessions("exact.example.com")
	if len(sessions) == 0 || sessions[0] != "client-c" {
		t.Fatalf("expected client-c for exact.example.com, got %v", sessions)
	}

	// Test unregister client-c, now wildcard (*.example.com -> client-b) takes over
	tbl.Unregister("client-c")
	sessions = tbl.MatchSessions("exact.example.com")
	if len(sessions) == 0 || sessions[0] != "client-b" {
		t.Fatalf("expected fallback to client-b for exact.example.com, got %v", sessions)
	}

	// Test re-registration replaces previous hostnames
	tbl.RegisterWithLease("client-a", []string{"new.domain.com"}, time.Time{})
	sessions = tbl.MatchSessions("foo.example.com")
	if len(sessions) > 0 && sessions[0] == "client-a" {
		t.Fatalf("foo.example.com should have been unregistered for client-a")
	}
	sessions = tbl.MatchSessions("new.domain.com")
	if len(sessions) == 0 || sessions[0] != "client-a" {
		t.Fatalf("expected client-a for new.domain.com")
	}
}

func TestRegistrationTable_MultipleClientsPerHostname(t *testing.T) {
	tbl := NewRegistrationTable()

	// Register 2 clients for the same exact hostname
	tbl.RegisterWithLease("client-1", []string{"shared.example.com", "*.shared.wildcard"}, time.Time{})
	tbl.RegisterWithLease("client-2", []string{"shared.example.com", "*.shared.wildcard"}, time.Time{})

	// Matching exact hostname should round-robin between client-1 and client-2
	s1 := tbl.MatchSessions("shared.example.com")
	s2 := tbl.MatchSessions("shared.example.com")
	s3 := tbl.MatchSessions("shared.example.com")

	if len(s1) == 0 || len(s2) == 0 || len(s3) == 0 {
		t.Fatalf("expected matches for shared.example.com")
	}
	m1, m2, m3 := s1[0], s2[0], s3[0]
	if m1 != "client-1" || m2 != "client-2" || m3 != "client-1" {
		t.Fatalf("expected round robin [client-1, client-2, client-1], got [%s, %s, %s]", m1, m2, m3)
	}

	// Matching wildcard should also round-robin
	ws1 := tbl.MatchSessions("foo.shared.wildcard")
	ws2 := tbl.MatchSessions("bar.shared.wildcard")
	ws3 := tbl.MatchSessions("baz.shared.wildcard")

	if len(ws1) == 0 || len(ws2) == 0 || len(ws3) == 0 {
		t.Fatalf("expected matches for wildcard")
	}
	w1, w2, w3 := ws1[0], ws2[0], ws3[0]
	if w1 != "client-1" || w2 != "client-2" || w3 != "client-1" {
		t.Fatalf("expected round robin wildcard [client-1, client-2, client-1], got [%s, %s, %s]", w1, w2, w3)
	}

	// Unregister client-1; client-2 should now get all requests
	tbl.Unregister("client-1")
	u1 := tbl.MatchSessions("shared.example.com")
	u2 := tbl.MatchSessions("shared.example.com")
	if len(u1) == 0 || len(u2) == 0 || u1[0] != "client-2" || u2[0] != "client-2" {
		t.Fatalf("expected client-2 after client-1 unregistered, got [%v, %v]", u1, u2)
	}

	// Unregister client-2; hostname should be not found
	tbl.Unregister("client-2")
	if u3 := tbl.MatchSessions("shared.example.com"); len(u3) > 0 {
		t.Fatalf("expected not found after all clients unregistered, got %v", u3)
	}
}

func TestRegistrationTable_Lease(t *testing.T) {
	tbl := NewRegistrationTable()
	now := time.Now()

	// 1. Register with lease in future
	tbl.RegisterWithLease("sess-1", []string{"foo.example.com"}, now.Add(10*time.Second))
	tbl.RegisterWithLease("sess-2", []string{"bar.example.com"}, now.Add(2*time.Second))

	// Match succeeds
	if sessions := tbl.MatchSessions("foo.example.com"); len(sessions) == 0 {
		t.Fatal("expected match for foo.example.com")
	}
	if sessions := tbl.MatchSessions("bar.example.com"); len(sessions) == 0 {
		t.Fatal("expected match for bar.example.com")
	}

	// 2. DropExpiredLeases at now + 5s (sess-2 expires, sess-1 still valid)
	expired := tbl.DropExpiredLeases(now.Add(5 * time.Second))
	if len(expired) != 1 || expired[0] != "sess-2" {
		t.Fatalf("expected expired [sess-2], got %v", expired)
	}

	if sessions := tbl.MatchSessions("bar.example.com"); len(sessions) > 0 {
		t.Fatal("expected bar.example.com to no longer match after lease expired")
	}
	if sessions := tbl.MatchSessions("foo.example.com"); len(sessions) == 0 {
		t.Fatal("expected foo.example.com to still match")
	}

	// 3. Extend sess-1 before it expires
	tbl.RegisterWithLease("sess-1", []string{"foo.example.com"}, now.Add(20*time.Second))

	// DropExpiredLeases at now + 15s (sess-1 should NOT expire because extended to 20s)
	expired = tbl.DropExpiredLeases(now.Add(15 * time.Second))
	if len(expired) != 0 {
		t.Fatalf("expected no expired sessions, got %v", expired)
	}

	// DropExpiredLeases at now + 25s (sess-1 now expires)
	expired = tbl.DropExpiredLeases(now.Add(25 * time.Second))
	if len(expired) != 1 || expired[0] != "sess-1" {
		t.Fatalf("expected expired [sess-1], got %v", expired)
	}
	if sessions := tbl.MatchSessions("foo.example.com"); len(sessions) > 0 {
		t.Fatal("expected foo.example.com to no longer match after lease expired")
	}
}

func TestCleanHostname(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "trailing dot",
			input: "a.example.com.",
			want:  "a.example.com",
		},
		{
			name:  "uppercase with trailing dot",
			input: "A.Example.COM.",
			want:  "a.example.com",
		},
		{
			name:  "dot only",
			input: ".",
			want:  "",
		},
		{
			name:  "standard hostname",
			input: "a.example.com",
			want:  "a.example.com",
		},
		{
			name:  "uppercase standard hostname",
			input: "A.Example.COM",
			want:  "a.example.com",
		},
		{
			name:  "trailing dot with port",
			input: "a.example.com.:443",
			want:  "a.example.com",
		},
		{
			name:  "port and uppercase",
			input: "A.EXAMPLE.COM:80",
			want:  "a.example.com",
		},
		{
			name:  "two trailing dots strips only one",
			input: "a.example.com..",
			want:  "a.example.com.",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanHostname(tt.input)
			if got != tt.want {
				t.Errorf("CleanHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
