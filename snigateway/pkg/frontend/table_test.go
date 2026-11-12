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
	tbl.Register("client-a", []string{"foo.example.com", "*.wildcard.org"})
	// Register client B
	tbl.Register("client-b", []string{"bar.example.com", "*.example.com", "*.sub.wildcard.org"})

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
			gotClient, gotFound := tbl.Match(tt.hostname)
			if gotFound != tt.wantFound {
				t.Fatalf("Match(%q) gotFound = %v, want %v", tt.hostname, gotFound, tt.wantFound)
			}
			if gotClient != tt.wantClient {
				t.Fatalf("Match(%q) gotClient = %q, want %q", tt.hostname, gotClient, tt.wantClient)
			}
		})
	}

	// Test exact match wins over wildcard when both are registered
	tbl.Register("client-c", []string{"exact.example.com"})
	gotClient, gotFound := tbl.Match("exact.example.com")
	if !gotFound || gotClient != "client-c" {
		t.Fatalf("expected client-c for exact.example.com, got %s (found=%v)", gotClient, gotFound)
	}

	// Test unregister client-c, now wildcard (*.example.com -> client-b) takes over
	tbl.Unregister("client-c")
	gotClient, gotFound = tbl.Match("exact.example.com")
	if !gotFound || gotClient != "client-b" {
		t.Fatalf("expected fallback to client-b for exact.example.com, got %s (found=%v)", gotClient, gotFound)
	}

	// Test re-registration replaces previous hostnames
	tbl.Register("client-a", []string{"new.domain.com"})
	gotClient, gotFound = tbl.Match("foo.example.com")
	if gotFound && gotClient == "client-a" {
		t.Fatalf("foo.example.com should have been unregistered for client-a")
	}
	gotClient, gotFound = tbl.Match("new.domain.com")
	if !gotFound || gotClient != "client-a" {
		t.Fatalf("expected client-a for new.domain.com")
	}
}

func TestRegistrationTable_MultipleClientsPerHostname(t *testing.T) {
	tbl := NewRegistrationTable()

	// Register 2 clients for the same exact hostname
	tbl.Register("client-1", []string{"shared.example.com", "*.shared.wildcard"})
	tbl.Register("client-2", []string{"shared.example.com", "*.shared.wildcard"})

	// Matching exact hostname should round-robin between client-1 and client-2
	m1, ok1 := tbl.Match("shared.example.com")
	m2, ok2 := tbl.Match("shared.example.com")
	m3, ok3 := tbl.Match("shared.example.com")

	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("expected matches for shared.example.com")
	}
	if m1 != "client-1" || m2 != "client-2" || m3 != "client-1" {
		t.Fatalf("expected round robin [client-1, client-2, client-1], got [%s, %s, %s]", m1, m2, m3)
	}

	// Matching wildcard should also round-robin
	w1, wok1 := tbl.Match("foo.shared.wildcard")
	w2, wok2 := tbl.Match("bar.shared.wildcard")
	w3, wok3 := tbl.Match("baz.shared.wildcard")

	if !wok1 || !wok2 || !wok3 {
		t.Fatalf("expected matches for wildcard")
	}
	if w1 != "client-1" || w2 != "client-2" || w3 != "client-1" {
		t.Fatalf("expected round robin wildcard [client-1, client-2, client-1], got [%s, %s, %s]", w1, w2, w3)
	}

	// Unregister client-1; client-2 should now get all requests
	tbl.Unregister("client-1")
	u1, uok1 := tbl.Match("shared.example.com")
	u2, uok2 := tbl.Match("shared.example.com")
	if !uok1 || !uok2 || u1 != "client-2" || u2 != "client-2" {
		t.Fatalf("expected client-2 after client-1 unregistered, got [%s, %s]", u1, u2)
	}

	// Unregister client-2; hostname should be not found
	tbl.Unregister("client-2")
	_, uok3 := tbl.Match("shared.example.com")
	if uok3 {
		t.Fatalf("expected not found after all clients unregistered")
	}
}

func TestRegistrationTable_Lease(t *testing.T) {
	tbl := NewRegistrationTable()
	now := time.Now()

	// 1. Register with lease in future
	tbl.RegisterWithLease("sess-1", []string{"foo.example.com"}, now.Add(10*time.Second))
	tbl.RegisterWithLease("sess-2", []string{"bar.example.com"}, now.Add(2*time.Second))

	// Match succeeds
	if _, ok := tbl.Match("foo.example.com"); !ok {
		t.Fatal("expected match for foo.example.com")
	}
	if _, ok := tbl.Match("bar.example.com"); !ok {
		t.Fatal("expected match for bar.example.com")
	}

	// 2. DropExpiredLeases at now + 5s (sess-2 expires, sess-1 still valid)
	expired := tbl.DropExpiredLeases(now.Add(5 * time.Second))
	if len(expired) != 1 || expired[0] != "sess-2" {
		t.Fatalf("expected expired [sess-2], got %v", expired)
	}

	if _, ok := tbl.Match("bar.example.com"); ok {
		t.Fatal("expected bar.example.com to no longer match after lease expired")
	}
	if _, ok := tbl.Match("foo.example.com"); !ok {
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
	if _, ok := tbl.Match("foo.example.com"); ok {
		t.Fatal("expected foo.example.com to no longer match after lease expired")
	}
}
