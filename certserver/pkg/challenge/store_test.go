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

package challenge

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryStore()

	now := time.Now()
	store.timeNow = func() time.Time { return now }

	token := "lifecycle-token"
	host := "sub.example.com"
	keyAuth := "lifecycle-token.thumbprint"

	// 1. Not found initially
	_, err := store.ResolveChallenge(ctx, "", host, token)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 2. Put
	if err := store.Put(ctx, token, host, keyAuth, now.Add(5*time.Minute), Requester{}); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 3. Resolve with exact host
	res, err := store.ResolveChallenge(ctx, "", host, token)
	if err != nil {
		t.Fatalf("ResolveChallenge failed: %v", err)
	}
	if res != keyAuth {
		t.Fatalf("expected %q, got %q", keyAuth, res)
	}

	// 4. Resolve with port & uppercase
	res, err = store.ResolveChallenge(ctx, "", "SUB.EXAMPLE.COM:443", token)
	if err != nil {
		t.Fatalf("ResolveChallenge with uppercase:port failed: %v", err)
	}
	if res != keyAuth {
		t.Fatalf("expected %q, got %q", keyAuth, res)
	}

	// 5. Host mismatch
	_, err = store.ResolveChallenge(ctx, "", "other.example.com", token)
	if !errors.Is(err, ErrHostMismatch) {
		t.Fatalf("expected ErrHostMismatch, got %v", err)
	}

	// 6. Expiry
	store.timeNow = func() time.Time { return now.Add(6 * time.Minute) }
	_, err = store.ResolveChallenge(ctx, "", host, token)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after expiry, got %v", err)
	}

	// 7. Remove
	if err := store.Put(ctx, "temp-token", host, keyAuth, now.Add(time.Hour), Requester{}); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Remove(ctx, "temp-token"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	_, err = store.ResolveChallenge(ctx, "", host, "temp-token")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after Remove, got %v", err)
	}
}

func TestMemoryStore_GetChallengesForRequester(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryStore()

	now := time.Now()
	store.timeNow = func() time.Time { return now }

	req1 := Requester{
		ClusterID:    "cluster-1",
		Gateway:      "default/gw-1",
		HostnamesKey: "app.example.com",
	}
	candidate1 := Requester{
		ClusterID:    "cluster-1",
		Gateway:      "default/gw-shared",
		HostnamesKey: "app.example.com",
	}

	// 1. Put challenge with primary req1 and candidate candidate1
	if err := store.PutWithCandidates(ctx, "tok-1", "app.example.com", "keyauth-1", now.Add(10*time.Minute), req1, []Requester{candidate1}); err != nil {
		t.Fatalf("PutWithCandidates failed: %v", err)
	}

	// Primary requester matches
	matches1 := store.GetChallengesForRequester(ctx, req1)
	if len(matches1) != 1 || matches1[0].Token != "tok-1" {
		t.Fatalf("expected 1 match for primary requester, got %d", len(matches1))
	}

	// Candidate requester matches
	matchesCandidate := store.GetChallengesForRequester(ctx, candidate1)
	if len(matchesCandidate) != 1 || matchesCandidate[0].Token != "tok-1" {
		t.Fatalf("expected 1 match for candidate requester, got %d", len(matchesCandidate))
	}

	// Different gateway in same cluster does not receive challenge
	reqOtherGW := Requester{
		ClusterID:    "cluster-1",
		Gateway:      "default/gw-other",
		HostnamesKey: "app.example.com",
	}
	matchesOtherGW := store.GetChallengesForRequester(ctx, reqOtherGW)
	if len(matchesOtherGW) != 0 {
		t.Fatalf("expected 0 matches for unrelated gateway, got %d", len(matchesOtherGW))
	}

	// Same gateway in different cluster does not receive challenge
	reqOtherCluster := Requester{
		ClusterID:    "cluster-2",
		Gateway:      "default/gw-1",
		HostnamesKey: "app.example.com",
	}
	matchesOtherCluster := store.GetChallengesForRequester(ctx, reqOtherCluster)
	if len(matchesOtherCluster) != 0 {
		t.Fatalf("expected 0 matches for unrelated cluster, got %d", len(matchesOtherCluster))
	}

	// Expired challenge is not returned
	store.timeNow = func() time.Time { return now.Add(11 * time.Minute) }
	matchesExpired := store.GetChallengesForRequester(ctx, req1)
	if len(matchesExpired) != 0 {
		t.Fatalf("expected 0 matches after expiry, got %d", len(matchesExpired))
	}
}
