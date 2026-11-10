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
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

var (
	// ErrNotFound is returned when a challenge token is not found or has expired.
	ErrNotFound = errors.New("challenge token not found or expired")

	// ErrHostMismatch is returned when the request host does not match the token's identifier.
	ErrHostMismatch = errors.New("request host does not match challenge identifier")
)

// Requester contains identity information of the Gateway requesting certificate issuance.
type Requester struct {
	ClusterID               string `json:"cluster_id"`
	Gateway                 string `json:"gateway"`
	DataPlaneServiceAccount string `json:"data_plane_service_account"`
	HostnamesKey            string `json:"hostnames_key"`
}

// Item represents an active ACME challenge in the store.
type Item struct {
	Token               string                    `json:"token"`
	Identifier          string                    `json:"identifier"` // normalized host
	KeyAuth             string                    `json:"key_auth"`
	ExpiresAt           time.Time                 `json:"expires_at"`
	Requester           Requester                 `json:"requester"`
	CandidateRequesters []Requester               `json:"candidate_requesters,omitempty"`
	AnsweringIdentities []registry.CallerIdentity `json:"answering_identities,omitempty"`
}

// ChallengeResolver provides a lookup method for HTTP-01 challenge responses,
// accepting a caller identity to support future authentication and challenge binding.
type ChallengeResolver interface {
	ResolveChallenge(ctx context.Context, caller string, host string, token string) (string, error)
}

// Store defines the interface for registering, resolving, and removing pending ACME challenges.
type Store interface {
	ChallengeResolver
	Put(ctx context.Context, token string, identifier string, keyAuth string, expiresAt time.Time, req Requester) error
	PutWithCandidates(ctx context.Context, token string, identifier string, keyAuth string, expiresAt time.Time, req Requester, candidates []Requester) error
	Get(ctx context.Context, token string) (*Item, error)
	GetChallengesForRequester(ctx context.Context, req Requester) []*Item
	RecordAnswer(ctx context.Context, token string, identity registry.CallerIdentity) error
	Remove(ctx context.Context, token string) error
}

// MemoryStore is an in-memory thread-safe implementation of Store.
type MemoryStore struct {
	// mu guards the challenges map.
	mu         sync.RWMutex
	challenges map[string]*Item

	timeNow func() time.Time
}

// NewMemoryStore initializes a new in-memory challenge store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		challenges: make(map[string]*Item),
		timeNow:    time.Now,
	}
}

// Put adds or updates a pending challenge with an explicit requester.
func (s *MemoryStore) Put(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req Requester) error {
	return s.PutWithCandidates(ctx, token, identifier, keyAuth, expiresAt, req, nil)
}

// PutWithCandidates adds or updates a pending challenge with a primary requester and candidate requesters.
func (s *MemoryStore) PutWithCandidates(ctx context.Context, token, identifier, keyAuth string, expiresAt time.Time, req Requester, candidates []Requester) error {
	normHost := NormalizeHost(identifier)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[token] = &Item{
		Token:               token,
		Identifier:          normHost,
		KeyAuth:             keyAuth,
		ExpiresAt:           expiresAt,
		Requester:           req,
		CandidateRequesters: candidates,
	}
	return nil
}

// Get returns a safe copy of the challenge item for token, or ErrNotFound if not found or expired.
// Copy is performed while holding the initial lock to avoid race conditions.
func (s *MemoryStore) Get(ctx context.Context, token string) (*Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.challenges[token]
	if !ok {
		return nil, ErrNotFound
	}

	now := s.timeNow()
	if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
		delete(s.challenges, token)
		return nil, ErrNotFound
	}

	cp := *item
	if len(item.AnsweringIdentities) > 0 {
		cp.AnsweringIdentities = make([]registry.CallerIdentity, len(item.AnsweringIdentities))
		copy(cp.AnsweringIdentities, item.AnsweringIdentities)
	}
	if len(item.CandidateRequesters) > 0 {
		cp.CandidateRequesters = make([]Requester, len(item.CandidateRequesters))
		copy(cp.CandidateRequesters, item.CandidateRequesters)
	}
	return &cp, nil
}

// GetChallengesForRequester returns all active challenges matching the given requester
// either as primary requester or as candidate requester.
func (s *MemoryStore) GetChallengesForRequester(ctx context.Context, req Requester) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.timeNow()
	var matches []*Item
	for _, item := range s.challenges {
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			continue
		}
		if requesterMatches(item, req) {
			cp := *item
			matches = append(matches, &cp)
		}
	}
	return matches
}

func requesterMatches(item *Item, req Requester) bool {
	if item.Requester.ClusterID == req.ClusterID && item.Requester.Gateway == req.Gateway {
		if req.HostnamesKey == "" || item.Requester.HostnamesKey == "" || item.Requester.HostnamesKey == req.HostnamesKey {
			return true
		}
	}
	for _, candidate := range item.CandidateRequesters {
		if candidate.ClusterID == req.ClusterID && candidate.Gateway == req.Gateway {
			if req.HostnamesKey == "" || candidate.HostnamesKey == "" || candidate.HostnamesKey == req.HostnamesKey {
				return true
			}
		}
	}
	return false
}

// RecordAnswer appends the answering caller identity to the challenge item.
func (s *MemoryStore) RecordAnswer(ctx context.Context, token string, identity registry.CallerIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.challenges[token]
	if !ok {
		return ErrNotFound
	}
	item.AnsweringIdentities = append(item.AnsweringIdentities, identity)
	return nil
}

// Remove deletes a challenge by token.
func (s *MemoryStore) Remove(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, token)
	return nil
}

// ResolveChallenge looks up the challenge response for the specified token and host,
// validating token existence, expiry, and identifier matching.
func (s *MemoryStore) ResolveChallenge(ctx context.Context, caller string, host string, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.challenges[token]
	if !ok {
		return "", ErrNotFound
	}

	now := s.timeNow()
	if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
		delete(s.challenges, token)
		return "", ErrNotFound
	}

	normReqHost := NormalizeHost(host)
	if normReqHost != item.Identifier {
		return "", ErrHostMismatch
	}

	return item.KeyAuth, nil
}

// NormalizeHost strips optional port and lowers the hostname string.
func NormalizeHost(host string) string {
	h := strings.TrimSpace(host)
	if strings.Contains(h, ":") {
		if parsedHost, _, err := net.SplitHostPort(h); err == nil {
			h = parsedHost
		} else {
			// Fallback for malformed host:port strings
			h = strings.Split(h, ":")[0]
		}
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}
