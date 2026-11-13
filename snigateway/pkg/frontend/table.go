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
	"net"
	"strings"
	"sync"
	"time"
)

// RegistrationTable maps registered hostnames to backend session identifiers.
// It supports multiple sessions registering the same hostname, and supports exact hostnames
// as well as wildcard hostnames (*.example.com), with exact match taking precedence.
type RegistrationTable struct {
	mu              sync.RWMutex
	sessionHosts    map[string][]string       // sessionID -> registered host patterns
	sessionIdentity map[string]ClientIdentity // sessionID -> client identity
	sessionLease    map[string]time.Time      // sessionID -> lease expiration time
	exact           map[string][]string       // normalized exact hostname -> slice of sessionIDs
	wildcard        map[string][]string       // normalized wildcard pattern (*.example.com) -> slice of sessionIDs
	exactRR         map[string]int            // round-robin counter per exact hostname
	wildcardRR      map[string]int            // round-robin counter per wildcard pattern
}

// NewRegistrationTable creates a new empty RegistrationTable.
func NewRegistrationTable() *RegistrationTable {
	return &RegistrationTable{
		sessionHosts:    make(map[string][]string),
		sessionIdentity: make(map[string]ClientIdentity),
		sessionLease:    make(map[string]time.Time),
		exact:           make(map[string][]string),
		wildcard:        make(map[string][]string),
		exactRR:         make(map[string]int),
		wildcardRR:      make(map[string]int),
	}
}

func stripPort(s string) string {
	h, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return h
}

// CleanHostname removes port if present and returns lowercase string.
func CleanHostname(host string) string {
	host = stripPort(host)
	return strings.ToLower(strings.TrimSpace(host))
}

// RegisterSession records a backend session with its verified client identity.
func (t *RegistrationTable) RegisterSession(sessionID string, identity ClientIdentity) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessionIdentity[sessionID] = identity
}

// GetSessionIdentity retrieves the client identity for a session.
func (t *RegistrationTable) GetSessionIdentity(sessionID string) (ClientIdentity, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	id, ok := t.sessionIdentity[sessionID]
	return id, ok
}

// Register sets the full list of hostnames served by sessionID, replacing any previous list for that session.
func (t *RegistrationTable) Register(sessionID string, hostnames []string) {
	t.RegisterWithLease(sessionID, hostnames, time.Time{})
}

// RegisterWithLease sets the hostnames served by sessionID with an optional lease expiration time.
func (t *RegistrationTable) RegisterWithLease(sessionID string, hostnames []string, leaseExpiry time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Clear previous registrations for this session
	t.unregisterLocked(sessionID)

	var registered []string
	for _, rawHost := range hostnames {
		h := CleanHostname(rawHost)
		if h == "" {
			continue
		}
		registered = append(registered, h)
		if strings.HasPrefix(h, "*.") {
			t.wildcard[h] = append(t.wildcard[h], sessionID)
		} else {
			t.exact[h] = append(t.exact[h], sessionID)
		}
	}
	t.sessionHosts[sessionID] = registered
	if !leaseExpiry.IsZero() {
		t.sessionLease[sessionID] = leaseExpiry
	} else {
		delete(t.sessionLease, sessionID)
	}
}

// GetSessionLease returns the lease expiration time for a session, if set.
func (t *RegistrationTable) GetSessionLease(sessionID string) (time.Time, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	exp, ok := t.sessionLease[sessionID]
	return exp, ok
}

// DropExpiredLeases unregisters hostnames for any sessions whose lease has expired before or at now.
// It returns the list of sessionIDs whose registrations expired.
func (t *RegistrationTable) DropExpiredLeases(now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	var expiredSessions []string
	for sessID, exp := range t.sessionLease {
		if !exp.IsZero() && !now.Before(exp) {
			t.unregisterLocked(sessID)
			delete(t.sessionLease, sessID)
			expiredSessions = append(expiredSessions, sessID)
		}
	}
	return expiredSessions
}

// Unregister removes all hostname registrations and identity for sessionID.
func (t *RegistrationTable) Unregister(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.unregisterLocked(sessionID)
	delete(t.sessionIdentity, sessionID)
	delete(t.sessionLease, sessionID)
}

func removeFromSlice(slice []string, val string) []string {
	var res []string
	for _, item := range slice {
		if item != val {
			res = append(res, item)
		}
	}
	return res
}

func (t *RegistrationTable) unregisterLocked(sessionID string) {
	if previous, exists := t.sessionHosts[sessionID]; exists {
		for _, h := range previous {
			if strings.HasPrefix(h, "*.") {
				newSlice := removeFromSlice(t.wildcard[h], sessionID)
				if len(newSlice) == 0 {
					delete(t.wildcard, h)
					delete(t.wildcardRR, h)
				} else {
					t.wildcard[h] = newSlice
				}
			} else {
				newSlice := removeFromSlice(t.exact[h], sessionID)
				if len(newSlice) == 0 {
					delete(t.exact, h)
					delete(t.exactRR, h)
				} else {
					t.exact[h] = newSlice
				}
			}
		}
		delete(t.sessionHosts, sessionID)
	}
}

// Match looks up the best matching sessionID for a given incoming SNI hostname.
// Exact match wins. If no exact match, longest matching wildcard pattern wins.
// If multiple sessions are registered for the matched pattern, selection is round-robined.
func (t *RegistrationTable) Match(hostname string) (string, bool) {
	sessions := t.MatchSessions(hostname)
	if len(sessions) == 0 {
		return "", false
	}
	return sessions[0], true
}

// MatchSessions returns all sessions registered for the matching hostname pattern,
// ordered starting from the round-robin selection.
func (t *RegistrationTable) MatchSessions(hostname string) []string {
	cleanHost := CleanHostname(hostname)
	if cleanHost == "" {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// 1. Exact match
	if sessions, ok := t.exact[cleanHost]; ok && len(sessions) > 0 {
		idx := t.exactRR[cleanHost] % len(sessions)
		t.exactRR[cleanHost]++
		return rotateSessions(sessions, idx)
	}

	// 2. Wildcard match (longest matching wildcard suffix wins)
	var bestPattern string
	bestPatternLen := -1

	for pattern, sessions := range t.wildcard {
		if len(sessions) == 0 {
			continue
		}
		suffix := pattern[1:] // e.g. .example.com
		if len(cleanHost) > len(suffix) && strings.HasSuffix(cleanHost, suffix) {
			if len(pattern) > bestPatternLen {
				bestPatternLen = len(pattern)
				bestPattern = pattern
			}
		}
	}

	if bestPatternLen >= 0 {
		sessions := t.wildcard[bestPattern]
		idx := t.wildcardRR[bestPattern] % len(sessions)
		t.wildcardRR[bestPattern]++
		return rotateSessions(sessions, idx)
	}

	return nil
}

func rotateSessions(sessions []string, start int) []string {
	n := len(sessions)
	if n == 0 {
		return nil
	}
	start = start % n
	res := make([]string, n)
	for i := 0; i < n; i++ {
		res[i] = sessions[(start+i)%n]
	}
	return res
}

// GetRegisteredHostnames returns the hostnames registered for a given sessionID.
func (t *RegistrationTable) GetRegisteredHostnames(sessionID string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hosts, ok := t.sessionHosts[sessionID]
	if !ok {
		return nil
	}
	res := make([]string, len(hosts))
	copy(res, hosts)
	return res
}

// GetRegisteredHostnamesForClient returns all hostnames registered by any active session of clientID.
func (t *RegistrationTable) GetRegisteredHostnamesForClient(clientID string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var res []string
	seen := make(map[string]bool)
	for sid, ident := range t.sessionIdentity {
		if ident.ID == clientID {
			for _, h := range t.sessionHosts[sid] {
				if !seen[h] {
					seen[h] = true
					res = append(res, h)
				}
			}
		}
	}
	return res
}
