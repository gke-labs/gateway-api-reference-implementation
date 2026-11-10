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

package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/rand"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/cache"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/metrics"
)

type renewalItem struct {
	hostnamesKey string
	metricID     string
	hostnames    []string
	cert         *cache.Certificate
	state        metrics.State
	renewAt      time.Time
	retryCount   int
	nextRetry    time.Time
	backoff      time.Duration
}

// metricSetID computes a short stable identifier for a hostname set.
func metricSetID(hostnamesKey string) string {
	h := sha256.Sum256([]byte(hostnamesKey))
	return hex.EncodeToString(h[:8])
}

// trackCertificateLocked registers or updates a certificate in the renewal tracker.
// Precondition: m.mu is held.
func (m *Manager) trackCertificateLocked(cert *cache.Certificate, now time.Time) {
	if cert == nil || cert.HostnamesKey == "" {
		return
	}

	renewAt := m.computeRenewAt(cert)
	state := metrics.StateValid
	if cert.IsExpired(now) {
		state = metrics.StateExpired
	} else if now.After(renewAt) {
		state = metrics.StateRenewing
	}

	metricID := metricSetID(cert.HostnamesKey)
	log.Printf("certserver: mapped certificate hostname set %q to metric ID %s", cert.HostnamesKey, metricID)

	m.renewals[cert.HostnamesKey] = &renewalItem{
		hostnamesKey: cert.HostnamesKey,
		metricID:     metricID,
		hostnames:    cert.Hostnames,
		cert:         cert,
		state:        state,
		renewAt:      renewAt,
		retryCount:   0,
	}

	m.updateMetricsLocked(now)
}

// computeRenewAt calculates when to renew a certificate (about 2/3 of lifetime with jitter).
func (m *Manager) computeRenewAt(cert *cache.Certificate) time.Time {
	lifetime := cert.ExpiresAt.Sub(cert.IssuedAt)
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}

	threshold := time.Duration(float64(lifetime) * m.opts.RenewalRatio)
	renewAt := cert.IssuedAt.Add(threshold)

	if m.opts.RenewalJitterPercent > 0 {
		jitterWindow := time.Duration(float64(lifetime) * m.opts.RenewalJitterPercent)
		if jitterWindow > 0 {
			jitter := time.Duration(rand.Int63n(int64(2*jitterWindow))) - jitterWindow
			renewAt = renewAt.Add(jitter)
		}
	}

	return renewAt
}

// updateMetricsLocked refreshes Prometheus metrics based on the current tracker state.
// Precondition: m.mu is held.
func (m *Manager) updateMetricsLocked(now time.Time) {
	if m.metrics == nil {
		return
	}

	validCount := 0
	renewingCount := 0
	expiredCount := 0

	for _, item := range m.renewals {
		switch item.state {
		case metrics.StateValid:
			validCount++
		case metrics.StateRenewing:
			renewingCount++
		case metrics.StateExpired:
			expiredCount++
		}

		remainingSeconds := item.cert.ExpiresAt.Sub(now).Seconds()
		m.metrics.SetCertificateExpiry(item.metricID, remainingSeconds)
	}

	m.metrics.SetCertificatesCount(metrics.StateValid, float64(validCount))
	m.metrics.SetCertificatesCount(metrics.StateRenewing, float64(renewingCount))
	m.metrics.SetCertificatesCount(metrics.StateExpired, float64(expiredCount))
}

// runRenewalLoop executes the background renewal checks periodically.
func (m *Manager) runRenewalLoop(ctx context.Context) {
	defer m.loopWg.Done()

	interval := m.opts.RenewalCheckInterval
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.CheckRenewals(ctx); err != nil && ctx.Err() != nil {
				return
			}
		}
	}
}

// CheckRenewals inspects all tracked certificates, executing renewals that are due.
func (m *Manager) CheckRenewals(ctx context.Context) error {
	now := m.opts.Clock.Now()
	if m.opts.BindingStore != nil {
		m.opts.BindingStore.Prune(now, 30*24*time.Hour)
	}

	m.mu.Lock()

	type dueTask struct {
		hostnamesKey string
		hostnames    []string
		retryCount   int
		requester    challenge.Requester
		candidates   []challenge.Requester
	}

	var dueTasks []dueTask

	for _, item := range m.renewals {
		if item.cert.IsExpired(now) {
			item.state = metrics.StateExpired
		}

		isDue := false
		if item.retryCount == 0 {
			if now.After(item.renewAt) {
				isDue = true
			}
		} else {
			if now.After(item.nextRetry) {
				isDue = true
			}
		}

		if isDue {
			item.state = metrics.StateRenewing
			var candidates []challenge.Requester
			if m.opts.BindingStore != nil {
				for _, binding := range m.opts.BindingStore.ListBindings() {
					_, bKey, err := NormalizeHostnames(binding.Hostnames, m.opts.MaxHostnamesPerSet, m.opts.MaxHostnameLength)
					if err != nil || bKey != item.hostnamesKey {
						continue
					}
					// Build candidates only from Gateways that hold a validated binding for that hostnames key.
					if _, ok := m.opts.BindingStore.GetValidatedBinding(binding.ClusterID, binding.Gateway, item.hostnamesKey); ok {
						candidate := challenge.Requester{
							ClusterID:               binding.ClusterID,
							Gateway:                 binding.Gateway,
							DataPlaneServiceAccount: binding.DataPlaneServiceAccount,
							HostnamesKey:            item.hostnamesKey,
						}
						candidates = append(candidates, candidate)
					}
				}
			}

			if len(candidates) == 0 && item.cert != nil {
				// Fall back to the Gateway that the certificate was issued to.
				candidates = append(candidates, challenge.Requester{
					ClusterID:               item.cert.ClusterID,
					Gateway:                 item.cert.Gateway,
					DataPlaneServiceAccount: item.cert.DataPlaneServiceAccount,
					HostnamesKey:            item.hostnamesKey,
				})
			}

			var req challenge.Requester
			if item.cert != nil {
				req = challenge.Requester{
					ClusterID:               item.cert.ClusterID,
					Gateway:                 item.cert.Gateway,
					DataPlaneServiceAccount: item.cert.DataPlaneServiceAccount,
					HostnamesKey:            item.hostnamesKey,
				}
			} else if len(candidates) > 0 {
				req = candidates[0]
			}

			dueTasks = append(dueTasks, dueTask{
				hostnamesKey: item.hostnamesKey,
				hostnames:    item.hostnames,
				retryCount:   item.retryCount,
				requester:    req,
				candidates:   candidates,
			})
		}
	}
	m.updateMetricsLocked(now)
	m.mu.Unlock()

	// Execute renewals through Renew to coalesce via renewSf, bound pending orders, and always issue a new certificate
	for _, task := range dueTasks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		newCert, err := m.Renew(ctx, task.hostnames, task.requester, task.candidates)
		now = m.opts.Clock.Now()

		m.mu.Lock()
		item, exists := m.renewals[task.hostnamesKey]
		if exists {
			if err != nil {
				// On failure: retry with capped exponential backoff and keep serving existing certificate
				item.retryCount++
				shift := item.retryCount - 1
				if shift > 30 {
					shift = 30
				}
				backoff := m.opts.InitialRetryBackoff * (1 << shift)
				if backoff > m.opts.MaxRetryBackoff || backoff <= 0 {
					backoff = m.opts.MaxRetryBackoff
				}
				item.backoff = backoff
				item.nextRetry = now.Add(backoff)
				if item.cert.IsExpired(now) {
					item.state = metrics.StateExpired
				} else {
					item.state = metrics.StateRenewing
				}
				log.Printf("certserver: certificate renewal failed for %s (attempt %d, next retry in %v; DNS may no longer point to an authorized gateway): %v",
					task.hostnamesKey, item.retryCount, backoff, err)
			} else {
				// On success: reset retry state, update certificate and recompute renewal time
				item.cert = newCert
				item.retryCount = 0
				item.backoff = 0
				item.renewAt = m.computeRenewAt(newCert)
				if now.Before(newCert.ExpiresAt) {
					item.state = metrics.StateValid
				} else {
					item.state = metrics.StateExpired
				}
			}
		}
		m.updateMetricsLocked(now)
		m.mu.Unlock()
	}

	return nil
}

// GetTrackedState returns the renewal tracking state for a hostnames key.
func (m *Manager) GetTrackedState(hostnamesKey string) (metrics.State, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.renewals[hostnamesKey]
	if !ok {
		return "", false
	}
	return item.state, true
}
