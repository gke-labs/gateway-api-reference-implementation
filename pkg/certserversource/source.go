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

package certserversource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/client"
	certserverv1 "github.com/gke-labs/gateway-api-reference-implementation/certserver/api/v1"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const (
	defaultMinBackoff     = 1 * time.Second
	defaultMaxBackoff     = 30 * time.Second
	defaultCheckInterval  = 1 * time.Minute
	defaultEvictionPeriod = 5 * time.Minute
	defaultLogInterval    = 30 * time.Second
)

// CertClient is the interface representing the pure certserver client.
type CertClient interface {
	GetCertificate(ctx context.Context, req *certserverv1.GetCertificateRequest) (*client.CertificateInfo, error)
	Close() error
}

type cacheKey struct {
	gateway   types.NamespacedName
	hostnames string
}

type entryState int

const (
	statePending entryState = iota
	stateReady
	stateFailed
)

type cacheEntry struct {
	key         cacheKey
	hostnames   []string
	gateway     string
	dataPlaneSA string
	addresses   []string

	state        entryState
	certificate  *tls.Certificate
	leaf         *x509.Certificate
	expiresAt    time.Time
	refreshAt    time.Time
	failedReason string

	inFlight      bool
	lastRequested time.Time
	lastLogged    time.Time
}

// Source implements GARI's CertificateSource adapter backed by a pure certserver client.
type Source struct {
	client         CertClient
	minBackoff     time.Duration
	maxBackoff     time.Duration
	checkInterval  time.Duration
	renewalWindow  time.Duration
	evictionPeriod time.Duration
	logInterval    time.Duration
	clusterID      string
	timeNow        func() time.Time

	// mu guards cache and recomputeTrigger.
	mu               sync.Mutex
	cache            map[cacheKey]*cacheEntry
	recomputeTrigger func()

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	stopCh    chan struct{}
}

// SourceOption configures optional parameters on Source.
type SourceOption func(*Source)

// WithMinBackoff overrides the minimum backoff for retrying failed issuance.
func WithMinBackoff(d time.Duration) SourceOption {
	return func(s *Source) {
		s.minBackoff = d
	}
}

// WithMaxBackoff overrides the maximum backoff for retrying failed issuance.
func WithMaxBackoff(d time.Duration) SourceOption {
	return func(s *Source) {
		s.maxBackoff = d
	}
}

// WithCheckInterval overrides the ticker interval for periodic renewal checks.
func WithCheckInterval(d time.Duration) SourceOption {
	return func(s *Source) {
		s.checkInterval = d
	}
}

// WithEvictionPeriod overrides the duration after which unused cache entries are evicted.
func WithEvictionPeriod(d time.Duration) SourceOption {
	return func(s *Source) {
		s.evictionPeriod = d
	}
}

// WithRenewalWindow overrides the window before expiry when background refresh begins.
func WithRenewalWindow(d time.Duration) SourceOption {
	return func(s *Source) {
		s.renewalWindow = d
	}
}

// WithClusterID sets the cluster ID sent to certserver.
func WithClusterID(id string) SourceOption {
	return func(s *Source) {
		s.clusterID = id
	}
}

// WithTimeNow overrides time.Now for deterministic testing.
func WithTimeNow(nowFn func() time.Time) SourceOption {
	return func(s *Source) {
		s.timeNow = nowFn
	}
}

// NewSource creates a new GARI CertificateSource adapter backed by the provided pure certserver client.
func NewSource(cli CertClient, opts ...SourceOption) *Source {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Source{
		client:         cli,
		minBackoff:     defaultMinBackoff,
		maxBackoff:     defaultMaxBackoff,
		checkInterval:  defaultCheckInterval,
		evictionPeriod: defaultEvictionPeriod,
		logInterval:    defaultLogInterval,
		timeNow:        time.Now,
		cache:          make(map[cacheKey]*cacheEntry),
		ctx:            ctx,
		cancel:         cancel,
		stopCh:         make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	go s.renewalTickerLoop()
	return s
}

func (s *Source) now() time.Time {
	if s.timeNow != nil {
		return s.timeNow()
	}
	return time.Now()
}

// SetRecomputeTrigger registers a callback invoked when a certificate issuance or failure status changes.
func (s *Source) SetRecomputeTrigger(trigger func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recomputeTrigger = trigger
}

func (s *Source) notifyTrigger() {
	s.mu.Lock()
	trigger := s.recomputeTrigger
	s.mu.Unlock()
	if trigger != nil {
		trigger()
	}
}

func (s *Source) renewalTickerLoop() {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkAndRefresh()
		}
	}
}

func (s *Source) checkAndRefresh() {
	s.mu.Lock()
	now := s.now()
	for k, entry := range s.cache {
		// Evict inactive entries that ResolveCertificates has not requested within EvictionPeriod.
		if now.Sub(entry.lastRequested) > s.evictionPeriod {
			delete(s.cache, k)
			continue
		}
		if entry.certificate != nil && !entry.inFlight && now.After(entry.refreshAt) {
			entry.inFlight = true
			go s.fetchLoop(entry.key, entry.hostnames, entry.gateway, entry.dataPlaneSA, entry.addresses)
		}
	}
	s.mu.Unlock()
}

// ResolveCertificates returns certificates from the local cache and triggers background fetching on cache misses.
// ResolveCertificates is strictly non-blocking and makes no network calls.
func (s *Source) ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (state.CertificateResult, error) {
	if gw == nil || listener == nil {
		return state.CertificateResult{
			FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
			FailedMessage:     "Gateway or listener is nil",
			ProgrammedMessage: "Gateway or listener is nil",
		}, nil
	}
	if listener.Hostname == nil || *listener.Hostname == "" {
		return state.CertificateResult{
			FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
			FailedMessage:     "Certificate source requires an exact, non-wildcard hostname",
			ProgrammedMessage: "Certificate source requires an exact, non-wildcard hostname",
		}, nil
	}

	rawHostnames := []string{string(*listener.Hostname)}
	normalized, hostnamesKey, err := client.NormalizeHostnames(rawHostnames, 100, 253)
	if err != nil {
		return state.CertificateResult{
			FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
			FailedMessage:     fmt.Sprintf("Invalid listener hostname: %v", err),
			ProgrammedMessage: fmt.Sprintf("Invalid listener hostname: %v", err),
		}, nil
	}

	gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	gwFormatted := gwKey.String()
	dpSA := singlepod.ResourceNameForGateway(gw.Name)
	if gw.Namespace != "" {
		dpSA = fmt.Sprintf("%s/%s", gw.Namespace, dpSA)
	}
	key := cacheKey{
		gateway:   gwKey,
		hostnames: hostnamesKey,
	}

	var addresses []string
	for _, address := range gw.Status.Addresses {
		if address.Type == nil || *address.Type == gatewayv1.IPAddressType {
			if trimmed := strings.TrimSpace(address.Value); trimmed != "" {
				addresses = append(addresses, trimmed)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	entry, ok := s.cache[key]
	if !ok {
		entry = &cacheEntry{
			key:           key,
			hostnames:     normalized,
			gateway:       gwFormatted,
			dataPlaneSA:   dpSA,
			addresses:     addresses,
			state:         statePending,
			lastRequested: now,
		}
		s.cache[key] = entry
	} else {
		entry.lastRequested = now
		entry.addresses = addresses
	}

	// If we have a valid unexpired certificate, keep serving it even if a recent background renewal failed.
	if entry.certificate != nil && !now.After(entry.expiresAt) {
		if now.After(entry.refreshAt) && !entry.inFlight {
			entry.inFlight = true
			go s.fetchLoop(entry.key, entry.hostnames, entry.gateway, entry.dataPlaneSA, entry.addresses)
		}
		return state.CertificateResult{
			Certificates: []*tls.Certificate{state.CopyTLSCertificate(entry.certificate)},
		}, nil
	}

	// No valid unexpired certificate:
	switch entry.state {
	case stateFailed:
		if !entry.inFlight {
			entry.inFlight = true
			go s.fetchLoop(entry.key, entry.hostnames, entry.gateway, entry.dataPlaneSA, entry.addresses)
		}
		msg := entry.failedReason
		if msg == "" {
			msg = "Certificate source error"
		}
		return state.CertificateResult{
			FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
			FailedMessage:     msg,
			ProgrammedMessage: msg,
		}, nil
	case stateReady:
		// Expired
		return state.CertificateResult{
			Pending:           true,
			ProgrammedMessage: "Certificate issuance in progress with certserver",
		}, nil
	default:
		if !entry.inFlight {
			entry.inFlight = true
			go s.fetchLoop(entry.key, entry.hostnames, entry.gateway, entry.dataPlaneSA, entry.addresses)
		}
		return state.CertificateResult{
			Pending:           true,
			ProgrammedMessage: "Certificate issuance in progress with certserver",
		}, nil
	}
}

func genericStatusMessage(code codes.Code) string {
	switch code {
	case codes.Unavailable:
		return "Certificate source unavailable"
	case codes.PermissionDenied:
		return "Certificate source permission denied"
	case codes.Unauthenticated:
		return "Certificate source authentication failed"
	case codes.InvalidArgument:
		return "Certificate source invalid argument"
	case codes.NotFound:
		return "Certificate source resource not found"
	case codes.ResourceExhausted:
		return "Certificate source rate limit exceeded"
	case codes.DeadlineExceeded:
		return "Certificate source request timed out"
	case codes.Internal:
		return "Certificate source internal error"
	default:
		return "Certificate source error"
	}
}

func isNonRetryableCode(code codes.Code) bool {
	switch code {
	case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument, codes.Internal, codes.NotFound:
		return true
	default:
		return false
	}
}

func (s *Source) fetchLoop(key cacheKey, hostnames []string, gateway string, dataPlaneSA string, addresses []string) {
	backoff := s.minBackoff
	var retryTimer *time.Timer
	defer func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()

	req := &certserverv1.GetCertificateRequest{
		Hostnames:               hostnames,
		Gateway:                 gateway,
		DataPlaneServiceAccount: dataPlaneSA,
		ClusterId:               s.clusterID,
		Addresses:               addresses,
	}

	for {
		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			if entry, ok := s.cache[key]; ok {
				entry.inFlight = false
			}
			s.mu.Unlock()
			return
		default:
		}

		// Evict entry if no longer requested via ResolveCertificates.
		s.mu.Lock()
		entry, ok := s.cache[key]
		if !ok || s.now().Sub(entry.lastRequested) > s.evictionPeriod {
			if ok {
				entry.inFlight = false
				delete(s.cache, key)
			}
			s.mu.Unlock()
			return
		}
		req.Addresses = entry.addresses
		s.mu.Unlock()

		info, err := s.client.GetCertificate(s.ctx, req)
		st, _ := status.FromError(err)
		stCode := st.Code()

		if err == nil {
			if info == nil || info.Certificate == nil {
				// A pending certificate is retried; this source doesn't serve challenges yet.
				// Poll at a short fixed interval (minBackoff, 1 second by default) rather than
				// backing off exponentially. This ensures the controller fetches challenges
				// promptly, well within the certserver self-check window (e.g. 15 seconds).
				if retryTimer == nil {
					retryTimer = time.NewTimer(s.minBackoff)
				} else {
					retryTimer.Reset(s.minBackoff)
				}
				select {
				case <-s.ctx.Done():
					return
				case <-retryTimer.C:
				}
				continue
			}

			s.mu.Lock()
			entry, ok := s.cache[key]
			if !ok {
				s.mu.Unlock()
				return
			}
			cert := info.Certificate
			leaf := info.Leaf
			entry.inFlight = false
			entry.state = stateReady
			entry.certificate = cert
			entry.leaf = leaf
			entry.expiresAt = leaf.NotAfter

			lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
			window := s.renewalWindow
			if window <= 0 {
				window = lifetime / 3
			}
			if window > 30*24*time.Hour {
				window = 30 * 24 * time.Hour
			}
			entry.refreshAt = leaf.NotAfter.Add(-window)
			if entry.refreshAt.Before(s.now()) {
				entry.refreshAt = s.now().Add(1 * time.Minute)
			}
			entry.failedReason = ""
			s.mu.Unlock()

			s.notifyTrigger()
			return
		}

		// Failed fetch: log with rate limit and record generic failure reason.
		now := s.now()
		genericReason := genericStatusMessage(stCode)

		s.mu.Lock()
		entry, ok = s.cache[key]
		if !ok {
			s.mu.Unlock()
			return
		}
		shouldLog := false
		if now.Sub(entry.lastLogged) >= s.logInterval {
			entry.lastLogged = now
			shouldLog = true
		}

		entry.failedReason = genericReason
		hasValidCert := entry.certificate != nil && !now.After(entry.expiresAt)
		notifyNeeded := false
		if !hasValidCert {
			if isNonRetryableCode(stCode) {
				if entry.state != stateFailed {
					entry.state = stateFailed
					notifyNeeded = true
				}
			}
		}
		s.mu.Unlock()

		if shouldLog {
			klog.Warningf("certserver: failed to fetch certificate for Gateway %s hostnames %v: %v", gateway, hostnames, err)
		}

		// If no valid certificate exists and the failure is non-retryable, trigger recompute to update condition.
		if notifyNeeded {
			s.notifyTrigger()
		}

		// Retry with capped backoff: use maximum backoff for non-retryable codes.
		if isNonRetryableCode(stCode) {
			backoff = s.maxBackoff
		} else {
			backoff *= 2
			if backoff > s.maxBackoff {
				backoff = s.maxBackoff
			}
		}

		if retryTimer == nil {
			retryTimer = time.NewTimer(backoff)
		} else {
			retryTimer.Reset(backoff)
		}

		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			if entry, ok := s.cache[key]; ok {
				entry.inFlight = false
			}
			s.mu.Unlock()
			return
		case <-retryTimer.C:
		}
	}
}

// Start satisfies controller-runtime manager.Runnable, running until ctx is cancelled and then closing the source.
func (s *Source) Start(ctx context.Context) error {
	<-ctx.Done()
	return s.Close()
}

// Close cancels background loops and closes the underlying pure client.
func (s *Source) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		close(s.stopCh)
		if s.client != nil {
			err = s.client.Close()
		}
	})
	return err
}
