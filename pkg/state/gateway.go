// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package state

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type GatewayState struct {
	*gatewayv1.Gateway
}

func (s *GatewayState) GetHTTPRoutes(allRoutes []*HTTPRouteState, controllerName string) []*HTTPRouteState {
	var matches []*HTTPRouteState
	for _, route := range allRoutes {
		if route.MatchesGateway(s.Gateway, controllerName) {
			matches = append(matches, route)
		}
	}
	return matches
}

func (s *HTTPRouteState) GetHostnames() []string {
	var hostnames []string
	for _, h := range s.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}
	return hostnames
}

func (s *HTTPRouteState) GetNamespace() string {
	return s.Namespace
}

// MatchType represents how specifically a hostname matched a listener.
type MatchType int

const (
	NoMatch MatchType = iota
	CatchAllMatch
	WildcardMatch
	ExactMatch
)

// InternalClientValidation holds the resolved frontend client certificate validation configuration for an HTTPS listener.
type InternalClientValidation struct {
	CACertPEMs [][]byte                             `json:"caCertPEMs,omitempty"`
	Mode       gatewayv1.FrontendValidationModeType `json:"mode,omitempty"`
}

// DeepCopy returns a deep copy of InternalClientValidation.
func (cv *InternalClientValidation) DeepCopy() *InternalClientValidation {
	if cv == nil {
		return nil
	}
	out := &InternalClientValidation{
		Mode: cv.Mode,
	}
	if cv.CACertPEMs != nil {
		out.CACertPEMs = make([][]byte, len(cv.CACertPEMs))
		for i, pem := range cv.CACertPEMs {
			out.CACertPEMs[i] = make([]byte, len(pem))
			copy(out.CACertPEMs[i], pem)
		}
	}
	return out
}

// InternalListener represents the computed configuration of a Gateway listener for the proxy.
type InternalListener struct {
	Name             string
	Protocol         gatewayv1.ProtocolType
	Port             gatewayv1.PortNumber
	Hostname         string
	GatewayName      types.NamespacedName
	Routes           []InternalRoute
	TLSMode          *gatewayv1.TLSModeType
	TLSBackends      map[string][]InternalTLSBackend
	TCPBackends      []InternalTCPBackend
	UDPBackends      []InternalUDPBackend
	ClientValidation *InternalClientValidation `json:"clientValidation,omitempty"`
	ACMEChallenge    bool                      `json:"acmeChallenge,omitempty"`
}

// hostWithoutPort returns s with the port stripped if present, or s unchanged if not.
func hostWithoutPort(s string) string {
	h, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return h
}

// SelectTLSBackends finds the backend targets matching the given SNI for a TLS listener.
// Follows Gateway API precedence: Exact match > longest matching wildcard > catch-all.
func (l *InternalListener) SelectTLSBackends(sni string) ([]InternalTLSBackend, bool) {
	if l == nil || len(l.TLSBackends) == 0 {
		return nil, false
	}
	sni = hostWithoutPort(sni)
	cleanSNI := strings.ToLower(sni)

	// 1. Exact match
	if cleanSNI != "" {
		if backends, ok := l.TLSBackends[cleanSNI]; ok && len(backends) > 0 {
			return backends, true
		}
	}

	// 2. Wildcard match (most specific / longest pattern wins)
	var bestWildcardBackends []InternalTLSBackend
	bestWildcardLen := -1
	for pattern, backends := range l.TLSBackends {
		if strings.HasPrefix(pattern, "*.") && MatchesWildcard(pattern, cleanSNI) {
			if len(pattern) > bestWildcardLen {
				bestWildcardLen = len(pattern)
				bestWildcardBackends = backends
			}
		}
	}
	if bestWildcardLen > 0 && len(bestWildcardBackends) > 0 {
		return bestWildcardBackends, true
	}

	// 3. Catch-all match ("*" or "")
	if backends, ok := l.TLSBackends["*"]; ok && len(backends) > 0 {
		return backends, true
	}
	if backends, ok := l.TLSBackends[""]; ok && len(backends) > 0 {
		return backends, true
	}

	return nil, false
}

// SelectTLSBackend returns a backend target matching the given SNI selected by weight.
func (l *InternalListener) SelectTLSBackend(sni string) (string, bool) {
	return l.SelectTLSBackendWithRand(sni, nil)
}

// SelectTLSBackendWithRand returns a backend target matching the given SNI using the provided RNG for selection.
// If r is nil, global rand.Int64N is used.
func (l *InternalListener) SelectTLSBackendWithRand(sni string, r *rand.Rand) (string, bool) {
	backends, ok := l.SelectTLSBackends(sni)
	if !ok || len(backends) == 0 {
		return "", false
	}
	return PickTLSBackendWithRand(backends, r)
}

// PickTLSBackend selects a backend target from a slice of InternalTLSBackend based on weight.
func PickTLSBackend(backends []InternalTLSBackend) (string, bool) {
	return PickTLSBackendWithRand(backends, nil)
}

// PickTLSBackendWithRand selects a backend target from a slice of InternalTLSBackend based on weight using the provided RNG.
func PickTLSBackendWithRand(backends []InternalTLSBackend, r *rand.Rand) (string, bool) {
	if len(backends) == 0 {
		return "", false
	}

	var totalWeight int64
	for _, b := range backends {
		if b.Weight > 0 {
			totalWeight += int64(b.Weight)
		}
	}

	if totalWeight <= 0 {
		return "", false
	}

	var n int64
	if r != nil {
		n = r.Int64N(totalWeight)
	} else {
		n = rand.Int64N(totalWeight)
	}

	for _, b := range backends {
		if b.Weight <= 0 {
			continue
		}
		if n < int64(b.Weight) {
			return b.Target, true
		}
		n -= int64(b.Weight)
	}

	for i := len(backends) - 1; i >= 0; i-- {
		if backends[i].Weight > 0 {
			return backends[i].Target, true
		}
	}

	return "", false
}

// SelectTCPBackend returns a backend target selected by weight for a TCP listener.
func (l *InternalListener) SelectTCPBackend() (string, bool) {
	return l.SelectTCPBackendWithRand(nil)
}

// SelectTCPBackendWithRand returns a backend target using the provided RNG for selection.
// If r is nil, global rand.Int64N is used.
func (l *InternalListener) SelectTCPBackendWithRand(r *rand.Rand) (string, bool) {
	if l == nil || len(l.TCPBackends) == 0 {
		return "", false
	}
	return PickTCPBackendWithRand(l.TCPBackends, r)
}

// SelectUDPBackend returns a backend target selected by weight for a UDP listener.
func (l *InternalListener) SelectUDPBackend() (string, bool) {
	return l.SelectUDPBackendWithRand(nil)
}

// SelectUDPBackendWithRand returns a backend target using the provided RNG for selection.
// If r is nil, global rand.Int64N is used.
func (l *InternalListener) SelectUDPBackendWithRand(r *rand.Rand) (string, bool) {
	if l == nil || len(l.UDPBackends) == 0 {
		return "", false
	}
	return PickTCPBackendWithRand(l.UDPBackends, r)
}

// PickTCPBackend selects a backend target from a slice of InternalTCPBackend based on weight.
func PickTCPBackend(backends []InternalTCPBackend) (string, bool) {
	return PickTCPBackendWithRand(backends, nil)
}

// PickTCPBackendWithRand selects a backend target from a slice of InternalTCPBackend based on weight using the provided RNG.
func PickTCPBackendWithRand(backends []InternalTCPBackend, r *rand.Rand) (string, bool) {
	if len(backends) == 0 {
		return "", false
	}

	var totalWeight int64
	for _, b := range backends {
		if b.Weight > 0 {
			totalWeight += int64(b.Weight)
		}
	}

	if totalWeight <= 0 {
		return "", false
	}

	var n int64
	if r != nil {
		n = r.Int64N(totalWeight)
	} else {
		n = rand.Int64N(totalWeight)
	}

	for _, b := range backends {
		if b.Weight <= 0 {
			continue
		}
		if n < int64(b.Weight) {
			return b.Target, true
		}
		n -= int64(b.Weight)
	}

	for i := len(backends) - 1; i >= 0; i-- {
		if backends[i].Weight > 0 {
			return backends[i].Target, true
		}
	}

	return "", false
}

// PickBackend selects an InternalBackend from a slice based on weight.
// If all backends have weight 0 or the list is empty, an error is returned.
func PickBackend(backends []InternalBackend) (InternalBackend, error) {
	return PickBackendWithRand(backends, nil)
}

// PickBackendWithRand selects an InternalBackend from a slice based on weight using the provided RNG.
// If all backends have weight 0 or the list is empty, an error is returned.
func PickBackendWithRand(backends []InternalBackend, r *rand.Rand) (InternalBackend, error) {
	if len(backends) == 0 {
		return InternalBackend{}, fmt.Errorf("no backends configured")
	}

	if len(backends) == 1 {
		if backends[0].Weight <= 0 {
			return InternalBackend{}, fmt.Errorf("all backends have zero weight")
		}
		return backends[0], nil
	}

	var totalWeight int64
	for _, b := range backends {
		if b.Weight > 0 {
			totalWeight += int64(b.Weight)
		}
	}

	if totalWeight <= 0 {
		return InternalBackend{}, fmt.Errorf("all backends have zero weight")
	}

	var n int64
	if r != nil {
		n = r.Int64N(totalWeight)
	} else {
		n = rand.Int64N(totalWeight)
	}

	for _, b := range backends {
		if b.Weight <= 0 {
			continue
		}
		if n < int64(b.Weight) {
			return b, nil
		}
		n -= int64(b.Weight)
	}

	for i := len(backends) - 1; i >= 0; i-- {
		if backends[i].Weight > 0 {
			return backends[i], nil
		}
	}

	return InternalBackend{}, fmt.Errorf("no backend selected")
}

type listenerMatchCandidate struct {
	listener       *InternalListener
	matchType      MatchType
	hostnameLength int
}

// MatchesWildcard reports whether a hostname matches a wildcard pattern (e.g. *.example.com).
func MatchesWildcard(pattern, host string) bool {
	host = hostWithoutPort(host)
	cleanHost := strings.ToLower(host)
	cleanPattern := strings.ToLower(pattern)
	if !strings.HasPrefix(cleanPattern, "*.") {
		return false
	}
	suffix := cleanPattern[1:]
	return len(cleanHost) > len(suffix) && strings.HasSuffix(cleanHost, suffix)
}

// MatchListeners finds all listeners that match a given host with the highest specificity (Exact > Wildcard > CatchAll).
func MatchListeners(listeners []InternalListener, host string) ([]InternalListener, MatchType) {
	host = hostWithoutPort(host)
	cleanHost := strings.ToLower(host)

	var (
		bestMatchType      = NoMatch
		bestHostnameLength = -1
	)

	for i := range listeners {
		l := &listeners[i]
		h := strings.ToLower(l.Hostname)

		if h == "" || h == "*" {
			candidate := &listenerMatchCandidate{
				listener:       l,
				matchType:      CatchAllMatch,
				hostnameLength: 0,
			}
			if isBetterListenerMatch(candidate, &listenerMatchCandidate{matchType: bestMatchType, hostnameLength: bestHostnameLength}) {
				bestMatchType = CatchAllMatch
				bestHostnameLength = 0
			}
			continue
		}

		if cleanHost != "" && h == cleanHost {
			candidate := &listenerMatchCandidate{
				listener:       l,
				matchType:      ExactMatch,
				hostnameLength: len(h),
			}
			if isBetterListenerMatch(candidate, &listenerMatchCandidate{matchType: bestMatchType, hostnameLength: bestHostnameLength}) {
				bestMatchType = ExactMatch
				bestHostnameLength = len(h)
			}
			continue
		}

		if cleanHost != "" && strings.HasPrefix(h, "*.") {
			suffix := h[1:]
			if len(cleanHost) > len(suffix) && strings.HasSuffix(cleanHost, suffix) {
				candidate := &listenerMatchCandidate{
					listener:       l,
					matchType:      WildcardMatch,
					hostnameLength: len(h),
				}
				if isBetterListenerMatch(candidate, &listenerMatchCandidate{matchType: bestMatchType, hostnameLength: bestHostnameLength}) {
					bestMatchType = WildcardMatch
					bestHostnameLength = len(h)
				}
			}
		}
	}

	if bestMatchType == NoMatch {
		return nil, NoMatch
	}

	var matched []InternalListener
	for i := range listeners {
		l := &listeners[i]
		h := strings.ToLower(l.Hostname)

		if bestMatchType == CatchAllMatch && (h == "" || h == "*") {
			matched = append(matched, *l)
		} else if bestMatchType == ExactMatch && cleanHost != "" && h == cleanHost {
			matched = append(matched, *l)
		} else if bestMatchType == WildcardMatch && cleanHost != "" && strings.HasPrefix(h, "*.") && len(h) == bestHostnameLength {
			suffix := h[1:]
			if len(cleanHost) > len(suffix) && strings.HasSuffix(cleanHost, suffix) {
				matched = append(matched, *l)
			}
		}
	}

	return matched, bestMatchType
}

// MatchListener finds the best matching listener for a given host among a slice of listeners.
func MatchListener(listeners []InternalListener, host string) (*InternalListener, MatchType) {
	matched, matchType := MatchListeners(listeners, host)
	if len(matched) == 0 {
		return nil, NoMatch
	}
	return &matched[0], matchType
}

func isBetterListenerMatch(current, best *listenerMatchCandidate) bool {
	if best == nil {
		return true
	}
	if current.matchType != best.matchType {
		return current.matchType > best.matchType
	}
	if current.hostnameLength != best.hostnameLength {
		return current.hostnameLength > best.hostnameLength
	}
	return false
}

// RouteHostname associates an effective listener hostname with the route's
// original configured hostname. The original hostname defines precedence.
type RouteHostname struct {
	Hostname         string
	OriginalHostname string
}

// NewRouteHostname constructs a RouteHostname pairing an effective listener hostname
// with the route's original configured hostname.
func NewRouteHostname(hostname, originalHostname string) RouteHostname {
	return RouteHostname{
		Hostname:         hostname,
		OriginalHostname: originalHostname,
	}
}

func (r RouteHostname) matchesHostname(cleanHost string) bool {
	cleanH := strings.ToLower(r.Hostname)
	return cleanH == "*" || cleanH == cleanHost || MatchesWildcard(cleanH, cleanHost)
}

func (r RouteHostname) score(cleanHost string) (int, int) {
	cleanOrig := strings.ToLower(r.OriginalHostname)
	if cleanOrig == "*" || cleanOrig == "" {
		return 0, 0
	}
	if cleanOrig == cleanHost {
		return len(cleanOrig), len(cleanOrig)
	}
	if MatchesWildcard(cleanOrig, cleanHost) {
		return 0, len(cleanOrig)
	}
	return 0, 0
}

// InternalRoute represents the computed state for a route, used by the proxy.
type InternalRoute struct {
	Hostnames []RouteHostname
	Rules     []InternalRule
}

func (ir *InternalRoute) matchRouteHostnames(host string) (bool, int, int) {
	if len(ir.Hostnames) == 0 {
		return true, 0, 0
	}

	cleanHost := strings.ToLower(hostWithoutPort(host))
	matched := false
	maxNonWildcardLen := 0
	maxHostnameLen := 0

	for _, rh := range ir.Hostnames {
		if !rh.matchesHostname(cleanHost) {
			continue
		}
		matched = true

		nonWildcardLen, hostnameLen := rh.score(cleanHost)
		if nonWildcardLen > maxNonWildcardLen {
			maxNonWildcardLen = nonWildcardLen
		}
		if hostnameLen > maxHostnameLen {
			maxHostnameLen = hostnameLen
		}
	}

	return matched, maxNonWildcardLen, maxHostnameLen
}

func (ir *InternalRoute) MatchHostname(host string) bool {
	matched, _, _ := ir.matchRouteHostnames(host)
	return matched
}

// MatchHostnameScore computes whether the host matches any of the route's hostnames,
// and returns the number of characters in the matching non-wildcard hostname and total matching hostname.
// Precedence is defined by OriginalHostname.
func (ir *InternalRoute) MatchHostnameScore(host string) (bool, int, int) {
	return ir.matchRouteHostnames(host)
}

// ErrorState represents an error that should be surfaced to the user.
// It includes both the API condition for status reporting and the HTTP response details for the proxy.
type ErrorState struct {
	// Condition is the status condition to be reported in the API.
	// This provides a machine-readable reason for the error.
	Condition metav1.Condition

	// HTTPStatusCode is the status code to return in the HTTP response.
	// This is the "user-facing" status code.
	HTTPStatusCode int

	// HTTPMessage is the message to return in the HTTP response body.
	// This is the "user-facing" error message.
	HTTPMessage string
}

// InternalMirror represents a mirror destination for a route rule.
type InternalMirror struct {
	Backend     InternalBackend
	Numerator   int32
	Denominator int32
}

// InternalRule is the internal representation of an HTTPRouteRule.
type InternalRule struct {
	Name     *gatewayv1.SectionName
	Matches  []InternalMatch
	Backends []InternalBackend
	Mirrors  []InternalMirror
	Redirect *InternalRedirect
	Rewrite  *InternalRewrite
	Timeouts *InternalTimeouts
	Retry    *CompiledHTTPRouteRetry
	// RequestHeaderModifier defines the request header modifications to apply.
	RequestHeaderModifier *gatewayv1.HTTPHeaderFilter
	// ResponseHeaderModifier defines the response header modifications to apply.
	ResponseHeaderModifier *gatewayv1.HTTPHeaderFilter
	// CORS defines the CORS filter configuration to apply.
	CORS *gatewayv1.HTTPCORSFilter
	// Error, if non-nil, indicates that this rule is invalid and should
	// return an error response if matched.
	Error *ErrorState
}

// CompiledHTTPRouteRetry represents the compiled retry configuration for a route rule.
type CompiledHTTPRouteRetry struct {
	Source *gatewayv1.HTTPRouteRetry

	Codes    []int
	Attempts *int
	Backoff  *time.Duration
}

// ParseRetry parses gatewayv1.HTTPRouteRetry into CompiledHTTPRouteRetry, returning an error if duration strings are invalid.
func ParseRetry(retry *gatewayv1.HTTPRouteRetry) (*CompiledHTTPRouteRetry, error) {
	if retry == nil {
		return nil, nil
	}
	ir := &CompiledHTTPRouteRetry{
		Source:   retry,
		Attempts: retry.Attempts,
	}
	for _, code := range retry.Codes {
		ir.Codes = append(ir.Codes, int(code))
	}
	if retry.Backoff != nil {
		d, err := time.ParseDuration(string(*retry.Backoff))
		if err != nil {
			return nil, err
		}
		ir.Backoff = &d
	}
	return ir, nil
}

// InternalTimeouts represents the timeout configuration for a route rule.
type InternalTimeouts struct {
	Request        *time.Duration
	BackendRequest *time.Duration
}

// ParseTimeouts parses gatewayv1.HTTPRouteTimeouts into InternalTimeouts, returning an error if duration strings are invalid.
func ParseTimeouts(timeouts *gatewayv1.HTTPRouteTimeouts) (*InternalTimeouts, error) {
	if timeouts == nil {
		return nil, nil
	}
	it := &InternalTimeouts{}
	if timeouts.Request != nil {
		d, err := time.ParseDuration(string(*timeouts.Request))
		if err != nil {
			return nil, err
		}
		it.Request = &d
	}
	if timeouts.BackendRequest != nil {
		d, err := time.ParseDuration(string(*timeouts.BackendRequest))
		if err != nil {
			return nil, err
		}
		it.BackendRequest = &d
	}
	return it, nil
}

// InternalRewrite represents the URL rewriting configuration for a route rule.
// It specifies how the hostname or path of the request should be modified before
// forwarding it to the backend.
type InternalRewrite struct {
	Hostname *gatewayv1.PreciseHostname
	Path     *InternalPathRewrite
}

// InternalPathRewrite represents a path rewrite operation.
// Value is the replacement string corresponding to the modifier Type.
type InternalPathRewrite struct {
	Type  gatewayv1.HTTPPathModifierType
	Value string
}

type InternalBackend struct {
	Host                   string
	Port                   int32
	AppProtocol            *string
	TLSConfig              *InternalTLSConfig
	Weight                 int32
	RequestHeaderModifier  *gatewayv1.HTTPHeaderFilter
	ResponseHeaderModifier *gatewayv1.HTTPHeaderFilter
	CORS                   *gatewayv1.HTTPCORSFilter
	Rewrite                *InternalRewrite
	Error                  *ErrorState
}

type InternalTLSConfig struct {
	Hostname                string
	CACerts                 [][]byte
	WellKnownCACertificates *gatewayv1.WellKnownCACertificatesType
	SubjectAltNames         []gatewayv1.SubjectAltName
	ClientCert              *tls.Certificate `json:"-"`
	ClientCertID            string           `json:"clientCertID,omitempty"`
}

type InternalRedirect struct {
	Scheme     *string
	Hostname   *gatewayv1.PreciseHostname
	Path       *InternalPathRedirect
	Port       *gatewayv1.PortNumber
	StatusCode *int
}

type InternalPathRedirect struct {
	Type  gatewayv1.HTTPPathModifierType
	Value string
}

type InternalMatch struct {
	Path        *InternalPathMatch
	Headers     []InternalHeaderMatch
	QueryParams []InternalQueryParamMatch
	Method      *gatewayv1.HTTPMethod
}

func (im *InternalMatch) Matches(method, path string, query url.Values, header http.Header) bool {
	if im.Method != nil {
		if string(*im.Method) != method {
			if method == http.MethodOptions && header.Get("Origin") != "" && header.Get("Access-Control-Request-Method") != "" {
				if !strings.EqualFold(string(*im.Method), header.Get("Access-Control-Request-Method")) {
					return false
				}
			} else {
				return false
			}
		}
	}
	if im.Path != nil {
		switch im.Path.Type {
		case gatewayv1.PathMatchExact:
			if path != im.Path.Value {
				return false
			}
		case gatewayv1.PathMatchPathPrefix:
			if !hasPathPrefix(path, im.Path.Value) {
				return false
			}
		}
	}

	for _, hm := range im.Headers {
		values := header[http.CanonicalHeaderKey(hm.Name)]
		matched := false
		for _, v := range values {
			if hm.Type == gatewayv1.HeaderMatchRegularExpression {
				if hm.MatchRegularExpressionValue != nil && hm.MatchRegularExpressionValue.MatchString(v) {
					matched = true
					break
				}
			} else {
				if v == hm.MatchExactValue {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	for _, qp := range im.QueryParams {
		values := query[qp.Name]
		if len(values) == 0 {
			return false
		}
		v := values[0]
		if qp.Type == gatewayv1.QueryParamMatchRegularExpression {
			if qp.MatchRegularExpressionValue == nil || !qp.MatchRegularExpressionValue.MatchString(v) {
				return false
			}
		} else {
			if v != qp.MatchExactValue {
				return false
			}
		}
	}

	return true
}

func hasPathPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	if len(path) > len(prefix) && path[len(prefix)] == '/' && path[:len(prefix)] == prefix {
		return true
	}
	// Also handle case where prefix ends with /
	if len(prefix) > 0 && prefix[len(prefix)-1] == '/' {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

type InternalPathMatch struct {
	Type  gatewayv1.PathMatchType
	Value string
}

type InternalHeaderMatch struct {
	Type                        gatewayv1.HeaderMatchType
	Name                        string
	MatchExactValue             string
	MatchRegularExpressionValue *regexp.Regexp
}

type InternalQueryParamMatch struct {
	Type                        gatewayv1.QueryParamMatchType
	Name                        string
	MatchExactValue             string
	MatchRegularExpressionValue *regexp.Regexp
}

type routeMatchCandidate struct {
	rule                   *InternalRule
	match                  *InternalMatch
	nonWildcardHostnameLen int
	hostnameLen            int
}

func MatchRoute(routes []InternalRoute, r *http.Request) (*InternalRule, *InternalMatch) {
	var bestCandidate *routeMatchCandidate
	query := r.URL.Query()

	for i := range routes {
		route := &routes[i]
		matched, nonWildcardLen, hostnameLen := route.MatchHostnameScore(r.Host)
		if !matched {
			continue
		}

		for j := range route.Rules {
			rule := &route.Rules[j]
			if len(rule.Matches) == 0 {
				defaultMatch := InternalMatch{
					Path: &InternalPathMatch{
						Type:  gatewayv1.PathMatchPathPrefix,
						Value: "/",
					},
				}
				candidate := &routeMatchCandidate{
					rule:                   rule,
					match:                  &defaultMatch,
					nonWildcardHostnameLen: nonWildcardLen,
					hostnameLen:            hostnameLen,
				}
				if isBetterCandidate(candidate, bestCandidate) {
					bestCandidate = candidate
				}
				continue
			}

			for k := range rule.Matches {
				match := &rule.Matches[k]
				if match.Matches(r.Method, r.URL.Path, query, r.Header) {
					candidate := &routeMatchCandidate{
						rule:                   rule,
						match:                  match,
						nonWildcardHostnameLen: nonWildcardLen,
						hostnameLen:            hostnameLen,
					}
					if isBetterCandidate(candidate, bestCandidate) {
						bestCandidate = candidate
					}
				}
			}
		}
	}

	if bestCandidate == nil {
		return nil, nil
	}
	return bestCandidate.rule, bestCandidate.match
}

func isBetterCandidate(current, best *routeMatchCandidate) bool {
	if best == nil {
		return true
	}

	// 1. Characters in a matching non-wildcard hostname
	if current.nonWildcardHostnameLen != best.nonWildcardHostnameLen {
		return current.nonWildcardHostnameLen > best.nonWildcardHostnameLen
	}

	// 2. Characters in a matching hostname
	if current.hostnameLen != best.hostnameLen {
		return current.hostnameLen > best.hostnameLen
	}

	// 3. Path match type priority: Exact > PathPrefix > None
	currentType := getPathMatchType(current.match)
	bestType := getPathMatchType(best.match)

	if currentType != bestType {
		return getPathMatchTypeWeight(currentType) > getPathMatchTypeWeight(bestType)
	}

	// 4. Longest path match wins
	currentPathLen := getPathLen(current.match)
	bestPathLen := getPathLen(best.match)
	if currentPathLen != bestPathLen {
		return currentPathLen > bestPathLen
	}

	// 5. Method match wins over no method match
	if (current.match.Method != nil) != (best.match.Method != nil) {
		return current.match.Method != nil
	}

	// 6. Most header matches win
	if len(current.match.Headers) != len(best.match.Headers) {
		return len(current.match.Headers) > len(best.match.Headers)
	}

	// 7. Most query param matches win
	if len(current.match.QueryParams) != len(best.match.QueryParams) {
		return len(current.match.QueryParams) > len(best.match.QueryParams)
	}

	return false
}

func getPathMatchType(m *InternalMatch) gatewayv1.PathMatchType {
	if m.Path == nil || m.Path.Type == "" {
		return gatewayv1.PathMatchPathPrefix
	}
	return m.Path.Type
}

func getPathMatchTypeWeight(t gatewayv1.PathMatchType) int {
	switch t {
	case gatewayv1.PathMatchExact:
		return 3
	case gatewayv1.PathMatchPathPrefix:
		return 2
	case "":
		return 1
	default:
		return 0
	}
}

func getPathLen(m *InternalMatch) int {
	if m.Path == nil || m.Path.Value == "" {
		return 1
	}
	return len(m.Path.Value)
}
