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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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

// InternalListener represents the computed configuration of a Gateway listener for the proxy.
type InternalListener struct {
	Name        string
	Protocol    gatewayv1.ProtocolType
	Port        gatewayv1.PortNumber
	Hostname    string
	GatewayName types.NamespacedName
	Routes      []InternalRoute
}

type listenerMatchCandidate struct {
	listener       *InternalListener
	matchType      MatchType
	hostnameLength int
}

// MatchesWildcard reports whether a hostname matches a wildcard pattern (e.g. *.example.com).
func MatchesWildcard(pattern, host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
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
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
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

// InternalRoute represents the computed state for a route, used by the proxy.
type InternalRoute struct {
	Hostnames []string
	Rules     []InternalRule
}

func (ir *InternalRoute) MatchHostname(host string) bool {
	matched, _, _ := ir.MatchHostnameScore(host)
	return matched
}

// MatchHostnameScore computes whether the host matches any of the route's hostnames,
// and returns the number of characters in the matching non-wildcard hostname and total matching hostname.
func (ir *InternalRoute) MatchHostnameScore(host string) (bool, int, int) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	cleanHost := strings.ToLower(host)

	if len(ir.Hostnames) == 0 {
		return true, 0, 0
	}

	matched := false
	maxNonWildcardLen := 0
	maxHostnameLen := 0

	for _, h := range ir.Hostnames {
		cleanH := strings.ToLower(h)
		if cleanH == "*" {
			matched = true
			continue
		}
		if cleanH == cleanHost {
			matched = true
			if len(cleanH) > maxNonWildcardLen {
				maxNonWildcardLen = len(cleanH)
			}
			if len(cleanH) > maxHostnameLen {
				maxHostnameLen = len(cleanH)
			}
			continue
		}
		if strings.HasPrefix(cleanH, "*.") {
			suffix := cleanH[1:] // .example.com
			if len(cleanHost) > len(suffix) && strings.HasSuffix(cleanHost, suffix) {
				matched = true
				if len(cleanH) > maxHostnameLen {
					maxHostnameLen = len(cleanH)
				}
			}
		}
	}

	return matched, maxNonWildcardLen, maxHostnameLen
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
	Error                  *ErrorState
}

type InternalTLSConfig struct {
	Hostname string
	CACerts  [][]byte
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
	if m.Path == nil {
		return ""
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
	if m.Path == nil {
		return 0
	}
	return len(m.Path.Value)
}

func (s *GatewayState) BuildInternalState(routes []*HTTPRouteState, services map[types.NamespacedName]*corev1.Service, backendTLSPolicies []*gatewayv1.BackendTLSPolicy, configMaps map[types.NamespacedName]*corev1.ConfigMap, refValidator ReferenceGrantValidator, controllerName string) ([]InternalListener, []InternalRoute) {
	for _, route := range routes {
		if route.HTTPRoute == nil {
			continue
		}
		route.Compile(services, backendTLSPolicies, configMaps, refValidator)
	}

	var internalListeners []InternalListener
	var allInternalRoutes []InternalRoute

	for _, listener := range s.Spec.Listeners {
		// Check if listener is compatible with HTTPRoute
		if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
			continue
		}

		iListener := InternalListener{
			Name:        string(listener.Name),
			Protocol:    listener.Protocol,
			Port:        listener.Port,
			Hostname:    string(ValueOf(listener.Hostname)),
			GatewayName: types.NamespacedName{Namespace: s.Namespace, Name: s.Name},
		}

		var listenerRoutes []InternalRoute

		for _, route := range routes {
			if route.HTTPRoute == nil || route.Internal == nil {
				continue
			}

			// Check if this route is bound to this Gateway and specifically this listener (if SectionName is set)
			bound := false
			var matchingParentRef *gatewayv1.ParentReference
			for i := range route.Spec.ParentRefs {
				parentRef := &route.Spec.ParentRefs[i]
				if string(parentRef.Name) != s.Name {
					continue
				}
				parentNamespace := route.Namespace
				if ns := ValueOf(parentRef.Namespace); ns != "" {
					parentNamespace = string(ns)
				}
				if parentNamespace != s.Namespace {
					continue
				}

				if sn := ValueOf(parentRef.SectionName); sn != "" && sn != listener.Name {
					continue
				}
				if port := ValueOf(parentRef.Port); port != 0 && port != listener.Port {
					continue
				}

				// Dynamically compute acceptance for this listener
				if cond := route.ComputeAcceptedCondition(*parentRef, []*GatewayState{s}); cond.Status == metav1.ConditionTrue {
					bound = true
					matchingParentRef = parentRef
					break
				}
			}

			if !bound {
				continue
			}

			// Calculate intersected hostnames
			routeHostnames := route.GetHostnames()
			listenerHostname := ValueOf(listener.Hostname)
			effectiveHostnames := IntersectHostnames(routeHostnames, string(listenerHostname))
			if len(effectiveHostnames) == 0 && len(routeHostnames) > 0 {
				// No intersection, skip this listener
				continue
			}

			ir := InternalRoute{
				Hostnames: effectiveHostnames,
				Rules:     route.Internal.Rules,
			}
			listenerRoutes = append(listenerRoutes, ir)
			allInternalRoutes = append(allInternalRoutes, ir)
			_ = matchingParentRef // keep for now
		}
		iListener.Routes = listenerRoutes
		internalListeners = append(internalListeners, iListener)
	}

	return internalListeners, allInternalRoutes
}

func (s *GatewayState) BuildInternalRoutes(routes []*HTTPRouteState, services map[types.NamespacedName]*corev1.Service, backendTLSPolicies []*gatewayv1.BackendTLSPolicy, configMaps map[types.NamespacedName]*corev1.ConfigMap, refValidator ReferenceGrantValidator, controllerName string) []InternalRoute {
	_, allInternalRoutes := s.BuildInternalState(routes, services, backendTLSPolicies, configMaps, refValidator, controllerName)
	return allInternalRoutes
}
