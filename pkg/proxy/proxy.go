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
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Proxy is a minimal implementation of a Gateway API proxy.
type Proxy struct {
	mu     sync.RWMutex
	routes []state.InternalRoute
}

func NewProxy() *Proxy {
	return &Proxy{
		routes: []state.InternalRoute{},
	}
}

func (p *Proxy) UpdateRoutes(routes []state.InternalRoute) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes = routes
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	routes := p.routes
	p.mu.RUnlock()

	var bestRule *state.InternalRule
	var bestMatch *state.InternalMatch

	for _, route := range routes {
		if !p.matchHostname(route.Hostnames, r.Host) {
			continue
		}

		for _, rule := range route.Rules {
			rRule := rule
			for _, match := range rRule.Matches {
				m := match
				if p.matchMatch(m, r) {
					if p.isBetterMatch(&m, bestMatch) {
						bestMatch = &m
						bestRule = &rRule
					}
				}
			}
			if len(rRule.Matches) == 0 {
				// Rule with no matches always matches, but is the least specific
				if bestRule == nil {
					bestRule = &rRule
					bestMatch = &state.InternalMatch{}
				}
			}
		}
	}

	if bestRule != nil {
		if bestRule.Redirect != nil {
			p.redirect(w, r, *bestRule.Redirect, bestMatch)
			return
		}
		if bestRule.Backend != nil {
			p.forward(w, r, *bestRule.Backend)
			return
		}
	}

	http.Error(w, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path), http.StatusNotFound)
}

func (p *Proxy) isBetterMatch(current, best *state.InternalMatch) bool {
	if best == nil {
		return true
	}

	// 1. Path match type priority: Exact > PathPrefix > None
	currentType := p.getPathMatchType(current)
	bestType := p.getPathMatchType(best)

	if currentType != bestType {
		return p.getPathMatchTypeWeight(currentType) > p.getPathMatchTypeWeight(bestType)
	}

	// 2. Longest path match wins
	currentPathLen := p.getPathLen(current)
	bestPathLen := p.getPathLen(best)
	if currentPathLen != bestPathLen {
		return currentPathLen > bestPathLen
	}

	// 3. Most header matches win
	return len(current.Headers) > len(best.Headers)
}

func (p *Proxy) getPathMatchType(m *state.InternalMatch) gatewayv1.PathMatchType {
	if m.Path == nil {
		return ""
	}
	return m.Path.Type
}

func (p *Proxy) getPathMatchTypeWeight(t gatewayv1.PathMatchType) int {
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

func (p *Proxy) getPathLen(m *state.InternalMatch) int {
	if m.Path == nil {
		return 0
	}
	return len(m.Path.Value)
}

func (p *Proxy) matchHostname(hostnames []string, host string) bool {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if len(hostnames) == 0 {
		return true
	}
	for _, h := range hostnames {
		if h == "*" {
			return true
		}
		if h == host {
			return true
		}
		if strings.HasPrefix(h, "*.") {
			suffix := h[1:] // .example.com
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func (p *Proxy) matchMatch(match state.InternalMatch, r *http.Request) bool {
	if match.Path != nil {
		switch match.Path.Type {
		case gatewayv1.PathMatchExact:
			if r.URL.Path != match.Path.Value {
				return false
			}
		case gatewayv1.PathMatchPathPrefix:
			if !p.hasPathPrefix(r.URL.Path, match.Path.Value) {
				return false
			}
		}
	}

	for _, hm := range match.Headers {
		values := r.Header[http.CanonicalHeaderKey(hm.Name)]
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

	return true
}

func (p *Proxy) hasPathPrefix(path, prefix string) bool {
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

func (p *Proxy) redirect(w http.ResponseWriter, r *http.Request, redirect state.InternalRedirect, match *state.InternalMatch) {
	newURL := *r.URL
	newURL.Scheme = state.ValueOf(redirect.Scheme)
	if newURL.Scheme == "" {
		newURL.Scheme = "http"
	}

	if hostname := state.ValueOf(redirect.Hostname); hostname != "" {
		newURL.Host = string(hostname)
	}

	if port := state.ValueOf(redirect.Port); port != 0 {
		host := newURL.Hostname()
		newURL.Host = fmt.Sprintf("%s:%d", host, port)
	}

	if redirect.Path != nil {
		switch redirect.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			newURL.Path = redirect.Path.Value
		case gatewayv1.PrefixMatchHTTPPathModifier:
			if match != nil && match.Path != nil && match.Path.Type == gatewayv1.PathMatchPathPrefix {
				prefix := match.Path.Value
				if strings.HasPrefix(r.URL.Path, prefix) {
					newURL.Path = redirect.Path.Value + r.URL.Path[len(prefix):]
				}
			}
		}
	}

	statusCode := state.ValueOf(redirect.StatusCode)
	if statusCode == 0 {
		statusCode = http.StatusFound
	}

	log.Log.Info("Redirecting request", "host", r.Host, "path", r.URL.Path, "target", newURL.String(), "status", statusCode)
	http.Redirect(w, r, newURL.String(), statusCode)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, backend state.InternalBackend) {
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", backend.Host, backend.Port),
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	log.Log.Info("Forwarding request", "host", r.Host, "path", r.URL.Path, "target", target.String())
	proxy.ServeHTTP(w, r)
}
