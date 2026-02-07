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
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Backend struct {
	Host string
	Port int32
}

type PathMatch struct {
	Type  string // Exact, PathPrefix
	Value string
}

type HeaderMatch struct {
	Type  string // Exact
	Name  string
	Value string
}

type RouteMatch struct {
	Path    *PathMatch
	Headers []HeaderMatch
}

type RouteRule struct {
	Matches []RouteMatch
	Backend Backend
}

type HTTPRoute struct {
	Hostnames []string
	Rules     []RouteRule
}

type Proxy struct {
	mu     sync.RWMutex
	routes []HTTPRoute
}

func NewProxy() *Proxy {
	return &Proxy{
		routes: []HTTPRoute{},
	}
}

func (p *Proxy) UpdateRoutes(routes []HTTPRoute) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes = routes
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	routes := p.routes
	p.mu.RUnlock()

	var bestBackend *Backend
	var bestMatch *RouteMatch

	for _, route := range routes {
		if !p.matchHostname(route.Hostnames, r.Host) {
			continue
		}

		for _, rule := range route.Rules {
			for _, match := range rule.Matches {
				m := match
				if p.matchMatch(m, r) {
					if p.isBetterMatch(&m, bestMatch) {
						bestMatch = &m
						bestBackend = &rule.Backend
					}
				}
			}
			if len(rule.Matches) == 0 {
				// Rule with no matches always matches, but is the least specific
				if bestBackend == nil {
					bestBackend = &rule.Backend
					bestMatch = &RouteMatch{}
				}
			}
		}
	}

	if bestBackend != nil {
		p.forward(w, r, *bestBackend)
		return
	}

	http.Error(w, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path), http.StatusNotFound)
}

func (p *Proxy) isBetterMatch(current, best *RouteMatch) bool {
	if best == nil {
		return true
	}

	// 1. Path match type priority: Exact > PathPrefix > None
	currentType := p.getPathMatchType(current)
	bestType := p.getPathMatchType(best)

	if currentType != bestType {
		return p.comparePathMatchType(currentType, bestType)
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

func (p *Proxy) getPathMatchType(m *RouteMatch) string {
	if m.Path == nil {
		return "None"
	}
	return m.Path.Type
}

func (p *Proxy) comparePathMatchType(a, b string) bool {
	weights := map[string]int{
		"Exact":      3,
		"PathPrefix": 2,
		"None":       1,
	}
	return weights[a] > weights[b]
}

func (p *Proxy) getPathLen(m *RouteMatch) int {
	if m.Path == nil {
		return 0
	}
	return len(m.Path.Value)
}

func (p *Proxy) matchHostname(hostnames []string, host string) bool {
	if len(hostnames) == 0 {
		return true
	}
	// TODO: Support wildcard hostnames
	for _, h := range hostnames {
		if h == "*" || h == host {
			return true
		}
	}
	return false
}

func (p *Proxy) matchRule(rule RouteRule, r *http.Request) bool {
	if len(rule.Matches) == 0 {
		return true
	}

	for _, match := range rule.Matches {
		if p.matchMatch(match, r) {
			return true
		}
	}
	return false
}

func (p *Proxy) matchMatch(match RouteMatch, r *http.Request) bool {
	if match.Path != nil {
		switch match.Path.Type {
		case "Exact":
			if r.URL.Path != match.Path.Value {
				return false
			}
		case "PathPrefix":
			if !p.hasPathPrefix(r.URL.Path, match.Path.Value) {
				return false
			}
		}
	}

	for _, hm := range match.Headers {
		if r.Header.Get(hm.Name) != hm.Value {
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

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, backend Backend) {
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", backend.Host, backend.Port),
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	log.Log.Info("Forwarding request", "host", r.Host, "path", r.URL.Path, "target", target.String())
	proxy.ServeHTTP(w, r)
}
