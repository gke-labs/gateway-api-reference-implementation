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

type Proxy struct {
	mu     sync.RWMutex
	routes map[string]Backend
}

func NewProxy() *Proxy {
	return &Proxy{
		routes: make(map[string]Backend),
	}
}

func (p *Proxy) UpdateRoutes(routes map[string]Backend) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes = routes
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	backend, ok := p.routes[r.Host]
	if !ok {
		backend, ok = p.routes["*"]
	}
	p.mu.RUnlock()

	if !ok {
		http.Error(w, fmt.Sprintf("No route for host %s", r.Host), http.StatusNotFound)
		return
	}

	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", backend.Host, backend.Port),
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	log.Log.Info("Forwarding request", "host", r.Host, "target", target.String())
	proxy.ServeHTTP(w, r)
}
