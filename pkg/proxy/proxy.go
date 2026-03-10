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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"golang.org/x/net/http2"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Proxy is a minimal implementation of a Gateway API proxy.
type Proxy struct {
	mu            sync.RWMutex
	routes        []state.InternalRoute
	mirrorClients sync.Map
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

	bestRule, bestMatch := state.MatchRoute(routes, r)

	if bestRule != nil {
		if bestRule.Redirect != nil {
			p.redirect(w, r, *bestRule.Redirect, bestMatch)
			return
		}
		if bestRule.Error != nil {
			// Per Gateway API specification, if a rule matches but its backend is invalid
			// or unresolved, the implementation SHOULD return an HTTP 500 Internal Server Error.
			// This is also verified by conformance tests like HTTPRouteInvalidBackendRefUnknownKind.
			http.Error(w, bestRule.Error.HTTPMessage, bestRule.Error.HTTPStatusCode)
			return
		}
		if bestRule.Backend != nil {
			if len(bestRule.Mirrors) > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1MB limit for mirroring
				body, err := io.ReadAll(r.Body)
				if err != nil {
					log.Log.Error(err, "Error reading request body for mirroring")
					if err.Error() == "http: request body too large" {
						http.Error(w, "Request body too large for mirroring", http.StatusRequestEntityTooLarge)
					} else {
						http.Error(w, "Error reading request body", http.StatusInternalServerError)
					}
					return
				}
				r.Body = io.NopCloser(bytes.NewBuffer(body))
				for _, mirror := range bestRule.Mirrors {
					mReq := r.Clone(context.WithoutCancel(r.Context()))
					mReq.Body = io.NopCloser(bytes.NewBuffer(body))
					go p.mirror(mReq, *mirror)
				}
			}
			p.forward(w, r, *bestRule.Backend)
			return
		}
	}

	http.Error(w, fmt.Sprintf("No route for host %s and path %s", r.Host, r.URL.Path), http.StatusNotFound)
}

func (p *Proxy) mirror(req *http.Request, backend state.InternalBackend) {
	scheme := "http"
	if state.ValueOf(backend.AppProtocol) == "https" {
		scheme = "https"
	}

	target := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", backend.Host, backend.Port),
		Path:   req.URL.Path,
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host
	req.RequestURI = "" // RequestURI must be empty for client requests

	key := fmt.Sprintf("%s-%s:%d", scheme, backend.Host, backend.Port)
	clientVal, ok := p.mirrorClients.Load(key)
	var client *http.Client
	if ok {
		client = clientVal.(*http.Client)
	} else {
		client = &http.Client{
			Timeout: 10 * time.Second, // Timeout to prevent goroutine leaks
		}
		if scheme == "https" {
			tlsConfig := &tls.Config{InsecureSkipVerify: false}
			if backend.TLSConfig != nil {
				if backend.TLSConfig.Hostname != "" {
					tlsConfig.ServerName = backend.TLSConfig.Hostname
				}
				if len(backend.TLSConfig.CACerts) > 0 {
					tlsConfig.RootCAs = x509.NewCertPool()
					for _, cert := range backend.TLSConfig.CACerts {
						if ok := tlsConfig.RootCAs.AppendCertsFromPEM(cert); !ok {
							log.Log.V(1).Info("Failed to parse CA certificate for mirror backend", "host", backend.Host)
						}
					}
				} else {
					tlsConfig.InsecureSkipVerify = true
				}
			} else {
				tlsConfig.InsecureSkipVerify = true
			}
			client.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}
		p.mirrorClients.Store(key, client)
	}

	log.Log.V(1).Info("Mirroring request", "host", req.Host, "path", req.URL.Path, "target", target.String())
	resp, err := client.Do(req)
	if err != nil {
		log.Log.Error(err, "Error mirroring request", "target", target.String())
		return
	}
	defer resp.Body.Close()
	// Drain the response body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
}

func (p *Proxy) redirect(w http.ResponseWriter, r *http.Request, redirect state.InternalRedirect, match *state.InternalMatch) {
	newURL := &url.URL{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Inherit scheme
	if r.TLS != nil {
		newURL.Scheme = "https"
	} else {
		newURL.Scheme = "http"
	}
	if scheme := state.ValueOf(redirect.Scheme); scheme != "" {
		newURL.Scheme = scheme
	}

	// Inherit host and port
	newURL.Host = r.Host

	if hostname := state.ValueOf(redirect.Hostname); hostname != "" {
		h, port, err := net.SplitHostPort(newURL.Host)
		if err != nil {
			// No port in current Host
			newURL.Host = string(hostname)
		} else {
			_ = h
			newURL.Host = net.JoinHostPort(string(hostname), port)
		}
	}

	if port := state.ValueOf(redirect.Port); port != 0 {
		h, _, err := net.SplitHostPort(newURL.Host)
		if err != nil {
			h = newURL.Host
		}
		newURL.Host = net.JoinHostPort(h, fmt.Sprintf("%d", port))
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
	scheme := "http"
	if state.ValueOf(backend.AppProtocol) == "https" {
		scheme = "https"
	}

	target := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", backend.Host, backend.Port),
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	if scheme == "https" {
		tlsConfig := &tls.Config{InsecureSkipVerify: false}
		if backend.TLSConfig != nil {
			if backend.TLSConfig.Hostname != "" {
				tlsConfig.ServerName = backend.TLSConfig.Hostname
			}
			if len(backend.TLSConfig.CACerts) > 0 {
				tlsConfig.RootCAs = x509.NewCertPool()
				for _, cert := range backend.TLSConfig.CACerts {
					tlsConfig.RootCAs.AppendCertsFromPEM(cert)
				}
			} else {
				tlsConfig.InsecureSkipVerify = true
			}
		} else {
			tlsConfig.InsecureSkipVerify = true
		}
		proxy.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	} else if state.ValueOf(backend.AppProtocol) == "kubernetes.io/h2c" {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	}

	log.Log.Info("Forwarding request", "host", r.Host, "path", r.URL.Path, "target", target.String(), "appProtocol", state.ValueOf(backend.AppProtocol))
	proxy.ServeHTTP(w, r)
}
