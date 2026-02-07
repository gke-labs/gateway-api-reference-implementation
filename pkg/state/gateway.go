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

package state

import (
	"fmt"
	"regexp"

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

// InternalRoute represents the computed state for a route, used by the proxy.
type InternalRoute struct {
	Hostnames []string
	Rules     []InternalRule
}

type InternalRule struct {
	Matches  []InternalMatch
	Backend  *InternalBackend
	Redirect *InternalRedirect
}

type InternalBackend struct {
	Host string
	Port int32
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
	Path    *InternalPathMatch
	Headers []InternalHeaderMatch
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

func (s *GatewayState) BuildInternalRoutes(routes []*HTTPRouteState, controllerName string) []InternalRoute {
	var internalRoutes []InternalRoute

	for _, listener := range s.Spec.Listeners {
		// Check if listener is compatible with HTTPRoute
		if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
			continue
		}

		for _, route := range routes {
			if !route.IsAccepted(controllerName) {
				continue
			}

			// Check if this route is bound to this Gateway and specifically this listener (if SectionName is set)
			bound := false
			var matchingParentRef *gatewayv1.ParentReference
			for _, parentRef := range route.Spec.ParentRefs {
				if string(parentRef.Name) != s.Name {
					continue
				}
				// Namespace check (optional for now as per current implementation)
				if ns := ValueOf(parentRef.Namespace); ns != "" && string(ns) != s.Namespace {
					continue
				}

				if sn := ValueOf(parentRef.SectionName); sn != "" && sn != listener.Name {
					continue
				}
				bound = true
				matchingParentRef = &parentRef
				break
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
			}

			for _, rule := range route.Spec.Rules {
				var redirect *InternalRedirect
				for _, filter := range rule.Filters {
					if filter.Type == gatewayv1.HTTPRouteFilterRequestRedirect {
						r := filter.RequestRedirect
						redirect = &InternalRedirect{
							Scheme:     r.Scheme,
							Hostname:   r.Hostname,
							Port:       r.Port,
							StatusCode: r.StatusCode,
						}
						if r.Path != nil {
							var pathValue string
							if r.Path.Type == gatewayv1.FullPathHTTPPathModifier {
								pathValue = ValueOf(r.Path.ReplaceFullPath)
							} else if r.Path.Type == gatewayv1.PrefixMatchHTTPPathModifier {
								pathValue = ValueOf(r.Path.ReplacePrefixMatch)
							}
							redirect.Path = &InternalPathRedirect{
								Type:  r.Path.Type,
								Value: pathValue,
							}
						}
						break
					}
				}

				iRule := InternalRule{
					Redirect: redirect,
				}

				if redirect == nil {
					for _, backendRef := range rule.BackendRefs {
						if ValueOf(backendRef.Kind) != "Service" && backendRef.Kind != nil {
							continue
						}

						if backendRef.Port == nil {
							continue
						}

						iRule.Backend = &InternalBackend{
							Host: fmt.Sprintf("%s.%s.svc.cluster.local", backendRef.Name, route.Namespace),
							Port: int32(*backendRef.Port),
						}

						// For minimal implementation, we just take the first Service backendRef for each rule
						break
					}
				}

				for _, match := range rule.Matches {
					iMatch := InternalMatch{}
					if match.Path != nil {
						iMatch.Path = &InternalPathMatch{
							Type:  ValueOf(match.Path.Type),
							Value: ValueOf(match.Path.Value),
						}
						if iMatch.Path.Type == "" {
							iMatch.Path.Type = gatewayv1.PathMatchPathPrefix
						}
					}
					for _, header := range match.Headers {
						headerType := ValueOf(header.Type)
						if headerType == "" {
							headerType = gatewayv1.HeaderMatchExact
						}
						hm := InternalHeaderMatch{
							Type:            headerType,
							Name:            string(header.Name),
							MatchExactValue: header.Value,
						}
						if headerType == gatewayv1.HeaderMatchRegularExpression {
							re, err := regexp.Compile(header.Value)
							if err == nil {
								hm.MatchRegularExpressionValue = re
							}
						}
						iMatch.Headers = append(iMatch.Headers, hm)
					}
					iRule.Matches = append(iRule.Matches, iMatch)
				}

				ir.Rules = append(ir.Rules, iRule)
			}
			internalRoutes = append(internalRoutes, ir)
			_ = matchingParentRef // keep for now
		}
	}

	return internalRoutes
}
