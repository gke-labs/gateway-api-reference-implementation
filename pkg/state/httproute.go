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
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalHTTPRoute represents a compiled HTTPRoute containing parsed rules, matches,
// backends, resolved references, and surfaced validation conditions.
type InternalHTTPRoute struct {
	Route                 *gatewayv1.HTTPRoute
	Rules                 []InternalRule
	Hostnames             []string
	ParentRefs            []gatewayv1.ParentReference
	ValidationCondition   metav1.Condition
	ResolvedRefsCondition metav1.Condition
}

type HTTPRouteState struct {
	*gatewayv1.HTTPRoute
	Internal *InternalHTTPRoute
}

// Compile compiles the HTTPRoute into an InternalHTTPRoute, resolving references,
// verifying permissions, compiling regexes and filters, and recording conditions.
func (s *HTTPRouteState) Compile(
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalHTTPRoute {
	if s.HTTPRoute == nil {
		return nil
	}
	s.Internal = CompileHTTPRoute(s.HTTPRoute, services, backendTLSPolicies, configMaps, refValidator)
	return s.Internal
}

// CompileHTTPRoute parses and compiles an HTTPRoute object into an InternalHTTPRoute.
func CompileHTTPRoute(
	route *gatewayv1.HTTPRoute,
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalHTTPRoute {
	if route == nil {
		return nil
	}

	validationCondition := NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonAccepted),
		"Route validation succeeded",
		route.Generation,
	)

	resolvedRefsCondition := NewCondition(
		string(gatewayv1.RouteConditionResolvedRefs),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonResolvedRefs),
		"All references resolved",
		route.Generation,
	)

	var hostnames []string
	for _, h := range route.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}

	// Deterministically sort a copy of BackendTLSPolicies by creation timestamp, then by namespaced name.
	var sortedTLSPolicies []*gatewayv1.BackendTLSPolicy
	if len(backendTLSPolicies) > 0 {
		sortedTLSPolicies = make([]*gatewayv1.BackendTLSPolicy, len(backendTLSPolicies))
		copy(sortedTLSPolicies, backendTLSPolicies)
		sort.SliceStable(sortedTLSPolicies, func(i, j int) bool {
			if sortedTLSPolicies[i].CreationTimestamp.Time.Before(sortedTLSPolicies[j].CreationTimestamp.Time) {
				return true
			}
			if sortedTLSPolicies[i].CreationTimestamp.Time.After(sortedTLSPolicies[j].CreationTimestamp.Time) {
				return false
			}
			if sortedTLSPolicies[i].Namespace != sortedTLSPolicies[j].Namespace {
				return sortedTLSPolicies[i].Namespace < sortedTLSPolicies[j].Namespace
			}
			return sortedTLSPolicies[i].Name < sortedTLSPolicies[j].Name
		})
	}

	var compiledRules []InternalRule
	seenRuleNames := make(map[gatewayv1.SectionName]bool)

	for _, rule := range route.Spec.Rules {
		iRule := InternalRule{
			Name: rule.Name,
		}

		if rule.Name != nil {
			if seenRuleNames[*rule.Name] {
				msg := fmt.Sprintf("duplicate rule name: %s", *rule.Name)
				errCond := NewCondition(
					string(gatewayv1.RouteConditionAccepted),
					metav1.ConditionFalse,
					string(gatewayv1.RouteReasonUnsupportedValue),
					msg,
					route.Generation,
				)
				if validationCondition.Status == metav1.ConditionTrue {
					validationCondition = errCond
				}
				if iRule.Error == nil {
					iRule.Error = &ErrorState{
						Condition:      errCond,
						HTTPStatusCode: http.StatusInternalServerError,
						HTTPMessage:    msg,
					}
				}
			}
			seenRuleNames[*rule.Name] = true
		}

		// 0. Process rule timeouts
		if timeouts, err := ParseTimeouts(rule.Timeouts); err != nil {
			errCond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonUnsupportedValue),
				err.Error(),
				route.Generation,
			)
			if validationCondition.Status == metav1.ConditionTrue {
				validationCondition = errCond
			}
			if iRule.Error == nil {
				iRule.Error = &ErrorState{
					Condition:      errCond,
					HTTPStatusCode: http.StatusInternalServerError,
					HTTPMessage:    err.Error(),
				}
			}
		} else {
			iRule.Timeouts = timeouts
		}

		// 1. Process rule filters
		for _, filter := range rule.Filters {
			switch filter.Type {
			case gatewayv1.HTTPRouteFilterRequestRedirect:
				r := filter.RequestRedirect
				if r == nil {
					continue
				}
				iRed := &InternalRedirect{
					Hostname:   r.Hostname,
					Port:       r.Port,
					StatusCode: r.StatusCode,
				}
				if r.Scheme != nil {
					schemeStr := string(*r.Scheme)
					iRed.Scheme = &schemeStr
				}
				if r.Path != nil {
					switch r.Path.Type {
					case gatewayv1.FullPathHTTPPathModifier:
						iRed.Path = &InternalPathRedirect{
							Type:  gatewayv1.FullPathHTTPPathModifier,
							Value: ValueOf(r.Path.ReplaceFullPath),
						}
					case gatewayv1.PrefixMatchHTTPPathModifier:
						iRed.Path = &InternalPathRedirect{
							Type:  gatewayv1.PrefixMatchHTTPPathModifier,
							Value: ValueOf(r.Path.ReplacePrefixMatch),
						}
					default:
						msg := fmt.Sprintf("Unsupported redirect path modifier type: %s", r.Path.Type)
						errCond := NewCondition(
							string(gatewayv1.RouteConditionAccepted),
							metav1.ConditionFalse,
							string(gatewayv1.RouteReasonUnsupportedValue),
							msg,
							route.Generation,
						)
						if validationCondition.Status == metav1.ConditionTrue {
							validationCondition = errCond
						}
						if iRule.Error == nil {
							iRule.Error = &ErrorState{
								Condition:      errCond,
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    msg,
							}
						}
					}
				}
				if iRule.Error == nil {
					iRule.Redirect = iRed
				}

			case gatewayv1.HTTPRouteFilterURLRewrite:
				rw := filter.URLRewrite
				if rw == nil {
					continue
				}
				iRw := &InternalRewrite{
					Hostname: rw.Hostname,
				}
				if rw.Path != nil {
					switch rw.Path.Type {
					case gatewayv1.FullPathHTTPPathModifier:
						iRw.Path = &InternalPathRewrite{
							Type:  gatewayv1.FullPathHTTPPathModifier,
							Value: ValueOf(rw.Path.ReplaceFullPath),
						}
					case gatewayv1.PrefixMatchHTTPPathModifier:
						iRw.Path = &InternalPathRewrite{
							Type:  gatewayv1.PrefixMatchHTTPPathModifier,
							Value: ValueOf(rw.Path.ReplacePrefixMatch),
						}
					default:
						msg := fmt.Sprintf("Unsupported rewrite path modifier type: %s", rw.Path.Type)
						errCond := NewCondition(
							string(gatewayv1.RouteConditionAccepted),
							metav1.ConditionFalse,
							string(gatewayv1.RouteReasonUnsupportedValue),
							msg,
							route.Generation,
						)
						if validationCondition.Status == metav1.ConditionTrue {
							validationCondition = errCond
						}
						if iRule.Error == nil {
							iRule.Error = &ErrorState{
								Condition:      errCond,
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    msg,
							}
						}
					}
				}
				if iRule.Error == nil {
					iRule.Rewrite = iRw
				}

			case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
				iRule.RequestHeaderModifier = filter.RequestHeaderModifier

			case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
				iRule.ResponseHeaderModifier = filter.ResponseHeaderModifier

			case gatewayv1.HTTPRouteFilterCORS:
				iRule.CORS = filter.CORS

			case gatewayv1.HTTPRouteFilterRequestMirror:
				if filter.RequestMirror != nil {
					mirror, validationErr, refErr := compileRequestMirrorFilter(
						filter.RequestMirror,
						route,
						services,
						sortedTLSPolicies,
						configMaps,
						refValidator,
					)
					if validationErr != nil {
						if validationCondition.Status == metav1.ConditionTrue {
							validationCondition = validationErr.Condition
						}
						if iRule.Error == nil {
							iRule.Error = validationErr
						}
					}
					if refErr != nil {
						if resolvedRefsCondition.Status == metav1.ConditionTrue {
							resolvedRefsCondition = refErr.Condition
						}
					}
					if mirror != nil {
						iRule.Mirrors = append(iRule.Mirrors, *mirror)
					}
				}

			default:
				msg := fmt.Sprintf("unsupported filter type: %s", filter.Type)
				errCond := NewCondition(
					string(gatewayv1.RouteConditionAccepted),
					metav1.ConditionFalse,
					string(gatewayv1.RouteReasonUnsupportedValue),
					msg,
					route.Generation,
				)
				if validationCondition.Status == metav1.ConditionTrue {
					validationCondition = errCond
				}
				if iRule.Error == nil {
					iRule.Error = &ErrorState{
						Condition:      errCond,
						HTTPStatusCode: http.StatusInternalServerError,
						HTTPMessage:    msg,
					}
				}
			}
		}

		// 2. Process matches
		for _, match := range rule.Matches {
			iMatch := InternalMatch{}
			if match.Method != nil {
				iMatch.Method = match.Method
			}
			if match.Path != nil {
				pathType := ValueOf(match.Path.Type)
				if pathType == "" {
					pathType = gatewayv1.PathMatchPathPrefix
				}
				iMatch.Path = &InternalPathMatch{
					Type:  pathType,
					Value: ValueOf(match.Path.Value),
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
					if err != nil {
						msg := fmt.Sprintf("invalid regular expression in header match: %v", err)
						errCond := NewCondition(
							string(gatewayv1.RouteConditionAccepted),
							metav1.ConditionFalse,
							string(gatewayv1.RouteReasonUnsupportedValue),
							msg,
							route.Generation,
						)
						if validationCondition.Status == metav1.ConditionTrue {
							validationCondition = errCond
						}
						if iRule.Error == nil {
							iRule.Error = &ErrorState{
								Condition:      errCond,
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    msg,
							}
						}
					} else {
						hm.MatchRegularExpressionValue = re
					}
				}
				iMatch.Headers = append(iMatch.Headers, hm)
			}
			seenQueryParams := make(map[string]bool)
			for _, qp := range match.QueryParams {
				qpName := string(qp.Name)
				if seenQueryParams[qpName] {
					continue
				}
				seenQueryParams[qpName] = true

				qpType := ValueOf(qp.Type)
				if qpType == "" {
					qpType = gatewayv1.QueryParamMatchExact
				}
				iqp := InternalQueryParamMatch{
					Type:            qpType,
					Name:            qpName,
					MatchExactValue: qp.Value,
				}
				if qpType == gatewayv1.QueryParamMatchRegularExpression {
					re, err := regexp.Compile(qp.Value)
					if err != nil {
						msg := fmt.Sprintf("invalid regular expression in query param match: %v", err)
						errCond := NewCondition(
							string(gatewayv1.RouteConditionAccepted),
							metav1.ConditionFalse,
							string(gatewayv1.RouteReasonUnsupportedValue),
							msg,
							route.Generation,
						)
						if validationCondition.Status == metav1.ConditionTrue {
							validationCondition = errCond
						}
						if iRule.Error == nil {
							iRule.Error = &ErrorState{
								Condition:      errCond,
								HTTPStatusCode: http.StatusInternalServerError,
								HTTPMessage:    msg,
							}
						}
					} else {
						iqp.MatchRegularExpressionValue = re
					}
				} else if qpType != gatewayv1.QueryParamMatchExact {
					msg := fmt.Sprintf("unsupported query param match type: %s", qpType)
					errCond := NewCondition(
						string(gatewayv1.RouteConditionAccepted),
						metav1.ConditionFalse,
						string(gatewayv1.RouteReasonUnsupportedValue),
						msg,
						route.Generation,
					)
					if validationCondition.Status == metav1.ConditionTrue {
						validationCondition = errCond
					}
					if iRule.Error == nil {
						iRule.Error = &ErrorState{
							Condition:      errCond,
							HTTPStatusCode: http.StatusInternalServerError,
							HTTPMessage:    msg,
						}
					}
				}
				iMatch.QueryParams = append(iMatch.QueryParams, iqp)
			}
			iRule.Matches = append(iRule.Matches, iMatch)
		}

		// 3. Process backend refs
		if iRule.Error == nil && iRule.Redirect == nil {
			for _, backendRef := range rule.BackendRefs {
				backend, refErr := resolveBackendTarget(
					backendRef.BackendObjectReference,
					route,
					services,
					sortedTLSPolicies,
					configMaps,
					refValidator,
				)
				if refErr != nil {
					if resolvedRefsCondition.Status == metav1.ConditionTrue {
						resolvedRefsCondition = refErr.Condition
					}
					if iRule.Error == nil {
						iRule.Error = refErr
					}
					break
				}

				// Backend filters
				var backendReqHeaderModifier *gatewayv1.HTTPHeaderFilter
				var backendRespHeaderModifier *gatewayv1.HTTPHeaderFilter
				var backendCORS *gatewayv1.HTTPCORSFilter
				var backendFilterErr error
				for _, filter := range backendRef.Filters {
					switch filter.Type {
					case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
						backendReqHeaderModifier = filter.RequestHeaderModifier
					case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
						backendRespHeaderModifier = filter.ResponseHeaderModifier
					case gatewayv1.HTTPRouteFilterCORS:
						backendCORS = filter.CORS
					default:
						backendFilterErr = fmt.Errorf("Unsupported backend filter type: %s", filter.Type)
					}
				}

				if backendFilterErr != nil {
					errCond := NewCondition(
						string(gatewayv1.RouteConditionAccepted),
						metav1.ConditionFalse,
						string(gatewayv1.RouteReasonUnsupportedValue),
						backendFilterErr.Error(),
						route.Generation,
					)
					if validationCondition.Status == metav1.ConditionTrue {
						validationCondition = errCond
					}
					if iRule.Error == nil {
						iRule.Error = &ErrorState{
							Condition:      errCond,
							HTTPStatusCode: http.StatusInternalServerError,
							HTTPMessage:    backendFilterErr.Error(),
						}
					}
					break
				}

				weight := int32(1)
				if backendRef.Weight != nil {
					weight = *backendRef.Weight
				}

				backend.Weight = weight
				backend.RequestHeaderModifier = backendReqHeaderModifier
				backend.ResponseHeaderModifier = backendRespHeaderModifier
				backend.CORS = backendCORS
				iRule.Backends = append(iRule.Backends, *backend)
			}
		}

		if iRule.Error != nil {
			iRule.Backends = nil
			iRule.Mirrors = nil
		}

		compiledRules = append(compiledRules, iRule)
	}

	return &InternalHTTPRoute{
		Route:                 route,
		Rules:                 compiledRules,
		Hostnames:             hostnames,
		ParentRefs:            route.Spec.ParentRefs,
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// Validate checks that the HTTPRoute values are syntactically and structurally correct.
func (s *HTTPRouteState) Validate() error {
	if s.HTTPRoute == nil {
		return nil
	}
	if s.Internal == nil {
		s.Compile(nil, nil, nil, nil)
	}
	if s.Internal.ValidationCondition.Status == metav1.ConditionFalse {
		return errors.New(s.Internal.ValidationCondition.Message)
	}
	return nil
}

// ComputeAcceptedCondition calculates the RouteConditionAccepted condition for a given parentRef and gateways.
func (s *HTTPRouteState) ComputeAcceptedCondition(parentRef gatewayv1.ParentReference, gateways []*GatewayState) metav1.Condition {
	if s.Internal == nil {
		s.Compile(nil, nil, nil, nil)
	}

	if s.Internal.ValidationCondition.Status == metav1.ConditionFalse {
		return s.Internal.ValidationCondition
	}

	if group := ValueOf(parentRef.Group); group != "" && group != "gateway.networking.k8s.io" {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingParent),
			fmt.Sprintf("Unsupported parent group: %s", group),
			s.Generation,
		)
	}

	if kind := ValueOf(parentRef.Kind); kind != "" && kind != "Gateway" {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingParent),
			fmt.Sprintf("Unsupported parent kind: %s", kind),
			s.Generation,
		)
	}

	// Check if Gateway exists and has matching listeners
	var gw *GatewayState
	targetNamespace := s.Namespace
	if parentNamespace := ValueOf(parentRef.Namespace); parentNamespace != "" {
		targetNamespace = string(parentNamespace)
	}
	for _, g := range gateways {
		if g.Name == string(parentRef.Name) && (targetNamespace == "" || g.Namespace == "" || g.Namespace == targetNamespace) {
			gw = g
			break
		}
	}

	if gw == nil {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingParent),
			"Gateway not found",
			s.Generation,
		)
	}

	hasMatchingListener := false
	hasAllowedListener := false
	hasMatchingHostname := false

	for _, listener := range gw.Spec.Listeners {
		if sectionName := ValueOf(parentRef.SectionName); sectionName != "" && sectionName != listener.Name {
			continue
		}
		if port := ValueOf(parentRef.Port); port != 0 && port != listener.Port {
			continue
		}
		hasMatchingListener = true

		// Check protocol compatibility
		if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
			continue
		}

		// Check AllowedRoutes kinds
		if listener.AllowedRoutes != nil && len(listener.AllowedRoutes.Kinds) > 0 {
			kindAllowed := false
			for _, k := range listener.AllowedRoutes.Kinds {
				if IsHTTPRoute(k.Group, k.Kind) {
					kindAllowed = true
					break
				}
			}
			if !kindAllowed {
				continue
			}
		}

		// Check AllowedRoutes namespaces
		if listener.AllowedRoutes != nil && listener.AllowedRoutes.Namespaces != nil && listener.AllowedRoutes.Namespaces.From != nil {
			switch *listener.AllowedRoutes.Namespaces.From {
			case gatewayv1.NamespacesFromSame:
				if s.Namespace != gw.Namespace {
					continue
				}
			case gatewayv1.NamespacesFromAll:
				// Allowed
			case gatewayv1.NamespacesFromSelector:
				if s.Namespace != gw.Namespace && listener.AllowedRoutes.Namespaces.Selector == nil {
					continue
				}
			}
		} else {
			// Default is Same namespace
			if s.Namespace != gw.Namespace {
				continue
			}
		}

		hasAllowedListener = true

		effectiveHostnames := IntersectHostnames(s.GetHostnames(), string(ValueOf(listener.Hostname)))
		if len(effectiveHostnames) > 0 || len(s.Spec.Hostnames) == 0 {
			hasMatchingHostname = true
			break
		}
	}

	if hasMatchingHostname {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionTrue,
			string(gatewayv1.RouteReasonAccepted),
			"Route accepted by reference implementation",
			s.Generation,
		)
	}
	if hasAllowedListener {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingListenerHostname),
			"No matching listener hostname",
			s.Generation,
		)
	}
	if hasMatchingListener {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNotAllowedByListeners),
			"Not allowed by listener permissions or protocol",
			s.Generation,
		)
	}
	return NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionFalse,
		string(gatewayv1.RouteReasonNoMatchingParent),
		"No matching listener for parentRef",
		s.Generation,
	)
}

// ComputeResolvedRefsCondition calculates the RouteConditionResolvedRefs condition.
func (s *HTTPRouteState) ComputeResolvedRefsCondition(services map[types.NamespacedName]*corev1.Service, refValidator ReferenceGrantValidator) metav1.Condition {
	if s.Internal == nil || services != nil || refValidator != nil {
		s.Compile(services, nil, nil, refValidator)
	}
	return s.Internal.ResolvedRefsCondition
}

func (s *HTTPRouteState) IsAccepted(controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}
	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			for _, c := range ps.Conditions {
				if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
					return true
				}
			}
		}
	}
	return false
}

func (s *HTTPRouteState) IsAcceptedForParentRef(parentRef gatewayv1.ParentReference, controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}
	parentNamespace := s.Namespace
	if ns := ValueOf(parentRef.Namespace); ns != "" {
		parentNamespace = string(ns)
	}
	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) != controllerName {
			continue
		}
		psNamespace := s.Namespace
		if ns := ValueOf(ps.ParentRef.Namespace); ns != "" {
			psNamespace = string(ns)
		}
		if string(ps.ParentRef.Name) == string(parentRef.Name) &&
			psNamespace == parentNamespace &&
			ValueOf(ps.ParentRef.SectionName) == ValueOf(parentRef.SectionName) &&
			ValueOf(ps.ParentRef.Port) == ValueOf(parentRef.Port) &&
			ValueOf(ps.ParentRef.Group) == ValueOf(parentRef.Group) &&
			ValueOf(ps.ParentRef.Kind) == ValueOf(parentRef.Kind) {
			for _, c := range ps.Conditions {
				if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
					return true
				}
			}
		}
	}
	return false
}

func (s *HTTPRouteState) MatchesGateway(gw *gatewayv1.Gateway, controllerName string) bool {
	if s.HTTPRoute == nil {
		return false
	}

	for _, ps := range s.HTTPRoute.Status.Parents {
		if string(ps.ControllerName) == controllerName {
			if string(ps.ParentRef.Name) == gw.Name {
				for _, c := range ps.Conditions {
					if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
						return true
					}
				}
			}
		}
	}

	return false
}

// resolveBackendTarget resolves a BackendObjectReference to an InternalBackend,
// performing kind/group checks, cross-namespace ReferenceGrant validation, Service resolution,
// and BackendTLSPolicy matching.
func resolveBackendTarget(
	backendRef gatewayv1.BackendObjectReference,
	route *gatewayv1.HTTPRoute,
	services map[types.NamespacedName]*corev1.Service,
	sortedTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) (*InternalBackend, *ErrorState) {
	group := ValueOf(backendRef.Group)
	kind := ValueOf(backendRef.Kind)
	if kind == "" {
		kind = "Service"
	}

	if (group != "" && group != "core") || kind != "Service" {
		var msg string
		if group != "" && group != "core" {
			msg = fmt.Sprintf("Unsupported backend: %s/%s", group, kind)
		} else {
			msg = fmt.Sprintf("Unsupported backend kind: %s", kind)
		}
		errCond := NewCondition(
			string(gatewayv1.RouteConditionResolvedRefs),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonInvalidKind),
			msg,
			route.Generation,
		)
		return nil, &ErrorState{
			Condition:      errCond,
			HTTPStatusCode: http.StatusInternalServerError,
			HTTPMessage:    msg,
		}
	}

	svcNamespace := route.Namespace
	if backendRef.Namespace != nil && string(*backendRef.Namespace) != "" {
		svcNamespace = string(*backendRef.Namespace)
	}

	// Cross-namespace ReferenceGrant check
	if svcNamespace != route.Namespace {
		from := Reference{
			GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: "HTTPRoute"},
			Namespace: route.Namespace,
		}
		to := Reference{
			GroupKind: schema.GroupKind{Group: string(group), Kind: string(kind)},
			Namespace: svcNamespace,
			Name:      string(backendRef.Name),
		}
		if refValidator == nil || !refValidator.IsReferencePermitted(from, to) {
			msg := fmt.Sprintf("Cross-namespace reference to service %s/%s is not permitted by any ReferenceGrant", svcNamespace, string(backendRef.Name))
			errCond := NewCondition(
				string(gatewayv1.RouteConditionResolvedRefs),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonRefNotPermitted),
				msg,
				route.Generation,
			)
			return nil, &ErrorState{
				Condition:      errCond,
				HTTPStatusCode: http.StatusInternalServerError,
				HTTPMessage:    msg,
			}
		}
	}

	// Service resolution
	port := int32(80)
	if backendRef.Port != nil {
		port = int32(*backendRef.Port)
	}

	svcKey := types.NamespacedName{
		Namespace: svcNamespace,
		Name:      string(backendRef.Name),
	}

	var appProtocol *string
	if services != nil {
		svc, ok := services[svcKey]
		if !ok || svc == nil {
			msg := fmt.Sprintf("Backend service %s/%s not found", svcNamespace, string(backendRef.Name))
			errCond := NewCondition(
				string(gatewayv1.RouteConditionResolvedRefs),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonBackendNotFound),
				msg,
				route.Generation,
			)
			return nil, &ErrorState{
				Condition:      errCond,
				HTTPStatusCode: http.StatusInternalServerError,
				HTTPMessage:    msg,
			}
		}

		for _, p := range svc.Spec.Ports {
			if p.Port == port {
				appProtocol = p.AppProtocol
				break
			}
		}
	}

	// BackendTLSPolicy resolution
	var tlsConfig *InternalTLSConfig
	for _, policy := range sortedTLSPolicies {
		if tlsConfig != nil {
			break
		}
		for _, targetRef := range policy.Spec.TargetRefs {
			if string(targetRef.Group) == "" && string(targetRef.Kind) == "Service" &&
				string(targetRef.Name) == string(backendRef.Name) &&
				policy.Namespace == svcNamespace {
				https := "https"
				appProtocol = &https

				var caCerts [][]byte
				for _, caRef := range policy.Spec.Validation.CACertificateRefs {
					if string(caRef.Group) == "" && string(caRef.Kind) == "ConfigMap" {
						cmName := types.NamespacedName{Namespace: policy.Namespace, Name: string(caRef.Name)}
						if cm, ok := configMaps[cmName]; ok {
							if data, ok := cm.Data["ca.crt"]; ok {
								caCerts = append(caCerts, []byte(data))
							} else if data, ok := cm.BinaryData["ca.crt"]; ok {
								caCerts = append(caCerts, data)
							}
						}
					}
				}

				tlsConfig = &InternalTLSConfig{
					Hostname: string(policy.Spec.Validation.Hostname),
					CACerts:  caCerts,
				}
				break
			}
		}
	}

	return &InternalBackend{
		Host:        fmt.Sprintf("%s.%s.svc.cluster.local", backendRef.Name, svcNamespace),
		Port:        port,
		AppProtocol: appProtocol,
		TLSConfig:   tlsConfig,
	}, nil
}

// compileRequestMirrorFilter validates the filter settings and resolves the mirror backend target.
func compileRequestMirrorFilter(
	m *gatewayv1.HTTPRequestMirrorFilter,
	route *gatewayv1.HTTPRoute,
	services map[types.NamespacedName]*corev1.Service,
	sortedTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) (*InternalMirror, *ErrorState, *ErrorState) {
	numerator := int32(100)
	denominator := int32(100)

	if m.Percent != nil && m.Fraction != nil {
		msg := "cannot specify both percent and fraction for request mirror filter"
		errCond := NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonUnsupportedValue),
			msg,
			route.Generation,
		)
		return nil, &ErrorState{
			Condition:      errCond,
			HTTPStatusCode: http.StatusInternalServerError,
			HTTPMessage:    msg,
		}, nil
	} else if m.Percent != nil {
		if *m.Percent < 0 || *m.Percent > 100 {
			msg := fmt.Sprintf("invalid percent %d for request mirror filter: must be between 0 and 100", *m.Percent)
			errCond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonUnsupportedValue),
				msg,
				route.Generation,
			)
			return nil, &ErrorState{
				Condition:      errCond,
				HTTPStatusCode: http.StatusInternalServerError,
				HTTPMessage:    msg,
			}, nil
		}
		numerator = *m.Percent
		denominator = 100
	} else if m.Fraction != nil {
		denom := int32(100)
		if m.Fraction.Denominator != nil {
			denom = *m.Fraction.Denominator
		}
		if m.Fraction.Numerator < 0 || denom < 1 || m.Fraction.Numerator > denom {
			msg := fmt.Sprintf("invalid fraction %d/%d for request mirror filter", m.Fraction.Numerator, denom)
			errCond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonUnsupportedValue),
				msg,
				route.Generation,
			)
			return nil, &ErrorState{
				Condition:      errCond,
				HTTPStatusCode: http.StatusInternalServerError,
				HTTPMessage:    msg,
			}, nil
		}
		numerator = m.Fraction.Numerator
		denominator = denom
	}

	backend, refErr := resolveBackendTarget(
		m.BackendRef,
		route,
		services,
		sortedTLSPolicies,
		configMaps,
		refValidator,
	)
	if refErr != nil {
		return nil, nil, refErr
	}

	return &InternalMirror{
		Backend:     *backend,
		Numerator:   numerator,
		Denominator: denominator,
	}, nil, nil
}
