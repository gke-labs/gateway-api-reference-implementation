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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalGRPCRoute represents a compiled GRPCRoute containing parsed rules, matches,
// backends, resolved references, and surfaced validation conditions.
type InternalGRPCRoute struct {
	Route                 *gatewayv1.GRPCRoute
	Rules                 []InternalRule
	Hostnames             []string
	ParentRefs            []gatewayv1.ParentReference
	ValidationCondition   metav1.Condition
	ResolvedRefsCondition metav1.Condition
}

// GRPCRouteState wraps a GRPCRoute with its compiled representation.
type GRPCRouteState struct {
	*gatewayv1.GRPCRoute
	Internal *InternalGRPCRoute
}

// GetHostnames returns the list of hostnames declared on the route as strings.
func (s *GRPCRouteState) GetHostnames() []string {
	if s == nil || s.GRPCRoute == nil {
		return nil
	}
	var res []string
	for _, h := range s.Spec.Hostnames {
		res = append(res, string(h))
	}
	return res
}

// GetNamespace returns the namespace of the route.
func (s *GRPCRouteState) GetNamespace() string {
	if s == nil || s.GRPCRoute == nil {
		return ""
	}
	return s.Namespace
}

// Validate checks that the GRPCRoute values are syntactically and structurally correct.
func (s *GRPCRouteState) Validate() error {
	if s == nil || s.GRPCRoute == nil {
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

// Compile compiles the GRPCRoute into an InternalGRPCRoute, resolving references,
// verifying permissions, compiling matches, and recording conditions.
func (s *GRPCRouteState) Compile(
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalGRPCRoute {
	if s == nil || s.GRPCRoute == nil {
		return nil
	}
	s.Internal = CompileGRPCRoute(s.GRPCRoute, services, backendTLSPolicies, configMaps, refValidator)
	return s.Internal
}

// CompileGRPCRoute parses and compiles a GRPCRoute object into an InternalGRPCRoute.
func CompileGRPCRoute(
	route *gatewayv1.GRPCRoute,
	services map[types.NamespacedName]*corev1.Service,
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	refValidator ReferenceGrantValidator,
) *InternalGRPCRoute {
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

	sortedTLSPolicies := sortBackendTLSPolicies(backendTLSPolicies)

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

		// 1. Process rule filters
		for _, filter := range rule.Filters {
			switch filter.Type {
			case gatewayv1.GRPCRouteFilterRequestHeaderModifier:
				iRule.RequestHeaderModifier = filter.RequestHeaderModifier

			case gatewayv1.GRPCRouteFilterResponseHeaderModifier:
				iRule.ResponseHeaderModifier = filter.ResponseHeaderModifier

			case gatewayv1.GRPCRouteFilterRequestMirror:
				if filter.RequestMirror != nil {
					mirror, validationErr, refErr := compileRequestMirrorFilter(
						filter.RequestMirror,
						"GRPCRoute",
						route.Namespace,
						route.Generation,
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
				service := ValueOf(match.Method.Service)
				method := ValueOf(match.Method.Method)
				if service != "" && method != "" {
					iMatch.Path = &InternalPathMatch{
						Type:  gatewayv1.PathMatchExact,
						Value: fmt.Sprintf("/%s/%s", service, method),
					}
				} else if service != "" {
					iMatch.Path = &InternalPathMatch{
						Type:  gatewayv1.PathMatchPathPrefix,
						Value: fmt.Sprintf("/%s/", service),
					}
				}
			}

			seenHeaders := make(map[string]bool)
			for _, header := range match.Headers {
				canonHeader := strings.ToLower(string(header.Name))
				if seenHeaders[canonHeader] {
					continue
				}
				seenHeaders[canonHeader] = true

				headerType := ValueOf(header.Type)
				if headerType == "" {
					headerType = gatewayv1.GRPCHeaderMatchExact
				}
				hm := InternalHeaderMatch{
					Type:            gatewayv1.HeaderMatchType(headerType),
					Name:            string(header.Name),
					MatchExactValue: header.Value,
				}
				if headerType == gatewayv1.GRPCHeaderMatchRegularExpression {
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
			iRule.Matches = append(iRule.Matches, iMatch)
		}

		// 2. Process backend refs
		if iRule.Error == nil {
			for _, backendRef := range rule.BackendRefs {
				backend, refErr := resolveBackendTarget(
					backendRef.BackendObjectReference,
					"GRPCRoute",
					route.Namespace,
					route.Generation,
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
				var backendFilterErr error
				for _, filter := range backendRef.Filters {
					switch filter.Type {
					case gatewayv1.GRPCRouteFilterRequestHeaderModifier:
						backendReqHeaderModifier = filter.RequestHeaderModifier
					case gatewayv1.GRPCRouteFilterResponseHeaderModifier:
						backendRespHeaderModifier = filter.ResponseHeaderModifier
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
					if weight < 0 {
						weight = 0
					}
				}

				backend.Weight = weight
				backend.RequestHeaderModifier = backendReqHeaderModifier
				backend.ResponseHeaderModifier = backendRespHeaderModifier
				iRule.Backends = append(iRule.Backends, *backend)
			}
		}

		if iRule.Error != nil {
			iRule.Backends = nil
			iRule.Mirrors = nil
		}

		compiledRules = append(compiledRules, iRule)
	}

	if noPolicyHosts := noPolicyTLSBackendHosts(compiledRules); len(noPolicyHosts) > 0 && resolvedRefsCondition.Status == metav1.ConditionTrue {
		if len(noPolicyHosts) == 1 {
			resolvedRefsCondition.Message = fmt.Sprintf("Backend TLS without BackendTLSPolicy: verifying against system trust roots with ServerName %s (backend Service specifies appProtocol: https without a BackendTLSPolicy)", noPolicyHosts[0])
		} else {
			resolvedRefsCondition.Message = fmt.Sprintf("Backend TLS without BackendTLSPolicy: verifying against system trust roots with ServerName for %s (backend Services specify appProtocol: https without a BackendTLSPolicy)", strings.Join(noPolicyHosts, ", "))
		}
	}

	return &InternalGRPCRoute{
		Route:                 route,
		Rules:                 compiledRules,
		Hostnames:             hostnames,
		ParentRefs:            route.Spec.ParentRefs,
		ValidationCondition:   validationCondition,
		ResolvedRefsCondition: resolvedRefsCondition,
	}
}

// ComputeAcceptedCondition calculates the RouteConditionAccepted condition for a given parentRef and gateways/listenerSets.
func (s *GRPCRouteState) ComputeAcceptedCondition(parentRef gatewayv1.ParentReference, gateways []*GatewayState, namespaces map[string]*corev1.Namespace, listenerSets []*ListenerSetState) metav1.Condition {
	if s.Internal == nil {
		s.Compile(nil, nil, nil, nil)
	}

	var gws []*gatewayv1.Gateway
	for _, g := range gateways {
		if g != nil && g.Gateway != nil {
			gws = append(gws, g.Gateway)
		}
	}
	var lss []*gatewayv1.ListenerSet
	for _, ls := range listenerSets {
		if ls != nil && ls.ListenerSet != nil {
			lss = append(lss, ls.ListenerSet)
		}
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     gws,
		ListenerSets: lss,
		GRPCRoutes:   []*gatewayv1.GRPCRoute{s.GRPCRoute},
		Namespaces:   namespaces,
	})

	boundListeners := make(map[*EffectiveListener]bool)
	return bindGRPCRouteParentRef(s.GRPCRoute, s, parentRef, compiled, namespaces, boundListeners)
}

// ComputeResolvedRefsCondition calculates the RouteConditionResolvedRefs condition.
func (s *GRPCRouteState) ComputeResolvedRefsCondition(services map[types.NamespacedName]*corev1.Service, refValidator ReferenceGrantValidator) metav1.Condition {
	if s.Internal == nil || services != nil || refValidator != nil {
		s.Compile(services, nil, nil, refValidator)
	}
	return s.Internal.ResolvedRefsCondition
}

// IsAccepted returns true if the route has an Accepted condition with Status True for the given controller.
func (s *GRPCRouteState) IsAccepted(controllerName string) bool {
	if s == nil || s.GRPCRoute == nil {
		return false
	}
	for _, ps := range s.Status.Parents {
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

// IsAcceptedForParentRef checks if the route is accepted for a specific parent reference.
func (s *GRPCRouteState) IsAcceptedForParentRef(parentRef gatewayv1.ParentReference, controllerName string) bool {
	if s == nil || s.GRPCRoute == nil {
		return false
	}
	parentNamespace := s.Namespace
	if ns := ValueOf(parentRef.Namespace); ns != "" {
		parentNamespace = string(ns)
	}
	pKind := ValueOf(parentRef.Kind)
	if pKind == "" {
		pKind = "Gateway"
	}
	pGroup := ValueOf(parentRef.Group)
	if pGroup == "" {
		pGroup = gatewayv1.GroupName
	}
	for _, ps := range s.Status.Parents {
		if string(ps.ControllerName) != controllerName {
			continue
		}
		psNamespace := s.Namespace
		if ns := ValueOf(ps.ParentRef.Namespace); ns != "" {
			psNamespace = string(ns)
		}
		psKind := ValueOf(ps.ParentRef.Kind)
		if psKind == "" {
			psKind = "Gateway"
		}
		psGroup := ValueOf(ps.ParentRef.Group)
		if psGroup == "" {
			psGroup = gatewayv1.GroupName
		}
		if string(ps.ParentRef.Name) == string(parentRef.Name) &&
			psNamespace == parentNamespace &&
			psKind == pKind &&
			psGroup == pGroup &&
			ValueOf(ps.ParentRef.SectionName) == ValueOf(parentRef.SectionName) &&
			ValueOf(ps.ParentRef.Port) == ValueOf(parentRef.Port) {
			for _, c := range ps.Conditions {
				if c.Type == string(gatewayv1.RouteConditionAccepted) && c.Status == metav1.ConditionTrue {
					return true
				}
			}
		}
	}
	return false
}
