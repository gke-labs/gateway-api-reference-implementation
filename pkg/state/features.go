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
	"cmp"
	"slices"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// SupportedFeatures is the list of Gateway API features supported by GARI.
// It is a claim checked by the conformance suite, so features must only be
// added together with passing tests.
var SupportedFeatures = []features.FeatureName{
	features.SupportBackendTLSPolicy,
	features.SupportBackendTLSPolicySANValidation,
	features.SupportGRPCRoute,
	features.SupportGRPCRouteNamedRouteRule,
	features.SupportGRPCRouteRequestHeaderModifier,
	features.SupportGateway,
	features.SupportGatewayAddressEmpty,
	features.SupportGatewayBackendClientCertificate,
	features.SupportGatewayFrontendClientCertificateValidation,
	features.SupportGatewayFrontendClientCertificateValidationInsecureFallback,
	features.SupportGatewayHTTPListenerIsolation,
	features.SupportGatewayHTTPSListenerDetectMisdirectedRequests,
	features.SupportGatewayInfrastructure,
	features.SupportGatewayPort8080,
	features.SupportGatewayStaticAddresses,
	features.SupportHTTPRoute,
	features.SupportHTTPRoute303RedirectStatusCode,
	features.SupportHTTPRoute307RedirectStatusCode,
	features.SupportHTTPRoute308RedirectStatusCode,
	features.SupportHTTPRouteBackendProtocolH2C,
	features.SupportHTTPRouteBackendProtocolWebSocket,
	features.SupportHTTPRouteBackendRequestHeaderModification,
	features.SupportHTTPRouteBackendTimeout,
	features.SupportHTTPRouteCORS,
	features.SupportHTTPRouteDestinationPortMatching,
	features.SupportHTTPRouteHostRewrite,
	features.SupportHTTPRouteMethodMatching,
	features.SupportHTTPRouteNamedRouteRule,
	features.SupportHTTPRouteParentRefPort,
	features.SupportHTTPRoutePathRedirect,
	features.SupportHTTPRoutePathRewrite,
	features.SupportHTTPRoutePortRedirect,
	features.SupportHTTPRouteQueryParamMatching,
	features.SupportHTTPRouteRequestMirror,
	features.SupportHTTPRouteRequestMultipleMirrors,
	features.SupportHTTPRouteRequestPercentageMirror,
	features.SupportHTTPRouteRequestTimeout,
	features.SupportHTTPRouteResponseHeaderModification,
	features.SupportHTTPRouteRetryCodes,
	features.SupportHTTPRouteRetryConnectionError,
	features.SupportHTTPRouteSchemeRedirect,
	features.SupportListenerSet,
	features.SupportReferenceGrant,
	features.SupportTCPRoute,
	features.SupportTLSRoute,
	features.SupportTLSRouteModeMixed,
	features.SupportTLSRouteModeTerminate,
	features.SupportUDPRoute,
}

// GatewayClassSupportedFeatures returns the sorted slice of SupportedFeature for GatewayClass status.
func GatewayClassSupportedFeatures() []gatewayv1.SupportedFeature {
	out := make([]gatewayv1.SupportedFeature, len(SupportedFeatures))
	for i, f := range SupportedFeatures {
		out[i] = gatewayv1.SupportedFeature{Name: gatewayv1.FeatureName(f)}
	}
	slices.SortFunc(out, func(a, b gatewayv1.SupportedFeature) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}
