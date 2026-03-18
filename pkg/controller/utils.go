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

package controller

import (
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func updateProxy(st *state.State, p *proxy.Proxy) {
	gateways := st.GetGateways()
	routes := st.GetHTTPRoutes()
	services := st.GetServices()
	backendTLSPolicies := st.GetBackendTLSPolicies()
	configMaps := st.GetConfigMaps()

	var proxyRoutes []state.InternalRoute
	for _, gw := range gateways {
		proxyRoutes = append(proxyRoutes, gw.BuildInternalRoutes(routes, services, backendTLSPolicies, configMaps, ControllerName)...)
	}
	p.UpdateRoutes(proxyRoutes)
}

func isReferencePermitted(fromNamespace string, to types.NamespacedName, fromGroup, fromKind string, toGroup, toKind string, rgs []*gatewayv1beta1.ReferenceGrant) bool {
	if fromNamespace == to.Namespace {
		return true
	}

	for _, rg := range rgs {
		if rg.Namespace != to.Namespace {
			continue
		}

		// Check if the grant allows fromNamespace
		fromAllowed := false
		for _, from := range rg.Spec.From {
			if string(from.Group) == fromGroup && string(from.Kind) == fromKind && string(from.Namespace) == fromNamespace {
				fromAllowed = true
				break
			}
		}

		if !fromAllowed {
			continue
		}

		// Check if the grant allows toKind
		for _, toRef := range rg.Spec.To {
			if string(toRef.Group) == toGroup && string(toRef.Kind) == toKind {
				if toRef.Name == nil || string(*toRef.Name) == to.Name {
					return true
				}
			}
		}
	}

	return false
}
