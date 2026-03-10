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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type GatewayControllerOptions struct {
	client.Client
	Scheme           *runtime.Scheme
	State            *state.State
	Proxy            *proxy.Proxy
	SkipStatusUpdate bool

	GatewayName      string
	GatewayNamespace string
}

func (o *GatewayControllerOptions) UpdateProxy() {
	if o.Proxy == nil {
		return
	}
	gateways := o.State.GetGateways()
	routes := o.State.GetHTTPRoutes()
	services := o.State.GetServices()
	backendTLSPolicies := o.State.GetBackendTLSPolicies()
	configMaps := o.State.GetConfigMaps()

	var proxyRoutes []state.InternalRoute
	for _, gw := range gateways {
		// If GatewayName is set, only build routes for that gateway
		if o.GatewayName != "" && gw.Name != o.GatewayName {
			continue
		}
		if o.GatewayNamespace != "" && gw.Namespace != o.GatewayNamespace {
			continue
		}
		proxyRoutes = append(proxyRoutes, gw.BuildInternalRoutes(routes, services, backendTLSPolicies, configMaps, ControllerName)...)
	}
	o.Proxy.UpdateRoutes(proxyRoutes)
}

func hasCondition(conditions []metav1.Condition, target metav1.Condition) bool {
	for _, c := range conditions {
		if c.Type == target.Type && c.Status == target.Status && c.Reason == target.Reason && c.ObservedGeneration == target.ObservedGeneration {
			return true
		}
	}
	return false
}

func mergeConditions(existing []metav1.Condition, newConds []metav1.Condition) []metav1.Condition {
	res := make([]metav1.Condition, len(existing))
	copy(res, existing)

	for _, n := range newConds {
		found := false
		for i, e := range res {
			if e.Type == n.Type {
				res[i] = n
				found = true
				break
			}
		}
		if !found {
			res = append(res, n)
		}
	}
	return res
}
