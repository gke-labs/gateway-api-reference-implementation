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
	"testing"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHTTPRouteState_Validate(t *testing.T) {
	tests := []struct {
		name    string
		route   *gatewayv1.HTTPRoute
		wantErr bool
	}{
		{
			name: "valid route without rule names",
			route: &gatewayv1.HTTPRoute{
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{},
						{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid route with unique rule names",
			route: &gatewayv1.HTTPRoute{
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Name: Ptr(gatewayv1.SectionName("rule1"))},
						{Name: Ptr(gatewayv1.SectionName("rule2"))},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid route with duplicate rule names",
			route: &gatewayv1.HTTPRoute{
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{Name: Ptr(gatewayv1.SectionName("rule1"))},
						{Name: Ptr(gatewayv1.SectionName("rule1"))},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &HTTPRouteState{
				HTTPRoute: tt.route,
			}
			if err := s.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("HTTPRouteState.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
