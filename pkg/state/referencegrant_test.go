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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestIsReferencePermitted(t *testing.T) {
	s := NewState()

	// Same namespace should always be permitted
	if !s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns1", "", "Secret", "ns1", "sec1") {
		t.Errorf("Same namespace reference should be permitted")
	}

	// Different namespace without ReferenceGrant should NOT be permitted
	if s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns1", "", "Secret", "ns2", "sec1") {
		t.Errorf("Cross-namespace reference without ReferenceGrant should NOT be permitted")
	}

	// Add a ReferenceGrant in ns2 allowing ns1 to access any Secret
	rg1 := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns2",
			Name:      "allow-ns1",
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     "gateway.networking.k8s.io",
					Kind:      "Gateway",
					Namespace: "ns1",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
				},
			},
		},
	}
	s.UpsertReferenceGrant(rg1)

	if !s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns1", "", "Secret", "ns2", "sec1") {
		t.Errorf("Cross-namespace reference with valid ReferenceGrant (all names) should be permitted")
	}

	// Reference from different namespace should NOT be permitted
	if s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns3", "", "Secret", "ns2", "sec1") {
		t.Errorf("Cross-namespace reference from unauthorized namespace should NOT be permitted")
	}

	// Add a ReferenceGrant in ns2 allowing only specific Secret name
	rg2 := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns2",
			Name:      "allow-ns3-specific",
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     "gateway.networking.k8s.io",
					Kind:      "Gateway",
					Namespace: "ns3",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
					Name:  Ptr(gatewayv1beta1.ObjectName("secret-a")),
				},
			},
		},
	}
	s.UpsertReferenceGrant(rg2)

	if !s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns3", "", "Secret", "ns2", "secret-a") {
		t.Errorf("Cross-namespace reference with valid ReferenceGrant (specific name) should be permitted")
	}

	if s.IsReferencePermitted("gateway.networking.k8s.io", "Gateway", "ns3", "", "Secret", "ns2", "secret-b") {
		t.Errorf("Cross-namespace reference with wrong name should NOT be permitted")
	}
}
