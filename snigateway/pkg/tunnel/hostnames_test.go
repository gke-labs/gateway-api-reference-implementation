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

package tunnel

import (
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestExtractHostnames(t *testing.T) {
	host1 := gatewayv1.Hostname("app.example.com")
	hostWildcard := gatewayv1.Hostname("*.example.com")
	hostUpper := gatewayv1.Hostname("API.EXAMPLE.ORG")
	hostEmpty := gatewayv1.Hostname("")
	hostSpaces := gatewayv1.Hostname("   ")
	hostHTTP := gatewayv1.Hostname("http.example.com")
	hostTLS := gatewayv1.Hostname("tls.example.com")

	tests := []struct {
		name     string
		gateways []*gatewayv1.Gateway
		want     []string
	}{
		{
			name:     "empty gateways",
			gateways: nil,
			want:     nil,
		},
		{
			name: "nil gateway item",
			gateways: []*gatewayv1.Gateway{
				nil,
			},
			want: nil,
		},
		{
			name: "mixed listeners: HTTPS, TLS, HTTP, TCP, nil hostname, empty hostname",
			gateways: []*gatewayv1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gw-1",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "https-1",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &host1,
							},
							{
								Name:     "https-wildcard",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &hostWildcard,
							},
							{
								Name:     "https-no-host",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: nil,
							},
							{
								Name:     "https-empty-host",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &hostEmpty,
							},
							{
								Name:     "https-spaces-host",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &hostSpaces,
							},
							{
								Name:     "http-listener",
								Protocol: gatewayv1.HTTPProtocolType,
								Hostname: &hostHTTP,
							},
							{
								Name:     "http-no-host",
								Protocol: gatewayv1.HTTPProtocolType,
								Hostname: nil,
							},
							{
								Name:     "tcp-listener",
								Protocol: gatewayv1.TCPProtocolType,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "gw-2",
						Namespace: "default",
					},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{
								Name:     "tls-listener",
								Protocol: gatewayv1.TLSProtocolType,
								Hostname: &hostTLS,
							},
							{
								Name:     "https-dup-case",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &hostUpper,
							},
							{
								Name:     "https-dup-exact",
								Protocol: gatewayv1.HTTPSProtocolType,
								Hostname: &host1,
							},
							{
								Name:     "http-listener",
								Protocol: gatewayv1.HTTPProtocolType,
								Hostname: &hostHTTP,
							},
						},
					},
				},
			},
			want: []string{
				"*.example.com",
				"api.example.org",
				"app.example.com",
				"http.example.com",
				"tls.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractHostnames(tt.gateways)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ExtractHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}
