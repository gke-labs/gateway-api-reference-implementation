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

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestExtractHostnames(t *testing.T) {
	sameNamespaces := gatewayv1.NamespacesFromSame
	allowSame := &gatewayv1.AllowedListeners{
		Namespaces: &gatewayv1.ListenerNamespaces{
			From: &sameNamespaces,
		},
	}
	namespaces := map[string]*corev1.Namespace{
		"default": {ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		"other":   {ObjectMeta: metav1.ObjectMeta{Name: "other"}},
	}
	defaultNamespace := gatewayv1.Namespace("default")

	tests := []struct {
		name         string
		gateways     []*gatewayv1.Gateway
		listenerSets []*gatewayv1.ListenerSet
		want         []string
	}{
		{
			name: "gateway with no hostname listeners plus accepted listenerSet",
			gateways: []*gatewayv1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						AllowedListeners: allowSame,
						Listeners: []gatewayv1.Listener{
							{Name: "default", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app-ls", Namespace: "default"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "shared-gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("App.Example.Com"))},
							{Name: "tls", Port: 8443, Protocol: gatewayv1.TLSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("*.tls.example.com"))},
							{Name: "https-no-host", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
							{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("http-only.example.com"))},
						},
					},
				},
			},
			want: []string{"*.tls.example.com", "app.example.com"},
		},
		{
			name: "conflicted listenerSet listener is excluded",
			gateways: []*gatewayv1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						AllowedListeners: allowSame,
						Listeners: []gatewayv1.Listener{
							{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
							{Name: "gw-https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("gw.example.com"))},
						},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "conflict-ls", Namespace: "default"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "shared-gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "hostname-conflict", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("gw.example.com"))},
							{Name: "protocol-conflict", Port: 80, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("conflicted.example.com"))},
							{Name: "valid-https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("valid.example.com"))},
						},
					},
				},
			},
			want: []string{"gw.example.com", "valid.example.com"},
		},
		{
			name: "listenerSet not allowed by allowedListeners is excluded",
			gateways: []*gatewayv1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "same-only-gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						AllowedListeners: allowSame,
						Listeners: []gatewayv1.Listener{
							{Name: "default", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "none-gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{Name: "default", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "other-ns-ls", Namespace: "other"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Namespace: &defaultNamespace, Name: "same-only-gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("cross-ns.example.com"))},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "same-ns-ls", Namespace: "default"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "none-gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("default-none.example.com"))},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "conflicted gateway listener is excluded",
			gateways: []*gatewayv1.Gateway{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "conflict-gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{Name: "http-443", Port: 443, Protocol: gatewayv1.HTTPProtocolType},
							{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: state.Ptr(gatewayv1.Hostname("gw-conflict.example.com"))},
						},
					},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled := state.CompileModel(state.ModelInputs{
				Gateways:     tt.gateways,
				ListenerSets: tt.listenerSets,
				Namespaces:   namespaces,
			})
			var listeners []*state.EffectiveListener
			for _, compiledGateway := range compiled.GatewaysList() {
				listeners = append(listeners, compiledGateway.EffectiveListeners...)
			}
			got := ExtractHostnames(listeners)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ExtractHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}
