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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/version"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

func generateTestCertPEM(t *testing.T, hostnames ...string) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames:  hostnames,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestCompileModel_EffectiveListeners(t *testing.T) {
	sameFrom := gatewayv1.NamespacesFromSame
	noneFrom := gatewayv1.NamespacesFromNone
	allFrom := gatewayv1.NamespacesFromAll
	selectorFrom := gatewayv1.NamespacesFromSelector

	tests := []struct {
		name                   string
		gateway                *gatewayv1.Gateway
		listenerSets           []*gatewayv1.ListenerSet
		namespaces             map[string]*corev1.Namespace
		expectedListenersCount int
		expectedAttachedLS     int32
		expectedOwnerKinds     []gatewayv1.Kind
	}{
		{
			name: "Gateway without ListenerSets",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			expectedListenersCount: 1,
			expectedAttachedLS:     0,
			expectedOwnerKinds:     []gatewayv1.Kind{"Gateway"},
		},
		{
			name: "Gateway with AllowedListeners None rejects ListenerSets",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &noneFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls1", Namespace: "default"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "ls-http", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			expectedListenersCount: 1,
			expectedAttachedLS:     0,
			expectedOwnerKinds:     []gatewayv1.Kind{"Gateway"},
		},
		{
			name: "Gateway with AllowedListeners Same allows same-namespace ListenerSet only",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &sameFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-same", Namespace: "default"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "ls-http", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-other", Namespace: "other"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "ls-other-http", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			expectedListenersCount: 2,
			expectedAttachedLS:     1,
			expectedOwnerKinds:     []gatewayv1.Kind{"Gateway", "ListenerSet"},
		},
		{
			name: "Gateway with AllowedListeners All allows cross-namespace ListenerSets in precedence order",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "ls-b",
						Namespace:         "ns-b",
						CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
					},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "http-b", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "ls-a",
						Namespace:         "ns-a",
						CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
					},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "http-a", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			expectedListenersCount: 3,
			expectedAttachedLS:     2,
			expectedOwnerKinds:     []gatewayv1.Kind{"Gateway", "ListenerSet", "ListenerSet"},
		},
		{
			name: "Gateway with AllowedListeners Selector filters by namespace labels",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{
							From: &selectorFrom,
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
						},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			namespaces: map[string]*corev1.Namespace{
				"prod-ns": {
					ObjectMeta: metav1.ObjectMeta{Name: "prod-ns", Labels: map[string]string{"env": "prod"}},
				},
				"dev-ns": {
					ObjectMeta: metav1.ObjectMeta{Name: "dev-ns", Labels: map[string]string{"env": "dev"}},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-prod", Namespace: "prod-ns"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "prod-http", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-dev", Namespace: "dev-ns"},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "dev-http", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
						},
					},
				},
			},
			expectedListenersCount: 2,
			expectedAttachedLS:     1,
			expectedOwnerKinds:     []gatewayv1.Kind{"Gateway", "ListenerSet"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled := CompileModel(ModelInputs{
				Gateways:     []*gatewayv1.Gateway{tt.gateway},
				ListenerSets: tt.listenerSets,
				Namespaces:   tt.namespaces,
			})

			gwKey := types.NamespacedName{Namespace: tt.gateway.Namespace, Name: tt.gateway.Name}
			cg := compiled.Gateways[gwKey]
			if cg == nil {
				t.Fatalf("expected compiled gateway for %v, got nil", gwKey)
			}

			if len(cg.EffectiveListeners) != tt.expectedListenersCount {
				t.Errorf("EffectiveListeners count = %d, want %d", len(cg.EffectiveListeners), tt.expectedListenersCount)
			}
			if cg.AttachedListenerSets != tt.expectedAttachedLS {
				t.Errorf("AttachedListenerSets = %d, want %d", cg.AttachedListenerSets, tt.expectedAttachedLS)
			}

			for i, el := range cg.EffectiveListeners {
				if i < len(tt.expectedOwnerKinds) && el.Owner.Kind != tt.expectedOwnerKinds[i] {
					t.Errorf("listener %d Owner.Kind = %s, want %s", i, el.Owner.Kind, tt.expectedOwnerKinds[i])
				}
			}
		})
	}
}

func TestCompileModel_RouteBinding(t *testing.T) {
	allFrom := gatewayv1.NamespacesFromAll
	sameFrom := gatewayv1.NamespacesFromSame
	selectorFrom := gatewayv1.NamespacesFromSelector

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-80",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
				},
				{
					Name:     "http-8080",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
				},
				{
					Name:     "http-same-ns",
					Port:     8081,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{From: &sameFrom},
					},
				},
				{
					Name:     "http-selector-ns",
					Port:     8082,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: &selectorFrom,
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"team": "frontend"},
							},
						},
					},
				},
				{
					Name:     "tcp-9000",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls-app", Namespace: "app-ns"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default"))},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "ls-http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("app.example.com")),
				},
			},
		},
	}

	namespaces := map[string]*corev1.Namespace{
		"default": {
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		},
		"app-ns": {
			ObjectMeta: metav1.ObjectMeta{Name: "app-ns", Labels: map[string]string{"team": "frontend"}},
		},
		"other-ns": {
			ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Labels: map[string]string{"team": "backend"}},
		},
	}

	tests := []struct {
		name               string
		route              *gatewayv1.HTTPRoute
		expectedStatus     metav1.ConditionStatus
		expectedReason     string
		expectedBoundCount int
	}{
		{
			name: "Route binds to Gateway listener with matching hostname",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw"},
						},
					},
					Hostnames: []gatewayv1.Hostname{"example.com"},
				},
			},
			expectedStatus:     metav1.ConditionTrue,
			expectedReason:     string(gatewayv1.RouteReasonAccepted),
			expectedBoundCount: 1,
		},
		{
			name: "Route binds to Gateway listener by SectionName",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", SectionName: Ptr(gatewayv1.SectionName("http-8080"))},
						},
					},
					Hostnames: []gatewayv1.Hostname{"api.example.com"},
				},
			},
			expectedStatus:     metav1.ConditionTrue,
			expectedReason:     string(gatewayv1.RouteReasonAccepted),
			expectedBoundCount: 1,
		},
		{
			name: "Route fails with NoMatchingParent when SectionName does not exist",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r3", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", SectionName: Ptr(gatewayv1.SectionName("non-existent"))},
						},
					},
				},
			},
			expectedStatus:     metav1.ConditionFalse,
			expectedReason:     string(gatewayv1.RouteReasonNoMatchingParent),
			expectedBoundCount: 0,
		},
		{
			name: "Route fails with NoMatchingListenerHostname when hostnames are disjoint",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r4", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", SectionName: Ptr(gatewayv1.SectionName("http-80"))},
						},
					},
					Hostnames: []gatewayv1.Hostname{"otherdomain.org"},
				},
			},
			expectedStatus:     metav1.ConditionFalse,
			expectedReason:     string(gatewayv1.RouteReasonNoMatchingListenerHostname),
			expectedBoundCount: 0,
		},
		{
			name: "Route fails with NotAllowedByListeners for incompatible listener protocol",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r5", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", SectionName: Ptr(gatewayv1.SectionName("tcp-9000"))},
						},
					},
				},
			},
			expectedStatus:     metav1.ConditionFalse,
			expectedReason:     string(gatewayv1.RouteReasonNotAllowedByListeners),
			expectedBoundCount: 0,
		},
		{
			name: "Route in other namespace fails AllowedRoutes Same check",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r6", Namespace: "other-ns"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default")), SectionName: Ptr(gatewayv1.SectionName("http-same-ns"))},
						},
					},
				},
			},
			expectedStatus:     metav1.ConditionFalse,
			expectedReason:     string(gatewayv1.RouteReasonNotAllowedByListeners),
			expectedBoundCount: 0,
		},
		{
			name: "Route in matching namespace passes AllowedRoutes Selector check",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r7", Namespace: "app-ns"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("default")), SectionName: Ptr(gatewayv1.SectionName("http-selector-ns"))},
						},
					},
				},
			},
			expectedStatus:     metav1.ConditionTrue,
			expectedReason:     string(gatewayv1.RouteReasonAccepted),
			expectedBoundCount: 1,
		},
		{
			name: "Route binds to ListenerSet parentRef",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r8", Namespace: "app-ns"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
								Kind:  Ptr(gatewayv1.Kind("ListenerSet")),
								Name:  "ls-app",
							},
						},
					},
					Hostnames: []gatewayv1.Hostname{"app.example.com"},
				},
			},
			expectedStatus:     metav1.ConditionTrue,
			expectedReason:     string(gatewayv1.RouteReasonAccepted),
			expectedBoundCount: 1,
		},
		{
			name: "Route fails when ListenerSet parentRef does not exist",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "r9", Namespace: "app-ns"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
								Kind:  Ptr(gatewayv1.Kind("ListenerSet")),
								Name:  "non-existent-ls",
							},
						},
					},
				},
			},
			expectedStatus:     metav1.ConditionFalse,
			expectedReason:     string(gatewayv1.RouteReasonNoMatchingParent),
			expectedBoundCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled := CompileModel(ModelInputs{
				Gateways:     []*gatewayv1.Gateway{gw},
				ListenerSets: []*gatewayv1.ListenerSet{ls},
				HTTPRoutes:   []*gatewayv1.HTTPRoute{tt.route},
				Namespaces:   namespaces,
			})

			rKey := types.NamespacedName{Namespace: tt.route.Namespace, Name: tt.route.Name}
			cRoute := compiled.HTTPRoutes[rKey]
			if cRoute == nil {
				t.Fatalf("expected compiled route for %v, got nil", rKey)
			}

			if len(cRoute.ParentConditions) == 0 {
				t.Fatalf("expected at least 1 parent condition, got 0")
			}

			cond := cRoute.ParentConditions[0]
			if cond.Status != tt.expectedStatus {
				t.Errorf("ParentCondition Status = %s, want %s (message: %s)", cond.Status, tt.expectedStatus, cond.Message)
			}
			if cond.Reason != tt.expectedReason {
				t.Errorf("ParentCondition Reason = %s, want %s", cond.Reason, tt.expectedReason)
			}
		})
	}
}

func TestExtractCertificates(t *testing.T) {
	certPEM1, keyPEM1 := generateTestCertPEM(t, "example.com")
	certPEM2, keyPEM2 := generateTestCertPEM(t, "app.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "gw-ns", Name: "gw-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns", Name: "gw-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM1,
				corev1.TLSPrivateKeyKey: keyPEM1,
			},
		},
		{Namespace: "ls-ns", Name: "ls-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "ls-ns", Name: "ls-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM2,
				corev1.TLSPrivateKeyKey: keyPEM2,
			},
		},
		{Namespace: "secret-ns", Name: "cross-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "secret-ns", Name: "cross-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM1,
				corev1.TLSPrivateKeyKey: keyPEM1,
			},
		},
	}

	allFrom := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https-gw",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "gw-cert"},
						},
					},
				},
				{
					Name:     "https-cross",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("cross.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Namespace: Ptr(gatewayv1.Namespace("secret-ns")),
								Name:      "cross-cert",
							},
						},
					},
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "ls-ns"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw", Namespace: Ptr(gatewayv1.Namespace("gw-ns"))},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https-ls",
					Port:     9443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("app.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "ls-cert"},
						},
					},
				},
			},
		},
	}

	st := NewState()
	// Allow cross-namespace Secret reference for Gateway
	st.UpsertReferenceGrant(&gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Namespace: "secret-ns", Name: "allow-gw"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Namespace: "gw-ns",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
					Name:  Ptr(gatewayv1.ObjectName("cross-cert")),
				},
			},
		},
	})

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		Secrets:      secrets,
		RefValidator: st,
	})

	certsMap, defaultCert := ExtractCertificates(compiled.GatewaysList())

	if certsMap["example.com"] == nil {
		t.Errorf("expected certificate for example.com")
	}
	if certsMap["app.example.com"] == nil {
		t.Errorf("expected certificate for app.example.com")
	}
	if certsMap["cross.example.com"] == nil {
		t.Errorf("expected certificate for cross.example.com permitted by ReferenceGrant")
	}
	if defaultCert == nil {
		t.Errorf("expected defaultCert to be set")
	}
}

func TestExtractCertificates_ListenerSetSANConflict(t *testing.T) {
	tests := []struct {
		name       string
		lsCertSANs []string
	}{
		{
			name:       "SAN includes exact hostname",
			lsCertSANs: []string{"b.example.com", "a.example.com"},
		},
		{
			name:       "wildcard SAN on ListenerSet certificate",
			lsCertSANs: []string{"b.example.com", "*.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEMA, keyPEMA := generateTestCertPEM(t, "a.example.com")
			certPEMB, keyPEMB := generateTestCertPEM(t, tt.lsCertSANs...)

			tlsCertA, err := tls.X509KeyPair(certPEMA, keyPEMA)
			if err != nil {
				t.Fatalf("failed to parse cert A: %v", err)
			}
			hA := sha256.Sum256(tlsCertA.Certificate[0])
			expectedGwCertID := hex.EncodeToString(hA[:])

			tlsCertB, err := tls.X509KeyPair(certPEMB, keyPEMB)
			if err != nil {
				t.Fatalf("failed to parse cert B: %v", err)
			}
			hB := sha256.Sum256(tlsCertB.Certificate[0])
			lsCertID := hex.EncodeToString(hB[:])

			if expectedGwCertID == lsCertID {
				t.Fatalf("expected different cert IDs for test")
			}

			secrets := map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "gw-cert"}: {
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-cert"},
					Data: map[string][]byte{
						corev1.TLSCertKey:       certPEMA,
						corev1.TLSPrivateKeyKey: keyPEMA,
					},
				},
				{Namespace: "default", Name: "ls-cert"}: {
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ls-cert"},
					Data: map[string][]byte{
						corev1.TLSCertKey:       certPEMB,
						corev1.TLSPrivateKeyKey: keyPEMB,
					},
				},
			}

			allFrom := gatewayv1.NamespacesFromAll
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
					},
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https-gw",
							Port:     443,
							Protocol: gatewayv1.HTTPSProtocolType,
							Hostname: Ptr(gatewayv1.Hostname("a.example.com")),
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{Name: "gw-cert"},
								},
							},
						},
					},
				},
			}

			ls := &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
					Listeners: []gatewayv1.ListenerEntry{
						{
							Name:     "https-ls",
							Port:     8443,
							Protocol: gatewayv1.HTTPSProtocolType,
							Hostname: Ptr(gatewayv1.Hostname("b.example.com")),
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{Name: "ls-cert"},
								},
							},
						},
					},
				},
			}

			compiled := CompileModel(ModelInputs{
				Gateways:     []*gatewayv1.Gateway{gw},
				ListenerSets: []*gatewayv1.ListenerSet{ls},
				Secrets:      secrets,
			})

			cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw"}]
			if cg == nil {
				t.Fatalf("expected compiled gateway")
			}

			dpCfg, err := BuildGatewayDataplaneConfig(cg)
			if err != nil {
				t.Fatalf("BuildGatewayDataplaneConfig failed: %v", err)
			}

			if got := dpCfg.HostCertificates["a.example.com"]; got != expectedGwCertID {
				t.Errorf("HostCertificates[a.example.com] = %q, want Gateway cert ID %q", got, expectedGwCertID)
			}
			if _, ok := dpCfg.HostCertificates["*.example.com"]; ok {
				t.Errorf("did not expect *.example.com in HostCertificates from ListenerSet serving b.example.com")
			}
		})
	}
}

func TestExtractCertificates_ExplicitHostnameBeatsSANFromOtherListener(t *testing.T) {
	certPEMCatchAll, keyPEMCatchAll := generateTestCertPEM(t, "catchall.example.com", "b.example.com")
	certPEMB, keyPEMB := generateTestCertPEM(t, "b.example.com")

	tlsCertB, err := tls.X509KeyPair(certPEMB, keyPEMB)
	if err != nil {
		t.Fatalf("failed to parse cert B: %v", err)
	}
	hB := sha256.Sum256(tlsCertB.Certificate[0])
	expectedCertBID := hex.EncodeToString(hB[:])

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "catchall-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "catchall-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEMCatchAll,
				corev1.TLSPrivateKeyKey: keyPEMCatchAll,
			},
		},
		{Namespace: "default", Name: "b-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "b-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEMB,
				corev1.TLSPrivateKeyKey: keyPEMB,
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https-catchall",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					// Hostname is nil (hostname-less listener first)
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "catchall-cert"},
						},
					},
				},
				{
					Name:     "https-b",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("b.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "b-cert"},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways: []*gatewayv1.Gateway{gw},
		Secrets:  secrets,
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw"}]
	if cg == nil {
		t.Fatalf("expected compiled gateway")
	}

	dpCfg, err := BuildGatewayDataplaneConfig(cg)
	if err != nil {
		t.Fatalf("BuildGatewayDataplaneConfig failed: %v", err)
	}

	if got := dpCfg.HostCertificates["b.example.com"]; got != expectedCertBID {
		t.Errorf("HostCertificates[b.example.com] = %q, want explicit listener cert ID %q", got, expectedCertBID)
	}
}

func TestCompileModel_AttachedRoutesCount(t *testing.T) {
	allFrom := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "http-ls",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	r1 := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
				},
			},
		},
	}

	r2 := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
					// Duplicate parentRef to same gateway
					{Name: "gw", SectionName: Ptr(gatewayv1.SectionName("http"))},
				},
			},
		},
	}

	r3 := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r3", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
						Kind:  Ptr(gatewayv1.Kind("ListenerSet")),
						Name:  "ls",
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		HTTPRoutes:   []*gatewayv1.HTTPRoute{r1, r2, r3},
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw"}]
	if cg == nil {
		t.Fatalf("expected compiled gateway, got nil")
	}

	var gwEl *EffectiveListener
	var lsEl *EffectiveListener
	for _, el := range cg.EffectiveListeners {
		if el.Owner.Kind == "Gateway" && el.Name == "http" {
			gwEl = el
		}
		if el.Owner.Kind == "ListenerSet" && el.Name == "http-ls" {
			lsEl = el
		}
	}

	if gwEl == nil || gwEl.AttachedRoutes != 2 {
		t.Errorf("expected 2 attached routes on gw listener, got %v", gwEl)
	}
	if lsEl == nil || lsEl.AttachedRoutes != 1 {
		t.Errorf("expected 1 attached route on ls listener, got %v", lsEl)
	}
}

func TestCompileModel_AttachedRoutes_TableDriven(t *testing.T) {
	tests := []struct {
		name                   string
		gateway                *gatewayv1.Gateway
		secrets                map[types.NamespacedName]*corev1.Secret
		routes                 []*gatewayv1.HTTPRoute
		expectedAttachedRoutes map[gatewayv1.SectionName]int32
		expectedRouteReason    map[string]gatewayv1.RouteConditionReason
	}{
		{
			name: "route with non-intersecting hostnames is not counted and reports NoMatchingListenerHostname",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
							Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
						},
					},
				},
			},
			routes: []*gatewayv1.HTTPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-mismatched", Namespace: "default"},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{
								{Name: "gw"},
							},
						},
						Hostnames: []gatewayv1.Hostname{"not-accepted.test.com"},
					},
				},
			},
			expectedAttachedRoutes: map[gatewayv1.SectionName]int32{
				"http": 0,
			},
			expectedRouteReason: map[string]gatewayv1.RouteConditionReason{
				"route-mismatched": gatewayv1.RouteReasonNoMatchingListenerHostname,
			},
		},
		{
			name: "unresolved certificateRef still reports attachedRoutes",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "unresolved-gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							Name:     "tls",
							Port:     443,
							Protocol: gatewayv1.HTTPSProtocolType,
							TLS: &gatewayv1.ListenerTLSConfig{
								Mode: Ptr(gatewayv1.TLSModeTerminate),
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{Name: "missing-cert"},
								},
							},
						},
					},
				},
			},
			routes: []*gatewayv1.HTTPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-tls", Namespace: "default"},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{
								{Name: "unresolved-gw", SectionName: Ptr(gatewayv1.SectionName("tls"))},
							},
						},
					},
				},
			},
			expectedAttachedRoutes: map[gatewayv1.SectionName]int32{
				"tls": 1,
			},
			expectedRouteReason: map[string]gatewayv1.RouteConditionReason{
				"route-tls": gatewayv1.RouteReasonAccepted,
			},
		},
		{
			name: "route with sectionName is counted only on the named listener",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-listener-gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					Listeners: []gatewayv1.Listener{
						{
							Name:     "http-unattached",
							Port:     8080,
							Protocol: gatewayv1.HTTPProtocolType,
						},
						{
							Name:     "http",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
						},
					},
				},
			},
			routes: []*gatewayv1.HTTPRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-section", Namespace: "default"},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{
								{Name: "multi-listener-gw", SectionName: Ptr(gatewayv1.SectionName("http"))},
							},
						},
					},
				},
			},
			expectedAttachedRoutes: map[gatewayv1.SectionName]int32{
				"http-unattached": 0,
				"http":            1,
			},
			expectedRouteReason: map[string]gatewayv1.RouteConditionReason{
				"route-section": gatewayv1.RouteReasonAccepted,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiled := CompileModel(ModelInputs{
				Gateways:   []*gatewayv1.Gateway{tc.gateway},
				HTTPRoutes: tc.routes,
				Secrets:    tc.secrets,
			})

			gwKey := types.NamespacedName{Namespace: tc.gateway.Namespace, Name: tc.gateway.Name}
			cg := compiled.Gateways[gwKey]
			if cg == nil {
				t.Fatalf("compiled gateway not found")
			}

			// Verify EffectiveListeners
			for sectionName, expectedCount := range tc.expectedAttachedRoutes {
				var matchedEl *EffectiveListener
				for _, el := range cg.EffectiveListeners {
					if el.Owner.Kind == "Gateway" && el.Name == sectionName {
						matchedEl = el
						break
					}
				}
				if matchedEl == nil {
					t.Fatalf("listener %q not found in effective listeners", sectionName)
				}
				if matchedEl.AttachedRoutes != expectedCount {
					t.Errorf("listener %q: expected AttachedRoutes = %d, got %d", sectionName, expectedCount, matchedEl.AttachedRoutes)
				}
			}

			// Verify GatewayStatus
			gwStatus := ComputeDesiredGatewayStatus(tc.gateway, cg, nil, GatewayReadiness{Ready: false}, "", nil)
			for _, ls := range gwStatus.Listeners {
				if expectedCount, ok := tc.expectedAttachedRoutes[ls.Name]; ok {
					if ls.AttachedRoutes != expectedCount {
						t.Errorf("gateway status listener %q: expected AttachedRoutes = %d, got %d", ls.Name, expectedCount, ls.AttachedRoutes)
					}
				}
			}

			// Verify route parent condition reasons
			for _, route := range tc.routes {
				routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
				cr := compiled.HTTPRoutes[routeKey]
				if cr == nil {
					t.Fatalf("compiled route %q not found", route.Name)
				}
				routeStatus := ComputeDesiredHTTPRouteStatus(route, cr, "example.net/gateway-controller")
				if len(routeStatus.Parents) == 0 {
					t.Fatalf("route %q has no parent statuses", route.Name)
				}
				expectedReason := tc.expectedRouteReason[route.Name]
				var acceptedCond *metav1.Condition
				for i := range routeStatus.Parents[0].Conditions {
					if routeStatus.Parents[0].Conditions[i].Type == string(gatewayv1.RouteConditionAccepted) {
						acceptedCond = &routeStatus.Parents[0].Conditions[i]
						break
					}
				}
				if acceptedCond == nil {
					t.Fatalf("route %q has no Accepted condition", route.Name)
				}
				if acceptedCond.Reason != string(expectedReason) {
					t.Errorf("route %q: expected Accepted reason %q, got %q", route.Name, expectedReason, acceptedCond.Reason)
				}
			}
		})
	}
}

func TestStatusComputation_PureFunctions(t *testing.T) {
	sameFrom := gatewayv1.NamespacesFromSame
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default", Generation: 1},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &sameFrom},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default", Generation: 1},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{Name: "http-ls", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default", Generation: 1},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
					{
						Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
						Kind:  Ptr(gatewayv1.Kind("ListenerSet")),
						Name:  "ls",
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		HTTPRoutes:   []*gatewayv1.HTTPRoute{route},
		Namespaces:   map[string]*corev1.Namespace{"default": {ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
	})

	// 1. Gateway Status
	addresses := []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}}
	gwStatus := ComputeDesiredGatewayStatus(gw, compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw"}], addresses, GatewayReadiness{Ready: true}, "", nil)
	if len(gwStatus.Conditions) != 3 {
		t.Errorf("expected 3 Gateway conditions, got %d", len(gwStatus.Conditions))
	}
	if len(gwStatus.Addresses) != 1 || gwStatus.Addresses[0].Value != "192.0.2.1" {
		t.Errorf("expected Gateway address 192.0.2.1, got %v", gwStatus.Addresses)
	}
	if gwStatus.AttachedListenerSets == nil || *gwStatus.AttachedListenerSets != 1 {
		t.Errorf("expected AttachedListenerSets = 1, got %v", gwStatus.AttachedListenerSets)
	}
	if len(gwStatus.Listeners) != 1 || gwStatus.Listeners[0].AttachedRoutes != 1 {
		t.Errorf("expected 1 attached route on Gateway listener status, got %v", gwStatus.Listeners)
	}

	// 2. ListenerSet Status
	lsStatus := ComputeDesiredListenerSetStatus(ls, gw, nil, compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw"}])
	if len(lsStatus.Conditions) != 2 {
		t.Errorf("expected 2 ListenerSet conditions, got %d", len(lsStatus.Conditions))
	}
	if len(lsStatus.Listeners) != 1 || lsStatus.Listeners[0].AttachedRoutes != 1 {
		t.Errorf("expected 1 attached route on ListenerSet listener status, got %v", lsStatus.Listeners)
	}

	// 3. HTTPRoute Status
	routeStatus := ComputeDesiredHTTPRouteStatus(route, compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "r1"}], "example.net/gateway-controller")
	if len(routeStatus.Parents) != 2 {
		t.Fatalf("expected 2 parent statuses on route, got %d", len(routeStatus.Parents))
	}
	for i, p := range routeStatus.Parents {
		if len(p.Conditions) != 2 {
			t.Errorf("parent %d expected 2 conditions, got %d", i, len(p.Conditions))
		}
	}
}

func TestValidateListener_CertificateRefGroup(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t, "example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "my-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	coreGroup := gatewayv1.Group("core")
	emptyGroup := gatewayv1.Group("")
	customGroup := gatewayv1.Group("example.com")

	tests := []struct {
		name               string
		group              *gatewayv1.Group
		kind               *gatewayv1.Kind
		expectProgrammed   metav1.ConditionStatus
		expectResolvedRefs metav1.ConditionStatus
		expectReason       string
	}{
		{
			name:               "nil group accepted",
			group:              nil,
			kind:               Ptr(gatewayv1.Kind("Secret")),
			expectProgrammed:   metav1.ConditionTrue,
			expectResolvedRefs: metav1.ConditionTrue,
			expectReason:       string(gatewayv1.ListenerReasonResolvedRefs),
		},
		{
			name:               "empty group accepted",
			group:              &emptyGroup,
			kind:               Ptr(gatewayv1.Kind("Secret")),
			expectProgrammed:   metav1.ConditionTrue,
			expectResolvedRefs: metav1.ConditionTrue,
			expectReason:       string(gatewayv1.ListenerReasonResolvedRefs),
		},
		{
			name:               "core group rejected",
			group:              &coreGroup,
			kind:               Ptr(gatewayv1.Kind("Secret")),
			expectProgrammed:   metav1.ConditionFalse,
			expectResolvedRefs: metav1.ConditionFalse,
			expectReason:       string(gatewayv1.ListenerReasonInvalidCertificateRef),
		},
		{
			name:               "custom group rejected",
			group:              &customGroup,
			kind:               Ptr(gatewayv1.Kind("Secret")),
			expectProgrammed:   metav1.ConditionFalse,
			expectResolvedRefs: metav1.ConditionFalse,
			expectReason:       string(gatewayv1.ListenerReasonInvalidCertificateRef),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener := gatewayv1.Listener{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{
					CertificateRefs: []gatewayv1.SecretObjectReference{
						{
							Group: tc.group,
							Kind:  tc.kind,
							Name:  "my-secret",
						},
					},
				},
			}

			validationResult := ValidateListener(
				ListenerToSpec(listener),
				ListenerOwner{Kind: "Gateway", Namespace: "default", Name: "gw"},
				&gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"}},
				1,
				secrets,
				nil,
				nil,
				nil,
				nil,
			)

			var progCond, resCond *metav1.Condition
			for i := range validationResult.Conditions {
				if validationResult.Conditions[i].Type == string(gatewayv1.ListenerConditionProgrammed) {
					progCond = &validationResult.Conditions[i]
				}
				if validationResult.Conditions[i].Type == string(gatewayv1.ListenerConditionResolvedRefs) {
					resCond = &validationResult.Conditions[i]
				}
			}

			if progCond == nil || progCond.Status != tc.expectProgrammed {
				t.Errorf("expected Programmed condition %v, got %v", tc.expectProgrammed, progCond)
			}
			if resCond == nil || resCond.Status != tc.expectResolvedRefs {
				t.Errorf("expected ResolvedRefs condition %v, got %v", tc.expectResolvedRefs, resCond)
			}
			if resCond != nil && resCond.Reason != tc.expectReason {
				t.Errorf("expected ResolvedRefs reason %q, got %q", tc.expectReason, resCond.Reason)
			}
		})
	}
}

func TestCompileModel_PrecedenceAndConflicts(t *testing.T) {
	sameFrom := gatewayv1.NamespacesFromSame
	allFrom := gatewayv1.NamespacesFromAll
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(10 * time.Minute)
	t2 := t0.Add(20 * time.Minute)

	tests := []struct {
		name                 string
		gateway              *gatewayv1.Gateway
		listenerSets         []*gatewayv1.ListenerSet
		expectedAttachedLS   int32
		expectedConflicted   map[string]gatewayv1.ListenerConditionReason
		expectedUnconflicted []string
		expectedLSStatus     map[string]metav1.ConditionStatus
		expectedLSReason     map[string]string
	}{
		{
			name: "Hostname conflict: Gateway listener wins over ListenerSet listener",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &sameFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "gw-http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("example.com"))},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls1", Namespace: "default", CreationTimestamp: metav1.NewTime(t0)},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "ls-conflict", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("example.com"))},
						},
					},
				},
			},
			expectedAttachedLS: 0,
			expectedConflicted: map[string]gatewayv1.ListenerConditionReason{
				"default/ls1/ls-conflict": gatewayv1.ListenerReasonHostnameConflict,
			},
			expectedUnconflicted: []string{"gw-http"},
			expectedLSStatus: map[string]metav1.ConditionStatus{
				"ls1": metav1.ConditionFalse,
			},
			expectedLSReason: map[string]string{
				"ls1": string(gatewayv1.ListenerSetReasonListenersNotValid),
			},
		},
		{
			name: "Protocol conflict: Gateway HTTP wins over ListenerSet TCP on port 80",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &sameFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "gw-http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls1", Namespace: "default", CreationTimestamp: metav1.NewTime(t0)},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "ls-tcp", Port: 80, Protocol: gatewayv1.TCPProtocolType},
						},
					},
				},
			},
			expectedAttachedLS: 0,
			expectedConflicted: map[string]gatewayv1.ListenerConditionReason{
				"default/ls1/ls-tcp": gatewayv1.ListenerReasonProtocolConflict,
			},
			expectedUnconflicted: []string{"gw-http"},
			expectedLSStatus: map[string]metav1.ConditionStatus{
				"ls1": metav1.ConditionFalse,
			},
			expectedLSReason: map[string]string{
				"ls1": string(gatewayv1.ListenerSetReasonListenersNotValid),
			},
		},
		{
			name: "Precedence by CreationTimestamp: older ListenerSet wins hostname conflict over younger",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "gw-other", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-younger", Namespace: "default", CreationTimestamp: metav1.NewTime(t2)},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("app.io"))},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-older", Namespace: "default", CreationTimestamp: metav1.NewTime(t1)},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("app.io"))},
						},
					},
				},
			},
			expectedAttachedLS: 1,
			expectedConflicted: map[string]gatewayv1.ListenerConditionReason{
				"default/ls-younger/http": gatewayv1.ListenerReasonHostnameConflict,
			},
			expectedUnconflicted: []string{"gw-other", "default/ls-older/http"},
			expectedLSStatus: map[string]metav1.ConditionStatus{
				"ls-older":   metav1.ConditionTrue,
				"ls-younger": metav1.ConditionFalse,
			},
			expectedLSReason: map[string]string{
				"ls-older":   string(gatewayv1.ListenerSetReasonAccepted),
				"ls-younger": string(gatewayv1.ListenerSetReasonListenersNotValid),
			},
		},
		{
			name: "Partial vs full conflict: ListenerSet with one valid listener stays Accepted=True",
			gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					AllowedListeners: &gatewayv1.AllowedListeners{
						Namespaces: &gatewayv1.ListenerNamespaces{From: &sameFrom},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "gw-http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("gw.io"))},
					},
				},
			},
			listenerSets: []*gatewayv1.ListenerSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ls-mixed", Namespace: "default", CreationTimestamp: metav1.NewTime(t0)},
					Spec: gatewayv1.ListenerSetSpec{
						ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
						Listeners: []gatewayv1.ListenerEntry{
							{Name: "conflicted-http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("gw.io"))},
							{Name: "valid-http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: Ptr(gatewayv1.Hostname("valid.io"))},
						},
					},
				},
			},
			expectedAttachedLS: 1,
			expectedConflicted: map[string]gatewayv1.ListenerConditionReason{
				"default/ls-mixed/conflicted-http": gatewayv1.ListenerReasonHostnameConflict,
			},
			expectedUnconflicted: []string{"gw-http", "default/ls-mixed/valid-http"},
			expectedLSStatus: map[string]metav1.ConditionStatus{
				"ls-mixed": metav1.ConditionTrue,
			},
			expectedLSReason: map[string]string{
				"ls-mixed": string(gatewayv1.ListenerSetReasonAccepted),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiled := CompileModel(ModelInputs{
				Gateways:     []*gatewayv1.Gateway{tc.gateway},
				ListenerSets: tc.listenerSets,
				Namespaces:   map[string]*corev1.Namespace{"default": {ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
			})

			gwKey := types.NamespacedName{Namespace: tc.gateway.Namespace, Name: tc.gateway.Name}
			cg := compiled.Gateways[gwKey]
			if cg == nil {
				t.Fatalf("compiled gateway not found")
			}

			if cg.AttachedListenerSets != tc.expectedAttachedLS {
				t.Errorf("expected AttachedListenerSets = %d, got %d", tc.expectedAttachedLS, cg.AttachedListenerSets)
			}

			// Check listeners
			for _, el := range cg.EffectiveListeners {
				qName := el.QualifiedName()
				expectedReason, shouldBeConflicted := tc.expectedConflicted[qName]
				if shouldBeConflicted {
					if !el.IsConflicted() {
						t.Errorf("listener %s expected to be conflicted", qName)
					}
					var confCond, accCond, progCond *metav1.Condition
					for i := range el.Conditions {
						if el.Conditions[i].Type == string(gatewayv1.ListenerConditionConflicted) {
							confCond = &el.Conditions[i]
						}
						if el.Conditions[i].Type == string(gatewayv1.ListenerConditionAccepted) {
							accCond = &el.Conditions[i]
						}
						if el.Conditions[i].Type == string(gatewayv1.ListenerConditionProgrammed) {
							progCond = &el.Conditions[i]
						}
					}
					if confCond == nil || confCond.Status != metav1.ConditionTrue || confCond.Reason != string(expectedReason) {
						t.Errorf("listener %s expected Conflicted=True reason %s, got %v", qName, expectedReason, confCond)
					}
					if accCond == nil || accCond.Status != metav1.ConditionFalse || accCond.Reason != string(expectedReason) {
						t.Errorf("listener %s expected Accepted=False reason %s, got %v", qName, expectedReason, accCond)
					}
					if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(expectedReason) {
						t.Errorf("listener %s expected Programmed=False reason %s, got %v", qName, expectedReason, progCond)
					}
				}
			}

			for _, unconf := range tc.expectedUnconflicted {
				var found *EffectiveListener
				for _, el := range cg.EffectiveListeners {
					if el.QualifiedName() == unconf {
						found = el
						break
					}
				}
				if found == nil {
					t.Fatalf("unconflicted listener %s not found in effective listeners", unconf)
				}
				if found.IsConflicted() {
					t.Errorf("listener %s expected to NOT be conflicted, but is", unconf)
				}
				if !found.IsAccepted() {
					t.Errorf("listener %s expected to be accepted, but is not", unconf)
				}
			}

			// Check ListenerSet desired status
			for _, ls := range tc.listenerSets {
				lsStatus := ComputeDesiredListenerSetStatus(ls, tc.gateway, map[string]*corev1.Namespace{"default": {ObjectMeta: metav1.ObjectMeta{Name: "default"}}}, cg)
				expectedStatus, ok := tc.expectedLSStatus[ls.Name]
				if ok {
					var accCond *metav1.Condition
					for i := range lsStatus.Conditions {
						if lsStatus.Conditions[i].Type == string(gatewayv1.ListenerSetConditionAccepted) {
							accCond = &lsStatus.Conditions[i]
						}
					}
					if accCond == nil || accCond.Status != expectedStatus {
						t.Errorf("ListenerSet %s expected Accepted=%v, got %v", ls.Name, expectedStatus, accCond)
					}
					if expectedReason, ok := tc.expectedLSReason[ls.Name]; ok {
						if accCond != nil && accCond.Reason != expectedReason {
							t.Errorf("ListenerSet %s expected Reason=%s, got %s", ls.Name, expectedReason, accCond.Reason)
						}
					}
				}
			}
		})
	}
}

func TestCompileModel_ListenerSetReferenceGrant(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t, "cross-ns.example.com")
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "secret-ns", Name: "my-secret"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "secret-ns", Name: "my-secret"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		},
	}

	stWithGrant := NewState()
	stWithGrant.UpsertReferenceGrant(&gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: "secret-ns"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "ListenerSet",
					Namespace: "ls-ns",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
					Name:  Ptr(gatewayv1.ObjectName("my-secret")),
				},
			},
		},
	})

	allFrom := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &allFrom},
			},
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls-tls", Namespace: "ls-ns"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name:      "gw",
				Namespace: Ptr(gatewayv1.Namespace("gw-ns")),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Namespace: Ptr(gatewayv1.Namespace("secret-ns")),
								Name:      "my-secret",
							},
						},
					},
				},
			},
		},
	}

	namespaces := map[string]*corev1.Namespace{
		"gw-ns":     {ObjectMeta: metav1.ObjectMeta{Name: "gw-ns"}},
		"ls-ns":     {ObjectMeta: metav1.ObjectMeta{Name: "ls-ns"}},
		"secret-ns": {ObjectMeta: metav1.ObjectMeta{Name: "secret-ns"}},
	}

	t.Run("Without ReferenceGrant", func(t *testing.T) {
		compiled := CompileModel(ModelInputs{
			Gateways:     []*gatewayv1.Gateway{gw},
			ListenerSets: []*gatewayv1.ListenerSet{ls},
			Secrets:      secrets,
			Namespaces:   namespaces,
			RefValidator: NewState(), // empty validator
		})

		cg := compiled.Gateways[types.NamespacedName{Namespace: "gw-ns", Name: "gw"}]
		if cg == nil {
			t.Fatalf("compiled gateway not found")
		}
		if cg.AttachedListenerSets != 0 {
			t.Errorf("expected AttachedListenerSets = 0 without grant, got %d", cg.AttachedListenerSets)
		}

		lsStatus := ComputeDesiredListenerSetStatus(ls, gw, namespaces, cg)
		var accCond, progCond *metav1.Condition
		for i := range lsStatus.Conditions {
			if lsStatus.Conditions[i].Type == string(gatewayv1.ListenerSetConditionAccepted) {
				accCond = &lsStatus.Conditions[i]
			}
			if lsStatus.Conditions[i].Type == string(gatewayv1.ListenerSetConditionProgrammed) {
				progCond = &lsStatus.Conditions[i]
			}
		}
		if accCond == nil || accCond.Status != metav1.ConditionFalse || accCond.Reason != string(gatewayv1.ListenerSetReasonListenersNotValid) {
			t.Errorf("expected ListenerSet Accepted=False (ListenersNotValid), got %v", accCond)
		}
		if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerSetReasonListenersNotValid) {
			t.Errorf("expected ListenerSet Programmed=False (ListenersNotValid), got %v", progCond)
		}

		if len(lsStatus.Listeners) != 1 {
			t.Fatalf("expected 1 listener in ListenerSet status, got %d", len(lsStatus.Listeners))
		}
		var resCond *metav1.Condition
		for i := range lsStatus.Listeners[0].Conditions {
			if lsStatus.Listeners[0].Conditions[i].Type == string(gatewayv1.ListenerConditionResolvedRefs) {
				resCond = &lsStatus.Listeners[0].Conditions[i]
			}
		}
		if resCond == nil || resCond.Status != metav1.ConditionFalse || resCond.Reason != string(gatewayv1.ListenerReasonRefNotPermitted) {
			t.Errorf("expected listener ResolvedRefs=False (RefNotPermitted), got %v", resCond)
		}
	})

	t.Run("With ReferenceGrant", func(t *testing.T) {
		compiled := CompileModel(ModelInputs{
			Gateways:     []*gatewayv1.Gateway{gw},
			ListenerSets: []*gatewayv1.ListenerSet{ls},
			Secrets:      secrets,
			Namespaces:   namespaces,
			RefValidator: stWithGrant,
		})

		cg := compiled.Gateways[types.NamespacedName{Namespace: "gw-ns", Name: "gw"}]
		if cg == nil {
			t.Fatalf("compiled gateway not found")
		}
		if cg.AttachedListenerSets != 1 {
			t.Errorf("expected AttachedListenerSets = 1 with grant, got %d", cg.AttachedListenerSets)
		}

		lsStatus := ComputeDesiredListenerSetStatus(ls, gw, namespaces, cg)
		var accCond, progCond *metav1.Condition
		for i := range lsStatus.Conditions {
			if lsStatus.Conditions[i].Type == string(gatewayv1.ListenerSetConditionAccepted) {
				accCond = &lsStatus.Conditions[i]
			}
			if lsStatus.Conditions[i].Type == string(gatewayv1.ListenerSetConditionProgrammed) {
				progCond = &lsStatus.Conditions[i]
			}
		}
		if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerSetReasonAccepted) {
			t.Errorf("expected ListenerSet Accepted=True (Accepted), got %v", accCond)
		}
		if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerSetReasonProgrammed) {
			t.Errorf("expected ListenerSet Programmed=True (Programmed), got %v", progCond)
		}

		if len(lsStatus.Listeners) != 1 {
			t.Fatalf("expected 1 listener in ListenerSet status, got %d", len(lsStatus.Listeners))
		}
		var resCond *metav1.Condition
		for i := range lsStatus.Listeners[0].Conditions {
			if lsStatus.Listeners[0].Conditions[i].Type == string(gatewayv1.ListenerConditionResolvedRefs) {
				resCond = &lsStatus.Listeners[0].Conditions[i]
			}
		}
		if resCond == nil || resCond.Status != metav1.ConditionTrue || resCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
			t.Errorf("expected listener ResolvedRefs=True (ResolvedRefs), got %v", resCond)
		}
	})
}

func TestCompileModel_GatewayUnresolvedCertRouteAttachment(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "nonexistent-secret",
							},
						},
					},
				},
			},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "gw",
					},
				},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "svc",
									Port: Ptr(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:   []*gatewayv1.Gateway{gw},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
		Services: map[types.NamespacedName]*corev1.Service{
			{Namespace: "default", Name: "svc"}: {ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "svc"}},
		},
		Secrets: map[types.NamespacedName]*corev1.Secret{}, // secret is missing
	})

	gwKey := types.NamespacedName{Namespace: "default", Name: "gw"}
	cg := compiled.Gateways[gwKey]
	if cg == nil {
		t.Fatalf("compiled gateway not found")
	}

	// Gateway should remain Accepted=True
	var gwAccCond *metav1.Condition
	for i := range cg.Conditions {
		if cg.Conditions[i].Type == string(gatewayv1.GatewayConditionAccepted) {
			gwAccCond = &cg.Conditions[i]
		}
	}
	if gwAccCond == nil || gwAccCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Gateway Accepted=True, got %v", gwAccCond)
	}

	// Listener should have ResolvedRefs=False, but AttachedRoutes=1
	if len(cg.EffectiveListeners) != 1 {
		t.Fatalf("expected 1 effective listener, got %d", len(cg.EffectiveListeners))
	}
	el := cg.EffectiveListeners[0]
	if el.AttachedRoutes != 1 {
		t.Errorf("expected listener AttachedRoutes=1, got %d", el.AttachedRoutes)
	}
	if !el.IsAccepted() {
		t.Errorf("expected listener IsAccepted()=true")
	}
	if el.IsProgrammed() {
		t.Errorf("expected listener IsProgrammed()=false (due to unresolved ref)")
	}

	// Route should be Accepted=True
	routeKey := types.NamespacedName{Namespace: "default", Name: "route"}
	cr := compiled.HTTPRoutes[routeKey]
	if cr == nil {
		t.Fatalf("compiled route not found")
	}
	routeStatus := ComputeDesiredHTTPRouteStatus(route, cr, "example.net/gateway-controller")
	if len(routeStatus.Parents) != 1 {
		t.Fatalf("expected 1 parent in route status, got %d", len(routeStatus.Parents))
	}
	var routeAccCond *metav1.Condition
	for i := range routeStatus.Parents[0].Conditions {
		if routeStatus.Parents[0].Conditions[i].Type == string(gatewayv1.RouteConditionAccepted) {
			routeAccCond = &routeStatus.Parents[0].Conditions[i]
		}
	}
	if routeAccCond == nil || routeAccCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Route Accepted=True, got %v", routeAccCond)
	}
}

func TestCompileModel_ListenerSetAllowedRoutesNamespaces(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromAll),
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "gw-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("gw.example.com")),
				},
			},
		},
	}

	rg := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "rg", Namespace: "gw-ns"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "ListenerSet",
					Namespace: "ls-ns",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: gatewayv1.GroupName,
					Kind:  "Gateway",
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "ls-ns"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name:      "gw",
				Namespace: Ptr(gatewayv1.Namespace("gw-ns")),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "listener-all",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("all.example.com")),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: Ptr(gatewayv1.NamespacesFromAll),
						},
					},
				},
				{
					Name:     "listener-same",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("same.example.com")),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: Ptr(gatewayv1.NamespacesFromSame),
						},
					},
				},
				{
					Name:     "listener-sel",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("sel.example.com")),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: Ptr(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"allowed": "yes"},
							},
						},
					},
				},
			},
		},
	}

	makeRoute := func(ns, name, sectionName, hostname string) *gatewayv1.HTTPRoute {
		r := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Kind:      Ptr(gatewayv1.Kind("ListenerSet")),
							Name:      "ls",
							Namespace: Ptr(gatewayv1.Namespace("ls-ns")),
						},
					},
				},
				Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(hostname)},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "svc",
										Port: Ptr(gatewayv1.PortNumber(8080)),
									},
								},
							},
						},
					},
				},
			},
		}
		if sectionName != "" {
			r.Spec.ParentRefs[0].SectionName = Ptr(gatewayv1.SectionName(sectionName))
		}
		return r
	}

	routeInLSNS := makeRoute("ls-ns", "route-same-ns", "listener-same", "same.example.com")
	routeInGWNS := makeRoute("gw-ns", "route-gw-ns", "listener-same", "same.example.com")
	routeInSelNS := makeRoute("sel-ns", "route-sel-ns", "listener-sel", "sel.example.com")
	routeInOtherNS := makeRoute("other-ns", "route-other-ns", "listener-sel", "sel.example.com")

	namespaces := map[string]*corev1.Namespace{
		"gw-ns":    {ObjectMeta: metav1.ObjectMeta{Name: "gw-ns"}},
		"ls-ns":    {ObjectMeta: metav1.ObjectMeta{Name: "ls-ns"}},
		"sel-ns":   {ObjectMeta: metav1.ObjectMeta{Name: "sel-ns", Labels: map[string]string{"allowed": "yes"}}},
		"other-ns": {ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Labels: map[string]string{"allowed": "no"}}},
	}

	s := NewState()
	s.UpsertReferenceGrant(rg)

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		RefValidator: s,
		HTTPRoutes:   []*gatewayv1.HTTPRoute{routeInLSNS, routeInGWNS, routeInSelNS, routeInOtherNS},
		Namespaces:   namespaces,
	})

	// 1. routeInLSNS targeting listener-same: Accepted=True
	crSame := compiled.HTTPRoutes[types.NamespacedName{Namespace: "ls-ns", Name: "route-same-ns"}]
	if crSame == nil || len(crSame.ParentConditions) != 1 || crSame.ParentConditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected routeInLSNS Accepted=True, got %v", crSame)
	}

	// 2. routeInGWNS targeting listener-same: Accepted=False (Reason: NotAllowedByListeners)
	// Because listener-same is scoped to ListenerSet's namespace (ls-ns), not the Gateway's namespace (gw-ns).
	crGW := compiled.HTTPRoutes[types.NamespacedName{Namespace: "gw-ns", Name: "route-gw-ns"}]
	if crGW == nil || len(crGW.ParentConditions) != 1 {
		t.Fatalf("expected routeInGWNS compiled route, got %v", crGW)
	}
	if crGW.ParentConditions[0].Status != metav1.ConditionFalse || crGW.ParentConditions[0].Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected routeInGWNS Accepted=False (NotAllowedByListeners), got %v", crGW.ParentConditions[0])
	}

	// 3. routeInSelNS targeting listener-sel: Accepted=True
	crSel := compiled.HTTPRoutes[types.NamespacedName{Namespace: "sel-ns", Name: "route-sel-ns"}]
	if crSel == nil || len(crSel.ParentConditions) != 1 || crSel.ParentConditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected routeInSelNS Accepted=True, got %v", crSel)
	}

	// 4. routeInOtherNS targeting listener-sel: Accepted=False (Reason: NotAllowedByListeners)
	crOther := compiled.HTTPRoutes[types.NamespacedName{Namespace: "other-ns", Name: "route-other-ns"}]
	if crOther == nil || len(crOther.ParentConditions) != 1 {
		t.Fatalf("expected routeInOtherNS compiled route, got %v", crOther)
	}
	if crOther.ParentConditions[0].Status != metav1.ConditionFalse || crOther.ParentConditions[0].Reason != string(gatewayv1.RouteReasonNotAllowedByListeners) {
		t.Errorf("expected routeInOtherNS Accepted=False (NotAllowedByListeners), got %v", crOther.ParentConditions[0])
	}
}

func TestCompileModel_ListenerSetGatewayParentSectionNameNotFound(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromSame),
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "gw-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("gw.example.com")),
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "ls-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("ls.example.com")),
				},
			},
		},
	}

	// Route targeting Gateway with sectionName "ls-listener" (exists on ListenerSet, not Gateway)
	routeViaGW := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-via-gw", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw",
						SectionName: Ptr(gatewayv1.SectionName("ls-listener")),
					},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "svc",
									Port: Ptr(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	// Route targeting ListenerSet with sectionName "ls-listener"
	routeViaLS := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-via-ls", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Kind:        Ptr(gatewayv1.Kind("ListenerSet")),
						Name:        "ls",
						SectionName: Ptr(gatewayv1.SectionName("ls-listener")),
					},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "svc",
									Port: Ptr(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		HTTPRoutes:   []*gatewayv1.HTTPRoute{routeViaGW, routeViaLS},
	})

	crGW := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-via-gw"}]
	if crGW == nil || len(crGW.ParentConditions) != 1 {
		t.Fatalf("expected routeViaGW compiled route, got %v", crGW)
	}
	if crGW.ParentConditions[0].Status != metav1.ConditionFalse || crGW.ParentConditions[0].Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
		t.Errorf("expected routeViaGW Accepted=False (NoMatchingParent), got %v", crGW.ParentConditions[0])
	}

	crLS := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-via-ls"}]
	if crLS == nil || len(crLS.ParentConditions) != 1 {
		t.Fatalf("expected routeViaLS compiled route, got %v", crLS)
	}
	if crLS.ParentConditions[0].Status != metav1.ConditionTrue || crLS.ParentConditions[0].Reason != string(gatewayv1.RouteReasonAccepted) {
		t.Errorf("expected routeViaLS Accepted=True (Accepted), got %v", crLS.ParentConditions[0])
	}
}

func TestCompileModel_ListenerSetRouteStatusScopedToParentRef(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromSame),
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "gw-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("gw.example.com")),
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "ls-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("ls.example.com")),
				},
			},
		},
	}

	routeGWOnly := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-gw", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
				},
			},
		},
	}

	routeLSOnly := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-ls", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Kind: Ptr(gatewayv1.Kind("ListenerSet")),
						Name: "ls",
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		HTTPRoutes:   []*gatewayv1.HTTPRoute{routeGWOnly, routeLSOnly},
	})

	crGW := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-gw"}]
	statusGW := ComputeDesiredHTTPRouteStatus(routeGWOnly, crGW, "example.net/gateway-controller")
	if len(statusGW.Parents) != 1 {
		t.Fatalf("expected exactly 1 parent in status for routeGWOnly, got %d", len(statusGW.Parents))
	}
	if statusGW.Parents[0].ParentRef.Name != "gw" || ValueOf(statusGW.Parents[0].ParentRef.Kind) != "" {
		t.Errorf("expected parentRef gw, got %+v", statusGW.Parents[0].ParentRef)
	}

	crLS := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-ls"}]
	statusLS := ComputeDesiredHTTPRouteStatus(routeLSOnly, crLS, "example.net/gateway-controller")
	if len(statusLS.Parents) != 1 {
		t.Fatalf("expected exactly 1 parent in status for routeLSOnly, got %d", len(statusLS.Parents))
	}
	if statusLS.Parents[0].ParentRef.Name != "ls" || ValueOf(statusLS.Parents[0].ParentRef.Kind) != "ListenerSet" {
		t.Errorf("expected parentRef ls (ListenerSet), got %+v", statusLS.Parents[0].ParentRef)
	}
}

func TestCompileModel_ListenerSetDualParentRefIndependence(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: Ptr(gatewayv1.NamespacesFromSame),
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "gw-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("gw.example.com")),
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "default"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "ls-listener",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("ls.example.com")),
				},
			},
		},
	}

	// Route with both parentRefs valid
	routeBothValid := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-both", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
					{
						Kind: Ptr(gatewayv1.Kind("ListenerSet")),
						Name: "ls",
					},
				},
			},
		},
	}

	// Route with Gateway parentRef invalid (sectionName ls-listener) and ListenerSet parentRef valid
	routeOneValid := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-one", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "gw",
						SectionName: Ptr(gatewayv1.SectionName("ls-listener")),
					},
					{
						Kind:        Ptr(gatewayv1.Kind("ListenerSet")),
						Name:        "ls",
						SectionName: Ptr(gatewayv1.SectionName("ls-listener")),
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:     []*gatewayv1.Gateway{gw},
		ListenerSets: []*gatewayv1.ListenerSet{ls},
		HTTPRoutes:   []*gatewayv1.HTTPRoute{routeBothValid, routeOneValid},
	})

	// Check route-both
	crBoth := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-both"}]
	if crBoth == nil || len(crBoth.ParentConditions) != 2 {
		t.Fatalf("expected 2 parent conditions for route-both, got %v", crBoth)
	}
	if crBoth.ParentConditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected parentRef[0] Accepted=True, got %v", crBoth.ParentConditions[0])
	}
	if crBoth.ParentConditions[1].Status != metav1.ConditionTrue {
		t.Errorf("expected parentRef[1] Accepted=True, got %v", crBoth.ParentConditions[1])
	}

	// Check route-one
	crOne := compiled.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route-one"}]
	if crOne == nil || len(crOne.ParentConditions) != 2 {
		t.Fatalf("expected 2 parent conditions for route-one, got %v", crOne)
	}
	if crOne.ParentConditions[0].Status != metav1.ConditionFalse || crOne.ParentConditions[0].Reason != string(gatewayv1.RouteReasonNoMatchingParent) {
		t.Errorf("expected parentRef[0] Accepted=False (NoMatchingParent), got %v", crOne.ParentConditions[0])
	}
	if crOne.ParentConditions[1].Status != metav1.ConditionTrue || crOne.ParentConditions[1].Reason != string(gatewayv1.RouteReasonAccepted) {
		t.Errorf("expected parentRef[1] Accepted=True (Accepted), got %v", crOne.ParentConditions[1])
	}
}

func TestGatewayHTTPListenerIsolation(t *testing.T) {
	allFrom := gatewayv1.NamespacesFromAll
	controllerName := "example.com/gateway-controller"

	listeners := []gatewayv1.Listener{
		{
			Name:     "empty-hostname",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &allFrom},
			},
		},
		{
			Name:     "wildcard-example-com",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &allFrom},
			},
		},
		{
			Name:     "wildcard-foo-example-com",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Hostname: Ptr(gatewayv1.Hostname("*.foo.example.com")),
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &allFrom},
			},
		},
		{
			Name:     "abc-foo-example-com",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Hostname: Ptr(gatewayv1.Hostname("abc.foo.example.com")),
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &allFrom},
			},
		},
	}

	createRoute := func(name, sectionName string, hostnames []gatewayv1.Hostname, path string, backendHost string) *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:        "gw",
							SectionName: Ptr(gatewayv1.SectionName(sectionName)),
						},
					},
				},
				Hostnames: hostnames,
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  Ptr(gatewayv1.PathMatchPathPrefix),
									Value: Ptr(path),
								},
							},
						},
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: gatewayv1.ObjectName(backendHost),
										Port: Ptr(gatewayv1.PortNumber(8080)),
									},
								},
							},
						},
					},
				},
			},
		}
	}

	type requestTest struct {
		host        string
		path        string
		wantBackend string // empty means 404
	}

	testMatrix := []requestTest{
		// bar.com matches only empty-hostname listener
		{host: "bar.com", path: "/empty-hostname", wantBackend: "backend-empty.default.svc.cluster.local"},
		{host: "bar.com", path: "/wildcard-example-com", wantBackend: ""},
		{host: "bar.com", path: "/wildcard-foo-example-com", wantBackend: ""},
		{host: "bar.com", path: "/abc-foo-example-com", wantBackend: ""},

		// bar.example.com matches wildcard-example-com listener (*.example.com)
		{host: "bar.example.com", path: "/empty-hostname", wantBackend: ""},
		{host: "bar.example.com", path: "/wildcard-example-com", wantBackend: "backend-wildcard-example.default.svc.cluster.local"},
		{host: "bar.example.com", path: "/wildcard-foo-example-com", wantBackend: ""},
		{host: "bar.example.com", path: "/abc-foo-example-com", wantBackend: ""},

		// bar.foo.example.com matches wildcard-foo-example-com listener (*.foo.example.com)
		{host: "bar.foo.example.com", path: "/empty-hostname", wantBackend: ""},
		{host: "bar.foo.example.com", path: "/wildcard-example-com", wantBackend: ""},
		{host: "bar.foo.example.com", path: "/wildcard-foo-example-com", wantBackend: "backend-wildcard-foo.default.svc.cluster.local"},
		{host: "bar.foo.example.com", path: "/abc-foo-example-com", wantBackend: ""},

		// abc.foo.example.com matches abc-foo-example-com listener (abc.foo.example.com)
		{host: "abc.foo.example.com", path: "/empty-hostname", wantBackend: ""},
		{host: "abc.foo.example.com", path: "/wildcard-example-com", wantBackend: ""},
		{host: "abc.foo.example.com", path: "/wildcard-foo-example-com", wantBackend: ""},
		{host: "abc.foo.example.com", path: "/abc-foo-example-com", wantBackend: "backend-abc-foo.default.svc.cluster.local"},
	}

	variants := []struct {
		name   string
		routes []*gatewayv1.HTTPRoute
	}{
		{
			name: "hostnames configured only in listeners",
			routes: []*gatewayv1.HTTPRoute{
				createRoute("attaches-to-empty-hostname", "empty-hostname", nil, "/empty-hostname", "backend-empty"),
				createRoute("attaches-to-wildcard-example-com", "wildcard-example-com", nil, "/wildcard-example-com", "backend-wildcard-example"),
				createRoute("attaches-to-wildcard-foo-example-com", "wildcard-foo-example-com", nil, "/wildcard-foo-example-com", "backend-wildcard-foo"),
				createRoute("attaches-to-abc-foo-example-com", "abc-foo-example-com", nil, "/abc-foo-example-com", "backend-abc-foo"),
			},
		},
		{
			name: "intersecting hostnames configured in listeners and HTTPRoutes",
			routes: []*gatewayv1.HTTPRoute{
				createRoute(
					"attaches-to-empty-hostname-with-hostname-intersection",
					"empty-hostname",
					[]gatewayv1.Hostname{"bar.com", "*.example.com", "*.foo.example.com", "abc.foo.example.com"},
					"/empty-hostname",
					"backend-empty",
				),
				createRoute(
					"attaches-to-wildcard-example-com-with-hostname-intersection",
					"wildcard-example-com",
					[]gatewayv1.Hostname{"bar.com", "*.example.com", "*.foo.example.com", "abc.foo.example.com"},
					"/wildcard-example-com",
					"backend-wildcard-example",
				),
				createRoute(
					"attaches-to-wildcard-foo-example-com-with-hostname-intersection",
					"wildcard-foo-example-com",
					[]gatewayv1.Hostname{"bar.com", "*.example.com", "*.foo.example.com", "abc.foo.example.com"},
					"/wildcard-foo-example-com",
					"backend-wildcard-foo",
				),
				createRoute(
					"attaches-to-abc-foo-example-com-with-hostname-intersection",
					"abc-foo-example-com",
					[]gatewayv1.Hostname{"bar.com", "*.example.com", "*.foo.example.com", "abc.foo.example.com"},
					"/abc-foo-example-com",
					"backend-abc-foo",
				),
			},
		},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "reference-class",
					Listeners:        listeners,
				},
			}
			gc := &gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
				Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(controllerName)},
			}

			outputs := ComputeOutputs(ModelInputs{
				Gateways:       []*gatewayv1.Gateway{gw},
				GatewayClasses: []*gatewayv1.GatewayClass{gc},
				HTTPRoutes:     v.routes,
				ControllerName: controllerName,
			})

			for _, tc := range testMatrix {
				t.Run(tc.host+tc.path, func(t *testing.T) {
					req, err := http.NewRequest("GET", "http://"+tc.host+tc.path, nil)
					if err != nil {
						t.Fatalf("failed to create request: %v", err)
					}
					reqHostListeners, _ := MatchListeners(outputs.ProxyListeners, tc.host)
					var matchedRoutes []InternalRoute
					for _, l := range reqHostListeners {
						matchedRoutes = append(matchedRoutes, l.Routes...)
					}
					bestRule, _ := MatchRoute(matchedRoutes, req)

					if tc.wantBackend == "" {
						if bestRule != nil && len(bestRule.Backends) > 0 {
							t.Errorf("expected 404 (no match), but matched backend %q", bestRule.Backends[0].Host)
						}
					} else {
						if bestRule == nil || len(bestRule.Backends) == 0 {
							t.Fatalf("expected backend %q, but got 404 (no match)", tc.wantBackend)
						}
						if bestRule.Backends[0].Host != tc.wantBackend {
							t.Errorf("got backend %q, want %q", bestRule.Backends[0].Host, tc.wantBackend)
						}
					}
				})
			}
		})
	}
}

func TestComputeDesiredBackendTLSPolicyStatus_ConditionsAndReasons(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
		{Namespace: "default", Name: "malformed-empty"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "malformed-empty"},
			Data:       map[string]string{},
		},
		{Namespace: "default", Name: "malformed-pem"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "malformed-pem"},
			Data:       map[string]string{ConfigMapCACertKey: "invalid-pem-bytes"},
		},
	}

	tests := []struct {
		name                   string
		caCertificateRefs      []gatewayv1.LocalObjectReference
		expectedAcceptedStatus metav1.ConditionStatus
		expectedAcceptedReason string
		expectedRefsStatus     metav1.ConditionStatus
		expectedRefsReason     string
	}{
		{
			name: "Valid ConfigMap CA reference",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
			},
			expectedAcceptedStatus: metav1.ConditionTrue,
			expectedAcceptedReason: string(gatewayv1.PolicyReasonAccepted),
			expectedRefsStatus:     metav1.ConditionTrue,
			expectedRefsReason:     string(gatewayv1.BackendTLSPolicyReasonResolvedRefs),
		},
		{
			name: "Invalid kind in caCertificateRefs",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "invalid.io", Kind: "InvalidKind", Name: "invalid-kind"},
			},
			expectedAcceptedStatus: metav1.ConditionFalse,
			expectedAcceptedReason: string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
			expectedRefsStatus:     metav1.ConditionFalse,
			expectedRefsReason:     string(gatewayv1.BackendTLSPolicyReasonInvalidKind),
		},
		{
			name: "Nonexistent ConfigMap reference",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "nonexistent-cm"},
			},
			expectedAcceptedStatus: metav1.ConditionFalse,
			expectedAcceptedReason: string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
			expectedRefsStatus:     metav1.ConditionFalse,
			expectedRefsReason:     string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
		},
		{
			name: "Malformed ConfigMap without ca.crt",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "malformed-empty"},
			},
			expectedAcceptedStatus: metav1.ConditionFalse,
			expectedAcceptedReason: string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
			expectedRefsStatus:     metav1.ConditionFalse,
			expectedRefsReason:     string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
		},
		{
			name: "Malformed ConfigMap with invalid PEM data",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "malformed-pem"},
			},
			expectedAcceptedStatus: metav1.ConditionFalse,
			expectedAcceptedReason: string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
			expectedRefsStatus:     metav1.ConditionFalse,
			expectedRefsReason:     string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: "",
								Kind:  "Service",
								Name:  "my-service",
							},
						},
					},
					Validation: gatewayv1.BackendTLSPolicyValidation{
						Hostname:          "example.com",
						CACertificateRefs: tc.caCertificateRefs,
					},
				},
			}

			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "reference-class",
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			}
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "my-service",
										},
									},
								},
							},
						},
					},
				},
			}

			compiled := CompileModel(ModelInputs{
				Gateways:           []*gatewayv1.Gateway{gw},
				HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
				BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
				ConfigMaps:         configMaps,
			})

			status := ComputeDesiredBackendTLSPolicyStatus(policy, compiled, configMaps, []*gatewayv1.BackendTLSPolicy{policy}, "test-controller")

			if len(status.Ancestors) != 1 {
				t.Fatalf("expected 1 ancestor in status, got %d", len(status.Ancestors))
			}

			ancestor := status.Ancestors[0]
			var acceptedCond, refsCond *metav1.Condition
			for i := range ancestor.Conditions {
				c := &ancestor.Conditions[i]
				if c.Type == string(gatewayv1.PolicyConditionAccepted) {
					acceptedCond = c
				} else if c.Type == string(gatewayv1.BackendTLSPolicyConditionResolvedRefs) {
					refsCond = c
				}
			}

			if acceptedCond == nil {
				t.Fatalf("missing Accepted condition")
			}
			if acceptedCond.Status != tc.expectedAcceptedStatus {
				t.Errorf("Accepted status = %v, want %v", acceptedCond.Status, tc.expectedAcceptedStatus)
			}
			if acceptedCond.Reason != tc.expectedAcceptedReason {
				t.Errorf("Accepted reason = %v, want %v", acceptedCond.Reason, tc.expectedAcceptedReason)
			}
			if acceptedCond.ObservedGeneration != 1 {
				t.Errorf("Accepted observedGeneration = %d, want 1", acceptedCond.ObservedGeneration)
			}

			if refsCond == nil {
				t.Fatalf("missing ResolvedRefs condition")
			}
			if refsCond.Status != tc.expectedRefsStatus {
				t.Errorf("ResolvedRefs status = %v, want %v", refsCond.Status, tc.expectedRefsStatus)
			}
			if refsCond.Reason != tc.expectedRefsReason {
				t.Errorf("ResolvedRefs reason = %v, want %v", refsCond.Reason, tc.expectedRefsReason)
			}
			if refsCond.ObservedGeneration != 1 {
				t.Errorf("ResolvedRefs observedGeneration = %d, want 1", refsCond.ObservedGeneration)
			}
		})
	}
}

func TestComputeOutputs_InvalidBackendTLSPolicy_CompiledBackendFails(t *testing.T) {
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "malformed"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "malformed"},
			Data:       map[string]string{ConfigMapCACertKey: "invalid"},
		},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "my-service"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Name: "https", Port: 443},
				},
			},
		},
	}

	testCases := []struct {
		name              string
		caCertificateRefs []gatewayv1.LocalObjectReference
	}{
		{
			name: "Invalid kind",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "invalid.io", Kind: "InvalidKind", Name: "invalid"},
			},
		},
		{
			name: "Nonexistent ConfigMap",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "nonexistent"},
			},
		},
		{
			name: "Malformed PEM data",
			caCertificateRefs: []gatewayv1.LocalObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "malformed"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "reference-class",
					Listeners: []gatewayv1.Listener{
						{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					},
				},
			}
			gc := &gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
				Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
			}
			port443 := gatewayv1.PortNumber(443)
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
					Hostnames: []gatewayv1.Hostname{"example.com"},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "my-service",
											Port: &port443,
										},
									},
								},
							},
						},
					},
				},
			}
			policy := &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
				Spec: gatewayv1.BackendTLSPolicySpec{
					TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
								Group: "",
								Kind:  "Service",
								Name:  "my-service",
							},
						},
					},
					Validation: gatewayv1.BackendTLSPolicyValidation{
						Hostname:          "backend.example.com",
						CACertificateRefs: tc.caCertificateRefs,
					},
				},
			}

			outputs := ComputeOutputs(ModelInputs{
				Gateways:           []*gatewayv1.Gateway{gw},
				GatewayClasses:     []*gatewayv1.GatewayClass{gc},
				HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
				BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
				ConfigMaps:         configMaps,
				Services:           services,
				ControllerName:     "test-controller",
			})

			// Verify the route is accepted (route's ResolvedRefs is True)
			routeStatus := outputs.HTTPRouteStatuses[types.NamespacedName{Namespace: "default", Name: "route"}]
			if len(routeStatus.Parents) != 1 {
				t.Fatalf("expected 1 route parent status, got %d", len(routeStatus.Parents))
			}
			for _, cond := range routeStatus.Parents[0].Conditions {
				if cond.Type == string(gatewayv1.RouteConditionResolvedRefs) && cond.Status != metav1.ConditionTrue {
					t.Errorf("expected route ResolvedRefs=True, got %v", cond.Status)
				}
			}

			// Verify the compiled backend in proxy listeners is configured to fail closed
			if len(outputs.ProxyListeners) != 1 || len(outputs.ProxyListeners[0].Routes) != 1 {
				t.Fatalf("expected 1 proxy listener with 1 route")
			}
			compiledRule := outputs.ProxyListeners[0].Routes[0].Rules[0]
			if len(compiledRule.Backends) != 1 {
				t.Fatalf("expected 1 compiled backend, got %d", len(compiledRule.Backends))
			}
			b := compiledRule.Backends[0]

			// Must not be plaintext:
			if b.AppProtocol == nil || *b.AppProtocol != "https" {
				t.Errorf("expected AppProtocol https (not plaintext), got %v", b.AppProtocol)
			}

			// Must have TLSConfig with no CA certs (not system pool fallback):
			if b.TLSConfig == nil || len(b.TLSConfig.CACerts) != 0 {
				t.Errorf("expected TLSConfig with 0 CACerts, got %v", b.TLSConfig)
			}

			// Must have Error configured so requests fail with 5xx:
			if b.Error == nil {
				t.Fatalf("expected backend.Error != nil for invalid policy, got nil")
			}
			if b.Error.HTTPStatusCode != http.StatusInternalServerError {
				t.Errorf("expected backend.Error.HTTPStatusCode 500, got %d", b.Error.HTTPStatusCode)
			}
		})
	}
}

func TestComputeOutputs_BackendTLSPolicy_ObservedGenerationBump(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "svc"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "svc"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "svc",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "svc",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "backend.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	// 1. Initial computation (generation 1)
	outputs1 := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		ConfigMaps:         configMaps,
		Services:           services,
		ControllerName:     "test-controller",
	})

	policyStatus1 := outputs1.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "policy"}]
	if len(policyStatus1.Ancestors) != 1 {
		t.Fatalf("expected 1 ancestor, got %d", len(policyStatus1.Ancestors))
	}
	for _, c := range policyStatus1.Ancestors[0].Conditions {
		if c.ObservedGeneration != 1 {
			t.Errorf("condition %s observedGeneration = %d, want 1", c.Type, c.ObservedGeneration)
		}
	}

	// 2. Spec update bumps metadata.generation to 2
	policyUpdated := policy.DeepCopy()
	policyUpdated.Generation = 2
	policyUpdated.Spec.Validation.Hostname = "new-backend.example.com"

	outputs2 := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policyUpdated},
		ConfigMaps:         configMaps,
		Services:           services,
		ControllerName:     "test-controller",
	})

	policyStatus2 := outputs2.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "policy"}]
	if len(policyStatus2.Ancestors) != 1 {
		t.Fatalf("expected 1 ancestor, got %d", len(policyStatus2.Ancestors))
	}
	for _, c := range policyStatus2.Ancestors[0].Conditions {
		if c.ObservedGeneration != 2 {
			t.Errorf("condition %s observedGeneration = %d, want 2", c.Type, c.ObservedGeneration)
		}
	}
}

func TestComputeOutputs_BackendTLSPolicy_SectionNameMatching(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "multi-port-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "multi-port-svc"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Name: "http", Port: 80},
					{Name: "btls", Port: 443},
				},
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	btlsSection := gatewayv1.SectionName("btls")
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "multi-port-svc",
					},
					SectionName: &btlsSection,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "backend.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	port443 := gatewayv1.PortNumber(443)
	routeMatching := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-matching", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "multi-port-svc",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	port80 := gatewayv1.PortNumber(80)
	routeNonMatching := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-non-matching", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "multi-port-svc",
									Port: &port80,
								},
							},
						},
					},
				},
			},
		},
	}

	outputs := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{routeMatching, routeNonMatching},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		ConfigMaps:         configMaps,
		Services:           services,
		ControllerName:     "test-controller",
	})

	// routeMatching targets port 443 (name "btls"), so policy applies
	crMatching := outputs.ProxyListeners[0].Routes[0].Rules[0].Backends[0]
	if crMatching.Port == 443 {
		if crMatching.TLSConfig == nil || crMatching.AppProtocol == nil || *crMatching.AppProtocol != "https" {
			t.Errorf("expected policy to apply to port 443, got TLSConfig=%v, AppProtocol=%v", crMatching.TLSConfig, crMatching.AppProtocol)
		}
	}

	// routeNonMatching targets port 80 (name "http"), so policy does NOT apply
	crNonMatching := outputs.ProxyListeners[0].Routes[1].Rules[0].Backends[0]
	if crNonMatching.Port == 80 {
		if crNonMatching.TLSConfig != nil {
			t.Errorf("expected policy not to apply to port 80, got TLSConfig=%v", crNonMatching.TLSConfig)
		}
	}
}

func TestComputeOutputs_BackendTLSPolicy_WellKnownCACertificatesSystem(t *testing.T) {
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "my-service"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	wellKnownSystem := gatewayv1.WellKnownCACertificatesSystem
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:                "backend.example.com",
				WellKnownCACertificates: &wellKnownSystem,
			},
		},
	}

	outputs := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		Services:           services,
		ControllerName:     "test-controller",
	})

	// 1. Verify policy status is Accepted=True and ResolvedRefs=True
	policyStatus := outputs.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "policy"}]
	if len(policyStatus.Ancestors) != 1 {
		t.Fatalf("expected 1 ancestor in policy status, got %d", len(policyStatus.Ancestors))
	}
	var acceptedCond, refsCond *metav1.Condition
	for i := range policyStatus.Ancestors[0].Conditions {
		c := &policyStatus.Ancestors[0].Conditions[i]
		if c.Type == string(gatewayv1.PolicyConditionAccepted) {
			acceptedCond = c
		} else if c.Type == string(gatewayv1.BackendTLSPolicyConditionResolvedRefs) {
			refsCond = c
		}
	}
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True for System well-known CA, got %v", acceptedCond)
	}
	if refsCond == nil || refsCond.Status != metav1.ConditionTrue {
		t.Errorf("expected ResolvedRefs=True for System well-known CA, got %v", refsCond)
	}

	// 2. Verify compiled backend
	if len(outputs.ProxyListeners) != 1 || len(outputs.ProxyListeners[0].Routes) != 1 {
		t.Fatalf("expected 1 proxy listener with 1 route")
	}
	backend := outputs.ProxyListeners[0].Routes[0].Rules[0].Backends[0]
	if backend.Error != nil {
		t.Errorf("expected backend.Error == nil, got %v", backend.Error)
	}
	if backend.AppProtocol == nil || *backend.AppProtocol != "https" {
		t.Errorf("expected AppProtocol 'https', got %v", backend.AppProtocol)
	}
	if backend.TLSConfig == nil {
		t.Fatalf("expected non-nil TLSConfig")
	}
	if backend.TLSConfig.Hostname != "backend.example.com" {
		t.Errorf("expected Hostname 'backend.example.com', got %q", backend.TLSConfig.Hostname)
	}
	if backend.TLSConfig.WellKnownCACertificates == nil || *backend.TLSConfig.WellKnownCACertificates != gatewayv1.WellKnownCACertificatesSystem {
		t.Errorf("expected WellKnownCACertificates System, got %v", backend.TLSConfig.WellKnownCACertificates)
	}
	if len(backend.TLSConfig.CACerts) != 0 {
		t.Errorf("expected 0 CACerts for System well-known CA, got %d", len(backend.TLSConfig.CACerts))
	}
}

func TestComputeOutputs_BackendTLSPolicy_TargetRefGroup(t *testing.T) {
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "my-service"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	wellKnownSystem := gatewayv1.WellKnownCACertificatesSystem
	// Policy has invalid group for Service: gateway.networking.k8s.io (Service is in core group "" only)
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "gateway.networking.k8s.io",
						Kind:  "Service",
						Name:  "my-service",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:                "backend.example.com",
				WellKnownCACertificates: &wellKnownSystem,
			},
		},
	}

	outputs := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		Services:           services,
		ControllerName:     "test-controller",
	})

	// TargetRef with group gateway.networking.k8s.io must NOT match Service
	backend := outputs.ProxyListeners[0].Routes[0].Rules[0].Backends[0]
	if backend.TLSConfig != nil {
		t.Errorf("expected TLSConfig == nil for policy with group gateway.networking.k8s.io targeting Service, got %v", backend.TLSConfig)
	}
}

func TestComputeDesiredBackendTLSPolicyStatus_SectionConflictResolution(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "default",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	sec := gatewayv1.SectionName("https-1")
	t0 := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	t1 := metav1.NewTime(time.Now().Add(-5 * time.Minute))

	// 1. Earlier creationTimestamp wins
	pOlder := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-older",
			Namespace:         "default",
			CreationTimestamp: t0,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
					SectionName: &sec,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "older.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	pNewer := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-newer",
			Namespace:         "default",
			CreationTimestamp: t1,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
					SectionName: &sec,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "newer.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	compiled1 := CompileModel(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{pOlder, pNewer},
		ConfigMaps:         configMaps,
	})

	allPolicies1 := []*gatewayv1.BackendTLSPolicy{pOlder, pNewer}
	statusOlder := ComputeDesiredBackendTLSPolicyStatus(pOlder, compiled1, configMaps, allPolicies1, "test-controller")
	statusNewer := ComputeDesiredBackendTLSPolicyStatus(pNewer, compiled1, configMaps, allPolicies1, "test-controller")

	if len(statusOlder.Ancestors) != 1 || statusOlder.Ancestors[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected older policy Accepted=True, got %v", statusOlder)
	}
	if len(statusNewer.Ancestors) != 1 || statusNewer.Ancestors[0].Conditions[0].Status != metav1.ConditionFalse || statusNewer.Ancestors[0].Conditions[0].Reason != string(gatewayv1.PolicyReasonConflicted) {
		t.Fatalf("expected newer policy Accepted=False with reason Conflicted, got %v", statusNewer)
	}

	// 2. Name tie-break when creationTimestamps are equal
	pA := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-a",
			Namespace:         "default",
			CreationTimestamp: t0,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
					SectionName: &sec,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "a.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	pB := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-b",
			Namespace:         "default",
			CreationTimestamp: t0,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
					SectionName: &sec,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "b.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	compiled2 := CompileModel(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{pA, pB},
		ConfigMaps:         configMaps,
	})

	allPolicies2 := []*gatewayv1.BackendTLSPolicy{pA, pB}
	statusA := ComputeDesiredBackendTLSPolicyStatus(pA, compiled2, configMaps, allPolicies2, "test-controller")
	statusB := ComputeDesiredBackendTLSPolicyStatus(pB, compiled2, configMaps, allPolicies2, "test-controller")

	if len(statusA.Ancestors) != 1 || statusA.Ancestors[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected p-a Accepted=True, got %v", statusA)
	}
	if len(statusB.Ancestors) != 1 || statusB.Ancestors[0].Conditions[0].Status != metav1.ConditionFalse || statusB.Ancestors[0].Conditions[0].Reason != string(gatewayv1.PolicyReasonConflicted) {
		t.Fatalf("expected p-b Accepted=False with reason Conflicted, got %v", statusB)
	}
}

func TestBackendTLSPolicy_SectionAndServiceWide_NoConflict(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "default",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "my-service"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports: []corev1.ServicePort{
					{Name: "https-1", Port: 443},
					{Name: "https-2", Port: 8443},
				},
			},
		},
	}

	port443 := gatewayv1.PortNumber(443)
	port8443 := gatewayv1.PortNumber(8443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port443,
								},
							},
						},
					},
				},
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port8443,
								},
							},
						},
					},
				},
			},
		},
	}

	t0 := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	t1 := metav1.NewTime(time.Now().Add(-5 * time.Minute))

	// Service-wide policy created EARLIER (t0)
	pServiceWide := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-servicewide",
			Namespace:         "default",
			CreationTimestamp: t0,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "servicewide.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	// Section-specific policy created LATER (t1)
	sec := gatewayv1.SectionName("https-1")
	pSection := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "p-section",
			Namespace:         "default",
			CreationTimestamp: t1,
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
					SectionName: &sec,
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "section.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	outputs := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{pServiceWide, pSection},
		Services:           services,
		ConfigMaps:         configMaps,
		ControllerName:     "test-controller",
	})

	// 1. Both policies must be Accepted (no conflict between section and service-wide)
	sectionStatus := outputs.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "p-section"}]
	if len(sectionStatus.Ancestors) != 1 || sectionStatus.Ancestors[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected section policy Accepted=True, got %v", sectionStatus)
	}
	serviceWideStatus := outputs.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "p-servicewide"}]
	if len(serviceWideStatus.Ancestors) != 1 || serviceWideStatus.Ancestors[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected service-wide policy Accepted=True, got %v", serviceWideStatus)
	}

	// 2. Compiled backends must pick up the right policy:
	// Rule 0 (port 443 / https-1) -> section policy (section.example.com)
	b443 := outputs.ProxyListeners[0].Routes[0].Rules[0].Backends[0]
	if b443.TLSConfig == nil || b443.TLSConfig.Hostname != "section.example.com" {
		t.Errorf("expected port 443 backend to use section policy with hostname 'section.example.com', got %v", b443.TLSConfig)
	}

	// Rule 1 (port 8443 / https-2) -> service-wide policy (servicewide.example.com)
	b8443 := outputs.ProxyListeners[0].Routes[0].Rules[1].Backends[0]
	if b8443.TLSConfig == nil || b8443.TLSConfig.Hostname != "servicewide.example.com" {
		t.Errorf("expected port 8443 backend to use service-wide policy with hostname 'servicewide.example.com', got %v", b8443.TLSConfig)
	}
}

func TestBackendTLSPolicy_CompiledInternalTLSConfig_CarriesSubjectAltNames(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "default",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "my-service"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports: []corev1.ServicePort{
					{Name: "https", Port: 443},
				},
			},
		},
	}

	port443 := gatewayv1.PortNumber(443)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "my-service",
									Port: &port443,
								},
							},
						},
					},
				},
			},
		},
	}

	expectedSANs := []gatewayv1.SubjectAltName{
		{
			Type:     gatewayv1.HostnameSubjectAltNameType,
			Hostname: "backend.example.com",
		},
		{
			Type: gatewayv1.URISubjectAltNameType,
			URI:  "spiffe://example.com/backend",
		},
	}

	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p-sans",
			Namespace: "default",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "my-service",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname:        "sni.example.com",
				SubjectAltNames: expectedSANs,
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	outputs := ComputeOutputs(ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		Services:           services,
		ConfigMaps:         configMaps,
		ControllerName:     "test-controller",
	})

	backend := outputs.ProxyListeners[0].Routes[0].Rules[0].Backends[0]
	if backend.TLSConfig == nil {
		t.Fatalf("expected backend.TLSConfig != nil")
	}
	if len(backend.TLSConfig.SubjectAltNames) != len(expectedSANs) {
		t.Fatalf("expected %d SubjectAltNames, got %d", len(expectedSANs), len(backend.TLSConfig.SubjectAltNames))
	}
	if backend.TLSConfig.SubjectAltNames[0].Hostname != "backend.example.com" {
		t.Errorf("expected first SAN hostname 'backend.example.com', got %q", backend.TLSConfig.SubjectAltNames[0].Hostname)
	}
	if backend.TLSConfig.SubjectAltNames[1].URI != "spiffe://example.com/backend" {
		t.Errorf("expected second SAN URI 'spiffe://example.com/backend', got %q", backend.TLSConfig.SubjectAltNames[1].URI)
	}
}

func TestComputeOutputs_BackendTLSPolicy_AncestorStatus_RouteTypes(t *testing.T) {
	caCertPEM, _ := generateTestCertPEM(t, "ca.example.com")
	gwCertPEM, gwKeyPEM := generateTestCertPEM(t, "gw.example.com")

	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
		},
	}
	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "gw-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-cert"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       gwCertPEM,
				corev1.TLSPrivateKeyKey: gwKeyPEM,
			},
		},
	}
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "test-svc"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-svc"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			},
		},
	}
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "default", Generation: 1},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "test-svc",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "backend.local",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				},
			},
		},
	}

	port443 := gatewayv1.PortNumber(443)
	terminateMode := gatewayv1.TLSModeTerminate
	passthroughMode := gatewayv1.TLSModePassthrough
	tlsSecretRef := []gatewayv1.SecretObjectReference{{Name: "gw-cert"}}

	tests := []struct {
		name          string
		routeKind     string
		listener      gatewayv1.Listener
		wantAncestors int
	}{
		{
			name:      "HTTPRoute backend reports ancestor status",
			routeKind: "HTTPRoute",
			listener: gatewayv1.Listener{
				Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			},
			wantAncestors: 1,
		},
		{
			name:      "GRPCRoute backend reports ancestor status",
			routeKind: "GRPCRoute",
			listener: gatewayv1.Listener{
				Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{CertificateRefs: tlsSecretRef},
			},
			wantAncestors: 1,
		},
		{
			name:      "TLSRoute Terminate backend reports ancestor status",
			routeKind: "TLSRoute",
			listener: gatewayv1.Listener{
				Name: "tls-terminate", Port: 8443, Protocol: gatewayv1.TLSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{Mode: &terminateMode, CertificateRefs: tlsSecretRef},
			},
			wantAncestors: 1,
		},
		{
			name:      "TLSRoute Passthrough backend reports no ancestor status",
			routeKind: "TLSRoute",
			listener: gatewayv1.Listener{
				Name: "tls-passthrough", Port: 8443, Protocol: gatewayv1.TLSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{Mode: &passthroughMode},
			},
			wantAncestors: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputs := ModelInputs{
				Gateways: []*gatewayv1.Gateway{{
					ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "reference-class",
						Listeners:        []gatewayv1.Listener{tc.listener},
					},
				}},
				GatewayClasses:     []*gatewayv1.GatewayClass{gc},
				BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
				ConfigMaps:         configMaps,
				Services:           services,
				Secrets:            secrets,
				ControllerName:     "test-controller",
			}
			backendObj := gatewayv1.BackendObjectReference{Name: "test-svc", Port: &port443}
			switch tc.routeKind {
			case "HTTPRoute":
				inputs.HTTPRoutes = []*gatewayv1.HTTPRoute{{
					ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}}},
						Rules: []gatewayv1.HTTPRouteRule{{
							BackendRefs: []gatewayv1.HTTPBackendRef{{
								BackendRef: gatewayv1.BackendRef{BackendObjectReference: backendObj},
							}},
						}},
					},
				}}
			case "GRPCRoute":
				inputs.GRPCRoutes = []*gatewayv1.GRPCRoute{{
					ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
					Spec: gatewayv1.GRPCRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}}},
						Rules: []gatewayv1.GRPCRouteRule{{
							BackendRefs: []gatewayv1.GRPCBackendRef{{
								BackendRef: gatewayv1.BackendRef{BackendObjectReference: backendObj},
							}},
						}},
					},
				}}
			case "TLSRoute":
				inputs.TLSRoutes = []*gatewayv1.TLSRoute{{
					ObjectMeta: metav1.ObjectMeta{Name: "tls-route", Namespace: "default"},
					Spec: gatewayv1.TLSRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}}},
						Rules: []gatewayv1.TLSRouteRule{{
							BackendRefs: []gatewayv1.BackendRef{{BackendObjectReference: backendObj}},
						}},
					},
				}}
			}

			outputs := ComputeOutputs(inputs)

			status, ok := outputs.BackendTLSPolicyStatuses[types.NamespacedName{Namespace: "default", Name: "policy"}]
			if !ok {
				t.Fatalf("expected policy status for policy")
			}
			if len(status.Ancestors) != tc.wantAncestors {
				t.Fatalf("expected %d ancestors, got %d", tc.wantAncestors, len(status.Ancestors))
			}
			if tc.wantAncestors > 0 {
				anc := status.Ancestors[0]
				if string(anc.AncestorRef.Name) != "gw" {
					t.Errorf("expected ancestor name 'gw', got %q", anc.AncestorRef.Name)
				}
				var acceptedCond, refsCond *metav1.Condition
				for i := range anc.Conditions {
					c := &anc.Conditions[i]
					if c.Type == string(gatewayv1.PolicyConditionAccepted) {
						acceptedCond = c
					} else if c.Type == string(gatewayv1.BackendTLSPolicyConditionResolvedRefs) {
						refsCond = c
					}
				}
				if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
					t.Errorf("expected Accepted=True, got %v", acceptedCond)
				}
				if refsCond == nil || refsCond.Status != metav1.ConditionTrue {
					t.Errorf("expected ResolvedRefs=True, got %v", refsCond)
				}
			}
		})
	}
}

func TestGatewayBackendClientCertificate_ResolvedRefs(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t, "client.example.com")
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	validSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-secret"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	crossSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "cross-secret"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	emptySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "empty-secret"},
		Data:       map[string][]byte{},
	}
	malformedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "malformed-secret"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("corrupt-cert"),
			corev1.TLSPrivateKeyKey: []byte("corrupt-key"),
		},
	}

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "valid-secret"}:     validSecret,
		{Namespace: "other-ns", Name: "cross-secret"}:    crossSecret,
		{Namespace: "default", Name: "empty-secret"}:     emptySecret,
		{Namespace: "default", Name: "malformed-secret"}: malformedSecret,
	}

	crossGrant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "allow-gw-secret"},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Namespace: "default",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
					Name:  Ptr(gatewayv1.ObjectName("cross-secret")),
				},
			},
		},
	}

	tests := []struct {
		name                 string
		tlsBackend           *gatewayv1.GatewayBackendTLS
		useGrant             bool
		expectResolvedRefs   metav1.ConditionStatus
		expectResolvedReason string
	}{
		{
			name:                 "no clientCertificateRef gains ResolvedRefs=True",
			tlsBackend:           nil,
			expectResolvedRefs:   metav1.ConditionTrue,
			expectResolvedReason: string(gatewayv1.GatewayReasonResolvedRefs),
		},
		{
			name: "valid clientCertificateRef",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("")),
					Kind:  Ptr(gatewayv1.Kind("Secret")),
					Name:  "valid-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionTrue,
			expectResolvedReason: string(gatewayv1.GatewayReasonResolvedRefs),
		},
		{
			name: "missing Secret",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("")),
					Kind:  Ptr(gatewayv1.Kind("Secret")),
					Name:  "nonexistent-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
		},
		{
			name: "wrong group",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("wrong.group.io")),
					Kind:  Ptr(gatewayv1.Kind("Secret")),
					Name:  "valid-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
		},
		{
			name: "wrong kind",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("")),
					Kind:  Ptr(gatewayv1.Kind("ConfigMap")),
					Name:  "valid-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
		},
		{
			name: "empty secret without tls.crt and tls.key",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("")),
					Kind:  Ptr(gatewayv1.Kind("Secret")),
					Name:  "empty-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
		},
		{
			name: "malformed secret with invalid cert/key bytes",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group: Ptr(gatewayv1.Group("")),
					Kind:  Ptr(gatewayv1.Kind("Secret")),
					Name:  "malformed-secret",
				},
			},
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
		},
		{
			name: "cross-namespace without ReferenceGrant",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group:     Ptr(gatewayv1.Group("")),
					Kind:      Ptr(gatewayv1.Kind("Secret")),
					Name:      "cross-secret",
					Namespace: Ptr(gatewayv1.Namespace("other-ns")),
				},
			},
			useGrant:             false,
			expectResolvedRefs:   metav1.ConditionFalse,
			expectResolvedReason: string(gatewayv1.GatewayReasonRefNotPermitted),
		},
		{
			name: "cross-namespace with ReferenceGrant",
			tlsBackend: &gatewayv1.GatewayBackendTLS{
				ClientCertificateRef: &gatewayv1.SecretObjectReference{
					Group:     Ptr(gatewayv1.Group("")),
					Kind:      Ptr(gatewayv1.Kind("Secret")),
					Name:      "cross-secret",
					Namespace: Ptr(gatewayv1.Namespace("other-ns")),
				},
			},
			useGrant:             true,
			expectResolvedRefs:   metav1.ConditionTrue,
			expectResolvedReason: string(gatewayv1.GatewayReasonResolvedRefs),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "ref-class",
					Listeners: []gatewayv1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
						},
					},
				},
			}
			if tc.tlsBackend != nil {
				gw.Spec.TLS = &gatewayv1.GatewayTLSConfig{
					Backend: tc.tlsBackend,
				}
			}

			inputs := ModelInputs{
				Gateways:       []*gatewayv1.Gateway{gw},
				GatewayClasses: []*gatewayv1.GatewayClass{gc},
				Secrets:        secrets,
				ControllerName: "test-controller",
			}
			if tc.useGrant {
				inputs.ReferenceGrants = map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{
					{Namespace: crossGrant.Namespace, Name: crossGrant.Name}: crossGrant,
				}
				inputs.RefValidator = mapReferenceValidator{referenceGrants: inputs.ReferenceGrants}
			}

			outputs := ComputeOutputs(inputs)
			gwKey := types.NamespacedName{Namespace: "default", Name: "gw"}
			status, ok := outputs.GatewayStatuses[gwKey]
			if !ok {
				t.Fatalf("expected GatewayStatus for gw")
			}

			// Verify Accepted is always ConditionTrue with Reason Accepted
			accCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionAccepted))
			if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.GatewayReasonAccepted) {
				t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
			}

			// Verify ResolvedRefs
			resCond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionResolvedRefs))
			if resCond == nil {
				t.Fatalf("expected ResolvedRefs condition on Gateway")
			}
			if resCond.Status != tc.expectResolvedRefs {
				t.Errorf("expected ResolvedRefs Status=%s, got %s", tc.expectResolvedRefs, resCond.Status)
			}
			if resCond.Reason != tc.expectResolvedReason {
				t.Errorf("expected ResolvedRefs Reason=%s, got %s", tc.expectResolvedReason, resCond.Reason)
			}
		})
	}
}

func TestGatewayBackendClientCertificate_DataplaneWiring(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t, "client.example.com")
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "client-cert-secret"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
			TLS: &gatewayv1.GatewayTLSConfig{
				Backend: &gatewayv1.GatewayBackendTLS{
					ClientCertificateRef: &gatewayv1.SecretObjectReference{
						Group: Ptr(gatewayv1.Group("")),
						Kind:  Ptr(gatewayv1.Kind("Secret")),
						Name:  "client-cert-secret",
					},
				},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "backend-svc"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 443, Name: "https"},
			},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "my-gw"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Group: Ptr(gatewayv1.Group("")),
									Kind:  Ptr(gatewayv1.Kind("Service")),
									Name:  "backend-svc",
									Port:  Ptr(gatewayv1.PortNumber(443)),
								},
							},
						},
					},
				},
			},
		},
	}

	caCertPEM, _ := generateTestCertPEM(t, "backend.example.com")
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "backend-ca"},
		Data: map[string]string{
			ConfigMapCACertKey: string(caCertPEM),
		},
	}

	policy := &gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "policy"},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  "backend-svc",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: "backend.example.com",
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{Group: "", Kind: "ConfigMap", Name: "backend-ca"},
				},
			},
		},
	}

	inputs := ModelInputs{
		Gateways:           []*gatewayv1.Gateway{gw},
		GatewayClasses:     []*gatewayv1.GatewayClass{gc},
		HTTPRoutes:         []*gatewayv1.HTTPRoute{route},
		BackendTLSPolicies: []*gatewayv1.BackendTLSPolicy{policy},
		Services:           map[types.NamespacedName]*corev1.Service{{Namespace: "default", Name: "backend-svc"}: svc},
		ConfigMaps:         map[types.NamespacedName]*corev1.ConfigMap{{Namespace: "default", Name: "backend-ca"}: caConfigMap},
		Secrets:            map[types.NamespacedName]*corev1.Secret{{Namespace: "default", Name: "client-cert-secret"}: clientSecret},
		ControllerName:     "test-controller",
	}

	outputs := ComputeOutputs(inputs)
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	dpConfig, ok := outputs.DataplaneConfigs[gwKey]
	if !ok || dpConfig == nil {
		t.Fatalf("expected DataplaneConfig for gateway")
	}

	if dpConfig.BackendClientCertID == "" {
		t.Fatalf("expected non-empty BackendClientCertID")
	}
	if _, ok := dpConfig.Certificates[dpConfig.BackendClientCertID]; !ok {
		t.Fatalf("expected certificate %s to be present in Certificates map", dpConfig.BackendClientCertID)
	}

	// Verify that applying dataplane config wires the client certificate into the backend TLSConfig
	data, err := dpConfig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal dataplane config: %v", err)
	}

	updater := &mockProxyUpdater{}
	if err := ApplyDataplaneConfig(updater, data); err != nil {
		t.Fatalf("ApplyDataplaneConfig failed: %v", err)
	}

	if len(updater.routes) == 0 || len(updater.routes[0].Rules) == 0 || len(updater.routes[0].Rules[0].Backends) == 0 {
		t.Fatalf("expected updated routes with backends")
	}
	backend := updater.routes[0].Rules[0].Backends[0]
	if backend.TLSConfig == nil {
		t.Fatalf("expected backend.TLSConfig != nil")
	}
	if backend.TLSConfig.ClientCert == nil {
		t.Fatalf("expected backend.TLSConfig.ClientCert to be wired, got nil")
	}
}

type mockProxyUpdater struct {
	listeners []InternalListener
	routes    []InternalRoute
	certs     map[string]*tls.Certificate
	defCert   *tls.Certificate
}

func (m *mockProxyUpdater) UpdateConfig(listeners []InternalListener, routes []InternalRoute) {
	m.listeners = listeners
	m.routes = routes
}

func (m *mockProxyUpdater) UpdateCertificates(certs map[string]*tls.Certificate, defaultCert *tls.Certificate) {
	m.certs = certs
	m.defCert = defaultCert
}

func TestFrontendClientCertValidation_PerPortOverridesDefault(t *testing.T) {
	certPEMDefault, _ := generateTestCertPEM(t, "default.example.com")
	certPEMPort, _ := generateTestCertPEM(t, "port.example.com")
	serverCertPEM, serverKeyPEM := generateTestCertPEM(t, "server.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "server-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "server-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       serverCertPEM,
				corev1.TLSPrivateKeyKey: serverKeyPEM,
			},
		},
	}
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "default-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEMDefault)},
		},
		{Namespace: "default", Name: "port-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "port-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEMPort)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: []gatewayv1.ObjectReference{
								{Kind: "ConfigMap", Group: "", Name: "default-ca"},
							},
						},
					},
					PerPort: []gatewayv1.TLSPortConfig{
						{
							Port: 8443,
							TLS: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{
										{Kind: "ConfigMap", Group: "", Name: "port-ca"},
									},
								},
							},
						},
					},
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https-default",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Kind: Ptr(gatewayv1.Kind("Secret")), Name: "server-cert"},
						},
					},
				},
				{
					Name:     "https-port",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Kind: Ptr(gatewayv1.Kind("Secret")), Name: "server-cert"},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:   []*gatewayv1.Gateway{gw},
		Secrets:    secrets,
		ConfigMaps: configMaps,
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "my-gw"}]
	if cg == nil {
		t.Fatalf("expected compiled gateway")
	}

	var elDefault, elPort *EffectiveListener
	for _, el := range cg.EffectiveListeners {
		switch el.Name {
		case "https-default":
			elDefault = el
		case "https-port":
			elPort = el
		}
	}

	if elDefault == nil || elPort == nil {
		t.Fatalf("expected both listeners to be present")
	}

	// 1. https-default resolves default-ca
	if elDefault.ClientValidation == nil {
		t.Fatalf("expected elDefault.ClientValidation != nil")
	}
	if len(elDefault.ClientValidation.CACertPEMs) != 1 || string(elDefault.ClientValidation.CACertPEMs[0]) != string(certPEMDefault) {
		t.Errorf("elDefault did not resolve default-ca PEM")
	}
	if elDefault.ClientValidation.Mode != gatewayv1.AllowValidOnly {
		t.Errorf("expected default mode AllowValidOnly, got %v", elDefault.ClientValidation.Mode)
	}

	// 2. https-port resolves port-ca (perPort overrides default)
	if elPort.ClientValidation == nil {
		t.Fatalf("expected elPort.ClientValidation != nil")
	}
	if len(elPort.ClientValidation.CACertPEMs) != 1 || string(elPort.ClientValidation.CACertPEMs[0]) != string(certPEMPort) {
		t.Errorf("elPort did not resolve port-ca PEM (perPort override)")
	}

	// 3. Both are Programmed=True in part 2 (AllowValidOnly)
	for _, el := range []*EffectiveListener{elDefault, elPort} {
		var progCond, accCond, refCond *metav1.Condition
		for i := range el.Conditions {
			switch el.Conditions[i].Type {
			case string(gatewayv1.ListenerConditionProgrammed):
				progCond = &el.Conditions[i]
			case string(gatewayv1.ListenerConditionAccepted):
				accCond = &el.Conditions[i]
			case string(gatewayv1.ListenerConditionResolvedRefs):
				refCond = &el.Conditions[i]
			}
		}
		if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
			t.Errorf("listener %s: expected Programmed=True/Programmed, got %v", el.Name, progCond)
		}
		if accCond == nil || accCond.Status != metav1.ConditionTrue {
			t.Errorf("listener %s: expected Accepted=True, got %v", el.Name, accCond)
		}
		if refCond == nil || refCond.Status != metav1.ConditionTrue {
			t.Errorf("listener %s: expected ResolvedRefs=True, got %v", el.Name, refCond)
		}

		// InternalListener carries CA PEMs and mode
		il := el.ToInternalListener()
		if il.ClientValidation == nil || len(il.ClientValidation.CACertPEMs) == 0 {
			t.Errorf("listener %s: InternalListener missing ClientValidation or CA PEMs", el.Name)
		}
	}

	// 4. Present in proxy listeners in part 2
	proxyListeners, _ := BuildProxyConfig(compiled.GatewaysList())
	if len(proxyListeners) != 2 {
		t.Errorf("expected 2 proxy listeners, got %d", len(proxyListeners))
	}
	certsMap, defaultCert := ExtractCertificates(compiled.GatewaysList())
	if defaultCert == nil && len(certsMap) == 0 {
		t.Errorf("expected certificates extracted, got certsMap=%v defaultCert=%v", certsMap, defaultCert)
	}
}

func TestFrontendClientCertValidation_PerPortHTTPIgnored(t *testing.T) {
	certPEM, _ := generateTestCertPEM(t, "example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "ca-cm"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ca-cm"},
			Data:       map[string]string{ConfigMapCACertKey: string(certPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-http"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: []gatewayv1.ObjectReference{
								{Kind: "ConfigMap", Group: "", Name: "ca-cm"},
							},
						},
					},
					PerPort: []gatewayv1.TLSPortConfig{
						{
							Port: 80,
							TLS: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{
										{Kind: "ConfigMap", Group: "", Name: "ca-cm"},
									},
								},
							},
						},
					},
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-80",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:   []*gatewayv1.Gateway{gw},
		ConfigMaps: configMaps,
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-http"}]
	if cg == nil || len(cg.EffectiveListeners) != 1 {
		t.Fatalf("expected compiled gateway with 1 listener")
	}

	el := cg.EffectiveListeners[0]
	if el.ClientValidation != nil {
		t.Errorf("expected ClientValidation == nil on HTTP listener, got %v", el.ClientValidation)
	}

	var progCond, accCond, refCond *metav1.Condition
	for i := range el.Conditions {
		switch el.Conditions[i].Type {
		case string(gatewayv1.ListenerConditionProgrammed):
			progCond = &el.Conditions[i]
		case string(gatewayv1.ListenerConditionAccepted):
			accCond = &el.Conditions[i]
		case string(gatewayv1.ListenerConditionResolvedRefs):
			refCond = &el.Conditions[i]
		}
	}
	if progCond == nil || progCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Programmed=True for HTTP listener, got %v", progCond)
	}
	if accCond == nil || accCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True for HTTP listener, got %v", accCond)
	}
	if refCond == nil || refCond.Status != metav1.ConditionTrue {
		t.Errorf("expected ResolvedRefs=True for HTTP listener, got %v", refCond)
	}

	// Must be present in proxy listeners
	proxyListeners, _ := BuildProxyConfig(compiled.GatewaysList())
	if len(proxyListeners) != 1 {
		t.Fatalf("expected HTTP listener present in proxy listeners, got %d", len(proxyListeners))
	}
	if proxyListeners[0].ClientValidation != nil {
		t.Errorf("expected InternalListener ClientValidation == nil for HTTP listener")
	}
}

func TestFrontendClientCertValidation_InvalidReasons(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateTestCertPEM(t, "server.example.com")
	caCertPEM, _ := generateTestCertPEM(t, "ca.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "server-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "server-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       serverCertPEM,
				corev1.TLSPrivateKeyKey: serverKeyPEM,
			},
		},
	}

	tests := []struct {
		name               string
		caRef              gatewayv1.ObjectReference
		configMaps         map[types.NamespacedName]*corev1.ConfigMap
		useGrant           bool
		expectedRefReason  gatewayv1.ListenerConditionReason
		expectedAccReason  gatewayv1.ListenerConditionReason
		expectedProgReason gatewayv1.ListenerConditionReason
		expectedRefStatus  metav1.ConditionStatus
		expectedAccStatus  metav1.ConditionStatus
		expectedProgStatus metav1.ConditionStatus
	}{
		{
			name: "nonexistent ConfigMap",
			caRef: gatewayv1.ObjectReference{
				Group: "",
				Kind:  "ConfigMap",
				Name:  "does-not-exist",
			},
			configMaps:         map[types.NamespacedName]*corev1.ConfigMap{},
			expectedRefReason:  gatewayv1.ListenerReasonInvalidCACertificateRef,
			expectedAccReason:  gatewayv1.ListenerReasonNoValidCACertificate,
			expectedProgReason: gatewayv1.ListenerReasonNoValidCACertificate,
			expectedRefStatus:  metav1.ConditionFalse,
			expectedAccStatus:  metav1.ConditionFalse,
			expectedProgStatus: metav1.ConditionFalse,
		},
		{
			name: "non-ConfigMap kind",
			caRef: gatewayv1.ObjectReference{
				Group: "",
				Kind:  "Service",
				Name:  "my-service",
			},
			configMaps:         map[types.NamespacedName]*corev1.ConfigMap{},
			expectedRefReason:  gatewayv1.ListenerReasonInvalidCACertificateKind,
			expectedAccReason:  gatewayv1.ListenerReasonNoValidCACertificate,
			expectedProgReason: gatewayv1.ListenerReasonNoValidCACertificate,
			expectedRefStatus:  metav1.ConditionFalse,
			expectedAccStatus:  metav1.ConditionFalse,
			expectedProgStatus: metav1.ConditionFalse,
		},
		{
			name: "cross-namespace without grant",
			caRef: gatewayv1.ObjectReference{
				Group:     "",
				Kind:      "ConfigMap",
				Namespace: Ptr(gatewayv1.Namespace("other-ns")),
				Name:      "remote-ca",
			},
			configMaps: map[types.NamespacedName]*corev1.ConfigMap{
				{Namespace: "other-ns", Name: "remote-ca"}: {
					ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "remote-ca"},
					Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
				},
			},
			useGrant:           false,
			expectedRefReason:  gatewayv1.ListenerReasonRefNotPermitted,
			expectedAccReason:  gatewayv1.ListenerReasonNoValidCACertificate,
			expectedProgReason: gatewayv1.ListenerReasonNoValidCACertificate,
			expectedRefStatus:  metav1.ConditionFalse,
			expectedAccStatus:  metav1.ConditionFalse,
			expectedProgStatus: metav1.ConditionFalse,
		},
		{
			name: "cross-namespace with grant",
			caRef: gatewayv1.ObjectReference{
				Group:     "",
				Kind:      "ConfigMap",
				Namespace: Ptr(gatewayv1.Namespace("other-ns")),
				Name:      "remote-ca",
			},
			configMaps: map[types.NamespacedName]*corev1.ConfigMap{
				{Namespace: "other-ns", Name: "remote-ca"}: {
					ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "remote-ca"},
					Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
				},
			},
			useGrant:           true,
			expectedRefReason:  gatewayv1.ListenerReasonResolvedRefs,
			expectedAccReason:  gatewayv1.ListenerReasonAccepted,
			expectedProgReason: gatewayv1.ListenerReasonProgrammed,
			expectedRefStatus:  metav1.ConditionTrue,
			expectedAccStatus:  metav1.ConditionTrue,
			expectedProgStatus: metav1.ConditionTrue,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-test"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "ref-class",
					TLS: &gatewayv1.GatewayTLSConfig{
						Frontend: &gatewayv1.FrontendTLSConfig{
							Default: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{
									CACertificateRefs: []gatewayv1.ObjectReference{tc.caRef},
								},
							},
						},
					},
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: gatewayv1.HTTPSProtocolType,
							TLS: &gatewayv1.ListenerTLSConfig{
								CertificateRefs: []gatewayv1.SecretObjectReference{
									{Kind: Ptr(gatewayv1.Kind("Secret")), Name: "server-cert"},
								},
							},
						},
					},
				},
			}

			inputs := ModelInputs{
				Gateways:   []*gatewayv1.Gateway{gw},
				Secrets:    secrets,
				ConfigMaps: tc.configMaps,
			}

			if tc.useGrant {
				grant := &gatewayv1beta1.ReferenceGrant{
					ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "allow-gw"},
					Spec: gatewayv1beta1.ReferenceGrantSpec{
						From: []gatewayv1beta1.ReferenceGrantFrom{
							{
								Group:     gatewayv1.GroupName,
								Kind:      "Gateway",
								Namespace: "default",
							},
						},
						To: []gatewayv1beta1.ReferenceGrantTo{
							{
								Group: "",
								Kind:  "ConfigMap",
								Name:  Ptr(gatewayv1.ObjectName("remote-ca")),
							},
						},
					},
				}
				inputs.ReferenceGrants = map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant{
					{Namespace: grant.Namespace, Name: grant.Name}: grant,
				}
				inputs.RefValidator = mapReferenceValidator{referenceGrants: inputs.ReferenceGrants}
			}

			compiled := CompileModel(inputs)
			cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-test"}]
			if cg == nil || len(cg.EffectiveListeners) != 1 {
				t.Fatalf("expected 1 effective listener")
			}

			el := cg.EffectiveListeners[0]
			var progCond, accCond, refCond *metav1.Condition
			for i := range el.Conditions {
				switch el.Conditions[i].Type {
				case string(gatewayv1.ListenerConditionProgrammed):
					progCond = &el.Conditions[i]
				case string(gatewayv1.ListenerConditionAccepted):
					accCond = &el.Conditions[i]
				case string(gatewayv1.ListenerConditionResolvedRefs):
					refCond = &el.Conditions[i]
				}
			}

			if refCond == nil || refCond.Status != tc.expectedRefStatus || refCond.Reason != string(tc.expectedRefReason) {
				t.Errorf("ResolvedRefs condition mismatch: want Status=%v Reason=%v, got %+v", tc.expectedRefStatus, tc.expectedRefReason, refCond)
			}
			if accCond == nil || accCond.Status != tc.expectedAccStatus || accCond.Reason != string(tc.expectedAccReason) {
				t.Errorf("Accepted condition mismatch: want Status=%v Reason=%v, got %+v", tc.expectedAccStatus, tc.expectedAccReason, accCond)
			}
			if progCond == nil || progCond.Status != tc.expectedProgStatus || progCond.Reason != string(tc.expectedProgReason) {
				t.Errorf("Programmed condition mismatch: want Status=%v Reason=%v, got %+v", tc.expectedProgStatus, tc.expectedProgReason, progCond)
			}
		})
	}
}

func TestFrontendClientCertValidation_AllowInsecureFallback_ProgrammedAndServed(t *testing.T) {
	caCertPEM, _ := generateTestCertPEM(t, "ca.example.com")
	serverCertPEM, serverKeyPEM := generateTestCertPEM(t, "server.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "server-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "server-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       serverCertPEM,
				corev1.TLSPrivateKeyKey: serverKeyPEM,
			},
		},
	}
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-valid"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: []gatewayv1.ObjectReference{
								{Kind: "ConfigMap", Group: "", Name: "valid-ca"},
							},
							Mode: gatewayv1.AllowInsecureFallback,
						},
					},
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Kind: Ptr(gatewayv1.Kind("Secret")), Name: "server-cert"},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:   []*gatewayv1.Gateway{gw},
		Secrets:    secrets,
		ConfigMaps: configMaps,
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-valid"}]
	if cg == nil || len(cg.EffectiveListeners) != 1 {
		t.Fatalf("expected 1 effective listener")
	}

	el := cg.EffectiveListeners[0]
	if el.ClientValidation == nil {
		t.Fatalf("expected ClientValidation != nil")
	}
	if el.ClientValidation.Mode != gatewayv1.AllowInsecureFallback {
		t.Errorf("expected Mode %v, got %v", gatewayv1.AllowInsecureFallback, el.ClientValidation.Mode)
	}
	if len(el.ClientValidation.CACertPEMs) != 1 || string(el.ClientValidation.CACertPEMs[0]) != string(caCertPEM) {
		t.Errorf("CACertPEMs mismatch")
	}

	// Verify Programmed=True status
	var progCond *metav1.Condition
	for i := range el.Conditions {
		if el.Conditions[i].Type == string(gatewayv1.ListenerConditionProgrammed) {
			progCond = &el.Conditions[i]
		}
	}
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	// Verify compiled InternalListener
	il := el.ToInternalListener()
	if il.ClientValidation == nil {
		t.Fatalf("expected InternalListener.ClientValidation != nil")
	}
	if il.ClientValidation.Mode != gatewayv1.AllowInsecureFallback {
		t.Errorf("expected InternalListener mode %v, got %v", gatewayv1.AllowInsecureFallback, il.ClientValidation.Mode)
	}
	if len(il.ClientValidation.CACertPEMs) != 1 || string(il.ClientValidation.CACertPEMs[0]) != string(caCertPEM) {
		t.Errorf("InternalListener CACertPEMs mismatch")
	}

	// Present in proxy listeners
	proxyListeners, _ := BuildProxyConfig(compiled.GatewaysList())
	if len(proxyListeners) != 1 {
		t.Errorf("expected 1 proxy listener, got %d", len(proxyListeners))
	}
	certsMap, _ := ExtractCertificates(compiled.GatewaysList())
	if len(certsMap) != 1 {
		t.Errorf("expected 1 certificate extracted, got %d", len(certsMap))
	}

	// Verify Gateway condition InsecureFrontendValidationMode=True Reason=ConfigurationChanged
	gwCond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
	if gwCond == nil || gwCond.Status != metav1.ConditionTrue || gwCond.Reason != string(gatewayv1.GatewayReasonConfigurationChanged) {
		t.Errorf("expected Gateway InsecureFrontendValidationMode=True/ConfigurationChanged, got %+v", gwCond)
	}
}

func TestGatewayCondition_InsecureFrontendValidationMode(t *testing.T) {
	caCertPEM, _ := generateTestCertPEM(t, "ca.example.com")
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
		},
	}

	t.Run("Gateway default mode AllowInsecureFallback sets condition", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-fallback"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
								Mode: gatewayv1.AllowInsecureFallback,
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways:   []*gatewayv1.Gateway{gw},
			ConfigMaps: configMaps,
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-fallback"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayReasonConfigurationChanged) {
			t.Errorf("expected InsecureFrontendValidationMode=True/ConfigurationChanged, got %+v", cond)
		}
	})

	t.Run("Gateway per-port mode AllowInsecureFallback sets condition", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-perport-fallback"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
								Mode: gatewayv1.AllowValidOnly,
							},
						},
						PerPort: []gatewayv1.TLSPortConfig{
							{
								Port: 8443,
								TLS: gatewayv1.TLSConfig{
									Validation: &gatewayv1.FrontendTLSValidation{
										CACertificateRefs: []gatewayv1.ObjectReference{
											{Kind: "ConfigMap", Group: "", Name: "ca"},
										},
										Mode: gatewayv1.AllowInsecureFallback,
									},
								},
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "https-443", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
					{Name: "https-8443", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways:   []*gatewayv1.Gateway{gw},
			ConfigMaps: configMaps,
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-perport-fallback"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayReasonConfigurationChanged) {
			t.Errorf("expected InsecureFrontendValidationMode=True/ConfigurationChanged, got %+v", cond)
		}
	})

	t.Run("Gateway AllowValidOnly condition is absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-valid-only"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
								Mode: gatewayv1.AllowValidOnly,
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways:   []*gatewayv1.Gateway{gw},
			ConfigMaps: configMaps,
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-valid-only"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond != nil {
			t.Errorf("expected InsecureFrontendValidationMode to be absent, got %+v", cond)
		}
	})

	t.Run("Gateway unspecified mode defaults to AllowValidOnly and condition is absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-default-mode"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways:   []*gatewayv1.Gateway{gw},
			ConfigMaps: configMaps,
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-default-mode"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond != nil {
			t.Errorf("expected InsecureFrontendValidationMode to be absent, got %+v", cond)
		}
	})

	t.Run("Gateway without frontend validation condition is absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-no-validation"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				Listeners: []gatewayv1.Listener{
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways: []*gatewayv1.Gateway{gw},
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-no-validation"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond != nil {
			t.Errorf("expected InsecureFrontendValidationMode to be absent, got %+v", cond)
		}
	})

	t.Run("Gateway with HTTP listeners only condition is absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-http-only"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
								Mode: gatewayv1.AllowInsecureFallback,
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		}

		compiled := CompileModel(ModelInputs{
			Gateways:   []*gatewayv1.Gateway{gw},
			ConfigMaps: configMaps,
		})
		cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-http-only"}]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		cond := findCondition(cg.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond != nil {
			t.Errorf("expected InsecureFrontendValidationMode to be absent for HTTP-only listeners, got %+v", cond)
		}
	})

	t.Run("Transition: condition present on AllowInsecureFallback and removed when changed to AllowValidOnly", func(t *testing.T) {
		st := NewState()
		st.SetControllerName("example.net/gateway-controller")

		gc := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
		}
		st.UpsertGatewayClass(gc)

		gwKey := types.NamespacedName{Namespace: "default", Name: "gw-transition"}
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-transition"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "ref-class",
				TLS: &gatewayv1.GatewayTLSConfig{
					Frontend: &gatewayv1.FrontendTLSConfig{
						Default: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{
									{Kind: "ConfigMap", Group: "", Name: "ca"},
								},
								Mode: gatewayv1.AllowInsecureFallback,
							},
						},
					},
				},
				Listeners: []gatewayv1.Listener{
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		}

		st.UpsertGateway(gw)
		st.UpsertConfigMap(configMaps[types.NamespacedName{Namespace: "default", Name: "ca"}])
		st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "10.0.0.1"}})
		st.SetGatewayReadiness(gwKey, GatewayReadiness{Ready: true})
		st.Recompute()

		status, ok := st.GetDesiredGatewayStatus(gwKey)
		if !ok {
			t.Fatalf("expected desired status for gateway")
		}
		cond := findCondition(status.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayReasonConfigurationChanged) {
			t.Fatalf("expected InsecureFrontendValidationMode=True/ConfigurationChanged initially, got %+v", cond)
		}

		// Update Gateway spec to AllowValidOnly
		gwUpdated := gw.DeepCopy()
		gwUpdated.Spec.TLS.Frontend.Default.Validation.Mode = gatewayv1.AllowValidOnly
		st.UpsertGateway(gwUpdated)
		st.Recompute()

		statusUpdated, ok := st.GetDesiredGatewayStatus(gwKey)
		if !ok {
			t.Fatalf("expected desired status for gateway after update")
		}
		condUpdated := findCondition(statusUpdated.Conditions, string(gatewayv1.GatewayConditionInsecureFrontendValidationMode))
		if condUpdated != nil {
			t.Errorf("expected InsecureFrontendValidationMode to be removed after change to AllowValidOnly, got %+v", condUpdated)
		}
	})
}

func TestFrontendClientCertValidation_AllowValidOnly_ProgrammedAndServed(t *testing.T) {
	caCertPEM, _ := generateTestCertPEM(t, "ca.example.com")
	serverCertPEM, serverKeyPEM := generateTestCertPEM(t, "server.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "server-cert"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "server-cert"},
			Data: map[string][]byte{
				corev1.TLSCertKey:       serverCertPEM,
				corev1.TLSPrivateKeyKey: serverKeyPEM,
			},
		},
	}
	configMaps := map[types.NamespacedName]*corev1.ConfigMap{
		{Namespace: "default", Name: "valid-ca"}: {
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-ca"},
			Data:       map[string]string{ConfigMapCACertKey: string(caCertPEM)},
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-valid-only"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: []gatewayv1.ObjectReference{
								{Kind: "ConfigMap", Group: "", Name: "valid-ca"},
							},
							Mode: gatewayv1.AllowValidOnly,
						},
					},
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Kind: Ptr(gatewayv1.Kind("Secret")), Name: "server-cert"},
						},
					},
				},
			},
		},
	}

	compiled := CompileModel(ModelInputs{
		Gateways:   []*gatewayv1.Gateway{gw},
		Secrets:    secrets,
		ConfigMaps: configMaps,
	})

	cg := compiled.Gateways[types.NamespacedName{Namespace: "default", Name: "gw-valid-only"}]
	if cg == nil || len(cg.EffectiveListeners) != 1 {
		t.Fatalf("expected 1 effective listener")
	}

	el := cg.EffectiveListeners[0]
	if el.ClientValidation == nil {
		t.Fatalf("expected ClientValidation != nil")
	}
	if el.ClientValidation.Mode != gatewayv1.AllowValidOnly {
		t.Errorf("expected Mode %v, got %v", gatewayv1.AllowValidOnly, el.ClientValidation.Mode)
	}

	// Verify Programmed=True
	var progCond *metav1.Condition
	for i := range el.Conditions {
		if el.Conditions[i].Type == string(gatewayv1.ListenerConditionProgrammed) {
			progCond = &el.Conditions[i]
		}
	}
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	// Verify compiled InternalListener
	il := el.ToInternalListener()
	if il.ClientValidation == nil {
		t.Fatalf("expected InternalListener.ClientValidation != nil")
	}
	if il.ClientValidation.Mode != gatewayv1.AllowValidOnly {
		t.Errorf("expected InternalListener mode %v, got %v", gatewayv1.AllowValidOnly, il.ClientValidation.Mode)
	}

	// Present in proxy listeners
	proxyListeners, _ := BuildProxyConfig(compiled.GatewaysList())
	if len(proxyListeners) != 1 {
		t.Errorf("expected 1 proxy listener, got %d", len(proxyListeners))
	}
	certsMap, _ := ExtractCertificates(compiled.GatewaysList())
	if len(certsMap) != 1 {
		t.Errorf("expected 1 certificate extracted, got %d", len(certsMap))
	}
}

func TestHTTPListener_AllInOneModeConflict(t *testing.T) {
	now := metav1.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw1-older",
			Namespace:         "default",
			CreationTimestamp: olderTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-shared",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
				},
			},
		},
	}

	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw2-newer",
			Namespace:         "default",
			CreationTimestamp: newerTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-shared",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	// 1. With AllInOneMode: true
	inputsAllInOne := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw2, gw1}, // pass in reverse order to ensure sorting works
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputsAllInOne := ComputeOutputs(inputsAllInOne)

	// First gateway (older) wins: Programmed=True
	gw1Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw1.Name}]
	var gw1ProgCond *metav1.Condition
	for _, c := range gw1Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw1ProgCond = &c
			break
		}
	}
	if gw1ProgCond == nil || gw1ProgCond.Status != metav1.ConditionTrue {
		t.Errorf("gw1 (older) expected Programmed=True, got %+v", gw1ProgCond)
	}

	// Second gateway (newer) loses: Programmed=False, reason HostnameConflict
	gw2Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2ProgCond *metav1.Condition
	for _, c := range gw2Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2ProgCond = &c
			break
		}
	}
	if gw2ProgCond == nil || gw2ProgCond.Status != metav1.ConditionFalse || gw2ProgCond.Reason != string(gatewayv1.ListenerReasonHostnameConflict) {
		t.Errorf("gw2 (newer) expected Programmed=False HostnameConflict, got %+v", gw2ProgCond)
	}
	if gw2ProgCond != nil && (!strings.Contains(gw2ProgCond.Message, "default/gw1-older") || !strings.Contains(gw2ProgCond.Message, "example.com")) {
		t.Errorf("gw2 expected message naming winning Gateway gw1-older and hostname, got %q", gw2ProgCond.Message)
	}

	// Proxy listeners in all-in-one should only include the first (gw1) listener
	if len(outputsAllInOne.ProxyListeners) != 1 || outputsAllInOne.ProxyListeners[0].GatewayName.String() != "default/gw1-older" {
		t.Errorf("expected only gw1 proxy listener, got %+v", outputsAllInOne.ProxyListeners)
	}

	// 2. With AllInOneMode: false (singlepod mode)
	inputsSinglePod := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw1, gw2},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ControllerName: "test-controller",
		AllInOneMode:   false,
	}

	outputsSinglePod := ComputeOutputs(inputsSinglePod)
	gw2SinglePodStatus := outputsSinglePod.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2SinglePodProg *metav1.Condition
	for _, c := range gw2SinglePodStatus.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2SinglePodProg = &c
			break
		}
	}
	if gw2SinglePodProg == nil || gw2SinglePodProg.Status != metav1.ConditionTrue {
		t.Errorf("in singlepod mode, gw2 expected Programmed=True, got %+v", gw2SinglePodProg)
	}
	if len(outputsSinglePod.ProxyListeners) != 2 {
		t.Errorf("in singlepod mode, expected 2 proxy listeners, got %d", len(outputsSinglePod.ProxyListeners))
	}
}

func TestHTTPListener_AllInOneModeConflict_Hostnameless(t *testing.T) {
	now := metav1.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw1-older",
			Namespace:         "default",
			CreationTimestamp: olderTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-catchall",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw2-newer",
			Namespace:         "default",
			CreationTimestamp: newerTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-catchall",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	inputsAllInOne := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw2, gw1},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputsAllInOne := ComputeOutputs(inputsAllInOne)

	// Older wins: Programmed=True
	gw1Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw1.Name}]
	var gw1ProgCond *metav1.Condition
	for _, c := range gw1Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw1ProgCond = &c
			break
		}
	}
	if gw1ProgCond == nil || gw1ProgCond.Status != metav1.ConditionTrue {
		t.Errorf("gw1 expected Programmed=True, got %+v", gw1ProgCond)
	}

	// Newer loses: Programmed=False, reason PortUnavailable
	gw2Status := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2ProgCond *metav1.Condition
	for _, c := range gw2Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2ProgCond = &c
			break
		}
	}
	if gw2ProgCond == nil || gw2ProgCond.Status != metav1.ConditionFalse || gw2ProgCond.Reason != string(gatewayv1.ListenerReasonPortUnavailable) {
		t.Errorf("gw2 expected Programmed=False PortUnavailable, got %+v", gw2ProgCond)
	}
	if gw2ProgCond != nil && !strings.Contains(gw2ProgCond.Message, "default/gw1-older") {
		t.Errorf("gw2 expected message naming winning Gateway gw1-older, got %q", gw2ProgCond.Message)
	}

	if len(outputsAllInOne.ProxyListeners) != 1 || outputsAllInOne.ProxyListeners[0].GatewayName.String() != "default/gw1-older" {
		t.Errorf("expected only gw1 proxy listener, got %+v", outputsAllInOne.ProxyListeners)
	}
}

func TestHTTPListener_AllInOneModeConflict_WildcardVsExact(t *testing.T) {
	now := metav1.Now()
	t1 := metav1.NewTime(now.Add(-20 * time.Minute))
	t2 := metav1.NewTime(now.Add(-15 * time.Minute))
	t3 := metav1.NewTime(now.Add(-10 * time.Minute))
	t4 := metav1.NewTime(now.Add(-5 * time.Minute))

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw1-wildcard",
			Namespace:         "default",
			CreationTimestamp: t1,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-wildcard",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
				},
			},
		},
	}

	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw2-exact",
			Namespace:         "default",
			CreationTimestamp: t2,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-exact",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
				},
			},
		},
	}

	gw3 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw3-wildcard-dup",
			Namespace:         "default",
			CreationTimestamp: t3,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-wildcard-dup",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
				},
			},
		},
	}

	gw4 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw4-exact-dup",
			Namespace:         "default",
			CreationTimestamp: t4,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-exact-dup",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw4, gw3, gw2, gw1},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputs := ComputeOutputs(inputs)

	getProgCond := func(gwName string) *metav1.Condition {
		status := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gwName}]
		for _, c := range status.Listeners[0].Conditions {
			if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
				return &c
			}
		}
		return nil
	}

	// gw1 (*.example.com) and gw2 (foo.example.com) do NOT conflict with each other
	gw1Prog := getProgCond("gw1-wildcard")
	if gw1Prog == nil || gw1Prog.Status != metav1.ConditionTrue {
		t.Errorf("gw1 expected Programmed=True, got %+v", gw1Prog)
	}

	gw2Prog := getProgCond("gw2-exact")
	if gw2Prog == nil || gw2Prog.Status != metav1.ConditionTrue {
		t.Errorf("gw2 expected Programmed=True (wildcard vs exact overlap allowed), got %+v", gw2Prog)
	}

	// gw3 conflicts with gw1 (*.example.com)
	gw3Prog := getProgCond("gw3-wildcard-dup")
	if gw3Prog == nil || gw3Prog.Status != metav1.ConditionFalse || gw3Prog.Reason != string(gatewayv1.ListenerReasonHostnameConflict) {
		t.Errorf("gw3 expected Programmed=False HostnameConflict, got %+v", gw3Prog)
	}
	if gw3Prog != nil && !strings.Contains(gw3Prog.Message, "default/gw1-wildcard") {
		t.Errorf("gw3 expected message naming gw1-wildcard, got %q", gw3Prog.Message)
	}

	// gw4 conflicts with gw2 (foo.example.com)
	gw4Prog := getProgCond("gw4-exact-dup")
	if gw4Prog == nil || gw4Prog.Status != metav1.ConditionFalse || gw4Prog.Reason != string(gatewayv1.ListenerReasonHostnameConflict) {
		t.Errorf("gw4 expected Programmed=False HostnameConflict, got %+v", gw4Prog)
	}
	if gw4Prog != nil && !strings.Contains(gw4Prog.Message, "default/gw2-exact") {
		t.Errorf("gw4 expected message naming gw2-exact, got %q", gw4Prog.Message)
	}

	// Proxy listeners should contain only gw1 and gw2
	if len(outputs.ProxyListeners) != 2 {
		t.Fatalf("expected 2 proxy listeners (gw1 and gw2), got %d", len(outputs.ProxyListeners))
	}
	proxyGWs := map[string]bool{
		outputs.ProxyListeners[0].GatewayName.String(): true,
		outputs.ProxyListeners[1].GatewayName.String(): true,
	}
	if !proxyGWs["default/gw1-wildcard"] || !proxyGWs["default/gw2-exact"] {
		t.Errorf("expected proxy listeners from gw1 and gw2, got %+v", outputs.ProxyListeners)
	}
}

func TestHTTPSAndTLSListener_AllInOneModeConflict(t *testing.T) {
	now := metav1.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	certPEM, keyPEM := generateTestCertPEM(t, "secure.example.com")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "default"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw1-https",
			Namespace:         "default",
			CreationTimestamp: olderTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("secure.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "tls-secret"},
						},
					},
				},
			},
		},
	}

	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw2-tls",
			Namespace:         "default",
			CreationTimestamp: newerTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     443,
					Protocol: gatewayv1.TLSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("secure.example.com")),
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw2, gw1},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		Secrets:        map[types.NamespacedName]*corev1.Secret{{Namespace: "default", Name: "tls-secret"}: secret},
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputs := ComputeOutputs(inputs)

	gw1Status := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw1.Name}]
	var gw1ProgCond *metav1.Condition
	for _, c := range gw1Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw1ProgCond = &c
			break
		}
	}
	if gw1ProgCond == nil || gw1ProgCond.Status != metav1.ConditionTrue {
		t.Errorf("gw1 expected Programmed=True, got %+v", gw1ProgCond)
	}

	gw2Status := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw2.Name}]
	var gw2ProgCond *metav1.Condition
	for _, c := range gw2Status.Listeners[0].Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) {
			gw2ProgCond = &c
			break
		}
	}
	if gw2ProgCond == nil || gw2ProgCond.Status != metav1.ConditionFalse || gw2ProgCond.Reason != string(gatewayv1.ListenerReasonHostnameConflict) {
		t.Errorf("gw2 expected Programmed=False HostnameConflict, got %+v", gw2ProgCond)
	}
	if gw2ProgCond != nil && !strings.Contains(gw2ProgCond.Message, "default/gw1-https") {
		t.Errorf("gw2 expected message naming winning Gateway gw1-https, got %q", gw2ProgCond.Message)
	}

	if len(outputs.ProxyListeners) != 1 || outputs.ProxyListeners[0].GatewayName.String() != "default/gw1-https" {
		t.Errorf("expected only gw1 proxy listener, got %+v", outputs.ProxyListeners)
	}
}

func TestListener_OverlappingTLSConfig(t *testing.T) {
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	certPEM1, keyPEM1 := generateTestCertPEM(t, "*.example.com", "foo.example.com")
	secret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-1"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM1,
			corev1.TLSPrivateKeyKey: keyPEM1,
		},
	}
	certPEM2, keyPEM2 := generateTestCertPEM(t, "foo.example.com")
	secret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-2"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM2,
			corev1.TLSPrivateKeyKey: keyPEM2,
		},
	}

	t.Run("overlapping hostnames with same certificate: OverlappingHostnames", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-same-cert", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "wildcard",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
					{
						Name:     "exact",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			Secrets: map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "cert-1"}: secret1,
			},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		if len(gwStatus.Listeners) != 2 {
			t.Fatalf("expected 2 listener statuses, got %d", len(gwStatus.Listeners))
		}

		for _, l := range gwStatus.Listeners {
			accCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionAccepted))
			if accCond == nil || accCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected Accepted=True, got %+v", l.Name, accCond)
			}
			progCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			if progCond == nil || progCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected Programmed=True, got %+v", l.Name, progCond)
			}

			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond == nil {
				t.Fatalf("listener %s expected OverlappingTLSConfig condition, got nil", l.Name)
			}
			if overlapCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected OverlappingTLSConfig Status=True, got %s", l.Name, overlapCond.Status)
			}
			if overlapCond.Reason != string(gatewayv1.ListenerReasonOverlappingHostnames) {
				t.Errorf("listener %s expected Reason=OverlappingHostnames, got %s", l.Name, overlapCond.Reason)
			}
		}
	})

	t.Run("overlapping hostnames with differing certificates: OverlappingCertificates", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-diff-cert", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "wildcard",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
					{
						Name:     "exact",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-2"},
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			Secrets: map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "cert-1"}: secret1,
				{Namespace: "default", Name: "cert-2"}: secret2,
			},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		if len(gwStatus.Listeners) != 2 {
			t.Fatalf("expected 2 listener statuses, got %d", len(gwStatus.Listeners))
		}

		for _, l := range gwStatus.Listeners {
			accCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionAccepted))
			if accCond == nil || accCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected Accepted=True, got %+v", l.Name, accCond)
			}
			progCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			if progCond == nil || progCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected Programmed=True, got %+v", l.Name, progCond)
			}

			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond == nil {
				t.Fatalf("listener %s expected OverlappingTLSConfig condition, got nil", l.Name)
			}
			if overlapCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected OverlappingTLSConfig Status=True, got %s", l.Name, overlapCond.Status)
			}
			if overlapCond.Reason != string(gatewayv1.ListenerReasonOverlappingCertificates) {
				t.Errorf("listener %s expected Reason=OverlappingCertificates, got %s", l.Name, overlapCond.Reason)
			}
		}
	})

	t.Run("non-overlapping listeners: OverlappingTLSConfig absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-distinct", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "foo",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
					{
						Name:     "bar",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("bar.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-2"},
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			Secrets: map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "cert-1"}: secret1,
				{Namespace: "default", Name: "cert-2"}: secret2,
			},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		for _, l := range gwStatus.Listeners {
			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond != nil {
				t.Errorf("listener %s expected OverlappingTLSConfig to be absent, got %+v", l.Name, overlapCond)
			}
		}
	})

	t.Run("HTTP listeners: OverlappingTLSConfig absent", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-http", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http-wildcard",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
					},
					{
						Name:     "http-exact",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("foo.example.com")),
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		for _, l := range gwStatus.Listeners {
			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond != nil {
				t.Errorf("HTTP listener %s expected OverlappingTLSConfig to be absent, got %+v", l.Name, overlapCond)
			}
		}
	})

	t.Run("overlapping wildcard and multi-level subdomain (*.example.com and a.foo.example.com)", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-multi-level", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "wildcard",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
					{
						Name:     "subdomain",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("a.foo.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			Secrets: map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "cert-1"}: secret1,
			},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		if len(gwStatus.Listeners) != 2 {
			t.Fatalf("expected 2 listener statuses, got %d", len(gwStatus.Listeners))
		}

		for _, l := range gwStatus.Listeners {
			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond == nil {
				t.Fatalf("listener %s expected OverlappingTLSConfig condition, got nil", l.Name)
			}
			if overlapCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected OverlappingTLSConfig Status=True, got %s", l.Name, overlapCond.Status)
			}
		}
	})

	t.Run("overlapping nested wildcards (*.example.com and *.foo.example.com)", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-nested-wildcard", Generation: 1},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "reference-class",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "wildcard",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
					{
						Name:     "nested-wildcard",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("*.foo.example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{Name: "cert-1"},
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways:       []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{gc},
			Secrets: map[types.NamespacedName]*corev1.Secret{
				{Namespace: "default", Name: "cert-1"}: secret1,
			},
			ControllerName: "test-controller",
		}

		outputs := ComputeOutputs(inputs)
		gwStatus := outputs.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: gw.Name}]
		if len(gwStatus.Listeners) != 2 {
			t.Fatalf("expected 2 listener statuses, got %d", len(gwStatus.Listeners))
		}

		for _, l := range gwStatus.Listeners {
			overlapCond := FindCondition(l.Conditions, string(gatewayv1.ListenerConditionOverlappingTLSConfig))
			if overlapCond == nil {
				t.Fatalf("listener %s expected OverlappingTLSConfig condition, got nil", l.Name)
			}
			if overlapCond.Status != metav1.ConditionTrue {
				t.Errorf("listener %s expected OverlappingTLSConfig Status=True, got %s", l.Name, overlapCond.Status)
			}
		}
	})
}

func TestComputeSupportedVersionCondition(t *testing.T) {
	generation := int64(3)
	compiledV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("failed to parse compiled bundle version %q: %v", gatewayconsts.BundleVersion, err)
	}
	major := compiledV.Major()
	minor := compiledV.Minor()

	sameMinorV0 := fmt.Sprintf("v%d.%d.0", major, minor)
	sameMinorV9 := fmt.Sprintf("v%d.%d.9", major, minor)
	prevMinorV0 := fmt.Sprintf("v%d.%d.0", major, minor-1)
	prevMinorV9 := fmt.Sprintf("v%d.%d.9", major, minor-1)
	twoMinorsOlder := fmt.Sprintf("v%d.%d.0", major, minor-2)
	newerMinor := fmt.Sprintf("v%d.%d.0", major, minor+1)
	diffMajor := fmt.Sprintf("v%d.%d.0", major+1, minor)
	preRelease := fmt.Sprintf("v%d.%d.0-rc1", major, minor)
	preReleasePrev := fmt.Sprintf("v%d.%d.0-rc1", major, minor-1)
	supportedRange := fmt.Sprintf("v%d.%d.x and v%d.%d.x", major, minor-1, major, minor)

	tests := []struct {
		name            string
		bundleVersion   string
		expectedStatus  metav1.ConditionStatus
		expectedReason  gatewayv1.GatewayClassConditionReason
		expectedMessage string
	}{
		{
			name:            fmt.Sprintf("previous minor version %s", prevMinorV0),
			bundleVersion:   prevMinorV0,
			expectedStatus:  metav1.ConditionTrue,
			expectedReason:  gatewayv1.GatewayClassReasonSupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is supported", prevMinorV0),
		},
		{
			name:            fmt.Sprintf("previous minor higher patch %s", prevMinorV9),
			bundleVersion:   prevMinorV9,
			expectedStatus:  metav1.ConditionTrue,
			expectedReason:  gatewayv1.GatewayClassReasonSupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is supported", prevMinorV9),
		},
		{
			name:            fmt.Sprintf("same minor version %s", sameMinorV0),
			bundleVersion:   sameMinorV0,
			expectedStatus:  metav1.ConditionTrue,
			expectedReason:  gatewayv1.GatewayClassReasonSupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is supported", sameMinorV0),
		},
		{
			name:            fmt.Sprintf("matching version %s", gatewayconsts.BundleVersion),
			bundleVersion:   gatewayconsts.BundleVersion,
			expectedStatus:  metav1.ConditionTrue,
			expectedReason:  gatewayv1.GatewayClassReasonSupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is supported", gatewayconsts.BundleVersion),
		},
		{
			name:            fmt.Sprintf("same minor higher patch %s", sameMinorV9),
			bundleVersion:   sameMinorV9,
			expectedStatus:  metav1.ConditionTrue,
			expectedReason:  gatewayv1.GatewayClassReasonSupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is supported", sameMinorV9),
		},
		{
			name:            fmt.Sprintf("two minors older %s", twoMinorsOlder),
			bundleVersion:   twoMinorsOlder,
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", twoMinorsOlder, supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            fmt.Sprintf("newer minor %s", newerMinor),
			bundleVersion:   newerMinor,
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", newerMinor, supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            "garbage version",
			bundleVersion:   "garbage",
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", "garbage", supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            "empty version",
			bundleVersion:   "",
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", "", supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            fmt.Sprintf("pre-release version %s", preRelease),
			bundleVersion:   preRelease,
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", preRelease, supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            fmt.Sprintf("previous minor pre-release version %s", preReleasePrev),
			bundleVersion:   preReleasePrev,
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", preReleasePrev, supportedRange, gatewayconsts.BundleVersion),
		},
		{
			name:            fmt.Sprintf("different major %s", diffMajor),
			bundleVersion:   diffMajor,
			expectedStatus:  metav1.ConditionFalse,
			expectedReason:  gatewayv1.GatewayClassReasonUnsupportedVersion,
			expectedMessage: fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", diffMajor, supportedRange, gatewayconsts.BundleVersion),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cond := ComputeSupportedVersionCondition(tc.bundleVersion, generation)
			if cond.Type != string(gatewayv1.GatewayClassConditionStatusSupportedVersion) {
				t.Errorf("expected Type=%s, got %s", gatewayv1.GatewayClassConditionStatusSupportedVersion, cond.Type)
			}
			if cond.Status != tc.expectedStatus {
				t.Errorf("expected Status=%s, got %s", tc.expectedStatus, cond.Status)
			}
			if cond.Reason != string(tc.expectedReason) {
				t.Errorf("expected Reason=%s, got %s", tc.expectedReason, cond.Reason)
			}
			if cond.ObservedGeneration != generation {
				t.Errorf("expected ObservedGeneration=%d, got %d", generation, cond.ObservedGeneration)
			}
			if cond.Message != tc.expectedMessage {
				t.Errorf("expected Message=%q, got %q", tc.expectedMessage, cond.Message)
			}
		})
	}
}

func TestUnsupportedBundleVersionMessage(t *testing.T) {
	t.Run("parsed compiled version derives minor range", func(t *testing.T) {
		msg := unsupportedBundleVersionMessage("v9.9.0", "v1.2.3")
		expected := `Gateway API CRD bundle-version "v9.9.0" is not supported (controller supports v1.1.x and v1.2.x, built against v1.2.3)`
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("parsed compiled version with minor 0", func(t *testing.T) {
		msg := unsupportedBundleVersionMessage("v9.9.0", "v1.0.0")
		expected := `Gateway API CRD bundle-version "v9.9.0" is not supported (controller supports v1.0.x, built against v1.0.0)`
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})

	t.Run("unparsable compiled version falls back to exact version", func(t *testing.T) {
		msg := unsupportedBundleVersionMessage("v9.9.0", "invalid-version")
		expected := `Gateway API CRD bundle-version "v9.9.0" is not supported (controller supports invalid-version)`
		if msg != expected {
			t.Errorf("expected %q, got %q", expected, msg)
		}
	})
}

func TestGatewayClassStatus_SupportedVersion(t *testing.T) {
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "my-class", Generation: 2},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	compiledV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("failed to parse compiled bundle version %q: %v", gatewayconsts.BundleVersion, err)
	}
	major := compiledV.Major()
	minor := compiledV.Minor()

	sameMinorV0 := fmt.Sprintf("v%d.%d.0", major, minor)
	sameMinorV9 := fmt.Sprintf("v%d.%d.9", major, minor)
	prevMinorV0 := fmt.Sprintf("v%d.%d.0", major, minor-1)
	prevMinorV9 := fmt.Sprintf("v%d.%d.9", major, minor-1)
	twoMinorsOlder := fmt.Sprintf("v%d.%d.0", major, minor-2)
	newerMinor := fmt.Sprintf("v%d.%d.0", major, minor+1)
	preRelease := fmt.Sprintf("v%d.%d.0-rc1", major, minor)
	preReleasePrev := fmt.Sprintf("v%d.%d.0-rc1", major, minor-1)
	supportedRange := fmt.Sprintf("v%d.%d.x and v%d.%d.x", major, minor-1, major, minor)

	for _, v := range []string{prevMinorV0, prevMinorV9, sameMinorV0, gatewayconsts.BundleVersion, sameMinorV9} {
		t.Run(fmt.Sprintf("supported version %s yields SupportedVersion=True", v), func(t *testing.T) {
			ver := v
			status := ComputeDesiredGatewayClassStatus(gc, "test-controller", &ver)
			cond := FindCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
			if cond == nil {
				t.Fatalf("expected SupportedVersion condition, got nil")
			}
			if cond.Status != metav1.ConditionTrue {
				t.Errorf("expected Status=True, got %s", cond.Status)
			}
			if cond.Reason != string(gatewayv1.GatewayClassReasonSupportedVersion) {
				t.Errorf("expected Reason=SupportedVersion, got %s", cond.Reason)
			}
			if cond.ObservedGeneration != 2 {
				t.Errorf("expected ObservedGeneration=2, got %d", cond.ObservedGeneration)
			}
		})
	}

	for _, v := range []string{twoMinorsOlder, newerMinor, "garbage", preRelease, preReleasePrev} {
		t.Run(fmt.Sprintf("unsupported version %s yields SupportedVersion=False", v), func(t *testing.T) {
			ver := v
			status := ComputeDesiredGatewayClassStatus(gc, "test-controller", &ver)
			cond := FindCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
			if cond == nil {
				t.Fatalf("expected SupportedVersion condition, got nil")
			}
			if cond.Status != metav1.ConditionFalse {
				t.Errorf("expected Status=False, got %s", cond.Status)
			}
			if cond.Reason != string(gatewayv1.GatewayClassReasonUnsupportedVersion) {
				t.Errorf("expected Reason=UnsupportedVersion, got %s", cond.Reason)
			}
			if cond.ObservedGeneration != 2 {
				t.Errorf("expected ObservedGeneration=2, got %d", cond.ObservedGeneration)
			}
			expectedMsg := fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", ver, supportedRange, gatewayconsts.BundleVersion)
			if cond.Message != expectedMsg {
				t.Errorf("expected Message=%q, got %q", expectedMsg, cond.Message)
			}
		})
	}

	t.Run("nil version: SupportedVersion absent", func(t *testing.T) {
		status := ComputeDesiredGatewayClassStatus(gc, "test-controller", nil)
		cond := FindCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond != nil {
			t.Errorf("expected SupportedVersion condition to be absent, got %+v", cond)
		}
	})

	t.Run("empty version: SupportedVersion absent", func(t *testing.T) {
		empty := ""
		status := ComputeDesiredGatewayClassStatus(gc, "test-controller", &empty)
		cond := FindCondition(status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond != nil {
			t.Errorf("expected SupportedVersion condition to be absent, got %+v", cond)
		}
	})
}

func TestGateway_AllInOneMode_RejectsListenerParameters(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw-params",
		},
		Data: map[string]string{
			"allowedSourceCIDRs": "35.191.0.0/16",
			"proxyProtocol":      "enabled",
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: "",
					Kind:  "ConfigMap",
					Name:  "gw-params",
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "reference-class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	// 1. In all-in-one mode: must reject with Accepted=False, Reason=InvalidParameters
	inputsAllInOne := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ConfigMaps:     map[types.NamespacedName]*corev1.ConfigMap{{Namespace: "default", Name: "gw-params"}: cm},
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputsAllInOne := ComputeOutputs(inputsAllInOne)
	gwStatusAllInOne := outputsAllInOne.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "my-gw"}]
	accCond := FindCondition(gwStatusAllInOne.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if accCond == nil || accCond.Status != metav1.ConditionFalse || accCond.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
		t.Errorf("in all-in-one mode, expected Accepted=False with InvalidParameters, got %+v", accCond)
	}

	// 2. In singlepod mode (AllInOneMode: false): must accept
	inputsSinglepod := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gw},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		ConfigMaps:     map[types.NamespacedName]*corev1.ConfigMap{{Namespace: "default", Name: "gw-params"}: cm},
		ControllerName: "test-controller",
		AllInOneMode:   false,
	}

	outputsSinglepod := ComputeOutputs(inputsSinglepod)
	gwStatusSinglepod := outputsSinglepod.GatewayStatuses[types.NamespacedName{Namespace: "default", Name: "my-gw"}]
	accCondSinglepod := FindCondition(gwStatusSinglepod.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if accCondSinglepod == nil || accCondSinglepod.Status != metav1.ConditionTrue {
		t.Errorf("in singlepod mode, expected Accepted=True, got %+v", accCondSinglepod)
	}
}

type fakeStaticCertSource struct {
	result CertificateResult
	err    error
}

func (f *fakeStaticCertSource) ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (CertificateResult, error) {
	return f.result, f.err
}

func TestCompileModel_CertificateSource(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	certPEM, keyPEM := generateTestCertPEM(t, "example.com")
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse test cert: %v", err)
	}

	t.Run("resolved certificate", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "default",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							Options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
								gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways: []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{
				{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			},
			CertificateSources: map[string]CertificateSource{
				"test-source": &fakeStaticCertSource{
					result: CertificateResult{
						Certificates: []*tls.Certificate{&tlsCert},
					},
				},
			},
		}

		outputs := ComputeOutputs(inputs)
		cg := outputs.CompiledGateways[gwKey]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		if len(cg.EffectiveListeners) != 1 {
			t.Fatalf("expected 1 effective listener, got %d", len(cg.EffectiveListeners))
		}
		el := cg.EffectiveListeners[0]
		if !el.IsAccepted() {
			t.Errorf("expected listener to be accepted")
		}
		if !el.IsProgrammed() {
			t.Errorf("expected listener to be programmed")
		}
		refCond := FindCondition(el.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if refCond == nil || refCond.Status != metav1.ConditionTrue || refCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
			t.Errorf("expected ResolvedRefs=True/ResolvedRefs, got %+v", refCond)
		}

		certsMap, defaultCert := ExtractCertificates([]*CompiledGateway{cg})
		if certsMap["example.com"] == nil {
			t.Errorf("expected certsMap[example.com] to be populated")
		}
		if defaultCert == nil {
			t.Errorf("expected defaultCert to be populated")
		}
	})

	t.Run("pending certificate", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-gw"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "default",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: Ptr(gatewayv1.Hostname("example.com")),
						TLS: &gatewayv1.ListenerTLSConfig{
							Options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
								gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
							},
						},
					},
				},
			},
		}

		inputs := ModelInputs{
			Gateways: []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{
				{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			},
			CertificateSources: map[string]CertificateSource{
				"test-source": &fakeStaticCertSource{
					result: CertificateResult{
						Pending: true,
					},
				},
			},
		}

		outputs := ComputeOutputs(inputs)
		cg := outputs.CompiledGateways[gwKey]
		if cg == nil {
			t.Fatalf("expected compiled gateway")
		}
		el := cg.EffectiveListeners[0]
		if !el.IsAccepted() {
			t.Errorf("expected listener to be accepted when pending")
		}
		if el.IsProgrammed() {
			t.Errorf("expected listener to NOT be programmed when pending")
		}
		refCond := FindCondition(el.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonPending) {
			t.Errorf("expected ResolvedRefs=False/Pending, got %+v", refCond)
		}
		progCond := FindCondition(el.Conditions, string(gatewayv1.ListenerConditionProgrammed))
		if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonPending) {
			t.Errorf("expected Programmed=False/Pending, got %+v", progCond)
		}
	})
}

func TestCompileModel_ValidatorHooks(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "test-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "default",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("example.com")),
				},
			},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "test-gw",
					},
				},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
		},
	}

	t.Run("ListenerValidator rejects listener", func(t *testing.T) {
		inputs := ModelInputs{
			Gateways: []*gatewayv1.Gateway{gw},
			GatewayClasses: []*gatewayv1.GatewayClass{
				{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			},
			HTTPRoutes: []*gatewayv1.HTTPRoute{route},
			ListenerValidator: func(spec ListenerSpec, owner ListenerOwner, g *gatewayv1.Gateway) []metav1.Condition {
				return []metav1.Condition{
					NewCondition(
						string(gatewayv1.ListenerConditionAccepted),
						metav1.ConditionFalse,
						string(gatewayv1.ListenerReasonUnsupportedValue),
						"hostname not allowed",
						g.Generation,
					),
				}
			},
		}

		outputs := ComputeOutputs(inputs)
		cg := outputs.CompiledGateways[gwKey]
		if cg == nil || len(cg.EffectiveListeners) != 1 {
			t.Fatalf("expected compiled gateway with 1 listener")
		}
		el := cg.EffectiveListeners[0]
		if el.IsAccepted() {
			t.Errorf("expected listener IsAccepted to be false")
		}
		accCond := FindCondition(el.Conditions, string(gatewayv1.ListenerConditionAccepted))
		if accCond == nil || accCond.Status != metav1.ConditionFalse || accCond.Reason != string(gatewayv1.ListenerReasonUnsupportedValue) {
			t.Errorf("expected Accepted=False/UnsupportedValue, got %+v", accCond)
		}

		// Proxy config should not serve the rejected listener
		proxyListeners, _ := BuildProxyConfig([]*CompiledGateway{cg})
		if len(proxyListeners) != 0 {
			t.Errorf("expected 0 proxy listeners for unaccepted listener, got %d", len(proxyListeners))
		}
	})
}

func TestRoute_HostnameIntersectionPrecedence_HTTPRoute(t *testing.T) {
	now := time.Now()
	tOlder := metav1.NewTime(now.Add(-10 * time.Minute))
	tNewer := metav1.NewTime(now.Add(-5 * time.Minute))
	port8080 := gatewayv1.PortNumber(8080)
	pathPrefix := gatewayv1.PathMatchPathPrefix
	headerExact := gatewayv1.HeaderMatchExact

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "backend-older"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-older", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		{Namespace: "default", Name: "backend-newer"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "backend-newer", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	tests := []struct {
		name             string
		listenerHostname string
		olderHostnames   []gatewayv1.Hostname
		newerHostnames   []gatewayv1.Hostname
		olderMatches     []gatewayv1.HTTPRouteMatch
		newerMatches     []gatewayv1.HTTPRouteMatch
		requestURL       string
		requestHeaders   map[string]string
		wantBackend      string
	}{
		{
			name:             "Exact hostname beats older wildcard route attached to same listener",
			listenerHostname: "abc.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.example.com"},
			newerHostnames:   []gatewayv1.Hostname{"abc.example.com"},
			requestURL:       "http://abc.example.com/",
			wantBackend:      "backend-newer.default.svc.cluster.local",
		},
		{
			name:             "More specific wildcard route beats older less specific wildcard route",
			listenerHostname: "*.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.com"},
			newerHostnames:   []gatewayv1.Hostname{"*.example.com"},
			requestURL:       "http://abc.example.com/",
			wantBackend:      "backend-newer.default.svc.cluster.local",
		},
		{
			name:             "Exact hostname route beats older wildcard route even with shorter path",
			listenerHostname: "abc.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.example.com"},
			newerHostnames:   []gatewayv1.Hostname{"abc.example.com"},
			olderMatches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: Ptr("/path/prefix")}},
			},
			newerMatches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: Ptr("/path")}},
			},
			requestURL:  "http://abc.example.com/path/prefix/longer",
			wantBackend: "backend-newer.default.svc.cluster.local",
		},
		{
			name:             "Unmatched traffic falls back to older wildcard route",
			listenerHostname: "abc.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.example.com"},
			newerHostnames:   []gatewayv1.Hostname{"abc.example.com"},
			olderMatches: []gatewayv1.HTTPRouteMatch{
				{
					Path:    &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: Ptr("/path/prefix")},
					Headers: []gatewayv1.HTTPHeaderMatch{{Type: &headerExact, Name: "Header-B", Value: "B"}},
				},
			},
			newerMatches: []gatewayv1.HTTPRouteMatch{
				{
					Path:    &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: Ptr("/path")},
					Headers: []gatewayv1.HTTPHeaderMatch{{Type: &headerExact, Name: "Header-A", Value: "A"}},
				},
			},
			requestURL:     "http://abc.example.com/path/prefix/longer",
			requestHeaders: map[string]string{"Header-B": "B"},
			wantBackend:    "backend-older.default.svc.cluster.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "ref-class",
					Listeners: []gatewayv1.Listener{
						{
							Name:     "http",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
							Hostname: Ptr(gatewayv1.Hostname(tt.listenerHostname)),
						},
					},
				},
			}

			olderRoute := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "route-older",
					Namespace:         "default",
					CreationTimestamp: tOlder,
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
					Hostnames: tt.olderHostnames,
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Matches: tt.olderMatches,
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend-older", Port: &port8080}}},
							},
						},
					},
				},
			}

			newerRoute := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "route-newer",
					Namespace:         "default",
					CreationTimestamp: tNewer,
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
					Hostnames: tt.newerHostnames,
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Matches: tt.newerMatches,
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend-newer", Port: &port8080}}},
							},
						},
					},
				},
			}

			outputs := ComputeOutputs(ModelInputs{
				Gateways:       []*gatewayv1.Gateway{gw},
				GatewayClasses: []*gatewayv1.GatewayClass{gc},
				HTTPRoutes:     []*gatewayv1.HTTPRoute{olderRoute, newerRoute},
				Services:       services,
				ControllerName: "example.net/gateway-controller",
			})

			req, err := http.NewRequest("GET", tt.requestURL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}
			listeners, _ := MatchListeners(outputs.ProxyListeners, req.Host)
			if len(listeners) == 0 {
				t.Fatalf("expected matching listener for host %q", req.Host)
			}
			rule, _ := MatchRoute(listeners[0].Routes, req)
			if rule == nil || len(rule.Backends) == 0 {
				t.Fatalf("expected matched rule, got nil")
			}
			if rule.Backends[0].Host != tt.wantBackend {
				t.Errorf("expected backend %q, got %q", tt.wantBackend, rule.Backends[0].Host)
			}
		})
	}
}

func TestRoute_HostnameIntersectionPrecedence_GRPCRoute(t *testing.T) {
	now := time.Now()
	tOlder := metav1.NewTime(now.Add(-10 * time.Minute))
	tNewer := metav1.NewTime(now.Add(-5 * time.Minute))
	port8080 := gatewayv1.PortNumber(8080)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.net/gateway-controller"},
	}

	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "default", Name: "grpc-backend-older"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "grpc-backend-older", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
		{Namespace: "default", Name: "grpc-backend-newer"}: {
			ObjectMeta: metav1.ObjectMeta{Name: "grpc-backend-newer", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		},
	}

	tests := []struct {
		name             string
		listenerHostname string
		olderHostnames   []gatewayv1.Hostname
		newerHostnames   []gatewayv1.Hostname
		wantBackend      string
	}{
		{
			name:             "GRPCRoute exact hostname beats older wildcard route",
			listenerHostname: "abc.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.example.com"},
			newerHostnames:   []gatewayv1.Hostname{"abc.example.com"},
			wantBackend:      "grpc-backend-newer.default.svc.cluster.local",
		},
		{
			name:             "GRPCRoute more specific wildcard route beats older less specific wildcard route",
			listenerHostname: "*.example.com",
			olderHostnames:   []gatewayv1.Hostname{"*.com"},
			newerHostnames:   []gatewayv1.Hostname{"*.example.com"},
			wantBackend:      "grpc-backend-newer.default.svc.cluster.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-grpc", Namespace: "default"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "ref-class",
					Listeners: []gatewayv1.Listener{
						{
							Name:     "grpc-listener",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
							Hostname: Ptr(gatewayv1.Hostname(tt.listenerHostname)),
						},
					},
				},
			}

			olderRoute := &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "grpcroute-older",
					Namespace:         "default",
					CreationTimestamp: tOlder,
				},
				Spec: gatewayv1.GRPCRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw-grpc"}},
					},
					Hostnames: tt.olderHostnames,
					Rules: []gatewayv1.GRPCRouteRule{
						{
							BackendRefs: []gatewayv1.GRPCBackendRef{
								{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "grpc-backend-older", Port: &port8080}}},
							},
						},
					},
				},
			}

			newerRoute := &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "grpcroute-newer",
					Namespace:         "default",
					CreationTimestamp: tNewer,
				},
				Spec: gatewayv1.GRPCRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw-grpc"}},
					},
					Hostnames: tt.newerHostnames,
					Rules: []gatewayv1.GRPCRouteRule{
						{
							BackendRefs: []gatewayv1.GRPCBackendRef{
								{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "grpc-backend-newer", Port: &port8080}}},
							},
						},
					},
				},
			}

			outputs := ComputeOutputs(ModelInputs{
				Gateways:       []*gatewayv1.Gateway{gw},
				GatewayClasses: []*gatewayv1.GatewayClass{gc},
				GRPCRoutes:     []*gatewayv1.GRPCRoute{olderRoute, newerRoute},
				Services:       services,
				ControllerName: "example.net/gateway-controller",
			})

			req, err := http.NewRequest("POST", "http://abc.example.com/echo.EchoService/Echo", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			listeners, _ := MatchListeners(outputs.ProxyListeners, "abc.example.com")
			if len(listeners) == 0 {
				t.Fatalf("expected matching listener")
			}
			rule, _ := MatchRoute(listeners[0].Routes, req)
			if rule == nil || len(rule.Backends) == 0 {
				t.Fatalf("expected matched rule, got nil")
			}
			if rule.Backends[0].Host != tt.wantBackend {
				t.Errorf("expected backend %q, got %q", tt.wantBackend, rule.Backends[0].Host)
			}
		})
	}
}

func TestComputeDesiredRouteStatus_NoParentRefs(t *testing.T) {
	httpRoute := &gatewayv1.HTTPRoute{}
	tlsRoute := &gatewayv1.TLSRoute{}
	grpcRoute := &gatewayv1.GRPCRoute{}
	tcpRoute := &gatewayv1.TCPRoute{}
	udpRoute := &gatewayv1.UDPRoute{}

	// Compiled routes with nil RouteState should not panic when ParentRefs is empty.
	if s := ComputeDesiredHTTPRouteStatus(httpRoute, &CompiledRoute{}, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredTLSRouteStatus(tlsRoute, &CompiledTLSRoute{}, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredGRPCRouteStatus(grpcRoute, &CompiledGRPCRoute{}, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredTCPRouteStatus(tcpRoute, &CompiledTCPRoute{}, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredUDPRouteStatus(udpRoute, &CompiledUDPRoute{}, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}

	// Nil compiled routes should also return empty status.
	if s := ComputeDesiredHTTPRouteStatus(httpRoute, nil, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredTLSRouteStatus(tlsRoute, nil, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredGRPCRouteStatus(grpcRoute, nil, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredTCPRouteStatus(tcpRoute, nil, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
	if s := ComputeDesiredUDPRouteStatus(udpRoute, nil, "ctrl"); len(s.Parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(s.Parents))
	}
}
