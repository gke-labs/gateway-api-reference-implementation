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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func generateTestTLSCert(t *testing.T, isRSA bool, commonName string, dnsNames []string) *tls.Certificate {
	t.Helper()
	var priv any
	var pub any
	var err error
	if isRSA {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		pub = &priv.(*rsa.PrivateKey).PublicKey
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:  dnsNames,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

func generatePEMSecret(t *testing.T, name, ns, host string) *corev1.Secret {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:  []string{host},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
}

func TestDataplaneConfig_Roundtrip(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}

	rsaCert := generateTestTLSCert(t, true, "example.com", []string{"example.com", "www.example.com"})
	ecdsaCert := generateTestTLSCert(t, false, "api.example.com", []string{"api.example.com"})
	clientCert := generateTestTLSCert(t, false, "client.example.com", []string{"client.example.com"})

	certsMap := map[string]*tls.Certificate{
		"example.com":     rsaCert,
		"www.example.com": rsaCert,
		"api.example.com": ecdsaCert,
	}
	defaultCert := rsaCert

	passthroughMode := gatewayv1.TLSModePassthrough
	listeners := []InternalListener{
		{
			Name:        "http",
			Protocol:    gatewayv1.HTTPProtocolType,
			Port:        80,
			Hostname:    "example.com",
			GatewayName: gwKey,
		},
		{
			Name:        "tls-pt",
			Protocol:    gatewayv1.TLSProtocolType,
			Port:        443,
			Hostname:    "pt.example.com",
			GatewayName: gwKey,
			TLSMode:     &passthroughMode,
			TLSBackends: map[string][]InternalTLSBackend{
				"pt.example.com": {{Target: "10.0.0.1:8443", Weight: 1}},
			},
		},
		{
			Name:        "tcp",
			Protocol:    gatewayv1.TCPProtocolType,
			Port:        9000,
			GatewayName: gwKey,
			TCPBackends: []InternalTCPBackend{
				{Target: "backend1.default.svc.cluster.local:9000", Weight: 10},
				{Target: "backend2.default.svc.cluster.local:9000", Weight: 0},
			},
		},
		{
			Name:        "udp",
			Protocol:    gatewayv1.UDPProtocolType,
			Port:        5301,
			GatewayName: gwKey,
			UDPBackends: []InternalUDPBackend{
				{Target: "dns1.default.svc.cluster.local:53", Weight: 10},
				{Target: "dns2.default.svc.cluster.local:53", Weight: 0},
			},
		},
	}

	routes := []InternalRoute{
		{
			Hostnames: routeHostnamesFromStrings("example.com"),
			Rules: []InternalRule{
				{
					Matches: []InternalMatch{
						{
							Path: &InternalPathMatch{
								Type:  gatewayv1.PathMatchPathPrefix,
								Value: "/api",
							},
							Headers: []InternalHeaderMatch{
								{
									Type:                        gatewayv1.HeaderMatchRegularExpression,
									Name:                        "X-Version",
									MatchRegularExpressionValue: regexp.MustCompile("^v[0-9]+$"),
								},
							},
						},
					},
					Backends: []InternalBackend{
						{
							Host:   "backend-svc.default.svc.cluster.local",
							Port:   8080,
							Weight: 100,
						},
					},
				},
			},
		},
	}

	cfg, err := BuildDataplaneConfig(gwKey, listeners, routes, certsMap, defaultCert, clientCert)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}

	// Verify certificate deduplication: 3 certificates total (rsaCert, ecdsaCert, clientCert)
	if len(cfg.Certificates) != 3 {
		t.Fatalf("expected 3 unique certificates in cfg, got %d", len(cfg.Certificates))
	}
	// example.com and www.example.com should point to the same certID
	if cfg.HostCertificates["example.com"] != cfg.HostCertificates["www.example.com"] {
		t.Errorf("expected example.com and www.example.com to share certID, got %s and %s",
			cfg.HostCertificates["example.com"], cfg.HostCertificates["www.example.com"])
	}
	// defaultCertID should match example.com's certID
	if cfg.DefaultCertID != cfg.HostCertificates["example.com"] {
		t.Errorf("expected DefaultCertID to match example.com certID")
	}
	// backendClientCertID should be non-empty and content-addressed by sha256
	expectedClientCertID := hex.EncodeToString(func() []byte {
		h := sha256.Sum256(clientCert.Certificate[0])
		return h[:]
	}())
	if cfg.BackendClientCertID != expectedClientCertID {
		t.Errorf("expected BackendClientCertID %s, got %s", expectedClientCertID, cfg.BackendClientCertID)
	}

	// Marshal to JSON
	data, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal from JSON
	restored, err := UnmarshalDataplaneConfig(data)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}

	if restored.GatewayName != gwKey {
		t.Errorf("GatewayName mismatch: want %v, got %v", gwKey, restored.GatewayName)
	}
	if len(restored.Listeners) != len(listeners) {
		t.Fatalf("Listeners count mismatch: want %d, got %d", len(listeners), len(restored.Listeners))
	}
	if len(restored.Routes) != len(routes) {
		t.Fatalf("Routes count mismatch: want %d, got %d", len(routes), len(restored.Routes))
	}

	// Verify regex preserved in matches
	reg := restored.Routes[0].Rules[0].Matches[0].Headers[0].MatchRegularExpressionValue
	if reg == nil || !reg.MatchString("v2") || reg.MatchString("bad") {
		t.Errorf("expected regular expression to match v2 and not bad, got %v", reg)
	}

	// Verify TCP listener with weighted backends
	var tcpListener *InternalListener
	for i := range restored.Listeners {
		if restored.Listeners[i].Protocol == gatewayv1.TCPProtocolType {
			tcpListener = &restored.Listeners[i]
			break
		}
	}
	if tcpListener == nil {
		t.Fatal("expected TCP listener in restored listeners")
	}
	if len(tcpListener.TCPBackends) != 2 {
		t.Fatalf("expected 2 TCPBackends, got %d", len(tcpListener.TCPBackends))
	}
	if tcpListener.TCPBackends[0].Target != "backend1.default.svc.cluster.local:9000" || tcpListener.TCPBackends[0].Weight != 10 {
		t.Errorf("unexpected TCPBackend[0]: %+v", tcpListener.TCPBackends[0])
	}
	if tcpListener.TCPBackends[1].Target != "backend2.default.svc.cluster.local:9000" || tcpListener.TCPBackends[1].Weight != 0 {
		t.Errorf("unexpected TCPBackend[1]: %+v", tcpListener.TCPBackends[1])
	}

	// Verify UDP listener with weighted backends
	var udpListener *InternalListener
	for i := range restored.Listeners {
		if restored.Listeners[i].Protocol == gatewayv1.UDPProtocolType {
			udpListener = &restored.Listeners[i]
			break
		}
	}
	if udpListener == nil {
		t.Fatal("expected UDP listener in restored listeners")
	}
	if len(udpListener.UDPBackends) != 2 {
		t.Fatalf("expected 2 UDPBackends, got %d", len(udpListener.UDPBackends))
	}
	if udpListener.UDPBackends[0].Target != "dns1.default.svc.cluster.local:53" || udpListener.UDPBackends[0].Weight != 10 {
		t.Errorf("unexpected UDPBackend[0]: %+v", udpListener.UDPBackends[0])
	}
	if udpListener.UDPBackends[1].Target != "dns2.default.svc.cluster.local:53" || udpListener.UDPBackends[1].Weight != 0 {
		t.Errorf("unexpected UDPBackend[1]: %+v", udpListener.UDPBackends[1])
	}

	// Extract certificates
	restoredCerts, restoredDefaultCert, err := restored.ExtractCertificates()
	if err != nil {
		t.Fatalf("ExtractCertificates failed: %v", err)
	}

	if restoredDefaultCert == nil {
		t.Fatalf("expected non-nil defaultCert")
	}
	if restoredCerts["example.com"] != restoredDefaultCert {
		t.Errorf("expected restored defaultCert and example.com to have pointer equality")
	}
	if restoredCerts["example.com"] != restoredCerts["www.example.com"] {
		t.Errorf("expected example.com and www.example.com to have pointer equality")
	}
	if restoredCerts["api.example.com"] == restoredCerts["example.com"] {
		t.Errorf("expected api.example.com to have distinct cert pointer")
	}

	// Verify restored certs can perform TLS handshakes
	testTLSHandshake(t, restoredCerts["example.com"], "example.com")
	testTLSHandshake(t, restoredCerts["api.example.com"], "api.example.com")

	// Verify restored backend client certificate
	if restored.BackendClientCertID != expectedClientCertID {
		t.Errorf("expected restored BackendClientCertID %s, got %s", expectedClientCertID, restored.BackendClientCertID)
	}
	restoredClientCert, err := restored.ExtractBackendClientCertificate()
	if err != nil {
		t.Fatalf("ExtractBackendClientCertificate failed: %v", err)
	}
	if restoredClientCert == nil {
		t.Fatalf("expected non-nil restoredClientCert")
	}
	testTLSHandshake(t, restoredClientCert, "client.example.com")
}

func TestInternalRoute_MarshalRoundTrip_PreservesOriginalHostname(t *testing.T) {
	route := InternalRoute{
		Hostnames: []RouteHostname{
			NewRouteHostname("abc.example.com", "*.example.com"),
		},
		Rules: []InternalRule{{Backends: []InternalBackend{{Host: "backend-2", Port: 8080}}}},
	}
	data, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("failed to marshal route: %v", err)
	}

	var roundTripped InternalRoute
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal route: %v", err)
	}
	if len(roundTripped.Hostnames) != 1 {
		t.Fatalf("expected 1 hostname, got %d", len(roundTripped.Hostnames))
	}
	if roundTripped.Hostnames[0].Hostname != "abc.example.com" {
		t.Errorf("expected effective hostname 'abc.example.com', got %q", roundTripped.Hostnames[0].Hostname)
	}
	if roundTripped.Hostnames[0].OriginalHostname != "*.example.com" {
		t.Errorf("expected original hostname '*.example.com', got %q", roundTripped.Hostnames[0].OriginalHostname)
	}
}

func TestInternalRoute_MarshalRoundTrip_MixedCaseRouteHostnameMatches(t *testing.T) {
	route := InternalRoute{
		Hostnames: []RouteHostname{
			NewRouteHostname("AbC.ExAmPlE.CoM", "*.ExAmPlE.CoM"),
		},
		Rules: []InternalRule{{Backends: []InternalBackend{{Host: "backend-1", Port: 8080}}}},
	}
	data, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("failed to marshal route: %v", err)
	}

	var roundTripped InternalRoute
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal route: %v", err)
	}
	if len(roundTripped.Hostnames) != 1 {
		t.Fatalf("expected 1 hostname, got %d", len(roundTripped.Hostnames))
	}
	if roundTripped.Hostnames[0].Hostname != "AbC.ExAmPlE.CoM" {
		t.Errorf("expected Hostname %q, got %q", "AbC.ExAmPlE.CoM", roundTripped.Hostnames[0].Hostname)
	}
	if roundTripped.Hostnames[0].OriginalHostname != "*.ExAmPlE.CoM" {
		t.Errorf("expected OriginalHostname %q, got %q", "*.ExAmPlE.CoM", roundTripped.Hostnames[0].OriginalHostname)
	}

	req := httptest.NewRequest("GET", "http://abc.example.com/", nil)
	rule, _ := MatchRoute([]InternalRoute{roundTripped}, req)
	if rule == nil || len(rule.Backends) == 0 || rule.Backends[0].Host != "backend-1" {
		t.Errorf("MatchRoute after unmarshal = %v, want backend-1", rule)
	}
}

func testTLSHandshake(t *testing.T, cert *tls.Certificate, serverName string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("failed to listen tls: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
		_ = conn.Close()
	}()

	certPool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	certPool.AddCert(leaf)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName: serverName,
		RootCAs:    certPool,
	})
	if err != nil {
		t.Fatalf("tls.Dial failed: %v", err)
	}
	_ = conn.Close()
	<-done
}

func TestBuildGatewayDataplaneConfig_Scoping(t *testing.T) {
	secretA := generatePEMSecret(t, "secret-a", "ns-a", "gw-a.example.com")
	secretB := generatePEMSecret(t, "secret-b", "ns-b", "gw-b.example.com")

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "ns-a", Name: "secret-a"}: secretA,
		{Namespace: "ns-b", Name: "secret-b"}: secretB,
	}

	gwA := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "gw-a"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     443,
					Hostname: Ptr(gatewayv1.Hostname("gw-a.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "secret-a"},
						},
					},
				},
			},
		},
	}
	gwB := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-b", Name: "gw-b"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ref-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     443,
					Hostname: Ptr(gatewayv1.Hostname("gw-b.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "secret-b"},
						},
					},
				},
			},
		},
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "ref-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gwA, gwB},
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		Secrets:        secrets,
		ControllerName: "test-controller",
	}

	outputs := ComputeOutputs(inputs)
	if outputs == nil {
		t.Fatalf("expected non-nil outputs")
	}

	cgA := outputs.CompiledGateways[types.NamespacedName{Namespace: "ns-a", Name: "gw-a"}]
	if cgA == nil {
		t.Fatalf("expected compiled gateway for gw-a")
	}

	cfgA, err := BuildGatewayDataplaneConfig(cgA)
	if err != nil {
		t.Fatalf("BuildGatewayDataplaneConfig failed: %v", err)
	}

	// Verify cfgA only contains certificate for gw-a, NOT gw-b
	if _, ok := cfgA.HostCertificates["gw-a.example.com"]; !ok {
		t.Errorf("expected gw-a.example.com in HostCertificates")
	}
	if _, ok := cfgA.HostCertificates["gw-b.example.com"]; ok {
		t.Errorf("did NOT expect gw-b.example.com in HostCertificates of gw-a!")
	}
	if len(cfgA.Certificates) != 1 {
		t.Errorf("expected exactly 1 certificate in cfgA, got %d", len(cfgA.Certificates))
	}
}

func TestInProcessDataplanePublisher_MultipleGatewaysClientCertIsolation(t *testing.T) {
	ctx := t.Context()

	clientCert := generateTestTLSCert(t, false, "client.example.com", nil)
	serverCertA := generateTestTLSCert(t, false, "a.example.com", []string{"a.example.com"})
	serverCertB := generateTestTLSCert(t, false, "b.example.com", []string{"b.example.com"})

	gwA := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-a"},
	}
	gwB := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "gw-b"},
	}

	routeA := InternalRoute{
		Hostnames: routeHostnamesFromStrings("a.example.com"),
		Rules: []InternalRule{
			{
				Backends: []InternalBackend{
					{
						Host: "backend-a",
						Port: 443,
						TLSConfig: &InternalTLSConfig{
							Hostname: "backend-a.local",
						},
					},
				},
			},
		},
	}
	routeB := InternalRoute{
		Hostnames: routeHostnamesFromStrings("b.example.com"),
		Rules: []InternalRule{
			{
				Backends: []InternalBackend{
					{
						Host: "backend-b",
						Port: 443,
						TLSConfig: &InternalTLSConfig{
							Hostname: "backend-b.local",
						},
					},
				},
			},
		},
	}

	listenersA := []InternalListener{
		{
			Name:        "https-a",
			Port:        443,
			Protocol:    gatewayv1.HTTPSProtocolType,
			Hostname:    "a.example.com",
			GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-a"},
			Routes:      []InternalRoute{routeA},
		},
	}
	listenersB := []InternalListener{
		{
			Name:        "https-b",
			Port:        443,
			Protocol:    gatewayv1.HTTPSProtocolType,
			Hostname:    "b.example.com",
			GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-b"},
			Routes:      []InternalRoute{routeB},
		},
	}

	// Gateway A has client certificate configured
	cfgA, err := BuildDataplaneConfig(
		types.NamespacedName{Namespace: "default", Name: "gw-a"},
		listenersA, []InternalRoute{routeA},
		map[string]*tls.Certificate{"a.example.com": serverCertA},
		serverCertA, clientCert,
	)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig gw-a failed: %v", err)
	}

	// Gateway B has NO client certificate configured
	cfgB, err := BuildDataplaneConfig(
		types.NamespacedName{Namespace: "default", Name: "gw-b"},
		listenersB, []InternalRoute{routeB},
		map[string]*tls.Certificate{"b.example.com": serverCertB},
		serverCertB, nil,
	)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig gw-b failed: %v", err)
	}

	updater := &mockProxyUpdater{}
	pub := NewInProcessDataplanePublisher(updater)
	if err := pub.Begin(ctx); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if err := pub.PublishDataplaneConfig(ctx, gwA, cfgA); err != nil {
		t.Fatalf("PublishDataplaneConfig gwA failed: %v", err)
	}
	if err := pub.PublishDataplaneConfig(ctx, gwB, cfgB); err != nil {
		t.Fatalf("PublishDataplaneConfig gwB failed: %v", err)
	}
	if err := pub.Commit(ctx); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Check top-level routes applied to proxy
	var foundA, foundB bool
	for _, r := range updater.routes {
		for _, rule := range r.Rules {
			for _, b := range rule.Backends {
				if b.Host == "backend-a" {
					foundA = true
					if b.TLSConfig == nil || b.TLSConfig.ClientCert == nil {
						t.Errorf("expected backend-a to carry client cert, got nil")
					}
				}
				if b.Host == "backend-b" {
					foundB = true
					if b.TLSConfig != nil && b.TLSConfig.ClientCert != nil {
						t.Errorf("expected backend-b to carry NO client cert, but got: %v", b.TLSConfig.ClientCert)
					}
				}
			}
		}
	}
	if !foundA {
		t.Errorf("backend-a not found in updater routes")
	}
	if !foundB {
		t.Errorf("backend-b not found in updater routes")
	}

	// Check listener routes applied to proxy
	for _, l := range updater.listeners {
		for _, r := range l.Routes {
			for _, rule := range r.Rules {
				for _, b := range rule.Backends {
					if b.Host == "backend-a" {
						if b.TLSConfig == nil || b.TLSConfig.ClientCert == nil {
							t.Errorf("expected listener backend-a to carry client cert, got nil")
						}
					}
					if b.Host == "backend-b" {
						if b.TLSConfig != nil && b.TLSConfig.ClientCert != nil {
							t.Errorf("expected listener backend-b to carry NO client cert, but got: %v", b.TLSConfig.ClientCert)
						}
					}
				}
			}
		}
	}
}

func TestDataplaneConfig_Roundtrip_ClientValidation(t *testing.T) {
	gwKey := types.NamespacedName{Namespace: "default", Name: "my-gateway"}
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nMIICfakecert\n-----END CERTIFICATE-----\n")

	listeners := []InternalListener{
		{
			Name:        "https",
			Protocol:    gatewayv1.HTTPSProtocolType,
			Port:        443,
			Hostname:    "example.com",
			GatewayName: gwKey,
			ClientValidation: &InternalClientValidation{
				CACertPEMs: [][]byte{caPEM},
				Mode:       gatewayv1.AllowValidOnly,
			},
		},
		{
			Name:        "http",
			Protocol:    gatewayv1.HTTPProtocolType,
			Port:        80,
			Hostname:    "example.com",
			GatewayName: gwKey,
		},
	}

	cfg, err := BuildDataplaneConfig(gwKey, listeners, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}

	data, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	restored, err := UnmarshalDataplaneConfig(data)
	if err != nil {
		t.Fatalf("UnmarshalDataplaneConfig failed: %v", err)
	}

	if len(restored.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(restored.Listeners))
	}

	httpsLis := restored.Listeners[0]
	if httpsLis.ClientValidation == nil {
		t.Fatalf("expected ClientValidation to be restored, got nil")
	}
	if httpsLis.ClientValidation.Mode != gatewayv1.AllowValidOnly {
		t.Errorf("expected Mode %v, got %v", gatewayv1.AllowValidOnly, httpsLis.ClientValidation.Mode)
	}
	if len(httpsLis.ClientValidation.CACertPEMs) != 1 || string(httpsLis.ClientValidation.CACertPEMs[0]) != string(caPEM) {
		t.Errorf("expected CACertPEMs to be restored, got %v", httpsLis.ClientValidation.CACertPEMs)
	}

	httpLis := restored.Listeners[1]
	if httpLis.ClientValidation != nil {
		t.Errorf("expected http listener ClientValidation to be nil, got %v", httpLis.ClientValidation)
	}
}

func TestInProcessDataplanePublisher_ConflictingHostnameCertificates(t *testing.T) {
	ctx := t.Context()

	now := metav1.Now()
	olderTime := metav1.NewTime(now.Add(-10 * time.Minute))
	newerTime := metav1.NewTime(now.Add(-5 * time.Minute))

	certPEM_A, keyPEM_A := generateTestCertPEM(t, "shared.example.com")
	certPEM_B, keyPEM_B := generateTestCertPEM(t, "shared.example.com")

	secretA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-a", Namespace: "default"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM_A,
			corev1.TLSPrivateKeyKey: keyPEM_A,
		},
	}
	secretB := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-b", Namespace: "default"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM_B,
			corev1.TLSPrivateKeyKey: keyPEM_B,
		},
	}

	gwA := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw-a-older",
			Namespace:         "default",
			CreationTimestamp: olderTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https-shared",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("shared.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "secret-a"},
						},
					},
				},
			},
		},
	}

	gwB := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gw-b-newer",
			Namespace:         "default",
			CreationTimestamp: newerTime,
			Generation:        1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "reference-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https-shared",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: Ptr(gatewayv1.Hostname("shared.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "secret-b"},
						},
					},
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

	secrets := map[types.NamespacedName]*corev1.Secret{
		{Namespace: "default", Name: "secret-a"}: secretA,
		{Namespace: "default", Name: "secret-b"}: secretB,
	}

	inputs := ModelInputs{
		Gateways:       []*gatewayv1.Gateway{gwB, gwA}, // passed in arbitrary order
		GatewayClasses: []*gatewayv1.GatewayClass{gc},
		Secrets:        secrets,
		ControllerName: "test-controller",
		AllInOneMode:   true,
	}

	outputs := ComputeOutputs(inputs)

	gwAKey := types.NamespacedName{Namespace: "default", Name: "gw-a-older"}
	gwBKey := types.NamespacedName{Namespace: "default", Name: "gw-b-newer"}

	cfgA := outputs.DataplaneConfigs[gwAKey]
	cfgB := outputs.DataplaneConfigs[gwBKey]

	if cfgA == nil {
		t.Fatalf("expected DataplaneConfig for gw-a-older")
	}
	if cfgB == nil {
		t.Fatalf("expected DataplaneConfig for gw-b-newer")
	}

	// gw-a-older (winner) carries the certificate for shared.example.com
	if _, ok := cfgA.HostCertificates["shared.example.com"]; !ok {
		t.Errorf("gw-a-older expected HostCertificates for shared.example.com")
	}

	// gw-b-newer (loser, Programmed=False) must NOT carry certificate for shared.example.com
	if _, ok := cfgB.HostCertificates["shared.example.com"]; ok {
		t.Errorf("gw-b-newer should NOT carry HostCertificates for shared.example.com when excluded")
	}

	// Publish both configs to InProcessDataplanePublisher
	updater := &mockProxyUpdater{}
	pub := NewInProcessDataplanePublisher(updater)
	if err := pub.Begin(ctx); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if err := pub.PublishDataplaneConfig(ctx, gwA, cfgA); err != nil {
		t.Fatalf("PublishDataplaneConfig gwA failed: %v", err)
	}
	if err := pub.PublishDataplaneConfig(ctx, gwB, cfgB); err != nil {
		t.Fatalf("PublishDataplaneConfig gwB failed: %v", err)
	}
	if err := pub.Commit(ctx); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// updater must only carry the winner's cert for shared.example.com
	appliedCert := updater.certs["shared.example.com"]
	if appliedCert == nil {
		t.Fatalf("expected cert for shared.example.com in updater, got nil")
	}
	expectedCert, err := tls.X509KeyPair(certPEM_A, keyPEM_A)
	if err != nil {
		t.Fatalf("failed to parse expected cert A: %v", err)
	}
	if !bytes.Equal(appliedCert.Certificate[0], expectedCert.Certificate[0]) {
		t.Errorf("expected winner (gw-a) certificate to be served for shared.example.com")
	}
}

func TestApplyDataplaneConfig_MissingBackendClientCertID(t *testing.T) {
	updater := &mockProxyUpdater{}

	// 1. Apply initial valid config
	initialCfg := &DataplaneConfig{
		GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-1"},
		Routes: []InternalRoute{
			{
				Hostnames: routeHostnamesFromStrings("initial.example.com"),
				Rules: []InternalRule{
					{
						Backends: []InternalBackend{
							{Host: "initial-backend", Port: 8080},
						},
					},
				},
			},
		},
	}
	initialData, err := initialCfg.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal initial config: %v", err)
	}
	if err := ApplyDataplaneConfig(updater, initialData); err != nil {
		t.Fatalf("failed to apply initial config: %v", err)
	}
	if len(updater.routes) != 1 || updater.routes[0].Hostnames[0].Hostname != "initial.example.com" {
		t.Fatalf("expected initial config in updater")
	}

	clientCert := generateTestTLSCert(t, false, "client.example.com", nil)
	h := sha256.Sum256(clientCert.Certificate[0])
	clientCertID := hex.EncodeToString(h[:])
	certData, err := tlsCertToData(clientCert)
	if err != nil {
		t.Fatalf("failed to convert client cert to data: %v", err)
	}

	t.Run("route backend with missing ClientCertID is rejected and previous config persists", func(t *testing.T) {
		missingCfg := &DataplaneConfig{
			GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-1"},
			Routes: []InternalRoute{
				{
					Hostnames: routeHostnamesFromStrings("secure.example.com"),
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{
									Host: "secure-backend",
									Port: 8443,
									TLSConfig: &InternalTLSConfig{
										Hostname:     "secure-backend",
										ClientCertID: clientCertID,
									},
								},
							},
						},
					},
				},
			},
			Certificates: map[string]CertificateData{}, // clientCertID is absent
		}
		missingData, err := missingCfg.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal missing config: %v", err)
		}

		err = ApplyDataplaneConfig(updater, missingData)
		if err == nil {
			t.Fatalf("expected ApplyDataplaneConfig to reject config with missing ClientCertID")
		}

		// Verify previously applied config stays in effect
		if len(updater.routes) != 1 || updater.routes[0].Hostnames[0].Hostname != "initial.example.com" {
			t.Fatalf("expected previously applied config to stay in effect, got routes: %+v", updater.routes)
		}
		if updater.routes[0].Rules[0].Backends[0].Host != "initial-backend" {
			t.Fatalf("expected initial backend to stay in effect")
		}

		// The same config with the certificate present applies as today
		missingCfg.Certificates[clientCertID] = certData
		validData, err := missingCfg.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal valid config: %v", err)
		}
		if err := ApplyDataplaneConfig(updater, validData); err != nil {
			t.Fatalf("expected ApplyDataplaneConfig to succeed with certificate present: %v", err)
		}
		if len(updater.routes) != 1 || updater.routes[0].Hostnames[0].Hostname != "secure.example.com" {
			t.Fatalf("expected updated config to be applied, got routes: %+v", updater.routes)
		}
		appliedBackend := updater.routes[0].Rules[0].Backends[0]
		if appliedBackend.TLSConfig == nil || appliedBackend.TLSConfig.ClientCert == nil {
			t.Fatalf("expected ClientCert to be wired when certificate is present")
		}
		if !bytes.Equal(appliedBackend.TLSConfig.ClientCert.Certificate[0], clientCert.Certificate[0]) {
			t.Errorf("expected wired client certificate to match")
		}
	})

	t.Run("listener backend with missing ClientCertID is rejected", func(t *testing.T) {
		missingCfg := &DataplaneConfig{
			GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-1"},
			Listeners: []InternalListener{
				{
					Name: "https",
					Routes: []InternalRoute{
						{
							Rules: []InternalRule{
								{
									Backends: []InternalBackend{
										{
											Host: "listener-backend",
											Port: 8443,
											TLSConfig: &InternalTLSConfig{
												Hostname:     "listener-backend",
												ClientCertID: "missing-cert-id",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Certificates: map[string]CertificateData{},
		}
		missingData, err := missingCfg.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal missing config: %v", err)
		}
		if err := ApplyDataplaneConfig(updater, missingData); err == nil {
			t.Fatalf("expected ApplyDataplaneConfig to reject listener config with missing ClientCertID")
		}
	})

	t.Run("mirror backend with missing ClientCertID is rejected", func(t *testing.T) {
		missingCfg := &DataplaneConfig{
			GatewayName: types.NamespacedName{Namespace: "default", Name: "gw-1"},
			Routes: []InternalRoute{
				{
					Hostnames: routeHostnamesFromStrings("mirror.example.com"),
					Rules: []InternalRule{
						{
							Backends: []InternalBackend{
								{Host: "normal-backend", Port: 8080},
							},
							Mirrors: []InternalMirror{
								{
									Backend: InternalBackend{
										Host: "mirror-backend",
										Port: 8443,
										TLSConfig: &InternalTLSConfig{
											Hostname:     "mirror-backend",
											ClientCertID: "missing-mirror-cert-id",
										},
									},
									Numerator:   1,
									Denominator: 1,
								},
							},
						},
					},
				},
			},
			Certificates: map[string]CertificateData{},
		}
		missingData, err := missingCfg.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal missing config: %v", err)
		}
		if err := ApplyDataplaneConfig(updater, missingData); err == nil {
			t.Fatalf("expected ApplyDataplaneConfig to reject mirror config with missing ClientCertID")
		}
	})
}

func TestDataplaneConfig_Revision(t *testing.T) {
	base := func() *DataplaneConfig {
		return &DataplaneConfig{
			GatewayName: types.NamespacedName{Namespace: "default", Name: "my-gw"},
			Listeners: []InternalListener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		}
	}

	baseRev, err := base().ComputeRevision()
	if err != nil || baseRev == "" {
		t.Fatalf("ComputeRevision failed: %v", err)
	}

	tests := []struct {
		name      string
		cfg       *DataplaneConfig
		wantEqual bool
	}{
		{
			name:      "equal configs produce identical revision",
			cfg:       base(),
			wantEqual: true,
		},
		{
			name: "existing revision field ignored",
			cfg: func() *DataplaneConfig {
				c := base()
				c.Revision = "old-revision"
				return c
			}(),
			wantEqual: true,
		},
		{
			name: "one-field change produces different revision",
			cfg: func() *DataplaneConfig {
				c := base()
				c.Listeners[0].Port = 8080
				return c
			}(),
			wantEqual: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rev, err := tc.cfg.ComputeRevision()
			if err != nil {
				t.Fatalf("ComputeRevision failed: %v", err)
			}
			if (rev == baseRev) != tc.wantEqual {
				t.Errorf("got revision %q, base %q, wantEqual=%v", rev, baseRev, tc.wantEqual)
			}
		})
	}
}
