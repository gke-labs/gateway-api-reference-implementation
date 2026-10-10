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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
	}

	routes := []InternalRoute{
		{
			Hostnames: []string{"example.com"},
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

	cfg, err := BuildDataplaneConfig(gwKey, listeners, routes, certsMap, defaultCert)
	if err != nil {
		t.Fatalf("BuildDataplaneConfig failed: %v", err)
	}

	// Verify certificate deduplication: 2 certificates total (rsaCert and ecdsaCert)
	if len(cfg.Certificates) != 2 {
		t.Fatalf("expected 2 unique certificates in cfg, got %d", len(cfg.Certificates))
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

	cfgA, err := BuildGatewayDataplaneConfig(cgA, secrets, nil)
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
