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

package viewtypes

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	googleproto "google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func newSampleFullConfigMap() *corev1.ConfigMap {
	now := metav1.NewTime(time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC))
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sample-service-config",
			Namespace:         "default",
			UID:               "d9a3b2c1-84e5-4f3a-92c7-0123456789ab",
			ResourceVersion:   "1049283",
			Generation:        4,
			CreationTimestamp: now,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "gateway-proxy",
				"app.kubernetes.io/instance":   "prod-east",
				"app.kubernetes.io/version":    "v1.4.0",
				"app.kubernetes.io/managed-by": "helm",
			},
			Annotations: map[string]string{
				"checksum/config": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"sample-service-config","namespace":"default"},"data":{"server.conf":"listen 8080;\nproxy_pass http://backend;\n"}}`,
			},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "gateway-proxy", UID: "dep-9988"},
			},
			Finalizers: []string{"kubernetes.io/test-finalizer"},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:    "helm",
					Operation:  metav1.ManagedFieldsOperationApply,
					APIVersion: "v1",
					Time:       &now,
					FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{"f:app.kubernetes.io/name":{}}},"f:data":{"f:server.conf":{}}}`)},
				},
				{
					Manager:    "kubectl-client-side-apply",
					Operation:  metav1.ManagedFieldsOperationUpdate,
					APIVersion: "v1",
					Time:       &now,
					FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:annotations":{"f:checksum/config":{}}}}`)},
				},
			},
		},
		Data: map[string]string{
			"server.conf": "listen 8080;\nproxy_pass http://backend;\nkeepalive_timeout 65;\nclient_max_body_size 10M;\n",
			"env.json":    `{"cluster":"us-east-1","debug":false,"max_conns":5000}`,
		},
		BinaryData: map[string][]byte{
			"cert.bundle": []byte("sample-intermediate-ca-binary-data-1234567890"),
		},
	}
}

func newSampleFullSecret() *corev1.Secret {
	now := metav1.NewTime(time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC))
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sample-tls-secret",
			Namespace:         "default",
			UID:               "sec-1122-3344-5566-778899aabbcc",
			ResourceVersion:   "2098412",
			Generation:        2,
			CreationTimestamp: now,
			Labels: map[string]string{
				"gateway.networking.k8s.io/cert": "rsa-2048",
				"environment":                    "production",
			},
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "api-gateway-tls",
			},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:    "cert-manager",
					Operation:  metav1.ManagedFieldsOperationUpdate,
					APIVersion: "v1",
					Time:       &now,
					FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:data":{"f:tls.crt":{},"f:tls.key":{}},"f:type":{}}`)},
				},
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n-----END CERTIFICATE-----\n"),
			corev1.TLSPrivateKeyKey: []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz9876543210zyxwvutsrqponmlkjihgfedcba\n-----END RSA PRIVATE KEY-----\n"),
		},
	}
}

func newSampleFullHTTPRoute() *gatewayv1.HTTPRoute {
	now := metav1.NewTime(time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC))
	port8080 := gatewayv1.PortNumber(8080)
	port8443 := gatewayv1.PortNumber(8443)
	weight1 := int32(80)
	weight2 := int32(20)
	prefixType := gatewayv1.PathMatchPathPrefix
	prefixVal := "/api/v2"
	loginVal := "/login"
	methodGet := gatewayv1.HTTPMethodGet
	methodPost := gatewayv1.HTTPMethodPost
	r1Name := gatewayv1.SectionName("api-v2-rule")
	r2Name := gatewayv1.SectionName("login-rule")

	return &gatewayv1.HTTPRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "gateway.networking.k8s.io/v1",
			Kind:       "HTTPRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sample-api-route",
			Namespace:         "gateway-system",
			UID:               "route-5544-3322-1100-aabbccddeeff",
			ResourceVersion:   "3098511",
			Generation:        5,
			CreationTimestamp: now,
			Labels: map[string]string{
				"app":  "api-gateway",
				"tier": "routing",
			},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:    "gateway-controller",
					Operation:  metav1.ManagedFieldsOperationUpdate,
					APIVersion: "gateway.networking.k8s.io/v1",
					Time:       &now,
					FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:spec":{"f:rules":{}}}`)},
				},
			},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"api.example.com", "v2.example.com"},
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "public-gateway", Port: &port8443},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Name: &r1Name,
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path:   &gatewayv1.HTTPPathMatch{Type: &prefixType, Value: &prefixVal},
							Method: &methodGet,
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
							RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
								Set: []gatewayv1.HTTPHeader{
									{Name: "X-Gateway-Proxy", Value: "GARI-Ref"},
								},
								Remove: []string{"X-Internal-Token"},
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "api-v2-blue",
									Port: &port8080,
								},
								Weight: &weight1,
							},
						},
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "api-v2-green",
									Port: &port8080,
								},
								Weight: &weight2,
							},
						},
					},
				},
				{
					Name: &r2Name,
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path:   &gatewayv1.HTTPPathMatch{Type: &prefixType, Value: &loginVal},
							Method: &methodPost,
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "auth-service",
									Port: &port8080,
								},
							},
						},
					},
				},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{Name: "public-gateway"},
						Conditions: []metav1.Condition{
							{
								Type:               "Accepted",
								Status:             metav1.ConditionTrue,
								Reason:             "Accepted",
								LastTransitionTime: now,
							},
						},
					},
				},
			},
		},
	}
}

var sinkAny any

// TestMeasureSteadyStateHeap measures the retained heap bytes per object for 10,000 objects.
func TestMeasureSteadyStateHeap(t *testing.T) {
	const count = 10000

	measureHeap := func(name string, populate func() any) uint64 {
		sinkAny = nil
		runtime.GC()
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		sinkAny = populate()

		runtime.GC()
		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)

		var diff uint64
		if m2.HeapAlloc > m1.HeapAlloc {
			diff = m2.HeapAlloc - m1.HeapAlloc
		}
		perObj := diff / count
		t.Logf("[%s] Retained Heap: %d KB (%d B/obj)", name, diff/1024, perObj)
		return perObj
	}

	fullCM := newSampleFullConfigMap()
	cmJSON, _ := json.Marshal(fullCM)
	cmStripped := fullCM.DeepCopy()
	cmStripped.ManagedFields = nil
	cmStrippedJSON, _ := json.Marshal(cmStripped)

	fullSec := newSampleFullSecret()
	secJSON, _ := json.Marshal(fullSec)
	secStripped := fullSec.DeepCopy()
	secStripped.ManagedFields = nil
	secStrippedJSON, _ := json.Marshal(secStripped)

	fullRoute := newSampleFullHTTPRoute()
	routeJSON, _ := json.Marshal(fullRoute)
	routeStripped := fullRoute.DeepCopy()
	routeStripped.ManagedFields = nil
	routeStrippedJSON, _ := json.Marshal(routeStripped)

	// Measure ConfigMap
	measureHeap("Full ConfigMap (with managedFields)", func() any {
		s := make([]*corev1.ConfigMap, count)
		for i := 0; i < count; i++ {
			var cm corev1.ConfigMap
			_ = json.Unmarshal(cmJSON, &cm)
			s[i] = &cm
		}
		return s
	})

	measureHeap("Full ConfigMap (stripped managedFields)", func() any {
		s := make([]*corev1.ConfigMap, count)
		for i := 0; i < count; i++ {
			var cm corev1.ConfigMap
			_ = json.Unmarshal(cmStrippedJSON, &cm)
			s[i] = &cm
		}
		return s
	})

	measureHeap("View ConfigMap", func() any {
		s := make([]*ConfigMapView, count)
		for i := 0; i < count; i++ {
			var cm ConfigMapView
			_ = json.Unmarshal(cmJSON, &cm)
			s[i] = &cm
		}
		return s
	})

	// Measure Secret
	measureHeap("Full Secret (with managedFields)", func() any {
		s := make([]*corev1.Secret, count)
		for i := 0; i < count; i++ {
			var sec corev1.Secret
			_ = json.Unmarshal(secJSON, &sec)
			s[i] = &sec
		}
		return s
	})

	measureHeap("Full Secret (stripped managedFields)", func() any {
		s := make([]*corev1.Secret, count)
		for i := 0; i < count; i++ {
			var sec corev1.Secret
			_ = json.Unmarshal(secStrippedJSON, &sec)
			s[i] = &sec
		}
		return s
	})

	measureHeap("View Secret", func() any {
		s := make([]*SecretView, count)
		for i := 0; i < count; i++ {
			var sec SecretView
			_ = json.Unmarshal(secJSON, &sec)
			s[i] = &sec
		}
		return s
	})

	// Measure HTTPRoute
	measureHeap("Full HTTPRoute (with managedFields)", func() any {
		s := make([]*gatewayv1.HTTPRoute, count)
		for i := 0; i < count; i++ {
			var route gatewayv1.HTTPRoute
			_ = json.Unmarshal(routeJSON, &route)
			s[i] = &route
		}
		return s
	})

	measureHeap("Full HTTPRoute (stripped managedFields)", func() any {
		s := make([]*gatewayv1.HTTPRoute, count)
		for i := 0; i < count; i++ {
			var route gatewayv1.HTTPRoute
			_ = json.Unmarshal(routeStrippedJSON, &route)
			s[i] = &route
		}
		return s
	})

	measureHeap("View HTTPRoute", func() any {
		s := make([]*HTTPRouteView, count)
		for i := 0; i < count; i++ {
			var route HTTPRouteView
			_ = json.Unmarshal(routeJSON, &route)
			s[i] = &route
		}
		return s
	})
}

// --- Benchmark Decode: JSON vs Protobuf vs Compact Binary ---

func BenchmarkDecode_ConfigMap_JSON_Full(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	raw, _ := json.Marshal(fullCM)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var cm corev1.ConfigMap
		if err := json.Unmarshal(raw, &cm); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_ConfigMap_JSON_View(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	raw, _ := json.Marshal(fullCM)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var cm ConfigMapView
		if err := json.Unmarshal(raw, &cm); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_ConfigMap_Protobuf_Full(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	type protoM interface {
		Marshal() ([]byte, error)
		Unmarshal([]byte) error
	}
	raw, err := any(fullCM).(protoM).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var cm corev1.ConfigMap
		if err := any(&cm).(protoM).Unmarshal(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_ConfigMap_Protobuf_Trimmed(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	rawJSON, _ := json.Marshal(fullCM)
	var cmView ConfigMapView
	_ = json.Unmarshal(rawJSON, &cmView)
	wireBytes, _ := EncodeConfigMapProtobufEnvelope(&cmView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeConfigMapProtobuf(wireBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_ConfigMap_CompactBinary(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	rawJSON, _ := json.Marshal(fullCM)
	var cmView ConfigMapView
	_ = json.Unmarshal(rawJSON, &cmView)
	wireBytes, _ := EncodeConfigMapBinary(&cmView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeConfigMapBinary(wireBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_Secret_JSON_Full(b *testing.B) {
	fullSec := newSampleFullSecret()
	raw, _ := json.Marshal(fullSec)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sec corev1.Secret
		if err := json.Unmarshal(raw, &sec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_Secret_JSON_View(b *testing.B) {
	fullSec := newSampleFullSecret()
	raw, _ := json.Marshal(fullSec)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sec SecretView
		if err := json.Unmarshal(raw, &sec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_Secret_Protobuf_Full(b *testing.B) {
	fullSec := newSampleFullSecret()
	type protoM interface {
		Marshal() ([]byte, error)
		Unmarshal([]byte) error
	}
	raw, err := any(fullSec).(protoM).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sec corev1.Secret
		if err := any(&sec).(protoM).Unmarshal(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_Secret_Protobuf_Trimmed(b *testing.B) {
	fullSec := newSampleFullSecret()
	rawJSON, _ := json.Marshal(fullSec)
	var secView SecretView
	_ = json.Unmarshal(rawJSON, &secView)
	wireBytes, _ := EncodeSecretProtobufEnvelope(&secView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeSecretProtobuf(wireBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_Secret_CompactBinary(b *testing.B) {
	fullSec := newSampleFullSecret()
	rawJSON, _ := json.Marshal(fullSec)
	var secView SecretView
	_ = json.Unmarshal(rawJSON, &secView)
	wireBytes, _ := EncodeSecretBinary(&secView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeSecretBinary(wireBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_HTTPRoute_JSON_Full(b *testing.B) {
	fullRoute := newSampleFullHTTPRoute()
	raw, _ := json.Marshal(fullRoute)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var route gatewayv1.HTTPRoute
		if err := json.Unmarshal(raw, &route); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_HTTPRoute_JSON_View(b *testing.B) {
	fullRoute := newSampleFullHTTPRoute()
	raw, _ := json.Marshal(fullRoute)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var route HTTPRouteView
		if err := json.Unmarshal(raw, &route); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode_HTTPRoute_CompactBinary(b *testing.B) {
	fullRoute := newSampleFullHTTPRoute()
	rawJSON, _ := json.Marshal(fullRoute)
	var routeView HTTPRouteView
	_ = json.Unmarshal(rawJSON, &routeView)
	wireBytes, _ := EncodeHTTPRouteBinary(&routeView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeHTTPRouteBinary(wireBytes); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Benchmark Cache Read Cost: DeepCopy vs View Receiver ---

func BenchmarkCacheRead_ConfigMap_Full_DeepCopy(b *testing.B) {
	cm := newSampleFullConfigMap()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := cm.DeepCopy()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

func BenchmarkCacheRead_ConfigMap_View_Receiver(b *testing.B) {
	fullCM := newSampleFullConfigMap()
	rawJSON, _ := json.Marshal(fullCM)
	var cmView ConfigMapView
	_ = json.Unmarshal(rawJSON, &cmView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := cmView.DeepCopyObject()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

func BenchmarkCacheRead_Secret_Full_DeepCopy(b *testing.B) {
	sec := newSampleFullSecret()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := sec.DeepCopy()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

func BenchmarkCacheRead_Secret_View_Receiver(b *testing.B) {
	fullSec := newSampleFullSecret()
	rawJSON, _ := json.Marshal(fullSec)
	var secView SecretView
	_ = json.Unmarshal(rawJSON, &secView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := secView.DeepCopyObject()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

func BenchmarkCacheRead_HTTPRoute_Full_DeepCopy(b *testing.B) {
	route := newSampleFullHTTPRoute()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := route.DeepCopy()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

func BenchmarkCacheRead_HTTPRoute_View_Receiver(b *testing.B) {
	fullRoute := newSampleFullHTTPRoute()
	rawJSON, _ := json.Marshal(fullRoute)
	var routeView HTTPRouteView
	_ = json.Unmarshal(rawJSON, &routeView)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cp := routeView.DeepCopyObject()
		if cp == nil {
			b.Fatal("nil copy")
		}
	}
}

// --- Benchmark ReadOnlyBytesMap.Get vs String Accessor ---

func BenchmarkReadOnlyBytesMap_Get(b *testing.B) {
	data := map[string][]byte{
		"tls.crt": bytes.Repeat([]byte("A"), 1500),
		"tls.key": bytes.Repeat([]byte("B"), 1700),
	}
	rbm := NewReadOnlyBytesMap(data)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		val, _ := rbm.Get("tls.crt")
		if len(val) == 0 {
			b.Fatal("empty value")
		}
	}
}

func BenchmarkReadOnlyMap_GetString_ZeroAlloc(b *testing.B) {
	data := map[string]string{
		"tls.crt": string(bytes.Repeat([]byte("A"), 1500)),
		"tls.key": string(bytes.Repeat([]byte("B"), 1700)),
	}
	rm := NewReadOnlyMap(data)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		val, _ := rm.Get("tls.crt")
		if len(val) == 0 {
			b.Fatal("empty value")
		}
	}
}

var _ = googleproto.Marshal
