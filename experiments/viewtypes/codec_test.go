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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestJSONDecoder_DropsUnreadFields(t *testing.T) {
	t.Run("ConfigMap", func(t *testing.T) {
		now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		fullCM := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-cm",
				Namespace:         "default",
				UID:               "cm-uid-123",
				ResourceVersion:   "456",
				Generation:        2,
				CreationTimestamp: now,
				Labels:            map[string]string{"env": "prod"},
				Annotations:       map[string]string{"note": "test"},
				Finalizers:        []string{"kubernetes.io/dummy-finalizer"},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: "v1", Kind: "Pod", Name: "my-pod", UID: "pod-123"},
				},
				ManagedFields: []metav1.ManagedFieldsEntry{
					{
						Manager:    "kubectl",
						Operation:  metav1.ManagedFieldsOperationApply,
						APIVersion: "v1",
						Time:       &now,
						FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:data":{"f:key":{}}}`)},
					},
					{
						Manager:    "controller",
						Operation:  metav1.ManagedFieldsOperationUpdate,
						APIVersion: "v1",
						Time:       &now,
						FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{"f:env":{}}}}`)},
					},
				},
			},
			Data: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
			BinaryData: map[string][]byte{
				"bin1": []byte("binary-payload-data"),
			},
		}

		rawJSON, err := json.Marshal(fullCM)
		if err != nil {
			t.Fatalf("failed to marshal full ConfigMap: %v", err)
		}

		var view ConfigMapView
		if err := json.Unmarshal(rawJSON, &view); err != nil {
			t.Fatalf("failed to unmarshal into ConfigMapView: %v", err)
		}

		if view.Name() != "test-cm" {
			t.Errorf("Name = %q, expected test-cm", view.Name())
		}
		if view.Namespace() != "default" {
			t.Errorf("Namespace = %q, expected default", view.Namespace())
		}
		if view.UID() != "cm-uid-123" {
			t.Errorf("UID = %q, expected cm-uid-123", view.UID())
		}
		if view.ResourceVersion() != "456" {
			t.Errorf("ResourceVersion = %q, expected 456", view.ResourceVersion())
		}
		if view.Generation() != 2 {
			t.Errorf("Generation = %d, expected 2", view.Generation())
		}
		ct := view.CreationTimestamp()
		if !ct.Equal(&now) {
			t.Errorf("CreationTimestamp = %v, expected %v", ct, now)
		}
		if val, ok := view.Labels().Get("env"); !ok || val != "prod" {
			t.Errorf("Labels[env] = %q, %v", val, ok)
		}
		if val, ok := view.Annotations().Get("note"); !ok || val != "test" {
			t.Errorf("Annotations[note] = %q, %v", val, ok)
		}
		if val, ok := view.Data().Get("key1"); !ok || val != "val1" {
			t.Errorf("Data[key1] = %q, %v", val, ok)
		}
		if bin, ok := view.BinaryData().Get("bin1"); !ok || !bytes.Equal(bin, []byte("binary-payload-data")) {
			t.Errorf("BinaryData[bin1] = %q, %v", string(bin), ok)
		}
	})

	t.Run("Secret", func(t *testing.T) {
		now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		fullSec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "my-secret",
				Namespace:         "kube-system",
				UID:               "sec-uid-789",
				ResourceVersion:   "999",
				Generation:        1,
				CreationTimestamp: now,
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "kube-controller-manager", Operation: metav1.ManagedFieldsOperationUpdate},
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("tls-cert-content"),
				corev1.TLSPrivateKeyKey: []byte("tls-key-content"),
			},
		}

		rawJSON, err := json.Marshal(fullSec)
		if err != nil {
			t.Fatalf("failed to marshal Secret: %v", err)
		}

		var view SecretView
		if err := json.Unmarshal(rawJSON, &view); err != nil {
			t.Fatalf("failed to unmarshal into SecretView: %v", err)
		}

		if view.Name() != "my-secret" || view.Namespace() != "kube-system" {
			t.Errorf("unexpected identity: %s/%s", view.Namespace(), view.Name())
		}
		if view.Type() != corev1.SecretTypeTLS {
			t.Errorf("Type = %s, expected TLS", view.Type())
		}
		cert, ok := view.Data().Get(corev1.TLSCertKey)
		if !ok || !bytes.Equal(cert, []byte("tls-cert-content")) {
			t.Errorf("unexpected cert: %s", string(cert))
		}
	})

	t.Run("HTTPRoute", func(t *testing.T) {
		pathType := gatewayv1.PathMatchPathPrefix
		pathVal := "/api/v1"
		method := gatewayv1.HTTPMethodGet
		secName := gatewayv1.SectionName("rule-1")
		port := gatewayv1.PortNumber(8080)
		weight := int32(100)

		fullRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "api-route",
				Namespace:       "gateway-infra",
				ResourceVersion: "12345",
				Generation:      3,
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "helm", Operation: metav1.ManagedFieldsOperationApply},
				},
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Hostnames: []gatewayv1.Hostname{"api.example.com"},
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "main-gateway",
							Port: &port,
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Name: &secName,
						Matches: []gatewayv1.HTTPRouteMatch{
							{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  &pathType,
									Value: &pathVal,
								},
								Method: &method,
							},
						},
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "api-service",
										Port: &port,
									},
									Weight: &weight,
								},
							},
						},
					},
				},
			},
			Status: gatewayv1.HTTPRouteStatus{
				RouteStatus: gatewayv1.RouteStatus{
					Parents: []gatewayv1.RouteParentStatus{
						{ParentRef: gatewayv1.ParentReference{Name: "main-gateway"}},
					},
				},
			},
		}

		rawJSON, err := json.Marshal(fullRoute)
		if err != nil {
			t.Fatalf("failed to marshal HTTPRoute: %v", err)
		}

		var view HTTPRouteView
		if err := json.Unmarshal(rawJSON, &view); err != nil {
			t.Fatalf("failed to unmarshal into HTTPRouteView: %v", err)
		}

		if view.Name() != "api-route" || view.Namespace() != "gateway-infra" {
			t.Errorf("unexpected identity: %s/%s", view.Namespace(), view.Name())
		}
		if view.Hostnames().Len() != 1 || view.Hostnames().Get(0) != "api.example.com" {
			t.Errorf("unexpected hostnames: %+v", view.Hostnames())
		}
		if view.ParentRefs().Len() != 1 || view.ParentRefs().Get(0).Name() != "main-gateway" {
			t.Errorf("unexpected parent refs: %+v", view.ParentRefs())
		}
		if view.Rules().Len() != 1 {
			t.Fatalf("expected 1 rule, got %d", view.Rules().Len())
		}
		rule := view.Rules().Get(0)
		if rule.Name() != "rule-1" {
			t.Errorf("rule Name = %s, expected rule-1", rule.Name())
		}
		if rule.Matches().Len() != 1 {
			t.Fatalf("expected 1 match, got %d", rule.Matches().Len())
		}
		match := rule.Matches().Get(0)
		if match.Path().Type() != string(gatewayv1.PathMatchPathPrefix) || match.Path().Value() != "/api/v1" {
			t.Errorf("unexpected path match: type=%s, val=%s", match.Path().Type(), match.Path().Value())
		}
		if match.Method() != "GET" {
			t.Errorf("method = %s, expected GET", match.Method())
		}
		if rule.BackendRefs().Len() != 1 || rule.BackendRefs().Get(0).Name() != "api-service" {
			t.Errorf("unexpected backend ref: %+v", rule.BackendRefs())
		}
	})
}

func TestProtobufCodec_RoundTrip(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))

	t.Run("ConfigMap", func(t *testing.T) {
		orig := &ConfigMapView{
			name:              "cm-proto",
			namespace:         "test-ns",
			uid:               "uid-cm-proto",
			resourceVersion:   "555",
			generation:        1,
			creationTimestamp: now,
			labels:            map[string]string{"tier": "frontend"},
			annotations:       map[string]string{"managed-by": "gari"},
			data:              map[string]string{"foo": "bar", "alpha": "beta"},
			binaryData:        map[string][]byte{"cert.bin": []byte("proto-binary-bytes")},
		}

		wireBytes, err := EncodeConfigMapProtobufEnvelope(orig)
		if err != nil {
			t.Fatalf("failed to encode protobuf envelope: %v", err)
		}

		decoded, err := DecodeConfigMapProtobuf(wireBytes)
		if err != nil {
			t.Fatalf("failed to decode protobuf envelope: %v", err)
		}

		if decoded.Name() != orig.Name() || decoded.Namespace() != orig.Namespace() {
			t.Errorf("identity mismatch: %s/%s vs %s/%s", decoded.Namespace(), decoded.Name(), orig.Namespace(), orig.Name())
		}
		if decoded.UID() != orig.UID() || decoded.ResourceVersion() != orig.ResourceVersion() {
			t.Errorf("meta mismatch: uid=%s rv=%s", decoded.UID(), decoded.ResourceVersion())
		}
		if val, ok := decoded.Data().Get("foo"); !ok || val != "bar" {
			t.Errorf("Data[foo] mismatch: %s, %v", val, ok)
		}
		if bin, ok := decoded.BinaryData().Get("cert.bin"); !ok || !bytes.Equal(bin, []byte("proto-binary-bytes")) {
			t.Errorf("BinaryData[cert.bin] mismatch: %s, %v", string(bin), ok)
		}
	})

	t.Run("Secret", func(t *testing.T) {
		orig := &SecretView{
			name:              "sec-proto",
			namespace:         "test-ns",
			uid:               "uid-sec-proto",
			resourceVersion:   "777",
			generation:        3,
			creationTimestamp: now,
			labels:            map[string]string{"app": "gateway"},
			secretType:        corev1.SecretTypeOpaque,
			data:              map[string][]byte{"password": []byte("super-secret-pwd")},
		}

		wireBytes, err := EncodeSecretProtobufEnvelope(orig)
		if err != nil {
			t.Fatalf("failed to encode Secret protobuf envelope: %v", err)
		}

		decoded, err := DecodeSecretProtobuf(wireBytes)
		if err != nil {
			t.Fatalf("failed to decode Secret protobuf envelope: %v", err)
		}

		if decoded.Name() != orig.Name() || decoded.Type() != orig.Type() {
			t.Errorf("name/type mismatch: %s, %s", decoded.Name(), decoded.Type())
		}
		pwd, ok := decoded.Data().Get("password")
		if !ok || !bytes.Equal(pwd, []byte("super-secret-pwd")) {
			t.Errorf("secret data mismatch: %s, %v", string(pwd), ok)
		}
	})

	t.Run("ConfigMapList", func(t *testing.T) {
		cm1 := &ConfigMapView{name: "cm-1", namespace: "ns-1", resourceVersion: "1"}
		cm2 := &ConfigMapView{name: "cm-2", namespace: "ns-1", resourceVersion: "2"}
		list := &ConfigMapViewList{
			metadata: metav1.ListMeta{ResourceVersion: "100"},
			Items:    []*ConfigMapView{cm1, cm2},
		}

		wireBytes, err := EncodeConfigMapListProtobufEnvelope(list)
		if err != nil {
			t.Fatalf("failed to encode ConfigMapList: %v", err)
		}

		decodedList, err := DecodeConfigMapListProtobuf(wireBytes)
		if err != nil {
			t.Fatalf("failed to decode ConfigMapList: %v", err)
		}

		if decodedList.GetListMeta().GetResourceVersion() != "100" {
			t.Errorf("ListMeta RV = %s, expected 100", decodedList.GetListMeta().GetResourceVersion())
		}
		if len(decodedList.Items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(decodedList.Items))
		}
		if decodedList.Items[0].Name() != "cm-1" || decodedList.Items[1].Name() != "cm-2" {
			t.Errorf("unexpected list items: %s, %s", decodedList.Items[0].Name(), decodedList.Items[1].Name())
		}
	})

	t.Run("SecretList", func(t *testing.T) {
		sec1 := &SecretView{name: "sec-1", namespace: "ns-1", secretType: corev1.SecretTypeOpaque}
		sec2 := &SecretView{name: "sec-2", namespace: "ns-1", secretType: corev1.SecretTypeTLS}
		list := &SecretViewList{
			metadata: metav1.ListMeta{ResourceVersion: "200"},
			Items:    []*SecretView{sec1, sec2},
		}

		wireBytes, err := EncodeSecretListProtobufEnvelope(list)
		if err != nil {
			t.Fatalf("failed to encode SecretList: %v", err)
		}

		decodedList, err := DecodeSecretListProtobuf(wireBytes)
		if err != nil {
			t.Fatalf("failed to decode SecretList: %v", err)
		}

		if decodedList.GetListMeta().GetResourceVersion() != "200" {
			t.Errorf("ListMeta RV = %s, expected 200", decodedList.GetListMeta().GetResourceVersion())
		}
		if len(decodedList.Items) != 2 {
			t.Fatalf("expected 2 items, got %d", len(decodedList.Items))
		}
	})
}

func TestCompactBinaryCodec_RoundTrip(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))

	t.Run("ConfigMap", func(t *testing.T) {
		orig := &ConfigMapView{
			name:              "compact-cm",
			namespace:         "default",
			uid:               "uid-compact-1",
			resourceVersion:   "8888",
			generation:        5,
			creationTimestamp: now,
			labels:            map[string]string{"k": "v"},
			annotations:       map[string]string{"ann": "val"},
			data:              map[string]string{"app.yaml": "replicas: 3"},
			binaryData:        map[string][]byte{"ca.crt": []byte("test-ca-bytes")},
		}

		enc, err := EncodeConfigMapBinary(orig)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}

		dec, err := DecodeConfigMapBinary(enc)
		if err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if dec.Name() != orig.Name() || dec.Namespace() != orig.Namespace() || dec.UID() != orig.UID() {
			t.Errorf("meta mismatch: %s/%s uid=%s", dec.Namespace(), dec.Name(), dec.UID())
		}
		if dec.ResourceVersion() != orig.ResourceVersion() || dec.Generation() != orig.Generation() {
			t.Errorf("rv/gen mismatch: %s, %d", dec.ResourceVersion(), dec.Generation())
		}
		val, ok := dec.Data().Get("app.yaml")
		if !ok || val != "replicas: 3" {
			t.Errorf("data mismatch: %s, %v", val, ok)
		}
		bin, ok := dec.BinaryData().Get("ca.crt")
		if !ok || !bytes.Equal(bin, []byte("test-ca-bytes")) {
			t.Errorf("binaryData mismatch: %s, %v", string(bin), ok)
		}
	})

	t.Run("Secret", func(t *testing.T) {
		orig := &SecretView{
			name:              "compact-sec",
			namespace:         "secure-ns",
			uid:               "uid-compact-sec",
			resourceVersion:   "9999",
			generation:        2,
			creationTimestamp: now,
			labels:            map[string]string{"type": "tls"},
			secretType:        corev1.SecretTypeTLS,
			data:              map[string][]byte{"tls.crt": []byte("crt-bytes"), "tls.key": []byte("key-bytes")},
		}

		enc, err := EncodeSecretBinary(orig)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}

		dec, err := DecodeSecretBinary(enc)
		if err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if dec.Name() != orig.Name() || dec.Type() != orig.Type() {
			t.Errorf("name/type mismatch: %s, %s", dec.Name(), dec.Type())
		}
		crt, ok := dec.Data().Get("tls.crt")
		if !ok || !bytes.Equal(crt, []byte("crt-bytes")) {
			t.Errorf("data mismatch: %s, %v", string(crt), ok)
		}
	})

	t.Run("HTTPRoute", func(t *testing.T) {
		orig := &HTTPRouteView{
			name:              "compact-route",
			namespace:         "routes-ns",
			uid:               "uid-compact-route",
			resourceVersion:   "11111",
			generation:        4,
			creationTimestamp: now,
			labels:            map[string]string{"env": "staging"},
			hostnames:         []string{"route.staging.example.com", "alt.example.com"},
			parentRefs: []ParentReferenceView{
				{group: "gateway.networking.k8s.io", kind: "Gateway", namespace: "routes-ns", name: "gw-1", port: 443},
			},
			rules: []HTTPRouteRuleView{
				{
					name: "login-rule",
					matches: []HTTPRouteMatchView{
						{
							path:   HTTPPathMatchView{matchType: "PathPrefix", value: "/login"},
							method: "POST",
							headers: []HTTPHeaderMatchView{
								{matchType: "Exact", name: "X-Auth-Version", value: "2"},
							},
						},
					},
					filters: []HTTPRouteFilterView{
						{
							filterType: "RequestHeaderModifier",
							requestHeaderModifier: HTTPHeaderFilterView{
								set:    []HTTPHeaderView{{name: "X-Client", value: "GARI"}},
								remove: []string{"X-Secret"},
							},
						},
					},
					backendRefs: []HTTPBackendRefView{
						{group: "", kind: "Service", namespace: "routes-ns", name: "auth-svc", port: 8080, weight: 100},
					},
					timeouts: HTTPRouteTimeoutsView{
						request:        "10s",
						backendRequest: "5s",
					},
				},
			},
		}

		enc, err := EncodeHTTPRouteBinary(orig)
		if err != nil {
			t.Fatalf("failed to encode: %v", err)
		}

		dec, err := DecodeHTTPRouteBinary(enc)
		if err != nil {
			t.Fatalf("failed to decode: %v", err)
		}

		if dec.Name() != orig.Name() || dec.Namespace() != orig.Namespace() {
			t.Errorf("name/namespace mismatch: %s/%s", dec.Namespace(), dec.Name())
		}
		if dec.Hostnames().Len() != 2 || dec.Hostnames().Get(0) != "route.staging.example.com" {
			t.Errorf("hostnames mismatch: %+v", dec.Hostnames())
		}
		if dec.ParentRefs().Len() != 1 || dec.ParentRefs().Get(0).Port() != 443 {
			t.Errorf("parentRefs mismatch: %+v", dec.ParentRefs())
		}
		if dec.Rules().Len() != 1 {
			t.Fatalf("expected 1 rule, got %d", dec.Rules().Len())
		}
		r := dec.Rules().Get(0)
		if r.Name() != "login-rule" {
			t.Errorf("rule name mismatch: %s", r.Name())
		}
		if r.Matches().Len() != 1 || r.Matches().Get(0).Path().Value() != "/login" {
			t.Errorf("matches mismatch: %+v", r.Matches())
		}
		if r.Timeouts().Request() != "10s" || r.Timeouts().BackendRequest() != "5s" {
			t.Errorf("timeouts mismatch: req=%s, bk=%s", r.Timeouts().Request(), r.Timeouts().BackendRequest())
		}
	})
}
