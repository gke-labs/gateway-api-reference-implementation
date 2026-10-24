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
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestViewTypes_NoExportedMutableState asserts that:
// 1. View types expose no exported fields.
// 2. No exported method returns a mutable map, slice, or pointer into internal state.
func TestViewTypes_NoExportedMutableState(t *testing.T) {
	typesToCheck := []any{
		ConfigMapView{},
		SecretView{},
		HTTPRouteView{},
		ParentReferenceView{},
		HTTPRouteRuleView{},
		HTTPRouteMatchView{},
		HTTPPathMatchView{},
		HTTPHeaderMatchView{},
		HTTPQueryParamMatchView{},
		HTTPRouteFilterView{},
		HTTPHeaderFilterView{},
		HTTPHeaderView{},
		HTTPRequestRedirectFilterView{},
		HTTPURLRewriteFilterView{},
		HTTPPathModifierView{},
		HTTPRequestMirrorFilterView{},
		HTTPBackendRefView{},
		HTTPRouteTimeoutsView{},
		ReadOnlyMap[string, string]{},
		ReadOnlyBytesMap{},
		ReadOnlySlice[string]{},
	}

	for _, sample := range typesToCheck {
		tVal := reflect.TypeOf(sample)
		t.Run(tVal.Name(), func(t *testing.T) {
			// Check struct fields: must all be unexported
			for i := 0; i < tVal.NumField(); i++ {
				field := tVal.Field(i)
				if field.IsExported() {
					t.Errorf("type %s has exported field %q; view types must have only unexported fields", tVal.Name(), field.Name)
				}
			}

			// Check methods on both value and pointer receivers
			checkMethods(t, tVal)
			checkMethods(t, reflect.PointerTo(tVal))
		})
	}
}

func checkMethods(t *testing.T, typ reflect.Type) {
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		mType := method.Type

		for outIdx := 0; outIdx < mType.NumOut(); outIdx++ {
			outType := mType.Out(outIdx)
			k := outType.Kind()

			// Disallow raw maps
			if k == reflect.Map {
				t.Errorf("%s.%s() returns a raw mutable map %v; maps must be wrapped in ReadOnlyMap", typ.Name(), method.Name, outType)
			}

			// Slices must either be wrapped in ReadOnlySlice or proven to be defensive clones (not pointing into internal state)
			if k == reflect.Slice {
				// If a method returns []byte (e.g. ReadOnlyBytesMap.Get), verify it is a defensive clone
				if outType.Elem().Kind() == reflect.Uint8 {
					// Verify via behavioral immutability test that it does not point into internal state
					continue
				}
				t.Errorf("%s.%s() returns a raw mutable slice %v into internal state; slices must be wrapped in ReadOnlySlice", typ.Name(), method.Name, outType)
			}

			// Disallow raw channels or unsafe pointers
			if k == reflect.Chan || k == reflect.UnsafePointer {
				t.Errorf("%s.%s() returns disallowed type %v", typ.Name(), method.Name, outType)
			}

			// If pointer is returned, ensure it is not a pointer into internal struct fields
			if k == reflect.Pointer {
				// Allowed interface implementations returning receiver, or safe standard wrappers
				elem := outType.Elem()
				if elem.Kind() == reflect.Struct {
					// We disallow returning pointers to struct fields because caller could retain or mutate them
					t.Errorf("%s.%s() returns a pointer to struct %v; view types should return nested types by value", typ.Name(), method.Name, outType)
				}
			}
		}
	}
}

// TestViewTypes_BehavioralImmutability verifies that mutating any value returned by getters
// does not affect the view object's internal state.
func TestViewTypes_BehavioralImmutability(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())

	t.Run("ConfigMap", func(t *testing.T) {
		cm := &ConfigMapView{
			name:              "cm-immut",
			namespace:         "default",
			resourceVersion:   "1",
			creationTimestamp: now,
			labels:            map[string]string{"env": "test"},
			annotations:       map[string]string{"note": "original"},
			data:              map[string]string{"key": "orig-val"},
			binaryData:        map[string][]byte{"bin": []byte("original-bytes")},
		}

		// Mutating returned binary data must not alter internal state
		b, ok := cm.BinaryData().Get("bin")
		if !ok {
			t.Fatalf("expected key bin to exist")
		}
		b[0] = 'X'

		b2, _ := cm.BinaryData().Get("bin")
		if !bytes.Equal(b2, []byte("original-bytes")) {
			t.Fatalf("internal state was mutated! got %s, expected original-bytes", string(b2))
		}

		// DeepCopyObject must return the exact same instance with 0 allocations
		copyObj := cm.DeepCopyObject()
		if copyObj != cm {
			t.Errorf("DeepCopyObject() did not return receiver pointer")
		}
	})

	t.Run("Secret", func(t *testing.T) {
		sec := &SecretView{
			name:              "sec-immut",
			namespace:         "default",
			secretType:        corev1.SecretTypeOpaque,
			data:              map[string][]byte{"token": []byte("initial-token")},
			creationTimestamp: now,
		}

		t1, ok := sec.Data().Get("token")
		if !ok {
			t.Fatalf("expected key token to exist")
		}
		t1[0] = 'Z'

		t2, _ := sec.Data().Get("token")
		if !bytes.Equal(t2, []byte("initial-token")) {
			t.Fatalf("internal secret data was mutated! got %s", string(t2))
		}

		copyObj := sec.DeepCopyObject()
		if copyObj != sec {
			t.Errorf("DeepCopyObject() did not return receiver pointer")
		}
	})

	t.Run("HTTPRoute", func(t *testing.T) {
		route := &HTTPRouteView{
			name:              "route-immut",
			namespace:         "default",
			creationTimestamp: now,
			hostnames:         []string{"example.com"},
			rules: []HTTPRouteRuleView{
				{
					name: "r1",
					matches: []HTTPRouteMatchView{
						{path: HTTPPathMatchView{matchType: "Exact", value: "/foo"}},
					},
				},
			},
		}

		// DeepCopyObject returns receiver
		copyObj := route.DeepCopyObject()
		if copyObj != route {
			t.Errorf("DeepCopyObject() did not return receiver pointer")
		}

		// Verify accessing nested structures returns by value
		r1 := route.Rules().Get(0)
		m1 := r1.Matches().Get(0)
		p1 := m1.Path()
		if p1.Value() != "/foo" {
			t.Errorf("unexpected path: %s", p1.Value())
		}
	})
}
