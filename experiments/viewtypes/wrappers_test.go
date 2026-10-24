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
	"testing"
)

func TestReadOnlyMap(t *testing.T) {
	orig := map[string]string{
		"k1": "v1",
		"k2": "v2",
	}
	rm := NewReadOnlyMap(orig)

	if rm.Len() != 2 {
		t.Fatalf("expected Len 2, got %d", rm.Len())
	}

	val, ok := rm.Get("k1")
	if !ok || val != "v1" {
		t.Errorf("Get(k1) = (%q, %v), expected (v1, true)", val, ok)
	}

	_, ok = rm.Get("k3")
	if ok {
		t.Errorf("Get(k3) succeeded unexpectedly")
	}

	collected := make(map[string]string)
	for k, v := range rm.All() {
		collected[k] = v
	}
	if len(collected) != 2 || collected["k1"] != "v1" || collected["k2"] != "v2" {
		t.Errorf("All() yielded unexpected map: %+v", collected)
	}

	// Test early break
	count := 0
	for range rm.All() {
		count++
		break
	}
	if count != 1 {
		t.Errorf("expected 1 iteration before break, got %d", count)
	}

	// Test nil map
	var nilMap ReadOnlyMap[string, string]
	if nilMap.Len() != 0 {
		t.Errorf("nil map Len = %d, expected 0", nilMap.Len())
	}
	if _, ok := nilMap.Get("foo"); ok {
		t.Errorf("nil map Get succeeded")
	}
}

func TestReadOnlyBytesMap(t *testing.T) {
	orig := map[string][]byte{
		"cert": []byte("initial-cert"),
	}
	rbm := NewReadOnlyBytesMap(orig)

	if rbm.Len() != 1 {
		t.Fatalf("expected Len 1, got %d", rbm.Len())
	}

	val, ok := rbm.Get("cert")
	if !ok || !bytes.Equal(val, []byte("initial-cert")) {
		t.Fatalf("unexpected Get value: %s", string(val))
	}

	// Attempt mutation on returned byte slice
	val[0] = 'X'

	// Verify internal state did NOT change
	val2, ok := rbm.Get("cert")
	if !ok || !bytes.Equal(val2, []byte("initial-cert")) {
		t.Fatalf("internal state mutated! got %s, expected initial-cert", string(val2))
	}

	// Verify All iteration
	for k, v := range rbm.All() {
		if k != "cert" || !bytes.Equal(v, []byte("initial-cert")) {
			t.Errorf("unexpected entry from All: %s=%s", k, string(v))
		}
		// Mutate yielded slice
		v[0] = 'Y'
	}
	val3, _ := rbm.Get("cert")
	if !bytes.Equal(val3, []byte("initial-cert")) {
		t.Fatalf("internal state mutated via All! got %s", string(val3))
	}
}

func TestReadOnlySlice(t *testing.T) {
	orig := []string{"apple", "banana", "cherry"}
	rs := NewReadOnlySlice(orig)

	if rs.Len() != 3 {
		t.Fatalf("expected Len 3, got %d", rs.Len())
	}

	if rs.Get(1) != "banana" {
		t.Errorf("Get(1) = %s, expected banana", rs.Get(1))
	}

	var collected []string
	for idx, val := range rs.All() {
		if val != orig[idx] {
			t.Errorf("at index %d: got %s, expected %s", idx, val, orig[idx])
		}
		collected = append(collected, val)
	}
	if len(collected) != 3 {
		t.Errorf("All() collected %d items, expected 3", len(collected))
	}

	var values []string
	for val := range rs.Values() {
		values = append(values, val)
	}
	if len(values) != 3 {
		t.Errorf("Values() collected %d items, expected 3", len(values))
	}
}
