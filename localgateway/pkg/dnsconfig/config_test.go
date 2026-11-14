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

package dnsconfig

import (
	"testing"
)

func TestConfig_ComputeRevision_Deterministic(t *testing.T) {
	config := Config{
		Records: []Record{
			{Name: "alpha.local", Addresses: []string{"192.168.1.1"}},
			{Name: "beta.local", Addresses: []string{"192.168.1.2"}},
		},
	}
	revision1, err := config.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision failed: %v", err)
	}
	revision2, err := config.ComputeRevision()
	if err != nil {
		t.Fatalf("ComputeRevision failed: %v", err)
	}
	if revision1 != revision2 || revision1 == "" {
		t.Errorf("expected deterministic non-empty revision, got revision1=%q revision2=%q", revision1, revision2)
	}
}

func TestConfig_ComputeRevision_DifferentRecords(t *testing.T) {
	config1 := Config{
		Records: []Record{
			{Name: "alpha.local", Addresses: []string{"192.168.1.1"}},
		},
	}
	config2 := Config{
		Records: []Record{
			{Name: "alpha.local", Addresses: []string{"192.168.1.2"}},
		},
	}
	config3 := Config{
		Records: []Record{
			{Name: "beta.local", Addresses: []string{"192.168.1.1"}},
		},
	}

	revision1, err := config1.ComputeRevision()
	if err != nil {
		t.Fatalf("config1 ComputeRevision failed: %v", err)
	}
	revision2, err := config2.ComputeRevision()
	if err != nil {
		t.Fatalf("config2 ComputeRevision failed: %v", err)
	}
	revision3, err := config3.ComputeRevision()
	if err != nil {
		t.Fatalf("config3 ComputeRevision failed: %v", err)
	}

	if revision1 == revision2 {
		t.Errorf("expected different revisions for differing addresses, got %q", revision1)
	}
	if revision1 == revision3 {
		t.Errorf("expected different revisions for differing names, got %q", revision1)
	}
}
