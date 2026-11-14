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

func TestConfig_ComputeRevision_OrderInvariance(t *testing.T) {
	r1 := Record{Name: "alpha.local", Addresses: []string{"192.168.1.1"}}
	r2 := Record{Name: "beta.local", Addresses: []string{"192.168.1.2"}}
	r3 := Record{Name: "gamma.local", Addresses: []string{"192.168.1.3", "2001:db8::1"}}

	permutations := [][]Record{
		{r1, r2, r3},
		{r1, r3, r2},
		{r2, r1, r3},
		{r2, r3, r1},
		{r3, r1, r2},
		{r3, r2, r1},
	}

	var baseRev string
	for i, perm := range permutations {
		cfg := Config{Records: perm}
		rev, err := cfg.ComputeRevision()
		if err != nil {
			t.Fatalf("ComputeRevision failed for permutation %d: %v", i, err)
		}
		if rev == "" {
			t.Fatalf("expected non-empty revision for permutation %d", i)
		}
		if i == 0 {
			baseRev = rev
		} else if rev != baseRev {
			t.Errorf("permutation %d produced revision %q, want %q", i, rev, baseRev)
		}
	}
}

func TestConfig_ComputeRevision_DifferentRecordsDifferentRevision(t *testing.T) {
	cfg1 := Config{
		Records: []Record{
			{Name: "alpha.local", Addresses: []string{"192.168.1.1"}},
		},
	}
	cfg2 := Config{
		Records: []Record{
			{Name: "alpha.local", Addresses: []string{"192.168.1.2"}},
		},
	}
	cfg3 := Config{
		Records: []Record{
			{Name: "beta.local", Addresses: []string{"192.168.1.1"}},
		},
	}

	rev1, err := cfg1.ComputeRevision()
	if err != nil {
		t.Fatalf("cfg1 ComputeRevision failed: %v", err)
	}
	rev2, err := cfg2.ComputeRevision()
	if err != nil {
		t.Fatalf("cfg2 ComputeRevision failed: %v", err)
	}
	rev3, err := cfg3.ComputeRevision()
	if err != nil {
		t.Fatalf("cfg3 ComputeRevision failed: %v", err)
	}

	if rev1 == rev2 {
		t.Errorf("expected different revisions for differing addresses, got %q", rev1)
	}
	if rev1 == rev3 {
		t.Errorf("expected different revisions for differing names, got %q", rev1)
	}
}

func TestConfig_ComputeRevision_EmptyAndNil(t *testing.T) {
	cfgNil := Config{Records: nil}
	cfgEmpty := Config{Records: []Record{}}

	revNil, err := cfgNil.ComputeRevision()
	if err != nil {
		t.Fatalf("cfgNil ComputeRevision failed: %v", err)
	}
	revEmpty, err := cfgEmpty.ComputeRevision()
	if err != nil {
		t.Fatalf("cfgEmpty ComputeRevision failed: %v", err)
	}

	if revNil != revEmpty {
		t.Errorf("expected nil and empty records to yield same revision, got nil=%q empty=%q", revNil, revEmpty)
	}
}
