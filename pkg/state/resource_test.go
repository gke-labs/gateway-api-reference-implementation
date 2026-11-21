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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestResourceNameForGateway(t *testing.T) {
	cases := []struct {
		name, gwName, want, mustDiff string
	}{
		{name: "short valid", gwName: "my-gw", want: "gari-my-gw-b6402a44"},
		{name: "exact 63 base", gwName: strings.Repeat("a", 58)},
		{name: "valid 63", gwName: strings.Repeat("a", 63), want: "gari-" + strings.Repeat("a", 49) + "-7d3e74a0"},
		{name: "valid 253", gwName: strings.Repeat("a", 253), want: "gari-" + strings.Repeat("a", 49) + "-32859a3a"},
		// Collision test pairs: sanitized names and spelled-out hashes must differ
		{name: "valid pair A", gwName: "my-gateway", want: "gari-my-gateway-6632e849"},
		{name: "sanitized pair A", gwName: "my.gateway", want: "gari-my-gateway-0f568ee0", mustDiff: "gari-my-gateway-6632e849"},
		{name: "spelled-out hash pair", gwName: "my-gateway-0f568ee0", mustDiff: "gari-my-gateway-0f568ee0"},
		{name: "valid pair B", gwName: "g-1gw", want: "gari-g-1gw-02e06d46"},
		{name: "sanitized pair B", gwName: "1gw", want: "gari-1gw-60bcb19e", mustDiff: "gari-g-1gw-02e06d46"},
		{name: "multiple dots", gwName: "foo.bar.baz"},
		{name: "leading dot", gwName: ".leading"},
		{name: "trailing dot", gwName: "trailing."},
		{name: "long with dots", gwName: "my.gateway." + strings.Repeat("a", 242)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResourceNameForGateway(tc.gwName)
			if tc.want != "" && got != tc.want {
				t.Errorf("ResourceNameForGateway(%q) = %q, want %q", tc.gwName, got, tc.want)
			}
			if tc.mustDiff != "" && got == tc.mustDiff {
				t.Errorf("expected ResourceNameForGateway(%q) != %q, got %q", tc.gwName, tc.mustDiff, got)
			}
			if len(got) > 63 || len(validation.IsDNS1035Label(got)) > 0 {
				t.Errorf("ResourceNameForGateway(%q) = %q is not a valid DNS-1035 label", tc.gwName, got)
			}
		})
	}
}
