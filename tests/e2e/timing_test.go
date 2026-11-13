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

package e2e

import (
	"testing"
	"time"
)

func TestFormatGatewayTiming(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		gwName    string
		event     string
		elapsed   time.Duration
		expected  string
	}{
		{
			name:      "first successful request matches issue example",
			namespace: "default",
			gwName:    "reference-gateway",
			event:     "first successful request",
			elapsed:   1980 * time.Millisecond,
			expected:  "gateway default/reference-gateway: first successful request after 1.98s",
		},
		{
			name:      "address assigned timing",
			namespace: "default",
			gwName:    "reference-gateway",
			event:     "address assigned",
			elapsed:   1230 * time.Millisecond,
			expected:  "gateway default/reference-gateway: address assigned after 1.23s",
		},
		{
			name:      "Programmed=True timing",
			namespace: "default",
			gwName:    "reference-gateway",
			event:     "Programmed=True",
			elapsed:   1450 * time.Millisecond,
			expected:  "gateway default/reference-gateway: Programmed=True after 1.45s",
		},
		{
			name:      "negative elapsed duration clamped to zero",
			namespace: "prod",
			gwName:    "api-gw",
			event:     "first successful request",
			elapsed:   -50 * time.Millisecond,
			expected:  "gateway prod/api-gw: first successful request after 0.00s",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := FormatGatewayTiming(tc.namespace, tc.gwName, tc.event, tc.elapsed)
			if actual != tc.expected {
				t.Errorf("FormatGatewayTiming() = %q, expected %q", actual, tc.expected)
			}
		})
	}
}

func TestHarnessGatewayTiming(t *testing.T) {
	h := NewHarness(t, "test-cluster")
	creationTimestamp := time.Now().Add(-1980 * time.Millisecond)

	h.SetGatewayCreationTimestamp("reference-gateway", "default", creationTimestamp)

	got := h.GatewayCreationTimestamp("reference-gateway", "default")
	if !got.Equal(creationTimestamp) {
		t.Errorf("GatewayCreationTimestamp() = %v, expected %v", got, creationTimestamp)
	}

	// Verify LogGatewayTiming runs cleanly with the stored timestamp
	h.LogGatewayTiming("reference-gateway", "default", "address assigned")
	h.LogGatewayTiming("reference-gateway", "default", "Programmed=True")
	h.LogGatewayTiming("reference-gateway", "default", "first successful request")
}
