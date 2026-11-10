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

//go:build linux || darwin

package main

import (
	"reflect"
	"testing"
)

func TestParseIDList(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expected    []uint32
		expectError bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single id",
			input:    "1000",
			expected: []uint32{1000},
		},
		{
			name:     "multiple ids with spaces",
			input:    " 1000, 2000 ,3000 ",
			expected: []uint32{1000, 2000, 3000},
		},
		{
			name:        "invalid id",
			input:       "1000,abc",
			expectError: true,
		},
		{
			name:        "negative id",
			input:       "-1",
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := parseIDList(testCase.input)
			if (err != nil) != testCase.expectError {
				t.Fatalf("parseIDList(%q) error = %v, expectError = %v", testCase.input, err, testCase.expectError)
			}
			if !testCase.expectError && !reflect.DeepEqual(result, testCase.expected) {
				t.Fatalf("parseIDList(%q) = %v, expected %v", testCase.input, result, testCase.expected)
			}
		})
	}
}
