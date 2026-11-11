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
	"strings"
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

func TestRun(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "missing socket",
			args:        []string{"--socket="},
			errContains: "--socket is required",
		},
		{
			name:        "invalid allowed-uids",
			args:        []string{"--allowed-uids=abc"},
			errContains: "invalid --allowed-uids",
		},
		{
			name:        "invalid allowed-gids",
			args:        []string{"--allowed-gids=xyz"},
			errContains: "invalid --allowed-gids",
		},
		{
			name:        "no allowed uids or gids",
			args:        nil,
			errContains: "at least one of --allowed-uids or --allowed-gids must be specified",
		},
		{
			name:        "invalid keys directory",
			args:        []string{"--allowed-uids=1000", "--keys-dir=/nonexistent/dir/that/does/not/exist"},
			errContains: "failed to initialize custodian server",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
			}
		})
	}
}
