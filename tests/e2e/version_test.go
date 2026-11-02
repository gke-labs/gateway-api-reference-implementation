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
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/util/version"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

func validatePreviousMinorCRDVersion(prevVersion, compiledVersion string) error {
	compiledV, err := version.ParseSemantic(compiledVersion)
	if err != nil {
		return fmt.Errorf("failed to parse compiled bundle version %q: %w", compiledVersion, err)
	}
	prevV, err := version.ParseSemantic(prevVersion)
	if err != nil {
		return fmt.Errorf("failed to parse previous minor CRD version %q: %w", prevVersion, err)
	}
	if compiledV.Minor() == 0 {
		return fmt.Errorf("gatewayconsts.BundleVersion (%s) has minor version 0: no previous minor exists within the major version", compiledVersion)
	}
	if prevV.Major() != compiledV.Major() || prevV.Minor()+1 != compiledV.Minor() {
		return fmt.Errorf("PreviousMinorCRDVersion (%s) must be exactly one minor version behind gatewayconsts.BundleVersion (%s). When bumping Gateway API to a new minor version, please update PreviousMinorCRDVersion in tests/e2e/harness.go to the latest patch release of v%d.%d.x",
			prevVersion, compiledVersion, compiledV.Major(), compiledV.Minor()-1)
	}
	return nil
}

func TestPreviousMinorCRDVersion(t *testing.T) {
	if err := validatePreviousMinorCRDVersion(PreviousMinorCRDVersion, gatewayconsts.BundleVersion); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePreviousMinorCRDVersion(t *testing.T) {
	tests := []struct {
		name            string
		prevVersion     string
		compiledVersion string
		wantErr         bool
		expectedErr     string
	}{
		{
			name:            "valid previous minor (v1.6.3 behind v1.7.0)",
			prevVersion:     "v1.6.3",
			compiledVersion: "v1.7.0",
			wantErr:         false,
		},
		{
			name:            "same minor not allowed",
			prevVersion:     "v1.7.0",
			compiledVersion: "v1.7.0",
			wantErr:         true,
			expectedErr:     "PreviousMinorCRDVersion (v1.7.0) must be exactly one minor version behind gatewayconsts.BundleVersion (v1.7.0). When bumping Gateway API to a new minor version, please update PreviousMinorCRDVersion in tests/e2e/harness.go to the latest patch release of v1.6.x",
		},
		{
			name:            "two minors behind (simulating gatewayconsts.BundleVersion bump to v1.8.0 without updating PreviousMinorCRDVersion)",
			prevVersion:     "v1.6.3",
			compiledVersion: "v1.8.0",
			wantErr:         true,
			expectedErr:     "PreviousMinorCRDVersion (v1.6.3) must be exactly one minor version behind gatewayconsts.BundleVersion (v1.8.0). When bumping Gateway API to a new minor version, please update PreviousMinorCRDVersion in tests/e2e/harness.go to the latest patch release of v1.7.x",
		},
		{
			name:            "different major",
			prevVersion:     "v1.6.3",
			compiledVersion: "v2.0.0",
			wantErr:         true,
			expectedErr:     "gatewayconsts.BundleVersion (v2.0.0) has minor version 0: no previous minor exists within the major version",
		},
		{
			name:            "different major with non-zero minor",
			prevVersion:     "v1.6.3",
			compiledVersion: "v2.1.0",
			wantErr:         true,
			expectedErr:     "PreviousMinorCRDVersion (v1.6.3) must be exactly one minor version behind gatewayconsts.BundleVersion (v2.1.0). When bumping Gateway API to a new minor version, please update PreviousMinorCRDVersion in tests/e2e/harness.go to the latest patch release of v2.0.x",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePreviousMinorCRDVersion(tc.prevVersion, tc.compiledVersion)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePreviousMinorCRDVersion() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.expectedErr != "" && err != nil && err.Error() != tc.expectedErr {
				t.Errorf("expected error %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}
