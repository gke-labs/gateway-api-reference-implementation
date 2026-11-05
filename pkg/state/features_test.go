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
	"testing"

	"sigs.k8s.io/gateway-api/pkg/features"
)

func TestFeaturesClassification(t *testing.T) {
	supported := make(map[features.FeatureName]int)
	for _, f := range SupportedFeatures {
		supported[f]++
		if supported[f] > 1 {
			t.Errorf("feature %q is duplicated in SupportedFeatures", f)
		}
	}

	unsupported := make(map[features.FeatureName]int)
	for _, f := range unsupportedFeatures {
		unsupported[f]++
		if unsupported[f] > 1 {
			t.Errorf("feature %q is duplicated in unsupportedFeatures", f)
		}
	}

	for _, f := range features.AllFeatures.UnsortedList() {
		inSupported := supported[f.Name] > 0
		inUnsupported := unsupported[f.Name] > 0

		switch {
		case inSupported && inUnsupported:
			t.Errorf("feature %q is in both SupportedFeatures and unsupportedFeatures", f.Name)
		case !inSupported && !inUnsupported:
			t.Errorf("feature %q is unclassified (missing from both SupportedFeatures and unsupportedFeatures)", f.Name)
		}
	}

	all := make(map[features.FeatureName]bool)
	for _, f := range features.AllFeatures.UnsortedList() {
		all[f.Name] = true
	}
	for f := range supported {
		if !all[f] {
			t.Errorf("SupportedFeatures contains unknown feature %q not in features.AllFeatures", f)
		}
	}
	for f := range unsupported {
		if !all[f] {
			t.Errorf("unsupportedFeatures contains unknown feature %q not in features.AllFeatures", f)
		}
	}
}
