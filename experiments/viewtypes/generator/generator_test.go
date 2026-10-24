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

package generator

import (
	"go/format"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKind(t *testing.T) {
	specs := DefaultSpecs()
	if len(specs) != 3 {
		t.Fatalf("expected 3 default specs, got %d", len(specs))
	}

	for _, spec := range specs {
		t.Run(spec.Kind, func(t *testing.T) {
			code, err := GenerateKind(spec)
			if err != nil {
				t.Fatalf("GenerateKind(%s) error = %v", spec.Kind, err)
			}
			if len(code) == 0 {
				t.Fatalf("GenerateKind(%s) returned empty code", spec.Kind)
			}
			formatted, err := format.Source(code)
			if err != nil {
				t.Fatalf("GenerateKind(%s) output is not valid gofmt code: %v", spec.Kind, err)
			}
			if len(formatted) == 0 {
				t.Fatalf("format.Source returned empty for %s", spec.Kind)
			}
		})
	}
}

func TestGenerateAll(t *testing.T) {
	tmpDir := t.TempDir()
	if err := GenerateAll(tmpDir); err != nil {
		t.Fatalf("GenerateAll failed: %v", err)
	}

	expectedFiles := []string{
		"configmap_view.go",
		"secret_view.go",
		"httproute_view.go",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(tmpDir, f)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("expected file %s not found: %v", f, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("file %s is empty", f)
		}
	}
}
