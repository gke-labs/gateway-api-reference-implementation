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

package scoped_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/scoped"
)

func TestLog_DefaultBareContext(t *testing.T) {
	ctx := t.Context()
	log := scoped.Log(ctx)
	if log != slog.Default() {
		t.Errorf("scoped.Log(ctx) with bare context = %v, want %v", log, slog.Default())
	}
}

func TestLog_DefaultNilContext(t *testing.T) {
	log := scoped.Log(nil)
	if log != slog.Default() {
		t.Errorf("scoped.Log(nil) = %v, want %v", log, slog.Default())
	}
}

func TestLog_WithLog(t *testing.T) {
	var buf bytes.Buffer
	custom := slog.New(slog.NewTextHandler(&buf, nil))

	ctx := scoped.WithLog(t.Context(), custom)
	log := scoped.Log(ctx)
	if log != custom {
		t.Errorf("scoped.Log(ctx) = %v, want %v", log, custom)
	}
}

func TestLog_WithLogNilReturnsDefault(t *testing.T) {
	ctx := scoped.WithLog(t.Context(), nil)
	log := scoped.Log(ctx)
	if log != slog.Default() {
		t.Errorf("scoped.Log(ctx) with nil logger = %v, want %v", log, slog.Default())
	}
}
