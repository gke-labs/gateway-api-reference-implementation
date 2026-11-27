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

// Package engine implements the disk-store database engine.
// It provides crash-consistent key-value storage using a write-ahead log,
// a self-describing block heap file, a fixed-size block pool, out-of-place
// buddy allocation, payload compression, and block-level encryption.
//
// See design.md for the engine design, terminology, on-disk formats, and invariants.
package engine
