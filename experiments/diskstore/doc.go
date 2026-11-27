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

// Package diskstore provides disk-backed storage implementations for informer caches.
// The implementation is divided into two packages:
//   - engine: A core database engine with a WAL, self-describing 4 KiB block heap file,
//     fixed-size direct I/O block pool, out-of-place buddy allocation, crash recovery,
//     and block-level encryption. See experiments/diskstore/engine/design.md for design details.
//   - kubecache: A Kubernetes cache adapter that implements client-go's cache.Indexer
//     on top of the engine with a fail-fast error policy.
package diskstore
