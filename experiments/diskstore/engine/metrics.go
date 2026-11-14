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

package engine

import "sync/atomic"

// Metrics tracks runtime counters for diskstore operations.
type Metrics struct {
	OversizeObjectsCount      atomic.Int64
	DirectIOFallbackCount     atomic.Int64
	QuarantineSweepFilesCount atomic.Int64
	QuarantineSweepBytesCount atomic.Int64
}

// GlobalMetrics holds the shared store metrics instance.
var GlobalMetrics = &Metrics{}

// OversizeCount returns the current count of active oversize objects.
func OversizeCount() int64 {
	return GlobalMetrics.OversizeObjectsCount.Load()
}

// DirectIOFallbackCount returns the number of times direct I/O fell back to buffered I/O.
func DirectIOFallbackCount() int64 {
	return GlobalMetrics.DirectIOFallbackCount.Load()
}

// QuarantineSweepFilesCount returns the total number of unreferenced files moved by quarantine sweeps.
func QuarantineSweepFilesCount() int64 {
	return GlobalMetrics.QuarantineSweepFilesCount.Load()
}

// QuarantineSweepBytesCount returns the total number of bytes moved by quarantine sweeps.
func QuarantineSweepBytesCount() int64 {
	return GlobalMetrics.QuarantineSweepBytesCount.Load()
}
