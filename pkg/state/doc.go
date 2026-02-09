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

// Package state holds the internal state of the Gateway API resources.
// It maintains a mapping from Kubernetes API objects to internal representations
// and provides helper methods to compute the proxy configuration.
//
// The state package follows a pattern where it holds the last-observed state of
// Kubernetes objects and provides unoptimized (but potentially memoized in the future)
// methods to derive the desired configuration for the proxy.
package state
