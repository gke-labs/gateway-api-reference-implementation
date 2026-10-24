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

package goconst

// Const is a defined pointer type representing an immutable reference to T.
// At runtime, Const[T] has identical representation, size, and ABI as *T.
// Mutations and conversions back to *T are detected and rejected by the goconst analyzer.
type Const[T any] *T

// WrapConst wraps a pointer as an immutable Const[T] reference.
// This is a compile-time type conversion with no runtime conversion code.
func WrapConst[T any](val *T) Const[T] {
	return Const[T](val)
}
