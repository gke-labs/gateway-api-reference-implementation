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

package viewtypes

import (
	"bytes"
	"iter"
)

// ReadOnlyMap provides an immutable, read-only wrapper around a Go map.
// It exposes no mutators and offers natural iteration via Go 1.23+ iterators.
type ReadOnlyMap[K comparable, V any] struct {
	m map[K]V
}

// NewReadOnlyMap creates a new ReadOnlyMap wrapping the provided map.
func NewReadOnlyMap[K comparable, V any](m map[K]V) ReadOnlyMap[K, V] {
	return ReadOnlyMap[K, V]{m: m}
}

// Len returns the number of key-value pairs in the map.
func (m ReadOnlyMap[K, V]) Len() int {
	return len(m.m)
}

// Get returns the value associated with key, and whether the key was present.
func (m ReadOnlyMap[K, V]) Get(key K) (V, bool) {
	if m.m == nil {
		var zero V
		return zero, false
	}
	v, ok := m.m[key]
	return v, ok
}

// All returns an iterator over key-value pairs in the map, allowing:
//
//	for k, v := range m.All() { ... }
func (m ReadOnlyMap[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m.m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// ReadOnlyBytesMap provides an immutable, read-only wrapper around a map[string][]byte.
// To guarantee immutability, Get returns a cloned copy of the byte slice.
type ReadOnlyBytesMap struct {
	m map[string][]byte
}

// NewReadOnlyBytesMap creates a new ReadOnlyBytesMap wrapping the provided map.
func NewReadOnlyBytesMap(m map[string][]byte) ReadOnlyBytesMap {
	return ReadOnlyBytesMap{m: m}
}

// Len returns the number of entries in the byte map.
func (m ReadOnlyBytesMap) Len() int {
	return len(m.m)
}

// Get returns a defensive clone of the byte slice associated with key, preventing
// caller mutations from affecting the view type's internal state.
func (m ReadOnlyBytesMap) Get(key string) ([]byte, bool) {
	if m.m == nil {
		return nil, false
	}
	v, ok := m.m[key]
	if !ok {
		return nil, false
	}
	return bytes.Clone(v), true
}

// All returns an iterator over key-value pairs, yielding defensive clones of byte values.
func (m ReadOnlyBytesMap) All() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		for k, v := range m.m {
			if !yield(k, bytes.Clone(v)) {
				return
			}
		}
	}
}

// ReadOnlySlice provides an immutable, read-only wrapper around a Go slice.
type ReadOnlySlice[T any] struct {
	s []T
}

// NewReadOnlySlice creates a new ReadOnlySlice wrapping the provided slice.
func NewReadOnlySlice[T any](s []T) ReadOnlySlice[T] {
	return ReadOnlySlice[T]{s: s}
}

// Len returns the number of elements in the slice.
func (s ReadOnlySlice[T]) Len() int {
	return len(s.s)
}

// Get returns the element at index i.
func (s ReadOnlySlice[T]) Get(i int) T {
	return s.s[i]
}

// All returns an iterator over (index, element) pairs in the slice, allowing:
//
//	for i, val := range s.All() { ... }
func (s ReadOnlySlice[T]) All() iter.Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s.s {
			if !yield(i, v) {
				return
			}
		}
	}
}

// Values returns an iterator over elements in the slice, allowing:
//
//	for val := range s.Values() { ... }
func (s ReadOnlySlice[T]) Values() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, v := range s.s {
			if !yield(v) {
				return
			}
		}
	}
}
