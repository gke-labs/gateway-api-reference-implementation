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

// FieldTypeKind denotes the high-level category of a field in a view type.
type FieldTypeKind int

const (
	TypeScalar FieldTypeKind = iota
	TypeStringMap
	TypeBytesMap
	TypeSlice
	TypeNested
)

// FieldSpec declares a single field to keep in a view type.
type FieldSpec struct {
	Name       string        // Exported getter name, e.g. "Name", "Data", "Rules"
	Field      string        // Unexported struct field name, e.g. "name", "data", "rules"
	JSONTag    string        // Wire JSON field name, e.g. "name", "data", "rules"
	Kind       FieldTypeKind // Scalar, StringMap, BytesMap, Slice, Nested
	TypeName   string        // Go return type: string, int64, types.UID, etc.
	ElemType   string        // For Slice: element type (e.g. "string", "HTTPRouteRuleView")
	NestedSpec *NestedSpec   // For TypeNested
}

// NestedSpec declares a nested view type structure.
type NestedSpec struct {
	TypeName string
	Fields   []FieldSpec
}

// KindSpec declaratively defines the fields to keep for a Kubernetes kind.
type KindSpec struct {
	Group       string
	Version     string
	Kind        string
	ViewName    string
	IsCore      bool
	Fields      []FieldSpec
	NestedTypes []NestedSpec
}
