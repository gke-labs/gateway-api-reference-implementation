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

// ConfigMapSpec returns the declarative KindSpec for corev1.ConfigMap.
func ConfigMapSpec() KindSpec {
	return KindSpec{
		Group:    "",
		Version:  "v1",
		Kind:     "ConfigMap",
		ViewName: "ConfigMapView",
		IsCore:   true,
		Fields: []FieldSpec{
			{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
			{Name: "Namespace", Field: "namespace", JSONTag: "namespace", Kind: TypeScalar, TypeName: "string"},
			{Name: "UID", Field: "uid", JSONTag: "uid", Kind: TypeScalar, TypeName: "types.UID"},
			{Name: "ResourceVersion", Field: "resourceVersion", JSONTag: "resourceVersion", Kind: TypeScalar, TypeName: "string"},
			{Name: "Generation", Field: "generation", JSONTag: "generation", Kind: TypeScalar, TypeName: "int64"},
			{Name: "CreationTimestamp", Field: "creationTimestamp", JSONTag: "creationTimestamp", Kind: TypeScalar, TypeName: "metav1.Time"},
			{Name: "Labels", Field: "labels", JSONTag: "labels", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Annotations", Field: "annotations", JSONTag: "annotations", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Data", Field: "data", JSONTag: "data", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "BinaryData", Field: "binaryData", JSONTag: "binaryData", Kind: TypeBytesMap, TypeName: "ReadOnlyBytesMap"},
		},
	}
}

// SecretSpec returns the declarative KindSpec for corev1.Secret.
func SecretSpec() KindSpec {
	return KindSpec{
		Group:    "",
		Version:  "v1",
		Kind:     "Secret",
		ViewName: "SecretView",
		IsCore:   true,
		Fields: []FieldSpec{
			{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
			{Name: "Namespace", Field: "namespace", JSONTag: "namespace", Kind: TypeScalar, TypeName: "string"},
			{Name: "UID", Field: "uid", JSONTag: "uid", Kind: TypeScalar, TypeName: "types.UID"},
			{Name: "ResourceVersion", Field: "resourceVersion", JSONTag: "resourceVersion", Kind: TypeScalar, TypeName: "string"},
			{Name: "Generation", Field: "generation", JSONTag: "generation", Kind: TypeScalar, TypeName: "int64"},
			{Name: "CreationTimestamp", Field: "creationTimestamp", JSONTag: "creationTimestamp", Kind: TypeScalar, TypeName: "metav1.Time"},
			{Name: "Labels", Field: "labels", JSONTag: "labels", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Annotations", Field: "annotations", JSONTag: "annotations", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Type", Field: "secretType", JSONTag: "type", Kind: TypeScalar, TypeName: "corev1.SecretType"},
			{Name: "Data", Field: "data", JSONTag: "data", Kind: TypeBytesMap, TypeName: "ReadOnlyBytesMap"},
		},
	}
}

// HTTPRouteSpec returns the declarative KindSpec for gatewayv1.HTTPRoute.
func HTTPRouteSpec() KindSpec {
	return KindSpec{
		Group:    "gateway.networking.k8s.io",
		Version:  "v1",
		Kind:     "HTTPRoute",
		ViewName: "HTTPRouteView",
		IsCore:   false,
		Fields: []FieldSpec{
			{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
			{Name: "Namespace", Field: "namespace", JSONTag: "namespace", Kind: TypeScalar, TypeName: "string"},
			{Name: "UID", Field: "uid", JSONTag: "uid", Kind: TypeScalar, TypeName: "types.UID"},
			{Name: "ResourceVersion", Field: "resourceVersion", JSONTag: "resourceVersion", Kind: TypeScalar, TypeName: "string"},
			{Name: "Generation", Field: "generation", JSONTag: "generation", Kind: TypeScalar, TypeName: "int64"},
			{Name: "CreationTimestamp", Field: "creationTimestamp", JSONTag: "creationTimestamp", Kind: TypeScalar, TypeName: "metav1.Time"},
			{Name: "Labels", Field: "labels", JSONTag: "labels", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Annotations", Field: "annotations", JSONTag: "annotations", Kind: TypeStringMap, TypeName: "ReadOnlyMap[string, string]"},
			{Name: "Hostnames", Field: "hostnames", JSONTag: "hostnames", Kind: TypeSlice, TypeName: "ReadOnlySlice[string]", ElemType: "string"},
			{Name: "ParentRefs", Field: "parentRefs", JSONTag: "parentRefs", Kind: TypeSlice, TypeName: "ReadOnlySlice[ParentReferenceView]", ElemType: "ParentReferenceView"},
			{Name: "Rules", Field: "rules", JSONTag: "rules", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPRouteRuleView]", ElemType: "HTTPRouteRuleView"},
		},
		NestedTypes: []NestedSpec{
			{
				TypeName: "ParentReferenceView",
				Fields: []FieldSpec{
					{Name: "Group", Field: "group", JSONTag: "group", Kind: TypeScalar, TypeName: "string"},
					{Name: "Kind", Field: "kind", JSONTag: "kind", Kind: TypeScalar, TypeName: "string"},
					{Name: "Namespace", Field: "namespace", JSONTag: "namespace", Kind: TypeScalar, TypeName: "string"},
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "SectionName", Field: "sectionName", JSONTag: "sectionName", Kind: TypeScalar, TypeName: "string"},
					{Name: "Port", Field: "port", JSONTag: "port", Kind: TypeScalar, TypeName: "int32"},
				},
			},
			{
				TypeName: "HTTPRouteRuleView",
				Fields: []FieldSpec{
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "Matches", Field: "matches", JSONTag: "matches", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPRouteMatchView]", ElemType: "HTTPRouteMatchView"},
					{Name: "Filters", Field: "filters", JSONTag: "filters", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPRouteFilterView]", ElemType: "HTTPRouteFilterView"},
					{Name: "BackendRefs", Field: "backendRefs", JSONTag: "backendRefs", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPBackendRefView]", ElemType: "HTTPBackendRefView"},
					{Name: "Timeouts", Field: "timeouts", JSONTag: "timeouts", Kind: TypeNested, TypeName: "HTTPRouteTimeoutsView"},
				},
			},
			{
				TypeName: "HTTPRouteMatchView",
				Fields: []FieldSpec{
					{Name: "Path", Field: "path", JSONTag: "path", Kind: TypeNested, TypeName: "HTTPPathMatchView"},
					{Name: "Headers", Field: "headers", JSONTag: "headers", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPHeaderMatchView]", ElemType: "HTTPHeaderMatchView"},
					{Name: "QueryParams", Field: "queryParams", JSONTag: "queryParams", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPQueryParamMatchView]", ElemType: "HTTPQueryParamMatchView"},
					{Name: "Method", Field: "method", JSONTag: "method", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPPathMatchView",
				Fields: []FieldSpec{
					{Name: "Type", Field: "matchType", JSONTag: "type", Kind: TypeScalar, TypeName: "string"},
					{Name: "Value", Field: "value", JSONTag: "value", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPHeaderMatchView",
				Fields: []FieldSpec{
					{Name: "Type", Field: "matchType", JSONTag: "type", Kind: TypeScalar, TypeName: "string"},
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "Value", Field: "value", JSONTag: "value", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPQueryParamMatchView",
				Fields: []FieldSpec{
					{Name: "Type", Field: "matchType", JSONTag: "type", Kind: TypeScalar, TypeName: "string"},
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "Value", Field: "value", JSONTag: "value", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPRouteFilterView",
				Fields: []FieldSpec{
					{Name: "Type", Field: "filterType", JSONTag: "type", Kind: TypeScalar, TypeName: "string"},
					{Name: "RequestHeaderModifier", Field: "requestHeaderModifier", JSONTag: "requestHeaderModifier", Kind: TypeNested, TypeName: "HTTPHeaderFilterView"},
					{Name: "ResponseHeaderModifier", Field: "responseHeaderModifier", JSONTag: "responseHeaderModifier", Kind: TypeNested, TypeName: "HTTPHeaderFilterView"},
					{Name: "RequestRedirect", Field: "requestRedirect", JSONTag: "requestRedirect", Kind: TypeNested, TypeName: "HTTPRequestRedirectFilterView"},
					{Name: "URLRewrite", Field: "urlRewrite", JSONTag: "urlRewrite", Kind: TypeNested, TypeName: "HTTPURLRewriteFilterView"},
					{Name: "RequestMirror", Field: "requestMirror", JSONTag: "requestMirror", Kind: TypeNested, TypeName: "HTTPRequestMirrorFilterView"},
				},
			},
			{
				TypeName: "HTTPHeaderFilterView",
				Fields: []FieldSpec{
					{Name: "Set", Field: "set", JSONTag: "set", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPHeaderView]", ElemType: "HTTPHeaderView"},
					{Name: "Add", Field: "add", JSONTag: "add", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPHeaderView]", ElemType: "HTTPHeaderView"},
					{Name: "Remove", Field: "remove", JSONTag: "remove", Kind: TypeSlice, TypeName: "ReadOnlySlice[string]", ElemType: "string"},
				},
			},
			{
				TypeName: "HTTPHeaderView",
				Fields: []FieldSpec{
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "Value", Field: "value", JSONTag: "value", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPRequestRedirectFilterView",
				Fields: []FieldSpec{
					{Name: "Scheme", Field: "scheme", JSONTag: "scheme", Kind: TypeScalar, TypeName: "string"},
					{Name: "Hostname", Field: "hostname", JSONTag: "hostname", Kind: TypeScalar, TypeName: "string"},
					{Name: "Path", Field: "path", JSONTag: "path", Kind: TypeNested, TypeName: "HTTPPathModifierView"},
					{Name: "Port", Field: "port", JSONTag: "port", Kind: TypeScalar, TypeName: "int32"},
					{Name: "StatusCode", Field: "statusCode", JSONTag: "statusCode", Kind: TypeScalar, TypeName: "int"},
				},
			},
			{
				TypeName: "HTTPURLRewriteFilterView",
				Fields: []FieldSpec{
					{Name: "Hostname", Field: "hostname", JSONTag: "hostname", Kind: TypeScalar, TypeName: "string"},
					{Name: "Path", Field: "path", JSONTag: "path", Kind: TypeNested, TypeName: "HTTPPathModifierView"},
				},
			},
			{
				TypeName: "HTTPPathModifierView",
				Fields: []FieldSpec{
					{Name: "Type", Field: "modifierType", JSONTag: "type", Kind: TypeScalar, TypeName: "string"},
					{Name: "ReplaceFullPath", Field: "replaceFullPath", JSONTag: "replaceFullPath", Kind: TypeScalar, TypeName: "string"},
					{Name: "ReplacePrefixMatch", Field: "replacePrefixMatch", JSONTag: "replacePrefixMatch", Kind: TypeScalar, TypeName: "string"},
				},
			},
			{
				TypeName: "HTTPRequestMirrorFilterView",
				Fields: []FieldSpec{
					{Name: "BackendRef", Field: "backendRef", JSONTag: "backendRef", Kind: TypeNested, TypeName: "HTTPBackendRefView"},
				},
			},
			{
				TypeName: "HTTPBackendRefView",
				Fields: []FieldSpec{
					{Name: "Group", Field: "group", JSONTag: "group", Kind: TypeScalar, TypeName: "string"},
					{Name: "Kind", Field: "kind", JSONTag: "kind", Kind: TypeScalar, TypeName: "string"},
					{Name: "Namespace", Field: "namespace", JSONTag: "namespace", Kind: TypeScalar, TypeName: "string"},
					{Name: "Name", Field: "name", JSONTag: "name", Kind: TypeScalar, TypeName: "string"},
					{Name: "Port", Field: "port", JSONTag: "port", Kind: TypeScalar, TypeName: "int32"},
					{Name: "Weight", Field: "weight", JSONTag: "weight", Kind: TypeScalar, TypeName: "int32"},
					{Name: "Filters", Field: "filters", JSONTag: "filters", Kind: TypeSlice, TypeName: "ReadOnlySlice[HTTPRouteFilterView]", ElemType: "HTTPRouteFilterView"},
				},
			},
			{
				TypeName: "HTTPRouteTimeoutsView",
				Fields: []FieldSpec{
					{Name: "Request", Field: "request", JSONTag: "request", Kind: TypeScalar, TypeName: "string"},
					{Name: "BackendRequest", Field: "backendRequest", JSONTag: "backendRequest", Kind: TypeScalar, TypeName: "string"},
				},
			},
		},
	}
}

// DefaultSpecs returns all supported KindSpecs.
func DefaultSpecs() []KindSpec {
	return []KindSpec{
		ConfigMapSpec(),
		SecretSpec(),
		HTTPRouteSpec(),
	}
}
