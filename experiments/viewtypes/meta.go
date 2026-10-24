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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// viewTypeMeta implements schema.ObjectKind for view types.
type viewTypeMeta struct {
	gvk schema.GroupVersionKind
}

func (t *viewTypeMeta) SetGroupVersionKind(gvk schema.GroupVersionKind) {
	t.gvk = gvk
}

func (t *viewTypeMeta) GroupVersionKind() schema.GroupVersionKind {
	return t.gvk
}

// viewMetaAccessor is an unexported helper implementing metav1.Object.
// It allows client-go reflector and cache.MetaNamespaceKeyFunc to access
// object identity without exposing mutable setters or internal state on the view type itself.
type viewMetaAccessor struct {
	name              string
	namespace         string
	uid               types.UID
	resourceVersion   string
	generation        int64
	creationTimestamp metav1.Time
}

var _ metav1.Object = (*viewMetaAccessor)(nil)

func (m *viewMetaAccessor) GetNamespace() string                  { return m.namespace }
func (m *viewMetaAccessor) SetNamespace(string)                   {}
func (m *viewMetaAccessor) GetName() string                       { return m.name }
func (m *viewMetaAccessor) SetName(string)                        {}
func (m *viewMetaAccessor) GetGenerateName() string               { return "" }
func (m *viewMetaAccessor) SetGenerateName(string)                {}
func (m *viewMetaAccessor) GetUID() types.UID                     { return m.uid }
func (m *viewMetaAccessor) SetUID(types.UID)                      {}
func (m *viewMetaAccessor) GetResourceVersion() string            { return m.resourceVersion }
func (m *viewMetaAccessor) SetResourceVersion(string)             {}
func (m *viewMetaAccessor) GetGeneration() int64                  { return m.generation }
func (m *viewMetaAccessor) SetGeneration(int64)                   {}
func (m *viewMetaAccessor) GetSelfLink() string                   { return "" }
func (m *viewMetaAccessor) SetSelfLink(string)                    {}
func (m *viewMetaAccessor) GetCreationTimestamp() metav1.Time     { return m.creationTimestamp }
func (m *viewMetaAccessor) SetCreationTimestamp(metav1.Time)      {}
func (m *viewMetaAccessor) GetDeletionTimestamp() *metav1.Time    { return nil }
func (m *viewMetaAccessor) SetDeletionTimestamp(*metav1.Time)     {}
func (m *viewMetaAccessor) GetDeletionGracePeriodSeconds() *int64 { return nil }
func (m *viewMetaAccessor) SetDeletionGracePeriodSeconds(*int64)  {}
func (m *viewMetaAccessor) GetLabels() map[string]string          { return nil }
func (m *viewMetaAccessor) SetLabels(map[string]string)           {}
func (m *viewMetaAccessor) GetAnnotations() map[string]string     { return nil }
func (m *viewMetaAccessor) SetAnnotations(map[string]string)      {}
func (m *viewMetaAccessor) GetFinalizers() []string               { return nil }
func (m *viewMetaAccessor) SetFinalizers([]string)                {}
func (m *viewMetaAccessor) GetOwnerReferences() []metav1.OwnerReference {
	return nil
}
func (m *viewMetaAccessor) SetOwnerReferences([]metav1.OwnerReference) {}
func (m *viewMetaAccessor) GetManagedFields() []metav1.ManagedFieldsEntry {
	return nil
}
func (m *viewMetaAccessor) SetManagedFields([]metav1.ManagedFieldsEntry) {}
