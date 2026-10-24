<!--
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Read-Only View Types for Informer Objects

## 1. Background & Motivation

Kubernetes controller caches store full upstream API objects (`corev1.ConfigMap`, `corev1.Secret`, `gatewayv1.HTTPRoute`, etc.). In typical cluster environments, controllers like GARI only inspect a subset of fields (such as metadata name/namespace, secret keys/certificates, or route rules and hostnames), yet the standard types retain every field transmitted by the API server. In particular, server-side apply metadata (`metadata.managedFields`) contributes several kilobytes of JSON trees, timestamps, and managers per object.

Furthermore, standard Go types expose mutable fields (`map[string]string`, `[]byte`, slices of nested structs). To prevent event handlers or controllers from mutating cached copies, in-memory caches perform defensive deep copies (`obj.DeepCopyObject()`) upon handing out pointers, incurring CPU and allocation overhead on every read.

This experiment investigates **read-only view types**:
1. Cut-down Go structs with unexported fields holding only the fields GARI reads.
2. Compile-time immutability, where maps and slices are wrapped in read-only wrappers (`ReadOnlyMap`, `ReadOnlyBytesMap`, `ReadOnlySlice`) exposing Go 1.23+ iterators (`All() iter.Seq2`).
3. Free copies (`DeepCopyObject` returns the receiver pointer with 0 allocations).
4. Direct decoders for JSON, API server protobuf envelopes (for core types), and a compact binary codec for disk store per-read decoding.
5. Standard client-go `reflector` compatibility against a dedicated `runtime.Scheme`.

The prototype is located under `experiments/viewtypes/`.

---

## 2. Architecture & Design

### 2.1 Struct Immutability & Safe Accessors

View types (`ConfigMapView`, `SecretView`, `HTTPRouteView`) enforce immutability at compile time:
- **No Exported Fields**: All struct fields are unexported.
- **Value Semantics for Scalars**: Getters return values (`string`, `int64`, `metav1.Time`, `types.UID`).
- **Read-Only Wrappers for Collections**:
  - `ReadOnlyMap[K, V]` wraps `map[K]V` with `Get(k)`, `Len()`, and `All() iter.Seq2[K, V]`.
  - `ReadOnlyBytesMap` wraps `map[string][]byte`. Its `Get` method returns a cloned byte slice (`bytes.Clone`), ensuring callers cannot mutate the view's internal bytes.
  - `ReadOnlySlice[T]` wraps `[]T` with `Get(i)`, `Len()`, `All() iter.Seq2[int, T]`, and `Values() iter.Seq[T]`.
- **Nested Views by Value**: Nested structs (such as `HTTPRouteRuleView`, `HTTPRouteMatchView`, `ParentReferenceView`) are themselves view types returned by value.

### 2.2 Client-Go Compatibility

A standard client-go reflector requires that list and watch objects implement `runtime.Object` and provide metadata access:
1. **Receiver Identity on DeepCopy**: Because view types cannot be mutated, `DeepCopyObject() runtime.Object` returns `v` directly.
2. **Metadata Accessor**: View types implement `metav1.ObjectMetaAccessor`, returning an unexported `viewMetaAccessor` implementing `metav1.Object`. This provides `GetName()`, `GetNamespace()`, `GetResourceVersion()`, etc., to `cache.MetaNamespaceKeyFunc` and reflector sync routines without exposing mutable setters on the view struct.
3. **List Types**: `ConfigMapViewList`, `SecretViewList`, and `HTTPRouteViewList` embed `metav1.ListMeta` and provide an exported `Items []*T` slice for `meta.ExtractListWithAlloc`.
4. **Dedicated Scheme**: View types are registered under their canonical kinds (`v1/ConfigMap`, `v1/Secret`, `gateway.networking.k8s.io/v1/HTTPRoute`) using `AddKnownTypeWithName`.

### 2.3 Codecs & Wire Decoders

The prototype implements three decoders:
1. **JSON Decoder (`UnmarshalJSON`)**: Drops unknown fields during deserialization. Unread metadata (such as `managedFields`, `ownerReferences`, and `finalizers`) is skipped without allocation.
2. **Trimmed Protobuf Envelope (`proto_decoder.go`)**: Core Kubernetes types (`ConfigMap` and `Secret`) support protobuf over the wire. We defined a trimmed `.proto` declaring identical field numbers to Kubernetes' `generated.proto`. When unmarshaling the raw protobuf payload from the API server's `k8s\x00` + `runtime.Unknown` envelope, protobuf wire deserialization skips undeclared field tags (including field 17 `managedFields`).
3. **Compact Binary Codec (`compact_codec.go`)**: A binary encoding for the disk store's per-read retrieval. It encodes fields in a dense format with varints and length-prefixed bytes, avoiding reflection and intermediate JSON parsing.

---

## 3. Fluency & Code Comparison: Before vs. After

### 3.1 Reading ConfigMap Data

**Before (Full Type):**
```go
// Reading from *corev1.ConfigMap
func processConfig(cm *corev1.ConfigMap) {
    if cm.Data != nil {
        if val, ok := cm.Data["server.conf"]; ok {
            useConfig(val)
        }
        for k, v := range cm.Data {
            recordEntry(k, v)
        }
    }
}
```

**After (View Type):**
```go
// Reading from *viewtypes.ConfigMapView
func processConfig(cm *viewtypes.ConfigMapView) {
    if val, ok := cm.Data().Get("server.conf"); ok {
        useConfig(val)
    }
    for k, v := range cm.Data().All() {
        recordEntry(k, v)
    }
}
```

### 3.2 Reading Secret TLS Data

**Before (Full Type):**
```go
// Reading from *corev1.Secret
func processTLSSecret(sec *corev1.Secret) {
    certBytes := sec.Data[corev1.TLSCertKey]
    keyBytes := sec.Data[corev1.TLSPrivateKeyKey]
    loadCertificate(certBytes, keyBytes)
}
```

**After (View Type):**
```go
// Reading from *viewtypes.SecretView
func processTLSSecret(sec *viewtypes.SecretView) {
    certBytes, _ := sec.Data().Get(corev1.TLSCertKey)
    keyBytes, _ := sec.Data().Get(corev1.TLSPrivateKeyKey)
    loadCertificate(certBytes, keyBytes)
}
```

### 3.3 Reading HTTPRoute Rules and Matches

**Before (Full Type):**
```go
// Reading from *gatewayv1.HTTPRoute
func compileRoute(route *gatewayv1.HTTPRoute) {
    for _, host := range route.Spec.Hostnames {
        addHost(string(host))
    }
    for _, rule := range route.Spec.Rules {
        for _, match := range rule.Matches {
            if match.Path != nil && match.Path.Value != nil {
                addPath(*match.Path.Value)
            }
        }
        for _, backend := range rule.BackendRefs {
            var port *int32
            if backend.Port != nil {
                p := int32(*backend.Port)
                port = &p
            }
            addBackend(string(backend.Name), port)
        }
    }
}
```

**After (View Type):**
```go
// Reading from *viewtypes.HTTPRouteView
func compileRoute(route *viewtypes.HTTPRouteView) {
    for _, host := range route.Hostnames().All() {
        addHost(host)
    }
    for _, rule := range route.Rules().All() {
        for _, match := range rule.Matches().All() {
            if match.Path().Value() != "" {
                addPath(match.Path().Value())
            }
        }
        for _, backend := range rule.BackendRefs().All() {
            addBackend(backend.Name(), backend.Port())
        }
    }
}
```

### 3.4 Semantic Limitations: Optional Fields and Presence Information

A limitation of the current view types is that optional fields are flattened into zero values:
- `HTTPBackendRefView.Port()` returns `int32`, where `0` conflates an unset port with an explicit port 0. In Gateway API, an unset backend port means "use the port specified by the target Service".
- `HTTPRouteMatchView.Path()` returns `HTTPPathMatchView`, where an unset path returns an empty `value`. In Gateway API, omitting the path match defaults to `PathPrefix /`, whereas an explicit empty string is invalid.
- Filter redirect and rewrite configurations are optional structures; returning zero-value structs makes it ambiguous whether a filter was configured or absent.

Flattening optional pointers into plain values discards presence information. Any production adoption of view types should provide presence-aware accessors, such as `(value, ok)` tuples or `Has...() bool` methods (e.g. `backend.Port() (int32, bool)` or `match.HasPath() bool`), rather than collapsing nil pointers to zero values.

---

## 4. Empirical Measurements

Measurements were performed on Linux (`amd64`, AMD EPYC 9B14, Go 1.27.3). Benchmarks used `testing.B` with `-benchmem`. Retained steady-state heap was measured by allocating 10,000 objects in retained slices and evaluating `runtime.MemStats.HeapAlloc` after two explicit `runtime.GC()` invocations.

### 4.1 Steady-State Retained Heap (10,000 Objects)

GARI's current caches strip `managedFields` before storing objects: the disk store codec strips it, and controller-runtime transforms can do so as well. We therefore compare view types against two baselines:
1. **Full Type (with managedFields)**: The raw object as received from the API server.
2. **Full Type (stripped managedFields)**: The full type after stripping `managedFields`, matching GARI's current cache behavior.
3. **View Type**: The cut-down immutable view struct.

| Kind | Full (with managedFields) | Full (stripped managedFields) | View Type | Savings vs Raw | Savings vs Stripped |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ConfigMap** | 2,364 B/obj (23.1 MB) | 1,912 B/obj (18.7 MB) | 1,641 B/obj (16.0 MB) | -723 B/obj (-30.6%) | **-271 B/obj (-14.2%)** |
| **Secret** | 1,936 B/obj (18.9 MB) | 1,704 B/obj (16.6 MB) | 1,528 B/obj (14.9 MB) | -408 B/obj (-21.1%) | **-176 B/obj (-10.3%)** |
| **HTTPRoute** | 2,185 B/obj (21.3 MB) | 2,008 B/obj (19.6 MB) | 1,852 B/obj (18.1 MB) | -333 B/obj (-15.2%) | **-156 B/obj (-7.8%)** |

*Analysis*:
- Compared to raw objects with `managedFields`, view types reduce retained heap by 15% to 31%.
- Compared to full types where `managedFields` has already been stripped (what GARI actually runs), the savings are smaller: 14.2% for ConfigMap, 10.3% for Secret, and 7.8% for HTTPRoute. Because `Data` payload bytes dominate the size of ConfigMaps and Secrets, keeping the payload while pruning unread struct fields yields modest memory reduction once `managedFields` is removed.

---

### 4.2 Decode Latency and Memory Allocations

The table below reports single-object decoding from each wire representation.

| Benchmark | Latency (ns/op) | Memory Allocated (B/op) | Allocations (allocs/op) |
| :--- | :--- | :--- | :--- |
| **ConfigMap: Full Protobuf** | 2,854 ns/op | 2,976 B/op | 51 allocs/op |
| **ConfigMap: Compact Binary** | 1,782 ns/op | 2,336 B/op | 31 allocs/op |
| **ConfigMap: Full JSON** | 12,173 ns/op | 3,022 B/op | 38 allocs/op |
| **ConfigMap: View JSON** | 11,805 ns/op | 2,297 B/op | 25 allocs/op |
| **ConfigMap: Trimmed Protobuf** | 4,899 ns/op | 4,152 B/op | 79 allocs/op |
| | | | |
| **Secret: Full Protobuf** | 1,622 ns/op | 1,840 B/op | 28 allocs/op |
| **Secret: Compact Binary** | 1,388 ns/op | 1,752 B/op | 22 allocs/op |
| **Secret: Full JSON** | 6,681 ns/op | 2,079 B/op | 23 allocs/op |
| **Secret: View JSON** | 7,541 ns/op | 1,796 B/op | 17 allocs/op |
| **Secret: Trimmed Protobuf** | 3,497 ns/op | 2,992 B/op | 54 allocs/op |
| | | | |
| **HTTPRoute: Full JSON** | 12,100 ns/op | 2,486 B/op | 46 allocs/op |
| **HTTPRoute: Compact Binary** | 2,201 ns/op | 2,200 B/op | 39 allocs/op |
| **HTTPRoute: View JSON** | 14,311 ns/op | 3,205 B/op | 46 allocs/op |

*Framing against disk store usage today:*
Today, GARI's disk store uses Protobuf for core types (ConfigMap, Secret) and JSON for custom resources (HTTPRoute). Evaluating the compact binary codec against these formats shows:
- **ConfigMap**: Full Protobuf is 2,854 ns/op; Compact Binary is 1,782 ns/op (a 1.6x speedup, with 20 fewer allocations).
- **Secret**: Full Protobuf is 1,622 ns/op; Compact Binary is 1,388 ns/op (a 1.17x speedup, with 6 fewer allocations).
- **HTTPRoute**: Full JSON is 12,100 ns/op; Compact Binary is 2,201 ns/op (a 5.5x speedup, with 7 fewer allocations).

*Analysis of Negative Results:*
1. **Trimmed Protobuf is slower than Full Protobuf**:
   - For ConfigMap, trimmed protobuf took 4,899 ns/op (79 allocs) compared to 2,854 ns/op (51 allocs) for full protobuf.
   - For Secret, trimmed protobuf took 3,497 ns/op (54 allocs) compared to 1,622 ns/op (28 allocs) for full protobuf.
   - *Cause*: The trimmed protobuf decoder first deserializes the payload into a generated proto struct (`pb.ConfigMap` / `pb.Secret`), and then copies its fields into the `ConfigMapView` / `SecretView` struct. In contrast, Kubernetes' generated full protobuf code deserializes directly into `corev1.ConfigMap` using custom unmarshaling logic in a single pass.
   - *Fixability*: To match or exceed full protobuf speed, the decoder would need a custom single-pass protobuf wire parser that reads field tags and directly assigns into the view struct without an intermediate `pb.ConfigMap` struct allocation.
2. **HTTPRoute View JSON is slower and allocates more than Full JSON**:
   - HTTPRoute view JSON took 14,311 ns/op and 3,205 B/op, compared to 12,100 ns/op and 2,486 B/op for full JSON.
   - *Cause*: Deserializing HTTPRoute view JSON requires allocating intermediate wire structs and then re-allocating value slices for nested rules, matches, filters, and backends. Standard `gatewayv1.HTTPRoute` unmarshaling uses direct pointers into slice buffers, avoiding this second transformation step.

---

### 4.3 Cost of `ReadOnlyBytesMap.Get`

To guarantee immutability, `ReadOnlyBytesMap.Get` returns `bytes.Clone(v)` so callers cannot mutate internal bytes. We benchmarked `Get` on a 1.5 KB payload (e.g. a certificate) versus accessing a string in `ReadOnlyMap[string, string]`:

| Benchmark | Latency (ns/op) | Memory Allocated (B/op) | Allocations (allocs/op) |
| :--- | :--- | :--- | :--- |
| **`ReadOnlyBytesMap.Get` (bytes.Clone)** | 682.7 ns/op | 1,536 B/op | 1 allocs/op |
| **`ReadOnlyMap.Get` (string accessor)** | 7.4 ns/op | 0 B/op | 0 allocs/op |

*Trade-off*:
Defensive cloning ensures safety when returning `[]byte`, but incurs an allocation of the payload size on every read (682 ns and 1.5 KB per read for a 1.5 KB certificate). For read-heavy paths, an alternative is to store secret and config data as `string` and expose string accessors (`GetString(key)`), since Go strings are immutable by design and can be passed without copying.

---

### 4.4 Cache Read Handover Cost

In standard controller-runtime and client-go informers, cached objects retrieved from an in-memory store require defensive copying (`obj.DeepCopyObject()`) to protect the cache from caller mutation. With immutable view types, `DeepCopyObject()` returns the receiver pointer directly:

| Kind | Full Type (`DeepCopy()`) | View Type (`DeepCopyObject()`) | Difference per Cache Read |
| :--- | :--- | :--- | :--- |
| **ConfigMap** | 1,702 ns/op (2,000 B/op, 18 allocs) | 0.31 ns/op (0 B/op, 0 allocs) | -1.70 µs, -2.0 KB, -18 allocs |
| **Secret** | 1,294 ns/op (1,584 B/op, 12 allocs) | 0.30 ns/op (0 B/op, 0 allocs) | -1.29 µs, -1.6 KB, -12 allocs |
| **HTTPRoute** | 1,835 ns/op (1,768 B/op, 35 allocs) | 0.30 ns/op (0 B/op, 0 allocs) | -1.83 µs, -1.8 KB, -35 allocs |

*Analysis*: When handing out cached objects, view types eliminate the deep copy overhead, saving 1.3 to 1.8 microseconds and 12 to 35 allocations per read.

---

## 5. Architectural Recommendations

### 5.1 Adoption for the Disk-Backed Informer

1. **Compact Binary Codec for Per-Read Disk Decoding**:
   - The compact binary codec improves decode latency over JSON by 5.5x for CRDs (2.2 µs vs 12.1 µs) and over Protobuf by 1.2x to 1.6x for core types.
   - For a disk-backed cache that deserializes objects from disk on each read, using the compact binary codec into an in-memory view type reduces CPU overhead compared to reading JSON or Protobuf.
   - Once deserialized into memory, returning the receiver on `DeepCopyObject()` avoids further copies when handing objects to handlers.

2. **Which Kinds Benefit Most**:
   - **Secret and ConfigMap**: Benefit moderately. When `managedFields` is already stripped, steady-state heap reduction is 10% to 14%. The compact binary codec is 1.2x to 1.6x faster than current protobuf decoding. However, `ReadOnlyBytesMap.Get` introduces allocation on read unless string accessors are used.
   - **Custom Resources (HTTPRoute)**: Yields the highest decode speedup with the compact binary codec (5.5x faster than JSON). However, view JSON decoding from the API server is slower than full JSON (14.3 µs vs 12.1 µs), and maintaining custom view schemas across Gateway API spec versions introduces maintenance overhead.

3. **Key Trade-offs & Limitations**:
   - **Scheme Isolation**: One `runtime.Scheme` maps a GVK to exactly one Go type. View types cannot share controller-runtime's shared manager cache with upstream full types. The disk-backed informer builds its own reflector and store, so this isolation is feasible, but views cannot be passed to standard controller-runtime client methods expecting `client.Object`.
   - **Presence Loss**: Flattening optional pointers into zero values loses semantic information (e.g. distinguishing unset ports or path matches from zero values). Any production implementation must retain presence information via `(value, ok)` or `Has...()` accessors.
