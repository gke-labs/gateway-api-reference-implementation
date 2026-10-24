# Investigation: Const-Correct Informer Reads with goconst `Const[T]` and Static Analysis

## Executive Summary

In Kubernetes controllers like GARI, objects decoded by `client-go` informers are stored in in-memory cache indexers and shared across event handlers. To ensure that event handlers and state processing never mutate objects in the shared cache, GARI currently defends the cache by calling `DeepCopy()` on every object when storing it in `State` (e.g. `s.tcpRoutes[key] = &TCPRouteState{ TCPRoute: route.DeepCopy() }`). The cache is protected today, but at the cost of duplicate heap copies and CPU overhead on each update.

This investigation evaluates whether `gke-labs-infra`'s `goconst` experiment (PR #162), which defines `type Const[T any] *T` and pairs it with a static analyzer, can let GARI drop that defensive copy safely by having State retain the informer's pointer directly.

### Key Conclusions

1. **Representation and Allocation Cost**: `type Const[T any] *T` has the exact same representation, size (8 bytes), alignment, and register-passing ABI as `*T`. Converting `*T` to `Const[T]` via `WrapConst(v)` inlines completely with no runtime conversion code and 0 heap allocations. In benchmarks, dropping `DeepCopy()` in the read path yields a **7.5x speedup (53.7 ns vs 401.8 ns)** and reduces allocation on state ingestion from **548 B to 16 B** per update.
2. **Retained Heap Reduction**: In the status quo, each object exists twice in memory: once in the informer cache and once as a deep copy in State. Retaining the cache's pointer behind `Const[T]` removes the second copy. For `TCPRoute`, this reduces combined retained heap (cache plus State) by **65–70%** (saving ~531 bytes per route).
3. **Soundness Gaps in Initial Prototype**: The original analyzer in `gke-labs-infra#162` only flagged implicit conversions from `Const[T]` to `*T`. It did not detect direct field writes (`c.Port = 5`), element assignments (`c.Data["k"] = "w"`), slice mutations (`append(c.Items, ...)`), address-of operations (`&c.Field`, `&(*c)`), explicit casts (`(*T)(c)`), or method calls with pointer receivers (`c.ObjectMeta.SetName(...)`). We implemented intra-procedural origin and alias tracking in `experiments/goconst/analyzer.go` (committed and pushed to `gke-labs-infra#162`), closing these gaps.
4. **The Method-Set & Embedding Friction**:
   - In Go, a defined pointer type (`type Const[T] *T`) has an **empty method set**. Top-level methods such as `DeepCopy()`, `GetObjectKind()`, or custom methods require explicit dereferencing `(*c).M()`.
   - `Const[T]` does not implement any Kubernetes interfaces (`runtime.Object`, `client.Object`).
   - Go's grammar **forbids embedding defined pointer types in structs** (`embedded field type cannot be a pointer`). GARI's wrapper structs (`TCPRouteState`, `HTTPRouteState`, `GatewayState`) cannot embed `Const[T]`; they must use named fields (`Route Const[T]`), breaking promoted field ergonomics on wrapper types.
5. **Comparison with Generated View Types (#816)**:
   - For cluster objects with metadata (**ConfigMaps and Secrets**), **Generated View Types (#816)** prune unread fields (such as `managedFields`) at decode time, measuring 15–31% heap savings on fixtures with metadata, and enforce immutability at compile time without relying on custom linters. However, because view types retain the `Data` payload, neither approach eliminates the bulk of large ConfigMaps or Secrets in memory.
   - For **Gateway API routing kinds** (`TCPRoute`, `HTTPRoute`, `TLSRoute`), `Const[T]` avoids maintaining separate generated schemas and removes the second copy in State, but its ergonomic friction (empty method set, lack of interface satisfaction, no struct embedding) makes widespread adoption across GARI's compiler layers unwieldy compared to standard defensive copies or generated accessor interfaces.

---

## 1. Soundness Analysis: Analyzer Gaps & Fixes

### Soundness Gaps in `gke-labs-infra#162`

In Go, defining a type as `type Const[T any] *T` changes the type name, but the underlying type remains `*T`. Consequently, the standard Go compiler permits operations that violate const semantics:

| Expression on `c Const[Obj]` | Go Compiler Behavior | Handled in `gke-labs-infra#162` (Initial)? | Soundness Impact |
| :--- | :--- | :--- | :--- |
| `p = c` (where `p` is `*Obj`) | Compiles (identical underlying types, `*Obj` is unnamed) | **Yes** (reported as implicit conversion) | Prevents trivial pointer escape |
| `c.Port = 5` (field assignment) | **Compiles** (Go auto-dereferences pointer receivers) | **No** (ignored) | In-place mutation of cache |
| `c.Bar++` / `c.Bar += 1` | **Compiles** | **No** (ignored) | In-place mutation |
| `c.Data["k"] = "w"` (map write) | **Compiles** | **No** (ignored) | Shared map mutation |
| `c.Items[0] = 10` (slice element write) | **Compiles** | **No** (ignored) | Shared backing array mutation |
| `delete(c.Data, "k")` | **Compiles** | **No** (ignored) | Shared map mutation |
| `_ = append(c.Items, 4)` | **Compiles** | **No** (ignored) | Overwrites slice buffer if cap > len |
| `_ = &c.Port` or `_ = &(*c)` | **Compiles** | **No** (ignored) | Leaks unconstrained `*int` or `*Obj` |
| `p = (*Obj)(c)` (explicit conversion) | **Compiles** | **No** (explicitly allowed as `// OK`) | Bypass of `Const` wrapper |
| `c.ObjectMeta.SetName("new")` | **Compiles** (promoted pointer receiver method) | **No** (ignored) | Mutates embedded `ObjectMeta` |
| `(*c).Mutate()` | **Compiles** (`*c` is addressable) | **No** (ignored) | Mutates top-level object |
| `return c` (in `func() *Obj`) | **Compiles** | **No** (commented as `// TODO`) | Escapes `Const` in returns |
| `m := c.Data; m["k"] = "w"` | **Compiles** | **No** (ignored) | Mutation via local alias |

### How the Gaps Were Closed in `gke-labs-infra`

To make `Const[T]` sound, the static analyzer was enhanced in `gke-labs-infra` (commit `13d9ddb` on PR #162) with:

1. **Intra-Procedural Origin Tracking (`originatesFromConst`)**:
   Recursively tracks whether an AST expression originates from a `Const[T]` root through selectors (`c.Field`), index operations (`c.Data["k"]`, `c.Items[i]`), slice expressions (`c.Items[:]`), star expressions (`*c`), parenthesized expressions, and address operations (`&`).
2. **Local Variable Alias Tracking (`constVars`)**:
   When a local variable is initialized or assigned from a `Const[T]`-derived expression (e.g. `m := c.Data` or `s := c.Items`), the variable's `types.Object` is registered as const-tainted. Subsequent mutations through the alias (such as `m["k"] = "v"` or `s[0] = 1`) are detected and flagged.
3. **Mutation and Assignment Diagnostics**:
   - `*ast.AssignStmt`: Flags assignments where LHS is a field selector, map index, slice index, or dereference rooted in a `Const[T]`.
   - `*ast.IncDecStmt`: Flags `++` and `--` on fields rooted in `Const[T]`.
   - `*ast.UnaryExpr`: Flags taking the address (`&`) of any field or dereference of a `Const[T]`.
4. **Builtin Function Checks**:
   Inspects calls to `delete`, `append`, and `copy` where the target container originates from a `Const[T]`.
5. **Method Receiver Inspection (`MethodVal`)**:
   Inspects `pass.TypesInfo.Selections[sel]`. If the method's declared signature has a pointer receiver (`sig.Recv().Type().(*types.Pointer)`), calling it on a receiver expression that originates from `Const[T]` (e.g. `c.ObjectMeta.SetName(...)` or `(*c).Mutate()`) is rejected. Methods with value receivers (e.g. `c.Meta.GetName()`, `(*c).ValueMethod()`) are permitted.
6. **Explicit Conversion Rejection**:
   Inspects `*ast.CallExpr` where the target is a type expression (`(*T)(c)`). If an argument of type `Const[T]` is cast to `*T`, the analyzer emits: `explicit conversion from Const[T] to *T`.
7. **Return Statement Checking**:
   Matches return expression types against the enclosing function signature's declared return types, flagging any `Const[T]` returned where `*T` is expected.

All checks were verified with `golang.org/x/tools/go/analysis/analysistest` in `testdata/src/a/a.go`.

---

## 2. The Method-Set Problem & Structural Ergonomics

### The Core Problem

In the Go language specification:
> *"The method set of a defined type `type P *T` is empty."*

Even though `T` may declare methods with value or pointer receivers, `c.M()` will **not compile** if `c` has type `Const[T]`.

Furthermore:
> *"An embedded field must be specified as a type name T or as a pointer to a non-pointer type name `*T`, and T itself may not be a pointer type."*

Because `Const[T]` is a defined pointer type, Go **forbids embedding `Const[T]` in any struct**:
```go
// COMPILER ERROR: embedded field type cannot be a pointer
type ConstTCPRouteState struct {
    Const[gatewayv1.TCPRoute]
}
```

### What Works Naturally vs. What Breaks

| Operation | Syntax | Compiles? | Notes |
| :--- | :--- | :---: | :--- |
| Direct field reads | `c.Spec.Rules`, `c.Generation` | **Yes** | Go automatically dereferences defined pointers for selectors |
| Promoted embedded fields | `c.Name`, `c.Namespace` | **Yes** | Fields promoted from `ObjectMeta` resolve directly |
| Embedded field methods | `c.CreationTimestamp.Before(t)` | **Yes** | Method is invoked on the embedded `metav1.Time` struct |
| Promoted value methods | `c.ObjectMeta.GetName()` | **Yes** | Explicitly targeting the embedded struct works |
| Top-level methods | `c.DeepCopy()`, `c.GetObjectKind()` | **NO** | `Const[T]` has an empty method set |
| Dereferenced method calls | `(*c).DeepCopy()` | **Yes** | Legal Go, but analyzer must audit the receiver |
| Interface passing | `x client.Object = c` | **NO** | `Const[T]` implements 0 methods; does not satisfy `runtime.Object` |
| Struct embedding | `type S struct { Const[T] }` | **NO** | Go spec forbids embedding defined pointer types |

### Strategies to Ease Method-Set Friction

1. **Analyzer-Approved `(*c).M()` for Value Receivers and Explicit Cloning**:
   Top-level value-receiver methods can be called using `(*c).M()`. The analyzer verifies that `M` has a value receiver and permits it. For `DeepCopy()`, `(*c).DeepCopy()` is recognized as an explicit cloning escape hatch when a caller intentionally requests a mutable copy.
2. **Top-Level Helper Functions**:
   Instead of methods, package-level functions can encapsulate operations:
   ```go
   func DeepCopy[T any](c Const[T]) *T { return (*c).DeepCopy() }
   ```
3. **Direct Field Conventions**:
   For Kubernetes resources, most reads access fields rather than methods. In GARI's route compilation, `c.Name`, `c.Namespace`, `c.Generation`, `c.Spec.Rules`, and `c.Spec.ParentRefs` are all struct fields that compile directly without `(*c)`.

---

## 3. Adoption in GARI: Converted `TCPRoute` Read Path

We implemented an end-to-end prototype of GARI's `TCPRoute` read path under `experiments/goconst`:
- `experiments/goconst/const.go`: `Const[T]` and `WrapConst[T]` definitions.
- `experiments/goconst/tcproute_readpath.go`: Informer event handler adapter, `ConstState` storing informer pointers, `CompileTCPRoute`, and `ComputeDesiredTCPRouteStatus`.
- `experiments/goconst/tcproute_readpath_test.go`: End-to-end conformance, equivalence test with `pkg/state`, and explicit cloning verification.
- `experiments/goconst/bench_test.go`: Retained-heap measurements and microbenchmarks comparing status-quo deep copying vs. `Const[T]`.

### Code Diff: Status Quo vs. `Const[T]`

#### Informer Event Handler & State Storage
```diff
--- pkg/state/state.go (Status Quo)
+++ experiments/goconst/tcproute_readpath.go (Const[T])
@@ -1,15 +1,15 @@
-type TCPRouteState struct {
-	*gatewayv1.TCPRoute
-	Internal *InternalTCPRoute
+type ConstTCPRouteState struct {
+	Route    Const[gatewayv1.TCPRoute]
+	Internal *state.InternalTCPRoute
 }
 
-func (s *State) UpsertTCPRoute(route *gatewayv1.TCPRoute) {
+func (s *ConstState) UpsertTCPRoute(route Const[gatewayv1.TCPRoute]) {
 	if route == nil {
 		return
 	}
 	s.mu.Lock()
 	defer s.mu.Unlock()
 
 	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
-	s.tcpRoutes[key] = &TCPRouteState{
-		TCPRoute: route.DeepCopy(), // 548 B, 7 allocations per upsert
-	}
+	s.tcpRoutes[key] = &ConstTCPRouteState{
+		Route: route, // Retains informer pointer without DeepCopy
+	}
 }
```

#### Route Compilation
```diff
--- pkg/state/tcproute.go (Status Quo)
+++ experiments/goconst/tcproute_readpath.go (Const[T])
@@ -1,12 +1,12 @@
 func CompileTCPRoute(
-	route *gatewayv1.TCPRoute,
+	route Const[gatewayv1.TCPRoute],
 	services map[types.NamespacedName]*corev1.Service,
-) *InternalTCPRoute {
+) *state.InternalTCPRoute {
 	if route == nil {
 		return nil
 	}
 
 	validationCondition := state.NewCondition(
 		string(gatewayv1.RouteConditionAccepted),
 		metav1.ConditionTrue,
 		string(gatewayv1.RouteReasonAccepted),
 		"Route validation succeeded",
 		route.Generation, // Field read works untouched
 	)
 
 	var compiledRules []state.InternalTCPRule
 	for _, rule := range route.Spec.Rules { // Field read works untouched
 		// ... backend resolution ...
 	}
 
 	return &state.InternalTCPRoute{
 		Rules:                 compiledRules,
 		ParentRefs:            route.Spec.ParentRefs, // Field read works untouched
 		ValidationCondition:   validationCondition,
 		ResolvedRefsCondition: resolvedRefsCondition,
 	}
 }
```

### Call Site Analysis for `TCPRoute` Read Path

| Call Site Type | Count in Converted Path | Required Changes |
| :--- | :---: | :--- |
| Informer cache ingress (`WrapConst(r)`) | 2 | Added `WrapConst(r)` cast at event handler boundary |
| State storage (`UpsertTCPRoute`) | 1 | Replaced `route.DeepCopy()` with direct pointer assignment |
| Field reads (`route.Namespace`, `route.Name`, `route.Generation`) | 8 | **0 changes** (promoted fields compile naturally) |
| Spec reads (`route.Spec.Rules`, `route.Spec.ParentRefs`) | 4 | **0 changes** (struct fields compile naturally) |
| Embedded methods (`route.CreationTimestamp.Equal/Before`) | 2 | **0 changes** (methods on embedded struct compile naturally) |
| Top-level methods requiring `(*route)` | 0 on pure read path | **0 changes** (1 if caller explicitly clones via `(*route).DeepCopy()`) |
| Wrapper struct embedding changes | 2 | Replaced embedded `*TCPRoute` with named field `Route Const[TCPRoute]` |

---

## 4. Runtime Cost & Empirical Measurements

### Theoretical Cost
`Const[T]` has the exact same machine layout as `*T`:
- Size: 8 bytes (64-bit architecture)
- Alignment: 8 bytes
- Passing: CPU register (`RAX`/`RDI`)
- Escape analysis: `WrapConst` inlines completely with no heap escape.

### Retained-Heap Measurements

Measured using `runtime.ReadMemStats` with forced garbage collection cycles on AMD EPYC 9B14 (Linux x86_64, Go 1.27.3). This test measures retained heap across the informer cache and State:
1. **Cache Only**: Informer cache holding `N` routes.
2. **Cache + Baseline**: Informer cache holding `N` routes, plus `BaselineState` holding `DeepCopy()` copies of those `N` routes.
3. **Cache + Const**: Informer cache holding `N` routes, plus `ConstState` holding `Const[TCPRoute]` references to the same `N` routes.

| Object Count | Cache Only | Cache + Baseline (DeepCopy) | Cache + Const (Retained Pointer) | Heap Saved | Savings | Saved Per Object |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1,000** | 162.6 KiB | 788.4 KiB | 274.4 KiB | 514.0 KiB | **65.2%** | 526 B |
| **5,000** | 651.1 KiB | 3,711.2 KiB | 1,113.6 KiB | 2,597.6 KiB | **70.0%** | 531 B |
| **10,000** | 1,301.9 KiB | 7,422.1 KiB | 2,226.9 KiB | 5,195.3 KiB | **70.0%** | 531 B |

**Why memory is saved**: In the status quo, each object is duplicated: once in the informer cache indexer, and once in State's `tcpRoutes` map. Calling `DeepCopy()` allocates approximately 530 bytes per `TCPRoute` across sub-structures (`ObjectMeta`, `Spec`, `Rules`, `BackendRefs`, `ParentRefs`). Retaining the cache's pointer behind `Const[T]` eliminates the second copy, leaving only the lightweight wrapper struct and pointer in State.

### CPU and Allocation Microbenchmarks

Measured on AMD EPYC 9B14 (Linux x86_64, Go 1.27.3, `-benchtime=1s`):

```
BenchmarkReadPath_Upsert/StatusQuo_WithDeepCopy-60         2,849,574    401.8 ns/op    548 B/op    7 allocs/op
BenchmarkReadPath_Upsert/Goconst_PointerRetained-60       22,073,010     53.7 ns/op     16 B/op    1 allocs/op

BenchmarkReadPath_EndToEnd/StatusQuo_DeepCopy-60             871,258   1343.0 ns/op   1231 B/op   15 allocs/op
BenchmarkReadPath_EndToEnd/Goconst_PointerRetained-60      1,318,521    942.0 ns/op    746 B/op   10 allocs/op
```

### Key Observations
1. **State Ingestion**: `Const[T]` runs in **53.7 ns vs 401.8 ns** (7.5x faster) and reduces per-operation allocations from **548 B (7 allocs) to 16 B (1 alloc)**. The remaining allocation is the `ConstTCPRouteState` wrapper entry.
2. **End-to-End Reconcile**: Reconciling a route from informer ingress through compilation and desired status calculation runs in **942 ns vs 1,343 ns** (1.4x faster) and uses **746 B vs 1,231 B** (39.4% allocation reduction).
3. **Allocation Rate**: In clusters with frequent route updates, dropping `DeepCopy()` avoids allocating and discarding intermediate copies during reconciliation, reducing the steady-state allocation rate.

---

## 5. Architectural Comparison: `Const[T]` vs. Generated View Types (#816)

The table below compares `Const[T]` + Analyzer with Generated View Types (Issue #816):

| Dimension | `Const[T]` + Analyzer (PR #162) | Generated View Types (Issue #816) |
| :--- | :--- | :--- |
| **Immutability Enforcement** | **Static Analyzer / Linter** (compiles with mutations if linter is disabled) | **Compile-Time Enforced** (unexported fields, getter-only methods) |
| **Unread Fields & Heap Size** | **Full Heap Object** (stores unread fields, managedFields, annotations) | **Pruned at decode time** (drops unread fields like `managedFields`; 15–31% heap reduction measured on fixtures with metadata; retains `Data` payload) |
| **Decoding Performance** | Standard JSON decode into full struct | Compact binary / protobuf decode of minimal fields |
| **Read Fluency** | High for struct fields (`c.Spec.Rules`, `c.Name`), but cannot embed in wrapper structs | High with Go iterators (`cm.Data().All()`, `r.Rules()`), returns view types |
| **Method Sets** | **Empty method set**; needs `(*c).M()` for top-level methods | Full method set defined on view types |
| **Interface Compatibility** | Cannot satisfy `runtime.Object` or `client.Object` | Custom scheme satisfies `runtime.Object` via receiver |
| **Code Generation Overhead** | Uses upstream Kubernetes API types directly | Requires a generator, custom types, and dedicated schemes |
| **Tooling Dependency** | Requires custom `goconst` analyzer in build pipeline | Standard `go build` and `go test` |

---

## 6. Recommendations

1. **For ConfigMaps and Secrets (Issue #816)**:
   - `Const[T]` eliminates the second copy in State, but retains the entire decoded API object, including metadata like `managedFields`.
   - Generated view types prune unread fields at decode time (saving 15–31% on objects with metadata) and provide compile-time immutability without an external linter. However, because view types retain the `Data` payload, neither approach removes the memory bulk of large ConfigMaps or Secrets; for that, offloading to a disk-backed store or keeping minimal projections (#799) is required.
2. **For Core Gateway API Routing Types (`TCPRoute`, `HTTPRoute`, `TLSRoute`)**:
   - `Const[T]` eliminates the duplicate object copy in `State.Upsert*` without requiring generated schemas.
   - However, the inability to embed `Const[T]` in wrapper structs (`TCPRouteState`) and the inability to pass `Const[T]` to interfaces (`client.Object`) creates architectural friction across GARI's controller boundaries.
   - If GARI adopts `Const[T]`, it should do so with a narrow scope: strictly as an internal type for read-only compiler input slices (`[]Const[TCPRoute]`), retaining explicit wrapper structs where necessary.
