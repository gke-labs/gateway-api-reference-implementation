# Design: filterlang — Implicitly-Typed, Statically-Typed HTTP Filter Language

## Summary

This document specifies **filterlang**, an experimental pure-Go scripting language for HTTP request and redirect filters in the Gateway API Reference Implementation (GARI).
The experiment lives under `experiments/filterlang/` and carries no Kubernetes dependencies.

filterlang uses a small Python-like syntax with static type inference and flat nullable types (`T | None`).
The GARI controller compiles and type-checks each script during route reconciliation.
The GARI data plane runs the compiled program in-process on matching HTTP requests inside a deterministic, resource-bounded sandbox.

## Motivation

Issue #1601 describes real-world vanity redirectors such as `kubernetes/k8s.io`.
Those workloads combine ordered path matching, optional capture groups, query-string and `#fragment` rewriting, and custom responses such as `?go-get=1` HTML meta tags.
Standard Gateway API `HTTPRoute` `RequestRedirect` filters do not support capture expansion, custom `#fragment` targets, or inline HTML responses.

Existing embedded languages each leave a gap for HTTP filter scripts:

- **Common Expression Language (CEL)** checks types before execution and runs in a bounded sandbox.
  However, CEL is expression-only.
  Multi-rule redirect tables, early-return guards, and helper functions become hard to read and maintain when written as nested conditional expressions.
- **Starlark** offers familiar Python syntax and deterministic sandboxing.
  However, Starlark is dynamically typed.
  Type mismatches and missing `None` checks surface only when a live HTTP request hits the affected branch.

This experiment also complements two parallel tracks from issue #1601:

- **Segment-scoped path templates (`pkg/pathtemplate`, #1637)** cover declarative redirects with static schemes and hostnames.
  They do not handle arbitrary conditional logic or inline HTML generation.
- **Out-of-process `ext_proc` extensions (#1638)** handle arbitrary logic in a separate gRPC service.
  They require deploying, scaling, and securing an extra service and add a network hop on each request.

filterlang tests the middle ground.
It provides readable in-process scripts whose type, null-handling, and pattern-syntax errors fail during route reconciliation rather than on live traffic.

## Goals and Non-Goals

### Goals

1. **Catch type, nullability, and pattern errors at reconcile time.**
   The compiler checks every expression, branch, return path, regular expression, and path template before the data plane serves traffic.
2. **Keep scripts concise without mandatory type annotations.**
   The type checker infers local variable, parameter, and return types by default while permitting optional annotations.
3. **Make null handling explicit on every type.**
   Any non-nullable type `T` can form a nullable type `T | None`.
   The type checker requires explicit `is None` or `is not None` narrowing before code uses a nullable value as `T`.
4. **Bound CPU, stack, and memory per request.**
   The evaluator enforces explicit step, recursion, loop, and allocation limits with no ambient I/O.
5. **Stay pure Go and small enough to audit.**
   The language core uses only the Go standard library and breaks down into small PRs matching the repository's 200-line budget (including tests).

### Non-Goals

1. **General-purpose programming or Python compatibility.**
   filterlang borrows familiar Python syntax rather than implementing Python semantics.
2. **Request or response body streaming.**
   The first version inspects request metadata (method, scheme, host, path, query, headers) and returns a single `Action`.
3. **External I/O or mutable cross-request state.**
   Scripts cannot make network calls, read files, inspect wall-clock time, generate random numbers, or retain state between requests.
4. **Controller or CRD integration in this experiment.**
   Wiring filterlang into `HTTPRoute` `ExtensionRef`, `pkg/state`, and `pkg/proxy` stays out of scope until the standalone experiment validates ergonomics and performance.

## Lifecycle: Compile Once, Evaluate Concurrently

filterlang splits execution into two phases:

```
Reconcile Time (Controller)                   Request Time (Data Plane)
───────────────────────────                   ─────────────────────────
Source text                                   Incoming HTTP Request
    │                                                  │
    ▼                                                  ▼
Lexer ─► Parser ─► Type Checker               Immutable Request view
                       │                               │
                       ▼                               ▼
           Pattern & Constant Init            Bounded Evaluator
           (RE2, PathTemplate, tables)        runs handle(request)
                       │                               │
                       ▼                               ▼
            Immutable Compiled Program ──────► Action (redirect / respond / next)
            (shared across goroutines)         or fail-closed runtime error
```

1. **Compile phase (`Compile(source, options) (*Program, error)`):**
   The compiler lexes and parses the script, runs type inference and flow-sensitive null checking, compiles all literal regular expressions and path templates, and evaluates top-level constants under a compile-time budget.
   The compiler outputs an immutable `Program`.
2. **Evaluation phase (`Program.Eval(request, limits) (Action, error)`):**
   The data plane calls `Eval` concurrently from many request goroutines against the same immutable `Program`.
   Each call allocates an isolated per-request execution frame and budget counter.
   Evaluation needs no locks because the compiled `Program` and all top-level constants are immutable.

## Syntax

filterlang defines a small, indentation-delimited subset of Python syntax.

### Lexical Rules

- **Indentation:** Blocks open after `:` and use space-only indentation.
  Increasing indentation opens a nested block, and decreasing indentation closes one or more blocks back to a previously active column.
  The lexer rejects tab characters in leading indentation to prevent mixed-indentation ambiguity.
- **Comments:** `#` starts a line comment extending to the end of the line.
- **Line continuation:** The lexer ignores embedded newlines and indentation inside `(...)`, `[...]`, or `{...}`.
  The lexer rejects backslash line continuations outside delimiters.
- **Identifiers and keywords:** Identifiers use ASCII letters, digits, and underscores (`[A-Za-z_][A-Za-z0-9_]*`).
  Reserved keywords are `and`, `break`, `continue`, `def`, `elif`, `else`, `False`, `for`, `if`, `in`, `is`, `None`, `not`, `or`, `pass`, `return`, and `True`.

### Literals and Expressions

| Construct | Syntax | Inferred Type | Notes |
| :--- | :--- | :--- | :--- |
| Boolean | `True`, `False` | `bool` | No implicit conversion from other types. |
| Integer | `0`, `302`, `-1` | `int` | Signed 64-bit integer. Overflow aborts at runtime. |
| String | `"abc"`, `'abc'` | `str` | UTF-8 string supporting `\n`, `\r`, `\t`, `\\`, `\"`, and `\'` escapes. |
| Raw string | `r"^/([^/]+)/?$"` | `str` | Backslashes stay literal. Intended for regular expressions. |
| Formatted string | `f"https://example.com/{slug}"` | `str` | Each `{expr}` must have type `str`. `{{` and `}}` escape braces. |
| Null | `None` | `None` | Absence value for any `T \| None`. |
| List | `[a, b]` | `list[T]` | Homogeneous immutable sequence. |
| Dict | `{"k": v}` | `dict[K, V]` | Homogeneous immutable ordered mapping. `K` is `str` or `int`. |
| Tuple | `(a, b)` | `tuple[T1, T2]` | Fixed-length heterogeneous immutable tuple of two or more elements. |

Adjacent string literals do not concatenate implicitly.
Scripts use `+` inside parentheses to span long strings across lines.
That rule prevents Python's missing-comma bug in list literals.

### Operators

- **Boolean (`and`, `or`, `not`):**
  Every operand must have type `bool`.
  The evaluator short-circuits `and` and `or` from left to right.
- **Null identity (`is None`, `is not None`):**
  The operand must have a nullable type `T | None` or `None`.
  The type checker rejects `is None` and `is not None` on a non-nullable `T` because the check is unreachable dead code.
- **Equality (`==`, `!=`):**
  Both operands must have the same non-nullable value type (`bool`, `int`, `str`, `list[T]`, `dict[K, V]`, or `tuple[...]`).
  The type checker rejects comparing `T | None` with `T` using `==`, so scripts narrow with `is not None` first.
  The type checker also rejects comparing against `None` with `==`, so scripts use `is None` or `is not None`.
- **Ordering (`<`, `<=`, `>`, `>=`):**
  Both operands must have matching `int` or `str` types.
- **Membership (`in`, `not in`):**
  The checker allows `T` in `list[T]`, `K` in `dict[K, V]`, and `str` in `str` (substring search).
- **Arithmetic and concatenation:**
  - `+` accepts `int + int -> int`, `str + str -> str`, or `list[T] + list[T] -> list[T]`.
    The checker rejects mixing `str` and `int`.
  - `-`, `*`, `//`, and `%` accept only `int` operands and return `int`.
    Division or modulo by zero aborts execution with a runtime error.
- **Slicing (`s[start:end]`):**
  Slicing works on `str` (indexed by UTF-8 runes to avoid splitting multibyte characters) and on `list[T]`.
  Slicing clamps out-of-range bounds instead of raising runtime errors.
  The language omits single-element indexing (`list[i]` and `dict[k]`) in favor of `.get(...) -> T | None`, which models missing elements through the type system without exceptions.

### Statements and Module Structure

A module contains only two kinds of top-level declarations:

1. **Top-level constant bindings:** `NAME = expr` or `NAME: Type = expr`.
   The compiler evaluates top-level bindings once during compilation and freezes them as immutable values.
   Functions cannot reassign top-level names.
2. **Function definitions:** `def name(param, other: str) -> Action:`.
   Parameter and return annotations are optional.
   Functions can call any other top-level function in the module regardless of declaration order.

Every filter script must define an entry point `def handle(request):` whose inferred or annotated signature matches `(Request) -> Action`.

Inside a function body, filterlang supports:

- Local assignment and rebinding: `x = expr` or `x: Type = expr`.
- Tuple unpacking assignment: `prefix, target = pair`.
- Conditionals: `if cond:`, `elif cond:`, and `else:`.
- Bounded loops: `for item in iterable:` and `for first, second in pairs:`, with `break` and `continue`.
- Explicit returns: `return expr`.
- Empty placeholder: `pass`.

### Omitted Python Features

filterlang omits these Python features by design:

- **Classes, inheritance, and metaclasses:** Filter scripts map requests to actions using small functions and immutable data tables.
  Omitting classes keeps the type system structural and avoids mutable object graphs.
- **Exceptions (`try`, `except`, `finally`, `raise`):** Scripts handle recoverable absence through `T | None`, which the compiler checks ahead of time.
  Unrecoverable faults (budget exhaustion, division by zero, or invalid HTTP output) abort the script immediately and fail closed.
- **`while` loops and generators:** Bounded `for` loops over finite collections and bounded `range` prevent accidental infinite loops while the step budget caps total work.
- **Dynamic evaluation and reflection (`eval`, `exec`, `getattr`, `setattr`, `__import__`):** The compiler resolves every name, attribute, and function call statically.
- **Arbitrary imports and I/O modules:** Scripts can reference only the fixed host prelude.
- **Mutation aliasing (in-place list or dict mutation and mutable globals):** All composite values (`list`, `dict`, `tuple`) are immutable.
  Passing a list or dict to a helper function cannot mutate the caller's value, concurrent request goroutines share top-level constants without locks, and flow-sensitive narrowing remains sound across calls.
- **Closures, nested `def`, `lambda`, `*args`, and `**kwargs`:** First-order top-level functions with fixed arity keep type inference and call-stack analysis simple.
- **Floating-point numbers (`float`) and sets (`set`):** HTTP redirect and header filters operate on strings, integers, booleans, lists, and dicts.
  Omitting `float` avoids NaN, infinity, and rounding edge cases.
- **Implicit truthiness:** The type checker rejects `if s:` when `s` has type `str`, `list[T]`, or `T | None`.
  Requiring `bool` prevents confusing empty strings (`""`) with missing values (`None`).

## Type System

filterlang is **implicitly typed yet strongly and statically typed**.
Authors omit most type annotations, and the compiler rejects type mismatches and unhandled `None` values before the script runs.

### Type Grammar

```
Type ::= "bool" | "int" | "str" | "None"
       | "Request" | "Regex" | "PathTemplate" | "Match" | "Action"
       | "list" "[" Type "]"
       | "dict" "[" KeyType "," Type "]"
       | "tuple" "[" Type ("," Type)+ "]"
       | NonNullType "|" "None"

KeyType ::= "str" | "int"
```

### Type System Invariants

The type checker enforces five invariants:

1. **Flat nullability:** The type checker normalizes `(T | None) | None` to `T | None` and `None | None` to `None`.
   `T | None` wraps a single non-nullable type `T`.
   General union types such as `int | str` do not exist.
2. **No implicit coercions:** Every operator, f-string interpolation, and function parameter rejects mismatched types.
   The only implicit widening passes or returns a non-nullable `T` where `T | None` is expected.
3. **Null safety:** The type checker rejects passing `T | None` to a parameter of type `T`, interpolating `T | None` in an f-string, applying operators to `T | None`, or accessing attributes and methods on `T | None` until control flow narrows the value to `T`.
4. **Sound narrowing:** The type checker narrows only immutable bindings and local variable slots whose reassignments it tracks within the current function.
   Because composite values are immutable and top-level bindings cannot change, calling another function cannot invalidate a narrowed local variable.
5. **Exhaustive returns:** Every function (including `handle`) must execute a `return` statement on every control-flow path.
   Falling off the end of a function never returns `None` implicitly.

### Inference Rules

The type checker combines Hindley-Milner unification with bidirectional local inference and flat optional joins:

1. **Fresh type variables:** The checker assigns fresh type variables (`?a`, `?b`) to unannotated function parameters, local variables initialized from polymorphic calls, and empty container literals (`[]`, `{}`).
2. **Unification with occurs check and flat nullability:** The unifier solves equality constraints recursively across composite types.
   An occurs check rejects infinite recursive types such as `?a = list[?a]`.
   When unifying `?a` with a nullable type `?t | None`, the unifier constrains `?t` to non-nullable types (and flattens nested nullability on substitution) so substitution never produces `(T | None) | None` or `None | None`.
3. **Flat optional `join` at merge points:** When branches of an `if`/`elif`/`else`, multiple `return` statements in a function, or elements of a list literal produce types `A` and `B`, the checker computes `join(A, B)`:
   - `join(None, None) = None`
   - `join(T, T) = T`
   - `join(T, None) = T | None` and `join(None, T) = T | None`
   - `join(T, T | None) = T | None` and `join(T | None, T) = T | None`
   - `join(T | None, T | None) = T | None`
   - `join(A, B)` for incompatible non-nullable types (such as `int` and `str`) reports a compile-time type error.
4. **Directed assignability at calls and annotations:** When passing `src` to a parameter or annotated target `dst`:
   - If `dst` is `T | None`, the checker accepts `None`, `T`, or `T | None`.
   - If `dst` is non-nullable `T`, the checker rejects `None` and `T | None`, and unifies `src` with `T`.
5. **Attribute resolution and deferred overload constraints:** Built-in attributes and methods belong to a closed set of host and primitive types.
   - When an expression accesses an attribute or method unique to one built-in type (for example, `request.path` or `request.query` on `Request`, or `.strip_prefix` on `str`), the checker unifies an unresolved receiver type variable with that type immediately.
   - Overloaded operations with more than one valid operand type (`len`, `+`, ordering comparisons, `in`/`not in`, slicing, `.get`, and `.match`) record a deferred constraint when their operand or receiver is still a type variable (for example, `len(raw_query)` before `f"?{raw_query}"` constrains `raw_query` to `str`).
   - The checker solves deferred constraints as unification progresses within an SCC.
     filterlang has no typeclass polymorphism: every deferred overload constraint must resolve to a single concrete type before generalization, or compilation fails and requests a type annotation.
6. **Let-polymorphism for top-level helpers:** The checker computes strongly connected components (SCCs) of the function call graph and checks them in topological order.
   Functions within one recursive SCC share monomorphic type variables while the checker inspects their bodies.
   After checking an SCC and solving its deferred overload constraints, the checker generalizes remaining unconstrained type variables into polymorphic schemes so helper functions such as `def unwrap_or(value, fallback)` work on both `str | None` and `int | None`.
7. **No unresolved ambiguity:** After checking `handle(request)` against `(Request) -> Action`, the checker reports a compile-time error for any remaining unconstrained type variable (such as an unused `items = []`) and asks for an explicit annotation.

### Flow-Sensitive Narrowing

**Flow-sensitive narrowing** refines the static type of a local variable inside branches where a runtime null check has already succeeded or exited.
The checker tracks both a variable's slot type (the joined type across assignments) and its narrowed type at the current program point.

The checker supports four narrowing forms:

1. **Positive and negative branch checks:**
   - Inside `if x is not None:`, the checker narrows `x` from `T | None` to `T`.
     Inside the matching `else:`, it narrows `x` to `None`.
   - Inside `if x is None:`, the checker narrows `x` to `None`.
     Inside the matching `else:`, it narrows `x` to `T`.
2. **Guard-clause early exit:**
   When every path inside `if x is None:` exits (`return`, `break`, or `continue`), the checker narrows `x` to `T` for all statements after the `if` block.
   ```python
   match = GIT_REPO_PATTERN.match(request.path)
   if match is None:
       return next()
   # match has type Match here.
   repo = match.named("repo")
   ```
3. **Compound `and` and `or` expressions:**
   - In `A and B`, positive narrowings from `A` (facts that hold when `A` is true) apply while checking `B` and inside the `then` branch.
     This enables `if go_get is not None and go_get == "1":`.
   - In `A or B`, negative narrowings from `A` (facts that hold when `A` is false) apply while checking `B`, and the combined negative narrowings from `A` and `B` apply in the `else` branch and after an early-exit guard.
     This enables both `if go_get is None or go_get != "1":` (where `go_get` narrows to `str` before `!= "1"`) and `if a is None or b is None: return next()` (where both `a` and `b` narrow after the guard).
4. **Rebinding invalidation:**
   When a statement reassigns `x = expr`, the checker checks `expr` against `x`'s slot type (widening an unannotated slot via `join`) and resets `x`'s narrowed type to the type of `expr`.

**Trade-off (local variables only):** The checker narrows local variable names, not arbitrary call expressions.
Writing `if request.query.get("q") is not None:` does not narrow a second call to `request.query.get("q")`.
Authors bind the lookup once (`q = request.query.get("q")`) and narrow `q`.
This trade-off avoids purity analysis over arbitrary expressions, keeps the narrowing pass small, and avoids repeated map lookups at runtime.

### Compile-Time Diagnostics

The compiler tracks a 1-based start and end line and column span for every source construct.
Diagnostics display the script identifier, line and column, offending source line, caret underline, and a corrective hint when applicable.

Consider a script that forgets to narrow a query parameter before escaping it:

```python
def handle(request):
    target = request.query.get("target")
    return redirect(302, f"https://cs.k8s.io/?q={url_query_escape(target)}")
```

The compiler rejects this script during reconciliation:

```text
HTTPRoute/default/go-k8s-io:3:67: type error: cannot pass 'str | None' to parameter 'value' of type 'str'
  3 |     return redirect(302, f"https://cs.k8s.io/?q={url_query_escape(target)}")
    |                                                                   ^^^^^^
  hint: narrow 'target' first with 'if target is not None:'
```

When a future PR integrates filterlang into GARI, the controller will report this message on the route or filter `Accepted=False` status condition and refuse to push the invalid script to the data plane.

## Sandboxing and Resource Bounds

Filter scripts run inside the GARI data-plane process.
A buggy or adversarial script must not hang a request goroutine, exhaust pod memory, or access host resources.

### Sandbox Invariants

1. **No ambient authority:** The evaluator exposes no filesystem, network, clock, randomness, environment variable, or concurrency APIs.
   Evaluating the same compiled `Program` on the same `Request` produces the same `Action`.
2. **Step budget:** Every statement, expression evaluation, loop iteration, and function call consumes from a per-request step budget.
   Pattern matching (`.match(text)`) and linear string scans (substring `in` and `.split`) charge steps proportional to input length (1 step per 64 bytes scanned, minimum 1 step) so a bounded loop cannot scan megabytes of text for a handful of steps.
   Exhausting the step budget aborts evaluation immediately.
3. **Call-depth bound:** Every function call counts against a per-request maximum call depth.
   Exceeding the call-depth bound aborts evaluation immediately.
4. **Loop bound:** Because `while` does not exist, every `for` loop iterates over a finite collection or bounded `range`, and each iteration consumes the step budget.
5. **Memory and size bounds:** Every string allocation (concatenation, f-string formatting, escaping, slicing, split), list allocation, and dict allocation checks single-value size caps and charges a per-request cumulative allocation budget before allocating.
   Exceeding any cap aborts evaluation immediately.
6. **Linear-time pattern matching:** The compiler compiles regular expressions with Go's standard `regexp` package (RE2), which matches in time linear in the input length without backtracking blowups.
   Path templates use linear-time segment matching.
7. **Compile-time bounds:** Compilation caps source byte length, AST node count, compiled pattern count, and top-level constant initialization steps and allocations so malformed scripts cannot stall the controller during reconciliation.

### Default Resource Limits

| Limit | Phase | Default | Purpose |
| :--- | :--- | ---: | :--- |
| `MaxSourceBytes` | Compile | 64 KiB | Bounds lexer and parser input size. |
| `MaxASTNodes` | Compile | 4,096 | Prevents deeply nested parser DoS payloads. |
| `MaxCompiledPatterns` | Compile | 256 | Caps RE2 and path-template memory per script. |
| `MaxInitSteps` | Compile | 50,000 | Bounds top-level constant initialization CPU work. |
| `MaxInitAllocBytes` | Compile | 256 KiB | Caps cumulative allocations during top-level constant initialization. |
| `MaxSteps` | Request | 10,000 | Bounds per-request CPU time. |
| `MaxCallDepth` | Request | 32 | Prevents stack overflow from recursion. |
| `MaxRangeLen` | Request | 1,024 | Caps `range(n)` length. |
| `MaxCollectionLen` | Compile & Request | 1,024 | Caps single list or dict element count. |
| `MaxStringBytes` | Compile & Request | 16 KiB | Caps any single string value, including response bodies. |
| `MaxAllocBytes` | Request | 64 KiB | Caps cumulative allocations per request evaluation. |

Callers can override limits through `CompileOptions` and `EvalLimits`.
These defaults are conservative starting values to tune after Issue 9 benchmarks realistic filter scripts.

### Runtime Failure and HTTP Output Safety

When evaluation aborts with a runtime error (budget exhaustion, division by zero, integer overflow, or invalid action arguments), `Program.Eval` returns a Go `error` instead of an `Action`.

**Fail-closed invariant:** The data plane never falls through to `next()` when a filter fails at runtime.
Falling through would silently bypass redirect, routing, or access rules.
Instead, the data plane responds with `500 Internal Server Error` (omitting script source and internal error details from the HTTP response), logs the structured error, and increments a failure metric.

The `redirect` and `respond` constructors also enforce HTTP safety invariants at runtime:

1. **Header injection prevention:** `redirect` rejects any `location` containing CR (`\r`, 0x0D), LF (`\n`, 0x0A), or NUL (`\x00`).
   `respond` validates header names as RFC 9110 tokens and rejects header values containing CR, LF, or NUL.
2. **Status code validation:** `redirect` accepts only `{301, 302, 303, 307, 308}`.
   `respond` accepts only status codes in `200..599`.
3. **Redirect scheme and host policy:** `redirect` accepts only a relative path starting with `/` (rejecting both `//` and `/\`, which browsers normalize to protocol-relative host redirects) or an explicit `http://` or `https://` URL.
   `EvalLimits` accepts an optional `AllowedRedirectHosts []string` allowlist.
   When configured, `redirect` rejects absolute URLs whose host is not in the allowlist.

**Trade-off (open-redirect defense):** Declarative path templates (#1637) keep redirect schemes and hostnames static by schema structure.
Because filterlang constructs `location` strings dynamically, the type checker cannot prove the target hostname is static in all scripts.
The host layer mitigates this with CR/LF rejection, `//` and `/\` rejection, and optional `AllowedRedirectHosts` checks at runtime.

## HTTP Filter Host API

The host API exposes a read-only view of the incoming HTTP request, compile-time-validated pattern matchers, escaping helpers, and explicit return actions.

### Read-Only `Request` Type

The host builds an immutable `Request` from Go's `*http.Request`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `request.method` | `str` | HTTP method, such as `"GET"` or `"HEAD"`. |
| `request.scheme` | `str` | Request scheme, `"http"` or `"https"`. |
| `request.host` | `str` | Lowercased request hostname with any trailing port stripped. |
| `request.path` | `str` | Decoded URL path (`r.URL.Path`). |
| `request.raw_query` | `str` | Raw query string without leading `?` (`r.URL.RawQuery`). |
| `request.query` | `dict[str, str]` | Parsed query parameters mapping each key to its first value. |
| `request.headers` | `dict[str, str]` | Lowercased header names mapping each key to its first value. |

**Trade-off (first-value maps):** Exposing `request.query` and `request.headers` as `dict[str, str]` keeps common lookups concise (`request.query.get("go-get") -> str | None`).
Scripts cannot inspect secondary values of repeated query parameters or multi-valued headers in v1.
Adding `request.query_all(name: str) -> list[str]` and `request.header_all(name: str) -> list[str]` later stays backwards-compatible.

### Pattern Matching and `Match`

- `re_compile(pattern: str) -> Regex`:
  Requires a string literal argument.
  The compiler parses `pattern` with Go RE2 during `Compile` and reports invalid syntax at the literal's source span.
  `regex.match(text: str) -> Match | None` returns a `Match` when `text` matches `regex`, or `None` otherwise.
- `path_template(template: str) -> PathTemplate`:
  Requires a string literal argument.
  The compiler parses segment-scoped path templates (`{var}`, `{var=*}`, `{var=**}`, and literal segments) following the `google.api.http` grammar from #1637 during `Compile`.
  `template.match(path: str) -> Match | None` returns a `Match` when `path` matches `template`, or `None` otherwise.
- `Match` methods:
  - `match.named(name: str) -> str | None` returns the matched substring for a named regex group `(?P<name>...)` or path-template variable `{name}`, or `None` when unmatched or absent.
  - `match.group(index: int) -> str | None` returns the matched substring for a 0-based regex capture group (`0` is the full match), or `None` when unmatched or out of range.

### Escaping, String, and Collection Helpers

Built-in functions:

- `url_query_escape(value: str) -> str` escapes a value for safe interpolation into a query parameter (`net/url.QueryEscape`).
- `url_path_escape(segment: str) -> str` escapes a single URL path segment (`net/url.PathEscape`).
- `url_segments_escape(path: str) -> str` splits `path` on `/`, escapes each segment with `net/url.PathEscape`, and rejoins with `/` so multi-segment captures preserve `/` without smuggling `?` or `#`.
- `html_escape(value: str) -> str` escapes HTML metacharacters (`html.EscapeString`) for safe inline HTML generation.
- `len(x) -> int` returns the rune count for `str` or the element count for `list[T]` and `dict[K, V]`.
- `str(n: int) -> str` converts an `int` to its base-10 string representation.
- `range(stop: int) -> list[int]` returns `[]` when `stop <= 0`, returns `[0, ..., stop-1]` when `0 < stop <= MaxRangeLen`, and aborts with a budget error when `stop > MaxRangeLen`.

Built-in methods:

- `str`:
  - `.startswith(prefix: str) -> bool`
  - `.endswith(suffix: str) -> bool`
  - `.strip_prefix(prefix: str) -> str | None` returns the remaining suffix when `prefix` matches, or `None` otherwise.
  - `.strip_suffix(suffix: str) -> str | None` returns the remaining prefix when `suffix` matches, or `None` otherwise.
  - `.lower() -> str`
  - `.split(sep: str) -> list[str]`
- `list[T]`:
  - `.get(index: int) -> T | None` returns `None` when `index < 0` or `index >= len(list)`.
- `dict[K, V]`:
  - `.get(key: K) -> V | None` returns `None` when `key` is absent.

### Return Actions

- `redirect(status: int, location: str) -> Action` returns an HTTP redirect response with `Location: <location>`.
- `respond(status: int, body: str, headers: dict[str, str] | None) -> Action` returns an immediate HTTP response with the given body and optional headers.
- `next() -> Action` passes the request to the next filter or backend in the route rule.

## Concrete Examples: `k8s.io` Vanity Redirector

The script below implements the `k8s.io` vanity redirector cases from issue #1601 in filterlang with no manual type annotations.
Each handler exercises a distinct capability: ordered regex rules and `?go-get=1` pass-through (`git.k8s.io`), table lookup and query escaping (`go.k8s.io`), prefix narrowing and fragment ordering (`rel.k8s.io`), optional regex groups with a polymorphic helper (`sbom.k8s.io`), and in-process `?go-get=1` HTML responses (`k8s.io`).

```python
GIT_REPO_PATTERN = re_compile(r"^/(?P<repo>[^/]+)/?$")
GIT_FILE_PATTERN = re_compile(r"^/(?P<repo>[^/]+)/(?P<path>.+)$")
OWNERS_TEMPLATE = path_template("/owners/{user}")
RELEASE_LINK_TEMPLATE = path_template("/{version}/{section}")
SBOM_PATTERN = re_compile(r"^/(?P<version>[^/]+)/release(?P<extension>\.sig|\.cert)?$")
GO_GET_PATTERN = re_compile(r"^/(?P<repo>[^/]+)(?:/.*)?$")

GO_SHORT_LINKS = [
    ("/b", "https://github.com/kubernetes/kubernetes/issues"),
    ("/pr", "https://github.com/kubernetes/kubernetes/pulls"),
]


def unwrap_or(value, fallback):
    if value is not None:
        return value
    return fallback


def capture(match, name):
    if match is None:
        return None
    return match.named(name)


def append_query_and_fragment(base_url, raw_query, fragment):
    query_part = ""
    if len(raw_query) > 0:
        query_part = f"?{raw_query}"
    return f"{base_url}{query_part}#{fragment}"


def handle_git(request):
    # Coexist with an HTTPRoute backend that serves ?go-get=1 requests.
    go_get = request.query.get("go-get")
    if go_get is not None and go_get == "1":
        return next()

    # Ordered rule 1: git.k8s.io/<repo> or git.k8s.io/<repo>/
    repo = capture(GIT_REPO_PATTERN.match(request.path), "repo")
    if repo is not None:
        return redirect(302, f"https://github.com/kubernetes/{url_path_escape(repo)}")

    # Ordered rule 2: git.k8s.io/<repo>/<path>
    file_match = GIT_FILE_PATTERN.match(request.path)
    repo = capture(file_match, "repo")
    file_path = capture(file_match, "path")
    if repo is not None and file_path is not None:
        escaped_repo = url_path_escape(repo)
        escaped_path = url_segments_escape(file_path)
        return redirect(
            302,
            f"https://github.com/kubernetes/{escaped_repo}/blob/master/{escaped_path}",
        )

    return redirect(302, "https://github.com/kubernetes")


def handle_go(request):
    # Bounded table lookup using tuple unpacking.
    for path, target in GO_SHORT_LINKS:
        if request.path == path:
            return redirect(302, target)

    # go.k8s.io/owners/<user>: escape capture while keeping literal %2F intact.
    user = capture(OWNERS_TEMPLATE.match(request.path), "user")
    if user is not None:
        escaped = url_query_escape(user)
        return redirect(
            302,
            f"https://cs.k8s.io/?q={escaped}&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=",
        )

    return next()


def handle_rel(request):
    # rel.k8s.io/v1.32/retro -> .../releases/release-1.32/links.md#retro
    match = RELEASE_LINK_TEMPLATE.match(request.path)
    raw_version = capture(match, "version")
    section = capture(match, "section")
    if raw_version is None or section is None:
        return next()

    release_number = raw_version.strip_prefix("v")
    if release_number is None:
        return next()

    base = (
        "https://github.com/kubernetes/sig-release/tree/master/releases/release-"
        + url_path_escape(release_number)
        + "/links.md"
    )
    location = append_query_and_fragment(base, request.raw_query, url_path_escape(section))
    return redirect(302, location)


def handle_sbom(request):
    # sbom.k8s.io/<ver>/release[.sig|.cert] -> optional capture via polymorphic helper.
    match = SBOM_PATTERN.match(request.path)
    version = capture(match, "version")
    if version is None:
        return next()

    suffix = unwrap_or(capture(match, "extension"), "")
    return redirect(
        302,
        f"https://dl.k8s.io/release/{url_path_escape(version)}/kubernetes-release.spdx{suffix}",
    )


def maybe_go_get_response(request):
    # Serve ?go-get=1 HTML directly in-process; inferred return type is Action | None.
    go_get = request.query.get("go-get")
    if go_get is None or go_get != "1":
        return None

    repo = capture(GO_GET_PATTERN.match(request.path), "repo")
    if repo is None:
        return None

    safe_repo = html_escape(repo)
    body = (
        "<!DOCTYPE html><html><head>"
        + f'<meta name="go-import" content="k8s.io/{safe_repo} git https://github.com/kubernetes/{safe_repo}">'
        + "</head><body></body></html>"
    )
    return respond(200, body, {"Content-Type": "text/html; charset=utf-8"})


def handle(request):
    if request.host == "k8s.io":
        return unwrap_or(maybe_go_get_response(request), next())
    if request.host == "git.k8s.io":
        return handle_git(request)
    if request.host == "go.k8s.io":
        return handle_go(request)
    if request.host == "rel.k8s.io":
        return handle_rel(request)
    if request.host == "sbom.k8s.io":
        return handle_sbom(request)
    return next()
```

### Ergonomics Notes from the Examples

- **Uniform null safety across all types:** `request.query.get("go-get")` (`str | None`), `GIT_REPO_PATTERN.match(...)` (`Match | None`), `match.named("extension")` (`str | None`), `raw_version.strip_prefix("v")` (`str | None`), and `maybe_go_get_response(request)` (`Action | None`) all use the same `T | None` narrowing rules.
- **Let-polymorphism reduces boilerplate:** The 4-line `unwrap_or` helper infers `(T | None, T) -> T` and works cleanly on both `str | None` (in `handle_sbom`) and `Action | None` (in `handle`), while `capture(match, name)` collapses chained `Match | None` and `str | None` checks into one `str | None` check.
- **Trade-off on required captures:** Because `match.named(...)` returns `str | None` even for required capture groups, scripts still check or unwrap required captures.
  This keeps the type checker independent of regex AST analysis.
  A later enhancement can inspect compiled pattern metadata to type required groups as `str` directly if scripts find the check noisy.

## Key Architectural Trade-Offs

1. **Tree-walking evaluator vs. bytecode VM:**
   The initial implementation walks the type-checked AST directly.
   A tree walker stays compact and maps runtime errors directly to source spans.
   The trade-off is higher per-step CPU overhead than a stack-based bytecode VM.
   Because the public Go API exposes only `Compile` and `Program.Eval`, replacing the internal evaluator with a bytecode compiler later requires no language or caller changes.
2. **Immutable composite values vs. local mutation:**
   Making `list` and `dict` immutable prevents mutation aliasing bugs, keeps narrowing sound across function calls, and lets concurrent request goroutines share top-level tables without locks.
   The trade-off is that building a large list element-by-element via `acc = acc + [item]` copies on each step and consumes the allocation budget quickly.
   This trade-off fits HTTP filter scripts, which read request fields and format small URLs or headers rather than transforming large collections.
3. **Flat `T | None` vs. general union types:**
   Supporting only `T | None` keeps unification decidable without union subtyping lattices and produces clear error messages.
   The trade-off is that scripts cannot store mixed `int` and `str` values in one list without tuples.
4. **No closures or first-class functions in v1:**
   Restricting functions to top-level `def` declarations simplifies let-polymorphism and call-depth enforcement, at the cost of no `lambda` callbacks.

## Implementation Breakdown

Following `AGENTS.md`, each follow-up issue targets at most 200 lines **including tests**, with explicit split points noted where an indivisible core plus unit tests may approach that ceiling.
No production code lands in this design PR.

1. **Issue 1 — `experiments/filterlang`: source spans, token definitions, and AST (~160 lines including tests)**
   - Define 1-based source spans, token kinds, and AST nodes for declarations, statements, expressions, and type annotations, with basic span/formatting tests.
2. **Issue 2 — `experiments/filterlang`: indentation-tracking lexer (~200 lines including tests)**
   - Implement space-only indentation block scanning (rejecting leading tabs), multiline delimiter grouping, raw strings, and f-string tokenization, with unit tests for edge cases and lexical error spans.
3. **Issue 3 — `experiments/filterlang`: expression and statement parser (~200 lines including tests)**
   - Parse top-level declarations, optional type annotations, statements, and operator-precedence expressions while enforcing compile-time source-size and AST-node caps.
   - If unit tests push this slice over 200 total lines, split into expression parsing (3a) followed by statement/declaration parsing (3b).
4. **Issue 4 — `experiments/filterlang`: type model, unifier, and flat nullability (~180 lines including tests)**
   - Implement type representations, type variables, unification with occurs check, flat `T | None` normalization and `join`, directed assignability, and unit tests.
5. **Issue 5 — `experiments/filterlang`: core type checker and SCC inference (~200 lines including tests)**
   - Implement call-graph SCC topological checking, attribute and deferred overload resolution, let-polymorphism, exhaustive return checking, and `handle` entry-point signature verification.
6. **Issue 6 — `experiments/filterlang`: flow-sensitive narrowing and diagnostics (~200 lines including tests)**
   - Add `is None` / `is not None` branch and early-exit guard narrowing, `and`/`or` short-circuit narrowing, rebinding invalidation, and caret-formatted `line:col` diagnostics with hints.
7. **Issue 7 — `experiments/filterlang`: immutable runtime values and bounded evaluator (~200 lines including tests)**
   - Implement top-level constant initialization, deterministic AST evaluation, and enforcement of the compile-time and per-request step, call-depth, loop, and allocation budgets.
8. **Issue 8 — `experiments/filterlang`: HTTP host API, pattern compilation, and output safety (~200 lines including tests)**
   - Implement read-only request bindings, compile-time RE2 and path-template compilation (reusing `pkg/pathtemplate` from #1637 if merged), escaping/string helpers, HTTP output safety validation, and the concurrent `Compile` / `Program.Eval` entry points.
   - If tests push this slice over 200 total lines, split pattern matchers and escaping helpers (8a) from HTTP request/action bindings and safety checks (8b).
9. **Issue 9 — `experiments/filterlang`: `k8s.io` corpus tests, fuzz targets, and benchmarks (~200 lines, tests and benchmarks only)**
   - Run the full `k8s.io` script and negative compile-time cases end to end, add fuzz targets verifying panic-free bounded execution on arbitrary input, and benchmark `Program.Eval` against a handwritten Go `http.Handler` to inform future GARI `ExtensionRef` integration.
