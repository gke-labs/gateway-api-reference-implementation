# Incremental State: the Computation Is the Dependency Graph

This document describes a concept for structuring Kubernetes controllers that
compute results across many objects, and how we plan to apply it to GARI.

In short: a central `State` holds every input object and computes the
outputs, which are per-object status and the data plane configuration. While
it computes an output, it records which inputs (and intermediate results)
that computation read, and at which version. When something changes, we
recompute only the outputs whose recorded dependencies changed. Nobody writes
invalidation logic by hand. The computation itself is the dependency logic.

None of this is new. Spreadsheets, build systems and incremental compilers
have worked this way for decades (see [Prior art](#prior-art-and-credit)).
What we think is worth writing down is how well it fits Kubernetes
controllers, and Gateway API in particular, where it is not yet common.

## The problem

A typical controller-runtime controller reconciles one kind of object. When
an object's result depends on *other* objects, the controller adds watches on
those kinds, plus a mapping function that answers: "this other object
changed, so which of my objects might be affected?"

Gateway API is full of cross-object dependencies. Some examples from GARI:

- Whether an HTTPRoute is accepted depends on its parent Gateways (or
  ListenerSets), their listeners' `allowedRoutes`, the GatewayClass and its
  controller name, the labels on the route's Namespace (for `Selector`), and
  hostname intersection with each listener.
- Whether a backend reference resolves depends on the Service existing and
  on a ReferenceGrant in another namespace allowing it.
- A Gateway's status counts attached routes and attached ListenerSets, so it
  depends on every route and ListenerSet that points at it.
- A ListenerSet's acceptance depends on its parent Gateway's
  `allowedListeners`, which may use a namespace label selector.
- Listener conflict detection depends on *every other* listener on the same
  Gateway, including listeners contributed by other ListenerSets.

Each of these turns into a watch plus a mapping function, and those mapping
functions are a **second copy of the logic**: one copy computes the result,
and the other guesses which objects the result depends on. The two copies
drift apart. When the mapping is too narrow, status goes stale and stays
stale until something unrelated triggers a reconcile. When it is too broad
("a Namespace changed, so enqueue every ListenerSet"), it is wasteful but
safe, and that is usually what people write. Every new feature has to update
both copies.

A second, related problem: each controller computes its own slice of the
result. The HTTPRoute controller decides whether a route is attached, and
the Gateway controller separately counts attached routes. These can
disagree, and the Gateway API conformance tests are very good at noticing
when they do.

## The idea

Put the computation in one place, and make it record its own dependencies.

1. **Inputs.** Controllers only *record* objects into `State` as watch events
   arrive. Each change is stamped with a value from a single, monotonically
   increasing `uint64` revision counter.
2. **Queries.** Everything else is a *query*: a pure function that computes
   a result from inputs and other queries. Examples are "the compiled
   Gateway `ns/name`", "the status of HTTPRoute `ns/name`" and "the proxy
   configuration".
3. **Tracked reads.** Queries can only read through a tracking reader. Every
   read (an input object, a list of objects, or another query) is recorded
   as a dependency, along with the revision at which that dependency last
   changed.
4. **Memoization.** Each query result is stored with its dependency list. To
   check whether a stored result is still valid, we check whether all of its
   dependencies are unchanged. If they are, we reuse the result without
   recomputing.
5. **Early cutoff.** If a query is recomputed and gives a result equal to the
   previous one, we keep its old "changed at" revision. Anything that depends
   on it stays valid, and the change stops spreading.
6. **Outputs.** Per-object status is a query. When an object's computed
   status changes, `State` notifies the controller for that kind, which
   reconciles the object and writes the status.

The controller code stops containing cross-object logic. There are no
mapping functions, no hand-written invalidation, and no per-controller
status logic that can disagree with another controller.

## Prior art and credit

This design borrows directly from several well-known systems.

- **Spreadsheets.** Spreadsheets have been the standard example of
  automatic recalculation since VisiCalc (1979). Modern spreadsheets such as
  Excel track which cells each formula reads, and recalculate only the cells
  that depend on an edit. They are still the most widely used incremental
  computation engine. Spreadsheets also show the hard case clearly:
  functions like `INDIRECT` compute their references at run time, so their
  dependencies cannot be known ahead of time. Spreadsheets handle these by
  treating them as "volatile" and always recalculating them. Our equivalent
  is a dependency on a set or on something being absent (see
  [below](#dependencies-on-sets-and-absence)).
- **Self-adjusting computation and Adapton.** Umut Acar's work on
  self-adjusting computation, and later Adapton (Hammer, Phang, Hicks and
  Foster, *Adapton: Composable, Demand-Driven Incremental Computation*,
  PLDI 2014), formalized the idea of recording a dynamic dependency graph
  while a program runs, and then reusing it to update results after inputs
  change. Adapton's demand-driven approach (mark results dirty when inputs
  change, then recompute lazily when something asks for them) is close to
  what we describe here.
- **Bazel's Skyframe.** Bazel evaluates builds as a graph of `SkyFunction`s
  keyed by `SkyKey`s. A `SkyFunction` declares dependencies simply by
  requesting other values from its environment, so the graph is discovered
  by running the functions. Skyframe's *change pruning* stops invalidation
  when a recomputed value equals its previous value, which is our early
  cutoff.
- **Salsa.** [Salsa](https://github.com/salsa-rs/salsa), the incremental
  computation framework behind rust-analyzer, is the most direct model.
  It has inputs and derived queries, a global revision counter, and for
  each memoized value it records the dependencies it read, the revision at
  which the value last changed (`changed_at`) and the revision at which it
  was last checked (`verified_at`). Its "red-green" algorithm checks
  dependencies before recomputing, and "backdating" keeps `changed_at`
  unchanged when a recomputed value is equal to the old one. Our design is
  essentially Salsa's model applied to a Kubernetes controller.
- **Build Systems à la Carte.** Mokhov, Mitchell and Peyton Jones
  (ICFP 2018) describe these systems in a common framework, and give us the
  vocabulary: dynamic dependencies, *verifying traces* (store each result's
  dependencies with their versions and check them before reuse), and *early
  cutoff*. In those terms, this design uses verifying traces with early
  cutoff and dynamic dependencies.

- **Envoy's xDS.** The versioned push and ACK/NACK model for multiple
  data-plane replicas (see
  [below](#multiple-data-plane-replicas)) follows Envoy's xDS protocol.

Credit for the ideas goes to these projects and their authors. Mistakes in
applying them to Kubernetes are ours.

## Design

The sketches below are illustrative Go, not a final API.

### Inputs and revisions

```go
type Revision uint64

type inputEntry struct {
	obj       client.Object
	changedAt Revision
}
```

When a watch event arrives, the controller calls something like
`state.SetInput(kind, key, obj)`. `State` increments the global revision and
stamps the entry. Deletion is also a change: the entry becomes "absent", with
its own `changedAt`.

Only the parts of an object that queries can read should count as a change.
In particular, our own status writes generate watch events, and those must
not bump the input's revision, or every status write would trigger another
recomputation. Spec, metadata labels and Secret data count; status of objects
we own does not. Comparing the relevant fields is more reliable than using
`metadata.generation`, because Namespaces and Secrets do not have one.

### Queries and the tracking reader

```go
type Reader interface {
	// Get returns the object, or nil if it does not exist. Both outcomes
	// are recorded as a dependency.
	Get(kind Kind, key types.NamespacedName) client.Object

	// List returns objects of a kind in a namespace ("" for all). The
	// dependency is on the set, so adding or removing a member counts as
	// a change.
	List(kind Kind, namespace string) []client.Object
}

// A query computes a value from a Reader. It must be pure: same reads,
// same result.
type Query[K comparable, V any] struct {
	Name    string
	Compute func(r Reader, key K) V
	Equal   func(a, b V) bool
}
```

A query can call other queries through the same reader, and those calls are
recorded as dependencies too.

### Memo entries and validation

```go
type dep struct {
	id        depID // input key, list key, or query key
	changedAt Revision
}

type memo struct {
	value      any
	deps       []dep
	changedAt  Revision // last revision at which value actually changed
	verifiedAt Revision // last revision at which deps were checked
}
```

To get a query's value at the current revision:

1. If there is no memo, compute it, recording dependencies.
2. If `verifiedAt` is the current revision, return the value.
3. Otherwise, check each dependency in order. For a query dependency, first
   bring that query up to date (recursively). If every dependency's
   `changedAt` is unchanged from what we recorded, set `verifiedAt` to the
   current revision and return the stored value. Nothing is recomputed.
4. If any dependency changed, recompute. If the new value is `Equal` to the
   old one, keep the old `changedAt` (early cutoff). Otherwise, set
   `changedAt` to the current revision.

### Dependencies on sets and absence

The easy case is "I read object X". The cases that cause stale-status bugs in
hand-written controllers are different:

- **Absence:** "the parent Gateway does not exist", "no ReferenceGrant allows
  this reference". If the dependency is not recorded, creating the missing
  object later never triggers a recompute. `Get` returning nil therefore
  records a dependency on that key, and creating the object later changes it.
- **Sets:** "every listener on this Gateway", "namespaces matching this
  selector", "all routes that reference this parent". `List` records a
  dependency on the collection (per kind, or per kind and namespace). The
  collection has its own `changedAt`, which changes whenever a member is
  added, removed or changed.

Set dependencies are coarse: any HTTPRoute change invalidates every query
that listed HTTPRoutes. That is fine, because early cutoff stops the change
from spreading. A query like "routes attached to Gateway X" is recomputed,
returns the same result for most Gateways, and stops there. If coarse
dependencies become a performance problem, we can add indexed queries (for
example, "routes whose parentRefs name Gateway X") as queries of their own.

### Outputs and controllers

The outputs are:

- **Per-object status.** These are queries such as `HTTPRouteStatus(key)`,
  `GatewayStatus(key)` and `ListenerSetStatus(key)`.
- **Proxy configuration.** This is a query that produces the
  `InternalRoutes`/listeners consumed by `pkg/proxy`, along with the hook
  callback for embedders.

After each batch of input changes, `State` brings the outputs up to date. For
each status output whose `changedAt` moved, it sends an event on a
per-kind channel. Each controller watches its channel using controller-runtime's
`WatchesRawSource(source.Channel(...))`, so a changed status turns into a
normal reconcile request.

The reconciler then reads the computed status from `State` and writes it to
the API server if it differs from the object's current status. We keep the
write in the reconciler, not in `State`, so that we keep controller-runtime's
retries, backoff, rate limiting and conflict handling, and so `State` stays
pure and easy to test without a cluster.

### Avoiding cycles

Queries must not depend on themselves, directly or indirectly. Gateway API
has a natural cycle if we are careless: route acceptance depends on the
Gateway, and Gateway status (attached routes) depends on routes. The fix is
to split queries into layers:

```
inputs (Gateway, GatewayClass, ListenerSet, HTTPRoute, Namespace, ReferenceGrant, Service, Secret, ...)
   │
   ▼
CompiledGateway(gw)          listeners from the Gateway and its allowed ListenerSets
                             ("effective listeners"), conflicts, allowedRoutes, certificates
   │
   ▼
RouteBinding(route)          for each parentRef: accepted?, which effective listeners, reason
   │
   ├──► HTTPRouteStatus(route)
   ├──► GatewayStatus(gw)     counts attached routes from RouteBinding of each route
   ├──► ListenerSetStatus(ls)
   └──► ProxyConfig()
```

`CompiledGateway` never reads routes, so there is no cycle. Detecting a cycle
at run time (a query that is already being computed is requested again) is
cheap, and should panic in tests.

### Correctness: purity and check mode

The scheme is only correct if queries read nothing except through the
`Reader`. An untracked read (a package-level variable, the clock, a direct
read of the `State` maps) produces results that never get recomputed. To make
this hard to get wrong:

- Query functions get only a `Reader`, never the `State` itself.
- In tests, we run in **check mode**: after every input change, we also
  recompute every output from scratch, with no memoization, and compare it
  with the incremental result. Any difference is a missing dependency. This
  is cheap at test scale, and it turns a whole class of subtle bugs into
  test failures.

### Concurrency

Computation runs under a single lock in `State`. Controllers record inputs
(cheap) and read outputs (cheap once they are up to date). At the scale GARI
targets this is more than fast enough, and it guarantees that all statuses
and the proxy configuration come from the same revision, which is exactly
the consistency that the conformance tests check. Recomputation can be
batched with a small delay, so a burst of watch events, such as at startup,
results in one recompute.

## Multiple data-plane replicas

So far we have assumed one GARI process that both computes state and serves
traffic. Once there is more than one data-plane router, for availability or
for capacity, this design gives a natural split between the controller and
the data plane.

- **The controller computes; routers apply.** All dependency tracking,
  validation and status computation stay in the controller. Routers receive
  compiled configuration and apply it. They don't need informers, the
  `State`, or any Gateway API logic.
- **Versioned push, with ACK/NACK.** The controller pushes the proxy
  configuration output with its revision. Each router applies it and
  reports back either "applied revision R" (ACK) or "rejected revision R,
  because ..." (NACK). This is the model of Envoy's
  [xDS protocol](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol),
  where each config carries a `version_info` and proxies ACK or NACK it;
  we credit xDS for it here. The incremental model maps naturally onto
  incremental (delta) xDS, because each query output already has its own
  version.

### Gating status on the data plane

Gateway API separates "the configuration is valid" from "the data plane has
it":

- **`Accepted` and `ResolvedRefs`** describe validity. The controller can
  decide these immediately; errors are detected in the controller and don't
  need a round trip to the data plane.
- **`Programmed`** (on Gateways and their listeners) describes the data
  plane. It should become `True` only once every serving router has applied
  the configuration.

The revisions make this check simple. A Gateway is programmed once every
serving router has ACKed a revision at or after the `changedAt` of that
Gateway's compiled configuration. Early cutoff matters here too: a change
that doesn't affect a Gateway's compiled configuration leaves its
`changedAt` alone, so its status doesn't flip back to "not yet programmed"
while routers catch up on unrelated changes.

Some failures can only be detected by a router, such as a port already in
use or a certificate the TLS stack refuses to load. A NACK carries the
reason, which becomes `Programmed=False` with a useful message.

### Which routers count

"Every serving router" needs a careful definition, or one bad pod can block
status for everyone.

- **New routers** report Ready (and so join the Service endpoints) only
  after applying the current configuration. Until then they get no traffic,
  so they don't need to be waited on.
- **Unresponsive routers** are removed from the set after a timeout, and
  should be restarted, so a wedged pod can't hold `Programmed` back forever.
- **During rollouts** routers briefly run different revisions. That's
  acceptable, as long as status only claims what every serving router has
  applied.

### Scope and acceleration

The unit of push can be a per-Gateway query (`ProxyConfig(gateway)`), so
that routers dedicated to a Gateway receive only that Gateway's
configuration and certificates. That fits the separation of provisioning
from the data plane, where each Gateway gets its own router Deployment. It
also keeps pushes small and limits where private keys are sent.

In single-process mode the router is in-process and ACKs immediately,
through the same interface.

This connects to [accelerated operations](accelerated-operations.md). If
the push protocol is a clean "versioned configuration plus ACK/NACK" stream,
an accelerated data plane is just another subscriber. It ACKs what it can
program, and GARI serves the rest.

## Plan

We will build this in three steps. Each step has no behaviour change of its
own and is checked against the conformance suite.

1. **Pure compiled model.** Move all cross-object computation into pure
   functions in `pkg/state`, built around a shared "effective listener" type
   that covers both Gateway listeners and ListenerSet entries. This removes
   the duplicated Gateway and ListenerSet logic that ListenerSet support
   introduced (#605), and it is needed whatever else we do.
2. **Central recompute and diff.** On any input change, `State` recomputes
   everything (GARI already rebuilds its whole internal state on each
   change), compares each object's computed status with the previous one,
   and signals controllers through channels. Controllers only record inputs
   and write status. This step delivers most of the benefit: no mapping
   functions, no hand-written invalidation, and one consistent computation.
3. **Memoization with dependency tracking.** Add the `Reader`, memo entries,
   validation and early cutoff behind the same interfaces. The outputs of
   step 2's full recompute become the oracle for check mode.

Later, once there is more than one router, a fourth step adds the versioned
push with ACK/NACK and gates `Programmed` on it, as described in
[Multiple data-plane replicas](#multiple-data-plane-replicas). It builds on
step 2, not step 3.

If step 2 turns out to be fast enough, step 3 can wait until there is a
reason to do it. The architectural win does not depend on it.

## Open questions

- **Granularity of `List` dependencies.** Is per-kind or per-kind-and-namespace
  enough, or do we want indexed queries from the start?
- **Equality.** Deep equality on large results (the proxy configuration) has
  a cost. We may want hashes, or to split the proxy configuration into
  per-Gateway queries.
- **Memory.** Memo entries for deleted objects need to be garbage-collected.
  Salsa uses LRU and durability levels. We can probably drop memos for keys
  that are absent and no longer read by any other query.
- **A library?** Nothing here is specific to Gateway API. If it works well in
  GARI, the `State`, `Reader` and query machinery could be extracted into a
  small library for other controllers.
