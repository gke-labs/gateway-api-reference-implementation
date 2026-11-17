# Design: Push Config Directly from Controller to Data Plane

## Context and Goals

Today the controller writes each Gateway's data-plane config to a Kubernetes
Secret (`config.json`), and the data plane watches that Secret. Direct push
from the controller to each data plane eliminates the intermediate Secret:

- **Faster.** Eliminates API server write and watch overhead between the
  controller and the data plane.
- **More observable.** The controller learns directly from the data plane which
  revision it applied, and why one failed.
- **Safer.** Keeps TLS private keys out of etcd and namespace Secrets, and
  removes the 1 MiB Secret size limit.

## Design Invariants

- The controller pushes compiled configuration directly to data planes over TLS
  to eliminate API server write and watch overhead.
- No component writes data-plane configurations or TLS private keys to Secrets,
  keeping credentials out of etcd and namespace-accessible storage.
- The controller authenticates each data plane and delivers only its Gateway's
  configuration to keep private keys and routes isolated.
- The data plane acknowledges a revision only after its listeners accept
  connections, guaranteeing that traffic routes only to live listeners.
- The data plane reports unready (`readyz=False`) whenever it lacks an applied
  configuration to prevent load balancers from directing traffic to it.

## 1. Who Connects to Whom

Two topology choices exist for establishing the configuration stream:

- **Controller dials data planes.** The controller discovers data-plane Pod IPs
  or EndpointSlices and dials an administrative port on each pod. Only the elected
  leader dials. This requires opening inbound admin ports on data-plane pods and
  configuring cross-namespace network policies to permit controller ingress.
- **Data planes dial controller.** Data planes dial a stable controller ClusterIP
  Service and maintain long-lived bidirectional gRPC streams. Standby controller
  replicas reject incoming streams with gRPC `UNAVAILABLE`. Data planes handle
  `UNAVAILABLE` by retrying with backoff until kube-proxy routes them to the
  elected leader. This avoids proxying between controllers or managing dynamic
  Service endpoints during failovers.

**Decision:** Data planes dial the controller. The maintainer chose this
direction for its compelling latency. It requires only standard pod egress
rather than opening inbound firewall ports into data planes across workload
namespaces, avoids pod endpoint discovery in the controller, and synchronizes
restarting data planes immediately when they dial on startup.

## 2. Authentication and Authorization

Each side proves its identity to ensure TLS private keys remain secure:

- **Data plane identity.** Data planes present projected ServiceAccount tokens
  (`audience: gari-controller`) over TLS. The controller verifies tokens via
  TokenReview or local JWT keys, identifying the pod's namespace and account.
- **Controller identity.** Data planes verify the controller's TLS certificate
  against the mounted cluster CA bundle (`ca.crt`).
- **Gateway scoping.** The controller verifies the ServiceAccount matches the
  Gateway (`ResourceNameForGateway(gw.Name)` in `gw.Namespace`). The controller
  sends only that Gateway's compiled config, protecting TLS private keys.

## 3. Start and Restart

A running data plane keeps serving the configuration it holds in memory if the
controller becomes unreachable. When a data plane starts or restarts while the
controller is down:

- **Serve nothing (fail closed).** The restarted data plane has no local cache,
  so it binds no listeners and reports unready until it reaches the controller
  and receives its configuration.
- **Serve from local cache.** The data plane writes applied config to an
  in-memory `emptyDir` volume (`/var/run/gari/cached-config.json`). On container
  restarts within the same pod, it loads the cache; fresh pods start empty.

**Decision:** Fail closed, with no serving from a local cache. The maintainer
chose this because it is simpler and avoids serving from a local cache at the
worst possible moment. The trade-off is in plain terms: no TLS private keys on
local disk and no stale config after a restart, at the cost of serving nothing
after a restart while the controller is down.

## 4. Acknowledgement

The push reply carries the applied revision or the reason the apply failed:

- **ACK and NACK framing.** The data plane replies with an ACK containing the
  applied revision, or a NACK containing the revision and the error reason.
- **Replaces polling.** Push replies replace the controller's HTTP polling of
  data-plane `/applied` endpoints with immediate, push-driven telemetry.
- **Programmed condition.** The controller sets `Programmed=True` when all active
  data-plane replicas acknowledge the desired revision and their listeners accept
  connections. A NACK or push timeout sets `Programmed=False` with reason
  `SyncError` and surfaces the data plane's error message.

## 5. Readiness

When the data plane has no config yet, its `/readyz` probe returns HTTP 503
(unready) and it reports no applied revision. This directly follows the rule
that the data plane reports ready and reports an applied revision only after
its listeners bind and accept connections. Unconfigured data-plane pods remain
unready in Kubernetes, preventing services from routing traffic prematurely.

## 6. Other Data Planes

Non-standard data planes receive configuration through the same mechanism:

- **snigateway.** The data-plane container runs the tunnel client next to the
  proxy, connects via push to receive `DataplaneConfig`, and registers hostnames.
- **localgateway DNS.** The mDNS daemon receives published hostnames and addresses
  over push without mounting Secrets or holding Secret RBAC.
- **What is shared.** All data planes share the push client and server transport
  library (`pkg/dataplane/push`), the `DataplaneConfig` schema, token validation,
  and ACK and NACK lifecycle semantics.

## 7. Order of Work

The migration proceeds in small, backward-compatible steps where the controller
serves and data planes connect and receive:

1. **Protocol library.** Add the push transport package (`pkg/dataplane/push`)
   defining the gRPC service, token authentication, and ACK and NACK types.
2. **Controller push server.** Add the gRPC push server to the controller to
   accept data-plane connections, validate tokens, and stream configurations
   alongside Secret publishing.
3. **Data-plane push client.** Add the push client to `pkg/gari` so data planes
   dial the controller Service, receive configuration streams, and send ACKs,
   while keeping Secret watching active as a fallback.
4. **Switch status derivation.** Derive `Programmed` from direct push ACKs.
5. **Remove Secret path.** Remove `PublishDataplaneConfig` Secret generation,
   delete `dataplaneSecretReconciler`, and drop data-plane Secret RBAC.

## Open Questions

- **Unifying address providers.** Can we unify the different address providers
  (`singlepod`, `localgateway`, and `snigateway`) around the shared push
  transport and lifecycle mechanism?
