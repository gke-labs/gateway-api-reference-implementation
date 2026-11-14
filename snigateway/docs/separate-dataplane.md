# Design Note: Running the Data Plane as a Separate Process in SNIGateway

## Context

The reference implementation is removing all-in-one mode so that every deployment runs the per-Gateway data-plane code path. In that model, the controller reconciles API objects and publishes configuration through a Secret, and an independent data-plane process watches the Secret and serves traffic. Removing all-in-one mode eliminates a divergent in-process execution path, measures real per-Gateway startup latency, and verifies configuration distribution end-to-end.

SNIGateway currently embeds the reference implementation controller and proxy in a single process, feeding reverse-tunnel connections from `snigateway-frontend` directly into an in-process proxy listener. This note evaluates whether SNIGateway can stop running the proxy in-process and split into separate controller and data-plane processes.

## 1. Where the Tunnel Ends

In a split architecture, the reverse tunnel must end in the data-plane process. The data plane terminates TLS, parses PROXY protocol v2 headers, evaluates HTTP routing, and proxies requests to backend pods; the controller handles only control-plane reconciliation. Terminating the tunnel in the controller would require re-proxying raw traffic to data-plane pods across the cluster network, defeating the purpose of the split. The process that dials the frontend and accepts reverse-tunnel connections must therefore be the data plane itself.

The data-plane process needs:
- **Tunnel client:** The reverse-tunnel client logic (`snigateway/pkg/client` and `snigateway/pkg/tunnel` manager and listener) to dial the frontend and accept connections.
- **Frontend address:** The address of `snigateway-frontend` (`--frontend`) and the management TLS ServerName (`--internal-hostname`).
- **Credentials:** The CA certificate (`--ca-cert`) to verify the frontend, and either a client certificate/key pair (`--client-cert`/`--client-key`) or a projected ServiceAccount token (`--token-file`) for mTLS authentication.

## 2. Registration

Today, the controller registers hostnames with the frontend from its compiled state using GARI's `OnGatewaysUpdate` hook.

After a split, the **data-plane process** must register hostnames with the frontend:
- **Session ownership:** Registrations on `snigateway-frontend` are scoped to an active tunnel session ID (`sessionID`) created during the mTLS handshake. Because the data plane dials and maintains the tunnel session, only the data plane holds the active session ID. Having the controller register would require an out-of-band IPC channel or status field for data-plane pods to report dynamic session IDs back to the controller.
- **Learning hostnames:** In the per-Gateway data-plane architecture, the controller compiles state and publishes a `DataplaneConfig` to a per-Gateway Secret (`config.json`). The data plane reads this configuration through the normal distribution, extracts the SNI hostnames from the configured HTTPS and TLS listeners, and calls `PUT /v1/registration` on the frontend whenever its configuration updates.

## 3. Addresses and Readiness

- **Gateway Addresses:** The reported address is the public address of `snigateway-frontend` (configured statically via `--frontend` or `--gateway-address`). The controller writes this address into `Gateway.status.addresses` directly without querying the data plane.
- **Readiness (`Programmed` condition):** Today the in-process controller inspects in-memory tunnel state (`tunnelState.IsConnected()` and `tunnelState.HasRegisteredHostnames()`). In a split, the controller cannot observe tunnel state directly.
- **Readiness propagation:** The data-plane process exposes an HTTP readiness probe on its health port (e.g. `:8081/readyz`) that succeeds only after its tunnel session is connected and its hostnames are registered with the frontend. The controller watches data-plane Pod readiness (reusing GARI's singlepod readiness observation logic) and sets `Programmed=True` once the data-plane pod becomes ready.

## 4. Options and Size

Three options exist for adapting SNIGateway:

1. **Full multi-pod split (dynamic per-Gateway provisioner):**
   - The controller dynamically provisions separate data-plane Deployments per Gateway.
   - Requires a custom provisioner in the controller, cross-namespace credential copying or projection, a custom data-plane image packaging the tunnel client, and expanded RBAC.
   - *Size:* Adds ~400–600 lines of Go plus new manifests and RBAC; deletes ~310 lines of in-process wiring and address provider logic.
   - *Config distribution:* Exercised across namespaces.

2. **Single-process in-process proxy for one Gateway:**
   - The controller compiles a single Gateway and pushes `DataplaneConfig` directly to an in-memory `pkg/proxy.Server`, passing tunnel connections to `HTTPSListener`.
   - *Reference implementation burden:* Keeps `HTTPSListener`, `HTTPListener`, `ProxyHTTPSAddr`, `ProxyAddr`, `OnGatewaysUpdate`, `Server.StartProxyServers`, and controller proxy setup in `pkg/gari` and `pkg/proxy` solely for this demo.
   - *Config distribution:* **Unexercised.** Secret creation, writing, watching, and deserialization are completely bypassed, preserving a second unexercised code path.
   - *Size:* Changes ~50 lines in `snigateway`; deletes nothing from `pkg/gari`.

3. **Two processes in one pod (shared-pod split):**
   - The controller container and a data-plane container share a single pod in the static demo Deployment.
   - The controller publishes `DataplaneConfig` via the standard Secret distribution. Because the demo serves one Gateway, the Deployment is static: it needs no dynamic per-Gateway provisioner and no credentials in other namespaces (credentials and Secrets remain in the controller's namespace).
   - The data-plane container runs the tunnel client next to the reference implementation's data plane, reads its config through the normal Secret distribution, registers its own hostnames, and feeds tunnel connections to the data plane over loopback (or via an in-pod adapter).
   - *Reference implementation burden:* None. `pkg/gari` and `pkg/proxy` can delete all in-process proxy options and hooks.
   - *Config distribution:* **Exercised.**
   - *Shared identity trade-off:* Because both containers share a single pod under the `snigateway-controller` ServiceAccount, the data-plane container shares the pod's identity and has the controller's permissions (such as create, update, and patch on Secrets). That is the cost of running two containers in a single static pod.
   - *Size:* Adds ~80–120 lines in `snigateway` (Deployment manifest update and a lightweight loopback tunnel forwarder/registration helper); deletes ~200 lines from `snigateway` and unblocks removing hundreds of lines of in-process proxy code in `pkg/gari`.

## 5. Verdict and Recommendation

**Verdict: Feasible as a small change via two processes in one pod.**

A full multi-pod split with dynamic provisioning (Option 1) is feasible only as a larger change and not worth it for a demo. Retaining an in-process proxy (Option 2) keeps a dead code path in the reference implementation and leaves config distribution untested, defeating the purpose of removing all-in-one mode.

Running two processes in one pod (Option 3) is the smallest change that works: it eliminates the in-process proxy from the controller, exercises the real per-Gateway config distribution path, avoids dynamic provisioner complexity and cross-namespace credential copying, and allows `pkg/gari` to cleanly delete all all-in-one proxy options.

**Recommendation:** Split SNIGateway into two containers in a single pod: a controller container that writes the Gateway's configuration to a Secret, and a data-plane container that runs the tunnel client alongside the reference implementation's data plane.
