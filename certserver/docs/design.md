# Design: certserver — Centralized TLS Certificate Management with In-Path ACME HTTP-01 Validation

## Summary

This document describes the design of **certserver**, a standalone service that runs outside Kubernetes clusters. certserver obtains, caches, and releases TLS certificates for Gateway API Reference Implementation (GARI) data planes.

certserver operates on a core principle:

> certserver never grants more than ACME HTTP-01 would grant to the same network position.

certserver acts as an Automated Certificate Management Environment (ACME) client toward public certificate authorities such as Google Public CA and Let's Encrypt. certserver uses the HTTP-01 challenge type. It holds no DNS credentials and does not edit DNS records.

GARI data planes participate directly in challenge verification by serving HTTP-01 challenges from memory ("serve, don't forward"). When certserver needs HTTP-01 validation for a requester, its `GetCertificate` reply says the certificate is pending and lists the challenges to serve: hostname, token, and key authorization. None of these is secret, because certificate authorities fetch key authorizations over plain HTTP. The GARI controller inserts these challenges into the requesting Gateway's data-plane config. The data plane answers exactly those `GET /.well-known/acme-challenge/<token>` requests for that hostname from memory. Every other path takes normal HTTPRoute routing immediately without timing dependencies or fall-through timeouts. certserver fetches each challenge URL itself (a self-check) and asks the certificate authority to validate only after the self-check succeeds.

Challenge binding follows directly from who serves the token. Only Gateways that certserver returned the challenge to can serve it, and the certificate authority fetches from wherever DNS points. A Gateway that certserver did not give the challenge to cannot complete it. certserver keeps deactivating pre-validated authorizations so that each issuance requires a fresh validation. This removes the data plane's challenge forwarder, the data plane's service-account token for certserver, certserver's challenge endpoint, and forwarder-identity checks.

## Motivation

In standard Kubernetes deployments, Gateway listeners obtain TLS certificates from Kubernetes Secrets. This model introduces operational and security difficulties:

1. Private keys reside in etcd as plain Kubernetes Secrets. Anyone with read access to Secrets in the Gateway namespace can read the private keys.
2. Every cluster that serves a hostname must run an in-cluster ACME client such as cert-manager.
3. Every cluster requires credentials to update DNS records when using ACME DNS-01 challenges. Distributing DNS credentials across application clusters increases the attack surface.
4. When multiple clusters or Gateways serve the same hostnames, each cluster requests independent certificates from public certificate authorities. This duplication consumes public certificate authority rate limits.

This design separates key custody from TLS termination. GARI selects certificates through standard Go TLS hooks (`tls.Config.GetCertificate`). GARI terminates TLS in the data plane, while certserver manages certificate issuance and key storage outside the cluster.

## Goals

1. **Keep private keys and DNS credentials out of Kubernetes clusters (end-state goal).** GARI clusters run no ACME clients and store no DNS update credentials. Phase 1 provides an exception for key delivery: the controller receives keys from certserver and writes them to GARI's per-Gateway config Secret, which stores them in etcd. In the end state, certserver keeps keys out of etcd by releasing them directly to data-plane memory or by retaining them on certserver for keyless signing.
2. **Centralize issuance and renewal.** certserver caches certificates by normalized hostname set. Multiple Gateways and clusters that serve the same hostnames share one certificate, which avoids duplicate orders and conserves certificate authority rate limits.
3. **Derive authorization from the real network path.** certserver validates domain control by routing HTTP-01 challenges through public DNS and the data plane. It requires no secondary policy language to grant certificates for public hostnames.
4. **Prevent cross-Gateway certificate hijacking.** certserver binds each challenge by returning it to the requesting Gateway (and its shared-front-end candidates). A Gateway cannot obtain certificates for hostnames that route to a different Gateway.
5. **Support gradual security hardening.** The architecture supports releasing certificates and keys to data planes in phase 1, keyless remote signing in phase 2, and private certificate authority issuance in phase 3.

## Non-Goals

1. **Replacing GARI TLS termination.** The GARI data plane terminates client TLS connections. certserver never proxies client application traffic.
2. **General secrets management.** certserver manages TLS certificates for GARI listeners. It does not manage arbitrary application secrets, database credentials, or tokens.
3. **ACME DNS-01 support in phase 1.** certserver does not use DNS-01 challenges and does not interact with cloud DNS providers.
4. **Wildcard certificates in phase 1.** Public certificate authorities require DNS-01 challenges for wildcard certificates such as `*.example.com`. certserver issues certificates for concrete hostname sets only.
5. **Replacing client-side certificate management for backend workloads.** certserver manages ingress certificates for Gateways, not internal pod-to-pod certificates.

## Components

The architecture consists of four primary components: certserver, the GARI controller, the GARI data plane, and the upstream certificate authority.

```
                           ACME HTTP-01
 ┌───────────────────────┐              ┌───────────────────────────┐
 │ Upstream Certificate  │◄────────────►│        certserver         │
 │ Authority (CA)        │              │  - ACME HTTP-01 Client    │
 └──────────┬────────────┘              │  - Shared Challenge Store │
            │                           │  - Certificate Cache      │
            │ HTTP-01 Challenge         │  - Cluster Registry       │
            │ GET /.well-known/...      │  - Self-Check Verifier    │
            ▼                           └───────┬─────────────▲─────┘
 ┌───────────────────────┐                      │             │
 │      Public DNS       │                      │             │
 └──────────┬────────────┘                      │             │
            │ Resolves to Gateway IP            │             │
            ▼                                   │             │
 ┌──────────────────────────────────────────────┼───────┐     │
 │ Kubernetes Cluster                           │       │     │
 │                                              │       │     │
 │  ┌────────────────────────────────────────┐  │       │     │
 │  │ GARI Controller                        │  │       │     │
 │  │  - Reconciles Gateways and listeners   ├──┼───────┼─────┘
 │  │  - Calls GetCertificate via gRPC       │  │       │ gRPC / TLS
 │  │  - Configures data plane challenges    │  │       │ (GetCertificate:
 │  └──────────────────┬─────────────────────┘  │       │  returns pending
 │                     │ DataplaneConfig        │       │  challenges)
 │                     ▼                        │       │
 │  ┌────────────────────────────────────────┐  │       │
 │  │ GARI Data Plane                        │  │       │
 │  │  - Listens on port 80 and port 443     │  │       │
 │  │  - Serves HTTP-01 challenges in memory │◄─┘       │ HTTP (Self-check:
 │  │  - Terminates TLS for client traffic   │          │  GET /.well-known/...)
 │  └────────────────────────────────────────┘          │
 └──────────────────────────────────────────────────────┘
```

### certserver

certserver runs on a dedicated, hardened machine outside the Kubernetes clusters, such as a Compute Engine Shielded VM. It contains these subsystems:

- **ACME Client:** Interacts with the upstream certificate authority using the ACME protocol. It supports External Account Binding (EAB), which Google Public CA requires. It creates orders, requests validation, downloads certificate chains, and runs automated renewals.
- **Shared Challenge Store:** Tracks active HTTP-01 challenge tokens, expected token responses (key authorizations), requester Gateway bindings, and challenge expiration.
- **Self-Check Verifier:** Sends outgoing HTTP GET requests to challenge URLs (`http://<hostname>/.well-known/acme-challenge/<token>`) over port 80 to verify that the key authorization is served before certserver asks the certificate authority to validate.
- **Certificate Cache:** Stores issued certificate chains and private keys on local encrypted disk storage, with directory permissions at `0700` and file permissions at `0600`. It keys certificates by normalized hostname set.
- **Client API:** Exposes a gRPC service over TLS. GARI controllers call the `GetCertificate` RPC to request certificates. When an order requires validation, `GetCertificate` returns a pending status along with the active challenges (hostname, token, and key authorization) to be served by the requesting Gateway.
- **Cluster Registry:** Stores configuration for each trusted Kubernetes cluster. It holds the cluster's OIDC issuer URL, JWKS discovery settings, an optional hostname allow and deny list, and shared-front-end group memberships.

### GARI Controller

The GARI controller runs inside each Kubernetes cluster. It reconciles `Gateway` resources and their listeners:

- The controller identifies `Terminate` listeners that configure certserver through `tls.options` with `gateway.gke-labs.io/certificate-source: certserver`. The Gateway API specification permits `tls.options` in place of `certificateRefs` on `Terminate` listeners.
- The controller obtains a projected Kubernetes service-account token with the audience `certserver`.
- The controller calls `GetCertificate` on certserver over gRPC. The request contains the normalized hostnames, the Gateway namespace and name, and the Gateway's attested addresses (from `status.addresses`).
- When certserver returns pending challenges in `GetCertificate`, the controller inserts them into the requesting Gateway's data-plane config (`DataplaneConfig`).
- When certserver returns a certificate and private key in phase 1, the controller writes them into GARI's per-Gateway data-plane config Secret and clears the pending challenges. The data plane reads the certificate and key from this Secret.

### GARI Data Plane

The GARI data plane runs in pods inside the Kubernetes cluster:

- The data plane listens for incoming HTTP traffic on port 80 and HTTPS traffic on port 443.
- When configured with pending challenges from `DataplaneConfig`, the data plane answers incoming `GET /.well-known/acme-challenge/<token>` requests matching the configured hostname and token directly from memory with `text/plain` and the key authorization body.
- Any incoming request that does not match an active challenge (different token or different hostname) takes normal HTTPRoute routing immediately. Nothing waits or times out.
- The data plane terminates client TLS connections on port 443 using certificates that certserver provides.
- The data plane does not authenticate to certserver, holds no certserver service-account token, and has no direct communication with certserver.

### Upstream Certificate Authority

The upstream certificate authority (such as Google Public CA or Let's Encrypt) issues public TLS certificates:

- The certificate authority receives ACME orders from certserver.
- The certificate authority performs HTTP-01 domain validation by resolving domain names through public DNS and sending HTTP GET requests to `http://<hostname>/.well-known/acme-challenge/<token>` on port 80.
- The certificate authority performs validation checks from multiple global vantage points to detect DNS spoofing and routing anomalies.

## Trust Boundaries

This architecture defines clear boundaries between components:

1. **Public Internet to Data Plane:** Incoming traffic on port 80 and port 443 comes from untrusted clients, certserver self-checks, and public certificate authorities. The data plane exposes only standard HTTP and HTTPS ports to the internet.
2. **Cluster to certserver Network:** Communication between cluster components and certserver is limited to controller-to-certserver over gRPC/TLS using projected service-account bearer tokens. certserver exposes only its gRPC API; it exposes no challenge endpoint, and data planes do not connect to certserver.
3. **Controller versus Data Plane Roles:** The GARI controller is the only component that authenticates to certserver to request certificates. The data plane receives its configuration (certificates, keys, and pending challenge tokens to serve) from the controller via Kubernetes configuration. The data plane holds no certserver credentials, has no access to certserver APIs, and cannot request certificates or forward challenges.
4. **Inter-Cluster Boundary:** Clusters share a certserver instance but do not trust each other. A workload in cluster A cannot view, modify, or obtain certificates intended for cluster B without explicit configuration in a shared-front-end group.
5. **Host Isolation:** certserver runs on an isolated operating system outside Kubernetes. Kubernetes cluster administrators have no access to certserver host storage, ACME account credentials, or cached certificates of other clusters.

## Authentication and Authorization Model

certserver authenticates and authorizes every controller request before it initiates orders, issues challenges, or releases certificates. The data plane does not authenticate to certserver and requires no service-account token.

### Authentication via Projected Service-Account Tokens

certserver authenticates all gRPC API requests from GARI controllers using Kubernetes projected service-account tokens:

- Callers present a JSON Web Token (JWT) with the audience set to `certserver`.
- certserver verifies tokens offline against the OIDC discovery document and JSON Web Key Set (JWKS) of the originating cluster.
- certserver maintains a local cache of public keys from each cluster's JWKS endpoint. It periodically refreshes keys and avoids network calls during request processing.
- certserver verifies the token signature, issuer (`iss`), audience (`aud`), expiration (`exp`), and not-before (`nbf`) claims.
- Offline verification ensures that certserver requires no Kubernetes API credentials and makes no calls into the Kubernetes API server.
- The validated token yields a caller identity containing three fields: `(clusterID, namespace, serviceAccount)`.

### Authorization Policy

certserver authorizes requests using three distinct controls:

1. **Per-Cluster Server Policy:** certserver maintains a local configuration (via static configuration file and/or dynamic registration directory) that defines policies for each known cluster:
   - `allowedHostnames`: An optional list of hostname patterns that the cluster may request.
   - `deniedHostnames`: An optional list of hostname patterns that the cluster cannot request.
   - `sharedFrontEndGroup`: An optional group name for clusters that share public IP addresses or load balancers.
2. **Controller Attestation:** The GARI controller calls `GetCertificate`. certserver permits only the designated controller service account for that cluster to invoke this RPC. The controller attests:
   - The Gateway resource name (`namespace/name`).
   - The requested hostnames.
   - The Gateway's external addresses (`status.addresses`).
3. **In-Path Challenge Validation:** certserver validates domain control by returning challenges to the requesting Gateway (and its shared-front-end candidates), verifying via local self-check that the data plane serves the token over public DNS, and requesting validation from the upstream certificate authority.

### Cluster Registration and Live Directory Reload

To avoid requiring clusters to expose their OIDC discovery documents or JWKS publicly to the internet, and to enable adding or rotating clusters without restarting `certserver`, certserver supports dynamic cluster registration via a dedicated directory (`--cluster-dir`):

- **Directory Layout**: Each cluster occupies a subdirectory `<dir>/<cluster-id>/` containing `cluster.json` (cluster ID, issuer URL, hostname policies, controller identity, groups) and `jwks.json` (trusted JSON Web Key Set). The directory is owned by the certserver user with permissions `0700` and files `0600`.
- **Subcommand over SSH**: Operators upload cluster configuration and JWKS via the `certserver register-cluster` subcommand over SSH, piping raw JWKS from `kubectl get --raw /openid/v1/jwks`.
- **Atomic Writes**: `register-cluster` writes files atomically (temporary file, `fsync`, and atomic rename) so partially written files are never read or loaded.
- **Reload Without Restart**: certserver watches or periodically scans the directory. It validates that `cluster.json` parses, the issuer uses HTTPS, and `jwks.json` has at least one usable public key before swapping it into memory. If validation fails, the previous registration remains active.
- **Dynamic Unregistration**: Removing a cluster's directory unregisters the cluster on the next scan.
- **Safe Key Rotation**: During Kubernetes ServiceAccount signing key rotation, both old and new keys are published simultaneously. Uploading the combined JWKS updates the cluster live with zero downtime.
- **Configuration Merge**: Static config (`--cluster-config-file`) and directory entries merge, and duplicate cluster IDs are rejected. All registration lifecycle changes are recorded in certserver's structured audit log.

### Local Pre-Validation, DNS Checks, and Self-Check

Before certserver initiates an order or notifies the public certificate authority, certserver performs local validation checks:

1. **DNS Resolution Check:** certserver resolves public DNS (A and AAAA records) for each requested hostname from its own vantage point using authoritative or public recursive resolvers. certserver compares the resolved IP addresses against the Gateway addresses that the controller attested in `GetCertificate`. If DNS does not resolve (NXDOMAIN) or points to an unrelated address, certserver rejects or requeues the request immediately with a retryable error. This check prevents certserver from creating premature ACME orders while users wait for DNS records to propagate.
2. **Challenge Self-Check:** Before asking the certificate authority to validate a challenge, certserver fetches each challenge URL itself: `GET http://<hostname>/.well-known/acme-challenge/<token>`. It asks the certificate authority to validate only after the self-check succeeds by returning an HTTP 200 response with the expected key authorization body (after trimming whitespace).
   - **Invariants and Security Limits:** certserver executes self-checks only for hostnames that passed cluster registry policy and DNS pre-checks. It sends requests over plain HTTP on port 80 and does not follow HTTP redirects. It enforces a bounded timeout (a few seconds) and limits response body reads to at most 1 KiB.
   - **Trade-Off and Vantage Point:** The self-check is an operational gate that saves certificate authority rate limits and avoids most wasted validation attempts, not the security boundary. Challenge binding comes from which Gateway serves the token where public DNS points, and the certificate authority's own fetch is what proves domain control. The self-check adds an outgoing HTTP fetch per challenge from certserver and depends on certserver reaching the hostname the way the certificate authority does. If the certificate authority resolves DNS differently from certserver's network position (for example, with split-horizon DNS), validation attempts may still be wasted or fail.

### Challenge Binding and Attack Prevention

Routing HTTP-01 challenges through a shared certserver creates a potential cross-cluster vulnerability if challenge requests lack strong binding.

#### The Cross-Gateway Hijacking Attack

Consider two independent clusters that use the same certserver:
- Cluster B runs a Gateway that serves `app.example.com`. Public DNS points `app.example.com` to the public IP address of Gateway B.
- A tenant in cluster A creates a Gateway and configures a listener for `app.example.com`.
- The controller in cluster A calls certserver to request a certificate for `app.example.com`.
- Without challenge binding, certserver creates an ACME order with the upstream certificate authority.
- The certificate authority attempts to validate `http://app.example.com/.well-known/acme-challenge/<token>`.
- Public DNS directs the request to Gateway B. If Gateway B answered or forwarded challenges indiscriminately, cluster A could obtain a certificate for `app.example.com`.
- Cluster A would now hold a valid public certificate for a domain that it does not serve, allowing it to impersonate `app.example.com` if it diverts traffic.

#### How "Serve, Don't Forward" Stops the Attack

Under the "serve, don't forward" model, binding follows directly from who serves the token:

1. When the controller for Gateway A requests a certificate, certserver initiates an order and returns the pending challenges (hostname, token, key authorization) to Gateway A (and its configured shared-front-end candidates).
2. Gateway A puts the challenge into its data-plane configuration. Gateway A's data plane now serves that token from memory.
3. Gateway B was never given the challenge. Gateway B's data plane has no entry in memory for that token.
4. When certserver executes its self-check (and subsequently when the certificate authority validates), the HTTP GET request for `http://app.example.com/.well-known/acme-challenge/<token>` resolves via public DNS to Gateway B's IP address.
5. Gateway B receives the request. Because Gateway B was not given the challenge, Gateway B's data plane has no matching token in memory and routes normally (falling through to user routes or returning 404). Gateway B cannot answer with the key authorization.
6. The self-check fails, and certserver does not request CA validation. Even if the certificate authority queried Gateway B, validation would fail with HTTP 404.
7. Gateway A does not receive the certificate. A Gateway that wasn't given a challenge cannot serve it, and therefore cannot complete it.
8. **Deactivating Pre-Validated Authorizations:** Certificate authorities may retain authorization state across orders for an ACME account. To prevent an unauthorized Gateway from capitalizing on an authorization previously validated by another Gateway, certserver deactivates pre-validated authorizations so that each issuance requires fresh HTTP-01 validation.

This design removes the data plane's challenge forwarder, the data plane's service-account token for certserver, certserver's HTTP challenge endpoint, and forwarder-identity checks.

### Shared-Front-End Groups

In some architectures, multiple Gateways or clusters share a single external Anycast IP address or cloud load balancer front end. For example, gcpgateway deployments in different regions can attach zonal NEGs to a single shared backend service.

When multiple Gateways share a front end, incoming HTTP-01 validation traffic may land on any healthy replica across the participating clusters. To accommodate this configuration, administrators define a `sharedFrontEndGroup` in the certserver configuration. When an order requires HTTP-01 validation, certserver returns the pending challenges to both the immediate requesting Gateway and all candidate Gateways within the same configured `sharedFrontEndGroup`. When their controllers poll `GetCertificate`, they receive the pending challenges and configure their data planes to serve them from memory. Any replica in the group can then answer certserver's self-check and the certificate authority's validation request.

### Cache Reuse and Authorization Checks

certserver caches issued certificates by normalized hostname set to avoid redundant ACME orders. However, certserver does not allow a cache hit to bypass authorization checks:

- If Gateway X requests a certificate that certserver already holds in cache from a prior issuance for Gateway Y, certserver does not release the certificate immediately.
- certserver releases the cached certificate only after Gateway X proves that it currently controls the hostnames.
- certserver completes this proof locally without forcing a new request to the public certificate authority:
  1. certserver looks up public DNS for each hostname in the set and verifies that the records resolve to Gateway X's attested addresses.
  2. certserver generates a local probe challenge (token and key authorization) and returns it as a pending challenge to Gateway X.
  3. Gateway X configures its data plane to serve the probe challenge from memory.
  4. certserver executes an HTTP self-check against `http://<hostname>/.well-known/acme-challenge/<probe-token>`. Because public DNS resolves to Gateway X, Gateway X serves the challenge and the self-check succeeds.
  5. Once Gateway X satisfies this local check, certserver releases the cached certificate.
- This local validation prevents unauthorized Gateways from reading certificates out of the cache while avoiding duplicate ACME orders and unnecessary certificate authority rate limit consumption.

## Issuance and Renewal Flow

### Initial Issuance Flow

The following sequence diagram illustrates the complete issuance process using the "serve, don't forward" model:

```
┌────────────┐     ┌────────────┐     ┌──────────────┐     ┌────────────┐     ┌────────────┐
│    GARI    │     │ certserver │     │   Upstream   │     │   Public   │     │    GARI    │
│ Controller │     │            │     │      CA      │     │    DNS     │     │ Data Plane │
└─────┬──────┘     └─────┬──────┘     └──────┬───────┘     └─────┬──────┘     └─────┬──────┘
      │                  │                   │                   │                  │
      │ 1. GetCertificate│                   │                   │                  │
      │   (hostnames,    │                   │                   │                  │
      │    gateway,      │                   │                   │                  │
      │    addresses)    │                   │                   │                  │
      ├─────────────────►│                   │                   │                  │
      │                  │ 2. Check policy   │                   │                  │
      │                  │    Check DNS      │                   │                  │
      │                  │    Deactivate old │                   │                  │
      │                  │    Create order   │                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │◄──────────────────┤                   │                  │
      │                  │    (return tokens)│                   │                  │
      │                  │                   │                   │                  │
      │ 3. Pending       │                   │                   │                  │
      │    challenges    │                   │                   │                  │
      │◄─────────────────┤                   │                   │                  │
      │                  │                   │                   │                  │
      │ 4. Configure DP  │                   │                   │                  │
      │    (serve tokens)│                   │                   │                  │
      ├──────────────────┼───────────────────┼───────────────────┼─────────────────►│
      │                  │                   │                   │                  │
      │                  │ 5. Self-check GET /.well-known/...    │                  │
      │                  ├──────────────────────────────────────►│                  │
      │                  │                   │                   ├─────────────────►│
      │                  │                   │    (resolves via  │                  │
      │                  │                   │     Public DNS)   │                  │
      │                  │◄─────────────────────────────────────────────────────────┤
      │                  │    (200 OK, key authorization)        │                  │
      │                  │                   │                   │                  │
      │                  │ 6. Trigger check  │                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │                   │ 7. Resolve host   │                  │
      │                  │                   ├──────────────────►│                  │
      │                  │                   │◄──────────────────┤                  │
      │                  │                   │    (Gateway IP)   │                  │
      │                  │                   │                   │                  │
      │                  │                   │ 8. GET /.well-known/...              │
      │                  │                   ├─────────────────────────────────────►│
      │                  │                   │                   │                  │
      │                  │                   │ 9. 200 OK (key authorization)        │
      │                  │                   │◄─────────────────────────────────────┤
      │                  │                   │                   │                  │
      │                  │ 10. Finalize order│                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │◄──────────────────┤                   │                  │
      │                  │    (Certificate)  │                   │                  │
      │                  │                   │                   │                  │
      │                  │ 11. Save to cache │                   │                  │
      │                  │                   │                   │                  │
      │ 12. Requeue retry│                   │                   │                  │
      │     GetCertificate                   │                   │                  │
      ├─────────────────►│                   │                   │                  │
      │ 13. Return cert  │                   │                   │                  │
      │     and key      │                   │                   │                  │
      │◄─────────────────┤                   │                   │                  │
      │                  │                   │                   │                  │
      │ 14. Configure DP │                   │                   │                  │
      │     (cert & key) │                   │                   │                  │
      ├──────────────────┼───────────────────┼───────────────────┼─────────────────►│
      │                  │                   │                   │                  │
```

The flow proceeds through these steps:

1. **Controller Request:** The GARI controller reconciles a Gateway. It identifies listeners configured with `gateway.gke-labs.io/certificate-source: certserver` under `tls.options`. It extracts the listener hostnames, sorts and deduplicates them, and sends a `GetCertificate` gRPC request to certserver. The request contains the hostnames, the Gateway namespace and name, and the Gateway's attested addresses (`status.addresses`).
2. **Policy Evaluation, Pre-Checks, and ACME Order Creation:** certserver verifies the controller's identity and checks the requested hostnames against cluster allow/deny lists. certserver deactivates any pre-validated ACME authorizations for the hostnames. It resolves public DNS for each hostname and verifies that it points to the Gateway's attested addresses. If DNS records do not match or return NXDOMAIN, certserver returns a retryable status to the controller and waits for DNS propagation. If no valid cached certificate exists, certserver creates an ACME order with the upstream certificate authority, obtaining HTTP-01 challenge tokens and key authorizations.
3. **Pending Challenges Response:** certserver returns a pending status response to the GARI controller. The response lists the challenges that the requesting Gateway should serve: hostname, token, and key authorization. None of these is secret.
4. **Data Plane Configuration:** The GARI controller writes the pending challenges into the requesting Gateway's data-plane config (`DataplaneConfig`). The data plane loads them into memory and begins answering matching `GET /.well-known/acme-challenge/<token>` requests for that hostname.
5. **certserver Self-Check:** Before contacting the certificate authority, certserver performs a self-check by sending an HTTP GET request to `http://<hostname>/.well-known/acme-challenge/<token>` over port 80 via public DNS. The data plane answers directly from memory with `text/plain` and the key authorization body. certserver compares the body against the expected key authorization.
6. **Validation Trigger:** Once the self-check succeeds, certserver notifies the certificate authority that challenges are ready for validation.
7. **DNS Resolution:** The certificate authority resolves the domain name through public DNS to the Gateway's public IP address.
8. **Validation Request:** The certificate authority sends an HTTP GET request to `http://<hostname>/.well-known/acme-challenge/<token>` on port 80.
9. **In-Path Data Plane Serving:** The data plane receives the request on port 80, matches the hostname and token in memory, and immediately responds with `text/plain` and the key authorization. Non-matching paths or tokens take normal HTTPRoute routing immediately without delay.
10. **Order Finalization:** The certificate authority marks the challenges valid. certserver generates a Certificate Signing Request (CSR), sends it to the certificate authority, and downloads the signed certificate chain.
11. **Cache Storage:** certserver writes the certificate chain and private key to its encrypted local disk cache.
12. **Controller Requeue:** The GARI controller retries the `GetCertificate` RPC.
13. **Certificate Release:** certserver detects the cached certificate, verifies that the requesting Gateway is authorized, and returns the certificate chain and private key to the controller.
14. **Data Plane Configuration:** In phase 1, the GARI controller writes the certificate and private key into GARI's per-Gateway data-plane config Secret and clears the pending challenges from `DataplaneConfig`. The data plane terminates TLS on port 443 with the new certificate and ceases serving the HTTP-01 challenge.

### Automated Renewal Flow

certserver manages certificate renewal independently in the background:

1. A background loop in certserver inspects cached certificates at regular intervals.
2. When a certificate reaches approximately two-thirds of its validity period, certserver initiates renewal.
3. certserver adds randomized jitter to the renewal schedule to avoid traffic spikes against the upstream certificate authority.
4. certserver starts a new ACME order for the certificate's hostname set.
5. When the renewal order creates pending HTTP-01 challenges, certserver records them for the original requester and its configured shared-front-end candidates. When their controllers poll `GetCertificate`, certserver returns the pending challenges.
6. The controllers update their Gateways' data planes to serve the pending challenges from memory.
7. certserver performs its HTTP self-check against each challenge URL.
8. Once the self-checks succeed, certserver asks the certificate authority to validate the challenges.
9. If public DNS still routes to the Gateways, the certificate authority successfully validates against the data plane's in-memory challenges. certserver downloads the renewed certificate and updates the local disk cache.
10. If the domain owner moved DNS away from the Gateways, the self-check fails (or the certificate authority's request lands elsewhere where the challenge is not served), certserver aborts the renewal, and the existing certificate expires naturally. This ensures that certserver stops renewing certificates for hostnames that the Gateways no longer serve.
11. When certserver updates the cache, the GARI controllers receive the new certificate on their next reconciliation loop and update data-plane configuration without connection disruption.

## Failure Modes and Recovery

certserver handles common operational and network failures predictably:

### 1. DNS Not Yet Pointing at the Gateway

A user creates a Gateway or Route before pointing public DNS records at the Gateway's external IP address.
- **Symptom:** When public DNS resolves the hostname, DNS returns NXDOMAIN or points to an unrelated server.
- **Handling:** certserver's DNS pre-check or local self-check fails before contacting the certificate authority. certserver withholds validation on the upstream challenge and returns a pending or retryable status to the GARI controller, which requeues reconciliation with exponential backoff. This avoids wasting certificate authority rate limits and failure quotas. Once the user configures DNS and records propagate across public resolvers, subsequent self-checks and challenge attempts succeed.

### 2. Port 80 Unreachable

The ACME HTTP-01 specification requires plain HTTP validation on port 80.
- **Symptom:** Upstream network firewalls, cloud security groups, or missing Gateway listeners block incoming TCP port 80 connections.
- **Handling:** certserver's self-check times out or fails with connection refused. certserver records the failure reason and does not trigger certificate authority validation, preventing CA-side authorization failures. The controller reports the failure in Gateway listener conditions (`Programmed=False`). Operators must expose port 80 to resolve the condition.

### 3. Self-Check Egress or Reachability Mismatch

certserver must reach the Gateway's public IP address on port 80 to perform its self-check.
- **Symptom:** Outbound firewall rules on the certserver host block egress to port 80, or split-horizon DNS prevents certserver from resolving the public address that the CA reaches.
- **Handling:** The self-check retries on a bounded schedule. If it fails to complete within the allotted time, certserver logs a clear diagnostic error and withholds validation requests to the certificate authority. Operators must ensure certserver can reach public endpoints on port 80 the same way public certificate authorities do.

### 4. CAA Refusals

A domain uses Certification Authority Authorization (CAA) DNS records to restrict which certificate authorities may issue certificates for that domain.
- **Symptom:** The domain's CAA records do not permit the upstream certificate authority that certserver uses (such as Google Trust Services or Let's Encrypt).
- **Handling:** The certificate authority checks CAA records before creating challenges and rejects the order immediately. certserver detects the CAA refusal, logs the failure, and returns a terminal error to the GARI controller. The controller reports the CAA error in the Gateway status conditions. The domain owner must update their CAA DNS records to permit the configured certificate authority.

### 5. Upstream Certificate Authority Outage or Rate Limiting

The upstream certificate authority becomes temporarily unavailable or rejects requests due to API rate limits.
- **Symptom:** ACME API calls fail with HTTP 5xx errors or rate limit errors (HTTP 429).
- **Handling:** For new orders, certserver retries with exponential backoff and returns a retryable status to the controller. For renewals, certserver continues serving the existing valid certificate from its cache while retrying renewal in the background. Because certserver shares certificates across Gateways and clusters, it minimizes duplicate orders and reduces overall rate limit consumption.

## Operating Modes

certserver supports three operational modes across three design phases:

### Phase 1: Release Mode

In phase 1, certserver operates in release mode. certserver acts as the ACME client, generates private keys, completes HTTP-01 challenges, and stores certificates and keys in its local cache.

certserver releases both certificate chains and private keys to the GARI controller over gRPC. The controller writes them into GARI's per-Gateway data-plane config Secret (`CertificateData.PrivateKey`). The data plane reads its configuration and private keys from this Secret.

Phase 1 accepts storing private keys in etcd through this Secret to reuse GARI's existing configuration distribution pipeline. This phase eliminates in-cluster ACME clients and removes all DNS credentials from Kubernetes clusters.

### Key Delivery Architecture

Key delivery follows a phased progression:

- **Phase 1 Decision:** The GARI controller receives private keys from certserver and delivers them to the data plane through the per-Gateway config Secret. This decision accepts private keys in etcd during phase 1. It avoids adding direct network dependencies or token exchange logic between data planes and certserver in the initial release.
- **End-State Target:** In the end state, certserver keeps private keys out of etcd. certserver achieves this through one of two mechanisms:
  1. **Direct Data-Plane Retrieval:** Data planes fetch certificates and private keys directly from certserver at startup using their own projected service-account tokens. The data plane holds keys in process memory only and never writes them to Secrets or disk.
  2. **Keyless Signing (Phase 2):** certserver retains private keys in secure host storage, and data planes delegate handshake signatures to certserver over RPC.

### Phase 2: Keyless Sign Mode

In phase 2, certserver operates in keyless mode. Private keys never leave certserver.
- certserver generates and retains the private keys in secure storage.
- certserver exposes an authenticated gRPC `Sign(certificateID, digest, algorithm)` endpoint.
- The GARI data plane implements the standard Go `crypto.Signer` interface. During a client TLS handshake, the data plane prepares the handshake digest, calls `Sign` on certserver over a persistent mTLS connection, and receives the signature.
- certserver releases public certificate chains to data planes, but private keys never enter cluster memory or etcd storage.

### Phase 3: Private Certificate Authority Mode

In phase 3, certserver functions as an internal private certificate authority for internal or cluster-local domains.
- certserver maintains root or intermediate private keys in a Hardware Security Module (HSM), virtual TPM, or cloud Key Management Service (KMS).
- certserver issues and signs certificates directly for authorized internal hostnames without communicating with external public certificate authorities.
- Data planes use the same `GetCertificate` and `Sign` interfaces for both public and private certificates.

## Deferred Capabilities

The initial release of certserver deliberately defers several capabilities:

- **Wildcard Certificates:** The ACME specification disallows HTTP-01 validation for wildcard hostnames such as `*.example.com`. Issuing wildcard certificates requires ACME DNS-01 validation and DNS API credentials. Wildcards remain out of scope for phase 1.
- **TLS-ALPN-01 Validation:** The ACME TLS-ALPN-01 challenge validates domain ownership over TLS on port 443 using a custom ALPN protocol (`acme-tls/1`). This protocol allows issuance when port 80 is unavailable. TLS-ALPN-01 requires dynamic TLS certificate presentation in the data plane and remains deferred to a future phase.
- **Keyless Signing Infrastructure:** The `Sign` RPC, data-plane `crypto.Signer` integration, connection pooling, and low-latency signing paths belong to phase 2.
- **Hardware Security Module Integration:** Storing root keys in vTPM or KMS and running private certificate authority issuance belong to phase 3.
- **Custom Gateway API CRD:** Direct listener references via a custom `RemoteCertificate` CRD in `certificateRefs` remain deferred. Listeners configure certserver per listener through `tls.options` with `gateway.gke-labs.io/certificate-source: certserver` instead.

## Open Questions

### Multi-Region Deployment and Cache Sharing

When GARI operates across multiple geographic regions, deploying a single central certserver instance creates cross-region latency and a single point of failure. Cross-region network round-trips become noticeable in phase 2 during keyless signing, where handshakes require low-latency signing operations.

The intended design direction uses leader election and replication with state persisted to cloud object storage:
- **State Persistence in Cloud Storage:** certserver persists its certificate cache, private keys, and challenge state to an encrypted Google Cloud Storage (GCS) bucket.
- **Leader Election:** certserver instances use a distributed lease or object locking to elect an active leader replica. The leader coordinates ACME orders, interacts with upstream certificate authorities, and runs automated renewal loops.
- **Regional Read and Sign Replicas:** Follower instances in other regions replicate cache state from storage. Regional instances serve low-latency local reads and execute local cryptographic signing operations during TLS handshakes in phase 2.
- The project will formalize multi-region replication and election mechanics when implementing phase 2 keyless signing.
