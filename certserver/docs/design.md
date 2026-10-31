# Design: certserver — Centralized TLS Certificate Management with In-Path ACME HTTP-01 Validation

## Summary

This document describes the design of **certserver**, a standalone service that runs outside Kubernetes clusters. certserver obtains, caches, and releases TLS certificates for Gateway API Reference Implementation (GARI) data planes.

certserver operates on a core principle:

> certserver never grants more than ACME HTTP-01 would grant to the same network position.

certserver acts as an Automated Certificate Management Environment (ACME) client toward public certificate authorities such as Google Public CA and Let's Encrypt. certserver uses the HTTP-01 challenge type exclusively. It holds no DNS credentials and does not edit DNS records.

GARI data planes participate directly in challenge verification. Challenge forwarding is opt-in per Gateway. For Gateways that opt in, each data plane forwards HTTP requests for `/.well-known/acme-challenge/<token>` to certserver over TLS. The data plane attaches its projected Kubernetes service-account token to each forwarded request. This design routes the certificate authority's validation traffic through the real network path: public DNS, the Gateway's public IP address, the GARI data plane, and certserver. When certserver returns an HTTP 404 response or does not answer in time, the data plane falls through to normal HTTPRoute routing. This fall-through allows users' own HTTP-01 solvers to keep working.

certserver binds every completed challenge to the identity of the forwarding data plane. certserver releases a certificate only when the validation request arrives through a data plane that belongs to the requesting Gateway or to an authorized shared-front-end group.

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
4. **Prevent cross-Gateway certificate hijacking.** certserver binds each challenge to the forwarding data-plane identity. A Gateway cannot obtain certificates for hostnames that route to a different Gateway.
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
            │ GET /.well-known/...      │  - Challenge Verifier     │
            ▼                           └─────────────▲─────────────┘
 ┌───────────────────────┐                            │
 │      Public DNS       │                            │
 └──────────┬────────────┘                            │
            │ Resolves to Gateway IP                  │
            ▼                                         │
 ┌──────────────────────────────────────────────┐     │
 │ Kubernetes Cluster                           │     │
 │                                              │     │
 │  ┌────────────────────────────────────────┐  │     │
 │  │ GARI Controller                        │  │     │
 │  │  - Reconciles Gateways and listeners   ├──┼─────┘
 │  │  - Calls GetCertificate via gRPC       │  │ gRPC / TLS
 │  │  - Authenticates with projected SA     │  │ (GetCertificate)
 │  └────────────────────────────────────────┘  │
 │                                              │
 │  ┌────────────────────────────────────────┐  │
 │  │ GARI Data Plane                        │  │
 │  │  - Listens on port 80 and port 443     │  │
 │  │  - Forwards HTTP-01 challenges over TLS├──┼─────┘
 │  │  - Authenticates with projected SA     │  │ HTTPS
 │  │  - Terminates TLS for client traffic   │  │ (Forwarded challenge)
 │  └────────────────────────────────────────┘  │
 └──────────────────────────────────────────────┘
```

### certserver

certserver runs on a dedicated, hardened machine outside the Kubernetes clusters, such as a Compute Engine Shielded VM. It contains these subsystems:

- **ACME Client:** Interacts with the upstream certificate authority using the ACME protocol. It supports External Account Binding (EAB), which Google Public CA requires. It creates orders, requests validation, downloads certificate chains, and runs automated renewals.
- **Shared Challenge Store:** Tracks active HTTP-01 challenge tokens, expected token responses (key authorizations), and the expiration time of each challenge.
- **Challenge Verification Endpoint:** Exposes an internal HTTP endpoint that accepts forwarded challenge requests from GARI data planes. It verifies data-plane identity, checks challenge binding, and returns the key authorization.
- **Certificate Cache:** Stores issued certificate chains and private keys on local encrypted disk storage, with directory permissions at `0700` and file permissions at `0600`. It keys certificates by normalized hostname set.
- **Client API:** Exposes a gRPC service over TLS. GARI controllers call the `GetCertificate` RPC to request certificates.
- **Cluster Registry:** Stores configuration for each trusted Kubernetes cluster. It holds the cluster's OIDC issuer URL, JWKS discovery settings, an optional hostname allow and deny list, and shared-front-end group memberships.

### GARI Controller

The GARI controller runs inside each Kubernetes cluster. It reconciles `Gateway` resources and their listeners:

- The controller identifies `Terminate` listeners that configure certserver through `tls.options` with `gateway.gke-labs.io/certificate-source: certserver`. The Gateway API specification permits `tls.options` in place of `certificateRefs` on `Terminate` listeners.
- The controller obtains a projected Kubernetes service-account token with the audience `certserver`.
- The controller calls `GetCertificate` on certserver over gRPC. The request contains the normalized hostnames, the Gateway namespace and name, the Gateway's attested addresses (from `status.addresses`), and the service account of the data plane that serves the Gateway.
- When certserver returns a certificate and private key in phase 1, the controller writes them into GARI's per-Gateway data-plane config Secret. The data plane reads the certificate and key from this Secret.

### GARI Data Plane

The GARI data plane runs in pods inside the Kubernetes cluster:

- The data plane listens for incoming HTTP traffic on port 80 and HTTPS traffic on port 443.
- Challenge forwarding is opt-in per Gateway. For Gateways that opt in, the data plane intercepts incoming plain-HTTP requests matching the path `/.well-known/acme-challenge/<token>` on port 80.
- The data plane forwards the request to certserver over TLS. The data plane attaches its projected service-account token in the HTTP `Authorization` header.
- When certserver returns an HTTP 200 response, the data plane relays the key authorization body to the certificate authority.
- When certserver returns an HTTP 404 response or does not answer in time, the data plane falls through to normal HTTPRoute routing. This fall-through allows users' own HTTP-01 solvers behind HTTPRoutes to keep working.
- The data plane terminates client TLS connections on port 443 using certificates that certserver provides.

### Upstream Certificate Authority

The upstream certificate authority (such as Google Public CA or Let's Encrypt) issues public TLS certificates:

- The certificate authority receives ACME orders from certserver.
- The certificate authority performs HTTP-01 domain validation by resolving domain names through public DNS and sending HTTP GET requests to `http://<hostname>/.well-known/acme-challenge/<token>` on port 80.
- The certificate authority performs validation checks from multiple global vantage points to detect DNS spoofing and routing anomalies.

## Trust Boundaries

This architecture defines clear boundaries between components:

1. **Public Internet to Data Plane:** Incoming traffic on port 80 and port 443 comes from untrusted clients and public certificate authorities. The data plane exposes only standard HTTP and HTTPS ports to the internet.
2. **Cluster to certserver Network:** Communication between cluster components and certserver uses TLS with mutual authentication or bearer tokens. certserver exposes its gRPC API and its challenge endpoint only on private networks or protected endpoints.
3. **Controller versus Data Plane Roles:** The GARI controller holds permission to request certificates for Gateways within its cluster. The data plane holds permission only to forward challenge tokens and receive its assigned certificate. A compromised data plane cannot request certificates for arbitrary hostnames.
4. **Inter-Cluster Boundary:** Clusters share a certserver instance but do not trust each other. A workload in cluster A cannot view, modify, or obtain certificates intended for cluster B without explicit configuration in a shared-front-end group.
5. **Host Isolation:** certserver runs on an isolated operating system outside Kubernetes. Kubernetes cluster administrators have no access to certserver host storage, ACME account credentials, or cached certificates of other clusters.

## Authentication and Authorization Model

certserver authenticates and authorizes every request before it initiates orders, completes challenges, or releases certificates.

### Authentication via Projected Service-Account Tokens

certserver authenticates all requests using Kubernetes projected service-account tokens:

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
   - The service account of the data plane that serves the Gateway.
   - The Gateway's external addresses (`status.addresses`).
3. **In-Path Challenge Validation:** certserver verifies that public DNS directs HTTP-01 challenge traffic through the attested data plane before it marks an order complete.

### Cluster Registration and Live Directory Reload

To avoid requiring clusters to expose their OIDC discovery documents or JWKS publicly to the internet, and to enable adding or rotating clusters without restarting `certserver`, certserver supports dynamic cluster registration via a dedicated directory (`--cluster-dir`):

- **Directory Layout**: Each cluster occupies a subdirectory `<dir>/<cluster-id>/` containing `cluster.json` (cluster ID, issuer URL, hostname policies, controller identity, groups) and `jwks.json` (trusted JSON Web Key Set). The directory is owned by the certserver user with permissions `0700` and files `0600`.
- **Subcommand over SSH**: Operators upload cluster configuration and JWKS via the `certserver register-cluster` subcommand over SSH, piping raw JWKS from `kubectl get --raw /openid/v1/jwks`.
- **Atomic Writes**: `register-cluster` writes files atomically (temporary file, `fsync`, and atomic rename) so partially written files are never read or loaded.
- **Reload Without Restart**: certserver watches or periodically scans the directory. It validates that `cluster.json` parses, the issuer uses HTTPS, and `jwks.json` has at least one usable public key before swapping it into memory. If validation fails, the previous registration remains active.
- **Dynamic Unregistration**: Removing a cluster's directory unregisters the cluster on the next scan.
- **Safe Key Rotation**: During Kubernetes ServiceAccount signing key rotation, both old and new keys are published simultaneously. Uploading the combined JWKS updates the cluster live with zero downtime.
- **Configuration Merge**: Static config (`--cluster-config-file`) and directory entries merge, and duplicate cluster IDs are rejected. All registration lifecycle changes are recorded in certserver's structured audit log.

### Local Pre-Validation and DNS Checks

Before certserver initiates an order with the public certificate authority, certserver performs local validation checks:

1. **DNS Resolution Check:** certserver resolves public DNS (A and AAAA records) for each requested hostname from its own vantage point using authoritative or public recursive resolvers. certserver compares the resolved IP addresses against the Gateway addresses that the controller attested in `GetCertificate`. If DNS does not resolve (NXDOMAIN) or points to an unrelated address, certserver rejects or requeues the request immediately with a retryable error. This check prevents certserver from creating premature ACME orders while users wait for DNS records to propagate.
2. **Local Self-Probing:** certserver can send an HTTP GET request to `http://<hostname>/.well-known/acme-challenge/<probe-token>` using a locally generated probe token before contacting the public certificate authority. The probe follows public DNS to the Gateway's public IP address, enters the data plane, and forwards back to certserver with the data plane's service-account token. This self-probe confirms that port 80 routing and challenge binding function properly before certserver consumes certificate authority rate limits.

### Challenge Binding and Attack Prevention

Routing HTTP-01 challenges through a shared certserver creates a potential cross-cluster vulnerability if challenge requests lack strong binding.

#### The Cross-Gateway Hijacking Attack

Consider two independent clusters that use the same certserver:
- Cluster B runs a Gateway that serves `app.example.com`. Public DNS points `app.example.com` to the public IP address of Gateway B.
- A tenant in cluster A creates a Gateway and configures a listener for `app.example.com`.
- The controller in cluster A calls certserver to request a certificate for `app.example.com`.
- Without challenge binding, certserver creates an ACME order with the upstream certificate authority.
- The certificate authority validates `http://app.example.com/.well-known/acme-challenge/<token>`.
- Public DNS directs the request to Gateway B. The data plane of Gateway B receives the challenge and forwards the token to certserver.
- If certserver verifies only that the token matches an open order, the challenge succeeds.
- certserver finalizes the order and releases the certificate for `app.example.com` to cluster A.
- Cluster A now holds a valid public certificate for a domain that it does not serve. Cluster A can impersonate `app.example.com` if it diverts traffic or obtains access to the network path.

#### How Challenge Binding Stops the Attack

certserver prevents this attack through challenge binding:

1. When the controller requests a certificate for Gateway G, certserver records an active binding requirement: `(clusterID, gatewayName, dataPlaneServiceAccount, hostnames)`.
2. When a data plane receives an HTTP-01 challenge, it forwards the request to certserver together with its own projected service-account token.
3. certserver authenticates the data plane's token and identifies the forwarding data-plane service account and cluster.
4. certserver accepts the challenge only if the forwarding data plane matches the service account recorded for Gateway G, or belongs to a Gateway in the same configured `sharedFrontEndGroup`.
5. If the forwarding data plane belongs to an unrelated Gateway (such as Gateway B in the scenario above), certserver rejects the forwarded challenge with an HTTP 404 response.
6. The certificate authority receives a 404 error and aborts the challenge. certserver rejects the issuance request from cluster A.

Through challenge binding, certserver ensures that a Gateway receives a certificate only if public DNS directs traffic to that Gateway's own data plane.

### Shared-Front-End Groups

In some architectures, multiple Gateways or clusters share a single external Anycast IP address or cloud load balancer front end. For example, gcpgateway deployments in different regions can attach zonal NEGs to a single shared backend service.

When multiple Gateways share a front end, the certificate authority's validation request may land on any healthy replica across the participating clusters. To accommodate this configuration, administrators define a `sharedFrontEndGroup` in the certserver configuration. When certserver evaluates challenge binding, it permits any data plane belonging to a Gateway within the same shared-front-end group to complete the challenge.

### Cache Reuse and Authorization Checks

certserver caches issued certificates by normalized hostname set to avoid redundant ACME orders. However, certserver must never allow a cache hit to bypass authorization checks:

- If Gateway X requests a certificate that certserver already holds in cache from a prior issuance for Gateway Y, certserver does not release the certificate immediately.
- certserver releases the cached certificate only after Gateway X proves that it currently controls the hostnames.
- certserver completes this proof locally without forcing a new request to the public certificate authority:
  1. certserver looks up public DNS for each hostname in the set and verifies that the records resolve to Gateway X's attested addresses.
  2. certserver initiates a local self-probe by requesting `http://<hostname>/.well-known/acme-challenge/<probe-token>`.
  3. When Gateway X's data plane receives the probe and forwards it with its projected service-account token, certserver verifies challenge binding for Gateway X.
  4. Once Gateway X satisfies this local challenge binding, certserver safely releases the cached certificate.
- This local validation prevents unauthorized Gateways from reading certificates out of the cache while avoiding duplicate ACME orders and unnecessary certificate authority rate limit consumption.

## Issuance and Renewal Flow

### Initial Issuance Flow

The following sequence diagram illustrates the complete issuance process using HTTP-01 challenge forwarding and challenge binding:

```
┌────────────┐     ┌────────────┐     ┌──────────────┐     ┌────────────┐     ┌────────────┐
│    GARI    │     │ certserver │     │   Upstream   │     │   Public   │     │    GARI    │
│ Controller │     │            │     │      CA      │     │    DNS     │     │ Data Plane │
└─────┬──────┘     └─────┬──────┘     └──────┬───────┘     └─────┬──────┘     └─────┬──────┘
      │                  │                   │                   │                  │
      │ 1. GetCertificate│                   │                   │                  │
      │   (hostnames,    │                   │                   │                  │
      │    gateway, SA,  │                   │                   │                  │
      │    addresses)    │                   │                   │                  │
      ├─────────────────►│                   │                   │                  │
      │                  │ 2. Check policy   │                   │                  │
      │                  │    Record binding │                   │                  │
      │                  │    Check DNS      │                   │                  │
      │                  │                   │                   │                  │
      │                  │ 3. Create order   │                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │◄──────────────────┤                   │                  │
      │                  │    (return tokens)│                   │                  │
      │                  │                   │                   │                  │
      │ 4. StatusRetry   │                   │                   │                  │
      │◄─────────────────┤                   │                   │                  │
      │                  │ 5. Trigger check  │                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │                   │ 6. Resolve host   │                  │
      │                  │                   ├──────────────────►│                  │
      │                  │                   │◄──────────────────┤                  │
      │                  │                   │    (Gateway IP)   │                  │
      │                  │                   │                   │                  │
      │                  │                   │ 7. GET /.well-known/...              │
      │                  │                   ├─────────────────────────────────────►│
      │                  │                   │                   │                  │
      │                  │ 8. Forward challenge + SA token       │                  │
      │                  │◄─────────────────────────────────────────────────────────┤
      │                  │                                       │                  │
      │                  │ 9. Verify SA token                    │                  │
      │                  │    Verify challenge binding           │                  │
      │                  │    Check token and host               │                  │
      │                  │                                       │                  │
      │                  │ 10. Key authorization                 │                  │
      │                  ├─────────────────────────────────────────────────────────►│
      │                  │                                       │                  │
      │                  │ 11. Relay key authorization                              │
      │                  │◄─────────────────────────────────────────────────────────┤
      │                  │                   │                   │                  │
      │                  │ 12. Finalize order│                   │                  │
      │                  ├──────────────────►│                   │                  │
      │                  │◄──────────────────┤                   │                  │
      │                  │    (Certificate)  │                   │                  │
      │                  │                   │                   │                  │
      │                  │ 13. Save to cache │                   │                  │
      │                  │                   │                   │                  │
      │ 14. Requeue retry│                   │                   │                  │
      │     GetCertificate                   │                   │                  │
      ├─────────────────►│                   │                   │                  │
      │ 15. Return cert  │                   │                   │                  │
      │     and key      │                   │                   │                  │
      │◄─────────────────┤                   │                   │                  │
      │                  │                   │                   │                  │
      │ 16. Configure DP │                   │                   │                  │
      ├────────────────────────────────────────────────────────────────────────────►│
      │                  │                   │                   │                  │
```

The flow proceeds through these steps:

1. **Controller Request:** The GARI controller reconciles a Gateway. It identifies listeners configured with `gateway.gke-labs.io/certificate-source: certserver` under `tls.options`. It extracts the listener hostnames, sorts and deduplicates them, and sends a `GetCertificate` gRPC request to certserver. The request contains the hostnames, the Gateway namespace and name, the Gateway's attested addresses (`status.addresses`), and the data plane's service account.
2. **Policy Evaluation, Binding Registration, and Local DNS Check:** certserver verifies the controller's identity and checks the requested hostnames against the cluster's allow and deny lists. certserver stores an active binding record that maps the pending order to the attested Gateway and data-plane service account. certserver also resolves public DNS for each hostname and verifies that it points to the Gateway's attested addresses. If DNS records do not match or return NXDOMAIN, certserver returns a retryable status to the controller and waits for DNS propagation before creating an order with the upstream certificate authority.
3. **ACME Order Creation:** certserver checks its local cache. If no valid certificate exists, certserver creates an ACME order with the upstream certificate authority. The certificate authority returns HTTP-01 challenge tokens. certserver stores these tokens in its shared challenge store.
4. **Retry Response:** certserver returns a retryable status code to the GARI controller. The controller requeues the Gateway for reconciliation after a short delay.
5. **Validation Trigger:** certserver notifies the certificate authority that challenges are ready for validation.
6. **DNS Resolution:** The certificate authority resolves the domain name through public DNS. Public DNS returns the Gateway's public IP address.
7. **Validation Request:** The certificate authority sends an HTTP GET request to `http://<hostname>/.well-known/acme-challenge/<token>` on port 80.
8. **In-Path Challenge Forwarding:** The Gateway opts in to challenge forwarding. The GARI data plane receives the request on port 80 and intercepts the challenge path. The data plane reads its projected service-account token from disk and forwards the challenge request to certserver over TLS, including the original `Host` header and the bearer token. If certserver returns an HTTP 404 response or does not answer in time, the data plane falls through to normal HTTPRoute routing.
9. **Challenge Binding Verification:** certserver validates the service-account token against the cluster's JWKS. certserver verifies that the token corresponds to the data-plane service account registered for this order in step 2. certserver also confirms that the token matches a pending challenge for the requested `Host`.
10. **Key Authorization Delivery:** certserver returns the ACME key authorization string to the data plane in an HTTP 200 response.
11. **Relaying Response:** The data plane relays the key authorization string back to the certificate authority with a `Content-Type: application/octet-stream` header.
12. **Order Finalization:** The certificate authority confirms validation and updates the order status to valid. certserver generates a Certificate Signing Request (CSR), sends it to the certificate authority, and downloads the signed certificate chain.
13. **Cache Storage:** certserver writes the certificate chain and private key to its encrypted local disk cache.
14. **Controller Requeue:** The GARI controller retries the `GetCertificate` RPC.
15. **Certificate Release and Cache Reuse:** certserver detects the cached certificate, verifies that the requesting Gateway passed authorization, and returns the certificate chain and private key to the controller. When another Gateway requests an existing cached certificate, certserver validates domain control locally via DNS resolution checks and local self-probing before releasing the certificate, avoiding duplicate upstream ACME orders.
16. **Data Plane Configuration:** In phase 1, the GARI controller writes the certificate and private key into GARI's per-Gateway data-plane config Secret. The data plane reads its configuration from this Secret and begins terminating TLS on port 443.

### Automated Renewal Flow

certserver manages certificate renewal independently in the background:

1. A background loop in certserver inspects cached certificates at regular intervals.
2. When a certificate reaches approximately two-thirds of its validity period, certserver initiates renewal.
3. certserver adds randomized jitter to the renewal schedule to avoid traffic spikes against the upstream certificate authority.
4. certserver starts a new ACME order for the certificate's hostname set.
5. The certificate authority validates each hostname through public DNS and the data plane, following the same in-path forwarding and challenge-binding rules as initial issuance.
6. If public DNS still routes to the Gateway, the challenge succeeds. certserver downloads the renewed certificate and updates the local disk cache.
7. If the domain owner moved DNS away from the Gateway, public DNS directs the validation request elsewhere. The validation fails, certserver aborts the renewal, and the existing certificate expires naturally. This ensures that certserver stops renewing certificates for hostnames that the Gateway no longer serves.
8. When certserver updates the cache, the GARI controller detects the new certificate on its next reconciliation loop and updates the data plane without connection disruption.

## Failure Modes and Recovery

certserver handles common operational and network failures predictably:

### 1. DNS Not Yet Pointing at the Gateway

A user creates a Gateway or Route before pointing public DNS records at the Gateway's external IP address.
- **Symptom:** When the certificate authority resolves the hostname, DNS returns NXDOMAIN or points to an unrelated server. The certificate authority's validation request fails to reach the GARI data plane.
- **Handling:** The certificate authority marks the challenge as failed. certserver cleans up the pending order and returns a retryable error to the GARI controller. The controller requeues reconciliation with exponential backoff. Once the user configures DNS and records propagate across public resolvers, subsequent challenge attempts succeed.

### 2. Port 80 Unreachable

The ACME HTTP-01 specification requires plain HTTP validation on port 80.
- **Symptom:** Upstream network firewalls, cloud security groups, or missing Gateway listeners block incoming TCP port 80 connections.
- **Handling:** The certificate authority's connection attempt times out or fails with connection refused. The challenge fails. certserver logs the failure, records the error reason, and returns a non-retryable error to the controller once configured retry limits expire. The controller updates the Gateway's listener condition to `Programmed=False` with a descriptive reason. Operators must expose port 80 to resolve the condition.

### 3. CAA Refusals

A domain uses Certification Authority Authorization (CAA) DNS records to restrict which certificate authorities may issue certificates for that domain.
- **Symptom:** The domain's CAA records do not permit the upstream certificate authority that certserver uses (such as Google Trust Services or Let's Encrypt).
- **Handling:** The certificate authority checks CAA records before creating challenges and rejects the order immediately. certserver detects the CAA refusal, logs the failure, and returns a terminal error to the GARI controller. The controller reports the CAA error in the Gateway status conditions. The domain owner must update their CAA DNS records to permit the configured certificate authority.

### 4. Upstream Certificate Authority Outage or Rate Limiting

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
  1. **Direct Data-Plane Retrieval:** Data planes fetch certificates and private keys directly from certserver at startup using their own projected service-account tokens. The data plane holds keys in process memory only and never writes them to Secrets or disk. Challenge binding already binds the data plane's service account to the Gateway.
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
