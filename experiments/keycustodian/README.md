# Key Custodian

The key custodian is an experiment in node-local private key isolation. It holds TLS private keys and signs TLS handshakes on behalf of the gateway process over a Unix domain socket, ensuring the gateway never holds private key bytes in memory or on its filesystem.

It lives under `experiments/keycustodian/` as an independent Go module, isolated from the core gateway code, with a view toward splitting it into a standalone project later.

## Interface

The interface lifts Go's `crypto.Signer` onto the wire using gRPC over a local Unix domain socket:

- **Digest-only signing:** The client computes the cryptographic hash and passes only the pre-computed digest to `Sign`. The custodian verifies that the digest length matches the requested hash algorithm, but never hashes arbitrary client-supplied payload data.
- **Minimal API surface:** Exposes `ListKeys`, `GetCertificateChain`, and `Sign`. There are no decrypt, key export, or key import RPCs. Private key bytes never cross the socket and are never logged.
- **Local Unix socket only:** Listens exclusively on a local filesystem socket (`mode 0660`). There is no TCP listener and no TLS on the socket. Clients enforce a concurrency bound and a per-call deadline.

## The Two Ladders

The design separates authorization and storage into two orthogonal axes that deployments climb independently.

### 1. Caller Policy (Who May Ask for a Signature)

- **Rung 0: Peer credentials (Implemented)**
  - *Mechanism:* Process isolation via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS), validating the caller's UID/GID against an allowlist over a shared hostPath Unix socket.
  - *Protects against:* Unauthorized local processes and unprivileged users on the host requesting signatures.
  - *Does not protect against:* Distinguishing between different pods or workloads that run with the same UID on the host.
- **Rung 1: Pod identity via DRA ResourceClaim**
  - *Mechanism:* Dynamic Resource Allocation (DRA) driver issuing per-claim Unix sockets via CDI, cross-checking caller cgroups against pod identity.
  - *Protects against:* A pod accessing keys outside its explicit claim; restricts each pod to only the keys granted in its ResourceClaim.
  - *Does not protect against:* A compromised container binary inside the authorized pod.
- **Rung 2: Calling container image digest/signature via CRI**
  - *Mechanism:* Interrogating the Container Runtime Interface (CRI) to verify the image digest and signature of the requesting container.
  - *Protects against:* Untrusted or tampered container images running inside an authorized pod.
  - *Does not protect against:* Post-startup memory compromises of a legitimately signed image.
- **Rung 3: Namespace and ServiceAccount constraints**
  - *Mechanism:* Cluster RBAC and admission control policies governing which namespaces and ServiceAccounts may claim specific keys.
  - *Protects against:* Unauthorized tenants or workloads requesting claims for keys outside their administrative boundary.
  - *Does not protect against:* Compromise of the cluster control plane or admission webhooks.

### 2. Key Custody (Where Keys Live and What Holds Before Release)

- **Rung 0: Custodian memory (Implemented)**
  - *Mechanism:* Keys loaded from local PEM files at startup and retained in the custodian process's memory.
  - *Protects against:* Gateway memory safety flaws and container-level exploits exposing the private key.
  - *Does not protect against:* Host root extracting keys from the custodian process's memory or disk.
- **Rung 1: TPM-resident key sealed to measured boot**
  - *Mechanism:* Keys generated in or imported into a TPM 2.0 (`/dev/tpmrm0`), sealed to PCR policies matching a measured boot state.
  - *Protects against:* Offline disk theft and extraction of the private key even by root; ensures key usage only in an uncompromised boot state.
  - *Does not protect against:* Hypervisor-level inspection or physical bus interposition attacks.
- **Rung 2: KMS release gated on node attestation**
  - *Mechanism:* Central KMS releases keys to a node only after remote attestation validates the node's identity and measured state.
  - *Protects against:* Untrusted or compromised nodes acquiring keys; simplifies centralized rotation and revocation.
  - *Does not protect against:* Node kernel compromises occurring after the key has been released to memory.
- **Rung 3: Confidential guest (AMD SEV-SNP / Intel TDX)**
  - *Mechanism:* Custodian or node runs inside a confidential VM with hardware memory encryption, with key release gated on the guest attestation report.
  - *Protects against:* Hypervisor compromises, host administrators, and unauthorized memory dumping outside the guest.
  - *Does not protect against:* Bugs internal to the guest kernel or the custodian daemon itself.

## Threat Model and Mitigations

### What Rung 0 Protects Against

- **Gateway memory compromise:** Memory safety bugs, uninitialized read vulnerabilities, or core dumps in the gateway process cannot leak the private key.
- **Gateway filesystem compromise:** Container breakout, local directory traversal, or file leaks restricted to the gateway container cannot access private key material.

### What Rung 0 Does Not Protect Against

- **Compromised authorized clients:** An attacker who compromises the gateway process cannot steal the private key, but *can* issue signing requests through the authorized socket while the compromise persists.
- **Root on the node:** A root user on the host node can inspect the custodian's memory or interact with the Unix socket directly.

### Mitigations

Because neither axis prevents an authorized client from signing while compromised, rung zero includes three foundational mitigations:

1. **Short certificate lifetimes:** Frequent certificate rotation minimizes the window of exposure if a key or signature is abused.
2. **Per-key rate limits:** Token-bucket rate limiting per key restricts how many signatures a client can request, preventing mass-signing attacks or denial of service.
3. **Structured audit logging:** Every `Sign` call emits a structured audit log containing the key name, caller UID/PID, hash algorithm, and outcome (success, rate-limited, rejected, or error). Digest contents and private key bytes are never logged.

## Fail-Closed Behaviour

The system fails closed in all error states:

- If the custodian daemon is down, unresponsive, or the Unix socket disappears, the gateway fails to complete TLS handshakes and marks itself unready.
- The gateway never falls back to an in-memory or locally cached private key.
