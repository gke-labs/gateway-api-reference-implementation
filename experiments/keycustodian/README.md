# Key Custodian

The key custodian is an experiment in node-local private key isolation. It holds TLS private keys and signs TLS handshakes on behalf of the gateway process over a Unix domain socket. This separation keeps private key bytes out of the gateway process memory and off its filesystem.

The experiment lives under `experiments/keycustodian/` as an independent Go module, isolated from the core gateway code, with a view toward splitting it into a standalone project later.

## Interface

The interface lifts Go's `crypto.Signer` onto the wire using gRPC over a local Unix domain socket:

- **Digest-only signing.** The client computes the cryptographic hash and passes only the pre-computed digest to `Sign`. The custodian verifies that the digest length matches the requested hash algorithm. The custodian does not hash client-supplied payload data.
- **Minimal API surface.** The service exposes `ListKeys`, `GetCertificateChain`, and `Sign`. It provides no RPCs for decryption, key export, or key import. Private key bytes do not cross the socket and do not appear in logs.
- **Local Unix socket only.** The daemon listens only on a local filesystem socket with mode 0660. It has no TCP listener and does not use TLS on the socket. Clients apply a concurrency bound and a per-call deadline.

## The Two Ladders

The design separates caller authorization and key storage into two orthogonal ladders. Deployments climb each ladder independently. Rung 0 on each ladder is the first step to be built.

### 1. Caller Policy (Who May Ask for a Signature)

- **Rung 0: Peer credentials (planned first step)**
  - *Mechanism:* The custodian uses process isolation via `SO_PEERCRED` on Linux or `LOCAL_PEERCRED` on macOS. It validates the caller UID and GID against an allowlist over a shared hostPath Unix socket.
  - *Protects against:* Unauthorized local processes and unprivileged host users requesting signatures.
  - *Does not protect against:* Distinguishing between different pods or workloads that run with the same UID on the host.
- **Rung 1: Pod identity via DRA ResourceClaim (planned follow-up)**
  - *Mechanism:* A Dynamic Resource Allocation (DRA) driver issues per-claim Unix sockets through CDI and cross-checks caller cgroups against pod identity.
  - *Protects against:* A pod using keys outside its assigned claim. Each pod accesses only the keys granted in its ResourceClaim.
  - *Does not protect against:* A compromised container binary inside an authorized pod.
- **Rung 2: Calling container image digest and signature via CRI (planned follow-up)**
  - *Mechanism:* The custodian queries the Container Runtime Interface (CRI) to verify the image digest and signature of the calling container.
  - *Protects against:* Untrusted or modified container images running inside an authorized pod.
  - *Does not protect against:* Memory compromises that happen after an authorized image starts.
- **Rung 3: Namespace and ServiceAccount constraints (planned follow-up)**
  - *Mechanism:* Cluster RBAC and admission control policies govern which namespaces and ServiceAccounts may claim specific keys.
  - *Protects against:* Unauthorized tenants requesting claims for keys outside their namespace.
  - *Does not protect against:* A compromise of the cluster control plane or admission webhooks.

### 2. Key Custody (Where Keys Live and What Holds Before Release)

- **Rung 0: Custodian memory (planned first step)**
  - *Mechanism:* The custodian loads keys from local PEM files at startup and keeps them in its own process memory.
  - *Protects against:* Gateway memory flaws and unauthorized reads within the gateway container, as long as the gateway pod does not mount the key directory.
  - *Does not protect against:* Root on the host extracting keys from the custodian process memory or from disk.
- **Rung 1: TPM-resident key sealed to measured boot (planned follow-up)**
  - *Mechanism:* Keys reside in a TPM 2.0 (`/dev/tpmrm0`) sealed to PCR policies that match a measured boot state.
  - *Protects against:* Offline disk theft and extraction of the raw private key. Even root cannot read private key bytes from the TPM.
  - *Does not protect against:* Root on the node asking the TPM to sign with the key while the PCR policy holds. It also does not protect against hypervisor-level inspection or physical bus interposition attacks.
- **Rung 2: KMS release gated on node attestation (planned follow-up)**
  - *Mechanism:* A central KMS releases keys to a node only after remote attestation validates the node identity and measured state.
  - *Protects against:* Untrusted or unverified nodes receiving keys. It also simplifies centralized key rotation and revocation.
  - *Does not protect against:* Node kernel compromises that occur after the key reaches memory.
- **Rung 3: Confidential guest (AMD SEV-SNP or Intel TDX) (planned follow-up)**
  - *Mechanism:* The custodian or the entire node runs inside a confidential VM with hardware memory encryption, and key release requires a valid guest attestation report.
  - *Protects against:* Hypervisor compromises, host administrators, and unauthorized memory inspection from outside the guest.
  - *Does not protect against:* Vulnerabilities in the guest kernel or inside the custodian daemon itself.

## Threat Model

### What Rung 0 Protects Against

- **Gateway memory compromise:** Memory bugs, uninitialized reads, or core dumps in the gateway process do not expose the private key, because the key material stays in the custodian process.
- **Gateway filesystem compromise:** Flaws inside the gateway container do not expose the private key, as long as the gateway pod does not mount the directory containing the key files.

### What Rung 0 Does Not Protect Against

- **Compromised authorized clients:** An attacker who compromises the gateway process cannot read the private key bytes, but the attacker can ask the custodian to sign handshakes through the authorized socket while the compromise lasts.
- **Root on the node:** A root user on the host node can inspect the custodian's memory or interact with the Unix socket directly.

## Planned Mitigations

Neither axis prevents an authorized client from requesting signatures while compromised. The project plans three complementary mitigations to limit that exposure:

1. **Short certificate lifetimes (provided by the issuing CA):** Frequent certificate rotation limits how long an attacker can exploit a compromised key or signature.
2. **Per-key rate limits:** The custodian daemon does not limit the rate of `Sign` calls, because any rate limit would cap the number of TLS handshakes the gateway can perform, and no specific limit value has an empirical basis yet.
3. **Structured audit logging (provided by the custodian daemon):** The custodian logs one structured JSON line per `Sign` call or peer-credential denial recording key name, caller UID and PID (from peer credentials), hash algorithm or method, and outcome (`success`, `rejected`, `denied`, `error`) to standard output. The audit log omits digest contents and private key bytes.

## Fail-Closed Requirement

The future gateway integration must fail closed:

- If the custodian daemon is down, unresponsive, or the Unix socket disappears, the gateway must fail TLS handshakes and report itself unready.
- The gateway must never fall back to an in-memory or locally cached private key.
