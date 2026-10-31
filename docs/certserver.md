# Automatic TLS Certificates via certserver

GARI controllers (`gateway-api-reference-implementation` and `gcpgateway`) support obtaining TLS certificates automatically from `certserver` using GARI's pluggable certificate source mechanism and certserver's authenticated `GetCertificate` gRPC API.

This document describes how to configure `certserver`, set up controller manifests and flags, and request certificates on Gateway listeners.

---

## 1. Registering the Cluster's OIDC Issuer with certserver

`certserver` validates controller requests by authenticating projected ServiceAccount tokens offline against the originating cluster's OIDC discovery endpoint or a local JSON Web Key Set (JWKS).

Clusters can be registered dynamically via a registration directory without restarting certserver, or statically via a configuration file.

### Dynamic Registration via `register-cluster` over SSH (Recommended)

When clusters do not expose their OIDC discovery documents or JWKS publicly to the internet, operators can register clusters or update their JWKS directly over SSH using the `certserver register-cluster` subcommand.

#### Discovering Issuer and JWKS via `kubectl get --raw`

To retrieve the cluster OIDC issuer URL:
```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```

To retrieve the cluster's current JWKS:
```bash
kubectl get --raw /openid/v1/jwks
```

#### Uploading JWKS over SSH

Pipe the JWKS from your local machine over SSH into `certserver register-cluster`:

```bash
kubectl get --raw /openid/v1/jwks | ssh certserver-vm sudo -u certserver certserver register-cluster \
  --dir /var/lib/certserver/clusters --cluster-id prod-1 \
  --issuer "$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)" \
  --allow '*.example.com' --controller-sa gcpgateway-system/gcpgateway-controller \
  --jwks -
```

Key flags for `register-cluster`:
- `--dir`: path to the certserver cluster registration directory (e.g. `/var/lib/certserver/clusters`).
- `--cluster-id`: unique cluster identifier matching the requesting controller's cluster ID.
- `--issuer`: cluster OIDC issuer URL (must start with `https://`).
- `--jwks`: path to a JWKS JSON file, or `-` to read from standard input.
- `--allow`: allowed hostname pattern(s) for certificate issuance (repeated flag or comma-separated).
- `--deny`: optional denied hostname pattern(s).
- `--controller-sa`: authorized controller ServiceAccount (e.g. `gcpgateway-system/gcpgateway-controller` or `system:serviceaccount:ns:sa`).
- `--controller-namespace`: optional controller namespace constraint.
- `--shared-frontend-group`: optional shared front-end group for cross-cluster challenge routing.

#### Registration Directory Structure & Live Reload

`certserver` watches and periodically scans the registration directory (configured with `--cluster-dir=/var/lib/certserver/clusters` and `--cluster-dir-poll-interval=2s`):
- Per-cluster files are stored in subdirectories:
  - `<dir>/<cluster-id>/cluster.json`: cluster configuration (cluster ID, issuer URL, allowed/denied hostnames, groups, controller identity).
  - `<dir>/<cluster-id>/jwks.json`: JSON Web Key Set containing trusted public signing keys.
- Directory and subdirectories are owned by the certserver user with permissions `0700`, and files are written with permissions `0600`.
- **Atomic Writes**: `register-cluster` writes files atomically (temporary file, `fsync`, and atomic rename) so partially written files are never read or loaded.
- **Validation Before Swap-in**: Before swapping in a changed cluster, `certserver` validates that `cluster.json` parses, the issuer is HTTPS, and `jwks.json` parses with at least one usable public key. If validation fails (such as an invalid upload), `certserver` keeps the previous version active and logs a structured audit event.
- **Dynamic Unregistration**: Removing a cluster's subdirectory (`rm -rf <dir>/<cluster-id>`) automatically unregisters the cluster and revokes its token verification on the next scan.
- **Audit Logging**: Every registration, update, unregistration, and validation refusal is recorded in certserver's structured audit log.

#### Handling ServiceAccount Key Rotation

When rotating Kubernetes ServiceAccount signing keys:
1. Kubernetes publishes both the old key and the new key in `/openid/v1/jwks` during the rotation overlap window.
2. Re-run `certserver register-cluster` with the dual-key JWKS:
   ```bash
   kubectl get --raw /openid/v1/jwks | ssh certserver-vm sudo -u certserver certserver register-cluster \
     --dir /var/lib/certserver/clusters --cluster-id prod-1 \
     --issuer "$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)" \
     --allow '*.example.com' --controller-sa gcpgateway-system/gcpgateway-controller \
     --jwks -
   ```
3. `certserver` detects the updated `jwks.json`, validates the keys, and swaps them in live without restarting. Tokens signed with either key verify during the transition window with zero downtime.

---

### Static Cluster Configuration File

Alternatively, clusters can be defined in a static YAML or JSON file passed via `--cluster-config-file`:

```yaml
clusters:
- clusterID: "cluster-prod-1"
  issuerURL: "https://container.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/clusters/my-cluster"
  jwksURL: "https://container.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/clusters/my-cluster/jwks"
  controllerNamespace: "default"
  controllerServiceAccount: "gari-controller"  # or gcpgateway-controller
  allowedHostnames:
  - "echo.example.com"
  - "*.example.com"
```

If both `--cluster-config-file` and `--cluster-dir` are provided, `certserver` merges the static clusters with directory-registered clusters. Any directory cluster attempting to duplicate a static cluster ID is rejected and audit-logged as refused.

---

## 2. Controller Configuration and Manifests

### Projected ServiceAccount Token Volume and Deployment Configuration

Controllers authenticate to `certserver` using a projected service-account token volume with audience `certserver` and 10-minute validity.

The default GARI manifest `k8s/controller.yaml` is certserver-free so standard installs without certserver work out of the box. To enable certserver, add the projected token volume, volume mount, and `--certserver-*` flags to your controller Deployment (or apply as a kustomize overlay):

```yaml
      containers:
      - name: controller
        args:
        - --dataplane-image=$(DATAPLANE_IMAGE)
        - --certserver-address=certserver.gateway-system.svc:8443
        - --certserver-ca-bundle-path=/etc/ssl/certs/certserver-ca.crt
        - --certserver-token-path=/var/run/secrets/tokens/certserver/token
        volumeMounts:
        - name: certserver-token
          mountPath: /var/run/secrets/tokens/certserver
          readOnly: true
      volumes:
      - name: certserver-token
        projected:
          sources:
          - serviceAccountToken:
              audience: certserver
              expirationSeconds: 600
              path: token
```

### Command-Line Flags and Environment Variables

Every GARI controller binary supports the following certserver flags (and corresponding environment variables):

| Flag | Env Var | Description |
| --- | --- | --- |
| `--certserver-address` | `CERTSERVER_ADDRESS` | The `host:port` address of the certserver gRPC service (e.g. `certserver.gateway-system.svc:8443`). |
| `--certserver-ca-bundle-path` | `CERTSERVER_CA_BUNDLE_PATH` | Path to the CA bundle PEM file to verify certserver TLS (e.g. `/etc/ssl/certs/certserver-ca.crt`). |
| `--certserver-token-path` | `CERTSERVER_TOKEN_PATH` | Path to the projected service-account token file (e.g. `/var/run/secrets/tokens/certserver/token`). |

If certserver flags are omitted, the `certserver` source is not registered, and any listener requesting it will report an `Unknown certificate source "certserver"` condition.

---

## 3. Requesting Certificates on Gateway Listeners

To request a certificate from `certserver`, configure an HTTPS listener on a `Gateway` with:
- An exact, non-wildcard `hostname`.
- TLS mode `Terminate`.
- The option `gateway.gke-labs.io/certificate-source: certserver` under `tls.options`.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: prod-gw
  namespace: default
spec:
  gatewayClassName: reference-class # or gcpgateway
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: "echo.example.com"
    tls:
      mode: Terminate
      options:
        gateway.gke-labs.io/certificate-source: certserver
```

---

## 4. Lifecycle, Caching, and Renewal

1. **Initial Request**: When the controller reconciles the Gateway listener, it initiates certificate issuance with `certserver`. While issuance is in progress, the listener condition reports `Pending`.
2. **Delivery & Deployment**: Once issued, the certificate and private key are cached in-memory and deployed to the Gateway data plane. The listener condition transitions to `Programmed=True`.
3. **Background Renewal**: Certificates are monitored and automatically renewed before expiry. If a renewal attempt fails while the existing certificate is still valid, the current valid certificate is preserved to avoid service disruption.
