# gcpgateway — GARI with Zonal NEGs behind Layer-4 Google Cloud Load Balancing

`gcpgateway` is a Google Cloud variant of GARI (Gateway API Reference Implementation). It runs on GKE (and self-managed Kubernetes on Google Compute Engine) using **zonal `GCE_VM_IP_PORT` Network Endpoint Groups (NEGs)** behind a Google Cloud Layer-4 External Managed TCP Proxy Load Balancer.

## Architecture

- **Front-end**: A Google Cloud external layer-4 TCP proxy load balancer receives public traffic on ports 443 (HTTPS) and 80 (HTTP). It forwards traffic over TCP to zonal NEGs with a **PROXY v1 header**, preserving client IP addresses.
- **Data plane**: GARI data-plane pods terminate TLS and enforce routing rules. HTTP and HTTPS listeners validate source IP addresses against `allowedSourceCIDRs` (dropping unauthorized traffic before TLS) and parse PROXY v1/v2 headers strictly from `proxyProtocolTrustedCIDRs` (GFE ranges `35.191.0.0/16` and `130.211.0.0/22`).
- **Readiness Gate & Draining**: Data-plane pods include the `gcpgateway.gke-labs.io/load-balancer-ready` readiness gate, set to `True` only after `backendServices.getHealth` confirms the pod is `HEALTHY`. A pure Go pre-stop hook writes a drain sentinel file `/var/run/gcpgateway/draining`, causing the health check on port `8999` (`/_gari/readyz`) to immediately report `503 Service Unavailable` while active connections gracefully complete.
- **Resource Naming & Ownership**: Resource names are constructed as `<prefix>-<8-char-hash>-<suffix>` without readable cluster or namespace names. Ownership identity (`cluster-id`, `namespace`, `gateway-name`, `port`) is stored as JSON in each resource's `description` metadata. The controller only mutates NEGs whose metadata matches its cluster and Gateway.

---

## Minimal Kubernetes RBAC

`gcpgateway` adheres to least-privilege RBAC. Each rule in `k8s/controller.yaml` is listed below with its justification:

| API Group | Resources | Verbs | Justification |
| --- | --- | --- | --- |
| `gateway.networking.k8s.io` | `gateways`, `gatewayclasses`, `httproutes`, `backendtlspolicies`, `referencegrants`, `listenersets` | `get`, `list`, `watch`, `update`, `patch` | Core Gateway API reconciliation and status condition updates. |
| `gateway.networking.k8s.io` | `tlsroutes`, `grpcroutes`, `tcproutes`, `udproutes` | `get`, `list`, `watch` | Route discovery for cross-protocol Gateway listeners. |
| `gateway.networking.k8s.io` | `*/status` subresources | `update`, `patch` | Updating `Accepted`, `Programmed`, and address status on Gateways and Routes. |
| `""` (core) | `services`, `serviceaccounts` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | Singlepod provisioner manages per-Gateway ServiceAccount and headless/ClusterIP Service. |
| `""` (core) | `secrets` | `get`, `list`, `watch` | Resolving TLS certificates referenced by Gateway listeners. |
| `apps` | `deployments` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | Singlepod provisioner creates and manages the per-Gateway data-plane Deployment. |
| `""` (core) | `configmaps`, `namespaces` | `get`, `list`, `watch` | Resolving parameters ConfigMaps referenced by `spec.infrastructure.parametersRef`. |
| `""` (core) | `nodes` | `get`, `list`, `watch` | Resolving node `spec.providerID` to GCE zone and instance name for NEG attachment. |
| `discovery.k8s.io` | `endpointslices` | `get`, `list`, `watch` | Detecting live backend endpoints for Gateway routing. |
| `""` (core) | `pods` | `get`, `list`, `watch` | Detecting data-plane pod IP, node assignment, and container readiness (`ContainersReady`). |
| `""` (core) | `pods/status` | `update`, `patch` | **Critical**: Setting the `gcpgateway.gke-labs.io/load-balancer-ready` readiness gate to `True` once load balancer health checks pass. |
| `apiextensions.k8s.io` | `customresourcedefinitions` | `get`, `list`, `watch` | Verifying Gateway API CRD installation and schema version. |

> **Note on `pods/status` Cluster-Wide Scope**:
> The `pods/status` `patch` and `update` permission is necessarily cluster-wide because Gateway instances and their associated singlepod data-plane Deployments may reside in any Kubernetes namespace. The `gcpgateway` controller uses this permission strictly and exclusively to patch its own readiness gate condition (`gcpgateway.gke-labs.io/load-balancer-ready`) on its own data-plane pods once confirmed healthy by `backendServices.getHealth`. The controller never modifies other status conditions on data-plane pods, and never inspects or mutates pods belonging to other Gateways or unrelated cluster workloads.

---

## Google Cloud Credentials and IAM Roles

The `gcpgateway` controller calls the Google Compute Engine API using Application Default Credentials (ADC). At start-up, the controller resolves credentials and fetches one access token unless `--fake-compute` is set. If credential resolution or token fetching fails, the controller exits with an error that lists the credential sources it tried. Data-plane pods do not call Google Cloud APIs and do not need Google Cloud credentials.

ADC checks three sources in order and stops at the first one it finds:

1. The JSON file named by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
2. The `gcloud` application default credentials file at `$HOME/.config/gcloud/application_default_credentials.json`.
3. The Google Compute Engine metadata server at `169.254.169.254` (or `GCE_METADATA_HOST` when set).

### Required IAM Permissions

`gcpgateway` separates runtime permissions from provisioning permissions using two IAM roles:

1. **`gcpgatewayNegRegistrar` (Runtime Controller Role)**:
   The controller uses this role inside the cluster. It can inspect NEGs and backend services, attach and detach endpoints, and query backend health. It cannot create or delete load-balancing infrastructure.
   - Permissions:
     - `compute.networkEndpointGroups.get`
     - `compute.networkEndpointGroups.list`
     - `compute.networkEndpointGroups.use`
     - `compute.networkEndpointGroups.attachNetworkEndpoints`
     - `compute.networkEndpointGroups.detachNetworkEndpoints`
     - `compute.instances.use` (required because `attachNetworkEndpoints` references the pod's VM)
     - `compute.backendServices.get` (also authorizes `getHealth`)
     - `compute.zoneOperations.get`
2. **`gcpgatewayOperatorHelper` (Provisioning Helper Role)**:
   Operators or CI/CD pipelines use this role when running `gcpgatewayctl frontend create` and `gcpgatewayctl frontend delete`.
   - Permissions cover addresses, health checks, NEGs, backend services, target TCP proxies, forwarding rules, and firewall rules.

> **Note on IAM Conditions and Multi-Cluster Isolation**:
> Resource names use `<prefix>-<8-char-hash>-<suffix>` without readable cluster names. A name-based IAM Condition such as `resource.name.startsWith(...)` cannot separate multiple clusters sharing the same GCP project unless each cluster uses a unique prefix such as `--neg-prefix=gcpgw-cluster1-`. Configure distinct prefixes per cluster if multiple clusters share a project.

### Supplying an Identity to the Controller

You can supply a Google Cloud identity to the `gcpgateway` controller in three ways.

#### 1. Node Service Account via the Metadata Server

When `GOOGLE_APPLICATION_CREDENTIALS` is unset and no `gcloud` credentials file exists in the container, ADC falls back to the Compute Engine metadata server. The controller then authenticates as the service account attached to the node VM.

This option requires three conditions:

- The controller pod can reach the metadata server at `169.254.169.254`.
- The node VM grants the `compute` or `cloud-platform` OAuth scope.
- The node's service account holds the `gcpgatewayNegRegistrar` role.

Granting `gcpgatewayNegRegistrar` to the node service account exposes those permissions to any pod on that node that can reach the metadata server. On clusters that block pod access to the metadata server, this option fails and the controller exits at start-up.

#### 2. Workload Identity on GKE

On GKE clusters with Workload Identity enabled, GKE intercepts metadata server requests from the controller pod and issues tokens for a bound Google Service Account (GSA). The controller pod still uses ADC through the metadata server endpoint, but it receives the GSA's identity instead of the node's service account. See [Step 1](#step-1-create-iam-roles--bind-workload-identity) and [Step 2](#step-2-deploy-the-controller) below for the GKE setup commands.

#### 3. Workload Identity Federation with a Projected ServiceAccount Token

On self-managed Kubernetes clusters running on GCE (such as kOps clusters where pods cannot reach the metadata server), you can authenticate the controller with Workload Identity Federation and a projected Kubernetes ServiceAccount token. The Go client reads the resulting `external_account` configuration automatically with no changes to the controller binary.

1. Create a Workload Identity Pool and an OIDC provider using the cluster's JSON Web Key Set (JWKS). Uploading the JWKS works even when the cluster's OIDC issuer is a private name that Google cannot fetch directly:

```bash
export PROJECT_ID="my-gcp-project"
export PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
export POOL="my-cluster-pool"

kubectl get --raw /openid/v1/jwks > jwks.json
ISSUER=$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)

gcloud iam workload-identity-pools create "${POOL}" \
  --project="${PROJECT_ID}" \
  --location="global"

gcloud iam workload-identity-pools providers create-oidc kubernetes \
  --project="${PROJECT_ID}" \
  --location="global" \
  --workload-identity-pool="${POOL}" \
  --issuer-uri="${ISSUER}" \
  --jwk-json-path="jwks.json" \
  --allowed-audiences="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/kubernetes" \
  --attribute-mapping="google.subject=assertion.sub"
```

2. Grant `gcpgatewayNegRegistrar` directly to the federated Kubernetes ServiceAccount (KSA) principal. Compute Engine accepts federated principals directly, so you do not need a Google Service Account:

```bash
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --role="projects/${PROJECT_ID}/roles/gcpgatewayNegRegistrar" \
  --member="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/subject/system:serviceaccount:default:gcpgateway-controller"
```

3. Generate an `external_account` credential configuration file and store it in a ConfigMap:

```bash
gcloud iam workload-identity-pools create-cred-config \
  "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/kubernetes" \
  --credential-source-file="/var/run/secrets/gcp-token/token" \
  --credential-source-type="text" \
  --output-file="gcp-wif-credentials.json"

kubectl create configmap gcpgateway-gcp-credentials \
  --namespace="default" \
  --from-file=credentials.json=gcp-wif-credentials.json
```

4. Mount the credential configuration ConfigMap and a projected `serviceAccountToken` volume into the `gcpgateway-controller` Deployment, and point `GOOGLE_APPLICATION_CREDENTIALS` at the mounted file:

```yaml
spec:
  template:
    spec:
      containers:
      - name: controller
        env:
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /var/run/secrets/gcp-credentials/credentials.json
        volumeMounts:
        - name: gcp-credentials
          mountPath: /var/run/secrets/gcp-credentials
          readOnly: true
        - name: gcp-token
          mountPath: /var/run/secrets/gcp-token
          readOnly: true
      volumes:
      - name: gcp-credentials
        configMap:
          name: gcpgateway-gcp-credentials
      - name: gcp-token
        projected:
          sources:
          - serviceAccountToken:
              audience: //iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/kubernetes
              expirationSeconds: 3600
              path: token
```

Once the controller runs with this configuration, Cloud Audit Logs record Compute API calls under `principalSubject: .../workloadIdentityPools/<POOL>/subject/system:serviceaccount:default:gcpgateway-controller`, and you can remove `gcpgatewayNegRegistrar` from the node service account.

> **Key Rotation Caveat**:
> When you configure the OIDC provider with an uploaded JWKS file, rotating the cluster's service-account signing key requires exporting the updated JWKS and re-running `gcloud iam workload-identity-pools providers update-oidc kubernetes --location="global" --workload-identity-pool="${POOL}" --jwk-json-path="jwks.json"`.

---

## Step-by-Step Operator Walkthrough (Zero to HTTPS Traffic)

### Prerequisites

- A GKE cluster with VPC-native networking enabled (`--enable-ip-alias`) and Workload Identity enabled.
- `gcloud` CLI authenticated with Project Owner or Security Admin permissions.
- `kubectl` configured with cluster administrator access.

### Step 1: Create IAM Roles & Bind Workload Identity

Set up environment variables:
```bash
export PROJECT_ID="my-gcp-project"
export REGION="us-central1"
export CLUSTER_NAME="my-cluster"
export CLUSTER_ID="cluster-prod-1"
export KSA_NAME="gcpgateway-controller"
export KSA_NAMESPACE="default"
export GSA_NAME="gcpgateway-controller-sa"
export PREFIX="gcpgw"
```

1. Create the runtime custom role:
```bash
gcloud iam roles create gcpgatewayNegRegistrar \
  --project="${PROJECT_ID}" \
  --title="GARI gcpgateway NEG Registrar" \
  --description="Authorizes gcpgateway controller to register endpoints and check health" \
  --stage="GA" \
  --permissions="compute.networkEndpointGroups.get,compute.networkEndpointGroups.list,compute.networkEndpointGroups.use,compute.networkEndpointGroups.attachNetworkEndpoints,compute.networkEndpointGroups.detachNetworkEndpoints,compute.instances.use,compute.backendServices.get,compute.zoneOperations.get"
```

2. Create the Google Service Account (GSA) and bind the role:
```bash
gcloud iam service-accounts create "${GSA_NAME}" \
  --project="${PROJECT_ID}" \
  --display-name="gcpgateway Controller Service Account"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="projects/${PROJECT_ID}/roles/gcpgatewayNegRegistrar"
```

3. Bind Workload Identity between the GSA and Kubernetes Service Account (KSA):
```bash
gcloud iam service-accounts add-iam-policy-binding \
  "${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project="${PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[${KSA_NAMESPACE}/${KSA_NAME}]"
```

### Step 2: Deploy the Controller

Annotate the Kubernetes ServiceAccount with the GSA email and apply the controller manifests:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gcpgateway-controller
  namespace: default
  annotations:
    iam.gke.io/gcp-service-account: ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
EOF

kubectl apply -f gcpgateway/k8s/controller.yaml
```

Verify the controller is running:
```bash
kubectl rollout status deployment/gcpgateway-controller -n default
```

### Step 3: Run the Front-end Provisioning Tool

Run `gcpgatewayctl frontend create` to provision the Google Cloud load balancer, IP address, health check, and zonal NEGs:
```bash
go run ./gcpgateway/cmd/gcpgatewayctl frontend create \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --cluster-id="${CLUSTER_ID}" \
  --namespace="default" \
  --gateway-name="prod-gw" \
  --prefix="${PREFIX}"
```

The tool outputs the static IP address and the ready-to-apply ConfigMap and Gateway manifests.

### Step 4: Apply Gateway and Parameters Manifests

Apply the ConfigMap and Gateway generated by the script:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: gcpgateway-params-prod-gw
  namespace: default
data:
  serviceType: ClusterIP
  allowedSourceCIDRs: "35.191.0.0/16,130.211.0.0/22"
  proxyProtocol: "enabled"
  proxyProtocolTrustedCIDRs: "35.191.0.0/16,130.211.0.0/22"
  externalIP: "<STATIC_IP_FROM_STEP_3>"
  clusterId: "${CLUSTER_ID}"
  gatewayNamespace: "default"
  gatewayName: "prod-gw"
  negHTTPS: "gcpgw-<HASH>-8443"
  negHTTP: "gcpgw-<HASH>-8080"
  negPrefix: "${PREFIX}"
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: prod-gw
  namespace: default
spec:
  gatewayClassName: gcpgateway
  addresses:
  - type: IPAddress
    value: "<STATIC_IP_FROM_STEP_3>"
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    tls:
      mode: Terminate
      certificateRefs:
      - name: prod-gw-cert
    allowedRoutes:
      namespaces:
        from: Same
  - name: http
    protocol: HTTP
    port: 80
    allowedRoutes:
      namespaces:
        from: Same
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: gcpgateway-params-prod-gw
EOF
```

### Step 5: Deploy Sample Application, TLS Secret, and Route

Create a self-signed TLS secret:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt -subj "/CN=echo.example.com"

kubectl create secret tls prod-gw-cert --cert=tls.crt --key=tls.key -n default
```

Deploy a backend service and an HTTPRoute:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: registry.k8s.io/e2e-test-images/agnhost:2.45
        args: ["netexec", "--http-port=8080"]
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: default
spec:
  ports:
  - port: 8080
    targetPort: 8080
  selector:
    app: echo
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: echo
  namespace: default
spec:
  parentRefs:
  - name: prod-gw
  hostnames:
  - "echo.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: echo
      port: 8080
EOF
```

### Step 6: Verify HTTPS Traffic

Wait for the Gateway to report `Programmed=True`:
```bash
kubectl wait --for=condition=Programmed gateway/prod-gw -n default --timeout=3m
```

Send an HTTPS request:
```bash
STATIC_IP=$(kubectl get gateway prod-gw -n default -o jsonpath='{.status.addresses[0].value}')
curl -kv --resolve "echo.example.com:443:${STATIC_IP}" "https://echo.example.com/"
```

The response confirms end-to-end traffic passing through the Google Cloud L4 Load Balancer, through the zonal NEG into the GARI data plane, terminating TLS, and reaching the backend pod.

---

## Automatic TLS Certificates via certserver

`gcpgateway` integrates with `certserver` to automatically provision and renew TLS certificates for HTTPS listeners using GARI's pluggable certificate-source hook and certserver's authenticated `GetCertificate` gRPC API.

For shared architecture, cluster registration, and certificate lifecycle details, see [docs/certserver.md](../docs/certserver.md).

### 1. Registering the Cluster's OIDC Issuer with certserver

`certserver` verifies projected ServiceAccount tokens offline against the originating cluster's OIDC discovery endpoint and JSON Web Key Set (JWKS). Before `gcpgateway` can request certificates, register the cluster in `certserver`'s configuration:

```yaml
clusters:
- clusterID: "cluster-prod-1"  # Matches gcpgateway --cluster-id
  issuerURL: "https://container.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/clusters/my-cluster"
  jwksURL: "https://container.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/clusters/my-cluster/jwks"
  controllerNamespace: "default"
  controllerServiceAccount: "gcpgateway-controller"
  allowedHostnames:
  - "echo.example.com"
  - "*.example.com"
```

Find your GKE cluster's OIDC issuer URL with:
```bash
kubectl get --raw /.well-known/openid-configuration
```

### 2. Controller Configuration and Manifests

The `gcpgateway-controller` Deployment in `k8s/controller.yaml` includes a projected service-account token volume (`certserver-token`) with audience `certserver` and 10-minute validity, mounted read-only at `/var/run/secrets/tokens/certserver/token`.

When starting the controller, pass the certserver flags:
- `--certserver-address`: The `host:port` address of the certserver gRPC service (e.g. `certserver.gateway-system.svc:8443`).
- `--certserver-ca-bundle-path`: Path to the CA bundle PEM file to verify the certserver TLS endpoint (e.g. `/etc/ssl/certs/certserver-ca.crt`).
- `--certserver-token-path`: Path to the projected service-account token file (e.g. `/var/run/secrets/tokens/certserver/token`).

Without these flags, `certserver` is not registered as a certificate source, and any listener requesting it receives an `Unknown certificate source "certserver"` condition.

### 3. Requesting Certificates on Gateway Listeners

To obtain a certificate from `certserver`, configure a Gateway listener with:
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
  gatewayClassName: gcpgateway
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

When evaluated, the controller requests the certificate from `certserver`. While issuance is in progress, the listener condition reports `Pending`. Once issued, the certificate and private key are stored in the controller's in-memory cache, pushed to the per-Gateway data-plane config Secret, and renewed automatically before expiry.

---

## Teardown

When a Gateway is deleted (`kubectl delete gateway`), the controller uses the finalizer `gcpgateway.gke-labs.io/cleanup` to cleanly detach all data-plane endpoints from the zonal NEGs before allowing Kubernetes to finalize and delete the Gateway resource.

### Manual Finalizer Removal

If the `gcpgateway` controller is uninstalled or stopped before its Gateways are deleted, Kubernetes keeps the deleting Gateways in the `Terminating` state waiting for the finalizer to be removed. Remove the finalizer manually with `kubectl patch`:

```bash
kubectl patch gateway <gateway-name> -n <namespace> \
  --type=merge \
  -p '{"metadata":{"finalizers":null}}'
```

After removing the finalizer, delete any remaining Google Cloud front-end resources using `teardown_frontend.py`.

### Front-End Resource Deletion

To delete all Google Cloud Load Balancer and NEG resources created for the Gateway:
```bash
go run ./gcpgateway/cmd/gcpgatewayctl frontend delete \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --cluster-id="${CLUSTER_ID}" \
  --namespace="default" \
  --gateway-name="prod-gw" \
  --prefix="${PREFIX}"
```

The teardown command inspects resource description metadata and deletes only resources belonging to the specified cluster and Gateway.
