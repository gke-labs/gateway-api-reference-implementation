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
| `""` (core) | `services`, `serviceaccounts`, `secrets` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | Singlepod provisioner manages per-Gateway ServiceAccount, headless/ClusterIP Service, and data-plane configuration Secrets. |
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

## Google Cloud IAM Roles & Workload Identity

To uphold least privilege, `gcpgateway` uses two distinct IAM roles:

1. **`gcpgatewayNegRegistrar` (Runtime Controller Role)**:
   Used by the controller in the cluster. It can **only** inspect NEGs and backend services, attach/detach endpoints, and query health. It cannot create or destroy infrastructure.
   - Permissions:
     - `compute.networkEndpointGroups.get`
     - `compute.networkEndpointGroups.list`
     - `compute.networkEndpointGroups.use`
     - `compute.networkEndpointGroups.attachNetworkEndpoints`
     - `compute.networkEndpointGroups.detachNetworkEndpoints`
     - `compute.instances.use` (attachNetworkEndpoints references the pod's VM)
     - `compute.backendServices.get` (also authorizes `getHealth`)
     - `compute.zoneOperations.get`
2. **`gcpgatewayOperatorHelper` (Provisioning Helper Role)**:
   Used by operators or CI/CD pipelines executing `gcpgatewayctl frontend create` and `gcpgatewayctl frontend delete`.
   - Permissions across addresses, health checks, NEGs, backend services, target TCP proxies, forwarding rules, and firewall rules.

> **Note on IAM Conditions and Multi-Cluster Isolation**:
> Because resource names use `<prefix>-<8-char-hash>-<suffix>` without readable cluster names, a name-based IAM Condition (e.g. `resource.name.startsWith(...)`) **cannot** separate multiple clusters sharing the same GCP project unless each cluster is configured with a unique prefix (e.g., `--neg-prefix=gcpgw-cluster1-`). If multiple clusters share a project, configure distinct prefixes per cluster to achieve IAM resource separation.

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
