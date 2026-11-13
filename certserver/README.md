# certserver

`certserver` manages TLS certificates for GARI data planes outside Kubernetes clusters. For full architecture, registration instructions, and manifests, see [docs/certserver.md](../docs/certserver.md).

## Shared Front-End Groups

Gateways in one group share a front end, so certserver treats a proof from one of them as covering the others. The cluster-level `SharedFrontEndGroup` puts every Gateway in the cluster into one group; an operator should set it only when all of the cluster's Gateways really share one front end.

Per-Gateway group membership can be configured in cluster configuration via `GatewaySharedFrontEndGroups` using the Gateway's full `namespace/name`.
