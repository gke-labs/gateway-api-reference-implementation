# Gateway Startup Latency: Per-Gateway Mode vs. All-in-One Mode

This document measures how long a Gateway takes to become usable and serve traffic in per-Gateway data-plane mode (`singlepod`) compared to all-in-one mode on a kind cluster, and breaks down where the time is spent across each step of the provisioning lifecycle.

## Environment

- **Machine:** Linux 6.12.110+ x86_64, 180 cores
- **kind version:** v0.27.0
- **Kubernetes version:** v1.32.2
- **Go version:** go1.27.4 linux/amd64
- **Command:** `RUN_E2E=1 go test -tags benchmark -v -timeout 15m ./tests/e2e -run TestBenchmarkGatewayStartup`
- **Sample size:**
  - Case 1 (First Gateway / Cold): 1 run on a fresh cluster
  - Case 2 (Later Gateway / Warm): 3 consecutive runs on the existing cluster
  - Case 3 (All-in-One Mode): 3 consecutive runs using an in-process data plane

## Measurements

All durations are measured from time zero (the moment the Gateway and HTTPRoute manifests are submitted to the Kubernetes API) until the respective milestone is reached.

| Step | Case 1: First Gateway (Cold, 1 run) | Case 2: Later Gateway (Warm, Median of 3 runs) | Case 3: All-in-One Mode (Median of 3 runs) |
|---|---|---|---|
| Deployment and Service exist | 0.50s | 0.24s (runs: 0.23s, 0.24s, 0.24s) | N/A |
| Pod scheduled | 0.50s | 0.24s (runs: 0.24s, 0.24s, 0.24s) | N/A |
| Container started | 2.11s | 1.16s (runs: 1.16s, 0.98s, 1.20s) | N/A |
| Config revision applied | 2.31s | 1.36s (runs: 1.36s, 1.18s, 1.40s) | 0.22s (runs: 0.22s, 0.22s, 0.22s) |
| Gateway address assigned | 3.10s | 1.97s (runs: 1.91s, 1.97s, 2.94s) | 0.15s (runs: 0.15s, 0.15s, 0.15s) |
| `Programmed=True` | 3.03s | 1.96s (runs: 1.96s, 1.90s, 2.99s) | 0.20s (runs: 0.20s, 0.20s, 0.20s) |
| First successful request | 3.15s | 1.98s (runs: 1.98s, 1.98s, 3.06s) | 0.20s (runs: 0.20s, 0.20s, 0.20s) |

The two largest steps contributing to per-Gateway startup latency are container startup (accounting for approximately 0.9s to 1.6s between pod scheduling and container execution) and LoadBalancer address allocation and status synchronization (accounting for approximately 0.6s to 1.5s between container start and the Gateway address being reflected on `status.addresses`). The third contributor is initial Deployment and Service creation by the provisioner, which adds approximately 0.24s to 0.50s. By contrast, all-in-one mode serves traffic in ~0.20s because the data plane is already running and requires neither container provisioning nor dedicated LoadBalancer IP allocation.
