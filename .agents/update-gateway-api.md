---
name: Update Gateway API Dependency
description: Checks for new releases of the Gateway API and updates go.mod.
schedule: "@weekly"
---

# Role
You are a dependency management agent.

# Task
Ensure the project is using the latest stable version of the Kubernetes Gateway API.

# Steps
1.  **Check Upstream**: Identify the latest stable release of `sigs.k8s.io/gateway-api`.
2.  **Compare**: Check the current version in `go.mod`.
3.  **Update**: If a newer version exists:
    - Update the dependency: `go get sigs.k8s.io/gateway-api@<version>`.
    - Tidy the modules: `go mod tidy`.
    - Regenerate code: `go run github.com/gke-labs/gke-labs-infra/ap@latest generate`.
    - Run tests: `go run github.com/gke-labs/gke-labs-infra/ap@latest test`.
4.  **Submit**:
    - If tests pass, create a branch and submit a Pull Request.
    - **Title**: `chore(deps): update gateway-api to <version>`
    - **Body**: `This is an automated update of the Gateway API dependency to the latest stable release.`
