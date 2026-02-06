# GEMINI.md

This file provides context and instructions for LLM coding agents working on the `gateway-api-reference-implementation` project.

## Project Vision

The `gateway-api-reference-implementation` is intended to be a simple, pure Go, reference implementation of the Kubernetes Gateway API. It should prioritize readability, maintainability, and full feature coverage over extreme performance.

## Key Principles for Agents

- **Prioritize Clarity**: Code should be easy to read and understand. Use idiomatic Go.
- **Pure Go**: Avoid CGO or complex platform-specific optimizations unless absolutely necessary for the reference implementation's goals.
- **Reference Over Performance**: If there's a trade-off between making the code more "reference-like" (easier to understand, follows specs closely) and making it faster, choose the former.
- **Full Feature Set**: When implementing features, aim for complete support of the Gateway API specification.
- **Testability**: Ensure that implementations are well-tested with unit and integration tests.

## Development Workflow

- Use standard Go tooling (`go build`, `go test`, `go mod`).
- Adhere to the project's coding style (standard `gofmt`).
- Follow the PR hygiene mentioned in the project's instructions:
    - Solve only the specific issue.
    - One idea per PR.
    - Well-structured commits.
    - Reference issues in the commit body.
