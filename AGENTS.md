# AGENTS.md

This file provides context and instructions for LLM coding agents working on the `gateway-api-reference-implementation` project.

## Project Vision

The `gateway-api-reference-implementation` is intended to be a simple, pure Go, reference implementation of the Kubernetes Gateway API. It should prioritize readability, maintainability, and full feature coverage over extreme performance.

## Key Principles for Agents

- **Prioritize Clarity**: Code should be easy to read and understand. Use idiomatic Go.
- **Pure Go**: Avoid CGO or complex platform-specific optimizations unless absolutely necessary for the reference implementation's goals.
- **Reference Over Performance**: If there's a trade-off between making the code more "reference-like" (easier to understand, follows specs closely) and making it faster, choose the former.
- **Full Feature Set**: When implementing features, aim for complete support of the Gateway API specification.
- **Testability**: Ensure that implementations are well-tested with unit and integration tests.

## Writing

Code comments, docstrings, commit messages, PR descriptions and docs should read clearly to someone new to the code. Follow Google's [Technical Writing One](https://developers.google.com/tech-writing/one) and, for details, the [Google developer documentation style guide](https://developers.google.com/style). For doc comments, see [Go doc comments](https://go.dev/doc/comment) and the docstring section of the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings).

The rules that matter most here:
- **Use active voice.** Say who does what: "the router claims the executor before it asks it to serve", not "the executor is claimed before it is asked to serve".
- **Write full sentences, one idea each.** Don't chain clauses with colons, semicolons and parenthetical asides.
- **Define a term before you use it,** and use the project's existing words. Don't coin shorthand.
- **Say what the code does and why,** not how it got that way.
- **For critical code, state the invariants, then explain them in active voice.** Storage, recovery, concurrency and security code should list the invariants it relies on, as short statements that a reviewer can check the code against. Write invariants actively where possible: "the engine fsyncs a segment before it creates the next one", not "segments are rotated only after being fsynced". Then explain who does what, when, and why each invariant makes the code correct.
- **Check all the prose in your change** before you send it. Start from the diff, and check every file that holds prose: docs (such as `design.md` and `README.md`), code comments, docstrings, proto and script comments, error and log messages, flag help, the commit message and the PR description.
- **Don't oversell. State what you measured or can show, and qualify it.** Avoid superlatives and absolutes such as "optimal", "guaranteed", "zero", "always", "strictly", "drastically" and "cryptographically", unless the statement really is absolute and the text says why. Report performance numbers with how and where they were measured. Describe trade-offs as trade-offs, including what is given up.

For example, rewrite this:

> The inputs of this engine's range that are numbers, not tensors (a prefill's length one segment hands another): from the network they come as tensors, and are turned back.

as this:

> The names of this range's inputs that are plain numbers rather than tensors, such as a prefill's length. The wire format carries only tensors, so the range server turns these back into numbers when they arrive.

To avoid overselling, rewrite this:

> ...preserving point-in-time consistency via `writerMu.RLock()` offers the optimal balance of architectural simplicity, zero steady-state memory overhead, and data integrity...

as this:

> ...preserving point-in-time consistency via `writerMu.RLock()` offers a balance of architectural simplicity, zero steady-state memory overhead, and data integrity...

## Behaviour beyond the Gateway API specification

Some behaviour in this project goes beyond the Gateway API specification. For example, the code may decide a case that the specification leaves open, or report a status condition that the specification does not request. Readers cannot distinguish those choices from required behaviour without comments, so they find the code hard to revisit when the specification changes.

- Where code does more than the Gateway API specification requires, or decides a case that the specification leaves open, mark it with a comment that starts with `Beyond the Gateway API specification:`.
- The comment says what the specification says or leaves unsaid, what this implementation does, and why.
- Where a tracking issue exists for the gap, the comment names it.

For example:

```go
// Beyond the Gateway API specification: the specification does not define
// a tie-break when two TLSRoutes claim identical hostnames on one listener.
// This controller chooses the older route by creation timestamp, following
// the HTTPRoute rule. See tracking issue #1211.
```

## Naming

**Don't abbreviate identifiers.** Write `header`, not `hdr`, and `buffer`, not `buf`. An abbreviation saves the writer a few keystrokes and costs every reader a lookup. When naming an error from a specific operation, spell out the operation. For example, an error from `Remove` is `removeErr`, not `rErr`.

The only exceptions are conventional Go:
- `i`, `j` and `k` as integer loop indices.
- A one- or two-letter method receiver, such as `p *Proxy`.
- The ecosystem idioms `ctx`, `err`, `ok`, `wg`, `mu` and `tx`. `context` and `error` are also package and type names.
- Protocol or on-disk field names that are themselves abbreviations, such as `fd` or `sha256`.

**Names must match signatures.** For example, a function that returns `[]byte` is `build...`, not `write...`. A `write...` function takes an `io.Writer` or a destination slice.

**Names must reflect side effects.** Use `init...` or `set...` rather than `new...` when a function modifies or initializes existing state. Reserve `New...` for constructors that allocate and return a fresh value.

**Use one name per concept.** Do not introduce multiple names for the same thing, such as `prepared` beside `encoded`.

## Development Workflow

- Use standard Go tooling (`go build`, `go test`, `go mod`).
- Adhere to the project's coding style (standard `gofmt`).
- Follow the PR hygiene mentioned in the project's instructions:
    - Solve only the specific issue.
    - Well-structured commits.
    - Reference issues in the commit body.

### Scope

Small, focused issues lead to small, focused PRs. Big PRs are hard to review because reviewers miss things when moves, refactors and behaviour changes arrive together. Big PRs are also harder to write correctly because each additional idea adds more ways for the pieces to interact, and more to keep in mind across review rounds.

- **One idea, one issue, one PR.** If a PR can be split into two ideas, split it.
- **A good PR changes at most 200 lines, including tests.** The time to review and understand a PR grows roughly with the square of the lines in the diff, so a 100-line PR costs a quarter as much as a 200-line one, and splitting a 200-line change in two halves the total. If the one idea needs more than 200 lines, say so on the issue before pushing and propose where to cut or how to order the parts.
- **Issues carry a line budget** for the same reason. Give an issue a budget before assigning it.
- **When an issue contains more than one idea,** don't deliver it as one large PR. Say so on the issue, propose the split, and deliver the parts as separate PRs, or ask for the issue to be split.
- **Separate mechanical changes from behaviour changes.** Moves, renames and reformatting go in their own PR, or at least their own commit first, with nothing else changed, so the reviewer can confirm nothing changed.
- **Stay in scope during review.** Fix what the review asks for. Problems found along the way that are outside the PR's idea become new issues, not extra changes in the same PR.
- **Don't add unrequested improvements,** such as compatibility shims, extra options or opportunistic refactors.
- **For people and agents writing issues,** write one idea per issue, with acceptance criteria for that idea only. Follow-on ideas become separate issues, with any ordering stated.

### Commit messages and PR descriptions

The git history is the permanent record; the GitHub PR description is not. It is not part of the merged artifact and is effectively lost after merge.

- **Put anything worth keeping in the code or the commits**: design decisions and non-obvious behaviour belong in code comments; the reasoning behind a change belongs in the commit message.
- **Keep the PR description to bookkeeping**: normally just `Fixes #<issue>`. Don't summarize or "sell" the change; the code and commits should stand on their own.
- When you revise a PR in response to review, don't maintain a changelog in the PR description.

### Commands

The project uses the `ap` tool for various tasks. Since `ap` is a custom tool, it should be run using `go run`:

- `go run github.com/gke-labs/gke-labs-infra/ap@latest build`: Build container images and artifacts.
- `go run github.com/gke-labs/gke-labs-infra/ap@latest deploy`: Build artifacts and deploy manifests to a cluster.
- `go run github.com/gke-labs/gke-labs-infra/ap@latest generate`: Regenerate any code and format.
- `go run github.com/gke-labs/gke-labs-infra/ap@latest test`: Run unit tests.
- `go run github.com/gke-labs/gke-labs-infra/ap@latest e2e`: Run e2e tests.
- `go run github.com/gke-labs/gke-labs-infra/ap@latest lint`: For deeper static analysis.

**Reminder**: Coding agents MUST run at least `ap generate` before sending PRs, and MUST run `ap e2e` locally to verify that all conformance and end-to-end tests pass before submitting changes! Running `ap e2e` locally before pushing is a strict requirement to prevent test regressions in CI.

## Testing

Follow these rules when writing or updating tests:

- **Build inputs from the real producer.** If component B consumes objects created by component A, construct test inputs with component A's code: constructors, templates, and exported constants. Do not hand-write fixtures that copy component A's labels, annotation keys, ports, or names as string literals.
- **Test through public entry points.** Drive behaviour through the package's public API, or through the controller with a real or `envtest` API server, rather than by mutating internal fields to simulate a condition. If a fault has to be injected, inject it at the boundary: the filesystem, the network, or a fake cloud API.
- **Every review-found bug gets an end-to-end regression test** that reproduces the reported scenario, not just the narrow fix.
- **Prefer shared constants.** Shared label keys and values, annotation keys, secret data keys, and ports should be exported once and imported by both production code and tests.

