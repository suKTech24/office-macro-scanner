# Proposal

## Why

Endpoints that enforce "only run macros from trusted publishers" will accept a document only if its VBA project carries a signature from a key those endpoints trust. The original pipeline spec's stage 4 covers how approved macros become signed artifacts with an audit trail — but it also carries two important properties the earlier stages do not: signing must happen only after the review gate passed, and the signing key must live in a managed key service that developers do not hold. This change captures the signing-and-release stage as an OpenSpec capability. Behavior only; no implementation lands here. Implementation is deliberately deferred because the original's own Implementation Notes warn that the Office VBA-project signing mechanism is not just `signtool.exe` and the key integration needs verification before it can be trusted.

## What Changes

- Introduce the `macro-signing-release` capability as a first-class, durable system behavior.
- Capture both the signing act and the surrounding security properties the original attaches to it: the gating of signing on a passed review verdict, the custody of the signing key in a managed key service, and the audit-and-integrity shape of the resulting release.
- Explicitly out of scope: the review gate itself (lives in `macro-review-gate`), the analyses that feed the gate, and any optional pre-signing step that compiles raw `.bas`/`.cls` into a template document. The optional compile step is an input-handling detail; this capability signs documents it is given.
- No tool, cloud, or vendor is named as a requirement. The original's references to `signtool.exe`, MS Office SIP, Azure Key Vault, and GitHub Releases are implementation choices; the spec requires the behavior and the security property, not the mechanism.

## Capabilities

### New Capabilities

- `macro-signing-release`: Produce signed macro documents that endpoints enforcing a trusted-publisher policy will accept, sign only changes that cleared the review gate, hold the signing key in a managed key service accessible only to the signing step, and publish signed releases with integrity hashes and an audit record.

### Modified Capabilities

<!-- None. -->

## Impact

- No runtime impact. No code, workflow, or dependency changes land with this proposal.
- Adds `openspec/specs/macro-signing-release/spec.md` once archived.
- Depends on `macro-review-gate` producing a pass verdict — the signing step reads that signal and refuses to sign without it. The spec pins the dependency as a behavior ("sign only if the review gate passed") rather than as a tool coupling.
- Three deliberate choices worth naming:
  - Key custody is a first-class spec requirement, not an advisory note, because the original's own Implementation Notes warn against storing signing keys in CI secret stores — it is a security property of the capability, not of the deployment.
  - The spec requires signatures that a trusted-publisher-enforcing endpoint will accept, without naming Office SIP, signtool, or Authenticode by name. This leaves room for the implementation change to decide (and verify) the Office signing mechanism, which the original flags as unresolved.
  - "Audit log" from the original is captured as "an audit record that identifies which change was signed" — the behavior is traceability back to the pull request, not any specific log format.