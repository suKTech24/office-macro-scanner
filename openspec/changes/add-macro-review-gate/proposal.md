# Proposal

## Why

The static and dynamic capabilities each produce findings, but by themselves they do not stop anything from merging. The original pipeline spec's rule — "a macro may run only if it passed automated analysis and peer review and was signed with a protected organisational key" — turns findings into a merge decision through a two-layered gate: an automated pass/fail verdict against policy, and a mandatory human review of the readable macro diff. This change captures that gate as an OpenSpec capability. Behavior only; no implementation lands here.

## What Changes

- Introduce the `macro-review-gate` capability as a first-class, durable system behavior.
- Scope the capability to turning findings into a merge decision: aggregating findings into a verdict, surfacing the verdict and its report on the pull request, blocking merge on a failing verdict, and requiring peer approval of the readable macro diff before merge.
- Capture both the automated gate and the human gate in one capability — the original treats them as two parts of the same "did this change earn the right to merge?" question, enforced on the same pull request.
- Explicitly out of scope: producing the findings themselves (lives in `macro-static-analysis` and `macro-dynamic-analysis`), rendering the readable diff (lives in `macro-source-extraction`), signing, and release.
- No tool or platform mechanism is named as a requirement. The original's references to GitHub Branch Protection, `CODEOWNERS`, and SARIF attachments are implementation choices; the spec requires the behavior, not the mechanism.

## Capabilities

### New Capabilities

- `macro-review-gate`: Decide whether a pull request that changes macro code may be merged, by aggregating analysis findings into a verdict, surfacing the verdict and its report on the pull request, blocking merge until the verdict passes, and requiring peer approval of the readable macro diff.

### Modified Capabilities

<!-- None. -->

## Impact

- No runtime impact. No code, workflow, or dependency changes land with this proposal.
- Adds `openspec/specs/macro-review-gate/spec.md` once archived.
- Consumes outputs of `macro-source-extraction` (the readable diff), `macro-static-analysis` (findings), and `macro-dynamic-analysis` (findings). The gate does not run the analyses; it decides on their outputs.
- Produces the signal that `macro-signing-release` depends on: only pull requests that have cleared this gate may reach signing.
- One deliberate choice: aggregation policy (which finding severities block, which are advisory) is a project configuration concern, not a spec requirement. The spec requires that *a* policy is applied; what the policy is belongs to the implementation and to project configuration files.
