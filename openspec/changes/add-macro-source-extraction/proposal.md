# Proposal

## Why

Office macro documents (`.xlsm`, `.docm`, `.dotm`) carry their code inside a compiled binary (`vbaProject.bin`) that Git cannot diff. Without a readable form of the macro, no reviewer can see what changed, so no later gate — static analysis, peer review, or signing — can be trusted. The original pipeline spec (`docs/archive/original_spec/original-pipeline-spec.md`) opens with this problem for a reason: every other stage depends on the macro being readable. This change captures that opening stage as an OpenSpec capability so later changes have a stable target to build against. It specifies behavior only; no implementation is introduced here.

## What Changes

- Introduce the `macro-source-extraction` capability as a first-class, durable system behavior.
- Scope the capability to what the original pipeline spec's "Unpack & Normalise" stage prescribes: extracting readable VBA source from a macro document, publishing it where reviewers can see it, and verifying the extracted source matches the binary that would ship.
- Explicitly leave outside this capability's scope: static analysis of the extracted source, review-gate behavior, dynamic analysis, signing, and release — each lives in its own capability captured by a separate change.
- No tool is named as a requirement. The original spec's choice of `oletools` / `olevba` is implementation detail, carried into tasks of a future implementation change, not into this spec.

## Capabilities

### New Capabilities

- `macro-source-extraction`: Produce a reviewable, text form of the macros in an Office document, make that form visible on the pull request that proposes the change, and verify the extracted source corresponds to the binary macro project that would ship.

### Modified Capabilities

<!-- None. No existing specs; this is a greenfield capability. -->

## Impact

- No runtime impact. No code, workflow, or dependency changes land with this proposal.
- Adds `openspec/specs/macro-source-extraction/spec.md` once the change is archived.
- Future changes that implement later stages (static analysis, review gate, signing) will treat this capability's output as their input. Those changes may add requirements to this spec if they discover extraction-side behavior they need (for example, a stable path layout for extracted files); this proposal does not pre-specify that.
- One intentional omission from the original spec: the original mentions a pre-commit hook as an alternative extraction surface. This capability does not require pre-commit. The requirement is that extraction happens, not where; the pre-commit option can be added by a later change if it becomes relevant.
