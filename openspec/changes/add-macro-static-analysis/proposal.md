# Proposal

## Why

Once macro source is readable (captured in `macro-source-extraction`), the pipeline needs an automated layer that reads it and flags dangerous capabilities, policy violations, embedded secrets, and quality problems — otherwise every review becomes a human line-by-line hunt, which does not scale and misses patterns a tool would catch. The original pipeline spec's stage 2 ("Static Analysis in GitHub Actions") covers this layer across three sub-blocks (indicators, custom rules, secrets+lint). This change captures that stage as an OpenSpec capability so later changes have a stable target to build against. Behavior only; no implementation lands here.

## What Changes

- Introduce the `macro-static-analysis` capability as a first-class, durable system behavior.
- Scope the capability to what the original pipeline spec's stage 2 prescribes: finding suspicious macro capability indicators, enforcing project-defined detection rules, detecting embedded secrets, and reporting VBA coding-quality problems.
- Keep each of those four as a distinct requirement, mirroring the original's own split (D1 oletools indicators, D2 YARA rules, D3 gitleaks + lint — with D3 split further because secrets and lint are two different behaviors and the OpenSpec guidance is one behavior per requirement).
- Explicitly out of this capability's scope: the actual pass/fail gate verdict that blocks the merge (that belongs to `macro-review-gate`), dynamic analysis, signing, and release.
- No tool is named as a requirement. The original spec's choices (`olevba`, `mraptor`, `YARA`, `gitleaks`, `Rubberduck`) are implementation detail, to be chosen in a future implementation change, not pinned by this spec.

## Capabilities

### New Capabilities

- `macro-static-analysis`: Read extracted macro source and the containing document, and produce structured findings covering suspicious capabilities, custom-rule matches, embedded secrets, and coding-quality problems — so a downstream gate can decide whether to admit the change.

### Modified Capabilities

<!-- None. No existing specs. Later implementation work may touch macro-source-extraction if it discovers extraction-side needs. -->

## Impact

- No runtime impact. No code, workflow, or dependency changes land with this proposal.
- Adds `openspec/specs/macro-static-analysis/spec.md` once archived.
- Consumes the output of `macro-source-extraction` (extracted VBA source files) and the containing document. Future implementation of this capability depends on `macro-source-extraction` being implemented first, but this spec does not need `macro-source-extraction` to be in the main specs to be captured.
- Produces structured findings that `macro-review-gate` will later consume to decide pass/fail. That coupling is noted in the proposal but not pinned as a spec-level requirement here, because the gate behavior lives in `macro-review-gate`.
- One intentional omission from the original: the original lists `msodde` and `pyxswf` DDE/embedded-OLE checks as part of indicator scanning. Those are tool choices, not distinct behaviors — rolled under "suspicious capability indicators" as examples, not pinned as separate requirements.