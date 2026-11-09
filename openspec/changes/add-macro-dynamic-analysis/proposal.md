# Proposal

## Why

Static analysis cannot see what a macro constructs at runtime — strings assembled from `Chr()` arithmetic, environment lookups, or XLM formula chains, and the API, process, file, and network operations those resolved values eventually drive. The original pipeline spec's stage 3 ("Somewhat Dynamic Analysis") covers that gap, offering three implementation options (headless emulation such as ViperMonkey, external sandbox API, self-hosted ephemeral Windows VM). This change captures the stage as an OpenSpec capability so later changes have a stable target. Behavior only; no implementation lands here. Implementation is deliberately deferred because the original's own Implementation Notes warn that this stage requires isolation infrastructure that is not yet decided.

## What Changes

- Introduce the `macro-dynamic-analysis` capability as a first-class, durable system behavior.
- Scope the capability to what stage 3 prescribes: resolving runtime obfuscation, producing an execution trace of operations the macro would perform, and performing all of this in an isolated environment.
- Capture the isolation property as a first-class requirement rather than an implementation note, because the original's Implementation Notes explicitly warn that running untrusted documents on general-purpose CI runners is unsafe — it is a spec-level security property, not a tool choice.
- Explicitly out of scope: the pass/fail merge gate verdict (belongs to `macro-review-gate`), static analysis, signing, and release.
- No tool or option is named as a requirement. ViperMonkey, XLMMacroDeobfuscator, CAPE/Cuckoo/Tria.ge/Joe Sandbox, and a self-hosted ephemeral Windows runner are all valid implementations and the choice between them is deliberately left to a later implementation change.

## Capabilities

### New Capabilities

- `macro-dynamic-analysis`: Execute macros in a controlled way to reveal runtime-only behavior — resolved obfuscated strings and formulas, called APIs, shell invocations, file-system operations, and network operations — and do so in an environment isolated from the general-purpose build infrastructure.

### Modified Capabilities

<!-- None. -->

## Impact

- No runtime impact. No code, workflow, or dependency changes land with this proposal.
- Adds `openspec/specs/macro-dynamic-analysis/spec.md` once archived.
- Future implementation will depend on infrastructure outside the application code: either a usable headless emulator, an external sandbox contract, or an isolated ephemeral VM. The spec does not pin which; it does require isolation.
- Produces findings that `macro-review-gate` will later consume for pass/fail. Coupling noted here, pinned there.
- One deliberate decision: the spec does not require that *both* VBA and XLM be covered by the same mechanism. Coverage of both is captured by scenarios on the obfuscation-resolution requirement; implementations may use different tools for each as long as the behavior is produced.