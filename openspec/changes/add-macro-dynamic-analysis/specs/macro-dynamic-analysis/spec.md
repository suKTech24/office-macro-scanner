# Spec Delta

## Purpose

Execute macros in a controlled way that reveals runtime-only behavior — resolved obfuscated strings and formulas, called APIs, shell invocations, file-system operations, and network operations — so a downstream gate can judge the document on behavior static analysis cannot see.

## ADDED Requirements

### Requirement: Resolve runtime-constructed strings and formulas

When a macro would construct strings or formulas at runtime — through character arithmetic, environment lookups, concatenation chains, or XLM formula chains — the system SHALL reduce those constructions to their resolved values and report each resolved value as a structured finding attributed to the module and location that produced it.

#### Scenario: VBA macro assembles a string from character arithmetic

- **WHEN** the macro constructs a string at runtime from character or arithmetic operations
- **THEN** the system reports a structured finding with the resolved string and the module and location that produced it

#### Scenario: Excel 4.0 (XLM) macro resolves an obfuscated formula chain

- **WHEN** the document contains an Excel 4.0 (XLM) macro whose behavior depends on a resolved formula chain
- **THEN** the system reports a structured finding with the resolved chain and the cell or location that produced it

### Requirement: Produce an execution trace of operations the macro would perform

When dynamic analysis runs a submitted document, the system SHALL produce an execution trace recording the operations the macro would perform — including API calls, shell or process invocations, file-system operations, and network operations — attributed to the module or location that initiated each operation.

#### Scenario: Macro invokes a shell command

- **WHEN** the macro invokes a shell command or starts a child process
- **THEN** the execution trace records the invocation, its arguments, and the module and location that initiated it

#### Scenario: Macro performs a network operation

- **WHEN** the macro initiates a network connection or request
- **THEN** the execution trace records the operation, its target, and the module and location that initiated it

### Requirement: Isolate the dynamic analysis environment

The system SHALL perform dynamic analysis only in an environment that is isolated from the general-purpose build infrastructure — such that execution of a hostile macro cannot read pipeline secrets, modify source, affect other builds, or persist beyond the analysis — so that an untrusted document cannot compromise the pipeline by being analysed.

#### Scenario: Dynamic analysis runs a hostile macro

- **WHEN** dynamic analysis executes a document whose macro attempts to read pipeline secrets, modify source, or affect other builds
- **THEN** those attempts do not reach the general-purpose build infrastructure, and the environment is torn down or reset so that no effect persists past the analysis
