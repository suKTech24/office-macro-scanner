# Spec Delta

## Purpose

Read extracted macro source and the containing document and produce structured findings about dangerous capabilities, policy violations, embedded secrets, and coding-quality problems, so a downstream gate can decide whether to admit the change.

## ADDED Requirements

### Requirement: Detect suspicious macro capability indicators

When extracted VBA source is available for a submitted document, the system SHALL scan the source and the containing document for indicators of dangerous capability — including auto-execution triggers, process or shell invocation, suspicious COM objects, Win32 API declarations, obfuscation patterns, and DDE or embedded-object inclusions — and report each hit as a structured finding.

#### Scenario: Macro contains an auto-execution trigger

- **WHEN** the extracted source contains an auto-execution entry point (such as a routine that runs on document open)
- **THEN** the system reports a structured finding identifying the trigger kind, the module, and the location

#### Scenario: Macro contains a shell or process invocation

- **WHEN** the extracted source contains a call that executes a shell command or a child process
- **THEN** the system reports a structured finding identifying the invocation kind, the module, and the location

### Requirement: Enforce project-defined detection rules

When extracted VBA source is available for a submitted document, the system SHALL evaluate project-defined detection rules against both the containing document and the extracted source, and report each rule match as a structured finding carrying the rule identifier and the location that matched.

#### Scenario: Project-defined rule matches extracted source

- **WHEN** a project-defined detection rule matches the extracted source or the containing document
- **THEN** the system reports a structured finding identifying the matching rule and the location that matched

### Requirement: Detect embedded secrets in extracted macro source

When extracted VBA source is available for a submitted document, the system SHALL scan it for embedded secrets — including credentials, API keys, tokens, and internal file-share paths — and report each hit as a structured finding that identifies the kind of secret and its location, without reproducing the secret value in a form that would leak it further.

#### Scenario: Macro contains an embedded credential

- **WHEN** the extracted source contains an embedded credential, API key, or token
- **THEN** the system reports a structured finding identifying the kind of secret and its location, and does not reproduce the secret value in the finding

### Requirement: Report VBA coding-quality problems

When extracted VBA source is available for a submitted document, the system SHALL check it against the project's VBA coding standards — such as explicit variable declaration and the presence of error handling — and report each violation as a structured finding identifying the rule and the location.

#### Scenario: Macro omits a required coding standard

- **WHEN** the extracted source violates a project-defined VBA coding standard
- **THEN** the system reports a structured finding identifying the standard and the location