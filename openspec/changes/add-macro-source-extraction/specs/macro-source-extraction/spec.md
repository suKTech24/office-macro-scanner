# Spec Delta

## Purpose

Make the macro code inside Office documents reviewable as text so humans and automated gates can inspect changes before the document is approved, signed, or published.

## ADDED Requirements

### Requirement: Extract VBA source from Office documents

When an Office macro document is submitted for review, the system SHALL extract its VBA modules as plain-text source files (one per module) that carry the module names and the code recorded inside `vbaProject.bin`.

#### Scenario: Document contains VBA modules

- **WHEN** a submitted Office document contains one or more VBA modules
- **THEN** the system produces one plain-text file per module, each carrying the module's name and its source

#### Scenario: Document contains no VBA

- **WHEN** a submitted Office document contains no VBA modules
- **THEN** the system records that the document has no macro source to review and produces no module files

### Requirement: Make extracted source visible on the pull request

When macro changes reach a pull request, the system SHALL make the extracted VBA source visible to reviewers on the pull request itself — either as a committed file set in the branch or as a pull-request comment or artifact — so a reviewer can read exactly what changed without opening the binary document.

#### Scenario: Reviewer sees macro change on the pull request

- **WHEN** a pull request adds or modifies an Office macro document
- **THEN** the extracted VBA source for that document is visible on the pull request as a readable diff a reviewer can read line by line

### Requirement: Verify extracted source corresponds to the binary

Before the extracted source is treated as the truth of the document for later gates, the system SHALL verify that the plain-text source and the macro binary that would ship represent the same VBA project, so an attacker cannot submit a benign-looking text diff while shipping a different binary.

#### Scenario: Extracted source matches binary

- **WHEN** the extracted source reproduces the modules contained in the submitted document's `vbaProject.bin`
- **THEN** the system records a source-to-binary match and permits the change to continue to later gates

#### Scenario: Extracted source does not match binary

- **WHEN** the extracted source does not reproduce the modules contained in the submitted document's `vbaProject.bin`
- **THEN** the system records a source-to-binary mismatch and blocks the change from proceeding to later gates
