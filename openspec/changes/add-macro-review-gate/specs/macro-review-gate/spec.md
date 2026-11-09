# Spec Delta

## Purpose

Decide whether a pull request that changes macro code may be merged, by combining the findings from automated analysis and the judgement of a human reviewer into a single enforced gate on the pull request.

## ADDED Requirements

### Requirement: Aggregate analysis findings into a verdict against policy

When analysis findings for a pull request are available, the system SHALL aggregate the findings from macro extraction, macro static analysis, and macro dynamic analysis and evaluate them against the project's gate policy to produce a single verdict of pass or fail for that pull request.

#### Scenario: All findings are within policy

- **WHEN** every finding for the pull request is within the project's gate policy
- **THEN** the system records a pass verdict for the pull request

#### Scenario: At least one finding violates policy

- **WHEN** at least one finding for the pull request violates the project's gate policy
- **THEN** the system records a fail verdict for the pull request, identifying the findings responsible

### Requirement: Surface the verdict and its report on the pull request

When a verdict is recorded for a pull request, the system SHALL surface that verdict and the underlying findings on the pull request, so a reviewer can see pass or fail and read the evidence without leaving the pull request.

#### Scenario: Verdict is produced for a pull request

- **WHEN** a pass or fail verdict is recorded for a pull request
- **THEN** the verdict and the underlying findings are visible on the pull request

### Requirement: Block merge on a failing verdict

When the current verdict for a pull request that changes macro code is a fail, the system SHALL prevent the pull request from being merged until the verdict becomes a pass.

#### Scenario: Pull request has a failing verdict

- **WHEN** the current verdict for a pull request that changes macro code is a fail
- **THEN** the pull request cannot be merged

#### Scenario: Failing verdict later becomes a pass

- **WHEN** the pull request's verdict changes from fail to pass after further commits
- **THEN** the merge block imposed by the verdict is lifted

### Requirement: Require peer approval of the readable macro diff before merge

When a pull request would change macro code, the system SHALL prevent merge until a designated peer reviewer with approval authority for macro changes has approved the readable macro diff for that pull request.

#### Scenario: Pull request has no peer approval

- **WHEN** a pull request that changes macro code has no approval from a designated peer reviewer for the readable macro diff
- **THEN** the pull request cannot be merged

#### Scenario: Pull request receives peer approval of the diff

- **WHEN** a designated peer reviewer approves the readable macro diff for the pull request
- **THEN** the merge block imposed by the peer-approval requirement is lifted