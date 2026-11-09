# Spec Delta

## Purpose

Produce signed macro documents that endpoints enforcing a trusted-publisher policy will accept, bind signing to a passed review gate, hold the signing key in a managed key service, and publish signed releases with integrity and audit evidence.

## ADDED Requirements

### Requirement: Sign only macro changes that cleared the review gate

When a macro change is submitted for signing, the system SHALL sign it only if the review gate has recorded a pass verdict for the change, so that no document reaches signing before automated analysis and peer approval have cleared it.

#### Scenario: Review gate passed for the change

- **WHEN** the review gate has recorded a pass verdict for the change submitted for signing
- **THEN** the system proceeds to sign the macro document for that change

#### Scenario: Review gate has not passed for the change

- **WHEN** the review gate has not recorded a pass verdict for the change submitted for signing
- **THEN** the system refuses to sign the macro document and records the refusal

### Requirement: Produce a VBA-project signature endpoints can trust

When signing a macro document, the system SHALL produce a digital signature over the VBA project such that an endpoint configured to run only trusted-publisher-signed macros will accept the resulting document, so a signed document can execute under a trusted-publisher policy without further per-endpoint configuration.

#### Scenario: Document is signed for a trusted publisher

- **WHEN** the system signs a macro document under the organisation's trusted-publisher identity
- **THEN** the signed document is accepted for execution by an endpoint configured to allow only macros from that trusted publisher

### Requirement: Hold the signing key in a managed key service

The system SHALL hold the private signing key in a managed key service rather than in developer environments or pipeline secret stores, and the key SHALL be usable only by the signing step of the release workflow — so that a compromised developer, build runner, or secret store cannot sign macros on the organisation's behalf.

#### Scenario: Signing step uses the key through the key service

- **WHEN** the signing step signs a macro document
- **THEN** it uses the key through the managed key service, and the private key material is not read into the pipeline secret store or any developer environment

#### Scenario: An entity outside the signing step requests the key

- **WHEN** any entity other than the release workflow's signing step attempts to use the signing key
- **THEN** the key service denies the request and the attempt is recorded

### Requirement: Publish signed releases with integrity and audit evidence

When a signed macro document is released, the system SHALL publish the signed document together with a cryptographic hash of the document (such as SHA-256) and an audit record that identifies which change was signed, so consumers can verify integrity and the organisation retains a tamper-evident trail from release back to the approved change.

#### Scenario: Signed document is released

- **WHEN** the system publishes a signed macro document as a release
- **THEN** the release includes the signed document, its cryptographic hash, and an audit record identifying the change that was signed