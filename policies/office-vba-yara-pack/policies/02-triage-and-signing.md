# Triage and signing policy

Policy version `1.0.0`. Apply this proposed policy across all artifacts for one submitted document. Evaluate rows in order. The matcher returns findings and scanner status. Implement the decision and approval steps in the surrounding pipeline.

| Order | Condition | Document disposition |
| --- | --- | --- |
| 1 | An expected artifact or required surface is incomplete, a job or parser fails, or a coverage record is missing. | `HOLD_INCOMPLETE`. Keep signing locked. Re-extract, escalate to a supported workflow or reject under local intake policy. Preserve any findings already returned. |
| 2 | Trusted stomping or p-code-with-empty-source evidence, a YARA finding with both `severity=high` and `confidence=high`, or corroborating evidence of harmful behavior from approved analysis. | `HOLD_HIGH_RISK`. Route to security review before signing. Record the behavior chain and whether the evidence shows intent, capability or an observed runtime action. |
| 3 | Any other medium or high severity finding, or linked informational findings that independently show a higher-risk chain across modules. | `REVIEW`. Review code, destinations, reachable entry points and the approved business use. Escalate if additional evidence satisfies row 2. |
| 4 | All required surfaces have complete or verified not-applicable coverage, only informational findings or no findings remain, and standard approval prerequisites are met. | `ELIGIBLE_FOR_STANDARD_APPROVAL`. Continue code review and other existing controls before signing. |

If row 4 prerequisites are pending, leave the submission pending. Confirmed malicious behavior should produce `REJECT` through the designated security decision process. A zero-match document remains a no-finding result at the tested coverage.

## Triage procedure

1. Review the original hash, coverage, file type, signer or submitter identity, p-code state, rule IDs and offsets.
2. Trace an auto-entry point or other reachable caller through to the flagged behavior. Inspect constants, inputs, destinations, recipients, file paths and authorization. Scope references to a procedure and module where possible. YARA string co-occurrence can include comments, literals, declarations or separate routines.
3. Correlate at the document level when a chain spans multiple modules. For example, an open handler in one module, HTTP retrieval in another and a reachable launcher in a third warrant code-flow review. Treat raw and decoded copies of one module, and overlapping rules that describe one operation, as one piece of underlying evidence.
4. For suspected stomping, inspect the source and p-code of the same module with a compatible parser. If organisational policy permits behavioral testing, use an isolated, disposable Office sandbox with approved telemetry and controlled networking. Compare observed process trees, file and registry writes, and network attempts with the static findings.
5. Record a finding as expected business behavior, suspicious, confirmed malicious or inconclusive. Preserve the reasons, reviewed document hash, rule-pack version and reviewer identity. Route inconclusive material evidence for further review.

## Exceptions and audit

Use a document-specific exception for expected business behavior where local policy permits. Bind it to the SHA-256, affected rule IDs, approving reviewer, owner, use case, restrictions and expiry. Require a new decision for changed content or newly observed behavior. Preserve the original matches in the audit record. Resolve incomplete coverage and VBA integrity holds through reinspection or security escalation before signing.

Keep signing and release decisions bound to the approved bytes. Where signing changes the container, retain the pre-signing and signed hashes and verify the signer and intended output. Protect the rule and policy repository with review and pin the approved rule-pack commit in the CI pipeline.

## Worked examples

| Evidence | Disposition before human decision |
| --- | --- |
| `Workbook_Open` performs formatting. It produces an informational hit and all other required coverage is complete. | Eligible for standard approval if prerequisites are met. |
| A signed business workbook uses Outlook automation to send report attachments. | Review the target recipients, data and business approval even if the behavior is expected. |
| No VBA source findings, but compiled instructions conflict with the same module's source. | High-risk hold. |
| No findings, but the extractor could not read an embedded child workbook. | Incomplete hold. |
| HTTP response body, save-to-file and VBA shell launcher in a module. | High-risk hold under the compound execution-chain rule. |

## Office endpoint policy

Maintain endpoint controls for released documents. Restrict macro execution to users with a business need, require an approved signing and trust process, block macros from internet-originating files under the applicable Office policy, and restrict write access to trusted locations. Document any permitted XLM workflows separately. Review the applicable Microsoft Defender ASR rules for Office child processes, executable content and Win32 API calls according to the organisation's deployment policy. Use the official configuration references for product and version differences.

- [Microsoft guidance on internet-originating macros](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked) and [trusted publishers](https://learn.microsoft.com/en-us/microsoft-365-apps/security/trusted-publisher).
- [Microsoft Defender attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) and [Microsoft guidance on Excel 4.0 macro settings](https://support.microsoft.com/en-us/excel/working-with-excel-4-0-macros).
