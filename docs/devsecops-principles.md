# DevSecOps Principles for This Project

This document explains the DevSecOps ideas, patterns and coding practices behind the macro pipeline. Each section says what the idea is, why it matters, and exactly where it shows up in this project.

Read it after [study-notes.md](study-notes.md) Parts 3–4 (Git and GitHub Actions), and keep it open while following [design-and-build-guide.md](design-and-build-guide.md).

## Contents

1. [What DevSecOps is](#1-what-devsecops-is)
2. [Core principles](#2-core-principles)
3. [Pipeline patterns](#3-pipeline-patterns)
4. [Software supply chain security](#4-software-supply-chain-security)
5. [Secrets and identity](#5-secrets-and-identity)
6. [Threat modelling](#6-threat-modelling)
7. [Coding design for pipeline tools](#7-coding-design-for-pipeline-tools)
8. [Testing the pipeline](#8-testing-the-pipeline)
9. [Git workflow and code review](#9-git-workflow-and-code-review)
10. [Feedback, metrics and continuous improvement](#10-feedback-metrics-and-continuous-improvement)
11. [Documentation as part of the system](#11-documentation-as-part-of-the-system)
12. [Anti-patterns to avoid](#12-anti-patterns-to-avoid)
13. [Principle-to-project map](#13-principle-to-project-map)
14. [Further reading](#14-further-reading)

---

## 1. What DevSecOps is

**DevOps** joins development (writing software) and operations (running it) so changes ship quickly and reliably through automation. **DevSecOps** adds security into that same flow, instead of a separate security team checking things at the end.

| Old model | DevSecOps model |
| :--- | :--- |
| Security review happens once, just before release | Security checks run on every change |
| Security team is a gate others wait on | Security is encoded as automated checks everyone can see and run |
| Findings arrive late and are expensive to fix | Findings appear in the pull request, minutes after the change |
| Rules live in documents and people's heads | Rules live in version-controlled code (YARA rules, policies, workflows) |
| "Trust the person" | "Trust the process, verify every step" |

**In this project:** a macro author gets automated security feedback on their PR, a reviewer approves with evidence in front of them, and signing happens automatically only when every gate has passed. Nobody needs to email the security team and wait.

### The CALMS model

A common way to describe DevSecOps culture:

| Letter | Meaning | In this project |
| :--- | :--- | :--- |
| **C**ulture | Shared responsibility for security | Authors, reviewers and security all see the same check results. |
| **A**utomation | Machines do repeatable checks | GitHub Actions runs extraction, scanning, signing. |
| **L**ean | Small changes, fast feedback | One macro change per PR; results in minutes. |
| **M**easurement | Track what happens | Findings, false positives, time to merge (section 10). |
| **S**haring | Knowledge is open | Rules, exceptions and docs live in the repo. |

---

## 2. Core principles

### 2.1 Shift left

Find problems as early as possible, where they are cheapest to fix.

```text
 Author PC        Pull request        Merge        Release        Endpoint
 (pre-commit) --> (CI checks)  -->  (review) --> (signing) --> (policy)
 cheapest fix  <--------------------------------------------- most expensive
```

**In this project:** the pre-commit hook extracts source before the commit; CI scans on the PR, not after release.

### 2.2 Shift right (also)

Some problems only appear in real use. Watch production too.

**In this project:** endpoint policy blocks unsigned macros in real use, and audit logs show what was released and run. Phase 10 of the build guide pilots with one team before full rollout.

### 2.3 Defence in depth

Never rely on one control. Stack independent layers so one failure is caught by another.

**In this project:** static analysis, emulation, optional detonation, human review, signing, and endpoint policy. A macro that fools YARA still needs a reviewer's approval, and an unsigned one still cannot run.

### 2.4 Least privilege

Every person, workflow and token gets only the access it needs, only for as long as it needs it.

**In this project:**
- Workflows declare `permissions:` explicitly (`contents: read` by default).
- Only the release job gets `id-token: write` and `contents: write`.
- The Azure identity can sign with one key in one vault, nothing else.

### 2.5 Separation of duties

No single person can both make and approve a risky change.

**In this project:** the author cannot approve their own PR; CODEOWNERS requires a different reviewer; security owns `rules/`, `tools/`, `.github/` and `exceptions.yml`; no human holds the signing key.

### 2.6 Fail closed (secure by default)

When something goes wrong (a tool crashes, a file is missing, a network call fails) the result must be **deny**, not allow.

**In this project:** `scan.py` returns non-zero when no YARA rules are found; signing failures throw; required status checks block merge if a job never ran.

### 2.7 Zero trust for inputs

Treat every input as potentially hostile, including files from colleagues.

**In this project:** documents are parsed by tools that never execute them on CI; detonation only happens in an isolated sandbox; PR titles and branch names are never pasted directly into shell commands.

### 2.8 Everything as code

If it matters, it is a file in Git: reviewed, versioned, and reproducible.

| What | As code |
| :--- | :--- |
| Pipeline | `.github/workflows/*.yml` |
| Security policy | `rules/*.yar` |
| Exceptions | `exceptions.yml` |
| Who approves what | `.github/CODEOWNERS` |
| Repo hygiene | `.gitattributes`, `.pre-commit-config.yaml` |
| Design decisions | ADRs in the build guide |

### 2.9 Automation over manual process

Humans are good at judgement, bad at repetition. Automate the repetitive checks; reserve human attention for "is this change appropriate for the business?".

### 2.10 Auditability and evidence

Every decision leaves a trace: who changed what, which checks ran, who approved, what was signed, its hash. An auditor (or you, during an incident) should be able to reconstruct the history of any released macro.

---

## 3. Pipeline patterns

### 3.1 Pipeline as code

Workflows are YAML files in the repository, changed through PRs like any other code.

Why: you can review pipeline changes, roll them back, and see when a check was added or removed.

### 3.2 Quality gates

A **gate** is a point the change cannot pass until a condition is met.

| Gate | Condition | Enforced by |
| :--- | :--- | :--- |
| Consistency | Committed source matches the document | `extract_vba.py --check` |
| Security scan | No error-level findings (or approved exception) | `scan.py`, required status check |
| Secrets | No credentials found | gitleaks step |
| Review | A CODEOWNER approved the latest commit | Branch ruleset |
| Release approval | A release approver approved the deployment | `signing` environment |

Gates must be **required**, not advisory. A check that can be ignored is a suggestion.

### 3.3 Policy as code

Security rules are written in a machine-readable language, stored in Git, and evaluated automatically.

**In this project:** YARA rules express "macros may not download files" or "macros may not declare Win32 APIs". Changing policy means a PR to `rules/`, reviewed by security, with history.

Larger organisations use dedicated engines such as Open Policy Agent (OPA) for this pattern across many systems.

### 3.4 Separate CI and CD with a trust boundary

- **CI** runs on untrusted input (any PR), with no secrets and read-only permissions.
- **CD** runs only on trusted input (`main` after review), with access to the signing key.

Never mix the two: a workflow that analyses a PR must not be able to sign.

### 3.5 Build once, promote the same artifact

What you tested should be exactly what you release. If you rebuild between test and release, you might ship something different.

**In this project:** the release workflow re-scans the same commit it signs, and records the commit SHA and file hashes in the release. Phase 9 (build from source) applies this pattern fully: the reviewed text becomes the released binary.

### 3.6 Immutable artifacts

Once released, an artifact never changes. A fix is a new version.

**In this project:** each release is tagged `v<run number>`, with `SHA256SUMS.txt`. A signed document with different contents would have a different hash.

### 3.7 Ephemeral, disposable environments

Build machines are created fresh for each job and destroyed after, so nothing persists between runs for an attacker to tamper with.

**In this project:** GitHub-hosted runners are ephemeral by default. A self-hosted runner (Phase 9) should be reset to a clean snapshot after each job.

### 3.8 Fast feedback, then deeper checks

Put fast, cheap checks first so authors get answers in seconds; run slow, expensive ones later or less often.

**In this project:** consistency check and olevba first (seconds); emulation next; sandbox detonation last, or nightly.

### 3.9 Exception management (break glass, with a paper trail)

Real systems need exceptions. Make them explicit, owned, time-limited and reviewed, rather than letting people bypass the pipeline.

**In this project:** `exceptions.yml` entries have a reason, approver and expiry; expired entries fail the build.

---

## 4. Software supply chain security

Your pipeline depends on other people's code: GitHub Actions, Python packages, Docker images, Office SIP. If any of them is compromised, so is your pipeline.

| Practice | What it means | In this project |
| :--- | :--- | :--- |
| **Pin dependencies** | Use exact versions, not "latest" | Pin actions to commit SHAs, `requirements.txt` to versions, Docker images to tags or digests. |
| **Verify downloads** | Check hashes of anything downloaded | Check the Office SIP package's SHA-256 before installing. |
| **Update deliberately** | Updates arrive as reviewed PRs | Enable Dependabot for actions and pip; security reviews each update. |
| **Minimise dependencies** | Fewer moving parts, smaller attack surface | Prefer standard library and well-known tools. |
| **Provenance** | Record how and where an artifact was built | Release notes include the commit SHA; consider build provenance attestations. |
| **SLSA** | A framework of levels for build integrity | Use it as a maturity target: scripted build → hosted build with provenance → hardened, isolated build. |
| **SBOM** | Software Bill of Materials: list of components | Less central here, but you can list tool versions used for each release. |

---

## 5. Secrets and identity

| Principle | Practice |
| :--- | :--- |
| No long-lived secrets where avoidable | Use **OIDC federation** so workflows get short-lived Azure tokens. |
| Scope identities tightly | Federated credential subject tied to `environment:signing` of one repo. |
| Keys never leave secure hardware | HSM-backed, non-exportable key in Key Vault. |
| Secrets never in code | gitleaks in CI; `.gitignore` for local files like `.pfx`. |
| Secrets never in logs | Use `--redact`; never `echo` a token; GitHub masks registered secrets but not derived values. |
| Rotate and revoke | Planned certificate renewal; documented response if a key is suspected compromised. |

---

## 6. Threat modelling

**Threat modelling** means asking, before and during building: *what could go wrong, and what will we do about it?*

A simple four-question method:

1. What are we building? (Architecture diagram, trust boundaries: build guide section 1.)
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good job? (Tests in build guide section 7.)

### STRIDE

A checklist for question 2. Applied to this pipeline:

| Threat type | Meaning | Example here | Mitigation |
| :--- | :--- | :--- | :--- |
| **S**poofing | Pretending to be someone else | Attacker's workflow pretends to be the release workflow to get a token | OIDC subject bound to `environment:signing`; environment restricted to `main`. |
| **T**ampering | Changing data or code | Editing the binary without updating `src/`; VBA stomping | Consistency check; stomping detection; build from source. |
| **R**epudiation | Denying an action | "I never approved that macro" | PR approvals, audit logs, signed commits (optional). |
| **I**nformation disclosure | Leaking data | Uploading confidential documents to a public sandbox; secrets in code | Private sandbox only; gitleaks. |
| **D**enial of service | Making the system unusable | Huge or malformed documents crash or stall scanners | Job timeouts; fail closed; file size limits. |
| **E**levation of privilege | Gaining more access | PR modifies the workflow to access the signing key | CI has no secrets; CODEOWNERS on `.github/`; separate CD workflow. |

Revisit the threat model whenever the architecture changes (e.g. adding a sandbox or a self-hosted runner).

---

## 7. Coding design for pipeline tools

The scripts in `tools/` are security controls. Write them to be simple, predictable and testable.

### 7.1 Small, single-purpose tools

Each script does one job and can be run on its own:

- `extract_vba.py`: document → text.
- `scan.py`: documents + rules → findings.

This follows the **Unix philosophy**: small tools combined by the pipeline. Each can be tested and replaced independently.

### 7.2 A clear contract: inputs, outputs, exit codes

| Element | Convention |
| :--- | :--- |
| Inputs | Explicit command-line arguments (`documents`, `rules`), no hidden global state. |
| Outputs | Machine-readable file (SARIF, JSON) plus a human-readable log. |
| Exit code `0` | Success, nothing blocking. |
| Exit code `1` | Policy failure (blocking findings, mismatch). |
| Exit code `2+` | Tool or configuration error (missing rules, unreadable file). |

CI only understands exit codes, so they are the most important part of the contract.

### 7.3 Fail closed in code

```python
# Good: missing configuration is an error
if not rule_files:
    print("No YARA rules found")
    return 2

# Bad: silently scanning with no rules looks like a clean pass
rules = yara.compile(filepaths=rule_files or {})
```

Also: do not wrap everything in `try/except: pass`. An unexpected exception should fail the job.

### 7.4 Deterministic and idempotent

- **Deterministic:** same input → same output. Sort file lists (`sorted(...)`), normalise line endings, avoid timestamps in outputs that are compared.
- **Idempotent:** running twice changes nothing the second time. `extract_vba.py` overwrites with identical content, so `git diff` stays clean.

### 7.5 Separate policy from mechanism

- **Mechanism** (how to scan) lives in `tools/`.
- **Policy** (what is forbidden, what is excepted) lives in `rules/` and `exceptions.yml`.

Security can change policy without touching code, and code changes do not silently change policy.

### 7.6 Configuration over hard-coding

Paths, severities and thresholds come from arguments or config files, not constants buried in code, so the same tool works locally, in CI, and in tests.

### 7.7 Structured, standard output formats

Use standards (SARIF for findings, SHA-256 checksum files for releases) so other tools can consume results without custom parsing.

### 7.8 Safe handling of untrusted data

- Parse, never execute, documents in CI.
- Treat extracted strings as data: never pass them to `eval`, a shell, or (if you add AI later) an LLM as instructions.
- Set timeouts and size limits for parsing.

### 7.9 Readable over clever

Reviewers must be able to verify these scripts. Prefer clear names, short functions, and comments that explain *why*, not *what*.

### 7.10 Workflow (YAML) design

| Practice | Why |
| :--- | :--- |
| Explicit `permissions:` at workflow and job level | Least privilege |
| `if: always()` on report-upload steps | Evidence is kept even when checks fail |
| Pass untrusted values via `env:`, not `${{ }}` inside `run:` | Prevents script injection |
| Pin actions to SHAs in sensitive workflows | Supply chain safety |
| Set `timeout-minutes:` on jobs | A stuck scan should not hang forever |
| Use `needs:` to order jobs (rescan before sign) | Gates are enforced by structure |
| Keep logic in scripts, not long inline shell | Scripts are testable locally; YAML stays readable |

---

## 8. Testing the pipeline

Security controls need tests like any software. If a rule silently stops matching, you lose protection without noticing.

| Level | What | Example |
| :--- | :--- | :--- |
| **Unit tests** | Individual functions | `to_sarif()` produces valid structure; exception expiry logic. |
| **Rule tests** | Each YARA rule matches what it should and not what it shouldn't | Known-bad snippet matches; clean macro does not. |
| **Integration tests** | Whole scripts on sample documents | `tests/samples/` with expected pass/fail (build guide section 7.1). |
| **Pipeline tests** | GitHub behaviour | Unapproved PR cannot merge; non-`main` cannot reach `signing`. |
| **Negative tests** | Failure handling | Missing rules directory → exit 2; corrupt document → job fails. |

Use `pytest` for Python tests and run them in CI on changes to `tools/` or `rules/`. Optionally use `act` to try workflows locally.

**Regression rule:** every false negative found in real use becomes a new test sample, so it can never silently return.

---

## 9. Git workflow and code review

### 9.1 Branching

Use **trunk-based development**: short-lived feature branches merged into `main` through PRs. `main` is always releasable. Avoid long-running branches that drift.

### 9.2 Small pull requests

One macro change or one pipeline change per PR. Small PRs are reviewed properly; large ones get rubber-stamped.

### 9.3 Meaningful commits

Commit messages explain why: `Block WinHttp in policy after phishing campaign`, not `update`.

### 9.4 What a security-minded reviewer checks

For macro PRs:
- Does the change match the stated business reason?
- Are flagged capabilities (file writes, shell, network) justified and minimal?
- Any hardcoded paths, credentials, hidden content, or obfuscation?
- Does `src/` diff look like what a human wrote?

For pipeline PRs (`.github/`, `tools/`, `rules/`):
- Does this weaken a gate, widen permissions, or add a dependency?
- Are new actions pinned and from trusted publishers?
- Does a rule change have tests?

### 9.5 Signed commits (optional)

Signing commits with SSH or GPG keys proves who made them. Useful for stronger non-repudiation; can be required by a ruleset.

### 9.6 Versioning

Releases need a clear, increasing version. This project uses `v<run number>`; Semantic Versioning (`MAJOR.MINOR.PATCH`) suits it if documents gain a public change history.

---

## 10. Feedback, metrics and continuous improvement

You cannot improve what you do not measure.

| Metric | What it tells you |
| :--- | :--- |
| Time from PR opened to merged | Is the pipeline slowing people down? |
| Pipeline duration | Are checks fast enough to keep authors engaged? |
| Findings per PR, by rule | Which rules fire most; candidates for tuning |
| False positive rate | High rate → people lose trust and seek workarounds |
| Exceptions count and age | Growing list → policy may be unrealistic |
| Unsigned macro blocks on endpoints | Are users hitting macros that never went through the pipeline? |
| Time to fix a flagged issue | How quickly security feedback is acted on |

The four **DORA metrics** (deployment frequency, lead time for changes, change failure rate, time to restore service) are the standard DevOps measures and apply here at small scale.

Hold a short review each month: tune noisy rules, add rules for new threats, retire expired exceptions.

---

## 11. Documentation as part of the system

| Document | Purpose |
| :--- | :--- |
| `office-macro-security-pipeline.md` | Specification: what the system should do |
| `docs/design-and-build-guide.md` | How it is built; ADRs record why |
| `docs/study-notes.md` | Concepts for newcomers |
| `docs/devsecops-principles.md` | This document: how we work |
| PR template | Forces authors to state purpose and justification |
| `CONTRIBUTING.md` (to add) | How to propose a macro or pipeline change |
| `SECURITY.md` (to add) | How to report a vulnerability in the project |

For an open-source project, `SECURITY.md`, a `LICENSE`, and `CONTRIBUTING.md` are expected.

**ADR habit:** whenever you make a design choice with trade-offs, add a short record (context, options, decision, consequences). Future you will need it.

---

## 12. Anti-patterns to avoid

| Anti-pattern | Why it hurts | Instead |
| :--- | :--- | :--- |
| Advisory-only checks | Ignored under deadline pressure | Required status checks |
| Admin bypass of rules | One compromised admin defeats everything | No bypass; break-glass process with audit |
| Signing key as a file in secrets or on a laptop | Can be copied and abused forever | HSM-backed, non-exportable, OIDC-scoped |
| `pull_request_target` with checkout of PR code | Runs untrusted code with secrets | `pull_request` for analysis |
| Unpinned `@main` actions | Upstream compromise flows straight in | Pin to SHAs, update via reviewed PRs |
| Catch-all `try/except: pass` | Hides failures; fails open | Let errors fail the job |
| Too many noisy rules | Alert fatigue; real issues missed | Tune rules, track false positives |
| Permanent exceptions | Policy erodes silently | Expiry dates, monthly review |
| Security team as bottleneck | People route around the process | Self-service checks; clear ownership |
| Scanning but not enforcing on endpoints | Pipeline is bypassed by just not using it | Signed-only macro policy (Phase 10) |

---

## 13. Principle-to-project map

| Principle or pattern | Where in this project | Build guide phase |
| :--- | :--- | :--- |
| Shift left | Pre-commit extraction, PR scanning | 1, 2 |
| Defence in depth | Static + emulation + review + signing + endpoint | 2–10 |
| Least privilege | Workflow `permissions:`, scoped Azure role | 2, 7, 8 |
| Separation of duties | CODEOWNERS, environment approvers, no human key access | 5, 7 |
| Fail closed | Script exit codes, required checks | 2 |
| Everything as code | Workflows, YARA, exceptions, CODEOWNERS | 0–6 |
| Quality gates | Consistency, scan, secrets, review, release approval | 2–8 |
| Policy as code | `rules/*.yar`, `exceptions.yml` | 2, 6 |
| CI/CD trust separation | `macro-ci.yml` vs `macro-release.yml` | 2, 8 |
| Build once, promote | Re-scan same commit; build from source | 8, 9 |
| Immutable artifacts | Versioned releases + SHA-256 | 8 |
| Ephemeral environments | GitHub-hosted runners; reset self-hosted runner | 2, 9 |
| Supply chain security | Pinned actions/packages, verified SIP download | 2, 8 |
| Short-lived identity | OIDC to Azure | 7, 8 |
| Threat modelling | STRIDE table, trust boundaries | Section 1, 8 of guide |
| Testable tools | `tests/samples/`, pytest | Section 7 of guide |
| Continuous improvement | Metrics and monthly review | Section 9 of guide |

---

## 14. Further reading

- OWASP DevSecOps Guideline: <https://owasp.org/www-project-devsecops-guideline/>
- OWASP Top 10 CI/CD Security Risks: <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- GitHub Actions security hardening: <https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- NIST SSDF (SP 800-218): <https://csrc.nist.gov/pubs/sp/800/218/final>
- SLSA: <https://slsa.dev>
- Threat Modeling Manifesto: <https://www.threatmodelingmanifesto.org>
- DORA research: <https://dora.dev>
