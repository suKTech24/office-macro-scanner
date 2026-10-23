# Microsoft Offfice Macro Security Automation

## Overview

This document outlines a high-level architecture for managing, analysing, and signing Microsoft Office macros (VBA and Excel 4.0/XLM) using GitHub and GitHub Actions. It combines static code analysis, headless emulation ("somewhat dynamic" analysis), peer review of extracted source code, and automated digital signing. It is framework-neutral: see [Security Framework Alignment](#security-framework-alignment) for how each control maps to NIST SSDF, CIS Controls, NIST SP 800-53, ISO/IEC 27001, ASD Essential Eight and UK NCSC guidance.

---

## High-Level Architecture

```mermaid
flowchart TD
    subgraph Dev["1. Authoring & Submission"]
        A["Developer / Analyst commits<br/>.xlsm / .docm or .bas / .cls"] --> B["Open Pull Request in GitHub"]
    end

    subgraph CI["2. GitHub Actions: CI Analysis Pipeline (Pull Request)"]
        B --> C["Unpack & Diff Stage<br/>Extract vbaProject.bin to plain text (.bas/.cls)<br/>Post readable code diff to PR"]
        C --> D["Static Analysis Gate"]
        C --> E["Dynamic / Emulation Gate"]

        subgraph Static["Static Checks (Ubuntu Runner)"]
            D --> D1["oletools (olevba / mraptor)<br/>Flag AutoExec, Shell, COM objects"]
            D --> D2["YARA Rules<br/>Block Win32 APIs, PowerShell, URLs"]
            D --> D3["Secret & Quality Scan<br/>Gitleaks (creds/paths) + Linting"]
        end

        subgraph Dynamic["'Somewhat Dynamic' Checks"]
            E --> E1["Headless Emulation<br/>ViperMonkey / XLMMacroDeobfuscator<br/>(Deobfuscate & trace calls)"]
            E --> E2["Optional: Sandbox Detonation<br/>Submit via API to CAPE / Ephemeral VM<br/>(Monitor Sysmon / network / child procs)"]
        end

        D1 & D2 & D3 & E1 & E2 --> F{"Security & Policy<br/>Checks Pass?"}
    end

    subgraph Review["3. Human Governance"]
        F -- "No (Flagged)" --> G["Block Merge<br/>Attach SARIF / Report to PR"]
        F -- "Yes (Clean)" --> H["Peer Code Review<br/>Approve readable .bas diff"]
    end

    subgraph CD["4. GitHub Actions: CD Release & Signing (Merge to Main)"]
        H --> I["Compile / Package Document<br/>(If built from raw .bas/.cls)"]
        I --> J["Digital Signing (Windows Runner)<br/>Sign VBA project via Azure Key Vault / Cert<br/>(Trusted-publisher macro policy)"]
        J --> K["Publish GitHub Release<br/>Signed Document + SHA-256 + Audit Log"]
    end
```

Flagged builds are blocked at the PR. Only clean, peer-approved code reaches signing and release.

## Stage-by-Stage Breakdown

| Stage | Purpose | Key Tools | Output / Gate |
| :--- | :--- | :--- | :--- |
| **1. Unpack & Normalise** | Make binary macros (`vbaProject.bin`) human-readable in Git so reviewers can inspect exact line changes. | `oletools` (`olevba`), `vbaProject` extractor | Plain-text `.bas`/`.cls`/`.frm` files committed or posted as a PR comment/artifact. |
| **2. Static Analysis** | Catch known dangerous capabilities, hardcoded secrets, and policy violations immediately. | `olevba`, `mraptor`, **YARA**, `gitleaks`, Rubberduck VBA | Pass/Fail status check; flags `WScript.Shell`, `Shell()`, Win32 `Declare` statements, DDE, and credentials. |
| **3. Somewhat Dynamic Analysis** | Resolve runtime string obfuscation (`Chr()`, `Environ()`) and trace execution behaviour without manual testing. | **ViperMonkey**, **XLMMacroDeobfuscator**, or Sandbox API (CAPE/Tria.ge) | Execution trace showing resolved strings, file writes, or network/process calls. |
| **4. Peer Review (PR Gate)** | Ensure a second pair of eyes verifies business logic and approves any justified exceptions. | GitHub Branch Protection + `CODEOWNERS` | Mandatory approval from Security/Engineering before merge is unlocked. |
| **5. Signing & Release** | Guarantee integrity and satisfy endpoint policies that run only macros signed by trusted publishers. | `signtool.exe` + MS Office SIP + Azure Key Vault | Digitally signed `.xlsm`/`.docm` published to GitHub Releases with an immutable audit trail. |

---

## Detailed Capabilities

### 1. Repository Structure: Source vs Binary

Office documents (`.xlsm`, `.docm`, `.dotm`) are ZIP containers storing macros inside a compiled binary (`vbaProject.bin`). Because Git cannot natively diff `vbaProject.bin` for code review:

- **Extract source automatically:** Use a pre-commit hook or GitHub Action (`olevba`) to unpack VBA source (`.bas`, `.cls`, `.frm`) into the PR for human review, and verify the binary matches the unpacked source.
- **Build on release:** Optionally use a Windows runner to compile the `.bas`/`.cls` files into the template document during the CD phase prior to signing.

### 2. Static Analysis in GitHub Actions

Runs on standard `ubuntu-latest` or `windows-latest` runners on every Pull Request:

- **Capability & Indicator Scanning (`oletools`):**
  - `olevba` and `mraptor` detect auto-execution triggers (`AutoOpen`, `Document_Open`), suspicious COM objects (`WScript.Shell`, `Scripting.FileSystemObject`), PowerShell/cmd execution, Base64/hex obfuscation, and DDE links.
  - `msodde` and `pyxswf` check for DDE injection or embedded Flash/OLE objects.
- **YARA Policy Enforcement:**
  - Run custom YARA rules against both the container document and extracted streams to enforce organisational policy (e.g. blocking `URLDownloadToFile`, Win32 API declarations like `VirtualAlloc`, or raw socket calls).
- **Secret Scanning & Linting:**
  - Scan extracted `.bas` files with `gitleaks` or GitHub Secret Scanning to catch hardcoded credentials, API keys, or internal file share paths.
  - Use Rubberduck VBA or custom regex checks to enforce coding standards (`Option Explicit`, error handling).

### 3. "Somewhat Dynamic" Analysis Options

Because GitHub-hosted runners do not include licensed Microsoft Office installations and GUI automation is brittle, dynamic analysis can be tiered:

- **Option A: VBA/XLM Emulation (Headless Linux/Windows Runners)**
  - **ViperMonkey:** Parses and symbolically executes VBA code without Office installed. Deobfuscates strings, traces execution paths on `AutoOpen`, and logs called APIs/shell commands.
  - **XLMMacroDeobfuscator:** Emulates Excel 4.0 (XLM) macros to resolve obfuscated formula chains.
- **Option B: Sandbox API Integration (Cloud Runners)**
  - Submit the compiled `.docm`/`.xlsm` via API from GitHub Actions to an external or self-hosted detonation sandbox (e.g. **CAPE Sandbox**, **Cuckoo**, **Tria.ge**, or **Joe Sandbox**).
  - Fail the PR if the behavioural report detects unexpected child processes, network connections, or file system modifications.
- **Option C: Self-Hosted Ephemeral Windows Runner**
  - Use an isolated, ephemeral VM with Microsoft Office and Sysmon/ETW logging enabled.
  - Launch the document headlessly via PowerShell COM (`New-Object -ComObject Word.Application`), capture ETW/Sysmon telemetry, and tear down the VM after execution.

---

## Security Framework Alignment

The pipeline enforces one rule: a macro may run only if it passed automated analysis and peer review and was signed with a protected organisational key.

- **Endpoint Requirement:** Only signed macros from trusted publishers are allowed to execute; macros must be vetted for malicious indicators before signing.
- **Pipeline Enforcement:** Developers never hold the code-signing certificate directly. The signing key resides in a key service (e.g. Azure Key Vault) and is **only** used by the CD workflow *after* automated static/dynamic checks pass and a designated `CODEOWNER` approves the plain-text code diff.

The table maps each pipeline control to common frameworks.

| Pipeline control | NIST SSDF (SP 800-218) | CIS Controls v8 | NIST SP 800-53 Rev 5 | ISO/IEC 27001:2022 | ASD Essential Eight | UK NCSC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Endpoints run only macros signed by trusted publishers | — | 2.7 Allowlist authorised scripts | CM-7, CM-14 | A.8.19 | Macro settings (ML2–3) | CE Secure configuration; Macro Security steps 5–6 |
| Automated malware and indicator scanning | PW.7, PW.8 | 10 Malware defences | SI-3 | A.8.7 | Macros vetted before signing | CE Malware protection |
| Peer review of readable source before merge | PW.7 | 16 Application software security | CM-3, CM-4 | A.8.28, A.8.32 | — | SSCoP 1.1, 1.3 |
| Signing key held in a key service, used only by CD | PS.1 | — | SC-12, SI-7 | A.8.24 | — | SSCoP 2.1, 2.2 |
| Signed release with SHA-256 and audit log | PS.2, PS.3 | — | SI-7, AU-10 | A.8.25 | — | SSCoP 3.1 |

UK NCSC sources: **CE** = [Cyber Essentials Requirements for IT Infrastructure v3.3](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) (in effect from 27 April 2026); **Macro Security** = [NCSC Macro Security for Microsoft Office](https://www.ncsc.gov.uk/guidance/macro-security-for-microsoft-office); **SSCoP** = [Software Security Code of Practice](https://www.gov.uk/government/publications/software-security-code-of-practice/software-security-code-of-practice).

NCSC notes that Office has no setting to allow only macros signed by a specific list of publishers: "only digitally signed macros" accepts any valid signature. NCSC prefers restricting macros to trusted locations, so pair signing with trusted locations or a trusted-publisher policy.

The pipeline helps meet these controls; it does not by itself make an organisation compliant.

---

## Implementation Notes

This document is **a proposal, not a deployed or verified pipeline**. Before implementation:

- Verify the control IDs in the framework table against the current version of each framework.
- Confirm the Office VBA-project signing mechanism and certificate/key integration: `signtool.exe` alone should not be assumed to sign VBA projects correctly.
- Keep signing private keys in a controlled key service rather than storing private-key material in GitHub Secrets.
- Run untrusted documents only in an isolated detonation environment, never on a general-purpose CI runner; Office COM automation does not itself guarantee macro execution.
- Treat sandbox results and source-to-binary correspondence as validation gates requiring explicit implementation and testing.
