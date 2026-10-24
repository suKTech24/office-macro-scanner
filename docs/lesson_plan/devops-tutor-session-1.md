# DevOps Tutor Session 1: Preparing for the Macro Security Pipeline

**Project in one sentence:** a GitHub-based pipeline that extracts VBA macros from Office files, scans them automatically on every pull request, requires human review, then signs approved macros with a protected certificate so company computers only run signed macros.

**My starting point:** new to Office macros, Git, GitHub Actions and CI/CD. I have read [study-notes.md](../study-notes.md) and [devsecops-principles.md](../devsecops-principles.md) and have the [build guide](../design-and-build-guide.md) as my roadmap.

**Goal for this session:** leave able to build Phases 0–2 of the build guide on my own: a protected repository, and a GitHub Actions workflow that runs a Python scan on every pull request and blocks the merge when it fails.

---

## 1. Priorities (if time is short)

Ask in this order. Topics 1–4 are the must-haves; 5–8 can move to a later session.

| # | Topic | Why I need it | Build guide phase |
| :--- | :--- | :--- | :--- |
| 1 | Git fundamentals and branching | Everything else depends on it | 0 |
| 2 | Pull requests, branch protection / rulesets, required checks | This is the "gate" in the project | 0, 2, 5 |
| 3 | GitHub Actions basics: workflow YAML, triggers, jobs, steps, runners | Runs all the automated checks | 2 |
| 4 | Running Python tools in CI, exit codes, artifacts | How a scan pass/fail becomes a red/green check | 2 |
| 5 | Workflow security: permissions, secrets, `pull_request` vs `pull_request_target`, pinning actions | Pipeline must not be the weak point | 2, 8 |
| 6 | Environments with approvals, OIDC to Azure | Protects the signing step | 7, 8 |
| 7 | Testing and debugging workflows (logs, re-runs, `act`) | I will get stuck here often | All |
| 8 | Repo hygiene: `.gitattributes`, pre-commit hooks, CODEOWNERS | Clean diffs and correct reviewers | 1, 5 |

---

## 2. Topics and questions to ask

### Topic 1: Git fundamentals

Ask the tutor to teach:
- The mental model: working directory, staging area, commits, branches, remote.
- Daily commands: `clone`, `status`, `switch -c`, `add`, `commit`, `push`, `pull`, `log`, `diff`.
- How to undo mistakes safely (`restore`, `revert`, and when *not* to use `reset --hard` or force push).
- Merge vs rebase, and which to use for a small team.

Questions:
- "What branching strategy would you use for a small security tool? Is trunk-based development right here?"
- "How should I handle binary files like `.xlsm` in Git? Do I need Git LFS?"
- "What makes a good commit message and a good-sized PR?"

### Topic 2: Pull requests and protecting `main`

Ask the tutor to teach:
- Opening, reviewing and merging a PR.
- Branch protection vs **rulesets**: which to use now.
- Required status checks, required approvals, dismissing stale approvals, blocking bypass.
- CODEOWNERS: how it assigns reviewers and how "require review from code owners" works.

Questions:
- "Can you show me how to set up a ruleset so nothing reaches `main` without a passing check and an approval?"
- "How do I stop admins (including me) bypassing the rules?"
- "Why doesn't a required check appear in the list until it has run once?"

### Topic 3: GitHub Actions basics

Ask the tutor to teach, ideally by writing one workflow together:
- Where workflows live (`.github/workflows/`) and the YAML structure.
- Events: `pull_request`, `push`, `workflow_dispatch`; filtering by `branches` and `paths`.
- Jobs, steps, `runs-on`, `uses:` vs `run:`, `with:`, `needs:`, `if:`.
- GitHub-hosted runners vs self-hosted runners.
- Reading logs and re-running failed jobs.

Questions:
- "Can we write a minimal workflow that runs `python --version` on every PR, then extend it?"
- "When should logic live in a script file instead of inline in YAML?"
- "How do I run the same job on Linux and Windows (matrix), and do I need that?"

### Topic 4: Python tools in CI

Ask the tutor to teach:
- `actions/setup-python`, installing from `requirements.txt`, caching pip.
- How exit codes decide pass/fail; making a script fail the job deliberately.
- Uploading artifacts (reports) with `if: always()` so they survive failures.
- Uploading SARIF so findings appear on the PR (and what it needs on private repos).

Questions:
- "My scan script returns 1 on findings and 2 on errors. Is that a good convention? How do I show the difference in the PR?"
- "How should I pin Python package versions for a security tool?"
- "How do I test the script locally so CI is not my only test loop?"

### Topic 5: Workflow security

Ask the tutor to teach:
- `permissions:` and the `GITHUB_TOKEN`; least privilege per job.
- Secrets vs variables; why forked PRs don't get secrets.
- The danger of `pull_request_target`.
- Script injection from `${{ github.event... }}` values, and the `env:` fix.
- Pinning actions to commit SHAs; Dependabot for updates.

Questions:
- "What are the most common ways GitHub Actions pipelines get compromised?"
- "Walk me through hardening a workflow line by line."
- "How do you review a third-party action before trusting it?"

### Topic 6: Environments and cloud identity (OIDC)

Ask the tutor to teach:
- GitHub **environments**: required reviewers, branch restrictions, environment secrets and variables.
- **OIDC**: how a workflow gets a short-lived Azure token with no stored password.
- Federated credential subjects (e.g. `repo:<org>/<repo>:environment:signing`).
- Keeping CI (untrusted PRs) and CD (trusted `main`) fully separate.

Questions:
- "How would you design the release workflow so only `main`, after approval, can use the signing key?"
- "Have you set up `azure/login` with OIDC? What usually goes wrong?"
- "Is Azure Key Vault a sensible place for a code-signing key, or would you suggest something else?"

### Topic 7: Testing and debugging pipelines

Ask the tutor to teach:
- Reading failed logs efficiently; enabling debug logging.
- Running workflows locally with `act`, and its limits.
- Testing a workflow change on a branch before relying on it.
- Writing `pytest` tests for pipeline scripts and running them in CI.

Questions:
- "What is your debugging routine when a workflow fails and the log is not clear?"
- "How do you test a change to a workflow that only runs on `main`?"

### Topic 8: Repo hygiene

Ask the tutor to teach:
- `.gitattributes` for line endings and binary files.
- The `pre-commit` framework and local hooks.
- CODEOWNERS patterns and team-based ownership.
- `README`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` for an open-source project.

Questions:
- "Which licence would you choose for an open-source security tool?"
- "What should be in `SECURITY.md`?"

---

## 3. Hands-on exercises to do together

Doing these with the tutor is worth more than any explanation. Each one is a real piece of the project.

1. **Create the repository** and push the docs and spec.
2. **Protect `main`** with a ruleset: PR required, 1 approval, no force push.
3. **First workflow:** on `pull_request`, check out, set up Python, run `python --version`.
4. **Make it fail on purpose:** add a step `run: exit 1`, open a PR, see the red check, then fix it.
5. **Add a required status check** and confirm the PR cannot merge while it fails.
6. **Run a real tool:** `pip install oletools`, run `olevba --help`, then `olevba` on a harmless test `.xlsm`.
7. **Upload an artifact** and download it from the run page.
8. *(Stretch)* Add `CODEOWNERS` and see the reviewer auto-assigned.

---

## 4. What to prepare before the session

- [ ] GitHub account ready; know whether I will use a personal account or an organisation.
- [ ] Installed: Git, VS Code, Python 3.12, GitHub CLI (`gh auth login` done). See build guide section 4.3.
- [ ] A harmless test document `test.xlsm` with one module (`Sub Hello(): MsgBox "Hi": End Sub`).
- [ ] This file and the build guide open so the tutor can see the target architecture.
- [ ] One sentence ready on the project's purpose (top of this page).
- [ ] Decide the project name (current favourite: MacroGate / `office-macro-gate`).

---

## 5. Things to show the tutor and ask for feedback on

- The architecture diagram in the [build guide, section 1.1](../design-and-build-guide.md#11-components).
- The CI workflow sketch in Phase 2 and the release workflow sketch in Phase 8.

Questions:
- "Is this architecture reasonable, or over-engineered for a first version?"
- "What would you cut for a minimum viable version?"
- "What would you do differently from a DevOps point of view?"

---

## 6. After the session

- [ ] Write down the three most important things I learned.
- [ ] Complete any exercise we did not finish.
- [ ] Tick off build guide Phases 0–2 in the [milestone checklist](../design-and-build-guide.md#10-milestone-checklist).
- [ ] Note open questions for the next session.

### Suggested later sessions

| Session | Focus |
| :--- | :--- |
| 2 | Workflow security hardening, secret scanning, pre-commit, CODEOWNERS (Phases 3, 5) |
| 3 | Environments, OIDC, Azure Key Vault, release workflow (Phases 7, 8) |
| 4 | Self-hosted Windows runner and build from source (Phase 9); endpoint policy with IT (Phase 10) |
| 5 | Testing the pipeline, metrics, open-source readiness |

---

## 7. Notes

_Space for notes during the session._
