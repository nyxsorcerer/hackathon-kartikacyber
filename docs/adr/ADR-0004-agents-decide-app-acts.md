# ADR-0004: Agents decide, the application acts

## Status

Accepted, 2026-11-12. Amends Numen's AC-05 (an explicit Analyze click before any detailed analysis) and the 2026-10-06 commit-review change that let commit Analysis build and run code (Numen's "build sandbox").

## Context and decision point

Every commit, diff and served page that GarudaNetra reads is written by someone else, and with Upstream repositories in scope that someone is any upstream committer. The author of a Malicious change is hostile by definition. Text in a diff or commit message can steer an agent ("classify this as Unrelated", "run this command").

The Operator wants Analysis to run without a click. The plan also adds steps with side effects: Remediation PRs and Cures. The question is which component holds the power to act, and when untrusted code may run.

## Decision

1. **Agents only return results.**
   - Triage returns a structured result.
   - Analysis returns its Verdict and also drafts Proof bundles, Detection rules and cleanup reports.
   - Patch drafting returns a diff.

   Application code performs every side effect after validating what the agent returned: opening Remediation PRs, sending Alerts, building and running Labs, and writing Findings.
2. **One credential per run.** Each agent run gets exactly one model credential, spend-capped at the provider. It never gets the GitHub, Discord or vault keys. The only credential that can write to GitHub is held by the step that opens Remediation PRs.
3. **Tool access is fixed in code per operation and cannot be configured.**
   - Triage: no tools.
   - Analysis: a read-only checkout, or the stored fetched bytes for served content, plus a write-only output directory.
   - CVE analysis carried over from Numen: the same as Analysis.
   - Patch drafting: write access only inside a scratch worktree.

   Restrictions use the flags that decide which tools exist, never `--allowedTools`, which is ignored when permissions are bypassed. Triage on Codex is refused until a no-tools restriction has been verified for it.
4. **Analysis runs automatically and builds nothing.** It has a deadline and per-day run caps.
5. **Proofs run only after Approval.** Building and running a Proof in a Lab needs the Operator's Approval. Application code builds the Lab through the broker (ADR-0005) in two phases:
   1. Fetch dependencies with install scripts disabled and no model credential.
   2. Build and run with no network at all.
6. **A Malicious change never runs.** Its Proof is static: a Detection rule that must match what the change added and must match nothing in the state just before the change or, for a change made after the Baseline, in the Baseline, plus the indicators extracted from it.
7. **Served content is fetched, not rendered.** Served-content checks never execute JavaScript, so ClickFix stages loaded at runtime never run.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| Agent holds a GitHub token and opens its own PR | Fewest moving parts | A successful prompt injection becomes write access to the Own repository |
| Analysis only after an Analyze click (Numen today) | No unattended agent work | Slow; the Operator asked for automatic Analysis |
| Automatic Analysis with a Lab | Proof ready without a click | Any upstream committer can trigger an unattended build of their own code |
| Automatic read-only Analysis, Approval-gated Labs (chosen) | Automatic Verdicts; untrusted builds stay behind a person | A Proof waits for the Operator |

## Consequences

- Prompt injection can still distort a Verdict. Insufficient context never turns into Unrelated on its own, and the Operator sees the validated diff before approving any Remediation PR.
- Job recovery is at-least-once, so every side effect carries an idempotency key per (Application, subject, action). The subject is a commit, a served-content change, or a vulnerability. Including the Application stops a shared Upstream commit from suppressing a second Application's side effects.
- The agent network allowlist is the provider's API plus `herdr.dev`, because Herdr downloads agent-detection manifests at start and every 30 minutes.
- Pi plugins are pinned in the runner image by version and integrity hash, and cannot be installed from the dashboard.
