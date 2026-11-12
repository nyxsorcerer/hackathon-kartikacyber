# ADR-0003: Build Asset Monitor as a fork of Numen

## Status

Accepted, 2026-11-12. Numbered after Numen's ADR-0001 and ADR-0002, which come along with the fork and stay in force unless a later ADR amends them.

## Context and decision point

The Asset Monitor plan matches Numen's own PRD (`docs/prd/numen-prd.md` at `4970c7b`, "PRD: Numen assets monitoring dashboard") almost feature for feature. On 2026-11-12, one agent checked every plan feature against Numen's code and a second agent tried to refute each claim; none was refuted. About 60 to 65 percent of the plan is already built end to end:

- Asset registration and polling.
- Triage on Pi, Claude Code or Codex, with model and effort checked against the account.
- Five of the six Verdicts as analysis categories, including Security hardening; only Malicious change is missing.
- Discord delivery.
- Proof, report and Lab bundles.
- Findings and Provider accounts.
- Herdr-hosted agent sessions, with Transcripts that have secrets removed.
- A runner broker with an egress gateway.
- Single-Operator auth.
- More than 350 tests.

A Numen Program pairs an Asset with the upstream software it runs (a CMS or plugin, from GitHub or WordPress.org). Numen watches only that upstream code.

Asset Monitor adds the following new scope:

- Own repositories.
- Upstream repositories shared across Applications, with Exposure.
- The Malicious change branch with Detection rules.
- Remediation PRs.
- Served-content checks and the Advisory check.
- Intervals shorter than a day.

The project is meant to be implemented in full. The hackathon is only where it is presented, so reusing existing code is allowed.

## Decision

Fork Numen into this directory, keeping its git history, from branch `experiment/herdr-agent-sessions` at commit `4970c7b`. Numen's `main` holds only the initial commit and lacks the Herdr session work. The uncommitted CVE-privilege work in Numen's working tree is not part of the fork base: on 2026-11-12 it was neither committed nor verified in Docker. It can be ported later as an ordinary change.

Rename Program to Application throughout (models, API, UI and migration). Each Program becomes an Application with no Own repository:

- its former source becomes an Upstream repository;
- its asset URL becomes the Asset;
- its CVE selectors and version recipes are kept.

The Operator can add an Own repository afterwards.

Keep Numen's extras as long as they don't get in the way:

- the Codex harness;
- Jev triage;
- WordPress SVN sources;
- NVD CVE sync, which becomes one feed of the Advisory check;
- version fingerprinting, which supplies the Deployed version;
- audit context.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| Rebuild from scratch | Clean model with no inherited names | Re-implements the isolation boundary, the riskiest and most-tested part, before any new feature exists |
| Extend Numen in place on a branch | No second codebase | Changes Numen's core model (one source per Program, read-only stance towards Assets) and mixes two products' requirements in one PRD |
| Fork Numen (chosen) | Keeps the tested runner, sessions, accounts and UI; Numen stays stable | Fixes made in Numen later must be ported by hand |

## Consequences

- `GLOSSARY.md` is this fork's vocabulary. Numen's "Program" survives only in migrations and ported history.
- Numen's PRD acceptance criteria stay in force except where `docs/prd/asset-monitor-prd.md` changes them.
- ADR-0004 amends how Analysis and Labs behave. ADR-0005 removes the privileged build daemon and restates ADR-0002's risk.
