# Asset Monitor implementation plan

This plan delivers `docs/prd/asset-monitor-prd.md` on a fork of Numen (ADR-0003). Phases are ordered so each one leaves a working, demonstrable system. Every phase ends with `make build`, `make check` and `make test`; `make test` includes `test-runtime`, and Compose sets `NUMEN_DOCKER_TESTS=1`. Phases that change UI flows also run `make test-journey`.

Tests make no paid model requests and send no traffic to real Assets or Upstream repositories. Agent outputs come from Numen's `FixtureBroker`.

## Phase 0: Fork

1. Run `git init` in this directory, fetch Numen's `experiment/herdr-agent-sessions`, and check out `4970c7b` as `main`. The files already here (`GLOSSARY.md`, `docs/adr/ADR-0003..0005`, `docs/prd/asset-monitor-prd.md`, this plan) don't collide with any Numen path.
2. Commit the design documents on top.
3. Run the suites on the untouched fork, and record the baseline counts and the known failures in `docs/verification.md`.

**Done when:** `make check test` passes, apart from failures already recorded in `docs/verification.md` (currently `test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider`).

## Phase 1: Applications, repositories and intake (A01, A02)

- Rename Program to Application in models, API, UI and types.
- Add Repository rows stored once per source URL: kind github or wordpress, cursor, ETag, watched branches.
- Add the Application–repository link: role own or upstream, on/off, removed, Locked version. An Application has at most one Own repository.
- Write an Alembic migration that moves each Program's source into an Upstream repository linked to an Application with no Own repository. It keeps CVE selectors and version recipes, and takes the Locked version from the latest version observation.
- Store intervals in seconds, with a 5-minute minimum. Numen's Check now carries over to Applications through the rename.
- Make the GitHub read token mandatory, and send `If-None-Match` on every poll. Move Numen's existing SVN revision cursor from Program onto the Repository row.
- Derive Upstream repositories from manifests and npm, pnpm, yarn and composer lockfiles. Add Release branch matching.
- Add the Pre-filter, Backfill, and marking of capped diffs as incomplete.

**Done when:** AC-A01 and AC-A02 have tests, and two fixture Applications that both use `react` share one Upstream repository.

## Phase 2: Triage, Analysis and the agent boundary (A03, A04, parts of A13)

- Split Triage into a one-shot run with no tools and a 120-second deadline: `claude -p --tools '' --setting-sources '' --strict-mcp-config --mcp-config '{"mcpServers":{}}' --no-session-persistence`, or `pi --print --mode json --no-tools`, with the reply validated by application code. Refuse Triage on Codex. Store each run's Transcript in the database.
- Make Analysis automatic and read-only, keeping the Herdr session:
  - a write-only output directory;
  - the `addresses` output (commits or advisory ids);
  - deadlines;
  - per-day caps persisted across restarts, with "waiting for cap" and the 00:00 UTC reset.
- Take build capability away from commit and CVE analysis. Delete the privileged build daemon and its image, which now have no user (ADR-0005).
- Migrate analysis categories to the six Verdicts plus confidence. Restrict the Verdicts allowed for served content. Add the Review queue.
- Enforce the tool profiles per operation in the runner adapters, using flags that decide which tools exist, never `--allowedTools`.
- Refuse automated runs on Provider accounts without an API key.
- Add `herdr.dev` to the agent egress allowlist next to the provider hosts.

**Done when:**
- AC-A03 and AC-A04 have tests;
- AC-A13's first and fourth bullets have tests;
- a runtime test shows an Analysis container with no Docker daemon, no registry access, and network access only to its provider's hosts and `herdr.dev`.

## Phase 3: Findings and Alerts (A11, A12)

- Migrate Finding to sources (commit, served content, advisory, cve) and the A11 lifecycle, keeping Draft as an artifact state only. Add Operator confirmation, dismissal and remediation.
- Link changes to Findings from the `addresses` output, mapped to each Application by application code.
- Replace Discord embeds with the fixed Alert template. Send Alerts when a Finding opens and when a cap is reached.

**Done when:** AC-A11 and AC-A12 have tests (AC-A12's not-exposed case waits for Phase 7), and a commit message containing `@everyone` produces an Alert without it.

## Phase 4: Labs behind Approval (A07 Labs, A15 Approval password)

- Gate Numen's existing Lab job behind an Approval that carries the Operator's password on every request.
- Split the Lab into two phases: dependency fetch with install scripts disabled and no model credential, then build and run with `--network none`. Node stack only.
- Apply ADR-0005's limits: image size and build and run deadlines, cleanup after each run, and no route from Lab networks to the application network.
- Build an Own-repository Proof's vulnerable app from the Own repository at the Verdict's commit.

**Done when:**
- runtime tests show that an install script does not run, the Lab has no network, and an oversized image fails and leaves nothing behind;
- a fixture Own-repository vulnerability reproduces after Approval, and a fixture that does not reproduce shows not reproduced;
- AC-A15's Approval bullet has a test.

## Phase 5: Malicious change branch (A07 static Proofs, Detection rules, cleanup reports)

- Add `yara` to the runner image, and add a runner job kind that validates a Detection rule with no network: against the commit's changed files, the parent tree and the Baseline tree.
- Add the Malicious change outputs to Analysis: Detection rule, indicators, static Proof and cleanup report.
- Have application code check the cleanup report.

**Done when:** a fixture malicious `postinstall` commit ends with a validated Detection rule, a cleanup report and a Confirmed Finding, and no job ever executes the payload. A Detection rule that fails validation leaves the artifacts in Draft and the lifecycle state unchanged, and a Backfill commit is checked against its parent tree only.

## Phase 6: Remediation PRs (A08)

- Add the write token setting, used only by the PR step.
- Make patch drafting automatic after a Verdict: a one-shot run with a 20-minute deadline that can write only in a scratch worktree and counts against the caps. Show the validated diff on the Approval screen.
- Open draft PRs from exactly the approved diff, with an idempotency key per (Application, subject, action). Implement the patch, revert (the Cure's PR) and pin/bump actions.
- Detect the merge commit on the Own repository's default branch and move the Finding to Remediated.

**Done when:** AC-A08 has tests against a recorded GitHub API fixture, a repeated Approval opens one PR, and a merged PR remediates its Finding.

## Phase 7: Exposure and Upstream Playbooks (A05, A06)

- Implement tag containment with patch-id matching across watched branches, the Locked-version-to-tag mapping, and SVN `tags/` containment.
- Recompute Exposure whenever a Locked version changes.
- Wire the Own and Upstream columns of the Playbook matrix:
  - the Deployed version check through version fingerprinting;
  - Disclosure reports (written, never sent);
  - Upstream pin/bump Remediation PRs.
- Move an Own-repository Vulnerability fix Finding to Remediated when the Deployed version check reports that the fix is being served.
- Build an Upstream Proof's vulnerable app from the Own repository's head with the Locked version installed, or from a minimal app that pins the Locked version.
- Refuse downloads of Upstream Proofs (A15).

**Done when:**
- AC-A05 and AC-A06 have tests for the Own and Upstream columns, including the backport case (the served-content sweep is tested in Phase 9);
- AC-A12's not-exposed case has a test;
- the React2Shell fixture is exposed at `react-server-dom-webpack@19.0.0` and reproduces in a Lab after Approval.

## Phase 8: Advisory check (A09)

- Read runtime pins (Dockerfile `FROM`, `.nvmrc`, `engines`, `composer.json` platform) and package versions.
- Match them against OSV and GHSA, and against NVD through CPEs derived from the pins, outside Numen's AC-09 and AC-10 gates.
- Key matches by (Application, vulnerability) with aliases merged, and attach them to existing commit or cve Findings.
- Add the advisory Playbook: report, Alert, and a bump Remediation PR after Approval.

**Done when:** AC-A09 has tests, including the CVE-2026-111497 fixture opening exactly one Finding across all three feeds and React2Shell sharing one Finding.

## Phase 9: Served-content checks (A10, the A06 served-content column)

- Add Watched pages and Check now for Assets.
- Extend `gateway.py`:
  - a per-request user agent from the fixed browser and Googlebot pair;
  - a served-content policy allowing any public origin for GET;
  - the demo fixture's private address range, on the demo VM only.
- Fetch the HTML and up to 20 linked scripts per page, without running JavaScript, and store the bytes.
- Build the Content fingerprint:
  - normalise bundler hash tokens in script URLs as hekata's `monitor/gather.py` `family()` does;
  - normalise minified identifiers as `monitor/jsdiff.py` does;
  - nonce and CSRF-token normalisation is new code.
- Add Baseline acceptance, triage of each distinct fingerprint at most once, and accepting a new Baseline after an Unrelated or Security hardening Verdict.
- Run Analysis on stored bytes, and validate Detection rules for served content.
- Add the Upstream Malicious change sweep of stored served content, and remediation when a check matches the Baseline again.

**Done when:** AC-A10, the served-content column of AC-A06 and the Upstream Malicious change sweep have tests using a judol and ClickFix fixture server.

## Phase 10: Plugins, Transcripts and display hardening (A13, A14, A15)

- Make the plugin list read-only.
- Upgrade Pi from 1.0.0 to 1.3.0 and `pi-commandcode-provider` from 0.7.3 to 0.7.8, with its integrity hash in `runner/plugins.lock.json`, and rebuild the runner image. Re-run the Pi runtime tests.
- Store Analysis Transcripts in artifact storage with secrets removed, keeping those without a Finding for 30 days. Add retention for Triage Transcripts, and include both in `make backup`.
- Add the Content Security Policy and escaped rendering. Confirm the dashboard is published only on `127.0.0.1`.

**Done when:**
- AC-A13's second and third bullets, AC-A14 and AC-A15 have tests;
- a backup-and-restore round trip keeps a Finding's Transcripts.

## Phase 11: Demo (A16)

- Seed the demo Node Application with its prepared commits and the React2Shell Backfill.
- Seed the PHP demo Application (no Own repository), whose Asset serves judol and ClickFix.
- Write a run sheet for the disposable VM.

**Done when:** AC-A16 passes on a fresh VM from `make up`.

## Later (after the first release)

- The On-server agent, which reports file changes on the server and can remove a Malicious change there.
- Push webhooks through the private tunnel.
- A PHP Lab.
- A GitHub App for Remediation PRs.
