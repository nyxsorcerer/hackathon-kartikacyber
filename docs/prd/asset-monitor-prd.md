# PRD: GarudaNetra

Status: agreed in a design-grilling session on 2026-11-12, then revised after an adversarial review of the documents against Numen's code. GarudaNetra is a fork of Numen (ADR-0003), and this document lists only what differs from the fork's `docs/prd/numen-prd.md` at commit `4970c7b`. Every Numen requirement and acceptance criterion not changed here stays in force. Terms are defined in `GLOSSARY.md`.

## Overview

### One-line summary

A self-hosted, all-Docker dashboard that watches the Operator's Applications for security-relevant changes in three places: their Own repository, the Upstream repositories they depend on, and the content their Asset serves. Each change gets a Verdict, and each Verdict triggers a fixed Playbook: a Proof, a report, a Detection rule, or a draft Remediation PR.

### Background

A Numen Program pairs an Asset with the upstream software it runs (a CMS or plugin). Numen triages that software's commits with a chosen agent, model and effort, alerts on Discord, and builds Proof, report and Lab bundles. GarudaNetra adds:

- Own repositories;
- Upstream repositories shared across Applications, with Exposure;
- a Malicious change branch with Detection rules and Cures;
- Remediation PRs;
- Served-content checks for injected content (judol, ClickFix);
- an Advisory check for runtime CVEs;
- intervals shorter than a day;
- automatic, read-only Analysis.

The hackathon is only where the product is presented; the scope below is meant to be implemented in full.

### Case studies and where each is detected

| Case | What it is | Detected by |
|---|---|---|
| React2Shell, CVE-2025-55182 | RCE through React Server Components (`react-server-dom-*`) | The Upstream fix commit (Vulnerability fix) and the package advisory share one Finding. Exposure comes from the Locked version. n-day Proof in a Node Lab |
| php2shell, CVE-2026-109618 / CVE-2026-109619 | Bugs in the PHP engine (informal name) | Advisory check of the pinned runtime version |
| node2shell, CVE-2026-111497 | Bug in the Brotli decoder bundled with Node (informal name) | Advisory check of the pinned runtime version |
| Judol | Indonesian gambling SEO spam, often shown only to search engines | Served-content check fetched as Googlebot |
| ClickFix | Fake CAPTCHA that pushes a paste-and-run command; its later stages load at runtime | Served-content check: injected loader tag and external script hosts |
| Malicious commit (backdoor, `postinstall`, obfuscated loader) | Supply-chain payload committed to a repository | Commit Triage, then a Malicious change Verdict with a static Proof and Detection rule |

Judol and ClickFix normally live on the server, in its database or in content loaded at runtime, not in git. Watching commits will not see them.

## Changes to Numen requirements

| Numen requirement | Change |
|---|---|
| R01 Operator login | Kept. A15 adds a password check on every Approval. |
| R02 Insert and manage programs | Replaced by A01. |
| R03 Monitor commits every X days | Replaced by A02. |
| R04 Commit list and optional security triage | Changed by A03. Triage stays optional per Application. |
| R05 Alert and decide whether to analyze a commit | Replaced by A04 (automatic read-only Analysis) and A12 (Alerts). |
| R06 Agent, model, and reasoning selection | Kept, within A13's limits. |
| R07 Determine the remote version using reusable scripts | Kept. It supplies the Deployed version. |
| R08 Audit context building | Kept. |
| R09 CVE monitoring and score criteria | Folded into A09. Its AC-09 and AC-10 gates stay only for Findings carried over from Numen. |
| R10 Findings | Replaced by A11. |
| R11 Finding artifacts | Kept and extended (A07, A08). AC-12's downloads are refused for Upstream Proofs (A15). |
| R12 Pi plugins list | Changed by A13. |
| R13 Account subscriptions and connections | Changed by A13. |
| R14 Defaults | Kept, with intervals stored in seconds. |
| R15 Discord webhook | Changed by A12. |
| R16 Docker deployment and durable work | Kept. ADR-0005 removes the privileged build daemon. |

## Requirements and acceptance criteria

### A01: Applications and repositories

An Application has:
- a name,
- an Asset URL,
- Watched pages,
- at most one Own repository on GitHub,
- any number of Upstream repositories.

Without an Own repository, the Own-repository Playbook steps and Remediation PRs are unavailable.

An Upstream repository (a GitHub repository or a WordPress.org plugin) is stored once per source URL. It is linked to each Application that uses it, and the link holds:
- its on/off state,
- whether it has been removed,
- its Locked version.

A shared Upstream repository is polled, triaged and analysed once. Exposure, Findings and Alerts are per Application.

Upstream repositories are worked out from the Own repository:
- Direct dependencies are those named in `package.json` (`dependencies`, `devDependencies`, `optionalDependencies`) or in `composer.json` (`require`, `require-dev`).
- Their versions are resolved through `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `composer.lock`.
- Each is mapped to its source repository through npm or Packagist metadata.
- All are on at first derivation; dependencies that appear later start off.
- The list is worked out again whenever a commit to the Own repository changes a lockfile or manifest.

The Operator can also add an Upstream repository by hand. Its Locked version is a version the Operator enters, or the Deployed version from fingerprinting. With neither, Exposure is unknown.

**AC-A01:**
- A saved Application reopens with its repositories and their states.
- A lockfile change adds new direct dependencies (off) and marks removed ones as removed, without deleting their history.
- A package whose source repository cannot be resolved is listed as unresolved, not dropped.
- Two Applications that both use `facebook/react` share one Upstream repository: one poll and one Triage per commit.
- Numen Programs migrate as follows:
  - each Program becomes an Application with no Own repository;
  - its former source becomes an enabled Upstream repository;
  - its asset URL becomes the Asset;
  - its CVE selectors and version recipes are kept;
  - its Locked version comes from its latest version observation.

### A02: Intake

**GitHub repositories:**
- Polled with a mandatory, fine-grained, read-only token (Contents + Metadata) using ETag conditional requests.
- An Own repository watches its default branch.
- An Upstream repository watches its default branch plus the Release branch of each Locked version in use. The Release branch is the first branch that exists among `{major}.x`, `{major}.{minor}`, `release-{major}` and `v{major}`. With none, the default branch only is watched and the UI says "release branch unknown".

**WordPress.org plugins:** polled over SVN with no token, using a revision cursor instead of an ETag, watching `trunk`. Exposure reads `tags/`.

**Intervals:** stored in seconds, shown as minutes, hours or days, with a minimum of 5 minutes. Each Application has **Check now** (Assets get it in A10).

**Baseline and Backfill:** when a repository is added, its head becomes the Baseline. Earlier commits are triaged only if the Operator asks for a Backfill of the last N commits.

**Pre-filter:** a Pre-filter runs before Triage and flags:
- lockfiles and dependency manifests,
- `package.json` scripts,
- CI workflows,
- minified or obfuscated code,
- authentication and cryptography paths.

**Diffs:** diffs passed to agents are capped in size, and a capped diff is marked as incomplete.

**Triage off:** Triage can be turned off per Application, as in Numen's AC-04. Nothing is then analysed automatically, and the Operator can start an Analysis by hand.

**AC-A02:**
- A repository added with 10,000 commits creates no Triage runs until new commits arrive or a Backfill is requested.
- A `304` response advances nothing and creates no job.
- A 5-minute interval is accepted; 4 minutes is rejected with a field error.
- An incomplete diff can never yield an Unrelated Verdict.
- A WordPress.org plugin with no new revision creates no job.

### A03: Triage

Triage is a one-shot agent run with no tools: `claude -p --tools '' --setting-sources '' --strict-mcp-config --mcp-config '{"mcpServers":{}}' --no-session-persistence` (as in hekata's `monitor/judge.py`), or `pi --print --mode json --no-tools`. Application code validates the reply against the Triage schema. Triage on Codex is refused until a no-tools restriction has been verified for it (ADR-0004).

Triage decides only whether a change deserves Analysis, and gives a short reason. The prompt, the reply and the metadata are stored as a Transcript.

**AC-A03:**
- A Triage run is offered no tools.
- A reply that fails the schema is recorded as failed and retried, never read as "not security-relevant".
- A Pre-filter hit that Triage rejects is still listed in the change history with both results.

### A04: Analysis and Verdicts

A change flagged by Triage is analysed automatically, in a Herdr session the Operator can watch and steer.

**What Analysis reads and writes:**
- Reads a read-only checkout for a commit, or the stored fetched bytes from both user agents for served content.
- Writes only to its output directory.
- Builds nothing.

**What Analysis returns:**
- exactly one Verdict, with a confidence: low, medium or high;
- evidence and a title;
- where relevant, a draft Proof bundle, a Detection rule and a cleanup report;
- optionally, the commits or advisory ids that the change addresses. Application code maps these to each affected Application's Open or Confirmed Findings, so one Analysis of a shared Upstream commit can link to Findings in several Applications.

Analysis of served content may return only Malicious change, Security hardening, Unrelated or Insufficient context. Insufficient context sends the change to the Review queue.

**Limits:**
- Analysis has a 30-minute deadline.
- Automatic Analysis is capped at 10 runs per Application per day and 30 runs per Provider account per day.
- Analysis of a shared Upstream repository counts only against the Provider account cap.
- Concurrency is bounded by Numen's worker and runner concurrency settings.
- Changes flagged beyond a cap wait as "waiting for cap" and start automatically, oldest first, when the caps reset at 00:00 UTC. Reaching a cap sends an Alert.

**AC-A04:**
- No Analysis run has a Docker daemon or package-registry network access.
- An expired deadline leaves the change pending with a visible timeout, not Unrelated.
- At a cap, new automatic Analyses wait; manual Analysis still works.
- A served-content Analysis that returns Vulnerability fix is rejected as failed.
- Numen's analysis categories migrate as follows. Migrated Verdicts show confidence "unknown".

  | Numen category | Verdict |
  |---|---|
  | Likely vulnerability fix | Vulnerability fix |
  | Potentially introduced vulnerability | Vulnerability introduced |
  | Security hardening | Security hardening |
  | Unrelated change | Unrelated |
  | Insufficient context | Insufficient context |

### A05: Exposure

Exposure applies to Upstream commits and to advisories. For an Upstream commit:

- **Containment:** a commit is contained in a release tag if the commit itself, or a commit with the same patch-id on a watched branch, is reachable from that tag. For SVN, it is contained in every `tags/` copy made from a revision at or after it.
- **Locked version to tag:** the first existing tag among `v{version}`, `{version}` and `{package}@{version}`. With no match, Exposure is unknown.
- Exposure uses tag reachability, never semantic-version ordering.

Results by Verdict:
- Vulnerability introduced or Malicious change: exposed if the Locked version's tag contains the commit.
- Vulnerability fix: exposed if it does not. When no release contains the fix yet, every version is exposed.
- Unknown counts as exposed everywhere.

A not-exposed Upstream Verdict is recorded on the Upstream repository only: no Finding, Proof, Remediation PR or Alert. Exposure is recomputed whenever a Locked version changes. If that makes the Application exposed, the Playbook runs then.

Exposure does not apply to Own repositories. The Finding for an Own-repository Vulnerability fix stays open until the Deployed version check reports that the fix is being served (A11).

**AC-A05:**
- An Application that locks `react-server-dom-webpack@19.0.0` is exposed to the React2Shell fix commit.
- An Application that locks a version containing the fix is not exposed.
- An Application that locks a release whose Release branch carries a backport of the fix (a different SHA with the same patch-id) is not exposed.
- Unresolvable tags give "unknown", which is treated as exposed.
- Bumping a Locked version into a release that contains a known Malicious change opens a Finding at that moment.

### A06: Playbooks

| Verdict | Own repository | Upstream repository (exposed) | Served content |
|---|---|---|---|
| Vulnerability introduced | Proof, report, patch Remediation PR | Proof, Disclosure report, pin or bump Remediation PR | Not allowed |
| Malicious change | Static Proof, Detection rule, revert Remediation PR and cleanup report (together, the Cure) | Static Proof, Detection rule, cleanup report, Remediation PR pinning a safe version, Detection rule sweep of the Asset's stored served content | Static Proof, Detection rule, cleanup report; no Remediation PR |
| Vulnerability fix | Report, Deployed version check | n-day Proof, bump Remediation PR once a release contains the fix | Not allowed |
| Security hardening | Record only | Record only | Record only; the Operator may accept the new fingerprint as the Baseline |
| Unrelated | Stop | Stop | Stop; the Operator may accept the new fingerprint as the Baseline |
| Insufficient context | Review queue | Review queue | Review queue |

An Advisory check match gets: a report, an Alert if it opens a Finding, and, after Approval, a bump Remediation PR to the lowest fixed version or base-image tag. It gets no Lab Proof.

Other rules:
- Every Lab Proof and every Remediation PR needs Approval.
- Without an Own repository, Remediation PR steps show "no Own repository" and are skipped.
- The Deployed version check uses Numen's version fingerprinting and reports "still serving code from before the fix", "serving the fix" or "unknown".

**AC-A06:**
- Each Verdict runs only the steps in its cell.
- A step that needs Approval waits, visibly, without blocking the other steps.
- When no fingerprint matches, the Deployed version is "unknown", never a guess.

### A07: Proofs, Labs, Detection rules and cleanup reports

**Labs.** After Approval, application code builds a Lab through the broker on the host Engine, which is Numen's existing Lab path (ADR-0005), in two phases:
1. Fetch dependencies with `npm --ignore-scripts` or `composer --no-scripts`, with no model credential.
2. Build and run with `--network none`.

The Lab is built from the Proof bundle, following Numen's bundle contract. The bundle's vulnerable app is:
- for an Own-repository Proof, the Own repository at the Verdict's commit;
- for an Upstream Proof, the Own repository at its default-branch head with the Locked version installed, or, with no Own repository, a minimal app that pins the Locked version.

In the first release, the only Lab stack is Node.

Lab limits:
- each Lab image at most 4 GB;
- builds limited to 15 minutes, runs to 10 minutes;
- images and containers removed after every run.

**Malicious changes** get only a static Proof: a Detection rule plus extracted indicators. Application code validates the Detection rule with `yara` in a runner job with no network:
- **Commit:** it must match at least one file the commit changed, and must match no file in the commit's parent tree. For a commit made after the Baseline, it must also match no file in the Baseline tree. A Backfill commit is checked against its parent tree only.
- **Served content:** it must match the changed fetch's stored bytes, and must not match the stored bytes of the Baseline fetch or of the previous fetch.

**Cleanup report.** Analysis drafts it and application code checks it. It lists:
- the files and indicators the change added;
- the commits and releases that contained it;
- the secrets its payload could reach, which must be rotated;
- the Detection rule to run on the server.

GarudaNetra never sends it.

**AC-A07:**
- A Lab build cannot run a dependency install script.
- A Lab run cannot reach any network.
- No job ever executes a Malicious change payload.
- A Detection rule that fails validation leaves the Finding's artifacts in Draft (Numen's AC-12 state), shows which check failed, and does not change the Finding's lifecycle state.
- A Lab that fails to reproduce stays visible as not reproduced.
- A Lab over a limit fails visibly and leaves no image behind.

### A08: Remediation PRs

**Drafting.** Patch drafting runs automatically after the Verdict and counts against the Analysis caps. It is a one-shot run that can write only inside a scratch worktree, and it outputs a diff. Application code validates the diff, and the Approval screen shows exactly that diff. A revert or a dependency pin or bump is generated by application code.

**Opening.** After Approval, application code opens a **draft** pull request on a branch named `asset-monitor/<short-sha>-<action>` in the Own repository, from exactly the approved diff.
- It uses a separate fine-grained token (Contents and Pull requests: read and write) limited to Own repositories.
- That token is never present in an agent run.
- GarudaNetra never pushes to a default branch, never merges, and never writes to an Upstream repository or to a server.
- Each (Application, subject, action) has an idempotency key.

**Merging.** The Operator merges. When the poller sees the PR's merge commit on the Own repository's default branch, the Finding becomes Remediated.

**AC-A08:**
- Approving twice, or recovering a crashed job, opens at most one PR per (Application, subject, action).
- A diff that does not apply cleanly, or that touches files outside the Own repository checkout, is rejected before any GitHub call.
- With the write token missing, the step fails visibly and the rest of the Finding is unaffected.
- A merged Remediation PR moves its Finding to Remediated.

### A09: Advisory check

**What is collected.** Daily, and whenever a lockfile, manifest or Dockerfile changes, GarudaNetra collects:
- each Application's pinned runtime versions: the Dockerfile's `FROM` image tag, `.nvmrc`, `engines`, and the `composer.json` platform setting;
- its package versions and Locked versions.

**Matching.** These are matched against OSV, GHSA and NVD.
- NVD matches use CPEs derived from the pin, for example `cpe:2.3:a:nodejs:node.js`. They do not go through Numen's AC-09 and AC-10 gates.
- Matches are keyed by (Application, vulnerability), and OSV, GHSA and CVE aliases count as one vulnerability.
- A match whose alias is already on an open commit or cve Finding attaches to it. Otherwise it opens a Finding with source advisory.
- Exposure is the advisory's affected ranges compared with the pinned version. A version that cannot be read gives "unknown".

**AC-A09:**
- A Dockerfile pinning a Node version exposed to CVE-2026-111497 opens exactly one Finding across all three feeds, and the next day's check does not open a duplicate.
- The React2Shell package advisory and the exposed React2Shell fix commit share one Finding.
- A bump to a fixed version, once seen on the default branch, moves the Finding to Remediated.
- A runtime version that cannot be read is reported as unknown, not as not exposed.

### A10: Served-content checks

**Watched pages.** Each Asset has Watched pages; the homepage is always one. They are checked on the Application's interval and on the Asset's **Check now**.

**Fetching.**
- Each page is fetched twice: once with a browser user agent and once as Googlebot.
- The fetches go through Numen's fetch gateway, which stays GET and HEAD only and is extended with:
  - a user agent chosen per request from that fixed pair;
  - a served-content policy that allows any public origin;
  - the demo fixture's private address range, allowed only on the demo VM.
- The scripts the HTML links to are fetched too, same-origin and external, at most 20 per page.
- No JavaScript is ever executed.
- Fetched bytes are stored as evidence.

**Comparing.**
- The Content fingerprint is compared against the Baseline.
- The Operator must accept the first fingerprint before it becomes the Baseline. Accepting a Baseline is not an Approval and needs no password.
- Each distinct fingerprint, per page and user agent, is triaged at most once.
- A changed fingerprint goes through Triage and Analysis.
- After an Unrelated or Security hardening Verdict, the Operator can accept the new fingerprint as the Baseline. So can a change that Triage declined to analyse, or that the Operator dismissed from the Review queue (defaulted decision 14).

**Remediation.** A served-content Finding becomes Remediated when a later check matches the Baseline again, or when the Operator marks it.

**AC-A10:**
- A page that serves gambling links only to the Googlebot fetch produces a changed fingerprint, with the difference attributed to that user agent.
- An added external script host produces a changed fingerprint.
- Rotating nonces, CSRF tokens and bundler hash tokens do not.
- No JavaScript from a fetched page is ever executed.
- Ten checks of an unchanged page after an Unrelated Verdict start no new Triage run.

### A11: Findings

**Opening.** A Finding opens for:
- a Vulnerability introduced, Malicious change or Vulnerability fix Verdict on the Own repository;
- such a Verdict on an Upstream repository whose Exposure is exposed or unknown;
- a Malicious change Verdict on served content;
- an Advisory check match (A09).

A change that addresses an existing Finding is linked to it instead of opening a new one. Application code makes the link from the commits or advisory ids that Analysis returns, and only within one Application.

**Source and contents.** The source is commit, served content, advisory, or cve (carried over from Numen only). The Finding holds the evidence, Proof, report, Remediation PRs, Detection rule, cleanup report, Disclosure report and Transcripts.

**Lifecycle.**
- **Open → Confirmed:** by a reproduced Proof, a validated Detection rule, an Advisory check match, or the Operator.
- **Open → Dismissed:** by the Operator only.
- **Open or Confirmed → Remediated:** by any of:
  - a merged Remediation PR;
  - a version bump seen on the Own repository's default branch;
  - a served-content check matching the Baseline again;
  - for an Own-repository Vulnerability fix, the Deployed version check reporting that the fix is being served;
  - the Operator.

Linking a fix does not by itself make a Finding Remediated. The Deployed version is shown separately, for example "fixed in the repository, Asset still serving the vulnerable version". Draft is an artifact-completeness state (Numen's AC-12), not a lifecycle state.

**Migration from Numen.**
- Status `open` becomes Open, and `fixed` becomes Remediated.
- Kind `0day` becomes source commit; kind `cve` keeps source cve.

**AC-A11:**
- A linked fix shows both changes in the Finding's history and leaves the state unchanged.
- A Dismissed Finding is not reopened by the same Verdict on a repeat Analysis.
- A Remediated Finding records what remediated it.

### A12: Alerts

Alerts go to Discord only, through a fixed template. It carries only fields the application generates:
- the Application name;
- the source: short SHA, Watched page, or advisory id (none for a cap Alert);
- the Verdict and confidence, or "Advisory", or "Cap reached";
- the dashboard deep link.

Alerts never include commit messages, agent text or Proof details, and they send `allowed_mentions: {"parse": []}`.

An Alert is sent when a Finding opens and when a cap is reached, and at no other time.

**AC-A12:**
- A commit message containing `@everyone` and a link appears in no Alert.
- Security hardening, Unrelated, not-exposed Verdicts and Review queue entries send no Alert.
- Delivery failure behaves as in Numen's AC-16.

### A13: Agents, accounts and plugins

- **Automated runs use API keys only.** This covers Triage, Analysis and patch drafting, on Anthropic, DeepSeek, OpenAI or Command Code. Command Code needs a plan that includes API access. Numen's subscription sign-ins remain only for runs the Operator starts and steers by hand in an unmodified harness. The scheduler never uses them.
- **Tool profiles** are fixed in code per operation (ADR-0004).
- **Prompt templates.** Each operation has its own prompt template, using Numen's editable sandboxed templates. These replace the original idea of "skills per operation".
- **Agent network access** is the provider's hosts plus `herdr.dev`.
- **Pi plugins** are a read-only list, pinned in the runner image by version and integrity hash. `pi-commandcode-provider` moves from 0.7.3 (the fork base, with Pi 1.0.0) to 0.7.8 together with Pi 1.3.0, the pairing hekata runs. Adding a plugin means changing the lockfile and rebuilding the image.
- **Default profiles:**
  - Triage on Pi with a DeepSeek key;
  - Analysis on Claude Code with an Anthropic key at high effort.

  Both can be changed.

**AC-A13:**
- The scheduler refuses to start an automated run on a Provider account without an API key, and says why.
- The plugin screen has no install action.
- A job records the plugin and image versions it used (Numen's AC-13).
- An Analysis run reaches only its provider's hosts and `herdr.dev`.

### A14: Transcripts

- Triage Transcripts are stored in the database and pruned after 30 days or once they pass 256 MB, oldest first.
- Analysis Transcripts are the harness's native JSONL plus the Herdr screen. They are copied into artifact storage with known secrets removed and linked to their Verdict.
- An Analysis Transcript is kept as long as its Finding. Without a Finding, it is kept 30 days.
- `make backup` includes both kinds.

**AC-A14:**
- No stored Transcript contains a configured secret value.
- A Finding's Transcripts survive a container rebuild and a backup and restore.

### A15: Access and display

- The dashboard is published on `127.0.0.1` only. Remote access, including Discord deep links opened on a phone, goes through a private tunnel the Operator runs.
- Every Approval request carries the Operator's password, which is checked on that request. There is no re-authentication window.
- Diffs, reports, agent output and Transcripts are rendered as escaped text under a Content Security Policy that forbids inline script.
- Upstream Proofs are never posted or exported, including by artifact download. This overrides Numen's AC-12 for Upstream Findings.
- The Disclosure report is shown for the Operator to copy into the Upstream repository's GitHub private vulnerability reporting form. GarudaNetra never sends it.

**AC-A15:**
- A commit message containing `<script>` renders as text.
- An Approval with a missing or wrong password is refused, even straight after another Approval.
- Downloading an Upstream Proof is refused.

### A16: Demo scenarios

**Demo Node Application.** It has an Own repository that locks `react-server-dom-webpack@19.0.0`, and a Dockerfile that pins a Node version exposed to CVE-2026-111497. It goes through these steps, each picked up with Check now:
1. Push a commit that introduces a vulnerability: Vulnerability introduced, a Lab Proof after Approval, and a patch Remediation PR.
2. Merge that Remediation PR: the poller sees the merge commit, and the Finding becomes Remediated.
3. Push a malicious `postinstall` or obfuscated loader: Malicious change and its Cure.
4. Run a Backfill on the React Upstream repository that reaches the React2Shell fix commit: Vulnerability fix, exposed. It shares a Finding with the advisory match, and gets an n-day Proof after Approval and a bump Remediation PR.
5. The Advisory check opens the node2shell Finding.

**Demo PHP Application.** It has no Own repository. Its Asset serves judol links only to Googlebot, plus a ClickFix loader tag, for the Served-content check.

**AC-A16:**
- On a fresh VM, the whole scenario runs from `make demo-up` to the last Remediation PR with no manual database edits. `make demo-up` is `make up` plus the local stand-ins (`docs/demo.md`); plain `make up` stays the production entry point with real GitHub, registries and feeds.

## Non-goals for the first release

- The On-server agent, which would report file changes on the server and remove a Malicious change there. Moved to release 2, where it moves files into a Quarantine folder after Approval instead of removing them (`docs/prd/asset-monitor-r2-prd.md`, B03 to B08).
- GitHub push webhooks or any other public inbound endpoint. Push webhooks moved to release 2, where the ingress's push listener is the only public endpoint (`docs/prd/asset-monitor-r2-prd.md`, B01 and B02).
- A PHP Lab. Moved to release 2 (`docs/prd/asset-monitor-r2-prd.md`, B09).
- Discord buttons or a bot.
- Multiple Operators or human roles.
- Installing Pi plugins from the dashboard.
- Sending Disclosure reports.

## Decisions Claude defaulted while the Operator was away

The Operator delegated these on 2026-11-12. Each one can be changed by editing this section and the plan.

1. **Fork base:** `experiment/herdr-agent-sessions` at `4970c7b`, without Numen's uncommitted CVE-privilege work.
2. **Migration:** Numen Programs migrate with no Own repository, because a Program's source is upstream software, not the Operator's own code.
3. **Labs:** built on the host Engine through the broker. The privileged build daemon is removed (ADR-0005).
4. **Deadlines:**

   | Run | Deadline |
   |---|---|
   | Triage | 120 s |
   | Analysis | 30 min |
   | Patch drafting | 20 min |
   | Lab build | 15 min |
   | Lab run | 10 min |

5. **Lab limits:** 4 GB per Lab image; images and containers removed after each run.
6. **Run caps:** 10 automatic Analyses per Application per day and 30 per Provider account per day, reset at 00:00 UTC. Run counts are used instead of money because some harnesses report no cost (Numen's AC-14).
7. **Remediation PR credential:** a fine-grained personal access token; a GitHub App can come later.
8. **Direct dependencies:** include `devDependencies` and `require-dev`, because a malicious dev dependency still runs on developer and CI machines.
9. **Release branch matching:** `{major}.x`, `{major}.{minor}`, `release-{major}`, `v{major}`, else the default branch only.
10. **Served content:** at most 20 linked scripts fetched per page.
11. **Default profiles:** Triage on Pi with DeepSeek; Analysis on Claude Code at high effort.
12. **Exposure "unknown":** treated as exposed everywhere.
13. **Plugin pin:** `pi-commandcode-provider` 0.7.8 with Pi 1.3.0, as agreed. That is an upgrade from the fork base's 0.7.3 with Pi 1.0.0.
14. **Baseline after Triage declines:** a served-content change that Triage declined to analyse, or that the Operator dismissed from the Review queue, may also be accepted as the new Baseline. Otherwise a legitimate redesign that Triage waves through could never become the Baseline without a hand-started Analysis.

## Risks

- Building Labs from code attackers can influence, through the Docker socket, is accepted on a disposable host (ADR-0005).
- Prompt injection can still distort a Verdict (ADR-0004).
- Numen's automated tests never use paid inference, and no real Discord delivery is recorded (`docs/verification.md`). Operator-run analyses on real Provider accounts have succeeded, but API-key-only automated runs at GarudaNetra's volume have not been tried.
- Exposure depends on tag naming and patch-id matching. When either fails, the result is unknown, which is treated as exposed.
- Herdr downloads agent-detection manifests remotely, so agent status detection can change without a Herdr upgrade.
- The CVE ids for php2shell and node2shell come from web research on 2026-11-12. Confirm them against OSV before the demo.

## References

- `docs/prd/numen-prd.md`, `docs/adr/ADR-0001-application-and-jobs.md` and `docs/adr/ADR-0002-agent-execution.md` (in the fork)
- `runner/numen_runner/session.py` (a Herdr session per job) and `runner/numen_runner/engine.py` (`build_lab`)
- hekata's `src/hekata/monitor/judge.py` (one-shot calls with no tools), and its `monitor/gather.py` and `monitor/jsdiff.py` (normalising script URLs and minified code)
- Anthropic Consumer Terms, section 3, and the Claude Code legal and compliance page (subscription use)
- GitHub REST best practices (a conditional `304` is free only with an `Authorization` header)
- Discord webhook and interactions documentation (incoming webhooks are send-only)
- Sucuri research on judol cloaking and ClickFix EtherHiding
