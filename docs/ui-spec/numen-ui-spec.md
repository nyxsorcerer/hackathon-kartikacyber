# Numen UI specification

Status: proposed. Date: 2026-10-03.  
Governing product scope: [PRD](../prd/numen-prd.md). No visual reference or existing UI was supplied.

## Overview and design evidence

The dashboard supports one operator moving from asset registration to a review decision and a reproducible finding. The original feature list and confirmed answers determine the screens below. Layout and interaction details are proposed implementation choices.

Use a desktop-first application shell with navigation for Dashboard, Programs, Commit review, CVEs, Findings, Jobs, and Settings. Smaller screens retain the same operations using stacked forms and horizontally scrollable data tables. Tables use explicit textual statuses alongside color. Source evidence and observation times appear wherever an interpretation depends on them.

## Screens and flow

| View | Entry | User-visible result | Governing acceptance |
|---|---|---|---|
| Login | Unauthenticated visit | Password login; successful login restores the originally requested review URL | AC-01 |
| Initial setup | First authenticated visit | Configure monitoring interval and account/default profiles; incomplete optional connections do not prevent saving programs | AC-02, AC-14, AC-15 |
| Dashboard | Main navigation | Program health, due/failed checks, pending security reviews, eligible CVEs, and open findings | AC-03–05, AC-09–11 |
| Programs | Main navigation | Searchable asset/source table with observed version, last check, next check, and monitoring state | AC-02, AC-03, AC-07 |
| Insert/Edit program | Programs action | Field groups for asset, upstream software, monitoring, version recipe, and CVE criteria | AC-02, AC-06, AC-09 |
| Program detail | Program row | Overview plus Version, Commits, Audit context, CVEs, and Findings tabs | AC-03–12 |
| Commit review | Candidate notification or commit row | Diff, triage evidence, source/context revision, review decision, and analysis history | AC-04–06 |
| CVEs | Main navigation or program tab | Product-match status, scoring eligibility, affected/fixed versions, observed-target applicability, and analysis state | AC-09, AC-10 |
| Finding detail | Findings list or analysis action | Title/status, upstream remediation, target exposure, report, PoC, Docker bundle, and lab result | AC-11, AC-12 |
| Jobs | Main navigation or submitted operation | Progress, chosen agent profile, timestamps, partial artifacts, failure reason, retry, and cancel | AC-06, AC-17, AC-18 |
| Settings | Main navigation | Accounts, Pi plugins, Defaults, Integrations, and Discord webhook tabs | AC-13–16 |

## Program form

| Group | Fields and behavior |
|---|---|
| Asset | Asset name, HTTP(S) URL, software kind (`CMS`, `plugin`, custom), product name |
| Source | GitHub or WordPress selector. GitHub shows repository and branch/path; WordPress shows plugin slug and SVN subtree, with the resolved release-source URL |
| Monitoring | Positive whole-day interval, inherit-default control, enabled/paused state, and next scheduled check after save |
| Version | Existing recipe and revision, last observation, Generate recipe and Run check actions; a manual observation records its source and time |
| CVE identity | Product/vendor/CPE selectors and source references; tentative identities are explicitly labeled |
| CVE analysis | Minimum Base score, chosen CVSS versions, auto-analysis enabled state, and default agent profile |

Saving the program does not invoke an agent. It queues the initial source check when monitoring is enabled. A version recipe or audit report is generated through its named action; scheduled checks can reuse an existing recipe. The auto-CVE-analysis toggle requires valid criteria, product identity, and a configured profile.

Field validation preserves entered values. A configuration error disables the dependent action and states the missing input next to that action. It does not block unrelated program edits.

## Commit review interaction

The commit header identifies the program, upstream source, immutable revision, author/time, triage status, and operator decision. The diff is followed by the triage input completeness and supporting context reference. Detailed results appear separately from the triage classification.

Actions are Analyze, Dismiss, and Leave pending. Analyze opens a job configuration dialog with agent, account, model, and supported effort. It shows the source/context inputs and starts only when the operator submits the dialog. Re-analysis creates a new immutable result and keeps older reports available.

A completed analysis displays one of the four exact PRD categories. Likely-fix and potential-introduction results offer Create finding; the operator selects the finding type and status. An insufficient-context result points to the missing source or stale context and permits another run after those inputs change.

Discord links open this view after login. A link visit does not submit an analysis action. Webhook configuration uses ordinary dashboard links; it does not imply Discord buttons can execute privileged actions.

## Model and account selection

Every agent selector offers Pi, Claude Code, and Codex CLI, then follows the same order: agent, account, available model, then supported effort. This includes audit context, version recipes, commit/CVE analysis, optional agent triage, and finding generation. Changing an upstream selection clears incompatible dependent values. Claude Code shows its Claude connection; Pi exposes its supported provider connections; Codex shows compatible OpenAI API-key or ChatGPT-login connections. A Command Code-hosted Claude model is labeled under Pi/Command Code.

If the model manages reasoning depth itself, display “Provider managed” instead of an enabled effort selector. Jev's triage model selection is separate and does not show a coding-agent effort control. Unavailable accounts, stale model metadata, and failed capability checks explain why execution is disabled.

Defaults resolve in the order job override, program override, global default. Codex can be saved as the default for any agent-backed operation. The submit dialog displays the resolved values and the job detail preserves them. Codex model and effort choices come from the selected connection's capability snapshot rather than a fixed list copied from another runtime.

## Version and context presentation

| Condition | Display | Recovery |
|---|---|---|
| No recipe | “Version check not configured” with Generate recipe | Select an agent/profile and generate |
| Exact supported observation | Version, evidence method, confidence basis, checked time, recipe revision | Run another check or inspect evidence |
| Ambiguous fingerprint | Candidate versions and explanation | Add another fingerprint or manual observation |
| Failed check | Failure reason plus last successful version and its age | Retry after resolving the failure |
| No audit context | Generate audit context action | Select source revision and profile |
| Current context | Entry report, supporting function documents, revision, coverage, and open questions | Inspect or regenerate |
| Stale/partial context | Stale or Partial badge plus the precise revision/coverage gap | Generate current/missing context |

Display confidence as a supported judgment, not a guarantee of deployment identity. Manual observations are labeled Manual and remain distinct from script observations.

## CVE and finding presentation

CVE rows separate Product match, Score eligibility, and Target applicability. A record can be score-eligible while its remote-version applicability is Unknown. Show every available v3/v4 score with its version, vector, and source; identify the score meeting the configured minimum. Below-threshold and unscored records remain inspectable and expose the reason analysis is unavailable.

Finding rows show identifier, title, Open/Fixed, fixed-in version when known, and artifact completeness. Detail uses separate fields for upstream status and remote exposure. A new observed target version updates exposure evidence and never silently changes the operator's finding status.

The artifact panel has Report, Python PoC, and Vulnerable app tabs. The Markdown report is rendered safely; code files have source previews and download controls. Draft findings show missing files. Complete bundles show integrity hashes and verification state. Verify in lab creates a separate job and shows its result, pinned version, prerequisites, and captured logs. The dashboard never labels an unrun bundle Verified.

## Settings

| Tab | Controls and states |
|---|---|
| Accounts | DeepSeek, Command Code, OpenAI, Claude, and Jev connection labels; supported-runtime badges; OpenAI API-key versus Codex ChatGPT-login mode; API-key input or container-based native login instructions; connection check; capability refresh; masked credentials; reported usage or Unknown |
| Pi plugins | Bundled name/source/version, enabled state, health, and linked provider; changes apply to subsequent jobs |
| Defaults | Monitoring days; audit-context and version profiles; reusable profiles for the other agent-backed operations |
| Integrations | GitHub token, optional CVE-source credentials, source health, and CVE sync timestamps |
| Discord | Masked webhook URL, enabled state, dashboard base URL, Test notification, and delivery history |

Native CLI login instructions invoke a container-managed login operation. Codex device login shows the provider verification link/code and pending/completed/expired state when that flow is available. Claude login shows the sign-in link and a protected authorization-code field, then shows submitted/verifying state; completing login refreshes the compatible model/effort choices. Secrets are entered in protected fields or the provider's native flow; they never appear as copyable command arguments or in job previews.

## Shared state and interaction rules

| State | Behavior |
|---|---|
| Empty installation | Programs page offers Insert program; counts reflect no records |
| Background action submitted | Show job link immediately and keep the current page usable |
| Account expired or plugin unavailable | Preserve configuration and offer reconnect/capability refresh |
| Source/Discord error | Show last successful state and a retry action; retain the review item |
| Cancellation requested | Show Cancelling until the workload is stopped; then show Cancelled and retained partial output |
| Duplicate submit | Reuse the existing job for the same idempotency key and show its link |

Use labeled controls, semantic tables, visible keyboard focus, keyboard-operable dialogs, and text-based error/progress announcements as implementation defaults. These are UI design choices, not additional user-specified feature scope.

## Acceptance traceability

| Acceptance | Observable UI proof |
|---|---|
| AC-01 | Protected review URL requires login and returns to that item afterward |
| AC-02, AC-03 | Insert/reopen program; pause/manual check; accurate last/next check and imported history |
| AC-04–06 | Disabled triage creates no job; candidate review requires explicit Analyze; exact result category and preserved profile |
| AC-07, AC-08 | Ambiguous/stale/partial version or context states remain visible with evidence |
| AC-09, AC-10 | Unscored/below-threshold records cannot start CVE analysis; eligibility and applicability are separate |
| AC-11, AC-12 | Upstream fixed version and remote exposure differ when appropriate; required artifacts and unverified lab state are visible |
| AC-13–16 | Plugin/account/default/webhook changes show the resulting availability or failure |
| AC-17, AC-18 | Job status survives a refresh/restart; cancel is truthful and partial outputs remain labeled |

## Open inputs

Global monitoring days, CVSS threshold, model choices, account credentials, and target/source records are entered during setup. No additional product-scope decision is required to implement the described screens. The visual palette and individual component library remain reversible implementation choices.
