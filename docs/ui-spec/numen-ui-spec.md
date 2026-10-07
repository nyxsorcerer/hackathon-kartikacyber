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
| Finding detail | Findings list or analysis action | Title/status, upstream remediation, target exposure, report, PoC, Docker bundle, and lab result; Delete finding (confirmed) removes a finding recorded in error and returns to its source commit, whose analysis then notes the deletion. The findings list selects findings on the current page and deletes them together after a confirming second click | AC-11, AC-12 |
| Jobs | Main navigation or submitted operation | Title naming the operation and its subject (e.g. "CVE analysis: CVE-…"), a link to that subject and to the program by name, a plain-language outcome (what succeeded work produced; for failures the reason, error code, remedy, and whether a plain retry can help), progress, chosen agent profile, timestamps and duration, partial artifacts, retry, and cancel | AC-06, AC-17, AC-18 |
| Settings | Main navigation | Accounts, Pi plugins, Defaults, Prompts, Integrations, and Discord webhook tabs. Prompts lists each operation's template and the shared sections they include; selecting one opens a monospace editor with its relations (Includes / Used by, each a link), Save, Discard changes, Reset to default (confirmed), Show default with Load into editor, a template-syntax reference, and a preview that renders an operation with the unsaved draft (a section picks which operation). Drafts are kept for the browser session, so switching templates, Settings tabs or pages never discards them; unsaved ones are marked in the list, and closing or reloading the tab with unsaved drafts asks first; a template customized before its shipped default changed shows a warning with Compare with default | AC-13–16 |

## Program form

| Group | Fields and behavior |
|---|---|
| Asset | Asset name, HTTP(S) URL, software kind (`CMS`, `plugin`, custom), product name |
| Source | GitHub or WordPress selector. GitHub shows repository and branch/path; WordPress shows plugin slug and SVN subtree, with the resolved release-source URL |
| Monitoring | Positive whole-day interval, inherit-default control, enabled/paused state, and next scheduled check after save |
| Version | Existing recipe and revision with its release-fingerprint coverage (releases captured, distinguishing files, releases that publish identical files), a warning when the active recipe has no fingerprints, last observation with the fingerprint files fetched and the releases each matched, Generate recipe and Run check actions; a manual observation records its source and time |
| CVE identity | Product/vendor/CPE selectors and source references; tentative identities are explicitly labeled |
| CVE analysis | Minimum Base score, chosen CVSS versions, auto-analysis enabled state, and default agent profile |

Saving the program does not invoke an agent. It queues the initial source check when monitoring is enabled. A version recipe or audit report is generated through its named action; scheduled checks can reuse an existing recipe. The auto-CVE-analysis toggle requires valid criteria, product identity, and a configured profile.

Field validation preserves entered values. A configuration error disables the dependent action and states the missing input next to that action. It does not block unrelated program edits.

## Commit review interaction

The review menu starts with searchable program selection and loads only the selected program's queue. Security candidates are the default view; decision, change-type, triage, analysis, and search filters remain available within that program. The primary title describes the potential vulnerability/security change; the original commit subject remains visible. Once a program is chosen, its switcher sits in the page heading. Rows have checkboxes (shift-click selects a range, the header selects the shown rows and then offers every matching row); while rows are selected, a sticky bar replaces the result count and sets Mark for review, Confirm finding, Leave pending, or Dismiss on all of them at once, then reports the outcome with Undo. Analyze (up to 50 selected rows) opens the execution-profile dialog listing the selected revisions and queues one detailed analysis per revision; the bar then reports how many were queued and how many were skipped because an analysis was already running or the revision belongs to an earlier source generation, with a link to the job (or the commit-analysis jobs). Changing a filter clears the selection so hidden rows are never changed. Detail/back navigation retains the program scope. The commit header identifies the upstream source, immutable revision, author/time, triage status, and review decision. Source diff, Triage, and Analysis & artifacts have separate tabs; saved analysis is the default when available.

Decisions are Mark for review, Confirm finding, Leave pending, and Dismiss; a Confirmed tab lists revisions confirmed as real vulnerabilities. A candidate whose analysis produced a finding shows Finding ready with its finding link and a Confirm finding prompt; a confirmed revision without a finding offers Create finding prefilled from the revision. Dismissing a revision with an open finding asks again and leaves the finding open. Actions are Analyze, Dismiss, and Leave pending. Analyze opens a job configuration dialog with agent, account, model, and supported effort. It shows the source/context inputs and starts only when the operator submits the dialog. Re-analysis creates a new immutable result and keeps older reports available.

A completed analysis displays one of the five PRD categories, distinguishing Security hardening from vulnerability fixes and introductions. Saved runs are selected one at a time, with their title, finding verdict/basis, confidence, before/after behavior, agent reproduction status, report, PoC/application files, job link, and immutable ZIP download. Supported findings are created automatically and linked; incomplete bundles remain labeled drafts/failed jobs. Non-findings create no finding, and insufficient evidence offers re-analysis. Independent lab verification is available on the finding and is never inferred from a narrative or generated bundle. Legacy reports remain readable and retain their manual Create finding action where appropriate.

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
| Audit context behind the source | Refresh for current source (primary) and Generate fresh context | The summary shows what a refresh reused, re-analysed and removed, and any functions deferred over the limit; the program form's Monitoring section offers Keep the audit context current |
| Current context | Entry report, supporting function documents, revision, coverage, and open questions | Inspect or regenerate |
| Stale/partial context | Stale or Partial badge plus the precise revision/coverage gap | Generate current/missing context |

Display confidence as a supported judgment, not a guarantee of deployment identity. Manual observations are labeled Manual and remain distinct from script observations.

## CVE and finding presentation

CVE rows separate Product match, Score eligibility, and Target applicability. A record can be score-eligible while its remote-version applicability is Unknown. Show every available v3/v4 score with its version, vector, and source; identify the score meeting the configured minimum. Below-threshold and unscored records remain inspectable and expose the reason analysis is unavailable.

CVE details use Overview, Analysis & artifacts, Scores, and References tabs. The selected CVE, tab, and analysis run are reflected in the URL; existing notification links remain supported. Saved results display one run at a time with its job status, summary, affected/fixed version ranges, confidence, and open questions. Job links open their specific run. Report, PoC, and run-specific ZIP downloads remain available for retained partial output. Closing the launch dialog returns to the selected CVE. Launch identifies the program, qualifying score, target applicability, and resolved execution profile, and explains when an explicit vulnerable revision is needed. Narrow screens display CVE rows as labeled cards.

Finding rows show identifier, title, Open/Fixed, fixed-in version when known, and artifact completeness. Detail uses separate fields for upstream status and remote exposure. A new observed target version updates exposure evidence and never silently changes the operator's finding status.

Finding lists and search load summaries without downloading artifact inventories or lab histories. Version evidence may be a string or a structured product/range/version record; display readable labels in rows, detail, and the editor. Editing status or other unrelated fields preserves the original structured version evidence.

The artifact panel has Report, Python PoC, Vulnerable app, and Supporting files tabs. It prioritizes the main report and application README/build files, searches file paths, and pages large file lists in groups of 50. Markdown has rendered/source views; code files have source previews and download controls. Relative report links open the related file within the same artifact set, including across tabs. Preview failures offer retry; large or binary files remain downloadable. Draft findings show missing files and permit downloading their saved output. Bundles preserve application paths and include an integrity manifest; individual hashes are expandable. Verify in lab creates a separate job and shows its result, pinned version, prerequisites, and captured logs. The dashboard never labels an unrun bundle Verified.

## Agent session in Jobs

Agent-backed job details retain the session panel while running, cancelling, and after success, failure, or cancellation. The run selector includes earlier agent phases and attempts; choosing a run clears the previous run's output and controls until that run loads. Completed sessions are read only and show no composer; a running job keeps its controls, disabled while the session is not live.

Terminal and Transcript views separate the terminal, rendered in the agent's own ANSI colors with its scrollback (up to 10,000 lines, so the operator can scroll back through the run), from the saved conversation. A live run opens on Terminal, a finished one on Transcript. The transcript is drawn the way the agent's terminal shows it, in the same palette: `>` user prompts, `●` assistant text with light markdown styling (bold, italic, inline code, headings, lists, quotes, dimmed code fences, colored diffs; never rendered HTML), `● name(argument)` tool calls with other arguments dimmed, and `⎿` tool output, keeping any ANSI colors the text carries and marking nonzero exits. Tool output, arguments and log metadata longer than 24 lines fold to their first 12 (or Show full tool output); prompts longer than 800 characters fold to their opening. Empty wrapper records are omitted. Both views offer copy as plain text and a taller view; the transcript wraps long lines by default. Polls that return identical output do not re-render.

The output area preserves terminal columns with horizontal scrolling and supports keyboard scrolling. It follows new output while at the bottom. Scrolling back pauses following; Follow output and Jump to latest restore it, scrolling smoothly unless reduced motion is preferred. While paused, new output is marked on Jump to latest and announced to screen readers. Switching views returns to following. The composer and terminal key controls are separate. While a message or control is being delivered, further steering is disabled. A failed delivery keeps the draft and explains the error; successful delivery preserves edits made while the request was pending.

Session reads finish before another poll starts. A temporary connection failure keeps the last successful output and offers Retry. Completed archives stop automatic polling. The dashboard applies no line or byte truncation to session history: it reads the saved native conversation, persisted tool-output files, and the latest terminal view. Redacted history remains available after workload cleanup and page reload. Native agents' own omitted output remains labeled by their recorded truncation markers; previously discarded output cannot be reconstructed.

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
