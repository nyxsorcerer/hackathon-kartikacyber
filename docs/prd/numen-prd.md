# PRD: Numen assets monitoring dashboard

Status: implementation specification; product scope confirmed in the conversation.  
Date: 2026-10-03.  
Delivery requested now: build the full application, with a few implementation subagents at xhigh reasoning effort.

## Overview

### One-line summary

Give one operator a Docker-hosted dashboard that turns remote software versions, upstream changes, and relevant CVEs into reviewable findings with reproducible artifacts.

### Background

The operator currently needs a way to relate an asset URL to upstream software, decide whether a change deserves security analysis, and retain the evidence supporting that decision. A commit classifier, an upstream fix, and a deployed target version are different observations. The dashboard must retain those distinctions so an upstream patch is not mistaken for proof that the remote asset has been patched.

### Product context

| Dimension | Understanding | Evidence |
|---|---|---|
| User | One operator, with login | Explicit user answer |
| Scope | Every listed feature, delivered in phases; no exclusions | Explicit user answer |
| Monitoring cadence | Check for new commits every X days | Explicit user answer |
| Deployment | All application components and workloads inside Docker | Original request |
| AI integrations | Pi, Claude Code, Codex CLI, optional TypeSafe AI Jev; Command Code through the specified Pi plugin | Original request, supplied links, and follow-up requesting Codex support |
| Existing foundation | Empty workspace, no Git repository, application, or test harness | Observed 2026-10-03; [evidence](../references.md#workspace-evidence) |
| Rough cost | High: new persisted data, asynchronous execution, provider integrations, and reproducible lab artifacts | Structural assessment; estimates in the [work plan](../plans/20261003-feature-numen.md#effort-estimate) |

## User stories

- As the operator, I register an asset and its upstream software so I can track deployed and released changes together.
- As the operator, I review security candidates before spending agent resources on detailed commit analysis.
- As the operator, I reuse a version script and source context instead of repeating the same reconnaissance.
- As the operator, I filter CVEs by product and CVSS criteria and retain findings with a Python PoC, vulnerable Docker application, and Markdown report.

## Requirement boundary

A **program** is one monitored asset/software pair: asset name and URL, software kind and product identity, upstream source, and monitoring configuration. For example, a CMS and a plugin on the same site can be two program records. This is a proposed modeling choice that directly represents the requested insertion fields; implementation can revise it while preserving their behavior.

The requested capabilities below are **desired-future** requirements traced to the user's feature list or subsequent answers. Acceptance details such as draft artifacts, lab verification, job recovery, and field validation are proposed supporting behavior, rather than additional user-confirmed feature requests. The empty workspace is **current-state** evidence. The user confirmed no exclusions from the listed feature set. Intermediate phases do not constitute the completed release.

## Functional requirements and acceptance criteria

### R01 — Operator login

Provide one operator account, password login, logout, and a container-based account recovery command.

**AC-01:** An unauthenticated visitor cannot read program details, reports, artifacts, job logs, or settings, and cannot submit a background operation. A logged-out session cannot perform those operations.

### R02 — Insert and manage programs

The insertion form contains asset name, HTTP(S) asset URL, software kind (`CMS`, `plugin`, or a custom value), product name, GitHub repository or WordPress plugin slug, source branch/path, monitoring interval in positive whole days, and monitoring enabled/paused. Store CVE identity selectors and version determination configuration alongside the program. Provide edit, pause/resume, and archive actions.

**AC-02:** A saved program reopens with its entered values. Invalid URLs, nonpositive monitoring intervals, and invalid source identifiers produce field-specific errors. A WordPress program works without requiring a GitHub repository.

### R03 — Monitor commits every X days

Use the per-program interval or the global default. On the first successful source sync, establish the current source revision as the monitoring baseline and display available history. Subsequent scheduled or manual checks import new revisions since the last successful baseline. X days is a polling interval, not a limit on the age of imported commits.

**AC-03:** A check after a missed interval imports every available unseen revision. Retrying a partial sync does not duplicate commits, advance past missing pages, or discard the previous successful cursor. Pause prevents new scheduled checks; manual checks remain available.

### R04 — Commit list and optional security triage

Show commit/revision identifier, message, author, time, changed paths, upstream link, triage status, and detailed-analysis status. The operator can choose triage disabled, Jev, Pi, Claude Code, or Codex CLI and can manually mark a revision for review. AI triage distinguishes a security candidate, an unrelated change, and insufficient context; this is separate from the detailed result categories.

Jev is the TypeSafe AI service supplied by the user. Its typed decisions support triage; the narrative investigation is performed by a coding agent. This division is a design inference from the [Jev primitives documentation](https://docs.typesafe.ai/primitives).

**AC-04:** With AI triage disabled, ingestion creates no AI triage jobs and commits remain available for manual review. With triage enabled, results record the input revision, selected service/model, decision, and available probability/confidence. Missing diffs or unavailable context cannot be represented as a confirmed unrelated change.

### R05 — Alert and decide whether to analyze a commit

Send security-candidate notifications to Discord. The notification opens the authenticated commit review page. The operator chooses analyze, leave pending, or dismiss. Analyze opens the agent/account/model/effort selector before submitting the job.

Detailed commit analysis returns exactly one of:

1. **Likely vulnerability fix**
2. **Potentially introduced vulnerability**
3. **Unrelated change**
4. **Insufficient context**

The report includes supporting source locations, the before/after comparison, the affected behavior, confidence with its basis, and open questions. A category is an analysis judgment and does not automatically create a confirmed 0day.

**AC-05:** A candidate produces a review item and a recorded notification attempt. It creates no detailed-analysis job until the operator submits Analyze in the dashboard. The result preserves one of the four exact category labels and the evidence used to reach it. A dismissed revision remains in history and can be reconsidered.

### R06 — Agent, model, and reasoning selection

Each agent-backed operation uses Pi, Claude Code, or Codex CLI, a connected account, a model available to that connection, and a supported reasoning effort. This applies to commit triage/analysis, version-recipe generation, audit context building, CVE analysis, and finding artifact generation. Defaults prefill the choice; the operator can override them for a submitted job. Persist the resolved choice with that job.

Pi connects to DeepSeek, Command Code through `pi-commandcode-provider`, OpenAI, and Claude/Anthropic using supported provider integrations. Claude Code uses its supported Claude connection. Codex CLI uses an OpenAI API-key connection or supported ChatGPT login, with model access validated for that auth mode. A Claude model accessed through Command Code is still a Pi job; choosing an OpenAI model through Pi does not change the runtime to Codex. Jev has its own triage configuration and is not presented as a coding-agent runtime.

**AC-06:** Pi, Claude Code, and Codex CLI are selectable for every listed agent-backed operation when a compatible connection exists. Unsupported agent/provider/model/effort combinations are rejected before execution. An unsupported effort is not silently translated to another value. A provider-managed effort displays that fact and omits an effort parameter. Changing defaults does not change a queued job's recorded profile.

### R07 — Determine the remote version using reusable scripts

An agent generates a reusable Python script, metadata describing its evidence sources, and fixture checks. Methods may use response disclosures, headers, exposed metadata, file hashes, asset hashes, or combinations. Retain script revisions and run the selected script on demand and during enabled version monitoring.

A result contains the detected version or candidate versions, method, evidence, observation time, and confidence/limitations. Support an explicitly labeled manual version observation when the operator has independent evidence.

**AC-07:** A generated script can be reused without invoking an agent again. One hash shared by multiple releases returns the candidate set or an unknown result. Unreachable targets, transformed assets, incomplete fingerprints, and contradictory evidence do not produce a fabricated exact version. A new failed check preserves the last successful observation with its age.

### R08 — Audit context building

Generate `audit-context-building.md` using the Trail of Bits audit-context-building skill with Pi, Claude Code, or Codex CLI. Preserve its supporting function documents and source evidence. Record the source revision, skill revision, selected agent/model/effort, coverage, unresolved questions, and generation time.

The context-building operation describes structure and assumptions; commit/CVE investigation is a separate operation. New source revisions mark prior context as stale relative to that revision and preserve it for historical comparison. See the [skill evidence](../references.md#trail-of-bits-audit-context-building).

**AC-08:** The context file opens from the program page with supporting documents and source references. A report for revision A cannot be labeled as context for revision B. An interrupted or limited run exposes its coverage and missing work.

### R09 — CVE monitoring and score criteria

Collect relevant CVE records and updates. Identify the software using source/product identifiers and operator-configured selectors, rather than treating a text-name match as verified applicability. Configure allowed scoring versions (`3.0`, `3.1`, `4.0`) and a minimum Base score from 0 to 10. Every CVE analysis request requires saved criteria and an agent profile; the operator can also enable automatic analysis of eligible records.

Proposed gate: a CVE passes when at least one available Base score in a selected version meets the inclusive minimum. Retain all score sources and vectors and identify the score that passed. Records with no selected-version score are visible as unscored and cannot start CVE analysis. CVSS v2 does not satisfy this requirement.

**AC-09:** At threshold 7.0, a selected-version Base score of 7.0 passes and 6.9 does not. A record with only v2 or no qualifying score creates no CVE-analysis job, including through a manual action. A later score update re-evaluates the gate. Every CVE-analysis job records and rechecks the qualifying product match and score criteria at execution.

**AC-10:** The dashboard separately displays product match, score eligibility, and applicability to the observed remote version (`affected`, `not affected`, or `unknown`). A missing version or an unsupported version-range convention remains unknown. Potential product matches require operator confirmation before CVE analysis.

### R10 — Findings

Maintain CVE findings identified as `CVE-YYYY-NNNN…` and 0day findings with a stable local identifier. Store title, linked program, source commit/CVE/analysis, status, affected versions, fixed versions, and evidence. Provide Open and Fixed status, with a separate preparation state for incomplete artifacts.

Show upstream remediation separately from the deployed asset's exposure. An upstream finding may be fixed in version X while the monitored remote deployment remains affected or unknown. The operator confirms finding status; analysis or a new release alone does not close it.

**AC-11:** A CVE row can display `CVE-… — title — Fixed in X`; a 0day can display `0day — title — Open`. An upstream fixed version does not overwrite the remote version or imply remote remediation. Linking a later CVE to a 0day preserves its original history.

### R11 — Finding artifacts

Each completed finding contains `poc.py`, a `vulnerable-app/` Docker bundle, and `report.md`. The operator can upload these files or request agent generation. The bundle includes pinned vulnerable software, startup instructions, and reproduction prerequisites. The report explains evidence, impact, affected/fixed versions when known, reproduction, and limitations.

Provide an explicit lab verification action. Verification executes the PoC against the isolated vulnerable Docker application and retains the result. Mark unverified or incomplete artifacts visibly.

**AC-12:** A completed finding downloads all three required artifact types and their integrity manifest. A Draft finding shows missing artifacts. Lab verification records the pinned application version and observed result. Failure to reproduce remains visible and does not silently become a successful verification.

### R12 — Pi plugins list

Settings displays the bundled Pi packages/extensions, source, pinned version, enabled state, health, and provider contribution. The list includes the Command Code provider. Enable/disable configuration changes the set available to subsequent jobs. Package changes are reflected by a reproducible runner-image rebuild.

**AC-13:** A disabled Command Code provider cannot be selected for a new job. An incompatible plugin shows a useful error and does not make its models appear available. Jobs retain the plugin/image versions they used.

### R13 — Account subscriptions and connections

Manage DeepSeek, Command Code, OpenAI, and Claude connections using supported API-key or native CLI login methods. OpenAI connection settings distinguish API-key access from ChatGPT login for Codex, and show which agent runtimes can use each connection. For headless Codex login, offer the native device-code flow when available to the account/workspace; preserve an explicit unavailable state when it is not supported. Store the connection label, credential state, model access, and provider-reported subscription/quota information where available. Jev credentials are managed alongside its optional triage setting. GitHub and optional CVE-source credentials belong to integration settings.

“Account subscription” means connecting an operator-owned account and showing the access it provides. Billing information that a provider does not expose is shown as unavailable; a subscription name is not treated as proof of API access.

**AC-14:** Saving credentials does not return the secret in an API response, log, or report. A connection check reports ready, expired, unavailable, or unsupported access. Model selection uses the connection's available models. Missing usage or pricing data displays Unknown rather than zero.

### R14 — Defaults

Provide a global monitoring interval in days and default agent profiles for audit context building and remote version determination. The same profile contract supplies optional commit triage, commit analysis, CVE analysis, and artifact generation defaults. Program and per-job overrides are explicit.

**AC-15:** A new program inherits the configured monitoring default. The job confirmation form shows the resolved profile. Program overrides take precedence over global defaults; a submitted job retains its resolved values.

### R15 — Discord webhook

Configure the Discord webhook, enabled state, and dashboard base URL. Provide a test action and delivery history. Notifications summarize candidate commits and eligible CVEs, link to the authenticated review item, and retain failed delivery attempts for retry.

**AC-16:** An unreachable webhook produces a visible delivery error without losing the review item. Retrying the same event preserves its identity. Discord failure does not start, cancel, or change an analysis decision.

### R16 — Docker deployment and durable work

Ship Dockerfiles and Compose configuration for the UI/API, database, scheduling, workers, agent runtimes, version scripts, and lab workloads. Persist configuration, observations, jobs, and artifact files across container replacement. The operator can inspect, cancel, and retry background jobs without blocking page requests.

**AC-17:** A clean environment can build and start the stack using Docker and Compose alone. Restarting application containers preserves programs, findings, completed artifacts, and resumable job state. Running work recovers to a truthful state instead of falsely succeeding.

**AC-18:** Agent and generated-script containers receive only the inputs and credentials needed for their operation. They cannot access the application database or Docker control socket. Cancellation stops the workload and reports whether any partial output was retained.

## Non-functional constraints

| Area | Constraint | Source |
|---|---|---|
| Deployment | Every application component and workload runs in Docker | User requirement |
| Access | Single operator with login | User answer |
| Evidence integrity | Observations and reports identify their source revision and execution profile | Derived acceptance detail necessary for version/commit/finding behavior |
| Background work | Long agent and monitoring operations expose progress and failures | Derived acceptance detail necessary for agent workflows |

Performance targets and asset-count limits have not been specified. The design starts with one concurrent expensive workload; this is a proposed capacity choice, not a measured guarantee.

## Success criteria

The operator can register an asset, receive new upstream changes at the configured cadence, determine its version with reusable evidence, review security candidates, analyze qualifying CVEs, and retrieve a finding's complete reproducible artifact bundle from a Docker-hosted authenticated dashboard.

Prove that outcome using one GitHub-backed program and one WordPress-backed program, both with fixture upstream services, plus container-level agent and lab contract checks. Live provider checks verify the selected integration using operator-supplied test credentials during implementation.

## Dependencies and risks

| Dependency/risk | Consequence | Planned handling |
|---|---|---|
| Provider access and model capabilities vary by account | An account may not offer a requested model or effort | Capability discovery and explicit unavailable states |
| Jev access and triage quality | Optional triage may be unavailable or misclassify changes | Disable option, manual review, fixture evaluation, retained model version |
| WordPress SVN contains released changes | History can differ from a separate development repository | Label the monitored source and retain SVN revision evidence |
| Remote version evidence may be ambiguous | An exact installed version cannot always be determined | Candidate sets, unknown results, evidence, and manual observations |
| CVE coverage/product identity may be incomplete | Matching can miss records or produce candidates | Visible selectors, operator confirmation, and source/update timestamps |
| Generated lab reproduction may require unavailable source or dependencies | A complete verified bundle may not yet be possible | Draft/unverified state and explicit missing prerequisites |

## Configuration and open items

| Item | Status | Handling |
|---|---|---|
| Numeric default for X days | Implemented default: seven days | Operator can change the global interval; individual programs can override it |
| Minimum CVSS and selected scoring versions | Not supplied | Operator saves criteria before submitting or enabling automatic CVE analysis |
| Default models and effort | Account-dependent | Select from validated runtime capabilities during setup |
| Program identifiers, private repositories, and CVE selectors | Deployment data | Enter per program; not required to complete these planning documents |
| Technical choices in the ADRs | Selected for implementation | Container/fixture checks verify repository-owned behavior; live provider eligibility is checked with operator credentials |

These configuration inputs are entered during setup. The user's subsequent “Build it” instruction authorizes implementation of the full scope, including Pi, Claude Code, and Codex CLI.

## References

- [UI specification](../ui-spec/numen-ui-spec.md)
- [Architecture](../design/numen-design.md)
- [Implementation plan](../plans/20261003-feature-numen.md)
- [Primary sources and workspace evidence](../references.md)
