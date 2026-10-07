# Work plan: Numen implementation

Created: 2026-10-03. Type: feature.  
Status: implementation complete, 2026-10-04. Authorized by the user's “Build it” instruction; Docker/fixture verification and local deployment passed. Operator-owned account configuration remains a deployment input.

## Implementation authorization

The user first requested planning documents, then instructed: **“Build it, use few subagents with xhigh reasoning effort to perform implementation.”** This authorizes implementing the full planned application, with three implementation agents at xhigh effort. Provider authentication, paid model calls, live target testing, and external notifications require operator-configured connections/actions; development verification uses controlled fixtures.

## Governing documents and scope

- [PRD](../prd/numen-prd.md): all requested features, one operator with login, checks every X days, no exclusions.
- [Architecture](../design/numen-design.md): contracts, data flow, persistence, isolation, and proof boundaries.
- [UI specification](../ui-spec/numen-ui-spec.md): required screens and operator transitions.
- [ADR-0001](../adr/ADR-0001-application-and-jobs.md): proposed stack and durable queue.
- [ADR-0002](../adr/ADR-0002-agent-execution.md): proposed execution boundary.
- [Evidence register](../references.md): primary integration sources and current inspection limits.

Complete the authenticated Docker dashboard through program monitoring, selectable Pi/Claude Code/Codex CLI agents, reusable version/context work, score-gated CVE analysis, and findings with all required artifacts. Intermediate checkpoints provide usable slices; release completion requires every phase. The user's follow-up adds Codex to all agent-backed operations and their defaults.

## Delivery rules and entrypoints

The interfaces below are implemented. Completed proof is recorded in [verification](../verification.md); paid/provider-specific checks are explicitly distinguished from executed fixture/container tests. Lockfiles and image digests pin dependencies. The [coordination contract](../implementation-contract.md) records actual shared API/runtime shapes and verified implementation adjustments.

| Entrypoint | Responsibility |
|---|---|
| `make check` | Backend/frontend lint, type checks, and production build |
| `make test-unit` | Pure policy/schema/version/response parsing proofs |
| `make test-integration CASE=<name>` | Real PostgreSQL/API/worker contracts with controlled upstream services |
| `make test-runtime CASE=<name>` | Broker/workload/proxy/lab checks against an actual Docker Engine |
| `make test-ui CASE=<name>` | Selected Playwright flows against the real frontend and controlled fixture data |
| `make test-journey` | Final clean-Compose operator journey using fixture sources/providers/webhook |
| `docker compose --profile setup run --rm migrate` | Apply migrations in a one-shot container |
| `docker compose --profile setup run --rm bootstrap-operator` | Create/reset the operator using protected interactive input |

`CASE` names below identify the proof contract to implement. The test commands reject an unknown case or an empty test selection. This prevents an unimplemented harness from appearing green.

## Phase 1 — Save and reopen a protected program

### P1-T1: Build the persisted/login foundation

- **Scope:** Backend/frontend manifests and lockfiles, multi-stage Dockerfile, Compose, migrations, operator/session models, encrypted-secret envelope/helper and master-key setup, API shell, login page, setup commands, test entrypoints.
- **Sources:** Architecture: Selected architecture, Data model, API and shared job contracts, Deployment. ADR-0001. UI: Login/Initial setup. PRD AC-01, AC-17.
- **Depends on:** None.
- **Verification:** `make check`; `make test-integration CASE=auth-persistence`; clean Compose start and migration/bootstrap commands.
- **Pass:** Login creates a revocable session; protected API/artifact routes and CSRF-protected writes reject invalid access; the build serves the actual compiled UI. The database survives application replacement.

### P1-T2: Implement program insertion and monitoring settings

- **Scope:** Program/source-generation models, CRUD/configuration API, Programs/Insert/Edit/Overview UI, monitoring default and explicit overrides, pause/archive behavior.
- **Sources:** Architecture: Data model, API contracts. UI: Program form/shared states. PRD AC-02, AC-15.
- **Depends on:** P1-T1.
- **Verification:** `make test-integration CASE=program-configuration`; `make test-ui CASE=register-program`.
- **Pass:** A GitHub or WordPress program reopens with persisted values; validation is field-specific; changing source generation cannot reuse a prior cursor. Pausing and overrides are visible.

**Checkpoint:** One operator can log in, save a program, restart containers, and reopen it. No fabricated monitoring or agent result is displayed.

## Phase 2 — Monitor upstream changes and review manual candidates

### P2-T1: Add durable checks and both upstream collectors

- **Scope:** Job/attempt/lease/event records, scheduler/worker services, source cursors/snapshots, GitHub and WordPress SVN collection, commit list, last/next check state.
- **Sources:** Architecture: Jobs/scheduling/recovery, Upstream source collection. ADR-0001. UI: Program Commits/Jobs/shared states. PRD AC-03, AC-04, AC-17.
- **Depends on:** P1-T2.
- **Verification:** `make test-integration CASE=source-monitoring`; `make test-integration CASE=job-recovery`.
- **Pass:** Initial sync establishes a baseline; later checks import unseen revisions, including old-dated newly merged changes and WordPress-only revisions. Partial pagination/export failures preserve the cursor. Duplicate claims and late results are fenced. AI-disabled checks create no triage job.

### P2-T2: Deliver candidate notifications and the operator decision flow

- **Scope:** Manual nomination, commit review decisions, transactional notification records, encrypted Discord integration settings using the P1 helper, Discord adapter/test action, delivery history, review links, Analyze dialog/API boundary ready for agent execution.
- **Sources:** Architecture: Commit triage/analysis, Discord delivery, API contracts. UI: Commit review/Discord/shared states. PRD AC-05, AC-16.
- **Depends on:** P2-T1.
- **Verification:** `make test-integration CASE=review-notification`; `make test-ui CASE=review-decision` using a webhook fixture.
- **Pass:** A nominated candidate retains a review item if delivery fails. Visiting its link after login cannot enqueue analysis. Submission explicitly records the operator's choice. Provider-unconfigured analysis is blocked with a useful prerequisite message.

**Checkpoint:** Both source kinds are monitored on schedule. Manual security review and Discord delivery work without requiring an AI connection.

## Phase 3 — Connect accounts and execute bounded agent jobs

### P3-T1: Implement the broker, account vault, and capability contract

- **Scope:** Pi/Claude/Codex runner images, proxy/gateway images and broker API, workload labels/cleanup, account encryption/native-login ingress/refresh, model/effort catalog, profiles/defaults, plugin inventory/enablement, account/settings UI. Add Codex OpenAI API-key versus ChatGPT-login connections and short-lived app-server model discovery.
- **Sources:** Architecture: Accounts/plugins/adapters, Container execution, Jobs/recovery. Both ADRs. UI: Model/account selection, Settings. PRD AC-06, AC-13–15, AC-18.
- **Depends on:** P2-T1.
- **Verification:** `make test-unit`; `make test-runtime CASE=execution-boundary`; `make test-runtime CASE=execution-recovery`; `make test-integration CASE=account-capabilities`.
- **Pass:** Real workload containers cannot reach PostgreSQL, the Engine socket, another job workspace, or unapproved egress. Selected-provider access through the proxy works; timeout/OOM/cancel/worker-restart states are observed. Unsupported combinations and disabled plugins are rejected. Credentials do not enter prompts, responses, published output, or argv.
- **Early prerequisite check:** Prove the selected Pi/Claude/Codex builds can use the constrained proxy before wiring paid analysis. Verify Codex native read-only/workspace-write behavior in Linux containers. A failing transport or sandbox must be repaired in the adapter/profile while preserving the network contract; do not declare isolated execution complete based on prompt restrictions.

### P3-T2: Wire Pi, Claude Code, Codex CLI, Jev triage, and commit analysis

- **Scope:** Versioned prompts/result schemas, Pi/Claude/Codex argument/event adapters, optional Jev HTTP adapter, triage input completeness, exact detailed categories/reports, immutable analysis history. Codex maps model/effort to native flags/config, parses JSONL completion/failure events, validates final schema output, and uses the shared profile/default contract.
- **Sources:** Architecture: Commit triage/analysis, Accounts/plugins/adapters. UI: Commit review/model selection. PRD AC-04–06, AC-13, AC-14.
- **Depends on:** P3-T1 and P2-T2.
- **Verification:** `make test-unit`; `make test-integration CASE=commit-analysis`; selected container smoke checks with test accounts for each provider/auth mode used in the release.
- **Pass:** Pi, Claude, and Codex produce validated results preserving the chosen profile and exact four-category enum. Codex failure/incomplete events cannot publish a success; unsupported efforts are rejected. Jev returns the shared triage contract and preserves uncertainty. Optional AI-off/manual flows remain usable. Invalid output is rejected or repaired once with attempt evidence. Retry keeps the same profile; a changed profile starts a new job.
- **External evidence:** Test DeepSeek, Command Code through the specified plugin, OpenAI through Pi and Codex, Claude, and optional Jev using funded/test access during implementation. Native subscription and API-key paths are checked separately, including Codex ChatGPT/device login where available. A fixture pass cannot be reported as live provider compatibility.

**Checkpoint:** A new candidate can be classified, notified, explicitly analyzed using a supported chosen profile, and reviewed with source evidence.

## Phase 4 — Reuse version scripts and grounded audit context

### P4-T1: Generate and reuse version recipes

- **Scope:** Pinned release/asset fingerprints, Python recipe contract and fixtures, scoped target fetching, activation/observations, scheduled reuse, manual observations, Version UI.
- **Sources:** Architecture: Version recipes/observations, Container execution. UI: Version presentation. PRD AC-07, AC-18.
- **Depends on:** P3-T2.
- **Verification:** `make test-unit`; `make test-runtime CASE=version-recipe`; generation adapter contract fixtures for Pi, Claude, and Codex.
- **Pass:** Re-running a validated recipe invokes no generation agent. Leaked metadata, unique/shared hashes, modified assets, denied redirects, unavailable targets, and conflicting signals yield truthful observations with evidence and corpus limitations.

### P4-T2: Integrate the pinned Trail of Bits context workflow

- **Scope:** Portable licensed skill content, orientation/function/synthesis orchestration, source citations, report/supporting files, coverage/cancellation, stale-state presentation and analysis-context selection.
- **Sources:** Architecture: Audit context workflow, Jobs/recovery, Commit analysis. Evidence: Trail of Bits skill. UI: Context presentation. PRD AC-08.
- **Depends on:** P3-T2.
- **Verification:** `make test-integration CASE=audit-context`; small funded fixture runs through Pi, Claude, and Codex adapters when validating actual generation behavior.
- **Pass:** The output includes `audit-context-building.md`, supporting function documents, pinned source/skill/profile references, and visible partial coverage/open questions. Changing the source revision makes prior context stale. Compact child results feed synthesis without silently omitting failed units.

**Checkpoint:** The operator reuses a recipe to observe remote versions and accesses source-grounded context for investigations.

## Phase 5 — Monitor and analyze eligible CVEs

### P5-T1: Implement CVE ingestion, identity, score gates, and ranges

- **Scope:** NVD connector/schema fixtures/cursors, configured product selectors and confirmations, record modification handling, Base-score gate, supported version comparators, eligibility/applicability UI.
- **Sources:** Architecture: CVE ingestion/gates/applicability, Data model. UI: CVE presentation. PRD AC-09, AC-10.
- **Depends on:** P4-T1 and P2-T1.
- **Verification:** `make test-unit`; `make test-integration CASE=cve-monitoring`; a read-only NVD connector smoke check during implementation to validate current query/rate behavior.
- **Pass:** Threshold boundaries and all selected scoring versions work; v2-only/unscored and unconfirmed identities are blocked. Compound or unsupported version conditions remain Unknown. A modified record is re-ingested; partial paging cannot skip records. Validate PHP comparison behavior with WordPress fixtures.

### P5-T2: Wire gated CVE analysis and notifications

- **Scope:** Manual/optional automatic CVE jobs, pre-dispatch revalidation, immutable analysis inputs, CVE report/evidence, meaningful-change deduplication, notification links, Create finding entry.
- **Sources:** Architecture: CVE gates, Agent contracts, Discord delivery. UI: CVEs/Findings entry. PRD AC-06, AC-09, AC-10, AC-16.
- **Depends on:** P5-T1, P3-T2, P4-T2.
- **Verification:** `make test-integration CASE=cve-dispatch`, including profile/dispatch contract fixtures for all three coding-agent runtimes.
- **Pass:** Neither manual nor scheduled paths can bypass the product/score gate. A change while queued prevents using stale eligibility. Analysis retains evidence and does not replace deterministic applicability or automatically mark a finding confirmed.

**Checkpoint:** Product-matched CVEs are updated, filtered, analyzed under current policy, and reviewable beside deployed-version evidence.

## Phase 6 — Complete findings and reproduce their artifacts

### P6-T1: Implement findings, status history, and artifact storage

- **Scope:** CVE/0day records and linking, Open/Fixed status, affected/fixed version evidence, draft/complete artifact sets, safe upload/previews/download, finding UI.
- **Sources:** Architecture: Findings/reproducible artifacts, Data model, API contracts. UI: Finding presentation. PRD AC-11, AC-12.
- **Depends on:** P5-T2.
- **Verification:** `make test-integration CASE=finding-artifacts`.
- **Pass:** Required Python/Docker/Markdown artifacts download intact. Missing artifacts remain Draft. Path/size/secret-bearing outputs are rejected. A fixed upstream release cannot silently close an affected remote target. CVE linkage preserves a 0day's history.

### P6-T2: Generate bundles and execute isolated lab verification

- **Scope:** Artifact-generation profile/prompts/manifests, pinned vulnerable-app bundle, bounded build profile, isolated lab/PoC runs, verification metadata and failure presentation.
- **Sources:** Architecture: Findings/reproducible artifacts, Container execution. ADR-0002. UI: Artifact/lab interaction. PRD AC-12, AC-18.
- **Depends on:** P6-T1 and P3-T1.
- **Verification:** `make test-runtime CASE=finding-lab` against an intentionally vulnerable local fixture and a non-reproducing fixture; artifact-generation adapter contract fixtures for Pi, Claude, and Codex.
- **Pass:** The pinned vulnerable fixture starts in Docker and its PoC produces the declared evidence. Verification has no outbound target access or real credentials. Failed reproduction, missing source/dependencies, and modified artifact revisions remain distinct and visible. Agent output is not labeled verified merely because it contains a Dockerfile.

**Checkpoint:** Every completed finding contains the three requested artifacts and preserves reproducibility/verification evidence.

## Phase 7 — Prove the complete Docker operator journey

### P7-T1: Finish recovery, self-hosting documentation, and acceptance

- **Scope:** Container-based backup/restore, credential-key recovery instructions, lifecycle reconciliation, production health checks, focused UI checks, final fixture journey, setup/user documentation.
- **Sources:** Architecture: Deployment/verification, Jobs/recovery, Security boundaries. UI: Shared states. PRD AC-01–18.
- **Depends on:** P4-T1, P4-T2, P5-T2, P6-T2.
- **Verification:** `make check`; complete focused suites once; `make test-journey`; clean Compose startup, application/worker/broker replacement, and consistent backup/restore.
- **Pass:** A clean host needs only Docker/Compose for application execution. The operator registers both source kinds, receives changes, makes the explicit analysis decision, observes version/context, analyzes only eligible CVEs, and retrieves a complete finding. Restart/restore retains evidence and truthful job/delivery state. All selected provider compatibility evidence is attached or explicitly unresolved.

**Release completion:** Every phase task and its focused proof is complete. Intermediate mock-only integrations and unavailable provider access cannot be described as finished functionality.

## Selected verification boundaries

Pure parsing, score math, range comparisons, input validation, and profile resolution use local tests. The following boundaries require broader proof. Tests can combine related assertions sharing the same fixture; implement no more than the skill's lane ceilings per observable outcome.

| Outcome / AC | Real boundary | Controlled dependency | Failure a local proof misses |
|---|---|---|---|
| Login/persisted program: AC-01, AC-02 | API/session/real PostgreSQL | Operator and input fixtures | Session/CSRF policy or schema integration differs from a local validator |
| Upstream monitoring: AC-03, AC-04 | Worker/cursor/snapshot/real DB | Fixture GitHub HTTP and local SVN repository | Partial imports advance a cursor, or an old-dated merge is missed |
| Review decision: AC-05, AC-16 | API/outbox/job transaction; one browser flow | Webhook/classifier responses | A notification/link visit accidentally submits an analysis |
| Isolated execution: AC-06, AC-18 | Broker/actual engine/workload/proxy | Provider fixture and hostile workload | Prompt/launch assertions pass while egress, secrets, limits, or cancellation fail |
| Recipe/context reuse: AC-07, AC-08 | Probe execution/DB; coordinator/artifact outputs | Target/agent result fixtures | Script reuse invokes another agent or reports stale/partial context as complete |
| CVE dispatch: AC-09, AC-10 | API/queue/policy records | NVD response fixtures | A manual request or queued job bypasses updated score eligibility |
| Finding bundle: AC-11, AC-12 | Artifact storage/download and actual lab build/run | Vulnerable and non-reproducing local apps | A complete-looking bundle is missing bytes or cannot reproduce the stated condition |

Use at most three focused browser flows: register/login/persistence, candidate review/explicit analysis, and the final operator journey. Settings and artifact edge cases are primarily API/component checks. The final journey adds clean deployment evidence; it does not replace the focused failure-boundary tests.

## Effort estimate

These are rough engineer-days for one experienced full-stack engineer, not measured estimates or elapsed-time promises. They include the specified proof and documentation. Runtime/provider access, audit scope, and lab complexity remain the largest uncertainties.

| Phase | Rough effort |
|---|---|
| 1 — Login/program foundation | 3–5 days |
| 2 — Durable monitoring/review/Discord | 5–8 days |
| 3 — Accounts, isolation, Pi/Claude/Codex/Jev | 10–16 days |
| 4 — Version recipes and audit context | 8–12 days |
| 5 — CVE matching and analysis | 7–12 days |
| 6 — Findings and reproducible labs | 9–15 days |
| 7 — Recovery and final acceptance | 5–8 days |
| **Total** | **47–76 engineer-days, about 10–16 working weeks** |

The Codex follow-up adds roughly 2–4 engineer-days to phase 3 for its runner, native auth/capability adapter, and protocol/sandbox verification. Shared operation contracts retain the same seven phases and thirteen tasks.

This is a high-cost new application because no code or harness exists and several external/process boundaries must be established. The first useful monitoring checkpoint arrives after phases 1–2; that checkpoint is not the requested complete release.

## Completion checklist

The 2026-10-06 CVE UI/UX correction follows this order: reproduce the saved-run and large-bundle presentation failures; add focused navigation, launch, preview, and immutable-download regressions; implement URL-selected CVE detail tabs, one-run result viewing, searchable/paged shared artifact browsing, and analysis-resource ZIP downloads; verify frontend/API tests, repository lint/type/build checks, and desktop/mobile Chrome behavior. Its scope is CVE details/launch, the shared artifact browser and launch form, finding downloads, job-to-result links, analysis response typing, and the authenticated hash-checked archive read path. Source ingestion, scoring gates, agent execution, and lab policy retain their contracts.

The 2026-10-05 agent-session correction follows this dependency order: enable full native history in private per-run storage and durable redacted broker archives; expose job-owned historical agent runs with live-only steering; implement completion polling, safe composer/actions, latest/selected-run viewing and stable scrolling; verify focused frontend/API regressions plus actual Docker exit/cancellation and a Chrome layout inspection. The implementation scope is the session component and its shared response type/styles, job detail mounting, session API/runtime-start metadata, and runner history collection/retention. Existing unrelated application and build changes remain outside this correction. Evidence is recorded in [verification](../verification.md).

- [x] Every PRD AC has an implementation task and an observable repository proof boundary.
- [x] Requested workflows are implemented, including WordPress without GitHub and optional AI-off/manual review.
- [x] Pi, Claude Code, and Codex CLI version/protocol/container behavior has compatibility evidence; live connections require operator credentials.
- [x] Codex is selectable for every agent-backed operation and can be saved in global/program defaults with native supported model/effort values.
- [x] Score criteria apply consistently to manual and automatic CVE analysis.
- [x] Upstream status, remote applicability, artifact completeness, and verification remain distinct.
- [x] Docker isolation/recovery is observed against the actual Engine.
- [x] Documentation and lockfiles describe actual behavior, including native-setup and declarative-lab limits.

Final results: 49 backend + 46 runtime + 12 frontend tests passed; HTTP journey, transaction visibility, backup/restore readback, build/type/lint checks, and clean main deployment passed. No operator provider accounts or production assets were configured during implementation.
