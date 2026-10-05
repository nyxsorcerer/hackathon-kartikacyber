# Implementation coordination contract

This is the shared contract for the first complete implementation, authorized by the user's “Build it” instruction. Preserve the PRD's outcomes and all three coding-agent choices. Each owner can make reversible local implementation choices within this boundary. Coordinate contract changes with the orchestrator before changing a consumer-facing shape.

## Ownership

- Backend agent: `backend/`, backend tests, migrations, domain services, scheduler/worker, API/security/persistence. Do not edit `runner/`, frontend, or root deployment files.
- Frontend agent: `frontend/`, its tests and package manifests. Do not edit backend, runner, or root deployment files.
- Runtime agent: `runner/`, root Dockerfiles/Compose files, runtime tests, and pinned agent/plugin/skill manifests. Do not edit frontend or backend modules.
- Orchestrator: root Makefile, bootstrap/backup helpers, integration fixtures/journey, documentation, cross-owner integration and final checks. When a correction belongs to another owner's active files, send it back to that owner.

All agents share the workspace. Preserve other owners' edits and adapt to their work. Read the PRD, design, and UI specification as governing context; these instructions settle serialization only.

## API

All paths below begin with `/api`. A session cookie authenticates requests. `GET /auth/session` returns `{authenticated: boolean, username?: string, csrf_token?: string}`. Login accepts `{username: "admin", password: string}` and returns the authenticated session shape. Browser mutations send `X-CSRF-Token` after login. Structured errors use `{code, message, fields?: object, retryable?: boolean}` with JSON; lists use `{items: array, next_cursor: string|null}`. Responses expose no secrets. IDs are strings; times use UTC ISO-8601.

### Domain records

Program fields: `id`, `asset_name`, `asset_url`, `product_kind`, `product_name`, `source_kind` (`github` or `wordpress`), `source_url`, `source_ref`, `source_path`, `plugin_slug`, `monitor_interval_days`, `monitor_enabled`, `archived`, `source_generation`, `last_check_at`, `next_check_at`, `last_error`, `version` (latest observation or null), and `config`.

`config` contains `triage_mode` (`disabled`, `jev`, `pi`, `claude`, `codex`), `profiles` keyed by operation, `cve_selectors` (list of typed selector objects), `cve_min_score`, `cve_versions` (subset of `3.0`, `3.1`, `4.0`), `cve_auto_analyze`, `active_recipe_id`, `monitor_interval_inherited`, `version_scheme`, `version_monitor_enabled`, `asset_origins`, `jev_connection_id`, and `jev_model_id`. Program `latest_version_check` supplies the latest failure independently of the last successful `version`. Agent operations are `commit_triage`, `commit_analysis`, `version_recipe`, `audit_context`, `cve_analysis`, and `finding_artifacts`.

Profile fields: `agent` (`pi`, `claude`, `codex`), `connection_id`, `model_id`, and nullable `reasoning_effort`. Server resolves defaults and validates every combination. These fields are identical for all operation submissions. Runtime receives a resolved provider/auth mode separately.

Commit fields: `id`, `program_id`, `revision`, `message`, `author`, `committed_at`, `url`, `files`, `diff`, `diff_complete`, `triage_status`, `triage_result`, `review_decision`, and `analyses`. Detailed analysis uses the four exact PRD category labels.

CVE fields: `id` (CVE ID), `program_id`, `title`, `description`, `published_at`, `modified_at`, `scores`, `match_status`, `eligible`, `eligibility_reason`, `applicability`, `affected_versions`, `fixed_versions`, `references`, and `analyses`. Score entries contain `version`, `base_score`, `vector`, `source`. Keep per-program match/eligibility separate from global records.

Finding fields: `id`, `program_id`, `kind` (`cve` or `0day`), nullable `cve_id`, `title`, `status` (`open` or `fixed`), `affected_versions`, `fixed_versions`, `target_applicability`, `source_commit_id`, `source_analysis_id`, `artifact_state`, `artifacts`, `lab_runs`, `created_at`, `updated_at`. `artifact_state` is `{status: "draft"|"complete", missing: string[], limitations: string[], vulnerable_version: string|null}`. Analysis records expose structured output under `result`; CVE `qualifying_score` names the gate witness.

CVE analysis generates the full n-day bundle in the analysis run and creates or updates its program's CVE finding, preserving an existing finding's title and operator status. Analysis `result.finding_id` and job `result.finding_id` link to that finding; earlier analysis files remain immutable. Both CVE analysis and finding generation require all paths in `artifacts.REQUIRED` and a valid pinning declaration before the job succeeds. Incomplete bundles are published as drafts, the job retains artifact/finding/analysis identifiers in `result`, and fails with `incomplete_bundle` and `partial_output_retained:true`. Finding generation receives the linked analysis JSON, original report and pinned CVE record as evidence. Generation never verifies reproduction or automatically closes a finding; unsupported lab build steps remain explicit prerequisites.

Job fields: `id`, `kind`, `program_id`, `status`, `progress`, `profile`, `created_at`, `started_at`, `finished_at`, `error`, `result`, `events`. Job submission returns `202 {job_id, status_url}`. Idempotency keys are supported. Profile/input changes create a new job; a retry reuses the recorded profile/input.

### Routes

- `GET /dashboard`: `{programs, security_reviews, eligible_cves, open_findings, running_jobs, failed_jobs, recent_events, due_programs}`; counts are numeric, lists are real data.
- `GET/POST /programs`; `GET/PATCH /programs/{id}`; `POST /programs/{id}/checks`.
- `GET /programs/{id}/commits`; `GET /commits/{id}`; `POST /commits/{id}/review` with `{decision: "pending"|"dismissed"|"candidate"}`; `POST /commits/{id}/analyses` with `{profile?: Profile}`.
- `POST /programs/{id}/version-recipes` with `{profile?: Profile}`; `POST /programs/{id}/version-checks`; `GET /programs/{id}/version-observations`; `POST /programs/{id}/version-observations` for `{version, evidence}` manual entries.
- `GET /programs/{id}/version-recipes` lists recipe revisions with metadata, status, profile, source reference/generation, and artifacts.
- `GET/POST /programs/{id}/audit-contexts`; generation accepts `{profile?: Profile, focus?: string}`; report entry includes `id`, `source_ref`, `skill_revision`, `coverage`, `status`, `created_at`, `artifacts`.
- `GET /cves` with optional `program_id`; `POST /programs/{id}/cves/{cve_id}/analyses`; `POST /programs/{id}/cves/{cve_id}/match` with `{confirmed: boolean}`; `POST /programs/{id}/cve-sync`.
- `GET/POST /findings`; `GET/PATCH /findings/{id}`; `POST /findings/{id}/artifacts` multipart upload; `POST /findings/{id}/artifact-generations`; `POST /findings/{id}/lab-runs`.
- `GET /artifacts/{id}/content`; `GET /findings/{id}/download` returns the complete bundle ZIP.
- `GET /jobs`; `GET /jobs/{id}`; `GET /jobs/{id}/events`; `POST /jobs/{id}/cancel`; `POST /jobs/{id}/retry`.
- `GET /jobs/{id}/session?run=` returns `{runs, run_id, agent, agent_status, screen, held}` for a running job's Herdr agent session (latest run by default); `POST /jobs/{id}/session` with `{run_id, action: "prompt"|"keys"|"hold"|"release", text?, keys?}` chats with or steers it. Only runs of the job's current attempt are reachable, so the application joins the `control` network.
- `GET/PATCH /settings`: monitoring days, `default_profiles`, webhook enabled/masked/configured state, dashboard URL, optional integration-health fields. Webhook URL/key writes are write-only.
- `GET/POST /accounts`; `PATCH/DELETE /accounts/{id}`; `POST /accounts/{id}/check`; `GET/POST /accounts/{id}/capabilities`; `POST /accounts/{id}/login`; `GET /accounts/{id}/login`.
- Native login starts reuse the account's queued/running/cancelling login attempt. A conflicting credential operation returns retryable `account_busy` (409) promptly. Login status includes verification events while the attempt runs, even when its runtime progress percentage stays unchanged.
- `POST /accounts/{id}/native-cache` accepts a protected multipart JSON file for native Claude/OpenAI connections. Upload limit is 1 MiB; the validated credential envelope is further bounded, encrypted, and write-only. Import resets capability state and never starts provider calls implicitly.
- Account fields: `id`, `label`, `provider` (`deepseek`, `commandcode`, `openai`, `claude`, `jev`, `github`, `nvd`), `auth_type` (`api_key`, `native_oauth`), `supported_agents`, `status`, `credential_configured`, `models`, `agent_models`, `usage`, `last_checked_at`. API-key writes use `api_key`. Model entries: `id`, `name`, `reasoning_efforts`, nullable `default_effort`. `agent_models` maps runtime IDs to their discovered model lists; `models` remains a union for compatibility. Profile selection and validation use the selected runtime's catalog, since Pi and Codex can expose different models/efforts for one OpenAI connection.
- `GET /plugins`; `PATCH /plugins/{id}` with `{enabled}`. Plugins expose pinned version, source, health, enabled state, and provider contribution.
- `POST /settings/webhook/test`; `GET /notifications` for delivery history.
- `POST /notifications/{id}/retry` queues a standard accepted delivery job for a retained failed event.

## Runtime broker contract

The internal broker is authenticated by `X-Broker-Token` from `NUMEN_BROKER_TOKEN`. URL environment: `NUMEN_BROKER_URL`. Its default port is 8081. Frontend callers never access it.

`POST /internal/runs` accepts `{attempt_token, kind, profile, prompt, output_schema, inputs, limits, target_policy?, build?}`. `profile` extends the public profile with `provider_id`, `auth_type`, and a protected `credential` envelope. Inputs are an array of `{path, content_base64}`. Paths are safe workspace-relative files. Limits and kind map to hardcoded broker-controlled profiles; caller values can lower limits, not exceed configured maxima. Prompt/schema never contain credential values. The broker does not accept arbitrary container flags, host mounts, images, or command strings.

Kinds include `agent`, `probe`, `lab`, `capabilities`, and `account_login`. `agent` has an `operation` in the profile. Probe inputs include the recipe/script and JSON target input; lab inputs include the finding bundle. `target_policy` scopes origins/methods and request budgets.

`build` is accepted only for an `agent` run whose operation supports it (`cve_analysis`), and is rejected for every other kind or operation. A build run reproduces a vulnerable application rather than only reading it, so the broker grants it: a private per-run Docker daemon reachable at `DOCKER_HOST=tcp://docker:2375`, a disk-backed writable `/workspace` volume in place of the memory-backed one, a higher limit ceiling (`timeout_seconds` 10800, `memory_mb` 8192, `cpus` 4, `pids` 2048, `output_bytes` 64MB), `nofile` 4096, and proxy CONNECT access to source-hosting, package-registry, and image-registry hosts in addition to the provider's own. The workload still runs nonroot with a read-only image, dropped capabilities and no new privileges, and it never receives the host Engine socket. The daemon container itself is privileged, which nested containers require on Engine 20.10 without cgroup delegation; its own dockerd runs unprivileged inside the rootless image, it holds no Numen or provider credential, and it has its own egress network. Everything the daemon builds or runs is labeled with the run and destroyed with it, so a build run can reach the public internet through the daemon and anything it must keep has to be written to `/workspace/outputs`.

Submission returns `{run_id, status}`. `GET /internal/runs/{id}` returns `{run_id, status, progress, events, error?, result?, outputs?}`. Outputs are `{path, content_base64, sha256, size}`. `POST /internal/runs/{id}/cancel` stops/reconciles the run. `GET /internal/runs/{id}/outputs` retrieves validated outputs. Standard statuses are `queued`, `running`, `succeeded`, `failed`, `cancelling`, `cancelled`.

Implement real Pi, Claude, and Codex argv/protocol adapters, isolated container jobs, and capabilities/native login flows. Fixture modes may exist only in explicit test configuration. Unsupported credentials or unavailable engines fail truthfully. Sensitive credentials are never included in ordinary run responses or logs. Trusted native-login credential ingress requires a separate authenticated retrieval channel, deleted after successful vault ingestion; coordinate the exact minimal channel with backend owner.

## Quality and verification

Backend uses Python/FastAPI/SQLAlchemy/Alembic and PostgreSQL in Docker; SQLite may be used for cheap deterministic API tests, but PostgreSQL claim/lease behavior must be checked against PostgreSQL. Frontend uses React/TypeScript/Vite. The backend serves built frontend assets at `/` in deployment. All actual source fetches, job execution, and database changes remain observable and durable. Implement all requested workflows; do not fabricate monitoring results or mark provider mocks as verified compatibility.

Each owner delivers completed code and focused test/build evidence, plus exact remaining limitations. The orchestrator performs cross-service and browser integration before declaring the application complete.

## Verified implementation adjustments

- Initial source history establishes a baseline. A GitHub baseline imports only the newest page of history (up to 100 revisions), so large repositories stay within API rate limits. Subsequent unseen revisions can trigger optional triage. Commit jobs pin immutable revisions; a later head advance does not invalidate historical evidence.
- CPE selectors query NVD by product identity (`virtualMatchString` with wildcard version fields), because `cpeName` rejects wildcard versions. Deployed-version applicability is evaluated separately.
- Source snapshots omit binary media (images, fonts, audio, video) and hold up to 20,000 files / 64 MiB, so CMS-sized sources fit. Agent runs receive `source/` as one compressed archive input that the runner validates (regular files, safe paths, the same expanded bounds) and expands into the read-only input volume; other inputs keep the 512-file / 32 MiB per-run limit.
- Version recipes receive the release fingerprint map as `release-corpus.json` and only a coverage summary in the prompt. Numen writes `fingerprints.json` from the corpus unless the agent supplies an identical map.
- Automatic CVE analysis is held while a program has no successful source check; the baseline check dispatches held analyses.
- Audit context takes `max_functions` (1–100, default 24) per request: orientation may select at most that many significant functions, each analyzed in its own agent run. Function analyses run in parallel (`NUMEN_AUDIT_CONCURRENCY`, default 3), and the job's progress reports the stage and how many functions are analysed. An interrupted, failed, or cancelled audit continues instead of starting over: lease recovery, Retry, or an identical request (same source and skill revisions, focus, max functions, and agent profile) reuses the latest interrupted checkpoint's function selection and analysed functions (checkpoints store their records as `audit-functions.json`) and re-runs only unfinished or failed functions. A continued checkpoint is marked `continued_by` and never reused twice; `fresh` starts over. Synthesis receives the per-function records as `audit-functions.json` with only an index in its prompt, so record size does not reach the prompt bound. When synthesis follows the skill's `audit-context/DOSSIER.md` layout, Numen writes the `audit-context-building.md` entry document linking it.
- Jobs run concurrently. The worker runs `NUMEN_WORKER_CONCURRENCY` job slots (default 3) plus one slot that never claims long agent, lab, or login work, so source checks, CVE syncs, version checks, and notifications proceed during long audits. Claims stay row-locked (`SKIP LOCKED`) and attempts fenced. The broker runs up to `NUMEN_RUNNER_CONCURRENCY` workloads at once (default 4); each run has its own containers, networks, and gateway, and an agent run may use up to its 1 GiB memory limit. An attempt records every runtime phase it starts (`runtime_phases`), so failure handling and lease recovery cancel all of its runs and treat it as stopped only when each is terminal; once an operation is stopping, no new phase starts, and a phase that finds its attempt cancelled or lost cancels its own run.
- Agent runs have no execution deadline: the backend omits `timeout_seconds` and waits until the run ends, the runner applies a deadline only when one is requested, and audit context has no cumulative time budget. Operators stop long runs by cancelling the job. Probe, lab, and login runs keep their time limits.
- A broker run is terminal only after owned workload cleanup is proved. Lost submission acknowledgement is resolved by authenticated attempt-token lookup; an unavailable broker/engine preserves cancelling/pending recovery instead of allowing overlapping replacement.
- API database transactions finish before an HTTP success is emitted, so a returned program/job/artifact identifier is immediately readable and a late constraint failure cannot follow a false success.
- Native connection setup supports protected cache import. Codex also supports device login, and Claude supports its manual OAuth login: the operator pastes the authorization code via `POST /api/accounts/{id}/login/code`, and the worker relays it to the running login workload. Command Code native connections run in Pi: the bundled plugin's login shows its Studio URL, and the operator pastes the resulting API key through the same endpoint. Native import accepts pi's or the Command Code CLI's `auth.json`. Pi automatic headless OAuth setup for other providers is not exposed as a working flow.
- The first lab verifier materializes pinned/local declarative Dockerfile instructions. Executable RUN/remote ADD are rejected explicitly; uploaded originals remain downloadable/unverified.
- The pinned Pi image applies a hash/integrity-verified brace-expansion security repair and audits the patched graph during build. See the runtime patch manifest and tests.
