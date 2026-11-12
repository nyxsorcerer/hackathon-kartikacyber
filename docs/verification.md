# Implementation verification

Date: 2026-10-04. The application is implemented and deployed locally. This record distinguishes executed repository proofs from account-dependent checks.

## Asset Monitor fork baseline (2026-11-12)

Forked from Numen `experiment/herdr-agent-sessions` at `4970c7b` (ADR-0003). Before any feature change, the fork's Docker project, images, labels and ports were renamed (`asset-monitor`, `asset-monitor-*`, 8788, 18788, 18091) so it can run beside a Numen deployment, and `undici` was raised from 8.11.2 to 8.12.4 in the Pi, Claude Code and Codex runtime locks (with an npm override for Pi's nested copy), because the image build's `npm audit --audit-level=high` now fails on advisories published against 8.0.0 to 8.12.1.

On Docker Desktop (Engine 20.10.22, 10 CPUs, 8 GB): `make build` and `make check` passed; backend unit 133 passed; runner unit 122 passed, 58 skipped; backend integration 227 passed; runtime 179 passed, 1 failed; frontend 96 passed in 18 files. The one failure is the already recorded `test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider` (the pinned Claude CLI no longer advertises Grep/Glob). No paid inference and no production-target request was made.

## Program renamed to Application (2026-11-13)

Phase 1, T1. Migration `3f1a2b4c5d61` renames `programs`/`program_cves` to `applications`/`application_cves`, every `program_id` to `application_id`, the generated constraint names, and `actions.resource_type` `program` to `application`. It also recomputes each job's `input_hash`, which fingerprints the owner under its column name, so an idempotency key used before the upgrade still returns its job instead of `idempotency_conflict`. The API moved to `/api/applications*` (query `application_id`, job `application_id`/`application_name`, dashboard `applications`/`due_applications`, error `immutable_application`) and the UI to `/applications*`. `test_postgres_migration_renames_programs_to_applications` inserts rows at `fe74f85e4023`, upgrades, checks ids, values, the reused idempotency key, no `program` constraint names and a clean `alembic check`, then downgrades and reads the old names back.

`make check` passed; backend unit 133 passed; runner unit 122 passed, 58 skipped; backend integration 228 passed; frontend 96 passed in 18 files; `make test-journey` passed. The runtime suite was not re-run: the runner change is two comments.

## Repositories linked to Applications (2026-11-13)

Phase 1, T2. Repositories are stored once per normalized source URL (`repositories`) and linked to Applications (`application_repositories`: role `own` or `upstream`, on/off, removed, Locked version and its source). A partial unique index allows one active Own repository per Application. Commits, snapshots, the cursor and the last error belong to the repository, so `schedule()` and Check now queue one `source_check` per repository however many Applications share it, and its new commits are triaged once, with the first linked Application that has Triage on. Check now returns `{items: [{repository_id, job_id, status_url}]}`.

Migration `4a2b3c5d6e72` turns each Program's source into an enabled Upstream repository with no Own repository, keeps CVE selectors, recipes and observations, and takes the Locked version (`deployed`) from the newest detected observation of the current source generation. Programs sharing a URL become one repository: the most recently checked one is canonical, and the others' commits and snapshots move to earlier generations, so they stay visible but count as `historical_source`. Queued source checks are pointed at their repository. `downgrade()` refuses, because the merge cannot be undone; `test_postgres_migration_renames_programs_to_applications` therefore stops at `3f1a2b4c5d61`, and the clean `alembic check` moved to `test_postgres_migration_moves_program_sources_to_upstream_repositories`. `tests/test_repositories.py` covers the AC-A01 cases: a saved Application reopening with its repository states, one Own repository at most, the shared `facebook/react` repository polled and triaged once, the commit list of linked repositories (removed links included), and Check now per repository.

Because a repository now outlives a journey run, the journey links its own `numen/fixture-<run>` GitHub repository (the fixture server serves it as `numen/fixture`) and checks the WordPress SVN change by the repository cursor rather than by commit counts. The journey stack's database, which held earlier runs' Applications with their source columns, upgraded through the migration.

`make check` passed; backend 224 passed, 10 skipped on SQLite and 234 passed against PostgreSQL (`./scripts/test-backend.sh all`); runner unit 122 passed, 58 skipped; frontend 96 passed in 18 files; `make test-journey` passed. The runtime suite was not re-run: this task does not change the runner.

## Intake: token, ETag, Baseline, Backfill and Pre-filter (2026-11-13)

Phase 1, T3 (A02). Every GitHub request goes through `Sources.github_headers()`, which refuses with `github_token_required` when no `github` Account holds a token. `schedule()` queues nothing for such a repository and sets that error on it instead, and Check now's job fails before any request. The commit-list poll sends `If-None-Match` with `repositories.etag` (migration `5b3c4d6e7f83`). A `304` returns before any compare or commit request, and the check then only sets `last_check_at` and clears `last_error` (`not_modified: true`). A repository's first check sets its Baseline at the head without importing history, on GitHub with one list request and over SVN with `svn info`. This removes Numen's newest-page GitHub import, its full SVN history import and the `baseline` triage status; the UI still labels old `baseline` rows. `POST /applications/{id}/repositories/{repository_id}/backfills {count: 1-100}` queues a `backfill` job. It imports the last N commits up to and including the Baseline through the same record builders, so the same diff caps apply, and triages them like new commits, marked `backfill: true`. Every imported commit records `prefilter` (`numen/prefilter.py`), which never changes its triage or review state. An incomplete diff whose analysis says `Unrelated change` is recorded as `Insufficient context` / `needs_more_evidence`, even after a whole-change `diff_review`, which changes Numen's tested behaviour.

`tests/test_intake.py` covers the AC-A02 cases: a head standing for 10,000 commits gives 1 request, 0 imports and 0 Triage runs, then 1 for a new head and 3 for Backfill 3; a 304; an unchanged WordPress plugin (real `svnadmin`); a missing token (no request, visible error, WordPress still polled); every Pre-filter rule; and capped diffs on the poll and Backfill paths. `test_an_incomplete_diff_never_yields_unrelated` replaces Numen's incomplete-diff test. The fixture server honours `sha` and answers `If-None-Match` with `304`. The journey adds a fixture GitHub token and asserts the empty Baseline, `b`/`c` after advancing, Backfill 1 importing `a`, and a `304` that imports nothing. It passed twice on the same stack.

`make check` passed; backend 258 passed against PostgreSQL (`./scripts/test-backend.sh all`); `make test-unit` passed (backend 160, runner 122 passed, 58 skipped); frontend 96 passed in 18 files; `make test-journey` passed. The runtime suite was not re-run: this task does not change the runner.

## Release branches and intervals in seconds (2026-11-13)

Phase 1, T4 (A02). An Upstream GitHub repository watches its default branch plus the Release branch of each Locked version that an active link uses (enabled, not removed, Application not archived). A check resolves each new Locked version once, trying `{major}.x`, `{major}.{minor}`, `release-{major}` and `v{major}` with `GET /repos/{repo}/branches/{name}` before the publication fence, and stores the result on the link (`release_branch`, `release_branch_version`). Each Release branch is polled with its own cursor and ETag in `repositories.watched_branches`, is baselined at its head the first time, and imports its new commits with `branch` set; branches no link uses any more are dropped. `release_branch_status` is `pending`, `matched` or `unknown` ("release branch unknown", default branch only), and null for Own links, WordPress repositories and links without a Locked version. Intervals are stored in seconds (`monitor_interval_seconds`, 300 to 315,360,000) for each Application and for the global default; `NUMEN_MONITOR_INTERVAL_DAYS` still seeds the default in days. The UI enters and shows them in minutes, hours or days. Migration `6c4d5e7f8094` adds the branch columns, converts `applications.monitor_interval_days` and the `settings` value to seconds (×86400), and its downgrade converts back to days, rounding up to at least 1.

`tests/test_intake.py` adds the candidate order, the matched branch (Baseline, an import tagged `18.2`, a 304 on every branch, a changed Locked version resolved again and the old branch dropped), the unknown branch (four lookups once, default-branch requests only, an Own repository never resolving) and the 5-minute minimum (300 accepted and scheduled 300 s ahead, 240 refused with `fields.monitor_interval_seconds` on both routes). `test_postgres_migration_stores_intervals_in_seconds` upgrades 2 days to 172,800 and the 7-day setting to 604,800 and downgrades back. The `ApplicationForm` test submits 5 minutes as 300 and keeps 4 minutes on the field error.

`make check` passed; backend 263 passed against PostgreSQL (`./scripts/test-backend.sh all`); backend unit 164 passed; runner unit 122 passed, 58 skipped; frontend 97 passed in 18 files; `make test-journey` passed, its Applications now created with a 300-second interval, and the journey stack's database upgraded through the migration. The runtime suite was not re-run: this task does not change the runner.

## Upstream derivation from the Own repository (2026-11-13)

Phase 1, T5 (A01). A check of an Own repository queues a `derive_upstreams` job (key `derive:{application id}:{head}`) after its Baseline and whenever an imported commit carries the `dependency_manifest` Pre-filter flag; linking an Own repository that another Application already checked queues one at once, because its unchanged head answers `304`. The job reads the manifests and lockfiles through the GitHub contents API (`Sources.github_file`, token required). `numen/dependencies.py` takes the direct dependencies from `package.json` and `composer.json` (platform packages skipped) and their versions from `package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml` (PyYAML, now declared), `yarn.lock` v1 and Berry, and `composer.lock`. It maps each one to `https://github.com/{owner}/{repo}` from npm's `/{name}/{version}` or Packagist's p2 metadata, using a `composer.lock` `source.url` first. In test mode `NUMEN_NPM_REGISTRY_URL` and `NUMEN_PACKAGIST_URL` replace the real registries, and the journey stack points both at the fixture server. Under the fence, each URL is found or created once and linked: on at the first derivation, off afterwards, with the Locked version recorded as `manifest`. Links whose packages are gone get `removed_at` and keep their commits; hand-added links are not removed; unresolved packages are stored on the Own link and returned as `unresolved_dependencies`. Migration `7d5e6f8091a5` adds `packages`, `unresolved` (both `[]` for existing links) and `derived_revision`.

`tests/test_dependencies.py` covers the parsers (package-lock v1 and v3, pnpm v9 with a peer suffix and v5, yarn v1 and Berry, composer.lock with `packages-dev`, composer.json without `php`/`ext-*`/`lib-*`/`composer-*`) and every repository-field form. Against one MockTransport that serves GitHub, npm and Packagist on fixture hosts, and asserts that no request left them, it also covers:
- a lockfile change that adds `lodash` off and removes `left-pad`, whose commit stays listed, while a hand-added link is untouched and a README commit derives nothing;
- unresolved packages (npm `404`, GitLab URL, no repository field) listed with reasons, scoped-name encoding, `latest` without a lockfile, and Packagist used only without a `composer.lock` source;
- two Own repositories using `react` (package-lock and pnpm) sharing one `facebook/react` repository, with one `source_check` per scheduler tick;
- a shared Own repository derived as soon as it is linked;
- an unreadable `package.json` failing with `invalid_manifest` on the repository's `last_error`.

`test_postgres_migration_keeps_links_and_adds_derivation_state` upgrades and downgrades a link, and the existing `alembic check` reports no drift.

`make check` passed; backend 291 passed against PostgreSQL (`./scripts/test-backend.sh all`); `make test-unit` passed (backend 191; runner 122 passed, 58 skipped); frontend 97 passed in 18 files (`--maxWorkers=2`); `make test-journey` passed, with no Own repository in the journey, and the journey stack was stopped with its volumes kept. The runtime suite was not re-run: this task does not change the runner.

## Phase 1: Applications, repositories and intake (2026-11-13)

Phase 1, T6 (A01, A02), and the phase as a whole. The Application page has a **Repositories** tab (`frontend/src/pages/ApplicationRepositories.tsx`), whose tab count is the number of active links. It has four parts:
- **Own repository:** shows its GitHub URL, branch, Baseline, last check, any `last_error` and a Backfill action. Remove asks for confirmation and calls `DELETE`. With no active Own link, a form POSTs `{role: "own", source_kind: "github", source_url}` and shows 409 and 422 messages, including field messages.
- **Upstream repositories:** one row per link, removed links last and dimmed. Each row has the repository link, its packages, an editable Locked version (an empty value sends `null`) with a Manifest, Operator or Deployed badge, a status (Removed, Error, Off or Watching, plus "Release branch {name}", "Release branch pending" or "release branch unknown"), a Watch switch (`PATCH {enabled}`, disabled when removed), the last check and Backfill.
- **Unresolved packages:** each package with its version and reason.
- **Add Upstream repository:** GitHub URL or WordPress plugin slug, with an optional Locked version.

Backfill opens a dialog for 1 to 100 commits (default 20), POSTs `.../backfills {count}` and reports "Backfill queued". It is disabled until the repository's first check has set its Baseline.

Three smaller changes:
- Source checks, Backfills and `derive_upstreams` jobs now link to `?tab=repositories` instead of `?tab=commits`, and the Jobs page summarises a derivation.
- `PATCH .../repositories/{id}` with `enabled: true` sets the Application's `next_check_at` to now, so a derived link the Operator turns on gets its Baseline on the next tick instead of after a full interval.
- The setup checklist step "Import source history" became "Link and check a repository". The old step could never complete, because a Baseline imports nothing.

`ApplicationRepositories.integration.test.tsx` renders `ApplicationDetail` against a fake API that keeps state and covers each acceptance item:
- the Own repository added after a 422 and a 409, shown with its error, then removed;
- each Upstream state and the switch, save and clear PATCH bodies;
- the same Application reopened after unmounting, with its edited states;
- unresolved packages;
- Backfill `{count: 5}`;
- a WordPress Upstream repository added by hand with a Locked version.

AC-A01 and AC-A02 are covered by `backend/tests/test_repositories.py`, `test_intake.py` and `test_dependencies.py`. The last of these includes two Own repositories using `react` that share one `facebook/react` Upstream repository.

On Docker Desktop (Engine 20.10, 8 GB):

| Command | Result |
|---|---|
| `make build` | passed |
| `make check` | passed (ruff, eslint, tsc, vite build) |
| `make test-unit` | backend 191 passed; runner 122 passed, 58 skipped |
| `make test-integration` | 291 passed against PostgreSQL |
| `make test-runtime` | 179 passed, 1 failed: the known `test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider` (the pinned Claude CLI no longer advertises Grep/Glob) |
| `make test-ui` | 103 passed in 19 files |
| `make test-journey` | passed, 8 PASS lines; the stack was then stopped with its volumes kept |

The first `make test-ui` run had one timeout under load, in `PromptTemplates.integration.test.tsx` at 5 s. A run with `--maxWorkers=2` and a second `make test-ui` both passed all 103. No paid inference and no request to a real Asset, GitHub or registry was made.

Deviations and limits recorded for this phase:
- **Migration merge.** Programs sharing one source URL become one Upstream repository. The Program with the newest `last_check_at` is canonical. The others' commits and snapshots move to earlier generations: they stay visible, and their analyses and findings stay intact, but they are `historical_source` and can no longer be analysed. Programs that share a URL but differ in `source_ref` or `source_path` stop the upgrade with a message naming them, so no Program's branch or subpath is dropped. `downgrade()` of `4a2b3c5d6e72` moves each repository back onto its Application when every Application links exactly one repository that no other Application links, and refuses otherwise.
- **Findings per Application (A01).** Until Phase 3, a commit analysis of a shared repository's commit runs in the context of the first Application that still uses the repository (not archived, link on and not removed; else the first that ever linked it: `commit_application`), and its Finding lands there.
- **Source repository (not in the PRD).** Numen's per-Application operations read a "source repository": the earliest linked repository that is not removed, whatever its role or on/off state. These are version recipe, version check, audit context, CVE analysis and finding artifacts. Adding an Own repository to a migrated Application, or turning a link on or off, keeps it, with the recipe and CVE cursor. Removing its link moves the source to the next earliest link and bumps the source generation, which clears the active recipe and marks audit contexts stale.
- **Fixed ref and path.** A repository's ref and path are fixed when its row is created. Applications that need different branches or subpaths of one URL share the first one's settings.
- **Lower-cased URLs.** GitHub URLs are lower-cased for identity, and the UI shows the lower-cased form.
- **No history import.** The first check no longer imports history, where Numen imported GitHub's newest page and the whole SVN history. Numen tests and the journey changed accordingly.
- **Incomplete diffs.** An incomplete diff whose analysis says `Unrelated change` is recorded as `Insufficient context`, even when the agent reported `diff_review` over a cloned repository. Numen dismissed it.
- **Mandatory GitHub token.** An existing deployment with GitHub sources and no `github` Account stops polling them, and they show `github_token_required`.
- **Short intervals.** With 5-minute intervals, `schedule()` also queues `cve_sync` (NVD rate limits) and `version_check` (which probes the live Asset) on every tick, as in Numen. A separate cadence is left for a later phase.
- **PyYAML.** PyYAML is now declared for `pnpm-lock.yaml`. Refreshing `uv.lock` reaches PyPI at build time, never from tests.
- **Release-branch cost.** Resolving a Release branch costs up to 4 GitHub branch lookups per new Locked version. Every watched Release branch adds one conditional request per poll.
- **npm metadata.** npm metadata is read from `/{name}/{version}`, or `/latest` without a lockfile version, because the full package document can be megabytes.
- **Migration drift.** `alembic check` reports no drift at the head, so its assertion stayed in.
- **Derivation.** Each derivation makes 7 GitHub contents requests plus one registry request per direct dependency, with nothing cached. Two derivations of one Application running at once apply in the order they finish (marked `ponytail:` in `Workflows.derive_upstreams`).
- **Force pushes.** A force push, where GitHub's compare fails, still makes `github_commits` page through up to 1000 list pages and import and triage them.
- **Fractional intervals.** `formatInterval` and `IntervalInput` handle whole minutes, hours or days only. A value such as 301 s set through the API shows as fractional minutes.
- **Image names (outside Phase 1).** Compose still names the `asset-monitor-backend-test`, `asset-monitor-frontend-test` and `asset-monitor-broker` images, so these runs rebuilt `asset-monitor-backend-test:0.1.0` and `asset-monitor-frontend-test:0.1.0`, which the Numen project also uses.

### Phase 1 review fixes (2026-11-13)

- **Source repository.** `domain.source_repository` is now the earliest linked repository that is not removed, whatever its role or on/off state. `test_migrated_application_keeps_its_source_when_it_gets_an_own_repository` adds an Own repository to a WordPress Application with an active recipe and turns the plugin off. It then checks that the generation, recipe, CVE cursor, selectors and job source ref are unchanged and that the recipe can be chosen again. Removing the plugin still bumps the generation.
- **Concurrent find-or-create.** `domain.repository_for` creates a repository inside a savepoint and reads the other transaction's row after an `IntegrityError`. Both `add_repository` and `derive_upstreams` use it. In `test_postgres_concurrent_derivations_create_one_shared_upstream_repository`, two workers derive one shared Own repository and both insert `facebook/react`, which a `before_insert` barrier forces. Both jobs succeed with one repository. Without the savepoint, one job fails with `internal_job_error`.
- **Migration.** `4a2b3c5d6e72` refuses Programs that share a URL with different `source_ref`/`source_path`, and its downgrade restores unmerged sources. `test_postgres_migration_refuses_to_merge_programs_with_different_subpaths` and `test_postgres_migration_downgrades_unmerged_repositories_to_programs` cover both: the downgrade test reaches `fe74f85e4023` with the original constraint names and upgrades again. The merge test now also expects the merged downgrade to be refused. `6c4d5e7f8094` rounds intervals up to whole days on downgrade, so 300 s becomes 1.
- **Commit context.** `commit_application` prefers an Application that still uses the repository. `test_commit_belongs_to_an_application_that_still_uses_its_repository` covers it.
- **Restored links.** A restored link drops its `packages`, `unresolved` and derived revision, and derivation never removes the Own link. `test_removed_upstream_added_back_as_own_repository_keeps_its_own_link` covers this.
- **Pre-filter.** Any changed line inside the `scripts` object, as the hunk shows it, is flagged, and so are the npm lifecycle hooks named without that context. A dependency bump in a later hunk is not.
- **Malformed manifests.** Manifests of the wrong shape fail with `invalid_manifest`; a parametrised test has four cases. A registry body that is not an object is listed as unresolved ("Registry metadata could not be read").
- **Settings text.** The empty source-credentials text now says GitHub needs a read-only token.

| Command | Result |
|---|---|
| `make build` | passed |
| `make check` | passed |
| `make test-unit` | backend 201 passed; runner 122 passed, 58 skipped |
| `make test-integration` | 304 passed against PostgreSQL |
| `make test-runtime` | 179 passed, 1 failed: the known `test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider` |
| `make test-ui` | 103 passed in 19 files |
| `make test-journey` | passed (JOURNEY PASSED); the stack was then stopped |

## Commit review correction (2026-10-06)

Program selection now precedes global review and only that program's records are fetched; switching programs clears the previous queue. New triage output includes a potential issue title and fix/hardening/introduction kind. Complete unrelated results are dismissed, incomplete evidence stays pending, and manual review actions after job submission take precedence. Jev's three typed questions follow its official contract; existing source messages and legacy reports remain readable without inventing classifications.

Detailed commit analysis uses the CVE build sandbox and produces a title, five-way category, finding verdict/basis, reproduction status, and validated vulnerable reference. Supported findings are automatically linked to immutable report/PoC/application output and reused on re-analysis without changing operator title/status. Fixes use a verified parent; introductions use the selected revision. Invalid references retain their report without a finding; incomplete bundles retain linked drafts. Finding regeneration uses the validated vulnerable source. Source, triage, and saved analysis/artifacts have separate tabs; historical runs are selected one at a time and links/downloads identify their run.

Checks passed: 64 frontend tests in Docker with two workers; 144 backend/API/workflow/account/artifact tests; 109 runner unit tests (environment-dependent Docker/native tests skipped in that lane); two selected actual-Docker build cases, one each for CVE and commit analysis. The actual cases observed the private daemon, preloaded lab base, writable per-run volume, nonroot/read-only workload, dropped capabilities, and absence of the host Engine socket, then removed owned resources. Backend/frontend/runner lint, frontend types/formatting, production builds, and diff checks passed. Browser inspection covered the scoped queue and saved report view at desktop and 375px widths, without horizontal page overflow or console errors. No authenticated provider inference or production-target request was made.

With no queued/running/cancelling jobs, app/worker/scheduler/broker and all three coding-agent images were refreshed. Live checks confirm both build operations and the new worker output contracts. Existing data contained 75 complete unrelated triage results still pending; those were set to dismissed with `triage_decision_normalized` audit records. None had a manual review override; baseline/uncertain/candidate records and all reports were retained. Updated services are healthy at localhost:8787.

## CVE analysis UI/UX correction (2026-10-06)

The CVE screen now separates overview, saved analysis/artifacts, scores, and references. It displays one run at a time with job status, structured version ranges, confidence, open questions, and direct report/PoC/immutable ZIP downloads. Closing a launch keeps the selected CVE and historical run. Existing notification links and job-to-run links are covered; ineligible records remain inspectable even when an old URL requests the launch action. Artifact browsing groups files, searches paths, limits navigation to 50 files per page, prioritizes the main report/application instructions, resolves related documents across groups, supports rendered/source views, and retries preview failures. Draft finding output remains downloadable.

All 62 frontend tests pass in Docker with `--maxWorkers=2`; uncapped parallel runs hit existing timing limits under concurrent local work. All 60 focused artifact/API tests pass, including historical ZIP contents after finding updates, draft retention, authentication, corruption rejection, and Content-Length. Backend/frontend lint, frontend types/formatting, production builds, and diff checks pass. Chrome inspection covers desktop and narrow layouts and searching/previewing a PHP file in the existing large application set without horizontal dialog overflow. No analysis or provider inference was started during verification.

Real authenticated downloads verified a two-file retained analysis and the 24,126-file, 80,202,049-byte application ZIP against every listed manifest size and SHA-256. The original ZIP response took 108.27 seconds including verification; preparing the same archive alone took 23.29 seconds and its BytesIO iterator produced 285,315 tiny chunks. Returning the already prepared bytes directly fixes both analysis and finding transfers and adds Content-Length. The final analysis download prepared in 18.05 seconds, transferred in 2.01 seconds, and completed full manifest verification in 21.00 seconds. These are local measurements of this existing bundle. The rebuilt application is healthy and serves the updated UI/API at localhost:8787; database and artifact volumes were retained.

## Agent session retention correction (2026-10-05)

The frontend terminal now completes each read before scheduling its next poll, keeps successful output on connection failure, follows the newest phase unless an earlier run is selected, guards duplicate steering, preserves draft edits, and offers follow/jump controls. Cancellation disables steering while polling continues through the final archive read. Completed and cancelled sessions remain inspectable, and noninteractive account jobs do not show a terminal. Historical API reads retain job ownership; only the current running attempt accepts input.

Focused regressions prove saved history beyond 400/1,000 lines and 4 MiB, large tool-output sidecars, credential redaction before disk writes, archive readback after broker restart, empty successful steering responses, and immutable final history against late live reads during completion/cleanup recovery. The runner unit suite and all 30 final focused session/broker/recovery tests pass. API/workflow/broker verification passed 67 tests with one environment-dependent skip.

Six real Docker cases cover all three native transcript formats after normal container exit and forced cancellation. Each retains 900,000 lines and both endpoint markers beyond 4 MiB, uses private exec transport, and removes its owned containers/volumes afterward. Chrome inspection of an isolated fixture confirmed 1,314 retained lines, both endpoint markers, desktop/narrow layout, and follow/jump behavior. No provider inference or production job was started for these checks.

All 55 frontend tests (including 29 focused session/job tests), typecheck, lint, production build, scoped formatting, backend/runner Ruff, and diff checks pass. The full frontend suite uses `--no-file-parallelism` to avoid an unrelated ProgramForm timeout under concurrent checks. Full-project frontend formatting still reports the unchanged `JobLaunch.tsx`; Vite retains its existing bundle-size warning. Source changes were verified without replacing running application services. Retention applies to new Herdr workloads; output discarded by old sessions or native tool limits is not recoverable. An abrupt broker restart retains the last redacted checkpoint, rather than exposing unredacted orphan native files.

## Executed boundaries

- Locked, digest-pinned application and Pi/Claude/Codex/probe/lab/gateway/dind images build on the actual Docker Engine.
- Backend API/domain tests cover authentication, CSRF, programs/defaults, optional AI-off/manual review, source history, score gates, immutable findings/artifacts, native-cache encryption/redaction, and typed Jev protocol parsing.
- PostgreSQL checks use disposable schemas and independent connections to prove SKIP LOCKED claims, fencing/recovery, migrations, scheduler deduplication, and persistence across app replacement.
- Frontend Docker build, typecheck, lint, and fifty-five behavior tests pass (the suite needs `--testTimeout` above its 5000ms default on a loaded machine), including protected native import, device-login polling/cancellation, runtime-specific model/effort selection, explicit Analyze submission, safe report rendering, and supporting-file navigation.
- Actual Engine tests exercise non-root execution, read-only inputs, absent socket/provider credentials in probes, direct egress denial, scoped proxy/fetch access, timeout/cancel/resource limits, pinned CLI versions, native Codex permissions, and real Docker lab/PoC outcomes.
- A lab bundle that installs its own dependencies and runs its own database is verified on the actual Engine: an ordinary Dockerfile with `RUN apt-get install mariadb-server` builds on a per-run bridge with network, its entrypoint initialises the database and serves port 8080 with a writable root filesystem, and the isolated PoC container observes the stored value through `http://application:8080` and records `verified`.
- The CVE-analysis build sandbox is exercised on the actual Engine: the per-run daemon becomes ready, the bundled lab base is streamed into its empty image store, the run's workspace is shared with it so a nested container reads what the agent wrote and writes back through `/workspace/share`, and the workload keeps its unprivileged user, read-only image, dropped capabilities and absent Engine socket while addressing the daemon directly rather than through the provider proxy.
- The isolated Compose journey passes GitHub HTTP and real WordPress SVN collection, old-dated merged changes, cursor deduplication, captured webhook delivery, CVSS boundary/update handling, complete artifact ZIP integrity, and logout protection.
- Container-based backup and restore executed successfully against the isolated test project. The main application data was preserved.
- Restore readback checked the original operator login, persisted GitHub/WordPress programs, open finding status, and every downloaded artifact's recorded byte length/SHA-256.
- One credential-free official NVD CVE API read confirmed its paginated envelope, expected CVE identifier, modified timestamp, and current metric fields. No production asset was contacted.
- The deployed UI was inspected in a dedicated browser session. The main installation has no seeded fixture programs or provider credentials.

## Review corrections

Two independently reproduced code-review findings were accepted: automatic triage captured the old mutable cursor, and broker restart could report a stopped workload after failed cleanup. The real HTTP journey also caught a response/commit race: a newly accepted job could briefly be missing because request-scope dependency teardown committed after the response was sent. Corrections pin evidence-producing jobs to immutable inputs, leave initial history as baseline, require positive cleanup/reconciliation before replacement, and commit the API transaction before success becomes observable. Focused tests cover these rules and related cancellation/lost-acknowledgement paths. The transaction boundary follows FastAPI's [function-scoped dependency lifecycle](https://fastapi.tiangolo.com/tutorial/dependencies/dependencies-with-yield/).

The Pi image's shrinkwrapped brace-expansion vulnerability is repaired using a pinned, integrity-verified compatible tarball and an exact-hash compiled-entrypoint patch. Build-time audit and real-image behavior checks cover the actual installed/bundled code rather than an ineffective lockfile-only override.

## Operator-dependent checks

No paid model inference, personal provider login, production-target testing, or actual Discord-channel delivery was performed. Connect operator-owned accounts, refresh model/effort capabilities, and check eligible API/subscription access before running agent work. Native Pi headless login setup is unsupported. Claude subscription login (authorization-code paste) and session import are available, but completing that login needs an operator account and was verified only with a synthetic CLI. Codex device login is account/workspace-dependent.

## Codex device-login regression

The first operator login exposed a startup bug: the empty container's Codex configuration directory did not exist. A second regression test showed that text-buffered readline/select could hold the link/code until the CLI exited. Login now initializes its private directory and reads bounded binary chunks so instructions appear while the CLI waits. Both tests failed before the correction and pass afterward. A live, credential-free isolated device-login check obtained the verification link/code before completion; the diagnostic was cancelled and fully reconciled without account linkage. Credential cache values remain absent from logs and ordinary responses.

The dashboard also discarded later login instructions when the runtime's status/progress stayed unchanged. Progress deduplication now includes the whitelisted verification events, with API-visible coverage for delayed instructions, duplicate suppression, and credential-log exclusion. Native login reuses an existing queued/running/cancelling attempt; a real PostgreSQL regression proves this response remains immediate while the worker holds the account's credential lock. The scheduler now joins the control network so it can reconcile stopped runtime attempts. The login dialog explains operator verification, disables duplicate starts, supports cancellation, and hides old codes after completion. Backend coverage also proves encrypted session ingestion commits before protected runtime cache deletion and queues capability discovery.

An independent real-PostgreSQL check reproduced a rapid-start race between the first pending-job read and the account lock. The endpoint now locks without waiting inside a savepoint, rechecks pending state on lock conflict, and returns a retryable `account_busy` response when another credential operation owns the lock. Both conflicting-login and no-login boundaries are covered while the worker's lock remains held.

The operator's completed provider verification exposed a separate runtime handoff bug: Docker Engine 20.10.22 archive retrieval returned `NotFound` for the native cache inside the workload's active temporary filesystem. A disposable synthetic native completion reproduced that exact failure without provider login or inference. The broker now reads and acknowledges through fixed non-root exec commands inside the mount namespace. Reads reject oversized/nonregular/linked files and invalid JSON; FIFO opens cannot block validation. Six actual Docker tests cover successful completion and file boundaries, and two transport tests cover safe errors and retained rotated cache after acknowledgement failure. Synthetic session bytes remain absent from main Docker logs, events, command arguments, and public errors. Only the broker image required updating.

The corrected broker and application services were redeployed and became healthy. A fresh application login produced both verification instructions before completion; the live browser confirmed the link/code, disabled duplicate Start, and available Cancel action. Final linkage of the operator-owned account requires the operator to complete that fresh provider verification.

The initial in-app lab verifier supports local declarative materialization and pinned bases. RUN/remote ADD are rejected; such uploaded bundles stay downloadable and unverified. A reproduced lab proves its recorded conditions for that artifact/image revision, not every statement in an investigation report.

## Commands

### Finding regeneration rejected before execution — 2026-10-06

Finding artifact job `06ce6bf8-5058-44de-8b6f-40888c293057` failed at submission with broker HTTP 422 and no runtime ID. Its finding serialized 24,126 artifact entries into approximately 7.8 MB of prompt facts, exceeding `RunRequest.prompt`'s 262,144-character bound. The existing complete artifact revision remained intact.

Generation now puts finding evidence/operator fields in `finding.json` and supplies analysis identity/results without file inventories in `analysis.json`. It reads only the original analysis report, retaining its integrity check, rather than hashing the entire saved application tree. A large-inventory/evidence regression failed before the fix and passes afterward. Using the actual job, pinned source, credential profile and current runner contract in a read-only transaction, the corrected request validated with an **8,646-character prompt**, five packed input files, and **zero model requests**. **155 backend tests**, all **8 PostgreSQL tests**, Ruff, and whitespace checks passed. The corrected worker was deployed, then the original inputs/profile were retried once as job `2962bde5-e45f-4270-93d6-92bccbfb0446`.

### Completed commit jobs blocked during publication — 2026-10-06

Two commit analyses had successful, reconciled broker runs but remained Running with expired leases. PostgreSQL showed each publication transaction holding its job lock while a synchronous source heartbeat on another connection waited for that same lock. Both older commits lacked `parent_revisions`, so vulnerable-parent validation entered network-dependent resolution after taking the publication fence.

Commit analysis now completes parent resolution/source snapshotting before fencing publication, while preserving the report when a proposed vulnerable revision is invalid. A real PostgreSQL regression reproduced the failure with a bounded lock wait and passed after the correction. The affected backend suite passed **154 tests**, all **8 PostgreSQL tests** passed, and Ruff/whitespace checks passed.

Both completed runtime results were privately backed up and their immutable parents verified against the source before recovery. The blocked heartbeat statements were cancelled with recovery scheduling temporarily stopped. Publication resumed through the normal schema, source-reference, secret, artifact, and finding validation using the retained results; **zero model calls** were made. Jobs `ea4ba980-f939-4873-93a1-fb3fda026883` and `1d79d0ab-1ac7-4313-bff2-7511daaa0035` finished Succeeded with linked analyses/findings. All **18 retained output files** were downloaded from their new analysis archives and verified byte-for-byte and by SHA-256 against the original runtime output. No blocked job queries remained, and the worker/scheduler were refreshed after all active work finished.

### Findings read performance — 2026-10-06

The Findings register previously waited 25–70 seconds for two rows and received 7,516,560 bytes. Profiling the larger finding attributed 20.1 of 23.4 seconds to loading its 24,126 files (170,890,354 bytes). The deployed summary endpoint returned those same two findings in 34–111 ms over three real HTTP reads, with a 2,734-byte response; Chrome measured 84 ms and rendered both rows with readable fixed versions and no error. The large full finding response retained all 24,126 artifact records and completed in 2.60 seconds.

The final affected backend suite passed **154 tests** and the sequential frontend suite passed **67 tests**. Regression coverage proves no artifact reads for published summaries, scoped pagination, latest lab status, legacy/stale revision completeness, preserved version evidence and operator notes, rejection of cache overrides, and corruption failures on preview/download/lab use. Lint, types, formatting, production build, and whitespace checks passed. A parallel UI run timed out under concurrent build/analysis load; the complete suite passed with one worker and unchanged assertions/timeouts.

The web service was refreshed and remained healthy. Existing revision summaries were populated under row locks without changing finding status or timestamps. Active worker analyses were left running; older publisher output remains supported by the metadata-and-two-declarations read path.

```sh
make check
make test-integration
make test-runtime
make test-ui
make test-journey
```

Use the service/schema/fixture entrypoints in the repository. Tests reject empty/unknown selections. Current verification: **138 backend**, **166 runtime** (including **57 actual Engine cases**), and **55 frontend** tests, **359 total**; all pass except `test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider`, which fails identically before these changes because the pinned Claude CLI no longer advertises its `Grep`/`Glob` tools to the loopback fixture. The full backend/runtime/UI suites passed after the login corrections. The final real HTTP journey passed after the earlier transaction correction. Lint/typecheck/build, locked-image builds, backup/restore readback, and the Pi patched dependency audit passed. The updated main stack is healthy at http://localhost:8787; the isolated test stack was stopped. Account-specific paid inference remains an operator-dependent check.
