# GarudaNetra release 2 implementation plan

This plan delivers `docs/prd/asset-monitor-r2-prd.md` on top of release 1 (phases 0 to 11 of `docs/plans/20261112-feature-asset-monitor.md`, on branch `asset-monitor`). The design is in ADR-0006, ADR-0007 and ADR-0008.

**Order.** Phases are ordered so that each one leaves a working, tested system, and so that nothing is built before what it depends on. Phases 14 to 17 and 19 are split into an a and a b part, each with its own Done when, so that each part fits one phase workflow.

**Checks.** Every phase ends with `make build`, `make check` and `make test`. `make test` includes `test-runtime`, and Compose sets `NUMEN_DOCKER_TESTS=1`. Phases that change UI flows also run `make test-journey`.

**Records.** Each phase records its tasks, its acceptance mapped to tests, its deviations and its run counts in `docs/verification.md`. It also updates `docs/implementation-contract.md` for every shape a consumer sees.

**Pins.** A new external base image is pinned as release 1's are, `<image>:<exact version>@sha256:<digest>`. The exact patch version and digest are chosen when the phase is built and recorded in `docs/verification.md`.

**No real traffic.** Tests make no paid model requests. They send no traffic to real Assets, servers, registries, Upstream repositories or GitHub. Model agent outputs come from `FixtureBroker` in backend tests and from `canned_broker.py` in the demo dry run. Every stand-in is a local container.

## Phase 12: Ingress (B01)

- **`numen.ingress`.** One module with two ASGI apps: the push listener on container port 8083, and the agent listener on 8084, served over TLS with a self-signed certificate made at start, on a tmpfs, from `NUMEN_AGENT_TLS_KEY`. Each app:
  - sends the same security headers as the dashboard;
  - checks each route's body cap on the bytes it reads, chunked bodies included, before parsing;
  - rate-limits per identity, with the global buckets of B01;
  - ignores cookies;
  - never imports `numen.api`.

  In this phase the push route answers `404` to every push id, because none exist yet, and the agent listener answers only `GET /health`.
- **Database roles.**
  - A migration chained from `a7b8c9d0e1f2` creates `asset_monitor_push` and `asset_monitor_agent` as `NOLOGIN` only if they are missing (a `DO $$ ... IF NOT EXISTS (SELECT FROM pg_roles ...)` block), with no grants. Its downgrade drops no role. Each later migration only grants and revokes on the tables it adds.
  - `python -m numen.cli ingress-roles`, which the `migrate` service runs after `alembic upgrade head` when both role passwords are set. It creates a missing role, and gives each `LOGIN`, its password from `.env`, a `CONNECTION LIMIT` and a `statement_timeout`.
  - `restore.sh` creates any missing role with the same `DO` block before it loads `database.sql`. It refuses a backup whose `deployment.env` lacks `NUMEN_INGRESS_KEY`, either role password or `NUMEN_AGENT_TLS_KEY`.
- **Keys.** Add `NUMEN_INGRESS_KEY`, `NUMEN_PUSH_DATABASE_PASSWORD`, `NUMEN_AGENT_DATABASE_PASSWORD`, `NUMEN_AGENT_TLS_KEY` and its pin `NUMEN_AGENT_TLS_PIN` to `.env`. `make init` (`scripts/init.sh`) adds missing keys to an existing `.env` and never changes existing ones.
- **The `ingress-push` and `ingress-agent` Compose services.**
  - Both run from the app image, not on the `x-app` anchor, with a read-only root file system, `cap_drop: ALL`, `no-new-privileges` and user 10001.
  - Each joins its own bridge (`push-inbound`, `agent-inbound`), which carries its published port, and its own internal network that it shares only with `db` (`push-db`, `agent-db`).
  - Their ports are `127.0.0.1:${NUMEN_PUSH_PORT:-8791}:8083` and `127.0.0.1:${NUMEN_AGENT_PORT:-8792}:8084`.
  - Both have `depends_on: migrate: condition: service_completed_successfully`.
  - `ingress-push` gets `NUMEN_INGRESS_KEY` and its role's URL. `ingress-agent` gets the TLS key and its role's URL. The app and the worker also get `NUMEN_INGRESS_KEY`.
  - `ingress-agent`'s healthcheck is `GET /health` over TLS. `ingress-push`'s is a TCP connect to its port.
- **Operations.**
  - Add both services to `make up` and `make logs`, and to the services `backup.sh` and `restore.sh` stop and start.
  - Add them to the service lists in `test-journey.sh`, `demo.sh` and `test-demo.sh`.
  - Give each project its own ingress host ports: journey 18791 and 18792, demo 8793 and 8794, demo test 18793 and 18794.
- **Tests.**
  - `test_deployment.py`:
    - both new ports are on loopback;
    - each ingress service is on its own two networks only, and on neither `application` nor `control`;
    - neither has `NUMEN_SECRET_KEY`, the broker token or the database owner URL; `ingress-agent` has no `NUMEN_INGRESS_KEY`, and `ingress-push` has no TLS key;
    - every external `FROM` in `Dockerfile` and `Dockerfile.runner` carries `@sha256:`.
  - Route isolation for both listeners, and the import test.
  - Grant tests against Postgres: neither role reads the release-1 tables. Two schemas migrated to head in one cluster, with one then downgraded, keep both roles and the other schema's grants.
  - Body caps, chunked bodies included, and rate limits. A request to an unknown push id makes no database query.
  - The journey's existing backup round trip (`down -v`, then `restore.sh`) now covers restoring the grants into a fresh cluster.

**Done when:** AC-B01 has tests, `make up` starts both ingress services next to an unchanged dashboard, and the journey's backup round trip passes.

## Phase 13: Push webhooks (B02, the A02 change)

- **Tables.** A migration adds `push_webhooks` (repository, push id, encrypted secret, last accepted, last refusal) and `push_deliveries` (delivery id unique, body SHA-256, push webhook, received at, processed at). A delivery's body SHA-256 is unique among those of the last 7 days, and older rows are pruned. `asset_monitor_push` may read `push_webhooks`, update only its last-accepted and last-refusal columns, and insert into `push_deliveries`.
- **Setup API.** Set up, Regenerate and Turn off, on Own repositories only. They need the session and CSRF, and no password. The secret is encrypted with `NUMEN_INGRESS_KEY` and shown once.
- **The push route.**
  - Before it reads the body, it checks the push id's format against an in-memory set of known push ids, refreshed every 15 s. An unknown push id gets `404`, with no row and no further query.
  - It then checks the `push` or `ping` event, the delivery id, and `X-Hub-Signature-256` over the raw bytes.
  - It deduplicates by delivery id, and by body SHA-256 for 7 days. It records a refusal reason at most once a minute per push id, and never parses the body.
- **The nudge.** The scheduler applies the B02 rule.
  - The Repository row lock is taken wherever source checks are queued: in `domain.schedule`, in `api.check_application` and in the nudge, each through `domain.active_source_check`, which takes the lock before it looks. Check now, the scheduler and a nudge therefore never queue two source checks.
  - A nudge reuses a queued check, and never touches `Application.next_check_at`.
- **Redaction.** `workflows.all_secrets` covers Push webhook secrets.
- **UI.** A Push webhook panel on the Own repository in the Repositories tab. It has the one-time setup dialog, Regenerate, Turn off, the last accepted delivery and the last refusal.
- **The GitHub stand-in** (`fixture_server.py`):
  - In test mode, a dedicated push stand-in, `numen/push-app-<run>`, has its own commits list and ETag, which `/admin/advance` never moves. `POST /admin/push {repository}` adds one commit to that repository only, then sends a signed Push delivery to each hook registered for it.
  - It records hooks registered through `/admin/hooks`. `/admin/hooks/redeliver` repeats a delivery, a replay helper resends a captured body under a new delivery id, and a forged-delivery helper sends a wrongly signed one.
  - It reaches `ingress-push` over a `stand-ins` internal network that only the overlays define.
- **Tests.**
  - Backend: signatures, events, deduplication by delivery id and by body, the unknown push id, the refusal-recording rate, the nudge rule, the row lock, and on-time scheduled checks with a delivery every minute.
  - `test_deployment.py`: the `stand-ins` network appears only in overlays, and it is internal.
  - The journey sets up a Push webhook on `numen/push-app-<run>`. A `POST /admin/push` is imported without Check now, a redelivery and a replayed body are deduplicated, and a forged delivery is refused and shown.

**Done when:** AC-B02 has tests, including the journey's push imported with no Check now.

## Phase 14a: PHP Lab runner (B09, the A07 change)

- **The PHP Lab images** in `Dockerfile.runner`:
  - a `lab-php` stage from a digest-pinned `php:8.4.<patch>-cli-bookworm` image, with no Composer and no git, the image label, uid 10001 and `/opt/lab`. It is `asset-monitor-lab-php:0.1.0`;
  - a `lab-php-fetch` stage, `FROM lab-php`, which adds unzip and a Composer 2 release downloaded by version and checked with `sha256sum -c` against the SHA-256 written in `Dockerfile.runner`. It is `asset-monitor-lab-php-fetch:0.1.0`.

  Their `lab-php-image` and `lab-php-fetch-image` services are in the `images` profile, with `network_mode: none`. They check the PHP and Composer versions, and that the base holds no `composer` or `composer.phar`.
- **Runner (`engine.py`).**
  - Choose the stack from the Dockerfile's `FROM`, and refuse mixed bases and the fetch image.
  - Accept the PHP base in `LAB_BASE`.
  - Run the PHP phase one in the fetch image, with Composer's home and cache on the run's volume.
  - Give a PHP Lab's gateway the `NUMEN_COMPOSER_HOSTS` list.
  - Filter the fetched archive to `vendor/`.
  - Refuse any `RUN` in a PHP-stack Dockerfile, and apply the database-server refusal to the bundle's files.
- **Settings.** `compose.yaml`'s `runner-broker` gets `NUMEN_COMPOSER_HOSTS: ${NUMEN_COMPOSER_HOSTS:-repo.packagist.org,api.github.com,codeload.github.com}`. `compose.test.yaml`, `compose.demo.yaml` and the `runner-runtime-tests` service set it to `registry.invalid`. `test_deployment.py` asserts the default and the overlays.
- **Runtime tests** (`test_docker_runtime.py`):
  - the PHP base runs PHP 8.4 and has no git and no Composer; the fetch image has the pinned Composer;
  - a vendored `composer-plugin` package, root `post-install-cmd` and `post-autoload-dump` scripts, and a dependency's autoload `files` entry leave no marker, in phase one or in the build;
  - a PHP-stack Dockerfile with a `RUN` is refused;
  - a fixture `composer.lock` in ADR-0008's path-dist form, with its vendored folder, installs with `NUMEN_COMPOSER_HOSTS=registry.invalid`, and a file in `vendor/` proves that the vendored version was installed. A minimal app's `composer.json` in ADR-0008's form does the same;
  - neither the application nor the PoC has a network;
  - a fixture reproduces, and another does not;
  - an over-limit Lab leaves no image;
  - Node runs unchanged.
- **Mirrors.** The `LAB_BASES` lists in the runner and backend tests change together.

**Done when:** the runtime tests pass for both stacks on the real Engine, and the `LAB_BASES` mirrors match.

## Phase 14b: PHP Lab backend (B09)

- **Completeness.** `artifacts.completeness` learns both stacks and the refusals: mixed bases, the fetch image, a `RUN` on the PHP stack, and a database server. `RULES` is bumped.
- **Own-head refusals.** For the PHP stack, `domain.lab_supplied` also returns the Own snapshot's `composer.json` content and whether it holds `wp-settings.php`, so `completeness` refuses a database-server Own head before Approval.
- **Composer in `workflows.lab_packages` and `workflows.lab_run`.** They:
  - copy the Locked version from the Upstream repository's tree, at the lock's commit or the Locked version's tag, under `vulnerable-app/.asset-monitor/<vendor>/<name>/`;
  - rewrite that package's lock entry to ADR-0008's path-dist form, or write the minimal app's `composer.json` with its path repository;
  - refuse a package with no watched GitHub source with `package_untrusted`.
- **Prompt.** `sections/bundle.md` describes both stacks and the no-`RUN` rule, and the pins in `test_prompts.py` move with it.
- **Tests.**
  - The Node-only refusal tests become "a bundle with no stack is refused".
  - An Own head that requires `ext-pdo_mysql` is refused before Approval.
  - The rewritten lock and `composer.json` match the fixtures that Phase 14a's runtime test installs.
  - The journey: a PHP bundle uploaded to a Finding opened by hand reproduces after Approval.

**Done when:** AC-B09 has tests, including the journey's PHP Lab run.

## Phase 15a: On-server agent binary (B03, the agent side of B04)

- **The `agent/` Go module,** standard library only. Owned by the Runtime agent, and added to the ownership list in `docs/implementation-contract.md`.
  - `enroll`:
    - reads the Enrollment code at a prompt or from standard input only;
    - requires `--allow`, resolves each path to its real path and applies B03's refusals;
    - resolves the URL's host, requires loopback or private addresses, keeps the address it checked, and connects over TLS accepting only the pinned key;
    - generates the Agent key, sends the Enrollment request, and prints the fingerprint;
    - writes the root-owned configuration and key under `/etc/asset-monitor-agent/`, and the systemd unit under `--unit-dir` (default `/etc/systemd/system`), with `ReadWritePaths=-<path>`, `StateDirectory`, the B03 directives and `IPAddressAllow`.
  - `repin --key <new key>` replaces the pinned Dashboard key and keeps the Agent key.
  - `run`:
    - polls at the configured poll interval: 30 s by default, never under 2 s;
    - verifies each signed message: signature, key id, agent id, type, a sequence higher than the last of that type it accepted, and expiry;
    - keeps the latest configuration, the sequences and the journal under the state directory, and writes nothing else outside the Allowed paths;
    - signs each request over the fixed prefix, the method, the path with its query string, the timestamp, the nonce and the body SHA-256, and gives each report its sequence number and configuration version;
    - refuses a Watched root outside its Allowed paths.
- **Build.** One script, `agent/build.sh`, used by both agent stages, with `CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly` and `-trimpath -buildvcs=false -ldflags='-s -w -buildid='`. An `agent-build` stage in the root Dockerfile:
  - from a digest-pinned `golang:1.25.<patch>-bookworm` image;
  - builds for linux/amd64 and linux/arm64;
  - writes `SHA256SUMS`, which the `app` stage copies.
- **Images and checks.**
  - An `agent-tests` service in the test profile, with `network_mode: none`, runs `go vet`, `gofmt -l` and `go test`. It builds both architectures twice, with fresh `GOCACHE` directories, and compares the outputs with each other and with the copied `SHA256SUMS`. It uses `debug/elf` to check that neither binary has a `PT_INTERP` or a `DT_NEEDED` entry.
  - `make check` and `make test-unit` include it.
  - `make agent` exports both binaries and `SHA256SUMS` to `dist/agent/`.
- **Go tests:**
  - the request signature's canonical form;
  - the TLS pin and the Dashboard key pin, and `repin`;
  - sequence order: an older configuration or command is refused;
  - expiry;
  - the URL rules;
  - the Allowed-path refusals: `/`, `/etc`, `/var`, and overlap with the Quarantine folder;
  - `run` writes nothing outside the state directory;
  - the rendered unit's directives;
  - the code is never read from the arguments or the environment.

**Done when:** the Go tests and the build tests pass in `make check` and `make test-unit`, and `make agent` writes both binaries and `SHA256SUMS`.

## Phase 15b: Enrollment (B04, the rest of B03)

- **Backend.**
  - A migration adds:
    - agents: name, Application, listener URL, public key, pinned key id, status (pending, enrolled or revoked), Allowed paths, version, architecture, last seen, last refusal, last report sequence and configuration version;
    - Enrollment codes: id, agent, hash of the secret part, expiry, used;
    - Enrollment requests;
    - agent requests: signed headers, raw body, and the time received, set by Postgres. They are unique on (agent, nonce), and each is kept until its timestamp leaves the replay window;
    - agent messages: signed configurations and commands, with sequence, type, key id, expiry and status.
  - `asset_monitor_agent` may read agents' ids, public keys and status, and codes' ids, agents and expiry. It may insert Enrollment requests, and agent requests without the time received. It may read agent messages. It has no other grant.
  - The Dashboard key is generated on first use. Its private half is encrypted under `NUMEN_SIGNING_KEY`, which only the `app` service gets, not the `x-app` anchor. `make init` adds the key, and `restore.sh` requires it. Each signed message carries its key id.
  - `NUMEN_AGENT_URL`, defaulting to `https://127.0.0.1:8792`. The test and demo overlays set `https://ingress-agent:8084`, and a 2 s poll interval that the app allows only under `NUMEN_TEST_MODE`. `test_deployment.py` asserts both.
- **Ingress.** The agent listener gains:
  - `enroll`, which stores the request and answers with the agent id from the code's row;
  - `poll`, which stores the request and answers with the signed messages newer than the agent's last.

  Both have the signature, timestamp and nonce checks, and the per-agent, per-code and unknown-id rate limits.
- **Scheduler.** Every 15 s it:
  - verifies each stored request again: signature, timestamp against the time received, nonce, the agent's status and the body SHA-256;
  - checks and spends Enrollment codes, binds keys as pending, and records refused requests on the agent's row;
  - updates last seen from verified polls only.
- **API and UI.** A Server files tab on the Application:
  - add an agent with a name and its listener URL. The enroll command (URL, TLS pin, Dashboard public key and key id), the Enrollment code beside it, and the checksums are shown once;
  - pending agents with their fingerprint and Allowed paths, and **Confirm fingerprint**, which enrolls the agent and signs its first configuration;
  - the agent list, showing pending, enrolled, silent, revoked or pinned to old key, with version, architecture and the last refusal;
  - revoke, and **Rotate Dashboard key** through `approval()`.
- **The stand-in server** (`compose.test.yaml`):
  - It runs as root, with a read-only root and only the capabilities the unit allows, on the `stand-ins` network.
  - It has volumes at `/etc/asset-monitor-agent` and `/var/lib/asset-monitor-agent`, the second a named volume so that Phase 18 can mount its Quarantine folder read-only into the fixture. `enroll --unit-dir` points at a tmpfs, so no systemd is needed.
  - `server_standin.py` waits for an enroll drop (the command and the code) that the fixture's `/admin/server/enroll` writes into a shared volume. It runs `enroll` with the code on standard input, and writes each run's exit status and stderr to the shared volume, where the fixture's `/admin/state` shows them. It then runs the agent.
  - Its `check` asserts that there are no `LISTEN` entries in `/proc/net/tcp`, `tcp6`, `udp` and `udp6`, and that the dashboard cannot be reached from it.
- **Tests.**
  - Backend: a code works once and expires; a pending agent's requests start nothing; a stored request tampered with after storage is ignored; refused requests are recorded; rotation stops signing with the old key.
  - Grant tests for `asset_monitor_agent` against Postgres.
  - The journey enrolls the stand-in, confirms its fingerprint, and sees it poll. A second enroll with the used code fails, and shows on the agent's row and in that run's stderr. The journey then revokes the agent.

**Done when:** AC-B03 and AC-B04 have tests, including the journey's Enrollment, confirmation and revocation of the stand-in server's agent.

## Phase 16a: File manifests and evidence (B05)

- **Agent.**
  - It walks the Watched roots through `os.Root`: `lstat` only, symbolic links recorded with their target, special files skipped.
  - It applies the secret list, the per-file limit, the 512 MiB hashing limit, the 4-minute walk deadline, the 4,096-byte path cap and the 50,000-file over-limit report.
  - It reports at the configured report interval and on a rescan command.
  - It uploads only wanted files from its own latest manifest, at most 1 MiB each and never secret ones, in uploads of up to 16 MiB, then marks the report done.
- **Ingress.** It gains the report, upload and done routes. They:
  - store each request as received;
  - cap a manifest at 16 MiB, and refuse a path that is absolute, not normalized, holds a NUL, is over 4,096 bytes or lies outside a declared Watched root;
  - refuse bytes that do not hash to their SHA-256.

  `poll` also returns the latest wanted list.
- **Backend.**
  - A migration adds wanted lists, held bytes (agent, SHA-256, size, and what references them), Watched roots and configuration versions. `asset_monitor_agent` may read wanted lists only. It has no grant on Watched roots, Baselines, Server changes or held bytes.
  - The scheduler verifies each stored report again, its sequence and configuration version included, checks its paths again, and writes its wanted list within B05's budgets and order.
  - Watched roots are edited through `approval()`, with the password, and record an Action. They are checked against the agent's Allowed paths. A new configuration is signed then, and when the Application's interval or monitoring changes.
  - Check now sends a rescan command.
  - The secret list is one backend module, and a test checks that it matches the Go list.
- **UI.** The Watched roots editor with its Approval dialog, and Check now.
- **Tests.** Go tests for the walk, the secret list, the limits, the deadline, the path cap and the choice of uploads. Backend tests for path refusal, the wanted list's order and budgets, re-verification, an ignored out-of-order report, and the rescan command.

**Done when:** a stand-in report and its uploads are stored, verified again and answered with a budgeted wanted list, with a test for each rule above.

## Phase 16b: Server changes and Baseline (B05)

- **Backend.**
  - A migration adds File manifest Baselines (agent, report, manifest SHA-256) and Server changes, unique on (agent, fingerprint), with the incomplete flag and its reasons. No ingress role has a grant on them.
  - The scheduler queues `server_check` for each verified report that is done or more than 10 minutes old. `server_check` is added to the exemption list in `Workflows.execute`, to `domain.APPLICATION_SUBJECTS` and to `frontend/src/jobSummary.ts`.
  - `server_check`:
    - hashes each uploaded file again, and refuses one that does not match;
    - moves the bytes into artifact storage (resource type `server_files`, keyed by SHA-256) and records them as held;
    - compares the report with the Baseline without mtime;
    - records the Server change once, with its incomplete flag and reasons;
    - releases held bytes that nothing references.
  - Baseline acceptance covers the first manifest and, after that, one named Server change with its manifest SHA-256. It reuses `baseline_allowed` and records an Action. The rules that need a Triage or a Verdict land in Phases 17a and 17b.
  - An agent becomes silent after 5 minutes without a verified poll.
- **UI.** Accept Baseline, and Server change rows: added, changed and removed, with their metadata, the incomplete flag and its reasons.
- **Stand-in.** `fixture_server.py` gains `/admin/server-files`, which writes or removes stand-in files in the stand-in server's web root. Both containers mount that volume.
- **Tests.**
  - Backend: ten inserted reports of one Server change give one row; the mtime rule; secret files by hash only, giving an incomplete change; symbolic links; the worker's hash-mismatch refusal; the first-manifest Baseline gate; a stale manifest SHA-256 refused; a first report larger than the Baseline budget leaves room for a change's bytes; unreferenced bytes released.
  - The journey: Baseline acceptance, a dropped file recorded as one Server change across three rescans, an mtime-only change ignored, `wp-config.php` reported by hash only, and an outward symbolic link not followed.
  - A backup and restore that keeps the held bytes and the Server changes.

**Done when:** every AC-B05 bullet except "one Triage run" and the Triage and Verdict Baseline rules has tests, and the journey shows a dropped file as exactly one Server change across three rescans.

## Phase 17a: Server-file Triage (B05, B06, the A03 change)

- **The new source.** Add the source `server_files` to:
  - `schemas.FINDING_SOURCES`, and the frontend's `findingSchema.source`;
  - `domain.FINDING_SUBJECTS` and `finding_subjects`, for Transcripts and their retention;
  - the `a08b9cb4d3e8` downgrade guard.
- **The new change model.** Add `ServerChange` beside `Commit` and `ServedChange` in:
  - `domain.start_waiting`, the Review queue in `api.dashboard`, `domain.job_subject`, `worker.subject`, and `api.retry`;
  - the `isinstance` branches of `triage_result` and `set_commit_decision`.
- **Pre-filter.** It flags web-executable and secret-list files, and the Server change rows show the flags.
- **`server_triage`.**
  - It runs on the `commit_triage` tool profile, through `RUNNER_OPERATIONS`, with an editable prompt template and an entry in `SCHEMAS`.
  - A cut diff makes the Triage incomplete.
  - It is added to the exemption list in `Workflows.execute`, to `worker.LONG_KINDS` and to `frontend/src/jobSummary.ts`.
- **Review.** `POST /server-changes/{id}/review`, mirroring the served-change route, with a test.
- **Baseline.** A change the Pre-filter flags cannot become the Baseline after a Triage decline alone.
- **Tests:**
  - ten reports of one Server change start one Triage run;
  - the first report starts no Triage run until it is accepted;
  - a cut diff is incomplete;
  - the Pre-filter's flags;
  - a flagged change that only Triage declined cannot be accepted, while an unflagged one can after the Operator dismisses it.

**Done when:** AC-B05's Triage and Baseline-after-decline bullets and AC-B06's Triage parts have tests.

## Phase 17b: Server-file Analysis and Playbook (B06, B07, the A04, A06, A11 and A12 changes)

- **`server_analysis`.**
  - It runs on the `commit_analysis` tool profile, through `RUNNER_OPERATIONS`, with an editable prompt template and an entry in `SCHEMAS`.
  - The Verdict check runs before the schema check, and an incomplete change can never stand as Unrelated.
  - It is in `CAPPED_KINDS`, and is added to the exemption list in `Workflows.execute`, to `worker.LONG_KINDS` and to `frontend/src/jobSummary.ts`.
  - `POST /server-changes/{id}/analyses` mirrors the served-change route, with a test.
- **Analysis inputs.** Only stored bytes, staged under their SHA-256: `source/changed/<sha256>`, `source/previous/<sha256>` and `source/baseline/<sha256>`, with paths only as data in `server-files.json`. Analysis locks the Server change row after its fence, so `open_finding` cannot open the same Finding twice.
- **The Playbook.**
  - `domain.PLAYBOOKS` gains `("server_files", "Malicious change"): ("static_proof", "detection_rule", "cleanup_report", "quarantine")`.
  - `domain.finding_cell` learns the `server_files` role.
  - `FINDING_TRANSITIONS` gains Remediated to Confirmed, which `transition_finding` allows for server-files Findings only.
- **Malicious change.**
  - `open_finding` opens the Finding, with a static Proof from indicators found in the changed bytes and in no Baseline bytes.
  - Application code checks the cleanup report.
  - `publish_finding_bundle` runs.
  - `Workflows.detection_rule` gains a `server_files` branch. Its trees are the changed files, their previous versions and the held Baseline bytes, all staged under their SHA-256. Its check messages say "files", not "fetches", and its result counts the Baseline files not scanned. The Finding names the files the rule matched, by path and SHA-256.
- **Findings opened by hand.** `schemas.FindingInput` gains `source_server_change_id`. `validate_finding_refs` checks that the change's agent belongs to the Application, and `create_finding` stores it as `data.subject_id`.
- **Remediation and regression.** For each new Server change, application code:
  - links every manifest entry whose SHA-256 a server-files Finding of that agent names;
  - remediates by B07's rule: no named SHA-256 left, and the Finding's files back at their judged Baseline state;
  - moves a Remediated Finding with a named SHA-256 back to Confirmed, marks it regressed, and sends an Alert.
- **Baseline.** The Verdict rules: an Unrelated or Security hardening Verdict, or a Review queue dismissal of Insufficient context.
- **Alerts.** The source field is the agent's name.
- **UI.** Findings page labels, the server-files cleanup report, the regressed mark, and links between a Finding and the Server files tab.
- **Tests.** They mirror `test_served_playbooks.py`:
  - the rule's three checks and the not-scanned count;
  - remediation by SHA-256 and Baseline state, where the same bytes under another path do not remediate;
  - regression with an Alert;
  - a Vulnerability fix Verdict rejected;
  - no Lab and no Remediation PR;
  - an Alert with no file path;
  - a path over 240 characters or with a backslash triaged, analysed and validated;
  - a hand-opened Finding with `source_server_change_id`, and that reference refused for another Application's change;
  - the Verdict Baseline rules.

**Done when:** AC-B06, AC-B07 and AC-B05's remaining Baseline bullets have tests, and a fixture dropped PHP shell ends with a Confirmed Finding whose payload no job runs.

## Phase 18: Quarantine and Restore (B08, the A08 and A15 changes)

- **The Quarantine list** is every entry of the agent's latest manifest whose SHA-256 the Finding names, plus the files of its Server change that the Operator ticks. Ticked files join the files the Finding names.
- **Approval routes.** `POST /findings/{id}/quarantines`, with the password, `list_sha256` and the ticked files, and `POST /findings/{id}/quarantines/{quarantine_id}/restores`, with the password and the file list's SHA-256.
  - Both go through `approval()` and record Actions.
  - A Quarantine's idempotency key is (Application, Finding, list SHA-256, attempt), and a Restore's is (Application, Finding, Quarantine command, file list SHA-256, attempt). The attempt goes up only after the previous command expired, was cancelled or finished, because `enqueue` returns any job with a matching key, whatever its status.
  - Both sign their command with the Dashboard key.
  - `api.retry` refuses to re-run either.
- **Playbook steps.** `playbook_steps` shows the quarantine step's status.
- **Results.** Command results arrive as stored agent requests. Application code verifies them, and the Finding shows each file's result. A command shows as expired when its 15 minutes pass.
- **Agent.** Quarantine and Restore follow B08:
  - refuse a path with a symbolic link component, and open the parent directory once as an `os.Root`, doing every later step through it;
  - rename aside to a name with no executable extension, open with `O_NOFOLLOW` and check with `fstat` that the file is regular;
  - copy into an `O_CREATE|O_EXCL` file with mode 0600 in the Quarantine folder, `fsync`, and verify the SHA-256 before removing the aside name;
  - put back without replacing anything (`Root.Link`, then `Root.Remove`);
  - restore by quarantine entry, from the agent's own record, with an exclusive create, then `File.Chown` and `File.Chmod` without setuid or setgid, and the mtime set on the descriptor;
  - keep a journal in the state directory, and rescan afterwards.
- **UI.** A Quarantine panel with its Approval dialog, which lists the files and lets the Operator tick unmatched ones, the per-file results, and Restore with its own Approval dialog and its payload warning.
- **Demo guard.** `test-demo.sh`'s check that the demo never approves also covers the `quarantines`, `restores`, Watched roots and Rotate Dashboard key routes.
- **Tests.**
  - Go tests:
    - a symbolic-link component refused, and an aside file swapped for a link;
    - a hash mismatch put back, and a put-back whose path was taken;
    - a Restore to a taken path (`EEXIST`);
    - a Restore through a swapped link re-owns nothing, and setuid is stripped;
    - a crash before the remove is finished or undone on restart;
    - no file's bytes are ever deleted.
  - Backend tests: the Approval rules; a double submit sends one command; a re-approval after expiry, and a Quarantine after a Restore, each send a new one; ticked files join the Finding's named files.
  - The journey:
    - opens a server-files Finding by hand on the injected Server change, with `source_server_change_id`, as it does for commit Findings, and uploads its Detection rule;
    - refuses a Quarantine with a wrong password, then approves it;
    - sees the file in the stand-in's Quarantine folder (the named volume, mounted read-only into the fixture for `/admin/state`) and the Finding Remediated;
    - restores the file, and sees the Finding regress.

**Done when:** AC-B08 has tests, including the journey's Quarantine and Restore on the stand-in server.

## Phase 19a: Demo, `push` and `server-inject` (B10, the A16 change)

- **`compose.demo.yaml`.**
  - Add the stand-in server, and a `stand-ins` network for both ingress services, the fixture and the server, with no fixed names.
  - Add the demo's ingress ports, `NUMEN_COMPOSER_HOSTS=registry.invalid`, `NUMEN_AGENT_URL` and the test-mode poll interval.
  - Update `test_deployment.py` to match.
- **Demo stand-ins** (`fixture_server.py`, demo mode):
  - the storefront's web root on the stand-in server;
  - the dropped-shell stand-in, whose payload would only print `asset-monitor-fixture`;
  - Push deliveries from `/admin/demo/push` to the hooks registered for `asset-monitor-demo/shop`.
- **`demo.py`.**
  - The seed enrolls the storefront's On-server agent through the fixture's enroll drop, confirms its fingerprint, and accepts the first File manifest as the Baseline.
  - New steps `push` and `server-inject`, with their `NEXT` text, added to `STEPS` after `php-clean`.
- **`docs/demo.md`.**
  - Extend the stand-ins statement, the run-at-a-glance table and the list of what works without model keys.
  - Add a section for each new step.
  - Add troubleshooting for a silent agent and for clock skew.
- **`test-demo.sh`.** The step loop gains the new steps, and the `status` check and the no-approval check move with them.
- **`demo_check.py` and `canned_broker.py`.**
  - Update the exact seed and dry-run sets knowingly: an enrolled agent, unchanged served rows and fetched hosts, and no Finding, Alert or stand-in write at seed.
  - Add canned replies for the server-file Triage and Analysis.

**Done when:** `make test-demo` passes, with no model keys and with canned decisions, through `push` and `server-inject`.

## Phase 19b: Demo, `php-lab` (B10)

- **Demo stand-ins** (`fixture_server.py`, demo mode):
  - the storefront's Own repository, `asset-monitor-demo/toko-batik`: plain PHP, with a `composer.lock` that locks templar 1.4.0;
  - a git-backed templar stand-in with Release 1.4.0, the fix commit and Release 1.4.1. Its 1.4.0 returns `asset-monitor-simulated-flaw` where the flaw would reach a filter outside the allowed list, and never evaluates anything;
  - Packagist stand-in routes under `/packagist`, which also end today's 404 on `NUMEN_PACKAGIST_URL`.
- **`demo.py`.**
  - The seed adds the storefront's Own repository and the Upstream repository derived from its lock.
  - The `php-lab` step, with its `NEXT` text, goes into `STEPS` between `push` and `server-inject`.
- **`docs/demo.md`.** A section for `php-lab`.
- **`test-demo.sh`, `demo_check.py` and `canned_broker.py`.**
  - The step loop and checks gain `php-lab`.
  - Update the exact seed sets knowingly: a new Own repository and Upstream repository.
  - Add the canned PHP n-day Proof bundle.

**Done when:** AC-B10 passes. `make test-demo` passes with no model keys and with canned decisions, and the extended scenario runs on a fresh VM from `make demo-up`.

## Later (after release 2)

- A GitHub App for Remediation PRs.
- Labs with a database sidecar, for WordPress Proofs.
- Excluding paths inside a Watched root.
- Sweeping held server-file bytes with an Upstream Malicious change's Detection rule.
- An Alert for a silent On-server agent.
