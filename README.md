# Numen

An authenticated, Docker-hosted dashboard for monitoring deployed software, upstream security changes, CVEs, and reproducible findings.

The application includes a React/TypeScript UI, FastAPI backend, PostgreSQL persistence and job queue, a scheduler/worker, and isolated Pi, Claude Code, Codex, Python probe, and lab containers.

## Start

Install Docker Engine/Desktop with Compose. No host Python, Node, or agent installation is required.

```sh
./scripts/init.sh
./scripts/compose.sh --profile images build
./scripts/compose.sh up -d --wait app worker scheduler runner-broker fetch-gateway
./scripts/compose.sh --profile setup run --rm bootstrap-operator
```

`make up` runs those steps together when Make is available.

Open **http://localhost:8788**. The operator is **admin**. Read the generated password locally:

```sh
cat .numen/bootstrap-password
```

Setup creates random credentials in protected `.env` and `.numen/bootstrap-password` files. It preserves existing configuration. Docker Desktop on macOS is detected even when its CLI and credential helper are absent from PATH. Ports are bound to loopback; database and broker ports are internal.

To reset the operator password interactively and revoke existing sessions:

```sh
make reset-password
```

## Use

1. **Settings → Accounts:** connect the providers you use. Pi supports DeepSeek, Command Code through the bundled provider plugin (API key, native login, or auth.json import), OpenAI, and Claude API connections. Codex supports OpenAI API-key access, eligible device login, or protected native-session import. Claude supports API keys, subscription native login, or protected native-session import. Run the connection check to discover account-compatible models and supported effort levels. Add a `github` account with a fine-grained, read-only token (Contents and Metadata): GitHub repositories are not polled without it, and show `github_token_required` until one is added.
2. **Settings → Defaults:** choose the global monitoring interval (in minutes, hours or days, at least 5 minutes; `NUMEN_MONITOR_INTERVAL_DAYS` seeds it in days on a new database) and agent/account/model/effort profiles for audit context, version recipes, commit/CVE analysis, and finding generation. Model catalogs are separate for each runtime. Jev has its own optional typed-triage connection.
3. **Applications → Insert application:** enter the asset URL and software identity, polling interval (at least 5 minutes), and optional CVE selectors/score criteria. The default interval is seven days and can be changed. Then open the Application's **Repositories** tab and link its repositories: at most one Own repository on GitHub (remove it to replace it; an Application may have none), and any number of Upstream repositories added by hand, a GitHub URL or a WordPress.org plugin slug, each with an optional Locked version. The tab lists each Upstream repository with its packages, its on/off switch, its Locked version (editable, with where it came from: Manifest, Operator or Deployed), its status (Watching, Off, Removed or Error, plus its Release branch, "Release branch pending" or "release branch unknown"), its last check and a Backfill action, and it lists the packages that could not be resolved. The API is `POST/PATCH/DELETE /api/applications/{id}/repositories` (see `docs/implementation-contract.md`). An Upstream GitHub repository also watches the Release branch of its Locked version (`{major}.x`, `{major}.{minor}`, `release-{major}` or `v{major}`, the first that exists); with none it watches the default branch only and reports `release_branch_status: "unknown"` (release branch unknown). A repository is stored once per URL, so Applications that share one are polled and triaged once. With an Own repository, its direct dependencies (`package.json` and `composer.json`, versions from `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `composer.lock`) are mapped to their GitHub repositories through npm or Packagist metadata and linked as Upstream repositories after its Baseline: all on the first time, later additions off. A commit that changes a manifest or lockfile derives them again; a dependency that is gone is marked removed and keeps its history, and a package with no GitHub source is listed in `unresolved_dependencies`. WordPress release monitoring works without GitHub.
4. **Application detail:** Check now checks every linked repository that is on, generate/reuse version recipes, build audit context with the pinned Trail of Bits skill, and inspect CVEs/findings. A repository's first check sets its Baseline at the head and imports no history; later checks import the revisions after it, and an unchanged GitHub repository answers `304` and creates nothing. To triage earlier commits, use Backfill on the Repositories tab to import and triage the last N (1–100, default 20) up to the Baseline (`POST /api/applications/{id}/repositories/{repository_id}/backfills`). Each imported commit records its Pre-filter flags (dependency manifests, `package.json` scripts, CI workflows, minified or obfuscated code, authentication and cryptography paths). Manual checks work while scheduled monitoring is paused.
5. **Commit review:** choose an Application to review its security queue. Triage (Jev, Pi or Claude Code; never Codex, which has no way to run without a shell) is one call with no tools and a 120-second deadline that decides whether a change deserves Analysis and gives a short reason and a potential-issue title. Application code checks the reply; a reply that fails the check is recorded as failed and retried twice, never read as unrelated, and each run is kept as a Transcript. Complete non-security changes are dismissed. A change Triage flags (security candidate or insufficient context) is analysed automatically, once per commit, so a commit of an Upstream repository several Applications share is analysed once. Automatic Analysis is capped at 10 runs per Application and 30 per Provider account each UTC day (a shared Upstream commit counts only against the account); a change over a cap waits as "waiting for cap" and starts, oldest first, after the caps reset at 00:00 UTC. Automated runs (Triage, automatic Analysis and CVE analysis, audit refresh) use only Provider accounts that hold an API key and are refused with the reason otherwise; Analyze by hand works at a cap and with a subscription sign-in. Analysis runs are read-only (Pi or Claude Code; Codex is refused for Analysis and CVE analysis, because it always has a shell): the agent reads the pinned revision's source snapshot and the diff, writes only its outputs, builds and runs nothing, and returns one Verdict with a confidence (low, medium or high): Vulnerability fix, Vulnerability introduced, Malicious change, Security hardening, Unrelated, or Insufficient context, which puts the change in the dashboard's Review queue. A Vulnerability fix, Vulnerability introduced or Malicious change Verdict opens one Finding in each Application that uses the repository (an Upstream repository's Exposure is not computed yet and counts as exposed), and a change is linked to that Application's Findings it addresses (a Vulnerability fix linked that way opens no Finding of its own); a repeat Analysis never opens a second Finding or reopens a Dismissed one. A Vulnerability fix or Vulnerability introduced Finding gets a report, Python PoC, and draft vulnerable application bundle that only a Lab run builds; a Malicious change keeps its drafted Detection rule and cleanup report with the analysis. Analysis has a 30-minute deadline: one that expires leaves the change pending with a visible timeout, never Unrelated. The commit list shows each change's Verdict with its confidence (unknown for Verdicts carried over from Numen) or where its Analysis stands (queued, waiting for cap, timed out after 30 minutes, blocked or failed with the reason), and its Pre-filter flags beside the Triage result, also when Triage rejected the change; filter by Verdict, or choose Show → Review queue. Each change links to the Findings it opened or was linked to, in every Application; Confirm revision records the commit review decision and leaves the Finding lifecycle alone. Saved runs, job links and immutable downloads remain available; independent lab verification is tracked on the finding.
6. **CVEs:** configure selected CVSS versions and an inclusive minimum Base score. Product matches, score eligibility, and deployed-version applicability are separate. Unscored, v2-only, below-threshold, and unconfirmed records cannot bypass the analysis gate. Analysis reads the newest release the record still reports as affected, resolved to that release tag's commit, because the monitored checkout already contains the fix; ranking releases requires an Application version scheme, and the launch dialog accepts an explicit revision when a record cannot be ranked. CVE analysis is read-only like commit Analysis: it reads the pinned source snapshot, has no Docker daemon or package-registry access, and drafts its bundle without building it. Analysis generates a linked finding with a report, Python PoC, and pinned vulnerable Docker bundle draft; success requires a complete bundle. Incomplete generation fails with its report and draft files retained. Jobs and analysis history link to the report and finding artifacts.
7. **Findings:** each Finding has a source (commit, served content, advisory, or a CVE carried over from Numen) and moves from Open to Confirmed or Dismissed, and from Open or Confirmed to Remediated, recording what moved it; the Operator can Confirm, Dismiss or Mark remediated with a reason, and a reproduced Lab Proof confirms it. Upload or generate `poc.py`, `report.md`, and a pinned `vulnerable-app/` Docker bundle. Download the integrity manifest and artifacts. **Start Lab** is an Approval: it asks for your password and checks it on that request alone, with no re-authentication window, so a missing or wrong password is refused even straight after another Approval. It then builds the bundle in an offline Node Lab (below): a Proof that reproduces confirms the Finding, and one that does not stays visible as Not reproduced and changes nothing. A Lab is never retried; start a new one, with a new Approval. The Finding page lists its history (opened, linked changes and state changes, each with its cause) and shows the Deployed version apart from the state (Unknown until the Deployed version check exists): a linked fix does not by itself make a Finding Remediated, and Draft only means its artifacts are incomplete. Opening a Finding, and reaching a cap, sends an Alert to the Discord webhook (Settings → Discord; Send test Alert checks it). An Alert carries only the Application or Provider account, the source (short SHA, Watched page or advisory id), the Verdict and confidence (or Advisory, or Cap reached) and a dashboard link, with mentions disabled; nothing else sends one, including a Finding you create by hand.

Secrets are write-only. Native session import accepts a bounded JSON file without previewing credentials. Native login availability depends on the runtime/account. Codex uses its device flow. Claude login shows the sign-in link, then you paste the authorization code from the page into the login dialog. Command Code login runs the bundled plugin's own login: open the Studio link, then paste the API key Studio shows. Pasted input is relayed to the isolated login process and is never shown in job events. Pi native login for other providers is not implemented. No host credential directory is mounted automatically.

Version recipes preserve ambiguous/unknown results and reuse Python without another generation call. Audit context retains its source/skill revisions, supporting function documents, partial coverage, and stale state. Jobs expose progress, errors, cancellation, and fenced recovery. Markdown reports and relative supporting-document links open inside the application.

## Runtime and reproduction

Only the trusted broker receives Docker Engine control. Workloads run non-root with resource limits, isolated networks, time limits for probe/lab/login runs, Triage (120 seconds), and Analysis, CVE analysis and audit function analyses (30 minutes; other agent runs continue until finished or cancelled), read-only inputs, and scoped provider/target access: an agent run reaches only its provider's hosts, plus `herdr.dev` when it hosts a Herdr session. Tool access is fixed per operation and never includes Docker. Native Codex sandboxing is retained, with a narrow namespace policy required by Docker's default syscall restrictions. See [runtime details](runner/README.md).

A Lab builds a Proof bundle as its own project on the host Engine, in two phases. Phase one fetches the Node app's dependencies from `package.json` and `package-lock.json` with install scripts disabled, no credential, and egress only to the npm registry. Phase two builds the ordinary Dockerfile (`RUN` and multi-stage included) with no network, on the bundled Lab base `asset-monitor-lab:0.1.0` only (pinned Node 24.9.0, npm set to skip install scripts), and runs the app and the PoC on an internal Lab network with no route out and none to the application network. For an Own-repository Proof the app is the Own repository at the Verdict's commit. Node is the only Lab stack; any other is refused with a message. Each Lab image is at most 4 GB, a build gets 15 minutes and a run 10, and every Lab's images and containers are removed after its run, so a Lab over a limit fails visibly and leaves no image behind. Original unsupported bundles remain downloadable and unverified; they are never silently changed or reported as reproduced.

Configure your own accounts before running paid agent work. Development verification uses controlled fixtures and credential-free native CLI checks; authenticated provider inference and account-specific entitlements require connection checks with your credentials.

## Checks

All normal check entrypoints run inside Docker:

```sh
make check
make test-unit
make test-integration
make test-runtime
make test-ui
make test-journey
```

`test-runtime` explicitly enables actual Docker Engine cases. `test-integration` includes PostgreSQL claims, fencing, persistence, source/CVE workflows, and native-cache handling. Named `CASE` values are validated; unknown cases and empty pytest selections fail.

The journey uses an isolated `asset-monitor-test` project at http://localhost:18788, with real HTTP/SVN source fixtures and captured webhook delivery. It makes no authenticated inference or production-target requests. Stop that test stack afterward:

```sh
./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml down
```

## Backup and restore

`make backup` briefly pauses application writers and creates a consistent database/artifact/credential-key set under `.numen/backups/`. Preserve the full private set, including `deployment.env`.

```sh
make backup
make restore BACKUP=.numen/backups/<timestamp>
```

Restore replaces the application database and artifacts with the chosen backup. It validates the backup and matching database credentials first. For a fresh deployment, restore its `deployment.env` as `.env` before creating the new project's empty database volume. Use the operator password associated with that backup, or reset it through the container command.

`make down` stops the main stack while keeping its volumes. `make logs` shows recent service output. Use `NUMEN_PORT` and `NUMEN_DASHBOARD_URL` in `.env` to change the local address.

## Implementation documents

| Document | Purpose |
|---|---|
| [PRD](docs/prd/numen-prd.md) | Product behavior and acceptance criteria |
| [UI specification](docs/ui-spec/numen-ui-spec.md) | Screens and operator interactions |
| [Architecture](docs/design/numen-design.md) | Components, persistence, jobs, integrations, and verification |
| [Application/jobs ADR](docs/adr/ADR-0001-application-and-jobs.md) | Stack and durable queue |
| [Execution ADR](docs/adr/ADR-0002-agent-execution.md) | Container execution boundary |
| [Work plan](docs/plans/20261003-feature-numen.md) | Implementation order and proof boundaries |
| [Coordination contract](docs/implementation-contract.md) | Actual shared API/runtime shapes and ownership |
| [Evidence register](docs/references.md) | Primary integration sources and inspection evidence |
