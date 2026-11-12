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

1. **Settings → Accounts:** connect the providers you use. Pi supports DeepSeek, Command Code through the bundled provider plugin (API key, native login, or auth.json import), OpenAI, and Claude API connections. Codex supports OpenAI API-key access, eligible device login, or protected native-session import. Claude supports API keys, subscription native login, or protected native-session import. Run the connection check to discover account-compatible models and supported effort levels.
2. **Settings → Defaults:** choose monitoring days and agent/account/model/effort profiles for audit context, version recipes, commit/CVE analysis, and finding generation. Model catalogs are separate for each runtime. Jev has its own optional typed-triage connection.
3. **Programs → Insert program:** enter the asset URL and software identity, GitHub repository or WordPress plugin slug, polling interval, and optional CVE selectors/score criteria. The default interval is seven days and can be changed. WordPress release monitoring works without GitHub.
4. **Program detail:** check source history, generate/reuse version recipes, build audit context with the pinned Trail of Bits skill, and inspect CVEs/findings. Initial source sync establishes a baseline; later checks import available unseen revisions. Manual checks work while scheduled monitoring is paused.
5. **Commit review:** choose a program to review its security queue. Jev/Pi/Claude/Codex triage names potential issues and distinguishes fixes, hardening, and introductions; complete non-security changes are dismissed. Explicit Analyze runs can build and exercise a pinned vulnerable lab, report finding/no-finding/needs-more-evidence, and automatically link supported findings to a report, Python PoC, and vulnerable application bundle. Saved runs, job links and immutable downloads remain available; independent lab verification is tracked on the finding.
6. **CVEs:** configure selected CVSS versions and an inclusive minimum Base score. Product matches, score eligibility, and deployed-version applicability are separate. Unscored, v2-only, below-threshold, and unconfirmed records cannot bypass the analysis gate. Analysis reads the newest release the record still reports as affected, resolved to that release tag's commit, because the monitored checkout already contains the fix; ranking releases requires a program version scheme, and the launch dialog accepts an explicit revision when a record cannot be ranked. CVE analysis runs with a build sandbox: a shell, `git`, and a private Docker daemon in a writable workspace, so the agent can clone upstream history, install the dependencies a vulnerable release pins, and actually build and run its bundle before claiming it works. That sandbox reaches source, package and image registries; it never receives the host Docker socket, and its daemon, images and workspace are destroyed with the run. It shares the agent's workspace with its daemon so bind mounts work, carries the same offline lab base the verifier builds with, and reports a rejected build on the job timeline instead of only in a container log. Analysis generates a linked finding with a report, Python PoC, and pinned vulnerable Docker bundle; success requires a complete bundle. Incomplete generation fails with its report and draft files retained. Jobs and analysis history link to the report and finding artifacts.
7. **Findings:** record CVE or local 0day findings with Open/Fixed status. Upload or generate `poc.py`, `report.md`, and a pinned `vulnerable-app/` Docker bundle. Download the integrity manifest and artifacts, and explicitly verify compatible bundles in an isolated lab. An upstream fix does not automatically close a deployed target's finding.

Secrets are write-only. Native session import accepts a bounded JSON file without previewing credentials. Native login availability depends on the runtime/account. Codex uses its device flow. Claude login shows the sign-in link, then you paste the authorization code from the page into the login dialog. Command Code login runs the bundled plugin's own login: open the Studio link, then paste the API key Studio shows. Pasted input is relayed to the isolated login process and is never shown in job events. Pi native login for other providers is not implemented. No host credential directory is mounted automatically.

Version recipes preserve ambiguous/unknown results and reuse Python without another generation call. Audit context retains its source/skill revisions, supporting function documents, partial coverage, and stale state. Jobs expose progress, errors, cancellation, and fenced recovery. Markdown reports and relative supporting-document links open inside the application.

## Runtime and reproduction

Only the trusted broker receives Docker Engine control. Workloads run non-root with resource limits, isolated networks, time limits for probe/lab/login runs (agent runs continue until finished or cancelled), read-only inputs, and scoped provider/target access. Native Codex sandboxing is retained, with a narrow namespace policy required by Docker's default syscall restrictions. See [runtime details](runner/README.md).

The lab verifier builds a bundle as its own project: an ordinary Dockerfile with `RUN` and multi-stage, with the network its dependencies need, and then one container with a writable root filesystem that may boot its own database and finish an install before serving. A bundle may be a whole application tree. It still must pin every base by digest and may not reach outside itself at build time. Original unsupported bundles remain downloadable and unverified; they are never silently changed or reported as reproduced.

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
