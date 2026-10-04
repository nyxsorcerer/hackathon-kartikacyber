# Implementation verification

Date: 2026-10-04. The application is implemented and deployed locally. This record distinguishes executed repository proofs from account-dependent checks.

## Executed boundaries

- Locked, digest-pinned application and Pi/Claude/Codex/probe/lab images build on the actual Docker Engine.
- Backend API/domain tests cover authentication, CSRF, programs/defaults, optional AI-off/manual review, source history, score gates, immutable findings/artifacts, native-cache encryption/redaction, and typed Jev protocol parsing.
- PostgreSQL checks use disposable schemas and independent connections to prove SKIP LOCKED claims, fencing/recovery, migrations, scheduler deduplication, and persistence across app replacement.
- Frontend Docker build, typecheck, lint, and thirteen behavior tests pass, including protected native import, device-login polling/cancellation, runtime-specific model/effort selection, explicit Analyze submission, safe report rendering, and supporting-file navigation.
- Actual Engine tests exercise non-root execution, read-only inputs, absent socket/provider credentials in probes, direct egress denial, scoped proxy/fetch access, timeout/cancel/resource limits, pinned CLI versions, native Codex permissions, and real Docker lab/PoC outcomes.
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

```sh
make check
make test-integration
make test-runtime
make test-ui
make test-journey
```

Use the service/schema/fixture entrypoints in the repository. Tests reject empty/unknown selections. Current verification: **55 backend**, **56 runtime** (including **24 actual Engine cases**), and **13 frontend** tests passed: **124 tests total**. The full backend/runtime/UI suites passed after the login corrections. The final real HTTP journey passed after the earlier transaction correction. Lint/typecheck/build, locked-image builds, backup/restore readback, and the Pi patched dependency audit passed. The updated main stack is healthy at http://localhost:8787; the isolated test stack was stopped. Account-specific paid inference remains an operator-dependent check.
