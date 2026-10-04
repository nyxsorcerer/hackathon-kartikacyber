# ADR-0001: Application stack and durable jobs

## Status

Accepted for implementation, 2026-10-04. React/TypeScript, FastAPI, PostgreSQL, and the durable job queue are implemented with Docker verification.

## Context and decision point

The [PRD](../prd/numen-prd.md) requires one authenticated operator, periodic upstream monitoring, long-running agent operations, and durable findings. The workspace has no application or storage pattern to preserve. Jobs and their triggering records must survive container replacement.

Two credible paths are a Python API with a separate queue service, and a Python API using PostgreSQL for both application state and a bounded job queue. A TypeScript API is also viable; there is no existing language investment in the workspace.

## Decision

Use React with TypeScript and Vite for the dashboard, FastAPI with SQLAlchemy and Alembic for the backend, and PostgreSQL for application data, durable jobs, and notification delivery state. Build the frontend in a Node build stage and serve its static files from the API image. Run API, worker, and scheduler processes as separate Compose services using the same backend image.

Claim runnable jobs in short transactions using `FOR UPDATE SKIP LOCKED`, then execute outside the transaction. PostgreSQL documents this lock mode as suitable for competing consumers of a queue-like table; lease recovery, deduplication, and fencing remain application responsibilities. [PostgreSQL SELECT documentation](https://www.postgresql.org/docs/current/sql-select.html)

Store artifact bytes on a persistent Docker volume with metadata and integrity hashes in PostgreSQL. There is no current requirement for an object storage service.

## Options considered

| Option | Fit and benefit | Cost and trade-off |
|---|---|---|
| FastAPI + PostgreSQL job table | Python fits PoC/probe tooling; one durable store permits atomic trigger/job creation | Requires a small, tested leasing/retry implementation and careful transactions |
| FastAPI + PostgreSQL + Redis/Celery | Established task framework; useful for larger distributed worker pools | Adds a broker and another persistence/recovery boundary for a single operator |
| TypeScript API + PostgreSQL | Shares the frontend language and Pi's Node ecosystem | Still needs Python and process adapters for probes/labs; no repository pattern favors it |
| SQLite and a local scheduler | Low initial setup cost | API, scheduler, and workers would coordinate writes across processes and shared storage; less suitable for the selected deployment split |

The first option is the proposed smallest complete deployment for the requested workload. It does not imply that PostgreSQL queue semantics provide exactly-once external side effects.

## Consequences and boundaries

- PostgreSQL is the source of truth for job status; an API process never executes an agent itself.
- The scheduler creates deduplicated due-check jobs, and workers claim them by lease.
- Notification records are created in the same transaction as their triggering review items and delivered asynchronously.
- Start with one expensive agent/lab workload at a time. Fast source fetches and notification delivery have separate bounded work slots.
- Keep repository checkout and artifact files outside the database; retain immutable reference/hash metadata inside it.
- Version-pin runtime dependencies during the first implementation task rather than using floating versions in Dockerfiles.

## Known unknowns and reconsideration

Throughput and database size are unmeasured. Reconsider the queue choice if measured job throughput or fairness requirements exceed the small worker implementation, or if independent worker fleets become a confirmed requirement. Retain the job contract and idempotency rules if the queue implementation changes.

## Governing implementation detail

The [architecture](../design/numen-design.md#jobs-scheduling-and-recovery) defines leases, retries, transaction boundaries, and acceptance checks. The [work plan](../plans/20261003-feature-numen.md) assigns their implementation and tests.
