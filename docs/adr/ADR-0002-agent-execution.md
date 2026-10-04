# ADR-0002: Execute agents, generated scripts, and labs in disposable containers

## Status

Accepted for implementation, 2026-10-04. Disposable workload isolation and native CLI policies have been exercised against the actual Docker Engine; credentialed inference compatibility remains account-dependent.

## Context and decision point

The application will consume upstream source and remotely returned content, generate executable Python, and build intentionally vulnerable applications. The operator also stores provider credentials and private reports. Those workloads need a different runtime boundary from the API and database.

The question is how to create disposable workloads while satisfying the all-Docker requirement and keeping application credentials and Docker control out of generated code.

## Decision

Run a trusted **runner broker** as a separate Compose service. Only that service receives the deployment's Docker Engine socket. Workers call its authenticated internal API with validated job types, immutable inputs, and a selected credential. The broker creates fixed workload profiles with fresh filesystems and retrieves bounded outputs. Application containers and workload containers receive no Docker socket.

The broker is a privileged control-plane component: Docker control can affect the host. Restricting callers and hardcoding container specifications reduces its exposed interface; it does not make the socket an unprivileged capability. [Docker Engine security](https://docs.docker.com/engine/security/)

Create separate images for Pi, Claude Code, Codex CLI, Python probes, and lab verification. Use the deployment's engine for child containers. A job receives neither arbitrary host mounts nor an operator-supplied container launch specification. Each coding-agent image implements the same job/result contract, with runtime-specific authentication, model/effort selection, and event parsing.

## Options considered

| Option | Current-scope benefit | Cost and trade-off |
|---|---|---|
| Agents run inside the API/worker container | Easy subprocess invocation | Untrusted execution shares persistence credentials and process lifetime; fails AC-18 |
| Disposable containers through a narrow trusted broker | Independent filesystems, resources, and network profiles; conventional Docker deployment | Broker is trusted with Engine control and needs explicit input validation and cleanup |
| Nested rootless Docker engine | Separate engine namespace for workloads | Additional daemon/storage/networking; rootless Docker-in-Docker still requires a privileged outer container in the documented configuration |
| Separate VM or hosted execution system | Stronger host separation | Adds infrastructure beyond the requested self-hosted Docker application |

The broker is selected for the single-operator deployment. Docker's [rootless tips](https://docs.docker.com/engine/security/rootless/tips/) establish the privilege caveat for the nested-engine alternative. This recommendation does not claim container isolation is equivalent to a VM boundary.

## Workload profiles

| Profile | Inputs | Allowed external access | Outputs |
|---|---|---|---|
| Pi / Claude / Codex analysis | Selected source snapshots, diff/context, job-specific provider credential | Selected provider endpoints through a job proxy | Structured result, report, bounded session metadata |
| Version-recipe generation | Source/release fingerprints and target snapshots; scoped fetch tool | Provider endpoints; target reads through the fetch gateway | Python script, recipe metadata, fixtures |
| Version probe | Saved recipe and target configuration | Program target through the fetch gateway | Version observation and evidence |
| Finding artifact generation | Approved investigation inputs and selected source version | Provider; explicit source/dependency retrieval handled by trusted collectors | PoC, Docker bundle, report |
| Lab build/verification | Artifact bundle and pinned dependencies | Build phase: approved registries; verification phase: isolated lab network | Build/health/reproduction logs and verification result |

Profiles supply non-root execution, resource/time limits, bounded disk/output, dropped capabilities, and controlled writable directories. A vulnerable application receives only its lab fixtures and dummy credentials.

## Consequences

- Model providers and target reads are separate egress roles. Network policy must be enforced by container networking/proxy rules, independently of the prompt.
- A child container has no application database route or application secret. Provider access supplies only the selected connection, never all configured accounts.
- Repository-supplied hooks, agent configuration, skills, and plugins are treated as source data. Jobs load only application-bundled resources for their profile.
- Building a vulnerable Dockerfile is executable work and uses the same isolation boundary; artifact upload never invokes a build.
- PoC verification targets the lab service. Starting it is a distinct operator action recorded with the finding.
- Broker restart must reconcile labeled containers, recover logs, and remove abandoned workloads. The job lease token prevents late results from replacing a newer attempt.

## Known unknowns and reconsideration

Actual Engine checks exercise the constrained proxy, immutable read-only inputs, no socket/provider credentials in probes, resource/time limits, cancellation, lab reproduction, and native Codex read/write/private-cache rules. Codex uses a narrow namespace syscall policy while retaining its native sandbox. The first verifier accepts local declarative lab materialization and reports unsupported executable build instructions explicitly. Account-specific model, OAuth, and inference access require operator credentials. See [runtime details](../../runner/README.md) and [verification](../verification.md).

Reconsider this boundary if multiple mutually untrusted users or a stronger host-isolation requirement enters scope. The [architecture](../design/numen-design.md#container-execution-and-network-boundary) supplies the broker protocol and network rules; the [plan](../plans/20261003-feature-numen.md#phase-3--connect-accounts-and-execute-bounded-agent-jobs) supplies acceptance evidence.
