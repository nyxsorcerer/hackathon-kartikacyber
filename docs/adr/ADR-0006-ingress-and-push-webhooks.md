# ADR-0006: Receive Push deliveries and On-server agent traffic through a separate ingress

## Status

Accepted, 2026-11-15. Amends A15 and the first-release non-goal "GitHub push webhooks or any other public inbound endpoint" in `docs/prd/asset-monitor-prd.md`, and the release-1 plan's "Push webhooks through the private tunnel". Implemented by B01 and B02 in `docs/prd/asset-monitor-r2-prd.md`. ADR-0007 relies on the agent listener described here.

## Context and decision point

Release 2 adds two kinds of inbound traffic: Push deliveries from GitHub, and reports and command polls from On-server agents. Today Asset Monitor has one HTTP surface, and it fits neither:

- `uvicorn numen.api:app` serves the dashboard, published on `127.0.0.1:8788` only. Every route except health and login needs the `numen_session` cookie, and every write also needs `X-CSRF-Token`. GitHub and an On-server agent can send neither.
- Importing `numen.api` runs `create_app()`, which builds the whole dashboard. No route can be mounted on its own.
- Every service on the `x-app` Compose anchor holds the vault key, the broker token and the database owner's password. It also sits on networks that reach `db`, `app` and the broker. Any bug in an internet-facing process with that anchor would hand over every credential, including the GitHub write token. The database owner's role alone is enough to rewrite the Operator's password hash.
- `throttle()` counts attempts per client address. Behind a tunnel, every client shares one address, so anonymous traffic could lock the Operator out of login and Approvals.
- Browsers do not keep cookies apart by port, so a second listener on the same host would receive `numen_session`.
- GitHub's servers cannot join the Operator's Private tunnel. A Push webhook needs a URL that GitHub can reach, so "through the private tunnel" in the release-1 plan cannot work for GitHub.
- The monitored server is the machine an attacker targets. If it reached the host through the Private tunnel, any local user on it, such as a compromised web app, could reach the dashboard's login and Approvals.
- Agent records are evidence: reports, uploaded bytes and command results decide Baselines, Quarantines and Remediation (ADR-0007). They must not rest on the same process as the internet-facing push path.

The question is where inbound machine traffic lands, and what the processes that receive it may hold.

## Decision

1. **Two ingress services, one per listener.** `ingress-push` and `ingress-agent` run `numen.ingress` from the app image, each as its own Compose service and process with its own ASGI app. Neither imports `numen.api`. Neither has a login, session, CSRF, SPA or `/api` route. Neither reads, logs or stores a `Cookie` header, and neither logs request bodies.
2. **Both listeners on loopback.**
   - The push listener, published on `127.0.0.1:${NUMEN_PUSH_PORT:-8791}`, answers only `POST /push/<push id>`. It is the only thing the Operator may point a Public tunnel at.
   - The agent listener, published on `127.0.0.1:${NUMEN_AGENT_PORT:-8792}`, serves TLS with the key `NUMEN_AGENT_TLS_KEY`, whose public-key pin On-server agents require (ADR-0007). It answers only the `/agent/` routes of ADR-0007 and a health check.
   - Each server reaches the agent listener through its own Agent tunnel, which may open that port and nothing else: for example a dedicated SSH key whose `authorized_keys` entry is `restrict,port-forwarding,permitopen="127.0.0.1:8792",command="/bin/false"`, or a VPN ACL that allows only that port from the server's peer. An Agent tunnel is never the Private tunnel the Operator's devices use.
   - The dashboard stays on `127.0.0.1:8788`, and neither listener, nor anything on an Agent tunnel, can reach it.
3. **Every request is authenticated by its signature.** A Push delivery is checked against `X-Hub-Signature-256`, and an On-server agent request against its Agent key (ADR-0007). A request that is unsigned or wrongly signed changes nothing.
4. **Strict limits, checked before any parsing.**
   - Body caps per route, counted on the bytes actually read, chunked bodies included: 1 MiB for a Push delivery, 16 MiB for a File manifest, 16 MiB for one upload of several files of at most 1 MiB each, and 64 KiB for everything else.
   - Rate limits are counted per push id, per agent and per Enrollment code id, never per client address, plus one global bucket on the push listener and one for requests that name an unknown agent or code id.
   - Before it reads a body, the push listener checks the push id's fixed format against an in-memory set of known push ids, refreshed every 15 s. An unknown push id gets `404` and is recorded nowhere.
   - Each ingress role has a `CONNECTION LIMIT` and a `statement_timeout`.
5. **Each ingress service holds as little as possible.**
   - Each connects to Postgres as its own role, created outside the migrations (decision 8).
   - `asset_monitor_push` may read `push_webhooks`, update only its last-accepted and last-refusal columns, and insert into `push_deliveries`. It has no grant on any agent table.
   - `asset_monitor_agent` may read agents' ids, public keys and status, the ids, agents and expiry of Enrollment codes (never their hashes), the wanted lists, and the signed configurations and Agent commands. It may insert Enrollment requests and agent requests, and nothing else. It cannot update an agent's key or status, and has no grant on push tables, Watched roots, Baselines, Server changes or held bytes. Application code, not the ingress, works out each wanted list (ADR-0007).
   - Neither role can read Accounts, Settings, Operators, sessions or Findings, or insert a job.
   - Push webhook secrets are encrypted with their own key, `NUMEN_INGRESS_KEY`, which only `ingress-push`, the app and the worker hold. `NUMEN_AGENT_TLS_KEY` is held by `ingress-agent` only.
   - Neither service gets `NUMEN_SECRET_KEY`, the broker token or any part of the Dashboard key.
   - In production each joins only two networks: its own bridge, which carries its published port, and an internal network that only it and `db` share. Neither is on `application` or `control`. The test and demo overlays add the internal `stand-ins` network.
6. **Application code acts, and re-checks what the agent listener stored.**
   - `ingress-agent` stores each request exactly as received: its signed headers and raw body. Postgres sets the time received, and the role cannot write it.
   - Before anything uses a stored request, application code verifies it again: the Agent-key signature, the timestamp against the time received, the nonce, the agent's status, the body SHA-256 and the report sequence (ADR-0007). The worker hashes every uploaded file again before it is held.
   - Application code, never the ingress, checks an Enrollment code and binds an Agent key to its agent.
   - Every 15 s, the scheduler turns accepted Push deliveries into polls, and verified agent reports into wanted lists and jobs. Receiving a request never sends an Alert, never opens a Finding and never stands in for an Approval.
7. **A Push delivery is only a nudge.**
   - The push listener checks the signature over the raw bytes and checks the `X-GitHub-Event` header. It accepts `push`, and `ping`, which changes nothing. It never parses the body.
   - Commit data still comes only from the GitHub API, through `Sources` with the read token.
   - Deliveries are deduplicated by `X-GitHub-Delivery`, and by the SHA-256 of the raw body for 7 days. GitHub's redeliveries reuse the delivery id, and two real pushes never share a body.
   - Scheduled polling continues as the fallback.
8. **Roles are created outside the migrations.** Postgres roles belong to the whole cluster, and the backend tests migrate many schemas in one cluster.
   - Migrations only grant and revoke on their own tables. They create a missing role `NOLOGIN` and never drop one on downgrade.
   - The `migrate` service then runs one idempotent step that gives each ingress role `LOGIN` and its password from `.env`.
   - `restore.sh` creates any missing role before it loads `database.sql`.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| Add Push webhook and agent routes to the dashboard app | Least code | The dashboard, login and Approvals become reachable from the internet, and the shared throttle lets anyone lock the Operator out |
| A forwarder that passes raw requests to an internal dashboard route | The ingress holds no secret | Unauthenticated bytes still reach the dashboard process, and the ingress gets a network path into it |
| A separate ingress on the `x-app` anchor | Reuses the app's settings and database session | A bug in an internet-facing process yields the vault key and the database owner's role |
| One ingress process for both listeners | One service and one role | A bug in the public push path can forge agent keys, reports and command results, which are the evidence for Baselines, Quarantines and Remediation |
| On-server agents through the Operator's Private tunnel | No second tunnel to run | Anything on the server can reach the dashboard, lock the Operator out of login and Approvals, or try the password |
| Polling only, no inbound traffic | No new surface | Pushes wait for the interval, and On-server agents cannot report at all |
| Two ingress services with their own roles and keys, Agent tunnels, and application code re-checking stored agent requests (chosen) | A compromised push service can at most forge nudges. A compromised agent service can withhold or delay agent traffic, but cannot forge it | Two database roles, new keys in `.env`, and up to 15 s before a delivery or report is acted on |

## Consequences

- A15 changes. The dashboard stays loopback-only. The push listener is the one public endpoint, and only through a Public tunnel that the Operator points at that port.
- The Operator runs one Agent tunnel per server, and points no Agent tunnel at the dashboard port.
- `make init` adds missing keys to an existing `.env` and never changes existing ones: `NUMEN_INGRESS_KEY`, the two ingress roles' passwords, and `NUMEN_AGENT_TLS_KEY` with its pin.
- `make up`, `make logs`, `make backup` and `make restore` include both ingress services. `restore.sh` refuses a backup whose environment lacks the ingress keys.
- `test_every_published_port_is_bound_to_loopback` covers the two new ports.
- Redaction covers Push webhook secrets.
- A captured delivery replayed under a new delivery id has the same body, so it is dropped for 7 days.
- A leaked push id lets anyone use up that push id's rate limit, so real deliveries are refused until the next scheduled poll catches up. Extra polls need the Push webhook secret.
- A compromised `ingress-agent` can delay, withhold or drop agent traffic. Because the wanted list is unsigned, it can also ask an agent for any file the agent may upload, and read those bytes (ADR-0007). It cannot forge a report, an Enrollment, a command result or an agent's liveness, because application code verifies each stored request with the agent's key.

## Reconsider when

GitHub App webhooks come into scope with the GitHub App for Remediation PRs, or Multiple Operators do.
