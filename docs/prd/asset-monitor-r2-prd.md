# PRD: Asset Monitor, release 2

Status: the Operator set the scope on 2026-11-15, and Claude defaulted the details the same day (see "Decisions Claude defaulted"). This document lists only what release 2 adds to `docs/prd/asset-monitor-prd.md` (release 1, A01 to A16), or changes in it. Every release-1 requirement and acceptance criterion not changed here stays in force. Terms are defined in `GLOSSARY.md`. The design is recorded in ADR-0006 (ingress and Push webhooks), ADR-0007 (On-server agent) and ADR-0008 (PHP Lab).

## Overview

### One-line summary

Release 2 lets Asset Monitor see the files on the server behind an Asset, build Lab Proofs for PHP applications, and poll an Own repository as soon as GitHub reports a push.

### Background

Release 1 watches everything from outside: repositories through the GitHub API or SVN, and served content over HTTP. It left three gaps as non-goals:

- Judol and ClickFix usually live in files on the server. A Served-content check sees only what is served, and only to its two user agents.
- PHP Applications and Packagist Upstream repositories get Verdicts but no Lab Proof, because Node is the only Lab stack.
- A push waits for the next poll, which can be up to the Application's interval away (at least 5 minutes).

Release 2 adds:

- the On-server agent, which reports a File manifest and can carry out a Quarantine of a Malicious change after an Approval;
- a PHP Lab stack;
- Push webhooks for Own repositories;
- the ingress, which receives both kinds of inbound traffic.

### Case studies and where each is detected

| Case | What it is | Detected by |
|---|---|---|
| Dropped PHP shell | An obfuscated `eval` loader written into an uploads folder | An On-server agent report, a Server change, then a Malicious change with a static Proof. Quarantine after Approval |
| Edited theme or core file | Judol links or a ClickFix loader added to an existing file, often shown only to some visitors | A Server change on a file that is in the Baseline, whoever the content is served to |
| Packagist n-day | A remote-code-execution class flaw reached through PHP code, here in a Packagist dependency | The Upstream fix commit, Exposure from `composer.lock`, and an n-day Proof in the PHP Lab |
| Push to an Own repository | Any commit | A Push delivery makes the poll start within about 15 s |

## Changes to release-1 requirements

| Release-1 requirement | Change |
|---|---|
| A01 Applications and repositories | An Application may also have On-server agents (B04). |
| A02 Intake | An Own repository on GitHub may also be polled at once after a Push delivery (B02). Scheduled polling, ETags and the `304` rule are unchanged. |
| A03 Triage | Also covers Server changes (B06). |
| A04 Analysis and Verdicts | Also reads stored server-file bytes, staged under their SHA-256. Server files may get only the Verdicts allowed for served content (B06). |
| A06 Playbooks | Adds a Server files column (B07). |
| A07 Proofs, Labs, Detection rules and cleanup reports | PHP is a second Lab stack. Its phase one runs `composer install --no-scripts --no-plugins` in a fetch image, and its build image has no Composer (B09). Detection rules are also validated for server files. Their Baseline check covers held bytes only, and lists how many Baseline files it did not scan (B07). |
| A08 Remediation PRs | "Never writes ... to a server" gains one exception: an approved Quarantine or Restore by an On-server agent, which moves files and deletes none (B08). |
| A11 Findings | Adds the source server files. A Malicious change in server files opens a Finding. It becomes Remediated when no reported file holds bytes it names and its files are back at their Baseline state, and it returns from Remediated to Confirmed when such bytes come back (B07). |
| A12 Alerts | The source field may be an On-server agent's name. A server-files Finding that returns to Confirmed sends an Alert, as a new Finding does. A Push delivery or an agent report never sends an Alert by itself. |
| A14 Transcripts | Server-file Transcripts follow the same rules. Push webhook secrets are redacted, and the Dashboard key's private half never reaches the worker. `make backup` includes the new tables, the held bytes and the ingress keys. |
| A15 Access and display | The ingress's two listeners are also loopback-only, and only the push listener may be exposed, through a Public tunnel (B01). Approval also covers Quarantine, Restore, Watched root changes and rotating the Dashboard key. |
| A16 Demo scenarios | Extended by B10. The demo PHP storefront gains an Own repository and an On-server agent. |

## Requirements and acceptance criteria

### B01: Ingress

The ingress is two services that receive inbound machine traffic (ADR-0006).

**Services and listeners.**
- `ingress-push` serves the push listener, on `127.0.0.1:${NUMEN_PUSH_PORT:-8791}`, which answers only `POST /push/<push id>`.
- `ingress-agent` serves the agent listener, on `127.0.0.1:${NUMEN_AGENT_PORT:-8792}`, over TLS with a key that every On-server agent pins (B04). It answers only the `/agent/` routes and `GET /health`.
- The dashboard stays on `127.0.0.1` only. The Operator may point a Public tunnel at the push listener and nothing else. Each server reaches the agent listener through its own Agent tunnel (B03), which reaches nothing else on the host.

**Authentication.**
- The ingress has no cookies, sessions or CSRF. It never reads, logs or stores a `Cookie` header.
- Every request is authenticated by its signature: `X-Hub-Signature-256` for a Push delivery (B02), and the Agent key for an On-server agent (B04).
- Application code verifies every stored On-server agent request again before using it (B04).

**Limits.** These are checked before any parsing, on the bytes actually read, chunked bodies included.
- Body caps: 1 MiB for a Push delivery, 16 MiB for a File manifest, 16 MiB for one upload of files of at most 1 MiB each, and 64 KiB for anything else.
- Rate limits are never counted per client address:
  - at most 120 requests per minute on the push listener in all;
  - at most 60 Push deliveries per minute per push id;
  - at most 600 requests per minute per On-server agent;
  - at most 10 Enrollment attempts per hour per Enrollment code;
  - at most 60 requests per minute in all that name an unknown agent or Enrollment code.
- Before it reads a body, the push listener checks the push id's fixed format and looks it up in an in-memory set of known push ids, refreshed every 15 s. An unknown push id gets `404` and is recorded nowhere.
- Each ingress database role has a connection limit and a statement timeout.

**What the ingress holds.**
- Each service connects to Postgres as its own role, with grants only on its own tables (ADR-0006). The push role reads Push webhooks and records deliveries. The agent role reads agents' keys and status, Enrollment code ids, wanted lists and signed messages, and may only insert Enrollment requests and agent requests.
- `ingress-push` holds `NUMEN_INGRESS_KEY`, which decrypts Push webhook secrets and nothing else. `ingress-agent` holds the agent listener's TLS key.
- Neither holds `NUMEN_SECRET_KEY`, the broker token or any part of the Dashboard key. Neither is on the `application` or `control` network.

**Acting.** The scheduler, every 15 s, turns accepted Push deliveries into polls, and verified agent reports into wanted lists and jobs. The ingress never inserts a job, never opens a Finding, never sends an Alert, never checks an Enrollment code and never changes an agent's key or status.

**Operations.**
- `make up`, `make logs`, `make backup` and `make restore` include both ingress services.
- `make init` adds missing keys to an existing `.env` and never changes the ones already there.
- The ingress roles are created outside the migrations. The `migrate` service sets their passwords from `.env` on every start, and `restore.sh` creates them before it loads a backup. `restore.sh` refuses a backup whose environment lacks the ingress keys.

**AC-B01:**
- Every port that Compose publishes, including both ingress listeners, is bound to `127.0.0.1`.
- Neither listener serves `/api`, `/api/auth/login`, the SPA or `/assets`, and the push listener answers nothing but `POST /push/<push id>`.
- Importing `numen.ingress` does not import `numen.api`.
- Neither ingress role can read Accounts, Settings, Operators, sessions or Findings, or insert a job. The push role has no grant on agent tables, and the agent role has none on push tables and cannot change an agent's key or status.
- A body over its route's cap is refused with `413` before it is parsed, also when it is sent chunked.
- A request to an unknown push id gets `404` and makes no database query.
- A request that carries a `numen_session` cookie is treated exactly like one without it.
- No request to the ingress sends an Alert by itself.
- Migrating two schemas of one cluster to head and downgrading one leaves the roles, and the other schema's grants, in place. A backup restored into a fresh database volume brings back the grants.

### B02: Push webhooks

**Setup.**
- On an Own repository on GitHub, the Operator chooses **Set up push webhook**. Asset Monitor generates a random push id and a Push webhook secret.
- It shows, once, everything to enter in GitHub:
  - the path `/push/<push id>`, to append to the Public tunnel's URL;
  - the secret;
  - content type `application/json`;
  - "Just the push event".
- The push listener accepts the new push id within 15 s.
- The Operator registers the Push webhook in GitHub by hand.
- **Regenerate** replaces the secret at once, and **Turn off** removes the push id.
- Push webhooks are offered only for Own repositories. Upstream repositories stay polled.

**Receiving.** The push listener accepts a Push delivery only when:
- the push id is known (otherwise it answers `404` and records nothing);
- `X-GitHub-Event` is `push` or `ping`;
- `X-GitHub-Delivery` is present;
- `X-Hub-Signature-256` matches the raw body under the repository's Push webhook secret.

Then:
- A valid `push` is recorded once per delivery id, and once per body SHA-256 within 7 days. A repeat gets `200` and changes nothing.
- A valid `ping` is recorded as "ping received" and does nothing else.
- Anything else for a known push id is refused, and the repository shows the reason (wrong signature, event not accepted, body too large). A refusal reason is recorded at most once a minute per push id.
- The body is never parsed. Commit data still comes only from the GitHub API, with the read token.

**Nudging.** Within 15 s, the scheduler looks at each repository with unprocessed deliveries:
- It acts only if the repository is the enabled Own repository of at least one Application that is not archived.
- It queues a `source_check` for that repository, reusing one already queued (`domain.active_source_check`). If one is running, the deliveries wait, and the next loop queues one more check after it.
- The Repository row lock is taken wherever source checks are queued: by the scheduler, by Check now (`api.check_application`) and by a nudge.
- A nudge does not need scheduled monitoring to be on, because the Operator turned the Push webhook on for that repository.
- A nudge never touches the Application's `next_check_at`.
- The GitHub read token rule of A02 applies unchanged.

**Fallback.** Scheduled polling continues at its interval, whatever the deliveries do.

**Display.** The repository shows when the last delivery was accepted, and why the last one was refused.

**AC-B02:**
- A valid Push delivery imports the new commit through the GitHub API with no Check now, and creates the same jobs that a source check of that repository creates.
- A delivery with a wrong signature or another event type changes nothing, and the repository shows why it was refused. A delivery to an unknown push id gets `404` and is recorded nowhere.
- The same delivery id received twice queues one check, and so does the same body under a new delivery id.
- Commits listed in a payload are never imported from the payload.
- Ten deliveries that arrive while a check is queued add no check. A delivery that arrives while a check is running is followed by exactly one more check.
- With a delivery every minute, the Application's scheduled check, Advisory check and version check still run on time.
- After **Turn off** or **Regenerate**, the old push id or secret is refused at once.
- A Push webhook cannot be set up on an Upstream repository.

### B03: On-server agent build and install

**Build.**
- The On-server agent is a Go static binary (`CGO_ENABLED=0`, standard library only), built inside Docker from a digest-pinned golang image, with `GOTOOLCHAIN=local` and `GOPROXY=off`, so the build downloads nothing.
- It is built for linux/amd64 and linux/arm64, with flags that make two builds byte-identical.
- `make agent` writes both binaries and a `SHA256SUMS` file to `dist/agent/`.
- The dashboard shows the same checksums on the Enrollment screen.

**Agent tunnel.** Before installing, the Operator sets up the server's Agent tunnel. It reaches the agent listener and nothing else on the host, and it is never the Private tunnel the Operator's devices use. For example:
- an SSH forward from the server, `ssh -N -L 127.0.0.1:8792:127.0.0.1:8792 <host>`, with a key used for nothing else, whose `authorized_keys` entry on the host is `restrict,port-forwarding,permitopen="127.0.0.1:8792",command="/bin/false"`. The agent listener's URL as the server sees it is then `https://127.0.0.1:8792`;
- or a VPN peer whose ACL allows only the agent listener's port from that server.

**Install.** The Operator, as root on the server:
1. copies the binary to `/usr/local/bin/asset-monitor-agent` and checks its SHA-256;
2. runs the enroll command the dashboard showed (B04), with `--allow <path>` for each path the agent may ever watch, such as `--allow /var/www/html`, and types the Enrollment code when asked. There is no default path;
3. runs `systemctl enable --now asset-monitor-agent`;
4. confirms in the dashboard that the agent's key fingerprint matches the one the enroll command printed.

The enroll command resolves each `--allow` to its real path and refuses:
- `/`;
- any path under or containing `/etc`, `/usr`, `/boot`, `/root`, `/proc`, `/sys`, `/dev`, `/run` or `/var/lib/asset-monitor-agent`;
- any path that contains the Quarantine folder or lies inside it.

It writes the configuration and the Agent key under `/etc/asset-monitor-agent/`, owned by root with mode 0600, and installs the systemd unit. Only `enroll` and `repin` (B04) write there.

**Sandbox.** The unit runs the agent as root and:
- makes the file system read-only except the Allowed paths (`ReadWritePaths=-<path>`) and the state directory, `/var/lib/asset-monitor-agent` (`StateDirectory`, mode 0700). The state directory holds the Quarantine folder (`quarantine/`), the configuration the agent last accepted, its sequence numbers and its journal;
- sets `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` and `UMask=0077`;
- bounds capabilities to reading, moving and re-owning files;
- allows only the IPv4 and IPv6 address families, and only the agent listener's address (`IPAddressDeny=any`, with `IPAddressAllow=` the address the enroll command checked).

**Uninstall.** Documented: stop and disable the unit, then remove the binary and `/etc/asset-monitor-agent/`. The state directory, with the Quarantine folder, is kept.

**AC-B03:**
- Two builds with fresh build caches produce byte-identical binaries for both architectures, and their SHA-256 values match the published checksums.
- Both binaries are statically linked, with no interpreter and no needed libraries, and run with no files besides their configuration and state directory.
- The installed unit sets:
  - `ProtectSystem=strict`, with `ReadWritePaths` limited to the Allowed paths, and the state directory;
  - the hardening directives above and the capability bounding set;
  - `IPAddressDeny=any`, with only the agent listener's address allowed.
- The agent opens no listening socket.
- The agent refuses a Watched root outside its Allowed paths. `enroll` refuses `--allow /`, `--allow /etc`, `--allow /var` and a path inside the Quarantine folder.
- The stand-in server reaches the agent listener and cannot reach the dashboard.

### B04: Enrollment and agent authentication

**Adding an agent.**
- On an Application, the Operator adds an On-server agent with a name and the agent listener's URL as the server sees it. The URL is prefilled from `NUMEN_AGENT_URL`, which defaults to `https://127.0.0.1:8792`, the SSH forward of B03.
- The dashboard shows, once:
  - an enroll command that holds that URL, the agent listener's TLS pin (`NUMEN_AGENT_TLS_PIN`, the SHA-256 of its public key), and the Dashboard key's public half with its key id;
  - beside it, a one-time Enrollment code to type when the command asks for it.
- The code is an id plus 160 random bits, good for one use within one hour. Only the hash of its secret part is stored.

**Enrolling.**
- `enroll` reads the code at a prompt or from standard input, never from its arguments or the environment.
- It resolves the URL's host and requires every address to be loopback or private. It keeps the address it checked, and connects to it over TLS, accepting only the pinned key.
- It generates the Ed25519 Agent key. It sends the public half, the code, its Allowed paths, its version and its architecture, and prints the Agent key's fingerprint.
- The agent listener only stores the request. Within 15 s, application code checks the code, spends it, binds the key to the agent, and shows the agent as pending, with the fingerprint and the Allowed paths. A refused request, such as one with a used code, is shown on that agent's row.
- The Operator confirms in the dashboard that the fingerprint matches. Only then is the agent enrolled. The app signs its first configuration, whose Watched roots are its Allowed paths.
- While an agent is pending, its reports start nothing, and nothing is signed for it.

**Requests.**
- Every agent request is signed with the Agent key over the fixed prefix `asset-monitor-agent-request-v1`, the method, the path with its query string, the timestamp, the nonce and the body SHA-256.
- The agent listener refuses:
  - a signature that does not verify;
  - a timestamp more than 5 minutes off its clock;
  - a nonce already seen from that agent while its request's timestamp is inside that window.
- The agent listener stores each accepted request exactly as received. Before anything uses it, application code verifies it again: the signature, the timestamp against the time Postgres recorded, the nonce, the agent's status and the body SHA-256. An agent's last-seen time comes only from verified polls.
- Every report carries an agent-side sequence number that only increases, and the version of the configuration it ran under. A report whose sequence does not increase is ignored. One made under an old configuration is flagged on the agent's row.
- The agent's row shows the reason for its last refused request, such as clock skew, and the last configuration or command the agent refused.

**Commands and configuration.**
- Every Agent command, and the agent's configuration (Watched roots, report interval and poll interval), is signed with the Dashboard key.
- Each signed message carries the agent id, its type (configuration or command), a per-agent sequence number that only increases, and the key id. The agent accepts a configuration or a command only if its sequence is higher than the last one of that type it accepted, which it keeps in its state directory.
- The app signs a new configuration whenever the Watched roots, the Application's interval or its scheduled monitoring change.
- A command names its agent and expires after 15 minutes.
- The agent polls every 30 s. Only under `NUMEN_TEST_MODE` may the configuration set a shorter poll interval, down to 2 s.
- The wanted list (B05) is the one unsigned input. The agent uploads only SHA-256 values from its own latest manifest, at most 1 MiB each, and never a file on the secret list.

**The Dashboard key.**
- The app generates it. Its private half is encrypted under `NUMEN_SIGNING_KEY`, which only the app holds, and no other service signs with it.
- **Rotate Dashboard key** is an Approval. The app stops signing with the old key, and each agent shows as "pinned to old key" until `asset-monitor-agent repin --key <new key>`, run on the server as root, pins the new one. Repinning keeps the Agent key.

**Revoking.** The Operator can revoke an agent. Its key is refused from then on, its pending commands are cancelled, and its history is kept. Enrolling again needs a new code and generates a new Agent key.

**Transport.** The agent speaks only TLS to the agent listener, and accepts only the pinned key. It has no plain-http mode and needs no CA certificates.

**AC-B04:**
- An Enrollment code works once, and not after one hour. A second Enrollment with a used code fails, and is shown on the agent's row.
- The enroll command never takes the code from its arguments or the environment.
- A pending agent's reports start no job, and nothing is signed for it until the Operator confirms its fingerprint.
- The agent refuses a TLS key that does not match its pin, and an agent listener address that is not loopback or private.
- A request with a bad signature, a timestamp more than 5 minutes off, or a reused nonce is refused and changes nothing.
- Application code ignores a stored request whose signature, body hash or agent status does not verify, and a report whose sequence does not increase.
- The agent runs no command that is unsigned, signed by another key, meant for another agent, expired, or not newer than the last one it accepted. It refuses a configuration older than the one it holds.
- A revoked agent's next request is refused, and its pending commands are cancelled.
- After **Rotate Dashboard key**, nothing more is signed with the old key, and each agent shows as pinned to the old key until it is repinned.
- Only the app's environment holds `NUMEN_SIGNING_KEY`, and no ingress table or setting holds the Dashboard key's private half.

### B05: File manifests and Server changes

**Watched roots.**
- The Operator sets each agent's Watched roots in the dashboard, inside the Allowed paths the agent reported at Enrollment. Changing them is an Approval: it needs the Operator's password and records an Action.
- The agent walks them and reports at the Application's interval when scheduled monitoring is on. It also reports whenever the Operator clicks **Check now** on the agent, which sends a rescan command.

**Reports.**
- A report is a File manifest. The agent never follows symbolic links; it records each one with its target. It skips devices, sockets and pipes.
- Paths are checked by the agent listener and again by application code: relative, normalized, with no NUL, at most 4,096 bytes, and inside a Watched root of the configuration the report ran under. A report with any other path is refused. The agent leaves out a longer path and marks the walk as cut short.
- A manifest is never truncated. Over 50,000 files, the agent sends a signed over-limit report instead. A file over 512 MiB is reported by size and modification time only. A walk that passes its 4-minute deadline is reported as cut short. Each of these is recorded as an incomplete Server change, and the agent's row shows why.

**Evidence.**
- Within 15 s of a verified report, application code answers it with a wanted list: the SHA-256 values whose bytes the dashboard wants and does not yet hold, each at most 1 MiB. They include the files of the Baseline, or of a first manifest, which a Detection rule's Baseline check needs (B07), as well as added and changed files.
- Web-executable files (`.php`, `.phtml`, `.phar`, `.htaccess`, `.user.ini`, `.js`) come first, then smaller files before larger ones.
- Held bytes are budgeted per agent and per change: at most 128 MiB for the Baseline's files, so the 64 MiB of new bytes that each Server change may hold is always free.
- The agent sends the wanted files in uploads of up to 16 MiB. The agent listener refuses bytes that do not hash to their SHA-256, and the worker hashes them again before it holds them.
- A report is complete when the agent says so, or 10 minutes after it arrived. Uploads after that are refused, and their bytes are asked for again with the next report.
- The worker moves the bytes into artifact storage, keyed by SHA-256.
- Held bytes that nothing references any more stop counting, and are removed when a Server change is judged or a new Baseline is accepted. They are referenced by the current Baseline, a first manifest waiting to be accepted, a Server change not yet judged, or a Finding.

**Secret files.** The agent and the dashboard never upload or ask for the bytes of:
- anything under a folder named `.ssh`, `.gnupg`, `.aws`, `.composer`, `.config` or `.git`;
- files named `.env*`, `wp-config*`, `id_*` (but not `*.pub`), `authorized_keys`, `.htpasswd`, `auth.json`, `.git-credentials`, `.netrc`, `.my.cnf`, `.pgpass`, `.npmrc`, `*_history`, `*.sql*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.kdbx`, `*.sqlite` and `*.db`;
- the CMS configuration files `configuration.php`, `LocalSettings.php`, `sites/*/settings.php` and `app/etc/env.php`.

Both read the list from code. Such files are reported by hash only.

**Pre-filter.** It flags a Server change as sensitive when the change adds or changes a web-executable file (`.php`, `.phtml`, `.phar`, `.phps`, `.htaccess`, `.user.ini`) or a file on the secret list. The dashboard marks each such file. A secret-named file with a web-executable extension, or outside both its Watched root's top level and the CMS locations above, is also shown as suspicious.

**Baseline.**
- The Operator must accept the first File manifest before it becomes the Baseline.
- After that, accepting a Baseline names one Server change, and the Baseline becomes exactly the manifest of the report that change came from. The request carries that manifest's SHA-256, and is refused if it differs.
- The A10 rules apply: a Server change can become the Baseline after an Unrelated or Security hardening Verdict, after a Triage decline, or after a Review queue dismissal (release-1 decision 14).
- A change the Pre-filter flags cannot become the Baseline after a Triage decline alone. It needs an Unrelated or Security hardening Verdict, or the Operator's dismissal from the Review queue.
- A Malicious change can never become the Baseline.
- Accepting a Baseline is not an Approval.

**Server changes.**
- A Server change is the difference between a manifest and the Baseline, by path, SHA-256, mode and owner. For a file over 512 MiB, its size and modification time stand in for the SHA-256. A change to the modification time alone is not a Server change.
- Each distinct Server change per agent is triaged at most once.
- A Server change is incomplete when:
  - the bytes of any added or changed file are not held: too large, over the budget, on the secret list, gone before upload, or uploaded too late;
  - its new bytes pass 64 MiB;
  - its report was over the file limit, had a file over 512 MiB, or was cut short.

  An incomplete Server change can never get an Unrelated Verdict.

**Silence.** An agent with no verified poll for 5 minutes is shown as silent. No Alert is sent.

**AC-B05:**
- The first report starts no Triage run until the Operator accepts it as the Baseline.
- Adding a file, changing its bytes, mode or owner, or removing it produces a Server change. Changing only its modification time does not.
- Ten reports of the same Server change start one Triage run.
- An upload whose bytes do not hash to the requested SHA-256 is refused.
- `wp-config.php`, `.env` and files under `.git/` or `.ssh/` are reported by hash only, and a change to any of them gives an incomplete Server change.
- A symbolic link that points outside its Watched root is reported with its target and never followed.
- A manifest over 50,000 files, a file over 512 MiB, or a walk past its deadline gives an incomplete Server change, never a truncated one.
- A report with a path that is absolute, not normalized, holds a NUL, or lies outside its Watched roots is refused.
- Accepting a Baseline with a stale manifest SHA-256 is refused. A flagged Server change that only Triage declined cannot be accepted.
- After a first report larger than the Baseline budget, a later Server change still has room for its bytes.
- Bytes that nothing references are released. Held bytes and Server changes survive a backup and restore.

### B06: Triage and Analysis of server files

**Triage.**
- Triage of a Server change is the A03 run with no tools and a 120 s deadline.
- Its facts are the added, changed and removed entries with their metadata and Pre-filter flags, a text diff of the held bytes cut to 100,000 characters, and whether the change is incomplete.
- A cut diff makes the Triage incomplete, as in A02.

**Analysis.**
- Analysis reads stored bytes only: the new bytes of the added and changed files, their previous and Baseline versions where held, and `server-files.json`.
- The bytes are staged under their SHA-256 (`source/changed/<sha256>`, and the same under `previous/` and `baseline/`). Server paths appear only as data in `server-files.json`, so no path an attacker chose names a staged file.
- It never executes any of them, and it has no network target.
- It may return only Malicious change, Security hardening, Unrelated or Insufficient context.
- It counts against the A04 caps, and Insufficient context sends the change to the Review queue.

**AC-B06:**
- A server-file Analysis that returns Vulnerability fix is rejected as failed.
- No job executes uploaded bytes.
- An incomplete Server change never stands as Unrelated.
- A Server change whose path is over 240 characters or holds a backslash is triaged and analysed like any other.
- At a cap, new automatic server-file Analyses wait, and a manual one still works.

### B07: Server-file Playbook and Findings

| Verdict | Server files |
|---|---|
| Vulnerability introduced | Not allowed |
| Malicious change | Static Proof, Detection rule, cleanup report, and Quarantine after Approval. No Remediation PR and no Lab |
| Vulnerability fix | Not allowed |
| Security hardening | Record only. The Operator may accept that change's manifest as the Baseline (B05) |
| Unrelated | Stop. The Operator may accept that change's manifest as the Baseline (B05) |
| Insufficient context | Review queue |

**Detection rule.** Application code validates it with yara in the `detection_rule` job, which has no network. The rule must:
- match at least one added or changed file of the Server change;
- match no held previous version of those files, a check that is skipped when the previous report is the Baseline;
- match no held Baseline file. This check covers held bytes only, and its result lists how many Baseline files were not scanned.

A rule that fails leaves the artifacts in Draft and the lifecycle state unchanged, as in A07.

**Cleanup report.** Analysis drafts it, and application code checks it. It lists:
- the files and indicators the change added, with their paths and the agent;
- when the change was first reported;
- the secrets the payload could reach, which must be rotated;
- the Detection rule.

It also warns that quarantining a file that is in the Baseline takes the site's copy of it offline, so the Operator must deploy a clean copy.

**Finding.**
- The source is server files.
- The Alert's source field is the agent's name, never a file path.
- The Finding names files, each by path and SHA-256: those the validated Detection rule matched, and any the Operator adds to an approved Quarantine (B08).
- A later manifest entry, in any Watched root, whose SHA-256 the Finding names is linked to the Finding without a Triage run. A renamed copy of a file therefore stays on the Finding.
- The Finding becomes Remediated when a later report has no entry with a SHA-256 the Finding names, and shows each of the Finding's files back at its state in the Baseline its Server change was judged against (absent, if that Baseline did not have it). The Operator can also mark it.
- A later report that again holds a SHA-256 the Finding names moves a Remediated Finding back to Confirmed. The Finding is shown as regressed and sends an Alert, as a new Finding does.

**AC-B07:**
- A fixture dropped PHP shell ends with a validated Detection rule, a cleanup report and a Confirmed Finding, and nothing ever runs the shell.
- A rule that also matches a Baseline file fails validation, leaves the artifacts in Draft and leaves the lifecycle state unchanged. The check result counts the Baseline files it did not scan.
- A later report without the dropped file remediates the Finding. A report that differs only somewhere else does not, and neither does one that holds the same bytes under another path.
- A report that brings back a file the Finding names after it was Remediated makes the Finding Confirmed again, shown as regressed, with an Alert.
- The Finding offers no Lab and no Remediation PR.
- Its Alert names the agent and carries no file path or file bytes.

### B08: Quarantine and Restore

**Quarantine.**
- The Quarantine list is every entry of the agent's latest manifest whose SHA-256 the Finding names, each with its path and SHA-256.
- The Operator may also tick other added or changed files of the Finding's Server change, by path and SHA-256. So a change whose bytes are not all held, or whose Detection rule could not be validated, can still be quarantined.
- The Approval request carries the Operator's password and the list's SHA-256. It is refused if the list has changed.
- The app then signs a Quarantine command with the Dashboard key, under the idempotency key (Application, Finding, list SHA-256, attempt). The attempt goes up only after the previous command for that list expired, was cancelled or finished. A double submit therefore sends one command, while a re-approval after expiry, or a second Quarantine after a Restore, sends a new one.
- For each file, the agent:
  1. refuses the path if any of its components below the Watched root is a symbolic link;
  2. opens the parent directory once, and does every later step through that handle;
  3. renames the file aside, to a name with no executable extension;
  4. opens it without following links, checks that it is a regular file, and copies it from that open descriptor into a file it creates exclusively in the Quarantine folder, with mode 0600. It keeps the original path, mode, owner and modification time as metadata only;
  5. checks the copy's SHA-256, then removes the aside name. If the hash does not match, it discards its copy and puts the file back without replacing anything. If the original path has been taken meanwhile, the file stays under its aside name and is reported as failed.
- A journal in the state directory lets a restarted agent finish or undo a step it had begun.
- The agent reports each file as quarantined, not present, hash mismatch, link refused or failed, then rescans.

**Restore.**
- The Operator can approve a Restore of quarantined files. The Approval carries the password and the SHA-256 of the file list.
- When the files are ones a Confirmed or Remediated Finding names, the dialog says that restoring them puts that Finding's payload back on the server. The regression rule of B07 then applies.
- The command names only quarantine entries. The agent takes each destination from its own record. It refuses one that no longer lies inside an Allowed path and a Watched root of its current configuration, or whose path has a symbolic link component.
- It creates the file exclusively at its original path, copies the bytes back and checks their SHA-256. It sets the owner, the mode without setuid or setgid, and the modification time on the open descriptor, then removes the quarantined copy.
- It reports each file as restored, path taken or failed.
- The idempotency key is (Application, Finding, Quarantine command, file list SHA-256, attempt), with the same attempt rule.

**Neither one:**
- deletes a file's bytes;
- changes a Finding's lifecycle state. The Finding shows each result.

A command that expires before the agent runs it shows as expired, and the Operator can approve it again, which sends a new command.

**AC-B08:**
- A Quarantine with a missing or wrong password, or with a stale list SHA-256, is refused and sends no command.
- Approving twice sends one command, and the agent runs it once. Re-approving after the command expired sends a new one, and so does a Quarantine after a Restore.
- A file whose bytes changed after the Finding is not moved, and is reported as a hash mismatch.
- A path with a symbolic link component is not moved, and neither is a file swapped for a link after it was renamed aside.
- A ticked file whose bytes are not held can be quarantined.
- After a Quarantine, the file's bytes are in the Quarantine folder with mode 0600 and its metadata kept, and its path is gone from the next report.
- A Restore puts the file back with its owner, its mode without setuid or setgid, and its modification time. It is refused when the path is taken, and never re-owns or changes the mode of another file through a link.
- An agent stopped between the copy and the removal finishes or undoes the step when it restarts.
- No Agent command deletes a file's bytes.

### B09: PHP Lab

**Stack.**
- PHP is a second Lab stack (ADR-0008). Its base, `asset-monitor-lab-php:0.1.0`, comes from a digest-pinned PHP 8.4 CLI image, with no Composer and no git.
- Phase one runs in `asset-monitor-lab-php-fetch:0.1.0`: that base plus Composer, pinned by version and SHA-256, and unzip.
- A bundle's Dockerfile chooses the stack with its `FROM` line:
  - `asset-monitor-lab:0.1.0` is Node, and needs `vulnerable-app/package.json`;
  - `asset-monitor-lab-php:0.1.0` is PHP, and needs `vulnerable-app/composer.json`;
  - the fetch image can never be named.

**Phase one.**
- It runs `composer install --no-scripts --no-plugins --no-interaction --prefer-dist --no-progress` with the audit off and no model credential.
- Its egress goes through the gateway to the Composer hosts only: `repo.packagist.org`, `api.github.com` and `codeload.github.com`.
- It returns `vendor/` only, with its generated autoloader.

**Phase two.**
- The build runs with `--network none`, from the base that has no Composer.
- A PHP-stack Dockerfile may not contain `RUN`, and is refused before Approval with a message that says so.
- The app runs under `php -S 0.0.0.0:8080` on the internal Lab network.
- The PoC runs as for Node.

**Limits.** A07's Lab limits and cleanup apply unchanged.

**Refused apps.** A bundle whose vulnerable app needs a database server is refused before Approval with a clear message: WordPress core (`wp-settings.php`), or a `composer.json` that requires `ext-mysqli`, `ext-pdo_mysql`, `ext-pgsql` or `ext-pdo_pgsql`. For an Own-head Proof, the check reads the Own repository's `composer.json` and file list from its stored snapshot. Apps that use SQLite run.

**Upstream Proofs for Packagist packages.** They follow A07's vulnerable-app rules: the Own repository's head with the Locked version installed, or a minimal app that pins it.
- Application code copies the Locked version from the watched Upstream repository's tree, at the commit `composer.lock` names or at the Locked version's tag, under `vulnerable-app/.asset-monitor/<vendor>/<name>/`.
- It points Composer at that folder as a path dist: in the lock for an Own head, or through a path repository in the `composer.json` it writes for a minimal app (ADR-0008).
- A package whose source is not a watched GitHub repository is refused with `package_untrusted`.

**AC-B09:**
- A PHP Lab runs no Composer plugin, root or dependency script, or dependency autoload file, either in phase one or in the build. The build image has no Composer.
- A PHP Lab run cannot reach any network.
- A fixture PHP vulnerability reproduces after Approval, and a fixture that does not reproduce shows not reproduced.
- A Dockerfile that names both bases, names the fetch image, or holds a `RUN` on the PHP stack is refused before Approval.
- A WordPress bundle, and an Own head whose `composer.json` requires `ext-pdo_mysql`, are refused before Approval with the database-server message.
- A PHP Lab over a limit fails visibly and leaves no image behind.
- An Upstream Proof for a Packagist package installs the Locked version from the vendored folder with no Composer host reachable, and a package with no watched GitHub source is refused.
- Node Labs behave exactly as in release 1.

### B10: Demo scenarios

B10 extends A16 and `docs/demo.md`.

**The demo PHP storefront** gains:
- an Own repository, `asset-monitor-demo/toko-batik`: a small stand-in PHP app whose `composer.lock` locks the stand-in Packagist package `asset-monitor-demo/templar` 1.4.0;
- the Upstream repository derived from that lock;
- an On-server agent, enrolled by the seed in a stand-in server container, watching its stand-in web root.

**New steps,** each started with `make demo-step STEP=<name>`. They run after `php-clean`, in this order:

1. **`push`.**
   - The step sets up a Push webhook on the demo Node Application's Own repository, `asset-monitor-demo/shop`, and registers it in the GitHub stand-in, as the Operator would in GitHub.
   - It then pushes a harmless commit and does not run Check now. The stand-in sends a signed Push delivery, and the commit is imported.
   - A redelivery of the same delivery is deduplicated, and a forged delivery is refused.
2. **`php-lab`.**
   - The step runs a Backfill on the templar stand-in that reaches its fix commit. The result is a Vulnerability fix, exposed at 1.4.0, with an n-day Proof drafted.
   - After **Start Lab** and the Operator's Approval, the PHP Lab builds the Own repository's head with 1.4.0 vendored. The PoC sees the stand-in's marker, `asset-monitor-simulated-flaw`.
3. **`server-inject`.**
   - The stand-in server's web root gains a stand-in dropped shell. If it were ever run, it would only print `asset-monitor-fixture`.
   - The step clicks Check now on the agent. The Server change gets a Malicious change Verdict, and a Finding is Confirmed by its Detection rule.
   - After the Operator approves the Quarantine, the agent moves the file away, and the next report remediates the Finding.

**Stand-ins.** Every stand-in is harmless and local. The templar stand-in's flaw only returns the marker and never evaluates anything. No step sends traffic to a real repository, registry, server or GitHub.

**AC-B10:**
- On a fresh VM, the extended scenario runs from `make demo-up` to its last step with no manual database edits.
- `make test-demo` passes, both with no model keys and with canned model agent decisions. It makes no paid model request and sends nothing to any host outside the project.
- The demo scripts give no Approval: no Lab, Remediation PR, Quarantine, Restore, Watched root change or Dashboard key rotation.

## Non-goals for release 2

Release 1's non-goals that release 2 does not deliver stay in force, plus:

- A GitHub App for Remediation PRs. It stays a later item.
- Push webhooks for Upstream repositories.
- Lab Proofs for apps that need a database server, such as WordPress with MySQL.
- On-server agents on Windows or macOS, or on servers without systemd.
- Updating the agent, or changing its Allowed paths, from the dashboard.
- Deleting files on a server, or any Agent command beyond rescan, Quarantine and Restore.
- Excluding paths inside a Watched root.
- Sweeping held server-file bytes with an Upstream Malicious change's Detection rule. The sweep stays served content only.
- An Alert for a silent On-server agent.

## Decisions the Operator made

Made on 2026-11-15. They are binding for release 2.

1. **Scope:** the On-server agent, a PHP Lab, and Push webhooks. A GitHub App for Remediation PRs, Discord buttons or a bot, Multiple Operators, and sending Disclosure reports stay out.
2. **On-server agent build:** a Go static binary (`CGO_ENABLED=0`) for Linux, running as root. It is built inside Docker from a digest-pinned golang image, for linux/amd64 and linux/arm64, with published SHA-256 checksums.
3. **On-server agent connections:** the agent dials out. It sends signed reports to the dashboard through the private tunnel the Operator runs, and polls the dashboard for approved commands. Nothing listens on the server.
4. **On-server agent actions:** the only action on a Malicious change is a Quarantine after an Approval. It moves only the files whose SHA-256 matches the Finding into a Quarantine folder outside the web root, so the Operator can restore them. It never deletes.
5. **Restore of a Confirmed Finding's files:** allowed after an Approval, with a warning, as in defaulted decision 40. The release-1 Finding lifecycle stays unchanged.
6. **Agent tunnels:** one restricted Agent tunnel per server, reaching only the agent port, as in defaulted decision 22. Servers never join the tunnel the Operator's own devices use.

## Decisions Claude defaulted

Claude set 1 to 11 on 2026-11-15. The rest were set while these documents were written and reviewed. Each one can be changed by editing this section, the ADRs and the plan.

1. **Enrollment:** a one-time Enrollment code, shown once in the dashboard. The agent generates its own Ed25519 Agent key and registers the public half.
2. **Signed requests:** every agent request is signed over the method, path, timestamp, nonce and body hash, within a replay window.
3. **Signed commands:** every Agent command is signed with a Dashboard key that the agent pins at Enrollment, so a tunnel compromise cannot forge commands. Agents can be revoked.
4. **Command set:** fixed in code: rescan, Quarantine and Restore. No shell, and no code from the dashboard.
5. **Reports:** a File manifest (path, SHA-256, size, mode, owner, mtime) of the Watched roots, which are set per agent in the dashboard. The bytes of changed files are uploaded as evidence, up to a size limit. The bytes of Baseline files are uploaded too, because a Detection rule's Baseline check needs them (B05, decision 23).
6. **Judging server files:** reports are compared against a Baseline the Operator accepts. Each distinct Server change is triaged once. Analysis reads stored bytes only and never executes them. Server files are a new Finding source.
7. **Server-file Playbook:** in the served-content style. A static Proof with a Detection rule validated on the uploaded bytes, which must match the changed files and nothing in the Baseline or previous versions; a cleanup report; and a Quarantine after Approval instead of a Remediation PR. A Restore also needs an Approval.
8. **Agent service:** a systemd service running as root, read-only everywhere except the Allowed paths, which hold every Watched root, and the state directory, which holds the Quarantine folder (decision 18). Its binary and configuration are owned by root. Watched roots change from the dashboard, and the sandboxed unit cannot rewrite its own `ReadWritePaths`, so the unit grants the Allowed paths rather than the Watched roots. yara is not in the agent; Detection rules run in the dashboard's network-less `detection_rule` job.
9. **Ingress:** the dashboard UI and API stay on `127.0.0.1` only. A separate ingress handles inbound traffic only, on its own loopback listeners: one for Push deliveries, the only part meant to be reachable from GitHub, through a Public tunnel pointed at that port only; and one for On-server agents, through the private tunnel the Operator runs for each server (decision 22). No cookies, sessions or CSRF on the ingress. Every request is authenticated by its signature, with strict size and rate limits.
10. **Push webhooks:** for Own repositories only. The Operator registers each one in GitHub by hand, with a per-repository secret generated by Asset Monitor. The ingress verifies `X-Hub-Signature-256` and the event type. A valid push only nudges the existing poller, like Check now: commit data still comes from the GitHub API. Duplicates are dropped by delivery id, and polling continues at its interval as a fallback.
11. **PHP Lab:** a second Lab stack from a digest-pinned PHP CLI image, with Composer pinned by version and checksum.
    - Phase one runs `composer install` with `--no-scripts` and `--no-plugins` and no model credential, with egress only to the Composer hosts it needs, through the gateway.
    - Phase two builds with no network and runs the app under PHP's built-in web server.
    - ADR-0005's limits and cleanup apply.
    - Apps that need a database server are refused.
    - Packagist Upstream Proofs follow the existing vulnerable-app rules.
12. **Ingress isolation:**
    - The ingress is two Compose services from the app image, `ingress-push` and `ingress-agent`, each running `numen.ingress` as its own process, with its own database role and its own internal network to `db`. Neither imports `numen.api`.
    - The push role reads `push_webhooks`, updates only its two status columns, and inserts into `push_deliveries`. Only `ingress-push`, the app and the worker hold `NUMEN_INGRESS_KEY`.
    - The agent role reads agents' keys and status, Enrollment code ids, wanted lists and signed messages, and may only insert Enrollment requests and agent requests. It cannot change an agent's key or status, and cannot read held bytes.
    - Neither role can read Accounts, Settings, Operators, sessions or Findings, or insert a job.
    - Application code verifies every stored agent request again, hashes uploaded bytes again, and alone checks Enrollment codes and binds Agent keys.
    - The scheduler, not the ingress, turns accepted traffic into jobs, so a compromised ingress cannot skip an Approval.
    - Roles are created outside the migrations: migrations create a missing role `NOLOGIN` and never drop it, the `migrate` service sets passwords on every start, and `restore.sh` creates the roles before loading a backup.
13. **Ports:** push listener `127.0.0.1:8791`, agent listener `127.0.0.1:8792`. The test and demo projects use their own host ports.
14. **Push URL:** `/push/<push id>`, with a random push id per repository. The path identifies the repository, so the ingress never parses the body. `ping` is accepted and does nothing.
15. **Push limits:**
    - A 1 MiB body, counted on the bytes read. A larger delivery gets `413`, and the next scheduled poll or Check now catches up.
    - 60 deliveries per minute per push id, and 120 requests per minute on the push listener in all.
    - The push id's format and an in-memory set of known push ids, refreshed every 15 s, are checked before the body is read. An unknown push id gets `404` and is recorded nowhere.
    - A refusal reason is recorded at most once a minute per push id.
    - Deduplication by delivery id, and by the raw body's SHA-256 for 7 days.
16. **Nudge rule:**
    - A nudge applies to the enabled Own repository of an Application that is not archived. Like Check now, it ignores whether scheduled monitoring is on.
    - It queues a `source_check` for that repository, reusing a queued one, and never touches the Application's `next_check_at`.
    - The Repository row lock is taken wherever source checks are queued (the scheduler, `check_application` and the nudge), so the three can never queue two checks.
17. **Push webhook secret:** shown once. Regenerate replaces it, and Turn off removes the push id.
18. **Allowed paths:**
    - Given with `--allow` at install, with no default; `/var/www/html` is the documented example. The enroll command resolves each to its real path.
    - It refuses `/`, any path under or containing `/etc`, `/usr`, `/boot`, `/root`, `/proc`, `/sys`, `/dev`, `/run` or the state directory, and any path that contains the Quarantine folder or lies inside it. The agent refuses such a Watched root too.
    - The agent reports them at Enrollment, and Watched roots must lie inside them.
    - The unit grants write access only there (`ReadWritePaths=-<path>`) and to the state directory, `/var/lib/asset-monitor-agent` (mode 0700), which holds the Quarantine folder `quarantine/`.
19. **Enrollment details:**
    - The Enrollment code is an id plus 160 random bits, good for one use within one hour, with the secret part stored hashed. It is typed at a prompt, never given on the command line or in the environment.
    - The enroll command carries the agent listener's URL and TLS pin and the Dashboard key's public half with its key id.
    - Application code, not the ingress, checks the code. The agent stays pending, with nothing processed or signed for it, until the Operator confirms its key's fingerprint.
    - Its first Watched roots are its Allowed paths.
20. **Timing:**
    - Replay window: 5 minutes. A nonce is kept until its request's timestamp leaves the window.
    - Commands expire after 15 minutes.
    - The agent polls every 30 s. Only test mode may set a shorter poll interval, down to 2 s.
    - It reports at the Application's interval only when scheduled monitoring is on, and on Check now. A walk has a 4-minute deadline.
    - An agent is shown as silent after 5 minutes without a verified poll.
21. **Signed messages:**
    - The configuration (Watched roots, report interval and poll interval) is signed with the Dashboard key too, and re-signed whenever the Watched roots, the Application's interval or its monitoring change.
    - Every message signed with the Dashboard key carries the agent id, its type, a per-agent sequence number that only increases, and the key id. The agent keeps the highest sequence of each type in its state directory and accepts only higher ones.
    - Every report carries its own increasing sequence number and its configuration version.
    - The request signature covers a fixed `asset-monitor-agent-request-v1` prefix and the path with its query string.
22. **Transport:**
    - Each server reaches the agent listener through its own Agent tunnel, the private tunnel of decision 3 for that server, which may reach that port and nothing else: for example an SSH key restricted with `permitopen`, or a VPN ACL. The Operator's device tunnel is never used.
    - The agent listener serves TLS with a key from `make init`. The agent accepts only that key's pin, and has no plain-http mode.
    - The enroll command resolves the URL's host, requires loopback or private addresses, and the unit allows only the address it checked.
23. **Evidence limits:**
    - 1 MiB per file; 128 MiB of held Baseline bytes per agent; 64 MiB of new bytes per Server change. These keep a Detection rule's trees, which are drawn from the held bytes, near the runner's 256 MB input ceiling. A run that would pass it fails visibly and leaves the artifacts in Draft.
    - 50,000 files per manifest, and a hashing limit of 512 MiB per file. Over either, or past the walk deadline, the change is incomplete, and a manifest is never truncated.
    - Uploads of up to 16 MiB, web-executable and smaller files first. Uploads after the 10-minute cut-off are refused and asked for again with the next report.
    - Files beyond a limit are reported by hash only, or by size and modification time over the hashing limit, and make the change incomplete.
    - Held bytes that no current Baseline, first manifest awaiting acceptance, unjudged Server change or Finding references stop counting, and are removed.
    - The agent listener stores uploaded bytes only inside the requests it stores. The worker hashes them again and moves them into artifact storage.
24. **Secret files:** fixed in code, in both the agent and the dashboard (B05): folders such as `.ssh` and `.git`, secret file names, and CMS configuration files. Their bytes are never uploaded, so they never reach a model provider. The Pre-filter flags any change to them.
25. **Server change identity:** the path, SHA-256, mode and owner of each difference from the Baseline, without mtime (size and mtime over the hashing limit). Symbolic links are recorded with their target and never followed.
26. **Quarantine list:** every entry of the agent's latest manifest whose SHA-256 the Finding names, plus files of the Server change that the Operator ticks. Its Approval carries the list's SHA-256, as a Remediation PR's Approval carries the diff's.
27. **Quarantine mechanics:**
    - Paths with a symbolic link component are refused, and every step goes through one handle on the parent directory.
    - The file is renamed aside to a name with no executable extension, then copied from its open descriptor into an exclusively created 0600 file in the 0700 Quarantine folder, and the copy is verified before the aside name is removed.
    - Putting back and Restore never replace a file. Owner and mode are set on the open descriptor, without setuid or setgid.
    - A Restore names only quarantine entries, and the agent takes the destination from its own record.
    - A journal in the state directory lets a restart finish or undo a step.
28. **Remediation:** a server-files Finding is Remediated when a later report has no entry with a SHA-256 the Finding names and each of its files is back at its state in the Baseline the change was judged against, or when the Operator marks it. A named SHA-256 seen again in any Watched root links that entry to the Finding without Triage, and moves a Remediated Finding back to Confirmed with an Alert. A Quarantine or a Restore changes no lifecycle state by itself.
29. **Alerts:** the source field is the agent's name, never a file path. A silent agent sends no Alert. A regressed server-files Finding sends an Alert, as a new one does.
30. **Agent build:** Go 1.25 or later, for `os.Root`. Standard library only, with `GOTOOLCHAIN=local`, `GOPROXY=off` and `GOFLAGS=-mod=readonly`, from one build script, so builds and tests download nothing. The checksums are copied into the app image so the dashboard can show them.
31. **PHP Lab images:**
    - The base, PHP 8.4 CLI on Debian bookworm, has no Composer and no git. A separate fetch image adds Composer and unzip, for phase one only.
    - A PHP-stack Dockerfile holds no `RUN`.
    - The stack is chosen by the base image the Dockerfile names.
32. **Composer hosts:** a broker setting that defaults to `repo.packagist.org`, `api.github.com` and `codeload.github.com`. Every test and demo overlay sets it to `registry.invalid`.
33. **Database-server refusal:** WordPress core (`wp-settings.php`), or a `composer.json` that requires a MySQL or PostgreSQL extension, read from the Own repository's snapshot for an Own-head Proof. SQLite is allowed.
34. **Packagist vendoring:** the Locked version is copied from the watched Upstream repository's tree at the commit `composer.lock` names. Packagist publishes no byte-stable integrity hash for GitHub dists, so the commit SHA is the pin. Composer reaches it as a path dist with symlinks off (ADR-0008).
35. **Demo:**
    - The PHP storefront gains an Own repository and an On-server agent, which keeps the PHP features in one Application.
    - The Push webhook is set up on `asset-monitor-demo/shop` in its own `push` step, not in the seed, so no earlier step's Check now races a delivery. The new steps run after `php-clean`: `push`, `php-lab`, then `server-inject`.
36. **Dashboard key custody:** its private half is encrypted under `NUMEN_SIGNING_KEY`, which only the app holds, so the worker, which handles attacker-written bytes, never has it. Rotating it is an Approval, and `asset-monitor-agent repin` pins the new key on each server.
37. **Command idempotency:** a Quarantine is keyed on (Application, Finding, list SHA-256, attempt), and a Restore on (Application, Finding, Quarantine command, file list SHA-256, attempt). The attempt goes up only after the previous command expired, was cancelled or finished.
38. **Server-file Baselines:** accepting a later Baseline names one Server change and carries its manifest's SHA-256. A Pre-filter-flagged change needs an Unrelated or Security hardening Verdict, or a Review queue dismissal; a Triage decline alone is not enough.
39. **Watched root changes are Approvals.** The report interval and scheduled monitoring stay ordinary Application settings, as in release 1, and only re-sign the configuration.
40. **Restore of a named file:** allowed for any quarantined file, with a warning when a Confirmed or Remediated Finding names it. The regression rule of decision 28 then applies.

## Risks

- **A root process on the server.** A bug in the agent's file handling runs as root. The systemd sandbox, `os.Root`, descriptor-based moves that refuse links, and the fixed command set limit what it can reach.
- **A compromised server** can stop its agent or report false manifests. A silent agent shows in the dashboard, but sends no Alert.
- **Agent tunnels.** Each server's tunnel must reach the agent listener and nothing else. A tunnel that also reaches the dashboard port gives every user on that server the dashboard's login and Approvals.
- **Server bytes reach model providers.** The bytes uploaded for Analysis go to the Analysis provider, and the secret list is a heuristic. A secret kept in an ordinary file, such as a PHP config file with another name, would be sent.
- **Quarantining a modified Baseline file** takes the site's copy offline until the Operator deploys a clean one, and the Finding stays unremediated until then.
- **A wrong Malicious change Verdict** cannot become the Baseline, as in served content. The way out is a manual Analysis. Restoring its files puts them back, and the Finding regresses if it was Remediated.
- **The push listener is public.** Its exposure depends on the Operator pointing the Public tunnel at that port only. A leaked push id lets anyone use up that push id's rate limit, so real deliveries are refused until the next scheduled poll. Extra polls need the secret.
- **Replayed deliveries.** A captured delivery replayed under a new delivery id is dropped for 7 days by its body hash. After that, it costs one more poll.
- **Clocks.** The agent needs a synchronised clock. More than 5 minutes of skew refuses every request.
- **Composer details** (flags, the audit, the path-dist lock form) come from upstream Composer, not from this repository. A runtime test checks them against the pinned version.
- **PHP egress.** Phase one reaches GitHub's code hosts without a credential, so rate limits can fail a fetch.
- **Architectures.** Only the host's architecture is run in tests. The other binary is checked by its checksum and static linking only.
- **Latency.** Up to 15 s pass between a delivery or a report and the job it causes, and up to 45 s before a report's wanted list reaches the agent.

## References

- `docs/prd/asset-monitor-prd.md` (release 1), ADR-0004, ADR-0005, ADR-0006, ADR-0007 and ADR-0008
- `backend/numen/api.py` (`create_app`, `auth`, `throttle`, `approval`, `check_application`, `create_finding`, `validate_finding_refs`), `backend/numen/security.py` (`RequestLimits`, `Vault`), `backend/numen/domain.py` (`schedule`, `active_source_check`, `enqueue`, `record_served_change`, `baseline_allowed`, `open_finding`, `PLAYBOOKS`, `finding_cell`, `FINDING_TRANSITIONS`), `backend/numen/workflows.py` (`execute`, `source_check`, `served_check`, `detection_rule`)
- `runner/numen_runner/engine.py` (`build_lab`, `fetch_dependencies`, `gateway_config`, `validate_dockerfile`), `runner/numen_runner/contracts.py` (`safe_path`)
- `scripts/restore.sh`, `scripts/test-backend.sh`, `backend/tests/test_postgres.py`
- GitHub webhook documentation (`X-Hub-Signature-256`, `X-GitHub-Delivery`, redelivery, the `ping` event)
- Go `os.Root`, `crypto/ed25519`, `crypto/tls`; systemd.exec (`ProtectSystem`, `ReadWritePaths`, `StateDirectory`, `CapabilityBoundingSet`, `SystemCallFilter`), systemd.resource-control (`IPAddressDeny`); OpenSSH `authorized_keys` options (`restrict`, `permitopen`)
- Composer CLI documentation (`--no-scripts`, `--no-plugins`, `allow-plugins`, path repositories)
