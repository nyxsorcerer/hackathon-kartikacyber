# ADR-0007: An On-server agent that dials out, reports files, and acts only by Quarantine after Approval

## Status

Accepted, 2026-11-15. Amends A08 ("never writes to an Upstream repository or to a server") and the release-1 plan's "Later" item, which would let the agent remove a Malicious change. Extends ADR-0004 to a component on the Operator's server. Implemented by B03 to B08 in `docs/prd/asset-monitor-r2-prd.md`. Its traffic arrives through the agent listener of ADR-0006.

## Context and decision point

Judol and ClickFix usually live in files on the server: a dropped PHP shell, an edited theme file, an injected loader tag. A Served-content check sees only what the server sends, to two user agents, from outside. The Operator wants a program on the server that reports file changes and can take a Malicious change out of service.

That program needs root to read every file under a web root. It runs on the machine an attacker targets, it is a channel from the dashboard into the server, and every file and directory it reads may have been written by someone hostile, who can also rename or swap them while it works. Four questions follow:

- How is it built and installed?
- Which way do connections go?
- How does each end know the other?
- What may it change on the server?

## Decision

1. **A Go static binary.**
   - It is built with `CGO_ENABLED=0` and the standard library only, inside Docker, from a digest-pinned golang image, for linux/amd64 and linux/arm64.
   - One build script, with `GOTOOLCHAIN=local`, `GOPROXY=off`, `-trimpath` and an empty build id, so the build downloads nothing and two builds are byte-identical.
   - SHA-256 checksums are published with the binaries and shown in the dashboard.
2. **Root, sandboxed by systemd.** It runs as a systemd service, as root. Its binary, configuration and Agent key are owned by root, and only `enroll` and `repin` write its configuration. The unit:
   - makes the whole file system read-only except the Allowed paths and the state directory (`ProtectSystem=strict`, `ReadWritePaths=-<path>` for each Allowed path, and `StateDirectory` with mode 0700, which holds the Quarantine folder);
   - sets `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` and `UMask=0077`;
   - bounds capabilities to reading, moving and re-owning files;
   - allows only the IPv4 and IPv6 address families, and only the agent listener's address (`IPAddressDeny=any` with `IPAddressAllow=`).

   The Allowed paths are given with `--allow` at install, with no default. `enroll` resolves each to its real path and refuses `/`, any path under or containing `/etc`, `/usr`, `/boot`, `/root`, `/proc`, `/sys`, `/dev`, `/run` or the state directory, and any path that contains the Quarantine folder or lies inside it. The dashboard can choose Watched roots only inside the Allowed paths, and the agent refuses any other.
3. **It dials out, and nothing listens on the server.**
   - It sends signed reports to the agent listener (ADR-0006) through the server's Agent tunnel, and polls it for Agent commands, every 30 s by default.
   - It speaks only TLS, and accepts only the certificate whose public key matches the SHA-256 pin in its configuration (`crypto/tls`, `VerifyPeerCertificate`). It has no plain-http mode and needs no CA certificates.
   - `enroll` resolves the URL's host once, requires every address to be loopback or private, and the agent connects only to the address it checked.
4. **Enrollment.**
   - The Operator adds an agent in the dashboard. The dashboard shows, once, an enroll command that holds the agent listener's URL and TLS pin and the Dashboard key's public half with its key id, and beside it a one-time Enrollment code.
   - `enroll` reads the code at a prompt or from standard input, never from its arguments or the environment, so other users on the server cannot read it.
   - The agent generates its Ed25519 Agent key and sends the public half, its Allowed paths, its version and its architecture, with the code. It prints the Agent key's fingerprint.
   - Application code checks the code: good for one use within one hour, with only its hash stored. It then holds the agent as pending until the Operator confirms in the dashboard that the fingerprint matches the one `enroll` printed. A pending agent's reports are not used, and nothing is signed for it.
5. **Both directions are signed.**
   - **Agent requests.** Each one is signed with the Agent key over a fixed `asset-monitor-agent-request-v1` prefix, the method, the path with its query string, the timestamp, the nonce and the body SHA-256. The agent listener refuses a timestamp more than 5 minutes off, and a nonce already seen while its request's timestamp is inside that window. Application code verifies each stored request again before using it (ADR-0006).
   - **Report order.** Every report carries an agent-side sequence number that only increases and is kept in the state directory, and the version of the configuration it ran under. Application code ignores a report whose sequence does not increase, and flags one made under an old configuration.
   - **Commands and configuration.** Every Agent command, and the agent's configuration (Watched roots, report interval and poll interval), is signed with the Dashboard key. Each signed message carries the agent id, its type (configuration or command), a per-agent sequence number that only increases, and the key id. The agent applies a configuration or runs a command only if its sequence is higher than the last one of that type it accepted, which it keeps in the state directory. So a compromised tunnel or ingress can neither forge one nor replay an older one.
   - **The wanted list** is the one unsigned input: the SHA-256 values whose bytes the dashboard asks for. The agent uploads only values from its own latest manifest, at most 1 MiB each, and never a file on its secret list.
   - **The Dashboard key.** Its private half is encrypted under `NUMEN_SIGNING_KEY`, which only the app holds. Rotating it needs the Operator's password: the app stops signing with the old key, and each agent shows as pinned to the old key until `asset-monitor-agent repin --key <new key>` is run on the server as root, which keeps the Agent key.
   - **Command lifetime.** A command names its agent and expires after 15 minutes.
   - **Revocation.** The Operator can revoke an agent. Its key is refused from then on, and its pending commands are cancelled.
6. **A fixed command set.** Rescan, Quarantine and Restore are written into the agent's code. There is no shell, no code or file sent from the dashboard, and no self-update.
7. **Reports.**
   - The agent walks its Watched roots and reports a File manifest: path, SHA-256, size, mode, owner and mtime.
   - It never follows symbolic links; it records each one with its target. It skips devices, sockets and pipes.
   - It never truncates a manifest. Over 50,000 files, it sends a signed over-limit report instead. A file over 512 MiB is reported by size and mtime only. A walk that passes its 4-minute deadline is reported as cut short. Each of these makes the Server change incomplete.
   - It uploads the files on the wanted list. It never uploads files whose names or folders usually hold secrets; that list is fixed in the agent's code and in the dashboard's.
8. **The dashboard judges, as it does for served content.**
   - Reports are compared against a Baseline the Operator accepts, and each distinct Server change is triaged once.
   - Analysis reads stored bytes only, staged under their SHA-256 rather than their server paths, and never executes them.
   - A Malicious change opens a server-files Finding. It gets a static Proof, a cleanup report, and a Detection rule validated on the uploaded bytes in the network-less `detection_rule` job. yara is not in the agent.
9. **Quarantine only, after Approval, and never delete.** The only changes the agent makes to a server are a Quarantine or a Restore, each after its own Approval.
   - It moves only the files whose SHA-256 matches the Finding.
   - It refuses a path any of whose components is a symbolic link, and does every step through one handle on the parent directory, opened once. Swapping a directory or a file for a link mid-way cannot redirect it.
   - It renames the file aside within that directory, to a name with no executable extension, and opens it without following links. It checks that it is a regular file, and copies it from that open descriptor into a new file in the Quarantine folder, which it creates exclusively and stores with mode 0600. It keeps the original path, mode, owner and mtime as metadata only, and checks the copy's SHA-256 before it removes the aside name. A file whose hash does not match is put back without replacing anything.
   - A Restore names only a quarantine entry. The agent takes the destination from its own record, and it must still lie inside an Allowed path and a current Watched root. The file is created exclusively, so it is never restored over another, and its owner and mode are set on the open descriptor, without setuid or setgid.
   - A journal in the state directory lets a restarted agent finish or undo a step it had begun.

## Options considered

| Option | Benefit | Cost |
|---|---|---|
| The agent listens and the dashboard connects to it | Commands arrive at once | Opens a port on the very server an attacker targets |
| The agent runs yara itself | Fewer bytes leave the server | Puts yara and the rules on the target, and a compromised server judges itself |
| The agent deletes Malicious files | Simplest cleanup | Cannot be undone, so a wrong Verdict loses the Operator's files |
| A shared bearer token instead of keys | Less code | Anyone who reads the token in the tunnel or the database can report or command |
| Plain http inside the tunnel | No certificate to manage | On a plain LAN or VPC, file bytes and the Enrollment code cross the network in clear |
| Rename-based moves by path | Fewer steps | Attacker-owned directories can redirect a rename or chown by root to another file |
| A Python or shell agent | Quicker to write | Needs an interpreter on the server, and is harder to pin and sandbox |
| A Go static binary that dials out over pinned TLS, signed both ways with ordered messages, with copy-based Quarantine after Approval (chosen) | Nothing listens on the server, commands cannot be forged or replayed without the Dashboard key, and every change can be undone | A root process on the server, an Agent tunnel per server, and up to 30 s before a command runs |

## Consequences

- **A08 changes.** Asset Monitor still never pushes to a default branch, never merges, and never writes to an Upstream repository. Its only writes to a server are an approved Quarantine or Restore, which move files and delete none.
- **Approvals.** Approval now also covers Quarantine, Restore, Watched root changes and rotating the Dashboard key, and the demo scripts never give any of them.
- **The Dashboard key.** Whoever holds its private half can quarantine any file under the Allowed paths, and widen the Watched roots within them. They cannot delete a file, run code or reach other paths. Only the app holds it, so the worker, which handles attacker-written bytes, does not.
- **The wanted list.** A compromised agent listener can ask an agent for the bytes of any file of at most 1 MiB under its Watched roots that is not on the secret list, and read them. The pinned TLS keeps a compromised tunnel from doing the same.
- **A compromised server.** Root on the server can stop or fool its agent. A silent agent is shown in the dashboard, and reports from a compromised server are evidence, not proof of a clean state.
- **Uploaded bytes go to model providers** during Analysis, as fetched served content does. The fixed secret list keeps the usual secret files and folders out. A change to one of them makes the Server change incomplete, so it can never be Unrelated.
- **Naming.** "agent" on its own means the On-server agent only inside a section about it. Everywhere else it keeps meaning a model agent.

## Reconsider when

Servers without systemd, or Windows or macOS servers, come into scope, or the Operator wants the agent to act without an Approval.
