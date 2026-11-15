# GarudaNetra

GarudaNetra watches the Operator's Applications for security-relevant changes in four places: their own code, the upstream code they depend on, the content their Assets serve, and, with an On-server agent, the files on the server behind an Asset. It responds to each change with a fixed Playbook. "GarudaNetra" is a working name.

## Language

### People

**Operator**:
The one person who runs GarudaNetra, protects its Applications and gives every Approval.
_Avoid_: user, admin, analyst

### Applications

**Application**:
An app the Operator protects: its Asset, the Upstream repositories it depends on, and, if the Operator has one, its Own repository.
_Avoid_: program, project, target

**Own repository**:
The repository that holds the Application's own source code. It is the only repository GarudaNetra ever proposes changes to. An Application may have none.
_Avoid_: main repo, app repo

**Upstream repository**:
The source of something the Application depends on, such as a library, CMS or plugin. It is watched but never changed, and one Upstream repository can serve several Applications.
_Avoid_: dependency repo, third-party repo

**Locked version**:
The version of an Upstream repository that an Application uses: pinned by its lockfile, entered by the Operator, or taken from its Deployed version.
_Avoid_: pinned version, current version

**Release branch**:
The Upstream branch that carries the release line of a Locked version.
_Avoid_: stable branch, maintenance branch

**Exposure**:
Whether an Upstream change or a published advisory reaches an Application: its Locked version, or the runtime version it pins, contains the weakness or payload, or does not yet contain the fix.
_Avoid_: impact, affected, applicability

**Deployed version**:
The version that an Asset is actually serving, as far as GarudaNetra can tell from outside. It may be unknown.
_Avoid_: remote version, live version

**Asset**:
The live URL where the Application is served. It receives Served-content checks, never Proofs.
_Avoid_: target, site, deployment

**Baseline**:
The trusted starting point for watching: the head of a repository when it is added, or the Content fingerprint of a Watched page or the File manifest of an On-server agent that the Operator has accepted, either the first one or a later one in its place. Changes are judged against it.
_Avoid_: snapshot, initial state

### Changes and verdicts

**Pre-filter**:
The rule-based check before Triage that marks a change as touching sensitive files. It never decides anything on its own.
_Avoid_: heuristic triage, quick scan

**Backfill**:
Triage of commits older than the Baseline, done only when the Operator asks.
_Avoid_: history scan, rescan (a rescan is an Agent command)

**Triage**:
The cheap first look at a new commit, served-content change or Server change that decides whether it deserves Analysis.
_Avoid_: classification, scan

**Analysis**:
The deep agent review of a commit, a served-content change, a Server change or a CVE record carried over from Numen, started by Triage or by the Operator, which produces its Verdict.
_Avoid_: investigation, escalation

**Verdict**:
The outcome of Analysis: exactly one of Vulnerability fix, Vulnerability introduced, Malicious change, Security hardening, Unrelated, or Insufficient context. Each comes with a confidence of low, medium or high, which is unknown for Verdicts carried over from Numen.
_Avoid_: result category, label

**Vulnerability fix**:
A Verdict for a commit that removes a vulnerability, possibly silently and before any advisory exists.
_Avoid_: security fix, likely vulnerability fix

**Vulnerability introduced**:
A Verdict for a commit that adds an exploitable weakness by mistake.
_Avoid_: potentially introduced vulnerability, security_vuln

**Malicious change**:
A Verdict for a change that deliberately adds a backdoor, injected content, or a supply-chain payload.
_Avoid_: security_supply_chain, backdoor commit

**Security hardening**:
A Verdict for a change that adds defence in depth without fixing or adding a specific vulnerability.
_Avoid_: hardening fix, minor security change

**Unrelated**:
A Verdict for a change with no security bearing.
_Avoid_: unrelated change, benign

**Insufficient context**:
A Verdict given when Analysis cannot decide from what it can see. The change goes to the Review queue.
_Avoid_: unknown, inconclusive

**Review queue**:
The changes with an Insufficient context Verdict that are waiting for the Operator to judge them.
_Avoid_: backlog, inbox

**Finding**:
One security weakness that GarudaNetra believes reaches an Application. It is opened by a Verdict, by a Malicious change in served content or in server files, or by an Advisory check match. It moves from Open to Confirmed or Dismissed, and from Open or Confirmed to Remediated. A server-files Finding also moves from Remediated back to Confirmed when a file it names comes back.
_Avoid_: alert, issue, vuln, lead

**Finding source**:
What opened a Finding: a commit, served content, server files, an advisory, or a CVE record carried over from Numen.
_Avoid_: kind, origin

### Responses

**Playbook**:
The fixed set of steps that a Verdict or an Advisory check match triggers. For a Verdict, it depends on where the change came from.
_Avoid_: workflow, pipeline, escalation

**Approval**:
The Operator's explicit yes, given with their password, before a Proof is built and run in a Lab, a Remediation PR is opened, an On-server agent carries out a Quarantine or a Restore or gets new Watched roots, or the Dashboard key is rotated.
_Avoid_: confirmation, decision

**Lab**:
A disposable environment that reproduces a vulnerable version of an application. It is the only place a Proof runs.
_Avoid_: sandbox, build sandbox, test environment

**Lab stack**:
Node or PHP: the toolchain a Lab builds and runs an application with, from its own pinned Lab base. A Proof bundle's Dockerfile names exactly one.
_Avoid_: runtime, language, image

**Proof**:
The evidence that demonstrates a Verdict. For a vulnerability it is a reproduction run in a Lab. For a Malicious change it is static: a Detection rule plus the indicators extracted from the change. The payload is never run.
_Avoid_: exploit, PoC

**Remediation PR**:
A draft pull request on the Own repository, built by GarudaNetra after an Approval: a patch, a revert, or a dependency pin or bump.
_Avoid_: auto-fix, patch apply, hotfix

**Cure**:
The complete response to a Malicious change in the Own repository: a revert Remediation PR, its Detection rule, and a cleanup report telling the Operator what to remove and which secrets to rotate.
_Avoid_: disinfection, quarantine (a Quarantine is the On-server agent's move)

**Quarantine**:
Moving the files a server-files Finding names into the On-server agent's Quarantine folder, after an Approval. Only files whose SHA-256 matches the Finding are moved, and no file is ever deleted.
_Avoid_: removal, deletion, cleanup

**Restore**:
Moving quarantined files back to their original paths, after an Approval. A file is never restored over one that is already there.
_Avoid_: undo, unquarantine, rollback (and it is not `make restore`, which restores a backup)

**Disclosure report**:
A report written for the maintainers of an Upstream repository about a weakness in their code. GarudaNetra writes it and never sends it.
_Avoid_: advisory, bug report

**Detection rule**:
A rule written for a Malicious change that matches what the change added and matches nothing in the state just before the change or, for a change made after the Baseline, in the Baseline.
_Avoid_: signature, IOC

**Advisory check**:
Matching the runtime and package versions an Application uses against published security advisories, independent of any commit.
_Avoid_: CVE scan, vulnerability scan

**Transcript**:
The stored record of one agent run, with secrets removed, attached to the Triage result, Verdict or Finding it belongs to.
_Avoid_: log, session, history

**Provider account**:
One model credential the Operator has added, together with the provider it belongs to. Automated runs use only accounts that hold an API key.
_Avoid_: subscription, connection

**Alert**:
A one-way message to the Operator's chat channel announcing something that needs attention. It links to the dashboard and never collects Approvals.
_Avoid_: notification, webhook, ping

### Served content

**Served-content check**:
Fetching an Asset's Watched pages without running them, once as a normal browser and once as a search-engine crawler, and comparing their Content fingerprints against the Baseline.
_Avoid_: site scan, crawl, render

**Watched page**:
A page of an Asset that Served-content checks fetch. The homepage is always one.
_Avoid_: monitored URL, target page

**Content fingerprint**:
The comparable summary of what a Watched page serves, built so that injected content changes it and routine changes do not.
_Avoid_: page hash, snapshot

### Server files

**On-server agent**:
A program the Operator installs as root on the server behind an Asset. It reports the File manifest of its Watched roots, uploads files as evidence, and acts only on Agent commands. It runs no model, listens on no port and never deletes a file.
_Avoid_: server agent, sensor, "agent" on its own outside a section about the On-server agent (elsewhere it is a model agent)

**Allowed path**:
A directory fixed at install in an On-server agent's local configuration. Every Watched root lies inside one, and the Allowed paths and the agent's state directory, which holds the Quarantine folder, are the only places the agent can write.
_Avoid_: whitelist, permitted path

**Watched root**:
A directory on the server that an On-server agent reports on. It is set per agent in the dashboard and must lie inside one of the agent's Allowed paths.
_Avoid_: watch path, monitored folder, web root

**File manifest**:
The list an On-server agent reports of every file under its Watched roots, with each file's path, SHA-256, size, mode, owner and modification time.
_Avoid_: inventory, listing, snapshot

**Server change**:
The difference between a File manifest and the Baseline: the files added, changed or removed. Each distinct Server change is triaged at most once.
_Avoid_: change set, file diff, delta

**Quarantine folder**:
The root-owned folder in the On-server agent's state directory, outside every Allowed path, where the agent keeps quarantined files together with their original path, mode, owner and modification time.
_Avoid_: trash, recycle bin, vault

**Agent command**:
One of the three actions the dashboard can ask an On-server agent to carry out: a rescan, a Quarantine or a Restore. Each is signed with the Dashboard key, and the set is fixed in the agent's code.
_Avoid_: task, job, remote command

**Enrollment**:
Joining an On-server agent to the dashboard. The agent presents an Enrollment code and the public half of its Agent key, and is enrolled once the Operator confirms that key's fingerprint.
_Avoid_: pairing, registration, onboarding

**Enrollment code**:
A one-time code, shown once in the dashboard and typed at the enroll command's prompt, that lets exactly one On-server agent request Enrollment before it expires.
_Avoid_: token, invite, password

**Agent key**:
The Ed25519 key pair an On-server agent generates at Enrollment. It signs every request the agent sends, and only its public half leaves the server.
_Avoid_: agent token, API key

**Dashboard key**:
The Ed25519 key pair the dashboard signs every Agent command and agent configuration with. Each On-server agent pins its public half at Enrollment, and is repinned by hand when the key is rotated.
_Avoid_: server key, master key

### Inbound traffic

**Ingress**:
The part of GarudaNetra that receives inbound machine traffic: two services, each with one loopback listener, the push listener for Push deliveries and the agent listener for On-server agents. It accepts only signed requests and never serves the dashboard.
_Avoid_: gateway, proxy, public API (and it is not the runner's credential ingress)

**Push webhook**:
A GitHub webhook the Operator registers by hand on an Own repository, so that each push makes GarudaNetra poll that repository at once. Scheduled polling continues as before.
_Avoid_: "webhook" on its own (an Alert is not a webhook), hook, callback

**Push webhook secret**:
The per-repository secret that GarudaNetra generates for a Push webhook and uses to verify the signature of each Push delivery.
_Avoid_: webhook secret, shared secret, token

**Push delivery**:
One push that GitHub reports to the push listener, identified by its delivery id. Its payload is never trusted for commit data.
_Avoid_: event, hook call, notification

**Private tunnel**:
The Operator's own encrypted route from their devices to the dashboard on the host's loopback, such as a VPN or an SSH tunnel. On-server agents never use it.
_Avoid_: remote access, VPN (as the term)

**Agent tunnel**:
The private tunnel the Operator runs for one server, which reaches the agent listener and nothing else: for example an SSH forward whose key may open only that port. Each server has its own.
_Avoid_: agent VPN, the Private tunnel

**Public tunnel**:
A tunnel the Operator runs that makes the push listener, and nothing else, reachable from GitHub.
_Avoid_: port forward, public endpoint
