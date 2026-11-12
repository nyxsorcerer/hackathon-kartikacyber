# Asset Monitor

Asset Monitor watches the Operator's Applications for security-relevant changes in three places: their own code, the upstream code they depend on, and the content their Assets serve. It responds to each change with a fixed Playbook. "Asset Monitor" is a working name.

## Language

### People

**Operator**:
The one person who runs Asset Monitor, protects its Applications and gives every Approval.
_Avoid_: user, admin, analyst

### Applications

**Application**:
An app the Operator protects: its Asset, the Upstream repositories it depends on, and, if the Operator has one, its Own repository.
_Avoid_: program, project, target

**Own repository**:
The repository that holds the Application's own source code. It is the only repository Asset Monitor ever proposes changes to. An Application may have none.
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
The version that an Asset is actually serving, as far as Asset Monitor can tell from outside. It may be unknown.
_Avoid_: remote version, live version

**Asset**:
The live URL where the Application is served. It receives Served-content checks, never Proofs.
_Avoid_: target, site, deployment

**Baseline**:
The trusted starting point for watching: the head of a repository when it is added, or the Content fingerprint of a Watched page that the Operator has accepted, either the first one or a later one in its place. Changes are judged against it.
_Avoid_: snapshot, initial state

### Changes and verdicts

**Pre-filter**:
The rule-based check before Triage that marks a change as touching sensitive files. It never decides anything on its own.
_Avoid_: heuristic triage, quick scan

**Backfill**:
Triage of commits older than the Baseline, done only when the Operator asks.
_Avoid_: history scan, rescan

**Triage**:
The cheap first look at a new commit or served-content change that decides whether it deserves Analysis.
_Avoid_: classification, scan

**Analysis**:
The deep agent review of a commit, a served-content change or a CVE record carried over from Numen, started by Triage or by the Operator, which produces its Verdict.
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
One security weakness that Asset Monitor believes reaches an Application. It is opened by a Verdict, by a Malicious change in served content, or by an Advisory check match. It moves from Open to Confirmed or Dismissed, and from Open or Confirmed to Remediated.
_Avoid_: alert, issue, vuln, lead

**Finding source**:
What opened a Finding: a commit, served content, an advisory, or a CVE record carried over from Numen.
_Avoid_: kind, origin

### Responses

**Playbook**:
The fixed set of steps that a Verdict or an Advisory check match triggers. For a Verdict, it depends on where the change came from.
_Avoid_: workflow, pipeline, escalation

**Approval**:
The Operator's explicit yes, given with their password, before a Proof is built and run in a Lab or a Remediation PR is opened.
_Avoid_: confirmation, decision

**Lab**:
A disposable environment that reproduces a vulnerable version of an application. It is the only place a Proof runs.
_Avoid_: sandbox, build sandbox, test environment

**Proof**:
The evidence that demonstrates a Verdict. For a vulnerability it is a reproduction run in a Lab. For a Malicious change it is static: a Detection rule plus the indicators extracted from the change. The payload is never run.
_Avoid_: exploit, PoC

**Remediation PR**:
A draft pull request on the Own repository, built by Asset Monitor after an Approval: a patch, a revert, or a dependency pin or bump.
_Avoid_: auto-fix, patch apply, hotfix

**Cure**:
The complete response to a Malicious change in the Own repository: a revert Remediation PR, its Detection rule, and a cleanup report telling the Operator what to remove and which secrets to rotate.
_Avoid_: disinfection, quarantine

**Disclosure report**:
A report written for the maintainers of an Upstream repository about a weakness in their code. Asset Monitor writes it and never sends it.
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

**On-server agent**:
A program installed on the server behind an Asset that reports changes to the files it serves.
_Avoid_: server agent, sensor
