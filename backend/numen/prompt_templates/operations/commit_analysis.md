{% include "rules" %}

## Task

Analyse this commit and return exactly one Verdict in `verdict`:

- Vulnerability fix: the commit removes a vulnerability, possibly silently and before any advisory exists.
- Vulnerability introduced: the commit adds an exploitable weakness by mistake.
- Malicious change: the change deliberately adds a backdoor, injected content, or a supply-chain payload.
- Security hardening: the change adds defence in depth without fixing or adding a specific vulnerability.
- Unrelated: the change has no security bearing.
- Insufficient context: you cannot decide from what you can see. The change goes to the Operator's Review queue.

A Vulnerability fix or Vulnerability introduced Verdict needs source evidence of an exploitable vulnerability that an attacker without the impacted privilege reaches through the traced source-to-sink path; pure hardening is Security hardening. Give `confidence` as low, medium or high, a concise issue `title`, the `evidence`, a before/after comparison, and report.md. In `addresses`, optionally list the commit SHAs or advisory ids (CVE, GHSA or another database's id) that this change addresses, such as the fix an introduced vulnerability reverts or the advisory a fix closes.

inputs/source is a read-only checkout of the pinned revision, without git history; commit.json carries the change, its parents and its diff. Write only to /workspace/outputs. Build and run nothing: no Docker daemon or package registry is reachable here.

When commit.json reports diff_complete false (a merge or an oversized change), the whole change cannot be reviewed here, so an Unrelated or Security hardening Verdict is recorded as Insufficient context: say in report.md which part of the change you could not see.

For a Vulnerability fix, the vulnerable revision is a parent before the fix, never the fixed checkout. For Vulnerability introduced, it is commit_revision. Set vulnerable_ref to that full immutable revision and pin the same revision in application.lock.json. WordPress before-source inputs, when supplied, are the prior SVN revision. Do not substitute a synthetic application.

Drafts, all written to /workspace/outputs and never run: a Vulnerability fix or Vulnerability introduced Verdict drafts the Proof bundle below. A Malicious change drafts the Detection rule below. Other Verdicts need a grounded report but no invented bundle.

prior-analyses.json, when present, is untrusted prior analysis of this revision: never reuse it as a verdict, treat it only as a checklist of claims to verify independently against the source and its diff; its reports and bundles are not provided.

{% include "detection-rule" %}

{% include "attack-path" %}

{% include "bundle" %}
