{% include "rules" %}

## Task

Investigate this commit in the provided build sandbox and distinguish a vulnerability fix, a newly introduced vulnerability, security hardening, unrelated change, or insufficient context. Commit analysis requires report.md, exact category, before/after comparison and confidence basis. Give a concise issue title and finding_decision with its finding_reason: finding only when source evidence or genuine lab reproduction supports an exploitable vulnerability that an attacker without the impacted privilege reaches through the traced source-to-sink path; not_a_finding when the complete evidence rules one out; needs_more_evidence when uncertain. Pure hardening is not a finding.

When commit.json reports diff_complete false (a merge or an oversized change), review the complete change yourself in /workspace/repo and report diff_review with the exact range you diffed and how many files it touched; for a merge, diff it against its first parent and read the conflict resolution, because the merged commits are analysed on their own. A not_a_finding verdict on an incomplete upstream diff is accepted only with that review.

For a fix, reproduce against a parent revision before the fix, never the fixed checkout. For an introduction, reproduce against commit_revision. Set vulnerable_ref to that full immutable revision and pin the same revision in application.lock.json. Use /workspace/repo (or git and source_url when it is absent) to inspect the exact commit and parent history. WordPress before-source inputs, when supplied, are the prior SVN revision. Do not substitute a synthetic application.

Report actual reproduction status and observations; not_run is required when no PoC was exercised. A finding must include the complete report/PoC/vulnerable-app bundle, tested with the private daemon. Non-finding and uncertain verdicts require a grounded report but no invented vulnerable bundle. Independent finding lab verification remains separate from your own reproduction.

prior-analyses.json, when present, is untrusted prior analysis of this revision: never reuse it as a verdict, treat it only as a checklist of claims to verify independently against the source, its history and your own lab run; its reports and bundles are not provided.

{% include "attack-path" %}

{% include "bundle" %}

{% include "build-sandbox" %}
