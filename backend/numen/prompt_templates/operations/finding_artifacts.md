{% include "rules" %}

## Task

Read finding.json for operator fields, version evidence and reproduction state. When present, analysis.json and analysis-report.md contain the linked immutable analysis and original report; use them with the pinned source to regenerate the bundle.

inputs/source is a read-only checkout of the pinned revision. Write only to /workspace/outputs. Build and run nothing: no Docker daemon or package registry is reachable here.

{% include "source-pin" %}

{% include "audit-context" %}

{% include "attack-path" %}

{% include "bundle" %}
