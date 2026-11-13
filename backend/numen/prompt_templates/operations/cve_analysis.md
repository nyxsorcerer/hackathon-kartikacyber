{% include "rules" %}

## Task

CVE analysis drafts a complete n-day finding bundle as well as its JSON result and must preserve deterministic product/score/applicability facts.

inputs/source is a read-only checkout of the pinned revision. Write only to /workspace/outputs. Build and run nothing: no Docker daemon or package registry is reachable here.

{% include "source-pin" %}

{% include "audit-context" %}

{% include "attack-path" %}

{% include "bundle" %}
