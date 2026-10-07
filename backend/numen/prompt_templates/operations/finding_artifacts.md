{% include "rules" %}

## Task

Read finding.json for operator fields, version evidence and reproduction state. When present, analysis.json and analysis-report.md contain the linked immutable analysis and original report; use them with the pinned source to regenerate the bundle.

{% include "source-pin" %}

{% include "audit-context" %}

{% include "attack-path" %}

{% include "bundle" %}
{% if build %}

{% include "build-sandbox" %}
{% endif %}
