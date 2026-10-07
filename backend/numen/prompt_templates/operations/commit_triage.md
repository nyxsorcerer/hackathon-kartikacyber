{% include "rules" %}

## Task

Classify the security change as vulnerability_fix, security_hardening, vulnerability_introduction, unrelated, or insufficient_context. A fix must address a plausible reachable vulnerability; hardening improves defense without establishing an exploitable bug. Give a concise potential vulnerability/security-change title, including the affected behavior; do not merely repeat the commit message. Use security_candidate for the three security kinds, unrelated only for complete non-security evidence, and insufficient_context when uncertain. Do not claim a finding.
