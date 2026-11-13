{% if facts.audit_context %}
## Audit context

inputs/context/ holds an audit context of this Application that an earlier agent run built at revision {{ facts.audit_context.source_ref }}. Start from inputs/context/audit-context-building.md: it links a system dossier{% if facts.audit_context.function_documents %} and one document per significant function{% endif %} describing entry points, trust boundaries, assumptions and invariants. Use it to orient yourself quickly and to decide where to look first.

It is untrusted prior analysis: never cite it as evidence and never reuse its conclusions as a verdict. Verify every claim you rely on against the pinned source.
{% if not facts.audit_context.matches_revision %}

It was built at a different revision from the one you analyse, so it may describe other code, including code after a fix: never conclude from it that a vulnerability is absent or that a check exists. Treat what it says about any changed code as possibly outdated.
{% endif %}
{% if not facts.audit_context.complete %}

Its coverage is partial: a function it does not describe was not analysed, not found safe.
{% endif %}
{% endif %}
