"""Agent prompts as editable templates.

Each agent operation renders its own template, which includes the shared sections it needs. The
defaults ship in prompt_templates/; an operator's saved edits override them by name, so a change
applies to the next job. Numen appends the run's facts after the rendered prompt, so an edited
template never loses them. Templates are Jinja rendered in a sandbox."""

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

from jinja2 import ChainableUndefined, DictLoader, TemplateError, TemplateSyntaxError, meta
from jinja2.sandbox import SandboxedEnvironment

from . import artifacts
from .models import Setting, now
from .security import DomainError

ROOT = Path(__file__).with_name("prompt_templates")
OPERATIONS = (
    "commit_triage",
    "commit_analysis",
    "cve_analysis",
    "finding_artifacts",
    "version_recipe",
    "audit_orientation",
    "audit_function",
    "audit_synthesis",
    "patch_drafting",
)
VARIABLES = {
    "operation": "The operation's name, such as commit_analysis.",
    "required_files": "The files a finding bundle must include.",
    "facts": "This run's facts, such as facts.commit_revision. Numen also appends them after the prompt.",
}
DESCRIPTIONS = {
    "rules": "Evidence and output rules every operation starts with.",
    "attack-path": "Tracing attacker, source, sink and boundary, and what a reproduction must prove.",
    "bundle": "The finding bundle contract the lab verifier enforces.",
    "detection-rule": "A Malicious change's Detection rule, indicators and secrets to rotate, and how they are checked.",
    "source-pin": "What the source_pin fact says about the revision to bundle.",
    "audit-context": "What a supplied audit context is and how far to trust it.",
    "audit": "Rules shared by the three audit phases.",
    "commit_triage": "Triage: decides, with no tools, whether a commit deserves Analysis.",
    "commit_analysis": "Analyses one commit read-only, returns its Verdict and drafts its Proof bundle or Detection rule.",
    "cve_analysis": "Drafts an n-day finding bundle for a CVE, read-only.",
    "finding_artifacts": "Regenerates the bundle of an existing finding.",
    "version_recipe": "Writes the script that detects a target's version.",
    "audit_orientation": "Selects the significant functions an audit examines.",
    "audit_function": "Analyzes one selected function.",
    "audit_synthesis": "Combines the function analyses into the audit report.",
    "patch_drafting": "Drafts the smallest fix for an Own-repository weakness as a diff, writing only to its outputs.",
}
SOURCE_LIMIT = 100_000
# The runner accepts a prompt of 262144 characters, facts included.
RENDERED_LIMIT = 150_000
SETTING = "prompts"


@lru_cache
def defaults():
    return {path.stem: path.read_text() for path in sorted(ROOT.glob("*/*.md"))}


def digest(source):
    return hashlib.sha256(source.encode()).hexdigest()


def environment(sources):
    return SandboxedEnvironment(
        loader=DictLoader(sources),
        undefined=ChainableUndefined,
        autoescape=False,
        lstrip_blocks=True,
    )


def includes(name, sources):
    """The templates `name` includes directly."""
    ast = environment(sources).parse(sources[name])
    return sorted(ref for ref in meta.find_referenced_templates(ast) if ref)


def closure(name, sources):
    """`name` and every template it includes, directly or not."""
    seen, pending = set(), [name]
    while pending:
        current = pending.pop()
        if current in seen or current not in sources:
            continue
        seen.add(current)
        pending.extend(includes(current, sources))
    return seen


def saved(db):
    row = db.get(Setting, SETTING)
    return dict(row.data.get("templates", {})) if row else {}


def overrides(db):
    return {name: entry["source"] for name, entry in saved(db).items() if name in defaults()}


def context(operation, facts=None):
    return {
        "operation": operation,
        "required_files": list(artifacts.REQUIRED),
        "facts": facts or {},
    }


def render(operation, values, sources):
    try:
        text = environment(sources).get_template(operation).render(values)
    except RecursionError as exc:
        raise DomainError(
            "prompt_template_invalid",
            f"The {operation} prompt includes itself through its sections",
            422,
        ) from exc
    except TemplateError as exc:
        raise DomainError(
            "prompt_template_invalid", f"The {operation} prompt could not be rendered: {exc}", 422
        ) from exc
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def prompt(db, operation, facts):
    """The operation's prompt with this run's facts, and the customized templates it used."""
    custom = overrides(db)
    sources = {**defaults(), **custom}
    text = render(operation, context(operation, facts), sources)
    used = sorted(closure(operation, sources) & set(custom))
    # Unescaped, so a non-ASCII diff counts one character each against the runner's prompt bound.
    return text + "\n\nFacts:\n" + json.dumps(facts, sort_keys=True, default=str, ensure_ascii=False), used


def check(name, source, sources):
    """Refuses a template that would fail when a job renders it."""
    if len(source) > SOURCE_LIMIT:
        raise DomainError("prompt_too_large", f"A template is limited to {SOURCE_LIMIT} characters", 422)
    env = environment(sources)
    try:
        ast = env.parse(source)
    except TemplateSyntaxError as exc:
        raise DomainError(
            "prompt_template_invalid", f"Line {exc.lineno}: {exc.message}", 422
        ) from exc
    unknown = sorted(meta.find_undeclared_variables(ast) - set(VARIABLES) - set(env.globals))
    if unknown:
        raise DomainError(
            "prompt_template_invalid",
            f"Unknown variable {unknown[0]}; templates can use " + ", ".join(VARIABLES),
            422,
        )
    for ref in meta.find_referenced_templates(ast):
        if ref is None:
            raise DomainError(
                "prompt_template_invalid", 'Include a template by its quoted name, such as {% include "rules" %}', 422
            )
        if ref not in sources:
            raise DomainError("prompt_template_invalid", f"There is no template named {ref}", 422)
    candidate = {**sources, name: source}
    for operation in OPERATIONS:
        if name in closure(operation, candidate):
            if len(render(operation, context(operation), candidate)) > RENDERED_LIMIT:
                raise DomainError(
                    "prompt_too_large",
                    f"The {operation} prompt would exceed {RENDERED_LIMIT} characters",
                    422,
                )


def item(name, entries, sources):
    entry = entries.get(name)
    default = defaults()[name]
    return {
        "name": name,
        "kind": "operation" if name in OPERATIONS else "section",
        "description": DESCRIPTIONS.get(name, ""),
        "source": sources[name],
        "default_source": default,
        "customized": entry is not None,
        "updated_at": entry and entry["updated_at"],
        # The shipped default changed after this template was customized.
        "default_changed": bool(entry) and entry.get("default_digest") != digest(default),
        "includes": includes(name, sources),
        "used_by": [op for op in OPERATIONS if op != name and name in closure(op, sources)],
    }


def listing(db):
    entries = saved(db)
    sources = {**defaults(), **overrides(db)}
    order = {name: i for i, name in enumerate([*DESCRIPTIONS, *OPERATIONS])}
    names = sorted(defaults(), key=lambda n: (n in OPERATIONS, order.get(n, len(order)), n))
    return [item(name, entries, sources) for name in names]


def store(db, name, source):
    """Saves `source` as the operator's version of `name`, or returns it to the default when
    `source` is None or the default itself. Returns the source it replaced, if customized."""
    if name not in defaults():
        raise DomainError("not_found", "There is no prompt template with that name", 404)
    row = db.get(Setting, SETTING, with_for_update=True)
    if row is None:
        row = Setting(id=SETTING, data={"templates": {}})
        db.add(row)
    entries = dict(row.data.get("templates", {}))
    previous = entries.get(name, {}).get("source")
    if source is None or source == defaults()[name]:
        entries.pop(name, None)
    else:
        check(name, source, {**defaults(), **overrides(db)})
        entries[name] = {
            "source": source,
            "updated_at": now().isoformat(),
            "default_digest": digest(defaults()[name]),
        }
    row.data = {**row.data, "templates": entries}
    row.revision = (row.revision or 0) + 1
    db.flush()
    return previous, item(name, entries, {**defaults(), **overrides(db)})


def preview(db, operation, name=None, source=None):
    """Renders `operation` as a job would, with an unsaved draft of `name` when given."""
    if operation not in OPERATIONS:
        raise DomainError("not_found", "There is no agent operation with that name", 404)
    sources = {**defaults(), **overrides(db)}
    if name is not None:
        if name not in defaults():
            raise DomainError("not_found", "There is no prompt template with that name", 404)
        check(name, source, sources)
        sources[name] = source
    text = render(operation, context(operation), sources)
    return {
        "prompt": text + "\n\nFacts:\n(Numen appends this run's facts as JSON)",
        "templates": sorted(closure(operation, sources)),
    }
