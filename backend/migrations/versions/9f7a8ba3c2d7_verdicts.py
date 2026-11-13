"""Numen's analysis categories become Verdicts; commits keep their Verdict and Analysis state"""

import re
import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "9f7a8ba3c2d7"
down_revision = "8e6f7a92b1c6"
branch_labels = None
depends_on = None

# AC-A04. A migrated Verdict's confidence is unknown; Numen's own is kept as numen_confidence.
VERDICTS = {
    "Likely vulnerability fix": "Vulnerability fix",
    "Potentially introduced vulnerability": "Vulnerability introduced",
    "Security hardening": "Security hardening",
    "Unrelated change": "Unrelated",
    "Insufficient context": "Insufficient context",
}
CATEGORIES = {verdict: category for category, verdict in VERDICTS.items()}
# Saved prompt templates this revision breaks: Triage and Analysis return a new result, and the
# build-sandbox section is gone, so a template that includes it no longer renders. Each is reset
# like a reset on the Prompt templates page, its saved version kept in the actions audit log.
RESET = ("commit_triage", "commit_analysis", "build-sandbox")
INCLUDES_BUILD = re.compile(r"""include\s+["']build-sandbox["']""")
RESET_REASON = "Asset Monitor changed this operation's result or removed the build sandbox it used"
settings = sa.table("settings", sa.column("id"), sa.column("data", sa.JSON), sa.column("revision"))
actions = sa.table("actions", sa.column("id"), sa.column("resource_type"), sa.column("resource_id"),
                   sa.column("data", sa.JSON), sa.column("created_at"))


def tables():
    def table(name, *columns):
        return sa.table(name, sa.column("id"), sa.column("kind"), sa.column("result", sa.JSON), *columns)

    return table("analyses", sa.column("subject_id"), sa.column("created_at")), table("jobs")


def rewrite(table, convert):
    """Rewrites each commit_analysis result row by row; `convert` returns None to keep one."""
    db = op.get_bind()
    rows = db.execute(sa.select(table.c.id, table.c.result).where(table.c.kind == "commit_analysis"))
    for ident, result in rows.all():
        changed = convert(result) if isinstance(result, dict) else None
        if changed is not None:
            db.execute(table.update().where(table.c.id == ident).values(result=changed))


def to_verdict(result):
    if result.get("category") not in VERDICTS:
        return None
    rest = {k: v for k, v in result.items() if k not in ("category", "confidence")}
    return {**rest, "verdict": VERDICTS[result["category"]], "confidence": "unknown",
            "numen_confidence": result.get("confidence")}


def to_category(result):
    if "verdict" not in result:
        return None
    rest = {k: v for k, v in result.items() if k not in ("verdict", "confidence", "numen_confidence")}
    # Numen has no Malicious change category: it is the nearest one it can still review.
    category = CATEGORIES.get(result["verdict"], "Insufficient context")
    confidence = result.get("numen_confidence", {"level": result.get("confidence")})
    return {**rest, "category": category, "confidence": confidence}


def save_templates(db, data, templates):
    db.execute(settings.update().where(settings.c.id == "prompts").values(
        data={**data, "templates": templates}, revision=settings.c.revision + 1))


def reset_templates(db):
    data = db.execute(sa.select(settings.c.data).where(settings.c.id == "prompts")).scalar()
    templates = dict((data or {}).get("templates", {}))
    broken = [name for name, entry in templates.items()
              if name in RESET or INCLUDES_BUILD.search(entry.get("source", ""))]
    for name in broken:
        entry = templates.pop(name)
        db.execute(actions.insert().values(
            id=str(uuid.uuid4()), resource_type="prompt", resource_id=name, created_at=datetime.now(timezone.utc),
            data={"action": "reset", "previous": entry.get("source"), "reason": RESET_REASON, "saved": entry}))
    if broken:
        save_templates(db, data, templates)


def restore_templates(db):
    rows = [(ident, name, data) for ident, name, data in db.execute(
        sa.select(actions.c.id, actions.c.resource_id, actions.c.data).where(actions.c.resource_type == "prompt"))
        if isinstance(data, dict) and data.get("reason") == RESET_REASON]
    if not rows:
        return
    data = db.execute(sa.select(settings.c.data).where(settings.c.id == "prompts")).scalar() or {}
    save_templates(db, data, {**data.get("templates", {}), **{name: row["saved"] for _, name, row in rows}})
    db.execute(actions.delete().where(actions.c.id.in_([ident for ident, _, _ in rows])))


def upgrade():
    op.add_column("commits", sa.Column("verdict", sa.String(), nullable=True))
    op.add_column("commits", sa.Column("analysis_state", sa.JSON(), nullable=True))
    analyses, jobs = tables()
    for table in (analyses, jobs):
        rewrite(table, to_verdict)
    db = op.get_bind()
    commits = sa.table("commits", sa.column("id"), sa.column("verdict"))
    newest = {}
    for subject, result in db.execute(
        sa.select(analyses.c.subject_id, analyses.c.result)
        .where(analyses.c.kind == "commit_analysis")
        .order_by(analyses.c.created_at)
    ):
        if isinstance(result, dict) and result.get("verdict"):
            newest[subject] = result["verdict"]
    for subject, verdict in newest.items():
        db.execute(commits.update().where(commits.c.id == subject).values(verdict=verdict))
    reset_templates(db)


def downgrade():
    restore_templates(op.get_bind())
    for table in tables():
        rewrite(table, to_category)
    op.drop_column("commits", "analysis_state")
    op.drop_column("commits", "verdict")
