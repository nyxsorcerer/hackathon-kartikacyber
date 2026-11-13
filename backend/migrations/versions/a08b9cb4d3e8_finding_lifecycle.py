"""Findings carry a source and the A11 lifecycle, each state with the cause that set it"""

from alembic import op
import sqlalchemy as sa

revision = "a08b9cb4d3e8"
down_revision = "9f7a8ba3c2d7"
branch_labels = None
depends_on = None

# A11: kind 0day becomes source commit, cve stays cve; status open stays Open, fixed becomes Remediated.
RENAMED = (("source", "0day", "commit"), ("status", "fixed", "remediated"))
findings = sa.table("findings", sa.column("id"), sa.column("source"), sa.column("status"),
                    sa.column("cve_id"), sa.column("data", sa.JSON))


def rewrite(convert):
    """Rewrites each Finding's data row by row; `convert` gets the row and returns its new data."""
    db = op.get_bind()
    for row in db.execute(sa.select(findings)).all():
        db.execute(findings.update().where(findings.c.id == row.id).values(data=convert(row)))


def upgrade():
    op.alter_column("findings", "kind", new_column_name="source")
    for column, old, new in RENAMED:
        op.execute(findings.update().where(findings.c[column] == old).values({column: new}))
    commits = sa.table("commits", sa.column("id"), sa.column("revision"))
    revisions = dict(op.get_bind().execute(sa.select(commits.c.id, commits.c.revision)).all())

    def lifecycle(row):
        data = row.data or {}
        commit = revisions.get(data.get("source_commit_id"))
        # Numen opened or edited every carried-over Finding; nothing records which.
        return {**data, "cause": {"by": "numen"}, "source_ref": commit[:7] if commit else row.cve_id}

    rewrite(lifecycle)


def downgrade():
    """Refused while any Finding is Confirmed or Dismissed, or came from served content or an
    advisory: Numen has neither those states nor those sources."""
    kept = op.get_bind().execute(sa.select(findings.c.id).where(sa.or_(
        findings.c.status.in_(("confirmed", "dismissed")),
        findings.c.source.in_(("served_content", "advisory")),
    )).order_by(findings.c.id)).scalars().all()
    if kept:
        raise RuntimeError(
            f"Findings {', '.join(kept)} are Confirmed or Dismissed, or have a served_content or"
            " advisory source, so Numen cannot hold them. Restore the backup taken before the"
            " upgrade instead."
        )
    rewrite(lambda row: {k: v for k, v in (row.data or {}).items() if k not in ("cause", "source_ref")})
    for column, old, new in RENAMED:
        op.execute(findings.update().where(findings.c[column] == new).values({column: old}))
    op.alter_column("findings", "source", new_column_name="kind")
