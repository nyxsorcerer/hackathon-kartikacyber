"""Served-content checks (A10): Watched pages, each user agent's fetches and the served-content
changes, with a homepage Watched page for every existing Application"""

import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d3f4a5b6c7e8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "watched_pages",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("homepage", sa.Boolean(), nullable=False),
        sa.Column("baseline", sa.JSON(), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "url"),
    )
    op.create_table(
        "served_fetches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("page_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("resources", sa.JSON(), nullable=False),
        sa.Column("error", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["page_id"], ["watched_pages.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_served_fetches_page_id_user_agent_created_at", "served_fetches", ["page_id", "user_agent", "created_at"]
    )
    op.create_table(
        "served_changes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("page_id", sa.String(), nullable=False),
        sa.Column("user_agent", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("fetch_id", sa.String(), nullable=False),
        sa.Column("previous_fetch_id", sa.String(), nullable=True),
        sa.Column("baseline_fetch_id", sa.String(), nullable=False),
        sa.Column("diff", sa.JSON(), nullable=False),
        sa.Column("triage_status", sa.String(), nullable=False),
        sa.Column("triage_result", sa.JSON(), nullable=True),
        sa.Column("review_decision", sa.String(), nullable=False),
        sa.Column("verdict", sa.String(), nullable=True),
        sa.Column("analysis_state", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["page_id"], ["watched_pages.id"]),
        sa.ForeignKeyConstraint(["fetch_id"], ["served_fetches.id"]),
        sa.ForeignKeyConstraint(["previous_fetch_id"], ["served_fetches.id"]),
        sa.ForeignKeyConstraint(["baseline_fetch_id"], ["served_fetches.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("page_id", "user_agent", "fingerprint"),
    )
    # The homepage is always a Watched page (A10), with no Baseline until the Operator accepts one.
    pages = sa.table(
        "watched_pages", sa.column("id"), sa.column("application_id"), sa.column("url"), sa.column("homepage"),
        sa.column("baseline", sa.JSON), sa.column("created_at"),
    )
    created = datetime.now(timezone.utc)
    rows = [{"id": str(uuid.uuid4()), "application_id": ident, "url": url, "homepage": True, "baseline": {},
             "created_at": created}
            for ident, url in op.get_bind().execute(sa.text("SELECT id, asset_url FROM applications"))]
    if rows:
        op.bulk_insert(pages, rows)


def downgrade():
    op.drop_table("served_changes")
    op.drop_table("served_fetches")
    op.drop_table("watched_pages")
