"""Remediation PRs (A08), one per (Application, subject, action)"""

from alembic import op
import sqlalchemy as sa

revision = "b19c0dd5e4f9"
down_revision = "a08b9cb4d3e8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_prs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("repository_id", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("base_ref", sa.String(), nullable=True),
        sa.Column("diff", sa.Text(), nullable=True),
        sa.Column("diff_sha256", sa.String(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.PrimaryKeyConstraint("id"),
        # ADR-0004's idempotency key: at most one Remediation PR per (Application, subject, action).
        sa.UniqueConstraint("application_id", "subject", "action"),
    )


def downgrade():
    op.drop_table("remediation_prs")
