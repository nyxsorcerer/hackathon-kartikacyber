"""Exposure (A05), one per (Application, Upstream Verdict's commit)"""

from alembic import op
import sqlalchemy as sa

revision = "c2b3d4e5f6a7"
down_revision = "b19c0dd5e4f9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "exposures",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("repository_id", sa.String(), nullable=False),
        sa.Column("commit_id", sa.String(), nullable=False),
        sa.Column("verdict", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.ForeignKeyConstraint(["commit_id"], ["commits.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "commit_id"),
    )


def downgrade():
    op.drop_table("exposures")
