"""transcripts keep each Triage run's prompt, reply and metadata"""

from alembic import op
import sqlalchemy as sa

revision = "8e6f7a92b1c6"
down_revision = "7d5e6f8091a5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "transcripts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("transcripts")
