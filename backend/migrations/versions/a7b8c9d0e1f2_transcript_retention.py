"""Transcript retention (A14): each Transcript's size, which bounds the Triage ones to 256 MB, and
an index on what it is about, which retention looks up by Finding"""

from alembic import op
import sqlalchemy as sa

revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("transcripts", sa.Column("size", sa.Integer(), nullable=False, server_default="0"))
    # Every existing Transcript is a Triage one, whose size is its stored data's.
    op.execute("UPDATE transcripts SET size = octet_length(CAST(data AS TEXT))")
    op.alter_column("transcripts", "size", server_default=None)
    op.create_index("ix_transcripts_subject_id", "transcripts", ["subject_id"])


def downgrade():
    op.drop_index("ix_transcripts_subject_id", table_name="transcripts")
    op.drop_column("transcripts", "size")
