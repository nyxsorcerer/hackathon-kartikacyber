"""Advisory check (A09): each Application's collected pins, its matches by (Application,
vulnerability), and the feeds' response cache"""

from alembic import op
import sqlalchemy as sa

revision = "d3f4a5b6c7e8"
down_revision = "c2b3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("applications", sa.Column("advisory_pins", sa.JSON(), nullable=True))
    op.create_table(
        "advisory_matches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("vulnerability", sa.String(), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "vulnerability"),
    )
    op.create_table(
        "advisory_cache",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("etag", sa.Text(), nullable=True),
        sa.Column("modified", sa.String(), nullable=True),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade():
    op.drop_table("advisory_cache")
    op.drop_table("advisory_matches")
    op.drop_column("applications", "advisory_pins")
