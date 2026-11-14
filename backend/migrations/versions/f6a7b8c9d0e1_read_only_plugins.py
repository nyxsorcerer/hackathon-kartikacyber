"""Read-only Pi plugins (A13): the plugin list is runner/plugins.lock.json's, so the table that kept
the Operator's enable or disable choice goes"""

from alembic import op
import sqlalchemy as sa

revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("plugins")


def downgrade():
    # Recreated empty: the older code reseeds it from the manifest on start.
    op.create_table(
        "plugins",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
