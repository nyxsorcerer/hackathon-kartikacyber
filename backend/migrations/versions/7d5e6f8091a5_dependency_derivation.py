"""application_repositories keep what Upstream derivation from the Own repository found"""

from alembic import op
import sqlalchemy as sa

revision = "7d5e6f8091a5"
down_revision = "6c4d5e7f8094"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("packages", "unresolved"):
        op.add_column(
            "application_repositories", sa.Column(name, sa.JSON(), nullable=False, server_default="[]")
        )
        op.alter_column("application_repositories", name, server_default=None)
    op.add_column("application_repositories", sa.Column("derived_revision", sa.String(), nullable=True))


def downgrade():
    for name in ("derived_revision", "unresolved", "packages"):
        op.drop_column("application_repositories", name)
