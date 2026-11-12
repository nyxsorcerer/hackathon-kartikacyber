"""repositories keep the ETag of their last GitHub commit list"""

from alembic import op
import sqlalchemy as sa

revision = "5b3c4d6e7f83"
down_revision = "4a2b3c5d6e72"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("repositories", sa.Column("etag", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("repositories", "etag")
