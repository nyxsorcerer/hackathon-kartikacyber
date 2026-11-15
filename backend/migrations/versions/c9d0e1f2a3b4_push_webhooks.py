"""Push webhooks (B02): push_webhooks and push_deliveries, and asset_monitor_push's grants on them
(ADR-0006 decision 5): read push_webhooks, update only its last_accepted and last_refusal, and
insert into push_deliveries."""

from alembic import op
import sqlalchemy as sa

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None

# Backend tests migrate into schemas where PUBLIC has no USAGE, so the schema is granted by name.
SCHEMA_USAGE = "DO $$ BEGIN EXECUTE format('{} USAGE ON SCHEMA %I {} asset_monitor_push', current_schema()); END $$"


def upgrade():
    op.create_table(
        "push_webhooks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("repository_id", sa.String(), nullable=False),
        sa.Column("push_id", sa.String(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_accepted", sa.JSON(), nullable=True),
        sa.Column("last_refusal", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("repository_id"),
        sa.UniqueConstraint("push_id"),
    )
    op.create_table(
        "push_deliveries",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("push_webhook_id", sa.String(), nullable=False),
        sa.Column("delivery_id", sa.String(), nullable=False),
        sa.Column("body_sha256", sa.String(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["push_webhook_id"], ["push_webhooks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("delivery_id"),
        sa.UniqueConstraint("body_sha256"),
    )
    op.execute(SCHEMA_USAGE.format("GRANT", "TO"))
    op.execute("GRANT SELECT ON push_webhooks TO asset_monitor_push")
    op.execute("GRANT UPDATE (last_accepted, last_refusal) ON push_webhooks TO asset_monitor_push")
    op.execute("GRANT INSERT ON push_deliveries TO asset_monitor_push")


def downgrade():
    """Dropping the tables drops their grants. Drops no role (ADR-0006 decision 8)."""
    op.drop_table("push_deliveries")
    op.drop_table("push_webhooks")
    op.execute(SCHEMA_USAGE.format("REVOKE", "FROM"))
