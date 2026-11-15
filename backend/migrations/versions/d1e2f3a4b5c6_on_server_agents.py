"""On-server agents (B04, ADR-0007): agents, enrollment_codes, agent_requests, agent_messages and
dashboard_keys, and asset_monitor_agent's grants (ADR-0006 decision 5): read agents' ids, keys,
status and wanted lists, Enrollment code ids, agents and expiry, and the signed messages; insert
agent requests without received_at. Nothing on dashboard_keys."""

from alembic import op
import sqlalchemy as sa

revision = "d1e2f3a4b5c6"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None

# Backend tests migrate into schemas where PUBLIC has no USAGE, so the schema is granted by name.
SCHEMA_USAGE = "DO $$ BEGIN EXECUTE format('{} USAGE ON SCHEMA %I {} asset_monitor_agent', current_schema()); END $$"
GRANTS = (
    "GRANT SELECT (id, public_key, status, wanted) ON agents TO asset_monitor_agent",
    "GRANT SELECT (id, agent_id, expires_at, used_at) ON enrollment_codes TO asset_monitor_agent",
    "GRANT SELECT (agent_id, type, sequence, key_id, payload, signature, status, expires_at)"
    " ON agent_messages TO asset_monitor_agent",
    "GRANT INSERT (id, agent_id, route, method, target, timestamp, nonce, content_sha256, signature, body)"
    " ON agent_requests TO asset_monitor_agent",
)


def upgrade():
    op.create_table(
        "agents",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("key_id", sa.String(), nullable=True),
        sa.Column("allowed_paths", sa.JSON(), nullable=False),
        sa.Column("watched_roots", sa.JSON(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("config_sequence", sa.Integer(), nullable=False),
        sa.Column("report_sequence", sa.Integer(), nullable=False),
        sa.Column("wanted", sa.JSON(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_refusal", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "enrollment_codes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("secret_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "agent_requests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("route", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("timestamp", sa.BigInteger(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("content_sha256", sa.String(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "nonce"),
    )
    op.create_table(
        "agent_messages",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "sequence"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_table(
        "dashboard_keys",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(SCHEMA_USAGE.format("GRANT", "TO"))
    for grant in GRANTS:
        op.execute(grant)


def downgrade():
    """Dropping the tables drops their grants. Drops no role (ADR-0006 decision 8)."""
    for table in ("dashboard_keys", "agent_messages", "agent_requests", "enrollment_codes", "agents"):
        op.drop_table(table)
    op.execute(SCHEMA_USAGE.format("REVOKE", "FROM"))
