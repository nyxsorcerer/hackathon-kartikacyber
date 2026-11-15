"""Ingress database roles (B01): asset_monitor_push and asset_monitor_agent, created NOLOGIN when
missing and granted nothing. `python -m numen.cli ingress-roles` gives each LOGIN and a password."""

from alembic import op

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "DO $$ BEGIN"
        " IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'asset_monitor_push')"
        " THEN CREATE ROLE asset_monitor_push NOLOGIN; END IF;"
        " IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'asset_monitor_agent')"
        " THEN CREATE ROLE asset_monitor_agent NOLOGIN; END IF;"
        " END $$"
    )


def downgrade():
    """Drops no role (ADR-0006 decision 8): roles belong to the whole cluster, where other schemas,
    the ingress-roles step and restore.sh rely on them."""
