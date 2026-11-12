"""Release branches watched per repository, and monitoring intervals in seconds"""

from alembic import op
import sqlalchemy as sa

revision = "6c4d5e7f8094"
down_revision = "5b3c4d6e7f83"
branch_labels = None
depends_on = None

DAY = 86400
settings = sa.table("settings", sa.column("id", sa.String()), sa.column("data", sa.JSON()))


def rename_setting(old, new, convert):
    bind = op.get_bind()
    for row in bind.execute(sa.select(settings.c.id, settings.c.data)).all():
        data = dict(row.data or {})
        if old in data:
            value = data.pop(old)
            data[new] = None if value is None else convert(value)
            bind.execute(settings.update().where(settings.c.id == row.id).values(data=data))


def upgrade():
    op.add_column(
        "repositories",
        sa.Column("watched_branches", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.alter_column("repositories", "watched_branches", server_default=None)
    op.add_column("application_repositories", sa.Column("release_branch", sa.String(), nullable=True))
    op.add_column(
        "application_repositories", sa.Column("release_branch_version", sa.String(), nullable=True)
    )
    op.add_column("applications", sa.Column("monitor_interval_seconds", sa.Integer(), nullable=True))
    op.execute(f"UPDATE applications SET monitor_interval_seconds = monitor_interval_days * {DAY}")
    op.alter_column("applications", "monitor_interval_seconds", nullable=False)
    op.drop_column("applications", "monitor_interval_days")
    rename_setting("monitor_interval_days", "monitor_interval_seconds", lambda days: days * DAY)


def downgrade():
    # Days round up, so an interval under a day stays valid (at least 1) under the old schema.
    rename_setting("monitor_interval_seconds", "monitor_interval_days", lambda seconds: max(1, -(-seconds // DAY)))
    op.add_column("applications", sa.Column("monitor_interval_days", sa.Integer(), nullable=True))
    op.execute(
        f"UPDATE applications SET monitor_interval_days = GREATEST(1, CEIL(monitor_interval_seconds / {DAY}.0))"
    )
    op.alter_column("applications", "monitor_interval_days", nullable=False)
    op.drop_column("applications", "monitor_interval_seconds")
    op.drop_column("application_repositories", "release_branch_version")
    op.drop_column("application_repositories", "release_branch")
    op.drop_column("repositories", "watched_branches")
