"""rename program to application"""

import hashlib
import json

from alembic import op
import sqlalchemy as sa

revision = "3f1a2b4c5d61"
down_revision = "fe74f85e4023"
branch_labels = None
depends_on = None

OWNED = (
    "commits",
    "source_snapshots",
    "analyses",
    "version_recipes",
    "version_observations",
    "audit_contexts",
    "application_cves",
    "findings",
    "jobs",
)


def rename_constraints(old, new):
    # Postgres keeps the generated names (programs_pkey, commits_program_id_fkey, ...) across renames.
    names = op.get_bind().execute(
        sa.text(
            "SELECT conrelid::regclass::text, conname FROM pg_constraint"
            " WHERE connamespace = to_regnamespace(current_schema()) AND conname LIKE :pattern"
        ),
        {"pattern": f"%{old}%"},
    )
    for table, name in names.all():
        op.execute(f'ALTER TABLE {table} RENAME CONSTRAINT "{name}" TO "{name.replace(old, new)}"')


def rehash_jobs(old, new):
    # A job's input_hash fingerprints its owner under the column's name; keep idempotency keys valid.
    def digest(row, key):
        value = {"kind": row.kind, key: row.application_id, "input": row.input, "profile": row.profile}
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()

    jobs = sa.table(
        "jobs",
        sa.column("id", sa.String),
        sa.column("kind", sa.String),
        sa.column("application_id", sa.String),
        sa.column("input", sa.JSON),
        sa.column("profile", sa.JSON),
        sa.column("input_hash", sa.String),
    )
    bind = op.get_bind()
    for row in bind.execute(sa.select(jobs)).all():
        if row.input_hash == digest(row, old):
            bind.execute(
                jobs.update().where(jobs.c.id == row.id).values(input_hash=digest(row, new))
            )


def upgrade():
    op.rename_table("programs", "applications")
    op.rename_table("program_cves", "application_cves")
    for table in OWNED:
        op.alter_column(table, "program_id", new_column_name="application_id")
    rename_constraints("program", "application")
    rehash_jobs("program_id", "application_id")
    op.execute("UPDATE actions SET resource_type = 'application' WHERE resource_type = 'program'")


def downgrade():
    op.execute("UPDATE actions SET resource_type = 'program' WHERE resource_type = 'application'")
    rehash_jobs("application_id", "program_id")
    rename_constraints("application", "program")
    for table in OWNED:
        op.alter_column(table, "application_id", new_column_name="program_id")
    op.rename_table("application_cves", "program_cves")
    op.rename_table("applications", "programs")
