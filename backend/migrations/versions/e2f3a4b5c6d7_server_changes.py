"""File manifests, Server changes and the agent's Baseline (B05). No ingress role gets a grant on
them: the agent listener reads only agents' wanted lists (d1e2f3a4b5c6)."""

from alembic import op
import sqlalchemy as sa

revision = "e2f3a4b5c6d7"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "file_manifests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("config_sequence", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("entries", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("incomplete", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "sequence"),
    )
    op.create_table(
        "server_changes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("manifest_id", sa.String(), nullable=False),
        sa.Column("baseline_manifest_id", sa.String(), nullable=False),
        sa.Column("diff", sa.JSON(), nullable=False),
        sa.Column("incomplete", sa.JSON(), nullable=False),
        sa.Column("triage_status", sa.String(), nullable=False),
        sa.Column("triage_result", sa.JSON(), nullable=True),
        sa.Column("review_decision", sa.String(), nullable=False),
        sa.Column("verdict", sa.String(), nullable=True),
        sa.Column("analysis_state", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["manifest_id"], ["file_manifests.id"]),
        sa.ForeignKeyConstraint(["baseline_manifest_id"], ["file_manifests.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "fingerprint"),
    )
    op.add_column("agents", sa.Column("baseline_manifest_id", sa.String(), nullable=True))
    op.create_foreign_key("fk_agents_baseline_manifest_id", "agents", "file_manifests",
                          ["baseline_manifest_id"], ["id"])


def downgrade():
    """Refused while any Finding has the server_files source, which the release before cannot hold."""
    findings = sa.table("findings", sa.column("id", sa.String()), sa.column("source", sa.String()))
    kept = op.get_bind().execute(sa.select(findings.c.id).where(findings.c.source == "server_files")
                                 .order_by(findings.c.id)).scalars().all()
    if kept:
        raise RuntimeError(
            f"Findings {', '.join(kept)} have the server_files source, which this release cannot hold."
            " Restore the backup taken before the upgrade instead."
        )
    op.drop_constraint("fk_agents_baseline_manifest_id", "agents", type_="foreignkey")
    op.drop_column("agents", "baseline_manifest_id")
    op.drop_table("server_changes")
    op.drop_table("file_manifests")
