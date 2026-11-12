"""repositories stored once per source URL and linked to Applications"""

import uuid
from datetime import datetime, timedelta, timezone
from itertools import groupby

from alembic import op
import sqlalchemy as sa

revision = "4a2b3c5d6e72"
down_revision = "3f1a2b4c5d61"
branch_labels = None
depends_on = None

MOVED = ("source_kind", "source_url", "source_ref", "source_path", "plugin_slug", "cursor", "last_error")


def source_url(row):
    if row.source_kind == "wordpress":
        return f"https://plugins.svn.wordpress.org/{row.plugin_slug}"
    return row.source_url.rstrip("/").removesuffix(".git").lower()


def upgrade():
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("source_kind", sa.String(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("plugin_slug", sa.String(), nullable=True),
        sa.Column("source_ref", sa.String(), nullable=True),
        sa.Column("source_path", sa.String(), nullable=True),
        sa.Column("source_generation", sa.Integer(), nullable=False),
        sa.Column("cursor", sa.String(), nullable=True),
        sa.Column("baseline_revision", sa.String(), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_url"),
    )
    op.create_table(
        "application_repositories",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("application_id", sa.String(), nullable=False),
        sa.Column("repository_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_version", sa.String(), nullable=True),
        sa.Column("locked_version_source", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "repository_id"),
    )
    op.create_index(
        "uq_application_own_repository",
        "application_repositories",
        ["application_id"],
        unique=True,
        postgresql_where=sa.text("role = 'own' AND removed_at IS NULL"),
    )
    for table in ("commits", "source_snapshots"):
        op.add_column(
            table,
            sa.Column("repository_id", sa.String(), sa.ForeignKey("repositories.id"), nullable=True),
        )

    bind = op.get_bind()
    applications = bind.execute(sa.text(
        "SELECT id, source_kind, source_url, source_ref, source_path, plugin_slug, source_generation,"
        " cursor, last_check_at, last_error FROM applications"
        " ORDER BY last_check_at NULLS FIRST, id"
    )).all()
    repositories = sa.table(
        "repositories", *(sa.column(name) for name in (
            "id", "source_kind", "source_url", "plugin_slug", "source_ref", "source_path",
            "source_generation", "cursor", "baseline_revision", "last_check_at", "created_at",
        )), sa.column("last_error", sa.JSON),
    )
    links = sa.table("application_repositories", *(sa.column(name) for name in (
        "id", "application_id", "repository_id", "role", "enabled", "locked_version",
        "locked_version_source", "created_at",
    )))
    observations = sa.table(
        "version_observations", sa.column("application_id"), sa.column("source_generation"),
        sa.column("checked_at"), sa.column("data", sa.JSON),
    )
    jobs = sa.table("jobs", sa.column("id"), sa.column("kind"), sa.column("status"),
                    sa.column("application_id"), sa.column("input", sa.JSON))
    created = datetime.now(timezone.utc)
    moved = {}
    # Programs sharing one source become one repository. The most recently checked one is
    # canonical; the others' history moves to earlier generations, so it never collides.
    for url, group in groupby(sorted(applications, key=source_url), key=source_url):
        group = list(group)  # A stable sort keeps the check order within each group.
        # The repository keeps one branch and subpath; refuse to drop another Program's.
        if len({(r.source_ref or None, r.source_path or None) for r in group}) > 1:
            raise RuntimeError(
                f"Programs {', '.join(r.id for r in group)} share {url} with different branches or"
                " subpaths. Give them the same source_ref and source_path, or move them to separate"
                " sources, then run the migration again."
            )
        ident, offset, canonical = str(uuid.uuid4()), 0, group[-1]
        generation = sum(r.source_generation for r in group)
        bind.execute(repositories.insert().values(
            id=ident, source_kind=canonical.source_kind, source_url=url,
            plugin_slug=canonical.plugin_slug, source_ref=canonical.source_ref,
            source_path=canonical.source_path, source_generation=generation,
            cursor=canonical.cursor, baseline_revision=canonical.cursor,
            last_check_at=canonical.last_check_at, last_error=canonical.last_error, created_at=created,
        ))
        for row in group:
            for table in ("commits", "source_snapshots"):
                bind.execute(
                    sa.text(f"UPDATE {table} SET repository_id = :repository,"
                            " source_generation = source_generation + :offset"
                            " WHERE application_id = :application"),
                    {"repository": ident, "offset": offset, "application": row.id},
                )
            offset += row.source_generation
            detected = next((
                o for o in bind.execute(
                    sa.select(observations.c.data).where(
                        observations.c.application_id == row.id,
                        observations.c.source_generation == row.source_generation,
                    ).order_by(observations.c.checked_at.desc())
                ).all()
                if (o.data or {}).get("status") == "detected" and o.data.get("version")
            ), None)
            # Distinct times keep "the first linked Application" in check order.
            bind.execute(links.insert().values(
                id=str(uuid.uuid4()), application_id=row.id, repository_id=ident, role="upstream",
                enabled=True, locked_version=detected.data["version"] if detected else None,
                locked_version_source="deployed" if detected else None,
                created_at=created + timedelta(microseconds=len(moved)),
            ))
            moved[row.id] = (ident, generation)
    # A queued check polls the repository now, at the repository's generation.
    for job in bind.execute(sa.select(jobs).where(
        jobs.c.kind == "source_check", jobs.c.status.in_(["queued", "running", "cancelling"])
    )).all():
        if job.application_id in moved:
            ident, generation = moved[job.application_id]
            bind.execute(jobs.update().where(jobs.c.id == job.id).values(input={
                **(job.input or {}), "repository_id": ident, "source_generation": generation,
            }))

    for table in ("commits", "source_snapshots"):
        op.alter_column(table, "repository_id", nullable=False)
        # Postgres drops the column's foreign key and the commits unique constraint with it.
        op.drop_column(table, "application_id")
    op.create_unique_constraint(
        "commits_repository_id_source_generation_revision_key",
        "commits",
        ["repository_id", "source_generation", "revision"],
    )
    for name in MOVED:
        op.drop_column("applications", name)


def downgrade():
    """Moves each repository back onto the one Application that links it. Refused when an
    Application links several repositories, or a repository is linked by several Applications
    (merged Programs or repositories shared since): their sources cannot be split again."""
    bind = op.get_bind()
    shared = bind.execute(sa.text(
        "SELECT a.id FROM applications a LEFT JOIN application_repositories l ON l.application_id = a.id"
        " GROUP BY a.id HAVING count(l.id) <> 1"
        " UNION SELECT l.application_id FROM application_repositories l WHERE l.repository_id IN ("
        "SELECT repository_id FROM application_repositories GROUP BY repository_id HAVING count(*) > 1)"
    )).scalars().all()
    if shared:
        raise RuntimeError(
            f"Applications {', '.join(sorted(shared))} link no repository, several, or one that"
            " another Application also links, so they cannot become Programs again. Restore the"
            " backup taken before the upgrade instead."
        )
    for name in MOVED:
        kind = sa.JSON() if name == "last_error" else sa.Text() if name == "source_url" else sa.String()
        op.add_column("applications", sa.Column(name, kind, nullable=True))
    op.execute(
        "UPDATE applications a SET " + ", ".join(f"{name} = r.{name}" for name in MOVED)
        + " FROM application_repositories l JOIN repositories r ON r.id = l.repository_id"
        " WHERE l.application_id = a.id"
    )
    op.alter_column("applications", "source_kind", nullable=False)
    for table in ("commits", "source_snapshots"):
        op.add_column(
            table,
            sa.Column(
                "application_id",
                sa.String(),
                sa.ForeignKey("applications.id", name=f"{table}_application_id_fkey"),
                nullable=True,
            ),
        )
        op.execute(
            f"UPDATE {table} t SET application_id = l.application_id FROM application_repositories l"
            " WHERE l.repository_id = t.repository_id"
        )
        op.alter_column(table, "application_id", nullable=False)
        op.drop_column(table, "repository_id")
    op.create_unique_constraint(
        "commits_application_id_source_generation_revision_key",
        "commits",
        ["application_id", "source_generation", "revision"],
    )
    op.drop_table("application_repositories")
    op.drop_table("repositories")
