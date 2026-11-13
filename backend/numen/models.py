import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid():
    return str(uuid.uuid4())


def now():
    return datetime.now(timezone.utc)


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


class Base(DeclarativeBase):
    pass


class Operator(Base):
    __tablename__ = "operators"
    id: Mapped[str] = mapped_column(String, primary_key=True, default="admin")
    password_hash: Mapped[str] = mapped_column(Text)


class LoginSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    csrf_token: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Setting(Base):
    __tablename__ = "settings"
    id: Mapped[str] = mapped_column(String, primary_key=True, default="global")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    label: Mapped[str] = mapped_column(String)
    provider: Mapped[str] = mapped_column(String)
    auth_type: Mapped[str] = mapped_column(String)
    credential: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Plugin(Base):
    __tablename__ = "plugins"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    asset_name: Mapped[str] = mapped_column(String)
    asset_url: Mapped[str] = mapped_column(Text)
    product_kind: Mapped[str] = mapped_column(String)
    product_name: Mapped[str] = mapped_column(String)
    # The generation of its source repository, which version recipes, observations and audit
    # contexts belong to.
    source_generation: Mapped[int] = mapped_column(Integer, default=1)
    monitor_interval_seconds: Mapped[int] = mapped_column(Integer)
    monitor_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    cve_cursor: Mapped[dict] = mapped_column(JSON, default=dict)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Repository(Base):
    """An Own or Upstream repository, stored once per source URL and polled once for every
    Application that links it."""

    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    source_kind: Mapped[str] = mapped_column(String)
    source_url: Mapped[str] = mapped_column(Text, unique=True)
    # ponytail: slug, ref and path are set when the row is created and never edited, so every
    # Application linking this URL shares the first one's branch and subpath; key the row by
    # (url, ref, path) if Applications need different ones.
    plugin_slug: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    source_path: Mapped[str | None] = mapped_column(String, nullable=True)
    source_generation: Mapped[int] = mapped_column(Integer, default=1)
    cursor: Mapped[str | None] = mapped_column(String, nullable=True)
    # The ETag of the last GitHub commit list, sent as If-None-Match on the next poll.
    etag: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The Release branches polled besides the default branch: {branch: {cursor, etag}}.
    watched_branches: Mapped[dict] = mapped_column(JSON, default=dict)
    baseline_revision: Mapped[str | None] = mapped_column(String, nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApplicationRepository(Base):
    __tablename__ = "application_repositories"
    __table_args__ = (
        UniqueConstraint("application_id", "repository_id"),
        Index(
            "uq_application_own_repository",
            "application_id",
            unique=True,
            postgresql_where=text("role = 'own' AND removed_at IS NULL"),
            sqlite_where=text("role = 'own' AND removed_at IS NULL"),
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    role: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_version: Mapped[str | None] = mapped_column(String, nullable=True)
    # manifest, operator or deployed
    locked_version_source: Mapped[str | None] = mapped_column(String, nullable=True)
    # The Release branch found for release_branch_version (None: none exists). A different
    # Locked version is resolved again on the next check.
    release_branch: Mapped[str | None] = mapped_column(String, nullable=True)
    release_branch_version: Mapped[str | None] = mapped_column(String, nullable=True)
    # A derived Upstream link: the packages it stands for, such as "npm:react". Hand-added: [].
    packages: Mapped[list] = mapped_column(JSON, default=list)
    # The Own link: the revision its Upstream repositories were last derived from, and the
    # packages that could not be mapped to one: [{ecosystem, name, version, reason}].
    derived_revision: Mapped[str | None] = mapped_column(String, nullable=True)
    unresolved: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Commit(Base):
    __tablename__ = "commits"
    __table_args__ = (UniqueConstraint("repository_id", "source_generation", "revision"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    source_generation: Mapped[int] = mapped_column(Integer)
    revision: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    triage_status: Mapped[str] = mapped_column(String, default="disabled")
    triage_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    review_decision: Mapped[str] = mapped_column(String, default="pending")
    # The newest Analysis's Verdict, and where the latest Analysis job stands (queued, completed,
    # failed or timed_out).
    verdict: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class Snapshot(Base):
    __tablename__ = "source_snapshots"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    source_generation: Mapped[int] = mapped_column(Integer)
    source_ref: Mapped[str] = mapped_column(String)
    files: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    kind: Mapped[str] = mapped_column(String)
    subject_id: Mapped[str] = mapped_column(String)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    input_hash: Mapped[str] = mapped_column(String)
    profile: Mapped[dict] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class VersionRecipe(Base):
    __tablename__ = "version_recipes"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    source_generation: Mapped[int] = mapped_column(Integer)
    source_ref: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Observation(Base):
    __tablename__ = "version_observations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    recipe_id: Mapped[str | None] = mapped_column(ForeignKey("version_recipes.id"), nullable=True)
    source_generation: Mapped[int] = mapped_column(Integer)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    data: Mapped[dict] = mapped_column(JSON)


class AuditContext(Base):
    __tablename__ = "audit_contexts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    source_generation: Mapped[int] = mapped_column(Integer)
    source_ref: Mapped[str] = mapped_column(String)
    skill_revision: Mapped[str] = mapped_column(String)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CVE(Base):
    __tablename__ = "cves"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    raw: Mapped[dict] = mapped_column(JSON)
    record_hash: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON)


class ApplicationCVE(Base):
    __tablename__ = "application_cves"
    __table_args__ = (UniqueConstraint("application_id", "cve_id"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id"))
    confirmed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    source: Mapped[str] = mapped_column(String)
    cve_id: Mapped[str | None] = mapped_column(ForeignKey("cves.id"), nullable=True)
    title: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="open")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_revision: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    resource_type: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    resource_type: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String)
    revision: Mapped[str] = mapped_column(String)
    path: Mapped[str] = mapped_column(String)
    storage_path: Mapped[str] = mapped_column(String)
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String)
    content_type: Mapped[str] = mapped_column(String, default="application/octet-stream")


class LabRun(Base):
    __tablename__ = "lab_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    artifact_revision: Mapped[str] = mapped_column(String)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    status: Mapped[str] = mapped_column(String, default="queued")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String, index=True)
    application_id: Mapped[str | None] = mapped_column(ForeignKey("applications.id"), nullable=True)
    status: Mapped[str] = mapped_column(String, index=True, default="queued")
    input: Mapped[dict] = mapped_column(JSON, default=dict)
    input_hash: Mapped[str] = mapped_column(String)
    idempotency_key: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    profile: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String, nullable=True)
    attempt_token: Mapped[str | None] = mapped_column(String, nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    broker_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class JobEvent(Base):
    __tablename__ = "job_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Transcript(Base):
    """The stored record of one agent run (its prompt, reply and metadata) with secrets removed.
    `subject_id` is what the run judged, such as the commit a Triage run belongs to."""

    __tablename__ = "transcripts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    kind: Mapped[str] = mapped_column(String)
    subject_id: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class JobAttempt(Base):
    __tablename__ = "job_attempts"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    status: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Notification(Base):
    __tablename__ = "notification_outbox"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    event_key: Mapped[str] = mapped_column(String, unique=True)
    status: Mapped[str] = mapped_column(String, default="pending")
    data: Mapped[dict] = mapped_column(JSON)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
