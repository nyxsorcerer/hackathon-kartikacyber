import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
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
    # The pins the last Advisory check collected (A09): {repository_id, revision, collected_at,
    # feeds, runtimes, packages}. Deferred, so lists and the scheduler never load a large lockfile's.
    advisory_pins: Mapped[dict | None] = mapped_column(JSON, nullable=True, deferred=True)


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


class PushWebhook(Base):
    """B02: the Push webhook of an Own repository, reached at /push/<push id>. The ingress role reads
    it and writes only last_accepted ({at, event: push or ping, delivery_id}) and last_refusal
    ({at, reason}: wrong_signature, event_not_accepted, body_too_large, delivery_id_missing or
    rate_limited)."""

    __tablename__ = "push_webhooks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), unique=True)
    # 32 lowercase hex characters.
    push_id: Mapped[str] = mapped_column(String, unique=True)
    # The Push webhook secret, Vault(NUMEN_INGRESS_KEY).encrypt(secret).
    secret: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_accepted: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_refusal: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class PushDelivery(Base):
    """B02: an accepted Push delivery, once per delivery id and per body SHA-256. The nudge sets
    processed_at and prunes rows older than 7 days, so a body is unique among the last 7 days."""

    __tablename__ = "push_deliveries"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    push_webhook_id: Mapped[str] = mapped_column(ForeignKey("push_webhooks.id"))
    delivery_id: Mapped[str] = mapped_column(String, unique=True)
    body_sha256: Mapped[str] = mapped_column(String, unique=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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


class RemediationPR(Base):
    """A Remediation PR (A08), from its draft diff through its Approval to the pull request opened
    from that diff. (application_id, subject, action) is ADR-0004's idempotency key: approving
    twice or recovering a crashed job finds this row and opens at most one pull request."""

    __tablename__ = "remediation_prs"
    __table_args__ = (UniqueConstraint("application_id", "subject", "action"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    # The Own repository, the only one a Remediation PR is opened on.
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    # The Commit's id; a vulnerability for an Advisory check.
    subject: Mapped[str] = mapped_column(String)
    # patch, revert, pin or bump
    action: Mapped[str] = mapped_column(String)
    # drafting, waiting_for_cap, draft_failed, ready, approved, failed, open, merged or closed
    status: Mapped[str] = mapped_column(String, default="drafting")
    # The revision the diff applies to.
    base_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff_sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    # revision, summary, paths, flags, error, job_id, dependency, branch, pull_number, pull_url,
    # head_sha, merge_commit_sha
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Exposure(Base):
    """Whether an Upstream Verdict on a commit reaches an Application (A05), from tag containment at
    its Locked version. A not-exposed one is recorded here only: it opens no Finding."""

    __tablename__ = "exposures"
    __table_args__ = (UniqueConstraint("application_id", "commit_id"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"))
    commit_id: Mapped[str] = mapped_column(ForeignKey("commits.id"))
    verdict: Mapped[str] = mapped_column(String)
    # exposed, not_exposed or unknown (which counts as exposed)
    state: Mapped[str] = mapped_column(String)
    # reason, locked_version, tag, target ({tag, version} a pin or bump would move to, or None),
    # analysis_id
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AdvisoryMatch(Base):
    """An Advisory check match (A09), one per (Application, vulnerability): `vulnerability` is the
    canonical id of the alias set, and `aliases` holds every OSV, GHSA and CVE id in it."""

    __tablename__ = "advisory_matches"
    __table_args__ = (UniqueConstraint("application_id", "vulnerability"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    vulnerability: Mapped[str] = mapped_column(String)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    # exposed, unknown (which counts as exposed) or not_exposed
    state: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AdvisoryCache(Base):
    """A feed response the Advisory check fetched, by request key, with what revalidates it."""

    __tablename__ = "advisory_cache"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    etag: Mapped[str | None] = mapped_column(Text, nullable=True)
    modified: Mapped[str | None] = mapped_column(String, nullable=True)
    body: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class WatchedPage(Base):
    """A Watched page of an Application's Asset (A10): the homepage (its Asset URL, always one) or a
    page the Operator added on the Asset URL's origin. `baseline` holds each user agent's accepted
    Content fingerprint: {user agent: {fetch_id, fingerprint, accepted_at}}."""

    __tablename__ = "watched_pages"
    __table_args__ = (UniqueConstraint("application_id", "url"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    url: Mapped[str] = mapped_column(Text)
    homepage: Mapped[bool] = mapped_column(Boolean, default=False)
    baseline: Mapped[dict] = mapped_column(JSON, default=dict)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ServedFetch(Base):
    """One user agent's fetch of a Watched page in a Served-content check (A10). Its bytes are
    stored as served_content Artifacts keyed by their sha256; `resources` lists them:
    [{kind: page|script, url, final_url, status, sha256, size, content_type, error}]."""

    __tablename__ = "served_fetches"
    __table_args__ = (Index("ix_served_fetches_page_id_user_agent_created_at", "page_id", "user_agent", "created_at"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    page_id: Mapped[str] = mapped_column(ForeignKey("watched_pages.id"))
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    user_agent: Mapped[str] = mapped_column(String)
    # fetched, or failed: the page did not answer 200
    status: Mapped[str] = mapped_column(String)
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    resources: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ServedChange(Base):
    """A served-content change (A10): a Content fingerprint unlike the Baseline, one per (page, user
    agent, fingerprint), so each distinct fingerprint is triaged at most once. Its Triage and
    Analysis fields are named as Commit's."""

    __tablename__ = "served_changes"
    __table_args__ = (UniqueConstraint("page_id", "user_agent", "fingerprint"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    page_id: Mapped[str] = mapped_column(ForeignKey("watched_pages.id"))
    user_agent: Mapped[str] = mapped_column(String)
    fingerprint: Mapped[str] = mapped_column(String)
    # The first fetch that served it, the newest fetched one before that, and the Baseline's.
    fetch_id: Mapped[str] = mapped_column(ForeignKey("served_fetches.id"))
    previous_fetch_id: Mapped[str | None] = mapped_column(ForeignKey("served_fetches.id"), nullable=True)
    baseline_fetch_id: Mapped[str] = mapped_column(ForeignKey("served_fetches.id"))
    diff: Mapped[dict] = mapped_column(JSON, default=dict)
    triage_status: Mapped[str] = mapped_column(String, default="disabled")
    triage_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    review_decision: Mapped[str] = mapped_column(String, default="pending")
    verdict: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Agent(Base):
    """B04: an On-server agent of an Application. Its id is also its X-Agent-Id. The status goes
    awaiting_enrollment -> pending (an Enrollment bound its key) -> enrolled (the Operator confirmed
    the fingerprint) -> revoked. `sequence` is the one per-agent counter of signed configurations
    and commands; `data` holds {version, os, arch, poll}; `last_refusal` is {at, route, reason}.
    The agent role reads only id, public_key, status and wanted."""

    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    name: Mapped[str] = mapped_column(String)
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="awaiting_enrollment")
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    # The Dashboard key id it pinned, set at confirmation.
    key_id: Mapped[str | None] = mapped_column(String, nullable=True)
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)
    watched_roots: Mapped[list] = mapped_column(JSON, default=list)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    config_sequence: Mapped[int] = mapped_column(Integer, default=0)
    report_sequence: Mapped[int] = mapped_column(Integer, default=0)
    # The File manifest the Operator accepted as the Baseline (B05); data.baseline_accepted_at says when.
    baseline_manifest_id: Mapped[str | None] = mapped_column(ForeignKey("file_manifests.id", use_alter=True, name="fk_agents_baseline_manifest_id"), nullable=True)
    # The unsigned wanted list (B05): {report_sequence, sha256: [...]}.
    wanted: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_refusal: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FileManifest(Base):
    """B05: a verified report of an On-server agent. `entries` is every root's entries flattened and
    sorted, each {root, path, type, sha256, size, mode, uid, gid, mtime, target?, secret?,
    over_hash_limit?}; `sha256` is the hex SHA-256 of their canonical JSON, which a Baseline request
    names. `incomplete` lists why it is not whole ({reason, root?, path?}). It is awaiting_uploads
    until the agent sends its wanted bytes, or 10 minutes pass, then complete. request_id has no
    foreign key: processed requests are pruned."""

    __tablename__ = "file_manifests"
    __table_args__ = (UniqueConstraint("agent_id", "sequence"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    request_id: Mapped[str] = mapped_column(String)
    sequence: Mapped[int] = mapped_column(Integer)
    config_sequence: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    entries: Mapped[list] = mapped_column(JSON, default=list)
    sha256: Mapped[str] = mapped_column(String)
    incomplete: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="awaiting_uploads")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ServerChange(Base):
    """B05: a Server change, a complete File manifest unlike the agent's Baseline by path, type,
    SHA-256, mode, owner or link target (never mtime alone), one per (agent, fingerprint), so each
    distinct one is triaged at most once. `diff` is {added: [entry], modified: [{before, after}],
    removed: [entry]}; `incomplete` lists why it is not whole. Its Triage and Analysis fields are
    named as ServedChange's."""

    __tablename__ = "server_changes"
    __table_args__ = (UniqueConstraint("agent_id", "fingerprint"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    fingerprint: Mapped[str] = mapped_column(String)
    # The first manifest that showed it, and the Baseline it was compared with.
    manifest_id: Mapped[str] = mapped_column(ForeignKey("file_manifests.id"))
    baseline_manifest_id: Mapped[str] = mapped_column(ForeignKey("file_manifests.id"))
    diff: Mapped[dict] = mapped_column(JSON, default=dict)
    incomplete: Mapped[list] = mapped_column(JSON, default=list)
    triage_status: Mapped[str] = mapped_column(String, default="disabled")
    triage_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    review_decision: Mapped[str] = mapped_column(String, default="pending")
    verdict: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class EnrollmentCode(Base):
    """B04: a one-time Enrollment code, `<id>.<secret>`. Only the hex SHA-256 of the secret part is
    stored; it is good for one use within one hour."""

    __tablename__ = "enrollment_codes"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    secret_hash: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AgentRequest(Base):
    """B04: an agent request the agent listener accepted, stored exactly as received, Enrollments
    included. Postgres sets received_at, which the agent role cannot write. Application code
    verifies it again, then sets processed_at and outcome ({status: accepted|refused, reason})."""

    __tablename__ = "agent_requests"
    __table_args__ = (UniqueConstraint("agent_id", "nonce"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    route: Mapped[str] = mapped_column(String)  # enroll, poll, report, upload or result
    method: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[int] = mapped_column(BigInteger)
    nonce: Mapped[str] = mapped_column(String)
    content_sha256: Mapped[str] = mapped_column(String)
    signature: Mapped[str] = mapped_column(Text)
    body: Mapped[bytes] = mapped_column(LargeBinary)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AgentMessage(Base):
    """B04: a configuration or Agent command signed with the Dashboard key, as the envelope the
    agent receives (payload and signature, standard base64). A command's id is its command_id; it
    expires_at 15 minutes after it is signed, and `data` holds its result."""

    __tablename__ = "agent_messages"
    __table_args__ = (UniqueConstraint("agent_id", "sequence"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    type: Mapped[str] = mapped_column(String)  # configuration or command
    sequence: Mapped[int] = mapped_column(Integer)
    key_id: Mapped[str] = mapped_column(String)
    payload: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(String, nullable=True)  # rescan, quarantine or restore
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # pending, done, refused, expired or cancelled
    status: Mapped[str] = mapped_column(String, default="pending")
    idempotency_key: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class DashboardKey(Base):
    """B04: the Ed25519 key that signs every configuration and Agent command. Its private half
    (the base64 seed) is Vault(NUMEN_SIGNING_KEY)-encrypted; only the app holds that key."""

    __tablename__ = "dashboard_keys"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    public_key: Mapped[str] = mapped_column(Text)
    private_key: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    `subject_id` is what the run judged, such as the commit a Triage run belongs to, or for a CVE
    Analysis, which runs per Application, `<application id>:<CVE id>`. `size` is
    its stored bytes: a Triage one's data as JSON, an Analysis one's transcript.txt."""

    __tablename__ = "transcripts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    kind: Mapped[str] = mapped_column(String)
    subject_id: Mapped[str] = mapped_column(String, index=True)
    data: Mapped[dict] = mapped_column(JSON)
    size: Mapped[int] = mapped_column(Integer, default=0)
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
