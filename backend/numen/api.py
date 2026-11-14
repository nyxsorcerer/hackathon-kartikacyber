import hmac
import json
import zipfile
import secrets
import shutil
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse, quote

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import and_, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError

from . import artifacts, cves, domain, prompts
from .broker import Broker
from .config import Config
from .db import make_database
from .models import (
    Account,
    Action,
    AdvisoryMatch,
    Analysis,
    Artifact,
    AuditContext,
    Commit,
    CVE,
    Finding,
    Job,
    JobAttempt,
    JobEvent,
    LabRun,
    LoginSession,
    Notification,
    Observation,
    Operator,
    Plugin,
    Application,
    ApplicationCVE,
    ApplicationRepository,
    RemediationPR,
    Repository,
    VersionRecipe,
    now,
    utc,
)
from .schemas import (
    AccountInput,
    ApprovalInput,
    BackfillInput,
    BatchAnalysisInput,
    BatchDeleteInput,
    BatchReviewInput,
    FindingInput,
    LoginCodeInput,
    LoginInput,
    MAX_INTERVAL,
    MIN_INTERVAL,
    ManualObservation,
    MatchInput,
    OPERATIONS,
    OperationInput,
    ApplicationInput,
    PromptInput,
    PromptPreviewInput,
    RemediationApprovalInput,
    RemediationDraftInput,
    RepositoryInput,
    RepositoryPatch,
    ReviewInput,
    SessionInput,
    TransitionInput,
    http_url,
)
from .security import (
    DomainError,
    Vault,
    hash_password,
    normalize_native_cache,
    RequestLimits,
    token_hash,
    verify_password,
)
from .queue import RUNTIME_EVENTS, runtime_phases
from .workflows import all_secrets

# The only artifacts of an Upstream Proof the page may read (A15): its report and Disclosure report.
REPORTS = ("report.md", "disclosure-report.md")


def accepted(job):
    return JSONResponse({"job_id": job.id, "status_url": f"/api/jobs/{job.id}"}, status_code=202)


ACTIVE_JOB = ["queued", "running", "cancelling"]


def create_app(database_url=None, artifact_root=None, admin_password=None, config=None):
    config = config or Config.from_env()
    if database_url:
        config.database_url = database_url
    if artifact_root:
        config.artifact_root = Path(artifact_root)
    test_setup = admin_password is not None
    engine, factory = make_database(config, initialize=test_setup)
    if admin_password:
        with factory.begin() as db:
            if not db.get(Operator, "admin"):
                db.add(Operator(id="admin", password_hash=hash_password(admin_password)))
    vault = Vault(config.secret_key)
    broker = Broker(config)
    attempts = defaultdict(deque)

    @asynccontextmanager
    async def lifespan(app):
        with factory.begin() as db:
            domain.settings(db, config)
            domain.plugin_records(db)
        yield
        engine.dispose()

    app = FastAPI(title="Numen", lifespan=lifespan)
    app.add_middleware(RequestLimits)
    app.state.config, app.state.factory, app.state.vault = config, factory, vault

    @app.exception_handler(DomainError)
    async def domain_error(_request, exc):
        return JSONResponse(exc.as_dict(), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def request_error(_request, exc):
        fields = {".".join(str(v) for v in e["loc"][1:]): e["msg"] for e in exc.errors()}
        return JSONResponse(
            {
                "code": "validation_error",
                "message": "Check the supplied fields",
                "fields": fields,
                "retryable": False,
            },
            status_code=422,
        )

    @app.exception_handler(ValidationError)
    async def schema_error(_request, exc):
        fields = {".".join(str(v) for v in e["loc"]): e["msg"] for e in exc.errors()}
        return JSONResponse(
            {
                "code": "validation_error",
                "message": "Check the supplied fields",
                "fields": fields,
                "retryable": False,
            },
            status_code=422,
        )

    @app.exception_handler(IntegrityError)
    async def conflict_error(_request, _exc):
        return JSONResponse(
            {
                "code": "record_conflict",
                "message": "The record conflicts with existing data",
                "retryable": False,
            },
            status_code=409,
        )

    def database():
        with factory() as db:
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise

    # One cached session for auth and route; commit/rollback before any response is sent.
    database_dependency = Depends(database, scope="function")

    def session_for(request, db):
        token = request.cookies.get("numen_session", "")
        row = db.get(LoginSession, token_hash(token)) if token else None
        return row if row and utc(row.expires_at) > now() else None

    def auth(request: Request, db=database_dependency):
        row = session_for(request, db)
        if not row:
            raise DomainError("unauthenticated", "Sign in to continue", 401)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            csrf = request.headers.get("X-CSRF-Token", "")
            if not csrf or not hmac.compare_digest(csrf, row.csrf_token):
                raise DomainError("csrf_required", "A valid CSRF token is required", 403)
        return row

    def paginate(db, stmt, mapper, cursor=None, limit=50, page_mapper=None):
        try:
            offset = int(cursor or "0")
            if offset < 0 or offset > 1000000 or not 1 <= limit <= 200:
                raise ValueError
        except ValueError as exc:
            raise DomainError("invalid_cursor", "Invalid pagination cursor or limit", 422) from exc
        rows = list(db.scalars(stmt.offset(offset).limit(limit + 1)))
        page = rows[:limit]
        if page_mapper:  # Shared lookups for the whole page instead of one per row.
            mapper = page_mapper(page)
        return {
            "items": [mapper(row) for row in page],
            "next_cursor": str(offset + limit) if len(rows) > limit else None,
        }

    def commit_page(db):
        def mapper(page):
            ids = [c.id for c in page]
            findings, exposures = domain.commit_findings(db, ids), domain.commit_exposures(db, ids)
            return lambda c: domain.commit_json(db, c, findings, exposures)

        return mapper

    def action(db, resource_type, ident, data):
        db.add(Action(resource_type=resource_type, resource_id=ident, data=data))

    def throttle(request, scope, code, message):
        """At most 10 attempts per client address in 60 s for each scope (login, approval)."""
        recent = attempts[(scope, request.client.host if request.client else "unknown")]
        while recent and recent[0] < time.monotonic() - 60:
            recent.popleft()
        if len(recent) >= 10:
            raise DomainError(code, message, 429, retryable=True)
        recent.append(time.monotonic())

    def approval(request, db, password):
        """An Approval (A15): the Operator's password, checked on this very request. There is
        no window: every Approval, also one straight after another, carries its own password."""
        throttle(request, "approval", "approval_rate_limited", "Wait before approving again")
        operator = db.get(Operator, "admin")
        # 403, not 401: a refused Approval must not sign the Operator out.
        if not password or not operator or not verify_password(password, operator.password_hash):
            raise DomainError("approval_refused", "The password is incorrect; nothing was approved", 403)

    @app.get("/api/health")
    def health(db=database_dependency):
        db.execute(text("SELECT 1"))
        return {"status": "ok"}

    @app.get("/api/auth/session")
    def session(request: Request, db=database_dependency):
        row = session_for(request, db)
        return (
            {"authenticated": True, "username": "admin", "csrf_token": row.csrf_token}
            if row
            else {"authenticated": False}
        )

    @app.post("/api/auth/login")
    def login(body: LoginInput, request: Request, response: Response, db=database_dependency):
        throttle(request, "login", "login_rate_limited", "Wait before trying to sign in again")
        operator = db.get(Operator, "admin")
        if (
            body.username != "admin"
            or not operator
            or not verify_password(body.password, operator.password_hash)
        ):
            raise DomainError("invalid_credentials", "Username or password is incorrect", 401)
        previous = session_for(request, db)
        if previous:
            db.delete(previous)
        token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        db.add(
            LoginSession(
                id=token_hash(token), csrf_token=csrf, expires_at=now() + timedelta(days=1)
            )
        )
        response.set_cookie(
            "numen_session",
            token,
            httponly=True,
            secure=config.cookie_secure,
            samesite="strict",
            max_age=86400,
            path="/",
        )
        return {"authenticated": True, "username": "admin", "csrf_token": csrf}

    router = APIRouter(prefix="/api", dependencies=[Depends(auth)])

    @router.post("/auth/logout")
    def logout(response: Response, row=Depends(auth), db=database_dependency):
        db.delete(row)
        response.delete_cookie("numen_session", path="/")
        return {"authenticated": False}

    @router.get("/dashboard")
    def dashboard(db=database_dependency):
        def count(cls, *conditions):
            return db.scalar(select(func.count()).select_from(cls).where(*conditions))

        eligible = sum(
            1
            for link in db.scalars(select(ApplicationCVE))
            if cves.gate(
                domain.get(db, Application, link.application_id), domain.get(db, CVE, link.cve_id), link
            )["eligible"]
        )
        recent = list(
            db.scalars(
                # Runtime plumbing belongs on a job's own timeline, not in the activity feed.
                select(JobEvent)
                .where(JobEvent.data["kind"].as_string().not_in(sorted(RUNTIME_EVENTS)))
                .order_by(JobEvent.created_at.desc())
                .limit(20)
            )
        )
        # The Review queue: Insufficient context Verdicts the Operator has not judged yet.
        # ponytail: sorted in Python because committed_at lives in commit data; index it if it grows.
        queue = sorted(
            db.scalars(
                select(Commit).where(
                    Commit.verdict == "Insufficient context", Commit.review_decision == "pending"
                )
            ),
            key=lambda c: c.data.get("committed_at") or "",
            reverse=True,
        )
        due = list(
            db.scalars(
                select(Application)
                .where(
                    Application.archived.is_(False),
                    Application.monitor_enabled.is_(True),
                    (Application.next_check_at <= now()) | (Application.next_check_at.is_(None)),
                )
                .limit(20)
            )
        )
        return {
            "applications": count(Application, Application.archived.is_(False)),
            "security_reviews": count(Commit, Commit.review_decision == "candidate"),
            "eligible_cves": eligible,
            "open_findings": count(Finding, Finding.status == "open"),
            "running_jobs": count(Job, Job.status.in_(["queued", "running", "cancelling"])),
            "failed_jobs": count(Job, Job.status == "failed"),
            "recent_events": [
                {"id": e.id, "job_id": e.job_id, "created_at": utc(e.created_at), **e.data}
                for e in recent
            ],
            "due_applications": [domain.application_json(db, p) for p in due],
            "review_queue": [
                {
                    "id": c.id,
                    "title": domain.commit_label(c),
                    "revision": c.revision,
                    "application_id": getattr(domain.commit_application(db, c), "id", None),
                    "committed_at": c.data.get("committed_at"),
                }
                for c in queue[:20]
            ],
            "review_queue_count": len(queue),
        }

    @router.get("/applications")
    def applications(
        q: str | None = None, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        stmt = select(Application).order_by(Application.asset_name, Application.id)
        if q:
            query = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            linked = (
                select(ApplicationRepository.application_id)
                .join(Repository, Repository.id == ApplicationRepository.repository_id)
                .where(
                    or_(
                        Repository.source_url.ilike(query, escape="\\"),
                        Repository.plugin_slug.ilike(query, escape="\\"),
                    )
                )
            )
            stmt = stmt.where(
                or_(
                    *(
                        getattr(Application, field).ilike(query, escape="\\")
                        for field in ("asset_name", "asset_url", "product_name")
                    ),
                    Application.id.in_(linked),
                )
            )
        return paginate(
            db,
            stmt,
            lambda p: domain.application_json(db, p),
            cursor,
            limit,
        )

    @router.post("/applications", status_code=201)
    def create_application(body: ApplicationInput, db=database_dependency):
        data = body.model_dump()
        seconds = data.get("monitor_interval_seconds") or domain.settings(db, config).data.get(
            "monitor_interval_seconds"
        )
        if not seconds:
            raise DomainError(
                "monitor_interval_required",
                "Set a global monitoring interval or enter one for this Application",
                422,
                {"monitor_interval_seconds": "Enter an interval or configure the global default"},
            )
        data["config"]["monitor_interval_inherited"] = data.get("monitor_interval_seconds") is None
        data["monitor_interval_seconds"] = seconds
        for operation, profile in data["config"]["profiles"].items():
            domain.resolve_profile(db, None, operation, profile)
        application = Application(**data, next_check_at=now())
        db.add(application)
        db.flush()
        action(db, "application", application.id, {"action": "created"})
        return domain.application_json(db, application)

    @router.get("/applications/{ident}")
    def application(ident: str, db=database_dependency):
        return domain.application_json(db, domain.get(db, Application, ident))

    @router.patch("/applications/{ident}")
    def patch_application(ident: str, body: dict, db=database_dependency):
        row = domain.get(db, Application, ident)
        current = {name: getattr(row, name) for name in ApplicationInput.model_fields}
        if "config" in body:
            if not isinstance(body["config"], dict):
                raise DomainError("validation_error", "Application config must be an object", 422)
            body = {**body, "config": {**current["config"], **body["config"]}}
        data = ApplicationInput.model_validate({**current, **body}).model_dump()
        if "monitor_interval_seconds" in body:
            inherited = body["monitor_interval_seconds"] is None
            data["config"]["monitor_interval_inherited"] = inherited
            if inherited:
                data["monitor_interval_seconds"] = domain.settings(db, config).data.get(
                    "monitor_interval_seconds"
                )
        if not data["monitor_interval_seconds"]:
            raise DomainError(
                "monitor_interval_required", "Configure a global interval before inheriting it", 422
            )
        for operation, profile in data["config"]["profiles"].items():
            if profile != row.config.get("profiles", {}).get(operation):
                domain.resolve_profile(db, row, operation, profile)
        if data["config"].get("active_recipe_id"):
            recipe = domain.get(db, VersionRecipe, data["config"]["active_recipe_id"])
            if recipe.application_id != row.id or recipe.source_generation != row.source_generation:
                raise DomainError(
                    "invalid_recipe", "Recipe must belong to this Application's source", 422
                )
        restored = row.archived and not data["archived"]
        for name, value in data.items():
            setattr(row, name, value)
        row.next_check_at = now() if row.monitor_enabled and not row.archived else None
        action(db, "application", row.id, {"action": "updated"})
        for _, repository in domain.links(db, row) if restored else ():
            domain.queue_exposure(db, row, repository)  # Verdicts stored while it was archived (A05)
        for linked in db.scalars(select(ApplicationCVE).where(ApplicationCVE.application_id == row.id)):
            domain.refresh_cve_policy(db, row, domain.get(db, CVE, linked.cve_id), linked)
        return domain.application_json(db, row)

    def application_link(db, ident, repository_id):
        link = db.scalar(
            select(ApplicationRepository).where(
                ApplicationRepository.application_id == ident,
                ApplicationRepository.repository_id == repository_id,
            )
        )
        if link is None:
            raise DomainError("not_found", "This repository is not linked to this Application", 404)
        return link

    def changed_link(db, application, link, previous, change):
        db.flush()
        domain.source_changed(db, application, previous.id if previous else None)
        action(db, "application", application.id, {"repository_id": link.repository_id, **change})
        return domain.link_json(link, db.get(Repository, link.repository_id))

    @router.post("/applications/{ident}/repositories", status_code=201)
    def add_repository(ident: str, body: RepositoryInput, db=database_dependency):
        application = domain.get(db, Application, ident)
        previous = domain.source_repository(db, application)
        current = {link.repository_id: link for link, _ in domain.links(db, application)}
        if body.role == "own" and any(
            link.role == "own" and link.removed_at is None for link in current.values()
        ):
            raise DomainError(
                "own_repository_exists",
                "This Application already has an Own repository; remove it first",
                409,
            )
        repository = domain.repository_for(
            db, body.source_url, **body.model_dump(exclude={"role", "locked_version", "source_url"})
        )
        link = current.get(repository.id)
        if link and link.removed_at is None:
            raise DomainError(
                "repository_linked", "This repository is already linked to this Application", 409
            )
        if link is None:
            link = ApplicationRepository(application_id=application.id, repository_id=repository.id)
            db.add(link)
        # A removed link is restored with its history, as a hand-added link: derivation state
        # from its earlier role is dropped.
        link.role, link.enabled, link.removed_at = body.role, True, None
        link.packages, link.derived_revision, link.unresolved = [], None, []
        link.locked_version = body.locked_version or None
        link.locked_version_source = "operator" if link.locked_version else None
        if application.monitor_enabled and not application.archived:
            application.next_check_at = now()
        if body.role == "own" and repository.cursor and link.derived_revision is None:
            # Already past its Baseline for another Application: derive its Upstream repositories
            # now, since an unchanged repository answers 304 and queues nothing.
            domain.enqueue(
                db,
                "derive_upstreams",
                application,
                domain.repository_input(repository),
                idempotency_key=f"derive:{application.id}:{repository.cursor}",
            )
        linked = changed_link(
            db, application, link, previous, {"action": "repository_added", "role": body.role}
        )
        domain.queue_exposure(db, application, repository)  # an Upstream link, new or restored (A05)
        return linked

    @router.patch("/applications/{ident}/repositories/{repository_id}")
    def patch_repository(
        ident: str, repository_id: str, body: RepositoryPatch, db=database_dependency
    ):
        application = domain.get(db, Application, ident)
        link = application_link(db, ident, repository_id)
        previous = domain.source_repository(db, application)
        turned_on = body.enabled and not link.enabled
        if body.enabled is not None:
            link.enabled = body.enabled
            if body.enabled and application.monitor_enabled and not application.archived:
                application.next_check_at = now()  # a link turned on gets its Baseline now
        relocked = "locked_version" in body.model_fields_set and link.locked_version != (body.locked_version or None)
        if "locked_version" in body.model_fields_set:
            link.locked_version = body.locked_version or None
            link.locked_version_source = "operator" if link.locked_version else None
        changed = changed_link(
            db, application, link, previous,
            {"action": "repository_updated", "changes": body.model_dump(exclude_unset=True)},
        )
        if relocked or turned_on:
            # A05: a Locked version changed, or a link turned on missed the Verdicts stored while it was off.
            domain.queue_exposure(db, application, db.get(Repository, repository_id))
        return changed

    @router.delete("/applications/{ident}/repositories/{repository_id}")
    def remove_repository(ident: str, repository_id: str, db=database_dependency):
        """Removes the link; the repository's commits stay in the Application's history."""
        application = domain.get(db, Application, ident)
        link = application_link(db, ident, repository_id)
        previous = domain.source_repository(db, application)
        link.removed_at = link.removed_at or now()
        return changed_link(db, application, link, previous, {"action": "repository_removed"})

    @router.post("/applications/{ident}/repositories/{repository_id}/backfills")
    def backfill_repository(
        ident: str, repository_id: str, body: BackfillInput, db=database_dependency
    ):
        """Backfill: imports and triages the last `count` commits up to the Baseline."""
        application = domain.get(db, Application, ident)
        application_link(db, ident, repository_id)
        repository = db.get(Repository, repository_id)
        if repository.baseline_revision is None:
            raise DomainError(
                "source_not_checked", "Check this repository once to set its Baseline first", 422
            )
        return accepted(domain.enqueue(
            db, "backfill", application, domain.repository_input(repository, count=body.count)
        ))

    @router.post("/applications/{ident}/checks")
    def check_application(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        """Check now: one source check per polled repository, reusing a check already active."""
        row = domain.get(db, Application, ident)
        repositories = domain.active_repositories(db, row)
        if not repositories:
            raise DomainError(
                "repository_required", "Link a repository to this Application first", 422
            )
        items = []
        for repository in repositories:
            item_key = f"{key}:{repository.id}" if key else None
            job = (
                item_key and db.scalar(select(Job).where(Job.idempotency_key == item_key))
            ) or domain.active_source_check(db, repository) or domain.enqueue(
                db, "source_check", row, domain.repository_input(repository), idempotency_key=item_key
            )
            items.append(
                {"repository_id": repository.id, "job_id": job.id, "status_url": f"/api/jobs/{job.id}"}
            )
        row.last_check_at = now()
        row.next_check_at = now() + timedelta(seconds=row.monitor_interval_seconds)
        return JSONResponse({"items": items}, status_code=202)

    @router.get("/commits")
    def all_commits(
        application_id: str | None = None,
        review_decision: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(Commit).order_by(Commit.id)
        if application_id:
            stmt = stmt.where(Commit.repository_id.in_(domain.linked_repository_ids(application_id)))
        if review_decision:
            stmt = stmt.where(Commit.review_decision == review_decision)
        return paginate(db, stmt, None, cursor, limit, commit_page(db))

    @router.get("/applications/{ident}/commits")
    def application_commits(
        ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        domain.get(db, Application, ident)
        return paginate(
            db,
            select(Commit)
            .where(Commit.repository_id.in_(domain.linked_repository_ids(ident)))
            .order_by(Commit.id),
            None,
            cursor,
            limit,
            commit_page(db),
        )

    @router.get("/commits/{ident}")
    def commit(ident: str, db=database_dependency):
        return domain.commit_json(db, domain.get(db, Commit, ident))

    def record_review(db, row, decision):
        row.review_decision = decision
        action(db, "commit", row.id, {"action": "review", "decision": decision})

    @router.post("/commits/review")
    def review_batch(body: BatchReviewInput, db=database_dependency):
        """Applies one decision to many revisions atomically; unknown ids change nothing."""
        ids = list(dict.fromkeys(body.ids))
        rows = {c.id: c for c in db.scalars(select(Commit).where(Commit.id.in_(ids)))}
        missing = [i for i in ids if i not in rows]
        if missing:
            raise DomainError(
                "not_found", f"{len(missing)} of {len(ids)} commits were not found", 404
            )
        items = []
        for ident in ids:
            row = rows[ident]
            previous = row.review_decision
            if previous != body.decision:
                record_review(db, row, body.decision)
            items.append({"id": ident, "previous": previous, "review_decision": body.decision})
        return {"items": items}

    @router.post("/commits/{ident}/review")
    def review(ident: str, body: ReviewInput, db=database_dependency):
        row = domain.get(db, Commit, ident)
        record_review(db, row, body.decision)
        return domain.commit_json(db, row)

    def queue_commit_analysis(db, row, application, profile, key):
        job = domain.submit_agent(
            db,
            "commit_analysis",
            application,
            {"commit_id": row.id, "source_ref": row.revision},
            profile.model_dump() if profile else None,
            key,
        )
        if job.status == "queued":  # An idempotent replay may return a finished job.
            row.analysis_state = {"status": "queued", "job_id": job.id}
        action(db, "commit", row.id, {"action": "analysis_requested", "job_id": job.id})
        return job

    @router.post("/commits/analyses")
    def analyze_batch(
        body: BatchAnalysisInput,
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        """Queues one commit analysis per revision. A revision from an earlier source generation,
        or one already being analyzed, is skipped and reported; an unknown id or an unusable
        profile queues nothing."""
        ids = list(dict.fromkeys(body.ids))
        rows = {c.id: c for c in db.scalars(select(Commit).where(Commit.id.in_(ids)))}
        missing = [i for i in ids if i not in rows]
        if missing:
            raise DomainError(
                "not_found", f"{len(missing)} of {len(ids)} commits were not found", 404
            )
        commit_id = Job.input["commit_id"].as_string()
        active = set(
            db.scalars(
                select(commit_id).where(
                    Job.kind == "commit_analysis",
                    Job.status.in_(ACTIVE_JOB),
                    commit_id.in_(ids),
                )
            )
        )
        items = []
        for ident in ids:
            row = rows[ident]
            application = domain.commit_application(db, row)
            # Each revision has its own key, so a resubmitted batch returns the same jobs.
            item_key = f"{key}:{ident}" if key else None
            replay = item_key and db.scalar(select(Job).where(Job.idempotency_key == item_key))
            if replay:
                items.append({"id": ident, "job_id": replay.id, "skipped": None})
            elif row.source_generation != db.get(Repository, row.repository_id).source_generation:
                items.append({"id": ident, "job_id": None, "skipped": "historical_source"})
            elif ident in active:
                items.append({"id": ident, "job_id": None, "skipped": "analysis_active"})
            else:
                job = queue_commit_analysis(db, row, application, body.profile, item_key)
                items.append({"id": ident, "job_id": job.id, "skipped": None})
        return JSONResponse({"items": items}, status_code=202)

    @router.post("/commits/{ident}/analyses")
    def analyze_commit(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Commit, ident)
        application = domain.commit_application(db, row)
        if row.source_generation != db.get(Repository, row.repository_id).source_generation:
            raise DomainError(
                "historical_source",
                "This commit belongs to a previous source generation; current source context cannot analyze it",
                422,
            )
        return accepted(queue_commit_analysis(db, row, application, body.profile, key))

    @router.get("/applications/{ident}/version-recipes")
    def recipes(ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency):
        domain.get(db, Application, ident)
        return paginate(
            db,
            select(VersionRecipe)
            .where(VersionRecipe.application_id == ident)
            .order_by(VersionRecipe.created_at.desc()),
            lambda r: {
                "id": r.id,
                "created_at": utc(r.created_at),
                "status": r.status,
                "source_ref": r.source_ref,
                "source_generation": r.source_generation,
                "metadata": r.data.get("metadata"),
                "profile": r.data.get("profile"),
                "artifacts": domain.artifact_rows(db, "recipe", r.id),
            },
            cursor,
            limit,
        )

    @router.post("/applications/{ident}/version-recipes")
    def generate_recipe(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Application, ident)
        return accepted(
            domain.submit_agent(
                db,
                "version_recipe",
                row,
                submitted=body.profile.model_dump() if body.profile else None,
                key=key,
            )
        )

    @router.post("/applications/{ident}/version-checks")
    def version_check(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        row = domain.get(db, Application, ident)
        if not row.config.get("active_recipe_id"):
            raise DomainError(
                "recipe_required", "Generate and validate a reusable recipe first", 422
            )
        return accepted(
            domain.enqueue(
                db,
                "version_check",
                row,
                domain.job_input(db, row, recipe_id=row.config["active_recipe_id"]),
                idempotency_key=key,
            )
        )

    @router.get("/applications/{ident}/advisories")
    def application_advisories(ident: str, db=database_dependency):
        """The runtime and package pins the last Advisory check collected (A09)."""
        return domain.advisories_json(db, domain.get(db, Application, ident))

    @router.post("/applications/{ident}/advisory-checks")
    def run_advisory_check(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        """The Advisory check, now: it reads the head of the Own repository, else the source repository."""
        row = domain.get(db, Application, ident)
        repository = domain.advisory_repository(db, row)
        if repository is None:
            raise DomainError("repository_required", "Link a repository to this Application first", 422)
        if repository.cursor is None:
            raise DomainError("source_not_checked", "Check this repository once to set its Baseline first", 422)
        return accepted(domain.queue_advisory(db, row, repository, key))

    @router.get("/applications/{ident}/version-observations")
    def observations(
        ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        domain.get(db, Application, ident)
        return paginate(
            db,
            select(Observation)
            .where(Observation.application_id == ident)
            .order_by(Observation.checked_at.desc()),
            domain.observation_json,
            cursor,
            limit,
        )

    @router.post("/applications/{ident}/version-observations", status_code=201)
    def observe(ident: str, body: ManualObservation, db=database_dependency):
        application = domain.get(db, Application, ident)
        row = Observation(
            application_id=application.id,
            source_generation=application.source_generation,
            data={
                "status": "detected",
                "version": body.version,
                "candidates": [],
                "method": "manual",
                "origin": "manual",
                "evidence": body.evidence if isinstance(body.evidence, list) else [body.evidence],
                "confidence": {"level": "operator", "basis": "Manually supplied evidence"},
                "limitations": [],
            },
        )
        db.add(row)
        db.flush()
        return domain.observation_json(row)

    @router.get("/applications/{ident}/audit-contexts")
    def contexts(ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency):
        domain.get(db, Application, ident)
        return paginate(
            db,
            select(AuditContext)
            .where(AuditContext.application_id == ident)
            .order_by(AuditContext.created_at.desc()),
            lambda r: {
                "id": r.id,
                "source_ref": r.source_ref,
                "source_generation": r.source_generation,
                "skill_revision": r.skill_revision,
                "coverage": r.coverage,
                "status": r.status,
                "job_id": r.job_id,
                "created_at": utc(r.created_at),
                "artifacts": domain.artifact_rows(
                    db, "audit", r.id, r.coverage.get("artifact_revision")
                ),
            },
            cursor,
            limit,
        )

    @router.post("/applications/{ident}/audit-contexts")
    def generate_context(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Application, ident)
        inputs = {
            "focus": body.focus,
            "max_functions": body.max_functions,
            **({"fresh": True} if body.fresh else {}),
        }
        if body.refresh_from:
            base = db.get(AuditContext, body.refresh_from)
            if base is None or base.application_id != row.id:
                raise DomainError("not_found", "There is no such audit context for this Application", 404)
            # A refresh keeps the scope the context was built with.
            inputs = domain.audit_refresh_input(db, row, base)
        return accepted(
            domain.submit_agent(
                db,
                "audit_context",
                row,
                inputs,
                body.profile.model_dump() if body.profile else None,
                key,
            )
        )

    @router.get("/cves")
    def cve_list(
        application_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(ApplicationCVE).order_by(ApplicationCVE.cve_id, ApplicationCVE.application_id)
        if application_id:
            domain.get(db, Application, application_id)
            stmt = stmt.where(ApplicationCVE.application_id == application_id)
        return paginate(
            db,
            stmt,
            lambda link: domain.cve_json(db, domain.get(db, CVE, link.cve_id), link),
            cursor,
            limit,
        )

    def application_cve(db, ident, cve_id):
        application, cve = domain.get(db, Application, ident), domain.get(db, CVE, cve_id)
        link = db.scalar(
            select(ApplicationCVE).where(ApplicationCVE.application_id == ident, ApplicationCVE.cve_id == cve_id)
        )
        if not link:
            raise DomainError("not_found", "CVE is not associated with this Application", 404)
        return application, cve, link

    @router.post("/applications/{ident}/cves/{cve_id}/analyses")
    def analyze_cve(
        ident: str,
        cve_id: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        application, cve, link = application_cve(db, ident, cve_id)
        return accepted(
            domain.queue_cve(
                db,
                application,
                cve,
                link,
                body.profile.model_dump() if body.profile else None,
                key,
                body.source_ref,
            )
        )

    @router.post("/applications/{ident}/cves/{cve_id}/match")
    def confirm_cve(ident: str, cve_id: str, body: MatchInput, db=database_dependency):
        application, cve, link = application_cve(db, ident, cve_id)
        link.confirmed = body.confirmed
        action(db, "cve", link.id, {"action": "match_confirmed", "confirmed": body.confirmed})
        domain.refresh_cve_policy(db, application, cve, link)
        return domain.cve_json(db, cve, link)

    @router.post("/applications/{ident}/cve-sync")
    def cve_sync(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        application = domain.get(db, Application, ident)
        return accepted(
            domain.enqueue(db, "cve_sync", application, domain.job_input(db, application), idempotency_key=key)
        )

    @router.get("/findings")
    def findings(
        application_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        view: Literal["full", "summary"] = "full",
        db=database_dependency,
    ):
        stmt = select(Finding).order_by(Finding.created_at.desc())
        if application_id:
            stmt = stmt.where(Finding.application_id == application_id)
        if view == "summary":
            page = paginate(db, stmt, lambda row: row, cursor, limit)
            page["items"] = domain.finding_summaries(db, page["items"], config.artifact_root)
            return page
        return paginate(
            db, stmt, lambda f: domain.finding_json(db, f, config.artifact_root), cursor, limit
        )

    def validate_finding_refs(db, body):
        domain.get(db, Application, body.application_id)
        if body.cve_id:
            application_cve(db, body.application_id, body.cve_id)
        commit = domain.get(db, Commit, body.source_commit_id) if body.source_commit_id else None
        analysis = domain.get(db, Analysis, body.source_analysis_id) if body.source_analysis_id else None
        if (
            commit
            and commit.repository_id
            not in set(db.scalars(domain.linked_repository_ids(body.application_id)))
        ) or (analysis and not domain.analysis_reaches(db, analysis, body.application_id)):
            raise DomainError(
                "invalid_reference", "Finding evidence must belong to the same Application", 422
            )

    @router.post("/findings", status_code=201)
    def create_finding(body: FindingInput, db=database_dependency):
        validate_finding_refs(db, body)
        data = body.model_dump()
        commit = db.get(Commit, body.source_commit_id) if body.source_commit_id else None
        row = Finding(
            **{k: data.pop(k) for k in ("application_id", "source", "cve_id", "title")},
            status="open",
            data={
                **data,
                "cause": {"by": "operator", "at": now().isoformat()},
                "source_ref": commit.revision[:7] if commit else body.cve_id,
            },
        )
        db.add(row)
        db.flush()
        action(
            db,
            "finding",
            row.id,
            {"action": "created", "source": row.source, "cve_id": row.cve_id, "status": row.status},
        )
        return domain.finding_json(db, row, config.artifact_root)

    @router.get("/findings/{ident}")
    def finding(ident: str, db=database_dependency):
        return domain.finding_json(db, domain.get(db, Finding, ident), config.artifact_root)

    @router.patch("/findings/{ident}")
    def patch_finding(ident: str, body: dict, db=database_dependency):
        row = domain.get(db, Finding, ident)
        db.refresh(row, with_for_update=True)
        current = {
            "application_id": row.application_id,
            "source": row.source,
            "cve_id": row.cve_id,
            "title": row.title,
            **domain.finding_data(row),
        }
        # Only editable fields: the lifecycle, its cause and private keys stay as they are.
        old = {k: v for k, v in current.items() if k in FindingInput.model_fields}
        data = FindingInput.model_validate({**old, **body})
        validate_finding_refs(db, data)
        if data.application_id != row.application_id:
            raise DomainError("immutable_application", "A finding cannot move to another Application", 422)
        if data.source != row.source:
            raise DomainError("immutable_source", "A Finding's source cannot change", 422)
        values = data.model_dump(exclude={"application_id", "source"})
        row.cve_id, row.title = values.pop("cve_id"), values.pop("title")
        if row.source == "cve":
            values["source_ref"] = row.cve_id
        elif row.source == "commit":  # As create_finding sets it.
            commit = db.get(Commit, data.source_commit_id) if data.source_commit_id else None
            values["source_ref"] = commit.revision[:7] if commit else row.cve_id
        row.data, row.updated_at = {**row.data, **values}, now()
        action(
            db,
            "finding",
            row.id,
            {
                "action": "updated",
                "previous": {"source": old["source"], "cve_id": old["cve_id"]},
                "changes": body,
            },
        )
        return domain.finding_json(db, row, config.artifact_root)

    @router.post("/findings/{ident}/transitions")
    def finding_transition(ident: str, body: TransitionInput, db=database_dependency):
        """The Operator's Confirm, Dismiss and Mark remediated, each with a reason (A11)."""
        row = domain.get(db, Finding, ident)
        if not domain.transition_finding(db, row, body.state, {"by": "operator", "reason": body.reason}):
            raise DomainError("invalid_transition", f"A {row.status} Finding cannot be {body.state}", 409)
        return domain.finding_json(db, row, config.artifact_root)

    def finding_jobs(db, ids):
        """The findings among `ids` that a queued or running job still works on."""
        finding_id = Job.input["finding_id"].as_string()
        return set(
            db.scalars(select(finding_id).where(Job.status.in_(ACTIVE_JOB), finding_id.in_(ids)))
        )

    def remove_finding(db, row):
        """Deletes the finding, its lab runs and their artifact records and its Remediation PRs, and
        frees its Advisory check matches, keeping an audit record of what was deleted. Returns the
        artifact revisions whose folders
        the caller removes once the rows are gone."""
        labs = list(db.scalars(select(LabRun.id).where(LabRun.finding_id == row.id)))
        owned = or_(
            and_(Artifact.resource_type == "finding", Artifact.resource_id == row.id),
            and_(Artifact.resource_type == "lab", Artifact.resource_id.in_(labs)),
        )
        revisions = set(db.scalars(select(Artifact.revision).where(owned)))
        db.execute(delete(Artifact).where(owned))
        db.execute(delete(LabRun).where(LabRun.finding_id == row.id))
        db.execute(delete(RemediationPR).where(RemediationPR.finding_id == row.id))
        # ponytail: a freed Advisory check match opens a new Finding on its next check while it is
        # exposed; Dismiss is the way to keep it closed
        db.execute(update(AdvisoryMatch).where(AdvisoryMatch.finding_id == row.id).values(finding_id=None))
        action(db, "finding", row.id, {
            "action": "deleted",
            "title": row.title,
            "source": row.source,
            "cve_id": row.cve_id,
            "status": row.status,
            "application_id": row.application_id,
            "source_commit_id": row.data.get("source_commit_id"),
            "source_analysis_id": row.data.get("source_analysis_id"),
        })
        db.delete(row)
        return revisions

    def remove_revision_folders(revisions):
        root = Path(config.artifact_root).resolve()
        for revision in revisions:
            # Each publication has its own revision folder, so nothing else shares these files.
            folder = (root / revision).resolve()
            if folder.parent == root and folder.is_dir():
                shutil.rmtree(folder, ignore_errors=True)

    @router.delete("/findings/{ident}", status_code=204)
    def delete_finding(ident: str, db=database_dependency):
        """Remove a finding recorded in error, such as one a false-positive analysis created:
        the finding, its lab runs and their artifacts. The analysis that produced it stays as it
        was, and an audit record keeps what was deleted."""
        row = domain.get(db, Finding, ident)
        db.refresh(row, with_for_update=True)
        if finding_jobs(db, [row.id]):
            raise DomainError(
                "finding_busy",
                "A job is still working on this finding; cancel it or let it finish before deleting the finding",
                409,
            )
        revisions = remove_finding(db, row)
        db.flush()
        remove_revision_folders(revisions)
        return Response(status_code=204)

    @router.post("/findings/delete")
    def delete_findings(body: BatchDeleteInput, db=database_dependency):
        """Deletes many findings as one change: an unknown id, or a finding a job still works on,
        deletes nothing."""
        ids = list(dict.fromkeys(body.ids))
        rows = {
            f.id: f
            for f in db.scalars(select(Finding).where(Finding.id.in_(ids)).with_for_update())
        }
        missing = [i for i in ids if i not in rows]
        if missing:
            raise DomainError(
                "not_found", f"{len(missing)} of {len(ids)} findings were not found", 404
            )
        busy = finding_jobs(db, ids)
        if busy:
            raise DomainError(
                "finding_busy",
                f"Jobs are still working on {len(busy)} of the selected findings; cancel them or "
                "let them finish, then delete again",
                409,
            )
        revisions = set()
        for ident in ids:
            revisions |= remove_finding(db, rows[ident])
        db.flush()
        remove_revision_folders(revisions)
        return {"deleted": ids}

    @router.post("/findings/{ident}/artifacts")
    async def upload_artifacts(
        ident: str,
        files: list[UploadFile] = File(...),
        paths: list[str] | None = Form(None),
        db=database_dependency,
    ):
        row = domain.get(db, Finding, ident)
        if paths is not None and len(paths) != len(files):
            raise DomainError("invalid_artifact_paths", "Supply one path per uploaded file", 422)
        values = (
            artifacts.resource_files(
                db, config.artifact_root, "finding", row.id, row.artifact_revision
            )
            if row.artifact_revision
            else {}
        )
        values.pop("manifest.json", None)
        for i, upload in enumerate(files):
            content = await upload.read(artifacts.MAX_FILE + 1)
            if len(content) > artifacts.MAX_FILE:
                raise DomainError("artifact_too_large", "Uploaded file exceeds the file limit", 413)
            path = paths[i] if paths else upload.filename
            if path and path.lower().endswith(".zip"):
                try:
                    values.update(artifacts.unpack_zip(content))
                except (ValueError, RuntimeError, zipfile.BadZipFile) as exc:
                    raise DomainError(
                        "invalid_archive", "Uploaded archive is invalid or encrypted", 422
                    ) from exc
            else:
                values[path or ""] = content
        revision, _ = artifacts.publish(
            db,
            config.artifact_root,
            "finding",
            row.id,
            values,
            {
                "application_id": row.application_id,
                "source_analysis_id": row.data.get("source_analysis_id"),
                "origin": "upload",
            },
            all_secrets(db, vault),
        )
        domain.set_finding_artifacts(db, row, revision, values)
        row.updated_at = now()
        action(db, "finding", row.id, {"action": "artifacts_uploaded", "revision": revision})
        return domain.finding_json(db, row, config.artifact_root)

    @router.post("/findings/{ident}/artifact-generations")
    def generate_artifacts(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Finding, ident)
        if domain.malicious_change(db, row):
            # The bundle agent would replace the static Proof with a Lab bundle.
            raise DomainError(
                "generation_not_available",
                "A Malicious change Finding is re-drafted by analysing its commit again or by "
                "uploading a corrected detection-rule.yar",
                409,
            )
        return accepted(
            domain.submit_agent(
                db,
                "finding_artifacts",
                domain.get(db, Application, row.application_id),
                # None resolves the newest still-affected release when the job runs.
                {"finding_id": row.id, "source_ref": body.source_ref},
                body.profile.model_dump() if body.profile else None,
                key,
            )
        )

    @router.post("/findings/{ident}/remediation-prs")
    def draft_remediation_pr(ident: str, body: RemediationDraftInput, db=database_dependency):
        """The Operator drafts a Remediation PR by hand (A08), such as again after a failed draft:
        a patch or revert on an Own-repository commit, a pin or bump for an Upstream one, a bump
        for an Advisory check match. Like a manual Analysis it is neither capped nor counted."""
        finding = domain.get(db, Finding, ident)
        application = domain.get(db, Application, finding.application_id)
        actions = domain.remediation_actions(db, finding)
        own = domain.own_repository(db, application)
        if body.action not in actions:
            raise DomainError("remediation_unavailable", (
                "No Own repository: Remediation PR steps are skipped"
                if own is None
                else f"This Finding's Playbook drafts a {' or a '.join(actions)}, not a {body.action}"
                if actions
                else "An Advisory check match is bumped only to a known fixed version of a direct dependency or "
                "a runtime pin" if finding.source == "advisory"
                else "Only a Vulnerability introduced or Malicious change commit of the Own repository gets a "
                "patch or revert, and an exposed Upstream Verdict a pin or bump once its release is known"
            ), 422)
        if finding.source == "advisory":
            subject, revision = finding.data["subject_id"], own.cursor
            dependency = domain.advisory_dependency(db, finding)[0]
        else:
            commit = db.get(Commit, finding.data["source_commit_id"])
            subject, revision, dependency = commit.id, commit.revision, None
            if body.action in ("pin", "bump"):
                dependency = domain.upstream_dependency(db, application, db.get(Repository, commit.repository_id),
                                                        domain.finding_exposure(db, finding).data["target"])
        row = domain.draft_remediation(db, application, finding, subject, body.action, revision,
                                       dependency=dependency,
                                       submitted=body.profile.model_dump() if body.profile else None)
        return accepted(db.get(Job, row.data["job_id"]))

    @router.post("/findings/{ident}/remediation-prs/{remediation_id}/approvals")
    def approve_remediation_pr(
        ident: str, remediation_id: str, request: Request, body: RemediationApprovalInput, db=database_dependency
    ):
        """The Approval of a draft Remediation PR (A08, A15): the Operator's password and the hash
        of the diff they reviewed. Approving it again returns the same job, so one PR is opened."""
        approval(request, db, body.password)
        row = domain.get(db, RemediationPR, remediation_id)
        db.refresh(row, with_for_update=True)
        if row.finding_id != ident:
            raise DomainError("not_found", "RemediationPR was not found", 404)
        if row.status in ("approved", "open", "merged"):
            return accepted(db.get(Job, row.data["job_id"]))
        if row.status not in ("ready", "failed"):
            raise DomainError("remediation_not_ready", f"This {row.action} is {row.status.replace('_', ' ')}; only a "
                              "ready draft can be approved", 409)
        if body.diff_sha256 != row.diff_sha256:
            raise DomainError("diff_changed", "The draft changed since you reviewed it; review the new diff", 409)
        application = domain.get(db, Application, row.application_id)
        if getattr(domain.own_repository(db, application), "id", None) != row.repository_id:
            raise DomainError("not_own_repository", "A Remediation PR is opened only on the Application's Own "
                              "repository", 409)
        # finding_id keeps the Finding from being deleted while the PR step runs.
        job = domain.enqueue(db, "remediation_pr", application, {
            "remediation_pr_id": row.id, "finding_id": row.finding_id, "diff_sha256": row.diff_sha256})
        row.status, row.data, row.updated_at = "approved", {**row.data, "job_id": job.id, "error": None}, now()
        action(db, "finding", row.finding_id, {
            "action": "approved",
            "approved": "remediation_pr",
            "remediation": row.action,
            "remediation_pr_id": row.id,
            "diff_sha256": row.diff_sha256,
            "job_id": job.id,
        })
        return accepted(job)

    @router.post("/findings/{ident}/lab-runs")
    def lab(
        ident: str,
        request: Request,
        body: ApprovalInput = ApprovalInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        approval(request, db, body.password)
        finding = domain.get(db, Finding, ident)
        domain.require_lab(db, finding)
        files = (
            artifacts.resource_files(
                db, config.artifact_root, "finding", ident, finding.artifact_revision
            )
            if finding.artifact_revision
            else {}
        )
        if artifacts.completeness(files, domain.lab_supplied(db, finding))["status"] != "complete":
            raise DomainError(
                "incomplete_bundle",
                "Complete and pin all required artifacts before verification",
                422,
            )
        application = domain.get(db, Application, finding.application_id)
        job = domain.enqueue(
            db,
            "lab_run",
            application,
            domain.job_input(
                db, application, finding_id=finding.id, artifact_revision=finding.artifact_revision
            ),
            idempotency_key=key,
        )
        existing = db.scalar(select(LabRun).where(LabRun.job_id == job.id))
        if not existing:
            row = LabRun(
                finding_id=finding.id,
                artifact_revision=finding.artifact_revision,
                job_id=job.id,
                status="queued",
                data={},
            )
            db.add(row)
            db.flush()
            action(db, "finding", finding.id, {
                "action": "approved",
                "approved": "lab_run",
                "job_id": job.id,
                "artifact_revision": finding.artifact_revision,
            })
        return accepted(job)

    def exported(db, resource_type, ident):
        """Refuses the export of an Upstream Proof (A15), overriding Numen's AC-12 for it."""
        if not domain.exportable(db, resource_type, ident):
            raise DomainError("upstream_proof_not_exported", "Upstream Proofs are never exported (A15)", 403)

    @router.get("/artifacts/{ident}/content")
    def artifact_content(ident: str, db=database_dependency):
        row = domain.get(db, Artifact, ident)
        if row.path not in REPORTS:  # Reports stay readable in the page; nothing else of an Upstream Proof.
            exported(db, row.resource_type, row.resource_id)
        content = artifacts.read_file(config.artifact_root, row)
        filename = Path(row.path).name.replace('"', "")
        return Response(
            content,
            media_type="text/plain"
            if row.path.endswith((".md", ".py", ".json", ".yaml", ".txt", "Dockerfile"))
            else "application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename=artifact; filename*=UTF-8''{quote(filename)}",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
            },
        )

    @router.get("/analyses/{ident}/download")
    def download_analysis(ident: str, db=database_dependency):
        row = domain.get(db, Analysis, ident)
        exported(db, "analysis", row.id)
        filename = f"{row.subject_id}-{row.id[:8]}-analysis.zip"
        return Response(
            artifacts.resource_zip(db, config.artifact_root, "analysis", row.id),
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    "attachment; filename=analysis.zip; "
                    f"filename*=UTF-8''{quote(filename, safe='')}"
                ),
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
            },
        )

    @router.get("/findings/{ident}/download")
    def download(ident: str, db=database_dependency):
        row = domain.get(db, Finding, ident)
        exported(db, "finding", row.id)
        return Response(
            artifacts.bundle_zip(db, config.artifact_root, row),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{row.id}.zip"',
                "Cache-Control": "private, no-store",
            },
        )

    @router.get("/jobs")
    def jobs(
        application_id: str | None = None,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(Job).order_by(Job.created_at.desc())
        if application_id:
            stmt = stmt.where(Job.application_id == application_id)
        if status:
            stmt = stmt.where(Job.status == status)
        return paginate(db, stmt, lambda j: domain.job_json(db, j, False), cursor, limit)

    @router.get("/jobs/{ident}")
    def job(ident: str, db=database_dependency):
        return domain.job_json(db, domain.get(db, Job, ident))

    @router.get("/jobs/{ident}/events")
    def job_events(ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency):
        domain.get(db, Job, ident)
        return paginate(
            db,
            select(JobEvent).where(JobEvent.job_id == ident).order_by(JobEvent.created_at),
            lambda e: {"id": e.id, "created_at": utc(e.created_at), **e.data},
            cursor,
            limit,
        )

    def session_runs(db, ident, live=False):
        """Job-owned runs, using their recorded start order for retained history."""
        row = domain.get(db, Job, ident)
        if live:
            if row.status != "running":
                return []
            attempt = db.scalar(
                select(JobAttempt).where(
                    JobAttempt.id == row.attempt_token,
                    JobAttempt.job_id == row.id,
                    JobAttempt.status == "running",
                )
            )
            return (
                [run for run in runtime_phases(attempt, row.broker_run_id).values() if run]
                if attempt else []
            )
        starts, non_agent_runs = {}, set()
        # Completed phases leave runtime_phases; their timeline records retain run membership.
        for event in db.scalars(
            select(JobEvent)
            .where(JobEvent.job_id == row.id, JobEvent.data["kind"].as_string() == "runtime_started")
            .order_by(JobEvent.created_at, JobEvent.id)
        ):
            run = event.data.get("run_id")
            if isinstance(run, str) and run:
                if event.data.get("runtime_kind") not in (None, "agent"):
                    non_agent_runs.add(run)
                    continue
                starts.setdefault(run, (utc(event.created_at), len(starts)))
        for attempt in db.scalars(
            select(JobAttempt).where(JobAttempt.job_id == row.id)
            .order_by(JobAttempt.created_at, JobAttempt.id)
        ):
            for run in runtime_phases(attempt).values():
                if isinstance(run, str) and run and run not in non_agent_runs:
                    starts.setdefault(run, (utc(attempt.created_at), len(starts)))
        runs = sorted(starts, key=starts.get)
        # Older records may have only the job's latest broker run, without a timeline entry.
        if row.broker_run_id and row.broker_run_id not in starts and row.broker_run_id not in non_agent_runs:
            runs.append(row.broker_run_id)
        return runs

    @router.get("/jobs/{ident}/session")
    def job_session(ident: str, run: str | None = None, db=database_dependency):
        runs = session_runs(db, ident)
        if not runs:
            raise DomainError("session_unavailable", "This job has no recorded agent session", 409)
        if run is not None and run not in runs:
            raise DomainError("session_unavailable", "That run does not belong to this job", 409)
        # Older mixed workloads can end with a probe. Default to the newest readable session.
        for run_id in [run] if run is not None else reversed(runs.copy()):
            try:
                state = broker.session(run_id)
            except DomainError as exc:
                if run is not None or exc.code != "session_unavailable" or exc.status != 409:
                    raise
                runs.remove(run_id)
                if not runs:
                    raise
            else:
                return {"runs": runs, "run_id": run_id, **state}

    @router.post("/jobs/{ident}/session", status_code=202)
    def job_session_input(ident: str, body: SessionInput, db=database_dependency):
        if body.run_id not in session_runs(db, ident, live=True):
            raise DomainError("session_unavailable", "That run is not a live session of this job", 409)
        broker.session(body.run_id, body.model_dump(exclude={"run_id"}, exclude_none=True))
        return {"status": "accepted"}

    @router.post("/jobs/{ident}/cancel")
    def cancel(ident: str, db=database_dependency):
        row = db.scalar(select(Job).where(Job.id == ident).with_for_update())
        if not row:
            raise DomainError("not_found", "Job was not found", 404)
        if row.status == "queued":
            row.status, row.finished_at = "cancelled", now()
            domain.remediation_job_ended(db, row, {"code": "cancelled", "message": "The Operator cancelled the job",
                                                   "retryable": False})
        elif row.status == "running":
            row.status = "cancelling"
        domain.event(db, row, "cancellation_requested", "Operator requested cancellation")
        return accepted(row)

    @router.post("/jobs/{ident}/retry")
    def retry(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        row = domain.get(db, Job, ident)
        if row.status not in ("failed", "cancelled"):
            raise DomainError(
                "job_not_retryable", "Only failed or cancelled jobs can be retried", 409
            )
        if row.kind == "lab_run":
            raise DomainError(
                "approval_required", "A Lab needs a new Approval: start it again from its Finding", 409
            )
        if row.kind == "remediation_pr":
            raise DomainError(
                "approval_required", "A Remediation PR needs a new Approval: approve it again from its Finding", 409
            )
        if row.kind in ("patch_drafting", "remediation_draft"):
            # A retried draft would run again only to be discarded: its record is no longer drafting.
            raise DomainError(
                "job_not_retryable", "Draft the Remediation PR again from its Finding", 409
            )
        if row.input.get("finding_id") and db.get(Finding, row.input["finding_id"]) is None:
            raise DomainError(
                "finding_removed", "The finding this job worked on has been deleted", 409
            )
        application = domain.get(db, Application, row.application_id) if row.application_id else None
        job = domain.enqueue(db, row.kind, application, row.input, row.profile, key)
        commit = db.get(Commit, row.input["commit_id"]) if row.kind == "commit_analysis" else None
        if commit and job.status == "queued":
            commit.analysis_state = {"status": "queued", "job_id": job.id}
        domain.event(
            db,
            job,
            "retry",
            "Retry preserves the original recorded inputs and profile",
            original_job_id=row.id,
        )
        return accepted(job)

    @router.get("/settings")
    def get_settings(db=database_dependency):
        row = domain.settings(db, config)
        return {
            **row.data,
            "webhook_configured": bool(row.webhook_secret),
            "webhook_masked": "Configured" if row.webhook_secret else None,
        }

    @router.patch("/settings")
    def patch_settings(body: dict, db=database_dependency):
        allowed = {
            "monitor_interval_seconds",
            "default_profiles",
            "webhook_enabled",
            "dashboard_url",
            "webhook_url",
            "webhook_key",
        }
        if set(body) - allowed:
            raise DomainError("validation_error", "Unknown settings fields", 422)
        row = domain.settings(db, config)
        values = {
            **row.data,
            **{k: v for k, v in body.items() if k not in ("webhook_url", "webhook_key")},
        }
        seconds = values.get("monitor_interval_seconds")
        if type(values.get("webhook_enabled")) is not bool:
            raise DomainError("validation_error", "Webhook enabled must be true or false", 422)
        if seconds is not None and (
            type(seconds) is not int or not MIN_INTERVAL <= seconds <= MAX_INTERVAL
        ):
            too_long = type(seconds) is int and seconds > MAX_INTERVAL
            message = "At most 10 years" if too_long else "At least 5 minutes"
            raise DomainError(
                "validation_error",
                "The monitoring interval must be between 5 minutes and 10 years",
                422,
                {"monitor_interval_seconds": message},
            )
        if values.get("dashboard_url"):
            try:
                values["dashboard_url"] = http_url(values["dashboard_url"])
            except ValueError as exc:
                raise DomainError(
                    "validation_error", str(exc), 422, {"dashboard_url": str(exc)}
                ) from exc
        if not isinstance(values.get("default_profiles"), dict) or set(
            values["default_profiles"]
        ) - set(OPERATIONS):
            raise DomainError(
                "validation_error", "Default profiles must be keyed by operation", 422
            )
        for operation, profile in values["default_profiles"].items():
            if profile != row.data.get("default_profiles", {}).get(operation):
                values["default_profiles"][operation] = domain.resolve_profile(
                    db, None, operation, profile
                )
        if "webhook_url" in body:
            url = body["webhook_url"]
            if url:
                parsed = urlparse(url)
                if not config.test_mode and (
                    parsed.scheme != "https"
                    or parsed.hostname not in ("discord.com", "discordapp.com")
                    or not parsed.path.startswith("/api/webhooks/")
                ):
                    raise DomainError(
                        "invalid_webhook",
                        "Use a Discord HTTPS webhook URL",
                        422,
                        {"webhook_url": "Invalid Discord webhook"},
                    )
                row.webhook_secret = vault.encrypt({"url": url, "key": body.get("webhook_key")})
            else:
                row.webhook_secret = None
        if seconds is None and any(
            p.config.get("monitor_interval_inherited") for p in db.scalars(select(Application))
        ):
            raise DomainError(
                "monitor_interval_required", "Existing Applications inherit the global interval", 422
            )
        if seconds is not None and seconds != row.data.get("monitor_interval_seconds"):
            for monitored in db.scalars(select(Application)):
                if monitored.config.get("monitor_interval_inherited"):
                    monitored.monitor_interval_seconds = seconds
                    monitored.next_check_at = (
                        (utc(monitored.last_check_at) or now()) + timedelta(seconds=seconds)
                        if monitored.monitor_enabled and not monitored.archived
                        else None
                    )
        row.data, row.revision = values, row.revision + 1
        return {
            **row.data,
            "webhook_configured": bool(row.webhook_secret),
            "webhook_masked": "Configured" if row.webhook_secret else None,
        }

    @router.get("/prompts")
    def prompt_templates(db=database_dependency):
        return {"items": prompts.listing(db), "variables": prompts.VARIABLES}

    @router.put("/prompts/{name}")
    def save_prompt(name: str, body: PromptInput, db=database_dependency):
        """Saves the operator's version of a template; the next job that uses it renders it."""
        previous, row = prompts.store(db, name, body.source)
        action(db, "prompt", name, {"action": "updated", "previous": previous, "customized": row["customized"]})
        return row

    @router.delete("/prompts/{name}")
    def reset_prompt(name: str, db=database_dependency):
        previous, row = prompts.store(db, name, None)
        action(db, "prompt", name, {"action": "reset", "previous": previous})
        return row

    @router.post("/prompts/preview")
    def preview_prompt(body: PromptPreviewInput, db=database_dependency):
        return prompts.preview(db, body.operation, body.name, body.source)

    @router.post("/settings/webhook/test")
    def webhook_test(db=database_dependency):
        row = domain.settings(db, config)
        if not row.webhook_secret or not row.data.get("webhook_enabled"):
            raise DomainError("webhook_unconfigured", "Configure and enable the webhook first", 422)
        note = Notification(
            event_key="test:" + secrets.token_hex(16),
            data={"verdict": "Webhook test", "link": "/"},
            status="pending",
        )
        db.add(note)
        db.flush()
        return accepted(domain.enqueue(db, "notification", inputs={"notification_id": note.id}))

    @router.get("/notifications")
    def notifications(cursor: str | None = None, limit: int = 50, db=database_dependency):
        return paginate(
            db,
            select(Notification).order_by(Notification.created_at.desc()),
            lambda n: {
                "id": n.id,
                "event_key": n.event_key,
                "status": n.status,
                "attempts": n.attempts,
                "created_at": utc(n.created_at),
                "next_attempt_at": utc(n.next_attempt_at),
                **n.data,
            },
            cursor,
            limit,
        )

    @router.post("/notifications/{ident}/retry")
    def retry_notification(ident: str, db=database_dependency):
        note = domain.get(db, Notification, ident)
        note.status = "pending"
        return accepted(domain.enqueue(db, "notification", inputs={"notification_id": note.id}))

    @router.get("/accounts")
    def accounts(cursor: str | None = None, limit: int = 50, db=database_dependency):
        rows = [
            a
            for a in db.scalars(select(Account).order_by(Account.label))
            if a.data.get("status") != "deleted"
        ]
        return {
            "items": [domain.public_account(a, domain.plugin_records(db)) for a in rows],
            "next_cursor": None,
        }

    @router.post("/accounts", status_code=201)
    def create_account(body: AccountInput, db=database_dependency):
        row = Account(
            label=body.label,
            provider=body.provider,
            auth_type=body.auth_type,
            credential=vault.encrypt({"api_key": body.api_key}) if body.api_key else None,
            data={"status": "unchecked", "models": [], "usage": None},
        )
        db.add(row)
        db.flush()
        return domain.public_account(row, domain.plugin_records(db))

    @router.patch("/accounts/{ident}")
    def patch_account(ident: str, body: dict, db=database_dependency):
        row = domain.get(db, Account, ident)
        parsed = AccountInput.model_validate(
            {"label": row.label, "provider": row.provider, "auth_type": row.auth_type, **body}
        )
        if parsed.provider != row.provider or parsed.auth_type != row.auth_type:
            raise DomainError(
                "immutable_connection_type",
                "Create a new connection to change provider or auth type",
                422,
            )
        row.label = parsed.label
        if "api_key" in body:
            row.credential = vault.encrypt({"api_key": parsed.api_key}) if parsed.api_key else None
            row.revision += 1
            row.data = {
                **row.data,
                "status": "unchecked",
                "models": [],
                "agent_models": {},
                "error": None,
            }
        return domain.public_account(row, domain.plugin_records(db))

    @router.delete("/accounts/{ident}", status_code=204)
    def delete_account(ident: str, db=database_dependency):
        row = domain.get(db, Account, ident)
        row.credential, row.revision = None, row.revision + 1
        row.data = {"status": "deleted", "models": [], "usage": None}
        return Response(status_code=204)

    def account_job(db, ident, kind):
        account = domain.get(db, Account, ident)
        return domain.enqueue(
            db, kind, inputs={"account_id": account.id, "credential_revision": account.revision}
        )

    @router.post("/accounts/{ident}/check")
    def check_account(ident: str, db=database_dependency):
        return accepted(account_job(db, ident, "account_check"))

    @router.post("/accounts/{ident}/native-cache")
    async def import_native_cache(ident: str, file: UploadFile = File(...), db=database_dependency):
        account = domain.get(db, Account, ident)
        if account.auth_type != "native_oauth":
            raise DomainError(
                "wrong_auth_mode", "Native cache import requires a native OAuth connection", 422
            )
        content = await file.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise DomainError(
                "native_cache_too_large", "Native credential cache upload exceeds 1 MiB", 413
            )
        try:
            value = json.loads(content)
        except (ValueError, UnicodeDecodeError) as exc:
            raise DomainError(
                "invalid_native_cache", "Credential cache file must contain valid JSON", 422
            ) from exc
        envelope = normalize_native_cache(account.provider, value)
        account.credential = vault.encrypt(envelope)
        account.revision += 1
        account.data = {
            "status": "unchecked",
            "models": [],
            "agent_models": {},
            "usage": None,
            "error": None,
        }
        action(
            db,
            "account",
            account.id,
            {"action": "native_cache_imported", "credential_revision": account.revision},
        )
        return domain.public_account(account, domain.plugin_records(db))

    @router.get("/accounts/{ident}/capabilities")
    def capabilities(ident: str, db=database_dependency):
        row = domain.get(db, Account, ident)
        return {
            "models": row.data.get("models", []),
            "agent_models": row.data.get("agent_models", {}),
            "usage": row.data.get("usage"),
            "status": row.data.get("status", "unchecked"),
            "last_checked_at": row.data.get("last_checked_at"),
        }

    @router.post("/accounts/{ident}/capabilities")
    def refresh_capabilities(ident: str, db=database_dependency):
        return accepted(account_job(db, ident, "account_capabilities"))

    @router.post("/accounts/{ident}/login")
    def account_login(ident: str, db=database_dependency):
        row = domain.get(db, Account, ident)
        if row.auth_type != "native_oauth":
            raise DomainError("unsupported_login", "API-key accounts do not use native login", 422)
        domain.require_provider_plugin(db, row.provider)
        if not vault.fernet:
            raise DomainError(
                "vault_unconfigured",
                "Configure the encryption key before starting native login",
                503,
            )
        pending_query = (
            select(Job)
            .where(
                Job.kind == "account_login",
                Job.status.in_(["queued", "running", "cancelling"]),
                Job.input["account_id"].as_string() == ident,
            )
            .order_by(Job.created_at.desc())
            .limit(1)
        )
        pending = db.scalar(pending_query)
        if pending:
            return accepted(pending)
        # A worker can claim another start between our read and lock. Do not wait on its
        # long-running credential transaction; keep the request transaction usable on conflict.
        try:
            with db.begin_nested():
                db.refresh(row, with_for_update={"nowait": True})
        except OperationalError as exc:
            if getattr(exc.orig, "sqlstate", None) != "55P03":
                raise
            pending = db.scalar(pending_query)
            if pending:
                return accepted(pending)
            raise DomainError(
                "account_busy",
                "This connection is busy. Try again when its current operation finishes.",
                409,
                retryable=True,
            ) from None
        return accepted(db.scalar(pending_query) or account_job(db, ident, "account_login"))

    @router.post("/accounts/{ident}/login/code", status_code=202)
    def submit_login_code(ident: str, body: LoginCodeInput, db=database_dependency):
        row = domain.get(db, Account, ident)
        if row.auth_type != "native_oauth" or row.provider not in domain.LOGIN_INPUT_PROVIDERS:
            raise DomainError(
                "unsupported_login", "This connection's native login does not accept pasted input", 422
            )
        job = db.scalar(
            select(Job)
            .where(
                Job.kind == "account_login",
                Job.status == "running",
                Job.input["account_id"].as_string() == ident,
            )
            .order_by(Job.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        attempt = db.get(JobAttempt, job.attempt_token) if job else None
        waiting = attempt and any(
            event.get("input_required") for event in domain.job_json(db, job)["events"]
        )
        if not waiting:
            raise DomainError(
                "login_not_waiting",
                "Start native login and wait for the sign-in link before submitting a code",
                409,
            )
        # The worker relays and removes this sealed value; it never enters job events or results.
        attempt.data = {**attempt.data, "login_code": vault.encrypt({"code": body.code})}
        db.add(
            JobEvent(
                job_id=job.id,
                data={
                    "kind": "login",
                    "message": "Sign-in input received",
                    "status": "code_received",
                },
            )
        )
        return JSONResponse(
            {"job_id": job.id, "status": "code_received", "status_url": f"/api/jobs/{job.id}"},
            status_code=202,
        )

    @router.get("/accounts/{ident}/login")
    def login_status(ident: str, db=database_dependency):
        domain.get(db, Account, ident)
        rows = list(
            db.scalars(
                select(Job).where(Job.kind == "account_login").order_by(Job.created_at.desc())
            )
        )
        row = next((j for j in rows if j.input.get("account_id") == ident), None)
        return {
            "status": row.status if row else "not_started",
            "job_id": row.id if row else None,
            "events": domain.job_json(db, row)["events"] if row else [],
            "error": row.error if row else None,
        }

    @router.get("/plugins")
    def plugins(db=database_dependency):
        return {
            "items": [
                {**p.data, "id": p.id, "enabled": p.enabled} for p in domain.plugin_records(db)
            ],
            "next_cursor": None,
        }

    @router.patch("/plugins/{ident}")
    def patch_plugin(ident: str, body: dict, db=database_dependency):
        if set(body) != {"enabled"} or type(body["enabled"]) is not bool:
            raise DomainError("validation_error", "Supply enabled=true or false", 422)
        row = domain.get(db, Plugin, ident)
        row.enabled = body["enabled"]
        return {**row.data, "id": row.id, "enabled": row.enabled}

    app.include_router(router)
    if config.frontend_root.is_dir():
        assets = config.frontend_root / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            if path.startswith("api/"):
                raise DomainError("not_found", "API route was not found", 404)
            return FileResponse(
                config.frontend_root / "index.html", headers={"Cache-Control": "no-cache"}
            )

    return app


app = create_app()
