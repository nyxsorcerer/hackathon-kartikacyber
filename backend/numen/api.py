import hmac
import io
import json
import zipfile
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse, quote

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError, OperationalError

from . import artifacts, cves, domain
from .config import Config
from .db import make_database
from .models import (
    Account,
    Action,
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
    Program,
    ProgramCVE,
    VersionRecipe,
    now,
    utc,
)
from .schemas import (
    AccountInput,
    FindingInput,
    LoginCodeInput,
    LoginInput,
    ManualObservation,
    MatchInput,
    OPERATIONS,
    OperationInput,
    ProgramInput,
    ReviewInput,
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
from .workflows import all_secrets


def accepted(job):
    return JSONResponse({"job_id": job.id, "status_url": f"/api/jobs/{job.id}"}, status_code=202)


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

    def paginate(db, stmt, mapper, cursor=None, limit=50):
        try:
            offset = int(cursor or "0")
            if offset < 0 or offset > 1000000 or not 1 <= limit <= 200:
                raise ValueError
        except ValueError as exc:
            raise DomainError("invalid_cursor", "Invalid pagination cursor or limit", 422) from exc
        rows = list(db.scalars(stmt.offset(offset).limit(limit + 1)))
        return {
            "items": [mapper(row) for row in rows[:limit]],
            "next_cursor": str(offset + limit) if len(rows) > limit else None,
        }

    def action(db, resource_type, ident, data):
        db.add(Action(resource_type=resource_type, resource_id=ident, data=data))

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
        origin = request.client.host if request.client else "unknown"
        recent = attempts[origin]
        while recent and recent[0] < time.monotonic() - 60:
            recent.popleft()
        if len(recent) >= 10:
            raise DomainError(
                "login_rate_limited", "Wait before trying to sign in again", 429, retryable=True
            )
        recent.append(time.monotonic())
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
            for link in db.scalars(select(ProgramCVE))
            if cves.gate(
                domain.get(db, Program, link.program_id), domain.get(db, CVE, link.cve_id), link
            )["eligible"]
        )
        recent = list(db.scalars(select(JobEvent).order_by(JobEvent.created_at.desc()).limit(20)))
        due = list(
            db.scalars(
                select(Program)
                .where(
                    Program.archived.is_(False),
                    Program.monitor_enabled.is_(True),
                    (Program.next_check_at <= now()) | (Program.next_check_at.is_(None)),
                )
                .limit(20)
            )
        )
        return {
            "programs": count(Program, Program.archived.is_(False)),
            "security_reviews": count(Commit, Commit.review_decision == "candidate"),
            "eligible_cves": eligible,
            "open_findings": count(Finding, Finding.status == "open"),
            "running_jobs": count(Job, Job.status.in_(["queued", "running", "cancelling"])),
            "failed_jobs": count(Job, Job.status == "failed"),
            "recent_events": [
                {"id": e.id, "job_id": e.job_id, "created_at": utc(e.created_at), **e.data}
                for e in recent
            ],
            "due_programs": [domain.program_json(db, p) for p in due],
        }

    @router.get("/programs")
    def programs(
        q: str | None = None, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        stmt = select(Program).order_by(Program.asset_name, Program.id)
        if q:
            query = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            stmt = stmt.where(
                or_(
                    *(
                        getattr(Program, field).ilike(query, escape="\\")
                        for field in (
                            "asset_name",
                            "asset_url",
                            "product_name",
                            "source_url",
                            "plugin_slug",
                        )
                    )
                )
            )
        return paginate(
            db,
            stmt,
            lambda p: domain.program_json(db, p),
            cursor,
            limit,
        )

    @router.post("/programs", status_code=201)
    def create_program(body: ProgramInput, db=database_dependency):
        data = body.model_dump()
        days = data.get("monitor_interval_days") or domain.settings(db, config).data.get(
            "monitor_interval_days"
        )
        if not days:
            raise DomainError(
                "monitor_interval_required",
                "Set a global monitoring interval or enter one for this program",
                422,
                {"monitor_interval_days": "Positive whole days required"},
            )
        data["config"]["monitor_interval_inherited"] = data.get("monitor_interval_days") is None
        data["monitor_interval_days"] = days
        for operation, profile in data["config"]["profiles"].items():
            domain.resolve_profile(db, None, operation, profile)
        program = Program(**data, next_check_at=now())
        db.add(program)
        db.flush()
        action(db, "program", program.id, {"action": "created"})
        return domain.program_json(db, program)

    @router.get("/programs/{ident}")
    def program(ident: str, db=database_dependency):
        return domain.program_json(db, domain.get(db, Program, ident))

    @router.patch("/programs/{ident}")
    def patch_program(ident: str, body: dict, db=database_dependency):
        row = domain.get(db, Program, ident)
        current = {name: getattr(row, name) for name in ProgramInput.model_fields}
        if "config" in body:
            if not isinstance(body["config"], dict):
                raise DomainError("validation_error", "Program config must be an object", 422)
            body = {**body, "config": {**current["config"], **body["config"]}}
        data = ProgramInput.model_validate({**current, **body}).model_dump()
        if "monitor_interval_days" in body:
            inherited = body["monitor_interval_days"] is None
            data["config"]["monitor_interval_inherited"] = inherited
            if inherited:
                data["monitor_interval_days"] = domain.settings(db, config).data.get(
                    "monitor_interval_days"
                )
        if not data["monitor_interval_days"]:
            raise DomainError(
                "monitor_interval_required", "Configure a global interval before inheriting it", 422
            )
        source_changed = any(
            getattr(row, k) != data[k]
            for k in ("source_kind", "source_url", "source_ref", "source_path", "plugin_slug")
        )
        for operation, profile in data["config"]["profiles"].items():
            if profile != row.config.get("profiles", {}).get(operation):
                domain.resolve_profile(db, row, operation, profile)
        if data["config"].get("active_recipe_id"):
            recipe = domain.get(db, VersionRecipe, data["config"]["active_recipe_id"])
            if recipe.program_id != row.id or recipe.source_generation != row.source_generation:
                raise DomainError(
                    "invalid_recipe", "Recipe must belong to this program source", 422
                )
        for name, value in data.items():
            setattr(row, name, value)
        if source_changed:
            row.source_generation += 1
            row.cursor, row.cve_cursor, row.last_error = None, {}, None
            row.config = {**row.config, "active_recipe_id": None}
            for context in db.scalars(
                select(AuditContext).where(AuditContext.program_id == row.id)
            ):
                context.status = "stale"
        row.next_check_at = now() if row.monitor_enabled and not row.archived else None
        action(db, "program", row.id, {"action": "updated", "source_changed": source_changed})
        for linked in db.scalars(select(ProgramCVE).where(ProgramCVE.program_id == row.id)):
            domain.refresh_cve_policy(db, row, domain.get(db, CVE, linked.cve_id), linked)
        return domain.program_json(db, row)

    @router.post("/programs/{ident}/checks")
    def check_program(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        row = domain.get(db, Program, ident)
        return accepted(
            domain.enqueue(db, "source_check", row, domain.job_input(row), idempotency_key=key)
        )

    @router.get("/commits")
    def all_commits(
        program_id: str | None = None,
        review_decision: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(Commit).order_by(Commit.id)
        if program_id:
            stmt = stmt.where(Commit.program_id == program_id)
        if review_decision:
            stmt = stmt.where(Commit.review_decision == review_decision)
        return paginate(db, stmt, lambda c: domain.commit_json(db, c), cursor, limit)

    @router.get("/programs/{ident}/commits")
    def program_commits(
        ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        domain.get(db, Program, ident)
        return paginate(
            db,
            select(Commit).where(Commit.program_id == ident).order_by(Commit.id),
            lambda c: domain.commit_json(db, c),
            cursor,
            limit,
        )

    @router.get("/commits/{ident}")
    def commit(ident: str, db=database_dependency):
        return domain.commit_json(db, domain.get(db, Commit, ident))

    @router.post("/commits/{ident}/review")
    def review(ident: str, body: ReviewInput, db=database_dependency):
        row = domain.get(db, Commit, ident)
        row.review_decision = body.decision
        action(db, "commit", row.id, {"action": "review", "decision": body.decision})
        if body.decision == "candidate":
            domain.notify(
                db,
                f"commit:{row.id}:candidate",
                "Security candidate: " + row.data.get("message", "")[:120],
                f"/commits/{row.id}",
                "Operator nominated this change for security review",
            )
        return domain.commit_json(db, row)

    @router.post("/commits/{ident}/analyses")
    def analyze_commit(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Commit, ident)
        program = domain.get(db, Program, row.program_id)
        if row.source_generation != program.source_generation:
            raise DomainError(
                "historical_source",
                "This commit belongs to a previous source generation; current source context cannot analyze it",
                422,
            )
        job = domain.submit_agent(
            db,
            "commit_analysis",
            program,
            {"commit_id": row.id, "source_ref": row.revision},
            body.profile.model_dump() if body.profile else None,
            key,
        )
        action(db, "commit", row.id, {"action": "analysis_requested", "job_id": job.id})
        return accepted(job)

    @router.get("/programs/{ident}/version-recipes")
    def recipes(ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency):
        domain.get(db, Program, ident)
        return paginate(
            db,
            select(VersionRecipe)
            .where(VersionRecipe.program_id == ident)
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

    @router.post("/programs/{ident}/version-recipes")
    def generate_recipe(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Program, ident)
        return accepted(
            domain.submit_agent(
                db,
                "version_recipe",
                row,
                submitted=body.profile.model_dump() if body.profile else None,
                key=key,
            )
        )

    @router.post("/programs/{ident}/version-checks")
    def version_check(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        row = domain.get(db, Program, ident)
        if not row.config.get("active_recipe_id"):
            raise DomainError(
                "recipe_required", "Generate and validate a reusable recipe first", 422
            )
        return accepted(
            domain.enqueue(
                db,
                "version_check",
                row,
                domain.job_input(row, recipe_id=row.config["active_recipe_id"]),
                idempotency_key=key,
            )
        )

    @router.get("/programs/{ident}/version-observations")
    def observations(
        ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency
    ):
        domain.get(db, Program, ident)
        return paginate(
            db,
            select(Observation)
            .where(Observation.program_id == ident)
            .order_by(Observation.checked_at.desc()),
            domain.observation_json,
            cursor,
            limit,
        )

    @router.post("/programs/{ident}/version-observations", status_code=201)
    def observe(ident: str, body: ManualObservation, db=database_dependency):
        program = domain.get(db, Program, ident)
        row = Observation(
            program_id=program.id,
            source_generation=program.source_generation,
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

    @router.get("/programs/{ident}/audit-contexts")
    def contexts(ident: str, cursor: str | None = None, limit: int = 50, db=database_dependency):
        domain.get(db, Program, ident)
        return paginate(
            db,
            select(AuditContext)
            .where(AuditContext.program_id == ident)
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

    @router.post("/programs/{ident}/audit-contexts")
    def generate_context(
        ident: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        row = domain.get(db, Program, ident)
        return accepted(
            domain.submit_agent(
                db,
                "audit_context",
                row,
                {
                    "focus": body.focus,
                    "max_functions": body.max_functions,
                    **({"fresh": True} if body.fresh else {}),
                },
                body.profile.model_dump() if body.profile else None,
                key,
            )
        )

    @router.get("/cves")
    def cve_list(
        program_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(ProgramCVE).order_by(ProgramCVE.cve_id, ProgramCVE.program_id)
        if program_id:
            domain.get(db, Program, program_id)
            stmt = stmt.where(ProgramCVE.program_id == program_id)
        return paginate(
            db,
            stmt,
            lambda link: domain.cve_json(db, domain.get(db, CVE, link.cve_id), link),
            cursor,
            limit,
        )

    def program_cve(db, ident, cve_id):
        program, cve = domain.get(db, Program, ident), domain.get(db, CVE, cve_id)
        link = db.scalar(
            select(ProgramCVE).where(ProgramCVE.program_id == ident, ProgramCVE.cve_id == cve_id)
        )
        if not link:
            raise DomainError("not_found", "CVE is not associated with this program", 404)
        return program, cve, link

    @router.post("/programs/{ident}/cves/{cve_id}/analyses")
    def analyze_cve(
        ident: str,
        cve_id: str,
        body: OperationInput = OperationInput(),
        key: str | None = Header(None, alias="Idempotency-Key"),
        db=database_dependency,
    ):
        program, cve, link = program_cve(db, ident, cve_id)
        return accepted(
            domain.queue_cve(
                db,
                program,
                cve,
                link,
                body.profile.model_dump() if body.profile else None,
                key,
                body.source_ref,
            )
        )

    @router.post("/programs/{ident}/cves/{cve_id}/match")
    def confirm_cve(ident: str, cve_id: str, body: MatchInput, db=database_dependency):
        program, cve, link = program_cve(db, ident, cve_id)
        link.confirmed = body.confirmed
        action(db, "cve", link.id, {"action": "match_confirmed", "confirmed": body.confirmed})
        domain.refresh_cve_policy(db, program, cve, link)
        return domain.cve_json(db, cve, link)

    @router.post("/programs/{ident}/cve-sync")
    def cve_sync(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        program = domain.get(db, Program, ident)
        return accepted(
            domain.enqueue(db, "cve_sync", program, domain.job_input(program), idempotency_key=key)
        )

    @router.get("/findings")
    def findings(
        program_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(Finding).order_by(Finding.created_at.desc())
        if program_id:
            stmt = stmt.where(Finding.program_id == program_id)
        return paginate(
            db, stmt, lambda f: domain.finding_json(db, f, config.artifact_root), cursor, limit
        )

    def validate_finding_refs(db, body):
        domain.get(db, Program, body.program_id)
        if body.cve_id:
            program_cve(db, body.program_id, body.cve_id)
        for cls, value in ((Commit, body.source_commit_id), (Analysis, body.source_analysis_id)):
            if value and domain.get(db, cls, value).program_id != body.program_id:
                raise DomainError(
                    "invalid_reference", "Finding evidence must belong to the same program", 422
                )

    @router.post("/findings", status_code=201)
    def create_finding(body: FindingInput, db=database_dependency):
        validate_finding_refs(db, body)
        data = body.model_dump()
        row = Finding(
            **{k: data.pop(k) for k in ("program_id", "kind", "cve_id", "title", "status")},
            data=data,
        )
        db.add(row)
        db.flush()
        action(
            db,
            "finding",
            row.id,
            {"action": "created", "kind": row.kind, "cve_id": row.cve_id, "status": row.status},
        )
        return domain.finding_json(db, row, config.artifact_root)

    @router.get("/findings/{ident}")
    def finding(ident: str, db=database_dependency):
        return domain.finding_json(db, domain.get(db, Finding, ident), config.artifact_root)

    @router.patch("/findings/{ident}")
    def patch_finding(ident: str, body: dict, db=database_dependency):
        row = domain.get(db, Finding, ident)
        old = {
            "program_id": row.program_id,
            "kind": row.kind,
            "cve_id": row.cve_id,
            "title": row.title,
            "status": row.status,
            **row.data,
        }
        data = FindingInput.model_validate({**old, **body})
        validate_finding_refs(db, data)
        if data.program_id != row.program_id:
            raise DomainError("immutable_program", "A finding cannot move to another program", 422)
        values = data.model_dump()
        for field in ("kind", "cve_id", "title", "status"):
            setattr(row, field, values.pop(field))
        values.pop("program_id")
        row.data, row.updated_at = values, now()
        action(
            db,
            "finding",
            row.id,
            {
                "action": "updated",
                "previous": {"kind": old["kind"], "cve_id": old["cve_id"], "status": old["status"]},
                "changes": body,
            },
        )
        return domain.finding_json(db, row, config.artifact_root)

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
                "program_id": row.program_id,
                "source_analysis_id": row.data.get("source_analysis_id"),
                "origin": "upload",
            },
            all_secrets(db, vault),
        )
        row.artifact_revision, row.updated_at = revision, now()
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
        return accepted(
            domain.submit_agent(
                db,
                "finding_artifacts",
                domain.get(db, Program, row.program_id),
                # None resolves the newest still-affected release when the job runs.
                {"finding_id": row.id, "source_ref": body.source_ref},
                body.profile.model_dump() if body.profile else None,
                key,
            )
        )

    @router.post("/findings/{ident}/lab-runs")
    def lab(
        ident: str, key: str | None = Header(None, alias="Idempotency-Key"), db=database_dependency
    ):
        finding = domain.get(db, Finding, ident)
        files = (
            artifacts.resource_files(
                db, config.artifact_root, "finding", ident, finding.artifact_revision
            )
            if finding.artifact_revision
            else {}
        )
        if artifacts.completeness(files)["status"] != "complete":
            raise DomainError(
                "incomplete_bundle",
                "Complete and pin all required artifacts before verification",
                422,
            )
        program = domain.get(db, Program, finding.program_id)
        job = domain.enqueue(
            db,
            "lab_run",
            program,
            domain.job_input(
                program, finding_id=finding.id, artifact_revision=finding.artifact_revision
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
        return accepted(job)

    @router.get("/artifacts/{ident}/content")
    def artifact_content(ident: str, db=database_dependency):
        row = domain.get(db, Artifact, ident)
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

    @router.get("/findings/{ident}/download")
    def download(ident: str, db=database_dependency):
        row = domain.get(db, Finding, ident)
        return StreamingResponse(
            io.BytesIO(artifacts.bundle_zip(db, config.artifact_root, row)),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{row.id}.zip"',
                "Cache-Control": "private, no-store",
            },
        )

    @router.get("/jobs")
    def jobs(
        program_id: str | None = None,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        db=database_dependency,
    ):
        stmt = select(Job).order_by(Job.created_at.desc())
        if program_id:
            stmt = stmt.where(Job.program_id == program_id)
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

    @router.post("/jobs/{ident}/cancel")
    def cancel(ident: str, db=database_dependency):
        row = db.scalar(select(Job).where(Job.id == ident).with_for_update())
        if not row:
            raise DomainError("not_found", "Job was not found", 404)
        if row.status == "queued":
            row.status, row.finished_at = "cancelled", now()
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
        program = domain.get(db, Program, row.program_id) if row.program_id else None
        job = domain.enqueue(db, row.kind, program, row.input, row.profile, key)
        if row.kind == "lab_run" and not db.scalar(select(LabRun).where(LabRun.job_id == job.id)):
            original = db.scalar(select(LabRun).where(LabRun.job_id == row.id))
            db.add(
                LabRun(
                    finding_id=original.finding_id,
                    artifact_revision=original.artifact_revision,
                    job_id=job.id,
                    status="queued",
                    data={},
                )
            )
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
            "monitor_interval_days",
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
        days = values.get("monitor_interval_days")
        if type(values.get("webhook_enabled")) is not bool:
            raise DomainError("validation_error", "Webhook enabled must be true or false", 422)
        if days is not None and (type(days) is not int or not 1 <= days <= 3650):
            raise DomainError(
                "validation_error",
                "Monitoring interval must be positive whole days",
                422,
                {"monitor_interval_days": "Positive whole days required"},
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
        if days is None and any(
            p.config.get("monitor_interval_inherited") for p in db.scalars(select(Program))
        ):
            raise DomainError(
                "monitor_interval_required", "Existing programs inherit the global interval", 422
            )
        if days is not None and days != row.data.get("monitor_interval_days"):
            for monitored in db.scalars(select(Program)):
                if monitored.config.get("monitor_interval_inherited"):
                    monitored.monitor_interval_days = days
                    monitored.next_check_at = (
                        (utc(monitored.last_check_at) or now()) + timedelta(days=days)
                        if monitored.monitor_enabled and not monitored.archived
                        else None
                    )
        row.data, row.revision = values, row.revision + 1
        return {
            **row.data,
            "webhook_configured": bool(row.webhook_secret),
            "webhook_masked": "Configured" if row.webhook_secret else None,
        }

    @router.post("/settings/webhook/test")
    def webhook_test(db=database_dependency):
        row = domain.settings(db, config)
        if not row.webhook_secret or not row.data.get("webhook_enabled"):
            raise DomainError("webhook_unconfigured", "Configure and enable the webhook first", 422)
        note = Notification(
            event_key="test:" + secrets.token_hex(16),
            data={
                "title": "Numen webhook test",
                "detail": "Delivery test from the authenticated operator",
                "link": "/",
            },
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
