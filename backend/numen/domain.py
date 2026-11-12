import json
from urllib.parse import quote
from datetime import timedelta
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from . import artifacts, cves
from .models import (
    Account,
    Action,
    Analysis,
    Artifact,
    AuditContext,
    CVE,
    Commit,
    Finding,
    Job,
    JobEvent,
    LabRun,
    Notification,
    Observation,
    Plugin,
    Application,
    ApplicationCVE,
    ApplicationRepository,
    Repository,
    Setting,
    now,
    utc,
)
from .schemas import AUDIT_MAX_FUNCTIONS, OPERATIONS, Profile
from .security import DomainError, fingerprint
from .sources import github_token_required


# Native subscription logins run in exactly one runtime per provider.
NATIVE_AGENTS = {"openai": "codex", "claude": "claude", "commandcode": "pi"}
# Native logins that finish with input pasted by the operator.
LOGIN_INPUT_PROVIDERS = {"claude", "commandcode"}
SUPPORTED = {
    "deepseek": ["pi"],
    "commandcode": ["pi"],
    "openai": ["pi", "codex"],
    "claude": ["pi", "claude"],
    "jev": [],
    "github": [],
    "nvd": [],
}


def get(db, cls, ident):
    item = db.get(cls, ident)
    if item is None:
        raise DomainError("not_found", f"{cls.__name__} was not found", 404)
    return item


def settings(db, config=None):
    row = db.get(Setting, "global")
    if row is None:
        row = Setting(
            id="global",
            data={
                "monitor_interval_seconds": config.monitor_interval_seconds if config else None,
                "default_profiles": {},
                "webhook_enabled": False,
                "dashboard_url": "",
            },
        )
        db.add(row)
        db.flush()
    return row


def plugin_records(db):
    # The runtime pins the actual bundled package and skill revisions in its build manifest.
    from pathlib import Path
    import os

    manifest = Path(os.getenv("NUMEN_PLUGIN_MANIFEST", "../runner/plugins.lock.json"))
    records = []
    if manifest.is_file():
        try:
            payload = json.loads(manifest.read_text())
            records = payload.get("plugins", []) if isinstance(payload, dict) else payload
        except (ValueError, TypeError):
            records = []
    if not records:
        records = [
            {
                "id": "pi-commandcode-provider",
                "name": "Command Code provider",
                "version": None,
                "source": "https://github.com/patlux/pi-commandcode-provider",
                "health": "unavailable",
                "provider_contribution": "commandcode",
            }
        ]
    for record in records:
        ident = record.get("id", record.get("name"))
        existing = db.get(Plugin, ident)
        if not existing:
            db.add(Plugin(id=ident, enabled=True, data=record))
        elif existing.data != record:
            existing.data = record
    db.flush()
    return list(db.scalars(select(Plugin)))


def public_account(account, plugins=None):
    supported = SUPPORTED.get(account.provider, [])
    if account.auth_type == "native_oauth":
        supported = [NATIVE_AGENTS[account.provider]]
    if account.data.get("status") == "ready" and account.data.get("agent_models") is not None:
        supported = list(account.data["agent_models"])
    selection_error = None
    if account.provider == "commandcode" and plugins is not None:
        plugin = next((p for p in plugins if p.id == "pi-commandcode-provider"), None)
        if not plugin or not plugin.enabled or plugin.data.get("health") != "ready":
            supported = []
            selection_error = "Command Code provider plugin is disabled or unavailable"
    return {
        "selection_error": selection_error,
        "id": account.id,
        "label": account.label,
        "provider": account.provider,
        "auth_type": account.auth_type,
        "credential_configured": bool(account.credential),
        "supported_agents": supported,
        "status": account.data.get("status", "unchecked"),
        "models": account.data.get("models", []),
        "agent_models": account.data.get("agent_models", {}),
        "capability_errors": account.data.get("capability_errors", {}),
        "usage": account.data.get("usage"),
        "last_checked_at": account.data.get("last_checked_at"),
        "error": account.data.get("error"),
    }


def enabled_plugins(db, provider):
    # A runtime loads only enabled, healthy bundled plugins that contribute this provider.
    return [
        p.id
        for p in plugin_records(db)
        if p.enabled
        and p.data.get("health") == "ready"
        and p.data.get("provider_contribution") == provider
    ]


def require_provider_plugin(db, provider):
    if provider == "commandcode" and not enabled_plugins(db, provider):
        raise DomainError(
            "plugin_unavailable",
            "The Command Code provider plugin is disabled or unavailable",
            422,
        )


def resolve_profile(db, application, operation, submitted=None):
    if operation not in OPERATIONS:
        raise DomainError("unknown_operation", "Unknown agent operation", 422)
    saved = application.config.get("profiles", {}).get(operation) if application else None
    value = submitted or saved or settings(db).data.get("default_profiles", {}).get(operation)
    if not value:
        raise DomainError(
            "profile_required",
            "Select an agent, connected account, model and supported effort",
            422,
        )
    profile = Profile.model_validate(value).model_dump()
    account = get(db, Account, profile["connection_id"])
    supported = public_account(account)["supported_agents"]
    if profile["agent"] not in supported:
        raise DomainError(
            "unsupported_profile", "This connection does not support the selected agent", 422
        )
    if not account.credential or account.data.get("status") != "ready":
        raise DomainError(
            "connection_not_ready", "Check or sign in to this connection before using it", 422
        )
    require_provider_plugin(db, account.provider)
    catalog = account.data.get("agent_models", {}).get(
        profile["agent"], account.data.get("models", [])
    )
    model = next((m for m in catalog if m.get("id") == profile["model_id"]), None)
    if not model:
        raise DomainError(
            "model_unavailable", "The selected model is not available to this connection", 422
        )
    effort = profile.get("reasoning_effort")
    if effort is not None and effort not in model.get("reasoning_efforts", []):
        raise DomainError(
            "unsupported_effort",
            "The selected reasoning effort is not supported by this model",
            422,
        )
    if effort is None and model.get("default_effort"):
        profile["reasoning_effort"] = model["default_effort"]
    return profile


def resolve_jev(db, config):
    account = get(db, Account, config.get("jev_connection_id", ""))
    if account.provider != "jev" or not account.credential or account.data.get("status") != "ready":
        raise DomainError(
            "jev_connection_required",
            "Select and check a Jev connection before enabling typed triage",
            422,
        )
    ids = [model["id"] for model in account.data.get("models", [])]
    model = config.get("jev_model_id") or (
        "jev-latest" if "jev-latest" in ids else (ids[0] if ids else None)
    )
    if not model or model not in ids:
        raise DomainError(
            "model_unavailable", "Select an available model for the Jev connection", 422
        )
    return {"jev_connection_id": account.id, "model_id": model}


def event(db, job, kind, message, **data):
    db.add(JobEvent(job_id=job.id, data={"kind": kind, "message": message, **data}))


def enqueue(db, kind, application=None, inputs=None, profile=None, idempotency_key=None):
    inputs = inputs or {}
    digest = fingerprint(
        {
            "kind": kind,
            "application_id": application.id if application else None,
            "input": inputs,
            "profile": profile,
        }
    )
    if idempotency_key:
        existing = db.scalar(select(Job).where(Job.idempotency_key == idempotency_key))
        if existing:
            if existing.input_hash != digest:
                raise DomainError(
                    "idempotency_conflict",
                    "This idempotency key was already used with different inputs",
                    409,
                )
            return existing
    job = Job(
        kind=kind,
        application_id=application.id if application else None,
        input=inputs,
        input_hash=digest,
        profile=profile,
        idempotency_key=idempotency_key,
        status="queued",
    )
    db.add(job)
    db.flush()
    event(db, job, "queued", "Job queued")
    return job


def links(db, application):
    """The Application's repository links with their repositories: the Own one first, then
    in the order they were added. Removed links are included."""
    return db.execute(
        select(ApplicationRepository, Repository)
        .join(Repository, Repository.id == ApplicationRepository.repository_id)
        .where(ApplicationRepository.application_id == application.id)
        .order_by(ApplicationRepository.role != "own", ApplicationRepository.created_at)
    ).all()


def active_repositories(db, application):
    """The repositories the Application polls: every enabled link that is not removed."""
    return [r for link, r in links(db, application) if link.enabled and link.removed_at is None]


def source_repository(db, application):
    """The repository Numen's per-Application operations read (version recipe, version check,
    audit context, CVE analysis, finding artifacts): the earliest linked one that is not removed,
    whatever its role or on/off state. Adding a repository or turning a link on or off keeps it,
    so a migrated Application keeps its recipe and CVE cursor when it gets an Own repository."""
    return db.scalar(
        select(Repository)
        .join(ApplicationRepository, ApplicationRepository.repository_id == Repository.id)
        .where(
            ApplicationRepository.application_id == application.id,
            ApplicationRepository.removed_at.is_(None),
        )
        .order_by(ApplicationRepository.created_at, ApplicationRepository.id)
        .limit(1)
    )


def required_repository(db, application):
    repository = source_repository(db, application)
    if repository is None:
        raise DomainError("repository_required", "Link a repository to this Application first", 422)
    return repository


def linked_repository_ids(application_id):
    """Every repository the Application links or once linked, whose commits it lists."""
    return select(ApplicationRepository.repository_id).where(
        ApplicationRepository.application_id == application_id
    )


def linked_applications(db, repository):
    """The Applications linking `repository`, oldest link first, with their links."""
    return db.execute(
        select(Application, ApplicationRepository)
        .join(ApplicationRepository, ApplicationRepository.application_id == Application.id)
        .where(ApplicationRepository.repository_id == repository.id)
        .order_by(ApplicationRepository.created_at)
    ).all()


def repository_for(db, source_url, **fields):
    """The repository stored for `source_url`, created from `fields` when there is none. A
    concurrent job or request that creates it first wins; this one then reads its row."""
    query = select(Repository).where(Repository.source_url == source_url)
    repository = db.scalar(query)
    if repository is None:
        try:
            with db.begin_nested():
                repository = Repository(source_url=source_url, **fields)
                db.add(repository)
        except IntegrityError:
            repository = db.scalar(query)
    return repository


def in_use(application, link):
    return not application.archived and link.enabled and link.removed_at is None


def commit_application(db, commit):
    """The first Application that uses the commit's repository (not archived, link on and not
    removed), else the first that ever linked it. Until Findings are per Application, it is the
    context for commit pages and commit analysis."""
    rows = linked_applications(db, db.get(Repository, commit.repository_id))
    return next((a for a, link in rows if in_use(a, link)), rows[0][0] if rows else None)


def triage_application(db, repository):
    """The Application whose Triage settings judge the repository's new commits: the first
    one that uses it and has Triage on. A shared repository is triaged once."""
    for application, link in linked_applications(db, repository):
        if in_use(application, link) and application.config.get("triage_mode", "disabled") != "disabled":
            return application
    return None


def job_input(db, application, **data):
    repository = source_repository(db, application)
    return {
        "source_generation": application.source_generation,
        "source_ref": repository.cursor if repository else None,
        **data,
    }


def repository_input(repository, **data):
    return {
        "repository_id": repository.id,
        "source_generation": repository.source_generation,
        "source_ref": repository.cursor,
        **data,
    }


def active_source_check(db, repository):
    return db.scalar(
        select(Job)
        .where(
            Job.kind == "source_check",
            Job.status.in_(["queued", "running", "cancelling"]),
            Job.input["repository_id"].as_string() == repository.id,
        )
        .limit(1)
    )


def source_changed(db, application, previous_repository_id):
    """Starts a new source generation when the repository the Application's operations read
    was replaced or went away: recipes, audit contexts and the CVE cursor belong to the old one."""
    repository = source_repository(db, application)
    if previous_repository_id is None or (repository and repository.id) == previous_repository_id:
        return False
    application.source_generation += 1
    application.cve_cursor = {}
    application.config = {**application.config, "active_recipe_id": None}
    for context in db.scalars(select(AuditContext).where(AuditContext.application_id == application.id)):
        context.status = "stale"
    for link in db.scalars(select(ApplicationCVE).where(ApplicationCVE.application_id == application.id)):
        refresh_cve_policy(db, application, db.get(CVE, link.cve_id), link)
    return True


def submit_agent(db, operation, application, inputs=None, submitted=None, key=None):
    profile = resolve_profile(db, application, operation, submitted)
    return enqueue(db, operation, application, job_input(db, application, **(inputs or {})), profile, key)


def audit_refresh_input(db, application, base):
    """Job input that refreshes `base` for the current source revision, keeping its scope."""
    if base.source_generation != application.source_generation:
        raise DomainError(
            "refresh_unavailable",
            "That audit context belongs to an earlier source generation; build a fresh context",
            409,
        )
    if not base.coverage.get("completed"):
        raise DomainError(
            "refresh_unavailable", "That audit context has no analysed functions to reuse", 409
        )
    repository = source_repository(db, application)
    if base.source_ref == (repository.cursor if repository else None):
        raise DomainError(
            "context_current", "That audit context is already built at the current source revision", 409
        )
    origin = db.get(Job, base.job_id)
    scope = origin.input if origin else {}
    return {
        "refresh_from": base.id,
        "focus": scope.get("focus"),
        "max_functions": scope.get("max_functions") or AUDIT_MAX_FUNCTIONS,
    }


def queue_cve(db, application, cve, link, submitted=None, key=None, source_ref=None):
    decision = cves.gate(application, cve, link)
    if not decision["eligible"]:
        raise DomainError("criteria_not_met", decision["eligibility_reason"], 422)
    return submit_agent(
        db,
        "cve_analysis",
        application,
        {
            "cve_id": cve.id,
            # None resolves the newest still-affected release when the job runs.
            "source_ref": source_ref,
            "gate_hash": cves.gate_hash(application, cve, link),
            "record_hash": cve.record_hash,
            "source_record": cve.raw,
            "eligibility": decision,
        },
        submitted,
        key,
    )


def refresh_cve_policy(db, application, cve, link):
    decision = cves.gate(application, cve, link)
    relevant_hash = cves.gate_hash(application, cve, link)
    if decision["eligible"] and link.data.get("notified_hash") != relevant_hash:
        notify(
            db,
            f"cve:{application.id}:{cve.id}:{relevant_hash}",
            cve.id + " — " + cve.data["title"],
            f"/cves?application_id={application.id}&cve_id={cve.id}",
            "Eligible Base score " + str(decision["qualifying_score"]["base_score"]),
        )
        link.data = {**link.data, "notified_hash": relevant_hash}
    if decision["eligible"] and application.config.get("cve_auto_analyze") and not application.archived:
        key = f"cve-analysis:{application.id}:{cve.id}:{relevant_hash}"
        if not db.scalar(select(Job).where(Job.idempotency_key == key)):
            try:
                repository = source_repository(db, application)
                if not repository or not repository.cursor:
                    # Held until a baseline source check, which dispatches it.
                    raise DomainError(
                        "source_not_checked",
                        "Complete a source check before generating grounded evidence",
                        422,
                    )
                queue_cve(db, application, cve, link, key=key)
                link.data = {**link.data, "analysis_blocked": None}
            except DomainError as exc:
                link.data = {**link.data, "analysis_blocked": exc.as_dict()}


def last_observation(db, application, success_only=False):
    rows = list(
        db.scalars(
            select(Observation)
            .where(
                Observation.application_id == application.id,
                Observation.source_generation == application.source_generation,
            )
            .order_by(Observation.checked_at.desc())
        )
    )
    return (
        next((r for r in rows if r.data.get("status") == "detected"), None)
        if success_only
        else (rows[0] if rows else None)
    )


def observation_json(row):
    return {
        **row.data,
        "id": row.id,
        "application_id": row.application_id,
        "recipe_id": row.recipe_id,
        "source_generation": row.source_generation,
        "checked_at": utc(row.checked_at),
    }


def release_branch_status(link, repository):
    """None where no Release branch applies; pending until the next check resolves the Locked
    version; unknown ('release branch unknown') when no candidate branch exists."""
    if link.role == "own" or repository.source_kind != "github" or not link.locked_version:
        return None
    if link.release_branch_version != link.locked_version:
        return "pending"
    return "matched" if link.release_branch else "unknown"


def link_json(link, repository):
    return {
        "repository_id": repository.id,
        "role": link.role,
        "enabled": link.enabled,
        "removed_at": utc(link.removed_at),
        "locked_version": link.locked_version,
        "locked_version_source": link.locked_version_source,
        "release_branch": link.release_branch,
        "release_branch_status": release_branch_status(link, repository),
        "packages": link.packages,
        "source_kind": repository.source_kind,
        "source_url": repository.source_url,
        "plugin_slug": repository.plugin_slug,
        "source_ref": repository.source_ref,
        "source_path": repository.source_path,
        "cursor": repository.cursor,
        "baseline_revision": repository.baseline_revision,
        "last_check_at": utc(repository.last_check_at),
        "last_error": repository.last_error,
    }


def application_json(db, row):
    columns = (
        "id",
        "asset_name",
        "asset_url",
        "product_kind",
        "product_name",
        "monitor_interval_seconds",
        "monitor_enabled",
        "archived",
        "source_generation",
        "last_check_at",
        "next_check_at",
        "config",
    )
    result = {name: getattr(row, name) for name in columns}
    for name in ("last_check_at", "next_check_at"):
        result[name] = utc(result[name])
    rows = links(db, row)
    result["repositories"] = [link_json(link, repository) for link, repository in rows]
    result["unresolved_dependencies"] = next(
        (link.unresolved for link, _ in rows if link.role == "own" and link.removed_at is None), []
    )
    result["version"] = (
        observation_json(last_observation(db, row, True))
        if last_observation(db, row, True)
        else None
    )
    latest = last_observation(db, row)
    result["latest_version_check"] = observation_json(latest) if latest else None
    return result


def artifact_json(row):
    return {
        "id": row.id,
        "path": row.path,
        "revision": row.revision,
        "size": row.size,
        "sha256": row.sha256,
        "content_type": row.content_type,
    }


def artifact_rows(db, resource_type, ident, revision=None):
    stmt = select(Artifact).where(
        Artifact.resource_type == resource_type, Artifact.resource_id == ident
    )
    if revision:
        stmt = stmt.where(Artifact.revision == revision)
    return [artifact_json(a) for a in db.scalars(stmt)]


def analysis_json(db, row, with_artifacts=True):
    superseded = False
    if row.kind == "cve_analysis":
        cve = db.get(CVE, row.subject_id)
        application = db.get(Application, row.application_id)
        link = db.scalar(
            select(ApplicationCVE).where(
                ApplicationCVE.application_id == row.application_id, ApplicationCVE.cve_id == row.subject_id
            )
        )
        if cve and application and link:
            superseded = cves.analysis_superseded(application, cve, link, row.result.get("gate_hash"))
    result = {
        "superseded": superseded,
        "id": row.id,
        "application_id": row.application_id,
        "kind": row.kind,
        "subject_id": row.subject_id,
        "job_id": row.job_id,
        "input_hash": row.input_hash,
        "profile": row.profile,
        "result": row.result,
        "created_at": utc(row.created_at),
    }
    linked = (row.result or {}).get("finding_id")
    if linked and db.get(Finding, linked) is None:
        # The stored analysis stays as it was; only its link to a deleted finding is withdrawn.
        result["result"] = {**row.result, "finding_id": None, "finding_removed": True}
    if with_artifacts:
        result["artifacts"] = artifact_rows(db, "analysis", row.id)
    return result


def commit_findings(db, ids):
    """The findings each commit produced, keyed by commit id."""
    linked = {}
    if not ids:
        return linked
    source = Finding.data["source_commit_id"].as_string()
    for finding in db.scalars(select(Finding).where(source.in_(list(ids))).order_by(Finding.created_at)):
        linked.setdefault(finding.data.get("source_commit_id"), []).append(
            {"id": finding.id, "title": finding.title, "status": finding.status, "kind": finding.kind}
        )
    return linked


def commit_json(db, row, findings=None):
    if findings is None:
        findings = commit_findings(db, [row.id])
    analyses = list(
        db.scalars(
            select(Analysis)
            .where(Analysis.kind == "commit_analysis", Analysis.subject_id == row.id)
            .order_by(Analysis.created_at.desc())
        )
    )
    application = commit_application(db, row)
    return {
        "id": row.id,
        "repository_id": row.repository_id,
        "application_id": application.id if application else None,
        "revision": row.revision,
        "source_generation": row.source_generation,
        **row.data,
        "triage_status": row.triage_status,
        "triage_result": row.triage_result,
        "review_decision": row.review_decision,
        "analyses": [analysis_json(db, a) for a in analyses],
        "findings": findings.get(row.id, []),
    }


def cve_json(db, cve, link):
    application = get(db, Application, link.application_id)
    analyses = list(
        db.scalars(
            select(Analysis)
            .where(
                Analysis.kind == "cve_analysis",
                Analysis.subject_id == cve.id,
                Analysis.application_id == application.id,
            )
            .order_by(Analysis.created_at.desc())
        )
    )
    return {
        "id": cve.id,
        "application_id": application.id,
        **cve.data,
        **cves.gate(application, cve, link),
        "applicability": cves.applicability(
            application, source_repository(db, application), cve, last_observation(db, application)
        ),
        "analyses": [analysis_json(db, a) for a in analyses],
        "analysis_blocked": link.data.get("analysis_blocked")
        if application.config.get("cve_auto_analyze")
        else None,
    }


# Fields every finding presents, whichever path created it. A commit analysis records only the
# evidence it established, so a finding it created starts without version ranges.
FINDING_DEFAULTS = {"affected_versions": [], "fixed_versions": [], "evidence": [], "target_applicability": "unknown"}


def finding_data(row):
    data = {key: value for key, value in row.data.items() if key != "_artifact_state"}
    return {**FINDING_DEFAULTS, **{key: value for key, value in data.items() if value is not None}}


def set_finding_artifacts(db, row, revision, files):
    # Publishing flushes the artifact metadata first. Refresh and lock before
    # adding the summary: generation may have loaded this finding before an edit.
    db.refresh(row, with_for_update=True)
    state = artifacts.completeness(files)
    row.artifact_revision = revision
    row.data = {**row.data, "_artifact_state": {"revision": revision, "state": state}}
    return state


def finding_artifact_state(db, row, root):
    if not row.artifact_revision:
        return artifacts.completeness({})
    cached = row.data.get("_artifact_state")
    if isinstance(cached, dict) and cached.get("revision") == row.artifact_revision:
        return cached["state"]
    return artifacts.resource_completeness(db, root, "finding", row.id, row.artifact_revision)


def finding_summaries(db, rows, root):
    if not rows:
        return []
    latest = (
        select(
            LabRun.finding_id,
            LabRun.status,
            func.row_number().over(
                partition_by=LabRun.finding_id,
                order_by=(LabRun.created_at.desc(), LabRun.id.desc()),
            ).label("rank"),
        )
        .where(LabRun.finding_id.in_([row.id for row in rows]))
        .subquery()
    )
    statuses = dict(
        db.execute(
            select(latest.c.finding_id, latest.c.status).where(latest.c.rank == 1)
        ).all()
    )
    return [
        {
            "id": row.id,
            "application_id": row.application_id,
            "kind": row.kind,
            "cve_id": row.cve_id,
            "title": row.title,
            "status": row.status,
            "affected_versions": row.data.get("affected_versions", []),
            "fixed_versions": row.data.get("fixed_versions", []),
            "target_applicability": row.data.get("target_applicability", "unknown"),
            "source_commit_id": row.data.get("source_commit_id"),
            "source_analysis_id": row.data.get("source_analysis_id"),
            "artifact_revision": row.artifact_revision,
            "artifact_state": finding_artifact_state(db, row, root),
            "lab_status": statuses.get(row.id),
            "created_at": utc(row.created_at),
            "updated_at": utc(row.updated_at),
        }
        for row in rows
    ]


def finding_json(db, row, root):
    labs = list(
        db.scalars(
            select(LabRun)
            .where(LabRun.finding_id == row.id)
            .order_by(LabRun.created_at.desc(), LabRun.id.desc())
        )
    )
    actions = list(
        db.scalars(
            select(Action)
            .where(Action.resource_type == "finding", Action.resource_id == row.id)
            .order_by(Action.created_at)
        )
    )
    return {
        "id": row.id,
        "application_id": row.application_id,
        "kind": row.kind,
        "cve_id": row.cve_id,
        "title": row.title,
        "status": row.status,
        **finding_data(row),
        "artifact_state": finding_artifact_state(db, row, root),
        "artifact_revision": row.artifact_revision,
        "artifacts": artifact_rows(db, "finding", row.id, row.artifact_revision),
        "lab_runs": [
            {
                "id": a.id,
                "job_id": a.job_id,
                "artifact_revision": a.artifact_revision,
                "status": a.status,
                "created_at": utc(a.created_at),
                **a.data,
            }
            for a in labs
        ],
        "events": [{"id": a.id, "created_at": utc(a.created_at), **a.data} for a in actions],
        "created_at": utc(row.created_at),
        "updated_at": utc(row.updated_at),
    }


def repository_label(repository):
    if repository.source_kind == "wordpress":
        return f"WordPress · {repository.plugin_slug}"
    return repository.source_url.removeprefix("https://github.com/")


# Application-level operations act on one part of the Application; link to its tab.
APPLICATION_SUBJECTS = {
    "source_check": ("source", "repositories"),
    "backfill": ("source", "repositories"),
    "derive_upstreams": ("source", "repositories"),
    "version_recipe": ("version", "version"),
    "version_check": ("version", "version"),
    "audit_context": ("audit", "audit"),
}


def job_subject(db, row, application):
    """What a job acts on, as a readable label, short reference, and dashboard link."""
    data = row.input if isinstance(row.input, dict) else {}
    ref = data.get("source_ref")
    if data.get("commit_id"):
        commit = db.get(Commit, data["commit_id"])
        if not commit:
            return {"type": "commit", "label": "Removed commit", "ref": None, "link": None}
        triage = commit.triage_result if isinstance(commit.triage_result, dict) else {}
        message = (commit.data.get("message") or commit.revision).split("\n")[0]
        return {
            "type": "commit",
            "label": (triage.get("title") or message)[:240],
            "ref": commit.revision[:10],
            "link": f"/commits/{commit.id}",
        }
    if data.get("cve_id"):
        cve = db.get(CVE, data["cve_id"])
        query = f"cve={quote(data['cve_id'])}"
        if row.application_id:
            query += f"&cve_application={quote(row.application_id)}"
        if row.kind == "cve_analysis":
            query += "&view=analysis"
        return {
            "type": "cve",
            "label": data["cve_id"],
            "detail": (cve.data.get("description") or cve.data.get("title")) if cve else None,
            "ref": None,
            "link": f"/cves?{query}",
        }
    if data.get("finding_id"):
        finding = db.get(Finding, data["finding_id"])
        return {
            "type": "finding",
            "label": finding.title[:240] if finding else "Removed finding",
            "ref": None,
            "link": f"/findings/{finding.id}" if finding else None,
        }
    if data.get("account_id"):
        account = db.get(Account, data["account_id"])
        return {
            "type": "account",
            "label": account.label if account else "Removed connection",
            "ref": account.provider if account else None,
            "link": "/settings?tab=accounts",
        }
    if data.get("notification_id"):
        notification = db.get(Notification, data["notification_id"])
        details = notification.data if notification else {}
        link = details.get("link")
        return {
            "type": "notification",
            "label": (details.get("title") or "Removed notification").split("\n")[0],
            "ref": None,
            "link": link if isinstance(link, str) and link.startswith("/") else None,
        }
    if application and row.kind in APPLICATION_SUBJECTS:
        kind, tab = APPLICATION_SUBJECTS[row.kind]
        # A source check's or Backfill's input ref is where it started, not what it found.
        pinned = isinstance(ref, str) and row.kind not in ("source_check", "backfill")
        repository = (
            db.get(Repository, data["repository_id"])
            if data.get("repository_id")
            else source_repository(db, application)
        )
        return {
            "type": kind,
            "label": repository_label(repository) if repository else application.asset_name,
            "ref": ref[:10] if pinned else None,
            "link": f"/applications/{application.id}?tab={tab}",
        }
    if application and row.kind == "cve_sync":
        return {
            "type": "cves",
            "label": application.product_name,
            "ref": None,
            "link": f"/cves?application={quote(application.id)}",
        }
    return None


def job_json(db, row, with_events=True):
    application = db.get(Application, row.application_id) if row.application_id else None
    result = {
        name: getattr(row, name)
        for name in (
            "id",
            "kind",
            "application_id",
            "status",
            "progress",
            "profile",
            "created_at",
            "started_at",
            "finished_at",
            "error",
            "result",
        )
    }
    for name in ("created_at", "started_at", "finished_at"):
        result[name] = utc(result[name])
    result["application_name"] = application.asset_name if application else None
    result["subject"] = job_subject(db, row, application)
    result["events"] = (
        [
            {"id": e.id, "created_at": utc(e.created_at), **e.data}
            for e in db.scalars(
                select(JobEvent).where(JobEvent.job_id == row.id).order_by(JobEvent.created_at)
            )
        ]
        if with_events
        else []
    )
    return result


def notify(db, event_key, title, link, detail):
    if db.scalar(select(Notification).where(Notification.event_key == event_key)):
        return
    row = Notification(
        event_key=event_key,
        data={"title": title[:240], "link": link, "detail": detail[:1000]},
        status="pending",
    )
    db.add(row)
    db.flush()
    enqueue(
        db,
        "notification",
        inputs={"notification_id": row.id},
        idempotency_key=f"notification:{event_key}",
    )


def schedule(db):
    current = now()
    due = list(
        db.scalars(
            select(Application)
            .where(
                Application.monitor_enabled.is_(True),
                Application.archived.is_(False),
                (Application.next_check_at.is_(None)) | (Application.next_check_at <= current),
            )
            .with_for_update(skip_locked=True)
        )
    )
    github_token = db.scalar(
        select(Account.id).where(Account.provider == "github", Account.credential.is_not(None)).limit(1)
    )
    for application in due:
        # A repository shared by several due Applications is polled once.
        for repository in active_repositories(db, application):
            if repository.source_kind == "github" and not github_token:
                repository.last_error = github_token_required().as_dict()
            elif not active_source_check(db, repository):
                enqueue(db, "source_check", application, repository_input(repository))
        application.last_check_at = current
        application.next_check_at = current + timedelta(seconds=application.monitor_interval_seconds)
        if application.config.get("cve_selectors"):
            if not db.scalar(
                select(Job).where(
                    Job.application_id == application.id,
                    Job.kind == "cve_sync",
                    Job.status.in_(["queued", "running", "cancelling"]),
                )
            ):
                enqueue(db, "cve_sync", application, job_input(db, application))
        if application.config.get("active_recipe_id") and application.config.get(
            "version_monitor_enabled", True
        ):
            enqueue(
                db,
                "version_check",
                application,
                job_input(db, application, recipe_id=application.config["active_recipe_id"]),
            )
    return len(due)
