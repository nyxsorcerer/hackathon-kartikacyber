import json
from datetime import timedelta
from sqlalchemy import select

from . import artifacts, cves
from .models import (
    Account,
    Action,
    Analysis,
    Artifact,
    CVE,
    Job,
    JobEvent,
    LabRun,
    Notification,
    Observation,
    Plugin,
    Program,
    ProgramCVE,
    Setting,
    now,
    utc,
)
from .schemas import OPERATIONS, Profile
from .security import DomainError, fingerprint


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
                "monitor_interval_days": config.monitor_interval_days if config else None,
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


def resolve_profile(db, program, operation, submitted=None):
    if operation not in OPERATIONS:
        raise DomainError("unknown_operation", "Unknown agent operation", 422)
    saved = program.config.get("profiles", {}).get(operation) if program else None
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


def enqueue(db, kind, program=None, inputs=None, profile=None, idempotency_key=None):
    inputs = inputs or {}
    digest = fingerprint(
        {
            "kind": kind,
            "program_id": program.id if program else None,
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
        program_id=program.id if program else None,
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


def job_input(program, **data):
    return {"source_generation": program.source_generation, "source_ref": program.cursor, **data}


def submit_agent(db, operation, program, inputs=None, submitted=None, key=None):
    profile = resolve_profile(db, program, operation, submitted)
    return enqueue(db, operation, program, job_input(program, **(inputs or {})), profile, key)


def queue_cve(db, program, cve, link, submitted=None, key=None):
    decision = cves.gate(program, cve, link)
    if not decision["eligible"]:
        raise DomainError("criteria_not_met", decision["eligibility_reason"], 422)
    return submit_agent(
        db,
        "cve_analysis",
        program,
        {
            "cve_id": cve.id,
            "gate_hash": cves.gate_hash(program, cve, link),
            "record_hash": cve.record_hash,
            "source_record": cve.raw,
            "eligibility": decision,
        },
        submitted,
        key,
    )


def refresh_cve_policy(db, program, cve, link):
    decision = cves.gate(program, cve, link)
    relevant_hash = cves.gate_hash(program, cve, link)
    if decision["eligible"] and link.data.get("notified_hash") != relevant_hash:
        notify(
            db,
            f"cve:{program.id}:{cve.id}:{relevant_hash}",
            cve.id + " — " + cve.data["title"],
            f"/cves?program_id={program.id}&cve_id={cve.id}",
            "Eligible Base score " + str(decision["qualifying_score"]["base_score"]),
        )
        link.data = {**link.data, "notified_hash": relevant_hash}
    if decision["eligible"] and program.config.get("cve_auto_analyze") and not program.archived:
        key = f"cve-analysis:{program.id}:{cve.id}:{relevant_hash}"
        if not db.scalar(select(Job).where(Job.idempotency_key == key)):
            try:
                if not program.cursor:
                    # Held until a baseline source check, which dispatches it.
                    raise DomainError(
                        "source_not_checked",
                        "Complete a source check before generating grounded evidence",
                        422,
                    )
                queue_cve(db, program, cve, link, key=key)
                link.data = {**link.data, "analysis_blocked": None}
            except DomainError as exc:
                link.data = {**link.data, "analysis_blocked": exc.as_dict()}


def last_observation(db, program, success_only=False):
    rows = list(
        db.scalars(
            select(Observation)
            .where(
                Observation.program_id == program.id,
                Observation.source_generation == program.source_generation,
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
        "program_id": row.program_id,
        "recipe_id": row.recipe_id,
        "source_generation": row.source_generation,
        "checked_at": utc(row.checked_at),
    }


def program_json(db, row):
    columns = (
        "id",
        "asset_name",
        "asset_url",
        "product_kind",
        "product_name",
        "source_kind",
        "source_url",
        "source_ref",
        "source_path",
        "plugin_slug",
        "monitor_interval_days",
        "monitor_enabled",
        "archived",
        "source_generation",
        "last_check_at",
        "next_check_at",
        "last_error",
        "config",
    )
    result = {name: getattr(row, name) for name in columns}
    for name in ("last_check_at", "next_check_at"):
        result[name] = utc(result[name])
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


def analysis_json(db, row):
    superseded = False
    if row.kind == "cve_analysis":
        cve = db.get(CVE, row.subject_id)
        program = db.get(Program, row.program_id)
        link = db.scalar(
            select(ProgramCVE).where(
                ProgramCVE.program_id == row.program_id, ProgramCVE.cve_id == row.subject_id
            )
        )
        if cve and program and link:
            superseded = cves.analysis_superseded(program, cve, link, row.result.get("gate_hash"))
    return {
        "superseded": superseded,
        "id": row.id,
        "program_id": row.program_id,
        "kind": row.kind,
        "subject_id": row.subject_id,
        "job_id": row.job_id,
        "input_hash": row.input_hash,
        "profile": row.profile,
        "result": row.result,
        "created_at": utc(row.created_at),
        "artifacts": artifact_rows(db, "analysis", row.id),
    }


def commit_json(db, row):
    analyses = list(
        db.scalars(
            select(Analysis)
            .where(Analysis.kind == "commit_analysis", Analysis.subject_id == row.id)
            .order_by(Analysis.created_at.desc())
        )
    )
    return {
        "id": row.id,
        "program_id": row.program_id,
        "revision": row.revision,
        "source_generation": row.source_generation,
        **row.data,
        "triage_status": row.triage_status,
        "triage_result": row.triage_result,
        "review_decision": row.review_decision,
        "analyses": [analysis_json(db, a) for a in analyses],
    }


def cve_json(db, cve, link):
    program = get(db, Program, link.program_id)
    analyses = list(
        db.scalars(
            select(Analysis)
            .where(
                Analysis.kind == "cve_analysis",
                Analysis.subject_id == cve.id,
                Analysis.program_id == program.id,
            )
            .order_by(Analysis.created_at.desc())
        )
    )
    return {
        "id": cve.id,
        "program_id": program.id,
        **cve.data,
        **cves.gate(program, cve, link),
        "applicability": cves.applicability(program, cve, last_observation(db, program)),
        "analyses": [analysis_json(db, a) for a in analyses],
        "analysis_blocked": link.data.get("analysis_blocked")
        if program.config.get("cve_auto_analyze")
        else None,
    }


def finding_json(db, row, root):
    files = (
        artifacts.resource_files(db, root, "finding", row.id, row.artifact_revision)
        if row.artifact_revision
        else {}
    )
    labs = list(
        db.scalars(
            select(LabRun).where(LabRun.finding_id == row.id).order_by(LabRun.created_at.desc())
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
        "program_id": row.program_id,
        "kind": row.kind,
        "cve_id": row.cve_id,
        "title": row.title,
        "status": row.status,
        **row.data,
        "artifact_state": artifacts.completeness(files),
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


def job_json(db, row, with_events=True):
    result = {
        name: getattr(row, name)
        for name in (
            "id",
            "kind",
            "program_id",
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
            select(Program)
            .where(
                Program.monitor_enabled.is_(True),
                Program.archived.is_(False),
                (Program.next_check_at.is_(None)) | (Program.next_check_at <= current),
            )
            .with_for_update(skip_locked=True)
        )
    )
    for program in due:
        if not db.scalar(
            select(Job).where(
                Job.program_id == program.id,
                Job.kind == "source_check",
                Job.status.in_(["queued", "running", "cancelling"]),
            )
        ):
            enqueue(db, "source_check", program, job_input(program))
        program.next_check_at = current + timedelta(days=program.monitor_interval_days)
        if program.config.get("cve_selectors"):
            if not db.scalar(
                select(Job).where(
                    Job.program_id == program.id,
                    Job.kind == "cve_sync",
                    Job.status.in_(["queued", "running", "cancelling"]),
                )
            ):
                enqueue(db, "cve_sync", program, job_input(program))
        if program.config.get("active_recipe_id") and program.config.get(
            "version_monitor_enabled", True
        ):
            enqueue(
                db,
                "version_check",
                program,
                job_input(program, recipe_id=program.config["active_recipe_id"]),
            )
    return len(due)
