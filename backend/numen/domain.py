import hashlib
import json
import re
from urllib.parse import quote, urlparse
from datetime import timedelta
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from . import advisories, artifacts, cves, detection, served
from .models import (
    Account,
    Action,
    Agent,
    AgentMessage,
    AdvisoryCache,
    AdvisoryMatch,
    Analysis,
    Artifact,
    AuditContext,
    CVE,
    Commit,
    Exposure,
    FileManifest,
    Finding,
    Job,
    JobEvent,
    LabRun,
    Notification,
    Observation,
    Application,
    ApplicationCVE,
    ApplicationRepository,
    PushDelivery,
    PushWebhook,
    RemediationPR,
    Repository,
    ServedChange,
    ServedFetch,
    ServerChange,
    Setting,
    Snapshot,
    Transcript,
    WatchedPage,
    now,
    utc,
)
from .schemas import AUDIT_MAX_FUNCTIONS, CODEX_REFUSED, OPERATIONS, Profile
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


def plugin_records():
    """The Pi plugins the runner image pins, read-only (A13): runner/plugins.lock.json's records,
    or one unavailable Command Code provider when the manifest cannot be read."""
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
    return records


def public_account(account, plugins=None):
    supported = SUPPORTED.get(account.provider, [])
    if account.auth_type == "native_oauth":
        supported = [NATIVE_AGENTS[account.provider]]
    if account.data.get("status") == "ready" and account.data.get("agent_models") is not None:
        supported = list(account.data["agent_models"])
    selection_error = None
    if account.provider == "commandcode" and plugins is not None:
        plugin = next((p for p in plugins if p.get("id") == "pi-commandcode-provider"), None)
        if not plugin or plugin.get("health") != "ready":
            supported = []
            selection_error = "Command Code provider plugin is unavailable in the runner image"
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


def enabled_plugins(provider):
    # A runtime loads only the ready bundled plugins that contribute this provider.
    return [
        p.get("id")
        for p in plugin_records()
        if p.get("health") == "ready" and p.get("provider_contribution") == provider
    ]


def require_provider_plugin(provider):
    if provider == "commandcode" and not enabled_plugins(provider):
        raise DomainError(
            "plugin_unavailable",
            "The Command Code provider plugin is unavailable in the runner image",
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
    if profile["agent"] == "codex" and operation in CODEX_REFUSED:
        raise DomainError(*CODEX_REFUSED[operation], 422)
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
    require_provider_plugin(account.provider)
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


def automated_profile(db, application, operation):
    """The saved or default profile of a run nobody started by hand. Automated runs use only
    Provider accounts that hold an API key (A13); subscription sign-ins stay for manual runs."""
    profile = resolve_profile(db, application, operation)
    account = db.get(Account, profile["connection_id"])
    if account.auth_type != "api_key":
        raise DomainError(
            "api_key_required",
            f"Automated runs use only Provider accounts that hold an API key; {account.label} uses a "
            "subscription sign-in. Start this run by hand or select an API-key account.",
            422,
        )
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
    in the order they were added (by link id when added at the same instant). Removed links are
    included."""
    return db.execute(
        select(ApplicationRepository, Repository)
        .join(Repository, Repository.id == ApplicationRepository.repository_id)
        .where(ApplicationRepository.application_id == application.id)
        .order_by(ApplicationRepository.role != "own", ApplicationRepository.created_at, ApplicationRepository.id)
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
        .order_by(ApplicationRepository.created_at, ApplicationRepository.id)
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
    removed), else the first that ever linked it. It is the context of commit pages and owns the
    commit's one Analysis; the Findings that Analysis opens are per affected Application."""
    rows = linked_applications(db, db.get(Repository, commit.repository_id))
    return next((a for a, link in rows if in_use(a, link)), rows[0][0] if rows else None)


def affected_applications(db, repository, exposures):
    """The Applications a Verdict on `repository` reaches: each one that uses it as its Own
    repository, and each one that uses it as an Upstream repository unless its Exposure in
    `exposures` ({application_id: Exposure}) is not_exposed. Unknown counts as exposed, and so does
    an Upstream link with no Exposure, which a Verdict that opens no Finding does not compute."""
    return [a for a, link in linked_applications(db, repository) if in_use(a, link) and (
        link.role == "own" or getattr(exposures.get(a.id), "state", "unknown") != "not_exposed")]


def record_exposure(db, application, commit, verdict, found):
    """Stores the Application's Exposure to `verdict` on `commit` (A05): `found` is {state, reason,
    locked_version, tag, target, analysis_id}. One row per (Application, commit), updated by a
    repeat Analysis. Returns the row."""
    query = select(Exposure).where(Exposure.application_id == application.id, Exposure.commit_id == commit.id)
    row = db.scalar(query)
    if row is None:
        # As repository_for: a concurrent writer that creates the key first wins, and this one updates it.
        try:
            with db.begin_nested():
                row = Exposure(application_id=application.id, repository_id=commit.repository_id,
                               commit_id=commit.id, verdict=verdict, state=found["state"], data={})
                db.add(row)
        except IntegrityError:
            row = db.scalar(query)
    row.verdict, row.state, row.updated_at = verdict, found["state"], now()
    row.data = {key: found.get(key) for key in ("reason", "locked_version", "tag", "target", "analysis_id")}
    return row


def queue_exposure(db, application, repository):
    """Queues the Application's exposure_check for `repository` after its Locked version changed or
    it was linked (A05), unless one is queued already. Only an in-use Upstream link gets one (Own
    links never get Exposure), and only once the repository has a Verdict that opens a Finding:
    before that there is nothing to recompute. Returns the job, or None."""
    link = next((link for link, r in links(db, application) if r.id == repository.id), None)
    if link is None or link.role != "upstream" or not in_use(application, link):
        return None
    if db.scalar(select(Commit.id).where(
            Commit.repository_id == repository.id, Commit.source_generation == repository.source_generation,
            Commit.verdict.in_(OPENING_VERDICTS)).limit(1)) is None:
        return None
    queued = db.scalar(select(Job).where(
        Job.kind == "exposure_check", Job.status == "queued", Job.application_id == application.id,
        Job.input["repository_id"].as_string() == repository.id).limit(1))
    return queued or enqueue(db, "exposure_check", application, repository_input(repository))


def exposure_json(row, application_name=None):
    return {"application_id": row.application_id, "application_name": application_name, "verdict": row.verdict,
            "state": row.state, **{key: row.data.get(key) for key in ("reason", "locked_version", "tag", "target")}}


def triage_application(db, repository):
    """The Application whose Triage settings judge the repository's new commits: the first
    one that uses it and has Triage on. A shared repository is triaged once."""
    for application, link in linked_applications(db, repository):
        if in_use(application, link) and application.config.get("triage_mode", "disabled") != "disabled":
            return application
    return None


# Automatic Analyses per UTC day (A04), automatic patch drafting (A08) and Proof bundle drafting
# (draft_bundle) included. Manual runs are neither capped nor counted.
ANALYSIS_CAPS = {"application": 10, "account": 30}
CAPPED_KINDS = ("commit_analysis", "served_analysis", "server_analysis", "patch_drafting", "finding_artifacts")


def over_cap(db, application, profile, shared):
    """The cap ("application" or "account") that one more automatic run of the Application on
    `profile` would pass today, else None. A shared Upstream commit counts only against the
    account's. Over a cap it records the scope's one event and Alert of the day (A12)."""
    midnight = now().replace(hour=0, minute=0, second=0, microsecond=0)
    # Job rows are durable, so the counts survive restarts and reset at midnight on their own.
    # ponytail: unlocked counts; concurrent flags can overrun a cap by the number of Triage
    # workers. Lock the account row here if exact caps ever matter.
    today = select(func.count(Job.id)).where(
        Job.kind.in_(CAPPED_KINDS),
        Job.created_at >= midnight,
        Job.input["automatic"].as_boolean().is_(True),
    )
    used = {
        "application": 0 if shared else db.scalar(today.where(
            Job.application_id == application.id, Job.input["shared"].as_boolean().is_(False)
        )),
        "account": db.scalar(today.where(Job.profile["connection_id"].as_string() == profile["connection_id"])),
    }
    cap = next((scope for scope, limit in ANALYSIS_CAPS.items() if used[scope] >= limit), None)
    if not cap:
        return None
    resource = application.id if cap == "application" else profile["connection_id"]
    day = midnight.date().isoformat()
    if not db.scalar(select(Action.id).where(
        Action.resource_type == cap,
        Action.resource_id == resource,
        Action.data["action"].as_string() == "analysis_cap_reached",
        Action.data["day"].as_string() == day,
    ).limit(1)):
        db.add(Action(resource_type=cap, resource_id=resource,
                      data={"action": "analysis_cap_reached", "day": day, "limit": ANALYSIS_CAPS[cap]}))
        # An account cap belongs to no Application, so its Alert names the Provider account.
        where = (
            {"application": application.asset_name, "link": f"/reviews?application={application.id}"}
            if cap == "application"
            else {"account": db.get(Account, resource).label, "link": "/settings?tab=accounts"}
        )
        notify(db, f"cap:{cap}:{resource}:{day}", verdict="Cap reached", **where)
    return cap


def start_analysis(db, commit):
    """Starts the automatic Analysis of a change Triage flagged, once per commit, so a shared
    Upstream commit is analysed once. It counts against the Application's and the Provider
    account's caps for the UTC day, a shared Upstream commit only against the account's. Over a
    cap the change waits, and schedule() starts it once the caps reset at 00:00 UTC."""
    key = f"analysis:{commit.id}"
    if db.scalar(select(Job.id).where(Job.idempotency_key == key)):
        return None
    rows = linked_applications(db, db.get(Repository, commit.repository_id))
    users = [a for a, link in rows if in_use(a, link)]
    if not users:
        return None
    application, shared = users[0], len(users) > 1  # users[0] is commit_application()
    inputs = job_input(db, application, commit_id=commit.id, source_ref=commit.revision)
    return start_automatic(db, commit, "commit_analysis", application, inputs, key, shared)


def start_served_analysis(db, change):
    """Starts the automatic Analysis of a served-content change Triage flagged (A10), once per
    change, within the same caps as a commit's: the Application's and the Provider account's."""
    key = f"served-analysis:{change.id}"
    if db.scalar(select(Job.id).where(Job.idempotency_key == key)):
        return None
    return start_automatic(db, change, "served_analysis", db.get(Application, change.application_id),
                           {"served_change_id": change.id}, key)


def start_server_analysis(db, change):
    """Starts the automatic Analysis of a Server change Triage flagged (B06), once per change,
    within the same caps as a commit's."""
    key = f"server-analysis:{change.id}"
    if db.scalar(select(Job.id).where(Job.idempotency_key == key)):
        return None
    return start_automatic(db, change, "server_analysis", db.get(Application, change.application_id),
                           {"server_change_id": change.id}, key)


def start_automatic(db, subject, kind, application, inputs, key, shared=False):
    """Queues the automatic Analysis `kind` of `subject`, a Commit, ServedChange or ServerChange, on the
    Application's commit_analysis profile, or records why it waits for a cap or is blocked."""
    try:
        profile = automated_profile(db, application, "commit_analysis")
    except DomainError as exc:
        subject.analysis_state = {"status": "blocked", "error": exc.as_dict()}
        return None
    cap = over_cap(db, application, profile, shared)
    if cap:
        previous = subject.analysis_state or {}
        since = previous.get("since") if previous.get("status") == "waiting_for_cap" else now().isoformat()
        subject.analysis_state = {"status": "waiting_for_cap", "since": since, "cap": cap}
        return None
    job = enqueue(db, kind, application, {**inputs, "automatic": True, "shared": shared}, profile, key)
    subject.analysis_state = {"status": "queued", "job_id": job.id}
    return job


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
    """The repository's queued, running or cancelling source check. It first takes the Repository
    row lock (FOR NO KEY UPDATE) until the transaction ends, so the scheduler, Check now and a
    nudge (B02), which all look here before they queue one, never queue two. Callers lock their
    Application FOR NO KEY UPDATE first."""
    # ponytail: a transaction that queues for several repositories locks them in link order, so
    # two crossing over shared repositories can deadlock and Postgres aborts one; lock them in id
    # order if that is ever seen.
    db.execute(select(Repository.id).where(Repository.id == repository.id).with_for_update(key_share=True))
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
                queue_cve(db, application, cve, link, automated_profile(db, application, "cve_analysis"), key)
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


def link_json(db, link, repository):
    # B02: only an Own link has a Push webhook. It shows the last delivery, never its push id or secret.
    webhook = link.role == "own" and db.scalar(select(PushWebhook).where(PushWebhook.repository_id == repository.id))
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
        "push_webhook": {
            "created_at": utc(webhook.created_at),
            "last_accepted": webhook.last_accepted,
            "last_refusal": webhook.last_refusal,
        } if webhook else None,
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
    result["repositories"] = [link_json(db, link, repository) for link, repository in rows]
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
        result["exportable"] = exportable(db, "analysis", row.id)
    return result


def commit_findings(db, ids):
    """The Findings each commit opened (relation source) or was linked to (relation linked), in
    every Application, keyed by commit id."""
    found = {}
    if not ids:
        return found
    ids = list(ids)
    named = select(Finding, Application.asset_name).join(Application, Application.id == Finding.application_id)
    source = Finding.data["source_commit_id"].as_string()
    linked = Action.data["commit_id"].as_string()
    rows = [
        (finding.data.get("source_commit_id"), finding, name, "source")
        for finding, name in db.execute(named.where(source.in_(ids)).order_by(Finding.created_at))
    ] + [
        (commit_id, finding, name, "linked")
        for finding, name, commit_id in db.execute(
            named.add_columns(linked)
            .join(Action, Action.resource_id == Finding.id)
            .where(Action.resource_type == "finding", Action.data["action"].as_string() == "linked", linked.in_(ids))
            .order_by(Action.created_at)
        )
    ]
    for commit_id, finding, name, relation in rows:
        found.setdefault(commit_id, []).append({
            "id": finding.id, "title": finding.title, "status": finding.status, "source": finding.source,
            "application_id": finding.application_id, "application_name": name, "relation": relation,
        })
    return found


def commit_exposures(db, ids):
    """Each commit's Exposures (A05), one per Application its Upstream Verdict was checked for,
    keyed by commit id. A not-exposed Verdict is recorded only here, on the Upstream repository."""
    found = {}
    rows = db.execute(
        select(Exposure, Application.asset_name)
        .join(Application, Application.id == Exposure.application_id)
        .where(Exposure.commit_id.in_(list(ids)))
        .order_by(Application.asset_name, Exposure.application_id)
    ) if ids else []
    for row, name in rows:
        found.setdefault(row.commit_id, []).append(exposure_json(row, name))
    return found


def commit_json(db, row, findings=None, exposures=None):
    if findings is None:
        findings = commit_findings(db, [row.id])
    if exposures is None:
        exposures = commit_exposures(db, [row.id])
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
        "verdict": row.verdict,
        "analysis_state": row.analysis_state,
        "analyses": [analysis_json(db, a) for a in analyses],
        "findings": findings.get(row.id, []),
        "exposures": exposures.get(row.id, []),
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


# The A11 lifecycle: the states each state can be reached from, and who or what may move a
# Finding there. Draft is an artifact-completeness state (AC-12), never a lifecycle state.
FINDING_TRANSITIONS = {"confirmed": ("open",), "dismissed": ("open",), "remediated": ("open", "confirmed")}
FINDING_CAUSES = {
    "confirmed": {"operator", "proof", "detection_rule", "advisory", "regression"},
    "dismissed": {"operator"},
    "remediated": {"operator", "remediation_pr", "version_bump", "baseline_match", "deployed_version", "manifest"},
}


def transition_finding(db, finding, state, cause):
    """Moves a Finding to `state`, recording `cause` ({by, ...refs}) and when. Returns False,
    changing nothing, when the Finding's state cannot move there. Callers decide whether the
    cause applies: a deployed_version cause is for Own-repository Vulnerability fix Findings only.
    A regression (B07: a named SHA-256 seen again) moves only a Remediated server_files Finding
    back to Confirmed."""
    if cause.get("by") not in FINDING_CAUSES[state]:
        raise ValueError(f"{cause.get('by')!r} cannot make a Finding {state}")
    db.refresh(finding, with_for_update=True)
    regression = cause["by"] == "regression"
    if regression and finding.source != "server_files":
        raise ValueError("Only a server_files Finding regresses")
    if finding.status not in (("remediated",) if regression else FINDING_TRANSITIONS[state]):
        return False
    cause = {**cause, "at": now().isoformat()}
    db.add(Action(resource_type="finding", resource_id=finding.id, data={
        "action": "transition", "from": finding.status, "to": state, "cause": cause}))
    finding.status, finding.updated_at = state, now()
    finding.data = {**finding.data, "cause": cause}
    return True


# The Verdicts that open a Finding (A11), on an Own repository or an exposed Upstream one.
OPENING_VERDICTS = ("Vulnerability fix", "Vulnerability introduced", "Malicious change")
# Where each source keeps its subject: the commit, the CVE record (the cve_id column), the
# served-content change or the advisory.
FINDING_SUBJECTS = {"commit": "source_commit_id", "cve": None, "served_content": "subject_id", "advisory": "subject_id",
                    "server_files": "subject_id"}


def open_finding(db, application, source, subject, title, ref, cause):
    """Opens the Application's Finding for `subject`, or returns the one it already has, in any
    state and unchanged: a repeat Analysis never opens a duplicate and never reopens a Dismissed
    or Remediated Finding. `ref` is the source shown (short SHA, Watched page or advisory id) and
    `cause` what opened it. Opening queues the Finding's one Alert. Returns (finding, opened)."""
    key = FINDING_SUBJECTS[source]
    match = Finding.cve_id == subject if key is None else Finding.data[key].as_string() == subject
    finding = db.scalar(
        select(Finding)
        .where(Finding.application_id == application.id, Finding.source == source, match)
        .order_by(Finding.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    if finding:
        return finding, False
    cause = {**cause, "at": now().isoformat()}
    finding = Finding(
        application_id=application.id, source=source, status="open", title=title[:300],
        cve_id=subject if source == "cve" else None,
        data={**({key: subject} if key else {}), "source_ref": ref, "cause": cause},
    )
    db.add(finding)
    db.flush()
    db.add(Action(resource_type="finding", resource_id=finding.id,
                  data={"action": "opened", "cause": cause, "source_ref": ref}))
    notify(db, f"finding:{finding.id}:opened", application=application.asset_name, source=ref,
           verdict=alert_verdict(cause), link=f"/findings/{finding.id}")
    return finding, True


def source_commit(db, finding):
    """A commit Finding's source commit, or the exposed Upstream Vulnerability fix that gave an
    advisory Finding its n-day Proof (run_playbook's fix_commit_id), or None."""
    key = {"commit": "source_commit_id", "advisory": "fix_commit_id"}.get(finding.source)
    return db.get(Commit, finding.data.get(key) or "") if key else None


def finding_verdict(db, finding):
    """The Verdict the Finding answers to: Malicious change when its source commit's newest
    Verdict is one, else the Verdict that opened it, else its source commit's newest Verdict.
    None for a Finding with no Verdict, such as a cve Finding or one the Operator opened."""
    commit = source_commit(db, finding)
    if commit is not None and commit.verdict == "Malicious change":
        return commit.verdict
    opened = db.scalar(select(Action).where(
        Action.resource_type == "finding", Action.resource_id == finding.id,
        Action.data["action"].as_string() == "opened"))
    return (opened and (opened.data.get("cause") or {}).get("verdict")) or getattr(commit, "verdict", None)


def malicious_change(db, finding):
    """Whether the Finding is for a Malicious change, which never runs (ADR-0004): a Malicious
    change Verdict opened it, or is its source commit's newest Verdict."""
    return finding_verdict(db, finding) == "Malicious change"


# The A06 Playbook matrix: the steps each Verdict runs, by the role of the repository it is about
# (own, upstream) or served_content, and an Advisory check match's steps.
PLAYBOOKS = {
    ("advisory", None): ("report", "remediation_pr"),
    ("own", "Vulnerability introduced"): ("proof", "report", "remediation_pr"),
    ("own", "Malicious change"): ("static_proof", "detection_rule", "remediation_pr", "cleanup_report"),
    ("own", "Vulnerability fix"): ("report", "deployed_version_check"),
    ("upstream", "Vulnerability introduced"): ("proof", "disclosure_report", "remediation_pr"),
    ("upstream", "Malicious change"): ("static_proof", "detection_rule", "cleanup_report", "remediation_pr",
                                       "served_content_sweep"),
    ("upstream", "Vulnerability fix"): ("proof", "remediation_pr"),
    ("served_content", "Malicious change"): ("static_proof", "detection_rule", "cleanup_report"),
    # B07: Quarantine after Approval. Its static Proof, Detection rule and cleanup report are deferred.
    ("server_files", "Malicious change"): ("quarantine",),
}


def finding_repository(db, finding):
    """The repository the Finding is about: its source commit's (source_commit), a cve Finding's
    Application's source repository; None for any other Finding."""
    if finding.source == "cve":
        return source_repository(db, db.get(Application, finding.application_id))
    commit = source_commit(db, finding)
    return db.get(Repository, commit.repository_id) if commit else None


def finding_role(db, finding):
    """own or upstream: the role of the Finding's repository in its Application, or None."""
    repository = finding_repository(db, finding)
    return next((link.role for link, r in links(db, db.get(Application, finding.application_id))
                 if repository is not None and r.id == repository.id), None)


def finding_cell(db, finding):
    """The Finding's cell of PLAYBOOKS: its (role, Verdict), the role being served_content for a
    served_content Finding, which for an advisory Finding is that of the exposed Upstream
    Vulnerability fix that gave it an n-day Proof (A16), else ("advisory", None) for an advisory
    Finding, or None, as for a Finding the Operator opened on no Verdict, which keeps every step."""
    role = finding.source if finding.source in ("served_content", "server_files") else finding_role(db, finding)
    cell = (role, finding_verdict(db, finding))
    return cell if cell in PLAYBOOKS else ("advisory", None) if finding.source == "advisory" else None


def finding_exposure(db, finding):
    """The Exposure (A05) of the Finding's Application to its source commit, or None."""
    commit = source_commit(db, finding)
    return commit and db.scalar(select(Exposure).where(
        Exposure.application_id == finding.application_id, Exposure.commit_id == commit.id))


def deployed_version(finding):
    """The Finding's Deployed version, shown apart from its lifecycle: before_fix, serving_fix or
    unknown, from its last Deployed version check (A06)."""
    return (finding.data.get("deployed_version_check") or {}).get("state", "unknown")


def deployed_findings(db, application):
    """The Application's open or confirmed Own-repository Vulnerability fix Findings: the only ones
    a Deployed version check is for (A06, A11)."""
    return [finding for finding in db.scalars(select(Finding).where(
        Finding.application_id == application.id, Finding.source == "commit",
        Finding.status.in_(("open", "confirmed"))).order_by(Finding.created_at))
        if finding_cell(db, finding) == ("own", "Vulnerability fix")]


def apply_deployed_check(db, finding, check, observation_id):
    """Records the Deployed version check `check` ({state, version, reason}) of the version check
    `observation_id` on an Own-repository Vulnerability fix Finding, and remediates it when the
    Asset serves the fix (A11). Any other Finding is left alone: transition_finding does not check
    a deployed_version cause, so this caller does. Returns whether it applied."""
    if finding_cell(db, finding) != ("own", "Vulnerability fix"):
        return False
    db.flush()  # Refreshing discards unflushed changes the caller made, such as run_playbook's.
    db.refresh(finding, with_for_update=True)
    finding.data = {**finding.data, "deployed_version_check": {
        **check, "observation_id": observation_id, "checked_at": now().isoformat()}}
    if check["state"] == "serving_fix":
        db.flush()
        transition_finding(db, finding, "remediated", {
            "by": "deployed_version", "observation_id": observation_id, "version": check["version"]})
    return True


def exportable(db, resource_type, resource_id):
    """Whether the artifacts of the resource may be exported (A15): never an Upstream Proof, which
    overrides Numen's AC-12 for Upstream Findings. Not exportable: an Upstream Finding (a cve
    Finding on an Upstream source repository among them) and its Labs' artifacts, an Analysis of
    a commit of a repository that any Application links as Upstream, and a CVE analysis of an
    Application whose source repository is an Upstream one. An Analysis Transcript is its
    Analysis's."""
    if resource_type == "transcript":
        transcript = db.get(Transcript, resource_id)
        resource_type, resource_id = "analysis", transcript and transcript.data.get("analysis_id")
    if resource_type == "lab":
        resource_type, resource_id = "finding", getattr(db.get(LabRun, resource_id), "finding_id", None)
    if resource_type == "finding":
        finding = db.get(Finding, resource_id or "")
        return finding is None or finding_role(db, finding) != "upstream"
    analysis = db.get(Analysis, resource_id or "") if resource_type == "analysis" else None
    if analysis is None or analysis.kind in ("served_analysis", "server_analysis"):  # neither has an Upstream Proof
        return True
    if analysis.kind == "commit_analysis":
        commit = db.get(Commit, analysis.subject_id)
        repository = commit and db.get(Repository, commit.repository_id)
        return repository is None or all(link.role != "upstream" for _, link in linked_applications(db, repository))
    application = db.get(Application, analysis.application_id)
    repository = application and source_repository(db, application)
    return repository is None or all(link.role != "upstream" for link, r in links(db, application) if r.id == repository.id)


def require_lab(db, finding):
    """Refuses a Lab for a Finding whose Playbook has no Lab Proof (A06): a Malicious change never
    runs (ADR-0004), an Own-repository Vulnerability fix gets a report and a Deployed version
    check instead, and an Advisory check match a report and a bump Remediation PR, unless an
    exposed Upstream Vulnerability fix gave its Finding that fix's n-day Proof (finding_cell)."""
    if finding.source == "server_files":
        raise DomainError("lab_not_allowed", "Server files are never run: a server-files Finding has no Lab", 409)
    if malicious_change(db, finding):
        raise DomainError("lab_not_allowed", "A Malicious change never runs: its Proof is static, so it has no Lab", 409)
    cell = finding_cell(db, finding)
    if cell == ("advisory", None):
        raise DomainError("lab_not_allowed", "An Advisory check match gets a report and a bump Remediation PR, "
                          "never a Lab Proof", 409)
    if cell and "proof" not in PLAYBOOKS[cell]:
        raise DomainError("lab_not_allowed", "An Own-repository Vulnerability fix gets a report and a Deployed "
                          "version check, not a Lab", 409)
    # AC-A07: no Lab installs an Upstream Malicious change. One built on the Own repository installs
    # all of its Upstream repositories; a minimal app only the Finding's.
    application = db.get(Application, finding.application_id)
    repository = finding_repository(db, finding)
    minimal = repository is not None and vulnerable_app_rule(db, application, repository) == "minimal"
    if malicious_exposures(db, application, repository if minimal else None):
        raise DomainError("lab_not_allowed", "This Lab would install an Upstream Malicious change the Application "
                          "is exposed to; pin a release without it first", 409)


def repository_link(db, application, repository):
    """The Application's link to `repository`, removed or not, or None."""
    return next((link for link, r in links(db, application) if repository is not None and r.id == repository.id),
                None)


def locked_packages(db, application, repository):
    """(ecosystem, names, Locked version) of the packages the Application's Upstream link to
    `repository` stands for, in its first package's ecosystem, which an Upstream Proof's Lab
    installs (A07); None for a link with no package or no Locked version."""
    link = repository_link(db, application, repository)
    if link is None or link.role != "upstream" or not link.packages or not link.locked_version:
        return None
    ecosystem = link.packages[0].split(":", 1)[0]
    return ecosystem, [p.split(":", 1)[1] for p in link.packages if p.startswith(ecosystem + ":")], link.locked_version


def vulnerable_app_rule(db, application, repository):
    """The vulnerable app a Proof of a change to `repository` builds for the Application (A07):
    own_commit, the Own repository at the Verdict's commit; own_head, the Own repository at its
    default-branch head with the Locked version installed, for an Upstream link with a package and
    a Locked version; else minimal, an app of its own that pins the Locked version, if any."""
    own = own_repository(db, application)
    if own is not None and repository is not None and own.id == repository.id:
        return "own_commit"
    return "own_head" if own is not None and locked_packages(db, application, repository) else "minimal"


def lab_supplied(db, finding):
    """The vulnerable-app/ paths a Lab adds to the Finding's bundle (A07): an Own-repository Proof's
    Own repository at the Verdict's commit, from its stored snapshot; an Upstream Proof's
    package.json, which pins its npm Locked version; else none."""
    application = db.get(Application, finding.application_id)
    repository, commit = finding_repository(db, finding), source_commit(db, finding)
    if repository is None:
        return ()
    if vulnerable_app_rule(db, application, repository) == "own_commit":
        files = commit and db.scalar(select(Snapshot.files).where(
            Snapshot.repository_id == repository.id, Snapshot.source_generation == repository.source_generation,
            Snapshot.source_ref == commit.revision))
        return {"vulnerable-app/" + p for p in files or () if p not in LAB_DROPPED}
    locked = locked_packages(db, application, repository)
    return {"vulnerable-app/package.json"} if locked and locked[0] == "npm" else ()


# An Own tree's files a Lab leaves out: the artifact manifest's name, and the .dockerignore of the
# repository's own Dockerfile, which the bundle's replaces (it would drop the fetched node_modules).
LAB_DROPPED = ("manifest.json", ".dockerignore")


def malicious_exposures(db, application, repository=None):
    """The Malicious change commits (current generation) on the Application's Upstream
    repositories, through links not removed (on `repository` only, when given), that are exposed or
    unknown to it (A05). One with no Exposure row for the Application, such as a Verdict stored
    while its link was off, is unknown, which counts as exposed."""
    query = select(Commit).join(Repository, and_(
        Repository.id == Commit.repository_id, Repository.source_generation == Commit.source_generation)).join(
        ApplicationRepository, ApplicationRepository.repository_id == Commit.repository_id).outerjoin(
        Exposure, and_(Exposure.application_id == application.id, Exposure.commit_id == Commit.id,
                       Exposure.verdict == "Malicious change")).where(
        ApplicationRepository.application_id == application.id, ApplicationRepository.role == "upstream",
        ApplicationRepository.removed_at.is_(None), Commit.verdict == "Malicious change",
        or_(Exposure.id.is_(None), Exposure.state != "not_exposed"))
    if repository is not None:
        query = query.where(Commit.repository_id == repository.id)
    return list(db.scalars(query))


def upstream_dependency(db, application, repository, target):
    """What a pin or bump of the Application's Upstream `repository` to the release `target`
    ({tag, version}) changes in the Own repository's manifest: {ecosystem, names, version}, with
    every package the link stands for in its first package's ecosystem, or only the one a
    {package}@ tag names. None without a target, or for a link that stands for no package."""
    link = next((link for link, r in links(db, application) if r.id == repository.id), None)
    if not target or link is None or not link.packages:
        return None
    ecosystem = link.packages[0].split(":", 1)[0]
    names = [p.split(":", 1)[1] for p in link.packages if p.split(":", 1)[0] == ecosystem]
    tagged = [name for name in names if target["tag"] == f"{name}@{target['version']}"]
    return {"ecosystem": ecosystem, "names": tagged or names, "version": target["version"]}


def playbook_steps(db, finding, root):
    """Where each step of the Finding's Playbook cell stands (A06): [{step, status}], [] without a
    cell. A step that needs Approval reads waiting_for_approval (a Proof) or ready (a Remediation
    PR's draft) and blocks no other."""
    cell = finding_cell(db, finding)
    if cell is None:
        return []
    application = db.get(Application, finding.application_id)
    paths = {a.path for a in db.scalars(select(Artifact).where(
        Artifact.resource_type == "finding", Artifact.resource_id == finding.id,
        Artifact.revision == (finding.artifact_revision or "")))}
    lab = db.scalar(select(LabRun.status).where(LabRun.finding_id == finding.id)
                    .order_by(LabRun.created_at.desc(), LabRun.id.desc()).limit(1))
    draft = db.scalar(select(RemediationPR.status).where(RemediationPR.finding_id == finding.id)
                      .order_by(RemediationPR.created_at.desc(), RemediationPR.id.desc()).limit(1))
    if own_repository(db, application) is None:
        remediation = "no_own_repository"
    elif finding.source == "advisory":  # its own bump, with or without an n-day Proof
        remediation = draft or advisory_dependency(db, finding)[1] or "not_drafted"
    elif draft or cell[0] == "own":
        remediation = draft or "not_drafted"
    else:
        exposure = finding_exposure(db, finding)
        target = exposure.data.get("target") if exposure else None
        remediation = (
            ("waiting_for_release" if cell[1] == "Vulnerability fix" else "no_safe_release") if not target
            else "not_drafted" if upstream_dependency(db, application, finding_repository(db, finding), target)
            else "no_package"
        )
    proof = (lab or ("waiting_for_approval" if finding_artifact_state(db, finding, root)["status"] == "complete"
                     else "draft"))
    static = (finding.data.get("static_proof") or {}).get("status", "pending")
    status = {
        "proof": proof,
        # An advisory Finding's report is rendered from its matches (finding_json's advisories).
        "report": "ready" if "report.md" in paths or finding.source == "advisory" else "missing",
        "disclosure_report": "ready" if "disclosure-report.md" in paths else "missing",
        "static_proof": static,
        "detection_rule": static,
        "cleanup_report": "ready" if finding.data.get("cleanup_report") else "missing",
        "remediation_pr": remediation,
        "deployed_version_check": deployed_version(finding),
        "served_content_sweep": (finding.data.get("served_content_sweep") or {}).get("status", "pending"),
        "quarantine": quarantine_status(db, finding) if cell[0] == "server_files" else None,
    }
    return [{"step": step, "status": status[step]} for step in PLAYBOOKS[cell]]


DISCLOSURE_LIMIT = 64 * 1024


def disclosure_report(db, finding, root):
    """The Disclosure report (A06, A15) the Analysis drafted for an Upstream Finding, read from
    its current revision for the Operator to copy into the Upstream repository's GitHub private
    vulnerability reporting form: {text, form_url}, or None. GarudaNetra never sends it."""
    cell = finding_cell(db, finding)
    if finding_role(db, finding) != "upstream" or (cell and "disclosure_report" not in PLAYBOOKS[cell]):
        return None
    row = db.scalar(select(Artifact).where(
        Artifact.resource_type == "finding", Artifact.resource_id == finding.id,
        Artifact.revision == (finding.artifact_revision or ""), Artifact.path == "disclosure-report.md"))
    if row is None:
        return None
    repository = finding_repository(db, finding)
    return {
        "text": artifacts.read_file(root, row)[:DISCLOSURE_LIMIT].decode(errors="replace"),
        "form_url": f"{repository.source_url}/security/advisories/new" if repository.source_kind == "github" else None,
    }


def own_repository(db, application):
    """The Application's Own repository (its Own link not removed), the only one a Remediation PR
    is ever opened on, or None."""
    return next((r for link, r in links(db, application) if link.role == "own" and link.removed_at is None), None)


def advisory_repository(db, application):
    """The repository whose head the Advisory check reads (A09): the Own repository, else the
    source repository."""
    return own_repository(db, application) or source_repository(db, application)


def queue_advisory(db, application, repository, key):
    return enqueue(db, "advisory_check", application, repository_input(repository), idempotency_key=key)


def schedule_advisory_checks(db):
    """Queues the Advisory check of each monitored Application once per UTC day (A09), once the
    repository it reads has a head."""
    day = now().date().isoformat()
    for application in db.scalars(select(Application).where(
            Application.monitor_enabled.is_(True), Application.archived.is_(False))):
        key = f"advisory:{application.id}:{day}"
        repository = advisory_repository(db, application)
        if repository and repository.cursor and db.scalar(select(Job.id).where(Job.idempotency_key == key)) is None:
            queue_advisory(db, application, repository, key)


# A Served-content check (A10) fetches each Watched page as each of this fixed pair (gateway.USER_AGENTS).
USER_AGENTS = ("browser", "googlebot")
MAX_WATCHED_PAGES = 20


def page_origin(url):
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname, parsed.port or {"http": 80, "https": 443}[parsed.scheme]


def sync_homepage(db, application):
    """Makes the Application's Asset URL its homepage Watched page (A10): a new Asset URL moves the
    homepage to a page with no Baseline, and the old one is no longer watched, nor is any other
    page left on an old origin (their history is kept, as for a removed page). A page the Operator
    already watched at the new URL becomes the homepage with its Baseline."""
    pages = list(db.scalars(select(WatchedPage).where(WatchedPage.application_id == application.id)))
    home = next((page for page in pages if page.homepage), None)
    if home and home.url == application.asset_url:
        return home
    if home:
        home.homepage, home.removed_at = False, home.removed_at or now()
    page = next((page for page in pages if page.url == application.asset_url), None)
    if page is None:
        page = WatchedPage(application_id=application.id, url=application.asset_url, baseline={})
        db.add(page)
    page.homepage, page.removed_at = True, None
    origin = page_origin(application.asset_url)
    for other in pages:  # Watched pages share the Asset URL's origin: those on the old one are no longer watched.
        if other is not page and other.removed_at is None and page_origin(other.url) != origin:
            other.removed_at = now()
    db.flush()
    return page


def watched_pages(db, application):
    """The Application's Watched pages that are not removed, the homepage first."""
    return list(db.scalars(select(WatchedPage).where(
        WatchedPage.application_id == application.id, WatchedPage.removed_at.is_(None),
    ).order_by(WatchedPage.homepage.desc(), WatchedPage.created_at, WatchedPage.id)))


def queue_served_check(db, application, key=None):
    """The Application's Served-content check (A10): the one already active, else a new one."""
    active = db.scalar(select(Job).where(
        Job.kind == "served_check", Job.application_id == application.id,
        Job.status.in_(["queued", "running", "cancelling"])).limit(1))
    return active or enqueue(db, "served_check", application, {}, idempotency_key=key)


def schedule_served_checks(db):
    """Queues the Served-content check of each monitored Application once per window of its
    interval (A10). It is not part of schedule(), which polls repositories."""
    for application in db.scalars(select(Application).where(
            Application.monitor_enabled.is_(True), Application.archived.is_(False))):
        key = f"served:{application.id}:{int(now().timestamp()) // application.monitor_interval_seconds}"
        if db.scalar(select(Job.id).where(Job.idempotency_key == key)) is None:
            queue_served_check(db, application, key)


def record_served_change(db, page, fetch):
    """The served-content change of `fetch`, a fetched fingerprint unlike the page's Baseline for
    its user agent (A10): one per (page, user agent, fingerprint), kept with the first fetch that
    served it, the newest fetched one before that, the Baseline's and the diff from the Baseline."""
    query = select(ServedChange).where(
        ServedChange.page_id == page.id, ServedChange.user_agent == fetch.user_agent,
        ServedChange.fingerprint == fetch.fingerprint)
    row = db.scalar(query)
    if row is None:
        baseline = db.get(ServedFetch, page.baseline[fetch.user_agent]["fetch_id"])
        previous = db.scalar(select(ServedFetch.id).where(
            ServedFetch.page_id == page.id, ServedFetch.user_agent == fetch.user_agent,
            ServedFetch.status == "fetched", ServedFetch.id != fetch.id,
        ).order_by(ServedFetch.created_at.desc()).limit(1))
        # As record_exposure: a concurrent check that records the fingerprint first wins, and only
        # it queues the change's one Triage.
        try:
            with db.begin_nested():
                row = ServedChange(application_id=page.application_id, page_id=page.id, user_agent=fetch.user_agent,
                                   fingerprint=fetch.fingerprint, fetch_id=fetch.id, previous_fetch_id=previous,
                                   baseline_fetch_id=baseline.id, diff=served.diff(baseline.summary, fetch.summary))
                db.add(row)
                db.flush()
                queue_served_triage(db, db.get(Application, page.application_id), row)
        except IntegrityError:
            row = db.scalar(query)
    return row


def queue_served_triage(db, application, change):
    """Queues the Triage of a served-content change by the Application's Triage settings, as
    import_commits does for a commit: none with Triage off, and none on Jev, which reads commits
    only. A profile that cannot run blocks it with the reason."""
    mode = application.config.get("triage_mode", "disabled")
    change.triage_status = "disabled" if mode == "disabled" else "pending"
    if mode == "disabled":
        return
    try:
        if mode == "jev":
            raise DomainError("jev_triage_unsupported",
                              "Jev Triage reads commits only; analyse this served-content change by hand", 422)
        profile = automated_profile(db, application, "commit_triage")
        if profile["agent"] != mode:
            raise DomainError("triage_profile_mismatch", "Triage mode and agent profile differ", 422)
        enqueue(db, "served_triage", application, {"served_change_id": change.id}, profile)
    except DomainError as exc:
        change.triage_status = "blocked"
        change.triage_result = {"decision": "insufficient_context", "reason": exc.message, "error": exc.code}


def queue_server_triage(db, application, change):
    """Queues the Triage of a Server change (B06) as queue_served_triage does a served-content one."""
    mode = application.config.get("triage_mode", "disabled")
    change.triage_status = "disabled" if mode == "disabled" else "pending"
    if mode == "disabled":
        return
    try:
        if mode == "jev":
            raise DomainError("jev_triage_unsupported",
                              "Jev Triage reads commits only; analyse this Server change by hand", 422)
        profile = automated_profile(db, application, "commit_triage")
        if profile["agent"] != mode:
            raise DomainError("triage_profile_mismatch", "Triage mode and agent profile differ", 422)
        enqueue(db, "server_triage", application, {"server_change_id": change.id}, profile)
    except DomainError as exc:
        change.triage_status = "blocked"
        change.triage_result = {"decision": "insufficient_context", "reason": exc.message, "error": exc.code}


SERVER_CHANGE_FIELDS = ("id", "agent_id", "fingerprint", "manifest_id", "baseline_manifest_id", "diff", "incomplete",
                        "triage_status", "triage_result", "review_decision", "verdict", "analysis_state")


def server_change_files(change):
    """The file entries a Server change added or changed: the bytes Triage and Analysis read."""
    return [entry for entry in [*change.diff.get("added", ()), *(m["after"] for m in change.diff.get("modified", ()))]
            if entry.get("type") == "file"]


def server_change_json(db, row):
    """A Server change, with the SHA-256 values of its added and changed files whose bytes are held."""
    digests = sorted({entry["sha256"] for entry in server_change_files(row) if entry.get("sha256")})
    held = set(db.scalars(select(Artifact.resource_id).where(
        Artifact.resource_type == "server_files", Artifact.resource_id.in_(digests)))) if digests else set()
    return {**{name: getattr(row, name) for name in SERVER_CHANGE_FIELDS}, "held": sorted(held),
            "created_at": utc(row.created_at)}


def server_change_label(db, change):
    """A Server change's readable name: its agent's. A server path never names it (B07)."""
    return f"{db.get(Agent, change.agent_id).name} · Server change"


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def named_sha256(finding):
    """The SHA-256 values a server_files Finding names (B07)."""
    return {entry["sha256"] for entry in finding.data.get("server_files") or () if entry.get("sha256")}


def quarantine_list(db, finding):
    """B07: the files of the agent's latest complete File manifest whose SHA-256 the Finding names,
    as a Quarantine command lists them, [{root, path, sha256}] sorted, and that list's SHA-256."""
    named = named_sha256(finding)
    manifest = db.scalar(select(FileManifest).where(
        FileManifest.agent_id == (finding.data.get("agent_id") or ""), FileManifest.status == "complete")
        .order_by(FileManifest.sequence.desc()).limit(1))
    files = sorted(({"root": e["root"], "path": e["path"], "sha256": e["sha256"]} for e in (manifest.entries if manifest else ())
                    if e["type"] == "file" and e.get("sha256") in named), key=lambda f: (f["root"], f["path"]))
    return files, canonical_sha256(files)


def finding_commands(db, finding):
    """The Quarantine and Restore commands signed for the Finding, in sequence order."""
    return list(db.scalars(select(AgentMessage).where(
        AgentMessage.type == "command", AgentMessage.data["finding_id"].as_string() == finding.id)
        .order_by(AgentMessage.sequence)))


def command_state(message):
    """A command's status, expired once past its expiry even before the scheduler marks it."""
    late = message.status == "pending" and message.expires_at is not None and utc(message.expires_at) <= now()
    return "expired" if late else message.status


def result_files(message):
    files = ((message.data or {}).get("result") or {}).get("files")
    return [item for item in files if isinstance(item, dict)] if isinstance(files, list) else []


def quarantined_files(commands):
    """The files done Quarantine commands moved aside that no done Restore has put back."""
    restored = {item.get("quarantine_id") for message in commands if message.name == "restore"
                and message.status == "done" for item in result_files(message) if item.get("status") == "restored"}
    return [{"quarantine_id": item["quarantine_id"], "root": item.get("root"), "path": item.get("path"),
             "sha256": item.get("sha256"), "command_id": message.id}
            for message in commands if message.name == "quarantine" and message.status == "done"
            for item in result_files(message) if item.get("status") == "quarantined"
            and re.fullmatch(r"[0-9a-f]{32}", str(item.get("quarantine_id"))) and item["quarantine_id"] not in restored]


def restore_entries(commands, quarantine):
    """The quarantine ids a Restore of the done Quarantine command `quarantine` names, and their SHA-256."""
    entries = [item["quarantine_id"] for item in quarantined_files(commands) if item["command_id"] == quarantine.id]
    return entries, canonical_sha256(entries)


def quarantine_status(db, finding):
    """The quarantine Playbook step: its latest Quarantine command's status, or waiting_for_approval."""
    latest = [message for message in finding_commands(db, finding) if message.name == "quarantine"]
    return command_state(latest[-1]) if latest else "waiting_for_approval"


def quarantine_json(db, finding):
    """B07: a server_files Finding's Quarantine list and its hash, each Quarantine and Restore
    command with the agent's verified result per file, and the files held in Quarantine. All of it
    is shown as text."""
    agent = db.get(Agent, finding.data.get("agent_id") or "")
    files, digest = quarantine_list(db, finding)
    commands = finding_commands(db, finding)
    rows = []
    for message in commands:
        result = (message.data or {}).get("result") or {}
        row = {"id": message.id, "name": message.name, "sequence": message.sequence, "status": command_state(message),
               "reason": result.get("reason"), "expires_at": utc(message.expires_at), "created_at": utc(message.created_at),
               **{key: message.data[key] for key in ("list_sha256", "entries_sha256", "quarantine_command_id")
                  if key in (message.data or {})}, "files": result_files(message)}
        if message.name == "quarantine" and message.status == "done":
            entries, entries_digest = restore_entries(commands, message)
            row["restore"] = {"entries": entries, "entries_sha256": entries_digest} if entries else None
        rows.append(row)
    return {"agent_id": agent and agent.id, "agent_name": agent and agent.name, "agent_status": agent and agent.status,
            "list": files, "list_sha256": digest, "commands": rows, "quarantined": quarantined_files(commands)}


def served_fetch_json(row):
    return row and {"id": row.id, "status": row.status, "fingerprint": row.fingerprint,
                    "created_at": utc(row.created_at), "error": row.error, "resources": row.resources}


SERVED_CHANGE_FIELDS = ("id", "fingerprint", "fetch_id", "previous_fetch_id", "baseline_fetch_id", "diff",
                        "triage_status", "triage_result", "review_decision", "verdict", "analysis_state")
# The Verdicts after which the Operator may accept a changed fingerprint as the Baseline (A06, A10).
BASELINE_VERDICTS = ("Security hardening", "Unrelated")


def baseline_allowed(change):
    """Whether a served-content change's fingerprint may become the Baseline (A10, decision 14):
    after a Security hardening or Unrelated Verdict, or, while it stays dismissed, after Triage
    declined it with no Analysis asked for, or its Insufficient context Verdict was dismissed
    from the Review queue."""
    if change.verdict in BASELINE_VERDICTS:
        return True
    if change.review_decision != "dismissed":
        return False
    declined = (change.verdict is None and change.analysis_state is None and change.triage_status == "completed"
                and (change.triage_result or {}).get("decision") == "unrelated")
    return declined or change.verdict == "Insufficient context"


def served_change_json(row):
    return {**{name: getattr(row, name) for name in SERVED_CHANGE_FIELDS}, "created_at": utc(row.created_at)}


def served_change_label(db, change):
    """A served-content change's readable name: its page and user agent."""
    return f"{db.get(WatchedPage, change.page_id).url} · {change.user_agent.capitalize()}"


def watched_page_json(db, page):
    """A Watched page with each user agent's latest fetch, its Baseline, how the two compare
    (awaiting_baseline, matches, changed or failed), their diff and the change recorded for it."""
    agents = []
    for agent in USER_AGENTS:
        latest = db.scalar(select(ServedFetch).where(ServedFetch.page_id == page.id, ServedFetch.user_agent == agent)
                           .order_by(ServedFetch.created_at.desc()).limit(1))
        accepted = page.baseline.get(agent)
        baseline = accepted and db.get(ServedFetch, accepted["fetch_id"])
        if latest is not None and latest.status == "failed":
            state = "failed"
        elif latest is None or baseline is None:
            state = "awaiting_baseline"
        else:
            state = "matches" if latest.fingerprint == accepted["fingerprint"] else "changed"
        change = state == "changed" and db.scalar(select(ServedChange).where(
            ServedChange.page_id == page.id, ServedChange.user_agent == agent,
            ServedChange.fingerprint == latest.fingerprint))
        agents.append({
            "user_agent": agent, "latest": served_fetch_json(latest), "baseline": accepted, "state": state,
            "diff": served.diff(baseline.summary, latest.summary) if state in ("matches", "changed") else None,
            # The served_content Finding a Malicious change Verdict opened for it, if any.
            "change": {**served_change_json(change), "finding_id": db.scalar(select(Finding.id).where(
                Finding.source == "served_content", Finding.data["subject_id"].as_string() == change.id))}
            if change else None,
            "accept_allowed": bool(latest is not None and latest.status == "fetched" and (
                accepted is None or change and baseline_allowed(change))),
        })
    return {"id": page.id, "url": page.url, "homepage": page.homepage, "removed_at": utc(page.removed_at),
            "created_at": utc(page.created_at), "user_agents": agents}


def accept_baseline(db, page, fetch):
    """The Operator accepts `fetch`'s Content fingerprint as the page's Baseline for its user agent
    (A10). It is not an Approval and needs no password. A first Baseline is always accepted; a
    later one only when its fingerprint's served-content change is baseline_allowed. Accepting
    the Baseline's own fingerprint again changes nothing."""
    db.refresh(page, with_for_update=True)
    if fetch.page_id != page.id or fetch.status != "fetched":
        raise DomainError("invalid_baseline", "Only a fetch of this Watched page that it served can become its Baseline", 422)
    current = page.baseline.get(fetch.user_agent)
    if current and current["fingerprint"] == fetch.fingerprint:
        return
    change = current and db.scalar(select(ServedChange).where(
        ServedChange.page_id == page.id, ServedChange.user_agent == fetch.user_agent,
        ServedChange.fingerprint == fetch.fingerprint))
    if current and not (change and baseline_allowed(change)):
        raise DomainError("baseline_not_allowed", "A new Baseline needs a Security hardening or Unrelated Verdict on"
                          " this fingerprint, a Triage that declined it, or its dismissal from the Review queue", 409)
    page.baseline = {**page.baseline, fetch.user_agent: {
        "fetch_id": fetch.id, "fingerprint": fetch.fingerprint, "accepted_at": now().isoformat()}}
    db.add(Action(resource_type="watched_page", resource_id=page.id, data={
        "action": "baseline_accepted", "user_agent": fetch.user_agent, "fetch_id": fetch.id,
        "fingerprint": fetch.fingerprint, "previous": current}))


def store_advisory_cache(db, writes):
    """Writes the feed answers an Advisory check fetched ({key: {etag, modified, body}}), in key
    order so two checks that write the same keys at once cannot deadlock."""
    for key in sorted(writes):
        values = {**writes[key], "fetched_at": now()}
        row = db.get(AdvisoryCache, key)
        if row is None:
            # As record_exposure: a concurrent check that creates the key first wins, and this one updates it.
            try:
                with db.begin_nested():
                    db.add(AdvisoryCache(key=key, **values))
                continue
            except IntegrityError:
                row = db.get(AdvisoryCache, key)
        for name, value in values.items():
            setattr(row, name, value)


def record_advisory_matches(db, application, records):
    """Stores the Advisory check's matches (A09) of `records` ([(feed, record)]) against the pins
    just collected, one row per (Application, vulnerability), and reads every stored match again
    against those pins. A vulnerability that shares an alias with stored rows folds into the oldest
    of them that has a Finding, else the oldest: its key and Finding stay and the aliases merge.
    Opens no Finding. Returns the Application's rows."""
    rows = list(db.scalars(select(AdvisoryMatch).where(AdvisoryMatch.application_id == application.id)
                           .order_by(AdvisoryMatch.created_at, AdvisoryMatch.id)))
    collected, groups = application.advisory_pins, {}
    for group in advisories.match(collected, records, [row.aliases for row in rows]):
        names = set(group["aliases"])
        overlapping = [row for row in rows if names & set(row.aliases)]
        if overlapping:
            row = next((other for other in overlapping if other.finding_id), overlapping[0])
            # ponytail: a row with another Finding stays beside it, each Finding keeping its own
            # match, as both were opened before the alias joined them; link the two if this happens
            for other in overlapping:
                if other is not row and other.finding_id in (None, row.finding_id):
                    db.delete(other)
                    rows.remove(other)
        else:
            query = select(AdvisoryMatch).where(AdvisoryMatch.application_id == application.id,
                                                AdvisoryMatch.vulnerability == group["vulnerability"])
            try:
                with db.begin_nested():
                    row = AdvisoryMatch(application_id=application.id, vulnerability=group["vulnerability"],
                                        aliases=group["aliases"], state=group["state"], data={})
                    db.add(row)
            except IntegrityError:
                row = db.scalar(query)
            rows.append(row)
        row.aliases = sorted(names | set(row.aliases))
        groups[row.id] = group
    for row in rows:
        row.data, row.state = advisories.refresh(row.data or {}, groups.get(row.id), collected)
        row.updated_at = now()
    return rows


def finding_aliases(db, finding):
    """The vulnerability ids a commit or cve Finding goes by (A09): a cve Finding's CVE id, the
    non-SHA `addresses` of a commit Finding's source Analysis, and the aliases of the Advisory check
    matches attached to it."""
    if finding.source == "cve":
        names = {finding.cve_id}
    else:
        # ponytail: the addresses of fixes linked to the Finding are not read; read them too if a
        # linked fix names an advisory that its source Analysis does not
        analysis = db.get(Analysis, finding.data.get("source_analysis_id") or "")
        names = {a for a in (analysis.result.get("addresses", []) if analysis else [])
                 if not re.fullmatch(r"[0-9a-f]{7,64}", a)}
    attached = db.scalars(select(AdvisoryMatch.aliases).where(AdvisoryMatch.finding_id == finding.id))
    return names.union(*attached)


def attach_advisory(db, application, match):
    """Gives an exposed or unknown Advisory check match its Finding, once (A09, A11): the
    Application's oldest Open or Confirmed commit or cve Finding that goes by one of its aliases,
    which the match Confirms without an Alert and drafts nothing for; else a Finding with source
    advisory, which open_finding alerts, an exposed match Confirms (an unknown one leaves it
    Open), and whose bump Remediation PR is drafted when the Application has an Own repository.
    A match that has a Finding keeps it, so a Dismissed or Remediated one is never reopened.
    Returns "opened", "attached" or None."""
    if match.state == "not_exposed" or match.finding_id:
        return None
    names, cause = set(match.aliases), {"by": "advisory", "advisory_id": match.vulnerability}
    # ponytail: an Analysis committing at the same time as this check can open its commit Finding
    # beside the advisory one, since run_playbook does not lock the Application row; lock it there
    # if two Findings for one vulnerability show up
    target = next((finding for finding in db.scalars(select(Finding).where(
        Finding.application_id == application.id, Finding.source.in_(("commit", "cve")),
        Finding.status.in_(("open", "confirmed"))).order_by(Finding.created_at, Finding.id))
        if finding_aliases(db, finding) & names), None)
    if target is not None:
        match.finding_id = target.id
        db.add(Action(resource_type="finding", resource_id=target.id, data={
            "action": "advisory_attached", "vulnerability": match.vulnerability, "aliases": match.aliases}))
        transition_finding(db, target, "confirmed", cause)
        return "attached"
    pin = next(entry for entry in match.data["pins"] if entry["state"] != "not_exposed")
    title = f"{pin['name']} {pin['version']}: {match.data.get('summary') or match.vulnerability}"
    cause = {**cause, "aliases": match.aliases}
    finding, opened = open_finding(db, application, "advisory", match.vulnerability, title, match.vulnerability, cause)
    if opened:
        if match.state == "exposed":
            transition_finding(db, finding, "confirmed", cause)
        finding.data = {**finding.data, "target_applicability": "affected" if match.state == "exposed" else "unknown"}
        # A06: the bump to the lowest fixed version, drafted by application code, opens after Approval.
        own = own_repository(db, application)
        dependency, _ = advisories.target(match.data, application.advisory_pins)
        if own is not None and dependency:
            draft_remediation(db, application, finding, match.vulnerability, "bump", own.cursor, automatic=True,
                              dependency=dependency)
    match.finding_id = finding.id
    return "opened" if opened else None


def advisory_dependency(db, finding):
    """(dependency, reason) of the bump an advisory Finding gets from the match that opened it
    (advisories.target), or (None, None) for any other Finding."""
    match = finding.source == "advisory" and db.scalar(select(AdvisoryMatch).where(
        AdvisoryMatch.finding_id == finding.id, AdvisoryMatch.vulnerability == finding.data.get("subject_id")))
    if not match:
        return None, None
    return advisories.target(match.data, db.get(Application, finding.application_id).advisory_pins or {})


def bumped(match, pins):
    """{name: versions} of the newly collected `pins` of each runtime or package the match lists,
    when every one of them is readable and outside the match's ranges; else None, as when one is
    no longer collected."""
    versions = {}
    for entry in match.data.get("pins", []):
        key = (entry["kind"], entry["ecosystem"], entry["name"])
        found = [pin["version"] for pin in pins["runtimes" if key[0] == "runtime" else "packages"]
                 if pin["name"] == key[2] and pin.get("ecosystem") == key[1]]
        if not found or any(advisories.pin_state(version, entry["ranges"], advisories.scheme_of(key))
                            != "not_exposed" for version in found):
            return None
        versions.setdefault(key[2], set()).update(found)
    return versions or None


def remediate_advisories(db, application, pins, revision):
    """A version bump seen on the Own repository's default branch (A09, A11): each Open or
    Confirmed Finding of Advisory check matches (the advisory Finding a match opened, or the
    commit or cve Finding it attached to) is Remediated when every one of its matches, as
    record_advisory_matches just read them again with the feeds' latest ranges, is bumped by the
    newly collected `pins`. The only caller that remediates by version_bump."""
    grouped = {}
    for match, finding in db.execute(select(AdvisoryMatch, Finding).join(
            Finding, Finding.id == AdvisoryMatch.finding_id).where(
            AdvisoryMatch.application_id == application.id, Finding.status.in_(("open", "confirmed")))
            .order_by(AdvisoryMatch.vulnerability)):
        grouped.setdefault(finding.id, (finding, []))[1].append(match)
    for finding, matches in grouped.values():
        found = [bumped(match, pins) for match in matches]
        if all(found):
            versions = {}
            for held in found:
                for name, values in held.items():
                    versions.setdefault(name, set()).update(values)
            transition_finding(db, finding, "remediated", {
                "by": "version_bump", "advisory_id": matches[0].vulnerability, "revision": revision,
                "versions": {name: sorted(values) for name, values in versions.items()}})


def advisory_json(row):
    return {"id": row.id, "vulnerability": row.vulnerability, "aliases": row.aliases, "state": row.state,
            "finding_id": row.finding_id, **row.data, "updated_at": row.updated_at}


def advisories_json(db, application):
    """The pins the last Advisory check collected and its matches. Each pin has its Exposure:
    unknown when its version cannot be read; else the worst state of the matches that list it, or
    not_exposed when none does and a feed answered; null before any feed answered."""
    pins = {"repository_id": None, "revision": None, "collected_at": None, "feeds": {}, "runtimes": [],
            "packages": [], **(application.advisory_pins or {})}
    rows = db.scalars(select(AdvisoryMatch).where(AdvisoryMatch.application_id == application.id)
                      .order_by(AdvisoryMatch.vulnerability)).all()
    states = {}
    for row in rows:
        for entry in row.data.get("pins", []):
            states.setdefault((entry["kind"], entry["ecosystem"], entry["name"], entry["version"]), set()).add(
                entry["state"])
    answered = any("error" not in feed for feed in pins["feeds"].values())
    readable = advisories.index(pins)
    for kind, label in (("runtimes", "runtime"), ("packages", "package")):
        listed = []
        for pin in pins[kind]:
            key = (label, pin.get("ecosystem"), pin["name"])
            if pin not in readable.get(key, []):
                exposure = "unknown"
            elif (*key, pin["version"]) in states:
                exposure = advisories.worst(states[(*key, pin["version"])])
            else:
                exposure = "not_exposed" if answered else None
            listed.append({**pin, "exposure": exposure})
        pins[kind] = listed
    pins["matches"] = [advisory_json(row) for row in rows]
    return pins


def remediation_actions(db, finding):
    """The Remediation PRs the Operator may draft for the Finding (A06), with an Own repository.
    On a commit of the Own repository: a revert (the Cure) for a Malicious change; a patch or a
    revert for a Vulnerability introduced, or for a commit with no Verdict yet (a Finding the
    Operator opened); none for any other Verdict, so a Vulnerability fix is never reverted. On an
    Upstream commit, once its Exposure knows the release to move to: a pin for a Vulnerability
    introduced or Malicious change, a bump for a Vulnerability fix. For an advisory Finding, a bump
    once its match has a fixed version to move to."""
    application = db.get(Application, finding.application_id)
    own = own_repository(db, application)
    if finding.source == "advisory":
        return ["bump"] if own is not None and advisory_dependency(db, finding)[0] else []
    commit = source_commit(db, finding)
    if own is None or commit is None:
        return []
    if commit.repository_id != own.id:
        cell = finding_cell(db, finding)
        exposure = finding_exposure(db, finding)
        if (cell is None or cell[0] != "upstream" or exposure is None or upstream_dependency(
                db, application, db.get(Repository, commit.repository_id), exposure.data.get("target")) is None):
            return []
        return ["bump"] if cell[1] == "Vulnerability fix" else ["pin"]
    if malicious_change(db, finding):
        return ["revert"]
    return ["patch", "revert"] if commit.verdict in (None, "Vulnerability introduced") else []


# A Remediation PR that a new draft leaves alone: it is drafting, or approved or opened.
REMEDIATION_BUSY = ("drafting", "approved", "open", "merged", "closed")


def draft_bundle(db, application, finding):
    """Queues the automatic finding_artifacts run that drafts the Finding's own Proof bundle (A06,
    A07) when its Analysis drafted one for another vulnerable app, such as an Upstream Proof built
    on the Own repository's head. It counts against the Analysis caps like patch drafting. A profile
    or cap problem leaves the Proof a Draft for the Operator's Generate. Returns the job, or None."""
    try:
        profile = automated_profile(db, application, "finding_artifacts")
    except DomainError:
        return None
    # ponytail: over a cap the bundle is not drafted later; add a waiting_for_cap state to
    # start_waiting if caps often cut it off.
    if over_cap(db, application, profile, False):
        return None
    return enqueue(db, "finding_artifacts", application, job_input(
        db, application, finding_id=finding.id, source_ref=None, automatic=True, shared=False), profile)


def draft_remediation(db, application, finding, subject, action, revision, automatic=False, dependency=None,
                      submitted=None):
    """Drafts the Application's Remediation PR for (subject, action) on its Own repository (A08),
    or returns None when it has none: its Remediation PR steps are skipped (A06). A patch is a
    one-shot agent run; an automatic one counts against the Analysis caps and waits over one. A
    revert, pin or bump is application code. An automatic draft never raises: a profile or cap
    problem is recorded on the row. A row that is drafting, approved or opened is left alone. A
    commit's patch or revert is drafted only while that commit is of the Own repository."""
    repository = own_repository(db, application)
    query = select(RemediationPR).where(RemediationPR.application_id == application.id,
                                        RemediationPR.subject == subject, RemediationPR.action == action)
    commit = db.get(Commit, subject) if action in ("patch", "revert") else None
    if repository is None or (commit is not None and commit.repository_id != repository.id):
        # The Own link was removed or replaced while this draft waited for a cap: it fails, rather
        # than waiting for good or drafting on another repository.
        waiting = db.scalar(query.where(RemediationPR.status == "waiting_for_cap"))
        if waiting:
            waiting.status, waiting.updated_at = "draft_failed", now()
            waiting.data = {**waiting.data, "error": DomainError(
                "not_own_repository", "The Application's Own repository changed while this draft waited", 409
            ).as_dict()}
        return None
    row, fresh = db.scalar(query), False
    if row is None:
        # As repository_for: a concurrent draft that creates the key first wins, and this one reads it.
        try:
            with db.begin_nested():
                row = RemediationPR(application_id=application.id, finding_id=finding.id,
                                    repository_id=repository.id, subject=subject, action=action, data={})
                db.add(row)
            fresh = True
        except IntegrityError:
            row = db.scalar(query)
    db.refresh(row, with_for_update=True)
    if not fresh and row.status in REMEDIATION_BUSY:
        if automatic:
            return row
        raise DomainError("remediation_busy", f"This {action} is already {row.status}", 409)
    data = {"revision": revision, "dependency": dependency or row.data.get("dependency")}
    if action == "patch":
        try:
            profile = (automated_profile(db, application, "patch_drafting") if automatic
                       else resolve_profile(db, application, "patch_drafting", submitted))
        except DomainError as exc:
            if not automatic:
                raise
            row.status, row.data, row.updated_at = "draft_failed", {**data, "error": exc.as_dict()}, now()
            return row
        cap = over_cap(db, application, profile, False) if automatic else None
        if cap:
            since = row.data.get("since") if row.status == "waiting_for_cap" else now().isoformat()
            row.status, row.data, row.updated_at = "waiting_for_cap", {**data, "since": since, "cap": cap}, now()
            return row
        job = enqueue(db, "patch_drafting", application, {
            "remediation_pr_id": row.id, "finding_id": finding.id, "automatic": automatic, "shared": False}, profile)
    else:
        job = enqueue(db, "remediation_draft", application, {"remediation_pr_id": row.id, "finding_id": finding.id})
    # A new draft replaces the last one, so nothing stale can be approved while it runs.
    row.finding_id, row.repository_id, row.status = finding.id, repository.id, "drafting"
    row.base_ref, row.diff, row.diff_sha256 = None, None, None
    row.data, row.updated_at = {**data, "job_id": job.id}, now()
    return row


def remediation_job_ended(db, job, error):
    """A draft job that failed or was cancelled leaves its draft draft_failed, with no diff to
    approve; a PR step leaves its approved draft failed, to approve again. The Finding is untouched."""
    if job.kind not in ("patch_drafting", "remediation_draft", "remediation_pr"):
        return
    draft = db.get(RemediationPR, job.input.get("remediation_pr_id"))
    pending, failed = ("approved", "failed") if job.kind == "remediation_pr" else ("drafting", "draft_failed")
    if draft and draft.status == pending and draft.data.get("job_id") == job.id:
        draft.status, draft.data, draft.updated_at = failed, {**draft.data, "error": error}, now()


def remediation_json(row):
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "repository_id": row.repository_id,
        "subject": row.subject,
        "action": row.action,
        "status": row.status,
        "base_ref": row.base_ref,
        "diff": row.diff,
        "diff_sha256": row.diff_sha256,
        **row.data,
        "created_at": utc(row.created_at),
        "updated_at": utc(row.updated_at),
    }


def link_change(db, application, addresses, change):
    """Links a change ({commit_id, revision, analysis_id, verdict}) to the Application's Findings,
    in any state, that its Analysis says it addresses: a commit SHA, full or abbreviated, matches
    the Finding's source commit, and any other id its CVE or advisory id, or an alias of an
    Advisory check match attached to it. A fix addressing a
    Dismissed or Remediated Finding is linked to it too, so it opens nothing new. It never looks
    at another Application's Findings, and it leaves status and cause as they are. Returns the
    linked Findings, which for a change linked before are the ones it was linked to then."""
    mine = select(Finding).where(Finding.application_id == application.id)
    earlier = list(db.scalars(mine.where(Finding.id.in_(
        select(Action.resource_id).where(
            Action.resource_type == "finding",
            Action.data["action"].as_string() == "linked",
            Action.data["commit_id"].as_string() == change["commit_id"],
        )
    ))))
    if earlier or not addresses:
        return earlier
    shas = [a for a in addresses if re.fullmatch(r"[0-9a-f]{7,64}", a)]
    ids = [a for a in addresses if a not in shas]
    advised = [row.finding_id for row in db.scalars(select(AdvisoryMatch).where(
        AdvisoryMatch.application_id == application.id, AdvisoryMatch.finding_id.is_not(None)))
        if set(row.aliases) & set(ids)]
    # ponytail: prefix match within one Application; a 7-character prefix shared by two of its
    # source commits links both.
    found = [
        finding
        for finding in db.scalars(
            mine.outerjoin(Commit, Commit.id == Finding.data["source_commit_id"].as_string()).where(or_(
                *(Commit.revision.startswith(sha) for sha in shas),
                Finding.cve_id.in_(ids),
                and_(Finding.source == "advisory", Finding.data["subject_id"].as_string().in_(ids)),
                Finding.id.in_(advised),
            ))
        )
        if finding.data.get("source_commit_id") != change["commit_id"]
    ]
    for finding in found:
        db.add(Action(resource_type="finding", resource_id=finding.id, data={"action": "linked", **change}))
    return found


def analysis_reaches(db, analysis, application_id):
    """Whether a Finding of the Application may refer to `analysis`: the Analysis is the
    Application's own, or it analysed a commit of a repository the Application links. A shared
    Upstream commit is analysed once, under the first Application that uses it."""
    if analysis.application_id == application_id:
        return True
    commit = db.get(Commit, analysis.subject_id) if analysis.kind == "commit_analysis" else None
    return commit is not None and commit.repository_id in set(db.scalars(linked_repository_ids(application_id)))


def finding_data(row):
    # Keys starting with an underscore are application state, such as the artifact summary.
    data = {key: value for key, value in row.data.items() if not key.startswith("_")}
    return {**FINDING_DEFAULTS, **{key: value for key, value in data.items() if value is not None}}


def finding_fields(row):
    """The identity and lifecycle fields that the full and summary views share."""
    return {
        "id": row.id,
        "application_id": row.application_id,
        "source": row.source,
        "source_ref": row.data.get("source_ref"),
        "cve_id": row.cve_id,
        "title": row.title,
        "status": row.status,
        "cause": row.data.get("cause"),
        "deployed_version": deployed_version(row),
    }


def set_finding_artifacts(db, row, revision, files):
    # Publishing flushes the artifact metadata first. Refresh and lock before
    # adding the summary: generation may have loaded this finding before an edit.
    db.refresh(row, with_for_update=True)
    row.artifact_revision = revision
    if "static_proof" in row.data or (row.source == "commit" and malicious_change(db, row)):
        # A Malicious change's static Proof: each new revision is a Draft until its Detection rule
        # validates (A07). A commit's Malicious change Finding without one, such as one opened
        # before Phase 5, starts it here.
        rule, failed = detection.rule_text(files)
        proof = {**row.data.get("static_proof", {}), "artifact_revision": revision, "files": sorted(files), "rule": rule,
                 "status": "failed" if failed else "pending", "checks": [failed] if failed else [], "job_id": None}
        if not failed:
            # Application code validates every revision's rule in the runner, where yara only reads.
            proof["job_id"] = enqueue(
                db, "detection_rule", db.get(Application, row.application_id),
                {"finding_id": row.id, "artifact_revision": revision},
                idempotency_key=f"detection-rule:{row.id}:{revision}",
            ).id
        row.data = {**row.data, "static_proof": proof}
        return detection.static_state(proof)
    supplied = lab_supplied(db, row)
    state = artifacts.completeness(files, supplied)
    row.data = {**row.data, "_artifact_state": {"revision": revision, "rules": artifacts.RULES,
                                                "supplied": fingerprint(sorted(supplied)), "state": state}}
    return state


def finding_artifact_state(db, row, root):
    if "static_proof" in row.data:
        return detection.static_state(row.data["static_proof"])
    if not row.artifact_revision:
        return artifacts.completeness({})
    # What the Lab supplies changes with the links, such as a newly set Locked version.
    supplied = lab_supplied(db, row)
    cached = row.data.get("_artifact_state")
    if (
        isinstance(cached, dict)
        and cached.get("revision") == row.artifact_revision
        and cached.get("rules") == artifacts.RULES
        and cached.get("supplied") == fingerprint(sorted(supplied))
    ):
        return cached["state"]
    return artifacts.resource_completeness(db, root, "finding", row.id, row.artifact_revision, supplied)


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
            **finding_fields(row),
            "affected_versions": row.data.get("affected_versions", []),
            "fixed_versions": row.data.get("fixed_versions", []),
            "target_applicability": row.data.get("target_applicability", "unknown"),
            "source_commit_id": row.data.get("source_commit_id"),
            "source_analysis_id": row.data.get("source_analysis_id"),
            "artifact_revision": row.artifact_revision,
            "artifact_state": finding_artifact_state(db, row, root),
            "malicious_change": malicious_change(db, row),
            "lab_status": statuses.get(row.id),
            "created_at": utc(row.created_at),
            "updated_at": utc(row.updated_at),
        }
        for row in rows
    ]


def finding_subjects(db, findings):
    """What the Findings are about, as Transcripts name it (`subject_id`, A14): each one's source
    commit, the fix commit that gave an advisory Finding its Proof, a served_content Finding's
    change, a cve Finding's CVE for its Application, and every commit linked to them."""
    subjects = {value for row in findings for value in (
        row.data.get("source_commit_id"), row.data.get("fix_commit_id"),
        row.data.get("subject_id") if row.source in ("served_content", "server_files") else None,
        f"{row.application_id}:{row.cve_id}" if row.source == "cve" else None) if value}
    subjects.update(db.scalars(select(Action.data["commit_id"].as_string()).where(
        Action.resource_type == "finding", Action.resource_id.in_([row.id for row in findings]),
        Action.data["action"].as_string() == "linked")))
    return subjects - {None}


TRANSCRIPT_DAYS = 30
TRIAGE_TRANSCRIPT_BYTES = 256 * 1024 * 1024


def prune_transcripts(db):
    """Transcript retention (A14), run by the scheduler. A Triage Transcript goes after 30 days, or
    oldest first while all Triage ones pass 256 MB. An Analysis one is kept while a Finding is
    about its subject, and otherwise goes after 30 days with its Artifact rows. Returns those
    Artifacts' revisions, whose folders the caller removes once this is committed."""
    unlinked = Transcript.subject_id.not_in(list(finding_subjects(db, list(db.scalars(select(Finding))))))
    old = Transcript.created_at < now() - timedelta(days=TRANSCRIPT_DAYS)
    triage = Transcript.kind == "triage"
    db.execute(delete(Transcript).where(triage, old))
    total = db.scalar(select(func.coalesce(func.sum(Transcript.size), 0)).where(triage))
    over = []
    for ident, size in db.execute(select(Transcript.id, Transcript.size).where(triage)
                                  .order_by(Transcript.created_at, Transcript.id)):
        if total <= TRIAGE_TRANSCRIPT_BYTES:
            break
        over.append(ident)
        total -= size
    analyses = list(db.scalars(select(Transcript.id).where(Transcript.kind == "analysis", unlinked, old)))
    owned = and_(Artifact.resource_type == "transcript", Artifact.resource_id.in_(analyses))
    revisions = set(db.scalars(select(Artifact.revision).where(owned)))
    db.execute(delete(Artifact).where(owned))
    db.execute(delete(Transcript).where(Transcript.id.in_(over + analyses)))
    return revisions


def transcript_json(row):
    return {"id": row.id, "kind": row.kind, "job_id": row.job_id, "subject_id": row.subject_id,
            "analysis_id": row.data.get("analysis_id"), "status": row.data.get("status"),
            "created_at": utc(row.created_at)}


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
        **finding_fields(row),
        **finding_data(row),
        "artifact_state": finding_artifact_state(db, row, root),
        "malicious_change": malicious_change(db, row),
        "artifact_revision": row.artifact_revision,
        "artifacts": artifact_rows(db, "finding", row.id, row.artifact_revision),
        "exportable": exportable(db, "finding", row.id),
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
        "playbook": playbook_steps(db, row, root),
        "deployed_version_check": row.data.get("deployed_version_check"),
        "exposure": exposure_json(exposure) if (exposure := finding_exposure(db, row)) else None,
        "disclosure_report": disclosure_report(db, row, root),
        "quarantine": quarantine_json(db, row) if row.source == "server_files" else None,
        # The Advisory check matches attached to it, each with its report, rendered as text.
        "advisories": [{**advisory, "report": advisories.report(advisory)} for advisory in map(
            advisory_json, db.scalars(select(AdvisoryMatch).where(AdvisoryMatch.finding_id == row.id)
                                      .order_by(AdvisoryMatch.vulnerability)))],
        # A06: without an Own repository the Remediation PR steps show "no Own repository".
        "own_repository": own_repository(db, db.get(Application, row.application_id)) is not None,
        "remediation_actions": remediation_actions(db, row),
        "remediation_prs": [remediation_json(r) for r in db.scalars(
            select(RemediationPR).where(RemediationPR.finding_id == row.id)
            .order_by(RemediationPR.created_at, RemediationPR.id))],
        # The Triage and Analysis Transcripts of what it is about, oldest first (A14).
        "transcripts": [transcript_json(t) for t in db.scalars(
            select(Transcript).where(Transcript.subject_id.in_(finding_subjects(db, [row])))
            .order_by(Transcript.created_at, Transcript.id))],
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
    "exposure_check": ("source", "repositories"),
    "advisory_check": ("advisory", "advisories"),
    "version_recipe": ("version", "version"),
    "version_check": ("version", "version"),
    "audit_context": ("audit", "audit"),
    "served_check": ("served", "served"),
}


def commit_label(commit):
    """A commit's readable name: its Triage title, else the first line of its message."""
    triage = commit.triage_result if isinstance(commit.triage_result, dict) else {}
    return (triage.get("title") or (commit.data.get("message") or commit.revision).split("\n")[0])[:240]


def job_subject(db, row, application):
    """What a job acts on, as a readable label, short reference, and dashboard link."""
    data = row.input if isinstance(row.input, dict) else {}
    ref = data.get("source_ref")
    if data.get("commit_id"):
        commit = db.get(Commit, data["commit_id"])
        if not commit:
            return {"type": "commit", "label": "Removed commit", "ref": None, "link": None}
        return {
            "type": "commit",
            "label": commit_label(commit),
            "ref": commit.revision[:10],
            "link": f"/commits/{commit.id}",
        }
    if data.get("served_change_id"):
        change = db.get(ServedChange, data["served_change_id"])
        if not change:
            return {"type": "served", "label": "Removed served-content change", "ref": None, "link": None}
        return {"type": "served", "label": served_change_label(db, change), "ref": change.fingerprint[:12],
                "link": f"/applications/{change.application_id}?tab=served"}
    if data.get("server_change_id"):
        change = db.get(ServerChange, data["server_change_id"])
        if not change:
            return {"type": "server", "label": "Removed Server change", "ref": None, "link": None}
        return {"type": "server", "label": server_change_label(db, change), "ref": change.fingerprint[:12],
                "link": f"/applications/{change.application_id}?tab=server"}
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
            "label": (details.get("verdict") or details.get("title") or "Removed notification").split("\n")[0],
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
            else None if kind == "served" else source_repository(db, application)
        )
        return {
            "type": kind,
            # A Served-content check reads the Asset, not a repository.
            "label": application.asset_url if kind == "served"
            else repository_label(repository) if repository else application.asset_name,
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


def alert_verdict(cause):
    """What an opening Alert says about the Finding's cause: the Verdict and confidence, else
    'Advisory' (an Advisory check match or a carried-over CVE analysis)."""
    if cause.get("by") == "verdict":
        return f"{cause['verdict']} · {cause['confidence']} confidence"
    return "Advisory"


def notify(db, event_key, *, verdict, link, application=None, account=None, source=None):
    """Queues an Alert (A12), once per event_key. It stores only the fields the fixed template
    shows, all application-generated: never commit messages, author names, agent text or Proofs."""
    if db.scalar(select(Notification).where(Notification.event_key == event_key)):
        return
    # Two workers reaching the same cap at once both pass the check above; the one that loses
    # the unique event_key keeps its own transaction (a Triage result) and sends nothing.
    try:
        with db.begin_nested():
            row = Notification(
                event_key=event_key,
                data={"application": application, "account": account, "source": source, "verdict": verdict, "link": link},
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
    except IntegrityError:
        pass


def github_token(db):
    """Whether a GitHub read token is configured: GitHub repositories are never polled without one (A02)."""
    return db.scalar(
        select(Account.id).where(Account.provider == "github", Account.credential.is_not(None)).limit(1)
    )


def schedule(db):
    current = now()
    # FOR NO KEY UPDATE: a worker's source_check holds a Repository lock that active_source_check
    # waits for, and inserts Jobs of these Applications, which take a key-share lock on them.
    due = list(
        db.scalars(
            select(Application)
            .where(
                Application.monitor_enabled.is_(True),
                Application.archived.is_(False),
                (Application.next_check_at.is_(None)) | (Application.next_check_at <= current),
            )
            .with_for_update(skip_locked=True, key_share=True)
        )
    )
    token = github_token(db)
    for application in due:
        # A repository shared by several due Applications is polled once.
        for repository in active_repositories(db, application):
            if repository.source_kind == "github" and not token:
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
    start_waiting(db)
    return len(due)


def nudge_push_deliveries(db):
    """B02: turns the accepted Push deliveries not yet processed into source checks. A nudge acts
    only for the enabled Own repository of an Application that is not archived, whether or not
    scheduled monitoring is on, under A02's GitHub read token rule. It reuses a queued check;
    while one is running the deliveries wait, so the first loop after it queues exactly one more.
    It never touches next_check_at or last_check_at. Deliveries older than 7 days are pruned
    first, so a body is unique among the last 7 days'."""
    current = now()
    db.execute(delete(PushDelivery).where(PushDelivery.received_at < current - timedelta(days=7)))
    token = github_token(db)
    pending = select(PushDelivery.push_webhook_id).where(PushDelivery.processed_at.is_(None))
    for webhook in db.scalars(select(PushWebhook).where(PushWebhook.id.in_(pending))).all():
        # Only these are marked processed: one accepted meanwhile waits for the next loop.
        ids = db.scalars(select(PushDelivery.id).where(
            PushDelivery.push_webhook_id == webhook.id, PushDelivery.processed_at.is_(None))).all()
        repository = db.get(Repository, webhook.repository_id)
        application = next((a for a, link in linked_applications(db, repository)
                            if link.role == "own" and in_use(a, link)), None)
        if application and not token:
            repository.last_error = github_token_required().as_dict()
        elif application:
            db.execute(select(Application.id).where(Application.id == application.id).with_for_update(key_share=True))
            check = active_source_check(db, repository)
            if check and check.status != "queued":
                continue
            if not check:
                enqueue(db, "source_check", application, repository_input(repository))
        db.execute(update(PushDelivery).where(PushDelivery.id.in_(ids)).values(processed_at=current))


def start_waiting(db):
    """Starts the changes waiting for a cap, oldest first. start_analysis re-checks the caps, so
    they start once the caps reset at 00:00 UTC, and only as many as the caps allow. A Triage
    flag runs this before its own change, so a new change never takes a freed slot first."""
    waiting = [
        row
        for model in (Commit, ServedChange, ServerChange)
        for row in db.scalars(
            select(model)
            .where(model.analysis_state["status"].as_string() == "waiting_for_cap")
            .with_for_update(skip_locked=True)
        )
    ]
    for subject in sorted(waiting, key=lambda s: s.analysis_state["since"]):
        start = {ServedChange: start_served_analysis, ServerChange: start_server_analysis}.get(type(subject), start_analysis)
        start(db, subject)
    # Then the automatic patch drafts waiting for a cap (A08), oldest first.
    drafts = db.scalars(
        select(RemediationPR).where(RemediationPR.status == "waiting_for_cap").with_for_update(skip_locked=True)
    )
    for row in sorted(drafts, key=lambda r: r.data["since"]):
        draft_remediation(db, db.get(Application, row.application_id), db.get(Finding, row.finding_id),
                          row.subject, row.action, row.data["revision"], automatic=True)
