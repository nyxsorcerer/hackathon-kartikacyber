import threading
import re
from datetime import timedelta
from sqlalchemy import select, update
from .models import AuditContext, Job, JobAttempt, JobEvent, VersionRecipe, now
from .security import DomainError
from .domain import event

LEASE_SECONDS = 120


def login_instructions(events):
    instructions = []
    for item in events:
        if not isinstance(item, dict):
            continue
        allowed = {
            k: item[k]
            for k in (
                "verification_uri",
                "verification_uri_complete",
                "user_code",
                "expires_at",
                "status",
                "input_required",
            )
            if k in item
        }
        if item.get("type") == "login_instruction":
            message = item.get("message", "")
            match = re.search(r"https://auth\.openai\.com/[A-Za-z0-9./?&=_-]+", message)
            if match:
                allowed["verification_uri"] = match.group(0)
            if re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4,6}", message):
                allowed["user_code"] = message
        if allowed:
            action = {"verification_uri", "user_code", "input_required"} & set(allowed)
            instructions.append(
                {
                    "kind": "login",
                    "message": "Native sign-in requires operator action"
                    if action
                    else "Native sign-in in progress",
                    **allowed,
                }
            )
    return instructions


def claim(db, owner, exclude=()):
    current = now()
    query = select(Job).where(
        Job.status == "queued", (Job.not_before.is_(None)) | (Job.not_before <= current)
    )
    if exclude:
        query = query.where(Job.kind.not_in(exclude))
    row = db.scalar(
        query.order_by(Job.created_at).with_for_update(skip_locked=True).limit(1)
    )
    if row is None:
        return None
    from .models import uid

    token = uid()
    # Conditional UPDATE also protects SQLite test claims where FOR UPDATE is not implemented.
    changed = db.execute(
        update(Job)
        .where(Job.id == row.id, Job.status == "queued")
        .values(
            status="running",
            lease_owner=owner,
            attempt_token=token,
            lease_until=current + timedelta(seconds=LEASE_SECONDS),
            started_at=current,
            finished_at=None,
            attempts=Job.attempts + 1,
            broker_run_id=None,
            error=None,
            result=None,
        )
        .execution_options(synchronize_session=False)
    )
    if changed.rowcount != 1:
        return None
    db.refresh(row)
    db.add(JobAttempt(id=token, job_id=row.id, status="running", data={"owner": owner}))
    event(db, row, "started", "Worker claimed job", attempt_token=token)
    return row


class ExecutionContext:
    def __init__(self, factory, job, broker):
        self.factory, self.job_id, self.token, self.broker = (
            factory,
            job.id,
            job.attempt_token,
            broker,
        )
        self.failure = None
        self.stop = threading.Event()
        self.callbacks = []
        self.executions = []
        self.secrets = []
        self.last_progress = None
        self.kind = job.kind
        # Operation progress (e.g. audit function counts) shown in place of the runtime state.
        self.operation = None
        # Runtime phases of one attempt may run concurrently; their records share this lock.
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._pulse, daemon=True)

    def _pulse(self):
        while not self.stop.wait(20):
            try:
                self.heartbeat()
            except DomainError as exc:
                self.failure = exc
                return

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)

    def heartbeat(self):
        if self.failure:
            raise self.failure
        with self.factory.begin() as db:
            row = db.get(Job, self.job_id)
            if (
                not row
                or row.attempt_token != self.token
                or row.status not in ("running", "cancelling")
            ):
                raise DomainError("lease_lost", "This worker no longer owns the attempt", 409)
            if row.status == "cancelling":
                raise DomainError("cancelled", "Operator requested cancellation", 409)
            db.execute(
                update(Job)
                .where(
                    Job.id == self.job_id, Job.attempt_token == self.token, Job.status == "running"
                )
                .values(lease_until=now() + timedelta(seconds=LEASE_SECONDS))
            )

    def fence(self, db):
        # Lock held until the publication transaction commits. Cancellation cannot race publication.
        row = db.scalar(
            select(Job)
            .where(Job.id == self.job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not row or row.attempt_token != self.token or row.status != "running":
            raise DomainError(
                "lease_lost", "Attempt ownership changed; its outputs were not published", 409
            )
        return row

    def set_run(self, run_id, attempt_token=None):
        with self.lock, self.factory.begin() as db:
            changed = db.execute(
                update(Job)
                .where(
                    Job.id == self.job_id, Job.attempt_token == self.token, Job.status == "running"
                )
                .values(broker_run_id=run_id)
            )
            if changed.rowcount != 1:
                self.broker.cancel(run_id)
                raise DomainError(
                    "lease_lost", "Attempt lost ownership before execution could be recorded", 409
                )
            if attempt_token:
                attempt = db.get(JobAttempt, self.token)
                phases = {**attempt.data.get("runtime_phases", {}), attempt_token: run_id}
                attempt.data = {**attempt.data, "runtime_phases": phases}
            db.add(
                JobEvent(
                    job_id=self.job_id,
                    data={
                        "kind": "runtime_started",
                        "message": "Isolated runtime started",
                        "run_id": run_id,
                    },
                )
            )

    def set_phase(self, attempt_token):
        # Every unfinished phase stays recorded, so failure handling and recovery stop all runs.
        with self.lock, self.factory.begin() as db:
            row = db.get(Job, self.job_id)
            if not row or row.attempt_token != self.token or row.status != "running":
                raise DomainError(
                    "lease_lost", "Attempt lost ownership before runtime submission", 409
                )
            row.broker_run_id = None
            attempt = db.get(JobAttempt, self.token)
            phases = {**attempt.data.get("runtime_phases", {}), attempt_token: None}
            attempt.data = {
                **attempt.data,
                "runtime_attempt_token": attempt_token,
                "runtime_phases": phases,
            }

    def end_phase(self, attempt_token):
        with self.lock, self.factory.begin() as db:
            attempt = db.get(JobAttempt, self.token)
            if attempt:
                phases = dict(attempt.data.get("runtime_phases", {}))
                phases.pop(attempt_token, None)
                attempt.data = {**attempt.data, "runtime_phases": phases}

    def progress(self, state):
        # Ordinary logs never pass arbitrary runtime output, prompts, or credentials into the UI.
        safe = {
            "status": state.get("status"),
            "progress": state.get("progress"),
            "execution": state.get("execution"),
        }
        instructions = (
            login_instructions(state.get("events", [])) if self.kind == "account_login" else []
        )
        # Device-login events can arrive while the CLI's status and percentage stay unchanged.
        safe["login_instructions"] = instructions
        digest = str(safe)
        with self.lock:
            if digest == self.last_progress:
                return
            self.last_progress = digest
        with self.factory.begin() as db:
            row = db.get(Job, self.job_id)
            if row and row.attempt_token == self.token:
                row.progress = self.operation or {"status": state.get("status"), "stage": "runtime"}
                execution = state.get("execution")
                if isinstance(execution, dict):
                    execution = {
                        k: execution[k]
                        for k in (
                            "image_digest",
                            "image",
                            "agent_version",
                            "plugin_versions",
                            "skill_revision",
                            "bundle_version",
                        )
                        if k in execution
                    }
                    record = {"run_id": state.get("run_id"), **execution}
                    if record not in self.executions:
                        self.executions.append(record)
                        db.add(
                            JobEvent(
                                job_id=row.id,
                                data={
                                    "kind": "runtime_provenance",
                                    "message": "Pinned runtime recorded",
                                    **record,
                                },
                            )
                        )
                if row.kind == "account_login":
                    existing = [
                        event.data
                        for event in db.scalars(select(JobEvent).where(JobEvent.job_id == row.id))
                    ]
                    for instruction in instructions:
                        if instruction not in existing:
                            db.add(JobEvent(job_id=row.id, data=instruction))
                            existing.append(instruction)

    def after_commit(self, callback):
        self.callbacks.append(callback)


def runtime_phases(attempt, run_id=None):
    """Runtime phases of an attempt that may still own a run: phase token -> run id or None."""
    data = attempt.data if attempt else {}
    if "runtime_phases" in data:
        return dict(data["runtime_phases"])
    phase = data.get("runtime_attempt_token")  # Attempts recorded before concurrent phases.
    return {phase: run_id} if phase else ({None: run_id} if run_id else {})


def stop_runs(broker, phases):
    """Cancel every phase's run. Stopped only when each is terminal or provably never started."""
    stopped, runs = True, []
    for phase, run_id in phases.items():
        try:
            if not run_id:
                found = broker.lookup_attempt(phase) if phase else None
                if not found:
                    continue  # Positive broker absence proof, not an HTTP error.
                run_id = found["run_id"]
            runs.append(run_id)
            broker.cancel(run_id)
            status = broker.request("GET", f"/internal/runs/{run_id}").get("status")
            stopped = stopped and status in ("cancelled", "failed", "succeeded")
        except DomainError:
            stopped = False
    return stopped, runs


def recover(factory, broker):
    with factory() as db:
        rows = list(
            db.scalars(
                select(Job).where(
                    Job.status.in_(["running", "cancelling"]), Job.lease_until < now()
                )
            )
        )
        candidates = []
        for row in rows:
            attempt = db.get(JobAttempt, row.attempt_token)
            candidates.append(
                (
                    row.id,
                    row.attempt_token,
                    runtime_phases(attempt, row.broker_run_id),
                    row.status,
                    attempt.data.get("pending_terminal_status") if attempt else None,
                )
            )
    recovered = 0
    for ident, token, phases, status, pending_terminal in candidates:
        stopped, runs = stop_runs(broker, phases)
        if not stopped:
            # Never issue a replacement while a former isolated run cannot be reconciled.
            continue
        run_id = runs[-1] if runs else None
        with factory.begin() as db:
            row = db.scalar(select(Job).where(Job.id == ident).with_for_update())
            if not row or row.attempt_token != token or row.status != status:
                continue
            attempt = db.get(JobAttempt, token)
            if attempt:
                attempt.status = "interrupted"
            for recipe in db.scalars(
                select(VersionRecipe).where(
                    VersionRecipe.program_id == row.program_id, VersionRecipe.status == "validating"
                )
            ):
                if recipe.data.get("job_id") == ident:
                    recipe.status = "rejected"
                    recipe.data = {
                        **recipe.data,
                        "error": {
                            "code": "interrupted",
                            "message": "Worker lease expired; generated revision retained",
                        },
                    }
            for report in db.scalars(
                select(AuditContext).where(
                    AuditContext.job_id == ident, AuditContext.status == "running"
                )
            ):
                report.status = "partial"
                report.coverage = {
                    **report.coverage,
                    "interrupted": True,
                    "reason": "Worker lease expired; checkpoint retained",
                }
            row.status = (pending_terminal or "cancelled") if status == "cancelling" else "queued"
            row.finished_at = now() if row.status in ("failed", "cancelled") else None
            if row.error and row.error.get("reconciliation_pending"):
                row.error = {**row.error, "reconciliation_pending": False}
            row.progress = {"stage": "reconciled"}
            row.lease_owner, row.lease_until = None, None
            row.broker_run_id = None
            event(
                db,
                row,
                "recovered",
                "Expired attempt reconciled; unpublished output was discarded",
                run_id=run_id,
                terminal_status=row.status,
            )
            recovered += 1
    return recovered
