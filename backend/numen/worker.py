import logging
import socket
import threading
import time
from datetime import timedelta

from sqlalchemy import select

from .broker import Broker
from .config import Config
from .db import make_database
from .models import (
    Account,
    Application,
    AuditContext,
    Commit,
    Job,
    JobAttempt,
    LabRun,
    Observation,
    Repository,
    VersionRecipe,
    now,
)
from .security import DomainError, Vault
from .queue import ExecutionContext, claim, runtime_phases, stop_runs
from .workflows import Workflows, all_secrets
from .domain import enqueue, event

log = logging.getLogger("numen.worker")
# Agent, lab, Detection rule and interactive login work that can occupy a slot for minutes or hours.
LONG_KINDS = (
    "account_login",
    "audit_context",
    "commit_analysis",
    "commit_triage",
    "cve_analysis",
    "detection_rule",
    "finding_artifacts",
    "lab_run",
    "version_recipe",
)
# Attempts at one Triage of a change; retry n waits n minutes.
TRIAGE_ATTEMPTS = 3


def run_once(config, factory, broker=None, owner=None, exclude=()):
    broker = broker or Broker(config)
    vault = Vault(config.secret_key)
    with factory.begin() as db:
        job = claim(db, owner or socket.gethostname(), exclude)
        if not job:
            return False
        ident, token = job.id, job.attempt_token
    context = ExecutionContext(factory, job, broker)
    context.start()
    try:
        with factory() as db:
            job = db.get(Job, ident)
            workflows = Workflows(config, vault, broker, context)
            try:
                result = workflows.execute(db, job)
            finally:
                workflows.close()
            context.fence(db)
            if context.executions:
                result = {**result, "runtime_executions": context.executions}
            job.status, job.result, job.finished_at = "succeeded", result, now()
            job.lease_until, job.lease_owner = None, None
            attempt = db.get(JobAttempt, token)
            attempt.status = "succeeded"
            event(db, job, "succeeded", "Job completed", partial_output_retained=False)
            db.commit()
        for callback in context.callbacks:
            try:
                callback()
            except DomainError:
                log.warning("Native credential ingress cleanup requires broker reconciliation")
    except Exception as exc:
        error = (
            exc.as_dict()
            if isinstance(exc, DomainError)
            else {
                "code": "internal_job_error",
                "message": "Job failed unexpectedly; no successful output was published",
                "retryable": False,
            }
        )
        with factory() as scan:
            try:
                secrets = [*all_secrets(scan, vault), *context.secrets]
            except DomainError:
                secrets = []
        for value in secrets:
            error["message"] = error["message"].replace(value, "[redacted]")
        with factory() as db:
            row = db.get(Job, ident)
            owned = row and row.attempt_token == token
            attempt = db.get(JobAttempt, token)
            # Concurrent phases may each own a run; all of them must stop before a terminal state.
            phases = runtime_phases(attempt, row.broker_run_id) if owned else {}
            terminal_target = (
                "cancelled"
                if (owned and row.status == "cancelling")
                or error["code"] in ("cancelled", "lease_lost")
                else "failed"
            )
        stopped, runs = stop_runs(broker, phases)
        run_id = runs[-1] if runs else None
        with factory.begin() as db:
            row = db.scalar(select(Job).where(Job.id == ident).with_for_update())
            if row and row.attempt_token == token and row.status in ("running", "cancelling"):
                row.status = terminal_target if stopped else "cancelling"
                if run_id:
                    row.broker_run_id = run_id
                if not stopped:
                    error = {**error, "reconciliation_pending": True}
                    row.progress = {"stage": "reconciliation_pending"}
                row.error, row.finished_at = error, now() if stopped else None
                row.lease_until = None if stopped else now()
                row.lease_owner = None
                attempt = db.get(JobAttempt, token)
                if attempt:
                    attempt.status = row.status
                    if not stopped:
                        attempt.data = {**attempt.data, "pending_terminal_status": terminal_target}
                partial_output_retained = bool(
                    row.kind in ("cve_analysis", "finding_artifacts")
                    and row.result
                    and row.result.get("artifact_revision")
                )
                repository = (
                    db.get(Repository, row.input.get("repository_id"))
                    if row.kind in ("source_check", "backfill", "derive_upstreams")
                    and row.input.get("repository_id")
                    else None
                )
                if repository and error["code"] not in ("input_changed", "source_check_superseded"):
                    repository.last_error = error
                if row.kind in ("commit_triage", "jev_triage"):
                    # A failed Triage has no decision: it is never read as unrelated. It is retried
                    # unless the attempt was cancelled, lost or overtaken by a source change.
                    commit = db.get(Commit, row.input.get("commit_id"))
                    attempt_number = row.input.get("attempt", 1)
                    if commit:
                        commit.triage_status, commit.triage_result = (
                            "failed",
                            {"error": error["code"], "reason": error["message"], "attempt": attempt_number},
                        )
                        if (
                            row.status == "failed"
                            and attempt_number < TRIAGE_ATTEMPTS
                            and error["code"] not in ("cancelled", "lease_lost", "input_changed")
                        ):
                            retry = enqueue(
                                db,
                                row.kind,
                                db.get(Application, row.application_id) if row.application_id else None,
                                {**row.input, "attempt": attempt_number + 1},
                                row.profile,
                            )
                            retry.not_before = now() + timedelta(seconds=60 * attempt_number)
                            commit.triage_result = {**commit.triage_result, "retry_job_id": retry.id}
                if row.kind == "commit_analysis":
                    # A failed or expired Analysis decides nothing: the review decision and the
                    # Verdict stay as they were, so an expired deadline is never Unrelated.
                    commit = db.get(Commit, row.input.get("commit_id"))
                    if commit:
                        commit.analysis_state = {
                            "status": "timed_out"
                            if error["code"] in ("timeout", "runtime_timeout")
                            else "failed",
                            "job_id": row.id,
                            "error": error,
                        }
                if row.kind in ("account_capabilities", "account_check", "account_login"):
                    account = db.get(Account, row.input.get("account_id"))
                    if account and account.revision == row.input.get("credential_revision"):
                        account.data = {
                            **account.data,
                            "status": "unavailable",
                            "error": error,
                            "last_checked_at": now().isoformat(),
                        }
                if row.kind == "version_check" and row.application_id:
                    db.add(
                        Observation(
                            application_id=row.application_id,
                            recipe_id=row.input.get("recipe_id"),
                            source_generation=row.input.get("source_generation", 1),
                            data={
                                "status": "error",
                                "version": None,
                                "candidates": [],
                                "method": "script",
                                "origin": "script",
                                "evidence": [],
                                "confidence": {"level": "unknown", "basis": "Execution failed"},
                                "limitations": [error["message"]],
                                "error": error,
                            },
                        )
                    )
                if row.kind == "version_recipe":
                    for recipe in db.scalars(
                        select(VersionRecipe).where(
                            VersionRecipe.application_id == row.application_id,
                            VersionRecipe.status.in_(["validating", "rejected"]),
                        )
                    ):
                        if recipe.data.get("job_id") == row.id:
                            partial_output_retained = True
                            recipe.status = "rejected"
                            recipe.data = {**recipe.data, "error": error}
                if row.kind == "audit_context":
                    for report in db.scalars(
                        select(AuditContext).where(
                            AuditContext.job_id == row.id, AuditContext.status == "running"
                        )
                    ):
                        partial_output_retained = (
                            bool(report.coverage.get("artifact_revision"))
                            or partial_output_retained
                        )
                        report.status = "partial"
                        report.coverage = {**report.coverage, "interrupted": True, "error": error}
                if row.kind == "lab_run":
                    lab = db.scalar(select(LabRun).where(LabRun.job_id == row.id))
                    if lab:
                        lab.status, lab.data = row.status, {"error": error}
                event(
                    db,
                    row,
                    row.status,
                    error["message"],
                    partial_output_retained=partial_output_retained,
                )
    finally:
        context.close()
    return True


def serve(config, factory, owner, exclude=()):
    broker = Broker(config)
    while True:
        try:
            busy = run_once(config, factory, broker, owner, exclude)
        except Exception:
            log.exception("Job slot %s failed outside a job attempt", owner)
            busy = False
            time.sleep(4)
        if not busy:
            time.sleep(1)


def main():
    config = Config.from_env()
    _, factory = make_database(config)
    host = socket.gethostname()
    # Claims are row-locked and attempts fenced, so slots run jobs concurrently. The extra slot
    # never takes long work, so checks, syncs and notifications keep moving during long audits.
    slots = [(f"{host}/{i}", ()) for i in range(max(1, config.worker_concurrency))]
    slots.append((f"{host}/short", LONG_KINDS))
    threads = [
        threading.Thread(target=serve, args=(config, factory, owner, exclude), daemon=True)
        for owner, exclude in slots
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
