from datetime import timedelta

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, check_now, connection, application, repository_of
from numen import domain, workflows
from numen.artifacts import publish
from numen.models import AuditContext, Job, JobEvent, Application, Setting, Snapshot, now
from numen.worker import run_once
from test_artifacts import bundle, queue_cve_analysis
from test_commit_review import assessment, prepared

CONTEXT_FILES = {
    "audit-context-building.md": b"# Audit context building\n\n- [parse](functions/001.md)\n",
    "audit-context/DOSSIER.md": b"# Dossier",
    "functions/001.md": b"# parse",
    "coverage.json": b"{}",
    "audit-functions.json": b"[]",
}


def add_context(app, config, application_id, source_ref, stage="complete", age=0, files=CONTEXT_FILES):
    """A finished audit context of the application, `age` minutes old."""
    with app.state.factory.begin() as db:
        application = db.get(Application, application_id)
        job = domain.enqueue(db, "audit_context", application, domain.job_input(db, application))
        job.status = "succeeded"
        row = AuditContext(
            application_id=application_id,
            source_generation=application.source_generation,
            source_ref=source_ref,
            skill_revision="skill",
            coverage={"selected": 1, "completed": 1, "failed": 0, "stage": stage},
            status="stale",
            job_id=job.id,
            created_at=now() - timedelta(minutes=age),
        )
        db.add(row)
        db.flush()
        revision, _ = publish(db, config.artifact_root, "audit", row.id, dict(files))
        row.coverage = {**row.coverage, "artifact_revision": revision}
        return row.id


def events(app, job_id, kind):
    with app.state.factory() as db:
        return [e.data for e in db.scalars(select(JobEvent).where(JobEvent.job_id == job_id))
                if e.data["kind"] == kind]


def analyse(system, application_id=None, result=None):
    """Queues a CVE analysis, of a new application unless `application_id` and its `result` are given.
    Without a version scheme it analyses the checked-out head, revision "a"."""
    if application_id is None:
        p, queued, result = queue_cve_analysis(system)
        application_id = p["id"]
    else:
        queued = system[1].post(
            f"/api/applications/{application_id}/cves/{result['cve_id']}/analyses", json={}
        ).json()["job_id"]
    return application_id, queued, result


def test_an_analysis_of_another_revision_starts_from_the_applications_audit_context(system):
    app, client, config = system
    application_id, queued, result = analyse(system)
    # Built at a later head than the revision under analysis, as every context usually is.
    context_id = add_context(app, config, application_id, "c" * 40)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    call = broker.calls[0]
    assert {"context/audit-context-building.md", "context/functions/001.md",
            "context/audit-context/DOSSIER.md"} <= set(call["files"])
    # Resume bookkeeping stays behind; it repeats the function documents.
    assert "context/audit-functions.json" not in call["files"]
    prompt = call["prompt"]
    assert "## Audit context" in prompt and "c" * 40 in prompt
    assert "inputs/context/audit-context-building.md" in prompt
    assert "never conclude from it that a vulnerability is absent" in prompt
    assert '"matches_revision": false' in prompt and f'"id": "{context_id}"' in prompt
    assert [e["context_id"] for e in events(app, queued, "audit_context_supplied")] == [context_id]


def test_commit_analysis_judges_the_change_without_the_audit_context(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    add_context(app, config, monitored["id"], "a" * 40)  # even one built at the commit itself
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(assessment("Security hardening", "not_a_finding"), {"report.md": b"# Assessment"})
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    call = broker.calls[0]
    assert not any(path.startswith("context/") for path in call["files"])
    assert "## Audit context" not in call["prompt"] and "audit_context" not in call["prompt"]
    assert events(app, queued, "audit_context_supplied") == []


def test_without_an_audit_context_the_prompt_says_nothing_about_one(system):
    app, _, config = system
    _, _, result = analyse(system)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    assert "## Audit context" not in broker.calls[0]["prompt"]
    assert '"audit_context": null' in broker.calls[0]["prompt"]
    assert not any(path.startswith("context/") for path in broker.calls[0]["files"])


@pytest.mark.parametrize("contexts,chosen", [
    # (source_ref, stage, minutes old); "a" is the analysed revision.
    ([("c", "complete", 1), ("a", "complete", 5)], 1),  # exact and complete wins
    ([("a", "functions", 1), ("c", "complete", 5)], 1),  # complete beats an exact partial
    ([("c", "complete", 5), ("d", "complete", 1)], 1),  # newest complete
    ([("c", "functions", 1), ("a", "functions", 5)], 1),  # no complete: exact partial
    ([("c", "functions", 5), ("d", "functions", 1)], 1),  # else the newest
])
def test_the_closest_finished_context_is_chosen(system, contexts, chosen):
    app, _, config = system
    application_id, queued, result = analyse(system)
    ids = [add_context(app, config, application_id, ref * 40, stage, age) for ref, stage, age in contexts]
    run_once(config, app.state.factory, FixtureBroker(result, bundle()))
    assert [e["context_id"] for e in events(app, queued, "audit_context_supplied")] == [ids[chosen]]


def test_an_oversized_context_keeps_its_entry_document_or_is_skipped(system, monkeypatch):
    app, _, config = system
    application_id, queued, result = analyse(system)
    add_context(app, config, application_id, "c" * 40,
                files={**CONTEXT_FILES, "functions/001.md": b"x" * 2048})
    monkeypatch.setattr(workflows, "CONTEXT_BUDGET", 1024)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    files = broker.calls[0]["files"]
    assert "context/audit-context-building.md" in files and "context/functions/001.md" not in files
    assert '"function_documents": false' in broker.calls[0]["prompt"]

    _, queued, _ = analyse(system, application_id, result)
    monkeypatch.setattr(workflows, "CONTEXT_BUDGET", 8)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    assert not any(path.startswith("context/") for path in broker.calls[0]["files"])
    assert events(app, queued, "audit_context_skipped")


def snapshot_files(app, application_id, revision, files):
    """Makes `revision` the application's head, with exactly `files` as its source."""
    with app.state.factory.begin() as db:
        repository = repository_of(db, application_id)
        repository.cursor = revision
        row = Snapshot(repository_id=repository.id, source_generation=repository.source_generation,
                       source_ref=revision, files=list(files))
        db.add(row)
        db.flush()
        publish(db, app.state.config.artifact_root, "snapshot", row.id, files)


def audit_application(system, tmp_path, monkeypatch, **config):
    app, client, _ = system
    connection(app)
    p = application(client, config=config) if config else application(client)
    skill = tmp_path / "skill"
    skill.mkdir(exist_ok=True)
    (skill / "SKILL.md").write_text("Analyze functions")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))
    return p


UNITS = [{"id": f"F{i}", "path": f"{name}.py", "name": name} for i, name in enumerate(("keep", "change", "gone"))]


class AuditBroker(FixtureBroker):
    """Answers each audit phase; `fail` maps a function index to the errors its runs raise."""

    def __init__(self, units=UNITS, fail=None):
        self.fail = dict(fail or {})
        super().__init__(handler=self.answer)
        self.units = units

    def answer(self, call):
        token = call["token"]
        if token.endswith(":orientation"):
            return {"overview": "Map", "functions": self.units}, {}
        if ":function:" in token:
            index = int(token.split(":function:")[1].split(":")[0])
            return ({"summary": "Converts input", "evidence": [{"path": "keep.py"}], "open_questions": []},
                    {"function.md": f"# {self.units[index]['name']} at {call['token'][-6:]}".encode()})
        return {"summary": "System model", "open_questions": []}, {"audit-context/DOSSIER.md": b"# Dossier"}

    def wait(self, run_id, heartbeat, progress, deadline=900):
        for index, errors in self.fail.items():
            if f":function:{index}" in run_id and errors:
                raise errors.pop(0)
        return super().wait(run_id, heartbeat, progress, deadline)


def phases(broker):
    return [call["token"].split(":", 1)[1] for call in broker.calls]


def test_a_failed_function_is_analysed_once_more_within_a_bounded_run(system, tmp_path, monkeypatch):
    from dataclasses import replace

    from numen.security import DomainError

    app, client, config = system
    p = audit_application(system, tmp_path, monkeypatch)
    snapshot_files(app, p["id"], "a" * 40, {"keep.py": b"k", "change.py": b"c", "gone.py": b"g"})
    timeout = DomainError("timeout", "Workload exceeded the configured execution deadline.", 502)
    invalid = DomainError("invalid_agent_output", "Result file contains invalid JSON", 422)
    # Function 1 recovers on its retry; function 2 fails twice and stays failed.
    broker = AuditBroker(fail={1: [timeout], 2: [invalid, invalid]})
    queued = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    run_once(replace(config, audit_concurrency=1), app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert job["result"]["coverage"]["completed"] == 2 and job["result"]["coverage"]["failed"] == 1
    assert phases(broker) == ["orientation", "function:0", "function:1", "function:1:retry",
                              "function:2", "function:2:retry", "synthesis"]
    functions = [c for c in broker.calls if ":function:" in c["token"]]
    # Every function run is bounded, with the agent run's other defaults kept.
    assert {c["limits"]["timeout_seconds"] for c in functions} == {1800}


def test_a_refresh_reanalyses_only_functions_whose_file_changed(system, tmp_path, monkeypatch):
    app, client, config = system
    p = audit_application(system, tmp_path, monkeypatch)
    snapshot_files(app, p["id"], "a" * 40, {"keep.py": b"k", "change.py": b"c1", "gone.py": b"g"})
    client.post(f"/api/applications/{p['id']}/audit-contexts", json={"focus": "Parsing", "max_functions": 5})
    run_once(config, app.state.factory, AuditBroker())
    base = client.get(f"/api/applications/{p['id']}/audit-contexts").json()["items"][0]
    assert base["coverage"]["stage"] == "complete"
    # Refreshing at the context's own revision has nothing to do.
    current = client.post(f"/api/applications/{p['id']}/audit-contexts", json={"refresh_from": base["id"]})
    assert current.status_code == 409 and current.json()["code"] == "context_current"
    assert client.post(f"/api/applications/{p['id']}/audit-contexts",
                       json={"refresh_from": "missing"}).status_code == 404

    snapshot_files(app, p["id"], "b" * 40, {"keep.py": b"k", "change.py": b"c2", "new.py": b"n"})
    queued = client.post(f"/api/applications/{p['id']}/audit-contexts",
                         json={"refresh_from": base["id"], "max_functions": 1}).json()["job_id"]
    broker = AuditBroker()
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    # Orientation is reused; only the changed file's function and synthesis run.
    assert phases(broker) == ["function:1", "synthesis"]
    coverage = job["result"]["coverage"]
    assert (coverage["completed"], coverage["removed"], coverage["failed"], coverage["reused_functions"]) == (2, 1, 0, 1)
    refresh = coverage["refresh"]
    assert refresh["from"] == base["id"] and refresh["from_revision"] == "a" * 40
    assert refresh["changed_files"] == ["change.py", "gone.py", "new.py"]
    assert refresh["removed_units"] == [{"index": 2, "name": "gone", "path": "gone.py"}]
    # The refresh keeps the scope its base was built with, not the request's.
    assert broker.calls[0]["prompt"].count('"max_functions": 5') == 1 and '"focus": "Parsing"' in broker.calls[0]["prompt"]
    synthesis = broker.calls[-1]["prompt"]
    assert "This synthesis refreshes the context built at revision " + "a" * 40 in synthesis
    latest = client.get(f"/api/applications/{p['id']}/audit-contexts").json()["items"][0]
    assert latest["source_ref"] == "b" * 40 and latest["status"] == "complete"
    def document(context, path):
        artifact = next(a for a in context["artifacts"] if a["path"] == path)
        return client.get(f"/api/artifacts/{artifact['id']}/content").content

    # The unchanged function keeps its earlier document; the changed one has a new analysis.
    assert document(latest, "functions/001.md") == document(base, "functions/001.md")
    assert document(latest, "functions/002.md").startswith(b"# change")


def test_the_audit_context_is_refreshed_after_a_source_check_when_the_application_asks(system, tmp_path, monkeypatch):
    from numen.sources import Sources

    app, client, config = system
    p = audit_application(system, tmp_path, monkeypatch, audit_auto_refresh=True)
    snapshot_files(app, p["id"], "a" * 40, {"keep.py": b"k", "change.py": b"c1", "gone.py": b"g"})
    client.post(f"/api/applications/{p['id']}/audit-contexts", json={})
    run_once(config, app.state.factory, AuditBroker())
    head = {"revision": "a" * 40}
    monkeypatch.setattr(Sources, "github_commits", lambda self, repository: (head["revision"], [], None))

    def check():
        queued = check_now(client, p["id"])
        run_once(config, app.state.factory, FixtureBroker())
        assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"

    def refreshes():
        with app.state.factory() as db:
            return db.scalars(select(Job).where(Job.kind == "audit_context",
                                                Job.input["refresh_from"].as_string().is_not(None))).all()

    check()  # The context is current: nothing to refresh.
    assert refreshes() == []
    snapshot_files(app, p["id"], "b" * 40, {"keep.py": b"k", "change.py": b"c2"})
    head["revision"] = "b" * 40
    with app.state.factory.begin() as db:
        repository_of(db, p["id"]).cursor = "a" * 40  # the check moves it
    check()
    queued = refreshes()
    assert len(queued) == 1 and queued[0].idempotency_key == f"audit-refresh:{p['id']}:{'b' * 40}"
    with app.state.factory.begin() as db:
        # Held back, so the next check runs while the refresh is still queued.
        db.get(Job, queued[0].id).not_before = now() + timedelta(hours=1)
    check()  # No second refresh while one is queued.
    assert len(refreshes()) == 1


def test_a_source_check_never_fails_for_an_audit_refresh_it_cannot_queue(system, tmp_path, monkeypatch):
    from numen.sources import Sources

    app, client, config = system
    p = audit_application(system, tmp_path, monkeypatch, audit_auto_refresh=True)
    snapshot_files(app, p["id"], "a" * 40, {"keep.py": b"k"})
    add_context(app, config, p["id"], "a" * 40)
    with app.state.factory.begin() as db:
        db.get(Setting, "global").data = {**db.get(Setting, "global").data, "default_profiles": {}}
    monkeypatch.setattr(Sources, "github_commits", lambda self, repository: ("b" * 40, [], None))
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    blocked = events(app, queued, "audit_refresh_blocked")
    assert blocked and blocked[0]["code"] == "profile_required"


def test_a_context_finished_before_records_were_kept_still_refreshes(system, tmp_path, monkeypatch):
    from numen.artifacts import resource_files

    app, client, config = system
    p = audit_application(system, tmp_path, monkeypatch)
    snapshot_files(app, p["id"], "a" * 40, {"keep.py": b"k", "change.py": b"c1", "gone.py": b"g"})
    client.post(f"/api/applications/{p['id']}/audit-contexts", json={})
    run_once(config, app.state.factory, AuditBroker())
    with app.state.factory.begin() as db:
        base = db.scalar(select(AuditContext))
        saved = resource_files(db, config.artifact_root, "audit", base.id, base.coverage["artifact_revision"])
        saved.pop("audit-functions.json")
        revision, _ = publish(db, config.artifact_root, "audit", base.id, saved)
        base.coverage = {**base.coverage, "artifact_revision": revision}
        base_id = base.id
    snapshot_files(app, p["id"], "b" * 40, {"keep.py": b"k", "change.py": b"c2", "gone.py": b"g"})
    client.post(f"/api/applications/{p['id']}/audit-contexts", json={"refresh_from": base_id})
    broker = AuditBroker()
    run_once(config, app.state.factory, broker)
    assert phases(broker) == ["function:1", "synthesis"]


@pytest.mark.parametrize("path,resolved", [
    ("src/Foo.php", "concrete/src/Foo.php"),  # package folder left out
    ("repo/concrete/src/Foo.php", "concrete/src/Foo.php"),  # a folder added
    ("inputs/source/index.php", "index.php"),
    ("Bar.php", "Bar.php"),  # ambiguous: left as named
    ("x/index.php", "x/index.php"),  # a bare file name never stands for a deeper path
])
def test_an_audit_path_off_by_leading_folders_resolves_only_when_unique(path, resolved):
    files = {"concrete/src/Foo.php": b"", "concrete/src/Bar.php": b"", "lib/Bar.php": b"",
             "index.php": b"", "concrete/index.php": b""}
    assert workflows.snapshot_path(path, files) == resolved
