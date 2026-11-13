"""Analysis returns one Verdict (A04): its schema, review routing, drafts, deadline, Review queue,
automatic start and per-day caps; automated runs use API keys only (A13)."""

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from conftest import FixtureBroker, application, check_now, connection, source_snapshot
from test_audit_context import add_context, events
from test_commit_review import assessment, pinned_bundle, prepared
from test_triage import record, reply, triage
from test_workflows import cve_raw, seed_cve
from numen import domain
from numen.api import create_app
from numen.models import CVE, Account, Action, Application, ApplicationCVE, Commit, Job, now
from numen.sources import Sources
from numen.schemas import SERVED_CONTENT_VERDICTS, VERDICTS
from numen.security import DomainError
from numen.workflows import check_verdict, validate_result
from numen.worker import run_once

REVIEW = {
    "Vulnerability fix": "candidate",
    "Vulnerability introduced": "candidate",
    "Malicious change": "candidate",
    "Security hardening": "dismissed",
    "Unrelated": "dismissed",
    "Insufficient context": "pending",
}


def analyze(system, ident, result, outputs):
    app, client, config = system
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(result, outputs)
    run_once(config, app.state.factory, broker, exclude=("notification",))  # Alerts stay queued.
    return client.get(f"/api/jobs/{queued}").json(), broker


@pytest.mark.parametrize("verdict", VERDICTS)
def test_analysis_returns_exactly_one_verdict_with_a_confidence(system, verdict):
    for wrong in (
        {"category": "Likely vulnerability fix"},
        {"verdict": "Likely vulnerability fix"},
        {"verdict": [verdict, "Unrelated"]},
        {"confidence": "unknown"},
        {"confidence": {"level": "high", "basis": "Numen's shape"}},
        {"title": ""},
    ):
        with pytest.raises(DomainError) as refused:
            validate_result("commit_analysis", {**assessment(verdict), **wrong})
        assert refused.value.code == "invalid_agent_output", wrong
    for field in ("verdict", "confidence", "title", "evidence"):
        partial = assessment(verdict)
        del partial[field]
        with pytest.raises(DomainError):
            validate_result("commit_analysis", partial)
    _, client, _ = system
    _, ident, _ = prepared(system)
    ref = "a" * 40 if verdict == "Vulnerability introduced" else "f" * 40
    job, broker = analyze(system, ident, assessment(verdict, ref=ref), pinned_bundle(ref))
    assert job["status"] == "succeeded", job
    assert broker.calls[0]["schema"]["properties"]["verdict"]["enum"] == list(VERDICTS)
    commit = client.get(f"/api/commits/{ident}").json()
    assert commit["verdict"] == job["result"]["verdict"] == verdict
    assert commit["review_decision"] == REVIEW[verdict]
    assert commit["analysis_state"] == {"status": "completed", "analysis_id": job["result"]["analysis_id"]}
    assert commit["analyses"][0]["result"]["confidence"] == "high"


@pytest.mark.parametrize("verdict,ref", [("Vulnerability fix", "f" * 40), ("Vulnerability introduced", "a" * 40)])
def test_fix_and_introduced_verdicts_publish_a_finding_with_the_drafted_bundle(system, verdict, ref):
    _, client, _ = system
    _, ident, _ = prepared(system)
    job, _ = analyze(system, ident, assessment(verdict, ref=ref), pinned_bundle(ref))
    assert job["status"] == "succeeded", job
    finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    assert finding["source_commit_id"] == ident and finding["source"] == "commit"
    assert finding["artifact_state"]["status"] == "complete"
    # Nothing is run, so an incomplete draft is still published, as a draft, and the job succeeds.
    job, _ = analyze(system, ident, assessment(verdict, ref=ref), {"report.md": b"# Drafted without a PoC"})
    assert job["status"] == "succeeded", job
    assert job["result"]["finding_id"] == finding["id"]
    assert job["result"]["artifact_state"]["status"] == "draft"
    assert client.get(f"/api/findings/{finding['id']}").json()["artifact_state"]["status"] == "draft"


def test_malicious_change_opens_a_finding_and_keeps_its_drafts_with_the_analysis(system):
    _, client, _ = system
    _, ident, _ = prepared(system)
    drafts = {
        "report.md": b"# A postinstall loader",
        "detection-rule.yar": b"rule loader { strings: $a = \"eval(atob(\" condition: $a }",
        "cleanup-report.md": b"# Remove the loader and rotate the npm token",
    }
    job, _ = analyze(system, ident, assessment("Malicious change"), drafts)
    assert job["status"] == "succeeded", job
    commit = client.get(f"/api/commits/{ident}").json()
    assert (commit["verdict"], commit["review_decision"]) == ("Malicious change", "candidate")
    (finding,) = client.get("/api/findings").json()["items"]
    assert [f["id"] for f in commit["findings"]] == [finding["id"]] == [job["result"]["finding_id"]]
    assert (finding["status"], finding["source"], finding["cause"]["verdict"]) == ("open", "commit", "Malicious change")
    # Its drafts stay with the Analysis until Phase 5: the Finding has no artifact revision.
    assert finding["artifact_revision"] is None and finding["artifacts"] == []
    assert commit["analyses"][0]["result"]["finding_id"] == finding["id"]
    saved = {a["path"] for a in commit["analyses"][0]["artifacts"]}
    assert {"detection-rule.yar", "cleanup-report.md", "report.md"} <= saved


def test_served_content_analysis_rejects_vulnerability_fix():
    for verdict in ("Vulnerability fix", "Vulnerability introduced"):
        with pytest.raises(DomainError) as refused:
            check_verdict(assessment(verdict), served_content=True)
        assert (refused.value.code, refused.value.status) == ("verdict_not_allowed", 422)
        assert check_verdict(assessment(verdict))["verdict"] == verdict
    assert SERVED_CONTENT_VERDICTS == ("Malicious change", "Security hardening", "Unrelated", "Insufficient context")
    for verdict in SERVED_CONTENT_VERDICTS:
        assert check_verdict(assessment(verdict), served_content=True)["verdict"] == verdict


def test_insufficient_context_lands_in_the_review_queue(system):
    app, client, _ = system
    monitored, older, _ = prepared(system)
    newer = source_snapshot(app, monitored["id"], "b" * 40)
    unrelated = source_snapshot(app, monitored["id"], "c" * 40)
    with app.state.factory.begin() as db:
        for ident, when in ((older, "2026-01-01T00:00:00Z"), (newer, "2026-02-01T00:00:00Z")):
            db.get(Commit, ident).data = {**db.get(Commit, ident).data, "committed_at": when}
    assert client.get("/api/dashboard").json()["review_queue"] == []
    for ident in (older, newer):
        job, _ = analyze(system, ident, assessment("Insufficient context"), {"report.md": b"# Cannot decide"})
        assert job["status"] == "succeeded", job
    analyze(system, unrelated, assessment("Unrelated"), {"report.md": b"# No bearing"})
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["review_queue_count"] == 2
    assert dashboard["review_queue"] == [
        {"id": newer, "title": "Fix validation", "revision": "b" * 40,
         "application_id": monitored["id"], "committed_at": "2026-02-01T00:00:00Z"},
        {"id": older, "title": "Fix validation", "revision": "a" * 40,
         "application_id": monitored["id"], "committed_at": "2026-01-01T00:00:00Z"},
    ]
    # The Operator's decision takes the change out of the queue.
    assert client.post(f"/api/commits/{newer}/review", json={"decision": "dismissed"}).status_code == 200
    dashboard = client.get("/api/dashboard").json()
    assert [c["id"] for c in dashboard["review_queue"]] == [older] and dashboard["review_queue_count"] == 1


def test_an_expired_deadline_leaves_the_change_pending_with_a_visible_timeout(system):
    app, client, config = system
    _, ident, _ = prepared(system)

    class Expired(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            raise DomainError("timeout", "Workload exceeded the configured execution deadline.", 502)

    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    assert client.get(f"/api/commits/{ident}").json()["analysis_state"] == {"status": "queued", "job_id": queued}
    broker = Expired(assessment("Unrelated"), {"report.md": b"# Never collected"})
    run_once(config, app.state.factory, broker)
    assert broker.calls[0]["limits"] == {"timeout_seconds": 1800}
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "timeout"
    commit = client.get(f"/api/commits/{ident}").json()
    assert commit["analysis_state"]["status"] == "timed_out"
    assert commit["analysis_state"]["job_id"] == queued
    assert commit["analysis_state"]["error"]["code"] == "timeout"
    assert (commit["review_decision"], commit["verdict"], commit["analyses"]) == ("pending", None, [])
    retry = client.post(f"/api/jobs/{queued}/retry").json()["job_id"]
    assert client.get(f"/api/commits/{ident}").json()["analysis_state"] == {"status": "queued", "job_id": retry}


def test_addresses_are_recorded(system):
    _, client, _ = system
    _, ident, _ = prepared(system)
    addresses = ["CVE-2025-55182", "GHSA-fv66-9v8q-g76r", "abc1234", "e" * 40, "PYSEC-2024-1"]
    for wrong in (["https://github.com/advisories/1"], ["fix the parser"], ["abc"], ["c" * 7] * 51):
        with pytest.raises(DomainError):
            validate_result("commit_analysis", {**assessment("Vulnerability fix"), "addresses": wrong})
    job, _ = analyze(system, ident, {**assessment("Vulnerability fix"), "addresses": addresses}, pinned_bundle())
    assert job["status"] == "succeeded", job
    assert job["result"]["addresses"] == addresses
    assert client.get(f"/api/commits/{ident}").json()["analyses"][0]["result"]["addresses"] == addresses
    # A later Analysis gets the addresses back as claims to check, never as a verdict.
    _, broker = analyze(system, ident, assessment("Vulnerability fix"), pinned_bundle())
    prior = json.loads(broker.calls[0]["files"]["prior-analyses.json"])
    assert prior["analyses"][0]["claims"]["addresses"] == addresses
    assert prior["analyses"][0]["claims"]["verdict"] == "Vulnerability fix"


# Automatic Analysis (A04) and the API-key rule for automated runs (A13).
CAPS = {"application": 10, "account": 30}
API_KEY = (
    "Automated runs use only Provider accounts that hold an API key; Claude Max uses a subscription "
    "sign-in. Start this run by hand or select an API-key account."
)
FLAG = ("commit_analysis", "notification")  # Runs only the Triage.


def automatic_jobs(app, ident=None):
    """The automatic Analyses queued so far, oldest first; of commit `ident` when given."""
    with app.state.factory() as db:
        jobs = db.scalars(select(Job).where(Job.kind == "commit_analysis").order_by(Job.created_at)).all()
    return [j for j in jobs if j.input.get("automatic") and ident in (None, j.input["commit_id"])]


def started(app, application_id, count, shared=False):
    """`count` automatic Analyses that already ran today on the Application's profile."""
    with app.state.factory.begin() as db:
        application = db.get(Application, application_id)
        profile = domain.resolve_profile(db, application, "commit_analysis")
        for index in range(count):
            inputs = {"commit_id": f"earlier-{shared}-{index}", "automatic": True, "shared": shared}
            domain.enqueue(db, "commit_analysis", application, inputs, profile).status = "succeeded"


def flag(app, application_id, *revisions):
    """New commits at `revisions`, each flagged by Triage in turn; their ids."""
    idents = [source_snapshot(app, application_id, revision) for revision in revisions]
    with app.state.factory.begin() as db:
        for ident in idents:
            domain.start_analysis(db, db.get(Commit, ident))
    return idents


def state(client, ident):
    return client.get(f"/api/commits/{ident}").json()["analysis_state"]


def cap_events(app):
    with app.state.factory() as db:
        return db.scalars(select(Action).where(Action.data["action"].as_string() == "analysis_cap_reached")).all()


def triaged(system, ident, application_id, decision="security_candidate"):
    app, _, config = system
    triage(app, ident, application_id)
    result = {"decision": decision, "title": "Template path check", "reason": "The diff changes a path check"}
    assert run_once(config, app.state.factory, FixtureBroker(reply(result)), exclude=FLAG)


def test_triage_flag_starts_one_automatic_analysis(system):
    app, client, config = system
    monitored, candidate, profile = prepared(system)
    unclear, unrelated = (source_snapshot(app, monitored["id"], r * 40) for r in "bc")
    for ident, decision in ((candidate, "security_candidate"), (unclear, "insufficient_context"), (unrelated, "unrelated")):
        triaged(system, ident, monitored["id"], decision)
    jobs = automatic_jobs(app)
    assert [j.input["commit_id"] for j in jobs] == [candidate, unclear]
    for job, revision in zip(jobs, ("a" * 40, "b" * 40)):
        assert job.idempotency_key == f"analysis:{job.input['commit_id']}"
        assert (job.input["automatic"], job.input["shared"], job.input["source_ref"]) == (True, False, revision)
        assert (job.application_id, job.profile["connection_id"]) == (monitored["id"], profile["connection_id"])
        assert state(client, job.input["commit_id"]) == {"status": "queued", "job_id": job.id}
    assert state(client, unrelated) is None
    triaged(system, candidate, monitored["id"])  # A second flag of the same change starts nothing.
    assert len(automatic_jobs(app)) == 2
    # The automatic Analysis then runs like a manual one.
    run_once(config, app.state.factory, FixtureBroker(assessment("Unrelated"), {"report.md": b"# No bearing"}), exclude=("notification",))
    assert client.get(f"/api/jobs/{jobs[0].id}").json()["status"] == "succeeded"
    assert state(client, candidate)["status"] == "completed"


def test_shared_upstream_commit_is_analysed_once_and_counts_only_against_the_account_cap(system):
    app, client, _ = system
    connection(app)
    shop, blog = application(client, asset_name="Shop"), application(client, asset_name="Blog")
    assert shop["repositories"][0]["repository_id"] == blog["repositories"][0]["repository_id"]
    started(app, shop["id"], CAPS["application"])  # Shop's own cap is full.
    ident = source_snapshot(app, shop["id"])
    triaged(system, ident, shop["id"])
    with app.state.factory.begin() as db:
        domain.start_analysis(db, db.get(Commit, ident))  # The same commit flagged again for Blog
    (job,) = automatic_jobs(app, ident)
    assert (job.input["shared"], job.status, job.application_id) == (True, "queued", shop["id"])
    assert state(client, ident) == {"status": "queued", "job_id": job.id}
    # It is the account's 11th Analysis today: 19 more fill the account cap.
    started(app, shop["id"], CAPS["account"] - 11, shared=True)
    (later,) = flag(app, shop["id"], "b" * 40)
    assert (state(client, later)["status"], state(client, later)["cap"]) == ("waiting_for_cap", "account")


def test_application_cap_makes_new_automatic_analyses_wait_and_records_one_cap_event(system):
    app, client, _ = system
    monitored, _, _ = prepared(system)
    idents = flag(app, monitored["id"], *(f"{index:040x}" for index in range(1, 13)))
    assert [j.input["commit_id"] for j in automatic_jobs(app)] == idents[:10]
    for ident in idents[10:]:
        waiting = state(client, ident)
        assert (waiting["status"], waiting["cap"]) == ("waiting_for_cap", "application") and waiting["since"]
    (event,) = cap_events(app)
    assert (event.resource_type, event.resource_id) == ("application", monitored["id"])
    assert event.data == {"action": "analysis_cap_reached", "day": now().date().isoformat(), "limit": 10}


def test_account_cap_of_thirty_makes_new_automatic_analyses_wait(system):
    app, client, _ = system
    monitored, _, profile = prepared(system)
    started(app, monitored["id"], CAPS["account"] - 1, shared=True)  # The Application cap is untouched.
    last, over = flag(app, monitored["id"], "b" * 40, "c" * 40)
    assert state(client, last)["status"] == "queued"
    assert (state(client, over)["status"], state(client, over)["cap"]) == ("waiting_for_cap", "account")
    (event,) = cap_events(app)
    assert (event.resource_type, event.resource_id, event.data["limit"]) == ("account", profile["connection_id"], 30)
    # The cap belongs to the Provider account: another API-key account starts the change.
    other = connection(app)
    with app.state.factory.begin() as db:
        domain.start_analysis(db, db.get(Commit, over))
    assert state(client, over)["status"] == "queued"
    assert automatic_jobs(app, over)[0].profile["connection_id"] == other["connection_id"]


def test_manual_analysis_still_works_at_a_cap(system):
    app, client, config = system
    monitored, _, _ = prepared(system)
    started(app, monitored["id"], CAPS["account"])  # Both caps are full.
    (ident,) = flag(app, monitored["id"], "b" * 40)
    assert state(client, ident)["status"] == "waiting_for_cap"
    response = client.post(f"/api/commits/{ident}/analyses", json={})
    assert response.status_code == 202, response.text
    queued = response.json()["job_id"]
    assert state(client, ident) == {"status": "queued", "job_id": queued}
    run_once(config, app.state.factory, FixtureBroker(assessment("Unrelated"), {"report.md": b"# No bearing"}), exclude=("notification",))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    assert state(client, ident)["status"] == "completed"
    assert [j.input["commit_id"] for j in automatic_jobs(app)] == [f"earlier-False-{i}" for i in range(30)]


def test_caps_reset_at_midnight_utc_and_waiting_changes_start_oldest_first(system):
    app, client, _ = system
    monitored, _, _ = prepared(system)
    started(app, monitored["id"], CAPS["application"])
    newer, older = flag(app, monitored["id"], "b" * 40, "c" * 40)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, older)  # It has waited longest.
        commit.analysis_state = {**commit.analysis_state, "since": (now() - timedelta(hours=1)).isoformat()}
    since = state(client, newer)["since"]

    def next_day():
        with app.state.factory.begin() as db:
            for job in db.scalars(select(Job)):
                job.created_at -= timedelta(days=1)

    next_day()
    started(app, monitored["id"], CAPS["application"] - 1)  # One place is left today.
    with app.state.factory.begin() as db:
        domain.schedule(db)
    assert state(client, older)["status"] == "queued"
    assert state(client, newer) == {"status": "waiting_for_cap", "since": since, "cap": "application"}
    next_day()
    with app.state.factory.begin() as db:
        domain.schedule(db)
    assert state(client, newer)["status"] == "queued"
    assert [j.input["commit_id"] for j in automatic_jobs(app)][-2:] == [older, newer]


def test_a_new_flag_after_the_reset_waits_behind_changes_already_waiting(system):
    """A Triage flag that arrives before the scheduler's next pass never takes a freed slot first."""
    app, client, _ = system
    monitored, _, _ = prepared(system)
    started(app, monitored["id"], CAPS["application"])
    (waiting,) = flag(app, monitored["id"], "b" * 40)
    with app.state.factory.begin() as db:
        for job in db.scalars(select(Job)):
            job.created_at -= timedelta(days=1)  # Midnight UTC has passed.
    started(app, monitored["id"], CAPS["application"] - 1)  # One place is left today.
    fresh = source_snapshot(app, monitored["id"], "c" * 40)
    triaged(system, fresh, monitored["id"])
    assert state(client, waiting)["status"] == "queued"
    assert (state(client, fresh)["status"], state(client, fresh)["cap"]) == ("waiting_for_cap", "application")


def test_caps_persist_across_restarts(system):
    app, client, config = system
    monitored, _, _ = prepared(system)
    started(app, monitored["id"], CAPS["application"])
    (waiting,) = flag(app, monitored["id"], "b" * 40)
    restarted = create_app(config=config, admin_password="test-password-long")
    with TestClient(restarted):
        with restarted.state.factory.begin() as db:
            domain.schedule(db)
        (later,) = flag(restarted, monitored["id"], "c" * 40)
        with restarted.state.factory() as db:
            for ident in (waiting, later):
                assert db.get(Commit, ident).analysis_state["status"] == "waiting_for_cap"
    assert len(automatic_jobs(app)) == CAPS["application"]


def test_automated_runs_refuse_accounts_without_an_api_key(system, monkeypatch):
    app, client, config = system
    connection(app)
    models = [{"id": "test-model", "name": "Test", "reasoning_efforts": ["high"], "default_effort": "high"}]
    with app.state.factory.begin() as db:
        account = Account(
            label="Claude Max", provider="claude", auth_type="native_oauth",
            credential=app.state.vault.encrypt({"auth_json": {"access_token": "native-fixture-secret"}}),
            data={"status": "ready", "models": models, "agent_models": {"claude": models}, "usage": None},
        )
        db.add(account)
        db.flush()
        native = {"agent": "claude", "connection_id": account.id, "model_id": "test-model", "reasoning_effort": "high"}
    p = application(client, config={
        "triage_mode": "claude",
        "profiles": {op: native for op in ("commit_triage", "commit_analysis", "cve_analysis", "audit_context")},
        "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
        "cve_min_score": 7, "cve_versions": ["3.1"], "cve_auto_analyze": True, "audit_auto_refresh": True,
    })
    ident = source_snapshot(app, p["id"], "a" * 40)
    add_context(app, config, p["id"], "a" * 40)
    monkeypatch.setattr(Sources, "github_commits", lambda *_: ("b" * 40, [record("b" * 40)], None))
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker(), exclude=("notification",))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    # The imported commit's Triage and the audit refresh are refused, and say why.
    rows = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}
    assert rows["b" * 40]["triage_status"] == "blocked"
    assert (rows["b" * 40]["triage_result"]["error"], rows["b" * 40]["triage_result"]["reason"]) == ("api_key_required", API_KEY)
    (blocked,) = events(app, queued, "audit_refresh_blocked")
    assert blocked["code"] == "api_key_required" and API_KEY in blocked["message"]
    # So are an automatic Analysis and an automatic CVE analysis.
    with app.state.factory.begin() as db:
        domain.start_analysis(db, db.get(Commit, ident))
    assert state(client, ident) == {"status": "blocked", "error": {"code": "api_key_required", "message": API_KEY, "retryable": False}}
    seed_cve(app, p["id"], cve_raw())
    with app.state.factory.begin() as db:
        link = db.scalar(select(ApplicationCVE).where(ApplicationCVE.application_id == p["id"]))
        domain.refresh_cve_policy(db, db.get(Application, p["id"]), db.get(CVE, link.cve_id), link)
    cve = client.get(f"/api/cves?application_id={p['id']}").json()["items"][0]
    assert (cve["analysis_blocked"]["code"], cve["analysis_blocked"]["message"]) == ("api_key_required", API_KEY)
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(
            Job.kind.in_(["commit_triage", "commit_analysis", "cve_analysis", "audit_context"]), Job.status == "queued")) == 0
    # The Operator can still start an Analysis by hand with the subscription sign-in.
    response = client.post(f"/api/commits/{ident}/analyses", json={})
    assert response.status_code == 202, response.text
    assert state(client, ident) == {"status": "queued", "job_id": response.json()["job_id"]}
    assert client.get(f"/api/jobs/{response.json()['job_id']}").json()["profile"]["connection_id"] == account.id
