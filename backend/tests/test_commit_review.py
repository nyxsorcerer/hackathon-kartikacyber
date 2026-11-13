import io
import json
import zipfile

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, check_now, connection, application, repository_of, source_snapshot
from test_artifacts import bundle
from numen import domain
from numen.models import Action, Artifact, Commit, Job, Notification, Application
from numen.worker import run_once


TRIAGED = {"reply": json.dumps({"decision": "security_candidate", "title": "Potential path traversal", "reason": "A trust boundary changed"})}


def prepared(system):
    app, client, _ = system
    profile = connection(app)
    monitored = application(client)
    ident = source_snapshot(app, monitored["id"])
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "parent_revisions": ["f" * 40]}
    return monitored, ident, profile


def assessment(verdict="Vulnerability fix", ref="f" * 40):
    finding = verdict in ("Vulnerability fix", "Vulnerability introduced")
    return {
        "title": "Path traversal through template file inclusion",
        "verdict": verdict,
        "confidence": "high",
        "summary": "The before/after source identifies the input trust boundary",
        "evidence": [{"path": "main.py", "lines": [1, 2], "revision": ref}],
        "open_questions": [],
        "before_after": "The commit rejects previously accepted traversal sequences",
        "affected_behavior": "Template file selection",
        "vulnerable_ref": ref if finding else None,
    }


def pinned_bundle(ref="f" * 40):
    files = bundle()
    files["vulnerable-app/application.lock.json"] = json.dumps({"version": "before-fix", "source_ref": ref, "images": []}).encode()
    return files


@pytest.mark.parametrize("decision,expected", [
    ("security_candidate", "candidate"),
    ("unrelated", "dismissed"),
    ("insufficient_context", "pending"),
])
def test_triage_records_security_title_and_routes_review_decision(system, decision, expected):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        row = db.get(Application, monitored["id"])
        job = domain.submit_agent(db, "commit_triage", row, {"commit_id": ident, "source_ref": "a" * 40})
        job_id = job.id
    result = {"decision": decision, "title": "Potential path traversal in template selection", "reason": "A source trust boundary was assessed"}
    run_once(config, app.state.factory, FixtureBroker({"reply": json.dumps(result)}))
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "succeeded", job
    row = client.get(f"/api/commits/{ident}").json()
    assert row["review_decision"] == expected
    assert row["triage_result"]["title"] == result["title"]
    assert row["triage_result"]["decision"] == decision


def test_late_manual_review_is_not_overwritten_by_triage(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        domain.submit_agent(db, "commit_triage", db.get(Application, monitored["id"]), {"commit_id": ident, "source_ref": "a" * 40})
    client.post(f"/api/commits/{ident}/review", json={"decision": "dismissed"})
    run_once(config, app.state.factory, FixtureBroker(TRIAGED))
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_result"]["decision"] == "security_candidate"
    assert row["review_decision"] == "dismissed"


@pytest.mark.parametrize("verdict,ref", [("Vulnerability fix", "f" * 40), ("Vulnerability introduced", "a" * 40)])
def test_supported_commit_finding_publishes_a_linked_immutable_bundle(system, verdict, ref):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(assessment(verdict, ref=ref), pinned_bundle(ref))
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert job["result"]["commit_id"] == ident
    finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    assert finding["source_commit_id"] == ident
    assert finding["source_analysis_id"] == job["result"]["analysis_id"]
    assert finding["title"] == assessment()["title"] and finding["kind"] == "0day"
    assert finding["artifact_state"]["status"] == "complete" and finding["lab_runs"] == []
    # A commit finding records no version ranges, but still presents every finding field.
    assert finding["affected_versions"] == [] and finding["fixed_versions"] == []
    assert finding["target_applicability"] == "unknown"
    original = client.get(f"/api/analyses/{job['result']['analysis_id']}/download")
    with zipfile.ZipFile(io.BytesIO(original.content)) as archive:
        assert {"report.md", "poc.py", "vulnerable-app/Dockerfile", "manifest.json"} <= set(archive.namelist())
    client.patch(f"/api/findings/{finding['id']}", json={"title": "Operator-reviewed title", "status": "fixed"})
    again = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(verdict, ref=ref), {**pinned_bundle(ref), "report.md": b"# Updated review"}))
    assert client.get(f"/api/jobs/{again}").json()["result"]["finding_id"] == finding["id"]
    current = client.get(f"/api/findings/{finding['id']}").json()
    assert current["title"] == "Operator-reviewed title" and current["status"] == "fixed"
    assert len(client.get("/api/findings").json()["items"]) == 1
    with zipfile.ZipFile(io.BytesIO(client.get(f"/api/analyses/{job['result']['analysis_id']}/download").content)) as archive:
        assert archive.read("report.md") == pinned_bundle()["report.md"]


@pytest.mark.parametrize("verdict,review", [
    ("Security hardening", "dismissed"),
    ("Unrelated", "dismissed"),
    ("Insufficient context", "pending"),
])
def test_nonfinding_commit_analysis_retains_report_without_creating_findings(system, verdict, review):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(assessment(verdict), {"report.md": b"# Assessment"})
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    row = client.get(f"/api/commits/{ident}").json()
    assert row["review_decision"] == review
    assert row["verdict"] == row["analyses"][0]["result"]["verdict"] == verdict
    assert client.get("/api/findings").json()["items"] == []


def test_commit_finding_cannot_publish_an_unrelated_vulnerable_revision(system):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(ref="e" * 40), pinned_bundle("e" * 40)))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "invalid_finding_revision"
    assert client.get("/api/findings").json()["items"] == []
    assert client.get(f"/api/commits/{ident}").json()["analyses"]


def test_finding_regeneration_uses_the_validated_vulnerable_parent(system, monkeypatch):
    from numen.sources import Sources
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(), pinned_bundle()))
    finding_id = client.get(f"/api/jobs/{queued}").json()["result"]["finding_id"]
    requested = []
    def snapshot(self, row, ref):
        requested.append(ref)
        return {"main.py": b"# Real pinned before-fix source fixture"}
    monkeypatch.setattr(Sources, "snapshot_github", snapshot)
    generation = client.post(f"/api/findings/{finding_id}/artifact-generations", json={}).json()["job_id"]
    broker = FixtureBroker({"summary": "Regenerated from parent"}, pinned_bundle())
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{generation}").json()["status"] == "succeeded"
    assert requested == ["f" * 40]
    assert broker.calls[0]["files"]["source/main.py"] == b"# Real pinned before-fix source fixture"
    assert "commit_finding" in broker.calls[0]["prompt"]


def test_parent_lookup_checks_the_requested_commit_and_immutable_hashes(system, monkeypatch):
    import httpx
    from numen.sources import Sources
    from numen.security import DomainError
    app, client, config = system
    monitored, _, _ = prepared(system)
    with app.state.factory() as db:
        row = repository_of(db, monitored["id"])
        source = Sources(config, "fixture-github-token")
        response = {"sha": "a" * 40, "parents": [{"sha": "f" * 40}]}
        seen = []
        def get(url, **kwargs):
            seen.append(url)
            return httpx.Response(200, json=response)
        monkeypatch.setattr(source, "get", get)
        try:
            assert source.commit_parents(row, "a" * 40) == ["f" * 40]
            assert seen == ["https://api.github.com/repos/demo/plugin/commits/" + "a" * 40]
            response["sha"] = "b" * 40
            with pytest.raises(DomainError, match="different commit"):
                source.commit_parents(row, "a" * 40)
            response["sha"], response["parents"] = "a" * 40, [{"sha": "branch-name"}]
            with pytest.raises(DomainError, match="immutable parent"):
                source.commit_parents(row, "a" * 40)
        finally:
            source.close()


def test_batch_review_records_each_decision_and_reports_previous_values(system):
    app, client, _ = system
    monitored, first, _ = prepared(system)
    second = source_snapshot(app, monitored["id"], "b" * 40)
    third = source_snapshot(app, monitored["id"], "c" * 40)
    client.post(f"/api/commits/{second}/review", json={"decision": "candidate"})
    client.post(f"/api/commits/{third}/review", json={"decision": "dismissed"})
    response = client.post("/api/commits/review", json={"ids": [first, second, third, first], "decision": "dismissed"})
    assert response.status_code == 200, response.text
    assert response.json()["items"] == [
        {"id": first, "previous": "pending", "review_decision": "dismissed"},
        {"id": second, "previous": "candidate", "review_decision": "dismissed"},
        {"id": third, "previous": "dismissed", "review_decision": "dismissed"},
    ]
    for ident in (first, second, third):
        assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "dismissed"
    with app.state.factory.begin() as db:
        reviews = db.scalars(select(Action).where(Action.resource_type == "commit")).all()
        # The already-dismissed revision records no second decision.
        assert sorted((a.resource_id, a.data["decision"]) for a in reviews) == sorted([
            (second, "candidate"), (third, "dismissed"), (first, "dismissed"), (second, "dismissed"),
        ])


def test_batch_review_with_an_unknown_commit_changes_nothing(system):
    _, client, _ = system
    _, ident, _ = prepared(system)
    response = client.post("/api/commits/review", json={"ids": [ident, "missing"], "decision": "dismissed"})
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "pending"
    assert client.post("/api/commits/review", json={"ids": [], "decision": "dismissed"}).status_code == 422


def test_batch_candidates_each_record_a_notification(system):
    app, client, _ = system
    monitored, first, _ = prepared(system)
    second = source_snapshot(app, monitored["id"], "b" * 40)
    assert client.post("/api/commits/review", json={"ids": [first, second], "decision": "candidate"}).status_code == 200
    with app.state.factory.begin() as db:
        keys = set(db.scalars(select(Notification.event_key)))
    assert {f"commit:{first}:candidate", f"commit:{second}:candidate"} <= keys


def test_late_batch_review_is_not_overwritten_by_triage(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        domain.submit_agent(db, "commit_triage", db.get(Application, monitored["id"]), {"commit_id": ident, "source_ref": "a" * 40})
    client.post("/api/commits/review", json={"ids": [ident], "decision": "dismissed"})
    run_once(config, app.state.factory, FixtureBroker(TRIAGED))
    assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "dismissed"


def test_jobs_name_their_subject_and_application_without_exposing_raw_input(system):
    app, client, _ = system
    monitored, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        db.get(Commit, ident).triage_result = {"title": "Potential path traversal in template selection"}
    analysis = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    check = check_now(client, monitored["id"])
    job = client.get(f"/api/jobs/{analysis}").json()
    assert job["application_name"] == monitored["asset_name"]
    assert job["subject"] == {
        "type": "commit",
        "label": "Potential path traversal in template selection",
        "ref": "a" * 10,
        "link": f"/commits/{ident}",
    }
    assert "input" not in job
    listed = {j["id"]: j for j in client.get("/api/jobs").json()["items"]}
    assert listed[analysis]["subject"]["link"] == f"/commits/{ident}"
    # A source check's queued ref is its starting cursor, so none is shown.
    assert listed[check]["subject"] == {
        "type": "source",
        "label": "demo/plugin",
        "ref": None,
        "link": f"/applications/{monitored['id']}?tab=repositories",
    }


def test_confirmed_commits_link_their_findings_without_a_candidate_notification(system):
    app, client, _ = system
    monitored, ident, _ = prepared(system)
    second = source_snapshot(app, monitored["id"], "b" * 40)
    assert client.get(f"/api/commits/{ident}").json()["findings"] == []
    finding = client.post("/api/findings", json={
        "application_id": monitored["id"], "kind": "0day", "title": "Path traversal in template selection",
        "source_commit_id": ident,
    })
    assert finding.status_code in (200, 201), finding.text
    linked = {"id": finding.json()["id"], "title": "Path traversal in template selection", "status": "open", "kind": "0day"}
    assert client.get(f"/api/commits/{ident}").json()["findings"] == [linked]
    listed = {c["id"]: c for c in client.get(f"/api/applications/{monitored['id']}/commits").json()["items"]}
    assert listed[ident]["findings"] == [linked] and listed[second]["findings"] == []
    assert client.post(f"/api/commits/{ident}/review", json={"decision": "confirmed"}).json()["review_decision"] == "confirmed"
    batch = client.post("/api/commits/review", json={"ids": [second], "decision": "confirmed"}).json()
    assert batch["items"] == [{"id": second, "previous": "pending", "review_decision": "confirmed"}]
    with app.state.factory.begin() as db:
        keys = set(db.scalars(select(Notification.event_key)))
        decisions = [a.data["decision"] for a in db.scalars(select(Action).where(Action.resource_type == "commit"))]
    assert not any(key.endswith(":candidate") for key in keys)
    assert decisions == ["confirmed", "confirmed"]
    # Awaiting review counts only candidates, so confirmed work leaves the badge.
    assert client.get("/api/dashboard").json()["security_reviews"] == 0


def test_analysis_reads_the_pinned_snapshot_without_a_repository_or_build(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    first = FixtureBroker(assessment("Security hardening"), {"report.md": b"# Assessment"})
    client.post(f"/api/commits/{ident}/analyses", json={})
    run_once(config, app.state.factory, first)
    call = first.calls[0]
    # The runner contract has no build or repository field; the source is the pinned snapshot.
    assert set(call) == {"token", "kind", "profile", "prompt", "schema", "files", "policy", "limits"}
    assert call["kind"] == "agent" and any(path.startswith("source/") for path in call["files"])
    assert "diff_review" not in call["schema"]["properties"]
    assert "prior-analyses.json" not in call["files"]
    prompt = call["prompt"]
    assert "never reuse it as a verdict" in prompt
    assert "inputs/source is a read-only checkout of the pinned revision" in prompt
    assert "Build and run nothing" in prompt and "draft" in prompt
    for gone in ("/workspace/repo", "DOCKER_HOST", "private daemon", "Build sandbox", "docker build", "lab run"):
        assert gone not in prompt, gone
    second = FixtureBroker(assessment("Security hardening"), {"report.md": b"# Assessment"})
    client.post(f"/api/commits/{ident}/analyses", json={})
    run_once(config, app.state.factory, second)
    files = second.calls[0]["files"]
    commit = json.loads(files["commit.json"])
    assert "analyses" not in commit and "findings" not in commit and commit["revision"] == "a" * 40
    prior = json.loads(files["prior-analyses.json"])
    assert prior["notice"].startswith("Untrusted prior analysis of this revision. Do not reuse it as a verdict")
    assert "lab run" not in prior["notice"]
    assert prior["analyses"][0]["claims"]["verdict"] == "Security hardening"
    assert "finding_id" not in prior["analyses"][0]["claims"]


def test_a_false_positive_finding_can_be_deleted_with_its_artifacts(system):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(), pinned_bundle()))
    job = client.get(f"/api/jobs/{queued}").json()
    finding_id, analysis_id = job["result"]["finding_id"], job["result"]["analysis_id"]
    with app.state.factory() as db:
        folders = {config.artifact_root / a.revision for a in db.scalars(
            select(Artifact).where(Artifact.resource_type == "finding", Artifact.resource_id == finding_id))}
    assert folders and all(folder.is_dir() for folder in folders)
    # A job still working on the finding blocks deletion.
    generation = client.post(f"/api/findings/{finding_id}/artifact-generations", json={}).json()["job_id"]
    busy = client.delete(f"/api/findings/{finding_id}")
    assert busy.status_code == 409 and busy.json()["code"] == "finding_busy"
    with app.state.factory.begin() as db:
        db.get(Job, generation).status = "failed"
    assert client.delete(f"/api/findings/{finding_id}").status_code == 204
    assert client.get(f"/api/findings/{finding_id}").status_code == 404
    assert not any(folder.exists() for folder in folders)
    commit = client.get(f"/api/commits/{ident}").json()
    assert commit["findings"] == []
    # The analysis that produced it is kept; only its link to the deleted finding is withdrawn.
    analysis = next(a for a in commit["analyses"] if a["id"] == analysis_id)
    assert analysis["result"]["finding_id"] is None and analysis["result"]["finding_removed"] is True
    assert client.get(f"/api/analyses/{analysis_id}/download").status_code == 200
    with app.state.factory() as db:
        record = db.scalar(select(Action).where(Action.resource_type == "finding", Action.resource_id == finding_id,
                                               Action.data["action"].as_string() == "deleted"))
    assert record.data["title"] == assessment()["title"] and record.data["source_commit_id"] == ident
    retried = client.post(f"/api/jobs/{generation}/retry")
    assert retried.status_code == 409 and retried.json()["code"] == "finding_removed"


def test_the_analysis_prompt_requires_a_traced_attack_path_delivered_through_its_source(system):
    app, client, config = system
    _, ident, _ = prepared(system)
    broker = FixtureBroker(assessment("Security hardening"), {"report.md": b"# Assessment"})
    client.post(f"/api/commits/{ident}/analyses", json={})
    run_once(config, app.state.factory, broker)
    prompt = broker.calls[0]["prompt"]
    for rule in (
        "Establish the attack path from the code before building anything",
        "the least privilege they need",
        "Deliver the payload only through the source, signed in as the least-privileged attacker role",
        "never the payload: do not write the malicious value into the database",
        "Report reproduction as reproduced only when the payload entered through the source",
        "an attacker without the impacted privilege reaches through the traced source-to-sink path",
    ):
        assert rule in prompt, rule


def test_an_incomplete_diff_never_yields_unrelated(system):
    app, client, config = system
    _, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "diff_complete": False}
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment("Unrelated"), {"report.md": b"# Merge review"}))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert job["result"]["verdict"] == "Insufficient context"
    commit = client.get(f"/api/commits/{ident}").json()
    assert (commit["verdict"], commit["review_decision"]) == ("Insufficient context", "pending")
    assert commit["analyses"][0]["result"]["verdict"] == "Insufficient context"


def test_an_incomplete_diff_never_stands_as_security_hardening(system):
    """No whole-change review is possible from the snapshot, so a Security hardening Verdict on an
    incomplete diff becomes Insufficient context, and a claimed review is refused."""
    app, client, config = system
    _, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "diff_complete": False}
    claimed = {**assessment("Security hardening"), "diff_review": {"range": "f" * 40 + ".." + "a" * 40}}
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(claimed, {"report.md": b"# Merge review"}))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "invalid_agent_output", job
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment("Security hardening"), {"report.md": b"# Merge review"}))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert job["result"]["verdict"] == "Insufficient context"
    assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "pending"


def analysis_jobs(app, ident=None):
    with app.state.factory() as db:
        query = select(Job).where(Job.kind == "commit_analysis")
        if ident:
            query = query.where(Job.input["commit_id"].as_string() == ident)
        return db.scalars(query).all()


def test_batch_analysis_queues_one_job_per_revision_and_skips_active_or_earlier_ones(system):
    app, client, _ = system
    monitored, first, profile = prepared(system)
    second = source_snapshot(app, monitored["id"], "b" * 40)
    third = source_snapshot(app, monitored["id"], "c" * 40)
    running = client.post(f"/api/commits/{second}/analyses", json={}).json()["job_id"]
    with app.state.factory.begin() as db:
        db.get(Commit, third).source_generation -= 1
    body = {"ids": [first, second, third, first], "profile": profile}
    response = client.post("/api/commits/analyses", json=body, headers={"Idempotency-Key": "batch-1"})
    assert response.status_code == 202, response.text
    items = response.json()["items"]
    queued = items[0]["job_id"]
    assert items == [
        {"id": first, "job_id": queued, "skipped": None},
        {"id": second, "job_id": None, "skipped": "analysis_active"},
        {"id": third, "job_id": None, "skipped": "historical_source"},
    ]
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["kind"] == "commit_analysis" and job["profile"] == profile
    assert [j.id for j in analysis_jobs(app, second)] == [running]
    # A resubmitted batch returns the job it already queued instead of reporting it as active.
    again = client.post("/api/commits/analyses", json=body, headers={"Idempotency-Key": "batch-1"})
    assert again.json()["items"] == items
    assert [j.id for j in analysis_jobs(app, first)] == [queued]
    with app.state.factory() as db:
        requested = db.scalars(select(Action).where(Action.resource_id == first,
                                                    Action.data["action"].as_string() == "analysis_requested")).all()
    assert [a.data["job_id"] for a in requested] == [queued]


@pytest.mark.parametrize("extra,status", [
    ({"ids": ["missing"]}, 404),
    ({"profile": {"agent": "pi", "connection_id": "missing", "model_id": "test-model"}}, 404),
    ({"ids": [f"c{i}" for i in range(50)]}, 422),  # 51 revisions, one more than a batch may queue
])
def test_batch_analysis_that_cannot_queue_every_revision_queues_nothing(system, extra, status):
    app, client, _ = system
    _, ident, _ = prepared(system)
    body = {**extra, "ids": [ident, *extra.get("ids", [])]}
    response = client.post("/api/commits/analyses", json=body)
    assert response.status_code == status, response.text
    assert analysis_jobs(app) == []
    assert client.post("/api/commits/analyses", json={"ids": []}).status_code == 422


def test_findings_are_deleted_together_and_any_blocked_one_deletes_none(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(), pinned_bundle()))
    analyzed = client.get(f"/api/jobs/{queued}").json()["result"]["finding_id"]
    manual = [
        client.post("/api/findings", json={"application_id": monitored["id"], "kind": "0day", "title": f"Duplicate {n}"}).json()["id"]
        for n in range(2)
    ]
    ids = [analyzed, *manual]
    with app.state.factory() as db:
        folders = {config.artifact_root / a.revision for a in db.scalars(
            select(Artifact).where(Artifact.resource_type == "finding", Artifact.resource_id == analyzed))}
    assert folders
    generation = client.post(f"/api/findings/{analyzed}/artifact-generations", json={}).json()["job_id"]
    busy = client.post("/api/findings/delete", json={"ids": ids})
    assert busy.status_code == 409 and busy.json()["code"] == "finding_busy"
    with app.state.factory.begin() as db:
        db.get(Job, generation).status = "failed"
    unknown = client.post("/api/findings/delete", json={"ids": [*ids, "missing"]})
    assert unknown.status_code == 404 and unknown.json()["code"] == "not_found"
    assert all(client.get(f"/api/findings/{i}").status_code == 200 for i in ids)
    response = client.post("/api/findings/delete", json={"ids": [*ids, analyzed]})
    assert response.status_code == 200, response.text
    assert response.json() == {"deleted": ids}
    assert all(client.get(f"/api/findings/{i}").status_code == 404 for i in ids)
    assert not any(folder.exists() for folder in folders)
    assert client.get(f"/api/commits/{ident}").json()["findings"] == []
    with app.state.factory() as db:
        deleted = db.scalars(select(Action.resource_id).where(Action.resource_type == "finding",
                                                              Action.data["action"].as_string() == "deleted")).all()
    assert sorted(deleted) == sorted(ids)
    assert client.post("/api/findings/delete", json={"ids": []}).status_code == 422
