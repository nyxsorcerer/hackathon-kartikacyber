import io
import json
import zipfile

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, connection, program, source_snapshot
from test_artifacts import bundle
from numen import domain
from numen.models import Action, Artifact, Commit, Job, Notification, Program
from numen.worker import run_once


def prepared(system):
    app, client, _ = system
    profile = connection(app)
    monitored = program(client)
    ident = source_snapshot(app, monitored["id"])
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "parent_revisions": ["f" * 40]}
    return monitored, ident, profile


def assessment(category="Likely vulnerability fix", decision="finding", ref="f" * 40):
    return {
        "title": "Path traversal through template file inclusion",
        "category": category,
        "summary": "The before/after source identifies the input trust boundary",
        "evidence": [{"path": "main.py", "lines": [1, 2], "revision": ref}],
        "confidence": {"level": "high", "basis": "Pinned source and reproduction"},
        "open_questions": [],
        "before_after": "The commit rejects previously accepted traversal sequences",
        "affected_behavior": "Template file selection",
        "finding_decision": decision,
        "finding_reason": "The pinned parent accepts a traversal payload" if decision == "finding" else "No reachable vulnerability was established",
        "vulnerable_ref": ref if decision == "finding" else None,
        "reproduction": {"status": "reproduced" if decision == "finding" else "not_run", "summary": "Observed in a controlled lab" if decision == "finding" else "No supported reproduction"},
    }


def pinned_bundle(ref="f" * 40):
    files = bundle()
    files["vulnerable-app/application.lock.json"] = json.dumps({"version": "before-fix", "source_ref": ref, "images": []}).encode()
    return files


@pytest.mark.parametrize("decision,kind,expected", [
    ("security_candidate", "vulnerability_fix", "candidate"),
    ("unrelated", "unrelated", "dismissed"),
    ("insufficient_context", "insufficient_context", "pending"),
])
def test_triage_records_security_title_and_routes_review_decision(system, decision, kind, expected):
    app, client, config = system
    monitored, ident, profile = prepared(system)
    with app.state.factory.begin() as db:
        row = db.get(Program, monitored["id"])
        job = domain.submit_agent(db, "commit_triage", row, {"commit_id": ident, "source_ref": "a" * 40}, profile)
        job_id = job.id
    result = {"decision": decision, "change_kind": kind, "title": "Potential path traversal in template selection", "reason": "A source trust boundary was assessed", "confidence": {"level": "medium"}}
    run_once(config, app.state.factory, FixtureBroker(result))
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "succeeded", job
    row = client.get(f"/api/commits/{ident}").json()
    assert row["review_decision"] == expected
    assert row["triage_result"]["title"] == result["title"]
    assert row["triage_result"]["change_kind"] == kind


def test_late_manual_review_is_not_overwritten_by_triage(system):
    app, client, config = system
    monitored, ident, profile = prepared(system)
    with app.state.factory.begin() as db:
        domain.submit_agent(db, "commit_triage", db.get(Program, monitored["id"]), {"commit_id": ident, "source_ref": "a" * 40}, profile)
    client.post(f"/api/commits/{ident}/review", json={"decision": "dismissed"})
    run_once(config, app.state.factory, FixtureBroker({"decision": "security_candidate", "change_kind": "vulnerability_introduction", "title": "Potential path traversal", "reason": "A trust boundary changed", "confidence": {"level": "high"}}))
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_result"]["decision"] == "security_candidate"
    assert row["review_decision"] == "dismissed"


@pytest.mark.parametrize("category,ref", [("Likely vulnerability fix", "f" * 40), ("Potentially introduced vulnerability", "a" * 40)])
def test_supported_commit_finding_builds_and_publishes_a_linked_immutable_bundle(system, category, ref):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(assessment(category, ref=ref), pinned_bundle(ref))
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert broker.calls[0]["build"] is True
    assert "private Docker daemon" in broker.calls[0]["prompt"]
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
    run_once(config, app.state.factory, FixtureBroker(assessment(category, ref=ref), {**pinned_bundle(ref), "report.md": b"# Updated review"}))
    assert client.get(f"/api/jobs/{again}").json()["result"]["finding_id"] == finding["id"]
    current = client.get(f"/api/findings/{finding['id']}").json()
    assert current["title"] == "Operator-reviewed title" and current["status"] == "fixed"
    assert len(client.get("/api/findings").json()["items"]) == 1
    with zipfile.ZipFile(io.BytesIO(client.get(f"/api/analyses/{job['result']['analysis_id']}/download").content)) as archive:
        assert archive.read("report.md") == pinned_bundle()["report.md"]


@pytest.mark.parametrize("category,decision,review", [
    ("Security hardening", "not_a_finding", "dismissed"),
    ("Unrelated change", "not_a_finding", "dismissed"),
    ("Insufficient context", "needs_more_evidence", "pending"),
])
def test_nonfinding_commit_analysis_retains_report_without_creating_findings(system, category, decision, review):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    broker = FixtureBroker(assessment(category, decision), {"report.md": b"# Assessment"})
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert broker.calls[0]["build"] is True
    row = client.get(f"/api/commits/{ident}").json()
    assert row["review_decision"] == review
    assert row["analyses"][0]["result"]["finding_decision"] == decision
    assert client.get("/api/findings").json()["items"] == []


def test_commit_finding_incomplete_bundle_fails_with_linked_draft_retained(system):
    app, client, config = system
    _, ident, _ = prepared(system)
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(assessment(), {"report.md": b"# Retained evidence"}))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "incomplete_bundle"
    finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    assert finding["artifact_state"]["status"] == "draft"
    assert client.get(f"/api/commits/{ident}").json()["analyses"][0]["id"] == job["result"]["analysis_id"]


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
        row = db.get(Program, monitored["id"])
        source = Sources(config)
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
    monitored, ident, profile = prepared(system)
    with app.state.factory.begin() as db:
        domain.submit_agent(db, "commit_triage", db.get(Program, monitored["id"]), {"commit_id": ident, "source_ref": "a" * 40}, profile)
    client.post("/api/commits/review", json={"ids": [ident], "decision": "dismissed"})
    run_once(config, app.state.factory, FixtureBroker({"decision": "security_candidate", "change_kind": "vulnerability_introduction", "title": "Potential path traversal", "reason": "A trust boundary changed", "confidence": {"level": "high"}}))
    assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "dismissed"


def test_jobs_name_their_subject_and_program_without_exposing_raw_input(system):
    app, client, _ = system
    monitored, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        db.get(Commit, ident).triage_result = {"title": "Potential path traversal in template selection"}
    analysis = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    check = client.post(f"/api/programs/{monitored['id']}/checks").json()["job_id"]
    job = client.get(f"/api/jobs/{analysis}").json()
    assert job["program_name"] == monitored["asset_name"]
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
        "link": f"/programs/{monitored['id']}?tab=commits",
    }


def test_confirmed_commits_link_their_findings_without_a_candidate_notification(system):
    app, client, _ = system
    monitored, ident, _ = prepared(system)
    second = source_snapshot(app, monitored["id"], "b" * 40)
    assert client.get(f"/api/commits/{ident}").json()["findings"] == []
    finding = client.post("/api/findings", json={
        "program_id": monitored["id"], "kind": "0day", "title": "Path traversal in template selection",
        "source_commit_id": ident,
    })
    assert finding.status_code in (200, 201), finding.text
    linked = {"id": finding.json()["id"], "title": "Path traversal in template selection", "status": "open", "kind": "0day"}
    assert client.get(f"/api/commits/{ident}").json()["findings"] == [linked]
    listed = {c["id"]: c for c in client.get(f"/api/programs/{monitored['id']}/commits").json()["items"]}
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


def test_analysis_gets_the_full_repository_and_prior_verdicts_only_as_a_checklist(system):
    app, client, config = system
    monitored, ident, _ = prepared(system)
    first = FixtureBroker(assessment("Security hardening", "not_a_finding"), {"report.md": b"# Assessment"})
    client.post(f"/api/commits/{ident}/analyses", json={})
    run_once(config, app.state.factory, first)
    call = first.calls[0]
    assert call["build"] is True
    assert call["repository"] == {"url": "https://github.com/demo/plugin", "ref": "a" * 40}
    assert "prior-analyses.json" not in call["files"]
    assert "/workspace/repo" in call["prompt"] and "never reuse it as a verdict" in call["prompt"]
    # The sandbox is described up front rather than discovered by trial.
    assert "How the build sandbox works" in call["prompt"]
    assert "never directly between two containers" in call["prompt"]
    assert "numen-lab:0.1.0 is Debian bookworm with Python 3.12, curl, git, unzip" in call["prompt"]
    second = FixtureBroker(assessment("Security hardening", "not_a_finding"), {"report.md": b"# Assessment"})
    client.post(f"/api/commits/{ident}/analyses", json={})
    run_once(config, app.state.factory, second)
    files = second.calls[0]["files"]
    commit = json.loads(files["commit.json"])
    assert "analyses" not in commit and "findings" not in commit and commit["revision"] == "a" * 40
    prior = json.loads(files["prior-analyses.json"])
    assert prior["notice"].startswith("Untrusted prior analysis of this revision. Do not reuse it as a verdict")
    assert prior["analyses"][0]["claims"]["category"] == "Security hardening"
    assert "finding_id" not in prior["analyses"][0]["claims"]


def test_only_a_canonical_github_source_is_mirrored():
    from types import SimpleNamespace

    from numen.workflows import source_repository

    github = SimpleNamespace(source_kind="github", source_url="https://github.com/demo/plugin/")
    assert source_repository(github, "b" * 40) == {"url": "https://github.com/demo/plugin", "ref": "b" * 40}
    assert source_repository(github, "main") is None
    assert source_repository(SimpleNamespace(source_kind="wordpress", source_url="https://plugins.svn.wordpress.org/x"), "1234") is None


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
    broker = FixtureBroker(assessment("Security hardening", "not_a_finding"), {"report.md": b"# Assessment"})
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
        "report diff_review with the exact range you diffed",
    ):
        assert rule in prompt, rule


class RepositoryBroker(FixtureBroker):
    """A run whose runtime reports that the full repository was prepared."""

    def submit(self, token, kind, *args, **kwargs):
        submitted = super().submit(token, kind, *args, **kwargs)
        if kwargs.get("repository"):
            self.states[token]["events"] = [{"type": "repository_ready", "message": "ready"}]
        return submitted


@pytest.mark.parametrize("broker_class,review,succeeds", [
    (FixtureBroker, None, False),  # an incomplete upstream diff and no review
    (FixtureBroker, {"range": "f" * 40 + ".." + "a" * 40, "files": 3}, False),  # a review without the repository
    (RepositoryBroker, None, False),  # the repository without a review
    (RepositoryBroker, {"range": "f" * 40 + ".." + "a" * 40, "files": 3}, True),
])
def test_an_incomplete_diff_is_ruled_unrelated_only_after_reviewing_the_whole_change(system, broker_class, review, succeeds):
    app, client, config = system
    _, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "diff_complete": False}
    result = {**assessment("Unrelated change", "not_a_finding"), **({"diff_review": review} if review else {})}
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    run_once(config, app.state.factory, broker_class(result, {"report.md": b"# Merge review"}))
    job = client.get(f"/api/jobs/{queued}").json()
    if succeeds:
        assert job["status"] == "succeeded", job
        assert client.get(f"/api/commits/{ident}").json()["review_decision"] == "dismissed"
    else:
        assert job["status"] == "failed" and job["error"]["code"] == "insufficient_diff"


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
    ({"profile": {"agent": "codex", "connection_id": "missing", "model_id": "test-model"}}, 404),
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
        client.post("/api/findings", json={"program_id": monitored["id"], "kind": "0day", "title": f"Duplicate {n}"}).json()["id"]
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
