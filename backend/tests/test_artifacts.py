import io
import json
import logging
import zipfile

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, connection, application, source_snapshot
from test_workflows import cve_raw, seed_cve
from numen.worker import run_once

APPROVAL = {"password": "test-password-long"}


def bundle(version="1.0.0"):
    return {
        "poc.py": b"print('proof')",
        "report.md": b"# Report\nFixture vulnerable behavior",
        "vulnerable-app/Dockerfile": b"FROM asset-monitor-lab:0.1.0\nCOPY fixture /fixture\n",
        "vulnerable-app/compose.yaml": b"services:\n  app:\n    build: .\n",
        "vulnerable-app/README.md": b"Use the supplied local fixture",
        "vulnerable-app/fixture": b"fixture bytes",
        "vulnerable-app/application.lock.json": json.dumps(
            {"version": version, "local_inputs": {"fixture": "immutable local bytes"}, "images": []}
        ).encode(),
    }


def finding(client, ident):
    response = client.post(
        "/api/findings",
        json={
            "application_id": ident,
            "source": "commit",
            "title": "Fixture finding",
            "fixed_versions": ["2.0.0"],
            "target_applicability": "affected",
        },
    )
    assert response.status_code == 201
    return response.json()


def upload(client, ident, files):
    return client.post(
        f"/api/findings/{ident}/artifacts",
        files=[("files", (path, data, "application/octet-stream")) for path, data in files.items()],
    )


def queue_cve_analysis(system, extra_config=None, body=None):
    app, client, _ = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
            **(extra_config or {}),
        },
    )
    source_snapshot(app, p["id"])
    raw = cve_raw()
    seed_cve(app, p["id"], raw)
    cve = client.get("/api/cves").json()["items"][0]
    job = client.post(f"/api/applications/{p['id']}/cves/{cve['id']}/analyses", json=body or {})
    from numen.security import fingerprint

    result = {
        "cve_id": cve["id"],
        "source_record_hash": fingerprint(raw),
        "summary": "Fixture CVE analysis",
        "evidence": [{"path": "main.py", "source_ref": "a" * 40}],
        "affected_versions": ["1.0.0"],
        "fixed_versions": ["2.0.0"],
        "confidence": {"basis": "Fixture source"},
        "open_questions": [],
    }
    return p, job.json()["job_id"], result


def test_cve_analysis_produces_downloadable_finding_bundle_and_reuses_finding(system):
    app, client, config = system
    p, queued, result = queue_cve_analysis(system)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    row = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    assert row["source"] == "cve" and row["cve_id"] == result["cve_id"]
    assert row["source_ref"] == result["cve_id"]
    assert (row["cause"]["by"], row["cause"]["analysis_id"]) == ("cve_analysis", job["result"]["analysis_id"])
    assert row["source_analysis_id"] == job["result"]["analysis_id"]
    assert row["fixed_versions"] == ["2.0.0"] and row["status"] == "open"
    assert row["target_applicability"] == "unknown" and row["lab_runs"] == []
    assert row["artifact_state"]["status"] == "complete"
    with zipfile.ZipFile(
        io.BytesIO(client.get(f"/api/findings/{row['id']}/download").content)
    ) as archive:
        assert {"poc.py", "report.md", "vulnerable-app/Dockerfile", "manifest.json"} <= set(
            archive.namelist()
        )
        assert archive.read("report.md") == bundle()["report.md"]
    analyses = client.get("/api/cves").json()["items"][0]["analyses"]
    assert analyses[0]["result"]["finding_id"] == row["id"]
    original_analysis_id = analyses[0]["id"]
    original_report = next(a for a in analyses[0]["artifacts"] if a["path"] == "report.md")
    client.post(f"/api/findings/{row['id']}/transitions", json={"state": "remediated", "reason": "Upgraded"})
    client.patch(f"/api/findings/{row['id']}", json={"title": "Reviewed title"})
    again = client.post(
        f"/api/applications/{p['id']}/cves/{result['cve_id']}/analyses", json={}
    ).json()["job_id"]
    run_once(
        config,
        app.state.factory,
        FixtureBroker(result, {**bundle(), "report.md": b"# Updated report"}),
        exclude=("notification",),
    )
    assert client.get(f"/api/jobs/{again}").json()["result"]["finding_id"] == row["id"]
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["status"] == "remediated" and current["title"] == "Reviewed title"
    assert (
        client.get(f"/api/artifacts/{original_report['id']}/content").content
        == bundle()["report.md"]
    )
    assert len(client.get("/api/findings").json()["items"]) == 1
    # A historical run downloads its own output, even after the linked finding changes.
    downloaded = client.get(f"/api/analyses/{original_analysis_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/zip"
    assert downloaded.headers.get("content-length") == str(len(downloaded.content))
    assert result["cve_id"] in downloaded.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        assert archive.read("report.md") == bundle()["report.md"]
        assert archive.read("vulnerable-app/fixture") == b"fixture bytes"
        assert "manifest.json" in archive.namelist()


@pytest.mark.parametrize("defect", ["missing_poc", "missing_dockerfile", "unpinned_image"])
def test_cve_analysis_incomplete_bundle_fails_and_retains_report(system, defect):
    app, client, config = system
    _, queued, result = queue_cve_analysis(system)
    outputs = bundle()
    if defect == "missing_poc":
        outputs.pop("poc.py")
    elif defect == "missing_dockerfile":
        outputs.pop("vulnerable-app/Dockerfile")
    else:
        outputs["vulnerable-app/Dockerfile"] = b"FROM python:latest\n"
    run_once(config, app.state.factory, FixtureBroker(result, outputs))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "incomplete_bundle"
    row = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    assert row["artifact_state"]["status"] == "draft"
    report = next(a for a in row["artifacts"] if a["path"] == "report.md")
    assert client.get(f"/api/artifacts/{report['id']}/content").content == bundle()["report.md"]
    assert (
        client.get("/api/cves").json()["items"][0]["analyses"][0]["id"]
        == job["result"]["analysis_id"]
    )
    events = client.get(f"/api/jobs/{queued}/events").json()["items"]
    assert any(event.get("partial_output_retained") is True for event in events)
    assert client.post(f"/api/findings/{row['id']}/lab-runs", json=APPROVAL).status_code == 422


def test_analysis_download_retains_drafts_and_enforces_auth_and_integrity(system):
    from fastapi.testclient import TestClient
    from numen.models import Artifact

    app, client, config = system
    _, queued, result = queue_cve_analysis(system)
    run_once(config, app.state.factory, FixtureBroker(result, {"report.md": b"# Draft evidence"}))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed"
    ident = job["result"]["analysis_id"]
    url = f"/api/analyses/{ident}/download"
    downloaded = client.get(url)
    assert downloaded.status_code == 200
    assert downloaded.headers["cache-control"] == "private, no-store"
    assert downloaded.headers.get("content-length") == str(len(downloaded.content))
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        assert archive.read("report.md") == b"# Draft evidence"
        assert "manifest.json" in archive.namelist()
        assert "poc.py" not in archive.namelist()
    with TestClient(app) as unauthenticated:
        assert unauthenticated.get(url).status_code == 401
    assert client.get("/api/analyses/missing/download").status_code == 404
    analysis = client.get("/api/cves").json()["items"][0]["analyses"][0]
    report = next(a for a in analysis["artifacts"] if a["path"] == "report.md")
    with app.state.factory() as db:
        path = config.artifact_root / db.get(Artifact, report["id"]).storage_path
    original = path.read_bytes()
    try:
        path.write_bytes(b"tampered")
        response = client.get(url)
        assert response.status_code == 409
        assert response.json()["code"] == "artifact_corrupt"
    finally:
        path.write_bytes(original)


def test_cve_analysis_pins_newest_affected_release_not_the_fixed_checkout(system, monkeypatch):
    from numen.sources import Sources

    app, client, config = system
    # cve_raw() reports every version below 2.0.0 as affected; 2.0.1 carries the fix.
    catalog = [("2.0.1", "d" * 40), ("2.0.0", "c" * 40), ("1.9.0RC1", "e" * 40), ("1.9.0", "b" * 40)]
    monkeypatch.setattr(Sources, "github_tags", lambda *_: catalog)
    monkeypatch.setattr(
        Sources, "snapshot_github", lambda self, row, revision: {"main.py": revision.encode()}
    )
    _, queued, result = queue_cve_analysis(system, {"version_scheme": "semver"})
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    assert broker.calls[0]["files"]["source/main.py"] == b"b" * 40
    facts = json.loads(broker.calls[0]["prompt"].split("Facts:\n")[1])
    assert facts["source_ref"] == "b" * 40
    assert facts["source_pin"] == {
        "basis": "affected_release",
        "version": "1.9.0",
        "source_ref": "b" * 40,
        "bound": {"version": "2.0.0", "inclusive": False},
    }
    pin = next(
        e
        for e in client.get(f"/api/jobs/{queued}/events").json()["items"]
        if e["kind"] == "source_pin"
    )
    assert pin["version"] == "1.9.0" and "1.9.0" in pin["message"]


def test_cve_analysis_is_read_only(system):
    app, client, config = system
    _, _, result = queue_cve_analysis(system)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    submitted = broker.calls[0]
    # No build or repository reaches the runner, and CVE analysis has Analysis's 30-minute deadline.
    assert set(submitted) == {"token", "kind", "profile", "prompt", "schema", "files", "policy", "limits"}
    assert submitted["limits"] == {"timeout_seconds": 1800}
    prompt = submitted["prompt"]
    assert "inputs/source is a read-only checkout of the pinned revision" in prompt and "Build and run nothing" in prompt
    assert "a Lab verifies it after the Operator's Approval" in prompt
    for gone in ("DOCKER_HOST", "private Docker daemon", "Build sandbox", "/workspace/repo"):
        assert gone not in prompt, gone
    generation = client.post(
        f"/api/findings/{client.get('/api/findings').json()['items'][0]['id']}/artifact-generations",
        json={},
    ).json()["job_id"]
    second = FixtureBroker({"summary": "Partial"}, {"report.md": b"# Partial"})
    run_once(config, app.state.factory, second, exclude=("notification",))
    assert "Build sandbox" not in second.calls[0]["prompt"]
    assert client.get(f"/api/jobs/{generation}").json()["status"] == "failed"


def test_cve_analysis_resolves_an_operator_source_ref_to_an_immutable_commit(system, monkeypatch):
    from numen.sources import Sources

    app, _, config = system
    monkeypatch.setattr(Sources, "commit_ref", lambda self, row, ref: "f" * 40)
    monkeypatch.setattr(
        Sources, "snapshot_github", lambda self, row, revision: {"main.py": revision.encode()}
    )
    _, _, result = queue_cve_analysis(system, body={"source_ref": "1.9.x"})
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    facts = json.loads(broker.calls[0]["prompt"].split("Facts:\n")[1])
    assert facts["source_ref"] == "f" * 40
    assert facts["source_pin"] == {
        "basis": "operator",
        "requested": "1.9.x",
        "source_ref": "f" * 40,
    }


def test_cve_analysis_without_a_version_scheme_retains_the_current_checkout(system):
    app, client, config = system
    # No scheme can rank releases, so nothing is pinned and no release catalog is requested.
    _, queued, result = queue_cve_analysis(system)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    facts = json.loads(broker.calls[0]["prompt"].split("Facts:\n")[1])
    assert facts["source_ref"] == "a" * 40
    assert facts["source_pin"]["basis"] == "unpinned"
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"


def test_finding_generation_uses_linked_cve_analysis_and_rejects_incomplete_output(system):
    app, client, config = system
    _, queued, result = queue_cve_analysis(system)
    run_once(config, app.state.factory, FixtureBroker(result, bundle()))
    completed = client.get(f"/api/jobs/{queued}").json()["result"]
    generation = client.post(
        f"/api/findings/{completed['finding_id']}/artifact-generations", json={}
    ).json()["job_id"]
    broker = FixtureBroker({"summary": "Missing PoC"}, {"report.md": b"# Partial generation"})
    run_once(config, app.state.factory, broker, exclude=("notification",))
    inputs = broker.calls[0]["files"]
    assert json.loads(inputs["analysis.json"])["result"]["cve_id"] == result["cve_id"]
    assert inputs["analysis-report.md"] == bundle()["report.md"]
    assert json.loads(inputs["cve.json"])["id"] == result["cve_id"]
    job = client.get(f"/api/jobs/{generation}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "incomplete_bundle"
    assert job["result"]["finding_id"] == completed["finding_id"]
    assert job["result"]["artifact_state"]["missing"]


def test_finding_generation_keeps_large_artifact_inventories_out_of_the_prompt(system):
    from numen.models import Finding

    app, client, config = system
    _, queued, result = queue_cve_analysis(system)
    files = {**bundle(), **{f"vulnerable-app/tree/file-{index:04}.php": b"source" for index in range(2000)}}
    run_once(config, app.state.factory, FixtureBroker(result, files))
    original = client.get(f"/api/jobs/{queued}").json()["result"]
    with app.state.factory.begin() as db:
        row = db.get(Finding, original["finding_id"])
        row.data = {**row.data, "evidence": [{"source_notes": "evidence " * 40000}]}
    generation = client.post(f"/api/findings/{original['finding_id']}/artifact-generations", json={}).json()["job_id"]
    broker = FixtureBroker({"summary": "Regenerated bundle"}, bundle())
    run_once(config, app.state.factory, broker, exclude=("notification",))
    call = broker.calls[0]
    assert len(call["prompt"]) < 262144  # The actual runner's RunRequest prompt bound.
    assert "finding.json" in call["files"]
    finding = json.loads(call["files"]["finding.json"])
    assert finding["evidence"] == [{"source_notes": "evidence " * 40000}]
    assert finding["id"] == original["finding_id"]
    assert "artifacts" not in finding and "lab_runs" not in finding
    analysis = json.loads(call["files"]["analysis.json"])
    assert analysis["result"]["cve_id"] == result["cve_id"]
    assert "artifacts" not in analysis
    assert call["files"]["analysis-report.md"] == files["report.md"]
    assert client.get(f"/api/jobs/{generation}").json()["status"] == "succeeded"


def test_bundle_draft_completion_immutable_revision_and_lab_failure(system):
    app, client, config = system
    p = application(client)
    row = finding(client, p["id"])
    assert row["status"] == "open" and row["artifact_state"]["status"] == "draft"
    assert client.post(f"/api/findings/{row['id']}/lab-runs", json=APPROVAL).status_code == 422
    first = upload(client, row["id"], {"poc.py": b"first proof"}).json()
    first_artifact = next(a for a in first["artifacts"] if a["path"] == "poc.py")
    complete = upload(client, row["id"], bundle()).json()
    assert complete["artifact_state"]["status"] == "complete", complete
    assert complete["status"] == "open" and complete["target_applicability"] == "affected"
    assert client.get(f"/api/artifacts/{first_artifact['id']}/content").content == b"first proof"
    downloaded = client.get(f"/api/findings/{row['id']}/download")
    assert downloaded.headers.get("content-length") == str(len(downloaded.content))
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        assert {"poc.py", "report.md", "vulnerable-app/Dockerfile", "manifest.json"}.issubset(
            archive.namelist()
        )
        assert archive.read("poc.py") == bundle()["poc.py"]
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["revision"] == complete["artifact_revision"]
        assert all(a["sha256"] and a["size"] > 0 for a in manifest["files"])
    queued = client.post(
        f"/api/findings/{row['id']}/lab-runs", json=APPROVAL, headers={"Idempotency-Key": "lab-once"}
    ).json()["job_id"]
    same = client.post(
        f"/api/findings/{row['id']}/lab-runs", json=APPROVAL, headers={"Idempotency-Key": "lab-once"}
    ).json()["job_id"]
    assert queued == same

    class Waiting(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            self.deadline = deadline
            return super().wait(run_id, heartbeat, progress, deadline)

    broker = Waiting(
        {
            "verified": False,
            "status": "not_reproduced",
            "exit_code": 1,
            "log": "Expected proof absent",
            "pinned_image": "fixture-sha",
        }
    )
    run_once(config, app.state.factory, broker)
    # The broker's ADR-0005 defaults apply, and the wait covers a 15 min build and a 10 min run.
    assert broker.calls[0]["limits"] is None and broker.deadline == 1800
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["lab_runs"][0]["status"] == "not_reproduced"
    assert current["lab_runs"][0]["artifact_revision"] == complete["artifact_revision"]
    assert current["lab_runs"][0]["vulnerable_version"] == "1.0.0"
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    # A Proof that did not reproduce leaves the Finding Open; a reproduced one confirms it (A11).
    assert current["status"] == "open" and current["cause"]["by"] == "operator"
    client.post(f"/api/findings/{row['id']}/lab-runs", json=APPROVAL, headers={"Idempotency-Key": "lab-twice"})
    run_once(config, app.state.factory, FixtureBroker({"verified": True, "status": "verified", "exit_code": 0}))
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["lab_runs"][0]["status"] == "verified"
    assert current["status"] == "confirmed"
    assert {k: v for k, v in current["cause"].items() if k != "at"} == {
        "by": "proof", "lab_run_id": current["lab_runs"][0]["id"]}
    # The idempotent repeat of the first Approval recorded no second Action.
    approved = [e["job_id"] for e in current["events"] if e["action"] == "approved"]
    assert len(approved) == 2 and queued in approved


def approved_lab(client):
    """A Finding with a complete bundle, ready for an Approval."""
    row = finding(client, application(client)["id"])
    assert upload(client, row["id"], bundle()).json()["artifact_state"]["status"] == "complete"
    return row


def lab_records(app):
    from numen.models import Action, Job, JobEvent, LabRun

    with app.state.factory() as db:
        return {
            "jobs": [j.input for j in db.scalars(select(Job).where(Job.kind == "lab_run"))],
            "labs": db.scalars(select(LabRun)).all(),
            "actions": [a.data for a in db.scalars(select(Action))],
            "events": [e.data for e in db.scalars(select(JobEvent))],
        }


def test_an_approval_checks_the_password_on_every_request(system, caplog):
    caplog.set_level(logging.DEBUG)
    app, client, _ = system
    row = approved_lab(client)
    path = f"/api/findings/{row['id']}/lab-runs"
    good = client.post(path, json=APPROVAL)
    assert good.status_code == 202, good.text
    job_id = good.json()["job_id"]
    revision = client.get(f"/api/findings/{row['id']}").json()["artifact_revision"]
    records = lab_records(app)
    assert len(records["labs"]) == 1 and records["labs"][0].job_id == job_id
    assert [a for a in records["actions"] if a["action"] == "approved"] == [
        {"action": "approved", "approved": "lab_run", "job_id": job_id, "artifact_revision": revision}
    ]
    # Each request is checked on its own: no window opens after a good Approval.
    for kwargs in ({"json": {"password": "wrong-password"}}, {}, {"json": {}}):
        refused = client.post(path, **kwargs)
        assert refused.status_code == 403 and refused.json()["code"] == "approval_refused", kwargs
    after = lab_records(app)
    assert len(after["jobs"]) == 1 and len(after["labs"]) == 1
    forged = client.post(path, json=APPROVAL, headers={"X-CSRF-Token": ""})
    assert forged.status_code == 403 and forged.json()["code"] == "csrf_required"
    again = client.post(path, json=APPROVAL)
    assert again.status_code == 202 and again.json()["job_id"] != job_id
    records = lab_records(app)
    assert len(records["labs"]) == 2
    stored = json.dumps([records["jobs"], records["actions"], records["events"]], default=str)
    assert APPROVAL["password"] not in stored
    assert APPROVAL["password"] not in caplog.text


def test_approvals_are_rate_limited_like_login(system):
    app, client, _ = system
    row = approved_lab(client)
    path = f"/api/findings/{row['id']}/lab-runs"
    for _ in range(10):
        assert client.post(path, json={"password": "wrong-password"}).status_code == 403
    limited = client.post(path, json=APPROVAL)
    assert limited.status_code == 429 and limited.json()["code"] == "approval_rate_limited"
    assert lab_records(app)["labs"] == []
    login = client.post("/api/auth/login", json={"username": "admin", "password": "test-password-long"})
    assert login.status_code == 200


def test_a_lab_job_is_never_retried_without_a_new_approval(system):
    app, client, config = system
    row = approved_lab(client)
    queued = client.post(f"/api/findings/{row['id']}/lab-runs", json=APPROVAL).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker({"status": "unobserved"}))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "failed"
    retried = client.post(f"/api/jobs/{queued}/retry", json=APPROVAL)
    assert retried.status_code == 409 and retried.json()["code"] == "approval_required"
    records = lab_records(app)
    assert len(records["jobs"]) == 1 and len(records["labs"]) == 1


def test_a_malicious_change_never_gets_a_lab(system):
    """ADR-0004 rule 6 and AC-A07: a Malicious change never runs, even with a complete bundle."""
    from numen import domain
    from numen.models import Application, Commit, Finding, Repository

    app, client, config = system
    row = approved_lab(client)
    path = f"/api/findings/{row['id']}/lab-runs"
    queued = client.post(path, json=APPROVAL).json()["job_id"]
    # A later Analysis finds the source commit is a Malicious change: the queued Lab never runs.
    with app.state.factory.begin() as db:
        commit = Commit(repository_id=db.scalar(select(Repository.id)), source_generation=1,
                        revision="a" * 40, verdict="Malicious change")
        db.add(commit)
        db.flush()
        current = db.get(Finding, row["id"])
        current.data = {**current.data, "source_commit_id": commit.id}
    broker = FixtureBroker({"verified": True, "status": "verified"})
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert broker.calls == [] and (job["status"], job["error"]["code"]) == ("failed", "lab_not_allowed")
    refused = client.post(path, json=APPROVAL)
    assert refused.status_code == 409 and refused.json()["code"] == "lab_not_allowed"
    # A Finding that a Malicious change Verdict opened is refused too, whatever its source.
    with app.state.factory.begin() as db:
        page, _ = domain.open_finding(db, db.get(Application, row["application_id"]), "served_content", "change-1",
                                      "Injected loader", "https://example.com/",
                                      {"by": "verdict", "verdict": "Malicious change", "confidence": "high"})
        page_id = page.id
    assert upload(client, page_id, bundle()).json()["artifact_state"]["status"] == "complete"
    refused = client.post(f"/api/findings/{page_id}/lab-runs", json=APPROVAL)
    assert refused.status_code == 409 and refused.json()["code"] == "lab_not_allowed"
    assert len(lab_records(app)["labs"]) == 1


def test_paths_archives_and_configured_secrets_rejected(system):
    app, client, _ = system
    connection(app)
    p = application(client)
    row = finding(client, p["id"])
    assert upload(client, row["id"], {"../escape.py": b"unsafe"}).status_code == 422
    assert (
        upload(client, row["id"], {"report.md": b"fixture-key-no-real-access"}).status_code == 422
    )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../../escape.py", b"bad")
    response = upload(client, row["id"], {"unsafe.zip": stream.getvalue()})
    assert response.status_code == 422
    assert client.get(f"/api/findings/{row['id']}").json()["artifacts"] == []


def test_webhook_failure_retry_retains_its_identity(system, monkeypatch):
    app, client, config = system
    assert (
        client.patch(
            "/api/settings",
            json={
                "webhook_enabled": True,
                "webhook_url": "http://fixture.local/api/webhooks/1/secret",
                "dashboard_url": "http://localhost:8080",
            },
        ).status_code
        == 200
    )
    import httpx

    sent = []
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: sent.append(kwargs["json"]) or httpx.Response(401))
    queued = client.post("/api/settings/webhook/test").json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker())
    # The test button uses the one Alert template.
    assert sent == [{"content": "Asset Monitor: Webhook test\nhttp://localhost:8080/", "allowed_mentions": {"parse": []}}]
    note = client.get("/api/notifications").json()["items"][0]
    assert note["status"] == "failed" and note["error"]["code"] == "webhook_http_error"
    assert client.get(f"/api/jobs/{queued}").json()["result"]["status"] == "failed"
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(200, json={"id": "discord-fixture-id"}),
    )
    client.post(f"/api/notifications/{note['id']}/retry")
    run_once(config, app.state.factory, FixtureBroker())
    delivered = client.get("/api/notifications").json()["items"][0]
    assert delivered["id"] == note["id"] and delivered["event_key"] == note["event_key"]
    assert delivered["status"] == "delivered" and delivered["attempts"] == 2
    assert "secret" not in json.dumps(client.get("/api/settings").json())


def test_inherited_interval_tracks_global_and_explicit_stays(system):
    _, client, _ = system
    inherited = application(client, monitor_interval_seconds=None)
    explicit = application(client, asset_name="Explicit", monitor_interval_seconds=3 * 3600)
    assert inherited["config"]["monitor_interval_inherited"] is True
    assert inherited["monitor_interval_seconds"] == 2 * 86400
    client.patch("/api/settings", json={"monitor_interval_seconds": 900})
    assert client.get(f"/api/applications/{inherited['id']}").json()["monitor_interval_seconds"] == 900
    assert client.get(f"/api/applications/{explicit['id']}").json()["monitor_interval_seconds"] == 3 * 3600
    changed = client.patch(f"/api/applications/{explicit['id']}", json={"monitor_interval_seconds": None})
    assert (
        changed.status_code == 200
        and changed.json()["config"]["monitor_interval_inherited"] is True
        and changed.json()["monitor_interval_seconds"] == 900
    )


LAB_BASES = [
    ("asset-monitor-lab:0.1.0", True),
    ("scratch", True),
    # The Engine would pull a digest base outside the offline build, and keep it after the run.
    ("python@sha256:" + "a" * 64, False),
    ("docker.io/library/php@sha256:" + "b" * 64, False),
    ("node:24.9.0-bookworm-slim@sha256:" + "d" * 64, False),
    ("python:3.12", False),
    ("mysql:latest", False),
]


@pytest.mark.parametrize("base,accepted", LAB_BASES)
def test_completeness_accepts_exactly_the_bases_the_lab_verifier_builds(base, accepted):
    from numen.artifacts import completeness

    files = {**bundle(), "vulnerable-app/Dockerfile": f"FROM {base}\nCOPY fixture /fixture\n".encode()}
    state = completeness(files)
    assert (state["status"] == "complete") is accepted, state["limitations"]


@pytest.mark.parametrize(
    "line,refused",
    [
        ("RUN composer install", False),
        ("ADD https://example.com/x /x", True),  # the Lab builds offline
        ("COPY --from=node@sha256:" + "a" * 64 + " /x /x", True),
        ("HEALTHCHECK CMD true", False),
        ("RUN --mount=type=secret,id=k cat /run/secrets/k", True),
        ('ENV OPTS="--mount=nothing"', False),
        ("COPY /etc/passwd /app/", True),
        ("ENV A=b", False),
        ("EXPOSE 8080", False),
    ],
)
def test_completeness_refuses_directives_the_lab_verifier_rejects(line, refused):
    from numen.artifacts import completeness

    files = {
        **bundle(),
        "vulnerable-app/Dockerfile": f"FROM asset-monitor-lab:0.1.0\n{line}\nCOPY fixture /fixture\n".encode(),
    }
    state = completeness(files)
    assert (state["status"] != "complete") is refused, state["limitations"]


def test_completeness_accepts_a_whole_application_sized_bundle():
    """A real vulnerable application is tens of thousands of files; that is not a defect."""
    from numen.artifacts import completeness

    padded = {**bundle(), **{f"vulnerable-app/app/src/File{i}.php": b"<?php\n" for i in range(20000)}}
    assert completeness(padded)["status"] == "complete"


@pytest.mark.parametrize(
    "dockerfile,complete",
    [
        (b"FROM asset-monitor-lab:0.1.0\nCOPY fixture /fixture\n", True),
        (b"# comment\n\tFROM asset-monitor-lab:0.1.0\r\nCOPY fixture /fixture\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY . /app/\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY *.py /app/\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY vendor/ /app/vendor/\n", False),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY .fixture /app/.fixture\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY fixture /f\nENTRYPOINT [\"sh\", \"/f\"]\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nRUN composer install --no-dev\nCOPY fixture /f\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nENV A=1 \\\n  B=2\nCOPY fixture /f\n", True),
        (b"FROM --platform=linux/amd64 asset-monitor-lab:0.1.0\nCOPY fixture /f\n", False),
        (b"FROM asset-monitor-lab:0.1.0\nUSER www-data\nCOPY fixture /f\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nCOPY --from=build /x /y\n", False),
        # The Engine drops a comment before joining continuations, so this FROM is its own.
        (b"FROM asset-monitor-lab:0.1.0\n# note \\\nFROM attacker.example/x:1\nCOPY fixture /f\n", False),
        (b"FROM asset-monitor-lab:0.1.0\nRUN echo \\\n  # skipped\n  done\nCOPY fixture /f\n", True),
        (b"FROM asset-monitor-lab:0.1.0\nARG U=https://example.com/x\nADD $U /x\nCOPY fixture /f\n", False),
        (b"# escape=`\nFROM asset-monitor-lab:0.1.0\nCOPY fixture /f\n", False),
    ],
)
def test_completeness_reads_the_dockerfile_shapes_the_verifier_will_see(dockerfile, complete):
    from numen.artifacts import completeness

    files = {**bundle(), "vulnerable-app/.fixture": b"dotfile", "vulnerable-app/Dockerfile": dockerfile}
    state = completeness(files)
    assert (state["status"] == "complete") is complete, state["limitations"]
    assert len(state["limitations"]) <= 20 and all(len(item) < 200 for item in state["limitations"])


def test_completeness_requires_the_lock_keys_at_its_top_level():
    """A live run published a lock whose version and source_ref sat under a nested object."""
    from numen.artifacts import completeness

    nested = json.dumps(
        {"upstream_application": {"version": "9.5.3", "source_ref": "9379c29cb26a1054208b37507b6869811aa75a32"}}
    ).encode()
    state = completeness({**bundle(), "vulnerable-app/application.lock.json": nested})
    assert state["status"] == "draft"
    assert any("vulnerable version" in item for item in state["limitations"])
    flat = json.dumps(
        {"version": "9.5.3", "source_ref": "9379c29cb26a1054208b37507b6869811aa75a32", "images": []}
    ).encode()
    assert completeness({**bundle(), "vulnerable-app/application.lock.json": flat})["status"] == "complete"


def test_completeness_requires_lock_images_to_be_the_bundled_lab_base():
    from numen.artifacts import completeness

    def locked(images):
        lock = {"version": "1.0.0", "local_inputs": {"fixture": "local bytes"}, "images": images}
        return completeness({**bundle(), "vulnerable-app/application.lock.json": json.dumps(lock).encode()})

    assert locked(["asset-monitor-lab:0.1.0"])["status"] == "complete"
    assert locked(["node@sha256:" + "a" * 64])["status"] == "draft"
