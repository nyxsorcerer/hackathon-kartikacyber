import io
import json
import zipfile

import pytest

from conftest import FixtureBroker, connection, program, source_snapshot
from test_workflows import cve_raw, seed_cve
from numen.worker import run_once


def bundle(version="1.0.0"):
    return {
        "poc.py": b"print('proof')",
        "report.md": b"# Report\nFixture vulnerable behavior",
        "vulnerable-app/Dockerfile": b"FROM scratch\nCOPY fixture /fixture\n",
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
            "program_id": ident,
            "kind": "0day",
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
    p = program(
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
    job = client.post(f"/api/programs/{p['id']}/cves/{cve['id']}/analyses", json=body or {})
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
    assert row["kind"] == "cve" and row["cve_id"] == result["cve_id"]
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
    original_report = next(a for a in analyses[0]["artifacts"] if a["path"] == "report.md")
    client.patch(f"/api/findings/{row['id']}", json={"status": "fixed", "title": "Reviewed title"})
    again = client.post(
        f"/api/programs/{p['id']}/cves/{result['cve_id']}/analyses", json={}
    ).json()["job_id"]
    run_once(
        config,
        app.state.factory,
        FixtureBroker(result, {**bundle(), "report.md": b"# Updated report"}),
    )
    assert client.get(f"/api/jobs/{again}").json()["result"]["finding_id"] == row["id"]
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["status"] == "fixed" and current["title"] == "Reviewed title"
    assert (
        client.get(f"/api/artifacts/{original_report['id']}/content").content
        == bundle()["report.md"]
    )
    assert len(client.get("/api/findings").json()["items"]) == 1


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
    assert events[-1]["partial_output_retained"] is True
    assert client.post(f"/api/findings/{row['id']}/lab-runs").status_code == 422


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


def test_cve_analysis_requests_a_build_run_and_other_operations_do_not(system):
    app, client, config = system
    _, _, result = queue_cve_analysis(system)
    broker = FixtureBroker(result, bundle())
    run_once(config, app.state.factory, broker)
    submitted = broker.calls[0]
    assert submitted["build"] is True and submitted["limits"] is None  # Broker defaults raise the ceiling.
    assert "private Docker daemon" in submitted["prompt"]
    generation = client.post(
        f"/api/findings/{client.get('/api/findings').json()['items'][0]['id']}/artifact-generations",
        json={},
    ).json()["job_id"]
    second = FixtureBroker({"summary": "Partial"}, {"report.md": b"# Partial"})
    run_once(config, app.state.factory, second)
    assert second.calls[0]["build"] is False
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
    run_once(config, app.state.factory, broker)
    inputs = broker.calls[0]["files"]
    assert json.loads(inputs["analysis.json"])["result"]["cve_id"] == result["cve_id"]
    assert inputs["analysis-report.md"] == bundle()["report.md"]
    assert json.loads(inputs["cve.json"])["id"] == result["cve_id"]
    job = client.get(f"/api/jobs/{generation}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "incomplete_bundle"
    assert job["result"]["finding_id"] == completed["finding_id"]
    assert job["result"]["artifact_state"]["missing"]


def test_bundle_draft_completion_immutable_revision_and_lab_failure(system):
    app, client, config = system
    p = program(client)
    row = finding(client, p["id"])
    assert row["status"] == "open" and row["artifact_state"]["status"] == "draft"
    assert client.post(f"/api/findings/{row['id']}/lab-runs").status_code == 422
    first = upload(client, row["id"], {"poc.py": b"first proof"}).json()
    first_artifact = next(a for a in first["artifacts"] if a["path"] == "poc.py")
    complete = upload(client, row["id"], bundle()).json()
    assert complete["artifact_state"]["status"] == "complete", complete
    assert complete["status"] == "open" and complete["target_applicability"] == "affected"
    assert client.get(f"/api/artifacts/{first_artifact['id']}/content").content == b"first proof"
    downloaded = client.get(f"/api/findings/{row['id']}/download")
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        assert {"poc.py", "report.md", "vulnerable-app/Dockerfile", "manifest.json"}.issubset(
            archive.namelist()
        )
        assert archive.read("poc.py") == bundle()["poc.py"]
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["revision"] == complete["artifact_revision"]
        assert all(a["sha256"] and a["size"] > 0 for a in manifest["files"])
    queued = client.post(
        f"/api/findings/{row['id']}/lab-runs", headers={"Idempotency-Key": "lab-once"}
    ).json()["job_id"]
    same = client.post(
        f"/api/findings/{row['id']}/lab-runs", headers={"Idempotency-Key": "lab-once"}
    ).json()["job_id"]
    assert queued == same
    broker = FixtureBroker(
        {
            "verified": False,
            "status": "not_reproduced",
            "exit_code": 1,
            "log": "Expected proof absent",
            "pinned_image": "fixture-sha",
        }
    )
    run_once(config, app.state.factory, broker)
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["lab_runs"][0]["status"] == "not_reproduced"
    assert current["lab_runs"][0]["artifact_revision"] == complete["artifact_revision"]
    assert current["lab_runs"][0]["vulnerable_version"] == "1.0.0"
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"


def test_paths_archives_and_configured_secrets_rejected(system):
    app, client, _ = system
    connection(app)
    p = program(client)
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


def test_webhook_failure_retry_retains_candidate_identity(system, monkeypatch):
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

    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: httpx.Response(401))
    queued = client.post("/api/settings/webhook/test").json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker())
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
    inherited = program(client, monitor_interval_days=None)
    explicit = program(client, asset_name="Explicit", monitor_interval_days=3)
    assert inherited["config"]["monitor_interval_inherited"] is True
    client.patch("/api/settings", json={"monitor_interval_days": 5})
    assert client.get(f"/api/programs/{inherited['id']}").json()["monitor_interval_days"] == 5
    assert client.get(f"/api/programs/{explicit['id']}").json()["monitor_interval_days"] == 3
    changed = client.patch(f"/api/programs/{explicit['id']}", json={"monitor_interval_days": None})
    assert (
        changed.status_code == 200
        and changed.json()["config"]["monitor_interval_inherited"] is True
    )
