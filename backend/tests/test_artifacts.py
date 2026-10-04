import io
import json
import zipfile

from conftest import FixtureBroker, connection, program
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
