from datetime import timedelta

import pytest
from sqlalchemy import select

from conftest import FixtureBroker, program
from numen import artifacts
from numen.models import Artifact, Finding, Job, LabRun, now
from numen.worker import run_once
from test_artifacts import bundle, finding, queue_cve_analysis, upload


def track_reads(monkeypatch):
    reads = []
    original = artifacts.read_file

    def read(root, row):
        reads.append(row.path)
        return original(root, row)

    monkeypatch.setattr(artifacts, "read_file", read)
    return reads


def test_summary_is_scoped_paginated_and_loads_no_published_artifact_bytes(system, monkeypatch):
    app, client, _ = system
    p = program(client)
    older = finding(client, p["id"])
    upload(client, older["id"], bundle())
    newer = finding(client, p["id"])
    other = finding(client, program(client, asset_name="Other asset")["id"])
    with app.state.factory.begin() as db:
        row = db.get(Finding, older["id"])
        row.created_at = now() - timedelta(days=1)
        row.data = {**row.data, "fixed_versions": [{"product": "Example CMS", "version": "2.0.0"}]}
        job = Job(kind="lab_run", program_id=p["id"], input_hash="lab", input={})
        db.add(job)
        db.flush()
        for status, age in (("failed", 2), ("verified", 1)):
            db.add(
                LabRun(
                    finding_id=row.id,
                    artifact_revision=row.artifact_revision,
                    job_id=job.id,
                    status=status,
                    created_at=now() - timedelta(hours=age),
                )
            )
    reads = track_reads(monkeypatch)
    endpoint = f"/api/findings?view=summary&program_id={p['id']}&limit=1"
    first = client.get(endpoint)
    assert first.status_code == 200
    page = first.json()
    assert [row["id"] for row in page["items"]] == [newer["id"]]
    assert page["next_cursor"] == "1"
    second = client.get(endpoint + "&cursor=1")
    assert second.status_code == 200
    row = second.json()["items"][0]
    assert row["id"] == older["id"] != other["id"]
    assert row["artifact_state"]["status"] == "complete"
    assert row["lab_status"] == "verified"
    assert row["fixed_versions"] == [{"product": "Example CMS", "version": "2.0.0"}]
    assert not {"artifacts", "lab_runs", "events", "evidence", "_artifact_state"} & row.keys()
    assert second.json()["next_cursor"] is None
    assert reads == []
    assert len(second.content) < 2000
    full = client.get(endpoint.replace("view=summary", "view=full") + "&cursor=1").json()["items"][
        0
    ]
    assert full["artifacts"] and full["lab_runs"][0]["status"] == "verified"
    assert "events" in full and "evidence" in full and "_artifact_state" not in full
    assert client.get("/api/findings?view=invalid").status_code == 422
    client.post("/api/auth/logout")
    assert client.get(endpoint).status_code == 401


@pytest.mark.parametrize(
    "cached_revision, defect",
    [
        (None, None),
        ("previous-revision", None),
        ("previous-revision", "empty_poc"),
        ("previous-revision", "missing_input"),
        ("previous-revision", "invalid_lock"),
        ("previous-revision", "unpinned"),
    ],
)
def test_legacy_and_new_revisions_compute_completeness_without_reading_application_tree(
    system, monkeypatch, cached_revision, defect
):
    app, client, config = system
    row = finding(client, program(client)["id"])
    files = bundle()
    if defect == "empty_poc":
        files["poc.py"] = b""
    elif defect == "missing_input":
        files.pop("vulnerable-app/fixture")
    elif defect == "invalid_lock":
        files["vulnerable-app/application.lock.json"] = b"not JSON"
    elif defect == "unpinned":
        files["vulnerable-app/Dockerfile"] = b"FROM python:latest\n"
    # Legacy publishers have no summary. A cache for a previous revision must also be ignored.
    with app.state.factory.begin() as db:
        current = db.get(Finding, row["id"])
        revision, _ = artifacts.publish(db, config.artifact_root, "finding", current.id, files)
        current.artifact_revision = revision
        if cached_revision:
            current.data = {
                **current.data,
                "_artifact_state": {
                    "revision": cached_revision,
                    "state": artifacts.completeness(bundle()),
                },
            }
    reads = track_reads(monkeypatch)
    response = client.get(f"/api/findings?view=summary&program_id={row['program_id']}")
    assert response.status_code == 200
    assert response.json()["items"][0]["artifact_state"] == artifacts.completeness(files)
    assert sorted(reads) == ["vulnerable-app/Dockerfile", "vulnerable-app/application.lock.json"]


def test_cached_summary_preserves_edits_and_integrity_is_checked_on_use(system, monkeypatch):
    app, client, config = system
    row = finding(client, program(client)["id"])
    uploaded = upload(client, row["id"], bundle()).json()
    with app.state.factory() as db:
        entry = db.scalar(
            select(Artifact).where(
                Artifact.resource_id == row["id"],
                Artifact.revision == uploaded["artifact_revision"],
                Artifact.path == "vulnerable-app/fixture",
            )
        )
        (config.artifact_root / entry.storage_path).write_bytes(b"tampered")
        artifact_id = entry.id
    reads = track_reads(monkeypatch)
    updated = client.patch(f"/api/findings/{row['id']}", json={"status": "fixed"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "fixed"
    assert updated.json()["artifact_state"]["status"] == "complete"
    assert updated.json()["artifacts"] and "events" in updated.json()
    assert "_artifact_state" not in updated.json()
    assert reads == []
    assert (
        client.patch(f"/api/findings/{row['id']}", json={"_artifact_state": {}}).status_code == 422
    )
    for endpoint, method in (
        (f"/api/findings/{row['id']}/download", client.get),
        (f"/api/findings/{row['id']}/lab-runs", client.post),
        (f"/api/artifacts/{artifact_id}/content", client.get),
    ):
        response = method(endpoint)
        assert response.status_code == 409
        assert response.json()["code"] == "artifact_corrupt"


def test_generated_bundle_summary_requires_no_artifact_reads(system, monkeypatch):
    app, client, config = system
    p, job_id, result = queue_cve_analysis(system)
    run_once(config, app.state.factory, FixtureBroker(result, bundle()))
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    reads = track_reads(monkeypatch)
    response = client.get(f"/api/findings?view=summary&program_id={p['id']}")
    assert response.status_code == 200
    assert response.json()["items"][0]["artifact_state"]["status"] == "complete"
    assert reads == []


def test_publication_preserves_operator_changes_made_after_the_finding_was_loaded(
    system, monkeypatch
):
    app, client, _ = system
    row = finding(client, program(client)["id"])
    original = artifacts.publish

    def publish(db, root, resource_type, resource_id, files, *args, **kwargs):
        with app.state.factory.begin() as operator:
            current = operator.get(Finding, resource_id)
            current.status = "fixed"
            current.data = {**current.data, "evidence": ["Operator note during publication"]}
        return original(db, root, resource_type, resource_id, files, *args, **kwargs)

    monkeypatch.setattr(artifacts, "publish", publish)
    response = upload(client, row["id"], bundle())
    assert response.status_code == 200
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["status"] == "fixed"
    assert current["evidence"] == ["Operator note during publication"]
    assert current["artifact_state"]["status"] == "complete"
