import base64
import hashlib
import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from conftest import FixtureBroker, application, connection, source_snapshot
from numen import artifacts, domain
from numen.security import DomainError
from numen.models import (
    Application, ApplicationCVE, ApplicationRepository, Artifact, Commit, Finding, Job, LabRun, Notification,
    Repository, now,
)
from numen.sources import Sources
from numen.worker import run_once
from test_analysis import CAPS, analyze, started
from test_artifacts import APPROVAL, automatic_bundle, bundle, finding, queue_cve_analysis, upload, without_package
from test_dependencies import npm_files
from test_exposure import PACKAGE, REACT, SERVER, react
from test_remediation_prs import HEAD, SHOP, tree
from test_commit_review import assessment, pinned_bundle, prepared
from test_workflows import cve_raw, seed_cve


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
    p = application(client)
    older = finding(client, p["id"])
    upload(client, older["id"], bundle())
    newer = finding(client, p["id"])
    other = finding(client, application(client, asset_name="Other asset")["id"])
    with app.state.factory.begin() as db:
        row = db.get(Finding, older["id"])
        row.created_at = now() - timedelta(days=1)
        row.data = {**row.data, "fixed_versions": [{"product": "Example CMS", "version": "2.0.0"}]}
        job = Job(kind="lab_run", application_id=p["id"], input_hash="lab", input={})
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
    endpoint = f"/api/findings?view=summary&application_id={p['id']}&limit=1"
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
    row = finding(client, application(client)["id"])
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
    response = client.get(f"/api/findings?view=summary&application_id={row['application_id']}")
    assert response.status_code == 200
    assert response.json()["items"][0]["artifact_state"] == artifacts.completeness(files)
    assert sorted(reads) == ["vulnerable-app/Dockerfile", "vulnerable-app/application.lock.json"]


def test_cached_summary_preserves_edits_and_integrity_is_checked_on_use(system, monkeypatch):
    app, client, config = system
    row = finding(client, application(client)["id"])
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
    updated = transition(client, row["id"], "confirmed")
    assert updated.status_code == 200
    assert updated.json()["status"] == "confirmed"
    assert updated.json()["artifact_state"]["status"] == "complete"
    assert updated.json()["artifacts"] and "events" in updated.json()
    assert "_artifact_state" not in updated.json()
    assert reads == []
    assert (
        client.patch(f"/api/findings/{row['id']}", json={"_artifact_state": {}}).status_code == 422
    )
    for endpoint, method in (
        (f"/api/findings/{row['id']}/download", client.get),
        (f"/api/findings/{row['id']}/lab-runs", lambda path: client.post(path, json=APPROVAL)),
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
    response = client.get(f"/api/findings?view=summary&application_id={p['id']}")
    assert response.status_code == 200
    assert response.json()["items"][0]["artifact_state"]["status"] == "complete"
    assert reads == []


def test_the_summary_carries_malicious_change(system):
    """A Malicious change never runs, so its list row needs no Lab badge (ADR-0004)."""
    _, client, _ = system
    monitored, ident, _ = prepared(system)
    rule = b'rule loader { strings: $a = "str(value)" condition: $a }'
    job, _ = analyze(system, ident, assessment("Malicious change"), {"report.md": b"# A loader", "detection-rule.yar": rule})
    other = finding(client, monitored["id"])
    rows = client.get("/api/findings?view=summary").json()["items"]
    assert {row["id"]: row["malicious_change"] for row in rows} == {job["result"]["finding_id"]: True, other["id"]: False}


def test_publication_preserves_operator_changes_made_after_the_finding_was_loaded(
    system, monkeypatch
):
    app, client, _ = system
    row = finding(client, application(client)["id"])
    original = artifacts.publish

    def publish(db, root, resource_type, resource_id, files, *args, **kwargs):
        with app.state.factory.begin() as operator:
            current = operator.get(Finding, resource_id)
            current.status = "remediated"
            current.data = {**current.data, "evidence": ["Operator note during publication"]}
        return original(db, root, resource_type, resource_id, files, *args, **kwargs)

    monkeypatch.setattr(artifacts, "publish", publish)
    response = upload(client, row["id"], bundle())
    assert response.status_code == 200
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["status"] == "remediated"
    assert current["evidence"] == ["Operator note during publication"]
    assert current["artifact_state"]["status"] == "complete"


def transition(client, ident, state, reason="Checked by the Operator", **kwargs):
    return client.post(
        f"/api/findings/{ident}/transitions", json={"state": state, "reason": reason}, **kwargs
    )


def test_operator_confirms_dismisses_and_remediates_with_a_reason(system):
    _, client, _ = system
    p = application(client)
    row = finding(client, p["id"])
    assert (row["source"], row["status"], row["cause"]["by"]) == ("commit", "open", "operator")
    # The Deployed version is shown apart from the lifecycle; Phase 7 fills it in.
    assert row["deployed_version"] == "unknown"
    summary = client.get(f"/api/findings?view=summary&application_id={p['id']}").json()["items"][0]
    assert (summary["source"], summary["deployed_version"]) == ("commit", "unknown")
    confirmed = transition(client, row["id"], "confirmed", "  Reproduced by hand  ")
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "confirmed"
    cause = confirmed.json()["cause"]
    assert (cause["by"], cause["reason"]) == ("operator", "Reproduced by hand") and cause["at"]
    refused = transition(client, row["id"], "dismissed")
    assert refused.status_code == 409 and refused.json()["code"] == "invalid_transition"
    assert refused.json()["message"] == "A confirmed Finding cannot be dismissed"
    remediated = transition(client, row["id"], "remediated", "Upgraded to 2.0.0").json()
    assert remediated["status"] == "remediated" and remediated["cause"]["reason"] == "Upgraded to 2.0.0"
    moves = [(e["from"], e["to"], e["cause"]) for e in remediated["events"] if e["action"] == "transition"]
    assert moves == [("open", "confirmed", cause), ("confirmed", "remediated", remediated["cause"])]
    assert transition(client, row["id"], "confirmed").json()["code"] == "invalid_transition"
    dismissed = finding(client, p["id"])
    assert transition(client, dismissed["id"], "dismissed").json()["status"] == "dismissed"
    for state in ("confirmed", "remediated"):
        again = transition(client, dismissed["id"], state)
        assert again.status_code == 409 and again.json()["code"] == "invalid_transition"
    other = finding(client, p["id"])
    assert transition(client, other["id"], "confirmed", "   ").status_code == 422
    assert transition(client, other["id"], "confirmed", "x" * 2001).status_code == 422
    forged = transition(client, other["id"], "confirmed", headers={"X-CSRF-Token": ""})
    assert forged.status_code == 403 and forged.json()["code"] == "csrf_required"
    assert client.get(f"/api/findings/{other['id']}").json()["status"] == "open"


@pytest.mark.parametrize(
    "by, ref",
    [
        ("remediation_pr", {"pull_request": "https://github.com/acme/shop/pull/7"}),
        ("version_bump", {"version": "2.0.1", "revision": "c" * 40}),
        ("baseline_match", {"check_id": "check-1"}),
        ("deployed_version", {"version": "2.0.1"}),
        ("operator", {"reason": "Patched on the server"}),
    ],
)
def test_a_remediated_finding_records_what_remediated_it(system, by, ref):
    app, client, _ = system
    row = finding(client, application(client)["id"])
    with app.state.factory.begin() as db:
        assert domain.transition_finding(db, db.get(Finding, row["id"]), "remediated", {"by": by, **ref})
    current = client.get(f"/api/findings/{row['id']}").json()
    assert current["status"] == "remediated"
    assert {k: v for k, v in current["cause"].items() if k != "at"} == {"by": by, **ref}
    history = current["events"][-1]
    assert (history["action"], history["from"], history["to"], history["cause"]) == (
        "transition", "open", "remediated", current["cause"])


@pytest.mark.parametrize("by", ["proof", "detection_rule", "advisory"])
def test_internal_confirmations_apply_only_to_open_findings(system, by):
    app, client, _ = system
    p = application(client)["id"]
    rows = {state: finding(client, p)["id"] for state in ("open", "dismissed", "remediated")}
    for state in ("dismissed", "remediated"):
        assert transition(client, rows[state], state).status_code == 200
    with app.state.factory.begin() as db:
        found = {state: db.get(Finding, ident) for state, ident in rows.items()}
        assert domain.transition_finding(db, found["open"], "confirmed", {"by": by, "ref": "r1"}) is True
        for state in ("dismissed", "remediated"):
            assert domain.transition_finding(db, found[state], "confirmed", {"by": by}) is False
        for state, cause in (("confirmed", "unknown"), ("dismissed", by), ("remediated", "proof")):
            with pytest.raises(ValueError):
                domain.transition_finding(db, found["open"], state, {"by": cause})
    confirmed = client.get(f"/api/findings/{rows['open']}").json()
    assert confirmed["status"] == "confirmed"
    assert (confirmed["cause"]["by"], confirmed["cause"]["ref"]) == (by, "r1")
    for state in ("dismissed", "remediated"):
        current = client.get(f"/api/findings/{rows[state]}").json()
        assert (current["status"], current["cause"]["by"]) == (state, "operator")
        assert [e["to"] for e in current["events"] if e["action"] == "transition"] == [state]


def test_draft_is_an_artifact_state_not_a_lifecycle_state(system):
    _, client, _ = system
    row = finding(client, application(client)["id"])
    drafted = upload(client, row["id"], {"report.md": b"# Drafted"}).json()
    assert drafted["status"] == "open" and drafted["artifact_state"]["status"] == "draft"
    assert transition(client, row["id"], "draft").status_code == 422
    for body in (
        {"status": "remediated"},
        {"status": "draft"},
        {"cause": {"by": "operator"}},
        {"source_ref": "deadbee"},
        {"_artifact_state": {}},
    ):
        assert client.patch(f"/api/findings/{row['id']}", json=body).status_code == 422, body
    moved = client.patch(f"/api/findings/{row['id']}", json={"source": "advisory"})
    assert moved.status_code == 422 and moved.json()["code"] == "immutable_source"
    edited = client.patch(f"/api/findings/{row['id']}", json={"title": "Reviewed title"}).json()
    assert (edited["title"], edited["status"], edited["source"]) == ("Reviewed title", "open", "commit")
    assert edited["cause"] == row["cause"] and edited["artifact_state"]["status"] == "draft"
    assert "_artifact_state" not in edited


# Opening Findings per affected Application and linking changes from 'addresses' (A11).
def analyzed(system, ident, verdict, ref="a" * 40, **extra):
    """The finished job of an Analysis of commit `ident` that returns `verdict`."""
    job, _ = analyze(system, ident, {**assessment(verdict, ref=ref), **extra}, pinned_bundle(ref))
    assert job["status"] == "succeeded", job
    return job


def shared(system, *names):
    """Applications named `names` that share demo/plugin, and a commit at a…a whose parent is f…f."""
    app, client, _ = system
    connection(app)
    apps = [application(client, asset_name=name) for name in names]
    return apps, parented(app, apps[0]["id"], "a" * 40, "f" * 40)


def parented(app, application_id, revision, parent, files=None):
    ident = source_snapshot(app, application_id, revision, files=files)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "parent_revisions": [parent]}
    return ident


def by_application(client):
    return {f["application_id"]: f for f in client.get("/api/findings").json()["items"]}


def test_a_shared_upstream_verdict_opens_a_finding_in_every_application_that_uses_it(system):
    _, client, _ = system
    (shop, blog, archived, off, removed), ident = shared(system, "Shop", "Blog", "Archive", "Off", "Removed")
    repository = shop["repositories"][0]["repository_id"]
    assert client.patch(f"/api/applications/{archived['id']}", json={"archived": True}).status_code == 200
    links = "/api/applications/{}/repositories/" + repository
    assert client.patch(links.format(off["id"]), json={"enabled": False}).status_code == 200
    assert client.delete(links.format(removed["id"])).status_code == 200
    job = analyzed(system, ident, "Vulnerability introduced")
    rows = by_application(client)
    assert set(rows) == {shop["id"], blog["id"]}
    for row in rows.values():
        assert (row["source"], row["status"], row["source_ref"]) == ("commit", "open", "aaaaaaa")
        assert (row["cause"]["by"], row["cause"]["verdict"]) == ("verdict", "Vulnerability introduced")
        assert row["source_commit_id"] == ident and row["artifact_state"]["status"] == "complete"
        assert row["events"][0]["action"] == "opened" and row["events"][0]["source_ref"] == "aaaaaaa"
    assert rows[shop["id"]]["artifact_revision"] != rows[blog["id"]]["artifact_revision"]
    assert job["result"]["finding_id"] == rows[shop["id"]]["id"]
    assert sorted(job["result"]["finding_ids"]) == sorted(row["id"] for row in rows.values())
    listed = client.get(f"/api/commits/{ident}").json()["findings"]
    assert sorted(listed, key=lambda item: item["application_name"]) == [
        {"id": rows[a["id"]]["id"], "title": assessment()["title"], "status": "open", "source": "commit",
         "application_id": a["id"], "application_name": a["asset_name"], "relation": "source"}
        for a in (blog, shop)
    ]


@pytest.mark.parametrize("verdict,ref", [
    ("Vulnerability fix", "f" * 40), ("Vulnerability introduced", "a" * 40), ("Malicious change", "a" * 40),
])
def test_an_own_repository_verdict_opens_a_finding(system, verdict, ref):
    app, client, _ = system
    connection(app)
    own = application(client, role="own", source_url="https://github.com/acme/shop")
    ident = parented(app, own["id"], "a" * 40, "f" * 40)
    job = analyzed(system, ident, verdict, ref)
    (row,) = client.get("/api/findings").json()["items"]
    assert (row["application_id"], row["source"], row["status"]) == (own["id"], "commit", "open")
    assert (row["cause"]["by"], row["cause"]["verdict"], row["cause"]["confidence"]) == ("verdict", verdict, "high")
    assert job["result"]["finding_id"] == row["id"] and job["result"]["finding_ids"] == [row["id"]]


def test_a_repeat_analysis_opens_no_duplicate_and_never_reopens_a_dismissed_finding(system):
    _, client, _ = system
    _, ident, _ = prepared(system)
    first = analyzed(system, ident, "Vulnerability introduced")
    finding_id = first["result"]["finding_id"]
    client.patch(f"/api/findings/{finding_id}", json={"target_applicability": "affected"})
    refreshed = analyzed(system, ident, "Vulnerability introduced")  # An Open Finding takes the new Analysis.
    current = client.get(f"/api/findings/{finding_id}").json()
    assert (current["source_analysis_id"], current["target_applicability"]) == (refreshed["result"]["analysis_id"], "affected")
    dismissed = transition(client, finding_id, "dismissed", "Not reachable from the Asset").json()
    count = len(client.get("/api/findings").json()["items"])
    for verdict in ("Vulnerability introduced", "Malicious change"):  # A different Verdict reuses it too.
        again = analyzed(system, ident, verdict)
        assert again["result"]["finding_id"] == finding_id
        current = client.get(f"/api/findings/{finding_id}").json()
        assert (current["status"], current["cause"]) == ("dismissed", dismissed["cause"])
        # A closed Finding keeps the evidence and bundle it was dismissed with.
        assert {k: current[k] for k in ("source_analysis_id", "artifact_revision", "target_applicability")} == {
            k: dismissed[k] for k in ("source_analysis_id", "artifact_revision", "target_applicability")}
        assert [e["action"] for e in current["events"]] == ["opened", "updated", "transition"]
        assert len(client.get("/api/findings").json()["items"]) == count == 1


def test_a_linked_fix_shows_both_changes_in_the_history_and_leaves_the_state_unchanged(system):
    app, client, _ = system
    monitored, x, _ = prepared(system)
    finding_id = analyzed(system, x, "Vulnerability introduced")["result"]["finding_id"]
    confirmed = transition(client, finding_id, "confirmed", "Reproduced by hand").json()
    y = parented(app, monitored["id"], "b" * 40, "a" * 40)
    fix = analyzed(system, y, "Vulnerability fix", "a" * 40, addresses=["a" * 7])
    assert (fix["result"]["finding_id"], fix["result"]["finding_ids"]) == (None, [])
    current = client.get(f"/api/findings/{finding_id}").json()
    assert (current["status"], current["cause"]) == ("confirmed", confirmed["cause"])
    history = [e for e in current["events"] if e["action"] in ("opened", "linked")]
    assert [(e["action"], e.get("commit_id") or e["cause"]["commit_id"]) for e in history] == [("opened", x), ("linked", y)]
    assert {k: history[1][k] for k in ("revision", "analysis_id", "verdict")} == {
        "revision": "b" * 40, "analysis_id": fix["result"]["analysis_id"], "verdict": "Vulnerability fix"}
    assert [f["id"] for f in client.get("/api/findings").json()["items"]] == [finding_id]
    (linked,) = client.get(f"/api/commits/{y}").json()["findings"]
    assert (linked["id"], linked["relation"], linked["status"]) == (finding_id, "linked", "confirmed")
    analyzed(system, y, "Vulnerability fix", "a" * 40, addresses=["a" * 7])
    events = client.get(f"/api/findings/{finding_id}").json()["events"]
    assert [e["action"] for e in events].count("linked") == 1
    assert len(client.get("/api/findings").json()["items"]) == 1


def test_links_map_addresses_only_within_each_application(system):
    app, client, _ = system
    (shop, blog), x = shared(system, "Shop", "Blog")
    analyzed(system, x, "Vulnerability introduced")
    found = by_application(client)
    transition(client, found[blog["id"]]["id"], "dismissed", "Blog does not load the plugin's templates")
    y = parented(app, shop["id"], "b" * 40, "a" * 40)
    fix = analyzed(system, y, "Vulnerability fix", "a" * 40, addresses=["a" * 7])
    # Each Application links the fix to its own X, Blog's Dismissed one too: it opens nothing new.
    for a, state in ((shop, "open"), (blog, "dismissed")):
        x_row = client.get(f"/api/findings/{found[a['id']]['id']}").json()
        assert [e["commit_id"] for e in x_row["events"] if e["action"] == "linked"] == [y] and x_row["status"] == state
    assert [f for f in client.get("/api/findings").json()["items"] if f.get("source_commit_id") == y] == []
    assert (fix["result"]["finding_id"], fix["result"]["finding_ids"]) == (None, [])
    with app.state.factory() as db:
        assert len(list(db.scalars(select(Notification)))) == 2  # X's opening Alerts only.
    # Advisory ids link only the same Application's cve and advisory Findings.
    other = application(client, asset_name="Other", source_url="https://github.com/demo/other")
    seed_cve(app, shop["id"], cve_raw())
    with app.state.factory.begin() as db:
        db.add(ApplicationCVE(application_id=other["id"], cve_id="CVE-2026-12345", confirmed=None, data={}))
    cve = {"source": "cve", "cve_id": "CVE-2026-12345", "title": "Template inclusion"}
    shop_cve, other_cve = (
        client.post("/api/findings", json={"application_id": a["id"], **cve}).json()["id"] for a in (shop, other))
    with app.state.factory.begin() as db:
        advisory, _ = domain.open_finding(db, db.get(Application, shop["id"]), "advisory", "GHSA-fv66-9v8q-g76r",
                                          "Template inclusion", "GHSA-fv66-9v8q-g76r",
                                          {"by": "advisory", "advisory_id": "GHSA-fv66-9v8q-g76r"})
        advisory_id = advisory.id
    z = parented(app, shop["id"], "c" * 40, "b" * 40)
    analyzed(system, z, "Vulnerability fix", "b" * 40, addresses=["CVE-2026-12345", "GHSA-fv66-9v8q-g76r"])

    def linked(ident):
        return [e["commit_id"] for e in client.get(f"/api/findings/{ident}").json()["events"] if e["action"] == "linked"]

    assert (linked(shop_cve), linked(advisory_id), linked(other_cve)) == ([z], [z], [])
    assert {f["relation"] for f in client.get(f"/api/commits/{z}").json()["findings"]} == {"linked", "source"}


def test_open_finding_takes_served_content_and_advisory_sources(system):
    app, client, _ = system
    shop, blog = application(client, asset_name="Shop"), application(client, asset_name="Blog")
    sources = {
        "served_content": ("change-1", "https://shop.example/",
                           {"by": "verdict", "verdict": "Malicious change", "confidence": "high"}),
        "advisory": ("GHSA-fv66-9v8q-g76r", "GHSA-fv66-9v8q-g76r",
                     {"by": "advisory", "advisory_id": "GHSA-fv66-9v8q-g76r"}),
    }
    with app.state.factory.begin() as db:
        for source, (subject, ref, cause) in sources.items():
            for ident in (shop["id"], blog["id"]):
                target = db.get(Application, ident)
                first, opened = domain.open_finding(db, target, source, subject, "Injected loader " + "x" * 400, ref, cause)
                again, reopened = domain.open_finding(db, target, source, subject, "Another title", ref, cause)
                assert (opened, reopened, again.id) == (True, False, first.id)
    rows = client.get("/api/findings").json()["items"]
    assert sorted((r["application_id"], r["source"]) for r in rows) == sorted(
        (a["id"], s) for a in (shop, blog) for s in sources)
    for row in rows:
        _, ref, cause = sources[row["source"]]
        assert (row["status"], row["source_ref"], len(row["title"])) == ("open", ref, 300)
        assert {k: v for k, v in row["cause"].items() if k != "at"} == cause and row["cause"]["at"]
        assert [(e["action"], e["source_ref"]) for e in row["events"]] == [("opened", ref)]


def test_a_second_applications_finding_accepts_the_shared_analysis(system):
    app, client, config = system
    (shop, blog), ident = shared(system, "Shop", "Blog")
    analyzed(system, ident, "Vulnerability introduced")
    found = by_application(client)[blog["id"]]
    assert found["source_analysis_id"] and found["source_commit_id"] == ident
    edited = client.patch(f"/api/findings/{found['id']}", json={"title": "Blog: template inclusion"})
    assert edited.status_code == 200, edited.text
    queued = client.post(f"/api/findings/{found['id']}/artifact-generations", json={})
    assert queued.status_code == 202, queued.text
    run_once(config, app.state.factory, FixtureBroker({"summary": "Regenerated for Blog"}, pinned_bundle("a" * 40)), exclude=("notification",))
    job = client.get(f"/api/jobs/{queued.json()['job_id']}").json()
    assert job["status"] == "succeeded", job
    assert job["result"]["finding_id"] == found["id"]


def test_editing_a_commit_findings_source_commit_updates_its_source_ref(system):
    app, client, _ = system
    monitored, _, _ = prepared(system)
    other = source_snapshot(app, monitored["id"], "b" * 40)
    row = client.post("/api/findings", json={"application_id": monitored["id"], "source": "commit", "title": "By hand"}).json()
    assert row["source_ref"] is None
    edited = client.patch(f"/api/findings/{row['id']}", json={"source_commit_id": other})
    assert edited.status_code == 200, edited.text
    assert edited.json()["source_ref"] == "bbbbbbb"
    assert client.patch(f"/api/findings/{row['id']}", json={"source_commit_id": None}).json()["source_ref"] is None


# An Own-repository Proof's vulnerable app is the Own repository at the Verdict's commit (A07).
OWN_SOURCE = {
    "package.json": b'{"name":"shop","version":"1.0.0","private":true}\n',
    "server.js": b'require("http").createServer((q,r)=>r.end(require("fs").readFileSync("."+q.url))).listen(8080);\n',
    "Dockerfile": b"FROM node:latest\n",  # The repository's own: the bundle's wins.
    ".dockerignore": b"node_modules\n",  # Its own Dockerfile's: it would drop the fetched deps.
}


def approved_commit_lab(system, role):
    """A Vulnerability introduced Finding from a commit of the Application's `role` repository,
    with its Lab approved: (Finding id, lab_run job id). An Own-repository Proof's bundle leaves
    package.json to the repository."""
    app, client, _ = system
    connection(app)
    shop = application(client, role=role, source_url="https://github.com/acme/shop")
    ident = parented(app, shop["id"], "a" * 40, "f" * 40, OWN_SOURCE)
    drafted = pinned_bundle("a" * 40)
    if role == "own":
        drafted.pop("vulnerable-app/package.json")
    job, broker = analyze(system, ident, assessment("Vulnerability introduced", "a" * 40), drafted)
    # The Analysis is told whether its Lab will supply the repository.
    facts = json.loads(broker.calls[0]["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert facts["own_repository"] is (role == "own")
    assert facts["vulnerable_app"] == ("own_commit" if role == "own" else "minimal")
    finding_id = job["result"]["finding_id"]
    queued = client.post(f"/api/findings/{finding_id}/lab-runs", json=APPROVAL)
    assert queued.status_code == 202, queued.text
    return finding_id, queued.json()["job_id"]


def run_lab(system, broker):
    app, _, config = system
    run_once(config, app.state.factory, broker, exclude=("notification",))  # Alerts stay queued.
    return broker


def test_an_approved_lab_builds_the_own_repository_at_the_verdicts_commit(system):
    _, client, _ = system
    finding_id, job_id = approved_commit_lab(system, "own")
    broker = run_lab(system, FixtureBroker({"verified": True, "status": "verified", "exit_code": 0}))
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    ((kind, files),) = [(call["kind"], call["files"]) for call in broker.calls]
    assert kind == "lab" and "manifest.json" in files
    assert "vulnerable-app/manifest.json" not in files and "vulnerable-app/.dockerignore" not in files
    for path in ("package.json", "server.js"):
        assert files["vulnerable-app/" + path] == OWN_SOURCE[path], path
    bundled = pinned_bundle("a" * 40)
    for path in ("vulnerable-app/Dockerfile", "vulnerable-app/application.lock.json", "poc.py"):
        assert files[path] == bundled[path], path
    current = client.get(f"/api/findings/{finding_id}").json()
    (lab,) = current["lab_runs"]
    assert (lab["status"], lab["source_ref"]) == ("verified", "a" * 40)
    assert current["status"] == "confirmed"
    assert {k: v for k, v in current["cause"].items() if k != "at"} == {"by": "proof", "lab_run_id": lab["id"]}


def test_an_upstream_proof_without_a_locked_package_keeps_the_bundle_only_lab(system):
    _, client, _ = system
    finding_id, _ = approved_commit_lab(system, "upstream")
    broker = run_lab(system, FixtureBroker({"verified": True, "status": "verified", "exit_code": 0}))
    (call,) = broker.calls
    assert set(call["files"]) == {*pinned_bundle(), "manifest.json"}
    (lab,) = client.get(f"/api/findings/{finding_id}").json()["lab_runs"]
    assert "source_ref" not in lab and "own_ref" not in lab
    assert lab["bundle_only"] == "The Upstream link names no package or Locked version to install"


def test_a_lab_that_does_not_reproduce_stays_visible_and_changes_no_state(system):
    _, client, _ = system
    finding_id, job_id = approved_commit_lab(system, "own")
    before = client.get(f"/api/findings/{finding_id}").json()
    run_lab(system, FixtureBroker({"verified": False, "status": "not_reproduced", "exit_code": 1, "log": "no traversal"}))
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    current = client.get(f"/api/findings/{finding_id}").json()
    (lab,) = current["lab_runs"]
    assert (lab["status"], lab["source_ref"], lab["log"]) == ("not_reproduced", "a" * 40, "no traversal")
    assert (current["status"], current["cause"]) == ("open", before["cause"])
    assert not [e for e in current["events"] if e["action"] == "transition"]


def test_a_lab_over_a_limit_fails_visibly_and_changes_no_state(system):
    _, client, _ = system
    finding_id, job_id = approved_commit_lab(system, "own")
    limit = {"code": "lab_image_too_large", "message": "The Lab image is larger than its 4 GB limit and was removed."}

    class OverLimit(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            self.states[run_id].update(status="failed", error=limit)
            raise DomainError(limit["code"], limit["message"], 502)

    run_lab(system, OverLimit())
    job = client.get(f"/api/jobs/{job_id}").json()
    assert (job["status"], job["error"]["code"]) == ("failed", "lab_image_too_large")
    current = client.get(f"/api/findings/{finding_id}").json()
    (lab,) = current["lab_runs"]
    assert lab["status"] == "failed" and {k: lab["error"][k] for k in limit} == limit
    assert current["status"] == "open" and current["cause"]["by"] == "verdict"


# An Upstream Proof's vulnerable app (A07): the Own repository at its default-branch head with the
# Locked version installed, or, with no Own repository, a minimal app that pins it. The Locked
# version is the fixture registry's tarball, vendored under vulnerable-app/.asset-monitor/.
TARBALL = b"react-server-dom-webpack 19.0.0 stand-in bytes"
VENDORED = f".asset-monitor/{PACKAGE}-19.0.0.tgz"
OWN_HEAD = {
    **{path: text.encode() for path, text in npm_files({PACKAGE: "19.0.0"}, {PACKAGE: "19.0.0"}).items()},
    "server.js": b'require("http").createServer((q, r) => r.end("shop")).listen(8080);\n',
    "Dockerfile": b"FROM node:latest\n",  # The repository's own: the bundle's wins.
    ".dockerignore": b"node_modules\n",
}
# An Upstream Proof's bundle: the Dockerfile and its own files; the Lab supplies package.json.
UPSTREAM_BUNDLE = without_package(pinned_bundle("f" * 40))


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


@pytest.fixture
def npm(monkeypatch):
    """The fixture npm registry at NUMEN_NPM_REGISTRY_URL=http://npm.fixture, serving the
    react-server-dom-webpack 19.0.0 metadata (dist) and tarball that a test may change: the
    paths it was asked for."""
    monkeypatch.setenv("NUMEN_NPM_REGISTRY_URL", "http://npm.fixture")
    registry = SimpleNamespace(paths=[], tarball=TARBALL, dist={
        "tarball": f"http://npm.fixture/{PACKAGE}/-/{PACKAGE}-19.0.0.tgz", "integrity": sri(TARBALL)})

    def answer(request):
        registry.paths.append(request.url.path)
        if request.url.path == f"/{PACKAGE}/19.0.0":
            return httpx.Response(200, json={"name": PACKAGE, "version": "19.0.0", "dist": registry.dist})
        if request.url.path == f"/{PACKAGE}/-/{PACKAGE}-19.0.0.tgz":
            return httpx.Response(200, content=registry.tarball)
        return httpx.Response(404, json={})

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(answer))

    monkeypatch.setattr(Sources, "__init__", setup)
    return registry


def react_finding(system, base, own):
    """The React2Shell fix commit on numen/react, exposed to an Application locking
    react-server-dom-webpack@19.0.0: Shop, with its Own repository acme/shop at HEAD (OWN_HEAD),
    when `own`, else Blog with no Own repository. (Application id, its Finding, the Analysis broker)"""
    app, client, _ = system
    connection(app)
    _, release, fix = react(base)
    if own:
        ident = application(client, asset_name="Shop", role="own", source_url=SHOP)["id"]
        linked = client.post(f"/api/applications/{ident}/repositories",
                             json={"source_kind": "github", "source_url": REACT, "locked_version": "19.0.0"})
        assert linked.status_code == 201, linked.text
        with app.state.factory() as db:
            shop_id = db.scalar(select(Repository.id).where(Repository.source_url == SHOP))
        tree(app, shop_id, HEAD, OWN_HEAD, head=True)
    else:
        ident = application(client, asset_name="Blog", source_url=REACT, locked_version="19.0.0")["id"]
    with app.state.factory.begin() as db:
        link = db.scalar(select(ApplicationRepository).where(
            ApplicationRepository.application_id == ident, ApplicationRepository.role == "upstream"))
        link.packages, react_id = [f"npm:{PACKAGE}"], link.repository_id
    commit = source_snapshot(app, ident, fix, repository_id=react_id, files={SERVER: b"export function decodeReply() {}\n"})
    with app.state.factory.begin() as db:
        row = db.get(Commit, commit)
        row.data = {**row.data, "parent_revisions": [release]}
    job, broker = analyze(system, commit, assessment("Vulnerability fix", release), without_package(pinned_bundle(release)))
    assert job["status"] == "succeeded", job
    (finding_id,) = job["result"]["finding_ids"]
    found = client.get(f"/api/findings/{finding_id}").json()
    assert (found["exposure"]["state"], found["exposure"]["reason"]) == ("exposed", "no release contains the fix yet")
    return ident, found, broker


def lab_files(system, finding_id):
    """Approves the Finding's Lab and runs it: (the lab call's files, the job, the LabRun)."""
    _, client, _ = system
    queued = client.post(f"/api/findings/{finding_id}/lab-runs", json=APPROVAL)
    assert queued.status_code == 202, queued.text
    broker = run_lab(system, FixtureBroker({"verified": True, "status": "verified", "exit_code": 0}))
    job = client.get(f"/api/jobs/{queued.json()['job_id']}").json()
    labs = client.get(f"/api/findings/{finding_id}").json()["lab_runs"]
    return ([call["files"] for call in broker.calls if call["kind"] == "lab"] or [None])[0], job, labs[0]


def test_an_upstream_proof_builds_the_own_repository_head_with_the_locked_version_installed(
        system, npm, local_sources):
    _, client, _ = system
    _, found, _ = react_finding(system, local_sources, own=True)
    # The Analysis drafted for an app of its own, not Shop's head: Shop gets the report, and its own
    # bundle is drafted automatically.
    assert {a["path"] for a in found["artifacts"]} == {"report.md", "manifest.json"}
    assert found["artifact_state"]["status"] == "draft"
    automatic_bundle(system, found["id"], UPSTREAM_BUNDLE)
    assert client.get(f"/api/findings/{found['id']}").json()["artifact_state"]["status"] == "complete"
    files, job, lab = lab_files(system, found["id"])
    assert job["status"] == "succeeded", job
    for path in ("server.js", "package-lock.json"):
        assert path in OWN_HEAD and "vulnerable-app/" + path in files, path
    assert files["vulnerable-app/server.js"] == OWN_HEAD["server.js"]
    for path in ("vulnerable-app/Dockerfile", "vulnerable-app/application.lock.json", "poc.py"):
        assert files[path] == UPSTREAM_BUNDLE[path], path
    assert "vulnerable-app/.dockerignore" not in files and "vulnerable-app/manifest.json" not in files
    # Exactly the registry's bytes of the Locked version, installed from the file: spec.
    assert files["vulnerable-app/" + VENDORED] == TARBALL
    manifest = json.loads(files["vulnerable-app/package.json"])
    locked = json.loads(files["vulnerable-app/package-lock.json"])
    assert manifest["dependencies"] == locked["packages"][""]["dependencies"] == {PACKAGE: "file:" + VENDORED}
    assert locked["packages"][f"node_modules/{PACKAGE}"] == {
        "version": "19.0.0", "resolved": "file:" + VENDORED, "integrity": sri(TARBALL)}
    assert npm.paths == [f"/{PACKAGE}/19.0.0", f"/{PACKAGE}/-/{PACKAGE}-19.0.0.tgz"]
    assert (lab["status"], lab["packages"], lab["locked_version"], lab["own_ref"]) == (
        "verified", [PACKAGE], "19.0.0", HEAD)


def test_an_upstream_proof_without_an_own_repository_builds_a_minimal_app_pinning_the_locked_version(
        system, npm, local_sources):
    _, found, broker = react_finding(system, local_sources, own=False)
    facts = json.loads(broker.calls[0]["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert (facts["vulnerable_app"], facts["own_repository"], facts["packages"], facts["locked_version"]) == (
        "minimal", False, [PACKAGE], "19.0.0")
    assert found["artifact_state"]["status"] == "complete", found["artifact_state"]
    files, job, lab = lab_files(system, found["id"])
    assert job["status"] == "succeeded", job
    assert json.loads(files["vulnerable-app/package.json"]) == {
        "name": "asset-monitor-lab", "version": "0.0.0", "private": True,
        "dependencies": {PACKAGE: "file:" + VENDORED}}
    assert files["vulnerable-app/" + VENDORED] == TARBALL and "vulnerable-app/package-lock.json" not in files
    assert (lab["packages"], lab["locked_version"], lab["own_ref"]) == ([PACKAGE], "19.0.0", None)


@pytest.mark.parametrize("tamper,message", [
    ("bytes", "does not match its registry integrity"),
    ("origin", "is not on the npm registry"),
    ("integrity", "has no sha512 integrity"),
])
def test_a_locked_package_whose_integrity_or_origin_does_not_match_is_refused(
        system, npm, local_sources, tamper, message):
    _, found, _ = react_finding(system, local_sources, own=False)
    if tamper == "bytes":
        npm.tarball = b"something else"
    elif tamper == "origin":
        npm.dist = {**npm.dist, "tarball": f"http://elsewhere.fixture/{PACKAGE}-19.0.0.tgz"}
    else:
        npm.dist = {**npm.dist, "integrity": "sha1-" + base64.b64encode(hashlib.sha1(TARBALL).digest()).decode()}
    files, job, lab = lab_files(system, found["id"])
    assert files is None and (job["status"], job["error"]["code"]) == ("failed", "package_untrusted")
    assert message in job["error"]["message"] and lab["status"] == "failed"
    assert (f"/{PACKAGE}/-/{PACKAGE}-19.0.0.tgz" in npm.paths) is (tamper == "bytes")


def test_the_automatic_bundle_draft_is_told_its_vulnerable_app_rule(system, local_sources):
    app, client, _ = system
    ident, found, _ = react_finding(system, local_sources, own=True)
    job, broker = automatic_bundle(system, found["id"], UPSTREAM_BUNDLE)
    assert job["status"] == "succeeded", job
    (call,) = broker.calls
    facts = json.loads(call["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert (facts["own_repository"], facts["vulnerable_app"], facts["packages"], facts["locked_version"]) == (
        False, "own_head", [PACKAGE], "19.0.0")
    assert (facts["source_pin"]["basis"], facts["source_ref"], facts["source_url"]) == ("own_head", HEAD, SHOP)
    # The Own repository's head, not the Upstream source, is the evidence it reads.
    assert call["files"]["source/server.js"] == OWN_HEAD["server.js"] and f"source/{SERVER}" not in call["files"]
    current = client.get(f"/api/findings/{found['id']}").json()
    assert current["artifact_state"]["status"] == "complete", current["artifact_state"]
    pins = [e for e in job["events"] if e["kind"] == "source_pin"]
    assert pins[0]["message"] == "Using the Own repository's head, where the Lab installs the Locked version"
    # It counts against the Analysis caps like patch drafting: over a cap none is queued, and the
    # Proof stays a Draft for Generate.
    started(app, ident, CAPS["application"] - 1)
    with app.state.factory.begin() as db:
        application, row = db.get(Application, ident), db.get(Finding, found["id"])
        assert domain.over_cap(db, application, domain.resolve_profile(db, application, "finding_artifacts"),
                               False) == "application"
        assert domain.draft_bundle(db, application, row) is None


def test_a_repository_own_for_one_application_and_upstream_for_another_gets_a_bundle_per_role(system):
    app, client, _ = system
    connection(app)
    shop = application(client, asset_name="Shop", role="own", source_url=SHOP)["id"]
    partner = application(client, asset_name="Partner", source_url=SHOP)["id"]
    ident = parented(app, shop, "a" * 40, "f" * 40, OWN_SOURCE)
    drafted = {**without_package(pinned_bundle("a" * 40)), "disclosure-report.md": b"# For acme/shop\n"}
    job, broker = analyze(system, ident, assessment("Vulnerability introduced", "a" * 40), drafted)
    facts = json.loads(broker.calls[0]["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert (facts["vulnerable_app"], facts["own_repository"], facts["upstream"]) == ("own_commit", True, True)
    rows = by_application(client)
    own, upstream = (client.get(f"/api/findings/{rows[a]['id']}").json() for a in (shop, partner))
    assert {a["path"] for a in own["artifacts"]} == {*drafted, "manifest.json"}
    assert own["artifact_state"]["status"] == "complete", own["artifact_state"]
    # Partner's Lab would build its own app: it gets the reports, and its own bundle draft is queued.
    assert {a["path"] for a in upstream["artifacts"]} == {"report.md", "disclosure-report.md", "manifest.json"}
    assert upstream["artifact_state"]["status"] == "draft" and upstream["disclosure_report"]
    assert {s["step"]: s["status"] for s in upstream["playbook"]}["proof"] == "draft"
    # That draft is for the minimal app Partner's Lab builds, and keeps the Disclosure report.
    job, broker = automatic_bundle(system, upstream["id"], pinned_bundle("a" * 40))
    assert job["status"] == "succeeded", job
    facts = json.loads(broker.calls[0]["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    assert (facts["vulnerable_app"], facts["own_repository"]) == ("minimal", False)
    upstream = client.get(f"/api/findings/{upstream['id']}").json()
    assert upstream["artifact_state"]["status"] == "complete", upstream["artifact_state"]
    assert upstream["disclosure_report"]["text"] == "# For acme/shop\n"
