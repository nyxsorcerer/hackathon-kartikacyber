import gzip
import io
import json
import tarfile
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from conftest import FixtureBroker, check_now, connection, application, github_account, repository_of, source_snapshot
from numen import artifacts, cves, domain
from numen.models import Account, Artifact, CVE, JobAttempt, Application, ApplicationCVE, Repository, VersionRecipe, now
from numen.queue import claim, recover
from numen.security import fingerprint
from numen.sources import Sources
from numen.worker import run_once


def cve_raw(score=7.0, version="3.1", cve_id="CVE-2026-12345"):
    key = {"3.0": "cvssMetricV30", "3.1": "cvssMetricV31", "4.0": "cvssMetricV40"}.get(
        version, "cvssMetricV2"
    )
    return {
        "id": cve_id,
        "vulnStatus": "Analyzed",
        "published": "2026-01-01T00:00:00Z",
        "lastModified": "2026-09-01T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "Fixture issue"}],
        "metrics": {
            key: [
                {
                    "source": "fixture",
                    "cvssData": {
                        "version": version,
                        "baseScore": score,
                        "vectorString": "fixture-vector",
                    },
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "2.0.0",
                            }
                        ],
                    }
                ]
            }
        ],
    }


def seed_cve(app, ident, raw):
    with app.state.factory.begin() as db:
        row = CVE(id=raw["id"], raw=raw, record_hash=fingerprint(raw), data=cves.parse_cve(raw))
        db.add(row)
        db.flush()
        db.add(ApplicationCVE(application_id=ident, cve_id=row.id, confirmed=None, data={}))


@pytest.mark.parametrize(
    "score,version,eligible",
    [(7, "3.0", True), (7, "3.1", True), (7, "4.0", True), (6.9, "3.1", False), (10, "2.0", False)],
)
def test_score_gate_all_manual_paths(system, score, version, eligible):
    app, client, _ = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.0", "3.1", "4.0"],
            "version_scheme": "semver",
        },
    )
    seed_cve(app, p["id"], cve_raw(score, version))
    row = client.get("/api/cves").json()["items"][0]
    assert row["eligible"] is eligible
    assert row["applicability"] == "unknown"
    response = client.post(f"/api/applications/{p['id']}/cves/{row['id']}/analyses", json={})
    assert response.status_code == (202 if eligible else 422)
    if not eligible:
        assert response.json()["code"] == "criteria_not_met"
        assert client.get("/api/jobs").json()["items"] == []


def test_unconfirmed_match_and_changed_queued_policy(system):
    app, client, config = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "keyword", "value": "plugin"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
        },
    )
    seed_cve(app, p["id"], cve_raw())
    endpoint = f"/api/applications/{p['id']}/cves/CVE-2026-12345"
    assert client.post(endpoint + "/analyses", json={}).status_code == 422
    assert client.post(endpoint + "/match", json={"confirmed": True}).json()["eligible"] is True
    queued = client.post(endpoint + "/analyses", json={}).json()["job_id"]
    assert (
        client.patch(f"/api/applications/{p['id']}", json={"config": {"cve_min_score": 8}}).status_code
        == 200
    )
    broker = FixtureBroker()
    while run_once(config, app.state.factory, broker):
        pass
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "criteria_not_met"
    assert broker.calls == []


def test_cve_applicability_keeps_environment_unknown(system):
    app, client, _ = system
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "version_scheme": "semver",
        },
    )
    seed_cve(app, p["id"], cve_raw())
    client.post(
        f"/api/applications/{p['id']}/version-observations",
        json={"version": "1.5.0", "evidence": ["fixture"]},
    )
    assert client.get("/api/cves").json()["items"][0]["applicability"] == "affected"
    client.post(
        f"/api/applications/{p['id']}/version-observations",
        json={"version": "2.0.0", "evidence": ["fixture"]},
    )
    assert client.get("/api/cves").json()["items"][0]["applicability"] == "not affected"
    with app.state.factory.begin() as db:
        row = db.get(CVE, "CVE-2026-12345")
        row.raw = {
            **row.raw,
            "configurations": [{"operator": "AND", "nodes": row.raw["configurations"][0]["nodes"]}],
        }
    assert client.get("/api/cves").json()["items"][0]["applicability"] == "unknown"


def test_profile_runtime_effort_and_frozen_retry(system):
    app, client, config = system
    profile = connection(
        app,
        {
            "pi": [
                {
                    "id": "test-model",
                    "name": "Test",
                    "reasoning_efforts": ["high"],
                    "default_effort": "high",
                }
            ],
            "codex": [
                {
                    "id": "test-model",
                    "name": "Test",
                    "reasoning_efforts": ["xhigh"],
                    "default_effort": "xhigh",
                }
            ],
        },
    )
    p = application(client)
    commit_id = source_snapshot(app, p["id"])
    endpoint = f"/api/commits/{commit_id}/analyses"
    assert (
        client.post(
            endpoint, json={"profile": {**profile, "reasoning_effort": "ultra"}}
        ).status_code
        == 422
    )
    # Efforts come from the selected runtime's catalog: xhigh is only in Codex's.
    assert client.post(endpoint, json={"profile": {**profile, "reasoning_effort": "xhigh"}}).status_code == 422
    queued = client.post(endpoint, json={}, headers={"Idempotency-Key": "analysis-once"}).json()[
        "job_id"
    ]
    same = client.post(endpoint, json={}, headers={"Idempotency-Key": "analysis-once"}).json()[
        "job_id"
    ]
    assert queued == same
    broker = FixtureBroker(result={"verdict": "invented verdict"})
    run_once(config, app.state.factory, broker)
    failed = client.get(f"/api/jobs/{queued}").json()
    assert failed["status"] == "failed" and failed["error"]["code"] == "invalid_agent_output"
    retry = client.post(f"/api/jobs/{queued}/retry").json()["job_id"]
    assert retry != queued
    assert client.get(f"/api/jobs/{retry}").json()["profile"] == failed["profile"]


def test_explicit_commit_analysis_retains_report_and_verdict(system):
    app, client, config = system
    profile = connection(app)
    p = application(client)
    commit_id = source_snapshot(app, p["id"])
    assert (
        client.post(f"/api/commits/{commit_id}/review", json={"decision": "candidate"}).status_code
        == 200
    )
    client.get(f"/api/commits/{commit_id}")
    assert all(j["kind"] != "commit_analysis" for j in client.get("/api/jobs").json()["items"])
    # Marking a candidate submits no Analysis.
    assert not run_once(config, app.state.factory, FixtureBroker())
    queued = client.post(f"/api/commits/{commit_id}/analyses", json={"profile": profile}).json()[
        "job_id"
    ]
    result = {
        "verdict": "Insufficient context",
        "title": "Potential input validation weakness",
        "vulnerable_ref": None,
        "summary": "Input conversion prevents misuse",
        "evidence": [{"path": "main.py", "lines": [1, 2]}],
        "confidence": "medium",
        "open_questions": [],
        "before_after": "Added conversion",
        "affected_behavior": "Input parsing",
    }
    broker = FixtureBroker(result, {"report.md": b"# Evidence\nPinned source analysis"})
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    analysis = client.get(f"/api/commits/{commit_id}").json()["analyses"][0]
    assert analysis["result"]["verdict"] == result["verdict"]
    assert analysis["profile"] == profile
    report = next(a for a in analysis["artifacts"] if a["path"] == "report.md")
    assert b"Pinned source" in client.get(f"/api/artifacts/{report['id']}/content").content
    assert "fixture-key" not in json.dumps(job)


def test_pause_scheduler_manual_and_source_generation(system):
    app, client, _ = system
    p = application(client, monitor_enabled=False)
    with app.state.factory.begin() as db:
        assert domain.schedule(db) == 0
    assert client.post(f"/api/applications/{p['id']}/checks").status_code == 202
    source_snapshot(app, p["id"])
    assert len(client.get(f"/api/applications/{p['id']}/commits").json()["items"]) == 1


def test_github_old_dated_history_and_partial_retry(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client)
    revisions = ["b" * 40, "a" * 40, "c" * 40]
    with app.state.factory.begin() as db:
        repository_of(db, p["id"]).cursor = "c" * 40  # the Baseline
    failures = {"enabled": True}

    def http(request):
        if "/compare/" in request.url.path:
            return httpx.Response(
                200, json={"status": "ahead", "total_commits": 2, "commits": [{"sha": "a" * 40}, {"sha": "b" * 40}]}
            )
        if request.url.path.endswith("/commits"):
            return httpx.Response(
                200,
                json=[
                    {
                        "sha": revision,
                        "html_url": "https://github.com/demo/plugin/commit/" + revision,
                        "commit": {
                            "message": "Old-dated merged revision",
                            "committer": {"date": "2001-01-01T00:00:00Z"},
                        },
                    }
                    for revision in revisions
                ],
            )
        if request.url.path.endswith("a" * 40) and failures["enabled"]:
            return httpx.Response(403)
        return httpx.Response(
            200,
            json={
                "commit": {
                    "message": "Change",
                    "author": {"name": "Fixture"},
                    "committer": {"date": "2001-01-01T00:00:00Z"},
                },
                "files": [
                    {"filename": "main.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}
                ],
            },
        )

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "failed"
    assert client.get(f"/api/applications/{p['id']}/commits").json()["items"] == []
    with app.state.factory() as db:
        assert repository_of(db, p["id"]).cursor == "c" * 40
    # The failure is shown on the repository, and the Application reports it.
    failed = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
    assert failed["last_error"]["code"] and failed["last_check_at"] is None
    failures["enabled"] = False
    client.post(f"/api/jobs/{queued}/retry")
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/applications/{p['id']}").json()["repositories"][0]["last_error"] is None
    commits = client.get(f"/api/applications/{p['id']}/commits").json()["items"]
    assert len(commits) == 2 and all(c["triage_status"] == "disabled" for c in commits)
    assert all(j["kind"] != "commit_triage" for j in client.get("/api/jobs").json()["items"])
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    assert len(client.get(f"/api/applications/{p['id']}/commits").json()["items"]) == 2


def test_github_archive_path_safety(system, monkeypatch):
    _, client, config = system
    p = application(client)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("root/../../escape")
        member.size = 3
        archive.addfile(member, io.BytesIO(b"bad"))
    source = Sources(config, "fixture-github-token")
    monkeypatch.setattr(
        source, "get", lambda *args, **kwargs: httpx.Response(200, content=stream.getvalue())
    )
    with system[0].state.factory() as db:
        with pytest.raises(ValueError):
            source.snapshot_github(repository_of(db, p["id"]), "a" * 40)


def test_github_snapshot_omits_media_and_fits_cms_scale_sources(system, monkeypatch):
    app, client, config = system
    p = application(client)
    stream = io.BytesIO()
    names = [f"root/src/{index}.php" for index in range(4500)]
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name in names + ["root/images/logo.PNG", "root/fonts/icons.woff2"]:
            member = tarfile.TarInfo(name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    source = Sources(config, "fixture-github-token")
    monkeypatch.setattr(
        source, "get", lambda *args, **kwargs: httpx.Response(200, content=stream.getvalue())
    )
    with app.state.factory() as db:
        files = source.snapshot_github(repository_of(db, p["id"]), "a" * 40)
    assert sorted(files) == sorted(name.removeprefix("root/") for name in names)


def test_short_work_slot_never_claims_long_jobs(system):
    from numen.worker import LONG_KINDS

    app, client, _ = system
    connection(app)
    p = application(client)
    audit = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    check = check_now(client, p["id"])
    with app.state.factory.begin() as db:
        assert claim(db, "slot/short", LONG_KINDS).id == check
    with app.state.factory.begin() as db:
        assert claim(db, "slot/0").id == audit


def test_release_corpus_falls_back_to_source_archives_for_unusable_packages(system, monkeypatch):
    from numen.artifacts import MAX_SET

    app, client, config = system
    p = application(client)
    asset = "https://api.github.com/repos/demo/plugin/releases/assets/"
    releases = [
        {"tag_name": "2.0.0", "assets": [{"name": "app.zip", "size": MAX_SET + 1, "url": asset + "2"}]},
        {"tag_name": "1.0.0", "assets": [{"name": "app.zip", "size": 9, "url": asset + "1"}]},
    ]
    requested = []

    def get(url, params=None, headers=None):
        requested.append(url)
        if url.endswith("/releases"):
            return httpx.Response(200, json=releases)
        return httpx.Response(200, content=b"not a zip")

    source = Sources(config, "fixture-github-token")
    monkeypatch.setattr(source, "get", get)
    monkeypatch.setattr(source, "snapshot_github", lambda _, tag: {"app.js": tag.encode()})
    with app.state.factory() as db:
        corpus = source.release_corpus(repository_of(db, p["id"]))
    assert [release["version"] for release in corpus["releases"]] == ["2.0.0", "1.0.0"]
    assert asset + "2" not in requested  # The oversized package is never downloaded.
    versions = [v for record in corpus["fingerprints"]["app.js"].values() for v in record["versions"]]
    assert sorted(versions) == ["1.0.0", "2.0.0"]
    limitations = " ".join(corpus["limitations"])
    assert "app.zip exceeds the download bound" in limitations
    assert "app.zip unavailable (BadZipFile)" in limitations
    assert "release capture failed" not in limitations


def test_lease_recovery_fences_old_attempt(system):
    app, client, _ = system
    p = application(client)
    queued = check_now(client, p["id"])
    with app.state.factory.begin() as db:
        old = claim(db, "old-worker")
        old_token = old.attempt_token
        old.lease_until = now() - timedelta(seconds=1)
    assert recover(app.state.factory, FixtureBroker()) == 1
    with app.state.factory.begin() as db:
        new = claim(db, "replacement-worker")
        assert new.id == queued and new.attempt_token != old_token
        assert db.get(JobAttempt, old_token).status == "interrupted"
        assert new.attempts == 2


def test_probe_reuse_and_failure_preserves_success(system):
    app, client, config = system
    p = application(client)
    source_snapshot(app, p["id"])
    with app.state.factory.begin() as db:
        recipe = VersionRecipe(
            application_id=p["id"], source_generation=1, source_ref="a" * 40, status="active", data={}
        )
        db.add(recipe)
        db.flush()
        from numen.artifacts import publish

        publish(
            db,
            config.artifact_root,
            "recipe",
            recipe.id,
            {"determine_version.py": b"print('fixture')", "recipe.json": b"{}"},
        )
        row = db.get(Application, p["id"])
        row.config = {**row.config, "active_recipe_id": recipe.id}
    result = {
        "status": "detected",
        "version": "1.0.0",
        "candidates": [],
        "method": "header",
        "evidence": [{"header": "version"}],
        "confidence": {"basis": "Disclosure"},
        "limitations": [],
    }
    broker = FixtureBroker(result)
    client.post(f"/api/applications/{p['id']}/version-checks")
    run_once(config, app.state.factory, broker)
    assert broker.calls[0]["kind"] == "probe" and broker.calls[0]["profile"] is None
    assert client.get(f"/api/applications/{p['id']}").json()["version"]["version"] == "1.0.0"
    broker.result = {
        "status": "error",
        "version": None,
        "candidates": [],
        "evidence": [],
        "limitations": ["Target unavailable"],
    }
    client.post(f"/api/applications/{p['id']}/version-checks")
    run_once(config, app.state.factory, broker)
    row = client.get(f"/api/applications/{p['id']}").json()
    assert row["version"]["version"] == "1.0.0"
    assert row["latest_version_check"]["status"] == "error"
    assert all(c["kind"] == "probe" for c in broker.calls)


def test_audit_coordinator_pinned_skill_and_partial_units(system, tmp_path, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("Analyze functions, assumptions and invariants")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))

    def handler(call):
        if call["token"].endswith(":orientation"):
            assert "skill/SKILL.md" in call["files"]
            return {
                "overview": "Map",
                "functions": [
                    {"id": "parse", "path": "main.py", "name": "parse"},
                    {"id": "missing", "path": "missing.py", "name": "missing"},
                ],
            }, {}
        if ":function:" in call["token"]:
            return {
                "summary": "Converts input",
                "evidence": [{"path": "main.py"}],
                "open_questions": [],
            }, {"function.md": b"# parse\nAssumptions and invariant evidence"}
        return {"summary": "Context", "open_questions": ["Missing function"]}, {
            "audit-context-building.md": b"# Context\nSee functions/001.md. Partial coverage."
        }

    queued = client.post(
        f"/api/applications/{p['id']}/audit-contexts", json={"focus": "Parser"}
    ).json()["job_id"]
    broker = FixtureBroker(handler=handler)
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    row = client.get(f"/api/applications/{p['id']}/audit-contexts").json()["items"][0]
    assert row["status"] == "partial" and row["coverage"]["failed"] == 1
    assert len(row["skill_revision"]) == 64
    assert {"functions/001.md", "audit-context-building.md"}.issubset(
        {a["path"] for a in row["artifacts"]}
    )
    assert len(broker.calls) == 3


def test_audit_accepts_workspace_unit_paths_and_the_skill_dossier(system, tmp_path, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("Analyze functions")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))

    def handler(call):
        if call["token"].endswith(":orientation"):
            # Pi's tools name files relative to /workspace.
            unit = {"id": "F01", "path": "inputs/source/main.py", "name": "parse"}
            return {"overview": "Map", "functions": [unit]}, {}
        if ":function:" in call["token"]:
            return {
                "summary": "Converts input",
                "evidence": [{"path": "main.py"}],
                "open_questions": [],
            }, {"function.md": b"# parse"}
        # The pinned skill writes its dossier rather than Numen's entry document.
        return {"summary": "System model", "open_questions": ["Who calls parse?"]}, {
            "audit-context/DOSSIER.md": b"# Dossier"
        }

    queued = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(handler=handler))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    row = client.get(f"/api/applications/{p['id']}/audit-contexts").json()["items"][0]
    assert row["coverage"]["completed"] == 1 and row["coverage"]["failed"] == 0
    with app.state.factory() as db:
        files = artifacts.resource_files(
            db, config.artifact_root, "audit", row["id"], row["coverage"]["artifact_revision"]
        )
    entry = files["audit-context-building.md"].decode()
    assert "[System dossier](audit-context/DOSSIER.md)" in entry and "(functions/001.md)" in entry
    assert "Who calls parse?" in entry


def test_audit_function_limit_is_configurable_and_records_reach_synthesis_as_a_file(
    system, tmp_path, monkeypatch
):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("Analyze functions")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))
    units = [{"id": f"F{i}", "path": "main.py", "name": f"parse{i}"} for i in range(2)]
    seen = {}

    def handler(call):
        if call["token"].endswith(":orientation"):
            seen["orientation"] = call["prompt"]
            return {"overview": "Map", "functions": units}, {}
        if ":function:" in call["token"]:
            # Real function records run to many KB each.
            return {
                "summary": "x" * 5000,
                "evidence": [{"path": "main.py"}],
                "open_questions": [],
            }, {"function.md": b"# parse"}
        seen["synthesis"] = call
        return {"summary": "System model", "open_questions": []}, {
            "audit-context/DOSSIER.md": b"# Dossier"
        }

    for limit in (1, 2):
        queued = client.post(
            f"/api/applications/{p['id']}/audit-contexts", json={"max_functions": limit}
        ).json()["job_id"]
        run_once(config, app.state.factory, FixtureBroker(handler=handler))
        job = client.get(f"/api/jobs/{queued}").json()
        assert job["status"] == "succeeded", job
        assert f'"max_functions": {limit}' in seen["orientation"]
        coverage = job["result"]["coverage"]
        if limit == 1:
            # Over-selection keeps the most significant functions and records the rest.
            assert coverage["completed"] == 1 and coverage["deferred"] == 1
            assert coverage["deferred_units"] == [{"name": "parse1", "path": "main.py"}]
        else:
            assert coverage["deferred"] == 0
    records = json.loads(seen["synthesis"]["files"]["audit-functions.json"])
    assert [record["unit"]["name"] for record in records] == ["parse0", "parse1"]
    assert "x" * 5000 not in seen["synthesis"]["prompt"]
    assert '"function_records": "audit-functions.json"' in seen["synthesis"]["prompt"]
    for value in (0, 101):
        response = client.post(
            f"/api/applications/{p['id']}/audit-contexts", json={"max_functions": value}
        )
        assert response.status_code == 422


def audit_setup(system, tmp_path, monkeypatch, count):
    app, client, _ = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("Analyze functions")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))
    units = [{"id": f"F{i}", "path": "main.py", "name": f"parse{i}"} for i in range(count)]

    def handler(call):
        if call["token"].endswith(":orientation"):
            return {"overview": "Map", "functions": units}, {}
        if ":function:" in call["token"]:
            return {
                "summary": "Converts input",
                "evidence": [{"path": "main.py"}],
                "open_questions": [],
            }, {"function.md": b"# parse"}
        return {"summary": "System model", "open_questions": []}, {
            "audit-context/DOSSIER.md": b"# Dossier"
        }

    queued = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    return queued, handler


def test_audit_analyzes_functions_concurrently_and_reports_progress(
    system, tmp_path, monkeypatch
):
    import threading

    app, client, config = system
    queued, handler = audit_setup(system, tmp_path, monkeypatch, 2)
    # Each function run waits until the other is in flight; sequential analysis would time out.
    barrier = threading.Barrier(2, timeout=10)

    class ConcurrentBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            if ":function:" in run_id:
                barrier.wait()
            return super().wait(run_id, heartbeat, progress, deadline)

    run_once(config, app.state.factory, ConcurrentBroker(handler=handler))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert job["progress"] == {"stage": "synthesis", "status": "2 of 2 analysed, 0 failed"}
    with app.state.factory() as db:
        attempt = db.scalar(select(JobAttempt).where(JobAttempt.job_id == queued))
        assert attempt.data["runtime_phases"] == {}


def test_audit_failure_cancels_every_in_flight_function_run(system, tmp_path, monkeypatch):
    import threading
    import time

    from numen.security import DomainError

    app, client, config = system
    queued, handler = audit_setup(system, tmp_path, monkeypatch, 2)
    both_started = threading.Barrier(2, timeout=10)

    class FailingBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            if run_id.endswith(":function:1"):
                both_started.wait()
                raise DomainError("broker_unavailable", "Execution broker is unavailable", 503)
            if run_id.endswith(":function:0"):
                both_started.wait()
                # Still working until the attempt's failure handling cancels this run.
                while self.states[run_id]["status"] != "cancelled":
                    time.sleep(0.02)
                raise DomainError("cancelled", "Runtime cancelled", 409)
            return super().wait(run_id, heartbeat, progress, deadline)

    broker = FailingBroker(handler=handler)
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "broker_unavailable", job
    in_flight = next(c["token"] for c in broker.calls if c["token"].endswith(":function:0"))
    assert broker.states[in_flight]["status"] == "cancelled"


def test_interrupted_audit_continues_without_repeating_work(system, tmp_path, monkeypatch):
    from dataclasses import replace

    from numen.security import DomainError

    app, client, config = system
    queued, handler = audit_setup(system, tmp_path, monkeypatch, 2)
    application_id = client.get(f"/api/jobs/{queued}").json()["application_id"]

    class InterruptedBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            if run_id.endswith(":function:1"):
                raise DomainError("broker_unavailable", "Execution broker is unavailable", 503)
            return super().wait(run_id, heartbeat, progress, deadline)

    # One function at a time, so function 0 is checkpointed before function 1 fails.
    sequential = replace(config, audit_concurrency=1)
    run_once(sequential, app.state.factory, InterruptedBroker(handler=handler))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "failed"

    retried = client.post(f"/api/jobs/{queued}/retry").json()["job_id"]
    broker = FixtureBroker(handler=handler)
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{retried}").json()["status"] == "succeeded"
    # Orientation and function 0 are reused; only the unfinished function and synthesis run.
    assert [call["token"].split(":", 1)[1] for call in broker.calls] == ["function:1", "synthesis"]
    contexts = client.get(f"/api/applications/{application_id}/audit-contexts").json()["items"]
    latest, first = contexts[0], contexts[1]
    assert latest["job_id"] == retried and latest["status"] in ("complete", "partial")
    assert latest["coverage"]["resumed_from"] == first["id"]
    assert latest["coverage"]["reused_functions"] == 1 and latest["coverage"]["completed"] == 2
    synthesis = next(call for call in broker.calls if call["token"].endswith(":synthesis"))
    assert len(json.loads(synthesis["files"]["audit-functions.json"])) == 2

    # A continued checkpoint is not reused again; fresh or a different scope starts over too.
    for body in ({}, {"fresh": True}, {"max_functions": 5}):
        client.post(f"/api/applications/{application_id}/audit-contexts", json=body)
        restart = FixtureBroker(handler=handler)
        run_once(config, app.state.factory, restart)
        assert restart.calls[0]["token"].endswith(":orientation"), body


def test_stop_runs_cancels_every_phase_and_requires_terminal_proof():
    from types import SimpleNamespace

    from numen.queue import runtime_phases, stop_runs

    class Broker:
        def __init__(self):
            self.cancelled, self.status = [], {"r1": "cancelled", "r2": "running"}

        def lookup_attempt(self, phase):
            return {"run_id": "r2"} if phase == "p2" else None  # p3 provably never started

        def cancel(self, run_id):
            self.cancelled.append(run_id)

        def request(self, method, path):
            return {"status": self.status[path.rsplit("/", 1)[-1]]}

    broker = Broker()
    assert stop_runs(broker, {"p1": "r1", "p2": None, "p3": None}) == (False, ["r1", "r2"])
    assert broker.cancelled == ["r1", "r2"]
    broker.status["r2"] = "cancelled"
    assert stop_runs(broker, {"p1": "r1", "p2": None}) == (True, ["r1", "r2"])
    # Attempts recorded before concurrent phases keep their single phase and run.
    assert runtime_phases(SimpleNamespace(data={"runtime_attempt_token": "p1"}), "r1") == {
        "p1": "r1"
    }
    finished = SimpleNamespace(data={"runtime_phases": {}, "runtime_attempt_token": "p1"})
    assert runtime_phases(finished, "r1") == {}


def test_capabilities_exact_runtime_native_ingress_and_secret_redaction(system):
    app, client, config = system
    account = client.post(
        "/api/accounts", json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"}
    ).json()
    queued = client.post(f"/api/accounts/{account['id']}/login").json()["job_id"]
    broker = FixtureBroker(result={"status": "signed_in"})
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    assert broker.ingress_deleted
    with app.state.factory() as db:
        account_row = db.get(Account, account["id"])
        assert "native-fixture-secret" not in account_row.credential
        assert (
            app.state.vault.decrypt(account_row.credential)["auth_json"]["access_token"]
            == "native-fixture-secret"
        )
    assert "native-fixture-secret" not in json.dumps(client.get("/api/accounts").json())
    broker.result = {
        "models": [
            {
                "id": "native-model",
                "name": "Native",
                "reasoning_efforts": ["high"],
                "default_effort": "high",
            }
        ],
        "usage": None,
    }
    while run_once(config, app.state.factory, broker):
        pass
    public = client.get("/api/accounts").json()["items"][0]
    assert public["status"] == "ready" and public["supported_agents"] == ["codex"]
    assert public["agent_models"]["codex"][0]["id"] == "native-model"


def test_ancestry_compare_imports_old_dated_commit_after_baseline(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client)
    baseline, head, merged_old = "a" * 40, "b" * 40, "c" * 40
    source_snapshot(app, p["id"], baseline)

    def http(request):
        if request.url.path.endswith("/commits"):
            # A chronological list encounters baseline before the newly merged old-dated change.
            return httpx.Response(200, json=[{"sha": head}, {"sha": baseline}, {"sha": merged_old}])
        if "/compare/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "status": "ahead",
                    "total_commits": 2,
                    "commits": [{"sha": merged_old}, {"sha": head}],
                },
            )
        return httpx.Response(
            200,
            json={
                "commit": {
                    "message": "Merged old change",
                    "committer": {"date": "2001-01-01T00:00:00Z"},
                },
                "files": [{"filename": "main.py", "patch": "@@ -1 +1 @@\n-a\n+b"}],
            },
        )

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    assert {baseline, head, merged_old} == {
        c["revision"] for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]
    }


def test_compressed_upstream_responses_are_decoded_once(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client)
    revision = "a" * 40
    with app.state.factory.begin() as db:
        repository_of(db, p["id"]).cursor = "b" * 40

    def http(request):
        if request.url.path.endswith("/commits"):
            payload = [{"sha": revision}]
        elif "/compare/" in request.url.path:
            payload = {"status": "ahead", "total_commits": 1, "commits": [{"sha": revision}]}
        else:
            payload = {
                "commit": {"message": "Change", "committer": {"date": "2026-01-01T00:00:00Z"}},
                "files": [{"filename": "main.py", "patch": "@@ -1 +1 @@\n-a\n+b"}],
            }
        # GitHub and NVD compress JSON; the transport delivers the encoded bytes.
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=httpx.ByteStream(gzip.compress(json.dumps(payload).encode())),
        )

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    commits = client.get(f"/api/applications/{p['id']}/commits").json()["items"]
    assert [c["revision"] for c in commits] == [revision]


def test_baseline_sets_the_head_without_importing_history(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client)
    history = [f"{index:040x}" for index in range(150, 0, -1)]
    pages = []

    def http(request):
        if request.url.path.endswith("/commits"):
            page = int(request.url.params["page"])
            pages.append(page)
            return httpx.Response(
                200, json=[{"sha": sha} for sha in history[(page - 1) * 100 : page * 100]]
            )
        return httpx.Response(
            200,
            json={
                "commit": {"message": "Change", "committer": {"date": "2026-01-01T00:00:00Z"}},
                "files": [{"filename": "main.py", "patch": "@@ -1 +1 @@\n-a\n+b"}],
            },
        )

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    assert pages == [1]
    assert client.get(f"/api/applications/{p['id']}/commits?limit=200").json()["items"] == []
    with app.state.factory() as db:
        repository = repository_of(db, p["id"])
        assert repository.cursor == repository.baseline_revision == history[0]


def test_nvd_incomplete_pages_and_updates_preserve_completed_cursor(system, monkeypatch):
    app, client, config = system
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
        },
    )
    state = {"partial": True, "score": 7}

    def http(request):
        index = int(request.url.params.get("startIndex", 0))
        if index == 1 and state["partial"]:
            return httpx.Response(200, json={"totalResults": 2, "vulnerabilities": []})
        raw = cve_raw(state["score"], cve_id="CVE-2026-12345" if index == 0 else "CVE-2026-12346")
        return httpx.Response(200, json={"totalResults": 2, "vulnerabilities": [{"cve": raw}]})

    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)
    queued = client.post(f"/api/applications/{p['id']}/cve-sync").json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["error"]["code"] == "incomplete_cve_page"
    assert client.get("/api/cves").json()["items"] == []
    with app.state.factory() as db:
        assert db.get(Application, p["id"]).cve_cursor == {}
    state["partial"] = False
    client.post(f"/api/jobs/{queued}/retry")
    run_once(config, app.state.factory, FixtureBroker())
    assert all(row["eligible"] for row in client.get("/api/cves").json()["items"])
    state["score"] = 6.9
    client.post(f"/api/applications/{p['id']}/cve-sync")
    run_once(config, app.state.factory, FixtureBroker())
    assert all(not row["eligible"] for row in client.get("/api/cves").json()["items"])
    with app.state.factory() as db:
        assert db.get(Application, p["id"]).cve_cursor["completed_at"]


def test_cpe_selectors_query_nvd_by_product(system):
    _, _, config = system
    queries = []

    def http(request):
        queries.append(dict(request.url.params))
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    source = Sources(config)
    source.client = httpx.Client(transport=httpx.MockTransport(http))
    source.collect_cves(
        [
            {"type": "cpe", "value": "cpe:2.3:a:demo:plugin:1.2.3:*:*:*:*:wordpress:*:*"},
            {"type": "keyword", "value": "Demo plugin"},
        ],
        {},
    )
    # NVD rejects wildcard cpeName values; versions are evaluated after product matching.
    assert all("cpeName" not in query for query in queries)
    assert queries[0]["virtualMatchString"] == "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"
    assert queries[1]["keywordSearch"] == "Demo plugin"


def test_audit_failed_synthesis_retains_function_checkpoint(system, tmp_path, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("Analyze assumptions")
    monkeypatch.setenv("NUMEN_SKILL_ROOT", str(skill))

    def handler(call):
        if call["token"].endswith(":orientation"):
            return {
                "overview": "Map",
                "functions": [{"id": "parse", "path": "main.py", "name": "parse"}],
            }, {}
        if ":function:" in call["token"]:
            return {
                "summary": "Input function",
                "evidence": [{"path": "main.py"}],
                "open_questions": [],
            }, {"function.md": b"# Preserved function evidence"}
        return {"invalid": True}, {}

    queued = client.post(f"/api/applications/{p['id']}/audit-contexts", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(handler=handler))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "failed"
    report = client.get(f"/api/applications/{p['id']}/audit-contexts").json()["items"][0]
    assert report["status"] == "partial" and report["coverage"]["completed"] == 1
    function = next(a for a in report["artifacts"] if a["path"] == "functions/001.md")
    assert (
        b"Preserved function evidence"
        in client.get(f"/api/artifacts/{function['id']}/content").content
    )


def test_broker_failure_version_observation_and_unrelated_profile_edits(system):
    app, client, config = system
    profile = connection(app)
    p = application(client, config={"profiles": {"commit_analysis": profile}})
    commit_id = source_snapshot(app, p["id"])
    with app.state.factory.begin() as db:
        db.get(Account, profile["connection_id"]).data = {"status": "expired", "models": []}
    assert (
        client.patch(f"/api/applications/{p['id']}", json={"monitor_enabled": False}).status_code == 200
    )
    assert client.patch("/api/settings", json={"monitor_interval_seconds": 432000}).status_code == 200
    assert client.post(f"/api/commits/{commit_id}/analyses", json={}).status_code == 422
    with app.state.factory.begin() as db:
        row = db.get(Application, p["id"])
        recipe = VersionRecipe(
            application_id=p["id"], source_generation=1, source_ref=repository_of(db, p["id"]).cursor,
            status="active", data={},
        )
        db.add(recipe)
        db.flush()
        from numen.artifacts import publish

        publish(
            db,
            config.artifact_root,
            "recipe",
            recipe.id,
            {"determine_version.py": b"print('fixture')"},
        )
        row.config = {**row.config, "active_recipe_id": recipe.id}
    client.post(
        f"/api/applications/{p['id']}/version-observations",
        json={"version": "1.0.0", "evidence": ["Before outage"]},
    )

    class UnavailableBroker(FixtureBroker):
        def submit(self, *args, **kwargs):
            from numen.security import DomainError

            raise DomainError("broker_unavailable", "Execution broker is unavailable", 503)

    client.post(f"/api/applications/{p['id']}/version-checks")
    run_once(config, app.state.factory, UnavailableBroker())
    changed = client.get(f"/api/applications/{p['id']}").json()
    assert (
        changed["version"]["version"] == "1.0.0"
        and changed["latest_version_check"]["status"] == "error"
    )
    assert changed["latest_version_check"]["error"]["code"] == "broker_unavailable"


def test_php_version_compare_uses_actual_php_if_available():
    import shutil

    if not shutil.which("php"):
        pytest.skip("Bundled PHP comparator is exercised in Docker")
    assert cves.compare_versions("1.0RC1", "1.0", "php") == -1
    assert cves.compare_versions("1.0pl1", "1.0", "php") == 1
    assert cves.compare_versions("1.0.0", "1.0", "php") == 1


def test_actual_wordpress_svn_import_export_and_subsequent_revision(system, tmp_path, monkeypatch):
    import shutil
    import subprocess

    if not shutil.which("svn") or not shutil.which("svnadmin"):
        pytest.skip("Real SVN client/repository are exercised in the Docker backend suite")
    app, client, config = system
    repo, seed, checkout = tmp_path / "svn", tmp_path / "seed", tmp_path / "checkout"
    trunk = seed / "fixture" / "trunk"
    trunk.mkdir(parents=True)
    (trunk / "plugin.php").write_text(
        "<?php /* Version: 1.0.0 */\nfunction get_data($x) { return $x; }\n"
    )

    def svn(*argv):
        subprocess.run(["svn", *argv, "--non-interactive"], check=True, capture_output=True)

    subprocess.run(["svnadmin", "create", str(repo)], check=True, capture_output=True)
    svn("import", str(seed), repo.as_uri(), "-m", "First plugin release")
    monkeypatch.setenv("NUMEN_WORDPRESS_SVN_URL", repo.as_uri())
    p = application(
        client, source_kind="wordpress", source_url=None, plugin_slug="fixture", source_ref="trunk"
    )
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    # The Baseline is the head; nothing before it is imported.
    assert client.get(f"/api/applications/{p['id']}/commits").json()["items"] == []
    svn("checkout", repo.as_uri() + "/fixture/trunk", str(checkout))
    (checkout / "plugin.php").write_text(
        "<?php /* Version: 1.0.1 */\nfunction get_data($x) { return htmlentities($x); }\n"
    )
    svn("commit", str(checkout), "-m", "Encode output")
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    rows = client.get(f"/api/applications/{p['id']}/commits").json()["items"]
    assert [row["revision"] for row in rows] == ["2"]
    revised = next(row for row in rows if row["revision"] == "2")
    assert revised["diff_complete"] is True and "htmlentities" in revised["diff"]
    with app.state.factory() as db:
        # The SVN revision cursor lives on the repository row.
        repository = db.scalar(select(Repository).where(Repository.plugin_slug == "fixture"))
        assert (repository.source_url, repository.cursor) == ("https://plugins.svn.wordpress.org/fixture", "2")
        snapshot = Sources(config).snapshot_wordpress(repository, "2")
        assert b"Version: 1.0.1" in snapshot["plugin.php"]


def test_administrative_cve_update_does_not_queue_duplicate_auto_analysis(system):
    app, client, _ = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
            "cve_auto_analyze": True,
        },
    )
    source_snapshot(app, p["id"])
    raw = cve_raw()
    seed_cve(app, p["id"], raw)
    with app.state.factory.begin() as db:
        monitored = db.get(Application, p["id"])
        row = db.get(CVE, raw["id"])
        link = db.scalar(select(ApplicationCVE).where(ApplicationCVE.application_id == monitored.id))
        domain.refresh_cve_policy(db, monitored, row, link)
        original_hash = cves.gate_hash(monitored, row, link)
    before = [
        job for job in client.get("/api/jobs").json()["items"] if job["kind"] == "cve_analysis"
    ]
    assert len(before) == 1
    with app.state.factory.begin() as db:
        row = db.get(CVE, raw["id"])
        row.raw = {**raw, "lastModified": "2026-10-04T00:00:00Z"}
        row.record_hash, row.data = fingerprint(row.raw), cves.parse_cve(row.raw)
        monitored = db.get(Application, p["id"])
        link = db.scalar(select(ApplicationCVE).where(ApplicationCVE.application_id == monitored.id))
        assert cves.gate_hash(monitored, row, link) == original_hash
        domain.refresh_cve_policy(db, monitored, row, link)
    after = [
        job for job in client.get("/api/jobs").json()["items"] if job["kind"] == "cve_analysis"
    ]
    assert [job["id"] for job in after] == [job["id"] for job in before]


def test_auto_analysis_waits_for_the_baseline_source_check(system, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
            "cve_auto_analyze": True,
        },
    )
    raw = cve_raw()
    seed_cve(app, p["id"], raw)
    with app.state.factory.begin() as db:
        monitored = db.get(Application, p["id"])
        link = db.scalar(select(ApplicationCVE).where(ApplicationCVE.application_id == monitored.id))
        domain.refresh_cve_policy(db, monitored, db.get(CVE, raw["id"]), link)

    def analyses():
        return [j for j in client.get("/api/jobs").json()["items"] if j["kind"] == "cve_analysis"]

    def blocked():
        return client.get(f"/api/cves?application_id={p['id']}").json()["items"][0]["analysis_blocked"]

    assert analyses() == [] and blocked()["code"] == "source_not_checked"
    monkeypatch.setattr(Sources, "github_commits", lambda *_: ("b" * 40, [], None))
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    assert len(analyses()) == 1 and blocked() is None


def test_rotated_native_auth_is_saved_even_when_runtime_fails(system):
    from numen.security import DomainError

    app, client, config = system
    account = client.post(
        "/api/accounts", json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"}
    ).json()
    with app.state.factory.begin() as db:
        row = db.get(Account, account["id"])
        row.credential = app.state.vault.encrypt(
            {"auth_json": {"access_token": "old-native-fixture-secret"}}
        )
        row.data = {"status": "unchecked", "models": []}
    queued = client.post(f"/api/accounts/{account['id']}/capabilities").json()["job_id"]

    class RefreshThenFail(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            self.states[run_id]["credential_updated"] = True
            self.states[run_id]["status"] = "failed"
            raise DomainError(
                "runtime_failed", "Capability runtime stopped after refreshing auth", 502
            )

        def credential(self, run_id):
            return {"auth_json": {"access_token": "rotated-native-fixture-secret"}}

    broker = RefreshThenFail()
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "failed"
    with app.state.factory() as db:
        row = db.get(Account, account["id"])
        assert row.revision == 2
        assert (
            app.state.vault.decrypt(row.credential)["auth_json"]["access_token"]
            == "rotated-native-fixture-secret"
        )
    assert broker.ingress_deleted
    assert "rotated-native-fixture-secret" not in json.dumps(client.get("/api/jobs").json())


@pytest.mark.parametrize("passing", [True, False])
def test_generated_recipe_validation_activation_and_retained_rejected_revision(
    system, monkeypatch, passing
):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    corpus = {
        "schema_version": 1,
        "fingerprints": {},
        "releases": [],
        "limitations": ["No known releases"],
        "complete": False,
    }
    monkeypatch.setattr(Sources, "release_corpus", lambda *_: corpus)
    script = b"import json\nprint(json.dumps({'status':'unknown','evidence':[]}))\n"

    def handler(call):
        if call["kind"] == "agent":
            assert call["policy"]["origins"] == ["https://example.com"]
            return {"metadata": {}}, {
                "determine_version.py": script,
                "recipe.json": b"{}",
                "fingerprints.json": b"{}",
                "fixtures/cases.json": b"[]",
            }
        assert call["kind"] == "probe" and call["policy"]["request_budget"] == 0
        assert "recipe.py" in call["files"] and "target.json" in call["files"]
        return {"status": "validated" if passing else "error", "fixtures_passed": passing}, {}

    queued = client.post(f"/api/applications/{p['id']}/version-recipes", json={}).json()["job_id"]
    run_once(config, app.state.factory, FixtureBroker(handler=handler))
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == ("succeeded" if passing else "failed"), job
    recipe = client.get(f"/api/applications/{p['id']}/version-recipes").json()["items"][0]
    assert recipe["status"] == ("active" if passing else "rejected")
    assert recipe["metadata"]["allowed_origins"] == ["https://example.com"]
    import hashlib

    assert recipe["metadata"]["script_sha256"] == hashlib.sha256(script).hexdigest()
    assert any(artifact["path"] == "determine_version.py" for artifact in recipe["artifacts"])
    assert (
        bool(client.get(f"/api/applications/{p['id']}").json()["config"]["active_recipe_id"]) is passing
    )


def test_recipe_fingerprints_come_from_the_corpus_file_not_the_prompt(system, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client)
    source_snapshot(app, p["id"])
    digest = "f" * 64
    corpus = {
        "schema_version": 1,
        "fingerprints": {"app.js": {digest: {"versions": ["1.0.0"], "size": 1}}},
        "releases": [{"version": "1.0.0", "distributed": False, "asset_count": 1}],
        "limitations": [],
        "complete": False,
    }
    monkeypatch.setattr(Sources, "release_corpus", lambda *_: corpus)
    probe_files, deadlines = {}, {}

    def handler(call):
        if call["kind"] == "agent":
            assert digest not in call["prompt"]
            assert json.loads(call["files"]["release-corpus.json"]) == corpus
            # The agent is told the exact probe contract Numen validates against.
            assert "NUMEN_TARGET_INPUT is the path of a JSON file" in call["prompt"]
            assert '{"mode":"validate","fixtures":true}' in call["prompt"]
            assert '"status":"validated","fixtures_passed"' in call["prompt"]
            return {"metadata": {}}, {
                "determine_version.py": b"print('{}')\n",
                "recipe.json": b"{}",
                "fixtures/cases.json": b"[]",
            }
        probe_files.update(call["files"])
        return {"status": "validated", "fixtures_passed": True}, {}

    class RecordingBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            kind = next(call["kind"] for call in self.calls if call["token"] == run_id)
            deadlines[kind] = deadline
            return super().wait(run_id, heartbeat, progress, deadline)

    queued = client.post(f"/api/applications/{p['id']}/version-recipes", json={}).json()["job_id"]
    run_once(config, app.state.factory, RecordingBroker(handler=handler))
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    assert json.loads(probe_files["fingerprints.json"]) == {"fingerprints": corpus["fingerprints"]}
    assert json.loads(probe_files["target.json"]) == {"mode": "validate", "fixtures": True}
    # Agent work has no deadline; generated-code probes keep theirs.
    assert deadlines == {"agent": None, "probe": 900}


def test_shared_and_conflicting_hashes_cannot_fabricate_exact_version():
    from numen.workflows import reconcile_hash_observation

    corpus = {
        "fingerprints": {
            "app.js": {"shared": {"versions": ["1.0.0", "1.0.1"]}, "other": {"versions": ["2.0.0"]}}
        },
        "limitations": ["Bounded releases"],
    }
    result = {
        "status": "detected",
        "version": "1.0.0",
        "method": "asset_hash",
        "evidence": [{"sha256": "shared"}],
        "limitations": [],
    }
    observed = reconcile_hash_observation(result, corpus)
    assert observed["status"] == "ambiguous" and observed["version"] is None
    assert observed["candidates"] == ["1.0.0", "1.0.1"]
    conflicting = reconcile_hash_observation(
        {**result, "evidence": [{"sha256": "shared"}, {"sha256": "other"}]}, corpus
    )
    assert conflicting["status"] == "unknown" and conflicting["version"] is None


def source_record(revision):
    return {
        "revision": revision,
        "message": "Security-relevant change",
        "author": "Fixture",
        "committed_at": "2026-10-04T00:00:00Z",
        "url": "https://github.com/demo/plugin/commit/" + revision,
        "files": [{"path": "main.py"}],
        "diff": "-return value\n+return str(value)",
        "diff_complete": True,
    }


def test_first_baseline_imports_no_history_and_queues_no_ai_jobs(system, monkeypatch):
    app, client, config = system
    connection(app)
    github_account(app)
    p = application(client, config={"triage_mode": "pi"})
    head = "a" * 40
    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[{"sha": head}])))

    monkeypatch.setattr(Sources, "__init__", setup)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded" and job["result"]["source_ref"] == head
    assert client.get(f"/api/applications/{p['id']}/commits").json()["items"] == []
    assert all(
        job["kind"] not in ("commit_triage", "jev_triage", "commit_analysis")
        for job in client.get("/api/jobs").json()["items"]
    )


def test_genuine_head_advance_automatic_triage_runs_broker(system, monkeypatch):
    app, client, config = system
    connection(app)
    p = application(client, config={"triage_mode": "pi"})
    source_snapshot(app, p["id"], "a" * 40)
    head = "b" * 40
    monkeypatch.setattr(Sources, "github_commits", lambda *_: (head, [source_record(head)], None))
    client.post(f"/api/applications/{p['id']}/checks")
    run_once(config, app.state.factory, FixtureBroker())
    triage = next(
        job for job in client.get("/api/jobs").json()["items"] if job["kind"] == "commit_triage"
    )
    broker = FixtureBroker(
        {
            "reply": json.dumps({
                "decision": "security_candidate",
                "title": "Potential input trust boundary vulnerability",
                "reason": "Input trust boundary changed",
            })
        }
    )
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{triage['id']}").json()["status"] == "succeeded"
    assert len(broker.calls) == 1 and broker.calls[0]["profile"]["operation"] == "commit_triage"
    revised = next(
        commit
        for commit in client.get(f"/api/applications/{p['id']}/commits").json()["items"]
        if commit["revision"] == head
    )
    assert revised["triage_result"]["revision"] == head
    assert revised["review_decision"] == "candidate"
    # The flag queues one automatic Analysis, not run here: no snapshot of the head is stored.
    (analysis,) = [job for job in client.get("/api/jobs").json()["items"] if job["kind"] == "commit_analysis"]
    assert analysis["status"] == "queued" and analysis["subject"]["ref"] == head[:10]


def test_historical_pinned_commit_job_remains_valid_after_current_head_advances(system):
    app, client, config = system
    connection(app)
    p = application(client)
    pinned = "a" * 40
    commit_id = source_snapshot(app, p["id"], pinned)
    queued = client.post(f"/api/commits/{commit_id}/analyses", json={}).json()["job_id"]
    with app.state.factory.begin() as db:
        monitored = db.get(Application, p["id"])
        repository_of(db, p["id"]).cursor = "b" * 40
        from numen.models import AuditContext
        from numen.artifacts import publish

        context_job = domain.enqueue(
            db, "audit_context", monitored, domain.job_input(db, monitored, source_ref=pinned)
        )
        context_job.status = "succeeded"
        report = AuditContext(
            application_id=monitored.id,
            source_generation=1,
            source_ref=pinned,
            skill_revision="fixture-pinned-skill",
            coverage={"selected": 1, "completed": 1},
            status="stale",
            job_id=context_job.id,
        )
        db.add(report)
        db.flush()
        publish(
            db,
            config.artifact_root,
            "audit",
            report.id,
            {"audit-context-building.md": b"# Historical context pinned to revision A"},
        )
    result = {
        "verdict": "Insufficient context",
        "title": "Potential input validation weakness",
        "vulnerable_ref": None,
        "summary": "Input conversion",
        "evidence": [{"path": "main.py", "lines": [1, 2]}],
        "confidence": "medium",
        "open_questions": [],
        "before_after": "Added conversion",
        "affected_behavior": "Input parsing",
    }
    broker = FixtureBroker(result, {"report.md": b"# Pinned historical source analysis"})
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    assert len(broker.calls) == 1 and pinned in broker.calls[0]["prompt"]
    assert "source/main.py" in broker.calls[0]["files"]
    # Commit analysis judges the change itself, without the audit context.
    assert not any(path.startswith("context/") for path in broker.calls[0]["files"])
    analysis = client.get(f"/api/commits/{commit_id}").json()["analyses"][0]
    manifest = next(
        artifact for artifact in analysis["artifacts"] if artifact["path"] == "manifest.json"
    )
    # An Upstream commit's Analysis is never exported (A15): read its manifest as stored.
    assert client.get(f"/api/artifacts/{manifest['id']}/content").status_code == 403
    with app.state.factory() as db:
        content = json.loads(artifacts.read_file(config.artifact_root, db.get(Artifact, manifest["id"])))
    assert content["source_ref"] == pinned and content["commit_revision"] == pinned


def test_changed_source_generation_still_blocks_pinned_commit_job(system):
    app, client, config = system
    connection(app)
    p = application(client)
    commit_id = source_snapshot(app, p["id"])
    queued = client.post(f"/api/commits/{commit_id}/analyses", json={}).json()["job_id"]
    # Removing the source repository changes the source the queued analysis was pinned to.
    client.delete(f"/api/applications/{p['id']}/repositories/{p['repositories'][0]['repository_id']}")
    broker = FixtureBroker()
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "input_changed"
    assert broker.calls == []


def test_source_generation_changed_during_fetch_cannot_promote_old_cursor(system, monkeypatch):
    app, client, config = system
    p = application(client)

    def collect(*_):
        with app.state.factory.begin() as db:
            repository_of(db, p["id"]).source_generation += 1
        return "a" * 40, [source_record("a" * 40)], None

    monkeypatch.setattr(Sources, "github_commits", collect)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(f"/api/jobs/{queued}").json()["error"]["code"] == "input_changed"
    with app.state.factory() as db:
        row = repository_of(db, p["id"])
        assert row.source_generation == 2 and row.cursor is None
    assert client.get(f"/api/applications/{p['id']}/commits").json()["items"] == []


def test_queued_cve_score_update_still_rechecks_record_hash_before_dispatch(system):
    app, client, config = system
    connection(app)
    p = application(
        client,
        config={
            "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
            "cve_min_score": 7,
            "cve_versions": ["3.1"],
        },
    )
    source_snapshot(app, p["id"])
    seed_cve(app, p["id"], cve_raw(7))
    queued = client.post(f"/api/applications/{p['id']}/cves/CVE-2026-12345/analyses", json={}).json()[
        "job_id"
    ]
    with app.state.factory.begin() as db:
        row = db.get(CVE, "CVE-2026-12345")
        row.raw = cve_raw(8)
        row.data, row.record_hash = cves.parse_cve(row.raw), fingerprint(row.raw)
    broker = FixtureBroker()
    run_once(config, app.state.factory, broker)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "failed" and job["error"]["code"] == "input_changed"
    assert broker.calls == []


@pytest.mark.parametrize("lost_submission", [False, True])
def test_unavailable_broker_never_reports_running_work_stopped_or_allows_retry(
    system, lost_submission
):
    from numen.security import DomainError

    app, client, config = system
    connection(app)
    p = application(client)
    commit_id = source_snapshot(app, p["id"])
    queued = client.post(f"/api/commits/{commit_id}/analyses", json={}).json()["job_id"]

    class UnacknowledgedBroker(FixtureBroker):
        online = False

        def submit(self, *args, **kwargs):
            result = super().submit(*args, **kwargs)
            self.states[result["run_id"]]["status"] = "running"
            if lost_submission:
                raise DomainError(
                    "broker_unavailable", "Submission acknowledgement unavailable", 503
                )
            return result

        def wait(self, *args, **kwargs):
            raise DomainError("broker_unavailable", "Broker polling is unavailable", 503)

        def lookup_attempt(self, token):
            if not self.online:
                raise DomainError("broker_unavailable", "Attempt lookup unavailable", 503)
            return super().lookup_attempt(token)

        def cancel(self, run_id):
            if not self.online:
                raise DomainError(
                    "broker_unavailable", "Cancellation acknowledgement unavailable", 503
                )
            return super().cancel(run_id)

        def request(self, *args, **kwargs):
            if not self.online:
                raise DomainError("broker_unavailable", "Runtime status unavailable", 503)
            return super().request(*args, **kwargs)

    broker = UnacknowledgedBroker()
    run_once(config, app.state.factory, broker)
    pending = client.get(f"/api/jobs/{queued}").json()
    assert pending["status"] == "cancelling" and pending["finished_at"] is None
    assert pending["error"]["reconciliation_pending"] is True
    assert client.post(f"/api/jobs/{queued}/retry").status_code == 409
    assert recover(app.state.factory, broker) == 0
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "cancelling"
    broker.online = True
    assert recover(app.state.factory, broker) == 1
    terminal = client.get(f"/api/jobs/{queued}").json()
    assert terminal["status"] == "failed" and terminal["finished_at"] is not None
    assert terminal["error"]["reconciliation_pending"] is False
    assert all(run["status"] == "cancelled" for run in broker.states.values())
    assert client.post(f"/api/jobs/{queued}/retry").status_code == 202
