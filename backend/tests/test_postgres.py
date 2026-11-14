"""Actual PostgreSQL lock/lease/migration/session proof in a disposable isolated schema."""

import json
import os
import subprocess
import sys
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import timedelta
from dataclasses import replace

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import load_only

from numen.api import create_app
from numen.config import Config
from numen.db import make_database
from numen.domain import enqueue, schedule
from numen.models import Account, Job, Application, now
from numen.queue import ExecutionContext, claim, recover
from numen.security import DomainError
from conftest import FixtureBroker, github_account


def alembic(url, *args, check=True):
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "NUMEN_DATABASE_URL": url},
        check=check,
        capture_output=True,
        text=True,
    )


def migrate(url, revision):
    alembic(url, "upgrade", revision)


@pytest.fixture
def schema_url():
    base = os.getenv("NUMEN_TEST_DATABASE_URL")
    if not base:
        pytest.skip("NUMEN_TEST_DATABASE_URL is required for the PostgreSQL boundary")
    schema = "numen_test_" + uuid.uuid4().hex
    control = create_engine(base)
    with control.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        yield (
            make_url(base)
            .update_query_dict({"options": f"-csearch_path={schema}"})
            .render_as_string(hide_password=False)
        )
    finally:
        with control.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        control.dispose()


@pytest.fixture
def postgres(schema_url, tmp_path):
    config = Config(database_url=schema_url, artifact_root=tmp_path / "artifacts", monitor_interval_seconds=172800)
    migrate(schema_url, "head")
    engine, factory = make_database(config, initialize=True)
    yield config, factory
    engine.dispose()


def test_postgres_migration_renames_programs_to_applications(schema_url, tmp_path):
    from numen.models import ApplicationCVE
    from numen.security import fingerprint

    migrate(schema_url, "fe74f85e4023")
    engine = create_engine(schema_url)
    inputs = {"source_generation": 1, "source_ref": None}
    # Before the rename a job's input hash named its owner program_id.
    old_hash = fingerprint({"kind": "source_check", "program_id": "p1", "input": inputs, "profile": None})
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO programs (id, asset_name, asset_url, product_kind, product_name, source_kind,"
            " source_url, source_generation, monitor_interval_days, monitor_enabled, archived, config,"
            " cve_cursor) VALUES ('p1', 'Site', 'https://example.com', 'plugin', 'Demo', 'github',"
            " 'https://github.com/demo/plugin', 1, 2, true, false, '{\"triage_mode\": \"disabled\"}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO commits (id, program_id, source_generation, revision, data, triage_status,"
            " review_decision) VALUES ('c1', 'p1', 1, 'abc', '{\"message\": \"Fix\"}', 'disabled', 'pending')"
        ))
        db.execute(text(
            "INSERT INTO cves (id, raw, record_hash, data) VALUES ('CVE-2026-1', '{}', 'h', '{}')"
        ))
        db.execute(text(
            "INSERT INTO program_cves (id, program_id, cve_id, confirmed, data)"
            " VALUES ('pc1', 'p1', 'CVE-2026-1', true, '{\"eligible\": true}')"
        ))
        db.execute(text(
            "INSERT INTO jobs (id, kind, program_id, status, input, input_hash, idempotency_key,"
            " progress, created_at, attempts) VALUES ('j1', 'source_check', 'p1', 'succeeded',"
            " CAST(:input AS json), :hash, 'check-1', '{}', now(), 0)"
        ), {"input": json.dumps(inputs), "hash": old_hash})
        db.execute(text(
            "INSERT INTO actions (id, resource_type, resource_id, data, created_at)"
            " VALUES ('a1', 'program', 'p1', '{\"action\": \"created\"}', now())"
        ))
    engine.dispose()

    # The next revision moves sources onto repositories; this one only renames.
    migrate(schema_url, "3f1a2b4c5d61")
    config = Config(database_url=schema_url, artifact_root=tmp_path / "artifacts", monitor_interval_seconds=172800)
    engine, factory = make_database(config)
    try:
        with factory.begin() as db:
            # Later revisions add columns this one does not have yet.
            application = db.get(Application, "p1", options=[load_only(Application.asset_name, Application.config)])
            assert (application.asset_name, application.config) == ("Site", {"triage_mode": "disabled"})
            assert db.execute(text("SELECT source_url FROM applications")).scalar() == "https://github.com/demo/plugin"
            assert db.execute(text("SELECT application_id FROM commits WHERE id = 'c1'")).scalar() == "p1"
            link = db.get(ApplicationCVE, "pc1")
            assert (link.application_id, link.cve_id, link.confirmed, link.data) == (
                "p1", "CVE-2026-1", True, {"eligible": True})
            assert db.get(Job, "j1").application_id == "p1"
            assert db.execute(text("SELECT resource_type FROM actions WHERE id = 'a1'")).scalar() == "application"
            # The renamed job still answers its idempotency key instead of reporting a conflict.
            assert enqueue(db, "source_check", application, inputs, idempotency_key="check-1").id == "j1"
            assert not db.execute(text(
                "SELECT conname FROM pg_constraint WHERE connamespace = to_regnamespace(current_schema())"
                " AND conname LIKE '%program%'"
            )).all()
    finally:
        engine.dispose()
    alembic(schema_url, "downgrade", "fe74f85e4023")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        assert db.execute(text("SELECT program_id, input_hash FROM jobs")).one() == ("p1", old_hash)
        assert db.execute(text("SELECT program_id FROM program_cves")).scalar() == "p1"
        assert db.execute(text("SELECT resource_type FROM actions")).scalar() == "program"
    engine.dispose()


def create_application(db, name="Fixture"):
    application = Application(
        asset_name=name,
        asset_url="https://example.com",
        product_kind="plugin",
        product_name="Fixture",
        monitor_interval_seconds=172800,
        config={"triage_mode": "disabled"},
        monitor_enabled=True,
    )
    db.add(application)
    db.flush()
    return application


def test_postgres_migration_moves_program_sources_to_upstream_repositories(schema_url, tmp_path):
    from numen.models import ApplicationRepository, Commit, Repository, Snapshot, VersionRecipe

    migrate(schema_url, "3f1a2b4c5d61")
    engine = create_engine(schema_url)
    selectors = [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}]

    def program(db, ident, url, generation, checked, cursor, kind="github", slug=None):
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_kind, source_url, plugin_slug, source_ref, source_generation,"
            " monitor_interval_days, monitor_enabled, archived, config, cve_cursor, cursor,"
            " last_check_at, last_error) VALUES (:id, :id, :asset, 'plugin',"
            " 'Demo', :kind, :url, :slug, 'main', :generation, 2, true, false, CAST(:config AS json),"
            " '{}', :cursor, :checked, CAST(:error AS json))"
        ), {"id": ident, "asset": f"https://{ident}.example", "url": url, "kind": kind, "slug": slug, "generation": generation,
            "config": json.dumps({"cve_selectors": selectors}), "cursor": cursor, "checked": checked,
            "error": json.dumps({"code": "source_unavailable"}) if ident == "newer" else None})

    def commit(db, ident, application, generation, revision):
        db.execute(text(
            "INSERT INTO commits (id, application_id, source_generation, revision, data, triage_status,"
            " review_decision) VALUES (:id, :application, :generation, :revision, '{}', 'disabled', 'pending')"
        ), {"id": ident, "application": application, "generation": generation, "revision": revision})

    def observation(db, ident, status, version, age, generation=1):
        db.execute(text(
            "INSERT INTO version_observations (id, application_id, source_generation, checked_at, data)"
            " VALUES (:id, 'wp', :generation, now() - :age * interval '1 hour', CAST(:data AS json))"
        ), {"id": ident, "generation": generation, "age": age,
            "data": json.dumps({"status": status, "version": version})})

    with engine.begin() as db:
        # Two Programs share one GitHub repository (spelled differently); "newer" was checked last.
        program(db, "older", "https://github.com/Demo/Plugin.git", 2, "2026-10-01T00:00:00Z", "b" * 40)
        program(db, "newer", "https://github.com/demo/plugin/", 1, "2026-11-01T00:00:00Z", "c" * 40)
        program(db, "wp", "https://plugins.svn.wordpress.org/fixture", 1, None, "7", "wordpress", "fixture")
        commit(db, "older-1", "older", 1, "a" * 40)  # an earlier generation of "older"
        commit(db, "older-2", "older", 2, "a" * 40)
        commit(db, "newer-1", "newer", 1, "a" * 40)
        commit(db, "wp-7", "wp", 1, "7")
        db.execute(text(
            "INSERT INTO source_snapshots (id, application_id, source_generation, source_ref, files,"
            " created_at) VALUES ('s1', 'older', 2, :ref, '[]', now())"
        ), {"ref": "b" * 40})
        observation(db, "o1", "detected", "1.2.0", 3)
        observation(db, "o2", "detected", "1.3.0", 2)
        observation(db, "o3", "error", None, 1)
        observation(db, "o4", "detected", "0.9.0", 0, generation=0)  # an earlier source
        db.execute(text("INSERT INTO jobs (id, kind, status, input, input_hash, progress, created_at,"
                        " attempts) VALUES ('j0', 'cve_sync', 'succeeded', '{}', 'h', '{}', now(), 0)"))
        db.execute(text(
            "INSERT INTO jobs (id, kind, application_id, status, input, input_hash, progress, created_at,"
            " attempts) VALUES ('j1', 'version_recipe', 'wp', 'succeeded', '{}', 'h', '{}', now(), 0)"
        ))
        db.execute(text(
            "INSERT INTO version_recipes (id, application_id, source_generation, source_ref, status, data,"
            " created_at) VALUES ('r1', 'wp', 1, '7', 'active', '{}', now())"
        ))
        db.execute(text(
            "INSERT INTO jobs (id, kind, application_id, status, input, input_hash, progress, created_at,"
            " attempts) VALUES ('j2', 'source_check', 'older', 'queued',"
            " '{\"source_generation\": 2, \"source_ref\": null}', 'h', '{}', now(), 0)"
        ))
    engine.dispose()

    migrate(schema_url, "head")
    config = Config(database_url=schema_url, artifact_root=tmp_path / "artifacts", monitor_interval_seconds=172800)
    engine, factory = make_database(config)
    try:
        with factory.begin() as db:
            repositories = {r.source_url: r for r in db.scalars(select(Repository))}
            assert sorted(repositories) == ["https://github.com/demo/plugin", "https://plugins.svn.wordpress.org/fixture"]
            shared = repositories["https://github.com/demo/plugin"]
            wordpress = repositories["https://plugins.svn.wordpress.org/fixture"]
            # The most recently checked Program is canonical; generations of both are kept apart.
            assert (shared.cursor, shared.baseline_revision, shared.source_generation) == ("c" * 40, "c" * 40, 3)
            assert shared.last_error == {"code": "source_unavailable"}
            assert (wordpress.source_kind, wordpress.plugin_slug, wordpress.cursor) == ("wordpress", "fixture", "7")
            links = {link.application_id: link for link in db.scalars(select(ApplicationRepository))}
            assert {ident: (link.repository_id, link.role, link.enabled, link.removed_at)
                    for ident, link in links.items()} == {
                "older": (shared.id, "upstream", True, None),
                "newer": (shared.id, "upstream", True, None),
                "wp": (wordpress.id, "upstream", True, None),
            }
            assert links["older"].created_at < links["newer"].created_at  # in check order
            assert (links["wp"].locked_version, links["wp"].locked_version_source) == ("1.3.0", "deployed")
            assert links["older"].locked_version is links["older"].locked_version_source is None
            commits = {c.id: (c.repository_id, c.source_generation) for c in db.scalars(select(Commit))}
            assert commits == {
                "older-1": (shared.id, 1), "older-2": (shared.id, 2),
                "newer-1": (shared.id, 3), "wp-7": (wordpress.id, 1),
            }
            assert (db.get(Snapshot, "s1").repository_id, db.get(Snapshot, "s1").source_generation) == (shared.id, 2)
            # Only the canonical Program's commits are current; the others' stay as history.
            current = [i for i, (_, generation) in commits.items() if generation == shared.source_generation]
            assert current == ["newer-1"]
            wp = db.get(Application, "wp")
            assert wp.asset_url == "https://wp.example" and wp.config["cve_selectors"] == selectors
            assert db.get(VersionRecipe, "r1").application_id == "wp"
            assert db.get(Job, "j2").input == {
                "source_generation": 3, "source_ref": None, "repository_id": shared.id}
            assert db.get(Job, "j1").input == {}
    finally:
        engine.dispose()
    drift = alembic(schema_url, "check", check=False)
    assert drift.returncode == 0, drift.stdout + drift.stderr
    # Merged Programs cannot be split again.
    refused = alembic(schema_url, "downgrade", "3f1a2b4c5d61", check=False)
    assert refused.returncode != 0 and "cannot become Programs again" in refused.stderr


def legacy_program(db, ident, source_path=None):
    db.execute(text(
        "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name, source_kind,"
        " source_url, source_ref, source_path, source_generation, monitor_interval_days,"
        " monitor_enabled, archived, config, cve_cursor, cursor) VALUES (:id, :id,"
        " 'https://example.com', 'plugin', 'Demo', 'github', 'https://github.com/demo/mono', 'main',"
        " :path, 1, 2, true, false, '{}', '{}', :cursor)"
    ), {"id": ident, "path": source_path, "cursor": "a" * 40})


def test_postgres_migration_refuses_to_merge_programs_with_different_subpaths(schema_url):
    migrate(schema_url, "3f1a2b4c5d61")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        legacy_program(db, "plugin-a", "plugins/a")
        legacy_program(db, "plugin-b", "plugins/b")
    failed = alembic(schema_url, "upgrade", "head", check=False)
    assert failed.returncode != 0
    assert "plugin-a, plugin-b share https://github.com/demo/mono" in failed.stderr
    with engine.begin() as db:
        # Nothing moved: both Programs keep their own subpath.
        assert dict(db.execute(text("SELECT id, source_path FROM applications")).all()) == {
            "plugin-a": "plugins/a", "plugin-b": "plugins/b"}
        assert db.execute(text("SELECT to_regclass('repositories')")).scalar() is None
    engine.dispose()


def test_postgres_migration_downgrades_unmerged_repositories_to_programs(schema_url):
    migrate(schema_url, "fe74f85e4023")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO programs (id, asset_name, asset_url, product_kind, product_name, source_kind,"
            " source_url, source_ref, source_path, source_generation, monitor_interval_days,"
            " monitor_enabled, archived, config, cve_cursor, cursor, last_error) VALUES ('p1', 'Site',"
            " 'https://example.com', 'plugin', 'Demo', 'github', 'https://github.com/demo/mono',"
            " 'main', 'plugins/a', 1, 2, true, false, '{}', '{}', :cursor, '{\"code\": \"x\"}')"
        ), {"cursor": "a" * 40})
        db.execute(text(
            "INSERT INTO commits (id, program_id, source_generation, revision, data, triage_status,"
            " review_decision) VALUES ('c1', 'p1', 1, :rev, '{}', 'disabled', 'pending')"
        ), {"rev": "a" * 40})
        db.execute(text(
            "INSERT INTO source_snapshots (id, program_id, source_generation, source_ref, files,"
            " created_at) VALUES ('s1', 'p1', 1, :rev, '[]', now())"
        ), {"rev": "a" * 40})
    migrate(schema_url, "head")
    alembic(schema_url, "downgrade", "fe74f85e4023")
    with engine.begin() as db:
        assert tuple(db.execute(text(
            "SELECT source_kind, source_url, source_ref, source_path, cursor, last_error,"
            " monitor_interval_days FROM programs"
        )).one()) == ("github", "https://github.com/demo/mono", "main", "plugins/a", "a" * 40,
                      {"code": "x"}, 2)
        assert db.execute(text("SELECT program_id FROM commits")).scalar() == "p1"
        assert db.execute(text("SELECT program_id FROM source_snapshots")).scalar() == "p1"
        assert {name for (name,) in db.execute(text(
            "SELECT conname FROM pg_constraint WHERE connamespace = to_regnamespace(current_schema())"
            " AND conrelid IN ('commits'::regclass, 'source_snapshots'::regclass) AND contype IN ('f', 'u')"
        ))} == {"commits_program_id_fkey", "commits_program_id_source_generation_revision_key",
                "source_snapshots_program_id_fkey"}
    engine.dispose()
    # The downgraded schema upgrades again.
    migrate(schema_url, "head")


def test_postgres_migration_stores_intervals_in_seconds(schema_url):
    migrate(schema_url, "5b3c4d6e7f83")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_days, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a1', 'Site', 'https://example.com', 'plugin', 'Demo', 1, 2, true, false, '{}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO settings (id, data, revision) VALUES ('global',"
            " '{\"monitor_interval_days\": 7, \"webhook_enabled\": false}', 1)"
        ))
    migrate(schema_url, "6c4d5e7f8094")
    with engine.begin() as db:
        assert db.execute(text("SELECT monitor_interval_seconds FROM applications")).scalar() == 172800
        assert db.execute(text("SELECT data FROM settings")).scalar() == {
            "monitor_interval_seconds": 604800, "webhook_enabled": False}
        # Intervals under a day, allowed since the upgrade, become one day on downgrade.
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_seconds, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a2', 'Shop', 'https://shop.example.com', 'app', 'Shop', 1, 300, true, false, '{}', '{}')"
        ))
        db.execute(text("UPDATE settings SET data = '{\"monitor_interval_seconds\": 300}'"))
    alembic(schema_url, "downgrade", "5b3c4d6e7f83")
    with engine.begin() as db:
        assert dict(db.execute(text("SELECT id, monitor_interval_days FROM applications")).all()) == {
            "a1": 2, "a2": 1}
        assert db.execute(text("SELECT data FROM settings")).scalar() == {"monitor_interval_days": 1}
    engine.dispose()


def test_postgres_migration_keeps_links_and_adds_derivation_state(schema_url):
    migrate(schema_url, "6c4d5e7f8094")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_seconds, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a1', 'Site', 'https://example.com', 'plugin', 'Demo', 1, 300, true, false, '{}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO repositories (id, source_kind, source_url, source_generation, watched_branches, created_at)"
            " VALUES ('r1', 'github', 'https://github.com/demo/plugin', 1, '{}', now())"
        ))
        db.execute(text(
            "INSERT INTO application_repositories (id, application_id, repository_id, role, enabled,"
            " locked_version, locked_version_source, created_at)"
            " VALUES ('l1', 'a1', 'r1', 'upstream', true, '1.2.0', 'deployed', now())"
        ))
    migrate(schema_url, "7d5e6f8091a5")
    with engine.begin() as db:
        assert tuple(db.execute(text(
            "SELECT locked_version, packages, unresolved, derived_revision FROM application_repositories"
        )).one()) == ("1.2.0", [], [], None)
    alembic(schema_url, "downgrade", "6c4d5e7f8094")
    with engine.begin() as db:
        assert db.execute(text("SELECT locked_version FROM application_repositories")).scalar() == "1.2.0"
    engine.dispose()


def test_postgres_migration_adds_triage_transcripts(schema_url):
    migrate(schema_url, "7d5e6f8091a5")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO jobs (id, kind, status, input, input_hash, progress, created_at, attempts)"
            " VALUES ('j1', 'commit_triage', 'succeeded', '{}', 'h', '{}', now(), 1)"
        ))
    migrate(schema_url, "8e6f7a92b1c6")
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO transcripts (id, job_id, kind, subject_id, data, created_at)"
            " VALUES ('t1', 'j1', 'triage', 'c1', '{\"status\": \"failed\", \"reply\": \"not JSON\"}', now())"
        ))
        assert db.execute(text("SELECT data FROM transcripts")).scalar() == {"status": "failed", "reply": "not JSON"}
    alembic(schema_url, "downgrade", "7d5e6f8091a5")
    with engine.begin() as db:
        assert db.execute(text("SELECT kind FROM jobs")).scalar() == "commit_triage"
        assert db.execute(text("SELECT to_regclass('transcripts')")).scalar() is None
    engine.dispose()


def test_postgres_migration_maps_categories_to_verdicts(schema_url):
    verdicts = {
        "Likely vulnerability fix": "Vulnerability fix",
        "Potentially introduced vulnerability": "Vulnerability introduced",
        "Security hardening": "Security hardening",
        "Unrelated change": "Unrelated",
        "Insufficient context": "Insufficient context",
    }
    migrate(schema_url, "8e6f7a92b1c6")
    engine = create_engine(schema_url)
    results = {}
    saved = {"updated_at": "2026-10-01T00:00:00+00:00", "default_digest": "numen"}
    templates = {
        "commit_triage": {**saved, "source": "Classify the change kind and its confidence."},
        "commit_analysis": {**saved, "source": "Report category and finding_decision."},
        "bundle": {**saved, "source": 'Bundle rules.\n{% include "build-sandbox" %}'},
        "audit-context": {**saved, "source": "Trust the audit context a little."},
    }
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_seconds, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a1', 'Site', 'https://example.com', 'plugin', 'Demo', 1, 300, true, false, '{}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO repositories (id, source_kind, source_url, source_generation, watched_branches, created_at)"
            " VALUES ('r1', 'github', 'https://github.com/demo/plugin', 1, '{}', now())"
        ))
        for ident in ("c1", "c2"):
            db.execute(text(
                "INSERT INTO commits (id, repository_id, source_generation, revision, data, triage_status,"
                " review_decision) VALUES (:id, 'r1', 1, :id, '{}', 'disabled', 'pending')"
            ), {"id": ident})
        # Each category once, oldest first, all about c1; the newest one is Insufficient context.
        for n, category in enumerate(verdicts):
            result = {
                "category": category, "title": f"Analysis {n}", "finding_decision": "needs_more_evidence",
                "confidence": {"level": "medium", "basis": "Pinned source"}, "summary": "Recorded",
            }
            results[f"x{n}"] = result
            row = {"id": f"x{n}", "result": json.dumps(result), "age": f"{10 - n} minutes"}
            db.execute(text(
                "INSERT INTO jobs (id, kind, status, input, input_hash, progress, result, created_at, attempts)"
                " VALUES (:id, 'commit_analysis', 'succeeded', '{}', 'h', '{}', CAST(:result AS json), now(), 1)"
            ), row)
            db.execute(text(
                "INSERT INTO analyses (id, application_id, kind, subject_id, job_id, input_hash, profile,"
                " result, created_at) VALUES (:id, 'a1', 'commit_analysis', 'c1', :id, 'h', '{}', CAST(:result AS json),"
                " now() - CAST(:age AS interval))"
            ), row)
        # Other operations keep their confidence object.
        db.execute(text(
            "INSERT INTO jobs (id, kind, status, input, input_hash, progress, result, created_at, attempts)"
            " VALUES ('cve', 'cve_analysis', 'succeeded', '{}', 'h', '{}', CAST(:result AS json), now(), 1)"
        ), {"result": json.dumps({"confidence": {"level": "high"}})})
        # Saved templates this revision breaks are reset; the others stay.
        db.execute(text("INSERT INTO settings (id, data, revision) VALUES ('prompts', CAST(:data AS json), 3)"),
                   {"data": json.dumps({"templates": templates})})
    migrate(schema_url, "9f7a8ba3c2d7")
    with engine.begin() as db:
        for table in ("analyses", "jobs"):
            rows = dict(db.execute(text(
                f"SELECT id, result FROM {table} WHERE kind = 'commit_analysis'")).all())
            assert rows == {
                ident: {
                    **{k: v for k, v in old.items() if k not in ("category", "confidence")},
                    "verdict": verdicts[old["category"]],
                    "confidence": "unknown",
                    "numen_confidence": old["confidence"],
                }
                for ident, old in results.items()
            }, table
        assert db.execute(text("SELECT result FROM jobs WHERE id = 'cve'")).scalar() == {"confidence": {"level": "high"}}
        assert dict(db.execute(text("SELECT id, verdict FROM commits")).all()) == {
            "c1": "Insufficient context", "c2": None}
        assert db.execute(text("SELECT analysis_state FROM commits WHERE id = 'c2'")).scalar() is None
        data, revision = db.execute(text("SELECT data, revision FROM settings WHERE id = 'prompts'")).one()
        assert (data, revision) == ({"templates": {"audit-context": templates["audit-context"]}}, 4)
        reset = dict(db.execute(text("SELECT resource_id, data FROM actions WHERE resource_type = 'prompt'")).all())
        assert {name: (row["action"], row["previous"]) for name, row in reset.items()} == {
            name: ("reset", templates[name]["source"]) for name in ("commit_triage", "commit_analysis", "bundle")}
    migrate(schema_url, "head")  # alembic check compares only a database at the head revision.
    drift = alembic(schema_url, "check", check=False)
    assert drift.returncode == 0, drift.stdout + drift.stderr
    alembic(schema_url, "downgrade", "8e6f7a92b1c6")
    with engine.begin() as db:
        for table in ("analyses", "jobs"):
            rows = dict(db.execute(text(
                f"SELECT id, result FROM {table} WHERE kind = 'commit_analysis'")).all())
            assert rows == results, table
        columns = {c for (c,) in db.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'commits'"
            " AND table_schema = current_schema()"))}
        assert not {"verdict", "analysis_state"} & columns and "review_decision" in columns
        assert db.execute(text("SELECT data FROM settings WHERE id = 'prompts'")).scalar() == {"templates": templates}
        assert db.execute(text("SELECT count(*) FROM actions")).scalar() == 0
    engine.dispose()


def test_postgres_migration_moves_findings_to_sources_and_the_lifecycle(schema_url):
    revision = "c" * 40
    rows = {  # id: (kind, status, cve_id, data)
        "f1": ("0day", "open", None, {"source_commit_id": "c1", "evidence": ["Seen"],
                                       "_artifact_state": {"revision": "rev"}}),
        "f2": ("0day", "fixed", None, {"evidence": []}),
        "f3": ("cve", "open", "CVE-2026-1", {"source_analysis_id": "x1", "fixed_versions": ["2.0"]}),
        "f4": ("cve", "fixed", "CVE-2026-1", {}),
    }
    migrate(schema_url, "9f7a8ba3c2d7")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_seconds, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a1', 'Site', 'https://example.com', 'plugin', 'Demo', 1, 300, true, false, '{}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO repositories (id, source_kind, source_url, source_generation, watched_branches, created_at)"
            " VALUES ('r1', 'github', 'https://github.com/demo/plugin', 1, '{}', now())"
        ))
        db.execute(text(
            "INSERT INTO commits (id, repository_id, source_generation, revision, data, triage_status,"
            " review_decision) VALUES ('c1', 'r1', 1, :revision, '{}', 'disabled', 'pending')"
        ), {"revision": revision})
        db.execute(text("INSERT INTO cves (id, raw, record_hash, data) VALUES ('CVE-2026-1', '{}', 'h', '{}')"))
        for ident, (kind, status, cve, data) in rows.items():
            db.execute(text(
                "INSERT INTO findings (id, application_id, kind, cve_id, title, status, data, artifact_revision,"
                " created_at, updated_at) VALUES (:id, 'a1', :kind, :cve, :id, :status, CAST(:data AS json),"
                " 'rev', now(), now())"
            ), {"id": ident, "kind": kind, "cve": cve, "status": status, "data": json.dumps(data)})
        db.execute(text(
            "INSERT INTO artifacts (id, resource_type, resource_id, revision, path, storage_path, size, sha256,"
            " content_type) VALUES ('art1', 'finding', 'f1', 'rev', 'report.md', 'rev/report.md', 3, 'h', 'text/markdown')"
        ))
        artifact = db.execute(text("SELECT * FROM artifacts")).one()
    migrate(schema_url, "a08b9cb4d3e8")
    refs = {"f1": revision[:7], "f2": None, "f3": "CVE-2026-1", "f4": "CVE-2026-1"}
    sources = {"0day": "commit", "cve": "cve"}
    statuses = {"open": "open", "fixed": "remediated"}
    with engine.begin() as db:
        found = {row[0]: tuple(row[1:]) for row in db.execute(text(
            "SELECT id, source, status, cve_id, data, artifact_revision FROM findings"))}
        assert found == {
            ident: (sources[kind], statuses[status], cve,
                    {**data, "cause": {"by": "numen"}, "source_ref": refs[ident]}, "rev")
            for ident, (kind, status, cve, data) in rows.items()
        }
        assert db.execute(text("SELECT * FROM artifacts")).one() == artifact
    migrate(schema_url, "head")  # alembic check compares only a database at the head revision.
    drift = alembic(schema_url, "check", check=False)
    assert drift.returncode == 0, drift.stdout + drift.stderr
    alembic(schema_url, "downgrade", "9f7a8ba3c2d7")
    with engine.begin() as db:
        assert {row[0]: tuple(row[1:]) for row in db.execute(text(
            "SELECT id, kind, status, cve_id, data FROM findings"))} == rows
        assert db.execute(text("SELECT * FROM artifacts")).one() == artifact
    migrate(schema_url, "a08b9cb4d3e8")
    with engine.begin() as db:
        db.execute(text("UPDATE findings SET status = 'dismissed' WHERE id = 'f3'"))
    # Numen has no Dismissed or Confirmed state, so it cannot hold this Finding.
    refused = alembic(schema_url, "downgrade", "9f7a8ba3c2d7", check=False)
    assert refused.returncode != 0 and "Findings f3 " in refused.stderr, refused.stderr
    with engine.begin() as db:
        assert db.execute(text("SELECT source, status FROM findings WHERE id = 'f3'")).one() == ("cve", "dismissed")
    engine.dispose()


def test_postgres_migration_adds_remediation_prs(schema_url):
    migrate(schema_url, "a08b9cb4d3e8")
    engine = create_engine(schema_url)
    with engine.begin() as db:
        db.execute(text(
            "INSERT INTO applications (id, asset_name, asset_url, product_kind, product_name,"
            " source_generation, monitor_interval_seconds, monitor_enabled, archived, config, cve_cursor)"
            " VALUES ('a1', 'Site', 'https://example.com', 'plugin', 'Demo', 1, 300, true, false, '{}', '{}')"
        ))
        db.execute(text(
            "INSERT INTO repositories (id, source_kind, source_url, source_generation, watched_branches, created_at)"
            " VALUES ('r1', 'github', 'https://github.com/demo/app', 1, '{}', now())"
        ))
        db.execute(text(
            "INSERT INTO findings (id, application_id, source, title, status, data, created_at, updated_at)"
            " VALUES ('f1', 'a1', 'commit', 'Fixture', 'open', '{}', now(), now())"
        ))
    insert = text(
        "INSERT INTO remediation_prs (id, application_id, finding_id, repository_id, subject, action, status,"
        " data, created_at, updated_at) VALUES (:id, 'a1', 'f1', 'r1', 'c1', 'patch', 'drafting', '{}', now(), now())"
    )
    for _ in range(2):  # upgrade, then again after a downgrade
        migrate(schema_url, "head")
        drift = alembic(schema_url, "check", check=False)
        assert drift.returncode == 0, drift.stdout + drift.stderr
        with engine.begin() as db:
            db.execute(insert, {"id": "p1"})
        # (Application, subject, action) is the idempotency key: a second row is refused.
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.execute(insert, {"id": "p2"})
        alembic(schema_url, "downgrade", "a08b9cb4d3e8")
        with engine.begin() as db:
            assert db.execute(text("SELECT to_regclass('remediation_prs')")).scalar() is None
            assert db.execute(text("SELECT id FROM findings")).scalar() == "f1"
    engine.dispose()


def test_postgres_legacy_commit_parent_lookup_does_not_block_its_own_heartbeat(postgres, monkeypatch):
    import httpx
    from numen.models import Commit
    from numen.sources import Sources
    from numen.worker import run_once
    from test_commit_review import assessment, pinned_bundle, prepared

    original, _ = postgres
    url = make_url(original.database_url)
    options = url.query.get("options", "") + " -clock_timeout=750ms -cstatement_timeout=5000"
    config = replace(
        original,
        database_url=url.update_query_dict({"options": options}).render_as_string(hide_password=False),
        secret_key=Fernet.generate_key().decode(),
        test_mode=True,
    )
    app = create_app(config=config, admin_password="test-password-long")
    lookups = []

    def source_get(self, url, **kwargs):
        # The real heartbeat uses another PostgreSQL connection. Looking up parents
        # after fencing this job used to wait forever on the publication transaction.
        self.heartbeat()
        lookups.append(url)
        return httpx.Response(200, json={"sha": "a" * 40, "parents": [{"sha": "f" * 40}]})

    monkeypatch.setattr(Sources, "get", source_get)
    try:
        with TestClient(app) as client:
            session = client.post("/api/auth/login", json={
                "username": "admin", "password": "test-password-long"}).json()
            client.headers["X-CSRF-Token"] = session["csrf_token"]
            github_account(app)
            _, ident, _ = prepared((app, client, config))
            with app.state.factory.begin() as db:
                row = db.get(Commit, ident)
                row.data = {key: value for key, value in row.data.items() if key != "parent_revisions"}
            job_id = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
            run_once(config, app.state.factory, FixtureBroker(assessment(), pinned_bundle()))
            job = client.get(f"/api/jobs/{job_id}").json()
            assert job["status"] == "succeeded", job
            assert lookups == ["https://api.github.com/repos/demo/plugin/commits/" + "a" * 40]
            finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
            assert finding["source_commit_id"] == ident
            assert finding["artifact_state"]["status"] == "complete"
    finally:
        app.state.factory.kw["bind"].dispose()


def test_postgres_automatic_analysis_caps_count_todays_automatic_jobs(postgres):
    from test_analysis import CAPS, automatic_jobs, cap_events, flag, started, state
    from test_commit_review import prepared

    original, _ = postgres
    config = replace(original, secret_key=Fernet.generate_key().decode(), test_mode=True)
    app = create_app(config=config, admin_password="test-password-long")
    try:
        with TestClient(app) as client:
            session = client.post("/api/auth/login", json={
                "username": "admin", "password": "test-password-long"}).json()
            client.headers["X-CSRF-Token"] = session["csrf_token"]
            monitored, _, _ = prepared((app, client, config))
            started(app, monitored["id"], CAPS["application"] - 1)
            started(app, monitored["id"], 5, shared=True)  # Counted only against the account.
            last, over = flag(app, monitored["id"], "b" * 40, "c" * 40)
            assert state(client, last)["status"] == "queued"
            assert (state(client, over)["status"], state(client, over)["cap"]) == ("waiting_for_cap", "application")
            with app.state.factory.begin() as db:
                schedule(db)  # Re-checked under FOR UPDATE SKIP LOCKED: still waiting, no second event.
            assert state(client, over)["status"] == "waiting_for_cap" and len(cap_events(app)) == 1
            assert len(automatic_jobs(app)) == CAPS["application"] + 5
    finally:
        app.state.factory.kw["bind"].dispose()


def test_postgres_findings_open_and_link_within_each_application(postgres):
    """Opening, linking and the commit's Finding list use JSON paths and row locks on PostgreSQL."""
    from test_findings import test_links_map_addresses_only_within_each_application as scenario

    original, _ = postgres
    config = replace(original, secret_key=Fernet.generate_key().decode(), test_mode=True)
    app = create_app(config=config, admin_password="test-password-long")
    try:
        with TestClient(app) as client:
            session = client.post("/api/auth/login", json={
                "username": "admin", "password": "test-password-long"}).json()
            client.headers["X-CSRF-Token"] = session["csrf_token"]
            scenario((app, client, config))
    finally:
        app.state.factory.kw["bind"].dispose()


def on_postgres(postgres, scenario, *args):
    """Runs a backend scenario test, which takes (system, *args), against PostgreSQL."""
    original, _ = postgres
    config = replace(original, secret_key=Fernet.generate_key().decode(), test_mode=True)
    app = create_app(config=config, admin_password="test-password-long")
    try:
        with TestClient(app) as client:
            session = client.post("/api/auth/login", json={
                "username": "admin", "password": "test-password-long"}).json()
            client.headers["X-CSRF-Token"] = session["csrf_token"]
            scenario((app, client, config), *args)
    finally:
        app.state.factory.kw["bind"].dispose()


@pytest.mark.parametrize("verdict", ["Vulnerability fix", "Malicious change"])
def test_postgres_exposure_is_recorded_once_per_application_and_commit(postgres, tmp_path, verdict):
    """Exposure rows (A05) upsert on their (Application, commit) key and join their Application."""
    from test_exposure import test_a_not_exposed_verdict_is_recorded_on_the_upstream_repository_only as scenario

    on_postgres(postgres, scenario, tmp_path, verdict)


def test_postgres_cleanup_report_maps_git_containment_to_stored_commits(postgres, tmp_path):
    from test_detection_rules import test_the_cleanup_report_lists_the_commits_and_releases_that_contained_the_change as scenario

    on_postgres(postgres, scenario, tmp_path)


def test_postgres_skip_locked_claims_and_fenced_recovery(postgres):
    config, factory = postgres
    with factory.begin() as db:
        application = create_application(db)
        first = enqueue(db, "source_check", application, {"source_generation": 1})
        second = enqueue(db, "source_check", application, {"source_generation": 1})
        first_id, second_id = first.id, second.id
    with factory() as locked:
        locked.begin()
        a = claim(locked, "worker-a")
        assert a.id == first_id
        # A second real connection must skip the uncommitted locked first row.
        with factory.begin() as other:
            b = claim(other, "worker-b")
            assert b.id == second_id and b.attempt_token != a.attempt_token
        locked.commit()
        old = ExecutionContext(factory, a, FixtureBroker())
    with factory.begin() as db:
        row = db.get(Job, first_id)
        row.lease_until = now() - timedelta(seconds=1)
    assert recover(factory, FixtureBroker()) == 1
    with factory.begin() as db:
        replacement = claim(db, "worker-replacement")
        assert replacement.id == first_id and replacement.attempt_token != old.token
    with factory.begin() as db:
        with pytest.raises(DomainError, match="ownership"):
            old.fence(db)


def test_postgres_worker_slots_run_jobs_concurrently(postgres, monkeypatch):
    from numen.worker import run_once
    from numen.workflows import Workflows

    config, factory = postgres
    config = replace(config, secret_key=Fernet.generate_key().decode())
    with factory.begin() as db:
        application = create_application(db)
        ids = [enqueue(db, "source_check", application, {"source_generation": 1}).id for _ in range(2)]
    # Each job waits until the other is running too; a sequential worker would time out.
    barrier = threading.Barrier(2, timeout=20)

    def source_check(self, db, job, application):
        barrier.wait()
        return {"concurrent": True}

    monkeypatch.setattr(Workflows, "source_check", source_check)
    with ThreadPoolExecutor(2) as pool:
        claimed = list(
            pool.map(lambda i: run_once(config, factory, FixtureBroker(), f"slot/{i}"), range(2))
        )
    assert claimed == [True, True]
    with factory() as db:
        jobs = [db.get(Job, ident) for ident in ids]
        assert [job.status for job in jobs] == ["succeeded", "succeeded"]
        assert all(job.result["concurrent"] for job in jobs)


def test_postgres_concurrent_derivations_create_one_shared_upstream_repository(postgres, monkeypatch):
    from numen.models import ApplicationRepository, Repository
    from numen.sources import Sources
    from numen.worker import run_once

    config, factory = postgres
    config = replace(config, secret_key=Fernet.generate_key().decode())
    react = "https://github.com/facebook/react"
    with factory.begin() as db:
        # Production and staging share their Own repository, which depends on react.
        own = Repository(source_kind="github", source_url="https://github.com/acme/shop", cursor="a" * 40)
        db.add(own)
        db.flush()
        ids = []
        for name in ("Production", "Staging"):
            application = create_application(db, name)
            db.add(ApplicationRepository(application_id=application.id, repository_id=own.id, role="own"))
            inputs = {"repository_id": own.id, "source_generation": 1, "source_ref": "a" * 40}
            ids.append(enqueue(db, "derive_upstreams", application, inputs).id)
    manifest = json.dumps({"dependencies": {"react": "^19.0.0"}})
    monkeypatch.setattr(Sources, "github_file", lambda self, repository, path, ref: manifest if path == "package.json" else None)
    monkeypatch.setattr(Sources, "npm_repository", lambda self, name, version: "facebook/react")
    # Both jobs have found no react repository before either inserts one.
    barrier = threading.Barrier(2, timeout=20)

    def insert(*_):
        barrier.wait()

    event.listen(Repository, "before_insert", insert)
    try:
        with ThreadPoolExecutor(2) as pool:
            claimed = list(pool.map(lambda i: run_once(config, factory, FixtureBroker(), f"slot/{i}"), range(2)))
    finally:
        event.remove(Repository, "before_insert", insert)
    assert claimed == [True, True]
    with factory() as db:
        jobs = [db.get(Job, ident) for ident in ids]
        assert [(job.status, job.error) for job in jobs] == [("succeeded", None)] * 2
        [shared] = db.scalars(select(Repository).where(Repository.source_url == react)).all()
        links = db.scalars(select(ApplicationRepository).where(ApplicationRepository.repository_id == shared.id)).all()
        assert sorted(link.application_id for link in links) == sorted(job.application_id for job in jobs)


def test_postgres_command_code_runs_share_their_native_connection(postgres):
    from numen.security import Vault
    from numen.workflows import Workflows

    config, factory = postgres
    config = replace(config, secret_key=Fernet.generate_key().decode())
    vault = Vault(config.secret_key)
    with factory.begin() as db:
        account = Account(
            label="cc",
            provider="commandcode",
            auth_type="native_oauth",
            credential=vault.encrypt({"auth_json": {"commandcode": {"access": "synthetic"}}}),
            data={},
        )
        db.add(account)
        db.flush()
        account_id = account.id
        enqueue(db, "audit_context", create_application(db), {"source_generation": 1})
    with factory.begin() as db:
        job = claim(db, "worker")
    # Both runs must be in flight at once; a lock held on the account row would time this out.
    barrier = threading.Barrier(2, timeout=20)

    class SharedBroker(FixtureBroker):
        def wait(self, run_id, heartbeat, progress, deadline=900):
            barrier.wait()
            return super().wait(run_id, heartbeat, progress, deadline)

    broker = SharedBroker(result={"summary": "ok"})
    workflows = Workflows(config, vault, broker, ExecutionContext(factory, job, broker))
    profile = {
        "agent": "pi",
        "auth_type": "native_oauth",
        "connection_id": account_id,
        "provider_id": "commandcode",
        "model_id": "m",
    }

    def phase(i):
        with factory() as db:
            return workflows.run(db, job, "agent", dict(profile), suffix=f":function:{i}")[0]

    with ThreadPoolExecutor(2) as pool:
        assert list(pool.map(phase, range(2))) == [{"summary": "ok"}, {"summary": "ok"}]


def test_postgres_pending_login_returns_while_worker_holds_account_lock(postgres):
    config, factory = postgres
    url = make_url(config.database_url)
    url = url.update_query_dict({"options": url.query["options"] + " -cstatement_timeout=1000"})
    config = replace(
        config,
        database_url=url.render_as_string(hide_password=False),
        secret_key=Fernet.generate_key().decode(),
    )
    app = create_app(config=config, admin_password="postgres-fixture-password")
    with TestClient(app) as client:
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "postgres-fixture-password"}
        ).json()
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        account = client.post(
            "/api/accounts",
            json={"label": "Native", "provider": "openai", "auth_type": "native_oauth"},
        ).json()
        endpoint = f"/api/accounts/{account['id']}/login"
        first = client.post(endpoint).json()["job_id"]
        with factory.begin() as db:
            assert claim(db, "native-worker").id == first
        with factory.begin() as locked:
            locked.scalar(select(Account).where(Account.id == account["id"]).with_for_update())
            # Native execution holds this lock while the operator verifies. Repeated Start must
            # return the existing attempt without waiting for that long-running transaction.
            response = client.post(endpoint)
            assert response.status_code == 202
            assert response.json()["job_id"] == first


@pytest.fixture
def native_login_api(postgres):
    config, factory = postgres
    url = make_url(config.database_url)
    url = url.update_query_dict({"options": url.query["options"] + " -cstatement_timeout=1000"})
    config = replace(
        config,
        database_url=url.render_as_string(hide_password=False),
        secret_key=Fernet.generate_key().decode(),
    )
    app = create_app(config=config, admin_password="postgres-fixture-password")
    with TestClient(app) as client:
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "postgres-fixture-password"}
        ).json()
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        account = client.post(
            "/api/accounts",
            json={
                "label": "Native race fixture",
                "provider": "openai",
                "auth_type": "native_oauth",
            },
        ).json()
        yield app, client, factory, account["id"], f"/api/accounts/{account['id']}/login"


def test_postgres_login_appearing_between_fast_check_and_lock_is_reused(native_login_api):
    app, client, factory, account_id, endpoint = native_login_api
    reached_lock, resume_lock = threading.Event(), threading.Event()
    engine = app.state.factory.kw["bind"]

    def pause_before_lock(_connection, _cursor, statement, _parameters, _context, _many):
        if "FROM accounts" in statement and "FOR UPDATE" in statement:
            reached_lock.set()
            assert resume_lock.wait(5), "Account lock boundary was not resumed"

    event.listen(engine, "before_cursor_execute", pause_before_lock)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(client.post, endpoint)
            assert reached_lock.wait(5), (
                "Request did not reach the account lock after its empty fast check"
            )
            # Another request commits a login, then its native worker locks the account while
            # this request is between the first pending-job SELECT and its lock statement.
            with factory.begin() as db:
                job = enqueue(
                    db, "account_login", inputs={"account_id": account_id, "credential_revision": 1}
                )
                existing_id = job.id
            with factory.begin() as db:
                assert claim(db, "native-race-worker").id == existing_id
            with factory.begin() as locked:
                locked.scalar(select(Account).where(Account.id == account_id).with_for_update())
                resume_lock.set()
                returned = response.result(timeout=5)
                assert returned.status_code == 202
                assert returned.json()["job_id"] == existing_id
            with factory() as db:
                rows = list(db.scalars(select(Job).where(Job.kind == "account_login")))
                assert len(rows) == 1
    finally:
        resume_lock.set()
        event.remove(engine, "before_cursor_execute", pause_before_lock)


def test_postgres_locked_account_without_pending_login_returns_retryable_busy(native_login_api):
    _, client, factory, account_id, endpoint = native_login_api
    with factory.begin() as locked:
        locked.scalar(select(Account).where(Account.id == account_id).with_for_update())
        # The statement timeout turns a blocking lock regression into a bounded failure. The
        # response must arrive while the other connection still holds the account lock.
        response = client.post(endpoint)
        assert response.status_code == 409
        assert response.json()["code"] == "account_busy"
        assert response.json()["retryable"] is True
    with factory() as db:
        assert list(db.scalars(select(Job).where(Job.kind == "account_login"))) == []


def test_postgres_scheduler_deduplicates_and_api_survives_replacement(postgres):
    config, factory = postgres
    app = create_app(config=config, admin_password="postgres-fixture-password")
    with TestClient(app) as client:
        login = client.post(
            "/api/auth/login", json={"username": "admin", "password": "postgres-fixture-password"}
        ).json()
        client.headers["X-CSRF-Token"] = login["csrf_token"]
        assert client.get("/api/applications").status_code == 200
        created = client.post(
            "/api/applications",
            json={
                "asset_name": "Persistent",
                "asset_url": "https://example.com",
                "product_kind": "plugin",
                "product_name": "Fixture",
                "monitor_interval_seconds": 172800,
            },
        ).json()
        client.post(f"/api/applications/{created['id']}/repositories",
                    json={"source_kind": "wordpress", "plugin_slug": "fixture"})
        cookie = client.cookies.get("numen_session")
    with factory.begin() as db:
        assert schedule(db) == 1
        assert schedule(db) == 0
    replacement = create_app(config=config)
    with TestClient(replacement) as client:
        client.cookies.set("numen_session", cookie)
        assert client.get(f"/api/applications/{created['id']}").json()["asset_name"] == "Persistent"
        assert len(client.get("/api/jobs").json()["items"]) == 1
        assert client.post(f"/api/applications/{created['id']}/checks").status_code == 403
