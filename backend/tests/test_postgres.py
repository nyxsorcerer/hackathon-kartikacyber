"""Actual PostgreSQL lock/lease/migration/session proof in a disposable isolated schema."""

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

from numen.api import create_app
from numen.config import Config
from numen.db import make_database
from numen.domain import enqueue, schedule
from numen.models import Account, Job, Program, now
from numen.queue import ExecutionContext, claim, recover
from numen.security import DomainError
from conftest import FixtureBroker


@pytest.fixture
def postgres(tmp_path):
    base = os.getenv("NUMEN_TEST_DATABASE_URL")
    if not base:
        pytest.skip("NUMEN_TEST_DATABASE_URL is required for the PostgreSQL boundary")
    schema = "numen_test_" + uuid.uuid4().hex
    control = create_engine(base)
    with control.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = (
        make_url(base)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    config = Config(database_url=url, artifact_root=tmp_path / "artifacts", monitor_interval_days=2)
    env = {**os.environ, "NUMEN_DATABASE_URL": url}
    try:
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            check=True,
            capture_output=True,
        )
        engine, factory = make_database(config, initialize=True)
        yield config, factory
        engine.dispose()
    finally:
        with control.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        control.dispose()


def create_program(db, name="Fixture"):
    program = Program(
        asset_name=name,
        asset_url="https://example.com",
        product_kind="plugin",
        product_name="Fixture",
        source_kind="wordpress",
        source_url="https://plugins.svn.wordpress.org/fixture",
        plugin_slug="fixture",
        source_ref="trunk",
        monitor_interval_days=2,
        config={"triage_mode": "disabled"},
        monitor_enabled=True,
    )
    db.add(program)
    db.flush()
    return program


def test_postgres_skip_locked_claims_and_fenced_recovery(postgres):
    config, factory = postgres
    with factory.begin() as db:
        program = create_program(db)
        first = enqueue(db, "source_check", program, {"source_generation": 1})
        second = enqueue(db, "source_check", program, {"source_generation": 1})
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
        program = create_program(db)
        ids = [enqueue(db, "source_check", program, {"source_generation": 1}).id for _ in range(2)]
    # Each job waits until the other is running too; a sequential worker would time out.
    barrier = threading.Barrier(2, timeout=20)

    def source_check(self, db, job, program):
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
        enqueue(db, "audit_context", create_program(db), {"source_generation": 1})
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
        assert client.get("/api/programs").status_code == 200
        created = client.post(
            "/api/programs",
            json={
                "asset_name": "Persistent",
                "asset_url": "https://example.com",
                "product_kind": "plugin",
                "product_name": "Fixture",
                "source_kind": "wordpress",
                "plugin_slug": "fixture",
                "monitor_interval_days": 2,
            },
        ).json()
        cookie = client.cookies.get("numen_session")
    with factory.begin() as db:
        assert schedule(db) == 1
        assert schedule(db) == 0
    replacement = create_app(config=config)
    with TestClient(replacement) as client:
        client.cookies.set("numen_session", cookie)
        assert client.get(f"/api/programs/{created['id']}").json()["asset_name"] == "Persistent"
        assert len(client.get("/api/jobs").json()["items"]) == 1
        assert client.post(f"/api/programs/{created['id']}/checks").status_code == 403
