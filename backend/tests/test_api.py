from fastapi.testclient import TestClient
import pytest
from numen.api import create_app


def test_auth_application_validation(tmp_path):
    app = create_app(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "files",
        admin_password="test-password-long",
    )
    with TestClient(app) as client:
        assert client.get("/api/applications").status_code == 401
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-long"}
        ).json()
        assert session["authenticated"] is True
        assert client.post("/api/applications", json={}).status_code == 403
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        invalid = client.post(
            "/api/applications",
            json={
                "asset_name": "X",
                "asset_url": "file:///tmp/x",
                "product_kind": "plugin",
                "product_name": "X",
                "monitor_interval_seconds": 0,
            },
        )
        assert invalid.status_code == 422
        result = client.post(
            "/api/applications",
            json={
                "asset_name": "Site",
                "asset_url": "https://example.com",
                "product_kind": "plugin",
                "product_name": "Plugin",
                "monitor_interval_seconds": 172800,
            },
        )
        assert result.status_code == 201
        application = result.json()
        repositories = f"/api/applications/{application['id']}/repositories"
        assert client.post(repositories, json={"source_kind": "wordpress", "plugin_slug": "Bad slug"}).status_code == 422
        assert client.post(repositories, json={"source_kind": "wordpress", "plugin_slug": "test-plugin"}).status_code == 201
        linked = client.get(f"/api/applications/{application['id']}").json()["repositories"]
        assert [r["plugin_slug"] for r in linked] == ["test-plugin"]
        assert client.post(f"/api/applications/{application['id']}/checks").status_code == 202
        assert client.get("/api/jobs").json()["items"][0]["kind"] == "source_check"
        client.post("/api/auth/logout")
        assert client.get("/api/applications").status_code == 401


def test_job_enqueue_commits_before_first_successful_response_event(system):
    from sqlalchemy import select
    from numen.models import Job
    from conftest import application

    app, client, _ = system
    monitored = application(client)
    endpoint = f"/api/applications/{monitored['id']}/checks"
    observed = []

    class ObserveResponse:
        async def __call__(self, scope, receive, send):
            async def checked_send(message):
                if (
                    scope.get("path") == endpoint
                    and message["type"] == "http.response.start"
                    and message["status"] == 202
                ):
                    with app.state.factory() as independent:
                        persisted = independent.scalar(
                            select(Job).where(
                                Job.application_id == monitored["id"], Job.kind == "source_check"
                            )
                        )
                        assert persisted is not None, (
                            "202 became observable before the queued job committed"
                        )
                        observed.append(persisted.id)
                await send(message)

            await app(scope, receive, checked_send)

    with TestClient(ObserveResponse()) as immediate:
        immediate.cookies.update(client.cookies)
        immediate.headers["X-CSRF-Token"] = client.headers["X-CSRF-Token"]
        response = immediate.post(endpoint)
        assert response.status_code == 202
        job_id = response.json()["items"][0]["job_id"]
        assert observed == [job_id]
        assert immediate.get(f"/api/jobs/{job_id}").status_code == 200
        # Logout deletes the row supplied by auth; a second uncached session would fail ownership.
        assert immediate.post("/api/auth/logout").status_code == 200
        assert immediate.get(f"/api/jobs/{job_id}").status_code == 401


def test_commit_constraint_failure_rolls_back_before_http_success(system):
    from sqlalchemy import event, select
    from sqlalchemy.exc import IntegrityError
    from numen.models import Job
    from conftest import application

    app, client, _ = system
    monitored = application(client)

    def reject_commit(session):
        if session.scalar(select(Job).where(Job.application_id == monitored["id"])):
            raise IntegrityError("commit constraint fixture", {}, Exception("fixture conflict"))

    event.listen(app.state.factory.class_, "before_commit", reject_commit)
    try:
        response = client.post(f"/api/applications/{monitored['id']}/checks")
        assert response.status_code == 409
        assert response.json()["code"] == "record_conflict"
        with app.state.factory() as independent:
            assert independent.scalar(select(Job).where(Job.application_id == monitored["id"])) is None
    finally:
        event.remove(app.state.factory.class_, "before_commit", reject_commit)


def test_job_session_inputs_only_reach_runs_of_the_running_attempt(system, monkeypatch):
    from numen.broker import Broker
    from numen.models import Job, JobAttempt

    app, client, _ = system
    calls = []

    def session(self, run_id, body=None):
        calls.append((run_id, body))
        return {
            "agent": "claude", "agent_status": "working", "screen": "thinking",
            "held": False, "live": True,
        }

    monkeypatch.setattr(Broker, "session", session)
    with app.state.factory.begin() as db:
        job = Job(kind="commit_analysis", status="running", input_hash="h", attempt_token="a",
                  broker_run_id="run-2")
        db.add(job)
        db.flush()
        db.add(JobAttempt(id="a", job_id=job.id, status="running",
                          data={"runtime_phases": {"a:1": "run-1", "a:2": "run-2", "a:3": None}}))
        ident = job.id
    state = client.get(f"/api/jobs/{ident}/session").json()
    assert state["runs"] == ["run-1", "run-2"] and state["run_id"] == "run-2"
    assert client.get(f"/api/jobs/{ident}/session?run=run-1").json()["run_id"] == "run-1"
    url = f"/api/jobs/{ident}/session"
    before_invalid = list(calls)
    assert client.get(url, params={"run": "other"}).status_code == 409
    assert calls == before_invalid
    assert client.post(url, json={"run_id": "other", "action": "hold"}).status_code == 409
    assert client.post(url, json={"run_id": "run-1", "action": "prompt"}).status_code == 422
    response = client.post(url, json={"run_id": "run-1", "action": "prompt", "text": "why?"})
    assert response.status_code == 202
    assert calls[-1] == ("run-1", {"action": "prompt", "text": "why?"})
    with app.state.factory.begin() as db:
        db.get(JobAttempt, "a").data = {"runtime_phases": {}}
    assert client.get(url).json()["run_id"] == "run-2"
    assert client.post(url, json={"run_id": "run-2", "action": "hold"}).status_code == 409
    with app.state.factory.begin() as db:
        db.get(Job, ident).status = "succeeded"
    assert client.post(url, json={"run_id": "run-1", "action": "hold"}).status_code == 409


@pytest.mark.parametrize("status", ["succeeded", "failed", "cancelled", "cancelling"])
def test_job_session_retains_full_screen_after_completion_or_cancellation(system, monkeypatch, status):
    from numen.broker import Broker
    from numen.models import Job, JobAttempt, JobEvent

    app, client, _ = system
    screen = "\n".join(f"terminal line {number}" for number in range(1001))
    retained = {
        "agent": "codex", "agent_status": "idle", "screen": screen,
        "held": False, "live": status == "cancelling",
    }
    calls = []

    def session(self, run_id, body=None):
        calls.append((run_id, body))
        return retained

    monkeypatch.setattr(Broker, "session", session)
    with app.state.factory.begin() as db:
        job = Job(kind="commit_analysis", status=status, input_hash="h", attempt_token="a",
                  broker_run_id="retained-run")
        db.add(job)
        db.flush()
        # Finished phases are removed from runtime_phases but remain on the job timeline.
        db.add(JobAttempt(id="a", job_id=job.id, status=status, data={"runtime_phases": {}}))
        db.add(JobEvent(job_id=job.id, data={"kind": "runtime_started", "run_id": "retained-run"}))
        ident = job.id

    url = f"/api/jobs/{ident}/session"
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json() == {"runs": ["retained-run"], "run_id": "retained-run", **retained}
    assert client.post(url, json={"run_id": "retained-run", "action": "hold"}).status_code == 409
    assert calls == [("retained-run", None)]


def test_job_session_reads_all_attempts_and_completed_phases_in_start_order(system, monkeypatch):
    from datetime import timedelta
    from numen.broker import Broker
    from numen.models import Job, JobAttempt, JobEvent, now

    app, client, _ = system
    calls = []

    def session(self, run_id, body=None):
        calls.append((run_id, body))
        return {"screen": run_id, "live": run_id == "current-run"}

    monkeypatch.setattr(Broker, "session", session)
    started = now()
    with app.state.factory.begin() as db:
        job = Job(kind="audit_context", status="running", input_hash="h", attempt_token="current",
                  broker_run_id="current-run")
        foreign = Job(kind="commit_analysis", status="running", input_hash="other")
        db.add_all([job, foreign])
        db.flush()
        # Deliberately insert newer records first: the API must use recorded chronology.
        db.add_all([
            JobAttempt(id="current", job_id=job.id, status="running",
                       created_at=started + timedelta(seconds=3),
                       data={"runtime_phases": {"current:1": "current-run"}}),
            JobAttempt(id="older", job_id=job.id, status="interrupted", created_at=started,
                       data={"runtime_phases": {"older:1": "older-run", "older:2": None}}),
            JobAttempt(id="foreign", job_id=foreign.id, status="running",
                       data={"runtime_phases": {"foreign:1": "foreign-run"}}),
            JobEvent(job_id=job.id, created_at=started + timedelta(seconds=4),
                     data={"kind": "runtime_started", "run_id": "current-run"}),
            JobEvent(job_id=job.id, created_at=started + timedelta(seconds=2),
                     data={"kind": "runtime_started", "run_id": "finished-run"}),
            JobEvent(job_id=job.id, created_at=started + timedelta(seconds=1),
                     data={"kind": "runtime_started", "run_id": "older-run"}),
            JobEvent(job_id=foreign.id, data={"kind": "runtime_started", "run_id": "foreign-run"}),
        ])
        ident = job.id

    url = f"/api/jobs/{ident}/session"
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json()["runs"] == ["older-run", "finished-run", "current-run"]
    assert response.json()["run_id"] == "current-run"
    for run in ("older-run", "finished-run"):
        response = client.get(url, params={"run": run})
        assert response.status_code == 200, response.text
        assert response.json()["screen"] == run
        assert client.post(url, json={"run_id": run, "action": "hold"}).status_code == 409
    assert client.post(url, json={"run_id": "current-run", "action": "hold"}).status_code == 202
    assert calls[-1] == ("current-run", {"action": "hold"})
    before_invalid = list(calls)
    for run in ("foreign-run", "unknown-run", ""):
        response = client.get(url, params={"run": run})
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "session_unavailable"
        response = client.post(url, json={"run_id": run, "action": "hold"})
        assert response.status_code == (409 if run else 422)
    assert calls == before_invalid


def test_job_session_legacy_run_requires_authentication_and_input_requires_csrf(system, monkeypatch):
    from numen.broker import Broker
    from numen.models import Job

    app, client, _ = system
    calls = []

    def session(self, run_id, body=None):
        calls.append((run_id, body))
        return {"screen": "retained legacy history", "live": False}

    monkeypatch.setattr(Broker, "session", session)
    with app.state.factory.begin() as db:
        job = Job(kind="commit_analysis", status="succeeded", input_hash="h",
                  broker_run_id="legacy-run")
        db.add(job)
        db.flush()
        ident = job.id
    url = f"/api/jobs/{ident}/session"
    with TestClient(app) as unauthenticated:
        assert unauthenticated.get(url).status_code == 401
        assert unauthenticated.post(url, json={"run_id": "legacy-run", "action": "hold"}).status_code == 401
    assert calls == []
    del client.headers["X-CSRF-Token"]
    assert client.post(url, json={"run_id": "legacy-run", "action": "hold"}).status_code == 403
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json()["runs"] == ["legacy-run"]
    assert response.json()["screen"] == "retained legacy history"
    assert calls == [("legacy-run", None)]


def test_job_session_cannot_steer_an_attempt_owned_by_another_job(system, monkeypatch):
    from numen.broker import Broker
    from numen.models import Job, JobAttempt

    app, client, _ = system
    calls = []
    monkeypatch.setattr(Broker, "session", lambda self, *args: calls.append(args) or {})
    with app.state.factory.begin() as db:
        job = Job(kind="commit_analysis", status="running", input_hash="h", attempt_token="foreign")
        foreign = Job(kind="commit_analysis", status="running", input_hash="other")
        db.add_all([job, foreign])
        db.flush()
        db.add(JobAttempt(id="foreign", job_id=foreign.id, status="running",
                          data={"runtime_phases": {"foreign:1": "foreign-run"}}))
        ident = job.id
    url = f"/api/jobs/{ident}/session"
    assert client.get(url).status_code == 409
    assert client.post(url, json={"run_id": "foreign-run", "action": "hold"}).status_code == 409
    assert calls == []


@pytest.mark.parametrize("code,status,expected", [
    ("session_unavailable", 409, 200),
    ("broker_error", 502, 502),
    ("broker_unavailable", 503, 503),
    ("record_conflict", 409, 409),
])
def test_job_session_default_skips_only_unavailable_legacy_sessions(
    system, monkeypatch, code, status, expected
):
    from datetime import timedelta
    from numen.broker import Broker
    from numen.models import Job, JobEvent, now
    from numen.security import DomainError

    app, client, _ = system
    calls = []

    def session(self, run_id, body=None):
        calls.append(run_id)
        if run_id == "legacy-probe":
            raise DomainError(code, "Latest run cannot provide a session", status)
        return {"screen": "retained agent terminal", "live": False}

    monkeypatch.setattr(Broker, "session", session)
    started = now()
    with app.state.factory.begin() as db:
        job = Job(kind="version_recipe", status="succeeded", input_hash="h",
                  broker_run_id="legacy-probe")
        db.add(job)
        db.flush()
        db.add_all([
            JobEvent(job_id=job.id, created_at=started,
                     data={"kind": "runtime_started", "run_id": "legacy-agent"}),
            JobEvent(job_id=job.id, created_at=started + timedelta(seconds=1),
                     data={"kind": "runtime_started", "run_id": "legacy-probe"}),
        ])
        ident = job.id
    url = f"/api/jobs/{ident}/session"
    response = client.get(url)
    assert response.status_code == expected, response.text
    if expected == 200:
        assert response.json()["run_id"] == "legacy-agent"
        assert response.json()["runs"] == ["legacy-agent"]
        assert response.json()["screen"] == "retained agent terminal"
        assert calls == ["legacy-probe", "legacy-agent"]
    else:
        assert response.json()["code"] == code
        assert calls == ["legacy-probe"]
    calls.clear()
    response = client.get(url, params={"run": "legacy-probe"})
    assert response.status_code == status, response.text
    assert calls == ["legacy-probe"]


def test_job_session_selector_excludes_recorded_non_agent_runtimes(system, monkeypatch):
    from numen.broker import Broker
    from numen.models import Job, JobAttempt
    from numen.queue import ExecutionContext

    app, client, _ = system
    calls = []

    def session(self, run_id, body=None):
        calls.append(run_id)
        assert run_id.startswith("agent-")
        return {"screen": run_id, "live": False}

    monkeypatch.setattr(Broker, "session", session)
    runs = [
        ("agent-older", "agent"), ("probe-older", "probe"),
        ("agent-current", "agent"), ("probe-current", "probe"),
        ("capabilities", "capabilities"), ("login", "account_login"), ("lab", "lab"),
    ]
    with app.state.factory.begin() as db:
        job = Job(kind="version_recipe", status="running", input_hash="h", attempt_token="a")
        db.add(job)
        db.flush()
        db.add(JobAttempt(id="a", job_id=job.id, status="running", data={}))
        ident = job.id
    context = ExecutionContext(app.state.factory, job, None)
    for index, (run_id, kind) in enumerate(runs):
        phase = f"a:{index}"
        context.set_phase(phase)
        context.set_run(run_id, phase, kind=kind)
        if kind == "agent":
            context.end_phase(phase)
    with app.state.factory.begin() as db:
        db.get(Job, ident).status = "succeeded"
        db.get(JobAttempt, "a").status = "succeeded"
    url = f"/api/jobs/{ident}/session"
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert response.json()["runs"] == ["agent-older", "agent-current"]
    assert response.json()["run_id"] == "agent-current"
    assert calls == ["agent-current"]
    for run_id, kind in runs:
        if kind != "agent":
            assert client.get(url, params={"run": run_id}).status_code == 409
    assert calls == ["agent-current"]


def test_every_response_is_served_under_a_content_security_policy_that_forbids_inline_script(
    tmp_path,
):
    """A15: the dashboard, its assets and the API carry a CSP that forbids inline script."""
    from numen.config import Config

    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text('<script type="module" src="/assets/app.js"></script>')
    (root / "assets" / "app.js").write_text("export {};")
    config = Config(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "files",
        frontend_root=root,
    )
    with TestClient(create_app(config=config, admin_password="test-password-long")) as client:
        for path in ("/", "/assets/app.js", "/api/auth/session"):
            response = client.get(path)
            assert response.status_code == 200, path
            policy = dict(
                part.strip().split(" ", 1)
                for part in response.headers["content-security-policy"].split(";")
            )
            assert policy["script-src"] == "'self'", path
            assert "unsafe" not in policy.get("default-src", "")
            for directive, value in (
                ("object-src", "'none'"),
                ("base-uri", "'none'"),
                ("frame-ancestors", "'none'"),
                ("form-action", "'self'"),
            ):
                assert policy[directive] == value, (path, directive)
            assert response.headers.get_list("x-content-type-options") == ["nosniff"], path
            assert response.headers["referrer-policy"] == "no-referrer", path
        for path in ("/docs", "/openapi.json", "/redoc"):
            assert "swagger" not in client.get(path).text.lower(), path


def test_the_built_dashboard_has_no_inline_script():
    """A15: the built index.html loads only same-origin script files and has no event handlers."""
    import os
    from html.parser import HTMLParser
    from pathlib import Path
    from urllib.parse import urlsplit

    index = Path(os.environ.get("NUMEN_FRONTEND_ROOT", "../frontend/dist")) / "index.html"
    if not index.is_file():
        pytest.skip("the built frontend is not in this image")
    scripts, handlers = [], []

    class Index(HTMLParser):
        def handle_starttag(self, tag, attrs):
            handlers.extend(name for name, _ in attrs if name.startswith("on"))
            if tag == "script":
                scripts.append({"src": dict(attrs).get("src"), "body": ""})

        def handle_data(self, data):
            if self.lasttag == "script" and scripts:
                scripts[-1]["body"] += data.strip()

    Index().feed(index.read_text())
    assert scripts, "the dashboard loads its script"
    for script in scripts:
        assert script["src"] and not urlsplit(script["src"]).netloc, script
        assert script["body"] == "", script
    assert handlers == []
