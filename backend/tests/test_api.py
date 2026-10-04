from fastapi.testclient import TestClient
from numen.api import create_app


def test_auth_program_validation(tmp_path):
    app = create_app(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "files",
        admin_password="test-password-long",
    )
    with TestClient(app) as client:
        assert client.get("/api/programs").status_code == 401
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-long"}
        ).json()
        assert session["authenticated"] is True
        assert client.post("/api/programs", json={}).status_code == 403
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        invalid = client.post(
            "/api/programs",
            json={
                "asset_name": "X",
                "asset_url": "file:///tmp/x",
                "product_kind": "plugin",
                "product_name": "X",
                "source_kind": "wordpress",
                "plugin_slug": "x",
                "monitor_interval_days": 0,
            },
        )
        assert invalid.status_code == 422
        result = client.post(
            "/api/programs",
            json={
                "asset_name": "Site",
                "asset_url": "https://example.com",
                "product_kind": "plugin",
                "product_name": "Plugin",
                "source_kind": "wordpress",
                "plugin_slug": "test-plugin",
                "monitor_interval_days": 2,
            },
        )
        assert result.status_code == 201
        program = result.json()
        assert client.get(f"/api/programs/{program['id']}").json()["plugin_slug"] == "test-plugin"
        assert client.post(f"/api/programs/{program['id']}/checks").status_code == 202
        assert client.get("/api/jobs").json()["items"][0]["kind"] == "source_check"
        client.post("/api/auth/logout")
        assert client.get("/api/programs").status_code == 401


def test_job_enqueue_commits_before_first_successful_response_event(system):
    from sqlalchemy import select
    from numen.models import Job
    from conftest import program

    app, client, _ = system
    monitored = program(client)
    endpoint = f"/api/programs/{monitored['id']}/checks"
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
                                Job.program_id == monitored["id"], Job.kind == "source_check"
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
        job_id = response.json()["job_id"]
        assert observed == [job_id]
        assert immediate.get(f"/api/jobs/{job_id}").status_code == 200
        # Logout deletes the row supplied by auth; a second uncached session would fail ownership.
        assert immediate.post("/api/auth/logout").status_code == 200
        assert immediate.get(f"/api/jobs/{job_id}").status_code == 401


def test_commit_constraint_failure_rolls_back_before_http_success(system):
    from sqlalchemy import event, select
    from sqlalchemy.exc import IntegrityError
    from numen.models import Job
    from conftest import program

    app, client, _ = system
    monitored = program(client)

    def reject_commit(session):
        if session.scalar(select(Job).where(Job.program_id == monitored["id"])):
            raise IntegrityError("commit constraint fixture", {}, Exception("fixture conflict"))

    event.listen(app.state.factory.class_, "before_commit", reject_commit)
    try:
        response = client.post(f"/api/programs/{monitored['id']}/checks")
        assert response.status_code == 409
        assert response.json()["code"] == "record_conflict"
        with app.state.factory() as independent:
            assert independent.scalar(select(Job).where(Job.program_id == monitored["id"])) is None
    finally:
        event.remove(app.state.factory.class_, "before_commit", reject_commit)
