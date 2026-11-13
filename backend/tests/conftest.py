import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from numen.api import create_app
from numen.config import Config
from numen.domain import source_repository
from numen.models import Account, Commit, Application, Repository, Setting, Snapshot
from numen.artifacts import publish

REPOSITORY_FIELDS = ("role", "source_kind", "source_url", "source_ref", "source_path", "plugin_slug", "locked_version")


@pytest.fixture
def system(tmp_path):
    config = Config(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "artifacts",
        secret_key=Fernet.generate_key().decode(),
        test_mode=True,
        frontend_root=Path("/missing-frontend"),
        monitor_interval_seconds=172800,
    )
    app = create_app(config=config, admin_password="test-password-long")
    with TestClient(app) as client:
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-long"}
        ).json()
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        yield app, client, config


def application(client, **overrides):
    """Creates an Application linked to one Upstream repository, built from the source_* overrides."""
    source = {
        "source_kind": "github",
        "source_url": "https://github.com/demo/plugin",
        "source_ref": "main",
        **{key: overrides.pop(key) for key in REPOSITORY_FIELDS if key in overrides},
    }
    body = {
        "asset_name": "Site",
        "asset_url": "https://example.com",
        "product_kind": "plugin",
        "product_name": "Demo",
        "monitor_interval_seconds": 172800,
    }
    result = client.post("/api/applications", json={**body, **overrides})
    assert result.status_code == 201, result.text
    ident = result.json()["id"]
    linked = client.post(f"/api/applications/{ident}/repositories", json=source)
    assert linked.status_code == 201, linked.text
    return client.get(f"/api/applications/{ident}").json()


def repository_of(db, ident):
    """The repository the Application's operations read."""
    return source_repository(db, db.get(Application, ident))


def check_now(client, ident):
    """Check now for an Application with one polled repository: that repository's job id."""
    response = client.post(f"/api/applications/{ident}/checks")
    assert response.status_code == 202, response.text
    return response.json()["items"][0]["job_id"]


def github_account(app):
    """A GitHub read token; GitHub repositories are never polled without one."""
    with app.state.factory.begin() as db:
        db.add(Account(
            label="GitHub", provider="github", auth_type="api_key",
            credential=app.state.vault.encrypt({"api_key": "fixture-github-token"}),
            data={"status": "unchecked", "models": [], "usage": None},
        ))


def connection(app, agents=None):
    models = [
        {
            "id": "test-model",
            "name": "Test",
            "reasoning_efforts": ["low", "high"],
            "default_effort": "low",
        }
    ]
    with app.state.factory.begin() as db:
        account = Account(
            label="Test access",
            provider="openai",
            auth_type="api_key",
            credential=app.state.vault.encrypt({"api_key": "fixture-key-no-real-access"}),
            data={
                "status": "ready",
                "models": models,
                "agent_models": agents or {"pi": models, "codex": models},
                "usage": None,
            },
        )
        db.add(account)
        db.flush()
        profile = {
            "agent": "pi",
            "connection_id": account.id,
            "model_id": "test-model",
            "reasoning_effort": "high",
        }
        setting = db.get(Setting, "global")
        setting.data = {
            **setting.data,
            # Codex is refused for Triage, Analysis and CVE analysis, so they run on Pi.
            "default_profiles": {
                **{
                    op: {**profile, "agent": "codex"}
                    for op in ("version_recipe", "audit_context", "finding_artifacts")
                },
                **{op: profile for op in ("commit_triage", "commit_analysis", "cve_analysis")},
            },
        }
    return profile


def source_snapshot(app, ident, revision="a" * 40, repository_id=None):
    """A snapshot and a commit at `revision` of the Application's source repository, or of
    `repository_id`."""
    with app.state.factory.begin() as db:
        row = db.get(Repository, repository_id) if repository_id else repository_of(db, ident)
        row.cursor = revision
        source = Snapshot(
            repository_id=row.id,
            source_generation=row.source_generation,
            source_ref=revision,
            files=["main.py"],
        )
        db.add(source)
        db.flush()
        publish(
            db,
            app.state.config.artifact_root,
            "snapshot",
            source.id,
            {"main.py": b"def parse(value):\n    return str(value)\n"},
        )
        commit = Commit(
            repository_id=row.id,
            source_generation=row.source_generation,
            revision=revision,
            data={
                "message": "Fix validation",
                "author": "Fixture",
                "files": [{"path": "main.py"}],
                "diff": "-return value\n+return str(value)",
                "diff_complete": True,
            },
            triage_status="disabled",
        )
        db.add(commit)
        db.flush()
        return commit.id


class FixtureBroker:
    def __init__(self, result=None, outputs=None, handler=None):
        self.result, self.outputs, self.handler = result or {}, outputs or {}, handler
        self.calls, self.states, self.ingress_deleted = [], {}, []

    def submit(
        self,
        token,
        kind,
        profile=None,
        prompt="",
        schema=None,
        files=None,
        policy=None,
        limits=None,
    ):
        call = {
            "token": token,
            "kind": kind,
            "profile": profile,
            "prompt": prompt,
            "schema": schema,
            "files": files or {},
            "policy": policy,
            "limits": limits,
        }
        self.calls.append(call)
        result, outputs = self.handler(call) if self.handler else (self.result, self.outputs)
        self.states[token] = {
            "run_id": token,
            "status": "succeeded",
            "result": result,
            "outputs": [
                {
                    "path": p,
                    "content_base64": base64.b64encode(data).decode(),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for p, data in outputs.items()
            ],
        }
        return {"run_id": token, "status": "queued"}

    def wait(self, run_id, heartbeat, progress, deadline=900):
        heartbeat()
        progress(self.states[run_id])
        return self.states[run_id]

    def request(self, method, path, **kwargs):
        return self.states[path.split("/")[-1]]

    def cancel(self, run_id):
        self.states[run_id]["status"] = "cancelled"
        return self.states[run_id]

    def lookup_attempt(self, attempt_token):
        state = self.states.get(attempt_token)
        return {"run_id": attempt_token, "status": state["status"]} if state else None

    def credential(self, run_id):
        return {"auth_json": {"access_token": "native-fixture-secret"}}

    def delete_credential(self, run_id):
        self.ingress_deleted.append(run_id)
